# surveillance_recon/utils/logger.py
# [SecOps Research // Encrypted Operational Logger v2.1]
# For authorized red team use under Security Research Protocol §7. All logs are encrypted and ephemeral by default.

import os
import json
import atexit
import base64
import hashlib
import threading
from datetime import datetime
from typing import Any, Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecureLogger:
    """
    Secure, encrypted logger with:
    - AES-256 encryption using target-derived key
    - Stealth file naming (mimics system files)
    - Auto-wipe on exit (optional)
    - Console + encrypted file dual output
    - Thread-safe write locking
    """

    def __init__(
        self,
        target_ip: str,
        log_dir: str = "logs",
        encrypt: bool = True,
        auto_wipe: bool = True,
        console_output: bool = True
    ):
        self.target_ip = target_ip
        self.log_dir = log_dir
        self.encrypt = encrypt
        self.auto_wipe = auto_wipe
        self.console_output = console_output
        self.lock = threading.Lock()
        self.log_entries = []
        self.log_path = None

        # Create log dir
        os.makedirs(self.log_dir, exist_ok=True)

        # Derive encryption key from target IP + static seed (obfuscated)
        if self.encrypt:
            salt = b"ZetaLog777"
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key_material = f"ZetaLogKey_{target_ip}".encode()
            key = base64.urlsafe_b64encode(kdf.derive(key_material))
            self.cipher = Fernet(key)
        else:
            self.cipher = None

        # Generate stealth log filename (mimics Windows/Linux temp files)
        ip_hash = hashlib.sha256(target_ip.encode()).hexdigest()[:8]
        if os.name == 'nt':
            self.log_path = os.path.join(self.log_dir, f"~{ip_hash}.tmp")
        else:
            self.log_path = os.path.join(self.log_dir, f".{ip_hash}.cache")

        # Register cleanup
        if self.auto_wipe:
            atexit.register(self._secure_wipe)

    def _secure_wipe(self):
        """Overwrite and delete log file on exit"""
        if not self.log_path or not os.path.exists(self.log_path):
            return
        try:
            with open(self.log_path, "ba+") as f:
                length = f.tell()
                f.seek(0)
                f.write(os.urandom(length))
            os.remove(self.log_path)
        except:
            try:
                os.remove(self.log_path)
            except: pass  # Silent fail

    def _format_entry(self, level: str, message: Any, **kwargs) -> Dict:
        """Structure log entry"""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": level,
            "target_ip": self.target_ip,
            "message": str(message),
            "extra": kwargs
        }
        return entry

    def _write_to_disk(self, entry: Dict):
        """Write encrypted or plaintext log entry"""
        try:
            serialized = json.dumps(entry, separators=(',', ':')) + "\n"
            data = serialized.encode('utf-8')

            if self.encrypt and self.cipher:
                data = self.cipher.encrypt(data)

            with self.lock:
                with open(self.log_path, "ab") as f:
                    f.write(data)
        except: pass  # Never crash on log failure

    def log(self, level: str, message: Any, **kwargs):
        """Main logging interface"""
        entry = self._format_entry(level, message, **kwargs)
        self.log_entries.append(entry)

        # Console output (if enabled)
        if self.console_output:
            prefix = {
                "INFO": "[+]",
                "WARN": "[!]",
                "ERROR": "[-]",
                "SUCCESS": "[✓]",
                "DATA": "[→]"
            }.get(level, f"[{level}]")
            print(f"{prefix} {message}")

        # Disk output
        self._write_to_disk(entry)

    def info(self, message: str, **kwargs):
        self.log("INFO", message, **kwargs)

    def warn(self, message: str, **kwargs):
        self.log("WARN", message, **kwargs)

    def error(self, message: str, **kwargs):
        self.log("ERROR", message, **kwargs)

    def success(self, message: str, **kwargs):
        self.log("SUCCESS", message, **kwargs)

    def data(self, key: str, value: Any, **kwargs):
        self.log("DATA", f"{key}: {value}", **{**kwargs, "raw_key": key, "raw_value": value})

    def save_full_report(self, report: Dict, filename: Optional[str] = None) -> str:
        """Save full structured report as encrypted JSON"""
        if not filename:
            ip_hash = hashlib.sha256(self.target_ip.encode()).hexdigest()[:10]
            filename = os.path.join(self.log_dir, f"zeta_report_{ip_hash}.json.enc")

        try:
            data = json.dumps(report, indent=2).encode('utf-8')
            if self.encrypt and self.cipher:
                data = self.cipher.encrypt(data)
                filename = filename if filename.endswith('.enc') else filename + '.enc'
            else:
                filename = filename.replace('.enc', '') if filename.endswith('.enc') else filename

            with open(filename, 'wb') as f:
                f.write(data)
            self.success(f"Full report saved: {filename}")
            return filename
        except Exception as e:
            self.error(f"Failed to save report: {e}")
            return ""

    def get_log_path(self) -> str:
        return self.log_path

    def disable_console(self):
        self.console_output = False

    def enable_console(self):
        self.console_output = True
