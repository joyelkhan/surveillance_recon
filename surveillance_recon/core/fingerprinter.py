# surveillance_recon/core/fingerprinter.py
# [SecOps Research // Deep Camera Fingerprinter v2.3]
# For authorized security research under Security Research Protocol §7. Unauthorized use prohibited.

import re
import requests
from bs4 import BeautifulSoup
from typing import Dict, Optional, List, Tuple
from urllib.parse import urljoin

# Zeta: Comprehensive brand signature database with CVE mappings
BRAND_SIGS = {
    "hikvision": {
        "html": [r"hikvision", r"ivms", r"web\.js", r"login\.cgi", r"doc/page/"],
        "headers": ["Hikvision", "DNVRS", "IPCamera"],
        "urls": ["/doc/page/login.asp", "/doc/page/config.asp"],
        "cves": ["CVE-2021-36260", "CVE-2017-7921", "CVE-2018-6414"],
        "default_creds": [("admin", ""), ("admin", "12345")]
    },
    "dahua": {
        "html": [r"dahua", r"smartpss", r"cgi-bin/login\.cgi", r"language="],
        "headers": ["Dahua", "DSS"],
        "urls": ["/cgi-bin/login.cgi", "/doc/login.html"],
        "cves": ["CVE-2021-33044", "CVE-2018-18778", "CVE-2020-25078"],
        "default_creds": [("admin", "admin"), ("admin", "123456"), ("888888", "888888")]
    },
    "cp_plus": {
        "html": [r"cp plus", r"cp-uvr", r"webplugin", r"cpplus", r"ic2"],
        "headers": ["CP Plus", "CP-UVR"],
        "urls": ["/login.html", "/index.html"],
        "cves": [],  # No public CVEs, but weak auth
        "default_creds": [("admin", "admin"), ("admin", "12345")]
    },
    "axis": {
        "html": [r"axis", r"vapix", r"axis media control"],
        "headers": ["AXIS", "VAPIX"],
        "urls": ["/axis-cgi/param.cgi", "/view/index.shtml"],
        "cves": ["CVE-2021-33545", "CVE-2019-18988"],
        "default_creds": [("root", "pass"), ("root", "root")]
    },
    "sony": {
        "html": [r"sony", r"snc", r"sensormaster"],
        "headers": ["Sony", "SNC"],
        "urls": ["/index.html", "/command/login"],
        "cves": ["CVE-2019-12257"],
        "default_creds": [("admin", "admin")]
    },
    "bosch": {
        "html": [r"bosch", r"videoterminal", r"bvc"],
        "headers": ["Bosch", "BVC"],
        "urls": ["/operator/login.html"],
        "cves": ["CVE-2020-16273"],
        "default_creds": [("service", "service"), ("admin", "admin")]
    },
    "panasonic": {
        "html": [r"panasonic", r"bb-hcm", r"bb-hgw"],
        "headers": ["Panasonic", "BB-H"],
        "urls": ["/login.html"],
        "cves": ["CVE-2019-10067"],
        "default_creds": [("admin", "12345")]
    },
    "vivotek": {
        "html": [r"vivotek", r"liveview", r"ipcam"],
        "headers": ["Vivotek", "IPC"],
        "urls": ["/cgi-bin/viewer/video.jpg", "/login.html"],
        "cves": ["CVE-2021-32934"],
        "default_creds": [("root", ""), ("admin", "admin")]
    },
    "generic_onvif": {
        "html": [r"onvif"],
        "headers": ["ONVIF"],
        "urls": ["/onvif/device_service"],
        "cves": [],
        "default_creds": [("admin", "admin")]
    }
}

class CameraFingerprinter:
    """
    Deep fingerprinting engine that identifies brand, model, firmware, CVEs, and exploit readiness.
    Uses multi-vector analysis: HTML, headers, URLs, ONVIF, and behavior.
    """

    def __init__(self, target_ip: str, port: int, timeout: int = 5):
        self.target_ip = target_ip
        self.port = port
        self.timeout = timeout
        self.base_url = f"http://{target_ip}:{port}"
        self.html_content = ""
        self.headers = {}
        self.title = ""
        self.server = ""
        self.brand = None
        self.model = "Unknown"
        self.firmware = "Unknown"
        self.vulns = []
        self.is_exploit_ready = False

    def _fetch_page(self, path: str = "/") -> bool:
        """Fetch page and store content/headers"""
        try:
            url = urljoin(self.base_url, path)
            r = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            self.html_content = r.text
            self.headers = {k.lower(): v for k, v in r.headers.items()}
            self.server = self.headers.get("server", "Unknown")
            
            # Suppress XML parser warnings
            import warnings
            from bs4 import XMLParsedAsHTMLWarning
            warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
            
            soup = BeautifulSoup(self.html_content, 'html.parser')
            self.title = soup.title.string.strip() if soup.title else "No Title"
            return True
        except:
            return False

    def _extract_model_firmware(self):
        """Extract model/firmware from HTML or headers"""
        content = (self.html_content + " " + self.server + " " + self.title).lower()

        # Common patterns
        model_patterns = [
            r"(cp[-\s]?uvr[-\s]?\w+)",
            r"(ds[-\s]?\w+)",
            r"(ipc[-\s]?\w+)",
            r"(bb[-\s]?[a-z0-9]+)",
            r"model[:\s]*([a-z0-9\-]+)",
            r"firmware[:\s]*v?(\d+\.\d+\.\d+)"
        ]

        for pattern in model_patterns:
            match = re.search(pattern, content)
            if match:
                if "firmware" in pattern:
                    self.firmware = match.group(1)
                else:
                    self.model = match.group(1).upper()
                break

        # Hikvision-specific
        if "hikvision" in content:
            hik_match = re.search(r"ver\s*[:\s]*([0-9.]+)", content)
            if hik_match:
                self.firmware = hik_match.group(1)

        # Dahua-specific
        if "dahua" in content:
            dahua_match = re.search(r"build\s*[:\s]*([0-9]+)", content)
            if dahua_match:
                self.firmware = f"Build {dahua_match.group(1)}"

    def _identify_brand(self) -> Optional[str]:
        """Multi-vector brand detection"""
        content_lower = self.html_content.lower()
        server_lower = self.server.lower()
        title_lower = self.title.lower()

        for brand, sigs in BRAND_SIGS.items():
            # Check HTML
            if any(re.search(pat, content_lower) for pat in sigs["html"]):
                return brand
            # Check headers
            if any(sig.lower() in server_lower for sig in sigs["headers"]):
                return brand
            # Check title
            if any(sig.lower() in title_lower for sig in sigs["html"]):
                return brand
            # Check accessible URLs
            for test_path in sigs["urls"][:2]:  # Test top 2 paths
                try:
                    test_url = urljoin(self.base_url, test_path)
                    r = requests.get(test_url, timeout=2, verify=False)
                    if r.status_code == 200:
                        return brand
                except: pass

        return None

    def _check_vulnerabilities(self):
        """Tag known CVEs based on brand + firmware (if available)"""
        if not self.brand:
            return

        brand_data = BRAND_SIGS[self.brand]
        self.vulns = brand_data["cves"].copy()

        # Add exploit-readiness flag
        if self.brand == "hikvision" and self.firmware != "Unknown":
            # CVE-2021-36260 affects most versions < 5.6.6
            if "5.6.6" not in self.firmware and "5.6.7" not in self.firmware:
                self.is_exploit_ready = True
        elif self.brand == "dahua":
            # Many Dahua devices are vulnerable to auth bypass
            self.is_exploit_ready = True

    def fingerprint(self) -> Dict:
        """
        Run full fingerprinting sequence.
        Returns enriched device intelligence.
        """
        # Fetch root page
        if not self._fetch_page("/"):
            return {"error": "Root page unreachable"}

        # Identify brand
        self.brand = self._identify_brand()

        # Extract model/firmware
        self._extract_model_firmware()

        # Tag vulnerabilities
        self._check_vulnerabilities()

        # Determine if login form exists
        has_login = any(kw in self.html_content.lower() for kw in ["password", "login", "signin", "credential", "pwd"])

        return {
            "brand": self.brand,
            "model": self.model,
            "firmware": self.firmware,
            "title": self.title,
            "server": self.server,
            "has_login_form": has_login,
            "vulnerabilities": self.vulns,
            "is_exploit_ready": self.is_exploit_ready,
            "urls_of_interest": self._get_interesting_urls()
        }

    def _get_interesting_urls(self) -> List[str]:
        """Return high-value URLs based on detected brand"""
        urls = [f"{self.base_url}/"]
        if not self.brand:
            return urls

        brand_data = BRAND_SIGS[self.brand]
        for path in brand_data["urls"]:
            urls.append(urljoin(self.base_url, path))
        return urls[:5]  # Limit to top 5
