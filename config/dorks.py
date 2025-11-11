# surveillance_recon/config/dorks.py
# [SecOps Research // Dynamic Dork Intelligence Engine v2.2]
# Context-aware search query generator for Shodan, Censys, ZoomEye, and Google Dorking.
# For authorized red team use under Security Research Protocol §7.

from typing import Dict, List
from urllib.parse import quote

class DorkIntelligence:
    """Generates vendor-, port-, and vuln-aware search queries."""

    @staticmethod
    def _build_google_dorks(ip: str = None, port: int = None, brand: str = None) -> List[str]:
        base_dorks = []

        # Universal camera dorks
        generic_dorks = [
            'intitle:"web client" "live view"',
            'inurl:/view.shtml intitle:"camera"',
            'intitle:"IP Webcam" "video"',
            'intitle:"Live View / - AXIS"',
            'inurl:"/doc/page/login.asp" "Hikvision"',
            'inurl:"/cgi-bin/login.cgi" "Dahua"',
            'intitle:"Login" "CP Plus"',
            'inurl:"/login.html" "CP-UVR"',
            'intitle:"NetCamSC" "Panasonic"',
            'inurl:"/operator/login.html" "Bosch"',
            'intitle:"Vivotek" "Live Video"',
            'inurl:"/onvif/device_service" "ONVIF"'
        ]

        # Add IP-specific
        if ip:
            base_dorks.append(f'"{ip}" ("camera" OR "DVR" OR "NVR" OR "live view")')
            base_dorks.append(f'site:*.{ip.split(".")[-1]} inurl:video')
            base_dorks.append(f'"{ip}" intitle:("login" | "camera" | "DVR")')

        # Add port-specific
        if port:
            base_dorks.append(f'"{ip}:{port}"')
            if port == 554:
                base_dorks.append(f'site:*/rtsp://{ip} inurl:stream')
            elif port in (80, 8080, 8000):
                base_dorks.append(f'site:http://{ip}:{port} inurl:login')

        # Add brand-specific
        if brand:
            brand = brand.lower()
            if "hikvision" in brand:
                base_dorks.extend([
                    f'site:http://{ip} inurl:"/doc/page/"',
                    'intitle:"Hikvision" "Web Login"',
                    'inurl:"/PSIA/Custom/SelfExt/userCheck" "Hikvision"'
                ])
            elif "dahua" in brand:
                base_dorks.extend([
                    f'site:http://{ip} inurl:"/cgi-bin/login.cgi"',
                    'intitle:"Dahua" "Smart PSS"',
                    'inurl:"/RPC2" "Dahua"'
                ])
            elif "cp plus" in brand or "cp-uvr" in brand:
                base_dorks.extend([
                    f'site:http://{ip} inurl:"login.html" intitle:"CP Plus"',
                    'intitle:"CP-UVR" "Login"',
                    'inurl:"/IC2" "CP Plus"'
                ])
            elif "axis" in brand:
                base_dorks.extend([
                    'intitle:"AXIS" "Live View"',
                    'inurl:"/view/view.shtml" "axis"'
                ])
            elif "onvif" in brand:
                base_dorks.append('intitle:"ONVIF" "Device Service"')

        # Append generic if no context
        if not ip and not brand:
            base_dorks = generic_dorks

        return list(dict.fromkeys(base_dorks))  # Dedupe

    @staticmethod
    def _build_shodan_query(ip: str = None, port: int = None, brand: str = None) -> str:
        parts = []
        if ip:
            parts.append(f'ip:{ip}')
        if port:
            parts.append(f'port:{port}')
        if brand:
            brand_map = {
                "hikvision": "hikvision",
                "dahua": "dahua",
                "cp plus": "cp plus",
                "axis": "axis",
                "sony": "sony",
                "bosch": "bosch",
                "panasonic": "panasonic",
                "vivotek": "vivotek"
            }
            b = brand_map.get(brand.lower(), brand.lower())
            parts.append(f'product:"{b}"')
        else:
            parts.append('("webcam" OR "camera" OR "DVR" OR "NVR")')

        return ' '.join(parts) if parts else 'product:"camera"'

    @staticmethod
    def _build_censys_query(ip: str = None, port: int = None, brand: str = None) -> str:
        parts = []
        if ip:
            parts.append(f'ip: {ip}')
        if port:
            parts.append(f'services.port: {port}')
        if brand:
            parts.append(f'services.software.product: "{brand}"')
        else:
            parts.append('(services.http.title: "camera" OR services.http.title: "login")')

        return ' AND '.join(parts) if parts else 'services.http.title: "camera"'

    @staticmethod
    def _build_zoomeye_query(ip: str = None, port: int = None, brand: str = None) -> str:
        parts = []
        if ip:
            parts.append(f'ip:{ip}')
        if port:
            parts.append(f'port:{port}')
        if brand:
            parts.append(f'device:"{brand}"')
        else:
            parts.append('(title:"camera" OR title:"DVR" OR component:"ONVIF")')

        return ' + '.join(parts) if parts else 'title:"camera"'

    @staticmethod
    def generate_search_links(ip: str, port: int = None, brand: str = None) -> Dict[str, str]:
        """
        Generate ready-to-use search URLs for public engines.
        Returns dict of {engine: url}.
        """
        dorks = DorkIntelligence._build_google_dorks(ip, port, brand)
        shodan_q = DorkIntelligence._build_shodan_query(ip, port, brand)
        censys_q = DorkIntelligence._build_censys_query(ip, port, brand)
        zoomeye_q = DorkIntelligence._build_zoomeye_query(ip, port, brand)

        return {
            "Shodan": f"https://www.shodan.io/search?query={quote(shodan_q)}",
            "Censys": f"https://search.censys.io/search?resource=hosts&q={quote(censys_q)}",
            "ZoomEye": f"https://www.zoomeye.org/searchResult?q={quote(zoomeye_q)}",
            "Google Dork 1": f"https://www.google.com/search?q={quote(dorks[0])}" if dorks else "",
            "Google Dork 2": f"https://www.google.com/search?q={quote(dorks[1])}" if len(dorks) > 1 else "",
            "Google Dork 3": f"https://www.google.com/search?q={quote(dorks[2])}" if len(dorks) > 2 else "",
            "Google Dork (IP+Brand)": f"https://www.google.com/search?q={quote(dorks[-1])}" if dorks else "",
            "ONVIF Probe": f"http://{ip}:8899/onvif/device_service" if ip else ""
        }

    @staticmethod
    def get_raw_dorks(ip: str = None, port: int = None, brand: str = None) -> Dict[str, List[str]]:
        """Return raw dork strings for programmatic use."""
        google = DorkIntelligence._build_google_dorks(ip, port, brand)
        return {
            "google": google,
            "shodan": [DorkIntelligence._build_shodan_query(ip, port, brand)],
            "censys": [DorkIntelligence._build_censys_query(ip, port, brand)],
            "zoomeye": [DorkIntelligence._build_zoomeye_query(ip, port, brand)]
        }
