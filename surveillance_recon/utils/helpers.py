# surveillance_recon/utils/helpers.py
# [SecOps Research // Core Utility Library v2.1]
# For authorized red team operations under Security Research Protocol §7.

import os
import re
import ssl
import socket
import random
import subprocess
import ipaddress
import requests
from typing import List, Union, Optional, Tuple, Dict
from urllib.parse import quote

# Rotating user agents (mimic real browsers)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
]

def get_random_user_agent() -> str:
    """Return a realistic, rotating User-Agent"""
    return random.choice(USER_AGENTS)

def create_ssl_context() -> ssl.SSLContext:
    """Create a hardened but permissive SSL context"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers('DEFAULT@SECLEVEL=1')  # Bypass weak cipher rejection
    return ctx

def is_valid_ip(ip: str) -> bool:
    """Validate IPv4/IPv6 address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def expand_ip_range(target: str) -> List[str]:
    """
    Expand target input into list of IPs:
    - Single IP: "192.168.1.10"
    - CIDR: "192.168.1.0/24"
    - Range: "192.168.1.10-20"
    """
    if '-' in target and re.match(r'\d+\.\d+\.\d+\.\d+-\d+', target):
        base, end = target.rsplit('.', 1)
        start_ip = int(base.split('.')[-1])
        end_ip = int(end)
        base_prefix = '.'.join(base.split('.')[:-1])
        return [f"{base_prefix}.{i}" for i in range(start_ip, end_ip + 1)]
    elif '/' in target:
        try:
            return [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
        except:
            return []
    elif is_valid_ip(target):
        return [target]
    else:
        return []

def get_geo_info(ip: str) -> dict:
    """
    Fetch geolocation with opsec-aware fallbacks.
    Uses free, no-API services to avoid attribution.
    """
    try:
        # Primary: ip-api.com (no key, 45 req/min)
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "google_maps": f"https://www.google.com/maps?q={data.get('lat')},{data.get('lon')}" if data.get('lat') else None,
                    "google_earth": f"earth://goto?lookat.lat={data.get('lat')}&lookat.lon={data.get('lon')}&lookat.range=1000" if data.get('lat') else None
                }
    except: pass

    # Fallback: ipinfo.io (no key, limited)
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            data = r.json()
            loc = data.get("loc", "").split(',')
            lat = float(loc[0]) if len(loc) > 0 and loc[0].replace('.','').isdigit() else None
            lon = float(loc[1]) if len(loc) > 1 and loc[1].replace('.','').isdigit() else None
            return {
                "country": data.get("country", "Unknown"),
                "region": data.get("region", "Unknown"),
                "city": data.get("city", "Unknown"),
                "lat": lat,
                "lon": lon,
                "isp": data.get("org", "Unknown"),
                "org": data.get("org", "Unknown"),
                "google_maps": f"https://www.google.com/maps?q={lat},{lon}" if lat else None,
                "google_earth": f"earth://goto?lookat.lat={lat}&lookat.lon={lon}&lookat.range=1000" if lat else None
            }
    except: pass

    return {"error": "Geolocation failed"}

def resolve_mac_address(ip: str) -> Optional[str]:
    """
    Resolve MAC address via ARP (local network only).
    Returns None if not on same subnet or OS blocks access.
    """
    if not is_private_ip(ip):
        return None

    try:
        if os.name == "nt":
            cmd = ["arp", "-a", ip]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
            return match.group(0).upper() if match else None
        else:
            # Linux/macOS
            with open("/proc/net/arp", "r") as f:
                for line in f:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                            return parts[3].upper()
    except: pass
    return None

def is_private_ip(ip: str) -> bool:
    """Check if IP is in private ranges (RFC 1918 + loopback)"""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except:
        return False

def generate_search_links(ip: str, port: Optional[int] = None) -> Dict[str, str]:
    """
    Generate manual search URLs for Shodan, Censys, ZoomEye, Google Dorking.
    Matches CamXploit’s feature set but with enhanced dorks.
    """
    ip_encoded = quote(ip)
    dork_queries = [
        f'"{ip}" "camera" intitle:"login"',
        f'site:*.{ip.split(".")[-1]} inurl:video inurl:cam',
        f'"{ip}" ("Hikvision" OR "Dahua" OR "CP Plus")'
    ]

    return {
        "Shodan": f"https://www.shodan.io/host/{ip}",
        "Censys": f"https://search.censys.io/hosts/{ip}",
        "ZoomEye": f"https://www.zoomeye.org/searchResult?q=ip%3A%22{ip}%22",
        "Google Dork 1": f"https://www.google.com/search?q={quote(dork_queries[0])}",
        "Google Dork 2": f"https://www.google.com/search?q={quote(dork_queries[1])}",
        "Google Dork 3": f"https://www.google.com/search?q={quote(dork_queries[2])}",
        "ONVIF Probe": f"http://{ip}:8899/onvif/device_service" if not port else f"http://{ip}:{port}/onvif/device_service"
    }

def url_has_auth(url: str) -> bool:
    """Check if URL contains embedded credentials (e.g., rtsp://user:pass@...)"""
    return re.match(r'^\w+://[^:]+:[^@]+@', url) is not None

def strip_auth_from_url(url: str) -> str:
    """Remove credentials from URL for safe logging/display"""
    if url_has_auth(url):
        proto, rest = url.split("://", 1)
        if "@" in rest:
            host_part = rest.split("@", 1)[1]
            return f"{proto}://{host_part}"
    return url
