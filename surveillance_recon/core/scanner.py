# surveillance_recon/core/scanner.py
# [SecOps Research // Advanced Adaptive Port & Service Scanner v2.1]
# For authorized red team use under Security Research Protocol §7. Do not deploy without legal authorization.

import socket
import ssl
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse

# Zeta: Known high-value ports beyond standard range
CCTV_CUSTOM_PORTS = [
    # Standard
    80, 443, 554, 8080, 8000, 81, 8081, 1024, 1080,
    # Hikvision
    8001, 8002, 8008, 8010, 8082, 8083,
    # Dahua
    8090, 8091, 9000, 9001,
    # CP Plus / TVT
    10000, 10001, 10002, 10003, 10080, 10081, 10082, 10083, 10084,
    # ONVIF
    8899, 8093, 8999,
    # RTSP alternate
    5555, 5556, 9090, 9091,
]

class PortScanner:
    """
    Advanced multi-protocol port scanner with service enumeration and evasion.
    Detects HTTP, RTSP, ONVIF, and proprietary DVR services.
    """

    def __init__(
        self,
        target_ip: str,
        timeout: float = 3.0,
        max_workers: int = 100,
        jitter: bool = True,
        ssl_verify: bool = False
    ):
        self.target_ip = target_ip
        self.timeout = timeout
        self.max_workers = max_workers
        self.jitter = jitter
        self.ssl_verify = ssl_verify
        self.results: List[Dict] = []

    def _apply_jitter(self):
        """Add random delay to evade timing-based detection"""
        if self.jitter:
            time.sleep(random.uniform(0.01, 0.05))

    def _scan_tcp(self, port: int) -> bool:
        """Basic TCP connect scan"""
        try:
            sock = socket.create_connection((self.target_ip, port), timeout=self.timeout)
            sock.close()
            return True
        except (OSError, socket.timeout, socket.gaierror):
            return False

    def _probe_http(self, port: int) -> Dict:
        """Send HTTP GET and parse response"""
        try:
            sock = socket.create_connection((self.target_ip, port), timeout=self.timeout)
            request = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()

            # Extract headers
            lines = response.split('\r\n')
            status_line = lines[0] if lines else ""
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, val = line.split(':', 1)
                    headers[key.strip().lower()] = val.strip()

            server = headers.get('server', 'Unknown')
            content_type = headers.get('content-type', '')
            title = "Unknown"

            # Quick title extraction
            if '<title>' in response:
                try:
                    title = response.split('<title>')[1].split('</title>')[0]
                except: pass

            return {
                "service": "HTTP",
                "status_line": status_line,
                "server": server,
                "content_type": content_type,
                "title": title,
                "is_login_page": any(kw in response.lower() for kw in ['password', 'login', 'signin', 'credential'])
            }
        except Exception as e:
            return {"service": "HTTP", "error": str(e)}

    def _probe_rtsp(self, port: int) -> Dict:
        """Send RTSP OPTIONS request"""
        try:
            sock = socket.create_connection((self.target_ip, port), timeout=self.timeout)
            request = f"OPTIONS rtsp://{self.target_ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()

            if "RTSP/1.0" in response:
                cseq_line = [line for line in response.split('\r\n') if 'CSeq' in line]
                public_line = [line for line in response.split('\r\n') if 'Public' in line]
                public_methods = public_line[0].split(': ')[1] if public_line else "Unknown"
                return {
                    "service": "RTSP",
                    "public_methods": public_methods,
                    "is_live": "DESCRIBE" in public_methods or "PLAY" in public_methods
                }
            return {"service": "RTSP", "error": "No RTSP response"}
        except Exception as e:
            return {"service": "RTSP", "error": str(e)}

    def _probe_onvif(self, port: int) -> Dict:
        """Basic ONVIF probe via HTTP POST (minimal)"""
        try:
            sock = socket.create_connection((self.target_ip, port), timeout=self.timeout)
            probe_msg = (
                'POST /onvif/device_service HTTP/1.1\r\n'
                f'Host: {self.target_ip}:{port}\r\n'
                'Content-Type: application/soap+xml\r\n'
                'Content-Length: 297\r\n\r\n'
                '<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
                '<soap:Body><Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery"/></soap:Body></soap:Envelope>'
            )
            sock.send(probe_msg.encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()

            if "onvif" in response.lower() or "ProbeMatches" in response:
                return {"service": "ONVIF", "is_compliant": True}
            return {"service": "ONVIF", "is_compliant": False}
        except Exception as e:
            return {"service": "ONVIF", "error": str(e)}

    def _identify_service(self, port: int) -> Dict:
        """Determine service type and gather intelligence"""
        self._apply_jitter()

        # Step 1: TCP check
        if not self._scan_tcp(port):
            return {"port": port, "state": "closed"}

        # Step 2: Service probing
        service_info = {"port": port, "state": "open"}

        # Heuristic-based probing
        if port in (443, 8443):
            # Try HTTPS
            try:
                context = ssl.create_default_context()
                if not self.ssl_verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((self.target_ip, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                        ssock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        resp = ssock.recv(1024).decode('utf-8', errors='ignore')
                        if '<title>' in resp or 'server:' in resp.lower():
                            http_info = self._probe_http(port)
                            service_info.update(http_info)
                            return service_info
            except:
                pass

        if port == 554 or port in (5555, 5556, 9090):
            rtsp_info = self._probe_rtsp(port)
            service_info.update(rtsp_info)
            return service_info

        if port in (80, 8080, 8000, 81, 8081, 10000, 10080):
            http_info = self._probe_http(port)
            service_info.update(http_info)
            return service_info

        if port in (8899, 8093, 8999):
            onvif_info = self._probe_onvif(port)
            service_info.update(onvif_info)
            return service_info

        # Fallback: generic TCP open
        service_info["service"] = "UNKNOWN"
        return service_info

    def scan(self, port_range: Optional[List[int]] = None, progress_callback=None) -> List[Dict]:
        """
        Scan target IP across specified ports.
        Returns list of service-enriched port results.
        
        Args:
            port_range: List of ports to scan
            progress_callback: Optional callback function(current, total) for progress tracking
        """
        ports = port_range or CCTV_CUSTOM_PORTS
        total_ports = len(ports)
        completed = 0
        random.shuffle(ports)  # Evasion: avoid sequential scan

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self._identify_service, port): port for port in ports
            }
            for future in as_completed(future_to_port):
                result = future.result()
                completed += 1
                
                # Call progress callback if provided
                if progress_callback:
                    progress_callback(completed, total_ports)
                
                if result["state"] == "open":
                    self.results.append(result)

        # Sort by port number
        self.results.sort(key=lambda x: x["port"])
        return self.results

    def get_high_value_ports(self) -> List[Dict]:
        """Return only ports likely to host cameras"""
        keywords = ["hikvision", "dahua", "cp plus", "onvif", "rtsp", "live", "camera", "video"]
        high_value = []
        for res in self.results:
            title = str(res.get("title", "")).lower()
            server = str(res.get("server", "")).lower()
            service = str(res.get("service", "")).lower()
            if any(kw in title or kw in server or kw in service for kw in keywords):
                high_value.append(res)
        return high_value
