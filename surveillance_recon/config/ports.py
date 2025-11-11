# surveillance_recon/config/ports.py
# [SecOps Research // Intelligent Port Intelligence Engine v2.1]
# Dynamic port database with vendor, protocol, and risk metadata.
# For authorized red team use under Security Research Protocol §7.

from typing import List, Dict, Tuple

# Core port database: (port, protocol, service, vendor, risk_score)
# Risk: 1 = informational, 2 = service, 3 = auth, 4 = exploit-ready
PORT_DATABASE = [
    # Standard Web & Auth
    (80, "HTTP", "Web Interface", "generic", 3),
    (443, "HTTPS", "Secure Web Interface", "generic", 3),
    (8080, "HTTP", "Alternate Web", "generic", 3),
    (8000, "HTTP", "Web Admin", "generic", 3),
    (81, "HTTP", "Web Alt", "generic", 2),
    (8081, "HTTP", "Web Alt 2", "generic", 2),

    # RTSP & Streaming
    (554, "RTSP", "Real-Time Streaming Protocol", "generic", 4),
    (5555, "RTSP", "RTSP Alt", "generic", 4),
    (5556, "RTSP", "RTSP Alt 2", "generic", 4),
    (9090, "RTSP", "RTSP Custom", "generic", 4),
    (9091, "RTSP", "RTSP Custom 2", "generic", 4),

    # Hikvision
    (8001, "HTTP", "Hikvision Web", "hikvision", 3),
    (8002, "HTTP", "Hikvision Mobile", "hikvision", 3),
    (8008, "HTTP", "Hikvision Config", "hikvision", 4),
    (8010, "HTTP", "Hikvision SDK", "hikvision", 4),  # CVE-2021-36260
    (8082, "HTTP", "Hikvision P2P", "hikvision", 2),
    (8083, "HTTP", "Hikvision ONVIF", "hikvision", 3),

    # Dahua
    (8090, "HTTP", "Dahua Web", "dahua", 3),
    (8091, "HTTP", "Dahua Mobile", "dahua", 3),
    (9000, "HTTP", "Dahua Debug", "dahua", 4),  # Often exposes RPC2
    (9001, "HTTP", "Dahua P2P", "dahua", 2),

    # CP Plus / TVT
    (10000, "HTTP", "CP Plus Web", "cp_plus", 3),
    (10001, "HTTP", "CP Plus Mobile", "cp_plus", 3),
    (10002, "HTTP", "CP Plus Config", "cp_plus", 4),
    (10003, "HTTP", "CP Plus Stream", "cp_plus", 4),
    (10080, "HTTP", "CP Plus Alt", "cp_plus", 3),
    (10081, "HTTP", "CP Plus DVR", "cp_plus", 4),
    (10082, "HTTP", "CP Plus NVR", "cp_plus", 4),
    (10083, "HTTP", "CP Plus IC2", "cp_plus", 4),  # CP-UVR-0401E1-IC2
    (10084, "HTTP", "CP Plus Admin", "cp_plus", 4),

    # ONVIF
    (8899, "HTTP", "ONVIF Device Service", "generic_onvif", 3),
    (8093, "HTTP", "ONVIF Media", "generic_onvif", 3),
    (8999, "HTTP", "ONVIF Event", "generic_onvif", 2),

    # Axis
    (10084, "HTTP", "Axis Web", "axis", 3),
    (10085, "HTTP", "Axis VAPIX", "axis", 4),

    # Sony
    (10005, "HTTP", "Sony SNC Web", "sony", 3),

    # Bosch
    (10006, "HTTP", "Bosch Web", "bosch", 3),

    # Panasonic
    (10007, "HTTP", "Panasonic Web", "panasonic", 3),

    # Vivotek
    (10008, "HTTP", "Vivotek Web", "vivotek", 3),

    # High-risk custom ranges (common in DVRs)
    *[(p, "HTTP", "Custom DVR Port", "generic", 3) for p in range(10000, 10100)],
]

class PortIntelligence:
    """Intelligent port manager with filtering and risk-aware selection."""

    @staticmethod
    def get_all_ports() -> List[int]:
        """Return flat list of all unique ports."""
        return sorted(set(port for port, *_ in PORT_DATABASE))

    @staticmethod
    def get_ports_by_vendor(vendor: str) -> List[int]:
        """Get ports associated with a specific vendor."""
        vendor = vendor.lower()
        return sorted(set(
            port for port, _, _, v, _ in PORT_DATABASE
            if v.lower() == vendor
        ))

    @staticmethod
    def get_high_risk_ports(min_risk: int = 3) -> List[int]:
        """Get ports with risk score >= min_risk (3=auth, 4=exploit)."""
        return sorted(set(
            port for port, _, _, _, risk in PORT_DATABASE
            if risk >= min_risk
        ))

    @staticmethod
    def get_ports_by_protocol(protocol: str) -> List[int]:
        """Get ports by protocol (HTTP, RTSP, etc.)."""
        protocol = protocol.upper()
        return sorted(set(
            port for port, proto, _, _, _ in PORT_DATABASE
            if proto == protocol
        ))

    @staticmethod
    def get_port_metadata(port: int) -> Dict[str, any]:
        """Get full metadata for a port."""
        for p, proto, svc, vendor, risk in PORT_DATABASE:
            if p == port:
                return {
                    "port": port,
                    "protocol": proto,
                    "service": svc,
                    "vendor": vendor,
                    "risk_score": risk
                }
        return {
            "port": port,
            "protocol": "UNKNOWN",
            "service": "Unknown Service",
            "vendor": "generic",
            "risk_score": 1
        }

    @staticmethod
    def get_adaptive_scan_list(target_brand: str = None, fast_mode: bool = False) -> List[int]:
        """
        Return context-aware port list:
        - If brand known: prioritize vendor + high-risk
        - If fast_mode: only high-risk (score >=3)
        - Else: full list
        """
        if fast_mode:
            return PortIntelligence.get_high_risk_ports(3)

        if target_brand:
            vendor_ports = PortIntelligence.get_ports_by_vendor(target_brand)
            high_risk = PortIntelligence.get_high_risk_ports(3)
            # Merge and dedupe
            combined = list(set(vendor_ports + high_risk))
            return sorted(combined)

        return PortIntelligence.get_all_ports()
