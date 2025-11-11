# surveillance_recon/config/creds.py
# [SecOps Research // Intelligent Credential Intelligence Engine v2.1]
# Dynamic, vendor-aware default credential database with mutation and risk scoring.
# For authorized red team use under Security Research Protocol §7.

from typing import List, Tuple, Dict, Any

# Core credential database: (username, password, vendor, risk_score, notes)
# Risk: 1 = generic, 2 = common default, 3 = debug/backdoor, 4 = hardcoded exploit
CREDENTIAL_DATABASE = [
    # Generic defaults
    ("admin", "admin", "generic", 2, "Universal default"),
    ("admin", "", "generic", 2, "Empty password"),
    ("root", "root", "generic", 2, "Linux-style default"),
    ("user", "user", "generic", 1, "Low-privilege default"),
    ("admin", "12345", "generic", 2, "Numeric default"),

    # Hikvision
    ("admin", "", "hikvision", 3, "Empty password — most models <5.6"),
    ("admin", "12345", "hikvision", 2, "Legacy numeric"),
    ("666666", "666666", "hikvision", 1, "Backup account"),
    ("888888", "888888", "hikvision", 1, "Viewer account"),

    # Dahua
    ("admin", "admin", "dahua", 2, "Old firmware default"),
    ("admin", "123456", "dahua", 2, "Common default"),
    ("888888", "888888", "dahua", 1, "Master user"),
    ("666666", "666666", "dahua", 1, "Default user"),
    ("admin", "777777", "dahua", 3, "Debug password — enables RPC2 shell"),
    ("root", "vizxv", "dahua", 4, "Hardcoded backdoor — older firmware"),

    # CP Plus
    ("admin", "admin", "cp_plus", 2, "CP-UVR default"),
    ("admin", "12345", "cp_plus", 2, "Numeric fallback"),
    ("user", "12345", "cp_plus", 1, "User account"),

    # Axis
    ("root", "pass", "axis", 2, "Default for older models"),
    ("root", "root", "axis", 2, "Fallback"),
    ("admin", "admin", "axis", 1, "Web admin"),

    # Sony
    ("admin", "admin", "sony", 2, "SNC series default"),

    # Bosch
    ("service", "service", "bosch", 3, "Service account — high privilege"),
    ("admin", "admin", "bosch", 2, "Admin default"),

    # Panasonic
    ("admin", "12345", "panasonic", 2, "BB-H series default"),

    # Vivotek
    ("root", "", "vivotek", 2, "Empty root password"),
    ("admin", "admin", "vivotek", 2, "Admin default"),

    # ONVIF Generic
    ("admin", "admin", "generic_onvif", 2, "ONVIF profile S default"),
    ("root", "root", "generic_onvif", 1, "Fallback"),
]

class CredentialIntelligence:
    """Intelligent credential manager with filtering, mutation, and risk-aware selection."""

    @staticmethod
    def get_all_credentials() -> List[Tuple[str, str]]:
        """Return flat list of (user, pass) pairs."""
        return [(user, pwd) for user, pwd, _, _, _ in CREDENTIAL_DATABASE]

    @staticmethod
    def get_credentials_by_vendor(vendor: str) -> List[Tuple[str, str, int, str]]:
        """
        Return credentials for a vendor: (user, pass, risk_score, notes)
        Sorted by risk_score (highest first).
        """
        vendor = vendor.lower()
        creds = [
            (user, pwd, risk, notes)
            for user, pwd, v, risk, notes in CREDENTIAL_DATABASE
            if v.lower() == vendor
        ]
        # Sort by risk (exploit-ready first)
        return sorted(creds, key=lambda x: x[2], reverse=True)

    @staticmethod
    def get_high_risk_credentials(min_risk: int = 3) -> List[Tuple[str, str, str]]:
        """Get credentials with risk score >= min_risk (3=debug, 4=hardcoded)."""
        return [
            (user, pwd, vendor)
            for user, pwd, vendor, risk, _ in CREDENTIAL_DATABASE
            if risk >= min_risk
        ]

    @staticmethod
    def mutate_credentials(base_creds: List[Tuple[str, str]], target_ip: str = None) -> List[Tuple[str, str]]:
        """
        Generate mutated credentials based on context:
        - IP-based: admin:<last_octet>, user:<last_octet>
        - Common variants: password123, admin123, etc.
        """
        mutated = set(base_creds)

        if target_ip:
            try:
                last_octet = target_ip.split('.')[-1]
                mutated.update([
                    ("admin", last_octet),
                    ("user", last_octet),
                    ("root", last_octet),
                    ("admin", f"admin{last_octet}"),
                    ("admin", f"password{last_octet}")
                ])
            except: pass

        # Common mutations
        common_suffixes = ["123", "1234", "12345", "2023", "2024", "!", "@"]
        for user, pwd in base_creds:
            if pwd in ["admin", "root", "user", ""]:
                for suf in common_suffixes:
                    mutated.add((user, pwd + suf if pwd else suf))

        return list(mutated)

    @staticmethod
    def get_adaptive_cred_list(target_brand: str = None, target_ip: str = None, include_mutations: bool = True) -> List[Tuple[str, str]]:
        """
        Return context-aware credential list:
        - If brand known: prioritize vendor creds
        - If IP known: add mutations
        - Always include high-risk + generic fallbacks
        """
        creds_set = set()

        # Vendor-specific (high risk first)
        if target_brand:
            vendor_creds = CredentialIntelligence.get_credentials_by_vendor(target_brand)
            creds_set.update((user, pwd) for user, pwd, _, _ in vendor_creds)

        # High-risk generic
        high_risk = CredentialIntelligence.get_high_risk_credentials(3)
        creds_set.update((user, pwd) for user, pwd, _ in high_risk)

        # Fallback to generic
        creds_set.update(CredentialIntelligence.get_all_credentials())

        cred_list = list(creds_set)

        # Apply mutations
        if include_mutations and target_ip:
            cred_list = CredentialIntelligence.mutate_credentials(cred_list, target_ip)

        # Dedupe and return
        seen = set()
        unique = []
        for user, pwd in cred_list:
            key = (user.lower(), pwd)
            if key not in seen:
                seen.add(key)
                unique.append((user, pwd))

        return unique
