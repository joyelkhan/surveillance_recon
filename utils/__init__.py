# surveillance_recon/utils/__init__.py
# [SecOps Research // Utilities Module Interface v2.1]
# Unified API for utility functions.

from .logger import SecureLogger
from .evasion import SandboxDetector
from .helpers import (
    get_random_user_agent,
    create_ssl_context,
    is_valid_ip,
    expand_ip_range,
    get_geo_info,
    resolve_mac_address,
    is_private_ip,
    generate_search_links,
    url_has_auth,
    strip_auth_from_url
)

__all__ = [
    "SecureLogger",
    "SandboxDetector",
    "get_random_user_agent",
    "create_ssl_context",
    "is_valid_ip",
    "expand_ip_range",
    "get_geo_info",
    "resolve_mac_address",
    "is_private_ip",
    "generate_search_links",
    "url_has_auth",
    "strip_auth_from_url"
]

