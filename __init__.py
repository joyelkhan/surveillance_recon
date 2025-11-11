# surveillance_recon/__init__.py
# [SurveillanceRecon // Advanced CCTV/IoT Security Assessment Framework v1.0.0]
# Root module initializer for security research and authorized penetration testing.
# For authorized security assessment use only.

import os
import sys

# 🔒 ENFORCE SANDBOX DETECTION — BEFORE ANY OTHER LOGIC
from .utils.evasion import SandboxDetector
SandboxDetector().abort_if_sandboxed()

# Framework metadata
__title__ = "SurveillanceRecon"
__version__ = "1.0.0"
__author__ = "SecOps Research Team"
__license__ = "Educational/Research Use Only"
__description__ = "Advanced CCTV/IoT security assessment and penetration testing framework"

# Public API — expose only high-level interfaces
from .core import (
    PortScanner,
    CameraFingerprinter,
    Authenticator,
    StreamValidator,
    DataExfiltrator,
    ReconEngine
)

from .utils import (
    SecureLogger,
    SandboxDetector
)

from .config import (
    PortIntelligence,
    CredentialIntelligence,
    DorkIntelligence
)

from .plugins import (
    SecurityPlugin,
    run_plugins
)

# Convenience function for programmatic use
def scan(target_ip: str, **kwargs):
    """
    One-liner reconnaissance API.
    Example:
        report = surveillance_recon.scan("203.0.113.45", brand="hikvision")
    """
    from .main import run_recon
    return run_recon(target_ip, **kwargs)

# CLI entry support
def cli():
    """Launch CLI interactively"""
    from .cli import main as cli_main
    cli_main()

# Ensure clean exit on Ctrl+C
import atexit
def _zeta_cleanup():
    # Silent, no output — opsec first
    pass
atexit.register(_zeta_cleanup)

# Final integrity assertion
assert "Educational" in __license__, "License integrity check failed"
