# surveillance_recon/main.py
# [SecOps Research // Sovereign Recon Main Execution Hub v2.3]
# Entry point that binds evasion, logging, CLI, and plugin execution into one opsec-perfect flow.
# For authorized red team use under Security Research Protocol §7.

import sys
import os

# Enforce Zeta evasion BEFORE any other logic
from surveillance_recon.utils.evasion import SandboxDetector
SandboxDetector().abort_if_sandboxed()

# Initialize global logger early (before imports that may log)
from surveillance_recon.utils.logger import SecureLogger
# Placeholder logger; replaced per-target in CLI
GLOBAL_LOGGER = None

def main():
    """
    Main entry point. Delegates to CLI for user interaction.
    Ensures all Zeta modules are imported in correct order.
    """
    try:
        from surveillance_recon.cli import main as cli_main
        cli_main()
    except KeyboardInterrupt:
        if GLOBAL_LOGGER:
            GLOBAL_LOGGER.warn("Operation interrupted by user")
        else:
            print("\n[!] Aborted.")
        sys.exit(0)
    except Exception as e:
        if GLOBAL_LOGGER:
            GLOBAL_LOGGER.error(f"Fatal error: {e}")
        else:
            print(f"[-] Fatal error: {e}")
        sys.exit(1)

# Optional: Allow direct import for programmatic use
def run_recon(
    target_ip: str,
    ports: list = None,
    brand: str = None,
    c2_onion: str = None,
    c2_https: str = None,
    auto_wipe_logs: bool = True,
    console_output: bool = True
):
    """
    Programmatic API for integration into larger Zeta operations.
    """
    global GLOBAL_LOGGER
    GLOBAL_LOGGER = SecureLogger(
        target_ip=target_ip,
        log_dir="zeta_logs",
        encrypt=True,
        auto_wipe=auto_wipe_logs,
        console_output=console_output
    )

    from surveillance_recon.config.ports import PortIntelligence
    from surveillance_recon.core import ReconEngine

    if not ports:
        ports = PortIntelligence.get_adaptive_scan_list(target_brand=brand)

    engine = ReconEngine(
        target_ip=target_ip,
        port_range=ports,
        c2_onion=c2_onion,
        c2_https=c2_https,
        use_tor=(c2_onion is not None),
        auto_wipe_logs=auto_wipe_logs,
        console_output=console_output
    )

    return engine.run_full_recon()

if __name__ == "__main__":
    main()
