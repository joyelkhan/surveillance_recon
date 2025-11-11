#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
surveillance_recon/banner.py
ASCII art banner and styled output for CLI
"""

import sys
from datetime import datetime

# ANSI color codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'

# Enable colors on Windows
def enable_windows_colors():
    if sys.platform == 'win32':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass

enable_windows_colors()

BANNER = f"""
{Colors.BRIGHT_RED}
   _____ __  ______     ________    __    __    _   ____________ 
  / ___// / / / __ \\   / ____/ /   / /   /  |  / | / / ____/ __/
  \\__ \\/ / / / /_/ /  / /   / /   / /   / /| | /  |/ / /   / __/ 
 ___/ / /_/ / _, _/  / /___/ /___/ /___/ ___ |/ /|  / /___/ /___ 
/____/\\____/_/ |_|   \\____/_____/_____/_/  |_/_/ |_/\\____/_____/
{Colors.BRIGHT_CYAN}
    ╔═══════════════════════════════════════════════════════════╗
    ║  {Colors.BRIGHT_WHITE}SurveillanceRecon{Colors.BRIGHT_CYAN} - CCTV/IoT Security Framework  ║
    ║  {Colors.BRIGHT_YELLOW}Advanced Reconnaissance & Exploitation Suite{Colors.BRIGHT_CYAN}      ║
    ╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.CYAN}[{Colors.BRIGHT_WHITE}*{Colors.CYAN}] {Colors.WHITE}Version    : {Colors.BRIGHT_GREEN}1.0.0{Colors.RESET}
{Colors.CYAN}[{Colors.BRIGHT_WHITE}*{Colors.CYAN}] {Colors.WHITE}Author     : {Colors.BRIGHT_GREEN}SecOps Research Team{Colors.RESET}
{Colors.CYAN}[{Colors.BRIGHT_WHITE}*{Colors.CYAN}] {Colors.WHITE}GitHub     : {Colors.BRIGHT_BLUE}https://github.com/joyelkhan/surveillance_recon{Colors.RESET}
{Colors.CYAN}[{Colors.BRIGHT_WHITE}*{Colors.CYAN}] {Colors.WHITE}License    : {Colors.BRIGHT_YELLOW}Educational/Research Use Only{Colors.RESET}

{Colors.BRIGHT_RED}[{Colors.BRIGHT_YELLOW}!{Colors.BRIGHT_RED}] {Colors.BRIGHT_YELLOW}For authorized security testing only!{Colors.RESET}
{Colors.DIM}{'─' * 70}{Colors.RESET}
"""

def print_banner():
    """Print the ASCII art banner"""
    print(BANNER)

def print_section(title: str):
    """Print a section header"""
    print(f"\n{Colors.BRIGHT_CYAN}[{Colors.BRIGHT_WHITE}●{Colors.BRIGHT_CYAN}] {Colors.BOLD}{title}{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 70}{Colors.RESET}")

def print_info(message: str):
    """Print info message"""
    print(f"{Colors.CYAN}[{Colors.BRIGHT_WHITE}ℹ{Colors.CYAN}] {Colors.WHITE}{message}{Colors.RESET}")

def print_success(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}[{Colors.BRIGHT_GREEN}✓{Colors.GREEN}] {Colors.BRIGHT_GREEN}{message}{Colors.RESET}")

def print_warning(message: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}[{Colors.BRIGHT_YELLOW}⚠{Colors.YELLOW}] {Colors.BRIGHT_YELLOW}{message}{Colors.RESET}")

def print_error(message: str):
    """Print error message"""
    print(f"{Colors.RED}[{Colors.BRIGHT_RED}✗{Colors.RED}] {Colors.BRIGHT_RED}{message}{Colors.RESET}")

def print_scanning(message: str):
    """Print scanning message"""
    print(f"{Colors.BLUE}[{Colors.BRIGHT_BLUE}→{Colors.BLUE}] {Colors.BRIGHT_BLUE}{message}{Colors.RESET}")

def print_finding(message: str):
    """Print finding message"""
    print(f"{Colors.MAGENTA}[{Colors.BRIGHT_MAGENTA}★{Colors.MAGENTA}] {Colors.BRIGHT_MAGENTA}{message}{Colors.RESET}")

def print_data(key: str, value: str):
    """Print key-value data"""
    print(f"{Colors.CYAN}  ├─ {Colors.WHITE}{key}: {Colors.BRIGHT_GREEN}{value}{Colors.RESET}")

def print_progress(current: int, total: int, prefix: str = "Progress"):
    """Print progress bar"""
    bar_length = 40
    filled = int(bar_length * current / total)
    bar = '█' * filled + '░' * (bar_length - filled)
    percent = int(100 * current / total)
    
    print(f"\r{Colors.CYAN}[{Colors.BRIGHT_WHITE}→{Colors.CYAN}] {Colors.WHITE}{prefix}: "
          f"{Colors.BRIGHT_CYAN}{bar}{Colors.RESET} {Colors.BRIGHT_GREEN}{percent}%{Colors.RESET}", end='', flush=True)
    
    if current == total:
        print()  # New line when complete

def print_table_header(columns: list):
    """Print table header"""
    header = " | ".join([f"{col:^15}" for col in columns])
    print(f"\n{Colors.BRIGHT_CYAN}{header}{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * (len(header) + 10)}{Colors.RESET}")

def print_table_row(values: list, color=Colors.WHITE):
    """Print table row"""
    row = " | ".join([f"{str(val):^15}" for val in values])
    print(f"{color}{row}{Colors.RESET}")

def print_box(title: str, content: list, color=Colors.CYAN):
    """Print content in a box"""
    max_len = max([len(line) for line in content] + [len(title)]) + 4
    
    print(f"\n{color}╔{'═' * max_len}╗{Colors.RESET}")
    print(f"{color}║ {Colors.BRIGHT_WHITE}{title:^{max_len-2}}{color} ║{Colors.RESET}")
    print(f"{color}╠{'═' * max_len}╣{Colors.RESET}")
    
    for line in content:
        print(f"{color}║ {Colors.WHITE}{line:<{max_len-2}}{color} ║{Colors.RESET}")
    
    print(f"{color}╚{'═' * max_len}╝{Colors.RESET}")

def print_summary(stats: dict):
    """Print scan summary"""
    print_section("SCAN SUMMARY")
    
    content = [
        f"Target IP       : {stats.get('target', 'N/A')}",
        f"Scan Duration   : {stats.get('duration', 'N/A')}s",
        f"Open Ports      : {stats.get('open_ports', 0)}",
        f"Cameras Found   : {stats.get('cameras', 0)}",
        f"Credentials     : {stats.get('credentials', 0)}",
        f"Live Streams    : {stats.get('streams', 0)}",
        f"Vulnerabilities : {stats.get('vulns', 0)}",
    ]
    
    print_box("Results", content, Colors.BRIGHT_GREEN)

def print_deployment_analysis(report: dict):
    """Print comprehensive CamXploit-style deployment analysis"""
    target = report.get("target_ip", "N/A")
    
    print(f"\n{Colors.BRIGHT_CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}📡  DEPLOYMENT ANALYSIS: {Colors.BRIGHT_YELLOW}{target}{Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}{'=' * 70}{Colors.RESET}\n")
    
    # Geolocation
    geo = report.get("geo", {})
    if geo:
        city = geo.get("city", "Unknown")
        country = geo.get("country", "Unknown")
        isp = geo.get("isp", "Unknown")
        print(f"{Colors.CYAN}📍 Location:{Colors.RESET} {Colors.WHITE}{city}, {country}{Colors.RESET} | {Colors.DIM}ISP: {isp}{Colors.RESET}")
        
        if geo.get("lat") and geo.get("lon"):
            maps_url = f"https://www.google.com/maps?q={geo['lat']},{geo['lon']}"
            print(f"{Colors.CYAN}🗺️  Map:{Colors.RESET} {Colors.BLUE}{maps_url}{Colors.RESET}\n")
    
    # Open Ports
    ports = report.get("open_ports", [])
    services = report.get("services", [])
    if ports:
        port_details = []
        for svc in services:
            port = svc.get("port")
            svc_type = svc.get("service_type", "UNKNOWN")
            banner = svc.get("server", "")
            if banner:
                port_details.append(f"{port} ({svc_type} - {banner})")
            else:
                port_details.append(f"{port} ({svc_type})")
        
        print(f"{Colors.GREEN}🔓 Open Ports:{Colors.RESET} {Colors.WHITE}{', '.join(port_details)}{Colors.RESET}\n")
    
    # Cameras
    cameras = report.get("camera_candidates", [])
    if cameras:
        print(f"{Colors.MAGENTA}🎥 Cameras:{Colors.RESET}")
        for cam in cameras:
            port = cam.get("port")
            brand = cam.get("brand", "Unknown")
            model = cam.get("model", "")
            firmware = cam.get("firmware", "")
            vulns = cam.get("vulnerabilities", [])
            
            cam_info = f"  {Colors.BRIGHT_WHITE}•{Colors.RESET} Port {Colors.BRIGHT_CYAN}{port}{Colors.RESET} | "
            cam_info += f"{Colors.BRIGHT_GREEN}{brand}{Colors.RESET}"
            if model:
                cam_info += f" {Colors.WHITE}{model}{Colors.RESET}"
            if firmware:
                cam_info += f" {Colors.DIM}(FW: {firmware}){Colors.RESET}"
            print(cam_info)
            
            if vulns:
                for vuln in vulns:
                    print(f"    {Colors.BRIGHT_RED}⚠️  {vuln}{Colors.RESET} {Colors.YELLOW}(RCE possible){Colors.RESET}")
        print()
    
    # Authentication
    auth_results = report.get("auth_results", {})
    if auth_results:
        print(f"{Colors.GREEN}🔑 Auth:{Colors.RESET}", end=" ")
        for port, auth in auth_results.items():
            creds = auth.get("credentials", {})
            username = creds.get("username", "")
            password = creds.get("password", "")
            print(f"{Colors.BRIGHT_GREEN}{username}{Colors.RESET} / {Colors.BRIGHT_YELLOW}{password}{Colors.RESET} {Colors.DIM}(works on port {port}){Colors.RESET}")
        print()
    
    # Streams
    streams = report.get("streams", [])
    if streams:
        print(f"{Colors.BLUE}📺 Streams:{Colors.RESET}")
        for stream in streams:
            protocol = stream.get("protocol", "Unknown")
            url = stream.get("playable_url", "")
            is_live = stream.get("is_live", False)
            status = f"{Colors.BRIGHT_GREEN}✅{Colors.RESET}" if is_live else f"{Colors.YELLOW}⚠️{Colors.RESET}"
            print(f"  {Colors.BRIGHT_WHITE}•{Colors.RESET} {Colors.CYAN}{protocol}:{Colors.RESET} {Colors.WHITE}{url}{Colors.RESET} {status}")
            
            screenshot = stream.get("screenshot")
            if screenshot:
                print(f"    {Colors.DIM}📸 Screenshot: {screenshot}{Colors.RESET}")
        print()
    
    # Search Links
    print(f"{Colors.CYAN}🔍 Search:{Colors.RESET}")
    print(f"  {Colors.BRIGHT_WHITE}•{Colors.RESET} Shodan: {Colors.BLUE}https://www.shodan.io/host/{target}{Colors.RESET}")
    print(f"  {Colors.BRIGHT_WHITE}•{Colors.RESET} Censys: {Colors.BLUE}https://search.censys.io/hosts/{target}{Colors.RESET}")
    
    # Report file (if available)
    report_file = report.get("report_file")
    if report_file:
        print(f"\n{Colors.DIM}📄 Encrypted backup: {report_file}{Colors.RESET}")
    
    print(f"{Colors.BRIGHT_CYAN}{'=' * 70}{Colors.RESET}\n")

def clear_line():
    """Clear current line"""
    print('\r' + ' ' * 80 + '\r', end='', flush=True)
