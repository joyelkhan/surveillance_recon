# Project Information - SurveillanceRecon

## Project Identity

- **Name:** SurveillanceRecon
- **Package Name:** `surveillance_recon`
- **Version:** 1.0.0
- **Author:** SecOps Research Team
- **License:** Educational/Research Use Only
- **Description:** Advanced CCTV/IoT Security Assessment Framework

## Quick Reference

### Installation
```bash
pip install -r requirements.txt
```

### Usage
```bash
# CLI
python -m surveillance_recon <target_ip>

# Or after installation
surveillance-recon <target_ip>
srecon <target_ip>  # Short alias
```

### Programmatic API
```python
import surveillance_recon

# Quick scan
report = surveillance_recon.scan("192.168.1.100")

# Advanced usage
from surveillance_recon import ReconEngine

engine = ReconEngine(target_ip="192.168.1.100")
report = engine.run_full_recon()
```

## Key Classes

- `ReconEngine` - Main orchestration engine
- `PortScanner` - Port and service scanner
- `CameraFingerprinter` - Device fingerprinting
- `Authenticator` - Credential testing
- `StreamValidator` - Stream validation
- `DataExfiltrator` - C2 exfiltration
- `SecureLogger` - Encrypted logging
- `SandboxDetector` - Evasion engine
- `SecurityPlugin` - Plugin base class

## Project Structure

```
surveillance_recon/
├── __init__.py           # Framework entry
├── main.py               # Execution hub
├── cli.py                # CLI interface
├── core/                 # Core modules
│   ├── scanner.py
│   ├── fingerprinter.py
│   ├── authenticator.py
│   ├── streamer.py
│   └── exfil.py
├── config/               # Intelligence databases
│   ├── ports.py
│   ├── creds.py
│   └── dorks.py
├── utils/                # Utilities
│   ├── logger.py
│   ├── evasion.py
│   └── helpers.py
└── plugins/              # Exploit plugins
    ├── hikvision_rce.py
    └── dahua_backdoor.py
```

## Supported Vendors

1. Hikvision (3+ CVEs, RCE plugin)
2. Dahua (3+ CVEs, backdoor plugin)
3. CP Plus
4. Axis
5. Sony
6. Bosch
7. Panasonic
8. Vivotek
9. Generic ONVIF

## Features

- ✅ Multi-protocol scanning (HTTP/HTTPS/RTSP/ONVIF)
- ✅ Deep fingerprinting with CVE mapping
- ✅ Credential testing with mutations
- ✅ Live stream validation
- ✅ Encrypted C2 exfiltration
- ✅ Sandbox/VM evasion
- ✅ Encrypted logging
- ✅ Plugin system

## Development

### Running Tests
```bash
python -m pytest tests/
```

### Code Style
```bash
flake8 surveillance_recon/
black surveillance_recon/
```

### Building Package
```bash
python setup.py sdist bdist_wheel
```

## Contact

- **GitHub:** https://github.com/yourusername/surveillance-recon
- **Issues:** https://github.com/yourusername/surveillance-recon/issues
- **Documentation:** See README.md

## Legal

This tool is for **authorized security testing only**. Unauthorized access to computer systems is illegal. Always obtain explicit written permission before testing.

---

**Built by SecOps Research Team for the security research community.**
