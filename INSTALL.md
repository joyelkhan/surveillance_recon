# Installation Guide - SurveillanceRecon

## Quick Start

### 1. System Requirements

- **Python:** 3.8 or higher
- **Operating System:** Windows, Linux, or macOS
- **RAM:** Minimum 2GB
- **Network:** Internet connection for package installation

### 2. Install Python Dependencies

```bash
# Navigate to project directory
cd surveillance_recon

# Install required packages
pip install -r requirements.txt
```

### 3. Install Optional Tools

#### VLC Media Player (Recommended for stream validation)

**Windows:**
```powershell
# Download from: https://www.videolan.org/vlc/
# Or use Chocolatey:
choco install vlc
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install vlc
```

**macOS:**
```bash
brew install --cask vlc
```

#### FFmpeg (Alternative to VLC)

**Windows:**
```powershell
# Download from: https://ffmpeg.org/download.html
# Or use Chocolatey:
choco install ffmpeg
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install ffmpeg
```

**macOS:**
```bash
brew install ffmpeg
```

#### Tor Browser (Optional - for C2 exfiltration)

**All Platforms:**
Download from: https://www.torproject.org/download/

### 4. Verify Installation

```bash
# Test basic import
python -c "import surveillance_recon; print('Installation successful!')"

# Run help
python -m surveillance_recon --help
```

### 5. Install as Package (Optional)

```bash
# Install in development mode
pip install -e .

# Or install normally
pip install .

# Now you can run from anywhere:
surveillance_recon --help
```

## Troubleshooting

### Issue: ModuleNotFoundError

**Solution:**
```bash
pip install --upgrade -r requirements.txt
```

### Issue: SSL Certificate Errors

**Solution:**
```bash
pip install --upgrade certifi
# Or disable SSL verification (not recommended for production)
```

### Issue: Permission Denied

**Solution:**
```bash
# Linux/macOS - use sudo
sudo pip install -r requirements.txt

# Or use virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

### Issue: VLC/FFmpeg Not Found

**Solution:**
- Ensure VLC or FFmpeg is in your system PATH
- Restart terminal after installation
- Verify with: `vlc --version` or `ffmpeg -version`

## Virtual Environment Setup (Recommended)

```bash
# Create virtual environment
python -m venv camxploit_env

# Activate it
# Windows:
camxploit_env\Scripts\activate
# Linux/macOS:
source camxploit_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python -m surveillance_recon
```

## Docker Installation (Advanced)

```dockerfile
# Dockerfile example
FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN apt-get update && \
    apt-get install -y vlc ffmpeg && \
    pip install -r requirements.txt

ENTRYPOINT ["python", "-m", "surveillance_recon"]
```

```bash
# Build and run
docker build -t surveillance_recon .
docker run -it surveillance_recon --help
```

## Next Steps

After installation:
1. Read the [README.md](README.md) for usage examples
2. Review the [LICENSE](LICENSE) for legal terms
3. Run your first scan: `python -m surveillance_recon <target_ip>`

## Support

For issues or questions:
- Check existing GitHub issues
- Review documentation
- Ensure all dependencies are installed correctly

