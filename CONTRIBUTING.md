# Contributing to SurveillanceRecon

Thank you for your interest in contributing to SurveillanceRecon! This document provides guidelines for contributing to the project.

## Code of Conduct

### Ethical Use Only
- All contributions must align with ethical security research principles
- Code must be designed for authorized testing only
- No contributions that facilitate illegal activities

## How to Contribute

### 1. Reporting Bugs

**Before submitting:**
- Check existing issues to avoid duplicates
- Verify the bug with the latest version

**Bug report should include:**
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs (sanitized)

### 2. Suggesting Features

**Feature requests should include:**
- Clear use case description
- How it benefits authorized security testing
- Potential implementation approach

### 3. Code Contributions

#### Setup Development Environment

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/surveillance_recon.git
cd surveillance_recon

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install in development mode
pip install -e .
pip install -r requirements.txt
```

#### Coding Standards

**Python Style:**
- Follow PEP 8 guidelines
- Use type hints where appropriate
- Maximum line length: 120 characters
- Use descriptive variable names

**Documentation:**
- Add docstrings to all functions/classes
- Update README.md if adding features
- Include inline comments for complex logic

**Example:**
```python
def scan_target(target_ip: str, ports: List[int]) -> Dict[str, Any]:
    """
    Scan target IP for open ports and services.
    
    Args:
        target_ip: IPv4 address to scan
        ports: List of ports to check
        
    Returns:
        Dictionary containing scan results
        
    Raises:
        ValueError: If target_ip is invalid
    """
    # Implementation
    pass
```

#### Commit Guidelines

**Commit message format:**
```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Example:**
```
feat: Add support for Axis camera fingerprinting

- Implement Axis-specific signatures
- Add VAPIX protocol detection
- Update credential database

Closes #42
```

#### Pull Request Process

1. **Create a branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make changes:**
   - Write clean, documented code
   - Follow coding standards
   - Test thoroughly

3. **Commit changes:**
   ```bash
   git add .
   git commit -m "feat: your feature description"
   ```

4. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create Pull Request:**
   - Provide clear description
   - Reference related issues
   - Include testing details

### 4. Adding New Plugins

**Plugin structure:**
```python
from surveillance_recon.plugins import ZetaPlugin

class YourPlugin(ZetaPlugin):
    NAME = "Your Plugin Name"
    DESCRIPTION = "What it does"
    TARGET_BRANDS = ["brand1", "brand2"]
    REQUIRED_VULNS = ["CVE-XXXX-XXXXX"]
    AUTHOR = "Your Name"
    VERSION = "1.0"
    
    def execute(self) -> dict:
        """Main exploit logic"""
        return {
            "success": True,
            "output": "Results"
        }
```

**Plugin checklist:**
- [ ] Inherits from `ZetaPlugin`
- [ ] Implements `execute()` method
- [ ] Includes proper error handling
- [ ] Returns structured results
- [ ] Includes documentation
- [ ] Tested on target platform

### 5. Adding Vendor Support

**To add a new camera vendor:**

1. **Update `config/ports.py`:**
   ```python
   (port, "HTTP", "Vendor Web", "vendor_name", risk_score)
   ```

2. **Update `config/creds.py`:**
   ```python
   ("username", "password", "vendor_name", risk, "notes")
   ```

3. **Update `core/fingerprinter.py`:**
   ```python
   "vendor_name": {
       "html": [r"pattern1", r"pattern2"],
       "headers": ["Header1"],
       "urls": ["/path1", "/path2"],
       "cves": ["CVE-XXXX-XXXXX"],
       "default_creds": [("user", "pass")]
   }
   ```

## Testing

### Manual Testing
```bash
# Test on controlled environment
python -m surveillance_recon <test_target_ip>
```

### Code Quality
```bash
# Check style
flake8 surveillance_recon/

# Type checking (if using mypy)
mypy surveillance_recon/
```

## Documentation

### Update Documentation When:
- Adding new features
- Changing existing behavior
- Adding new dependencies
- Modifying CLI arguments

### Documentation Files:
- `README.md` - Main documentation
- `INSTALL.md` - Installation guide
- `CONTRIBUTING.md` - This file
- Inline code comments
- Docstrings

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (Educational/Research Use Only).

## Questions?

- Open an issue for discussion
- Check existing documentation
- Review closed issues for similar questions

## Recognition

Contributors will be acknowledged in:
- README.md contributors section
- Release notes
- Project documentation

Thank you for contributing to SurveillanceRecon!

