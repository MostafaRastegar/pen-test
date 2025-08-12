# Auto-Pentest Framework v0.9.1 - Development Guide

## 🎯 **Welcome to Development**

This comprehensive development guide will help you contribute to the Auto-Pentest Framework, whether you're fixing bugs, adding features, creating custom scanners, or improving documentation.

### **🚀 Getting Started**

The Auto-Pentest Framework is designed with developer experience in mind, featuring:
- **Clean Architecture**: Modular design with clear separation of concerns
- **Comprehensive Testing**: 90%+ test coverage with automated CI/CD
- **Rich Documentation**: API docs, examples, and best practices
- **Developer Tools**: Linting, formatting, and debugging utilities
- **Plugin System**: Extensible architecture for custom components

---

## 🛠️ **Development Environment Setup**

### **Prerequisites**

```bash
# Required Software
- Python 3.8+ (3.9+ recommended)
- Git 2.20+
- Virtual Environment (venv/virtualenv/conda)
- IDE/Editor (VS Code, PyCharm, vim, etc.)

# Optional Tools
- Docker & Docker Compose
- Pre-commit hooks
- Make (for automation)
```

### **Quick Setup**

```bash
# 1. Clone the repository
git clone https://github.com/your-org/auto-pentest-framework.git
cd auto-pentest-framework

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install development dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 4. Install pre-commit hooks
pre-commit install

# 5. Verify installation
python verify_installation.py
python -m pytest tests/ -v

# 6. Run the framework
python main.py --help
```

### **Development Dependencies**

```bash
# requirements-dev.txt

# Testing
pytest>=7.0.0
pytest-cov>=3.0.0
pytest-mock>=3.6.0
pytest-asyncio>=0.18.0

# Code Quality
black>=22.0.0
isort>=5.10.0
flake8>=4.0.0
pylint>=2.12.0
mypy>=0.950

# Development Tools
pre-commit>=2.17.0
tox>=3.24.0
sphinx>=4.5.0
sphinx-rtd-theme>=1.0.0

# Performance
memory-profiler>=0.60.0
line-profiler>=3.5.0
py-spy>=0.3.0

# Debugging
pdb++>=0.10.0
pudb>=2022.1
icecream>=2.1.0
```

### **IDE Configuration**

#### **VS Code Settings**
```json
// .vscode/settings.json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "python.sortImports.args": ["--profile", "black"],
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    },
    "python.testing.pytestEnabled": true,
    "python.testing.unittestEnabled": false,
    "python.testing.pytestArgs": [
        "tests"
    ],
    "files.exclude": {
        "**/__pycache__": true,
        "**/*.pyc": true,
        ".pytest_cache": true,
        ".coverage": true,
        "output/": true
    }
}
```

#### **PyCharm Configuration**
```python
# PyCharm Setup
1. File → Settings → Project → Python Interpreter
   - Select: ./venv/bin/python

2. File → Settings → Tools → External Tools
   - Add Black formatter
   - Add isort import sorter
   - Add pytest runner

3. File → Settings → Editor → Code Style → Python
   - Set line length to 88 (Black standard)
   - Enable automatic imports optimization

4. File → Settings → Build → Console → Python Console
   - Add PYTHONPATH: ./src
```

---

## 📐 **Project Structure**

### **Directory Organization**

```
auto-pentest-framework/
├── src/                          # Source code
│   ├── core/                     # Core framework components
│   │   ├── __init__.py
│   │   ├── scanner_base.py       # Base scanner class
│   │   ├── executor.py           # Command execution
│   │   └── validator.py          # Input validation
│   ├── scanners/                 # Scanner implementations
│   │   ├── recon/                # Reconnaissance scanners
│   │   │   ├── port_scanner.py
│   │   │   └── dns_scanner.py
│   │   └── vulnerability/        # Vulnerability scanners
│   │       ├── web_scanner.py
│   │       ├── directory_scanner.py
│   │       └── ssl_scanner.py
│   ├── orchestrator/             # Workflow orchestration
│   │   ├── orchestrator.py
│   │   └── scheduler.py
│   └── utils/                    # Utility modules
│       ├── logger.py
│       ├── reporter.py
│       ├── cache.py
│       └── performance.py
├── config/                       # Configuration files
│   ├── settings.py
│   ├── tools_config.yaml
│   └── logging_config.yaml
├── templates/                    # Report templates
│   ├── report_html.jinja2
│   ├── executive_summary.jinja2
│   └── compliance_reports/
├── tests/                        # Test suite
│   ├── unit/                     # Unit tests
│   ├── integration/              # Integration tests
│   ├── fixtures/                 # Test fixtures
│   └── mocks/                    # Mock objects
├── docs/                         # Documentation
│   ├── api_documentation.md
│   ├── user_manual.md
│   ├── architecture_overview.md
│   └── development_guide.md
├── scripts/                      # Utility scripts
│   ├── setup_dev.sh
│   ├── run_tests.sh
│   └── build_docker.sh
├── output/                       # Generated output
│   ├── logs/
│   ├── reports/
│   ├── cache/
│   └── raw/
├── main.py                       # Main entry point
├── requirements.txt              # Production dependencies
├── requirements-dev.txt          # Development dependencies
├── setup.py                      # Package setup
├── pyproject.toml               # Project metadata
├── .pre-commit-config.yaml      # Pre-commit hooks
├── .github/                     # GitHub workflows
│   └── workflows/
│       ├── ci.yml
│       ├── release.yml
│       └── security.yml
└── README.md                    # Project overview
```

### **Module Import Strategy**

```python
# Import Guidelines

# 1. Standard library imports first
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

# 2. Third-party imports second
import click
import requests
from jinja2 import Template

# 3. Local imports last
from src.core.scanner_base import ScannerBase, ScanResult
from src.utils.logger import get_logger
from config.settings import settings

# 4. Use absolute imports for internal modules
from src.scanners.recon.port_scanner import PortScanner  # Good
from .port_scanner import PortScanner  # Avoid

# 5. Group imports logically
from src.core import (  # Multi-line imports
    ScannerBase,
    CommandExecutor,
    InputValidator
)
```

---

## 🧪 **Testing Strategy**

### **Test Structure**

```python
# Test Organization
tests/
├── unit/                         # Unit tests (fast, isolated)
│   ├── test_core/
│   │   ├── test_scanner_base.py
│   │   ├── test_executor.py
│   │   └── test_validator.py
│   ├── test_scanners/
│   │   ├── test_port_scanner.py
│   │   ├── test_dns_scanner.py
│   │   └── test_web_scanner.py
│   └── test_utils/
│       ├── test_logger.py
│       ├── test_reporter.py
│       └── test_cache.py
├── integration/                  # Integration tests (slower, real components)
│   ├── test_workflows.py
│   ├── test_report_generation.py
│   └── test_scanner_integration.py
├── e2e/                         # End-to-end tests (slowest, full system)
│   ├── test_cli_interface.py
│   ├── test_full_scanning.py
│   └── test_report_pipeline.py
├── fixtures/                    # Test data and fixtures
│   ├── sample_nmap_output.xml
│   ├── sample_nikto_output.csv
│   └── test_targets.json
├── mocks/                       # Mock objects and utilities
│   ├── mock_scanner.py
│   ├── mock_tools.py
│   └── test_helpers.py
└── conftest.py                  # Pytest configuration
```

### **Writing Unit Tests**

```python
# Example: test_port_scanner.py

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from src.scanners.recon.port_scanner import PortScanner
from src.core.scanner_base import ScanResult, SeverityLevel
from tests.mocks.test_helpers import create_mock_nmap_output


class TestPortScanner:
    """Test suite for PortScanner class"""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance for testing"""
        return PortScanner()
    
    @pytest.fixture
    def mock_nmap_output(self):
        """Mock nmap XML output"""
        return create_mock_nmap_output(
            target="192.168.1.1",
            open_ports=[22, 80, 443],
            services=["ssh", "http", "https"]
        )
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly"""
        assert scanner.scanner_name == "port_scanner"
        assert scanner.logger is not None
        assert scanner.cache_manager is not None
    
    def test_validate_target_valid_ip(self, scanner):
        """Test target validation with valid IP"""
        assert scanner.validate_target("192.168.1.1") is True
        assert scanner.validate_target("10.0.0.1") is True
    
    def test_validate_target_invalid_ip(self, scanner):
        """Test target validation with invalid IP"""
        assert scanner.validate_target("300.300.300.300") is False
        assert scanner.validate_target("not.an.ip") is False
    
    @patch('src.scanners.recon.port_scanner.subprocess.run')
    def test_scan_success(self, mock_subprocess, scanner, mock_nmap_output):
        """Test successful port scan"""
        # Setup mock
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = mock_nmap_output
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result
        
        # Execute test
        result = scanner.scan("192.168.1.1", {"ports": "1-1000"})
        
        # Assertions
        assert isinstance(result, ScanResult)
        assert result.success is True
        assert result.scanner_name == "port_scanner"
        assert result.target == "192.168.1.1"
        assert len(result.findings) > 0
        
        # Verify subprocess call
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args[0][0]
        assert "nmap" in call_args
        assert "192.168.1.1" in call_args
    
    @patch('src.scanners.recon.port_scanner.subprocess.run')
    def test_scan_failure(self, mock_subprocess, scanner):
        """Test scan failure handling"""
        # Setup mock for failure
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Permission denied"
        mock_subprocess.return_value = mock_result
        
        # Execute test
        result = scanner.scan("192.168.1.1")
        
        # Assertions
        assert result.success is False
        assert "Permission denied" in result.error_message
    
    def test_severity_assessment(self, scanner):
        """Test vulnerability severity assessment"""
        # Test high-risk ports
        high_risk_severity = scanner._assess_port_severity(22, "ssh")
        assert high_risk_severity == SeverityLevel.HIGH
        
        # Test medium-risk ports
        medium_risk_severity = scanner._assess_port_severity(25, "smtp")
        assert medium_risk_severity == SeverityLevel.MEDIUM
        
        # Test low-risk ports
        low_risk_severity = scanner._assess_port_severity(80, "http")
        assert low_risk_severity == SeverityLevel.LOW
    
    def test_get_capabilities(self, scanner):
        """Test scanner capabilities"""
        capabilities = scanner.get_capabilities()
        
        assert isinstance(capabilities, dict)
        assert "name" in capabilities
        assert "description" in capabilities
        assert "supported_targets" in capabilities
        assert "features" in capabilities
    
    @pytest.mark.integration
    def test_real_scan_localhost(self, scanner):
        """Integration test with real nmap (if available)"""
        pytest.importorskip("nmap")  # Skip if nmap not available
        
        result = scanner.scan("127.0.0.1", {"ports": "22,80,443"})
        
        assert isinstance(result, ScanResult)
        assert result.target == "127.0.0.1"
        # Note: Success depends on actual system state
    
    @pytest.mark.slow
    def test_performance_large_port_range(self, scanner, mock_nmap_output):
        """Performance test for large port ranges"""
        with patch('src.scanners.recon.port_scanner.subprocess.run') as mock_subprocess:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = mock_nmap_output
            mock_result.stderr = ""
            mock_subprocess.return_value = mock_result
            
            import time
            start_time = time.time()
            result = scanner.scan("192.168.1.1", {"ports": "1-65535"})
            execution_time = time.time() - start_time
            
            assert result.success is True
            assert execution_time < 10  # Should complete in reasonable time
```

### **Integration Testing**

```python
# Example: test_workflow_integration.py

import pytest
from pathlib import Path
import tempfile

from src.orchestrator.orchestrator import WorkflowOrchestrator, ExecutionMode
from src.orchestrator.scheduler import WorkflowStep
from tests.mocks.mock_scanner import MockScanner
from tests.mocks.test_helpers import TestEnvironment


class TestWorkflowIntegration:
    """Integration tests for workflow orchestration"""
    
    @pytest.fixture
    def test_env(self):
        """Setup test environment"""
        with TestEnvironment() as env:
            yield env
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator for testing"""
        return WorkflowOrchestrator(max_workers=2)
    
    def test_parallel_workflow_execution(self, test_env, orchestrator):
        """Test parallel workflow execution"""
        # Create mock scanners
        port_scanner = test_env.create_mock_scanner(
            "port_scanner",
            findings=[{"type": "open_port", "port": 80, "severity": "low"}],
            execution_time=1.0
        )
        
        web_scanner = test_env.create_mock_scanner(
            "web_scanner",
            findings=[{"type": "web_vuln", "severity": "medium"}],
            execution_time=2.0
        )
        
        # Create workflow steps
        steps = [
            WorkflowStep(
                scanner_name="port_scanner",
                scanner_class=lambda: port_scanner,
                options={},
                dependencies=[]
            ),
            WorkflowStep(
                scanner_name="web_scanner",
                scanner_class=lambda: web_scanner,
                options={},
                dependencies=[]
            )
        ]
        
        # Execute workflow
        result = orchestrator.execute_workflow(
            workflow_id="test_parallel",
            target="test.example.com",
            steps=steps,
            execution_mode=ExecutionMode.PARALLEL
        )
        
        # Assertions
        assert result.success is True
        assert result.steps_completed == 2
        assert result.total_steps == 2
        assert len(result.results) == 2
        assert "port_scanner" in result.results
        assert "web_scanner" in result.results
        
        # Verify parallel execution (should be faster than sequential)
        assert result.execution_time < 2.5  # Both scanners run in parallel
    
    def test_sequential_workflow_execution(self, test_env, orchestrator):
        """Test sequential workflow execution"""
        # Similar setup but with sequential execution
        # ... (implementation similar to parallel test)
        
        result = orchestrator.execute_workflow(
            workflow_id="test_sequential",
            target="test.example.com",
            steps=steps,
            execution_mode=ExecutionMode.SEQUENTIAL
        )
        
        assert result.success is True
        # Sequential should take longer than parallel
        assert result.execution_time >= 3.0
    
    def test_dependency_resolution(self, test_env, orchestrator):
        """Test workflow dependency resolution"""
        # Create scanners with dependencies
        port_scanner = test_env.create_mock_scanner("port_scanner")
        ssl_scanner = test_env.create_mock_scanner("ssl_scanner")
        
        steps = [
            WorkflowStep(
                scanner_name="ssl_scanner",
                scanner_class=lambda: ssl_scanner,
                options={},
                dependencies=["port_scanner"]  # Depends on port scanner
            ),
            WorkflowStep(
                scanner_name="port_scanner",
                scanner_class=lambda: port_scanner,
                options={},
                dependencies=[]
            )
        ]
        
        # Execute - should handle dependency order automatically
        result = orchestrator.execute_workflow(
            workflow_id="test_dependencies",
            target="test.example.com",
            steps=steps
        )
        
        assert result.success is True
        # Verify execution order through timing or other means
    
    def test_error_handling_in_workflow(self, test_env, orchestrator):
        """Test error handling in workflow execution"""
        # Create a failing scanner
        failing_scanner = test_env.create_mock_scanner(
            "failing_scanner",
            should_fail=True
        )
        
        working_scanner = test_env.create_mock_scanner("working_scanner")
        
        steps = [
            WorkflowStep(
                scanner_name="failing_scanner",
                scanner_class=lambda: failing_scanner,
                options={},
                dependencies=[]
            ),
            WorkflowStep(
                scanner_name="working_scanner",
                scanner_class=lambda: working_scanner,
                options={},
                dependencies=[]
            )
        ]
        
        result = orchestrator.execute_workflow(
            workflow_id="test_error_handling",
            target="test.example.com",
            steps=steps
        )
        
        # Workflow should continue despite one failure
        assert result.steps_completed == 1  # Only working scanner succeeded
        assert result.total_steps == 2
        assert not result.results["failing_scanner"].success
        assert result.results["working_scanner"].success
```

### **End-to-End Testing**

```python
# Example: test_e2e_cli.py

import subprocess
import pytest
from pathlib import Path
import json


class TestEndToEndCLI:
    """End-to-end tests for CLI interface"""
    
    def test_cli_help_command(self):
        """Test CLI help command works"""
        result = subprocess.run(
            ["python", "main.py", "--help"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "Auto-Pentest Framework" in result.stdout
        assert "scan" in result.stdout
    
    def test_cli_version_command(self):
        """Test CLI version command"""
        result = subprocess.run(
            ["python", "main.py", "version"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "0.9.1" in result.stdout
    
    def test_cli_list_tools_command(self):
        """Test list tools command"""
        result = subprocess.run(
            ["python", "main.py", "list-tools"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "nmap" in result.stdout
        assert "nikto" in result.stdout
    
    @pytest.mark.slow
    def test_cli_scan_localhost(self):
        """Test actual scan of localhost"""
        result = subprocess.run([
            "python", "main.py", "scan", "127.0.0.1",
            "--include-port", "--ports", "22,80,443",
            "--json-output"
        ], capture_output=True, text=True, timeout=120)
        
        # Should succeed or fail gracefully
        assert result.returncode in [0, 1]  # Allow scan failures
        
        if result.returncode == 0:
            # Verify JSON output is valid
            output_dir = Path("output/reports")
            json_files = list(output_dir.glob("*.json"))
            assert len(json_files) > 0
            
            # Validate JSON structure
            with open(json_files[0]) as f:
                scan_data = json.load(f)
            
            assert "metadata" in scan_data
            assert "findings" in scan_data
            assert scan_data["metadata"]["target"] == "127.0.0.1"
    
    def test_cli_invalid_target(self):
        """Test CLI with invalid target"""
        result = subprocess.run([
            "python", "main.py", "scan", "invalid.target.999"
        ], capture_output=True, text=True)
        
        assert result.returncode != 0
        assert "invalid" in result.stderr.lower() or "error" in result.stderr.lower()
```

### **Test Configuration**

```python
# conftest.py - Pytest configuration

import pytest
import tempfile
import shutil
from pathlib import Path

# Test markers
pytest_plugins = []

def pytest_configure(config):
    """Configure pytest markers"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "e2e: marks tests as end-to-end tests"
    )
    config.addinivalue_line(
        "markers", "network: marks tests that require network access"
    )

@pytest.fixture(scope="session")
def temp_output_dir():
    """Create temporary output directory for tests"""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir)

@pytest.fixture(autouse=True)
def setup_test_environment(temp_output_dir, monkeypatch):
    """Setup clean test environment"""
    # Set output directory to temp location
    monkeypatch.setenv("OUTPUT_DIR", str(temp_output_dir))
    monkeypatch.setenv("CACHE_ENABLED", "false")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    
    # Create required directories
    (temp_output_dir / "logs").mkdir(exist_ok=True)
    (temp_output_dir / "reports").mkdir(exist_ok=True)
    (temp_output_dir / "cache").mkdir(exist_ok=True)

@pytest.fixture
def sample_scan_result():
    """Sample scan result for testing"""
    from src.core.scanner_base import ScanResult
    
    return ScanResult(
        scanner_name="test_scanner",
        target="test.example.com",
        findings=[
            {
                "type": "test_finding",
                "severity": "medium",
                "title": "Test Finding",
                "description": "This is a test finding"
            }
        ],
        metadata={"test": True},
        execution_time=1.5,
        success=True
    )
```

### **Running Tests**

```bash
# Test Execution Commands

# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html --cov-report=term

# Run specific test categories
pytest -m "not slow"              # Skip slow tests
pytest -m integration             # Only integration tests
pytest -m "slow or e2e"           # Slow and e2e tests

# Run specific test files
pytest tests/unit/test_core/
pytest tests/integration/test_workflows.py

# Run with verbose output
pytest -v -s

# Run with specific markers
pytest -m "not network" -v        # Skip network-dependent tests

# Run tests in parallel (with pytest-xdist)
pytest -n auto

# Generate test report
pytest --html=test_report.html --self-contained-html
```

---

## 🎨 **Code Style & Standards**

### **Python Style Guide**

```python
# Code Style Standards

# 1. Follow PEP 8 with Black formatting
# Line length: 88 characters (Black default)
# Indentation: 4 spaces (no tabs)

# 2. Naming Conventions
class ScannerBase:              # PascalCase for classes
    pass

def execute_scan():             # snake_case for functions
    pass

CONSTANT_VALUE = "value"        # UPPER_CASE for constants

scanner_instance = Scanner()    # snake_case for variables

# 3. Type Hints (Required)
def scan_target(target: str, options: Dict[str, Any]) -> ScanResult:
    """Scan target with specified options"""
    return ScanResult(...)

# 4. Docstrings (Google Style)
def complex_function(param1: str, param2: int) -> bool:
    """
    Perform complex operation with parameters.
    
    Args:
        param1: Description of first parameter
        param2: Description of second parameter
        
    Returns:
        bool: True if operation successful
        
    Raises:
        ValueError: If parameters are invalid
        RuntimeError: If operation fails
        
    Example:
        >>> result = complex_function("test", 42)
        >>> assert result is True
    """
    if not param1:
        raise ValueError("param1 cannot be empty")
    
    try:
        # Implementation
        return True
    except Exception as e:
        raise RuntimeError(f"Operation failed: {e}")

# 5. Import Organization
# Standard library
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Third-party
import click
import requests

# Local imports
from src.core.scanner_base import ScannerBase
from src.utils.logger import get_logger

# 6. Error Handling Patterns
class ScannerError(Exception):
    """Base exception for scanner errors"""
    pass

class ValidationError(ScannerError):
    """Raised when input validation fails"""
    pass

def robust_function():
    """Example of proper error handling"""
    try:
        # Risky operation
        result = risky_operation()
    except SpecificException as e:
        logger.error(f"Specific error occurred: {e}")
        raise ScannerError(f"Failed to process: {e}")
    except Exception as e:
        logger.exception("Unexpected error occurred")
        raise ScannerError(f"Unexpected error: {e}")
    else:
        logger.info("Operation completed successfully")
        return result
    finally:
        # Cleanup code
        cleanup_resources()
```

### **Code Quality Tools**

```yaml
# .pre-commit-config.yaml

repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict
      - id: debug-statements

  - repo: https://github.com/psf/black
    rev: 22.12.0
    hooks:
      - id: black
        args: [--line-length=88]

  - repo: https://github.com/pycqa/isort
    rev: 5.11.4
    hooks:
      - id: isort
        args: [--profile=black]

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: [--max-line-length=88, --extend-ignore=E203,W503]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v0.991
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
        args: [--ignore-missing-imports]

  - repo: https://github.com/pycqa/pylint
    rev: v2.15.9
    hooks:
      - id: pylint
        args: [--rcfile=.pylintrc]

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.4
    hooks:
      - id: bandit
        args: [-r, src/, -f, json, -o, bandit-report.json]
```

### **Configuration Files**

```ini
# .pylintrc

[MASTER]
load-plugins=pylint.extensions.docparams

[MESSAGES CONTROL]
disable=C0103,R0903,R0913,W0613,C0116

[FORMAT]
max-line-length=88
good-names=i,j,k,ex,Run,_,e,f,fp

[DESIGN]
max-args=7
max-locals=15
max-returns=6
max-branches=12
max-statements=50
max-parents=7
max-attributes=7
min-public-methods=2
max-public-methods=20

[SIMILARITIES]
min-similarity-lines=4
ignore-comments=yes
ignore-docstrings=yes
```

```toml
# pyproject.toml

[build-system]
requires = ["setuptools>=45", "wheel", "setuptools_scm[toml]>=6.2"]
build-backend = "setuptools.build_meta"

[project]
name = "auto-pentest-framework"
version = "0.9.1"
description = "Enterprise-grade automated penetration testing framework"
authors = [{name = "Auto-Pentest Team", email = "team@autopentest.org"}]
license = {text = "MIT"}
readme = "README.md"
requires-python = ">=3.8"
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
]

[tool.black]
line-length = 88
target-version = ['py38']
include = '\.pyi?$'
extend-exclude = '''
/(
  # directories
  \.eggs
  | \.git
  | \.hg
  | \.mypy_cache
  | \.tox
  | \.venv
  | build
  | dist
)/
'''

[tool.isort]
profile = "black"
multi_line_output = 3
line_length = 88
known_first_party = ["src", "tests"]

[tool.mypy]
python_version = "3.8"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
show_error_codes = true

[tool.pytest.ini_options]
minversion = "7.0"
addopts = "-ra -q --strict-markers --strict-config"
testpaths = ["tests"]
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks tests as integration tests",
    "e2e: marks tests as end-to-end tests",
    "network: marks tests that require network access",
]

[tool.coverage.run]
source = ["src"]
omit = [
    "*/tests/*",
    "*/test_*",
    "setup.py",
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "if self.debug:",
    "if settings.DEBUG",
    "raise AssertionError",
    "raise NotImplementedError",
    "if 0:",
    "if __name__ == .__main__.:",
    "class .*\\bProtocol\\):",
    "@(abc\\.)?abstractmethod",
]
```

---

## 🔧 **Custom Scanner Development**

### **Creating a New Scanner**

```python
# Example: Custom CVE Scanner

# 1. Create scanner file: src/scanners/vulnerability/cve_scanner.py

from typing import Dict, List, Any, Optional
import requests
import json
from datetime import datetime

from src.core.scanner_base import ScannerBase, ScanResult, SeverityLevel
from src.core.executor import CommandExecutor
from src.core.validator import InputValidator, ValidationError
from src.utils.logger import get_logger


class CVEScanner(ScannerBase):
    """
    CVE (Common Vulnerabilities and Exposures) Scanner
    
    This scanner identifies known vulnerabilities by checking
    service versions against CVE databases.
    """
    
    def __init__(self):
        super().__init__("cve_scanner")
        self.cve_api_base = "https://cve.circl.lu/api"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Auto-Pentest-Framework/0.9.1'
        })
    
    def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """
        Execute CVE scan
        
        Args:
            target: Target to scan (requires service information)
            options: Scanner options
                - services: List of detected services
                - severity_filter: Minimum severity level
                - max_age_days: Maximum CVE age in days
                
        Returns:
            ScanResult: CVE scan results
        """
        options = options or {}
        start_time = datetime.now()
        
        try:
            # Validate inputs
            self._validate_scan_options(options)
            
            # Get service information (from previous scans or options)
            services = options.get('services', [])
            if not services:
                return self._create_empty_result(target, "No service information provided")
            
            # Search for CVEs
            findings = []
            for service in services:
                service_cves = self._search_cves_for_service(service, options)
                findings.extend(service_cves)
            
            # Filter and sort findings
            findings = self._filter_findings(findings, options)
            findings = self._sort_by_severity(findings)
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ScanResult(
                scanner_name=self.scanner_name,
                target=target,
                findings=findings,
                metadata={
                    "services_scanned": len(services),
                    "cve_database": "CVE CIRCL",
                    "scan_options": options
                },
                execution_time=execution_time,
                success=True
            )
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"CVE scan failed for {target}: {e}")
            
            return ScanResult(
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                metadata={"error_details": str(e)},
                execution_time=execution_time,
                success=False,
                error_message=str(e)
            )
    
    def validate_target(self, target: str) -> bool:
        """
        Validate target for CVE scanning
        
        Args:
            target: Target to validate
            
        Returns:
            bool: True if target is valid
        """
        try:
            # CVE scanner can work with any target format
            # as it operates on service information
            validator = InputValidator()
            return (validator.validate_ip(target) or 
                   validator.validate_domain(target) or 
                   validator.validate_url(target))
        except Exception:
            return False
    
    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get scanner capabilities
        
        Returns:
            dict: Scanner capabilities and metadata
        """
        return {
            "name": "CVE Scanner",
            "description": "Identifies known vulnerabilities in detected services",
            "version": "1.0.0",
            "supported_targets": ["ip", "domain", "url"],
            "features": [
                "cve_lookup",
                "severity_filtering", 
                "service_mapping",
                "cvss_scoring",
                "exploitability_assessment"
            ],
            "dependencies": [
                "requests library",
                "CVE CIRCL API access",
                "Service detection data"
            ],
            "output_formats": ["json", "html"],
            "performance": {
                "typical_scan_time": "10-30 seconds",
                "rate_limit": "100 requests/minute",
                "cache_duration": "24 hours"
            }
        }
    
    def _validate_scan_options(self, options: Dict[str, Any]):
        """Validate scanner-specific options"""
        valid_severities = ["low", "medium", "high", "critical"]
        
        if "severity_filter" in options:
            severity = options["severity_filter"]
            if severity not in valid_severities:
                raise ValidationError(f"Invalid severity filter: {severity}")
        
        if "max_age_days" in options:
            max_age = options["max_age_days"]
            if not isinstance(max_age, int) or max_age < 0:
                raise ValidationError("max_age_days must be a non-negative integer")
    
    def _search_cves_for_service(self, service: Dict[str, Any], options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search CVEs for a specific service"""
        findings = []
        
        try:
            # Extract service information
            name = service.get('name', '').lower()
            version = service.get('version', '')
            product = service.get('product', '')
            
            if not name or not version:
                self.logger.warning(f"Incomplete service info: {service}")
                return findings
            
            # Search CVE database
            search_terms = self._build_search_terms(name, product, version)
            
            for term in search_terms:
                cves = self._query_cve_api(term)
                
                for cve in cves:
                    if self._is_relevant_cve(cve, service):
                        finding = self._create_cve_finding(cve, service)
                        findings.append(finding)
            
        except Exception as e:
            self.logger.error(f"Error searching CVEs for service {service}: {e}")
        
        return findings
    
    def _build_search_terms(self, name: str, product: str, version: str) -> List[str]:
        """Build search terms for CVE lookup"""
        terms = []
        
        # Primary search term
        if product:
            terms.append(f"{product} {version}")
        else:
            terms.append(f"{name} {version}")
        
        # Secondary search terms
        if product and product != name:
            terms.append(f"{name} {version}")
        
        # Version-less search
        if product:
            terms.append(product)
        else:
            terms.append(name)
        
        return terms
    
    def _query_cve_api(self, search_term: str) -> List[Dict[str, Any]]:
        """Query CVE API for search term"""
        try:
            # Check cache first
            cache_key = f"cve_search_{search_term}"
            cached_result = self.cache_manager.get(cache_key)
            
            if cached_result:
                return cached_result
            
            # Make API request
            url = f"{self.cve_api_base}/search/{search_term}"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            cves = response.json()
            
            # Cache results for 24 hours
            self.cache_manager.set(cache_key, cves, ttl=86400)
            
            return cves
            
        except requests.RequestException as e:
            self.logger.error(f"CVE API request failed: {e}")
            return []
        except json.JSONDecodeError as e:
            self.logger.error(f"CVE API response parsing failed: {e}")
            return []
    
    def _is_relevant_cve(self, cve: Dict[str, Any], service: Dict[str, Any]) -> bool:
        """Check if CVE is relevant to the service"""
        # Implement relevance checking logic
        # This would include version comparison, product matching, etc.
        return True  # Simplified for example
    
    def _create_cve_finding(self, cve: Dict[str, Any], service: Dict[str, Any]) -> Dict[str, Any]:
        """Create finding from CVE data"""
        cve_id = cve.get('id', 'Unknown')
        summary = cve.get('summary', 'No description available')
        cvss_score = cve.get('cvss', 0)
        
        # Determine severity based on CVSS score
        severity = self._cvss_to_severity(cvss_score)
        
        return {
            "type": "cve_vulnerability",
            "cve_id": cve_id,
            "title": f"CVE {cve_id} - {service.get('name', 'Unknown Service')}",
            "description": summary,
            "severity": severity.value,
            "cvss_score": cvss_score,
            "service": service,
            "affected_versions": cve.get('vulnerable_configuration', []),
            "references": cve.get('references', []),
            "published_date": cve.get('Published', ''),
            "modified_date": cve.get('Modified', ''),
            "recommendation": self._generate_recommendation(cve, service),
            "exploitability": self._assess_exploitability(cve),
            "metadata": {
                "cve_source": "CVE CIRCL",
                "scan_timestamp": datetime.now().isoformat(),
                "confidence": "high"
            }
        }
    
    def _cvss_to_severity(self, cvss_score: float) -> SeverityLevel:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return SeverityLevel.CRITICAL
        elif cvss_score >= 7.0:
            return SeverityLevel.HIGH
        elif cvss_score >= 4.0:
            return SeverityLevel.MEDIUM
        elif cvss_score > 0:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def _generate_recommendation(self, cve: Dict[str, Any], service: Dict[str, Any]) -> str:
        """Generate remediation recommendation"""
        service_name = service.get('name', 'service')
        
        return f"""
        Update {service_name} to the latest version that addresses CVE {cve.get('id', '')}.
        
        1. Check vendor security advisories for patches
        2. Test updates in a non-production environment
        3. Apply security patches following change management procedures
        4. Verify the vulnerability is resolved after patching
        5. Consider implementing compensating controls if immediate patching is not possible
        
        Priority: {self._cvss_to_severity(cve.get('cvss', 0)).value.upper()}
        """
    
    def _assess_exploitability(self, cve: Dict[str, Any]) -> str:
        """Assess CVE exploitability"""
        # Simplified exploitability assessment
        cvss_score = cve.get('cvss', 0)
        
        if cvss_score >= 9.0:
            return "Critical - Likely exploitable"
        elif cvss_score >= 7.0:
            return "High - Potentially exploitable"
        elif cvss_score >= 4.0:
            return "Medium - May be exploitable"
        else:
            return "Low - Unlikely to be exploitable"
    
    def _filter_findings(self, findings: List[Dict[str, Any]], options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Filter findings based on options"""
        filtered = findings
        
        # Filter by severity
        severity_filter = options.get('severity_filter')
        if severity_filter:
            severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            min_level = severity_order.get(severity_filter, 0)
            
            filtered = [
                f for f in filtered 
                if severity_order.get(f.get('severity', 'info'), 0) >= min_level
            ]
        
        # Filter by age
        max_age_days = options.get('max_age_days')
        if max_age_days:
            cutoff_date = datetime.now() - timedelta(days=max_age_days)
            # Implementation would filter by CVE publication date
        
        return filtered
    
    def _sort_by_severity(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort findings by severity (highest first)"""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        
        return sorted(
            findings,
            key=lambda f: (
                severity_order.get(f.get('severity', 'info'), 4),
                -f.get('cvss_score', 0)
            )
        )
    
    def _create_empty_result(self, target: str, reason: str) -> ScanResult:
        """Create empty result with reason"""
        return ScanResult(
            scanner_name=self.scanner_name,
            target=target,
            findings=[],
            metadata={"reason": reason},
            execution_time=0,
            success=True
        )
```

### **Scanner Integration**

```python
# 2. Register scanner in orchestrator
# src/orchestrator/scanner_registry.py

from src.scanners.vulnerability.cve_scanner import CVEScanner

AVAILABLE_SCANNERS = {
    "port_scanner": "src.scanners.recon.port_scanner.PortScanner",
    "dns_scanner": "src.scanners.recon.dns_scanner.DNSScanner", 
    "web_scanner": "src.scanners.vulnerability.web_scanner.WebScanner",
    "directory_scanner": "src.scanners.vulnerability.directory_scanner.DirectoryScanner",
    "ssl_scanner": "src.scanners.vulnerability.ssl_scanner.SSLScanner",
    "cve_scanner": "src.scanners.vulnerability.cve_scanner.CVEScanner",  # New scanner
}

def get_scanner_class(scanner_name: str):
    """Dynamically import and return scanner class"""
    if scanner_name not in AVAILABLE_SCANNERS:
        raise ValueError(f"Unknown scanner: {scanner_name}")
    
    module_path = AVAILABLE_SCANNERS[scanner_name]
    module_name, class_name = module_path.rsplit('.', 1)
    
    module = importlib.import_module(module_name)
    return getattr(module, class_name)

# 3. Add CLI integration
# main.py - Add new command

@click.command()
@click.argument('target')
@click.option('--services-file', help='JSON file with service information')
@click.option('--severity-filter', type=click.Choice(['low', 'medium', 'high', 'critical']),
              help='Minimum severity level')
@click.option('--max-age-days', type=int, default=365, help='Maximum CVE age in days')
@common_options
def cve(target, services_file, severity_filter, max_age_days, **kwargs):
    """CVE vulnerability scanning"""
    try:
        scanner = CVEScanner()
        
        # Load services from file or previous scan
        services = []
        if services_file:
            with open(services_file) as f:
                services = json.load(f)
        
        options = {
            'services': services,
            'severity_filter': severity_filter,
            'max_age_days': max_age_days
        }
        
        result = scanner.scan(target, options)
        
        if result.success:
            click.echo(f"CVE scan completed: {len(result.findings)} vulnerabilities found")
            display_results(result, **kwargs)
        else:
            click.echo(f"CVE scan failed: {result.error_message}", err=True)
            
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

# Add to main CLI group
cli.add_command(cve)
```

### **Testing Custom Scanner**

```python
# 3. Create tests: tests/unit/test_cve_scanner.py

import pytest
from unittest.mock import Mock, patch, MagicMock
import json

from src.scanners.vulnerability.cve_scanner import CVEScanner
from src.core.scanner_base import ScanResult, SeverityLevel


class TestCVEScanner:
    """Test suite for CVE Scanner"""
    
    @pytest.fixture
    def scanner(self):
        return CVEScanner()
    
    @pytest.fixture
    def sample_services(self):
        return [
            {
                "name": "ssh",
                "version": "7.4",
                "product": "OpenSSH",
                "port": 22
            },
            {
                "name": "http",
                "version": "2.4.41",
                "product": "Apache",
                "port": 80
            }
        ]
    
    @pytest.fixture
    def sample_cve_response(self):
        return [
            {
                "id": "CVE-2021-1234",
                "summary": "Buffer overflow in OpenSSH 7.4",
                "cvss": 7.5,
                "Published": "2021-01-01",
                "Modified": "2021-01-15",
                "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-1234"]
            }
        ]
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly"""
        assert scanner.scanner_name == "cve_scanner"
        assert scanner.cve_api_base == "https://cve.circl.lu/api"
        assert scanner.session is not None
    
    def test_validate_target(self, scanner):
        """Test target validation"""
        assert scanner.validate_target("192.168.1.1") is True
        assert scanner.validate_target("example.com") is True
        assert scanner.validate_target("https://example.com") is True
        assert scanner.validate_target("invalid") is False
    
    def test_get_capabilities(self, scanner):
        """Test scanner capabilities"""
        capabilities = scanner.get_capabilities()
        
        assert isinstance(capabilities, dict)
        assert capabilities["name"] == "CVE Scanner"
        assert "cve_lookup" in capabilities["features"]
        assert "ip" in capabilities["supported_targets"]
    
    @patch('src.scanners.vulnerability.cve_scanner.requests.Session.get')
    def test_scan_with_services(self, mock_get, scanner, sample_services, sample_cve_response):
        """Test CVE scan with service information"""
        # Mock API response
        mock_response = Mock()
        mock_response.json.return_value = sample_cve_response
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        options = {
            "services": sample_services,
            "severity_filter": "medium"
        }
        
        result = scanner.scan("example.com", options)
        
        assert isinstance(result, ScanResult)
        assert result.success is True
        assert result.scanner_name == "cve_scanner"
        assert len(result.findings) > 0
        
        # Check finding structure
        finding = result.findings[0]
        assert "cve_id" in finding
        assert "cvss_score" in finding
        assert "severity" in finding
    
    def test_scan_without_services(self, scanner):
        """Test CVE scan without service information"""
        result = scanner.scan("example.com", {})
        
        assert result.success is True
        assert len(result.findings) == 0
        assert "No service information provided" in result.metadata["reason"]
    
    def test_cvss_to_severity_mapping(self, scanner):
        """Test CVSS score to severity conversion"""
        assert scanner._cvss_to_severity(9.5) == SeverityLevel.CRITICAL
        assert scanner._cvss_to_severity(7.8) == SeverityLevel.HIGH
        assert scanner._cvss_to_severity(5.2) == SeverityLevel.MEDIUM
        assert scanner._cvss_to_severity(2.1) == SeverityLevel.LOW
        assert scanner._cvss_to_severity(0.0) == SeverityLevel.INFO
    
    def test_search_terms_generation(self, scanner):
        """Test CVE search term generation"""
        terms = scanner._build_search_terms("ssh", "OpenSSH", "7.4")
        
        assert "OpenSSH 7.4" in terms
        assert "ssh 7.4" in terms
        assert "OpenSSH" in terms
    
    @patch('src.scanners.vulnerability.cve_scanner.requests.Session.get')
    def test_api_error_handling(self, mock_get, scanner, sample_services):
        """Test API error handling"""
        # Mock API failure
        mock_get.side_effect = requests.RequestException("API unavailable")
        
        options = {"services": sample_services}
        result = scanner.scan("example.com", options)
        
        # Should handle error gracefully
        assert result.success is True  # Scanner continues despite API errors
        assert len(result.findings) == 0
    
    def test_findings_filtering(self, scanner):
        """Test findings filtering by severity"""
        findings = [
            {"severity": "low", "cvss_score": 2.0},
            {"severity": "medium", "cvss_score": 5.0},
            {"severity": "high", "cvss_score": 8.0},
            {"severity": "critical", "cvss_score": 9.5}
        ]
        
        options = {"severity_filter": "medium"}
        filtered = scanner._filter_findings(findings, options)
        
        assert len(filtered) == 3  # medium, high, critical
        assert all(f["severity"] in ["medium", "high", "critical"] for f in filtered)
    
    def test_findings_sorting(self, scanner):
        """Test findings sorting by severity"""
        findings = [
            {"severity": "low", "cvss_score": 2.0},
            {"severity": "critical", "cvss_score": 9.5},
            {"severity": "medium", "cvss_score": 5.0},
            {"severity": "high", "cvss_score": 8.0}
        ]
        
        sorted_findings = scanner._sort_by_severity(findings)
        
        severities = [f["severity"] for f in sorted_findings]
        assert severities == ["critical", "high", "medium", "low"]
```

---

## 🚀 **Git Workflow & Contribution**

### **Branch Strategy**

```bash
# Git Flow Workflow

main                    # Production-ready code
├── develop             # Development integration branch
│   ├── feature/new-scanner     # Feature branches
│   ├── feature/api-endpoint    # Feature branches
│   ├── hotfix/critical-bug     # Hotfix branches
│   └── release/v0.10.0         # Release branches

# Branch Naming Conventions
feature/scanner-cve-integration
feature/api-authentication
bugfix/port-scanner-timeout
hotfix/critical-security-fix
release/v0.10.0
docs/api-documentation-update
```

### **Contribution Process**

```bash
# 1. Fork and Clone
git clone https://github.com/your-username/auto-pentest-framework.git
cd auto-pentest-framework

# 2. Setup Development Environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
pre-commit install

# 3. Create Feature Branch
git checkout develop
git pull origin develop
git checkout -b feature/your-feature-name

# 4. Make Changes and Commit
# ... make your changes ...
git add .
git commit -m "feat: add CVE scanner integration

- Implement CVE API integration
- Add severity mapping from CVSS scores  
- Include comprehensive test coverage
- Update documentation

Closes #123"

# 5. Push and Create Pull Request
git push origin feature/your-feature-name
# Create PR via GitHub interface

# 6. Address Review Comments
# ... make requested changes ...
git add .
git commit -m "fix: address review comments"
git push origin feature/your-feature-name

# 7. Merge and Cleanup
# After PR is merged
git checkout develop
git pull origin develop
git branch -d feature/your-feature-name
```

### **Commit Message Convention**

```bash
# Commit Message Format (Conventional Commits)

<type>[optional scope]: <description>

[optional body]

[optional footer(s)]

# Types:
feat:     # New feature
fix:      # Bug fix
docs:     # Documentation changes
style:    # Code style changes (formatting, etc.)
refactor: # Code refactoring
perf:     # Performance improvements
test:     # Adding or updating tests
chore:    # Maintenance tasks
ci:       # CI/CD changes
build:    # Build system changes

# Examples:
feat(scanner): add CVE vulnerability scanner
fix(port-scanner): resolve timeout handling issue
docs(api): update scanner development guide
test(cve-scanner): add comprehensive test coverage
refactor(orchestrator): improve error handling
perf(cache): optimize memory usage
```

### **Pull Request Template**

```markdown
## Pull Request Description

### Changes Made
- [ ] Feature/Bug fix description
- [ ] Documentation updates
- [ ] Test coverage improvements

### Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

### Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed
- [ ] All tests pass

### Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes

### Related Issues
Closes #(issue_number)

### Screenshots (if applicable)
<!-- Add screenshots here -->

### Additional Notes
<!-- Any additional information -->
```

---

## 📚 **Documentation Guidelines**

### **Documentation Standards**

```markdown
# Documentation Writing Guidelines

## 1. Structure
- Use clear hierarchical headings (H1, H2, H3)
- Include table of contents for long documents
- Provide quick start sections
- Include comprehensive examples

## 2. Code Documentation
- Document all public APIs
- Include parameter descriptions
- Provide return value information
- Add usage examples
- Document exceptions/errors

## 3. User Documentation
- Write for different skill levels
- Provide step-by-step instructions
- Include troubleshooting sections
- Add screenshots where helpful

## 4. API Documentation  
- Document all endpoints/methods
- Include request/response examples
- Provide authentication details
- Document error codes
- Include rate limiting information
```

### **Docstring Standards**

```python
# Google Style Docstrings (Required)

def scan_target(target: str, 
                options: Dict[str, Any], 
                timeout: int = 300) -> ScanResult:
    """
    Execute security scan against target.
    
    This function performs a comprehensive security scan using the specified
    options and returns structured results.
    
    Args:
        target: The target to scan (IP address, domain, or URL)
        options: Scan configuration options
            - ports: Port range to scan (default: "1-1000")
            - service_detection: Enable service detection (default: True)
            - scripts: NSE scripts to run (default: "default")
        timeout: Maximum scan duration in seconds (default: 300)
        
    Returns:
        ScanResult: Structured scan results containing:
            - findings: List of discovered vulnerabilities/services
            - metadata: Scan execution metadata
            - success: Boolean indicating scan success
            - execution_time: Time taken for scan completion
            
    Raises:
        ValidationError: If target format is invalid
        TimeoutError: If scan exceeds timeout duration
        ScannerError: If scanner execution fails
        
    Example:
        >>> scanner = PortScanner()
        >>> options = {"ports": "22,80,443", "service_detection": True}
        >>> result = scanner.scan("192.168.1.1", options)
        >>> print(f"Found {len(result.findings)} open ports")
        Found 3 open ports
        
    Note:
        This function requires appropriate system permissions for
        raw socket access when using SYN scanning techniques.
        
    See Also:
        validate_target(): Target validation function
        get_capabilities(): Scanner capability information
    """
    # Implementation here
    pass
```

### **README Structure**

```markdown
# Project README Template

# Auto-Pentest Framework

[![Build Status](badge-url)](build-url)
[![Coverage](badge-url)](coverage-url)
[![License](badge-url)](license-url)

Brief project description and value proposition.

## 🚀 Quick Start

```bash
# Installation commands
```

## 📋 Features

- Feature 1
- Feature 2  
- Feature 3

## 📖 Documentation

- [User Manual](docs/user_manual.md)
- [API Documentation](docs/api_documentation.md)
- [Development Guide](docs/development_guide.md)

## 🛠️ Installation

Detailed installation instructions...

## 💡 Usage Examples

Code examples and common use cases...

## 🤝 Contributing

Contribution guidelines and process...

## 📄 License

License information...
```

---

## 🔄 **Release Process**

### **Versioning Strategy**

```bash
# Semantic Versioning (SemVer)

MAJOR.MINOR.PATCH

# Examples:
0.9.1   # Current version
0.10.0  # Minor release (new features)
1.0.0   # Major release (breaking changes)
1.0.1   # Patch release (bug fixes)

# Pre-release versions:
1.0.0-alpha.1
1.0.0-beta.1
1.0.0-rc.1
```

### **Release Checklist**

```markdown
# Release Checklist Template

## Pre-Release
- [ ] All tests passing
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version numbers updated
- [ ] Security review completed
- [ ] Performance benchmarks verified

## Release Process
- [ ] Create release branch
- [ ] Final testing on release branch
- [ ] Tag release version
- [ ] Build release artifacts
- [ ] Create GitHub release
- [ ] Deploy to production (if applicable)

## Post-Release
- [ ] Verify release deployment
- [ ] Update documentation sites
- [ ] Announce release
- [ ] Monitor for issues
- [ ] Merge release branch back to develop
```

### **Automated Release Pipeline**

```yaml
# .github/workflows/release.yml

name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      - name: Run tests
        run: pytest --cov=src
      - name: Run security checks
        run: bandit -r src/

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build package
        run: python setup.py sdist bdist_wheel
      - name: Store artifacts
        uses: actions/upload-artifact@v3
        with:
          name: dist
          path: dist/

  release:
    needs: [test, build]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Download artifacts
        uses: actions/download-artifact@v3
        with:
          name: dist
          path: dist/
      - name: Create Release
        uses: actions/create-release@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          tag_name: ${{ github.ref }}
          release_name: Release ${{ github.ref }}
          draft: false
          prerelease: false
```

---

## 🐛 **Debugging & Performance**

### **Debugging Techniques**

```python
# Debugging Tools and Techniques

# 1. Logging for Debugging
import logging
from src.utils.logger import get_logger

logger = get_logger(__name__)

def debug_function():
    logger.debug("Starting function execution")
    logger.info(f"Processing target: {target}")
    
    try:
        result = complex_operation()
        logger.debug(f"Operation result: {result}")
    except Exception as e:
        logger.exception("Operation failed")
        raise

# 2. Interactive Debugging with PDB
import pdb

def problematic_function():
    pdb.set_trace()  # Debugger will stop here
    # ... rest of function

# 3. Advanced Debugging with pudb
import pudb

def visual_debug():
    pudb.set_trace()  # Full-screen visual debugger

# 4. Performance Debugging
import cProfile
import pstats

def profile_function():
    """Profile function performance"""
    pr = cProfile.Profile()
    pr.enable()
    
    # Code to profile
    result = expensive_operation()
    
    pr.disable()
    stats = pstats.Stats(pr)
    stats.sort_stats('cumulative')
    stats.print_stats(10)  # Top 10 functions

# 5. Memory Debugging
from memory_profiler import profile

@profile
def memory_intensive_function():
    """Function with memory profiling"""
    # Memory usage will be tracked line by line
    data = [i for i in range(1000000)]
    return data

# 6. Line Profiling
# Run with: kernprof -l -v your_script.py
@profile
def line_by_line_profile():
    """Line-by-line performance profiling"""
    for i in range(1000):
        expensive_computation(i)
```

### **Performance Optimization**

```python
# Performance Optimization Patterns

# 1. Caching Expensive Operations
from functools import lru_cache
from src.utils.cache import CacheManager

class OptimizedScanner:
    def __init__(self):
        self.cache = CacheManager()
    
    @lru_cache(maxsize=128)
    def expensive_computation(self, param):
        """Cache results in memory"""
        return complex_calculation(param)
    
    def cached_operation(self, key, computation_func):
        """Cache results persistently"""
        result = self.cache.get(key)
        if result is None:
            result = computation_func()
            self.cache.set(key, result, ttl=3600)
        return result

# 2. Batch Processing
def process_targets_batch(targets, batch_size=10):
    """Process targets in batches to reduce memory usage"""
    for i in range(0, len(targets), batch_size):
        batch = targets[i:i + batch_size]
        yield process_batch(batch)

# 3. Lazy Loading
class LazyDataLoader:
    def __init__(self, data_source):
        self._data_source = data_source
        self._data = None
    
    @property
    def data(self):
        if self._data is None:
            self._data = self._load_data()
        return self._data
    
    def _load_data(self):
        """Load data only when needed"""
        return expensive_data_loading(self._data_source)

# 4. Parallel Processing
import concurrent.futures
from multiprocessing import Pool

def parallel_processing(items, worker_func, max_workers=None):
    """Process items in parallel"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker_func, item) for item in items]
        results = [future.result() for future in futures]
    return results

def cpu_intensive_parallel(items):
    """CPU-intensive parallel processing"""
    with Pool() as pool:
        results = pool.map(cpu_worker_func, items)
    return results

# 5. Memory-Efficient Processing
def memory_efficient_scanner(large_dataset):
    """Process large datasets without loading everything into memory"""
    for chunk in chunk_iterator(large_dataset, chunk_size=1000):
        processed_chunk = process_chunk(chunk)
        yield processed_chunk
        # Chunk is automatically garbage collected

# 6. Network Optimization
import aiohttp
import asyncio

async def async_network_requests(urls):
    """Asynchronous network requests for better performance"""
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url(session, url) for url in urls]
        results = await asyncio.gather(*tasks)
    return results

async def fetch_url(session, url):
    async with session.get(url) as response:
        return await response.text()
```

### **Profiling & Monitoring**

```python
# Production Monitoring and Profiling

# 1. Application Performance Monitoring
import time
import psutil
from contextlib import contextmanager

@contextmanager
def performance_monitor(operation_name):
    """Monitor operation performance"""
    start_time = time.time()
    start_memory = psutil.Process().memory_info().rss
    
    try:
        yield
    finally:
        end_time = time.time()
        end_memory = psutil.Process().memory_info().rss
        
        duration = end_time - start_time
        memory_delta = end_memory - start_memory
        
        logger.info(f"Operation: {operation_name}")
        logger.info(f"Duration: {duration:.2f}s")
        logger.info(f"Memory delta: {memory_delta / 1024 / 1024:.2f}MB")

# Usage
with performance_monitor("port_scan"):
    result = port_scanner.scan(target)

# 2. Custom Metrics Collection
class MetricsCollector:
    def __init__(self):
        self.metrics = {}
    
    def increment_counter(self, metric_name):
        self.metrics[metric_name] = self.metrics.get(metric_name, 0) + 1
    
    def record_timing(self, metric_name, duration):
        if metric_name not in self.metrics:
            self.metrics[metric_name] = []
        self.metrics[metric_name].append(duration)
    
    def get_stats(self):
        return {
            name: {
                'count': len(values) if isinstance(values, list) else values,
                'avg': sum(values) / len(values) if isinstance(values, list) else None,
                'max': max(values) if isinstance(values, list) else None,
                'min': min(values) if isinstance(values, list) else None
            } for name, values in self.metrics.items()
        }

# 3. Health Checks
def system_health_check():
    """Comprehensive system health check"""
    health = {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'process_count': len(psutil.pids()),
        'network_connections': len(psutil.net_connections()),
    }
    
    # Check if any metrics exceed thresholds
    alerts = []
    if health['cpu_percent'] > 80:
        alerts.append("High CPU usage")
    if health['memory_percent'] > 85:
        alerts.append("High memory usage")
    if health['disk_usage'] > 90:
        alerts.append("High disk usage")
    
    health['alerts'] = alerts
    health['status'] = 'healthy' if not alerts else 'warning'
    
    return health
```

---

## 🎉 **Development Resources**

### **Useful Commands**

```bash
# Development Shortcuts (Makefile)

# Code Quality
make lint          # Run all linters
make format        # Format code with black
make type-check    # Run mypy type checking
make security      # Run security checks

# Testing
make test          # Run all tests
make test-unit     # Run only unit tests
make test-integration  # Run integration tests
make test-coverage # Run tests with coverage
make test-watch    # Run tests in watch mode

# Documentation
make docs          # Build documentation
make docs-serve    # Serve docs locally
make docs-clean    # Clean docs build

# Build & Release
make build         # Build package
make clean         # Clean build artifacts
make release       # Create release (with checks)

# Development
make setup         # Setup development environment
make install-dev   # Install development dependencies
make update-deps   # Update dependencies
```

### **IDE Extensions & Tools**

```json
// VS Code Extensions
{
  "recommendations": [
    "ms-python.python",
    "ms-python.pylint", 
    "ms-python.black-formatter",
    "ms-python.isort",
    "ms-python.mypy-type-checker",
    "ms-vscode.test-adapter-converter",
    "hbenl.vscode-test-explorer",
    "njpwerner.autodocstring",
    "ms-vscode.vscode-json",
    "redhat.vscode-yaml",
    "yzhang.markdown-all-in-one",
    "davidanson.vscode-markdownlint"
  ]
}
```

### **Learning Resources**

```markdown
# Recommended Learning Resources

## Python Development
- [Python Official Documentation](https://docs.python.org/)
- [Real Python Tutorials](https://realpython.com/)
- [Python Type Hints](https://mypy.readthedocs.io/)

## Security Tools
- [Nmap Documentation](https://nmap.org/docs.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CVE Database](https://cve.mitre.org/)

## Testing & Quality
- [Pytest Documentation](https://docs.pytest.org/)
- [Test-Driven Development](https://testdriven.io/)
- [Code Coverage Best Practices](https://coverage.readthedocs.io/)

## Architecture & Design
- [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [Python Design Patterns](https://python-patterns.guide/)
- [API Design Guidelines](https://restfulapi.net/)
```

---

**🎯 This development guide provides everything you need to contribute effectively to the Auto-Pentest Framework. Whether you're fixing bugs, adding features, or improving documentation, these guidelines will help you maintain code quality and consistency.**

**Happy coding! 🚀**