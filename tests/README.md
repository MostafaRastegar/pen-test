# Auto-Pentest Framework - Test Suite

## 🎯 Overview

This directory contains a comprehensive test suite for the Auto-Pentest Framework, covering all major components with safe, fast, and reliable tests.

## 📋 Test Files

### Core Framework Tests
- **`test_core_framework.py`** - Foundation components (ScannerBase, CommandExecutor, Validator)

### Scanner Tests  
- **`test_port_scanner.py`** - Network port scanning and service detection
- **`test_dns_scanner.py`** - DNS enumeration and security analysis
- **`test_web_scanner.py`** - Web application vulnerability scanning  
- **`test_directory_scanner.py`** - Directory and file enumeration
- **`test_ssl_scanner.py`** - SSL/TLS security assessment

### System Tests
- **`test_orchestrator_safe.py`** - Workflow management and execution
- **`test_cli_interface.py`** - Command line interface testing
- **`test_reporter.py`** - Report generation and formatting

### Utilities
- **`test_suite_summary.py`** - Test suite overview and health check
- **`run_tests_fast.py`** - Fast test execution script

## 🚀 Quick Start

### 1. Health Check
```bash
python tests/test_suite_summary.py
```

### 2. Quick Tests (30 seconds)
```bash
python run_tests_fast.py quick
```

### 3. Full Test Suite (2-3 minutes)
```bash
python run_tests_fast.py parallel
```

## 🎛️ Execution Options

### Fast Test Runner
```bash
# Core tests only
python run_tests_fast.py quick

# All tests in parallel  
python run_tests_fast.py parallel

# Specific component
python run_tests_fast.py orchestrator
python run_tests_fast.py cli
python run_tests_fast.py reporter

# Single test file
python run_tests_fast.py single test_core_framework.py

# All tests sequential
python run_tests_fast.py all
```

### Direct Execution
```bash
# Individual test
python tests/test_core_framework.py

# With pytest
python -m pytest tests/test_core_framework.py -v

# All tests with pytest
python -m pytest tests/ -v
```

### Parallel Execution
```bash
# Install pytest-xdist first
pip install pytest-xdist

# Run in parallel
python -m pytest tests/ -n auto
python -m pytest tests/ -n 4
```

## 📊 Test Features

### 🛡️ Safe Testing
- All tests use mocks and dry-runs
- No real network scanning performed
- No external dependencies required for core tests
- Safe for CI/CD environments

### ⚡ Performance Optimized
- Fast execution with mock implementations
- Parallel test execution support
- Optimized timeout values
- Minimal resource usage

### 🔧 Flexible Architecture
- Tests work with or without real components
- Graceful fallback to mock implementations
- Optional dependency handling
- Cross-platform compatibility

### 📝 Comprehensive Coverage
- Unit tests for all components
- Integration tests for workflows
- Error handling and edge cases
- CLI interface testing
- Report generation testing

## 🔍 Test Categories

### Unit Tests
- Individual component testing
- Mock-based isolated testing
- Fast execution (< 1 minute total)

### Integration Tests
- Component interaction testing
- Workflow orchestration
- End-to-end CLI testing
- Report generation pipeline

### Performance Tests
- Parallel vs sequential execution
- Resource usage validation
- Timeout handling
- Concurrent operation testing

## 📦 Dependencies

### Required
- Python 3.7+
- Standard library modules (unittest, pathlib, subprocess)

### Recommended
```bash
pip install pytest pytest-xdist rich
```

### Optional (for enhanced features)
```bash
pip install jinja2 weasyprint coverage
```

## 🔧 Test Configuration

### Environment Variables
```bash
# Optional: Set test timeout
export TEST_TIMEOUT=60

# Optional: Enable debug mode
export TEST_DEBUG=1

# Optional: Specify test output directory
export TEST_OUTPUT_DIR=./test_output
```

### Custom Configuration
Create `tests/config.json` for custom settings:
```json
{
  "timeout": 30,
  "parallel_workers": 4,
  "output_dir": "./test_output",
  "verbose": true
}
```

## 🐛 Troubleshooting

### Common Issues

#### Import Errors
```bash
# Ensure you're in the project root
cd /path/to/auto-pentest-framework
python tests/test_core_framework.py
```

#### Module Not Found
```bash
# Check Python path
python -c "import sys; print(sys.path)"

# Run with explicit path
PYTHONPATH=. python tests/test_core_framework.py
```

#### Timeout Issues
```bash
# Run with longer timeout
python run_tests_fast.py quick --timeout 60

# Or run individual tests
python tests/test_core_framework.py
```

#### Permission Errors
```bash
# Ensure write permissions for test output
chmod 755 tests/
mkdir -p output/tests/
```

### Test Failures

#### Mock-related Failures
- Tests use mock implementations when real components aren't available
- This is expected and doesn't indicate system issues
- Focus on logic and structure validation

#### Timeout Failures
- Increase timeout values in test configuration
- Check system performance and load
- Consider running tests individually

#### Import Failures
- Verify project structure and Python path
- Check for missing dependencies
- Use mock implementations as fallback

## 📈 Continuous Integration

### GitHub Actions Example
```yaml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: 3.8
      - run: pip install pytest pytest-xdist
      - run: python run_tests_fast.py parallel
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Test') {
            steps {
                sh 'python run_tests_fast.py parallel'
            }
        }
    }
}
```

## 📊 Coverage Analysis

### Generate Coverage Report
```bash
# Install coverage
pip install coverage

# Run with coverage
python -m pytest tests/ --cov=src --cov-report=html

# View report
open htmlcov/index.html
```

### Coverage Targets
- Core Framework: > 95%
- Scanners: > 90%
- CLI Interface: > 85%
- Reporter: > 90%
- Overall: > 90%

## 🤝 Contributing

### Adding New Tests
1. Follow naming convention: `test_component_name.py`
2. Use existing patterns and mock implementations
3. Include both positive and negative test cases
4. Add timeout protection for long-running tests
5. Update `run_tests_fast.py` with new test file

### Test Best Practices
- Keep tests fast and focused
- Use descriptive test names
- Include error condition testing
- Mock external dependencies
- Provide clear failure messages
- Follow DRY principles

### Review Checklist
- [ ] Tests are fast (< 30s per file)
- [ ] No external network calls
- [ ] Proper error handling
- [ ] Cross-platform compatibility
- [ ] Clear documentation
- [ ] Mock implementations for missing components

## 📞 Support

For questions or issues:
1. Check this README
2. Run `python tests/test_suite_summary.py`
3. Review test output and logs
4. Check project documentation
5. Create an issue with test output

---

**Happy Testing! 🎯**