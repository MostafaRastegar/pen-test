# Auto-Pentest Tool - Installation and Setup Guide

## 🚀 Complete Installation Guide for Linux

This guide will walk you through setting up the Auto-Pentest tool on a fresh Linux system.

### 📋 System Requirements

- **Operating System**: Ubuntu 18.04+ / Debian 9+ / CentOS 7+ / Fedora 30+
- **Python**: 3.8 or higher
- **RAM**: Minimum 2GB (4GB recommended)
- **Disk Space**: At least 1GB free space
- **Network**: Internet connection for tool downloads

### 🛠️ Step 1: Update System and Install Prerequisites

```bash
# Update package lists
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y git python3 python3-pip python3-venv curl wget

# Verify Python version (should be 3.8+)
python3 --version
```

### 🔧 Step 2: Install Required Security Tools

```bash
# Install network and security tools
sudo apt install -y \
    nmap \
    nikto \
    sqlmap \
    dirb \
    dnsutils \
    whois \
    sslscan \
    gobuster

# Optional: Additional tools for enhanced functionality
sudo apt install -y \
    masscan \
    wfuzz \
    subfinder

# Verify nmap installation (critical for port scanning)
nmap --version

# Verify dig installation (critical for DNS scanning)
dig -v
```

### 📁 Step 3: Download and Setup Project

```bash
# Create project directory
mkdir -p ~/security-tools
cd ~/security-tools

# Clone or create project structure
mkdir auto-pentest
cd auto-pentest

# Create the directory structure
mkdir -p {src/{core,scanners/{recon,vulnerability,exploit},utils,orchestrator},config,tests/{core,unit,integration},output/{logs,reports,raw},templates}

# We'll create all files in the next steps
```

### 🐍 Step 4: Setup Python Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python DNS library (required for DNS scanning)
pip install dnspython
```

### 📝 Step 5: Create Project Files

Now we need to create all the project files. Let me provide you with a setup script:

**Create setup script: `setup_project.sh`**

```bash
#!/bin/bash

echo "🚀 Setting up Auto-Pentest Tool..."

# Create requirements.txt
cat > requirements.txt << 'EOF'
# Core dependencies
click>=8.0.0
pyyaml>=6.0
python-dotenv>=0.19.0
colorama>=0.4.4
rich>=12.0.0

# DNS scanning
dnspython>=2.1.0

# Web requests
requests>=2.25.0
urllib3>=1.26.0

# Data processing
pandas>=1.3.0
jinja2>=3.0.0

# Validation
validators>=0.18.0

# Testing
pytest>=7.0.0
pytest-cov>=3.0.0

# Linting & Formatting
black>=22.0.0
flake8>=4.0.0
EOF

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Create .env file
cat > .env << 'EOF'
# General Settings
DEBUG=False
LOG_LEVEL=INFO
OUTPUT_DIR=./output

# Scan Settings
MAX_THREADS=10
TIMEOUT=30
RATE_LIMIT=100

# Tool Paths (auto-detected)
NMAP_PATH=nmap
SQLMAP_PATH=sqlmap
NIKTO_PATH=nikto
DIRB_PATH=dirb
EOF

# Create .gitignore
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
build/
dist/
*.egg-info/
.pytest_cache/

# Project specific
output/
*.log
.env
*.db
*.sqlite

# IDE
.vscode/
.idea/
*.swp
*.swo
.DS_Store
EOF

echo "✅ Project structure created successfully!"
echo "📁 Current directory: $(pwd)"
echo "🔧 Next: Copy the source code files manually or run the project files creation"
```

### 🎯 Step 6: Run Setup Script

```bash
# Make setup script executable
chmod +x setup_project.sh

# Run setup script
./setup_project.sh
```

### 📄 Step 7: Create Core Project Files

You need to create these files with the content from our previous development:

1. **Core Module Files** (copy content from artifacts):
   - `src/core/__init__.py`
   - `src/core/scanner_base.py`
   - `src/core/executor.py`
   - `src/core/validator.py`

2. **Utility Files**:
   - `src/utils/__init__.py`
   - `src/utils/logger.py`

3. **Scanner Files**:
   - `src/scanners/__init__.py`
   - `src/scanners/recon/__init__.py`
   - `src/scanners/recon/port_scanner.py`
   - `src/scanners/recon/dns_scanner.py`

4. **Configuration Files**:
   - `config/__init__.py`
   - `config/settings.py`
   - `config/tools_config.yaml`

5. **Main CLI File**:
   - `main.py`

6. **Test Files**:
   - `tests/__init__.py`
   - `tests/core/test_core.py`
   - `tests/test_port_scanner.py`
   - `tests/test_dns_scanner.py`
   - `test_project.py`

### 🧪 Step 8: Quick Installation Verification

Create a quick test script to verify installation:

**Create `verify_installation.py`:**

```python
#!/usr/bin/env python3
"""
Quick installation verification script
"""

import sys
import subprocess
from pathlib import Path

def check_python_version():
    """Check Python version"""
    version = sys.version_info
    if version >= (3, 8):
        print(f"✅ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"❌ Python version too old: {version.major}.{version.minor}")
        return False

def check_dependencies():
    """Check Python dependencies"""
    required_packages = [
        'click', 'rich', 'dnspython', 'requests', 
        'pyyaml', 'colorama', 'validators'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package} (missing)")
            missing.append(package)
    
    return len(missing) == 0

def check_system_tools():
    """Check system tools"""
    tools = ['nmap', 'dig', 'nslookup']
    
    all_good = True
    for tool in tools:
        result = subprocess.run(['which', tool], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {tool}: {result.stdout.strip()}")
        else:
            print(f"❌ {tool}: not found")
            all_good = False
    
    return all_good

def check_project_structure():
    """Check project files"""
    required_files = [
        'main.py',
        'requirements.txt',
        'src/core/scanner_base.py',
        'src/core/executor.py',
        'src/utils/logger.py',
        'config/settings.py'
    ]
    
    missing = []
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} (missing)")
            missing.append(file_path)
    
    return len(missing) == 0

def main():
    """Main verification function"""
    print("🔍 Auto-Pentest Installation Verification")
    print("=" * 50)
    
    checks = [
        ("Python Version", check_python_version),
        ("Python Dependencies", check_dependencies),
        ("System Tools", check_system_tools),
        ("Project Structure", check_project_structure)
    ]
    
    all_passed = True
    for check_name, check_func in checks:
        print(f"\n{check_name}:")
        if not check_func():
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 All checks passed! Installation successful!")
        print("\nNext steps:")
        print("1. python main.py --help")
        print("2. python main.py list-tools")
        print("3. python main.py scan 127.0.0.1")
    else:
        print("❌ Some checks failed. Please fix the issues above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

### 🚀 Step 9: Test Basic Functionality

```bash
# Activate virtual environment if not already active
source venv/bin/activate

# Run installation verification
python verify_installation.py

# Test help command
python main.py --help

# Check tool availability
python main.py list-tools

# Test info command
python main.py info
```

### 🎯 Step 10: Run First Scans

```bash
# Test port scan on localhost
python main.py scan 127.0.0.1 --ports 22,80,443

# Test DNS enumeration
python main.py dns google.com

# Test combined scan
python main.py scan google.com --include-dns

# Run comprehensive test suite
python test_project.py
```

### 🐛 Step 11: Troubleshooting Common Issues

#### Issue 1: Python Version Too Old
```bash
# Install Python 3.8+ on Ubuntu 18.04
sudo apt install software-properties-common
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.8 python3.8-venv python3.8-dev
python3.8 -m venv venv
```

#### Issue 2: nmap Permission Denied
```bash
# For some scan types, nmap needs root privileges
sudo python main.py scan 192.168.1.1

# Or configure nmap capabilities (advanced)
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
```

#### Issue 3: DNS Resolution Issues
```bash
# Test DNS manually
dig google.com
nslookup google.com

# Check /etc/resolv.conf
cat /etc/resolv.conf
```

#### Issue 4: Missing Python Dependencies
```bash
# Reinstall requirements
pip install --upgrade -r requirements.txt

# Install specific missing package
pip install dnspython
```

#### Issue 5: Import Errors
```bash
# Check Python path
python -c "import sys; print(sys.path)"

# Add src to Python path (if needed)
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```

### 📊 Step 12: Performance Test

Create a performance test script:

**Create `performance_test.py`:**

```python
#!/usr/bin/env python3
"""
Performance test for Auto-Pentest Tool
"""

import time
import subprocess
import sys

def time_command(cmd):
    """Time a command execution"""
    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    duration = time.time() - start
    
    return {
        'duration': duration,
        'success': result.returncode == 0,
        'output_length': len(result.stdout)
    }

def main():
    """Run performance tests"""
    print("⚡ Auto-Pentest Performance Test")
    print("=" * 40)
    
    tests = [
        {
            'name': 'Help Command',
            'cmd': ['python', 'main.py', '--help'],
            'expected_max': 2.0
        },
        {
            'name': 'Tool Check',
            'cmd': ['python', 'main.py', 'list-tools'],
            'expected_max': 5.0
        },
        {
            'name': 'Quick Port Scan',
            'cmd': ['python', 'main.py', 'scan', '127.0.0.1', '--ports', '22,80,443'],
            'expected_max': 30.0
        },
        {
            'name': 'DNS Basic Scan',
            'cmd': ['python', 'main.py', 'dns', 'google.com'],
            'expected_max': 15.0
        }
    ]
    
    all_passed = True
    
    for test in tests:
        print(f"\n🔍 Testing: {test['name']}")
        result = time_command(test['cmd'])
        
        status = "✅" if result['success'] else "❌"
        time_status = "✅" if result['duration'] <= test['expected_max'] else "⚠️"
        
        print(f"  {status} Success: {result['success']}")
        print(f"  {time_status} Duration: {result['duration']:.2f}s (max: {test['expected_max']}s)")
        print(f"  📄 Output: {result['output_length']} characters")
        
        if not result['success'] or result['duration'] > test['expected_max']:
            all_passed = False
    
    print("\n" + "=" * 40)
    if all_passed:
        print("🎉 All performance tests passed!")
    else:
        print("⚠️ Some tests failed or were slow")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
```

### 🎯 Step 13: Final Verification

```bash
# Run all tests
echo "🧪 Running final verification..."

# 1. Basic functionality
python verify_installation.py

# 2. Performance test
python performance_test.py

# 3. Unit tests (if files are created)
python -m pytest tests/ -v || echo "Unit tests not available yet"

# 4. Integration test
python test_project.py || echo "Integration tests not available yet"

echo "✅ Verification complete!"
```

### 📝 Step 14: Quick Reference Commands

Once everything is set up, here are the most useful commands:

```bash
# Activate environment (always run this first)
source venv/bin/activate

# Quick commands
python main.py scan 192.168.1.1              # Port scan
python main.py dns example.com                # DNS scan
python main.py scan example.com --include-dns # Combined scan
python main.py list-tools                     # Check tools
python main.py info                          # Show info

# Advanced commands
python main.py scan target.com --profile full # Full scan
python main.py dns target.com --zone-transfer # DNS with zone transfer
python main.py scan target.com --output results.json # Save results
```

### 🎉 Success Indicators

Your installation is successful if:

1. ✅ `python main.py --help` shows the help menu
2. ✅ `python main.py list-tools` shows tools with checkmarks
3. ✅ `python main.py scan 127.0.0.1` completes without errors
4. ✅ `python main.py dns google.com` shows DNS records
5. ✅ Results are saved in `output/reports/` directory

### 🆘 Getting Help

If you encounter issues:

1. **Check the logs**: `tail -f output/logs/*.log`
2. **Run with debug**: `python main.py --debug scan target`
3. **Verify tools**: `python main.py list-tools`
4. **Check Python path**: `python -c "import sys; print(sys.path)"`

---

**Next Steps After Installation:**
1. Copy all source code files from our development session
2. Run verification tests
3. Test with real targets (with permission!)
4. Explore advanced features

**Remember**: Only scan targets you own or have explicit permission to test!