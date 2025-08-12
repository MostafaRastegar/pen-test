# Auto-Pentest Tool - Enhanced Installation Guide

## 📋 Prerequisites

### System Requirements
- **Python**: 3.8 or higher
- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, Debian 10+), macOS, Windows 10+
- **RAM**: Minimum 4GB, Recommended 8GB+
- **Disk Space**: 2GB for installation + space for reports
- **Network**: Internet connection for initial setup and scanning

### Required System Tools

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y nmap nikto dirb gobuster sslscan dnsutils openssl wget curl git

# CentOS/RHEL/Fedora
sudo yum install -y nmap nikto dirb gobuster sslscan bind-utils openssl wget curl git
# OR for newer versions:
sudo dnf install -y nmap nikto dirb gobuster sslscan bind-utils openssl wget curl git

# macOS (using Homebrew)
brew install nmap nikto dirb gobuster sslscan dig openssl wget curl git

# Arch Linux
sudo pacman -S nmap nikto dirb gobuster sslscan bind-tools openssl wget curl git
```

## 🚀 Quick Installation (Recommended)

### Step 1: Download and Setup
```bash
# Clone or download the project
git clone <repository-url> auto-pentest-tool
cd auto-pentest-tool

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 2: PDF Support Setup

**Option A: WeasyPrint (Recommended)**
```bash
# Ubuntu/Debian
sudo apt install -y python3-dev python3-pip libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
pip install weasyprint

# macOS
brew install pango
pip install weasyprint

# Windows (may require additional setup)
pip install weasyprint
```

**Option B: PDFKit (Alternative)**
```bash
# Install wkhtmltopdf first
# Ubuntu/Debian
sudo apt install -y wkhtmltopdf
pip install pdfkit

# macOS
brew install --cask wkhtmltopdf
pip install pdfkit

# CentOS/RHEL
sudo yum install -y wkhtmltopdf
pip install pdfkit
```

### Step 3: Verify Installation
```bash
# Run verification script
python verify_installation.py

# Test basic functionality
python main.py --help
python main.py list-tools
python main.py info
```

## 📦 Detailed Installation Steps

### Step 1: Environment Setup

**Create Project Directory:**
```bash
mkdir auto-pentest-tool
cd auto-pentest-tool
```

**Setup Python Virtual Environment:**
```bash
# Using venv (recommended)
python3 -m venv venv
source venv/bin/activate

# Or using virtualenv
pip install virtualenv
virtualenv venv
source venv/bin/activate

# Or using conda
conda create -n auto-pentest python=3.9
conda activate auto-pentest
```

### Step 2: Dependencies Installation

**Core Python Dependencies:**
```bash
# Install from requirements.txt
pip install -r requirements.txt

# Or install manually
pip install click>=8.0.0 pyyaml>=6.0 python-dotenv>=0.19.0 colorama>=0.4.4 rich>=12.0.0
pip install dnspython>=2.1.0 requests>=2.25.0 urllib3>=1.26.0 pandas>=1.3.0 jinja2>=3.0.0
pip install validators>=0.18.0 pytest>=7.0.0 pytest-cov>=3.0.0
```

**PDF Generation Dependencies:**
```bash
# Choose one of the following:

# Option 1: WeasyPrint (Better CSS support, easier to install)
pip install weasyprint>=60.0

# Option 2: PDFKit (Requires wkhtmltopdf system package)
pip install pdfkit>=1.0.0

# Optional: Chart generation for advanced reports
pip install plotly>=5.0.0 matplotlib>=3.5.0
```

### Step 3: System Tools Installation

**Security Tools:**
```bash
# Essential tools
sudo apt install -y nmap nikto dirb gobuster sslscan

# DNS tools
sudo apt install -y dnsutils bind9-dnsutils

# Additional tools (optional)
sudo apt install -y masscan wfuzz sqlmap subfinder amass
```

**PDF Generation System Dependencies:**

For WeasyPrint:
```bash
# Ubuntu/Debian
sudo apt install -y python3-dev libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libfribidi0 libfontconfig1

# CentOS/RHEL
sudo yum install -y python3-devel pango harfbuzz fribidi fontconfig

# macOS
brew install pango harfbuzz fribidi fontconfig
```

For PDFKit:
```bash
# Ubuntu/Debian
sudo apt install -y wkhtmltopdf

# CentOS/RHEL
sudo yum install -y wkhtmltopdf

# macOS
brew install --cask wkhtmltopdf
```

### Step 4: Project Structure Setup

**Create Directory Structure:**
```bash
mkdir -p {src/{core,scanners/{recon,vulnerability},utils,orchestrator},config,templates,output/{logs,reports,raw},tests/{unit,integration,fixtures}}
```

**Create Configuration Files:**
```bash
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
NIKTO_PATH=nikto
DIRB_PATH=dirb
GOBUSTER_PATH=gobuster
SSLSCAN_PATH=sslscan
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
custom_branding.json

# IDE
.vscode/
.idea/
*.swp
*.swo
.DS_Store

# Reports
reports/
*.pdf
*.html
EOF
```

### Step 5: Test Installation

**Basic Tests:**
```bash
# Test Python version
python --version

# Test core dependencies
python -c "import click, rich, dnspython, requests, jinja2; print('✓ Core dependencies OK')"

# Test PDF dependencies
python -c "import weasyprint; print('✓ WeasyPrint OK')" 2>/dev/null || echo "⚠ WeasyPrint not available"
python -c "import pdfkit; print('✓ PDFKit OK')" 2>/dev/null || echo "⚠ PDFKit not available"

# Test system tools
which nmap && echo "✓ nmap available" || echo "✗ nmap missing"
which nikto && echo "✓ nikto available" || echo "✗ nikto missing"
which dirb && echo "✓ dirb available" || echo "✗ dirb missing"
```

**Comprehensive Verification:**
```bash
# Run full verification
python verify_installation.py

# Test CLI interface
python main.py --help
python main.py list-tools
python main.py info
```

### Step 6: First Test Run

**Basic Functionality Test:**
```bash
# Test port scan
python main.py scan 127.0.0.1 --include-port --ports 22,80,443

# Test with HTML report
python main.py scan 127.0.0.1 --include-port --html-report

# Test with PDF report (if PDF support installed)
python main.py scan 127.0.0.1 --include-port --pdf-report

# Test all reports
python main.py scan scanme.nmap.org --profile quick --all-reports
```

## 🔧 Advanced Configuration

### Custom Branding Setup

**Create Custom Branding File:**
```bash
cp custom_branding_example.json my_company_branding.json
# Edit the file with your company details

# Use custom branding
python main.py scan target.com --custom-branding my_company_branding.json --pdf-report
```

### Performance Tuning

**For High-Performance Scanning:**
```bash
# Increase system limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize Python
export PYTHONOPTIMIZE=1
export PYTHONDONTWRITEBYTECODE=1

# Use parallel scanning
python main.py scan target.com --profile full --parallel
```

### Docker Installation (Optional)

**Create Dockerfile:**
```dockerfile
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    nmap nikto dirb gobuster sslscan dnsutils \\
    python3-dev libpango-1.0-0 libharfbuzz0b \\
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app
WORKDIR /app

# Install Python dependencies
RUN pip install -r requirements.txt

# Run application
ENTRYPOINT ["python", "main.py"]
```

**Build and Run:**
```bash
docker build -t auto-pentest .
docker run -v $(pwd)/output:/app/output auto-pentest scan target.com --all-reports
```

## 🐛 Troubleshooting

### Common Issues and Solutions

**1. PDF Generation Fails**
```bash
# Check PDF dependencies
python -c "import weasyprint" 2>/dev/null && echo "WeasyPrint OK" || echo "WeasyPrint missing"
python -c "import pdfkit" 2>/dev/null && echo "PDFKit OK" || echo "PDFKit missing"

# Install missing dependencies
pip install weasyprint  # OR pip install pdfkit

# System dependencies for WeasyPrint
sudo apt install -y libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
```

**2. Permission Denied Errors**
```bash
# For nmap raw socket scanning
sudo python main.py scan target.com

# Or set capabilities (Linux only)
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

**3. DNS Resolution Issues**
```bash
# Test DNS manually
dig google.com
nslookup google.com

# Check system DNS
cat /etc/resolv.conf

# Use custom DNS server
python main.py dns target.com --dns-server 8.8.8.8
```

**4. Import Errors**
```bash
# Add project to Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Or use development install
pip install -e .
```

**5. Tool Not Found Errors**
```bash
# Check tool availability
python main.py list-tools

# Install missing tools
sudo apt install -y <missing-tool>

# Use custom tool paths
export NMAP_PATH=/usr/local/bin/nmap
```

### Performance Issues

**Memory Usage:**
```bash
# Monitor memory usage during scans
python main.py scan target.com --profile full &
top -p $!

# Reduce thread count if needed
python main.py scan target.com --profile full --max-threads 5
```

**Timeout Issues:**
```bash
# Increase timeouts for slow networks
python main.py scan target.com --timeout 600

# Use sequential scanning for stability
python main.py scan target.com --profile full --sequential
```

## 📊 Usage Examples

### Basic Scanning
```bash
# Quick scan with all reports
python main.py quick target.com

# Full scan with parallel execution
python main.py full target.com

# Custom scan with specific components
python main.py scan target.com --include-web --include-ssl --pdf-report
```

### Advanced Reporting
```bash
# Generate PDF report with custom branding
python main.py scan target.com --pdf-report --custom-branding company.json

# Compliance report
python main.py scan target.com --compliance-report pci_dss

# All report formats
python main.py scan target.com --all-reports

# Generate reports from existing results
python main.py generate-report scan_results.json --pdf --html
```

### Integration Examples
```bash
# CI/CD pipeline
python main.py scan $TARGET --profile web --json-output results.json
python main.py generate-report results.json --pdf --output-dir ./reports

# Scheduled scanning
0 2 * * * cd /path/to/auto-pentest && python main.py scan target.com --all-reports
```

## ✅ Verification Checklist

- [ ] Python 3.8+ installed
- [ ] Virtual environment created and activated
- [ ] All Python dependencies installed (`pip list`)
- [ ] System tools available (`python main.py list-tools`)
- [ ] PDF generation working (`python -c "import weasyprint"`)
- [ ] Basic scan successful (`python main.py scan 127.0.0.1`)
- [ ] Reports generating (`--html-report --pdf-report`)
- [ ] No permission errors
- [ ] Output directory writable

## 🎯 Next Steps

1. **Read the Documentation**: Check project documentation for detailed usage
2. **Run Test Scans**: Start with safe targets like `scanme.nmap.org`
3. **Customize Configuration**: Adapt settings for your environment
4. **Setup Automation**: Create scripts for regular scanning
5. **Explore Advanced Features**: Try compliance reports and custom branding

## 📞 Support

If you encounter issues:
1. Check this troubleshooting guide
2. Run `python verify_installation.py` for diagnostics
3. Review logs in `output/logs/`
4. Check system requirements and dependencies
5. Consult project documentation

**System Information for Support:**
```bash
# Gather system info for troubleshooting
python --version
pip freeze | grep -E "(weasyprint|pdfkit|jinja2|click|rich)"
python main.py list-tools
uname -a
```