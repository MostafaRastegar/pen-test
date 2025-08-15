# Auto-Pentest Framework - Installation Guide


### **📋 System Requirements**

#### **Core Dependencies**
```bash
# Network & Web Security Tools
- nmap (Network scanning)
- nikto (Web vulnerability scanning)  
- dirb/gobuster (Directory enumeration)
- sslscan (SSL/TLS analysis)

# NEW Phase 1.1: CMS Security
- wpscan (WordPress security scanner) ⭐
```

#### **Python Requirements**
- Python 3.8+ (3.9+ recommended)
- Virtual environment (recommended)
- PDF generation libraries (optional but recommended)

---

## 🔧 **Quick Installation**

### **Option 1: Automated Installation (Recommended)**
```bash
# Clone the repository
git clone <repository-url>
cd auto-pentest-framework

# Run automated installer
chmod +x install_dependencies.sh
./install_dependencies.sh

# Verify installation
python3 verify_installation.py
```

### **Option 2: Manual Installation**

#### **Ubuntu/Debian**
```bash
# Update packages
sudo apt update

# Install core security tools
sudo apt install -y nmap nikto dirb gobuster sslscan dnsutils

# Install WPScan (NEW - Phase 1.1)
sudo apt install -y wpscan
# OR install via Ruby gem if apt version not available:
# sudo apt install -y ruby ruby-dev && gem install wpscan

# Install PDF generation dependencies (optional)
sudo apt install -y python3-dev libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libfribidi0 libfontconfig1

# Install Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Install PDF support (optional)
pip install weasyprint
```

#### **CentOS/RHEL/Fedora**
```bash
# Install core tools
sudo dnf install -y nmap nikto dirb gobuster sslscan bind-utils

# Install WPScan via Ruby
sudo dnf install -y ruby ruby-devel gcc make
gem install wpscan

# Install Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install weasyprint
```

#### **macOS**
```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install security tools
brew install nmap nikto dirb gobuster sslscan wpscan

# Install Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install weasyprint
```

---

## 🔍 **WordPress Scanner Setup**

### **WPScan API Token (Recommended)**

For enhanced vulnerability detection, get a free API token:

1. **Register** at [https://wpscan.com/api](https://wpscan.com/api)
2. **Get your token** (free tier: 25 requests/day)
3. **Set environment variable**:
   ```bash
   export WPSCAN_API_TOKEN="your_api_token_here"
   
   # Make it permanent
   echo 'export WPSCAN_API_TOKEN="your_api_token_here"' >> ~/.bashrc
   source ~/.bashrc
   ```

### **Verify WPScan Installation**
```bash
# Check if WPScan is installed
wpscan --version

# Test basic functionality
wpscan --help

# Test with a WordPress site (with API token)
wpscan --url https://wordpress.org --api-token $WPSCAN_API_TOKEN
```

---

## 📚 **Usage Examples**

### **Basic WordPress Scan**
```bash
# Simple WordPress scan
python3 main.py wordpress example.com

# WordPress scan with all report formats
python3 main.py wordpress example.com --all-reports

# WordPress scan with WPScan API token
python3 main.py wordpress example.com --wpscan-api-token YOUR_TOKEN --all-reports
```

### **Advanced WordPress Scanning**
```bash
# Comprehensive WordPress security assessment
python3 main.py wordpress https://blog.example.com \
  --enumerate-plugins \
  --enumerate-themes \
  --enumerate-users \
  --wpscan-api-token YOUR_TOKEN \
  --all-reports

# Quick enumeration without WPScan
python3 main.py wordpress example.com \
  --no-use-wpscan \
  --html-report

# Custom port and scheme
python3 main.py wordpress example.com \
  --scheme http \
  --port 8080 \
  --pdf-report
```

### **Report Generation**
```bash
# Generate specific report formats
python3 main.py wordpress example.com --json-report
python3 main.py wordpress example.com --html-report  
python3 main.py wordpress example.com --pdf-report
python3 main.py wordpress example.com --all-reports

# Custom output directory
python3 main.py wordpress example.com \
  --all-reports \
  --output-dir /path/to/reports
```

---

## 🔧 **Troubleshooting**

### **WPScan Installation Issues**

#### **Problem: `wpscan: command not found`**
```bash
# Solution 1: Install via apt (Ubuntu/Debian)
sudo apt update && sudo apt install wpscan

# Solution 2: Install via Ruby gem
sudo apt install ruby ruby-dev
gem install wpscan

# Solution 3: Add gem binary to PATH
echo 'export PATH="$HOME/.gem/ruby/$(ruby -e "puts RUBY_VERSION")/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### **Problem: WPScan permission errors**
```bash
# Install for current user only
gem install --user-install wpscan

# Or use system-wide installation
sudo gem install wpscan
```

#### **Problem: WPScan API issues**
```bash
# Test API connectivity
curl -H "Authorization: Token YOUR_API_TOKEN" https://wpscan.com/api/v3/status

# Verify token is set
echo $WPSCAN_API_TOKEN

# Set token temporarily
export WPSCAN_API_TOKEN="your_token"
```

### **PDF Generation Issues**

#### **Problem: PDF generation fails**
```bash
# Install WeasyPrint dependencies (Ubuntu/Debian)
sudo apt install python3-dev libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libfribidi0 libfontconfig1
pip install weasyprint

# Alternative: Use PDFKit
sudo apt install wkhtmltopdf
pip install pdfkit
```

### **General Troubleshooting**
```bash
# Run comprehensive verification
python3 verify_installation.py

# Check individual components
python3 -c "from src.scanners.cms.wordpress_scanner import WordPressScanner; print('✓ WordPress scanner OK')"

# Test CLI integration
python3 main.py wordpress --help

# Check logs for detailed error information
python3 main.py wordpress example.com --debug
```

---

## 🐳 **Docker Support**

### **Using Docker for WPScan**
```bash
# Pull WPScan Docker image
docker pull wpscanteam/wpscan

# Use with framework (if WPScan not installed locally)
docker run -it --rm wpscanteam/wpscan --url https://example.com --enumerate p,t,u
```

### **Framework Docker Build**
```dockerfile
FROM python:3.9-slim

# Install system dependencies including WPScan
RUN apt-get update && apt-get install -y \
    nmap nikto dirb gobuster sslscan dnsutils \
    ruby ruby-dev gcc make \
    && gem install wpscan \
    && apt-get clean

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
ENTRYPOINT ["python", "main.py"]
```

---

## ✅ **Verification Checklist**

Before using the WordPress scanner, ensure:

- [ ] **WPScan installed**: `wpscan --version` works
- [ ] **Python dependencies**: `pip install -r requirements.txt` completed
- [ ] **Project structure**: `python3 verify_installation.py` passes
- [ ] **CLI integration**: `python3 main.py wordpress --help` shows options
- [ ] **API token configured**: `echo $WPSCAN_API_TOKEN` shows your token
- [ ] **PDF generation**: At least one PDF library installed (weasyprint/pdfkit)

---

## 🎯 **What's New in Phase 1.1**

### **WordPress Security Scanner Features**
- ✅ **WordPress Detection**: Intelligent WordPress installation detection
- ✅ **Version Fingerprinting**: WordPress version identification and vulnerability assessment
- ✅ **Plugin Enumeration**: Discovery and security analysis of WordPress plugins
- ✅ **Theme Analysis**: WordPress theme enumeration and security evaluation
- ✅ **User Enumeration**: WordPress user discovery using multiple techniques
- ✅ **WPScan Integration**: Full integration with WPScan vulnerability database
- ✅ **Security Configuration**: Analysis of WordPress security settings
- ✅ **XML-RPC Testing**: XML-RPC endpoint security assessment
- ✅ **Professional Reporting**: Multi-format reports (HTML, PDF, JSON, TXT)

### **Enhanced CLI Interface**
```bash
# New WordPress-specific command
python3 main.py wordpress TARGET [OPTIONS]

# Enhanced reporting options
--html-report    # Generate HTML report
--pdf-report     # Generate PDF report  
--all-reports    # Generate all formats
--json-report    # Generate JSON report (default)
```

### **Framework Improvements**
- ✅ **Scanner Registry**: Dynamic scanner discovery and management
- ✅ **Workflow Integration**: WordPress scanner integrated into orchestration engine
- ✅ **Enhanced Error Handling**: Improved error reporting and recovery
- ✅ **Configuration Management**: WPScan configuration in tools_config.yaml
- ✅ **Comprehensive Testing**: Full test suite for WordPress scanner

---

## 🔮 **Coming Next: Phase 1.2**

The next phase will include:
- **Drupal Scanner**: Comprehensive Drupal security assessment
- **Joomla Scanner**: Joomla vulnerability detection and analysis
- **CMS Auto-Detection**: Intelligent CMS identification
- **Enhanced Workflows**: Multi-CMS scanning workflows

---

## 🆘 **Getting Help**

If you encounter issues:

1. **Run verification**: `python3 verify_installation.py`
2. **Check logs**: Enable debug mode with `--debug` flag
3. **Update tools**: Ensure all security tools are up to date
4. **Check dependencies**: Verify all required packages are installed
5. **API token**: Ensure WPScan API token is properly configured

For detailed troubleshooting, check the logs in `output/logs/` directory.