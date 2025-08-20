# Auto-Pentest Framework v0.9.6 - Installation Guide
**Phase 2.3: Network Vulnerability Scanner Integration Complete**

## 📋 **System Requirements**

### **Core Dependencies**
```bash
# Network & Web Security Tools
- nmap (Network scanning)
- nikto (Web vulnerability scanning)  
- dirb/gobuster (Directory enumeration)
- sslscan (SSL/TLS analysis)

# Phase 1.1: CMS Security
- wpscan (WordPress security scanner) ⭐

# Phase 2.3: Network Vulnerability Assessment
- nuclei (Vulnerability scanner with templates) 🚀
```

### **Python Requirements**
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

# Verify installation including new Network Scanner
python3 verify_installation.py
```

### **Option 2: Manual Installation**

#### **Ubuntu/Debian**
```bash
# Update packages
sudo apt update

# Install core security tools
sudo apt install -y nmap nikto dirb gobuster sslscan dnsutils

# Install WPScan (Phase 1.1)
sudo apt install -y wpscan
# OR install via Ruby gem if apt version not available:
# sudo apt install -y ruby ruby-dev && gem install wpscan

# 🚀 NEW: Install Nuclei (Phase 2.3) - Multiple options:

# Option A: Install from APT (if available)
sudo apt install -y nuclei

# Option B: Install via Snap
sudo snap install nuclei

# Option C: Download binary directly (recommended)
cd /tmp
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.1.0_linux_amd64.zip
unzip nuclei_3.1.0_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
sudo chmod +x /usr/local/bin/nuclei

# Option D: Install via Go (if Go is installed)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install Nuclei templates
nuclei -update-templates

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

# 🚀 Install Nuclei (Phase 2.3)
# Download binary
cd /tmp
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.1.0_linux_amd64.zip
unzip nuclei_3.1.0_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
sudo chmod +x /usr/local/bin/nuclei

# Install templates
nuclei -update-templates

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

# 🚀 Install Nuclei (Phase 2.3)
brew install nuclei

# Update templates
nuclei -update-templates

# Install Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install weasyprint
```

#### **Kali Linux**
```bash
# Most tools are pre-installed, just update
sudo apt update && sudo apt upgrade

# Install missing tools if needed
sudo apt install -y nuclei wpscan

# Update Nuclei templates
nuclei -update-templates

# Python setup
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install weasyprint
```

---

## 🚀 **Phase 2.3: Network Vulnerability Scanner Setup**

### **Nuclei Installation Verification**
```bash
# Check Nuclei installation
nuclei -version

# Update templates to latest version
nuclei -update-templates

# List available templates (optional)
nuclei -templates-list | head -20

# Test Nuclei with a safe target
nuclei -target https://httpbin.org/get -severity info
```

### **Network Scanner Configuration**
```bash
# Verify Network Scanner integration
python3 main.py network --help

# Test Network Scanner functionality
python3 main.py network https://httpbin.org --templates info --verbose

# Check scanner availability
python3 main.py info
```

---

## 🔍 **WordPress Scanner Setup (Phase 1.1)**

### **WPScan API Token (Recommended)**

For enhanced vulnerability detection, get a free API token:

1. **Register** at [https://wpscan.com/api](https://wpscan.com/api)
2. **Get your token** (free tier: 25 requests/day)
3. **Configure the token:**
   ```bash
   # Option 1: Environment variable
   export WPSCAN_API_TOKEN=your_api_token_here
   
   # Option 2: Use with command
   python3 main.py wordpress example.com --wpscan-api-token your_token
   ```

### **WPScan Verification**
```bash
# Test WPScan installation
wpscan --version

# Update WPScan database
wpscan --update

# Test with framework
python3 main.py wordpress --help
```

---

## 🧪 **Installation Verification**

### **Complete System Test**
```bash
# Run comprehensive verification
python3 verify_installation.py

# Test all scanner components
python3 main.py info

# Test individual scanners
python3 main.py port 127.0.0.1 --ports 22,80,443
python3 main.py dns google.com
python3 main.py web https://httpbin.org/get
python3 main.py ssl https://badssl.com

# 🚀 NEW: Test Network Vulnerability Scanner
python3 main.py network https://httpbin.org --templates critical
python3 main.py network 127.0.0.1 --templates info --verbose

# Test WordPress scanner (if WordPress target available)
python3 main.py wordpress https://wpscanteam.com --plugin-check

# Test report generation
python3 main.py network https://httpbin.org --all-reports --output-dir test-reports
```

### **Quick Scanner Test**
```bash
# Quick functionality test
python3 main.py scan 127.0.0.1 --include-port --ports 22,80,443 --json-report

# Verify all scanners are available
python3 -c "
from src.scanners import SCANNER_REGISTRY
print('📊 Available Scanners:')
for name, scanner in SCANNER_REGISTRY.items():
    print(f'  ✅ {name}: {scanner.__name__}')
print(f'📈 Total: {len(SCANNER_REGISTRY)} scanners')
"
```

---

## 🎯 **Feature Verification by Phase**

### **Phase 1: Core Features**
```bash
# Port Scanner
python3 main.py port 127.0.0.1 --ports 22,80,443 --verbose

# DNS Scanner  
python3 main.py dns google.com --verbose

# Web Scanner
python3 main.py web https://httpbin.org/get --verbose

# Directory Scanner
python3 main.py directory https://httpbin.org --tool dirb --verbose

# SSL Scanner
python3 main.py ssl https://badssl.com --verbose
```

### **Phase 1.1: CMS Security**
```bash
# WordPress Scanner (requires WordPress target)
python3 main.py wordpress https://wpscanteam.com --plugin-check --theme-check --verbose
```

### **Phase 2.1: API Security** 
```bash
# API Security Scanner
python3 main.py api https://httpbin.org --owasp-only --verbose
```

### **Phase 2.2: WAF Detection**
```bash
# WAF Scanner
python3 main.py waf https://httpbin.org --detection-only --verbose
```

### **🚀 Phase 2.3: Network Vulnerability Assessment**
```bash
# Network Vulnerability Scanner - Basic
python3 main.py network https://httpbin.org --templates critical --verbose

# Network Scanner - Advanced
python3 main.py network 127.0.0.1 --templates high --service-analysis --protocol-analysis

# Network Scanner - All templates (comprehensive)
python3 main.py network httpbin.org --templates all --rate-limit 100 --timeout 300

# Network Scanner with full reporting
python3 main.py network httpbin.org --templates medium --all-reports --output-dir network-reports
```

---

## 📊 **Report Generation Verification**

### **Test All Report Formats**
```bash
# JSON Reports
python3 main.py network httpbin.org --json-report

# HTML Reports
python3 main.py network httpbin.org --html-report

# PDF Reports (requires weasyprint)
python3 main.py network httpbin.org --pdf-report

# All Report Formats
python3 main.py network httpbin.org --all-reports --output-dir comprehensive-reports

# Custom Output Directory
python3 main.py network httpbin.org --all-reports --output-dir ~/security-reports/$(date +%Y%m%d)
```

---

## 🐛 **Troubleshooting**

### **Nuclei Installation Issues**

#### **Nuclei Not Found**
```bash
# Check if nuclei is in PATH
which nuclei
whereis nuclei

# Manual installation
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.1.0_linux_amd64.zip
unzip nuclei_3.1.0_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
sudo chmod +x /usr/local/bin/nuclei

# Add to PATH if needed
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
source ~/.bashrc
```

#### **Template Issues**
```bash
# Update templates manually
nuclei -update-templates

# Check templates directory
ls -la ~/.config/nuclei/

# Force template download
rm -rf ~/.config/nuclei/nuclei-templates
nuclei -update-templates

# Test with specific template
nuclei -target https://httpbin.org/get -t ~/.config/nuclei/nuclei-templates/http/technologies/
```

#### **Permission Issues**
```bash
# Fix nuclei permissions
sudo chmod +x $(which nuclei)

# Fix template directory permissions
sudo chown -R $USER:$USER ~/.config/nuclei/

# Run with explicit path
/usr/bin/nuclei -target https://httpbin.org/get -severity info
```

### **Network Scanner Specific Issues**

#### **Scanner Not Available**
```bash
# Check Network Scanner import
python3 -c "from src.scanners.vulnerability.network_scanner import NetworkScanner; print('✅ Network Scanner OK')"

# Check CLI integration
python3 main.py network --help

# Check in scanner registry
python3 -c "from src.scanners import SCANNER_REGISTRY; print('network' in SCANNER_REGISTRY)"
```

#### **Nuclei Command Issues**
```bash
# Test nuclei directly
nuclei -target https://httpbin.org/get -severity critical -j -silent

# Check nuclei version compatibility
nuclei -version

# Test with framework debugging
python3 main.py network httpbin.org --templates critical --verbose --debug
```

### **PDF Generation Issues**
```bash
# Install WeasyPrint dependencies (Ubuntu/Debian)
sudo apt install python3-dev libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libfribidi0 libfontconfig1
pip install weasyprint

# Alternative: Use PDFKit
sudo apt install wkhtmltopdf
pip install pdfkit

# Test PDF generation
python3 -c "import weasyprint; print('✅ WeasyPrint OK')" 2>/dev/null || echo "❌ WeasyPrint missing"
```

### **General Troubleshooting**
```bash
# Run comprehensive verification
python3 verify_installation.py

# Check individual components
python3 -c "from src.scanners.vulnerability.network_scanner import NetworkScanner; print('✓ Network scanner OK')"

# Test CLI integration
python3 main.py network --help

# Check logs for detailed error information
python3 main.py network httpbin.org --debug --verbose
```

---

## 🐳 **Docker Support**

### **Using Docker for Nuclei**
```bash
# Pull Nuclei Docker image
docker pull projectdiscovery/nuclei

# Use with framework (if Nuclei not installed locally)
docker run -it --rm projectdiscovery/nuclei -target https://httpbin.org/get -severity critical
```

### **Framework Docker Build**
```dockerfile
FROM python:3.9-slim

# Install system dependencies including Nuclei
RUN apt-get update && apt-get install -y \
    nmap nikto dirb gobuster sslscan dnsutils \
    ruby ruby-dev gcc make wget unzip \
    && gem install wpscan \
    && wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.1.0_linux_amd64.zip \
    && unzip nuclei_3.1.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && nuclei -update-templates \
    && apt-get clean

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install weasyprint

COPY . .
RUN python verify_installation.py

# Test all scanners
RUN python main.py info

ENTRYPOINT ["python", "main.py"]
```

### **Docker Compose for Development**
```yaml
version: '3.8'
services:
  auto-pentest:
    build: .
    volumes:
      - ./output:/app/output
      - ./reports:/app/reports
    environment:
      - DEBUG=True
      - OUTPUT_DIR=/app/output
    command: network httpbin.org --all-reports --output-dir /app/reports
```

---

## 🚀 **Production Deployment Considerations**

### **System Resources**
```bash
# Recommended minimum resources for Network Scanner:
# - CPU: 4+ cores (Nuclei can be CPU intensive)
# - RAM: 8GB+ (for large template sets)
# - Disk: 10GB+ (for templates and reports)
# - Network: Stable internet for template updates

# Monitor resource usage during scans
htop
iotop
```

### **Template Management**
```bash
# Regular template updates (add to cron)
0 2 * * * /usr/local/bin/nuclei -update-templates >/dev/null 2>&1

# Custom template directory
export NUCLEI_TEMPLATES_DIR=/opt/custom-nuclei-templates
nuclei -t $NUCLEI_TEMPLATES_DIR -target example.com
```

### **Security Considerations**
```bash
# Run framework in restricted environment
# Limit network access for scanning targets only
# Use dedicated scanning user account
sudo useradd -m -s /bin/bash pentest-user
sudo usermod -aG docker pentest-user  # if using Docker

# Restrict outbound connections (example with iptables)
sudo iptables -A OUTPUT -p tcp --dport 80,443,22,53 -j ACCEPT
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -j DROP
```

---

## 📈 **Performance Optimization**

### **Nuclei Performance Tuning**
```bash
# Optimize for faster scans
python3 main.py network target.com \
    --templates critical \
    --rate-limit 200 \
    --timeout 5 \
    --service-analysis

# Optimize for thoroughness
python3 main.py network target.com \
    --templates all \
    --rate-limit 50 \
    --timeout 30 \
    --service-analysis \
    --protocol-analysis
```

### **System Optimization**
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize network settings
echo 'net.core.rmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## 🎯 **Next Steps**

### **After Installation**
1. **Read User Manual**: `docs/user_manual.md`
2. **Review Available Scanners**: `python3 main.py info`
3. **Test with Safe Targets**: Use `httpbin.org`, `scanme.nmap.org`
4. **Configure Branding**: Set up custom reports
5. **Set up Templates**: Customize Nuclei templates for your needs
6. **Schedule Regular Updates**: Set up cron jobs for template updates

### **Advanced Configuration**
1. **Custom Templates**: Create organization-specific Nuclei templates
2. **Integration**: Set up API integrations and webhooks
3. **Automation**: Configure CI/CD pipeline integration
4. **Monitoring**: Set up performance and health monitoring
5. **Scaling**: Configure distributed scanning capabilities

---

## 📞 **Support**

### **Getting Help**
- **Documentation**: `docs/` directory
- **Troubleshooting**: `docs/troubleshooting_guide.md`
- **User Manual**: `docs/user_manual.md`
- **API Reference**: `docs/api_documentation.md`

### **Common Commands**
```bash
# Quick help
python3 main.py --help
python3 main.py network --help

# System information
python3 main.py info
python3 verify_installation.py

# Test installation
python3 main.py network httpbin.org --templates info --verbose
```

**Auto-Pentest Framework v0.9.6 with Network Vulnerability Scanner is now ready for production use!** 🚀🎉