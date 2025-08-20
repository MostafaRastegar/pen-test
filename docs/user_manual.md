# Auto-Pentest Framework v0.9.6 - User Manual

## 📋 **Overview**

The Auto-Pentest Framework is a comprehensive security assessment platform that automates penetration testing workflows with enterprise-grade reporting. This manual covers all scanners and features available in version 0.9.6.

### **🎯 Complete Scanner Suite (100% Complete - 8/8 Scanners)**
- ✅ **Port Scanner** - Network reconnaissance and service discovery
- ✅ **DNS Scanner** - Domain name system analysis and enumeration  
- ✅ **Web Scanner** - Web application security assessment
- ✅ **Directory Scanner** - Hidden directory and file discovery
- ✅ **SSL Scanner** - SSL/TLS security analysis
- ✅ **WordPress Scanner** - CMS-specific vulnerability assessment
- ✅ **API Security Scanner** - REST/GraphQL API security testing
- ✅ **WAF Detection Engine** - Web Application Firewall detection and bypass testing
- ✅ **Network Vulnerability Scanner** - Advanced network vulnerability assessment using Nuclei

---

## 🚀 **Quick Start Guide**

### **Basic Installation**
```bash
# Clone repository
git clone <repository-url>
cd auto-pentest-framework

# Install dependencies
pip install -r requirements.txt

# Install Nuclei for network scanning
sudo apt install nuclei
# or download from: https://github.com/projectdiscovery/nuclei

# Verify installation
python main.py --version
```

### **First Scan**
```bash
# Basic reconnaissance
python main.py port 192.168.1.1

# Web application scan
python main.py web https://example.com

# Network vulnerability scan (NEW!)
python main.py network 192.168.1.1

# Complete assessment
python main.py scan example.com --profile full
```

---

## 🔍 **Scanner Documentation**

### **1. Port Scanner**
Network reconnaissance and service discovery using Nmap integration.

#### **Basic Usage**
```bash
# Basic port scan
python main.py port 192.168.1.1

# Custom port range
python main.py port 192.168.1.1 --ports 1-1000

# Service detection
python main.py port 192.168.1.1 --service-detection

# Operating system detection
python main.py port 192.168.1.1 --os-detection
```

#### **Advanced Options**
```bash
# Stealth scan
python main.py port 192.168.1.1 --stealth

# UDP scan
python main.py port 192.168.1.1 --udp

# Fast scan (top 100 ports)
python main.py port 192.168.1.1 --fast

# Comprehensive scan
python main.py port 192.168.1.1 --comprehensive
```

### **2. DNS Scanner**
Domain name system analysis and subdomain enumeration.

#### **Basic Usage**
```bash
# Basic DNS analysis
python main.py dns example.com

# Subdomain enumeration
python main.py dns example.com --subdomains

# DNS record analysis
python main.py dns example.com --records all
```

#### **Advanced Options**
```bash
# Zone transfer attempt
python main.py dns example.com --zone-transfer

# Reverse DNS lookup
python main.py dns 192.168.1.1 --reverse

# Custom DNS server
python main.py dns example.com --dns-server 8.8.8.8
```

### **3. Web Scanner**
Web application security assessment using Nikto and custom analysis.

#### **Basic Usage**
```bash
# Basic web scan
python main.py web https://example.com

# Include directory enumeration
python main.py web https://example.com --directory-enum

# SSL analysis included
python main.py web https://example.com --ssl-analysis
```

#### **Advanced Options**
```bash
# Custom user agent
python main.py web https://example.com --user-agent "Custom Scanner"

# Proxy support
python main.py web https://example.com --proxy http://proxy:8080

# Authentication
python main.py web https://example.com --auth-user admin --auth-pass password
```

### **4. Directory Scanner**
Hidden directory and file discovery using multiple tools.

#### **Basic Usage**
```bash
# Basic directory scan
python main.py directory https://example.com

# Specific wordlist
python main.py directory https://example.com --wordlist common

# File extensions
python main.py directory https://example.com --extensions php,asp,jsp
```

#### **Advanced Options**
```bash
# Multiple tools
python main.py directory https://example.com --tools dirb,gobuster

# Custom wordlist file
python main.py directory https://example.com --custom-wordlist /path/to/wordlist.txt

# Rate limiting
python main.py directory https://example.com --delay 1
```

### **5. SSL Scanner**
SSL/TLS security analysis and certificate validation.

#### **Basic Usage**
```bash
# Basic SSL scan
python main.py ssl example.com:443

# Certificate analysis
python main.py ssl example.com:443 --cert-analysis

# Cipher suite testing
python main.py ssl example.com:443 --cipher-testing
```

#### **Advanced Options**
```bash
# Vulnerability testing
python main.py ssl example.com:443 --vuln-testing

# Protocol testing
python main.py ssl example.com:443 --protocol-testing

# Compliance check
python main.py ssl example.com:443 --compliance pci
```

### **6. WordPress Scanner**
Comprehensive WordPress CMS security assessment.

#### **Basic Usage**
```bash
# Basic WordPress scan
python main.py wordpress https://wordpress-site.com

# Plugin security analysis
python main.py wordpress https://wordpress-site.com --plugin-check

# Theme security analysis
python main.py wordpress https://wordpress-site.com --theme-check
```

#### **Advanced Options**
```bash
# Complete WordPress assessment
python main.py wordpress https://wordpress-site.com --plugin-check --theme-check --user-enum --brute-force-test

# With WPScan API token
python main.py wordpress https://wordpress-site.com --wpscan-api-token YOUR_TOKEN

# Timeout adjustment
python main.py wordpress https://wordpress-site.com --timeout 600
```

### **7. API Security Scanner**
REST and GraphQL API security testing with OWASP API Top 10 coverage.

#### **Basic Usage**
```bash
# Basic API scan
python main.py api https://api.example.com

# GraphQL testing
python main.py api https://api.example.com/graphql --graphql-test

# JWT analysis
python main.py api https://api.example.com --jwt-analysis
```

#### **Advanced Options**
```bash
# Complete API assessment
python main.py api https://api.example.com --rate-limit-test --graphql-test --jwt-analysis --owasp-only

# With authentication
python main.py api https://api.example.com --auth-header "Bearer TOKEN"

# Swagger/OpenAPI testing
python main.py api https://api.example.com --swagger-url https://api.example.com/swagger.json
```

### **8. WAF Detection Engine**
Web Application Firewall detection and bypass testing.

#### **Basic Usage**
```bash
# Basic WAF detection
python main.py waf https://example.com

# Quick detection mode
python main.py waf https://example.com --quick

# Detection only (no bypass testing)
python main.py waf https://example.com --detection-only
```

#### **Advanced Options**
```bash
# Aggressive testing with bypass attempts
python main.py waf https://example.com --aggressive

# Complete WAF assessment with all reports
python main.py waf https://example.com --aggressive --all-reports

# Custom timeout
python main.py waf https://example.com --timeout 600
```

### **9. Network Vulnerability Scanner** 🆕
Advanced network vulnerability assessment using Nuclei templates.

#### **Basic Usage**
```bash
# Basic network vulnerability scan
python main.py network 192.168.1.1

# Critical vulnerabilities only
python main.py network 192.168.1.1 --templates critical

# High and critical severity
python main.py network 192.168.1.1 --templates high
```

#### **Advanced Options**
```bash
# Complete network assessment with all severity levels
python main.py network 192.168.1.1 --templates all --service-analysis --protocol-analysis

# Custom rate limiting
python main.py network 192.168.1.1 --rate-limit 100

# Custom template path
python main.py network 192.168.1.1 --templates custom --template-path /path/to/templates

# Extended timeout for large scans
python main.py network 192.168.1.1 --timeout 1200

# With comprehensive reporting
python main.py network 192.168.1.1 --templates high --all-reports --output-dir ~/network-reports
```

#### **Template Options**
- **`critical`** - Only critical severity vulnerabilities
- **`high`** - High and critical severity  
- **`medium`** - Medium, high, and critical (default)
- **`all`** - All templates regardless of severity
- **`custom`** - Use custom template path

#### **Network Scanner Features**
- **🎯 Nuclei Integration** - Uses latest Nuclei templates (5000+ templates)
- **🔍 CVE Detection** - Comprehensive CVE vulnerability scanning
- **🌐 Protocol Support** - HTTP, HTTPS, TCP, UDP protocols
- **⚡ Rate Limiting** - Configurable request rate (default: 150/sec)
- **📊 Detailed Reporting** - JSON, HTML, and PDF reports
- **🎲 Service Analysis** - Network service security assessment
- **🔧 Custom Templates** - Support for custom Nuclei templates

---

## 📊 **Report Generation**

### **Individual Scanner Reports**
```bash
# JSON report
python main.py network 192.168.1.1 --json-report

# HTML report  
python main.py network 192.168.1.1 --html-report

# PDF report
python main.py network 192.168.1.1 --pdf-report

# All report formats
python main.py network 192.168.1.1 --all-reports

# Custom output directory
python main.py network 192.168.1.1 --all-reports --output-dir ~/security-reports
```

### **Orchestrated Scan Reports**
```bash
# Complete assessment with all scanners
python main.py scan example.com --profile full --all-reports

# Custom scanner selection
python main.py scan example.com --include-network --include-web --include-ssl --html-report
```

### **Report Types**

#### **1. Raw JSON Data**
- Complete scan results in JSON format
- Suitable for automation and integration
- Contains all technical details

#### **2. Formatted JSON Report**
- Structured report with summary statistics
- Severity breakdown and risk analysis
- Machine-readable format

#### **3. HTML Report**
- Professional, web-viewable report
- Interactive severity charts
- Responsive design for all devices
- Suitable for stakeholder review

#### **4. PDF Report**
- Print-ready professional report
- Executive summary included
- Suitable for compliance documentation
- Requires weasyprint or wkhtmltopdf

---

## 🔧 **Installation Requirements**

### **Core Dependencies**
```bash
# Network & Web Security Tools
- nmap (Network scanning)
- nikto (Web vulnerability scanning)  
- dirb/gobuster (Directory enumeration)
- sslscan (SSL/TLS analysis)
- nuclei (Network vulnerability scanning) ⭐ NEW

# CMS Security Tools
- wpscan (WordPress security scanner)

# Python Libraries
- requests, dnspython, click, rich
- weasyprint (PDF generation - optional)
```

### **Nuclei Installation** 🆕
```bash
# Method 1: APT (Recommended for Debian/Ubuntu)
sudo apt update && sudo apt install nuclei

# Method 2: Direct download
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.4.6_linux_amd64.zip
unzip nuclei_3.4.6_linux_amd64.zip
sudo mv nuclei /usr/local/bin/

# Method 3: Go install (if Go is installed)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Method 4: Snap
sudo snap install nuclei

# Verify installation
nuclei -version

# Update templates
nuclei -update-templates
```

---

## 🎯 **Best Practices**

### **Network Vulnerability Scanning**
1. **Start with Critical** - Begin with `--templates critical` for high-priority issues
2. **Rate Limiting** - Use appropriate `--rate-limit` to avoid overwhelming targets
3. **Template Updates** - Regularly update Nuclei templates: `nuclei -update-templates`
4. **Custom Templates** - Create custom templates for organization-specific checks
5. **Report Everything** - Use `--all-reports` for comprehensive documentation

### **Responsible Scanning**
1. **Authorization** - Only scan systems you own or have explicit permission to test
2. **Rate Limiting** - Use conservative rate limits to avoid service disruption
3. **Time Windows** - Perform scans during appropriate maintenance windows
4. **Monitoring** - Monitor target systems during scans for any issues
5. **Documentation** - Document all findings and remediation steps

### **Performance Optimization**
1. **Template Selection** - Use specific severity levels rather than `--templates all`
2. **Timeout Management** - Adjust `--timeout` based on network conditions
3. **Parallel Scanning** - Use orchestrated scans for multiple targets
4. **Cache Management** - Clear cache regularly with `python main.py clear-cache`

---

## 🏆 **Advanced Usage Examples**

### **Complete Infrastructure Assessment**
```bash
# Network discovery and vulnerability assessment
python main.py port 192.168.1.0/24 --fast
python main.py network 192.168.1.1-254 --templates high --all-reports

# Web application security testing
python main.py web https://app.example.com --directory-enum --ssl-analysis
python main.py waf https://app.example.com --aggressive
python main.py api https://api.example.com --graphql-test --jwt-analysis

# CMS-specific testing
python main.py wordpress https://blog.example.com --plugin-check --theme-check --user-enum
```

### **Compliance Scanning**
```bash
# PCI DSS compliance scanning
python main.py scan payment.example.com --include-ssl --include-network --include-web --compliance pci

# OWASP Top 10 assessment
python main.py api https://api.example.com --owasp-only --all-reports
python main.py web https://app.example.com --owasp-testing --html-report
```

### **Automated Security Monitoring**
```bash
# Daily vulnerability checks
python main.py network production-server.com --templates critical --json-report --output-dir /var/log/security/

# Weekly comprehensive assessment
python main.py scan production-environment.com --profile full --all-reports --output-dir /reports/weekly/
```

---

## 🔍 **Troubleshooting**

### **Network Scanner Issues**
```bash
# Check Nuclei installation
nuclei -version
which nuclei

# Update templates
nuclei -update-templates

# Test Nuclei directly
nuclei -target https://httpbin.org/get -templates info

# Check scanner availability
python main.py network --help
```

### **Common Issues**
1. **"Nuclei not found"** - Install Nuclei using methods above
2. **"No templates found"** - Run `nuclei -update-templates`
3. **"Connection timeout"** - Increase `--timeout` value
4. **"Rate limited"** - Decrease `--rate-limit` value
5. **"Permission denied"** - Check network permissions and firewall rules

### **Report Generation Issues**
1. **PDF generation fails** - Install weasyprint: `pip install weasyprint`
2. **Large reports** - Use `--output-dir` with sufficient disk space
3. **Special characters** - Reports use UTF-8 encoding automatically

---

## 📞 **Support**

### **Getting Help**
```bash
# Framework help
python main.py --help

# Scanner-specific help
python main.py network --help
python main.py api --help

# Check versions
python main.py version

# List available tools
python main.py list-tools
```

### **Logging and Debugging**
```bash
# Verbose output
python main.py network 192.168.1.1 --verbose

# Debug mode
python main.py network 192.168.1.1 --debug

# Check logs
tail -f output/logs/pentest.log
```

---

## 🎉 **Conclusion**

The Auto-Pentest Framework v0.9.6 now provides a complete security assessment platform with 8 specialized scanners, including the powerful new Network Vulnerability Scanner. The framework offers enterprise-grade reporting, comprehensive coverage of security assessment needs, and professional documentation suitable for compliance and stakeholder communication.

For advanced usage, integration scenarios, and development information, please refer to the Development Guide and API Documentation.

**Framework Statistics:**
- **8 Active Scanners** (100% Complete)
- **5000+ Nuclei Templates** for network vulnerability detection
- **Multiple Report Formats** (JSON, HTML, PDF)
- **Enterprise Ready** with professional reporting
- **Compliance Support** (PCI DSS, OWASP, NIST)