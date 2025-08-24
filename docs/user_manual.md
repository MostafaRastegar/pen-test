# Auto-Pentest Framework v0.9.6 - User Manual

## 📋 **Overview**

The Auto-Pentest Framework is a comprehensive security assessment platform that automates penetration testing workflows with enterprise-grade reporting. This manual covers all scanners and features available in version 0.9.6.

### **🎯 Complete Scanner Suite (100% Complete - 9/9 Scanners)**
- ✅ **Port Scanner** - Network reconnaissance and service discovery
- ✅ **DNS Scanner** - Domain name system analysis and enumeration  
- ✅ **Web Scanner** - Web application security assessment
- ✅ **Directory Scanner** - Hidden directory and file discovery
- ✅ **SSL Scanner** - SSL/TLS security analysis
- ✅ **WordPress Scanner** - CMS-specific vulnerability assessment
- ✅ **API Security Scanner** - REST/GraphQL API security testing
- ✅ **WAF Detection Engine** - Web Application Firewall detection and bypass testing
- ✅ **Network Vulnerability Scanner** - Advanced network vulnerability assessment using Nuclei
- 🆕 **OSINT & Information Gathering** - Open Source Intelligence collection and analysis

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

# Install OSINT tools (optional - for enhanced functionality)
sudo apt install theharvester whois

# Verify installation
python main.py --version
```

### **First Scan**
```bash
# Basic reconnaissance
python main.py port 192.168.1.1

# Web application scan
python main.py web https://example.com

# Network vulnerability scan
python main.py network 192.168.1.1

# OSINT information gathering (NEW!)
python main.py osint example.com

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
python main.py wordpress https://blog.example.com

# Plugin enumeration
python main.py wordpress https://blog.example.com --plugin-check

# Theme analysis
python main.py wordpress https://blog.example.com --theme-check
```

#### **Advanced Options**
```bash
# User enumeration
python main.py wordpress https://blog.example.com --user-enum

# Vulnerability database check
python main.py wordpress https://blog.example.com --vuln-check

# Brute force protection test
python main.py wordpress https://blog.example.com --brute-check
```

### **7. API Security Scanner**
REST and GraphQL API security testing.

#### **Basic Usage**
```bash
# Basic API scan
python main.py api https://api.example.com

# Swagger/OpenAPI analysis
python main.py api https://api.example.com --swagger-url /api/docs

# GraphQL testing
python main.py api https://api.example.com/graphql --graphql-test
```

#### **Advanced Options**
```bash
# JWT security testing
python main.py api https://api.example.com --jwt-analysis

# CORS testing
python main.py api https://api.example.com --cors-test

# Rate limiting analysis
python main.py api https://api.example.com --rate-limit-test
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

### **9. Network Vulnerability Scanner**
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

### **10. OSINT & Information Gathering** 🆕
Comprehensive Open Source Intelligence collection and analysis using free sources.

#### **Basic Usage**
```bash
# Basic OSINT gathering
python main.py osint example.com

# Email harvesting only
python main.py osint email example.com

# Search engine reconnaissance
python main.py osint search example.com

# WHOIS analysis
python main.py osint whois example.com
```

#### **Advanced Options**
```bash
# Comprehensive OSINT scan
python main.py osint comprehensive example.com --include-all --save-evidence

# Email harvesting with validation
python main.py osint email example.com --validate-emails --limit 200 --html-report

# Search reconnaissance with specific sources
python main.py osint search example.com --sources google,bing --social-media --html-report

# WHOIS analysis with historical data
python main.py osint whois example.com --historical-data --save-raw --all-reports

# Rate-limited comprehensive scan
python main.py osint comprehensive example.com --rate-limit 2 --timeout 120 --all-reports
```

#### **OSINT Commands**

##### **Email Harvesting**
```bash
# Basic email harvesting
python main.py osint email example.com

# With specific sources
python main.py osint email example.com --sources theharvester

# With validation and limits
python main.py osint email example.com --validate-emails --limit 50 --json-report
```

##### **Search Engine Reconnaissance**
```bash
# Search engine dorking
python main.py osint search example.com

# Social media discovery
python main.py osint search example.com --social-media --limit 100

# Specific search patterns
python main.py osint search example.com --patterns "filetype:pdf,site:" --html-report
```

##### **WHOIS Analysis**
```bash
# Enhanced WHOIS analysis
python main.py osint whois example.com

# With geolocation data
python main.py osint whois example.com --geolocation --json-report

# Historical WHOIS records
python main.py osint whois example.com --historical --save-raw --txt-report
```

##### **Comprehensive OSINT**
```bash
# Complete OSINT assessment
python main.py osint comprehensive example.com

# All techniques with evidence saving
python main.py osint comprehensive example.com --include-all --save-evidence --all-reports

# Custom rate limiting and timeout
python main.py osint comprehensive example.com --rate-limit 1 --timeout 300 --html-report
```

##### **Service Information**
```bash
# OSINT service capabilities
python main.py osint info

# Test OSINT functionality
python main.py osint test example.com

# Quick test mode
python main.py osint test google.com --quick
```

#### **OSINT Features**
- **🆓 Free APIs Only** - No API keys required for basic functionality
- **⚡ Rate Limited** - Respectful usage of external services
- **📧 Email Harvesting** - TheHarvester integration with validation
- **🔍 Search Engine Reconnaissance** - Google dorking and pattern analysis
- **🌐 Enhanced WHOIS** - Extended WHOIS analysis with geolocation
- **📱 Social Media Discovery** - Profile and presence detection
- **🔒 Certificate Analysis** - Certificate transparency log analysis
- **📊 Multi-format Reports** - JSON, HTML, TXT reporting
- **💾 Evidence Preservation** - Raw data saving for forensic analysis
- **🎯 Privacy Assessment** - Information exposure scoring

#### **OSINT Report Contents**
- **📧 Email Addresses** - Discovered email addresses with validation status
- **🌐 Subdomains** - Found subdomains from various sources
- **📱 Social Media** - Discovered social media profiles and presence
- **🔍 Search Results** - Relevant search engine findings
- **📜 WHOIS Data** - Domain registration and historical information
- **🔒 Certificates** - SSL certificate transparency data
- **📊 Privacy Score** - Overall information exposure assessment
- **📋 Recommendations** - Security and privacy improvement suggestions

#### **Best Practices for OSINT**
```bash
# Respectful scanning with appropriate delays
python main.py osint email example.com --timeout 60 --limit 100

# Use specific sources to avoid overwhelming services
python main.py osint search example.com --sources google --limit 50

# Save evidence for forensic analysis
python main.py osint comprehensive example.com --save-evidence --output-dir ~/osint-results

# Regular rate limiting for large assessments
python main.py osint comprehensive example.com --rate-limit 2 --include-all
```

---

## 📊 **Report Generation**

### **Individual Scanner Reports**
```bash
# JSON report
python main.py network 192.168.1.1 --json-report
python main.py osint email example.com --json-report

# HTML report  
python main.py network 192.168.1.1 --html-report
python main.py osint comprehensive example.com --html-report

# TXT report (OSINT specific)
python main.py osint whois example.com --txt-report

# All report formats
python main.py network 192.168.1.1 --all-reports
python main.py osint comprehensive example.com --all-reports

# Custom output directory
python main.py network 192.168.1.1 --all-reports --output-dir ~/security-reports
python main.py osint comprehensive example.com --all-reports --output-dir ~/osint-reports
```

### **Orchestrated Scan Reports**
```bash
# Complete assessment with all scanners including OSINT
python main.py scan example.com --profile full --all-reports

# Custom scanner selection including OSINT
python main.py scan example.com --include-network --include-web --include-ssl --include-osint --html-report
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

#### **4. TXT Report** (OSINT Specific)
- Plain text format for easy parsing
- Command-line friendly output
- Suitable for further processing

#### **5. Evidence Files** (OSINT Specific)
- Raw tool outputs saved separately
- Forensic-grade evidence preservation
- Complete audit trail

---

## ⚙️ **Configuration & Best Practices**

### **OSINT Configuration**
```bash
# Set custom timeout for slow sources
export OSINT_TIMEOUT=120

# Configure rate limiting (requests per second)
export OSINT_RATE_LIMIT=1

# Set custom output directory
export OSINT_OUTPUT_DIR=~/osint-investigations

# Enable debug mode for troubleshooting
export OSINT_DEBUG=true
```

### **Ethical OSINT Guidelines**
1. **Legal Compliance** - Ensure all OSINT activities comply with local laws
2. **Responsible Disclosure** - Report findings through appropriate channels
3. **Rate Limiting** - Use conservative rate limits to avoid service disruption
4. **Time Windows** - Perform scans during appropriate maintenance windows
5. **Monitoring** - Monitor target systems during scans for any issues
6. **Documentation** - Document all findings and remediation steps

### **Performance Optimization**
1. **Template Selection** - Use specific severity levels rather than `--templates all`
2. **Timeout Management** - Adjust `--timeout` based on network conditions
3. **Parallel Scanning** - Use orchestrated scans for multiple targets
4. **Cache Management** - Clear cache regularly with `python main.py clear-cache`
5. **OSINT Source Selection** - Use specific sources rather than `--sources all`
6. **Evidence Storage** - Use `--save-evidence` selectively to manage disk space

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

# OSINT reconnaissance (NEW!)
python main.py osint comprehensive example.com --include-all --save-evidence --all-reports
```

### **Complete OSINT Investigation Workflow**
```bash
# Phase 1: Initial reconnaissance
python main.py osint email example.com --validate-emails --json-report

# Phase 2: Search engine intelligence
python main.py osint search example.com --social-media --html-report

# Phase 3: Infrastructure analysis  
python main.py osint whois example.com --historical --geolocation --txt-report

# Phase 4: Comprehensive assessment
python main.py osint comprehensive example.com --include-all --save-evidence --all-reports --output-dir ~/investigation-example-com

# Phase 5: Evidence review and analysis
cd ~/investigation-example-com
ls -la *.json *.html *.txt
cat osint_comprehensive_*.txt | grep -E "(email|subdomain|social)"
```

### **Compliance Scanning**
```bash
# PCI DSS compliance scanning
python main.py scan payment.example.com --include-ssl --include-network --include-web --compliance pci

# OWASP Top 10 assessment
python main.py api https://api.example.com --owasp-only --all-reports
python main.py web https://app.example.com --owasp-testing --html-report

# Privacy compliance assessment (NEW!)
python main.py osint comprehensive company.com --save-evidence --all-reports --output-dir ~/privacy-assessment
```

### **Automated Security Monitoring**
```bash
# Daily vulnerability checks
python main.py network production-server.com --templates critical --json-report --output-dir /var/log/security/

# Weekly comprehensive assessment
python main.py scan production-environment.com --profile full --all-reports --output-dir /reports/weekly/

# Monthly OSINT monitoring (NEW!)
python main.py osint email company.com --validate-emails --limit 200 --json-report --output-dir /reports/osint-monthly/
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

### **OSINT Scanner Issues** 🆕
```bash
# Check OSINT service availability
python main.py osint info

# Test OSINT functionality
python main.py osint test example.com --quick

# Check individual tools
theharvester -d example.com -l 5 -b google
whois example.com

# Debug OSINT operations
python main.py osint email example.com --timeout 30 --limit 10 --json-report
```

### **Common Issues**
1. **"Nuclei not found"** - Install Nuclei using methods above
2. **"No templates found"** - Run `nuclei -update-templates`
3. **"Connection timeout"** - Increase `--timeout` value
4. **"Rate limited"** - Decrease `--rate-limit` value
5. **"Permission denied"** - Check network permissions and firewall rules
6. **"OSINT tools not found"** - Install optional OSINT tools: `sudo apt install theharvester whois` 🆕
7. **"OSINT timeout errors"** - Increase `--timeout` for OSINT operations 🆕
8. **"No OSINT results"** - Check internet connectivity and service availability 🆕

### **Report Generation Issues**
1. **PDF generation fails** - Install weasyprint: `pip install weasyprint`
2. **Large reports** - Use `--output-dir` with sufficient disk space
3. **OSINT evidence files missing** - Use `--save-evidence` flag explicitly 🆕
4. **HTML report styling issues** - Ensure all CSS dependencies are installed 🆕

### **Performance Issues**
1. **Slow OSINT scans** - Increase `--rate-limit` value (higher = faster) 🆕
2. **Memory usage during OSINT** - Use smaller `--limit` values 🆕
3. **Disk space for evidence** - Monitor disk usage when using `--save-evidence` 🆕

---

## 📚 **Additional Resources**

### **Documentation**
- Installation Guide: `docs/installation_guide.md`
- API Documentation: `docs/api_documentation.md`
- Development Guide: `docs/development_guide.md`
- Troubleshooting: `docs/troubleshooting_guide.md`

### **External Resources**
- **Nuclei Templates**: https://github.com/projectdiscovery/nuclei-templates
- **TheHarvester**: https://github.com/laramies/theHarvester 🆕
- **OSINT Framework**: https://osintframework.com 🆕
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/

### **Community**
- Report issues and feature requests through the project repository
- Contribute OSINT techniques and improvements 🆕
- Share custom Nuclei templates with the community
- Follow responsible disclosure practices for security findings

---

**Auto-Pentest Framework v0.9.6 with comprehensive OSINT capabilities is ready for professional security assessments and investigations!** 🚀🔍