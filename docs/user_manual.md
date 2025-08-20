# Auto-Pentest Framework v0.9.6 - User Manual

## 📋 **Overview**

The Auto-Pentest Framework is a comprehensive security assessment platform that automates penetration testing workflows with enterprise-grade reporting. This manual covers all scanners and features available in version 0.9.6.

### **🎯 Current Scanner Suite (90% Complete)**
- ✅ **Port Scanner** - Network reconnaissance and service discovery
- ✅ **DNS Scanner** - Domain name system analysis and enumeration  
- ✅ **Web Scanner** - Web application security assessment
- ✅ **Directory Scanner** - Hidden directory and file discovery
- ✅ **SSL Scanner** - SSL/TLS security analysis
- ✅ **WordPress Scanner** - CMS-specific vulnerability assessment
- ✅ **API Security Scanner** - REST/GraphQL API security testing
- ✅ **WAF Detection Engine** - Web Application Firewall detection and bypass testing

---

## 🚀 **Quick Start Guide**

### **Basic Installation**
```bash
# Clone repository
git clone <repository-url>
cd auto-pentest-framework

# Install dependencies
pip install -r requirements.txt

# Verify installation
python main.py --version
```

### **First Scan**
```bash
# Basic reconnaissance
python main.py port 192.168.1.1

# Web application scan
python main.py web https://example.com

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

# Plugin enumeration
python main.py wordpress https://wordpress-site.com --enumerate-plugins

# User enumeration
python main.py wordpress https://wordpress-site.com --enumerate-users
```

#### **Advanced Options**
```bash
# Theme analysis
python main.py wordpress https://wordpress-site.com --enumerate-themes

# Security configuration
python main.py wordpress https://wordpress-site.com --security-checks

# Vulnerability assessment
python main.py wordpress https://wordpress-site.com --vulnerability-scan
```

#### **WordPress Scanner Features**
- **Plugin Security Analysis**: 50+ vulnerable plugins database
- **Theme Security Assessment**: Custom and known theme vulnerabilities
- **User Security Evaluation**: Multi-vector user enumeration and analysis
- **Brute Force Protection Testing**: Login security mechanism assessment
- **Security Plugin Detection**: Major WordPress security solutions analysis

### **7. API Security Scanner**
REST and GraphQL API security testing with OWASP API Top 10 coverage.

#### **Basic Usage**
```bash
# Basic API scan
python main.py api https://api.example.com

# REST API testing
python main.py api https://api.example.com/v1 --api-type rest

# GraphQL testing
python main.py api https://api.example.com/graphql --api-type graphql
```

#### **Advanced Options**
```bash
# Authentication testing
python main.py api https://api.example.com --auth-testing

# Rate limiting assessment
python main.py api https://api.example.com --rate-limit-testing

# JWT token analysis
python main.py api https://api.example.com --jwt-analysis

# Basic scan with JSON report
python main.py api https://api.example.com --json-report

# All reports
python main.py api https://api.example.com --all-reports

# Custom output directory
python main.py api https://api.example.com --json-report --output-dir my_reports

```

#### **API Scanner Features**
- **OWASP API Top 10 (2023)**: Complete coverage of all 10 categories
- **REST API Discovery**: 29+ endpoint patterns for comprehensive enumeration
- **GraphQL Security**: Introspection attacks and depth testing
- **JWT Token Analysis**: Token extraction and vulnerability detection
- **Authorization Testing**: BOLA/BFLA comprehensive assessment
- **API Documentation Security**: Swagger/OpenAPI security analysis

### **8. WAF Detection Engine** 🆕
Web Application Firewall detection and bypass testing capabilities.

#### **Basic Usage**
```bash
# Basic WAF detection
python main.py waf https://example.com

# WAF detection with domain
python main.py waf example.com

# Verbose output
python main.py waf https://example.com --verbose
```

#### **Advanced Options**
```bash
# Extended timeout for thorough testing
python main.py waf https://example.com --timeout 600

# Aggressive testing mode
python main.py waf https://example.com --aggressive

# Skip bypass testing (detection only)
python main.py waf https://example.com --detection-only
```

#### **WAF Scanner Features**
- **WAF Vendor Detection**: 8 major vendors (Cloudflare, AWS WAF, Akamai, F5, Imperva, Fortinet, Sucuri, ModSecurity)
- **Behavioral Analysis**: Advanced response pattern matching and timing analysis
- **Bypass Testing**: 42+ evasion payloads across 4 attack vectors (SQL injection, XSS, LFI, Command injection)
- **Effectiveness Assessment**: Comprehensive WAF security posture evaluation
- **Real-time Adaptation**: Dynamic payload modification based on WAF responses

#### **Supported WAF Vendors**
- **Cloudflare**: CF-Ray headers, error patterns, behavioral analysis
- **AWS WAF**: Amazon-specific signatures and response patterns
- **Akamai**: EdgeScape detection and fingerprinting
- **F5 Big-IP**: ASM mode detection and configuration analysis
- **Imperva/Incapsula**: Security response patterns and blocking behavior
- **Fortinet**: FortiGate/FortiWeb signatures and protection analysis
- **Sucuri**: Website firewall detection and security assessment
- **ModSecurity**: Apache module signatures and rule analysis

#### **Bypass Testing Categories**
- **SQL Injection**: 13+ techniques with encoding variations
- **Cross-Site Scripting (XSS)**: 12+ evasion methods and filter bypasses
- **Local File Inclusion (LFI)**: 8+ path traversal and encoding bypasses
- **Command Injection**: 9+ system command evasion techniques

---

## 🎯 **Workflow Orchestration**

### **Profile-Based Scanning**
```bash
# Quick scan (essential checks)
python main.py scan target.com --profile quick

# Standard scan (balanced coverage)
python main.py scan target.com --profile standard

# Full scan (comprehensive assessment)
python main.py scan target.com --profile full

# Custom scan profile
python main.py scan target.com --profile custom --scanners port,web,waf
```

### **Parallel Execution**
```bash
# Parallel scanner execution
python main.py scan target.com --parallel --max-threads 4

# Resource management
python main.py scan target.com --parallel --memory-limit 4GB

# Performance monitoring
python main.py scan target.com --parallel --performance-monitoring
```

### **Target Management**
```bash
# Multiple targets
python main.py scan target1.com,target2.com,192.168.1.1

# Target file
python main.py scan --target-file targets.txt

# CIDR notation
python main.py scan 192.168.1.0/24
```

---

## 📊 **Output and Reporting**

### **Output Formats**
```bash
# JSON output
python main.py port 192.168.1.1 --output json

# XML output
python main.py port 192.168.1.1 --output xml

# CSV output
python main.py port 192.168.1.1 --output csv

# Text output (default)
python main.py port 192.168.1.1 --output text
```

### **Report Generation**
```bash
# HTML report
python main.py scan target.com --report html

# PDF report
python main.py scan target.com --report pdf

# Combined reports
python main.py scan target.com --report html,pdf

# Custom report template
python main.py scan target.com --report html --template custom
```

### **Output Management**
```bash
# Custom output directory
python main.py scan target.com --output-dir /path/to/results

# Timestamped outputs
python main.py scan target.com --timestamp

# Compressed results
python main.py scan target.com --compress
```

---

## ⚙️ **Configuration**

### **Configuration Files**
```bash
# System configuration
config/scanner_config.yaml

# User preferences
~/.autopentest/config.yaml

# Project-specific settings
./pentest_config.yaml
```

### **Environment Variables**
```bash
# Scanner timeout
export AUTOPENTEST_TIMEOUT=300

# Output directory
export AUTOPENTEST_OUTPUT_DIR=/tmp/pentest

# Debug mode
export AUTOPENTEST_DEBUG=true
```

### **Tool Dependencies**
```bash
# Check tool availability
python main.py check-tools

# List available scanners
python main.py list-scanners

# Scanner capabilities
python main.py scanner-info waf
```

---

## 🔧 **Advanced Features**

### **Authentication**
```bash
# HTTP Basic Authentication
python main.py web https://example.com --auth basic:username:password

# Custom headers
python main.py web https://example.com --header "Authorization: Bearer token"

# Session cookies
python main.py web https://example.com --cookie "session=value"
```

### **Proxy and Network**
```bash
# HTTP proxy
python main.py web https://example.com --proxy http://proxy:8080

# SOCKS proxy
python main.py web https://example.com --proxy socks5://proxy:1080

# Custom DNS
python main.py dns example.com --dns-server 8.8.8.8

# Network interface
python main.py port 192.168.1.1 --interface eth0

# Source port
python main.py port 192.168.1.1 --source-port 12345
```

### **Performance Tuning**
```bash
# Custom timeout
python main.py web https://example.com --timeout 60

# Rate limiting
python main.py directory https://example.com --delay 2

# Thread control
python main.py scan target.com --max-threads 8

# Memory management
python main.py scan target.com --memory-limit 2GB
```

### **Security Options**
```bash
# Skip SSL verification (testing only)
python main.py web https://example.com --no-ssl-verify

# Safe mode (read-only tests)
python main.py scan target.com --safe-mode

# Ethical testing mode
python main.py scan target.com --ethical
```

---

## 🛡️ **Security Guidelines**

### **Ethical Testing Principles**
- **Authorization Required**: Only test systems you own or have explicit written permission to test
- **Scope Compliance**: Stay within the defined scope of testing
- **Impact Awareness**: Understand potential impact of scanning activities
- **Responsible Disclosure**: Follow coordinated disclosure practices for vulnerabilities
- **Legal Compliance**: Ensure compliance with local laws and regulations

### **Best Practices**
```bash
# Rate limiting to avoid overloading targets
python main.py scan target.com --delay 1

# Respectful scanning
python main.py scan target.com --polite

# Logging for audit trails
python main.py scan target.com --log-level info

# Safe testing mode
python main.py scan target.com --safe-mode
```

### **WAF Testing Ethics**
- **Bypass Testing**: Only test WAF bypass techniques on systems you own
- **Detection Impact**: Be aware that bypass testing may trigger security alerts
- **Rate Limiting**: Use built-in delays to avoid overwhelming WAF systems
- **Documentation**: Document all testing activities for compliance

---

## 📈 **Performance Optimization**

### **Scanner Performance**
```bash
# Fast scan modes
python main.py port target.com --fast
python main.py directory target.com --quick

# Parallel processing
python main.py scan target.com --parallel

# Caching optimization
python main.py scan target.com --cache-results

# Resource monitoring
python main.py scan target.com --monitor-resources
```

### **Output Optimization**
```bash
# Minimal output
python main.py scan target.com --quiet

# Essential findings only
python main.py scan target.com --critical-only

# Compressed results
python main.py scan target.com --compress
```

---

## 🐛 **Troubleshooting**

### **Common Issues**

#### **Permission Errors**
```bash
# Error: Permission denied for raw socket operations
sudo python main.py port target.com

# Alternative: Use non-privileged scan
python main.py port target.com --no-privileged
```

#### **Tool Dependencies**
```bash
# Error: Tool not found
python main.py check-tools

# Install missing tools
sudo apt install nmap nikto dirb gobuster sslscan

# Manual tool path
export NMAP_PATH=/usr/bin/nmap
```

#### **Network Issues**
```bash
# Error: Connection timeout
python main.py web target.com --timeout 120

# Error: DNS resolution
python main.py web target.com --dns-server 8.8.8.8

# Error: SSL certificate
python main.py web target.com --no-ssl-verify
```

#### **WAF Scanner Issues**
```bash
# Error: WAF detection timeout
python main.py waf target.com --timeout 300

# Error: Rate limiting triggered
python main.py waf target.com --delay 2

# Error: Connection refused
python main.py waf target.com --user-agent "Mozilla/5.0"
```

### **Debug Mode**
```bash
# Enable debug logging
python main.py scan target.com --debug

# Verbose output
python main.py scan target.com --verbose

# Save debug logs
python main.py scan target.com --debug --log-file debug.log
```

---

## 📋 **Command Reference**

### **Global Options**
```bash
--version               Show version information
--help                  Show help message
--config FILE          Use custom configuration file
--output-dir DIR        Set output directory
--timeout SECONDS       Set global timeout
--verbose               Enable verbose output
--debug                 Enable debug mode
--quiet                 Minimize output
--log-file FILE         Save logs to file
```

### **Scanner Options**
```bash
--profile PROFILE       Use scan profile (quick/standard/full/custom)
--scanners LIST         Specify scanners to use
--parallel              Enable parallel execution
--max-threads NUM       Maximum concurrent threads
--delay SECONDS         Delay between requests
--user-agent STRING     Custom user agent
--proxy URL             Proxy server URL
--timeout SECONDS       Scanner timeout
--output FORMAT         Output format (json/xml/csv/text)
--report FORMAT         Report format (html/pdf)
```

### **Target Options**
```bash
--target-file FILE      Read targets from file
--exclude FILE          Exclude targets from file
--include-private       Include private IP ranges
--dns-server IP         Custom DNS server
--source-ip IP          Source IP address
--interface IFACE       Network interface
```

---

## 📚 **Examples and Use Cases**

### **External Penetration Testing**
```bash
# Phase 1: Reconnaissance
python main.py dns target.com --subdomains
python main.py port target.com --comprehensive

# Phase 2: Service Analysis
python main.py web https://target.com --directory-enum
python main.py ssl target.com:443 --vuln-testing

# Phase 3: Application Testing
python main.py wordpress https://target.com/blog
python main.py api https://api.target.com

# Phase 4: WAF Analysis
python main.py waf https://target.com --aggressive
```

### **Internal Network Assessment**
```bash
# Network discovery
python main.py port 192.168.1.0/24 --fast

# Service enumeration
python main.py port 192.168.1.1-100 --service-detection

# Web application testing
python main.py web http://internal-app.local

# Complete internal scan
python main.py scan 192.168.1.0/24 --profile internal
```

### **API Security Assessment**
```bash
# API discovery
python main.py api https://api.example.com --discovery

# Authentication testing
python main.py api https://api.example.com --auth-testing

# GraphQL specific testing
python main.py api https://api.example.com/graphql --graphql-introspection

# OWASP API Top 10 testing
python main.py api https://api.example.com --owasp-testing
```

### **WordPress Security Audit**
```bash
# Basic WordPress scan
python main.py wordpress https://wp-site.com

# Plugin vulnerability assessment
python main.py wordpress https://wp-site.com --plugin-vulns

# User security analysis
python main.py wordpress https://wp-site.com --user-security

# Comprehensive WordPress audit
python main.py wordpress https://wp-site.com --comprehensive
```

### **WAF Assessment Scenarios**
```bash
# WAF detection and identification
python main.py waf https://protected-site.com

# Bypass testing for penetration testing
python main.py waf https://target.com --bypass-testing

# WAF effectiveness assessment
python main.py waf https://client-site.com --effectiveness-assessment

# Custom payload testing
python main.py waf https://target.com --custom-payloads payloads.txt
```

---

## 🔄 **Integration**

### **CI/CD Pipeline Integration**
```yaml
# Example GitHub Actions workflow
- name: Security Scan
  run: |
    python main.py scan ${{ env.TARGET_URL }} --profile standard
    python main.py waf ${{ env.TARGET_URL }} --detection-only
```

### **API Integration**
```python
# Python integration example
from auto_pentest import AutoPentestFramework

framework = AutoPentestFramework()
result = framework.scan_target("example.com", profile="standard")

# WAF detection integration
waf_result = framework.scan_waf("https://example.com")
if waf_result.waf_detected:
    print(f"WAF detected: {waf_result.detected_wafs}")
```

### **SIEM Integration**
```bash
# Send results to SIEM
python main.py scan target.com --siem-output --siem-server siem.company.com
```

---

## 📊 **Scanner Comparison Matrix**

| Scanner | Target Type | Speed | Depth | Use Case |
|---------|-------------|--------|-------|----------|
| **Port** | IP/Network | Fast | Medium | Network reconnaissance |
| **DNS** | Domain | Fast | High | Domain enumeration |
| **Web** | URL | Medium | High | Web app security |
| **Directory** | URL | Slow | Medium | Content discovery |
| **SSL** | Host:Port | Fast | High | TLS security |
| **WordPress** | URL | Medium | Very High | CMS security |
| **API** | URL/Endpoint | Medium | Very High | API security |
| **WAF** | URL | Medium | High | WAF analysis |

---

## 📈 **Performance Benchmarks**

### **Typical Scan Times**
- **Port Scan (1000 ports)**: 30-120 seconds
- **DNS Enumeration**: 1-5 minutes
- **Web Application Scan**: 5-15 minutes
- **Directory Enumeration**: 10-30 minutes
- **SSL Analysis**: 30-60 seconds
- **WordPress Assessment**: 3-10 minutes
- **API Security Scan**: 5-15 minutes
- **WAF Detection**: 1-5 minutes

### **Resource Usage**
- **Memory**: 100-500MB per scanner
- **CPU**: Low to moderate usage
- **Network**: Depends on target responsiveness
- **Disk**: 10-100MB for results and logs

---

## 🔮 **Future Features**

### **Planned Enhancements (Phase 2.3)**
- **Network Vulnerability Scanner**: Advanced network security testing with Nessus/OpenVAS integration
- **Enhanced WordPress Integration**: Real-time WPScan execution and CVE database updates
- **Performance Optimization**: Parallel execution improvements and intelligent caching

### **Advanced Features (Phase 3)**
- **Interactive HTML Reports**: JavaScript-powered dashboards and data visualization
- **Machine Learning Engine**: AI-powered vulnerability prioritization and false positive reduction
- **Enterprise Integration**: REST API, database integration, and SIEM connectivity

---

## 📞 **Support and Resources**

### **Documentation**
- **Installation Guide**: Complete setup instructions
- **Developer Guide**: Architecture and extension documentation
- **Troubleshooting Guide**: Common issues and solutions
- **API Documentation**: Programmatic interface reference

### **Community**
- **GitHub Repository**: Source code and issue tracking
- **Documentation**: Online manual and guides
- **Support**: Community support and discussion

### **Security Considerations**
- **Responsible Testing**: Follow ethical hacking principles
- **Legal Compliance**: Ensure proper authorization
- **Impact Assessment**: Understand testing implications
- **Coordinated Disclosure**: Report vulnerabilities responsibly

---

**Auto-Pentest Framework v0.9.6** - Your comprehensive security assessment platform with 8 integrated scanners including the new WAF Detection Engine! 🚀🛡️