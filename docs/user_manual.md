# **Auto-Pentest Framework v0.9.5 - User Manual**

## 🚀 **Quick Start**

### **Main Commands**

#### **1. Full Scan with Reports (Recommended)**
```bash
# Quick scan + reports (2-3 minutes)
python main.py quick scanme.nmap.org

# Full scan + reports (10-30 minutes)  
python main.py full scanme.nmap.org

# Web-focused scan + reports
python main.py scan scanme.nmap.org --profile web --all-reports
```

#### **2. Selective Scan with Reports**
```bash
# SSL only + reports
python main.py scan scanme.nmap.org --include-ssl --all-reports

# Port + SSL + reports
python main.py scan scanme.nmap.org --include-port --include-ssl --html-report

# All scanners + specific report
python main.py scan scanme.nmap.org --include-port --include-dns --include-web --include-directory --include-ssl --pdf-report
```

#### **3. Individual Scanner Commands (No automatic reports)**
```bash
# Execution only, no report files
python main.py ssl scanme.nmap.org --vulnerabilities
python main.py port scanme.nmap.org --ports 22,80,443
python main.py web https://scanme.nmap.org --use-nikto
python main.py dns scanme.nmap.org --subdomain-enum
python main.py directory https://scanme.nmap.org --wordlist
python main.py wordpress https://scanme.nmap.org --all-reports
python main.py api https://httpbin.org/json --owasp-only
```

---

## 📊 **CLI Command Structure**

### **Main Command: `scan`** (With reporting capabilities)
```bash
python main.py scan TARGET [OPTIONS]
```

**Key Options:**
```bash
# Profile Selection
--profile {quick|web|full|custom}     # Scan type

# Scanner Selection  
--include-port                        # Port scanning
--include-dns                         # DNS enumeration
--include-web                         # Web vulnerability scanning
--include-directory                   # Directory enumeration  
--include-ssl                         # SSL/TLS analysis

# Report Generation (scan command only)
--json-report                         # JSON report
--html-report                         # HTML report
--pdf-report                          # PDF report
--all-reports                         # All formats

# Execution
--parallel                            # Parallel execution (default)
--sequential                          # Sequential execution
--timeout SECONDS                     # Total workflow timeout
--output DIR                          # Output directory
```

### **Shortcut Commands** (With automatic reports)
```bash
python main.py quick TARGET          # Equivalent to: scan --profile quick --all-reports
python main.py full TARGET           # Equivalent to: scan --profile full --all-reports  
```

### **Individual Scanner Commands** (No automatic reports)
```bash
# Port Scanner
python main.py port TARGET [OPTIONS]
  --ports RANGE                       # Port range (e.g., 1-1000, 80,443)
  --scan-type {tcp|udp|syn}          # Scan type
  --fast                             # Fast mode

# DNS Scanner  
python main.py dns TARGET [OPTIONS]
  --subdomain-enum                   # Subdomain enumeration
  --zone-transfer                    # Zone transfer test
  --dns-bruteforce                   # DNS brute force

# Web Scanner
python main.py web TARGET [OPTIONS]  
  --use-nikto                        # Use Nikto
  --directory-enum                   # Directory enumeration
  --ssl-analysis                     # SSL analysis

# Directory Scanner
python main.py directory TARGET [OPTIONS]
  --tool {dirb|gobuster}             # Tool selection
  --wordlist FILE                    # Custom wordlist file
  --extensions EXTS                  # File extensions (php,asp,jsp)

# SSL Scanner
python main.py ssl TARGET [OPTIONS]
  --cipher-enum                      # Cipher enumeration
  --cert-info                        # Certificate information
  --vulnerabilities                  # Vulnerability checks

# WordPress Scanner
python main.py wordpress TARGET [OPTIONS]
  --enumerate-plugins                # Plugin enumeration and security analysis
  --enumerate-themes                 # Theme enumeration and security analysis
  --enumerate-users                  # User enumeration
  --use-wpscan                       # Use WPScan integration
  --wpscan-api-token TOKEN           # WPScan API token for enhanced data

# API Security Scanner (NEW in v0.9.5)
python main.py api TARGET [OPTIONS]
  --timeout SECONDS                  # Request timeout (default: 30)
  --rate-limit-test                  # Enable rate limiting assessment
  --graphql-test                     # Enable GraphQL security testing
  --jwt-analysis                     # Enable JWT token security analysis
  --owasp-only                       # Focus only on OWASP API Top 10 tests
```

### **Utility Commands**
```bash
python main.py info                   # Framework information
python main.py list-tools             # Available tools
python main.py version                # Version info
python main.py cache-stats            # Cache statistics
python main.py clear-cache            # Clear cache
```

### **Common Options** (Available for all scanner commands)
```bash
--output DIR                          # Output directory
--format {json|txt|csv}              # Basic output format
--verbose, -v                        # Verbose output
--debug                              # Debug mode
--no-color                           # Disable colored output
--save-raw                           # Save raw tool output
--timeout SECONDS                    # Scanner timeout (default: 300)
```

---

## 💡 **Usage Examples**

### **Different Use Case Scenarios**

#### **1. Quick Initial Assessment**
```bash
# Fast reconnaissance + comprehensive reports
python main.py quick scanme.nmap.org
```

#### **2. Web Security Assessment**
```bash
# Web-focused scan + reports
python main.py scan https://scanme.nmap.org --profile web --all-reports

# Or manual selection
python main.py scan scanme.nmap.org --include-web --include-ssl --include-directory --html-report
```

#### **3. API Security Testing (NEW)**
```bash
# Comprehensive API security assessment
python main.py api https://httpbin.org/json --rate-limit-test --graphql-test --jwt-analysis

# Quick OWASP API Top 10 scan
python main.py api https://api.example.com --owasp-only --timeout 60

# GraphQL-specific testing
python main.py api https://api.example.com/graphql --graphql-test --verbose

# API security with output
python main.py api https://httpbin.org/json --all-reports --output ./api_results
```

#### **4. WordPress Security Assessment**
```bash
# Complete WordPress security analysis
python main.py wordpress https://example.com --wpscan-api-token YOUR_TOKEN

# Quick WordPress check
python main.py wordpress https://example.com --enumerate-plugins --enumerate-users
```

#### **5. Infrastructure Security Assessment**
```bash
# Full infrastructure scan + reports
python main.py full scanme.nmap.org

# Or step-by-step
python main.py scan scanme.nmap.org --include-port --include-dns --include-ssl --all-reports
```

#### **6. Focused SSL/TLS Analysis**
```bash
# SSL-only with reports
python main.py scan https://scanme.nmap.org --include-ssl --html-report

# Or direct SSL command
python main.py ssl https://scanme.nmap.org --vulnerabilities --cert-info
```

#### **7. Directory and File Discovery**
```bash
# Directory enumeration with custom wordlist
python main.py directory https://scanme.nmap.org --wordlist /usr/share/wordlists/dirb/common.txt

# Multiple file extensions
python main.py directory https://scanme.nmap.org --extensions php,asp,jsp,txt
```

---

## 🎯 **API Security Scanner - Detailed Usage**

### **What is API Security Scanner?**

The API Security Scanner implements **OWASP API Security Top 10 (2023)** testing methodology to identify vulnerabilities in REST APIs, GraphQL endpoints, and web APIs.

### **Key Features:**
- ✅ **REST API Discovery**: Automatic endpoint discovery
- ✅ **GraphQL Security**: Introspection and depth attack testing
- ✅ **JWT Analysis**: Token security assessment
- ✅ **Rate Limiting**: Abuse protection testing
- ✅ **OWASP Compliance**: Complete API Top 10 coverage
- ✅ **Authentication Testing**: Bypass detection
- ✅ **Authorization Testing**: BOLA/BFLA vulnerability detection

### **API Scanner Options:**

```bash
python main.py api TARGET [OPTIONS]

# Required:
TARGET                               # API URL, endpoint, or domain

# Optional:
--timeout SECONDS                    # Request timeout (default: 30)
--rate-limit-test                    # Test API rate limiting protection
--graphql-test                       # Enable GraphQL security testing
--jwt-analysis                       # Analyze JWT tokens if found
--owasp-only                         # Focus only on OWASP API Top 10

# Common options:
--output DIR                         # Save results to directory
--verbose                            # Detailed output
--format json                        # Output format
```

### **API Testing Examples:**

#### **Basic API Security Scan:**
```bash
# Simple API assessment
python main.py api https://httpbin.org/json

# With timeout adjustment
python main.py api https://api.slow-example.com --timeout 60
```

#### **Comprehensive API Testing:**
```bash
# Full feature testing
python main.py api https://api.example.com \
  --rate-limit-test \
  --graphql-test \
  --jwt-analysis \
  --verbose \
  --output ./api_scan_results
```

#### **GraphQL-Specific Testing:**
```bash
# GraphQL endpoint testing
python main.py api https://api.example.com/graphql --graphql-test

# GraphQL with rate limiting
python main.py api https://api.example.com/graphql --graphql-test --rate-limit-test
```

#### **OWASP Compliance Testing:**
```bash
# OWASP API Top 10 focused scan
python main.py api https://api.example.com --owasp-only --verbose

# Quick compliance check
python main.py api https://api.example.com --owasp-only --timeout 30
```

#### **API Discovery and Testing:**
```bash
# Test various API endpoints
python main.py api https://example.com --verbose          # Auto-discover APIs
python main.py api https://example.com/api --jwt-analysis # Specific API path
python main.py api https://example.com:8080 --rate-limit-test # Custom port
```

### **API Scanner Output:**

The API scanner provides:
- **Risk Score** (0-100): Overall security risk assessment
- **OWASP Coverage**: Which of the 10 categories were tested
- **Findings by Severity**: Critical, High, Medium, Low, Info
- **Technical Details**: Specific vulnerabilities and recommendations

### **Sample API Scanner Output:**
```
🎯 API Security Scanner Results:
   Target: https://api.example.com
   Risk Score: 65/100
   OWASP API Top 10 Coverage: 8/10 categories

📊 Findings by Severity:
   HIGH: 2 findings
   MEDIUM: 5 findings  
   LOW: 3 findings
   INFO: 7 findings

🔍 Key Issues Found:
   - Authentication bypass possible
   - Rate limiting not implemented
   - GraphQL introspection enabled
   - Missing security headers
```

---

## 🔧 **Configuration and Customization**

### **Output Formats**
```bash
# JSON output (structured data)
python main.py api https://api.example.com --format json --output ./results

# Verbose text output
python main.py api https://api.example.com --verbose --format txt

# CSV format for analysis
python main.py api https://api.example.com --format csv --output ./results
```

### **Advanced Usage Patterns**

#### **Multiple API Testing:**
```bash
#!/bin/bash
# Script to test multiple APIs
APIS=(
  "https://api.service1.com"
  "https://api.service2.com/v1"
  "https://internal-api.company.com/graphql"
)

for api in "${APIS[@]}"; do
  echo "Testing: $api"
  python main.py api "$api" --owasp-only --output "./results/$(basename $api)"
done
```

#### **CI/CD Integration:**
```bash
# API security in CI/CD pipeline
python main.py api $API_ENDPOINT \
  --owasp-only \
  --timeout 120 \
  --format json \
  --output ./security_reports/api_scan.json

# Check exit code for CI/CD decisions
if [ $? -eq 0 ]; then
  echo "API security scan completed"
else
  echo "API security scan failed"
  exit 1
fi
```

---

## 📋 **Troubleshooting**

### **Common Issues and Solutions**

#### **API Scanner Issues:**

**Problem**: "Invalid target" error
```bash
# Solution: Ensure target is a valid URL or domain
python main.py api https://api.example.com  # ✅ Correct
python main.py api api.example.com          # ✅ Also works
python main.py api invalid..url             # ❌ Invalid
```

**Problem**: Timeout errors
```bash
# Solution: Increase timeout for slow APIs
python main.py api https://slow-api.com --timeout 120
```

**Problem**: GraphQL testing not working
```bash
# Solution: Ensure GraphQL endpoint is correct
python main.py api https://api.example.com/graphql --graphql-test
```

#### **General Scanner Issues:**

**Problem**: "Command not found" error
```bash
# Solution: Ensure you're in the project directory
cd /path/to/auto-pentest-framework
python main.py api https://api.example.com
```

**Problem**: Missing dependencies
```bash
# Solution: Install requirements
pip install -r requirements.txt
```

**Problem**: Permission errors
```bash
# Solution: Check file permissions or use different output directory
python main.py api https://api.example.com --output ~/api_results
```

---

## 📊 **Report Generation**

### **Available Report Formats**

The framework generates different types of reports:

#### **1. JSON Reports** (Structured data)
```bash
python main.py scan target --json-report
python main.py api https://api.example.com --format json --output ./reports
```

#### **2. HTML Reports** (Visual, shareable)
```bash
python main.py scan target --html-report
```

#### **3. PDF Reports** (Professional, printable)
```bash
python main.py scan target --pdf-report
```

#### **4. Text Reports** (Simple, readable)
```bash
python main.py api https://api.example.com --format txt --verbose
```

### **Report Contents**

Each report includes:
- **Executive Summary**: High-level overview
- **Technical Findings**: Detailed vulnerability information
- **Risk Assessment**: Severity ratings and impact analysis
- **Recommendations**: Actionable remediation steps
- **Appendices**: Raw output and technical details

---

## 🎯 **Best Practices**

### **Scanning Best Practices**

1. **Always start with quick scans** for initial assessment
2. **Use verbose mode** for debugging and detailed analysis
3. **Save outputs** for historical tracking and compliance
4. **Test in stages** rather than running all scanners at once
5. **Respect rate limits** and avoid overwhelming target systems

### **API Security Testing Best Practices**

1. **Start with OWASP-focused scans** for compliance
2. **Test authentication endpoints** specifically
3. **Enable GraphQL testing** for GraphQL APIs
4. **Use appropriate timeouts** for different API speeds
5. **Document findings** for development teams

### **Security Considerations**

1. **Only scan systems you own** or have permission to test
2. **Be mindful of rate limits** to avoid service disruption
3. **Use appropriate scan intensity** for production systems
4. **Review findings carefully** before acting on them
5. **Keep scan results secure** as they contain sensitive information

---

## 📚 **Additional Resources**

### **Documentation**
- `docs/installation_guide.md` - Complete installation instructions
- `docs/troubleshooting_guide.md` - Problem resolution guide
- `docs/development_guide.md` - For developers and contributors

### **External Resources**
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [WordPress Security Guidelines](https://wordpress.org/support/article/hardening-wordpress/)
- [Nmap Reference Guide](https://nmap.org/book/)

### **Community and Support**
- GitHub Issues for bug reports and feature requests
- Documentation for comprehensive guides
- Community contributions welcome

---

**🎉 Congratulations! You're now ready to use the Auto-Pentest Framework v0.9.5 with the new API Security Scanner. Happy testing!** 🚀