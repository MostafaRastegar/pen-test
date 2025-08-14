# **Auto-Pentest Framework v0.9.1 - User Manual**

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

#### **3. Comprehensive Assessment**
```bash
# Full scan + multiple report formats
python main.py full scanme.nmap.org --output ./reports/

# Or manual control
python main.py scan scanme.nmap.org --include-port --include-dns --include-web --include-directory --include-ssl --all-reports --parallel
```

#### **4. Targeted Scans Without Reports**
```bash
# SSL assessment only
python main.py ssl scanme.nmap.org --vulnerabilities --cert-info

# Specific ports only  
python main.py port scanme.nmap.org --ports 80,443,8080,8443 --fast

# Directory enumeration only
python main.py directory https://scanme.nmap.org --tool gobuster --wordlist /usr/share/wordlists/dirb/common.txt
```

#### **5. Specialized DNS Analysis**
```bash
# Comprehensive DNS testing
python main.py dns scanme.nmap.org --subdomain-enum --zone-transfer --dns-bruteforce --verbose
```

#### **6. Custom Output Directory**
```bash
# Save to specific path
python main.py scan scanme.nmap.org --include-ssl --include-web --all-reports --output ./my_reports/

# View generated files
ls -la ./my_reports/
```

---

## 📋 **Available Profiles**

### **Quick Profile** ⚡
- Includes: Port scanning (common ports)
- Duration: 2-3 minutes
- Best for: Initial reconnaissance

### **Web Profile** 🌐  
- Includes: Web scanning + SSL analysis + Directory enumeration
- Duration: 10-15 minutes
- Best for: Website assessment

### **Full Profile** 🔍
- Includes: All scanners
- Duration: 20-60 minutes (depends on target)
- Best for: Comprehensive assessment

### **Custom Profile** ⚙️
- Includes: Manual selection with `--include-*`
- Duration: Variable
- Best for: Specific requirements

---

## 🎯 **Key Difference: Reports vs No Reports**

### ✅ **Commands with automatic reports:**
```bash
python main.py quick scanme.nmap.org              # ✅ Generates reports
python main.py full scanme.nmap.org               # ✅ Generates reports  
python main.py scan scanme.nmap.org --all-reports # ✅ Generates reports
```

### ❌ **Commands without reports (terminal display only):**
```bash
python main.py ssl scanme.nmap.org                # ❌ No report files
python main.py port scanme.nmap.org               # ❌ No report files
python main.py web scanme.nmap.org                # ❌ No report files
```

### 🔧 **Solution: Combine with scan command for reports:**
```bash
# Instead of:
python main.py ssl scanme.nmap.org

# Use:
python main.py scan scanme.nmap.org --include-ssl --all-reports
```

---

## 🛠️ **Troubleshooting**

### **Common Issues**

#### **1. Tool Not Found**
```bash
# Check available tools
python main.py list-tools --check-status

# Install required tools (Ubuntu/Debian)
sudo apt update
sudo apt install nmap nikto dirb gobuster sslscan
```

#### **2. Permission Issues**
```bash
# For privileged ports
sudo python main.py scan scanme.nmap.org --include-port

# Or use non-privileged ports
python main.py port scanme.nmap.org --ports 80,443,8080,8443
```

#### **3. PDF Generation Issues**
```bash
# Check PDF library
python -c "import weasyprint; print('✅ PDF OK')"

# Install if missing
pip install weasyprint

# System dependencies (Ubuntu/Debian)
sudo apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
```

#### **4. Timeout Issues**
```bash
# Increase timeout
python main.py scan scanme.nmap.org --timeout 1800 --include-port --include-ssl

# Sequential execution for slow networks
python main.py scan scanme.nmap.org --sequential --timeout 3600
```

#### **5. Memory Issues**
```bash
# Reduce threads
python main.py scan scanme.nmap.org --threads 2 --sequential

# Clear cache
python main.py clear-cache --all --force
```

---

## 📁 **Output File Structure**

### **Default Paths:**
```
output/
├── reports/          # Generated reports
├── logs/            # Log files  
└── cache/           # Scan cache
```

### **Report File Types:**
```bash
# Available formats
security_report_target_20241201_143022.html    # Interactive HTML report
security_report_target_20241201_143022.pdf     # Printable PDF report
security_report_target_20241201_143022.json    # Structured data
security_report_target_20241201_143022.txt     # Text summary
security_report_target_20241201_143022.csv     # Tabular format
```

---

## 🎯 **Best Practices**

### **Before Scanning:**
- [ ] Written authorization obtained for scanning
- [ ] Scope clearly defined  
- [ ] System requirements verified
- [ ] Output directory prepared

### **During Scanning:**
- [ ] Start with safe targets (scanme.nmap.org)
- [ ] Use quick profile for initial testing
- [ ] Monitor system resources
- [ ] Manage scan timing appropriately

### **After Scanning:**
- [ ] Review results before delivery
- [ ] Generate reports in multiple formats
- [ ] Store files securely
- [ ] Document lessons learned

---

## 📞 **Help & Reference**

### **Getting Help:**
```bash
python main.py --help              # General help
python main.py scan --help         # Scan command help
python main.py ssl --help          # SSL scanner help
```

### **System Information:**
```bash
python main.py info                # Framework capabilities
python main.py list-tools          # Installed tools
python main.py version             # Version information
```

### **Cache Management:**
```bash
python main.py cache-stats         # Cache status
python main.py clear-cache --all   # Clear cache
```

---

## 🎊 **Important Summary**

### **For Report Generation:**
✅ **Use:** `scan`, `quick`, `full`  
❌ **Don't use:** `ssl`, `port`, `web`, `dns`, `directory` (no reports)

### **Recommended Commands:**
```bash
# Quick start
python main.py quick scanme.nmap.org

# Comprehensive assessment  
python main.py full scanme.nmap.org

# Precise control
python main.py scan scanme.nmap.org --include-ssl --include-web --all-reports --output ./reports/
```

---

**🚀 Auto-Pentest Framework v0.9.1 is ready to use!**

This framework is designed for security teams, consultants, and researchers to conduct professional security assessments with comprehensive reporting capabilities.

**Happy scanning! 🔒**