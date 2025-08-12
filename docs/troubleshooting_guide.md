# Auto-Pentest Framework v0.9.1 - Troubleshooting Guide

## 🚨 **Quick Diagnostic Commands**

Before diving into specific issues, run these diagnostic commands to identify problems:

```bash
# 1. System health check
python verify_installation.py

# 2. Tool availability check
python main.py list-tools

# 3. Framework information
python main.py info

# 4. Test basic functionality
python main.py scan 127.0.0.1 --include-port --ports 22,80,443 --debug

# 5. Check cache and performance
python main.py cache-stats
```

---

## 🔧 **Installation & Setup Issues**

### **Python Environment Problems**

#### **Wrong Python Version**
```bash
# Check Python version
python --version
python3 --version

# If Python < 3.8, install newer version
sudo apt update
sudo apt install python3.9 python3.9-venv python3.9-dev

# Use correct Python version
python3.9 -m venv venv
source venv/bin/activate
```

#### **Virtual Environment Issues**
```bash
# Recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate

# Verify activation
which python
python --version

# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

#### **Permission Issues**
```bash
# Fix ownership of virtual environment
sudo chown -R $USER:$USER venv/

# Create with proper permissions
python3 -m venv --system-site-packages venv

# Alternative: user-level installation
pip install --user -r requirements.txt
```

### **Dependency Installation Problems**

#### **Missing System Dependencies**
```bash
# Ubuntu/Debian - Install missing packages
sudo apt update
sudo apt install -y python3-dev python3-pip build-essential

# For PDF generation
sudo apt install -y libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libfribidi0

# For security tools
sudo apt install -y nmap nikto dirb gobuster sslscan dnsutils

# Check installation
dpkg -l | grep -E "(nmap|nikto|dirb|gobuster|sslscan)"
```

#### **Python Package Conflicts**
```bash
# Check for conflicts
pip check

# Clear pip cache
pip cache purge

# Force reinstall problematic packages
pip uninstall weasyprint pdfkit
pip install --no-cache-dir weasyprint

# Use specific versions
pip install weasyprint==60.0 pdfkit==1.0.0
```

#### **PDF Generation Dependencies**
```bash
# Test PDF libraries
python -c "import weasyprint; print('✅ WeasyPrint OK')" 2>/dev/null || echo "❌ WeasyPrint missing"
python -c "import pdfkit; print('✅ PDFKit OK')" 2>/dev/null || echo "❌ PDFKit missing"

# Install WeasyPrint (recommended)
pip install weasyprint

# Install PDFKit alternative
sudo apt install wkhtmltopdf
pip install pdfkit

# Fix system dependencies for WeasyPrint
sudo apt install -y python3-dev libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
```

---

## 🔍 **Scanner-Specific Issues**

### **Port Scanner Problems**

#### **Permission Denied (Nmap Raw Sockets)**
```bash
# Error: "Permission denied" or "raw sockets" error

# Solution 1: Run with sudo
sudo python main.py scan target.com --include-port

# Solution 2: Set capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)

# Solution 3: Use unprivileged mode
python main.py scan target.com --include-port --no-privileged

# Verify nmap permissions
nmap --privileged --version
```

#### **Nmap Not Found or Wrong Version**
```bash
# Check nmap installation
which nmap
nmap --version

# Install/update nmap
sudo apt install nmap
sudo apt update && sudo apt upgrade nmap

# Manual path configuration
export NMAP_PATH=/usr/local/bin/nmap
python main.py scan target.com --include-port

# Check in framework
python main.py list-tools | grep nmap
```

#### **Slow Port Scanning**
```bash
# Issue: Port scanning takes too long

# Solution 1: Reduce port range
python main.py scan target.com --include-port --top-ports 100

# Solution 2: Use faster scan techniques
python main.py scan target.com --include-port --fast-scan

# Solution 3: Skip host discovery
python main.py scan target.com --include-port --no-ping

# Solution 4: Parallel scanning
python main.py scan target.com --include-port --parallel --max-threads 20
```

### **DNS Scanner Problems**

#### **DNS Resolution Failures**
```bash
# Error: "Name resolution failed" or "DNS query timeout"

# Check DNS configuration
cat /etc/resolv.conf
nslookup target.com
dig target.com

# Use custom DNS servers
python main.py dns target.com --dns-servers 8.8.8.8,1.1.1.1

# Test with simple query
python main.py dns google.com

# Debug DNS issues
python main.py dns target.com --debug --verbose
```

#### **Subdomain Enumeration Issues**
```bash
# Issue: No subdomains found or slow enumeration

# Check wordlist availability
python main.py list-wordlists

# Use smaller wordlist for testing
python main.py dns target.com --subdomain-enum --wordlist small

# Increase timeout
python main.py dns target.com --subdomain-enum --timeout 30

# Enable debug mode
python main.py dns target.com --subdomain-enum --debug
```

#### **Zone Transfer Problems**
```bash
# Issue: Zone transfer fails or times out

# Manual verification
dig @ns1.target.com target.com AXFR
nslookup -type=ns target.com

# Framework debug
python main.py dns target.com --zone-transfer --debug

# Skip if not supported
python main.py dns target.com --no-zone-transfer
```

### **Web Scanner Problems**

#### **Nikto Integration Issues**
```bash
# Error: "Nikto not found" or execution fails

# Check nikto installation
which nikto
nikto -Version

# Install nikto
sudo apt install nikto

# Update nikto database
sudo nikto -update

# Manual path configuration
export NIKTO_PATH=/usr/bin/nikto

# Test nikto manually
nikto -h target.com -Format csv -output test.csv
```

#### **SSL Certificate Issues**
```bash
# Error: SSL certificate verification failed

# Skip SSL verification (testing only)
python main.py web https://target.com --no-ssl-verify

# Debug SSL issues
python main.py ssl target.com --debug

# Test manual SSL connection
openssl s_client -connect target.com:443
```

#### **HTTP Connection Problems**
```bash
# Error: Connection refused or timeout

# Check target accessibility
curl -I http://target.com
wget --spider http://target.com

# Use custom user agent
python main.py web target.com --user-agent "Mozilla/5.0 Custom"

# Configure proxy if needed
python main.py web target.com --proxy http://proxy:8080

# Increase timeout
python main.py web target.com --timeout 60
```

### **Directory Scanner Problems**

#### **Tool Not Found Errors**
```bash
# Error: "dirb not found" or "gobuster not found"

# Check tool availability
which dirb gobuster
python main.py list-tools

# Install missing tools
sudo apt install dirb gobuster

# Use specific tool
python main.py directory target.com --tool dirb
python main.py directory target.com --tool gobuster

# Manual tool testing
dirb http://target.com /usr/share/dirb/wordlists/common.txt
```

#### **Wordlist Issues**
```bash
# Error: "Wordlist not found" or "No wordlist available"

# Check available wordlists
python main.py list-wordlists
ls -la /usr/share/dirb/wordlists/
ls -la /usr/share/wordlists/

# Use custom wordlist
python main.py directory target.com --wordlist /path/to/custom.txt

# Download additional wordlists
sudo apt install seclists
python main.py directory target.com --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
```

#### **False Positive Results**
```bash
# Issue: Too many false positives or irrelevant results

# Filter by status codes
python main.py directory target.com --exclude-status 404,403

# Filter by response size
python main.py directory target.com --min-response-size 100

# Use smaller wordlist
python main.py directory target.com --wordlist small

# Enable intelligent filtering
python main.py directory target.com --smart-filter
```

### **SSL Scanner Problems**

#### **SSLScan Tool Issues**
```bash
# Error: "sslscan not found" or execution fails

# Check sslscan installation
which sslscan
sslscan --version

# Install sslscan
sudo apt install sslscan

# Manual testing
sslscan target.com:443

# Use alternative SSL analysis
python main.py ssl target.com --use-openssl

# Debug SSL scanner
python main.py ssl target.com --debug
```

#### **Certificate Analysis Problems**
```bash
# Issue: Certificate chain validation fails

# Manual certificate check
openssl s_client -connect target.com:443 -showcerts

# Skip certificate validation
python main.py ssl target.com --no-cert-verify

# Check specific certificate issues
python main.py ssl target.com --cert-analysis --debug

# Test different SSL versions
openssl s_client -connect target.com:443 -tls1_2
openssl s_client -connect target.com:443 -tls1_3
```

---

## 📊 **Report Generation Issues**

### **HTML Report Problems**

#### **Template Rendering Errors**
```bash
# Error: Template not found or rendering fails

# Check template availability
ls -la templates/
ls -la templates/report_html.jinja2

# Verify Jinja2 installation
python -c "import jinja2; print(jinja2.__version__)"

# Reinstall template dependencies
pip install --upgrade jinja2

# Debug template rendering
python main.py scan target.com --html-report --debug

# Use basic template
python main.py scan target.com --html-report --basic-template
```

#### **CSS/Styling Issues**
```bash
# Issue: Report displays without proper styling

# Check template integrity
python -c "from jinja2 import Template; print('Jinja2 OK')"

# Regenerate with embedded styles
python main.py scan target.com --html-report --embed-styles

# Use minimal styling
python main.py scan target.com --html-report --minimal-style

# Debug HTML generation
python main.py scan target.com --html-report --debug --verbose
```

### **PDF Report Problems**

#### **PDF Generation Failures**
```bash
# Error: "PDF generation failed" or library import errors

# Check PDF libraries
python -c "import weasyprint; print('✅ WeasyPrint available')"
python -c "import pdfkit; print('✅ PDFKit available')"

# Install WeasyPrint (recommended)
pip install weasyprint

# Install system dependencies for WeasyPrint
sudo apt install -y libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0

# Alternative: Install PDFKit
sudo apt install wkhtmltopdf
pip install pdfkit

# Test PDF generation manually
python -c "
import weasyprint
weasyprint.HTML(string='<h1>Test</h1>').write_pdf('test.pdf')
print('PDF generation successful')
"
```

#### **Font and Rendering Issues**
```bash
# Issue: Missing fonts or poor rendering in PDF

# Install additional fonts
sudo apt install fonts-liberation fonts-dejavu-core

# For WeasyPrint font issues
sudo apt install fontconfig
fc-cache -f -v

# Debug font issues
python main.py scan target.com --pdf-report --debug

# Use basic fonts only
python main.py scan target.com --pdf-report --basic-fonts

# Generate HTML first, then convert
python main.py scan target.com --html-report
# Manual PDF conversion if needed
```

### **Custom Branding Issues**

#### **Branding File Problems**
```bash
# Error: "Branding file not found" or JSON parsing errors

# Check branding file format
python -c "
import json
with open('branding.json') as f:
    data = json.load(f)
print('✅ JSON format valid')
"

# Validate branding schema
python main.py validate-branding branding.json

# Use example branding file
cp custom_branding_example.json test_branding.json
python main.py scan target.com --custom-branding test_branding.json

# Debug branding integration
python main.py scan target.com --custom-branding branding.json --debug
```

#### **Logo Integration Problems**
```bash
# Issue: Logo not displaying or corrupted

# Check logo format (must be base64 encoded)
python -c "
import base64
with open('logo.png', 'rb') as f:
    encoded = base64.b64encode(f.read()).decode()
print(f'data:image/png;base64,{encoded[:50]}...')
"

# Use SVG format (recommended)
# Convert to base64 SVG
python -c "
import base64
with open('logo.svg', 'rb') as f:
    encoded = base64.b64encode(f.read()).decode()
print(f'data:image/svg+xml;base64,{encoded}')
"

# Test without logo
# Remove logo field from branding JSON temporarily
```

---

## ⚡ **Performance Issues**

### **Memory Problems**

#### **Out of Memory Errors**
```bash
# Error: "MemoryError" or system freezing during scans

# Check available memory
free -h
python main.py scan target.com --memory-monitor

# Reduce thread count
python main.py scan target.com --max-threads 5

# Use sequential scanning
python main.py scan target.com --sequential

# Clear cache to free memory
python main.py clear-cache

# Enable memory-efficient mode
python main.py scan target.com --memory-efficient

# Monitor memory usage during scan
watch -n 1 'free -h'
```

#### **Memory Leaks**
```bash
# Issue: Memory usage keeps increasing

# Enable memory debugging
python main.py scan target.com --debug --memory-debug

# Force garbage collection
python main.py scan target.com --force-gc

# Use memory profiling
pip install memory_profiler
python -m memory_profiler main.py scan target.com

# Clear cache frequently
python main.py scan target.com --cache-clear-interval 300
```

### **Performance Degradation**

#### **Slow Scanning Performance**
```bash
# Issue: Scans are much slower than expected

# Check cache status
python main.py cache-stats

# Clear corrupted cache
python main.py clear-cache --force

# Monitor system resources
top -p $(pgrep -f python)
iotop -p $(pgrep -f python)

# Optimize scan parameters
python main.py scan target.com --optimize-performance

# Use faster scan profiles
python main.py quick target.com

# Enable performance monitoring
python main.py scan target.com --performance-monitor
```

#### **Cache Issues**
```bash
# Issue: Cache not working or corrupted

# Check cache directory
ls -la output/cache/
du -sh output/cache/

# Clear all cache
python main.py clear-cache --all

# Disable cache temporarily
python main.py scan target.com --no-cache

# Rebuild cache
python main.py rebuild-cache

# Check cache permissions
chmod -R 755 output/cache/
```

### **Network Performance Issues**

#### **Connection Timeouts**
```bash
# Error: "Connection timeout" or "Network unreachable"

# Check network connectivity
ping target.com
traceroute target.com
curl -I http://target.com

# Increase timeout values
python main.py scan target.com --timeout 120

# Reduce concurrent connections
python main.py scan target.com --max-threads 3

# Use connection pooling
python main.py scan target.com --connection-pool

# Enable network debugging
python main.py scan target.com --network-debug
```

#### **Rate Limiting Issues**
```bash
# Issue: Target blocking or rate limiting requests

# Reduce scan rate
python main.py scan target.com --rate-limit 10

# Add delays between requests
python main.py scan target.com --delay 2

# Use random delays
python main.py scan target.com --random-delay

# Rotate user agents
python main.py scan target.com --rotate-user-agents

# Use proxy rotation (if available)
python main.py scan target.com --proxy-rotation
```

---

## 🌐 **Network & Connectivity Issues**

### **Firewall & Filtering**

#### **Firewall Blocking**
```bash
# Issue: Scans fail due to firewall blocking

# Test basic connectivity
telnet target.com 80
nc -zv target.com 80 443

# Use stealth scanning
python main.py scan target.com --stealth-mode

# Fragment packets (nmap)
python main.py scan target.com --include-port --fragment

# Use decoy hosts
python main.py scan target.com --include-port --decoy-hosts

# Scan from different source ports
python main.py scan target.com --include-port --source-port 53
```

#### **IDS/IPS Detection**
```bash
# Issue: Intrusion detection systems blocking scans

# Use slower scanning
python main.py scan target.com --slow-scan

# Add random delays
python main.py scan target.com --random-delay --delay 5

# Use minimal footprint
python main.py scan target.com --minimal-footprint

# Avoid detection signatures
python main.py scan target.com --evasion-mode
```

### **DNS Issues**

#### **DNS Resolution Problems**
```bash
# Issue: DNS lookups failing or slow

# Check DNS configuration
cat /etc/resolv.conf
nslookup target.com

# Use alternative DNS servers
python main.py scan target.com --dns-servers 8.8.8.8,1.1.1.1

# Bypass DNS resolution
python main.py scan 192.168.1.1 --no-dns

# Use hosts file
echo "192.168.1.1 target.com" | sudo tee -a /etc/hosts

# Debug DNS resolution
python main.py scan target.com --dns-debug
```

### **Proxy & VPN Issues**

#### **Proxy Configuration**
```bash
# Issue: Scans failing through proxy

# Test proxy connectivity
curl --proxy http://proxy:8080 http://target.com

# Configure proxy for all requests
export HTTP_PROXY=http://proxy:8080
export HTTPS_PROXY=http://proxy:8080

# Use framework proxy support
python main.py scan target.com --proxy http://proxy:8080

# Bypass proxy for specific targets
python main.py scan target.com --no-proxy

# Debug proxy issues
python main.py scan target.com --proxy http://proxy:8080 --debug
```

---

## 🛠️ **Tool Integration Issues**

### **System Tool Problems**

#### **Tool Version Compatibility**
```bash
# Issue: Tools not working due to version incompatibility

# Check tool versions
python main.py tool-versions
nmap --version
nikto -Version
dirb
gobuster version
sslscan --version

# Update tools to latest versions
sudo apt update
sudo apt upgrade nmap nikto dirb gobuster sslscan

# Install specific versions if needed
sudo apt install nmap=7.80+dfsg1-2build1

# Use framework compatibility mode
python main.py scan target.com --compatibility-mode
```

#### **Tool Configuration Issues**
```bash
# Issue: Tools not configured properly

# Check tool paths
python main.py list-tools
which nmap nikto dirb gobuster sslscan

# Manual path configuration
export NMAP_PATH=/usr/local/bin/nmap
export NIKTO_PATH=/usr/local/bin/nikto

# Update tool configurations
vim config/tools_config.yaml

# Verify tool configurations
python main.py verify-tools

# Reset to default configurations
python main.py reset-tool-config
```

### **Tool Output Parsing**

#### **XML/CSV Parsing Errors**
```bash
# Error: "Failed to parse tool output" or "Malformed XML"

# Check tool output manually
nmap -oX test.xml target.com
nikto -h target.com -Format csv -output test.csv

# Validate XML output
xmllint --noout test.xml

# Enable debug parsing
python main.py scan target.com --parse-debug

# Use alternative output formats
python main.py scan target.com --output-format json

# Skip problematic parsers
python main.py scan target.com --skip-xml-parsing
```

---

## 📝 **Configuration Issues**

### **Environment Configuration**

#### **.env File Problems**
```bash
# Issue: Environment variables not loading

# Check .env file exists
ls -la .env

# Validate .env format
cat .env | grep -v '^#' | grep '='

# Test environment loading
python -c "
from dotenv import load_dotenv
import os
load_dotenv()
print('DEBUG:', os.getenv('DEBUG'))
print('LOG_LEVEL:', os.getenv('LOG_LEVEL'))
"

# Create .env from template
cp .env.example .env

# Set permissions
chmod 600 .env
```

#### **Configuration File Issues**
```bash
# Issue: Configuration files not found or invalid

# Check configuration files
ls -la config/
cat config/settings.py
cat config/tools_config.yaml

# Validate YAML syntax
python -c "
import yaml
with open('config/tools_config.yaml') as f:
    data = yaml.safe_load(f)
print('✅ YAML valid')
"

# Reset to default configuration
cp config/settings.py.example config/settings.py
cp config/tools_config.yaml.example config/tools_config.yaml

# Verify configuration loading
python main.py config-test
```

### **Permission Issues**

#### **File System Permissions**
```bash
# Issue: Permission denied accessing files/directories

# Check output directory permissions
ls -la output/
chmod -R 755 output/

# Fix ownership
sudo chown -R $USER:$USER output/

# Create missing directories
mkdir -p output/{logs,reports,cache,raw}

# Check log file permissions
touch output/logs/app.log
chmod 644 output/logs/app.log
```

#### **Tool Execution Permissions**
```bash
# Issue: Cannot execute security tools

# Check tool permissions
ls -la /usr/bin/nmap
ls -la /usr/bin/nikto

# Fix executable permissions
sudo chmod +x /usr/bin/nmap
sudo chmod +x /usr/bin/nikto

# Check PATH
echo $PATH
which nmap nikto dirb gobuster sslscan

# Add to PATH if needed
export PATH=$PATH:/usr/local/bin
```

---

## 🔍 **Debugging & Logging**

### **Debug Mode**

#### **Enable Comprehensive Debugging**
```bash
# Enable all debug options
python main.py scan target.com --debug --verbose --memory-monitor --performance-monitor

# Framework-specific debugging
python main.py scan target.com --framework-debug

# Scanner-specific debugging
python main.py scan target.com --include-port --scanner-debug

# Network debugging
python main.py scan target.com --network-debug

# Output debugging
python main.py scan target.com --output-debug
```

### **Log Analysis**

#### **Log File Locations**
```bash
# Main application log
tail -f output/logs/app.log

# Error logs
tail -f output/logs/error.log

# Scanner-specific logs
tail -f output/logs/port_scanner.log
tail -f output/logs/web_scanner.log

# Performance logs
tail -f output/logs/performance.log

# Debug logs
tail -f output/logs/debug.log
```

#### **Log Analysis Commands**
```bash
# Search for errors
grep -i error output/logs/*.log

# Search for warnings
grep -i warning output/logs/*.log

# Search for specific scanner issues
grep -i "port scanner" output/logs/*.log

# Search for performance issues
grep -i "memory\|timeout\|slow" output/logs/*.log

# Get last 100 log entries
tail -n 100 output/logs/app.log

# Real-time log monitoring
tail -f output/logs/app.log | grep -i error
```

### **Diagnostic Commands**

#### **System Information**
```bash
# System information for support
python main.py system-info

# Dependency information
python main.py dependency-info

# Performance statistics
python main.py performance-stats

# Cache information
python main.py cache-info

# Tool information
python main.py tool-info
```

---

## 📞 **Getting Help**

### **Self-Diagnosis Checklist**

#### **Before Seeking Help**
- [ ] Run `python verify_installation.py`
- [ ] Check `python main.py list-tools`
- [ ] Review log files in `output/logs/`
- [ ] Try with `--debug --verbose` flags
- [ ] Test with known good target (scanme.nmap.org)
- [ ] Check system requirements and dependencies
- [ ] Verify network connectivity to target

#### **Information to Gather**
```bash
# System information
uname -a
python --version
pip freeze | grep -E "(weasyprint|pdfkit|jinja2|click|rich|dnspython)"

# Framework information
python main.py version
python main.py info

# Tool versions
python main.py tool-versions

# Recent logs
tail -n 50 output/logs/app.log
```

### **Common Solution Patterns**

#### **Quick Fixes for Common Issues**
```bash
# 1. Permission issues
sudo python main.py scan target.com

# 2. PDF generation problems
pip install --upgrade weasyprint

# 3. Tool not found
sudo apt install nmap nikto dirb gobuster sslscan

# 4. Memory issues
python main.py scan target.com --sequential --max-threads 3

# 5. Network timeouts
python main.py scan target.com --timeout 120 --rate-limit 10

# 6. Cache problems
python main.py clear-cache --force

# 7. Configuration issues
cp .env.example .env && cp config/settings.py.example config/settings.py
```

### **Advanced Troubleshooting**

#### **Environment Reset**
```bash
# Complete environment reset (use with caution)
deactivate
rm -rf venv/
rm -rf output/cache/*
rm -rf output/logs/*

# Recreate environment
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
python verify_installation.py
```

#### **Minimal Test Setup**
```bash
# Test with minimal configuration
python main.py scan 127.0.0.1 --include-port --ports 22 --debug

# Test individual components
python -c "from src.core.scanner_base import ScannerBase; print('✅ Core OK')"
python -c "from src.scanners.recon.port_scanner import PortScanner; print('✅ Port Scanner OK')"
python -c "from src.utils.reporter import Reporter; print('✅ Reporter OK')"

# Test basic report generation
python main.py scan 127.0.0.1 --include-port --ports 22 --json-output
```

---

## 🎯 **Prevention Tips**

### **Avoiding Common Issues**

#### **Best Practices**
1. **Always test with safe targets first** (e.g., scanme.nmap.org)
2. **Use virtual environments** for Python dependencies
3. **Keep tools updated** but test compatibility
4. **Monitor system resources** during large scans
5. **Use appropriate scan profiles** for your environment
6. **Enable caching** for repeated assessments
7. **Regular log cleanup** to prevent disk space issues
8. **Backup working configurations** before changes

#### **Monitoring & Maintenance**
```bash
# Regular system maintenance
sudo apt update && sudo apt upgrade
pip list --outdated
python main.py cache-cleanup
python main.py log-rotation

# Performance monitoring
python main.py performance-stats
df -h output/
free -h

# Configuration backup
cp config/settings.py config/settings.py.backup
cp .env .env.backup
```

---

## 🚨 **Emergency Procedures**

### **System Recovery**

#### **Framework Not Responding**
```bash
# Kill stuck processes
pkill -f "python main.py"
pkill -f nmap
pkill -f nikto

# Check for zombie processes
ps aux | grep -E "(python|nmap|nikto)" | grep -v grep

# Reset environment
source venv/bin/activate
python main.py clear-cache --force
python main.py reset-config
```

#### **Disk Space Issues**
```bash
# Check disk usage
df -h
du -sh output/*

# Clean up old files
find output/logs/ -name "*.log" -mtime +7 -delete
find output/cache/ -name "*" -mtime +1 -delete
find output/reports/ -name "*" -mtime +30 -delete

# Emergency cleanup
python main.py emergency-cleanup
```

#### **System Overload**
```bash
# Reduce system load
python main.py scan target.com --sequential --max-threads 1 --rate-limit 5

# Monitor system load
top
htop
iotop

# Kill intensive processes if needed
kill -TERM $(pgrep -f "python main.py")
```

---

## 📋 **Quick Reference**

### **Common Error Codes**
- **Exit Code 1**: General error (check logs)
- **Exit Code 2**: Configuration error
- **Exit Code 3**: Network connectivity issue
- **Exit Code 4**: Tool execution failure
- **Exit Code 5**: Permission denied
- **Exit Code 6**: Memory/resource exhaustion
- **Exit Code 7**: Report generation failure

### **Emergency Commands**
```bash
# Stop all framework processes
pkill -f "auto-pentest"

# Emergency reset
python main.py emergency-reset

# Safe mode startup
python main.py safe-mode

# System diagnostic
python main.py diagnostic-full

# Recovery mode
python main.py recovery-mode
```

### **Support Information**
When seeking help, always include:
- Framework version (`python main.py version`)
- System information (`uname -a`, `python --version`)
- Error messages from logs
- Command that caused the issue
- Target type (if not sensitive)
- System resource availability

---

**🎯 Remember: Most issues can be resolved by following this guide systematically. Start with the quick diagnostic commands and work through the relevant sections based on your specific problem.**

**💡 Pro Tip: Enable debug mode (`--debug --verbose`) when troubleshooting to get detailed information about what's happening behind the scenes.**