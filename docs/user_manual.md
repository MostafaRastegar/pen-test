# Auto-Pentest Framework v0.9.1 - User Manual

## 🚀 Enhanced Features Overview

The Auto-Pentest Framework now includes advanced features for professional security assessments:

### 📑 New in v0.9.1
- **PDF Report Generation** - Professional PDF reports with custom branding
- **Compliance Reports** - PCI DSS, NIST, and ISO27001 compliance mapping
- **Performance Optimization** - Result caching, memory monitoring, and network optimization
- **Custom Branding** - Personalize reports with company logos and colors
- **Advanced Analytics** - Detailed performance metrics and cache statistics

## 📋 Quick Start Guide

### Basic Usage
```bash
# Quick scan with all report formats
python main.py quick target.com

# Comprehensive scan with custom reports
python main.py scan target.com --profile full --parallel --all-reports

# Generate PDF report with custom branding
python main.py scan target.com --pdf-report --custom-branding company.json
```

### Report Generation
```bash
# HTML and PDF reports
python main.py scan target.com --html-report --pdf-report

# Compliance assessment
python main.py scan target.com --compliance-report pci_dss

# Generate reports from existing scan data
python main.py generate-report results.json --pdf --html --executive
```

## 🔧 Advanced Configuration

### Custom Branding Setup
Create a JSON file with your company branding:

```json
{
  "company_name": "YourCompany Security",
  "company_logo": "data:image/svg+xml;base64,...",
  "primary_color": "#2563eb",
  "secondary_color": "#1e40af",
  "website": "https://yourcompany.com",
  "contact_email": "security@yourcompany.com"
}
```

Use with: `--custom-branding yourcompany.json`

### Performance Optimization
The framework automatically optimizes performance based on system resources:

- **Memory Monitoring**: Automatically adjusts scan intensity based on available memory
- **Result Caching**: Caches scan results for faster repeated scans (30-minute default TTL)
- **Network Optimization**: Connection pooling and retry logic for web requests

### Compliance Reporting
Generate compliance-specific reports:

```bash
# PCI DSS compliance assessment
python main.py scan target.com --compliance-report pci_dss

# NIST Cybersecurity Framework mapping  
python main.py scan target.com --compliance-report nist

# ISO 27001 controls assessment
python main.py scan target.com --compliance-report iso27001
```

## 📊 Command Reference

### Main Scan Command
```bash
python main.py scan TARGET [OPTIONS]
```

**Key Options:**
- `--profile {quick|full|web}` - Predefined scan profiles
- `--parallel` - Run scanners in parallel (faster)
- `--html-report` - Generate HTML report
- `--pdf-report` - Generate PDF report (requires weasyprint/pdfkit)
- `--exec-summary` - Generate executive summary
- `--all-reports` - Generate all report formats
- `--compliance-report {pci_dss|nist|iso27001}` - Compliance assessment
- `--custom-branding FILE` - Use custom branding

### Individual Scanner Commands
```bash
# Port scanning with caching
python main.py port target.com --ports top1000 --timing 4

# DNS enumeration  
python main.py dns target.com --subdomain-enum --zone-transfer

# Web application scanning
python main.py web https://target.com --use-nikto --check-headers

# Directory enumeration
python main.py directory target.com --tool gobuster --wordlist big

# SSL/TLS analysis
python main.py ssl target.com --port 443 --vulnerability-tests
```

### Utility Commands
```bash
# Show available tools and their status
python main.py list-tools

# Display framework information
python main.py info

# Performance and cache statistics
python main.py scan target.com --debug  # Shows performance stats in logs
```

## 📈 Performance Features

### Automatic Caching
Scan results are automatically cached to improve performance:
- **Cache Duration**: 30 minutes (configurable)
- **Cache Location**: `output/cache/` directory
- **Cache Size**: Up to 100 entries by default
- **Memory Monitoring**: Automatic cache cleanup under memory pressure

### Memory Optimization
- **Automatic Detection**: Monitors system memory usage
- **Adaptive Behavior**: Reduces scan intensity under memory pressure
- **Cleanup**: Automatic cleanup of expired cache entries

### Network Optimization
- **Connection Pooling**: Reuses HTTP connections for better performance
- **Retry Logic**: Automatic retries with exponential backoff
- **Rate Limiting**: Prevents overwhelming target systems

## 📑 Report Formats

### HTML Reports
Professional HTML reports with:
- Executive summary dashboard
- Interactive severity breakdown
- Detailed findings by category
- Custom branding support
- Print-friendly styling

### PDF Reports
Publication-ready PDF reports featuring:
- Professional layout and typography
- Company branding integration
- Executive summary page
- Detailed technical findings
- Compliance mapping (when applicable)

### Executive Summaries
Concise text summaries including:
- Risk assessment overview
- Key findings breakdown
- Prioritized recommendations
- Next steps guidance

### Compliance Reports
Framework-specific assessments with:
- Requirement mapping
- Compliance scoring
- Gap analysis
- Remediation roadmap

## 🛠️ Installation & Setup

### PDF Support Installation
```bash
# Option 1: WeasyPrint (recommended)
pip install weasyprint

# Option 2: PDFKit (requires wkhtmltopdf)
sudo apt install wkhtmltopdf  # Ubuntu/Debian
pip install pdfkit

# System dependencies for WeasyPrint
sudo apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
```

### Performance Dependencies
```bash
# Memory monitoring
pip install psutil

# Enhanced networking
pip install requests[security]
```

## 🔍 Troubleshooting

### PDF Generation Issues
```bash
# Check PDF library availability
python -c "import weasyprint; print('WeasyPrint available')"
python -c "import pdfkit; print('PDFKit available')"

# Install missing system dependencies
sudo apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
```

### Performance Issues
```bash
# Check memory usage
python main.py scan target.com --debug

# Clear cache if needed
rm -rf output/cache/*

# Use sequential scanning for stability
python main.py scan target.com --sequential
```

### Compliance Report Issues
```bash
# Verify compliance module
python -c "from src.utils.compliance_mapper import ComplianceMapper; print('OK')"

# Use basic compliance template if module unavailable
# (Framework will automatically fallback)
```

## 📞 Advanced Usage Examples

### Corporate Security Assessment
```bash
# Full assessment with branded PDF report
python main.py scan corporate-target.com \
  --profile full \
  --parallel \
  --pdf-report \
  --compliance-report pci_dss \
  --custom-branding corporate-brand.json \
  --output corporate-assessment
```

### Rapid Vulnerability Assessment
```bash
# Quick assessment with caching for speed
python main.py quick target.com
python main.py quick target2.com  # Uses cached results where applicable
```

### Compliance Audit Preparation
```bash
# Generate all compliance reports
python main.py scan target.com --compliance-report pci_dss --pdf-report
python main.py scan target.com --compliance-report nist --pdf-report  
python main.py scan target.com --compliance-report iso27001 --pdf-report
```

### Performance Monitoring
```bash
# Monitor performance during large scans
python main.py scan large-target.com --profile full --debug 2>&1 | tee scan.log
grep -E "(Performance|Cache|Memory)" scan.log
```

## 🎯 Best Practices

### For Performance
1. **Use Caching**: Let the framework cache results for faster repeated scans
2. **Monitor Memory**: Watch for memory warnings during large scans
3. **Parallel Execution**: Use `--parallel` for faster scans when system resources allow
4. **Profile Selection**: Choose appropriate scan profiles for your needs

### For Reporting
1. **Custom Branding**: Create professional reports with your organization's branding
2. **Multiple Formats**: Generate both HTML and PDF for different audiences
3. **Executive Summaries**: Always include executive summaries for management
4. **Compliance Mapping**: Use compliance reports for audit preparation

### For Security
1. **Regular Scans**: Schedule regular scans with caching for efficiency
2. **Incremental Assessment**: Use cached results to focus on changes
3. **Documentation**: Maintain scan history for trend analysis
4. **Compliance Tracking**: Regular compliance assessments for audit readiness

## 📚 API Reference

### Performance Manager
```python
from src.utils.performance import get_performance_manager

pm = get_performance_manager()
stats = pm.get_performance_stats()
print(f"Cache hit rate: {stats['cache']['hit_rate']}%")
```

### Custom Compliance Mapping
```python
from src.utils.compliance_mapper import ComplianceMapper

mapper = ComplianceMapper()
mapping = mapper.map_findings_to_compliance(findings, "pci_dss")
compliance_score = mapping['summary']['compliance_score']
```

### Report Generation
```python
from src.utils.reporter import generate_comprehensive_report

files = generate_comprehensive_report(
    results=scan_results,
    output_dir=Path("reports"),
    include_pdf=True,
    branding=custom_branding
)
```

## 🎉 Framework Capabilities Summary

### ✅ Complete Scanner Suite
- Port Scanner (with performance caching)
- DNS Enumeration  
- Web Application Scanner
- Directory/File Scanner
- SSL/TLS Analyzer

### ✅ Advanced Orchestration
- Parallel execution
- Dependency management
- Resource monitoring
- Memory optimization

### ✅ Professional Reporting
- HTML reports with custom branding
- PDF generation
- Executive summaries
- Compliance assessments (PCI DSS, NIST, ISO27001)

### ✅ Performance Features
- Intelligent result caching
- Memory pressure monitoring
- Network optimization
- Adaptive scan parameters

The Auto-Pentest Framework v0.9.1 is now production-ready for professional security assessments with enterprise-grade performance and reporting capabilities.