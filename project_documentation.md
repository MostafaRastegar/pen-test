# Auto-Pentest Tool - Project Documentation

## 🎯 Project Overview

An automated penetration testing framework built in Python that orchestrates various Linux security tools to perform comprehensive security assessments. The tool accepts a target (IP, domain, or URL) and automatically executes all necessary scans, vulnerability assessments, and generates detailed reports.

### Core Principles
- **Clean Code Architecture**: Single responsibility, clear separation of concerns
- **DRY (Don't Repeat Yourself)**: Reusable components and base classes
- **Security First**: Safe command execution with validation and sandboxing
- **Modular Design**: Easy to extend with new scanners and tools
- **Professional Output**: Structured logging and comprehensive reporting

## 📁 Project Structure

```
auto-pentest/
│
├── README.md                    # User documentation
├── requirements.txt             # Python dependencies
├── setup.py                     # Package installation
├── .env.example                 # Environment variables template
├── .gitignore                   # Git ignore file
│
├── config/                      # Configuration files
│   ├── __init__.py
│   ├── settings.py             # General settings and constants
│   └── tools_config.yaml       # Tool-specific configurations
│
├── src/                        # Main source code
│   ├── __init__.py
│   │
│   ├── core/                   # Core modules [✅ COMPLETED]
│   │   ├── __init__.py
│   │   ├── scanner_base.py    # Base scanner class
│   │   ├── executor.py        # Command execution engine
│   │   └── validator.py       # Input validation utilities
│   │
│   ├── scanners/              # Scanner modules [🚧 IN PROGRESS]
│   │   ├── __init__.py
│   │   ├── recon/            # Reconnaissance scanners
│   │   │   ├── __init__.py
│   │   │   ├── port_scanner.py      # [TODO] Nmap integration
│   │   │   ├── subdomain_scanner.py # [TODO] Subdomain enumeration
│   │   │   └── dns_scanner.py       # [TODO] DNS reconnaissance
│   │   │
│   │   ├── vulnerability/     # Vulnerability scanners
│   │   │   ├── __init__.py
│   │   │   ├── web_scanner.py       # [TODO] Nikto/Nuclei integration
│   │   │   ├── network_scanner.py   # [TODO] OpenVAS integration
│   │   │   └── ssl_scanner.py       # [TODO] SSL/TLS testing
│   │   │
│   │   └── exploit/          # Exploitation tools
│   │       ├── __init__.py
│   │       ├── sql_injection.py     # [TODO] SQLMap integration
│   │       └── xss_scanner.py       # [TODO] XSS testing
│   │
│   ├── utils/                # Utility modules
│   │   ├── __init__.py
│   │   ├── logger.py        # [✅ COMPLETED] Logging system
│   │   ├── reporter.py      # [TODO] Report generation
│   │   ├── parser.py        # [TODO] Output parsing
│   │   └── helpers.py       # [TODO] Helper functions
│   │
│   └── orchestrator/         # Workflow management
│       ├── __init__.py
│       ├── workflow.py       # [TODO] Scan workflow engine
│       └── scheduler.py      # [TODO] Task scheduling
│
├── templates/                 # Report templates
│   ├── report_html.jinja2   # [TODO] HTML report template
│   └── report_md.jinja2     # [TODO] Markdown report template
│
├── output/                    # Output directory
│   ├── logs/                 # Scan logs
│   ├── reports/              # Generated reports
│   └── raw/                  # Raw scanner output
│
├── tests/                     # Test suite
│   ├── __init__.py
│   ├── unit/                 # Unit tests
│   ├── integration/          # Integration tests
│   └── fixtures/             # Test data
│
└── main.py                    # [TODO] Main entry point

```

## ✅ Completed Components

### 1. Core Modules (`src/core/`)

#### **scanner_base.py**
- `ScannerBase`: Abstract base class for all scanners
- `ScanResult`: Standardized result structure
- `ScanStatus`: Enum for scan states (PENDING, RUNNING, COMPLETED, FAILED, CANCELLED)
- `ScanSeverity`: Vulnerability severity levels (INFO, LOW, MEDIUM, HIGH, CRITICAL)
- Features:
  - Automatic status management
  - JSON/file export capabilities
  - Finding categorization by severity
  - Metadata support

#### **executor.py**
- `CommandExecutor`: Safe system command execution
- `CommandResult`: Command execution results
- Features:
  - Synchronous execution with timeout
  - Asynchronous execution support
  - Streaming output capability
  - Process group management
  - Tool existence checking
  - Version detection

#### **validator.py**
- `InputValidator`: Central validation system
- Validation functions for:
  - IP addresses (IPv4/IPv6)
  - IP ranges (CIDR notation)
  - Domains (with optional DNS check)
  - URLs (with scheme validation)
  - Ports and port ranges
  - Email addresses
  - File paths
- Target type auto-detection
- Input sanitization

#### **logger.py**
- `LoggerSetup`: Centralized logging configuration
- `JsonFormatter`: Structured JSON logging
- `ColoredFormatter`: Colored console output
- Rich console integration with themes
- Progress bars and visual feedback
- Log rotation and separate error logs

### 2. Configuration Files

#### **settings.py**
- Environment variable loading
- Path configuration
- Tool path definitions
- Scan profiles (quick, full, web)

#### **tools_config.yaml**
- Tool binary paths
- Default arguments
- Profile-specific configurations

## 🚧 Components In Development

### Phase 1: Scanner Implementation (Current Phase)

#### 1. Port Scanner (`port_scanner.py`)
```python
class PortScanner(ScannerBase):
    - Nmap integration
    - TCP/UDP scanning
    - Service detection
    - OS fingerprinting
    - Script scanning
```

#### 2. Subdomain Scanner (`subdomain_scanner.py`)
```python
class SubdomainScanner(ScannerBase):
    - Multiple tool integration (subfinder, amass)
    - DNS brute forcing
    - Certificate transparency logs
    - Permutation generation
```

#### 3. Web Scanner (`web_scanner.py`)
```python
class WebScanner(ScannerBase):
    - Nikto integration
    - Directory fuzzing
    - Technology detection
    - Common vulnerability checks
```

### Phase 2: Orchestrator Development

#### Workflow Engine (`workflow.py`)
- Scan pipeline management
- Dependency resolution
- Parallel execution
- Result aggregation

#### Task Scheduler (`scheduler.py`)
- Thread pool management
- Priority queuing
- Resource limiting
- Progress tracking

### Phase 3: Reporting System

#### Report Generator (`reporter.py`)
- Multiple format support (HTML, PDF, JSON, Markdown)
- Executive summary generation
- Vulnerability prioritization
- Remediation recommendations
- Evidence attachment

### Phase 4: CLI Interface

#### Main Entry Point (`main.py`)
```python
Features:
- Interactive mode
- Batch processing
- Profile selection
- Custom configurations
- Real-time progress display
```

## 🔧 Tool Integrations

### Reconnaissance Tools
| Tool | Purpose | Status | Linux Package |
|------|---------|--------|---------------|
| nmap | Port scanning | TODO | `nmap` |
| masscan | Fast port scanning | TODO | `masscan` |
| subfinder | Subdomain enumeration | TODO | `subfinder` |
| amass | Attack surface mapping | TODO | `amass` |
| dnsrecon | DNS enumeration | TODO | `dnsrecon` |
| whatweb | Technology identification | TODO | `whatweb` |

### Vulnerability Scanners
| Tool | Purpose | Status | Linux Package |
|------|---------|--------|---------------|
| nikto | Web server scanner | TODO | `nikto` |
| nuclei | Template-based scanner | TODO | `nuclei` |
| wpscan | WordPress scanner | TODO | `wpscan` |
| sqlmap | SQL injection | TODO | `sqlmap` |
| sslscan | SSL/TLS testing | TODO | `sslscan` |

### Directory/Fuzzing Tools
| Tool | Purpose | Status | Linux Package |
|------|---------|--------|---------------|
| dirb | Directory brute force | TODO | `dirb` |
| gobuster | Directory/DNS/vhost fuzzing | TODO | `gobuster` |
| wfuzz | Web fuzzer | TODO | `wfuzz` |
| ffuf | Fast web fuzzer | TODO | `ffuf` |

## 🎯 Features Roadmap

### MVP Features (v1.0)
- [x] Core framework implementation
- [x] Command execution engine
- [x] Input validation system
- [x] Logging infrastructure
- [ ] Basic port scanning
- [ ] Subdomain enumeration
- [ ] Web vulnerability scanning
- [ ] Basic reporting (JSON/HTML)
- [ ] CLI interface

### Advanced Features (v2.0)
- [ ] API scanning capabilities
- [ ] Authenticated scanning
- [ ] Custom wordlist management
- [ ] Exploit verification
- [ ] Real-time notifications
- [ ] Web UI dashboard
- [ ] Docker containerization
- [ ] CI/CD integration

### Enterprise Features (v3.0)
- [ ] Multi-target scanning
- [ ] Distributed scanning
- [ ] Role-based access control
- [ ] Compliance reporting (PCI, HIPAA)
- [ ] Integration with ticketing systems
- [ ] Custom plugin system
- [ ] Machine learning for false positive reduction

## 💻 Development Guidelines

### Code Style
- Follow PEP 8 guidelines
- Use type hints for all functions
- Write comprehensive docstrings
- Maintain test coverage above 80%

### Git Workflow
1. Feature branches from `develop`
2. Descriptive commit messages
3. Pull requests with review
4. Semantic versioning

### Testing Strategy
- Unit tests for all modules
- Integration tests for scanners
- End-to-end workflow tests
- Performance benchmarks

## 🚀 Next Steps

### Immediate Tasks (Continue from here)
1. **Implement Port Scanner**
   - Create `src/scanners/recon/port_scanner.py`
   - Integrate nmap with service detection
   - Parse and structure results
   - Add unit tests

2. **Create CLI Interface**
   - Implement `main.py` with Click
   - Add command structure
   - Interactive mode support
   - Progress display

3. **Build First Workflow**
   - Simple recon workflow
   - Port scan → Service detection → Report
   - Test with real targets

### Code Example to Continue

```python
# src/scanners/recon/port_scanner.py
from src.core import ScannerBase, ScanResult, CommandExecutor
import xml.etree.ElementTree as ET

class PortScanner(ScannerBase):
    def __init__(self):
        super().__init__("port_scanner")
        self.executor = CommandExecutor(timeout=300)
    
    def _execute_scan(self, target: str, options: dict) -> ScanResult:
        # Implement nmap integration here
        pass
```

## 📝 Environment Setup

### Required System Tools
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y nmap nikto sqlmap dirb gobuster \
    sslscan dnsrecon whois masscan wfuzz

# Python dependencies
pip install -r requirements.txt
```

### Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit configuration
vim config/settings.py
```

## 🔒 Security Considerations

1. **Input Validation**: All user inputs are validated before processing
2. **Command Injection Prevention**: Using subprocess with arrays, not shell=True
3. **Resource Limits**: Timeouts and memory limits on all operations
4. **Output Sanitization**: Preventing XSS in HTML reports
5. **Secure Storage**: Sensitive data encrypted at rest

## 📊 Performance Targets

- Scan initiation: < 1 second
- Port scan (1000 ports): < 60 seconds
- Full scan completion: < 10 minutes
- Report generation: < 5 seconds
- Memory usage: < 500MB per scan

## 🤝 Contributing

### How to Add a New Scanner
1. Create new file in appropriate `src/scanners/` subdirectory
2. Inherit from `ScannerBase`
3. Implement required methods
4. Add configuration to `tools_config.yaml`
5. Write unit tests
6. Update documentation

### Code Review Checklist
- [ ] Type hints added
- [ ] Docstrings complete
- [ ] Error handling implemented
- [ ] Logging added
- [ ] Tests written
- [ ] Documentation updated

## 📞 Contact & Support

- GitHub Issues: For bug reports and feature requests
- Documentation: This file and inline code documentation
- Testing: Run `pytest` for test suite

---

**Last Updated**: Current session
**Version**: 0.1.0-dev
**Status**: Active Development