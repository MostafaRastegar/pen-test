# Auto-Pentest Framework v0.9.1 - API Documentation

## 📋 **API Overview**

The Auto-Pentest Framework provides a comprehensive, modular API architecture that enables developers to:

- **Extend the framework** with custom scanners and tools
- **Integrate the framework** into existing security platforms
- **Build custom workflows** and automation scripts
- **Create specialized reporting** and analytics solutions
- **Develop plugins** and third-party integrations

### **🏗️ Architecture Layers**

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│                  (CLI, Web UI, APIs)                       │
├─────────────────────────────────────────────────────────────┤
│                  Orchestration Layer                       │
│              (Workflows, Task Scheduling)                  │
├─────────────────────────────────────────────────────────────┤
│                    Scanner Layer                           │
│         (Port, DNS, Web, Directory, SSL Scanners)         │
├─────────────────────────────────────────────────────────────┤
│                     Core Layer                            │
│          (Base Classes, Executors, Validators)            │
├─────────────────────────────────────────────────────────────┤
│                   Utility Layer                           │
│        (Logging, Reporting, Caching, Performance)         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 **Core Framework APIs**

### **ScannerBase Class**

The foundation class for all security scanners.

```python
# Location: src/core/scanner_base.py

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ScanResult:
    """Standard scan result structure"""
    scanner_name: str
    target: str
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    execution_time: float
    success: bool
    error_message: Optional[str] = None

class ScannerBase(ABC):
    """Abstract base class for all scanners"""
    
    def __init__(self, scanner_name: str):
        """
        Initialize scanner
        
        Args:
            scanner_name: Unique identifier for the scanner
        """
        self.scanner_name = scanner_name
        self.logger = self._setup_logger()
        self.cache_manager = self._get_cache_manager()
    
    @abstractmethod
    def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """
        Execute scan against target
        
        Args:
            target: Target to scan (IP, domain, URL)
            options: Scanner-specific options
            
        Returns:
            ScanResult: Structured scan results
        """
        pass
    
    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """
        Validate target format for this scanner
        
        Args:
            target: Target to validate
            
        Returns:
            bool: True if target is valid
        """
        pass
    
    @abstractmethod
    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get scanner capabilities and metadata
        
        Returns:
            dict: Scanner capabilities information
        """
        pass
    
    def _setup_logger(self):
        """Setup scanner-specific logging"""
        from utils.logger import get_logger
        return get_logger(f"scanner.{self.scanner_name}")
    
    def _get_cache_manager(self):
        """Get cache manager instance"""
        from utils.cache import CacheManager
        return CacheManager(scanner_name=self.scanner_name)
```

#### **Usage Example:**

```python
from src.core.scanner_base import ScannerBase, ScanResult, SeverityLevel

class CustomScanner(ScannerBase):
    def __init__(self):
        super().__init__("custom_scanner")
    
    def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """Custom scan implementation"""
        start_time = time.time()
        
        try:
            # Implement your scanning logic here
            findings = self._execute_custom_scan(target, options or {})
            
            return ScanResult(
                scanner_name=self.scanner_name,
                target=target,
                findings=findings,
                metadata={"scan_type": "custom", "options": options},
                execution_time=time.time() - start_time,
                success=True
            )
        except Exception as e:
            return ScanResult(
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                metadata={},
                execution_time=time.time() - start_time,
                success=False,
                error_message=str(e)
            )
    
    def validate_target(self, target: str) -> bool:
        """Validate target for custom scanner"""
        # Implement validation logic
        return True
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Return scanner capabilities"""
        return {
            "name": "Custom Scanner",
            "description": "Custom security scanner implementation",
            "supported_targets": ["ip", "domain", "url"],
            "features": ["custom_check_1", "custom_check_2"]
        }
```

### **CommandExecutor Class**

Secure command execution with timeout and validation.

```python
# Location: src/core/executor.py

import subprocess
import shlex
from typing import List, Dict, Optional, Union
from dataclasses import dataclass

@dataclass
class CommandResult:
    """Command execution result"""
    command: str
    returncode: int
    stdout: str
    stderr: str
    execution_time: float
    success: bool

class CommandExecutor:
    """Secure command execution engine"""
    
    def __init__(self, timeout: int = 300, working_dir: Optional[str] = None):
        """
        Initialize command executor
        
        Args:
            timeout: Default command timeout in seconds
            working_dir: Working directory for command execution
        """
        self.timeout = timeout
        self.working_dir = working_dir
        self.logger = self._setup_logger()
    
    def execute(self, 
                command: Union[str, List[str]], 
                timeout: Optional[int] = None,
                capture_output: bool = True,
                check: bool = False,
                env: Optional[Dict[str, str]] = None) -> CommandResult:
        """
        Execute command securely
        
        Args:
            command: Command string or list of arguments
            timeout: Command timeout (uses default if None)
            capture_output: Capture stdout/stderr
            check: Raise exception on non-zero exit
            env: Environment variables
            
        Returns:
            CommandResult: Execution result
        """
        import time
        
        start_time = time.time()
        
        # Sanitize command
        if isinstance(command, str):
            command = shlex.split(command)
        
        # Validate command
        self._validate_command(command)
        
        try:
            result = subprocess.run(
                command,
                timeout=timeout or self.timeout,
                capture_output=capture_output,
                text=True,
                cwd=self.working_dir,
                env=env,
                check=check
            )
            
            execution_time = time.time() - start_time
            
            return CommandResult(
                command=' '.join(command),
                returncode=result.returncode,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                execution_time=execution_time,
                success=result.returncode == 0
            )
            
        except subprocess.TimeoutExpired as e:
            return CommandResult(
                command=' '.join(command),
                returncode=-1,
                stdout="",
                stderr=f"Command timeout after {timeout or self.timeout}s",
                execution_time=timeout or self.timeout,
                success=False
            )
        except Exception as e:
            return CommandResult(
                command=' '.join(command),
                returncode=-1,
                stdout="",
                stderr=str(e),
                execution_time=time.time() - start_time,
                success=False
            )
    
    def _validate_command(self, command: List[str]):
        """Validate command for security"""
        if not command:
            raise ValueError("Empty command")
        
        # Check for command injection patterns
        dangerous_chars = [';', '|', '&', '$(', '`']
        command_str = ' '.join(command)
        
        for char in dangerous_chars:
            if char in command_str:
                self.logger.warning(f"Potentially dangerous character '{char}' in command")
    
    def _setup_logger(self):
        """Setup executor logging"""
        from utils.logger import get_logger
        return get_logger("core.executor")
```

#### **Usage Example:**

```python
from src.core.executor import CommandExecutor

# Initialize executor
executor = CommandExecutor(timeout=60)

# Execute nmap scan
result = executor.execute([
    'nmap', '-sS', '-O', '-sV', 
    '-oX', 'scan_results.xml', 
    '192.168.1.1'
])

if result.success:
    print(f"Scan completed in {result.execution_time:.2f}s")
    # Process result.stdout
else:
    print(f"Scan failed: {result.stderr}")
```

### **InputValidator Class**

Comprehensive input validation and sanitization.

```python
# Location: src/core/validator.py

import re
import ipaddress
from urllib.parse import urlparse
from typing import Union, List, Optional
import validators

class ValidationError(Exception):
    """Input validation error"""
    pass

class InputValidator:
    """Input validation and sanitization"""
    
    @staticmethod
    def validate_ip(ip_str: str) -> bool:
        """
        Validate IP address
        
        Args:
            ip_str: IP address string
            
        Returns:
            bool: True if valid IP
        """
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """
        Validate domain name
        
        Args:
            domain: Domain name string
            
        Returns:
            bool: True if valid domain
        """
        if not domain or len(domain) > 255:
            return False
        
        # Basic domain regex
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        return bool(re.match(domain_pattern, domain))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """
        Validate URL
        
        Args:
            url: URL string
            
        Returns:
            bool: True if valid URL
        """
        return validators.url(url)
    
    @staticmethod
    def validate_port_range(port_range: str) -> bool:
        """
        Validate port range (e.g., "80", "80-443", "22,80,443")
        
        Args:
            port_range: Port range string
            
        Returns:
            bool: True if valid port range
        """
        try:
            ports = []
            for part in port_range.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    if not (1 <= start <= end <= 65535):
                        return False
                    ports.extend(range(start, end + 1))
                else:
                    port = int(part)
                    if not (1 <= port <= 65535):
                        return False
                    ports.append(port)
            return True
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize filename for safe filesystem usage
        
        Args:
            filename: Original filename
            
        Returns:
            str: Sanitized filename
        """
        # Remove dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Limit length
        sanitized = sanitized[:255]
        # Remove leading/trailing dots and spaces
        sanitized = sanitized.strip('. ')
        return sanitized or "unnamed"
    
    @classmethod
    def validate_target(cls, target: str, target_type: str = "auto") -> str:
        """
        Validate and normalize target
        
        Args:
            target: Target string (IP, domain, or URL)
            target_type: Expected target type ("ip", "domain", "url", "auto")
            
        Returns:
            str: Normalized target
            
        Raises:
            ValidationError: If target is invalid
        """
        target = target.strip()
        
        if not target:
            raise ValidationError("Empty target")
        
        if target_type == "auto":
            # Auto-detect target type
            if cls.validate_ip(target):
                return target
            elif cls.validate_url(target):
                return target
            elif cls.validate_domain(target):
                return target
            else:
                raise ValidationError(f"Invalid target format: {target}")
        
        elif target_type == "ip":
            if not cls.validate_ip(target):
                raise ValidationError(f"Invalid IP address: {target}")
            return target
        
        elif target_type == "domain":
            if not cls.validate_domain(target):
                raise ValidationError(f"Invalid domain name: {target}")
            return target
        
        elif target_type == "url":
            if not cls.validate_url(target):
                raise ValidationError(f"Invalid URL: {target}")
            return target
        
        else:
            raise ValidationError(f"Unknown target type: {target_type}")
```

#### **Usage Example:**

```python
from src.core.validator import InputValidator, ValidationError

validator = InputValidator()

# Validate different target types
try:
    ip = validator.validate_target("192.168.1.1", "ip")
    domain = validator.validate_target("example.com", "domain")
    url = validator.validate_target("https://example.com", "url")
    
    # Auto-detect target type
    target = validator.validate_target("example.com", "auto")
    
except ValidationError as e:
    print(f"Validation error: {e}")

# Validate port ranges
if validator.validate_port_range("80,443,8080-8090"):
    print("Valid port range")

# Sanitize filenames
safe_filename = validator.sanitize_filename("report<test>.html")
```

---

## 🔍 **Scanner APIs**

### **Port Scanner API**

```python
# Location: src/scanners/recon/port_scanner.py

from src.core.scanner_base import ScannerBase, ScanResult
from src.core.executor import CommandExecutor
from typing import Dict, List, Any, Optional
import xml.etree.ElementTree as ET

class PortScanner(ScannerBase):
    """Network port scanner using Nmap"""
    
    def __init__(self):
        super().__init__("port_scanner")
        self.executor = CommandExecutor(timeout=600)
    
    def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """
        Execute port scan
        
        Args:
            target: Target IP or domain
            options: Scan options
                - ports: Port range (default: "1-1000")
                - scan_type: Scan type ("tcp", "udp", "both")
                - service_detection: Enable service detection
                - os_detection: Enable OS detection
                - script_scan: Enable NSE scripts
                - stealth: Use stealth scanning
                
        Returns:
            ScanResult: Port scan results
        """
        options = options or {}
        
        # Build nmap command
        command = self._build_nmap_command(target, options)
        
        # Execute scan
        result = self.executor.execute(command)
        
        if result.success:
            # Parse XML output
            findings = self._parse_nmap_xml(result.stdout)
            return ScanResult(
                scanner_name=self.scanner_name,
                target=target,
                findings=findings,
                metadata={
                    "command": result.command,
                    "scan_options": options
                },
                execution_time=result.execution_time,
                success=True
            )
        else:
            return ScanResult(
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                metadata={"command": result.command},
                execution_time=result.execution_time,
                success=False,
                error_message=result.stderr
            )
    
    def _build_nmap_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        """Build nmap command based on options"""
        command = ["nmap"]
        
        # Port specification
        ports = options.get("ports", "1-1000")
        command.extend(["-p", ports])
        
        # Scan type
        scan_type = options.get("scan_type", "tcp")
        if scan_type == "tcp":
            command.append("-sS")
        elif scan_type == "udp":
            command.append("-sU")
        elif scan_type == "both":
            command.extend(["-sS", "-sU"])
        
        # Service detection
        if options.get("service_detection", True):
            command.append("-sV")
        
        # OS detection
        if options.get("os_detection", False):
            command.append("-O")
        
        # Script scanning
        if options.get("script_scan", False):
            command.append("-sC")
        
        # Stealth mode
        if options.get("stealth", False):
            command.extend(["-f", "-T2"])
        
        # Output format
        command.extend(["-oX", "-"])  # XML to stdout
        
        # Target
        command.append(target)
        
        return command
    
    def _parse_nmap_xml(self, xml_output: str) -> List[Dict[str, Any]]:
        """Parse nmap XML output"""
        findings = []
        
        try:
            root = ET.fromstring(xml_output)
            
            for host in root.findall('.//host'):
                host_findings = self._parse_host(host)
                findings.extend(host_findings)
                
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse nmap XML: {e}")
        
        return findings
    
    def _parse_host(self, host_element) -> List[Dict[str, Any]]:
        """Parse individual host from nmap XML"""
        findings = []
        
        # Get host IP
        address_elem = host_element.find('.//address[@addrtype="ipv4"]')
        if address_elem is None:
            return findings
        
        host_ip = address_elem.get('addr')
        
        # Get hostname if available
        hostname_elem = host_element.find('.//hostname')
        hostname = hostname_elem.get('name') if hostname_elem is not None else None
        
        # Parse ports
        for port in host_element.findall('.//port'):
            port_info = self._parse_port(port, host_ip, hostname)
            if port_info:
                findings.append(port_info)
        
        return findings
    
    def _parse_port(self, port_element, host_ip: str, hostname: Optional[str]) -> Optional[Dict[str, Any]]:
        """Parse individual port information"""
        port_id = port_element.get('portid')
        protocol = port_element.get('protocol')
        
        state_elem = port_element.find('state')
        if state_elem is None:
            return None
        
        state = state_elem.get('state')
        
        # Only include open ports
        if state != 'open':
            return None
        
        # Get service information
        service_elem = port_element.find('service')
        service_info = {}
        
        if service_elem is not None:
            service_info = {
                'name': service_elem.get('name', 'unknown'),
                'version': service_elem.get('version', ''),
                'product': service_elem.get('product', ''),
                'extrainfo': service_elem.get('extrainfo', '')
            }
        
        # Determine severity
        severity = self._assess_port_severity(int(port_id), service_info.get('name', ''))
        
        return {
            'type': 'open_port',
            'host': host_ip,
            'hostname': hostname,
            'port': int(port_id),
            'protocol': protocol,
            'state': state,
            'service': service_info,
            'severity': severity.value,
            'description': f"Open {protocol.upper()} port {port_id} ({service_info.get('name', 'unknown')})",
            'recommendation': self._get_port_recommendation(int(port_id), service_info.get('name', ''))
        }
    
    def _assess_port_severity(self, port: int, service: str) -> SeverityLevel:
        """Assess security severity of open port"""
        # High-risk ports
        high_risk_ports = [21, 22, 23, 25, 53, 135, 139, 445, 1433, 1521, 3389, 5432]
        
        # Administrative/remote access ports
        admin_ports = [22, 23, 3389, 5900, 5901]
        
        if port in admin_ports:
            return SeverityLevel.HIGH
        elif port in high_risk_ports:
            return SeverityLevel.MEDIUM
        elif port < 1024:  # Well-known ports
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
```

#### **Usage Example:**

```python
from src.scanners.recon.port_scanner import PortScanner

# Initialize scanner
scanner = PortScanner()

# Basic scan
result = scanner.scan("192.168.1.1")

# Advanced scan with options
result = scanner.scan("example.com", {
    "ports": "1-65535",
    "service_detection": True,
    "os_detection": True,
    "script_scan": True
})

# Process results
if result.success:
    for finding in result.findings:
        if finding['type'] == 'open_port':
            print(f"Port {finding['port']}: {finding['service']['name']}")
```

### **DNS Scanner API**

```python
# Location: src/scanners/recon/dns_scanner.py

import dns.resolver
import dns.zone
import dns.query
from typing import Dict, List, Any, Optional

class DNSScanner(ScannerBase):
    """DNS enumeration and security scanner"""
    
    def __init__(self):
        super().__init__("dns_scanner")
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 10
        self.resolver.lifetime = 30
    
    def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """
        Execute DNS scan
        
        Args:
            target: Target domain
            options: Scan options
                - record_types: DNS record types to query
                - subdomain_enum: Enable subdomain enumeration
                - zone_transfer: Test zone transfers
                - security_analysis: Enable security analysis
                - dns_servers: Custom DNS servers
                
        Returns:
            ScanResult: DNS scan results
        """
        options = options or {}
        findings = []
        
        try:
            # Basic DNS record enumeration
            if options.get("record_enumeration", True):
                findings.extend(self._enumerate_dns_records(target, options))
            
            # Subdomain enumeration
            if options.get("subdomain_enum", False):
                findings.extend(self._enumerate_subdomains(target, options))
            
            # Zone transfer testing
            if options.get("zone_transfer", False):
                findings.extend(self._test_zone_transfer(target))
            
            # Security analysis
            if options.get("security_analysis", False):
                findings.extend(self._security_analysis(target))
            
            return ScanResult(
                scanner_name=self.scanner_name,
                target=target,
                findings=findings,
                metadata={"scan_options": options},
                execution_time=0,  # Calculate actual time
                success=True
            )
            
        except Exception as e:
            return ScanResult(
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                metadata={},
                execution_time=0,
                success=False,
                error_message=str(e)
            )
    
    def _enumerate_dns_records(self, domain: str, options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enumerate DNS records"""
        findings = []
        record_types = options.get("record_types", ["A", "AAAA", "MX", "NS", "TXT", "SOA"])
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                for rdata in answers:
                    findings.append({
                        'type': 'dns_record',
                        'domain': domain,
                        'record_type': record_type,
                        'value': str(rdata),
                        'ttl': answers.ttl,
                        'severity': 'info',
                        'description': f"{record_type} record for {domain}: {rdata}"
                    })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception as e:
                self.logger.warning(f"Error querying {record_type} for {domain}: {e}")
        
        return findings
    
    def _enumerate_subdomains(self, domain: str, options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enumerate subdomains"""
        findings = []
        wordlist = options.get("subdomain_wordlist", self._get_default_subdomain_wordlist())
        
        for subdomain in wordlist:
            full_domain = f"{subdomain}.{domain}"
            try:
                answers = self.resolver.resolve(full_domain, "A")
                for rdata in answers:
                    findings.append({
                        'type': 'subdomain',
                        'domain': full_domain,
                        'ip': str(rdata),
                        'severity': 'info',
                        'description': f"Subdomain found: {full_domain} -> {rdata}"
                    })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
        
        return findings
    
    def _get_default_subdomain_wordlist(self) -> List[str]:
        """Get default subdomain wordlist"""
        return [
            "www", "mail", "ftp", "admin", "test", "dev", "staging", 
            "api", "app", "secure", "vpn", "remote", "support"
        ]
```

---

## 🎼 **Orchestrator APIs**

### **Workflow Orchestrator**

```python
# Location: src/orchestrator/orchestrator.py

from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import asyncio
import concurrent.futures
from src.core.scanner_base import ScannerBase, ScanResult

class ExecutionMode(Enum):
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    MIXED = "mixed"

@dataclass
class WorkflowStep:
    """Workflow step definition"""
    scanner_name: str
    scanner_class: type
    options: Dict[str, Any]
    dependencies: List[str]
    timeout: Optional[int] = None

@dataclass
class WorkflowResult:
    """Workflow execution result"""
    workflow_id: str
    target: str
    steps_completed: int
    total_steps: int
    results: Dict[str, ScanResult]
    execution_time: float
    success: bool
    error_message: Optional[str] = None

class WorkflowOrchestrator:
    """Advanced workflow orchestration engine"""
    
    def __init__(self, max_workers: int = 10):
        """
        Initialize orchestrator
        
        Args:
            max_workers: Maximum concurrent workers
        """
        self.max_workers = max_workers
        self.logger = self._setup_logger()
        self.performance_monitor = self._get_performance_monitor()
    
    def execute_workflow(self,
                        workflow_id: str,
                        target: str,
                        steps: List[WorkflowStep],
                        execution_mode: ExecutionMode = ExecutionMode.PARALLEL,
                        global_timeout: Optional[int] = None) -> WorkflowResult:
        """
        Execute workflow with specified steps
        
        Args:
            workflow_id: Unique workflow identifier
            target: Target for scanning
            steps: List of workflow steps
            execution_mode: Execution mode (parallel/sequential/mixed)
            global_timeout: Global workflow timeout
            
        Returns:
            WorkflowResult: Workflow execution results
        """
        import time
        start_time = time.time()
        
        try:
            if execution_mode == ExecutionMode.PARALLEL:
                results = self._execute_parallel(target, steps, global_timeout)
            elif execution_mode == ExecutionMode.SEQUENTIAL:
                results = self._execute_sequential(target, steps, global_timeout)
            else:  # MIXED
                results = self._execute_mixed(target, steps, global_timeout)
            
            execution_time = time.time() - start_time
            
            return WorkflowResult(
                workflow_id=workflow_id,
                target=target,
                steps_completed=len([r for r in results.values() if r.success]),
                total_steps=len(steps),
                results=results,
                execution_time=execution_time,
                success=all(r.success for r in results.values())
            )
            
        except Exception as e:
            return WorkflowResult(
                workflow_id=workflow_id,
                target=target,
                steps_completed=0,
                total_steps=len(steps),
                results={},
                execution_time=time.time() - start_time,
                success=False,
                error_message=str(e)
            )
    
    def _execute_parallel(self, 
                         target: str, 
                         steps: List[WorkflowStep],
                         global_timeout: Optional[int]) -> Dict[str, ScanResult]:
        """Execute steps in parallel"""
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_step = {}
            for step in steps:
                scanner = step.scanner_class()
                future = executor.submit(scanner.scan, target, step.options)
                future_to_step[future] = step
            
            # Collect results
            for future in concurrent.futures.as_completed(
                future_to_step, 
                timeout=global_timeout
            ):
                step = future_to_step[future]
                try:
                    result = future.result()
                    results[step.scanner_name] = result
                except Exception as e:
                    # Create error result
                    results[step.scanner_name] = ScanResult(
                        scanner_name=step.scanner_name,
                        target=target,
                        findings=[],
                        metadata={},
                        execution_time=0,
                        success=False,
                        error_message=str(e)
                    )
        
        return results
    
    def _execute_sequential(self,
                           target: str,
                           steps: List[WorkflowStep],
                           global_timeout: Optional[int]) -> Dict[str, ScanResult]:
        """Execute steps sequentially"""
        results = {}
        
        for step in steps:
            try:
                scanner = step.scanner_class()
                result = scanner.scan(target, step.options)
                results[step.scanner_name] = result
                
                # Stop on failure if required
                if not result.success:
                    self.logger.warning(f"Step {step.scanner_name} failed: {result.error_message}")
                
            except Exception as e:
                results[step.scanner_name] = ScanResult(
                    scanner_name=step.scanner_name,
                    target=target,
                    findings=[],
                    metadata={},
                    execution_time=0,
                    success=False,
                    error_message=str(e)
                )
        
        return results
    
    def create_scan_profile(self, profile_name: str) -> List[WorkflowStep]:
        """
        Create predefined scan profiles
        
        Args:
            profile_name: Profile name ("quick", "web", "full", "custom")
            
        Returns:
            List[WorkflowStep]: Workflow steps for profile
        """
        from src.scanners.recon.port_scanner import PortScanner
        from src.scanners.recon.dns_scanner import DNSScanner
        from src.scanners.vulnerability.web_scanner import WebScanner
        from src.scanners.vulnerability.directory_scanner import DirectoryScanner
        from src.scanners.vulnerability.ssl_scanner import SSLScanner
        
        if profile_name == "quick":
            return [
                WorkflowStep(
                    scanner_name="port_scanner",
                    scanner_class=PortScanner,
                    options={"ports": "1-1000", "service_detection": True},
                    dependencies=[]
                )
            ]
        
        elif profile_name == "web":
            return [
                WorkflowStep(
                    scanner_name="web_scanner",
                    scanner_class=WebScanner,
                    options={"use_nikto": True},
                    dependencies=[]
                ),
                WorkflowStep(
                    scanner_name="directory_scanner",
                    scanner_class=DirectoryScanner,
                    options={"wordlist": "common"},
                    dependencies=[]
                ),
                WorkflowStep(
                    scanner_name="ssl_scanner",
                    scanner_class=SSLScanner,
                    options={"detailed_analysis": True},
                    dependencies=[]
                )
            ]
        
        elif profile_name == "full":
            return [
                WorkflowStep(
                    scanner_name="port_scanner",
                    scanner_class=PortScanner,
                    options={"ports": "1-65535", "service_detection": True, "os_detection": True},
                    dependencies=[]
                ),
                WorkflowStep(
                    scanner_name="dns_scanner",
                    scanner_class=DNSScanner,
                    options={"subdomain_enum": True, "security_analysis": True},
                    dependencies=[]
                ),
                WorkflowStep(
                    scanner_name="web_scanner",
                    scanner_class=WebScanner,
                    options={"use_nikto": True, "comprehensive": True},
                    dependencies=[]
                ),
                WorkflowStep(
                    scanner_name="directory_scanner",
                    scanner_class=DirectoryScanner,
                    options={"wordlist": "big", "recursive": True},
                    dependencies=["web_scanner"]
                ),
                WorkflowStep(
                    scanner_name="ssl_scanner",
                    scanner_class=SSLScanner,
                    options={"detailed_analysis": True, "vulnerability_check": True},
                    dependencies=["port_scanner"]
                )
            ]
        
        else:
            raise ValueError(f"Unknown profile: {profile_name}")
```

#### **Usage Example:**

```python
from src.orchestrator.orchestrator import WorkflowOrchestrator, ExecutionMode

# Initialize orchestrator
orchestrator = WorkflowOrchestrator(max_workers=5)

# Create workflow using predefined profile
steps = orchestrator.create_scan_profile("full")

# Execute workflow
result = orchestrator.execute_workflow(
    workflow_id="full_scan_001",
    target="example.com",
    steps=steps,
    execution_mode=ExecutionMode.PARALLEL
)

# Process results
if result.success:
    print(f"Workflow completed in {result.execution_time:.2f}s")
    for scanner_name, scan_result in result.results.items():
        print(f"{scanner_name}: {len(scan_result.findings)} findings")
else:
    print(f"Workflow failed: {result.error_message}")
```

---

## 📊 **Reporter APIs**

### **Report Generation**

```python
# Location: src/utils/reporter.py

from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import json
from datetime import datetime

class ReportFormat(Enum):
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    TXT = "txt"
    CSV = "csv"

@dataclass
class ReportConfig:
    """Report generation configuration"""
    format: ReportFormat
    include_executive_summary: bool = True
    include_technical_details: bool = True
    custom_branding: Optional[Dict[str, Any]] = None
    compliance_framework: Optional[str] = None
    output_dir: Optional[Path] = None

class Reporter:
    """Professional report generation engine"""
    
    def __init__(self):
        self.logger = self._setup_logger()
        self.template_engine = self._setup_template_engine()
    
    def generate_comprehensive_report(self,
                                    results: Dict[str, Any],
                                    target: str,
                                    config: ReportConfig) -> Dict[str, Path]:
        """
        Generate comprehensive security assessment report
        
        Args:
            results: Consolidated scan results
            target: Target that was scanned
            config: Report generation configuration
            
        Returns:
            Dict[str, Path]: Generated report files by format
        """
        generated_files = {}
        
        # Prepare report data
        report_data = self._prepare_report_data(results, target, config)
        
        try:
            if config.format == ReportFormat.HTML:
                file_path = self._generate_html_report(report_data, config)
                generated_files['html'] = file_path
            
            elif config.format == ReportFormat.PDF:
                file_path = self._generate_pdf_report(report_data, config)
                generated_files['pdf'] = file_path
            
            elif config.format == ReportFormat.JSON:
                file_path = self._generate_json_report(report_data, config)
                generated_files['json'] = file_path
            
            return generated_files
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            raise
    
    def _prepare_report_data(self, 
                            results: Dict[str, Any], 
                            target: str,
                            config: ReportConfig) -> Dict[str, Any]:
        """Prepare consolidated report data"""
        
        # Aggregate findings by severity
        findings_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        total_findings = 0
        
        for scanner_name, scan_result in results.items():
            if hasattr(scan_result, 'findings'):
                for finding in scan_result.findings:
                    severity = finding.get('severity', 'info')
                    findings_by_severity[severity].append({
                        **finding,
                        'scanner': scanner_name
                    })
                    total_findings += 1
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(findings_by_severity)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            findings_by_severity, risk_score, target
        ) if config.include_executive_summary else None
        
        # Apply compliance mapping if requested
        compliance_mapping = None
        if config.compliance_framework:
            compliance_mapping = self._apply_compliance_mapping(
                findings_by_severity, config.compliance_framework
            )
        
        return {
            'metadata': {
                'target': target,
                'scan_date': datetime.now().isoformat(),
                'total_findings': total_findings,
                'risk_score': risk_score,
                'report_format': config.format.value
            },
            'executive_summary': executive_summary,
            'findings_by_severity': findings_by_severity,
            'scanner_results': results,
            'compliance_mapping': compliance_mapping,
            'custom_branding': config.custom_branding
        }
    
    def _generate_html_report(self, 
                             report_data: Dict[str, Any], 
                             config: ReportConfig) -> Path:
        """Generate HTML report"""
        
        template = self.template_engine.get_template('report_html.jinja2')
        
        html_content = template.render(
            metadata=report_data['metadata'],
            executive_summary=report_data['executive_summary'],
            findings=report_data['findings_by_severity'],
            scanner_results=report_data['scanner_results'],
            compliance_mapping=report_data['compliance_mapping'],
            branding=report_data['custom_branding']
        )
        
        # Save HTML file
        output_dir = config.output_dir or Path('output/reports')
        output_dir.mkdir(parents=True, exist_ok=True)
        
        filename = f"security_report_{report_data['metadata']['target']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        file_path = output_dir / filename
        
        file_path.write_text(html_content, encoding='utf-8')
        
        return file_path
    
    def _generate_pdf_report(self,
                            report_data: Dict[str, Any],
                            config: ReportConfig) -> Path:
        """Generate PDF report"""
        
        # First generate HTML
        html_report_config = ReportConfig(
            format=ReportFormat.HTML,
            include_executive_summary=config.include_executive_summary,
            include_technical_details=config.include_technical_details,
            custom_branding=config.custom_branding,
            compliance_framework=config.compliance_framework,
            output_dir=config.output_dir
        )
        
        html_file = self._generate_html_report(report_data, html_report_config)
        
        # Convert HTML to PDF
        try:
            import weasyprint
            
            output_dir = config.output_dir or Path('output/reports')
            filename = f"security_report_{report_data['metadata']['target']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_file = output_dir / filename
            
            weasyprint.HTML(filename=str(html_file)).write_pdf(str(pdf_file))
            
            return pdf_file
            
        except ImportError:
            # Fallback to pdfkit
            import pdfkit
            
            output_dir = config.output_dir or Path('output/reports')
            filename = f"security_report_{report_data['metadata']['target']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_file = output_dir / filename
            
            pdfkit.from_file(str(html_file), str(pdf_file))
            
            return pdf_file
    
    def _calculate_risk_score(self, findings_by_severity: Dict[str, List]) -> float:
        """Calculate overall risk score (0-10)"""
        weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 0
        }
        
        total_score = 0
        total_findings = 0
        
        for severity, findings in findings_by_severity.items():
            count = len(findings)
            total_score += count * weights.get(severity, 0)
            total_findings += count
        
        if total_findings == 0:
            return 0.0
        
        # Normalize to 0-10 scale
        max_possible = total_findings * 10
        risk_score = min(10.0, (total_score / max_possible) * 10)
        
        return round(risk_score, 1)
```

#### **Usage Example:**

```python
from src.utils.reporter import Reporter, ReportConfig, ReportFormat
from pathlib import Path

# Initialize reporter
reporter = Reporter()

# Configure report generation
config = ReportConfig(
    format=ReportFormat.PDF,
    include_executive_summary=True,
    include_technical_details=True,
    custom_branding={
        "company_name": "SecureCorp",
        "company_logo": "data:image/svg+xml;base64,...",
        "primary_color": "#1e40af"
    },
    compliance_framework="pci_dss",
    output_dir=Path("reports/client_assessments")
)

# Generate comprehensive report
generated_files = reporter.generate_comprehensive_report(
    results=workflow_results,
    target="example.com",
    config=config
)

print(f"Generated reports: {generated_files}")
```

---

## ⚡ **Performance & Cache APIs**

### **Cache Management**

```python
# Location: src/utils/cache.py

import hashlib
import json
import pickle
import time
from pathlib import Path
from typing import Any, Optional, Dict, List
from dataclasses import dataclass

@dataclass
class CacheEntry:
    """Cache entry metadata"""
    key: str
    data: Any
    timestamp: float
    ttl: int
    size_bytes: int

class CacheManager:
    """Intelligent result caching system"""
    
    def __init__(self, 
                 cache_dir: Path = Path("output/cache"),
                 default_ttl: int = 1800,  # 30 minutes
                 max_cache_size: int = 1000):
        """
        Initialize cache manager
        
        Args:
            cache_dir: Cache storage directory
            default_ttl: Default time-to-live in seconds
            max_cache_size: Maximum number of cache entries
        """
        self.cache_dir = cache_dir
        self.default_ttl = default_ttl
        self.max_cache_size = max_cache_size
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'total_size': 0
        }
    
    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve item from cache
        
        Args:
            key: Cache key
            
        Returns:
            Cached data or None if not found/expired
        """
        cache_file = self._get_cache_file(key)
        
        if not cache_file.exists():
            self.stats['misses'] += 1
            return None
        
        try:
            with open(cache_file, 'rb') as f:
                entry = pickle.load(f)
            
            # Check if expired
            if self._is_expired(entry):
                cache_file.unlink()
                self.stats['misses'] += 1
                return None
            
            self.stats['hits'] += 1
            return entry.data
            
        except Exception:
            # Corrupted cache file
            if cache_file.exists():
                cache_file.unlink()
            self.stats['misses'] += 1
            return None
    
    def set(self, key: str, data: Any, ttl: Optional[int] = None) -> bool:
        """
        Store item in cache
        
        Args:
            key: Cache key
            data: Data to cache
            ttl: Time-to-live in seconds
            
        Returns:
            bool: True if successfully cached
        """
        ttl = ttl or self.default_ttl
        
        try:
            # Serialize data
            serialized_data = pickle.dumps(data)
            size_bytes = len(serialized_data)
            
            entry = CacheEntry(
                key=key,
                data=data,
                timestamp=time.time(),
                ttl=ttl,
                size_bytes=size_bytes
            )
            
            # Store to file
            cache_file = self._get_cache_file(key)
            with open(cache_file, 'wb') as f:
                pickle.dump(entry, f)
            
            self.stats['total_size'] += size_bytes
            
            # Cleanup if cache is too large
            self._cleanup_cache()
            
            return True
            
        except Exception:
            return False
    
    def generate_key(self, scanner_name: str, target: str, options: Dict[str, Any]) -> str:
        """
        Generate cache key for scan parameters
        
        Args:
            scanner_name: Name of scanner
            target: Scan target
            options: Scan options
            
        Returns:
            str: Generated cache key
        """
        # Create deterministic key from parameters
        key_data = {
            'scanner': scanner_name,
            'target': target,
            'options': sorted(options.items()) if options else []
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics"""
        total_requests = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'hits': self.stats['hits'],
            'misses': self.stats['misses'],
            'hit_rate': round(hit_rate, 2),
            'evictions': self.stats['evictions'],
            'total_size_mb': round(self.stats['total_size'] / (1024 * 1024), 2),
            'cache_entries': len(list(self.cache_dir.glob('*.cache')))
        }
    
    def clear(self) -> int:
        """
        Clear all cache entries
        
        Returns:
            int: Number of entries cleared
        """
        count = 0
        for cache_file in self.cache_dir.glob('*.cache'):
            cache_file.unlink()
            count += 1
        
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'total_size': 0
        }
        
        return count
    
    def _get_cache_file(self, key: str) -> Path:
        """Get cache file path for key"""
        return self.cache_dir / f"{key}.cache"
    
    def _is_expired(self, entry: CacheEntry) -> bool:
        """Check if cache entry is expired"""
        return time.time() - entry.timestamp > entry.ttl
    
    def _cleanup_cache(self):
        """Cleanup old or excess cache entries"""
        cache_files = list(self.cache_dir.glob('*.cache'))
        
        if len(cache_files) <= self.max_cache_size:
            return
        
        # Sort by modification time (oldest first)
        cache_files.sort(key=lambda f: f.stat().st_mtime)
        
        # Remove oldest entries
        excess = len(cache_files) - self.max_cache_size
        for cache_file in cache_files[:excess]:
            cache_file.unlink()
            self.stats['evictions'] += 1
```

#### **Usage Example:**

```python
from src.utils.cache import CacheManager

# Initialize cache manager
cache = CacheManager(
    cache_dir=Path("output/cache"),
    default_ttl=1800,  # 30 minutes
    max_cache_size=500
)

# Generate cache key
key = cache.generate_key(
    scanner_name="port_scanner",
    target="example.com",
    options={"ports": "1-1000", "service_detection": True}
)

# Check cache first
cached_result = cache.get(key)
if cached_result:
    print("Using cached result")
    scan_result = cached_result
else:
    # Perform scan
    scanner = PortScanner()
    scan_result = scanner.scan("example.com", {"ports": "1-1000"})
    
    # Cache the result
    cache.set(key, scan_result, ttl=3600)  # Cache for 1 hour

# Get cache statistics
stats = cache.get_stats()
print(f"Cache hit rate: {stats['hit_rate']}%")
```

---

## 🔧 **Configuration APIs**

### **Settings Management**

```python
# Location: config/settings.py

import os
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv

class Settings:
    """Framework configuration management"""
    
    def __init__(self, env_file: Optional[str] = None):
        """
        Initialize settings
        
        Args:
            env_file: Path to .env file (optional)
        """
        if env_file:
            load_dotenv(env_file)
        else:
            load_dotenv()  # Load from default .env
        
        self._load_settings()
    
    def _load_settings(self):
        """Load all configuration settings"""
        
        # General settings
        self.DEBUG = self._get_bool('DEBUG', False)
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
        self.OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './output'))
        
        # Performance settings
        self.MAX_THREADS = self._get_int('MAX_THREADS', 10)
        self.TIMEOUT = self._get_int('TIMEOUT', 300)
        self.RATE_LIMIT = self._get_int('RATE_LIMIT', 100)
        
        # Cache settings
        self.CACHE_ENABLED = self._get_bool('CACHE_ENABLED', True)
        self.CACHE_TTL = self._get_int('CACHE_TTL', 1800)  # 30 minutes
        self.CACHE_MAX_SIZE = self._get_int('CACHE_MAX_SIZE', 1000)
        
        # Tool paths (auto-detected if not specified)
        self.TOOL_PATHS = {
            'nmap': os.getenv('NMAP_PATH', 'nmap'),
            'nikto': os.getenv('NIKTO_PATH', 'nikto'),
            'dirb': os.getenv('DIRB_PATH', 'dirb'),
            'gobuster': os.getenv('GOBUSTER_PATH', 'gobuster'),
            'sslscan': os.getenv('SSLSCAN_PATH', 'sslscan'),
        }
        
        # Report settings
        self.REPORT_FORMATS = os.getenv('REPORT_FORMATS', 'html,json').split(',')
        self.CUSTOM_BRANDING_FILE = os.getenv('CUSTOM_BRANDING_FILE')
        
        # Database settings (if using database)
        self.DATABASE_URL = os.getenv('DATABASE_URL')
        
        # API settings (future use)
        self.API_ENABLED = self._get_bool('API_ENABLED', False)
        self.API_HOST = os.getenv('API_HOST', '0.0.0.0')
        self.API_PORT = self._get_int('API_PORT', 8000)
        self.API_KEY = os.getenv('API_KEY')
    
    def _get_bool(self, key: str, default: bool) -> bool:
        """Get boolean environment variable"""
        value = os.getenv(key, str(default)).lower()
        return value in ('true', '1', 'yes', 'on')
    
    def _get_int(self, key: str, default: int) -> int:
        """Get integer environment variable"""
        try:
            return int(os.getenv(key, str(default)))
        except ValueError:
            return default
    
    def get_tool_path(self, tool_name: str) -> str:
        """
        Get path for security tool
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            str: Path to tool executable
        """
        return self.TOOL_PATHS.get(tool_name, tool_name)
    
    def update_setting(self, key: str, value: Any):
        """
        Update configuration setting
        
        Args:
            key: Setting key
            value: New value
        """
        setattr(self, key, value)
    
    def get_all_settings(self) -> Dict[str, Any]:
        """Get all configuration settings"""
        return {
            key: value for key, value in self.__dict__.items()
            if not key.startswith('_')
        }

# Global settings instance
settings = Settings()
```

#### **Usage Example:**

```python
from config.settings import settings

# Access settings
max_threads = settings.MAX_THREADS
output_dir = settings.OUTPUT_DIR
nmap_path = settings.get_tool_path('nmap')

# Update settings
settings.update_setting('MAX_THREADS', 20)

# Check if debugging is enabled
if settings.DEBUG:
    print("Debug mode enabled")

# Get all settings
all_settings = settings.get_all_settings()
```

---

## 🧪 **Testing & Development APIs**

### **Mock Scanner for Testing**

```python
# Location: tests/mocks/mock_scanner.py

from src.core.scanner_base import ScannerBase, ScanResult, SeverityLevel
from typing import Dict, List, Any
import time
import random

class MockScanner(ScannerBase):
    """Mock scanner for testing purposes"""
    
    def __init__(self, scanner_name: str = "mock_scanner"):
        super().__init__(scanner_name)
        self.mock_findings = []
        self.mock_execution_time = 1.0
        self.should_fail = False
    
    def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """Mock scan implementation"""
        time.sleep(self.mock_execution_time)
        
        if self.should_fail:
            return ScanResult(
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                metadata={},
                execution_time=self.mock_execution_time,
                success=False,
                error_message="Mock scanner failure"
            )
        
        return ScanResult(
            scanner_name=self.scanner_name,
            target=target,
            findings=self.mock_findings or self._generate_mock_findings(),
            metadata={"mock": True, "options": options},
            execution_time=self.mock_execution_time,
            success=True
        )
    
    def validate_target(self, target: str) -> bool:
        """Always validate successfully for mocking"""
        return True
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Mock capabilities"""
        return {
            "name": "Mock Scanner",
            "description": "Scanner for testing purposes",
            "supported_targets": ["ip", "domain", "url"],
            "features": ["mock_feature_1", "mock_feature_2"]
        }
    
    def set_mock_findings(self, findings: List[Dict[str, Any]]):
        """Set custom mock findings"""
        self.mock_findings = findings
    
    def set_execution_time(self, execution_time: float):
        """Set mock execution time"""
        self.mock_execution_time = execution_time
    
    def set_should_fail(self, should_fail: bool):
        """Set whether scanner should fail"""
        self.should_fail = should_fail
    
    def _generate_mock_findings(self) -> List[Dict[str, Any]]:
        """Generate random mock findings"""
        findings = []
        
        # Generate 1-5 random findings
        for i in range(random.randint(1, 5)):
            severity = random.choice(['info', 'low', 'medium', 'high', 'critical'])
            findings.append({
                'type': 'mock_finding',
                'id': f"mock_{i}",
                'title': f"Mock Finding {i}",
                'description': f"This is mock finding number {i}",
                'severity': severity,
                'recommendation': f"Fix mock finding {i}"
            })
        
        return findings
```

### **Test Utilities**

```python
# Location: tests/utils/test_helpers.py

import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, List
from src.core.scanner_base import ScanResult
from tests.mocks.mock_scanner import MockScanner

class TestEnvironment:
    """Test environment setup and cleanup"""
    
    def __init__(self):
        self.temp_dir = None
        self.mock_scanners = {}
    
    def __enter__(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup test environment"""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def create_mock_scanner(self, 
                           scanner_name: str,
                           findings: List[Dict[str, Any]] = None,
                           execution_time: float = 1.0,
                           should_fail: bool = False) -> MockScanner:
        """Create and configure mock scanner"""
        scanner = MockScanner(scanner_name)
        
        if findings:
            scanner.set_mock_findings(findings)
        
        scanner.set_execution_time(execution_time)
        scanner.set_should_fail(should_fail)
        
        self.mock_scanners[scanner_name] = scanner
        return scanner
    
    def create_test_config(self, **kwargs) -> Dict[str, Any]:
        """Create test configuration"""
        default_config = {
            'DEBUG': True,
            'LOG_LEVEL': 'DEBUG',
            'OUTPUT_DIR': str(self.temp_dir),
            'MAX_THREADS': 2,
            'TIMEOUT': 30,
            'CACHE_ENABLED': False
        }
        
        default_config.update(kwargs)
        return default_config

def assert_scan_result_valid(result: ScanResult):
    """Assert that scan result is valid"""
    assert result is not None
    assert hasattr(result, 'scanner_name')
    assert hasattr(result, 'target')
    assert hasattr(result, 'findings')
    assert hasattr(result, 'metadata')
    assert hasattr(result, 'execution_time')
    assert hasattr(result, 'success')
    assert isinstance(result.findings, list)
    assert isinstance(result.metadata, dict)
    assert isinstance(result.execution_time, (int, float))
    assert isinstance(result.success, bool)

def create_sample_findings(count: int = 3) -> List[Dict[str, Any]]:
    """Create sample findings for testing"""
    severities = ['info', 'low', 'medium', 'high', 'critical']
    findings = []
    
    for i in range(count):
        findings.append({
            'type': 'test_finding',
            'id': f"test_{i}",
            'title': f"Test Finding {i}",
            'description': f"This is test finding number {i}",
            'severity': severities[i % len(severities)],
            'recommendation': f"Fix test finding {i}",
            'references': [f"https://example.com/ref{i}"]
        })
    
    return findings
```

#### **Usage Example:**

```python
import pytest
from tests.utils.test_helpers import TestEnvironment, assert_scan_result_valid, create_sample_findings
from src.orchestrator.orchestrator import WorkflowOrchestrator

def test_workflow_orchestrator():
    """Test workflow orchestrator with mock scanners"""
    
    with TestEnvironment() as test_env:
        # Create mock scanners
        port_scanner = test_env.create_mock_scanner(
            "port_scanner",
            findings=create_sample_findings(2),
            execution_time=0.5
        )
        
        web_scanner = test_env.create_mock_scanner(
            "web_scanner", 
            findings=create_sample_findings(3),
            execution_time=1.0
        )
        
        # Test orchestrator
        orchestrator = WorkflowOrchestrator(max_workers=2)
        
        # Create workflow steps using mock scanners
        from src.orchestrator.orchestrator import WorkflowStep
        
        steps = [
            WorkflowStep(
                scanner_name="port_scanner",
                scanner_class=lambda: port_scanner,
                options={},
                dependencies=[]
            ),
            WorkflowStep(
                scanner_name="web_scanner",
                scanner_class=lambda: web_scanner,
                options={},
                dependencies=[]
            )
        ]
        
        # Execute workflow
        result = orchestrator.execute_workflow(
            workflow_id="test_workflow",
            target="test.example.com",
            steps=steps
        )
        
        # Assertions
        assert result.success
        assert result.steps_completed == 2
        assert result.total_steps == 2
        assert len(result.results) == 2
        
        # Validate individual results
        for scanner_name, scan_result in result.results.items():
            assert_scan_result_valid(scan_result)
            assert scan_result.success
            assert len(scan_result.findings) > 0
```

---

## 📋 **Integration Patterns**

### **Framework Integration**

```python
# Example: Integrating with external security platforms

from src.core.scanner_base import ScannerBase, ScanResult
from src.orchestrator.orchestrator import WorkflowOrchestrator
from src.utils.reporter import Reporter, ReportConfig, ReportFormat
from typing import Dict, Any, List

class SecurityPlatformIntegration:
    """Integration with external security platforms"""
    
    def __init__(self, api_endpoint: str, api_key: str):
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.orchestrator = WorkflowOrchestrator()
        self.reporter = Reporter()
    
    def automated_assessment(self, 
                           targets: List[str],
                           scan_profile: str = "full") -> Dict[str, Any]:
        """
        Perform automated security assessment
        
        Args:
            targets: List of targets to scan
            scan_profile: Scan profile to use
            
        Returns:
            Dict containing assessment results
        """
        results = {}
        
        for target in targets:
            try:
                # Create workflow
                steps = self.orchestrator.create_scan_profile(scan_profile)
                
                # Execute assessment
                workflow_result = self.orchestrator.execute_workflow(
                    workflow_id=f"auto_assessment_{target}",
                    target=target,
                    steps=steps
                )
                
                # Generate reports
                report_config = ReportConfig(
                    format=ReportFormat.JSON,
                    include_executive_summary=True
                )
                
                reports = self.reporter.generate_comprehensive_report(
                    results=workflow_result.results,
                    target=target,
                    config=report_config
                )
                
                results[target] = {
                    'workflow_result': workflow_result,
                    'reports': reports,
                    'success': workflow_result.success
                }
                
                # Send to external platform
                self._send_to_platform(target, workflow_result)
                
            except Exception as e:
                results[target] = {
                    'success': False,
                    'error': str(e)
                }
        
        return results
    
    def _send_to_platform(self, target: str, workflow_result):
        """Send results to external security platform"""
        # Implementation depends on the external platform's API
        import requests
        
        payload = {
            'target': target,
            'scan_results': workflow_result.results,
            'execution_time': workflow_result.execution_time,
            'success': workflow_result.success
        }
        
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            f"{self.api_endpoint}/assessments",
            json=payload,
            headers=headers
        )
        
        return response.status_code == 200
```

---

## 📚 **Best Practices**

### **API Development Guidelines**

1. **Error Handling**
   ```python
   try:
       result = scanner.scan(target, options)
   except ValidationError as e:
       # Handle validation errors
       pass
   except TimeoutError as e:
       # Handle timeout errors
       pass
   except Exception as e:
       # Handle general errors
       pass
   ```

2. **Logging**
   ```python
   from utils.logger import get_logger
   
   logger = get_logger(__name__)
   logger.info("Starting scan")
   logger.error("Scan failed", exc_info=True)
   ```

3. **Resource Management**
   ```python
   with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
       futures = [executor.submit(scan_func, target) for target in targets]
       results = [f.result() for f in futures]
   ```

4. **Configuration**
   ```python
   from config.settings import settings
   
   timeout = settings.TIMEOUT
   max_threads = settings.MAX_THREADS
   ```

### **Extension Development**

1. **Custom Scanner Implementation**
   - Inherit from `ScannerBase`
   - Implement required abstract methods
   - Follow naming conventions
   - Include comprehensive error handling
   - Add proper logging

2. **Integration Testing**
   - Use `TestEnvironment` for test setup
   - Create mock scanners for unit tests
   - Test error conditions
   - Validate scan results structure

3. **Performance Considerations**
   - Use caching for expensive operations
   - Implement proper timeout handling
   - Monitor resource usage
   - Consider parallel execution

---

**🎯 This API documentation provides comprehensive guidance for extending and integrating the Auto-Pentest Framework. Whether you're developing custom scanners, building integrations, or creating specialized workflows, these APIs provide the foundation for powerful security automation solutions.**