#!/usr/bin/env python3
"""
Test script for core modules
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.core import (
    CommandExecutor, 
    InputValidator,
    validate_ip,
    validate_domain,
    validate_url
)
from src.utils.logger import LoggerSetup, log_banner, log_success, log_error, log_info


def test_command_executor():
    """Test CommandExecutor"""
    log_banner("Testing CommandExecutor")
    
    executor = CommandExecutor(timeout=10)
    
    # Test simple command
    log_info("Testing simple command: 'echo Hello World'")
    result = executor.execute("echo Hello World")
    if result.success:
        log_success(f"Output: {result.stdout.strip()}")
    else:
        log_error(f"Command failed: {result.stderr}")
    
    # Test command with error
    log_info("Testing command with error: 'ls /nonexistent'")
    result = executor.execute("ls /nonexistent")
    if not result.success:
        log_success(f"Correctly detected error: {result.stderr.strip()}")
    
    # Test tool existence
    log_info("Checking if 'nmap' exists")
    if executor.check_tool_exists("nmap"):
        log_success("nmap found!")
        version = executor.get_tool_version("nmap")
        if version:
            log_info(f"nmap version: {version.split('\\n')[0]}")
    else:
        log_error("nmap not found")
    
    # Test timeout
    log_info("Testing command timeout (sleep 5 with 2s timeout)")
    result = executor.execute("sleep 5", timeout=2)
    if result.timed_out:
        log_success("Timeout worked correctly")
    else:
        log_error("Timeout did not work")


def test_validator():
    """Test InputValidator"""
    log_banner("Testing InputValidator")
    
    validator = InputValidator()
    
    # Test IP validation
    test_ips = [
        ("192.168.1.1", True),
        ("8.8.8.8", True),
        ("256.256.256.256", False),
        ("not.an.ip", False),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", True),  # IPv6
    ]
    
    log_info("Testing IP validation:")
    for ip, expected in test_ips:
        is_valid = validate_ip(ip)
        status = "✓" if is_valid == expected else "✗"
        log_info(f"  {status} {ip}: {is_valid}")
    
    # Test domain validation
    test_domains = [
        ("google.com", True),
        ("sub.domain.example.com", True),
        ("invalid_domain", False),
        ("-invalid.com", False),
        ("192.168.1.1", False),  # IP not domain
    ]
    
    log_info("\\nTesting domain validation:")
    for domain, expected in test_domains:
        is_valid = validate_domain(domain)
        status = "✓" if is_valid == expected else "✗"
        log_info(f"  {status} {domain}: {is_valid}")
    
    # Test URL validation
    test_urls = [
        ("http://example.com", True),
        ("https://example.com:8080/path", True),
        ("ftp://example.com", False),  # Not in allowed schemes
        ("not-a-url", False),
        ("http://192.168.1.1", True),
    ]
    
    log_info("\\nTesting URL validation:")
    for url, expected in test_urls:
        is_valid = validate_url(url)
        status = "✓" if is_valid == expected else "✗"
        log_info(f"  {status} {url}: {is_valid}")
    
    # Test target validation
    test_targets = [
        ("192.168.1.1", "ip"),
        ("192.168.1.0/24", "ip_range"),
        ("google.com", "domain"),
        ("http://example.com", "url"),
        ("invalid@target", "invalid"),
    ]
    
    log_info("\\nTesting target identification:")
    for target, expected_type in test_targets:
        is_valid, target_type, _ = validator.validate_target(target)
        status = "✓" if target_type == expected_type else "✗"
        log_info(f"  {status} {target}: {target_type}")


def test_scanner_base():
    """Test ScannerBase functionality"""
    log_banner("Testing ScannerBase")
    
    from src.core import ScannerBase, ScanResult, ScanStatus, ScanSeverity
    from datetime import datetime
    
    # Create a simple test scanner
    class TestScanner(ScannerBase):
        def validate_target(self, target: str) -> bool:
            return validate_ip(target) or validate_domain(target)
        
        def _execute_scan(self, target: str, options: dict) -> ScanResult:
            # Simulate scan
            result = ScanResult(
                scanner_name=self.name,
                target=target,
                status=ScanStatus.RUNNING,
                start_time=datetime.now()
            )
            
            # Add some mock findings
            result.add_finding(
                title="Test Finding 1",
                description="This is a test finding",
                severity=ScanSeverity.LOW,
                details={"port": 80, "service": "http"}
            )
            
            result.add_finding(
                title="Test Finding 2",
                description="This is a critical finding",
                severity=ScanSeverity.CRITICAL,
                details={"vulnerability": "SQL Injection"}
            )
            
            result.status = ScanStatus.COMPLETED
            return result
        
        def get_capabilities(self) -> dict:
            return {
                "name": self.name,
                "supported_targets": ["ip", "domain"],
                "scan_types": ["basic", "full"]
            }
    
    # Test the scanner
    scanner = TestScanner("test_scanner")
    
    log_info("Running test scan on 192.168.1.1")
    try:
        result = scanner.scan("192.168.1.1")
        log_success(f"Scan completed with status: {result.status.value}")
        log_info(f"Found {len(result.findings)} findings")
        
        # Show findings by severity
        critical = result.get_findings_by_severity(ScanSeverity.CRITICAL)
        if critical:
            log_error(f"Critical findings: {len(critical)}")
        
        # Test JSON output
        json_output = result.to_json()
        log_info(f"JSON output length: {len(json_output)} chars")
        
    except Exception as e:
        log_error(f"Scan failed: {e}")


def main():
    """Run all tests"""
    log_banner("Auto-Pentest Core Modules Test", "bold magenta")
    
    # Setup logger
    logger = LoggerSetup.setup_logger(
        name="test",
        level="DEBUG",
        use_rich=True
    )
    
    try:
        test_command_executor()
        print()  # Add spacing
        test_validator()
        print()
        test_scanner_base()
        
        log_banner("All Tests Completed", "bold green")
        
    except Exception as e:
        log_error(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()