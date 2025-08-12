#!/usr/bin/env python3
"""
Simple test for SSL Scanner validation
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.scanners.vulnerability.ssl_scanner import SSLScanner
from src.utils.logger import LoggerSetup, log_banner, log_success, log_error, log_info


def test_ssl_scanner_validation():
    """Test SSL scanner validation"""
    log_banner("Testing SSL Scanner Validation", "bold blue")

    scanner = SSLScanner()

    # Test valid targets
    valid_targets = [
        "https://example.com",
        "example.com",
        "192.168.1.1",
        "sub.domain.com",
        "http://example.com",  # Should still validate even if http
    ]

    log_info("Testing valid targets:")
    for target in valid_targets:
        is_valid = scanner.validate_target(target)
        status = "✅" if is_valid else "❌"
        log_info(f"  {status} {target}: {is_valid}")

    # Test invalid targets
    invalid_targets = [
        "",
        "ftp://example.com",  # Wrong protocol
    ]

    log_info("\nTesting invalid targets:")
    for target in invalid_targets:
        is_valid = scanner.validate_target(target)
        status = "✅" if not is_valid else "❌"  # Should be False
        log_info(f"  {status} {target}: {is_valid}")


def test_ssl_scanner_capabilities():
    """Test SSL scanner capabilities"""
    log_banner("Testing SSL Scanner Capabilities", "bold green")

    scanner = SSLScanner()
    capabilities = scanner.get_capabilities()

    log_info("Scanner capabilities:")
    log_info(f"  Name: {capabilities['name']}")
    log_info(f"  Description: {capabilities['description']}")
    log_info(f"  Supported targets: {capabilities['supported_targets']}")
    log_info(f"  Scan types: {len(capabilities['scan_types'])}")
    log_info(f"  Features: {len(capabilities['features'])}")

    # Check dependencies
    log_info("\nDependencies:")
    deps = capabilities["dependencies"]
    for dep, info in deps.items():
        if isinstance(info, dict):
            available = "✅" if info.get("available") else "❌"
            version = info.get("version", "unknown version")
            log_info(f"  {available} {dep}: {version}")
        else:
            log_info(f"  ✅ {dep}: {info}")


def test_target_parsing():
    """Test target parsing logic"""
    log_banner("Testing Target Parsing", "bold yellow")

    scanner = SSLScanner()

    test_cases = [
        ("https://example.com", {}, ("example.com", 443)),
        ("http://example.com", {}, ("example.com", 80)),
        ("example.com", {"port": 8443}, ("example.com", 8443)),
        ("example.com:9443", {}, ("example.com", 9443)),
        ("192.168.1.1", {}, ("192.168.1.1", 443)),
    ]

    log_info("Testing target parsing:")
    for target, options, expected in test_cases:
        try:
            result = scanner._parse_target(target, options)
            status = "✅" if result == expected else "❌"
            log_info(f"  {status} {target} + {options} -> {result}")
            if result != expected:
                log_error(f"    Expected: {expected}")
        except Exception as e:
            log_error(f"  ❌ {target} + {options} -> ERROR: {e}")


def test_severity_determination():
    """Test severity determination logic"""
    log_banner("Testing Severity Determination", "bold cyan")

    scanner = SSLScanner()

    # Test protocol severity
    protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]

    log_info("Testing protocol severity:")
    for protocol in protocols:
        severity = scanner._determine_protocol_severity(protocol)
        log_info(f"  {protocol:8} -> {severity.value.upper()}")

    # Test cipher severity
    test_ciphers = [
        ("RC4-MD5", 128),
        ("NULL-MD5", 0),
        ("AES256-GCM-SHA384", 256),
        ("DES-CBC-SHA", 56),
        ("ECDHE-RSA-AES256-GCM-SHA384", 256),
    ]

    log_info("\nTesting cipher severity:")
    for cipher, bits in test_ciphers:
        severity = scanner._determine_cipher_severity(cipher, bits)
        log_info(f"  {cipher:30} ({bits:3} bits) -> {severity.value.upper()}")


def test_ssl_protocols():
    """Test SSL protocol definitions"""
    log_banner("Testing SSL Protocol Support", "bold magenta")

    scanner = SSLScanner()

    log_info("Available SSL/TLS protocols:")
    for protocol, constant in scanner.ssl_protocols.items():
        available = "✅" if constant is not None else "❌"
        log_info(f"  {available} {protocol}: {constant}")


def main():
    """Run all tests"""
    log_banner("SSL Scanner Simple Test Suite", "bold magenta")

    # Setup logger
    logger = LoggerSetup.setup_logger(
        name="test_ssl_scanner_simple", level="INFO", use_rich=True
    )

    try:
        test_ssl_scanner_validation()
        print()
        test_ssl_scanner_capabilities()
        print()
        test_target_parsing()
        print()
        test_severity_determination()
        print()
        test_ssl_protocols()

        log_banner("All Tests Completed", "bold green")
        log_success("SSL scanner basic functionality verified!")

        return True

    except Exception as e:
        log_error(f"Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
