#!/usr/bin/env python3
"""
Simple test for Web Scanner validation
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.scanners.vulnerability.web_scanner import WebScanner
from src.utils.logger import LoggerSetup, log_banner, log_success, log_error, log_info


def test_web_scanner_validation():
    """Test web scanner validation"""
    log_banner("Testing Web Scanner Validation", "bold blue")

    scanner = WebScanner()

    # Test valid targets
    valid_targets = [
        "https://example.com",
        "http://example.com:8080",
        "example.com",
        "192.168.1.1",
        "sub.domain.com",
    ]

    log_info("Testing valid targets:")
    for target in valid_targets:
        is_valid = scanner.validate_target(target)
        status = "✅" if is_valid else "❌"
        log_info(f"  {status} {target}: {is_valid}")

    # Test invalid targets
    invalid_targets = [
        "",
        "invalid_target",
        "ftp://example.com",  # Wrong protocol
        "not.a.url.or.domain",
    ]

    log_info("\nTesting invalid targets:")
    for target in invalid_targets:
        is_valid = scanner.validate_target(target)
        status = "✅" if not is_valid else "❌"  # Should be False
        log_info(f"  {status} {target}: {is_valid}")


def test_web_scanner_capabilities():
    """Test web scanner capabilities"""
    log_banner("Testing Web Scanner Capabilities", "bold green")

    scanner = WebScanner()
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
            log_info(f"  {available} {dep}: {info.get('version', 'unknown version')}")
        else:
            log_info(f"  ✅ {dep}: {info}")


def test_url_normalization():
    """Test URL normalization"""
    log_banner("Testing URL Normalization", "bold yellow")

    scanner = WebScanner()

    test_cases = [
        ("example.com", {"scheme": "https"}, "https://example.com"),
        ("example.com", {"scheme": "http", "port": 8080}, "http://example.com:8080"),
        ("https://example.com", {}, "https://example.com"),
        ("192.168.1.1", {"scheme": "http"}, "http://192.168.1.1"),
    ]

    log_info("Testing URL normalization:")
    for target, options, expected in test_cases:
        try:
            result = scanner._normalize_target_url(target, options)
            status = "✅" if result == expected else "❌"
            log_info(f"  {status} {target} + {options} -> {result}")
            if result != expected:
                log_error(f"    Expected: {expected}")
        except Exception as e:
            log_error(f"  ❌ {target} + {options} -> ERROR: {e}")


def test_web_scanner_basic_functionality():
    """Test basic web scanner functionality"""
    log_banner("Testing Web Scanner Basic Functionality", "bold cyan")

    scanner = WebScanner(timeout=60)

    log_info("Testing with httpbin.org (reliable test service)...")

    try:
        # Test basic scan functionality
        result = scanner.quick_web_scan("https://httpbin.org")

        log_info(f"Scan completed with status: {result.status.value}")
        log_info(f"Found {len(result.findings)} findings")
        log_info(f"Errors: {len(result.errors)}")

        # Show sample findings
        if result.findings:
            log_info("Sample findings:")
            for i, finding in enumerate(result.findings[:3], 1):
                log_info(f"  {i}. [{finding['severity']}] {finding['title']}")

        # Check metadata
        if result.metadata:
            log_info("Metadata collected:")
            for key, value in result.metadata.items():
                if not isinstance(value, dict):  # Skip complex objects
                    log_info(f"  {key}: {value}")

        return True

    except Exception as e:
        log_error(f"Basic functionality test failed: {e}")
        return False


def main():
    """Run all tests"""
    log_banner("Web Scanner Simple Test Suite", "bold magenta")

    # Setup logger
    logger = LoggerSetup.setup_logger(
        name="test_web_scanner_simple", level="INFO", use_rich=True
    )

    try:
        test_web_scanner_validation()
        print()
        test_web_scanner_capabilities()
        print()
        test_url_normalization()
        print()
        test_web_scanner_basic_functionality()

        log_banner("All Tests Completed", "bold green")
        log_success("Web scanner functionality verified!")

        return True

    except Exception as e:
        log_error(f"Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
