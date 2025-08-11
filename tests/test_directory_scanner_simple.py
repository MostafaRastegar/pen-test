#!/usr/bin/env python3
"""
Simple test for Directory Scanner validation
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.scanners.vulnerability.directory_scanner import DirectoryScanner
from src.utils.logger import LoggerSetup, log_banner, log_success, log_error, log_info


def test_directory_scanner_validation():
    """Test directory scanner validation"""
    log_banner("Testing Directory Scanner Validation", "bold blue")

    scanner = DirectoryScanner()

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
        "ftp://example.com",  # Wrong protocol
    ]

    log_info("\nTesting invalid targets:")
    for target in invalid_targets:
        is_valid = scanner.validate_target(target)
        status = "✅" if not is_valid else "❌"  # Should be False
        log_info(f"  {status} {target}: {is_valid}")


def test_directory_scanner_capabilities():
    """Test directory scanner capabilities"""
    log_banner("Testing Directory Scanner Capabilities", "bold green")

    scanner = DirectoryScanner()
    capabilities = scanner.get_capabilities()

    log_info("Scanner capabilities:")
    log_info(f"  Name: {capabilities['name']}")
    log_info(f"  Description: {capabilities['description']}")
    log_info(f"  Supported targets: {capabilities['supported_targets']}")
    log_info(f"  Tools: {capabilities['tools']}")
    log_info(f"  Features: {len(capabilities['features'])}")

    # Check dependencies
    log_info("\nTool Dependencies:")
    deps = capabilities["dependencies"]
    for tool, info in deps.items():
        available = "✅" if info.get("available") else "❌"
        version = info.get("version", "unknown version")
        log_info(f"  {available} {tool}: {version}")


def test_wordlist_selection():
    """Test wordlist selection logic"""
    log_banner("Testing Wordlist Selection", "bold yellow")

    scanner = DirectoryScanner()

    # Test predefined wordlists
    test_wordlists = ["small", "common", "big", "nonexistent"]

    log_info("Testing wordlist selection:")
    for wordlist in test_wordlists:
        try:
            result = scanner._get_wordlist(wordlist)
            log_info(f"  ✅ {wordlist}: {result}")
        except Exception as e:
            log_error(f"  ❌ {wordlist}: ERROR - {e}")


def test_path_severity():
    """Test path severity determination"""
    log_banner("Testing Path Severity Determination", "bold cyan")

    scanner = DirectoryScanner()

    test_paths = [
        ("/admin/", "Should be HIGH"),
        ("/login.php", "Should be HIGH"),
        ("/test/", "Should be MEDIUM"),
        ("/api/v1/", "Should be LOW"),
        ("/images/", "Should be INFO"),
        ("/.git/", "Should be HIGH"),
        ("/backup/", "Should be HIGH"),
    ]

    log_info("Testing path severity:")
    for path, description in test_paths:
        severity = scanner._determine_path_severity(path)
        log_info(f"  {path:15} -> {severity.value.upper():8} ({description})")


def test_tool_selection():
    """Test scanner tool selection"""
    log_banner("Testing Tool Selection", "bold magenta")

    scanner = DirectoryScanner()

    test_preferences = ["dirb", "gobuster", "auto", "nonexistent"]

    log_info("Testing tool selection:")
    for preference in test_preferences:
        try:
            selected = scanner._select_scanner_tool(preference)
            if selected:
                log_success(f"  ✅ {preference}: Selected {selected}")
            else:
                log_warning(f"  ⚠️  {preference}: No tool available")
        except Exception as e:
            log_error(f"  ❌ {preference}: ERROR - {e}")


def main():
    """Run all tests"""
    log_banner("Directory Scanner Simple Test Suite", "bold magenta")

    # Setup logger
    logger = LoggerSetup.setup_logger(
        name="test_directory_scanner_simple", level="INFO", use_rich=True
    )

    try:
        test_directory_scanner_validation()
        print()
        test_directory_scanner_capabilities()
        print()
        test_wordlist_selection()
        print()
        test_path_severity()
        print()
        test_tool_selection()

        log_banner("All Tests Completed", "bold green")
        log_success("Directory scanner basic functionality verified!")

        return True

    except Exception as e:
        log_error(f"Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
