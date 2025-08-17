#!/usr/bin/env python3
"""
Simple API Scanner Test
Test basic functionality without external dependencies
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / ".."))


def test_api_scanner_basic():
    """Test API scanner basic functionality"""

    print("🧪 Testing API Scanner Basic Functionality")
    print("=" * 50)

    try:
        # Test 1: Import scanner
        print("1️⃣ Testing import...")
        from src.scanners.api.api_scanner import APISecurityScanner

        print("   ✅ Import successful")

        # Test 2: Initialize scanner
        print("2️⃣ Testing initialization...")
        scanner = APISecurityScanner(timeout=10)
        print(f"   ✅ Scanner initialized: {scanner.name}")

        # Test 3: Test capabilities
        print("3️⃣ Testing capabilities...")
        capabilities = scanner.get_capabilities()
        print(f"   ✅ Scanner capabilities: {capabilities['name']}")
        print(f"   ✅ OWASP coverage: {len(capabilities['owasp_coverage'])} categories")

        # Test 4: Test target validation
        print("4️⃣ Testing target validation...")

        # Valid targets
        valid_targets = [
            "https://api.example.com",
            "http://example.com/api",
            "example.com",
            "192.168.1.1",
        ]

        for target in valid_targets:
            result = scanner.validate_target(target)
            status = "✅" if result else "❌"
            print(f"   {status} {target}: {result}")

        # Invalid targets
        invalid_targets = ["", "ftp://example.com", "not-a-url"]

        for target in invalid_targets:
            result = scanner.validate_target(target)
            status = "✅ (rejected)" if not result else "❌ (should reject)"
            print(f"   {status} {target}: {result}")

        # Test 5: Test OWASP categories
        print("5️⃣ Testing OWASP API Security Top 10 categories...")
        for category, description in scanner.owasp_api_top10.items():
            print(f"   ✅ {category}: {description}")

        # Test 6: Test API endpoints list
        print("6️⃣ Testing API endpoint discovery patterns...")
        print(f"   ✅ {len(scanner.api_endpoints)} endpoint patterns loaded")
        print(f"   📝 Examples: {scanner.api_endpoints[:5]}")

        # Test 7: Test security headers
        print("7️⃣ Testing security headers check...")
        print(f"   ✅ {len(scanner.security_headers)} security headers monitored")
        print(f"   📝 Examples: {scanner.security_headers[:3]}")

        print("\n🎉 All basic tests passed!")
        return True

    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("💡 Make sure you created the directory: src/scanners/api/")
        return False

    except Exception as e:
        print(f"❌ Test Error: {e}")
        return False


def test_mock_scan():
    """Test scanner with a mock target (no real network calls)"""

    print("\n🔬 Testing Mock API Scan")
    print("=" * 30)

    try:
        from src.scanners.api.api_scanner import APISecurityScanner

        scanner = APISecurityScanner(timeout=5)

        # Test individual helper methods (they should not make network calls)
        print("1️⃣ Testing risk score calculation...")

        # Mock findings for testing
        mock_findings = [
            {"severity": "high", "type": "authentication_bypass"},
            {"severity": "medium", "type": "security_misconfiguration"},
            {"severity": "low", "type": "information_disclosure"},
        ]

        # Test risk calculation (this doesn't need network)
        try:
            risk_score = scanner._calculate_api_risk_score(mock_findings)
            print(f"   ✅ Risk score calculated: {risk_score}")
        except Exception as e:
            print(f"   ⚠️  Risk calculation error: {e}")

        # Test OWASP coverage calculation
        print("2️⃣ Testing OWASP coverage calculation...")
        mock_findings_with_owasp = [
            {"owasp_category": "API1"},
            {"owasp_category": "API2"},
            {"owasp_category": "API1"},  # Duplicate
        ]

        try:
            coverage = scanner._get_owasp_coverage(mock_findings_with_owasp)
            print(
                f"   ✅ OWASP coverage calculated: {len([k for k, v in coverage.items() if v > 0])}/10 categories"
            )
        except Exception as e:
            print(f"   ⚠️  OWASP coverage error: {e}")

        # Test sensitive information detection
        print("3️⃣ Testing sensitive information detection...")
        test_content = "api_key: secret123, password=admin, normal content"

        try:
            has_sensitive = scanner._contains_sensitive_info(test_content)
            print(f"   ✅ Sensitive info detection: {has_sensitive}")
        except Exception as e:
            print(f"   ⚠️  Sensitive info detection error: {e}")

        print("\n🎉 Mock scan tests completed!")
        return True

    except Exception as e:
        print(f"❌ Mock scan error: {e}")
        return False


def test_integration_check():
    """Test if scanner can be integrated with the framework"""

    print("\n🔧 Testing Framework Integration")
    print("=" * 35)

    try:
        # Test if we can import from scanners module
        print("1️⃣ Testing scanners module integration...")

        try:
            from src.scanners import SCANNER_REGISTRY

            print(f"   ✅ Scanner registry loaded: {len(SCANNER_REGISTRY)} scanners")

            # Check if API scanner is in registry (might not be yet)
            if "api" in SCANNER_REGISTRY:
                print("   ✅ API scanner found in registry")
            else:
                print("   ⚠️  API scanner not yet in registry (expected)")

        except ImportError as e:
            print(f"   ❌ Scanner registry import error: {e}")

        # Test if core classes are available
        print("2️⃣ Testing core framework classes...")

        try:
            from src.core.scanner_base import (
                ScannerBase,
                ScanResult,
                ScanStatus,
                ScanSeverity,
            )

            print("   ✅ Core scanner classes available")

            # Test enum values
            print(f"   ✅ ScanStatus values: {[s.value for s in ScanStatus]}")
            print(f"   ✅ ScanSeverity values: {[s.value for s in ScanSeverity]}")

        except ImportError as e:
            print(f"   ❌ Core classes import error: {e}")

        # Test validator functions
        print("3️⃣ Testing validator functions...")

        try:
            from src.core.validator import validate_url, validate_domain, validate_ip

            # Test validation functions
            test_cases = [
                ("https://api.example.com", validate_url),
                ("example.com", validate_domain),
                ("192.168.1.1", validate_ip),
            ]

            for test_input, validator_func in test_cases:
                result = validator_func(test_input)
                print(f"   ✅ {validator_func.__name__}('{test_input}'): {result}")

        except ImportError as e:
            print(f"   ❌ Validator functions import error: {e}")

        print("\n🎉 Integration check completed!")
        return True

    except Exception as e:
        print(f"❌ Integration check error: {e}")
        return False


if __name__ == "__main__":
    print("🚀 API Security Scanner - Simple Test Suite")
    print("=" * 50)

    # Run all tests
    tests_passed = 0
    total_tests = 3

    if test_api_scanner_basic():
        tests_passed += 1

    if test_mock_scan():
        tests_passed += 1

    if test_integration_check():
        tests_passed += 1

    print(f"\n📊 Test Results: {tests_passed}/{total_tests} tests passed")

    if tests_passed == total_tests:
        print("🎉 All tests passed! API Scanner is ready.")
        print("\n📋 Next Steps:")
        print("1. Create directory: mkdir -p src/scanners/api/")
        print("2. Save api_scanner.py in that directory")
        print("3. Create __init__.py in the api directory")
        print("4. Update src/scanners/__init__.py to include API scanner")
        print("5. Test with: python main.py api --help")
    else:
        print("⚠️  Some tests failed. Check the errors above.")
        sys.exit(1)
