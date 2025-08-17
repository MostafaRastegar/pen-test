#!/usr/bin/env python3
"""
WAF Scanner Test Suite - Phase 2.2
Basic integration and functionality tests for the WAF Detection Engine

File Location: tests/test_waf_scanner.py
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import requests

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from scanners.security.waf_scanner import WAFScanner
    from core.scanner_base import ScannerBase, ScanResult, ScanStatus, ScanSeverity
    from utils.logger import log_info, log_error, log_success, log_warning
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure you're running this from the project root directory")
    print("Try: python -m pytest tests/test_waf_scanner.py -v")
    sys.exit(1)


class TestWAFScanner(unittest.TestCase):
    """Test cases for WAF Scanner"""

    def setUp(self):
        """Set up test fixtures"""
        self.scanner = WAFScanner(timeout=30)
        self.test_url = "https://example.com"
        self.test_domain = "example.com"

    def test_scanner_initialization(self):
        """Test WAF scanner initialization"""
        log_info("Testing WAF scanner initialization")

        # Verify scanner inherits from ScannerBase
        self.assertIsInstance(self.scanner, ScannerBase)

        # Verify scanner name
        self.assertEqual(self.scanner.name, "waf_scanner")

        # Verify timeout setting
        self.assertEqual(self.scanner.timeout, 30)

        # Verify WAF signatures are loaded
        self.assertIsInstance(self.scanner.waf_signatures, dict)
        self.assertGreater(len(self.scanner.waf_signatures), 0)

        # Verify bypass payloads are loaded
        self.assertIsInstance(self.scanner.bypass_payloads, dict)
        self.assertGreater(len(self.scanner.bypass_payloads), 0)

        log_success("✅ WAF scanner initialization test passed")

    def test_target_validation(self):
        """Test target validation functionality"""
        log_info("Testing target validation")

        # Valid URLs
        valid_targets = [
            "https://example.com",
            "http://test.com",
            "https://192.168.1.1",
            "example.com",
            "192.168.1.1",
        ]

        for target in valid_targets:
            self.assertTrue(
                self.scanner.validate_target(target), f"Should accept {target}"
            )

        # Invalid targets
        invalid_targets = ["", "not_a_url", "ftp://example.com", "javascript:alert(1)"]

        for target in invalid_targets:
            self.assertFalse(
                self.scanner.validate_target(target), f"Should reject {target}"
            )

        log_success("✅ Target validation test passed")

    def test_get_capabilities(self):
        """Test scanner capabilities reporting"""
        log_info("Testing get_capabilities method")

        capabilities = self.scanner.get_capabilities()

        # Verify required fields
        required_fields = ["name", "description", "version", "category", "targets"]
        for field in required_fields:
            self.assertIn(field, capabilities, f"Missing required field: {field}")

        # Verify category
        self.assertEqual(capabilities["category"], "security")

        # Verify WAF vendors list
        self.assertIn("waf_vendors", capabilities)
        self.assertIsInstance(capabilities["waf_vendors"], list)
        self.assertGreater(len(capabilities["waf_vendors"]), 0)

        log_success("✅ Get capabilities test passed")

    def test_waf_signatures_structure(self):
        """Test WAF signatures data structure"""
        log_info("Testing WAF signatures structure")

        required_waf_vendors = [
            "cloudflare",
            "aws_waf",
            "akamai",
            "f5_big_ip",
            "imperva",
            "fortinet",
            "sucuri",
            "mod_security",
        ]

        for vendor in required_waf_vendors:
            self.assertIn(
                vendor, self.scanner.waf_signatures, f"Missing WAF vendor: {vendor}"
            )

            signature = self.scanner.waf_signatures[vendor]
            self.assertIsInstance(signature, dict)

            # Check required signature fields
            required_fields = [
                "headers",
                "error_codes",
                "error_messages",
                "response_patterns",
            ]
            for field in required_fields:
                self.assertIn(
                    field, signature, f"Missing signature field {field} for {vendor}"
                )
                self.assertIsInstance(signature[field], list)

        log_success("✅ WAF signatures structure test passed")

    def test_bypass_payloads_structure(self):
        """Test bypass payloads data structure"""
        log_info("Testing bypass payloads structure")

        required_attack_types = ["sql_injection", "xss", "lfi", "command_injection"]

        for attack_type in required_attack_types:
            self.assertIn(
                attack_type,
                self.scanner.bypass_payloads,
                f"Missing attack type: {attack_type}",
            )

            payloads = self.scanner.bypass_payloads[attack_type]
            self.assertIsInstance(payloads, list)
            self.assertGreater(len(payloads), 0, f"No payloads for {attack_type}")

            # Verify payloads are strings
            for payload in payloads:
                self.assertIsInstance(payload, str)
                self.assertGreater(len(payload), 0)

        log_success("✅ Bypass payloads structure test passed")

    def test_url_normalization(self):
        """Test URL normalization functionality"""
        log_info("Testing URL normalization")

        test_cases = [
            ("example.com", "https://example.com"),
            ("http://example.com", "http://example.com"),
            ("https://example.com", "https://example.com"),
            ("192.168.1.1", "https://192.168.1.1"),
        ]

        for input_url, expected_output in test_cases:
            result = self.scanner._normalize_target_url(input_url)
            self.assertEqual(
                result, expected_output, f"Normalization failed for {input_url}"
            )

        log_success("✅ URL normalization test passed")

    @patch("requests.Session.get")
    def test_basic_waf_detection_mock(self, mock_get):
        """Test basic WAF detection with mocked responses"""
        log_info("Testing basic WAF detection with mock responses")

        # Mock Cloudflare response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"cf-ray": "12345", "server": "cloudflare"}
        mock_response.text = "Test page with cloudflare protection"
        mock_get.return_value = mock_response

        # Test detection
        detection_result = self.scanner._perform_basic_waf_detection(
            "https://example.com"
        )

        # Verify structure
        self.assertIsInstance(detection_result, dict)
        self.assertIn("findings", detection_result)
        self.assertIn("detected_wafs", detection_result)
        self.assertIn("confidence_scores", detection_result)

        # Should detect Cloudflare
        findings = detection_result["findings"]
        self.assertGreater(len(findings), 0)

        log_success("✅ Basic WAF detection mock test passed")

    def test_payload_analysis_methods(self):
        """Test payload analysis utility methods"""
        log_info("Testing payload analysis methods")

        # Test bypass detection
        mock_response_bypassed = Mock()
        mock_response_bypassed.status_code = 200
        mock_response_bypassed.text = "' OR '1'='1 mysql error"

        is_bypassed = self.scanner._is_payload_bypassed(
            mock_response_bypassed, "' OR '1'='1"
        )
        self.assertTrue(is_bypassed)

        # Test block detection
        mock_response_blocked = Mock()
        mock_response_blocked.status_code = 403
        mock_response_blocked.text = "Access denied by security policy"

        is_blocked = self.scanner._is_payload_blocked(mock_response_blocked)
        self.assertTrue(is_blocked)

        log_success("✅ Payload analysis methods test passed")

    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        log_info("Testing risk score calculation")

        # Test with empty findings
        risk_score = self.scanner._calculate_waf_risk_score([])
        self.assertEqual(risk_score, 0.0)

        # Test with sample findings
        sample_findings = [
            {"severity": ScanSeverity.HIGH},
            {"severity": ScanSeverity.MEDIUM},
            {"severity": ScanSeverity.LOW},
        ]

        risk_score = self.scanner._calculate_waf_risk_score(sample_findings)
        self.assertIsInstance(risk_score, float)
        self.assertGreaterEqual(risk_score, 0.0)
        self.assertLessEqual(risk_score, 100.0)

        log_success("✅ Risk score calculation test passed")

    def test_scanner_registry_integration(self):
        """Test integration with scanner registry"""
        log_info("Testing scanner registry integration")

        try:
            from scanners import (
                get_scanner_by_name,
                get_scanners_by_category,
                SCANNER_REGISTRY,
            )

            # Test registry includes WAF scanner
            waf_scanner_class = get_scanner_by_name("waf")
            self.assertIsNotNone(waf_scanner_class)
            self.assertEqual(waf_scanner_class, WAFScanner)

            # Test security category
            security_scanners = get_scanners_by_category("security")
            self.assertIn("waf", security_scanners)
            self.assertEqual(security_scanners["waf"], WAFScanner)

            # Test scanner in main registry
            self.assertIn("waf", SCANNER_REGISTRY)
            self.assertEqual(SCANNER_REGISTRY["waf"], WAFScanner)

            log_success("✅ Scanner registry integration test passed")

        except ImportError as e:
            log_warning(f"⚠️  Scanner registry integration test skipped: {e}")


def run_waf_scanner_tests():
    """Run all WAF scanner tests"""
    print("🔍 WAF Scanner Test Suite - Phase 2.2")
    print("=" * 50)

    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestWAFScanner)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Summary
    if result.wasSuccessful():
        log_success("🎉 All WAF scanner tests passed!")
        return True
    else:
        log_error(
            f"❌ {len(result.failures)} test(s) failed, {len(result.errors)} error(s)"
        )
        return False


if __name__ == "__main__":
    success = run_waf_scanner_tests()
    sys.exit(0 if success else 1)
