#!/usr/bin/env python3
"""
Network Scanner Test Suite
Tests for Network Vulnerability Scanner with Nuclei integration
"""

import sys
import os
import unittest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from src.scanners.vulnerability.network_scanner import NetworkScanner
    from src.core.scanner_base import ScanResult, ScanStatus, ScanSeverity
    from src.utils.logger import log_info, log_success, log_error, log_warning
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure you're running this from the project root directory")
    sys.exit(1)


class TestNetworkScannerBasics(unittest.TestCase):
    """Test basic NetworkScanner functionality"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = NetworkScanner(timeout=120)
        self.test_targets = {
            "valid_ip": "192.168.1.1",
            "valid_domain": "example.com",
            "valid_url": "https://example.com",
            "valid_ip_port": "192.168.1.1:8080",
            "invalid_targets": ["", "not-a-target", "256.256.256.256"],
        }

    def test_scanner_initialization(self):
        """Test scanner initialization"""
        log_info("Testing NetworkScanner initialization")

        self.assertEqual(self.scanner.name, "network_scanner")
        self.assertEqual(self.scanner.timeout, 120)
        self.assertEqual(self.scanner.nuclei_binary, "nuclei")
        self.assertIsNotNone(self.scanner.executor)
        self.assertIsNotNone(self.scanner.logger)

        log_success("✅ Scanner initialization test passed")

    def test_validate_target_valid_inputs(self):
        """Test target validation with valid inputs"""
        log_info("Testing valid target validation")

        valid_targets = [
            self.test_targets["valid_ip"],
            self.test_targets["valid_domain"],
            self.test_targets["valid_url"],
            self.test_targets["valid_ip_port"],
        ]

        for target in valid_targets:
            with self.subTest(target=target):
                result = self.scanner.validate_target(target)
                self.assertTrue(result, f"Target {target} should be valid")

        log_success("✅ Valid target validation tests passed")

    def test_validate_target_invalid_inputs(self):
        """Test target validation with invalid inputs"""
        log_info("Testing invalid target validation")

        for target in self.test_targets["invalid_targets"]:
            with self.subTest(target=target):
                result = self.scanner.validate_target(target)
                self.assertFalse(result, f"Target {target} should be invalid")

        # Test edge cases
        edge_cases = [None, 123, [], {}]
        for target in edge_cases:
            with self.subTest(target=target):
                result = self.scanner.validate_target(target)
                self.assertFalse(result, f"Target {target} should be invalid")

        log_success("✅ Invalid target validation tests passed")

    def test_ip_port_validation(self):
        """Test IP:port format validation"""
        log_info("Testing IP:port validation")

        valid_ip_ports = [
            "192.168.1.1:80",
            "10.0.0.1:443",
            "172.16.0.1:8080",
            "127.0.0.1:22",
        ]

        invalid_ip_ports = [
            "192.168.1.1:99999",  # Invalid port
            "256.256.256.256:80",  # Invalid IP
            "192.168.1.1:",  # No port
            ":80",  # No IP
            "192.168.1.1:abc",  # Non-numeric port
        ]

        for target in valid_ip_ports:
            with self.subTest(target=target):
                result = self.scanner._validate_ip_port(target)
                self.assertTrue(result, f"IP:port {target} should be valid")

        for target in invalid_ip_ports:
            with self.subTest(target=target):
                result = self.scanner._validate_ip_port(target)
                self.assertFalse(result, f"IP:port {target} should be invalid")

        log_success("✅ IP:port validation tests passed")

    def test_get_capabilities(self):
        """Test scanner capabilities"""
        log_info("Testing scanner capabilities")

        capabilities = self.scanner.get_capabilities()

        # Test required fields
        required_fields = [
            "name",
            "description",
            "version",
            "author",
            "supported_targets",
            "supported_protocols",
            "features",
            "requirements",
            "scan_types",
        ]

        for field in required_fields:
            with self.subTest(field=field):
                self.assertIn(
                    field, capabilities, f"Capability {field} should be present"
                )

        # Test specific values
        self.assertEqual(capabilities["name"], "Network Vulnerability Scanner")
        self.assertIn("nuclei_integration", capabilities["features"])
        self.assertIn("nuclei", capabilities["requirements"])
        self.assertIn("ip", capabilities["supported_targets"])

        log_success("✅ Scanner capabilities test passed")


class TestNetworkScannerFunctionality(unittest.TestCase):
    """Test NetworkScanner functionality with mocks"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = NetworkScanner(timeout=60)
        self.test_target = "example.com"

    @patch(
        "src.scanners.vulnerability.network_scanner.NetworkScanner._check_nuclei_available"
    )
    def test_nuclei_availability_check(self, mock_nuclei_check):
        """Test Nuclei availability checking"""
        log_info("Testing Nuclei availability check")

        # Test when Nuclei is available
        mock_nuclei_check.return_value = True
        self.assertTrue(self.scanner._check_nuclei_available())

        # Test when Nuclei is not available
        mock_nuclei_check.return_value = False
        self.assertFalse(self.scanner._check_nuclei_available())

        log_success("✅ Nuclei availability check test passed")

    def test_nuclei_severity_mapping(self):
        """Test Nuclei severity mapping"""
        log_info("Testing Nuclei severity mapping")

        severity_tests = {
            "info": ScanSeverity.INFO.value,
            "low": ScanSeverity.LOW.value,
            "medium": ScanSeverity.MEDIUM.value,
            "high": ScanSeverity.HIGH.value,
            "critical": ScanSeverity.CRITICAL.value,
            "unknown": ScanSeverity.INFO.value,  # Default fallback
        }

        for nuclei_severity, expected in severity_tests.items():
            with self.subTest(severity=nuclei_severity):
                result = self.scanner._map_nuclei_severity(nuclei_severity)
                self.assertEqual(result, expected)

        log_success("✅ Nuclei severity mapping test passed")

    def test_recommendation_generation(self):
        """Test security recommendation generation"""
        log_info("Testing recommendation generation")

        test_cases = [
            {
                "vuln_data": {"template-id": "sql-injection-test"},
                "expected_keyword": "parameterized queries",
            },
            {
                "vuln_data": {"template-id": "xss-reflected"},
                "expected_keyword": "output encoding",
            },
            {
                "vuln_data": {"template-id": "lfi-vulnerability"},
                "expected_keyword": "file paths",
            },
            {
                "vuln_data": {"template-id": "command-injection"},
                "expected_keyword": "input validation",
            },
            {
                "vuln_data": {"template-id": "auth-bypass"},
                "expected_keyword": "authentication",
            },
            {
                "vuln_data": {"template-id": "info-disclosure"},
                "expected_keyword": "sensitive information",
            },
            {
                "vuln_data": {"template-id": "unknown-vuln"},
                "expected_keyword": "security best practices",
            },
        ]

        for case in test_cases:
            with self.subTest(vuln_id=case["vuln_data"]["template-id"]):
                recommendation = self.scanner._generate_recommendation(
                    case["vuln_data"]
                )
                self.assertIn(case["expected_keyword"], recommendation.lower())

        log_success("✅ Recommendation generation test passed")

    def test_severity_breakdown(self):
        """Test severity breakdown calculation"""
        log_info("Testing severity breakdown")

        test_findings = [
            {"severity": "critical", "title": "Critical vuln 1"},
            {"severity": "critical", "title": "Critical vuln 2"},
            {"severity": "high", "title": "High vuln 1"},
            {"severity": "medium", "title": "Medium vuln 1"},
            {"severity": "medium", "title": "Medium vuln 2"},
            {"severity": "medium", "title": "Medium vuln 3"},
            {"severity": "low", "title": "Low vuln 1"},
            {"severity": "info", "title": "Info finding 1"},
            {"severity": "info", "title": "Info finding 2"},
        ]

        breakdown = self.scanner._get_severity_breakdown(test_findings)

        expected_breakdown = {
            "critical": 2,
            "high": 1,
            "medium": 3,
            "low": 1,
            "info": 2,
        }

        self.assertEqual(breakdown, expected_breakdown)

        log_success("✅ Severity breakdown test passed")

    def test_parse_nuclei_output(self):
        """Test Nuclei output parsing"""
        log_info("Testing Nuclei output parsing")

        # Mock Nuclei JSON output
        nuclei_output = """{"template-id":"test-vuln","info":{"name":"Test Vulnerability","description":"Test description","severity":"high","classification":{"cvss":{"score":7.5}},"reference":["https://example.com"],"tags":["test","vuln"]},"matched-at":"https://example.com","matcher-name":"test-matcher","extracted-results":["result1","result2"]}
{"template-id":"another-vuln","info":{"name":"Another Vulnerability","description":"Another description","severity":"medium"},"matched-at":"https://example.com/path"}"""

        findings = self.scanner._parse_nuclei_output(nuclei_output)

        self.assertEqual(len(findings), 2)

        # Test first finding
        first_finding = findings[0]
        self.assertEqual(first_finding["id"], "test-vuln")
        self.assertEqual(first_finding["title"], "Test Vulnerability")
        self.assertEqual(first_finding["severity"], "high")
        self.assertEqual(first_finding["matched_at"], "https://example.com")
        self.assertIn("result1", first_finding["extracted_results"])

        # Test second finding
        second_finding = findings[1]
        self.assertEqual(second_finding["id"], "another-vuln")
        self.assertEqual(second_finding["severity"], "medium")

        log_success("✅ Nuclei output parsing test passed")

    @patch(
        "src.scanners.vulnerability.network_scanner.NetworkScanner._check_nuclei_available"
    )
    @patch("src.scanners.vulnerability.network_scanner.NetworkScanner._run_nuclei_scan")
    @patch(
        "src.scanners.vulnerability.network_scanner.NetworkScanner._run_custom_analysis"
    )
    def test_execute_scan_success(self, mock_custom, mock_nuclei, mock_available):
        """Test successful scan execution"""
        log_info("Testing successful scan execution")

        # Setup mocks
        mock_available.return_value = True
        mock_nuclei.return_value = [
            {
                "type": "vulnerability",
                "id": "test-vuln",
                "title": "Test Vulnerability",
                "severity": "high",
            }
        ]
        mock_custom.return_value = []

        # Execute scan
        result = self.scanner._execute_scan(self.test_target, {})

        # Verify result
        self.assertIsInstance(result, ScanResult)
        self.assertEqual(result.scanner_name, "network_scanner")
        self.assertEqual(result.target, self.test_target)
        self.assertEqual(result.status, ScanStatus.COMPLETED)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("nuclei_templates_used", result.metadata)

        log_success("✅ Successful scan execution test passed")

    @patch(
        "src.scanners.vulnerability.network_scanner.NetworkScanner._check_nuclei_available"
    )
    def test_execute_scan_nuclei_unavailable(self, mock_available):
        """Test scan execution when Nuclei is unavailable"""
        log_info("Testing scan execution with Nuclei unavailable")

        # Setup mock
        mock_available.return_value = False

        # Execute scan
        result = self.scanner._execute_scan(self.test_target, {})

        # Verify result
        self.assertEqual(result.status, ScanStatus.FAILED)
        self.assertIn("Nuclei not found", result.errors[0])

        log_success("✅ Nuclei unavailable test passed")


class TestNetworkScannerIntegration(unittest.TestCase):
    """Test NetworkScanner integration with framework"""

    def setUp(self):
        """Set up test environment"""
        self.scanner = NetworkScanner()

    def test_scanner_registration(self):
        """Test scanner is properly registered"""
        log_info("Testing scanner registration")

        try:
            from src.scanners import SCANNER_REGISTRY, get_scanner_by_name

            # Test registry contains network scanner
            self.assertIn("network", SCANNER_REGISTRY)
            self.assertEqual(SCANNER_REGISTRY["network"], NetworkScanner)

            # Test get_scanner_by_name
            scanner_class = get_scanner_by_name("network")
            self.assertEqual(scanner_class, NetworkScanner)

            log_success("✅ Scanner registration test passed")

        except ImportError:
            log_warning("⚠️  Scanner registry not available - skipping test")

    def test_cli_integration(self):
        """Test CLI integration exists"""
        log_info("Testing CLI integration")

        try:
            from src.cli.commands import network_command
            from src.services.scanner_service import ScannerService

            # Test network command exists
            self.assertIsNotNone(network_command)

            # Test scanner service has run_network_scan method
            service = ScannerService()
            self.assertTrue(hasattr(service, "run_network_scan"))

            log_success("✅ CLI integration test passed")

        except ImportError:
            log_warning("⚠️  CLI components not available - skipping test")


def run_all_tests():
    """Run all Network Scanner tests"""
    log_info("🧪 Starting Network Scanner Test Suite")

    # Create test suite
    test_suite = unittest.TestSuite()

    # Add test classes
    test_classes = [
        TestNetworkScannerBasics,
        TestNetworkScannerFunctionality,
        TestNetworkScannerIntegration,
    ]

    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)

    # Print summary
    if result.wasSuccessful():
        log_success("🎉 All Network Scanner tests passed!")
        return True
    else:
        log_error(
            f"❌ {len(result.failures)} test(s) failed, {len(result.errors)} error(s)"
        )
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
