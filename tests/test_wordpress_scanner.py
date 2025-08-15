#!/usr/bin/env python3
"""
Unit tests for WordPress Scanner
Phase 1.1 Implementation: CMS-Specific Vulnerability Scanners
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.scanners.cms.wordpress_scanner import WordPressScanner
from src.core import ScanStatus, ScanSeverity
from src.utils.logger import LoggerSetup, log_banner, log_success, log_error, log_info


class TestWordPressScanner(unittest.TestCase):
    """Test cases for WordPressScanner"""

    def setUp(self):
        """Set up test fixtures"""
        self.scanner = WordPressScanner(timeout=60)

    def test_validate_target(self):
        """Test target validation"""
        log_info("Testing WordPress scanner target validation")

        # Valid targets
        valid_targets = [
            "https://example.com",
            "http://example.com:8080",
            "example.com",
            "sub.domain.com",
            "192.168.1.100",
        ]

        for target in valid_targets:
            self.assertTrue(
                self.scanner.validate_target(target), f"Should validate: {target}"
            )

        # Invalid targets
        invalid_targets = [
            "",  # Empty string
            "ftp://example.com",  # Wrong protocol
            "invalid_format",  # Invalid format
        ]

        for target in invalid_targets:
            self.assertFalse(
                self.scanner.validate_target(target), f"Should not validate: {target}"
            )

        log_success("Target validation tests passed")

    def test_get_capabilities(self):
        """Test scanner capabilities"""
        log_info("Testing WordPress scanner capabilities")

        capabilities = self.scanner.get_capabilities()

        # Check required fields
        required_fields = [
            "name",
            "description",
            "version",
            "supported_targets",
            "scan_types",
            "features",
            "dependencies",
        ]

        for field in required_fields:
            self.assertIn(field, capabilities, f"Missing capability field: {field}")

        # Check scan types
        expected_scan_types = [
            "wordpress_detection",
            "version_enumeration",
            "plugin_enumeration",
            "theme_enumeration",
            "user_enumeration",
            "vulnerability_assessment",
        ]

        for scan_type in expected_scan_types:
            self.assertIn(scan_type, capabilities["scan_types"])

        # Check features
        self.assertGreater(len(capabilities["features"]), 0)
        self.assertIn("WPScan integration", capabilities["features"])

        log_success("Capabilities test passed")

    def test_normalize_target_url(self):
        """Test URL normalization"""
        log_info("Testing URL normalization")

        test_cases = [
            ("example.com", {}, "https://example.com"),
            ("example.com", {"scheme": "http"}, "http://example.com"),
            (
                "example.com",
                {"scheme": "https", "port": 8080},
                "https://example.com:8080",
            ),
            ("https://example.com", {}, "https://example.com"),
            ("http://example.com:8080", {}, "http://example.com:8080"),
        ]

        for target, options, expected in test_cases:
            result = self.scanner._normalize_target_url(target, options)
            self.assertEqual(result, expected, f"Normalization failed for {target}")

        log_success("URL normalization tests passed")

    @patch("src.scanners.cms.wordpress_scanner.requests.Session")
    def test_detect_wordpress_positive(self, mock_session):
        """Test WordPress detection when WordPress is present"""
        log_info("Testing WordPress detection (positive case)")

        # Mock successful WordPress detection
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<html><head><meta name="generator" content="WordPress 6.3" /></head></html>'

        mock_session_instance = Mock()
        mock_session_instance.get.return_value = mock_response
        mock_session.return_value = mock_session_instance

        # Create a scan result to populate
        from src.core import ScanResult
        from datetime import datetime

        result = ScanResult(
            scanner_name="test",
            target="https://example.com",
            status=ScanStatus.RUNNING,
            start_time=datetime.now(),
        )

        # Test WordPress detection
        wp_detected = self.scanner._detect_wordpress("https://example.com", result)

        self.assertTrue(wp_detected, "Should detect WordPress")
        self.assertGreater(len(result.findings), 0, "Should have detection findings")

        log_success("WordPress detection (positive) test passed")

    @patch("src.scanners.cms.wordpress_scanner.requests.Session")
    def test_detect_wordpress_negative(self, mock_session):
        """Test WordPress detection when WordPress is not present"""
        log_info("Testing WordPress detection (negative case)")

        # Mock no WordPress detection
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><head><title>Regular Website</title></head></html>"

        mock_session_instance = Mock()
        mock_session_instance.get.return_value = mock_response
        mock_session.return_value = mock_session_instance

        # Create a scan result to populate
        from src.core import ScanResult
        from datetime import datetime

        result = ScanResult(
            scanner_name="test",
            target="https://example.com",
            status=ScanStatus.RUNNING,
            start_time=datetime.now(),
        )

        # Test WordPress detection
        wp_detected = self.scanner._detect_wordpress("https://example.com", result)

        self.assertFalse(wp_detected, "Should not detect WordPress")

        log_success("WordPress detection (negative) test passed")

    @patch("src.scanners.cms.wordpress_scanner.requests.Session")
    def test_detect_wp_version(self, mock_session):
        """Test WordPress version detection"""
        log_info("Testing WordPress version detection")

        # Mock version detection via generator meta tag
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<meta name="generator" content="WordPress 6.3.1" />'

        mock_session_instance = Mock()
        mock_session_instance.get.return_value = mock_response
        mock_session.return_value = mock_session_instance

        # Create a scan result to populate
        from src.core import ScanResult
        from datetime import datetime

        result = ScanResult(
            scanner_name="test",
            target="https://example.com",
            status=ScanStatus.RUNNING,
            start_time=datetime.now(),
        )

        # Test version detection
        version = self.scanner._detect_wp_version("https://example.com", result)

        self.assertEqual(version, "6.3.1", "Should detect correct version")
        self.assertGreater(len(result.findings), 0, "Should have version findings")

        log_success("WordPress version detection test passed")

    @patch("src.scanners.cms.wordpress_scanner.requests.Session")
    def test_enumerate_plugins(self, mock_session):
        """Test plugin enumeration"""
        log_info("Testing WordPress plugin enumeration")

        # Mock plugin detection responses
        def mock_get(url, **kwargs):
            mock_response = Mock()
            if "/wp-content/plugins/akismet/" in url:
                mock_response.status_code = 200
            elif "/wp-content/plugins/jetpack/" in url:
                mock_response.status_code = 403  # Plugin exists but protected
            else:
                mock_response.status_code = 404
            return mock_response

        mock_session_instance = Mock()
        mock_session_instance.get.side_effect = mock_get
        mock_session.return_value = mock_session_instance

        # Create a scan result to populate
        from src.core import ScanResult
        from datetime import datetime

        result = ScanResult(
            scanner_name="test",
            target="https://example.com",
            status=ScanStatus.RUNNING,
            start_time=datetime.now(),
        )

        # Test plugin enumeration
        self.scanner._enumerate_plugins("https://example.com", result, {})

        # Should find plugins that returned 200 or 403
        self.assertGreater(len(result.findings), 0, "Should have plugin findings")

        log_success("Plugin enumeration test passed")

    @patch("src.scanners.cms.wordpress_scanner.requests.Session")
    def test_enumerate_users(self, mock_session):
        """Test user enumeration"""
        log_info("Testing WordPress user enumeration")

        # Mock user enumeration via REST API
        mock_api_response = Mock()
        mock_api_response.status_code = 200
        mock_api_response.json.return_value = [
            {"slug": "admin", "id": 1},
            {"slug": "editor", "id": 2},
        ]

        def mock_get(url, **kwargs):
            if "/wp-json/wp/v2/users" in url:
                return mock_api_response
            else:
                mock_response = Mock()
                mock_response.status_code = 404
                return mock_response

        mock_session_instance = Mock()
        mock_session_instance.get.side_effect = mock_get
        mock_session.return_value = mock_session_instance

        # Create a scan result to populate
        from src.core import ScanResult
        from datetime import datetime

        result = ScanResult(
            scanner_name="test",
            target="https://example.com",
            status=ScanStatus.RUNNING,
            start_time=datetime.now(),
        )

        # Test user enumeration
        self.scanner._enumerate_users("https://example.com", result, {})

        # Should find users from API
        self.assertGreater(len(result.findings), 0, "Should have user findings")

        log_success("User enumeration test passed")

    def test_assess_version_security(self):
        """Test version security assessment"""
        log_info("Testing version security assessment")

        # Test different version severities
        test_cases = [
            ("5.8", ScanSeverity.HIGH),  # Old major version
            ("6.2", ScanSeverity.MEDIUM),  # Older minor version
            ("6.4", ScanSeverity.LOW),  # Recent version
        ]

        for version, expected_severity in test_cases:
            severity = self.scanner._assess_version_security(version)
            self.assertEqual(
                severity,
                expected_severity,
                f"Version {version} should have severity {expected_severity}",
            )

        log_success("Version security assessment test passed")

    def test_assess_vulnerability_severity(self):
        """Test vulnerability severity assessment"""
        log_info("Testing vulnerability severity assessment")

        test_cases = [
            ({"title": "Remote Code Execution", "type": "RCE"}, ScanSeverity.CRITICAL),
            (
                {"title": "SQL Injection Vulnerability", "type": "SQLi"},
                ScanSeverity.CRITICAL,
            ),
            ({"title": "Cross-Site Scripting", "type": "XSS"}, ScanSeverity.HIGH),
            ({"title": "Information Disclosure", "type": "Info"}, ScanSeverity.MEDIUM),
        ]

        for vuln, expected_severity in test_cases:
            severity = self.scanner._assess_vulnerability_severity(vuln)
            self.assertEqual(
                severity,
                expected_severity,
                f"Vulnerability {vuln['title']} should have severity {expected_severity}",
            )

        log_success("Vulnerability severity assessment test passed")

    @patch("src.scanners.cms.wordpress_scanner.CommandExecutor")
    def test_wpscan_integration(self, mock_executor):
        """Test WPScan integration"""
        log_info("Testing WPScan integration")

        # Mock WPScan available
        with patch.object(self.scanner, "_check_wpscan_available") as mock_check:
            mock_check.return_value = {"available": True, "version": "3.8.22"}

            # Mock WPScan output
            mock_wpscan_output = {
                "version": {
                    "number": "6.3.1",
                    "vulnerabilities": [
                        {
                            "title": "WordPress Core Vulnerability",
                            "vuln_type": "XSS",
                            "references": {"url": ["https://example.com"]},
                        }
                    ],
                },
                "plugins": {
                    "test-plugin": {
                        "vulnerabilities": [
                            {
                                "title": "Plugin Vulnerability",
                                "vuln_type": "SQLi",
                                "references": {"cve": ["CVE-2023-1234"]},
                            }
                        ]
                    }
                },
            }

            # Mock command execution
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = json.dumps(mock_wpscan_output)
            mock_result.stderr = ""

            mock_executor_instance = Mock()
            mock_executor_instance.execute_command.return_value = mock_result
            mock_executor.return_value = mock_executor_instance

            # Create a scan result to populate
            from src.core import ScanResult
            from datetime import datetime

            result = ScanResult(
                scanner_name="test",
                target="https://example.com",
                status=ScanStatus.RUNNING,
                start_time=datetime.now(),
            )

            # Test WPScan integration
            self.scanner._run_wpscan("https://example.com", result, {})

            # Should have vulnerabilities from WPScan
            vulnerability_findings = [
                f for f in result.findings if "Vulnerability" in f.get("title", "")
            ]
            self.assertGreater(
                len(vulnerability_findings),
                0,
                "Should have vulnerability findings from WPScan",
            )

        log_success("WPScan integration test passed")

    @patch("src.scanners.cms.wordpress_scanner.requests.Session")
    def test_full_scan_workflow(self, mock_session):
        """Test complete scan workflow"""
        log_info("Testing complete WordPress scan workflow")

        # Mock WordPress detection
        mock_wp_response = Mock()
        mock_wp_response.status_code = 200
        mock_wp_response.text = """
        <html>
        <head>
            <meta name="generator" content="WordPress 6.3.1" />
            <link rel="stylesheet" href="/wp-content/themes/twentytwentythree/style.css" />
            <script src="/wp-content/plugins/akismet/js/akismet.js"></script>
        </head>
        </html>
        """

        # Mock various endpoint responses
        def mock_get(url, **kwargs):
            if "/wp-login.php" in url:
                mock_wp_response.status_code = 200
                return mock_wp_response
            elif "/wp-content/" in url:
                mock_wp_response.status_code = 200
                return mock_wp_response
            elif "/xmlrpc.php" in url:
                mock_response = Mock()
                mock_response.status_code = 405  # XML-RPC enabled
                return mock_response
            else:
                return mock_wp_response

        mock_session_instance = Mock()
        mock_session_instance.get.side_effect = mock_get
        mock_session.return_value = mock_session_instance

        # Mock WPScan not available for this test
        with patch.object(self.scanner, "_check_wpscan_available") as mock_check:
            mock_check.return_value = {"available": False}

            # Execute full scan
            scan_options = {
                "enumerate_plugins": True,
                "enumerate_themes": True,
                "enumerate_users": True,
                "use_wpscan": False,
            }

            result = self.scanner._execute_scan("https://example.com", scan_options)

            # Verify scan completion
            self.assertEqual(
                result.status, ScanStatus.COMPLETED, "Scan should complete successfully"
            )
            self.assertGreater(len(result.findings), 0, "Should have findings")
            self.assertIsNotNone(result.end_time, "Should have end time")

        log_success("Full scan workflow test passed")


def test_wordpress_scanner_basic():
    """Basic WordPress scanner test"""
    log_banner("Testing WordPress Scanner", "bold blue")

    scanner = WordPressScanner()

    # Test scanner info
    info = scanner.get_capabilities()
    log_info(f"Scanner: {info['name']}")
    log_info(f"Description: {info['description']}")
    log_info(f"Features: {len(info['features'])}")

    # Test target validation
    valid_targets = ["https://example.com", "example.com"]
    invalid_targets = ["", "ftp://example.com"]

    log_info("Testing valid targets:")
    for target in valid_targets:
        is_valid = scanner.validate_target(target)
        status = "✅" if is_valid else "❌"
        log_info(f"  {status} {target}: {is_valid}")

    log_info("Testing invalid targets:")
    for target in invalid_targets:
        is_valid = scanner.validate_target(target)
        status = "✅" if not is_valid else "❌"  # Should be False
        log_info(f"  {status} {target}: {is_valid}")

    log_success("WordPress scanner basic test completed")


if __name__ == "__main__":
    # Setup logging
    LoggerSetup.setup_console_logging()

    # Run basic test
    test_wordpress_scanner_basic()

    # Run unit tests
    log_banner("Running WordPress Scanner Unit Tests", "bold red")
    unittest.main(verbosity=2)
