#!/usr/bin/env python3
"""
Comprehensive test for Web Scanner functionality
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.scanners.vulnerability.web_scanner import WebScanner
from src.core import ScanStatus, ScanSeverity
from src.utils.logger import LoggerSetup, log_banner, log_success, log_error, log_info


class TestWebScanner(unittest.TestCase):
    """Test cases for WebScanner"""

    def setUp(self):
        """Set up test fixtures"""
        self.scanner = WebScanner(timeout=60)

    def test_validate_target(self):
        """Test target validation"""
        log_info("Testing target validation")

        # Valid targets
        valid_targets = [
            "https://example.com",
            "http://example.com:8080",
            "example.com",
            "192.168.1.1",
            "sub.domain.com",
        ]

        for target in valid_targets:
            self.assertTrue(
                self.scanner.validate_target(target), f"Should validate: {target}"
            )

        # Invalid targets - only truly invalid formats
        invalid_targets = [
            "",  # Empty string
            "ftp://example.com",  # Wrong protocol in URL
            "invalid_format_no_tld",  # No TLD
            "192.168.999.1",  # Invalid IP
        ]

        for target in invalid_targets:
            is_valid = self.scanner.validate_target(target)
            self.assertFalse(
                is_valid, f"Should not validate: {target} (got: {is_valid})"
            )

        log_success("Target validation tests passed")

    def test_normalize_url(self):
        """Test URL normalization"""
        log_info("Testing URL normalization")

        test_cases = [
            ("example.com", {"scheme": "https"}, "https://example.com"),
            (
                "example.com",
                {"scheme": "http", "port": 8080},
                "http://example.com:8080",
            ),
            ("https://example.com", {}, "https://example.com"),
            ("192.168.1.1", {"scheme": "http"}, "http://192.168.1.1"),
        ]

        for target, options, expected in test_cases:
            result = self.scanner._normalize_target_url(target, options)
            self.assertEqual(result, expected, f"Failed for {target} with {options}")

    def test_nikto_severity_determination(self):
        """Test Nikto severity determination"""
        log_info("Testing Nikto severity determination")

        test_cases = [
            ("Shell found on server", "999999", ScanSeverity.CRITICAL),
            ("SQL injection vulnerability", "123456", ScanSeverity.CRITICAL),
            ("XSS vulnerability found", "789012", ScanSeverity.HIGH),
            ("Administrative interface found", "345678", ScanSeverity.MEDIUM),
            ("Interesting directory found", "567890", ScanSeverity.LOW),
            ("Server version disclosed", "234567", ScanSeverity.LOW),
        ]

        for message, vuln_id, expected_severity in test_cases:
            result = self.scanner._determine_nikto_severity(message, vuln_id)
            self.assertEqual(result, expected_severity, f"Failed for: {message}")

    @patch("requests.Session")
    def test_http_header_analysis(self, mock_session_class):
        """Test HTTP header analysis"""
        log_info("Testing HTTP header analysis")

        # Mock session and response
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.url = "https://example.com"
        mock_response.history = []
        mock_response.headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3",
            "X-Debug": "enabled",
            "Content-Type": "text/html",
        }
        mock_session.head.return_value = mock_response

        # Create scanner with mocked session
        scanner = WebScanner()
        scanner.session = mock_session

        from src.core import ScanResult, ScanStatus
        from datetime import datetime

        result = ScanResult(
            scanner_name="test",
            target="https://example.com",
            status=ScanStatus.RUNNING,
            start_time=datetime.now(),
        )

        # Test header analysis
        scanner._analyze_http_headers("https://example.com", result)

        # Verify findings
        self.assertGreater(len(result.findings), 0)

        # Check for specific findings
        categories = [f.get("category") for f in result.findings]
        self.assertIn("server_info", categories)
        self.assertIn("tech_disclosure", categories)
        self.assertIn("info_disclosure", categories)

    def test_security_headers_check(self):
        """Test security headers checking"""
        log_info("Testing security headers check")

        # Test with missing security headers
        headers = {
            "Server": "nginx/1.18.0",
            "Content-Type": "text/html",
            # Missing all security headers
        }

        with patch.object(self.scanner.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.headers = headers
            mock_get.return_value = mock_response

            from src.core import ScanResult, ScanStatus
            from datetime import datetime

            result = ScanResult(
                scanner_name="test",
                target="https://example.com",
                status=ScanStatus.RUNNING,
                start_time=datetime.now(),
            )

            self.scanner._check_security_headers("https://example.com", result)

            # Should find missing security headers
            missing_headers = [
                f
                for f in result.findings
                if f.get("category") == "security_header_missing"
            ]
            self.assertGreater(len(missing_headers), 0)

    def test_robots_txt_analysis(self):
        """Test robots.txt analysis"""
        log_info("Testing robots.txt analysis")

        robots_content = """User-agent: *
Disallow: /admin/
Disallow: /private/
Disallow: /backup/
Allow: /public/
Sitemap: https://example.com/sitemap.xml"""

        with patch.object(self.scanner.session, "get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = robots_content
            mock_get.return_value = mock_response

            from src.core import ScanResult, ScanStatus
            from datetime import datetime

            result = ScanResult(
                scanner_name="test",
                target="https://example.com",
                status=ScanStatus.RUNNING,
                start_time=datetime.now(),
            )

            self.scanner._analyze_robots_txt("https://example.com", result)

            # Should find robots.txt findings
            robots_findings = [
                f for f in result.findings if f.get("category") == "robots_txt"
            ]
            self.assertGreater(len(robots_findings), 0)

            # Should detect interesting paths
            interesting_findings = [
                f
                for f in robots_findings
                if "interesting" in f.get("title", "").lower()
            ]
            self.assertGreater(len(interesting_findings), 0)

    def test_http_methods_testing(self):
        """Test HTTP methods testing"""
        log_info("Testing HTTP methods testing")

        with patch.object(
            self.scanner.session, "options"
        ) as mock_options, patch.object(
            self.scanner.session, "request"
        ) as mock_request:

            # Mock OPTIONS response
            mock_options_response = Mock()
            mock_options_response.headers = {"Allow": "GET, POST, PUT, DELETE, TRACE"}
            mock_options.return_value = mock_options_response

            # Mock individual method responses
            mock_request.return_value = Mock(status_code=200)

            from src.core import ScanResult, ScanStatus
            from datetime import datetime

            result = ScanResult(
                scanner_name="test",
                target="https://example.com",
                status=ScanStatus.RUNNING,
                start_time=datetime.now(),
            )

            self.scanner._test_http_methods("https://example.com", result)

            # Should find dangerous methods
            dangerous_findings = [
                f for f in result.findings if "dangerous" in f.get("title", "").lower()
            ]
            self.assertGreater(len(dangerous_findings), 0)

    def test_get_capabilities(self):
        """Test scanner capabilities"""
        log_info("Testing scanner capabilities")

        capabilities = self.scanner.get_capabilities()

        # Verify basic structure
        self.assertEqual(capabilities["name"], "web_scanner")
        self.assertIn("url", capabilities["supported_targets"])
        self.assertIn("domain", capabilities["supported_targets"])
        self.assertIn("ip", capabilities["supported_targets"])

        # Verify features
        self.assertGreater(len(capabilities["features"]), 0)
        self.assertIn("HTTP header analysis", capabilities["features"])
        self.assertIn("Security headers checking", capabilities["features"])


def run_web_scanner_demo():
    """Run a demonstration of the web scanner"""
    log_banner("Web Scanner Demo", "bold cyan")

    try:
        scanner = WebScanner(timeout=120)

        log_info("Web Scanner created successfully")

        # Show capabilities
        capabilities = scanner.get_capabilities()
        log_info(f"Scanner: {capabilities['name']}")
        log_info(f"Features: {len(capabilities['features'])} available")
        log_info(
            f"Dependencies: nikto available = {capabilities['dependencies']['nikto']['available']}"
        )

        log_info("\nSimulating web scan on httpbin.org...")

        # For demo, create a mock result
        from src.core import ScanResult, ScanStatus
        from datetime import datetime

        demo_result = ScanResult(
            scanner_name="web_scanner",
            target="https://httpbin.org",
            status=ScanStatus.COMPLETED,
            start_time=datetime.now(),
        )

        # Add some demo findings
        demo_result.add_finding(
            title="Server Information: nginx/1.18.0",
            description="Server header reveals: nginx/1.18.0",
            severity=ScanSeverity.INFO,
            category="server_info",
        )

        demo_result.add_finding(
            title="Missing Security Header: HSTS",
            description="Strict-Transport-Security header is not set",
            severity=ScanSeverity.MEDIUM,
            category="security_header_missing",
        )

        demo_result.add_finding(
            title="Technology Detected: nginx",
            description="Detected nginx web server",
            severity=ScanSeverity.INFO,
            category="technology_detection",
        )

        # Show results
        log_success(f"Web scan completed with status: {demo_result.status.value}")
        log_info(f"Found {len(demo_result.findings)} findings:")

        for finding in demo_result.findings:
            severity_color = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "green",
                "info": "cyan",
            }.get(finding["severity"], "white")

            log_info(
                f"  [{severity_color}]{finding['severity'].upper()}[/{severity_color}] {finding['title']}"
            )

        log_banner("Demo Completed Successfully", "bold green")

    except Exception as e:
        log_error(f"Demo failed: {e}")
        import traceback

        traceback.print_exc()


def main():
    """Run all tests and demo"""
    log_banner("Web Scanner Comprehensive Test Suite", "bold magenta")

    # Setup logger
    logger = LoggerSetup.setup_logger(
        name="test_web_scanner_comprehensive", level="INFO", use_rich=True
    )

    try:
        # Run unit tests
        log_banner("Running Unit Tests", "bold blue")

        test_suite = unittest.TestLoader().loadTestsFromTestCase(TestWebScanner)
        test_runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
        test_result = test_runner.run(test_suite)

        if test_result.wasSuccessful():
            log_success(f"All {test_result.testsRun} tests passed!")
        else:
            log_error(
                f"Tests failed: {len(test_result.failures)} failures, {len(test_result.errors)} errors"
            )
            return False

        print()  # Add spacing

        # Run demo
        run_web_scanner_demo()

        return True

    except Exception as e:
        log_error(f"Test suite failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
