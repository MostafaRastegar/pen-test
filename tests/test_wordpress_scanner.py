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


@patch("src.scanners.cms.wordpress_scanner.requests.Session")
def test_multisite_detection(self, mock_session):
    """Test WordPress Multisite detection"""
    log_info("Testing WordPress Multisite detection")

    # Mock multisite response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = """
    <html>
    <body>
        <script src="/wp-includes/ms-files.js"></script>
        <div class="wp-admin/network">Network Admin</div>
    </body>
    </html>
    """

    mock_session_instance = Mock()
    mock_session_instance.get.return_value = mock_response
    mock_session.return_value = mock_session_instance

    # Test multisite detection
    multisite_info = self.scanner._detect_multisite("https://example.com")

    self.assertTrue(multisite_info["is_multisite"])
    self.assertGreater(len(multisite_info["indicators"]), 0)

    log_success("✅ Multisite detection test passed")


@patch("src.scanners.cms.wordpress_scanner.requests.Session")
def test_enhanced_plugin_enumeration(self, mock_session):
    """Test enhanced plugin enumeration with security analysis"""
    log_info("Testing enhanced plugin enumeration")

    # Mock WordPress page with plugin references
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = """
    <html>
    <head>
        <script src="/wp-content/plugins/akismet/js/akismet.js"></script>
        <link rel="stylesheet" href="/wp-content/plugins/contact-form-7/css/styles.css" />
    </head>
    </html>
    """

    mock_session_instance = Mock()
    mock_session_instance.get.return_value = mock_response
    mock_session.return_value = mock_session_instance

    # Test plugin detection
    plugins = self.scanner._detect_plugins_from_source("https://example.com")

    # Should detect plugins mentioned in HTML
    detected_plugin_names = [p["name"] for p in plugins]
    self.assertIn("akismet", detected_plugin_names)
    self.assertIn("contact-form-7", detected_plugin_names)

    log_success("✅ Enhanced plugin enumeration test passed")


def test_plugin_security_analysis(self):
    """Test plugin security status analysis"""
    log_info("Testing plugin security analysis")

    # Test vulnerable plugin
    vulnerable_plugin = {
        "name": "revslider",
        "version": "4.1",
        "path": "/wp-content/plugins/revslider/",
    }

    security_status = self.scanner._check_plugin_security_status(vulnerable_plugin)
    self.assertTrue(security_status["vulnerable"])

    # Test safe plugin
    safe_plugin = {
        "name": "safe-plugin",
        "version": "5.0",
        "path": "/wp-content/plugins/safe-plugin/",
    }

    safe_status = self.scanner._check_plugin_security_status(safe_plugin)
    self.assertFalse(safe_status["vulnerable"])

    log_success("✅ Plugin security analysis test passed")


@patch("src.scanners.cms.wordpress_scanner.requests.Session")
def test_htaccess_security_analysis(self, mock_session):
    """Test .htaccess security analysis"""
    log_info("Testing .htaccess security analysis")

    from src.core import ScanResult
    from datetime import datetime

    result = ScanResult(
        scanner_name="test",
        target="https://example.com",
        status=ScanStatus.RUNNING,
        start_time=datetime.now(),
    )

    # Mock .htaccess accessible (security issue)
    mock_htaccess_response = Mock()
    mock_htaccess_response.status_code = 200
    mock_htaccess_response.content = b"RewriteEngine On\nOptions -Indexes"
    mock_htaccess_response.headers = {"Content-Type": "text/plain"}

    # Mock main site response
    mock_main_response = Mock()
    mock_main_response.status_code = 200
    mock_main_response.headers = {"Server": "Apache"}

    def mock_get(url, **kwargs):
        if ".htaccess" in url:
            return mock_htaccess_response
        return mock_main_response

    mock_session_instance = Mock()
    mock_session_instance.get.side_effect = mock_get
    mock_session.return_value = mock_session_instance

    # Test .htaccess accessibility check
    accessibility = self.scanner._check_htaccess_accessibility("https://example.com")
    self.assertTrue(accessibility["accessible"])

    log_success("✅ .htaccess security analysis test passed")


@patch("src.scanners.cms.wordpress_scanner.requests.Session")
def test_security_plugin_detection(self, mock_session):
    """Test WordPress security plugin detection"""
    log_info("Testing security plugin detection")

    from src.core import ScanResult
    from datetime import datetime

    result = ScanResult(
        scanner_name="test",
        target="https://example.com",
        status=ScanStatus.RUNNING,
        start_time=datetime.now(),
    )

    # Mock WordPress page with Wordfence indicators
    mock_main_response = Mock()
    mock_main_response.status_code = 200
    mock_main_response.text = """
    <html>
    <head>
        <script src="/wp-content/plugins/wordfence/js/wf.js"></script>
        <script>var wfConfig = {'firewall': true};</script>
    </head>
    </html>
    """

    # Mock Wordfence plugin directory (403 - protected)
    mock_plugin_response = Mock()
    mock_plugin_response.status_code = 403

    def mock_get(url, **kwargs):
        if "/wp-content/plugins/wordfence/" in url:
            return mock_plugin_response
        return mock_main_response

    mock_session_instance = Mock()
    mock_session_instance.get.side_effect = mock_get
    mock_session.return_value = mock_session_instance

    # Test specific security plugin detection
    wordfence_info = self.scanner.security_plugins["wordfence"]
    detection_result = self.scanner._detect_specific_security_plugin(
        "https://example.com", wordfence_info
    )

    self.assertTrue(detection_result["detected"])
    self.assertGreater(detection_result["confidence"], 0)

    log_success("✅ Security plugin detection test passed")


@patch("src.scanners.cms.wordpress_scanner.requests.Session")
def test_database_security_checks(self, mock_session):
    """Test database security configuration checks"""
    log_info("Testing database security checks")

    from src.core import ScanResult
    from datetime import datetime

    result = ScanResult(
        scanner_name="test",
        target="https://example.com",
        status=ScanStatus.RUNNING,
        start_time=datetime.now(),
    )

    # Mock database error response
    mock_error_response = Mock()
    mock_error_response.status_code = 200
    mock_error_response.text = """
    <html>
    <body>
        <h1>Database Error</h1>
        <p>MySQL error: Table 'wordpress.wp_posts' doesn't exist</p>
    </body>
    </html>
    """

    # Mock wp-config.php exposure (critical issue)
    mock_config_response = Mock()
    mock_config_response.status_code = 200
    mock_config_response.content = b"""<?php
    define('DB_NAME', 'wordpress_db');
    define('DB_USER', 'wp_user');
    define('DB_PASSWORD', 'secret_password');
    """

    mock_normal_response = Mock()
    mock_normal_response.status_code = 200
    mock_normal_response.text = "<html><body>Normal page</body></html>"

    def mock_get(url, **kwargs):
        if "wp-config.php" in url:
            return mock_config_response
        elif "p='" in url:  # SQL injection test
            return mock_error_response
        return mock_normal_response

    mock_session_instance = Mock()
    mock_session_instance.get.side_effect = mock_get
    mock_session.return_value = mock_session_instance

    # Test database info leakage
    self.scanner._test_database_info_leakage("https://example.com", result)

    # Should have critical finding for wp-config.php exposure
    critical_findings = [
        f for f in result.findings if f.get("severity") == ScanSeverity.CRITICAL
    ]
    self.assertGreater(len(critical_findings), 0)

    log_success("✅ Database security checks test passed")


@patch("src.scanners.cms.wordpress_scanner.requests.Session")
def test_theme_security_analysis(self, mock_session):
    """Test enhanced theme enumeration and security analysis"""
    log_info("Testing theme security analysis")

    # Mock WordPress page with theme references
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = """
    <html>
    <head>
        <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
    </head>
    </html>
    """

    # Mock theme style.css with version
    mock_style_response = Mock()
    mock_style_response.status_code = 200
    mock_style_response.text = """
    /*
    Theme Name: Twenty Twenty-Four
    Version: 1.0
    */
    """

    def mock_get(url, **kwargs):
        if "style.css" in url:
            return mock_style_response
        return mock_response

    mock_session_instance = Mock()
    mock_session_instance.get.side_effect = mock_get
    mock_session.return_value = mock_session_instance

    # Test active theme detection
    active_theme = self.scanner._detect_active_theme("https://example.com")

    self.assertIsNotNone(active_theme)
    self.assertEqual(active_theme["name"], "twentytwentyfour")

    # Test theme security analysis
    theme_security = self.scanner._analyze_theme_security(
        "https://example.com", active_theme
    )

    # twentytwentyfour is a default theme, should be secure
    self.assertFalse(theme_security["custom_theme"])
    self.assertGreater(theme_security["security_score"], 50)

    log_success("✅ Theme security analysis test passed")


def test_enhanced_scan_workflow(self):
    """Test complete enhanced WordPress scan workflow"""
    log_info("Testing enhanced scan workflow")

    # Mock WordPress detection
    with patch.object(self.scanner, "_detect_wordpress") as mock_wp_detect:
        mock_wp_detect.return_value = True

        # Mock all enhanced scanner methods
        with patch.object(self.scanner, "_detect_wp_version"), patch.object(
            self.scanner, "_enumerate_plugins_enhanced"
        ), patch.object(self.scanner, "_enumerate_themes_enhanced"), patch.object(
            self.scanner, "_enumerate_users"
        ), patch.object(
            self.scanner, "_check_multisite_security"
        ), patch.object(
            self.scanner, "_analyze_htaccess_security"
        ), patch.object(
            self.scanner, "_detect_security_plugins"
        ), patch.object(
            self.scanner, "_check_database_security"
        ), patch.object(
            self.scanner, "_test_brute_force_protection"
        ), patch.object(
            self.scanner, "_run_wpscan"
        ), patch.object(
            self.scanner, "_analyze_security_config"
        ), patch.object(
            self.scanner, "_test_xmlrpc"
        ):

            # Run complete scan with enhanced options
            options = {
                "enumerate_plugins": True,
                "enumerate_themes": True,
                "enumerate_users": True,
                "check_multisite": True,
                "check_htaccess": True,
                "detect_security_plugins": True,
                "check_database_security": True,
                "test_brute_force": True,
                "use_wpscan": True,
            }

            result = self.scanner.scan("https://example.com", options)

            # Verify scan completed successfully
            self.assertEqual(result.status, ScanStatus.COMPLETED)
            self.assertIsNotNone(result.end_time)

    log_success("✅ Enhanced scan workflow test passed")


def test_security_recommendations(self):
    """Test security recommendation generation"""
    log_info("Testing security recommendations")

    # Test plugin recommendations
    vulnerable_status = {"vulnerable": True, "outdated": True, "abandoned": False}

    recommendations = self.scanner._get_plugin_recommendations(vulnerable_status)
    self.assertIn("Update or remove vulnerable plugin", recommendations)
    self.assertIn("Update plugin to latest version", recommendations)

    # Test theme recommendations
    vulnerable_theme_analysis = {
        "vulnerable": True,
        "outdated": False,
        "custom_theme": True,
    }

    theme_recommendations = self.scanner._get_theme_recommendations(
        vulnerable_theme_analysis
    )
    self.assertIn("Update vulnerable theme", theme_recommendations)
    self.assertIn("custom theme follows WordPress security", theme_recommendations)

    log_success("✅ Security recommendations test passed")


def test_enhanced_wordpress_features():
    """Test enhanced WordPress scanner features"""
    log_banner("Testing Enhanced WordPress Features", "bold green")

    scanner = WordPressScanner()

    # Test scanner has enhanced capabilities
    capabilities = scanner.get_capabilities()

    # Check for enhanced features
    enhanced_features = [
        "Multisite security testing",
        "Enhanced plugin enumeration",
        "Security plugin detection",
        "Database security analysis",
        ".htaccess security testing",
    ]

    log_info("Checking enhanced features:")
    for feature in enhanced_features:
        # Check if feature description exists in capabilities
        feature_exists = any(
            feature.lower() in str(capabilities).lower()
            for feature in enhanced_features
        )
        status = "✅" if feature_exists else "⚠️"
        log_info(f"  {status} Enhanced features available")

    # Test security plugins configuration
    security_plugins = scanner.security_plugins
    log_info(f"Security plugins supported: {len(security_plugins)}")

    expected_plugins = ["wordfence", "sucuri", "ithemes", "jetpack"]
    for plugin in expected_plugins:
        if plugin in security_plugins:
            log_info(f"  ✅ {security_plugins[plugin]['name']}")
        else:
            log_info(f"  ❌ {plugin} not configured")

    log_success("Enhanced WordPress features test completed")


if __name__ == "__main__":
    # Setup logging
    LoggerSetup.setup_console_logging()

    # Run basic test
    test_wordpress_scanner_basic()

    # NEW: Run enhanced features test
    test_enhanced_wordpress_features()

    # Run unit tests
    log_banner("Running WordPress Scanner Unit Tests", "bold red")
    unittest.main(verbosity=2)
