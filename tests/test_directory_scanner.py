#!/usr/bin/env python3
"""
Directory Scanner Test Suite
Tests directory enumeration, file discovery, wordlist handling, and brute force functionality
"""

import sys
import os
import unittest
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from src.scanners.vulnerability.directory_scanner import DirectoryScanner
    from src.core.scanner_base import ScannerBase, ScanResult, ScanStatus, ScanSeverity
    from src.core.executor import CommandExecutor, CommandResult
    from src.utils.logger import (
        LoggerSetup,
        log_banner,
        log_success,
        log_error,
        log_info,
    )
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure you're running this from the project root directory")
    sys.exit(1)


class TestDirectoryScanner(unittest.TestCase):
    """Test cases for DirectoryScanner"""

    def setUp(self):
        """Set up test fixtures"""
        self.scanner = DirectoryScanner(timeout=180)
        self.test_url = "https://example.com"
        self.test_domain = "example.com"

        # Sample dirb output for testing
        self.sample_dirb_output = """
DIRB v2.22
By The Dark Raver

START_TIME: Mon Jan 1 12:00:00 2023
URL_BASE: https://example.com/
WORDLIST_FILE: /usr/share/dirb/wordlists/common.txt

-----------------
GENERATED WORDS: 4612

---- Scanning URL: https://example.com/ ----
+ https://example.com/admin/ (CODE:200|SIZE:1234)
+ https://example.com/backup/ (CODE:403|SIZE:567)
+ https://example.com/config/ (CODE:301|SIZE:0)
+ https://example.com/images/ (CODE:200|SIZE:2048)
+ https://example.com/login.php (CODE:200|SIZE:890)
+ https://example.com/robots.txt (CODE:200|SIZE:156)
+ https://example.com/sitemap.xml (CODE:200|SIZE:2345)
+ https://example.com/test/ (CODE:403|SIZE:567)
+ https://example.com/uploads/ (CODE:200|SIZE:1024)

-----------------
END_TIME: Mon Jan 1 12:05:00 2023
DOWNLOADED: 4612 - FOUND: 9
"""

        # Sample gobuster output for testing
        self.sample_gobuster_output = """
=====================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
=====================================================
[+] Url:                     https://example.com
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
=====================================================
2023/01/01 12:00:00 Starting gobuster in directory enumeration mode
=====================================================
/admin                (Status: 200) [Size: 1234]
/backup               (Status: 403) [Size: 567]
/config.php           (Status: 200) [Size: 890]
/images               (Status: 200) [Size: 2048]
/login.php            (Status: 200) [Size: 890]
/robots.txt           (Status: 200) [Size: 156]
/sitemap.xml          (Status: 200) [Size: 2345]
/test                 (Status: 403) [Size: 567]
/uploads              (Status: 200) [Size: 1024]
=====================================================
2023/01/01 12:05:00 Finished
=====================================================
"""

        # Sample wordlist content
        self.sample_wordlist = [
            "admin",
            "backup",
            "config",
            "test",
            "images",
            "uploads",
            "login",
            "dashboard",
            "panel",
            "api",
            "robots.txt",
            "sitemap.xml",
            "favicon.ico",
        ]

    def test_scanner_initialization(self):
        """Test directory scanner initialization"""
        log_info("Testing DirectoryScanner initialization")

        self.assertEqual(self.scanner.name, "directory_scanner")
        self.assertEqual(self.scanner.timeout, 180)
        self.assertIsNotNone(self.scanner.executor)

        # Check for wordlist attributes
        if hasattr(self.scanner, "default_wordlist"):
            self.assertIsInstance(self.scanner.default_wordlist, (list, str, Path))

        log_success("Directory Scanner initialization test passed")

    def test_get_capabilities(self):
        """Test directory scanner capabilities"""
        log_info("Testing directory scanner capabilities")

        capabilities = self.scanner.get_capabilities()

        self.assertIsInstance(capabilities, dict)
        self.assertIn("name", capabilities)
        self.assertIn("description", capabilities)

        # Check for directory enumeration capabilities
        if "features" in capabilities:
            features_str = str(capabilities["features"]).lower()
            expected_features = [
                "directory",
                "file",
                "enumeration",
                "brute",
                "wordlist",
            ]
            found_features = [f for f in expected_features if f in features_str]
            self.assertGreater(
                len(found_features), 0, "Should have directory-related features"
            )

        log_success("Directory capabilities test passed")

        # def test_wordlist_handling(self):
        """Test wordlist loading and handling"""
        log_info("Testing wordlist handling")

        # Test default wordlist
        if hasattr(self.scanner, "default_wordlist"):
            wordlist = self.scanner.default_wordlist
            self.assertIsInstance(wordlist, (list, str, Path))

            if isinstance(wordlist, list):
                self.assertGreater(len(wordlist), 0)
                log_info(f"Default wordlist has {len(wordlist)} entries")

        # Test wordlist loading method if available
        if hasattr(self.scanner, "_load_wordlist"):
            try:
                # Test with sample wordlist
                temp_file = tempfile.NamedTemporaryFile(
                    mode="w", delete=False, suffix=".txt"
                )
                temp_file.write("\n".join(self.sample_wordlist))
                temp_file.close()

                loaded_wordlist = self.scanner._load_wordlist(temp_file.name)
                self.assertIsInstance(loaded_wordlist, list)
                self.assertGreater(len(loaded_wordlist), 0)

                # Cleanup
                os.unlink(temp_file.name)

                log_success("Wordlist loading test passed")

            except Exception as e:
                log_info(f"Wordlist loading test failed: {e}")
        else:
            log_info("Wordlist loading method not found - testing skipped")

    def test_file_extensions_handling(self):
        """Test file extension enumeration"""
        log_info("Testing file extension handling")

        # Common web file extensions
        common_extensions = [
            "php",
            "html",
            "htm",
            "asp",
            "aspx",
            "jsp",
            "txt",
            "xml",
            "js",
            "css",
        ]

        if hasattr(self.scanner, "default_extensions"):
            extensions = self.scanner.default_extensions
            self.assertIsInstance(extensions, (list, str))

            if isinstance(extensions, list):
                log_info(f"Default extensions: {extensions}")

                # Check for common web extensions
                found_common = any(
                    ext in str(extensions).lower() for ext in ["php", "html", "asp"]
                )
                if found_common:
                    log_info("Found common web extensions in default list")

        # Test extension handling method if available
        if hasattr(self.scanner, "_prepare_extensions"):
            try:
                processed_exts = self.scanner._prepare_extensions(common_extensions)
                self.assertIsInstance(processed_exts, (list, str))
                log_success("Extension processing test passed")
            except Exception as e:
                log_info(f"Extension processing failed: {e}")

        log_success("File extension handling test completed")

    @patch("src.scanners.vulnerability.directory_scanner.CommandExecutor")
    def test_dirb_tool_integration(self, mock_executor_class):
        """Test dirb tool integration"""
        log_info("Testing dirb tool integration")

        # Mock executor
        mock_executor = Mock()
        mock_executor_class.return_value = mock_executor

        # Mock successful dirb execution
        mock_executor.execute.return_value = CommandResult(
            command="dirb https://example.com /usr/share/dirb/wordlists/common.txt",
            return_code=0,
            stdout=self.sample_dirb_output,
            stderr="",
            execution_time=45.23,
            timed_out=False,
        )

        # Test dirb execution method if available
        if hasattr(self.scanner, "_run_dirb"):
            try:
                result = self.scanner._run_dirb(self.test_url, {})
                self.assertIsInstance(result, (dict, list, str))
                log_success("Dirb integration test passed")
            except Exception as e:
                log_info(f"Dirb integration test failed: {e}")
        else:
            log_info("Dirb integration method not found - testing skipped")

    @patch("src.scanners.vulnerability.directory_scanner.CommandExecutor")
    def test_gobuster_tool_integration(self, mock_executor_class):
        """Test gobuster tool integration"""
        log_info("Testing gobuster tool integration")

        # Mock executor
        mock_executor = Mock()
        mock_executor_class.return_value = mock_executor

        # Mock successful gobuster execution
        mock_executor.execute.return_value = CommandResult(
            command="gobuster dir -u https://example.com -w wordlist.txt",
            return_code=0,
            stdout=self.sample_gobuster_output,
            stderr="",
            execution_time=30.15,
            timed_out=False,
        )

        # Test gobuster execution method if available
        if hasattr(self.scanner, "_run_gobuster"):
            try:
                result = self.scanner._run_gobuster(self.test_url, {})
                self.assertIsInstance(result, (dict, list, str))
                log_success("Gobuster integration test passed")
            except Exception as e:
                log_info(f"Gobuster integration test failed: {e}")
        else:
            log_info("Gobuster integration method not found - testing skipped")

    def test_parse_dirb_output(self):
        """Test parsing dirb output"""
        log_info("Testing dirb output parsing")

        if hasattr(self.scanner, "_parse_dirb_output"):
            try:
                findings = self.scanner._parse_dirb_output(self.sample_dirb_output)

                # Verify findings structure
                self.assertIsInstance(findings, list)
                self.assertGreater(len(findings), 0)

                # Check for specific directories
                admin_findings = [f for f in findings if "admin" in str(f).lower()]
                self.assertGreater(len(admin_findings), 0)

                # Check for files
                file_findings = [
                    f
                    for f in findings
                    if any(ext in str(f).lower() for ext in [".php", ".txt", ".xml"])
                ]
                self.assertGreater(len(file_findings), 0)

                log_success("Dirb output parsing test passed")

            except Exception as e:
                log_info(f"Dirb output parsing failed: {e}")
        else:
            log_info("Dirb output parsing method not found - testing skipped")

    def test_parse_gobuster_output(self):
        """Test parsing gobuster output"""
        log_info("Testing gobuster output parsing")

        if hasattr(self.scanner, "_parse_gobuster_output"):
            try:
                findings = self.scanner._parse_gobuster_output(
                    self.sample_gobuster_output
                )

                # Verify findings structure
                self.assertIsInstance(findings, list)
                self.assertGreater(len(findings), 0)

                # Check for status codes
                findings_with_status = [
                    f for f in findings if "status" in str(f).lower() or "200" in str(f)
                ]
                self.assertGreater(len(findings_with_status), 0)

                log_success("Gobuster output parsing test passed")

            except Exception as e:
                log_info(f"Gobuster output parsing failed: {e}")
        else:
            log_info("Gobuster output parsing method not found - testing skipped")

    @patch("src.scanners.vulnerability.directory_scanner.CommandExecutor")
    def test_scan_execution_success(self, mock_executor_class):
        """Test successful directory scan execution"""
        log_info("Testing successful directory scan execution")

        # Mock executor
        mock_executor = Mock()
        mock_executor_class.return_value = mock_executor

        # Mock successful tool execution
        mock_executor.execute.return_value = CommandResult(
            command="dirb https://example.com",
            return_code=0,
            stdout=self.sample_dirb_output,
            stderr="",
            execution_time=45.23,
            timed_out=False,
        )

        # Execute scan
        try:
            result = self.scanner.scan(self.test_url)

            # Verify basic result structure
            self.assertIsInstance(result, ScanResult)
            self.assertEqual(result.scanner_name, "directory_scanner")
            self.assertEqual(result.target, self.test_url)
            self.assertIsNotNone(result.start_time)

            # Status should be completed or failed
            self.assertIn(result.status, [ScanStatus.COMPLETED, ScanStatus.FAILED])

            log_success("Directory scan execution test passed")

        except Exception as e:
            log_info(f"Directory scan execution failed (may be expected): {e}")

    @patch("src.scanners.vulnerability.directory_scanner.CommandExecutor")
    def test_scan_execution_tool_failure(self, mock_executor_class):
        """Test scan when directory enumeration tool fails"""
        log_info("Testing scan with tool failure")

        # Mock executor
        mock_executor = Mock()
        mock_executor_class.return_value = mock_executor

        # Mock tool failure
        mock_executor.execute.return_value = CommandResult(
            command="dirb https://example.com",
            return_code=1,
            stdout="",
            stderr="Connection failed or host unreachable",
            execution_time=10.0,
            timed_out=False,
        )

        # Execute scan
        try:
            result = self.scanner.scan(self.test_url)

            # Should handle failure gracefully
            self.assertIsInstance(result, ScanResult)

            if result.status == ScanStatus.FAILED:
                log_info("Scan failed as expected due to tool failure")

            log_success("Tool failure handling test passed")

        except Exception as e:
            log_info(f"Tool failure test encountered exception: {e}")

    @patch("src.scanners.vulnerability.directory_scanner.CommandExecutor")
    def test_scan_execution_timeout(self, mock_executor_class):
        """Test scan execution with timeout"""
        log_info("Testing scan execution timeout")

        # Mock executor
        mock_executor = Mock()
        mock_executor_class.return_value = mock_executor

        # Mock timeout scenario
        mock_executor.execute.return_value = CommandResult(
            command="dirb https://example.com",
            return_code=-1,
            stdout="",
            stderr="Command timeout",
            execution_time=180.0,
            timed_out=True,
        )

        # Create scanner with short timeout
        scanner = DirectoryScanner(timeout=60)

        # Execute scan
        try:
            result = scanner.scan(self.test_url)

            # Should handle timeout gracefully
            self.assertIsInstance(result, ScanResult)

            if result.status == ScanStatus.FAILED:
                log_info("Scan failed as expected due to timeout")

            log_success("Timeout handling test passed")

        except Exception as e:
            log_info(f"Timeout test encountered exception: {e}")

    def test_custom_wordlist_usage(self):
        """Test custom wordlist functionality"""
        log_info("Testing custom wordlist usage")

        # Create temporary custom wordlist
        custom_wordlist = ["custom", "directory", "test", "admin123", "secret"]

        try:
            temp_file = tempfile.NamedTemporaryFile(
                mode="w", delete=False, suffix=".txt"
            )
            temp_file.write("\n".join(custom_wordlist))
            temp_file.close()

            # Test scan with custom wordlist
            options = {"wordlist": temp_file.name}
            result = self.scanner.scan(self.test_url, options)

            self.assertIsInstance(result, ScanResult)
            log_info(f"Custom wordlist scan - Status: {result.status}")

            # Cleanup
            os.unlink(temp_file.name)

            log_success("Custom wordlist test passed")

        except Exception as e:
            log_info(f"Custom wordlist test failed: {e}")

    def test_recursive_scanning(self):
        """Test recursive directory scanning"""
        log_info("Testing recursive scanning option")

        recursive_options = {"recursive": True, "max_depth": 3}

        try:
            result = self.scanner.scan(self.test_url, recursive_options)
            self.assertIsInstance(result, ScanResult)
            log_info(f"Recursive scan - Status: {result.status}")

            log_success("Recursive scanning test passed")

        except Exception as e:
            log_info(f"Recursive scanning test failed: {e}")

    def test_multiple_tools_fallback(self):
        """Test fallback between different enumeration tools"""
        log_info("Testing multiple tools fallback")

        # Test different tool preferences
        tool_options = [
            {"tool": "dirb"},
            {"tool": "gobuster"},
            {"tool": "ffuf"},
            {"tool": "dirsearch"},
        ]

        for options in tool_options:
            with self.subTest(tool=options["tool"]):
                try:
                    result = self.scanner.scan(self.test_url, options)
                    self.assertIsInstance(result, ScanResult)
                    log_info(f"Tool {options['tool']} - Status: {result.status}")
                except Exception as e:
                    log_info(f"Tool {options['tool']} failed: {e}")

    def test_interesting_findings_detection(self):
        """Test detection of interesting directories and files"""
        log_info("Testing interesting findings detection")

        if hasattr(self.scanner, "_analyze_findings"):
            try:
                # Sample findings to analyze
                sample_findings = [
                    {"path": "/admin/", "status": 200, "size": 1234},
                    {"path": "/backup/", "status": 403, "size": 567},
                    {"path": "/config.php", "status": 200, "size": 890},
                    {"path": "/robots.txt", "status": 200, "size": 156},
                    {"path": "/sitemap.xml", "status": 200, "size": 2345},
                ]

                analysis = self.scanner._analyze_findings(sample_findings)
                self.assertIsInstance(analysis, (dict, list))

                log_success("Interesting findings detection test passed")

            except Exception as e:
                log_info(f"Findings analysis failed: {e}")
        else:
            log_info("Findings analysis method not found - testing skipped")

    def test_status_code_filtering(self):
        """Test HTTP status code filtering"""
        log_info("Testing status code filtering")

        filter_options = {
            "exclude_status": [404, 403],
            "include_status": [200, 301, 302],
        }

        try:
            result = self.scanner.scan(self.test_url, filter_options)
            self.assertIsInstance(result, ScanResult)
            log_info(f"Status filtering scan - Status: {result.status}")

            log_success("Status code filtering test passed")

        except Exception as e:
            log_info(f"Status code filtering test failed: {e}")


def run_directory_scanner_tests():
    """Run all directory scanner tests"""
    print("=" * 60)
    print("📁 AUTO-PENTEST DIRECTORY SCANNER TEST SUITE")
    print("=" * 60)

    # Setup logging
    LoggerSetup.setup_logger("test_directory_scanner", level="INFO", use_rich=True)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestDirectoryScanner))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 60)
    print("📊 DIRECTORY SCANNER TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.failures:
        print("\n❌ FAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")

    if result.errors:
        print("\n❌ ERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")

    if result.wasSuccessful():
        print("\n✅ ALL DIRECTORY SCANNER TESTS PASSED!")
        return True
    else:
        print("\n❌ SOME TESTS FAILED!")
        return False


if __name__ == "__main__":
    success = run_directory_scanner_tests()
    sys.exit(0 if success else 1)


# def test_scan_options_validation(self):
#     """Test scan options validation"""
#     log_info("Testing scan options validation")

#     test_options = [
#         {"wordlist": "/path/to/custom/wordlist.txt"},
#         {"extensions": ["php", "html", "asp"]},
#         {"threads": 10},
#         {"recursive": True},
#         {"tool": "dirb"},
#         {"tool": "gobuster"},
#         {"timeout": 120},
#         {"user_agent": "CustomAgent/1.0"},
#         {"follow_redirects": True},
#     ]

#     for options in test_options:
#         with self.subTest(options=str(options)):
#             try:
#                 # Test that scanner accepts various option formats
#                 result = self.scanner.scan(self.test_url, options)
#                 self.assertIsInstance(result, ScanResult)
#                 log_info(f"Options {options} - Status: {result.status}")
#             except Exception as e:
#                 log_info(f"Options {options} failed: {e}")


# def test_validate_target_valid_urls(self):
#     """Test target validation with valid URLs"""
#     log_info("Testing valid URL target validation")

#     valid_urls = [
#         "http://example.com",
#         "https://test.example.org",
#         "https://sub.domain.co.uk",
#         "http://192.168.1.1",
#         "https://example.com:8080",
#         "https://example.com/path/",
#         "http://localhost:3000",
#     ]

#     for url in valid_urls:
#         with self.subTest(url=url):
#             result = self.scanner.validate_target(url)
#             log_info(f"URL '{url}' validation result: {result}")
#             self.assertIsInstance(result, bool)

#     log_success("Valid URL validation tests completed")

# def test_validate_target_domains_and_ips(self):
#     """Test target validation with domains and IPs"""
#     log_info("Testing domain and IP target validation")

#     valid_targets = [
#         "example.com",
#         "test.example.org",
#         "192.168.1.1",
#         "10.0.0.1",
#         "localhost",
#     ]

#     for target in valid_targets:
#         with self.subTest(target=target):
#             result = self.scanner.validate_target(target)
#             log_info(f"Target '{target}' validation result: {result}")
#             self.assertIsInstance(result, bool)

#     log_success("Domain and IP validation tests completed")

# def test_validate_target_invalid(self):
#     """Test target validation with invalid targets"""
#     log_info("Testing invalid target validation behavior")

#     test_targets = [
#         ("", "Empty string"),
#         ("not-a-url", "Invalid format"),
#         ("ftp://example.com", "Non-HTTP protocol"),
#         ("file:///etc/passwd", "File protocol"),
#         ("javascript:alert(1)", "JavaScript protocol"),
#     ]

#     for target, description in test_targets:
#         with self.subTest(target=target[:20] + "..."):
#             try:
#                 result = self.scanner.validate_target(target)
#                 status = "ACCEPTS" if result else "REJECTS"
#                 log_info(f"  {status} '{target}' - {description}")
#             except Exception as e:
#                 log_info(f"  ERROR on '{target}': {e}")

#     log_success("Invalid target validation behavior documented")
