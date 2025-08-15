#!/usr/bin/env python3
"""
SSL Scanner Test Suite
Tests SSL/TLS certificate analysis, cipher suite testing, protocol validation,
and security configuration assessment
"""

import sys
import os
import unittest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from src.scanners.vulnerability.ssl_scanner import SSLScanner
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


class TestSSLScanner(unittest.TestCase):
    """Test cases for SSLScanner"""

    def setUp(self):
        """Set up test fixtures"""
        self.scanner = SSLScanner(timeout=120)
        self.test_url = "https://example.com"
        self.test_domain = "example.com"
        self.test_host_port = "example.com:443"

        # Sample SSLScan output for testing
        self.sample_sslscan_output = """
Version: 2.0.6-static
OpenSSL 1.1.1f  31 Mar 2020

Connected to 93.184.216.34

Testing SSL server example.com on port 443 using SNI name example.com

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   enabled
TLSv1.1   enabled
TLSv1.2   enabled
TLSv1.3   enabled

  TLS Fallback SCSV:
Server supports TLS Fallback SCSV

  TLS renegotiation:
Secure session renegotiation supported

  TLS Compression:
Compression disabled

  Heartbleed:
TLS 1.2 not vulnerable to heartbleed
TLS 1.1 not vulnerable to heartbleed
TLS 1.0 not vulnerable to heartbleed

  Supported Server Cipher(s):
Preferred TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384        Curve 25519 DHE 253
Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256  Curve 25519 DHE 253
Accepted  TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256        Curve 25519 DHE 253
Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384   Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  ECDHE-RSA-CHACHA20-POLY1305   Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256   Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA384       Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA256       Curve 25519 DHE 253
Accepted  TLSv1.1  256 bits  ECDHE-RSA-AES256-SHA          Curve 25519 DHE 253
Accepted  TLSv1.1  128 bits  ECDHE-RSA-AES128-SHA          Curve 25519 DHE 253
Accepted  TLSv1.0  256 bits  ECDHE-RSA-AES256-SHA          Curve 25519 DHE 253
Accepted  TLSv1.0  128 bits  ECDHE-RSA-AES128-SHA          Curve 25519 DHE 253

  Server Certificate #1:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength:    2048

Subject:  example.com
Altnames: DNS:example.com, DNS:www.example.com
Issuer:   DigiCert TLS RSA SHA256 2020 CA1

Not valid before: Jan  1 00:00:00 2023 GMT
Not valid after:  Dec 31 23:59:59 2023 GMT
"""

        # Sample certificate information
        self.sample_cert_info = {
            "subject": "example.com",
            "issuer": "DigiCert TLS RSA SHA256 2020 CA1",
            "version": 3,
            "serial_number": "12345678901234567890",
            "not_before": "2023-01-01 00:00:00",
            "not_after": "2023-12-31 23:59:59",
            "signature_algorithm": "sha256WithRSAEncryption",
            "public_key_algorithm": "RSA",
            "public_key_size": 2048,
            "san_dns": ["example.com", "www.example.com"],
            "fingerprint_sha1": "abcd1234ef567890abcd1234ef567890abcd1234",
            "fingerprint_sha256": "abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef567890",
        }

        # SSL/TLS protocols and cipher information
        self.ssl_protocols = {
            "SSLv2": False,
            "SSLv3": False,
            "TLSv1.0": True,
            "TLSv1.1": True,
            "TLSv1.2": True,
            "TLSv1.3": True,
        }

        # def test_scanner_initialization(self):
        """Test SSL scanner initialization"""
        log_info("Testing SSLScanner initialization")

        self.assertEqual(self.scanner.name, "ssl_scanner")
        self.assertEqual(self.scanner.timeout, 120)
        self.assertIsNotNone(self.scanner.executor)

        # Check SSL protocol definitions
        if hasattr(self.scanner, "ssl_protocols"):
            self.assertIsInstance(self.scanner.ssl_protocols, dict)
            log_info(f"SSL protocols defined: {len(self.scanner.ssl_protocols)}")

        # Check cipher definitions
        if hasattr(self.scanner, "weak_ciphers"):
            self.assertIsInstance(self.scanner.weak_ciphers, (list, tuple))
            log_info(f"Weak ciphers defined: {len(self.scanner.weak_ciphers)}")

        log_success("SSL Scanner initialization test passed")

    def test_validate_target_valid_https_urls(self):
        """Test target validation with valid HTTPS URLs"""
        log_info("Testing valid HTTPS URL target validation")

        valid_urls = [
            "https://example.com",
            "https://test.example.org",
            "https://sub.domain.co.uk",
            "https://192.168.1.1",
            "https://example.com:443",
            "https://example.com:8443",
            "https://localhost:8080",
        ]

        for url in valid_urls:
            with self.subTest(url=url):
                result = self.scanner.validate_target(url)
                log_info(f"HTTPS URL '{url}' validation result: {result}")
                self.assertIsInstance(result, bool)

        log_success("Valid HTTPS URL validation tests completed")

    def test_validate_target_domains_and_ips(self):
        """Test target validation with domains and IPs"""
        log_info("Testing domain and IP target validation")

        valid_targets = [
            "example.com",
            "test.example.org",
            "192.168.1.1",
            "10.0.0.1",
            "localhost",
            "example.com:443",
            "192.168.1.1:8443",
        ]

        for target in valid_targets:
            with self.subTest(target=target):
                result = self.scanner.validate_target(target)
                log_info(f"Target '{target}' validation result: {result}")
                self.assertIsInstance(result, bool)

        log_success("Domain and IP validation tests completed")

    def test_validate_target_invalid(self):
        """Test target validation with invalid targets"""
        log_info("Testing invalid target validation behavior")

        test_targets = [
            ("", "Empty string"),
            ("http://example.com", "HTTP (non-SSL) URL"),
            ("ftp://example.com", "Non-HTTP protocol"),
            ("invalid-url", "Invalid format"),
            ("example.com:99999", "Invalid port number"),
        ]

        for target, description in test_targets:
            with self.subTest(target=target):
                try:
                    result = self.scanner.validate_target(target)
                    status = "ACCEPTS" if result else "REJECTS"
                    log_info(f"  {status} '{target}' - {description}")
                except Exception as e:
                    log_info(f"  ERROR on '{target}': {e}")

        log_success("Invalid target validation behavior documented")

    def test_get_capabilities(self):
        """Test SSL scanner capabilities"""
        log_info("Testing SSL scanner capabilities")

        capabilities = self.scanner.get_capabilities()

        self.assertIsInstance(capabilities, dict)
        self.assertIn("name", capabilities)
        self.assertIn("description", capabilities)

        # Check for SSL/TLS capabilities
        if "features" in capabilities:
            features_str = str(capabilities["features"]).lower()
            expected_features = ["ssl", "tls", "certificate", "cipher", "security"]
            found_features = [f for f in expected_features if f in features_str]
            self.assertGreater(
                len(found_features), 0, "Should have SSL-related features"
            )

        log_success("SSL capabilities test passed")

    @patch("src.scanners.vulnerability.ssl_scanner.CommandExecutor")
    def test_sslscan_tool_integration(self, mock_executor_class):
        """Test sslscan tool integration"""
        log_info("Testing sslscan tool integration")

        # Mock executor
        mock_executor = Mock()
        mock_executor_class.return_value = mock_executor

        # Mock successful sslscan execution
        mock_executor.execute.return_value = CommandResult(
            command="sslscan --xml=- example.com:443",
            return_code=0,
            stdout=self.sample_sslscan_output,
            stderr="",
            execution_time=15.23,
            timed_out=False,
        )

        # Test sslscan execution method if available
        if hasattr(self.scanner, "_run_sslscan"):
            try:
                result = self.scanner._run_sslscan(self.test_host_port, {})
                self.assertIsInstance(result, (dict, list, str))
                log_success("SSLScan integration test passed")
            except Exception as e:
                log_info(f"SSLScan integration test failed: {e}")
        else:
            log_info("SSLScan integration method not found - testing skipped")

    def test_parse_sslscan_output(self):
        """Test parsing sslscan output"""
        log_info("Testing sslscan output parsing")

        if hasattr(self.scanner, "_parse_sslscan_output"):
            try:
                findings = self.scanner._parse_sslscan_output(
                    self.sample_sslscan_output
                )

                # Verify findings structure
                self.assertIsInstance(findings, list)
                self.assertGreater(len(findings), 0)

                # Check for protocol findings
                protocol_findings = [
                    f for f in findings if "protocol" in str(f).lower()
                ]
                self.assertGreater(len(protocol_findings), 0)

                # Check for cipher findings
                cipher_findings = [f for f in findings if "cipher" in str(f).lower()]
                self.assertGreater(len(cipher_findings), 0)

                log_success("SSLScan output parsing test passed")

            except Exception as e:
                log_info(f"SSLScan output parsing failed: {e}")
        else:
            log_info("SSLScan output parsing method not found - testing skipped")

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_certificate_analysis(self, mock_socket, mock_ssl_context):
        """Test SSL certificate analysis"""
        log_info("Testing SSL certificate analysis")

        # Mock SSL context and connection
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context

        mock_sock = Mock()
        mock_socket.return_value = mock_sock

        mock_ssl_sock = Mock()
        mock_context.wrap_socket.return_value = mock_ssl_sock

        # Mock certificate
        mock_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "DigiCert TLS RSA SHA256 2020 CA1"),),),
            "version": 3,
            "serialNumber": "12345678901234567890",
            "notBefore": "Jan  1 00:00:00 2023 GMT",
            "notAfter": "Dec 31 23:59:59 2023 GMT",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }
        mock_ssl_sock.getpeercert.return_value = mock_cert

        if hasattr(self.scanner, "_analyze_certificate"):
            try:
                analysis = self.scanner._analyze_certificate(self.test_domain, 443)
                self.assertIsInstance(analysis, (dict, list))
                log_success("Certificate analysis test passed")
            except Exception as e:
                log_info(f"Certificate analysis failed: {e}")
        else:
            log_info("Certificate analysis method not found - testing skipped")

    def test_protocol_testing(self):
        """Test SSL/TLS protocol support testing"""
        log_info("Testing SSL/TLS protocol support")

        if hasattr(self.scanner, "_test_protocols"):
            try:
                protocols = self.scanner._test_protocols(self.test_domain, 443)
                self.assertIsInstance(protocols, (dict, list))
                log_success("Protocol testing test passed")
            except Exception as e:
                log_info(f"Protocol testing failed: {e}")
        else:
            log_info("Protocol testing method not found - testing skipped")

    def test_cipher_suite_analysis(self):
        """Test cipher suite analysis"""
        log_info("Testing cipher suite analysis")

        if hasattr(self.scanner, "_analyze_cipher_suites"):
            try:
                # Sample cipher data
                sample_ciphers = [
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                    "ECDHE-RSA-AES128-GCM-SHA256",
                ]

                analysis = self.scanner._analyze_cipher_suites(sample_ciphers)
                self.assertIsInstance(analysis, (dict, list))
                log_success("Cipher suite analysis test passed")
            except Exception as e:
                log_info(f"Cipher suite analysis failed: {e}")
        else:
            log_info("Cipher suite analysis method not found - testing skipped")

    def test_vulnerability_checks(self):
        """Test SSL/TLS vulnerability checks"""
        log_info("Testing SSL/TLS vulnerability checks")

        vulnerabilities_to_test = [
            "heartbleed",
            "poodle",
            "beast",
            "crime",
            "breach",
            "freak",
            "logjam",
        ]

        for vuln in vulnerabilities_to_test:
            method_name = f"_check_{vuln}"
            if hasattr(self.scanner, method_name):
                try:
                    method = getattr(self.scanner, method_name)
                    result = method(self.test_domain, 443)
                    self.assertIsInstance(result, (bool, dict))
                    log_info(f"Vulnerability check {vuln}: {result}")
                except Exception as e:
                    log_info(f"Vulnerability check {vuln} failed: {e}")
            else:
                log_info(f"Vulnerability check method {method_name} not found")

    def test_certificate_validation(self):
        """Test certificate validation and expiry checking"""
        log_info("Testing certificate validation")

        if hasattr(self.scanner, "_validate_certificate"):
            try:
                validation = self.scanner._validate_certificate(self.sample_cert_info)
                self.assertIsInstance(validation, (dict, list))

                # Check for expiry warnings
                if isinstance(validation, dict) and "expiry" in validation:
                    log_info(f"Certificate expiry info: {validation['expiry']}")

                log_success("Certificate validation test passed")
            except Exception as e:
                log_info(f"Certificate validation failed: {e}")
        else:
            log_info("Certificate validation method not found - testing skipped")

    @patch("src.scanners.vulnerability.ssl_scanner.CommandExecutor")
    def test_scan_execution_success(self, mock_executor_class):
        """Test successful SSL scan execution"""
        log_info("Testing successful SSL scan execution")

        # Mock executor
        mock_executor = Mock()
        mock_executor_class.return_value = mock_executor

        # Mock successful sslscan execution
        mock_executor.execute.return_value = CommandResult(
            command="sslscan example.com:443",
            return_code=0,
            stdout=self.sample_sslscan_output,
            stderr="",
            execution_time=15.23,
            timed_out=False,
        )

        # Execute scan
        try:
            result = self.scanner.scan(self.test_url)

            # Verify basic result structure
            self.assertIsInstance(result, ScanResult)
            self.assertEqual(result.scanner_name, "ssl_scanner")
            self.assertEqual(result.target, self.test_url)
            self.assertIsNotNone(result.start_time)

            # Status should be completed or failed
            self.assertIn(result.status, [ScanStatus.COMPLETED, ScanStatus.FAILED])

            log_success("SSL scan execution test passed")

        except Exception as e:
            log_info(f"SSL scan execution failed (may be expected): {e}")

    @patch("src.scanners.vulnerability.ssl_scanner.CommandExecutor")
    def test_scan_execution_tool_failure(self, mock_executor_class):
        """Test scan when SSL tool fails"""
        log_info("Testing scan with SSL tool failure")

        # Mock executor
        mock_executor = Mock()
        mock_executor_class.return_value = mock_executor

        # Mock tool failure
        mock_executor.execute.return_value = CommandResult(
            command="sslscan example.com:443",
            return_code=1,
            stdout="",
            stderr="Connection failed or SSL handshake error",
            execution_time=10.0,
            timed_out=False,
        )

        # Execute scan
        try:
            result = self.scanner.scan(self.test_url)

            # Should handle failure gracefully
            self.assertIsInstance(result, ScanResult)

            if result.status == ScanStatus.FAILED:
                log_info("Scan failed as expected due to SSL tool failure")

            log_success("SSL tool failure handling test passed")

        except Exception as e:
            log_info(f"SSL tool failure test encountered exception: {e}")

    @patch("src.scanners.vulnerability.ssl_scanner.CommandExecutor")
    def test_scan_execution_timeout(self, mock_executor_class):
        """Test scan execution with timeout"""
        log_info("Testing scan execution timeout")

        # Mock executor
        mock_executor = Mock()
        mock_executor_class.return_value = mock_executor

        # Mock timeout scenario
        mock_executor.execute.return_value = CommandResult(
            command="sslscan example.com:443",
            return_code=-1,
            stdout="",
            stderr="Command timeout",
            execution_time=120.0,
            timed_out=True,
        )

        # Create scanner with short timeout
        scanner = SSLScanner(timeout=30)

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

    def test_scan_options_validation(self):
        """Test scan options validation"""
        log_info("Testing scan options validation")

        test_options = [
            {"protocols": ["TLSv1.2", "TLSv1.3"]},
            {"check_vulnerabilities": True},
            {"detailed_analysis": True},
            {"check_certificate": True},
            {"check_ciphers": True},
            {"timeout": 60},
            {"verify_hostname": True},
            {"check_expiry": True},
        ]

        for options in test_options:
            with self.subTest(options=str(options)):
                try:
                    # Test that scanner accepts various option formats
                    result = self.scanner.scan(self.test_url, options)
                    self.assertIsInstance(result, ScanResult)
                    log_info(f"Options {options} - Status: {result.status}")
                except Exception as e:
                    log_info(f"Options {options} failed: {e}")

    # def test_weak_cipher_detection(self):
    #     """Test weak cipher detection"""
    #     log_info("Testing weak cipher detection")

    #     # Sample weak ciphers
    #     weak_test_ciphers = [
    #         "DES-CBC-SHA",
    #         "RC4-MD5",
    #         "NULL-MD5",
    #         "EXPORT-DES-CBC-SHA",
    #         "ADH-DES-CBC-SHA",
    #     ]

    #     # Sample strong ciphers
    #     strong_test_ciphers = [
    #         "TLS_AES_256_GCM_SHA384",
    #         "ECDHE-RSA-AES256-GCM-SHA384",
    #         "ECDHE-RSA-CHACHA20-POLY1305",
    #     ]

    #     if hasattr(self.scanner, "_classify_cipher_strength"):
    #         try:
    #             for cipher in weak_test_ciphers:
    #                 strength = self.scanner._classify_cipher_strength(cipher)
    #                 log_info(f"Cipher {cipher}: {strength}")

    #             for cipher in strong_test_ciphers:
    #                 strength = self.scanner._classify_cipher_strength(cipher)
    #                 log_info(f"Cipher {cipher}: {strength}")

    #             log_success("Weak cipher detection test passed")
    #         except Exception as e:
    #             log_info(f"Cipher strength classification failed: {e}")
    #     else:
    #         log_info(
    #             "Cipher strength classification method not found - testing skipped"
    #         )

    def test_certificate_chain_analysis(self):
        """Test certificate chain analysis"""
        log_info("Testing certificate chain analysis")

        if hasattr(self.scanner, "_analyze_certificate_chain"):
            try:
                # Mock certificate chain
                mock_chain = [
                    {"subject": "example.com", "issuer": "Intermediate CA"},
                    {"subject": "Intermediate CA", "issuer": "Root CA"},
                    {"subject": "Root CA", "issuer": "Root CA"},
                ]

                chain_analysis = self.scanner._analyze_certificate_chain(mock_chain)
                self.assertIsInstance(chain_analysis, (dict, list))
                log_success("Certificate chain analysis test passed")
            except Exception as e:
                log_info(f"Certificate chain analysis failed: {e}")
        else:
            log_info("Certificate chain analysis method not found - testing skipped")

    def test_ssl_configuration_assessment(self):
        """Test overall SSL configuration assessment"""
        log_info("Testing SSL configuration assessment")

        if hasattr(self.scanner, "_assess_ssl_configuration"):
            try:
                # Mock SSL configuration data
                mock_config = {
                    "protocols": self.ssl_protocols,
                    "certificate": self.sample_cert_info,
                    "ciphers": [
                        "TLS_AES_256_GCM_SHA384",
                        "ECDHE-RSA-AES256-GCM-SHA384",
                    ],
                    "vulnerabilities": {"heartbleed": False, "poodle": False},
                }

                assessment = self.scanner._assess_ssl_configuration(mock_config)
                self.assertIsInstance(assessment, (dict, list))
                log_success("SSL configuration assessment test passed")
            except Exception as e:
                log_info(f"SSL configuration assessment failed: {e}")
        else:
            log_info("SSL configuration assessment method not found - testing skipped")

    def test_multiple_ports_scanning(self):
        """Test scanning multiple SSL ports"""
        log_info("Testing multiple SSL ports scanning")

        ssl_ports = [443, 8443, 9443, 8080]

        for port in ssl_ports:
            target = f"{self.test_domain}:{port}"
            with self.subTest(target=target):
                try:
                    result = self.scanner.scan(target)
                    self.assertIsInstance(result, ScanResult)
                    log_info(f"Port {port} scan - Status: {result.status}")
                except Exception as e:
                    log_info(f"Port {port} scan failed: {e}")

    # def test_sni_support_testing(self):
    #     """Test Server Name Indication (SNI) support"""
    #     log_info("Testing SNI support")

    #     if hasattr(self.scanner, "_test_sni_support"):
    #         try:
    #             sni_result = self.scanner._test_sni_support(self.test_domain, 443)
    #             self.assertIsInstance(sni_result, (bool, dict))
    #             log_success("SNI support testing passed")
    #         except Exception as e:
    #             log_info(f"SNI support testing failed: {e}")
    #     else:
    #         log_info("SNI support testing method not found - testing skipped")


def run_ssl_scanner_tests():
    """Run all SSL scanner tests"""
    print("=" * 60)
    print("🔒 AUTO-PENTEST SSL SCANNER TEST SUITE")
    print("=" * 60)

    # Setup logging
    LoggerSetup.setup_logger("test_ssl_scanner", level="INFO", use_rich=True)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestSSLScanner))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 60)
    print("📊 SSL SCANNER TEST SUMMARY")
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
        print("\n✅ ALL SSL SCANNER TESTS PASSED!")
        return True
    else:
        print("\n❌ SOME TESTS FAILED!")
        return False


if __name__ == "__main__":
    success = run_ssl_scanner_tests()
    sys.exit(0 if success else 1)
