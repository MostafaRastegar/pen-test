"""
Advanced Subdomain Enumeration Service - Unit Tests
FILE PATH: tests/services/test_subdomain_service.py

Comprehensive test suite for SubdomainService
Following testing best practices and ensuring >90% coverage
"""

import unittest
import tempfile
import json
import time
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from datetime import datetime

# Test imports
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from src.services.subdomain_service import SubdomainService, SubdomainServiceInterface
from src.core.validator import validate_domain


class TestSubdomainServiceInterface(unittest.TestCase):
    """Test SubdomainService interface compliance"""

    def test_interface_implementation(self):
        """Test that SubdomainService implements required interface"""
        service = SubdomainService()

        # Test interface compliance
        self.assertIsInstance(service, SubdomainServiceInterface)

        # Test required methods exist
        self.assertTrue(hasattr(service, "enumerate_subdomains"))
        self.assertTrue(hasattr(service, "get_service_info"))

        # Test method signatures
        self.assertTrue(callable(getattr(service, "enumerate_subdomains")))
        self.assertTrue(callable(getattr(service, "get_service_info")))


class TestSubdomainServiceConfiguration(unittest.TestCase):
    """Test SubdomainService configuration and initialization"""

    def setUp(self):
        """Set up test environment"""
        self.service = SubdomainService()

    def test_service_initialization(self):
        """Test service initializes correctly"""
        # Test service attributes
        self.assertIsNotNone(self.service.validator)
        self.assertIsNotNone(self.service.executor)
        self.assertIsNotNone(self.service.report_service)
        self.assertIsNotNone(self.service.logger)

        # Test configuration
        self.assertIsInstance(self.service.config, dict)
        self.assertIn("timeout", self.service.config)
        self.assertIn("max_subdomains", self.service.config)
        self.assertIn("output_dir", self.service.config)

    def test_service_info(self):
        """Test service information method"""
        info = self.service.get_service_info()

        # Test required keys
        required_keys = [
            "name",
            "version",
            "description",
            "capabilities",
            "dependencies",
            "report_formats",
            "cli_integration",
        ]

        for key in required_keys:
            self.assertIn(key, info)

        # Test specific values
        self.assertEqual(info["name"], "SubdomainService")
        self.assertEqual(info["cli_integration"], True)
        self.assertIn("json", info["report_formats"])
        self.assertIn("subdomain_enumeration", info["capabilities"])

    def test_output_directory_creation(self):
        """Test output directory is created correctly"""
        output_dir = self.service.config["output_dir"]
        self.assertTrue(output_dir.exists())
        self.assertTrue(output_dir.is_dir())


class TestSubdomainServiceValidation(unittest.TestCase):
    """Test input validation functionality"""

    def setUp(self):
        """Set up test environment"""
        self.service = SubdomainService()

    def test_domain_validation_success(self):
        """Test successful domain validation"""
        valid_domains = [
            "example.com",
            "test.example.org",
            "sub.domain.co.uk",
            "single-word.com",
        ]

        for domain in valid_domains:
            with self.subTest(domain=domain):
                validated = self.service._validate_domain_input(domain)
                self.assertEqual(validated, domain.lower())

    def test_domain_validation_cleanup(self):
        """Test domain validation with cleanup"""
        test_cases = [
            ("HTTP://EXAMPLE.COM", "example.com"),
            ("https://test.example.org/path", "test.example.org"),
            ("Example.Com/", "example.com"),
            ("  test.com  ", "test.com"),
        ]

        for input_domain, expected in test_cases:
            with self.subTest(input=input_domain, expected=expected):
                validated = self.service._validate_domain_input(input_domain)
                self.assertEqual(validated, expected)

    def test_domain_validation_failure(self):
        """Test domain validation failure cases"""
        invalid_domains = [
            "",
            None,
            "invalid_domain",
            "256.1.1.1",  # Invalid IP as domain
            "too-long-" + "a" * 250 + ".com",
        ]

        for domain in invalid_domains:
            with self.subTest(domain=domain):
                if domain is None:
                    with self.assertRaises(ValueError):
                        self.service._validate_domain_input(domain)
                else:
                    with self.assertRaises(ValueError):
                        self.service._validate_domain_input(domain)


class TestSubdomainServiceOptions(unittest.TestCase):
    """Test options preparation and validation"""

    def setUp(self):
        """Set up test environment"""
        self.service = SubdomainService()

    def test_default_options_preparation(self):
        """Test default options preparation"""
        options = self.service._prepare_enumeration_options({})

        # Test default values
        self.assertIn("tools", options)
        self.assertIn("passive_only", options)
        self.assertIn("use_wordlist", options)
        self.assertIn("rate_limit", options)

        # Test default tool selection
        self.assertIsInstance(options["tools"], list)
        self.assertGreater(len(options["tools"]), 0)

    def test_custom_options_preparation(self):
        """Test custom options preparation"""
        custom_options = {
            "passive_only": True,
            "rate_limit": 2.0,
            "max_results": 5000,
            "json_report": True,
        }

        options = self.service._prepare_enumeration_options(custom_options)

        # Test custom values are preserved
        self.assertEqual(options["passive_only"], True)
        self.assertEqual(options["rate_limit"], 2.0)
        self.assertEqual(options["max_results"], 5000)
        self.assertEqual(options["json_report"], True)

    def test_tool_availability_filtering(self):
        """Test that only available tools are selected"""
        # Mock tool availability
        with patch.object(self.service.config, "__getitem__") as mock_config:
            mock_config.side_effect = lambda key: {
                "tools_available": {
                    "subfinder": True,
                    "amass": False,
                    "sublist3r": True,
                    "ct_logs": False,
                }
            }.get(key, self.service.config.get(key))

            options = self.service._prepare_enumeration_options({})
            available_tools = [
                tool
                for tool in options["tools"]
                if self.service.config["tools_available"].get(tool, False)
            ]

            self.assertIn("subfinder", available_tools)
            self.assertIn("sublist3r", available_tools)
            self.assertNotIn("amass", available_tools)
            self.assertNotIn("ct_logs", available_tools)


class TestSubdomainServiceEnumeration(unittest.TestCase):
    """Test subdomain enumeration functionality"""

    def setUp(self):
        """Set up test environment"""
        self.service = SubdomainService()
        self.test_domain = "example.com"

    @patch("src.services.subdomain_service.SubdomainService._run_enumeration_tool")
    def test_enumeration_execution_success(self, mock_run_tool):
        """Test successful enumeration execution"""
        # Mock tool results
        mock_run_tool.return_value = {
            "tool": "subfinder",
            "success": True,
            "subdomains": ["www.example.com", "api.example.com"],
            "execution_time": 10.5,
        }

        # Mock available tools
        self.service.config["tools_available"] = {"subfinder": True}

        options = {"tools": ["subfinder"]}
        result = self.service._execute_subdomain_enumeration(self.test_domain, options)

        # Test result structure
        self.assertIn("domain", result)
        self.assertIn("enumeration_methods", result)
        self.assertIn("raw_results", result)
        self.assertEqual(result["domain"], self.test_domain)

    @patch("src.services.subdomain_service.SubdomainService._run_enumeration_tool")
    def test_enumeration_tool_failure_handling(self, mock_run_tool):
        """Test tool failure handling"""
        # Mock tool failure
        mock_run_tool.side_effect = Exception("Tool execution failed")

        # Mock available tools
        self.service.config["tools_available"] = {"subfinder": True}

        options = {"tools": ["subfinder"]}
        result = self.service._execute_subdomain_enumeration(self.test_domain, options)

        # Test error handling
        self.assertIn("errors", result)
        self.assertGreater(len(result["errors"]), 0)
        self.assertIn("subfinder", result["enumeration_methods"])
        self.assertEqual(result["enumeration_methods"]["subfinder"]["status"], "failed")

    def test_result_processing(self):
        """Test result processing and deduplication"""
        # Mock enumeration result
        mock_result = {
            "domain": self.test_domain,
            "enumeration_methods": {
                "subfinder": {"status": "success"},
                "amass": {"status": "success"},
            },
            "raw_results": {
                "subfinder": {
                    "success": True,
                    "subdomains": [
                        "www.example.com",
                        "api.example.com",
                        "test.example.com",
                    ],
                },
                "amass": {
                    "success": True,
                    "subdomains": [
                        "www.example.com",
                        "mail.example.com",
                        "api.example.com",
                    ],
                },
            },
            "errors": [],
        }

        processed = self.service._process_enumeration_results(
            mock_result, self.test_domain
        )

        # Test deduplication
        self.assertIn("unique_subdomains", processed)
        unique_subdomains = processed["unique_subdomains"]

        # Should have 4 unique subdomains: www, api, test, mail
        expected_subdomains = sorted(
            [
                "www.example.com",
                "api.example.com",
                "test.example.com",
                "mail.example.com",
            ]
        )
        self.assertEqual(sorted(unique_subdomains), expected_subdomains)

        # Test statistics
        self.assertIn("statistics", processed)
        stats = processed["statistics"]
        self.assertEqual(stats["total_unique_subdomains"], 4)
        self.assertEqual(stats["tools_used"], 2)
        self.assertEqual(stats["successful_tools"], 2)


class TestSubdomainServiceIntegration(unittest.TestCase):
    """Integration tests for SubdomainService"""

    def setUp(self):
        """Set up test environment"""
        self.service = SubdomainService()
        self.test_domain = "example.com"

    @patch(
        "src.services.subdomain_service.SubdomainService._execute_subdomain_enumeration"
    )
    @patch(
        "src.services.subdomain_service.SubdomainService._process_enumeration_results"
    )
    @patch("src.services.subdomain_service.SubdomainService._handle_report_generation")
    def test_full_enumeration_workflow(self, mock_report, mock_process, mock_execute):
        """Test complete enumeration workflow"""
        # Mock workflow steps
        mock_execute.return_value = {"mock": "enumeration_result"}
        mock_process.return_value = {
            "domain": self.test_domain,
            "unique_subdomains": ["www.example.com", "api.example.com"],
            "statistics": {"total_unique_subdomains": 2},
        }
        mock_report.return_value = {"generated": True, "formats": ["json"]}

        # Execute enumeration
        result = self.service.enumerate_subdomains(self.test_domain)

        # Test workflow execution
        mock_execute.assert_called_once()
        mock_process.assert_called_once()
        mock_report.assert_called_once()

        # Test result structure
        self.assertIn("domain", result)
        self.assertIn("unique_subdomains", result)
        self.assertIn("statistics", result)
        self.assertIn("metadata", result)
        self.assertIn("execution_time", result)

    def test_error_handling_invalid_domain(self):
        """Test error handling for invalid domain"""
        with self.assertRaises(ValueError):
            self.service.enumerate_subdomains("")

        with self.assertRaises(ValueError):
            self.service.enumerate_subdomains("invalid_domain")

    @patch("src.services.subdomain_service.subprocess.run")
    def test_tool_availability_check(self, mock_subprocess):
        """Test tool availability checking"""
        # Mock successful tool check
        mock_subprocess.return_value = Mock(returncode=0)

        self.service._check_tool_availability()

        # Test that subprocess.run was called for each tool
        expected_calls = len(["subfinder", "amass", "sublist3r", "ctfr"])
        self.assertEqual(mock_subprocess.call_count, expected_calls)


class TestSubdomainServiceReporting(unittest.TestCase):
    """Test reporting functionality"""

    def setUp(self):
        """Set up test environment"""
        self.service = SubdomainService()

    @patch("src.services.subdomain_service.ReportService")
    def test_report_generation_success(self, mock_report_service):
        """Test successful report generation"""
        # Mock report service
        mock_report_instance = Mock()
        mock_report_service.return_value = mock_report_instance
        mock_report_instance.generate_reports.return_value = "/path/to/report.json"

        result = {"domain": "example.com", "unique_subdomains": ["www.example.com"]}
        options = {"json_report": True, "html_report": True}

        report_result = self.service._handle_report_generation(result, options)

        # Test report generation
        self.assertTrue(report_result["generated"])
        self.assertIn("json", report_result["formats"])

    def test_report_generation_no_requests(self):
        """Test when no reports are requested"""
        result = {"domain": "example.com"}
        options = {}  # No report options

        report_result = self.service._handle_report_generation(result, options)

        # Test no reports generated
        self.assertFalse(report_result["generated"])
        self.assertEqual(len(report_result["formats"]), 0)


class TestSubdomainServicePerformance(unittest.TestCase):
    """Test performance aspects of SubdomainService"""

    def setUp(self):
        """Set up test environment"""
        self.service = SubdomainService()

    def test_large_subdomain_list_processing(self):
        """Test processing of large subdomain lists"""
        # Generate large subdomain list
        large_subdomain_list = [f"sub{i}.example.com" for i in range(1000)]

        start_time = time.time()

        # Mock large enumeration result
        mock_result = {
            "domain": "example.com",
            "enumeration_methods": {"subfinder": {"status": "success"}},
            "raw_results": {
                "subfinder": {"success": True, "subdomains": large_subdomain_list}
            },
            "errors": [],
        }

        processed = self.service._process_enumeration_results(
            mock_result, "example.com"
        )

        processing_time = time.time() - start_time

        # Test processing performance (should complete in reasonable time)
        self.assertLess(processing_time, 5.0)  # 5 seconds max

        # Test result correctness
        self.assertEqual(len(processed["unique_subdomains"]), 1000)
        self.assertEqual(processed["statistics"]["total_unique_subdomains"], 1000)

    def test_subdomain_level_analysis_performance(self):
        """Test performance of subdomain level analysis"""
        # Generate varied subdomain levels
        subdomains = [
            "www.example.com",  # Level 1
            "api.test.example.com",  # Level 2
            "v1.api.test.example.com",  # Level 3
            "deep.v1.api.test.example.com",  # Level 4+
        ] * 250  # 1000 subdomains total

        start_time = time.time()
        levels = self.service._analyze_subdomain_levels(subdomains, "example.com")
        analysis_time = time.time() - start_time

        # Test performance
        self.assertLess(analysis_time, 1.0)  # 1 second max

        # Test correctness
        self.assertEqual(levels["1"], 250)  # www
        self.assertEqual(levels["2"], 250)  # api.test
        self.assertEqual(levels["3"], 250)  # v1.api.test
        self.assertEqual(levels["4+"], 250)  # deep.v1.api.test


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2, buffer=True)
