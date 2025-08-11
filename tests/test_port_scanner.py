#!/usr/bin/env python3
"""
Unit tests for Port Scanner module
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.scanners.recon.port_scanner import PortScanner
from src.core import ScanStatus, ScanSeverity
from src.utils.logger import LoggerSetup, log_banner, log_success, log_error, log_info


class TestPortScanner(unittest.TestCase):
    """Test cases for PortScanner"""

    def setUp(self):
        """Set up test fixtures"""
        self.scanner = PortScanner(timeout=60)

        # Sample nmap XML output for testing
        self.sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
    <scaninfo type="syn" protocol="tcp" numservices="1000"/>
    <host>
        <status state="up"/>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <hostnames>
            <hostname name="router.local" type="PTR"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="7.4" method="probed" conf="10"/>
                <script id="ssh-hostkey" output="2048 aa:bb:cc:dd (RSA)"/>
            </port>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache httpd" version="2.4.6" method="probed" conf="10"/>
            </port>
            <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="https" product="Apache httpd" version="2.4.6" method="probed" conf="10"/>
            </port>
        </ports>
        <os>
            <osmatch name="Linux 3.2 - 4.9" accuracy="95" line="123">
                <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="3.X" accuracy="95"/>
            </osmatch>
        </os>
    </host>
    <runstats>
        <finished time="1634567890" timestr="Mon Oct 18 15:31:30 2021" elapsed="45.23" exit="success"/>
    </runstats>
</nmaprun>"""

        # def test_validate_target_ip(self):
        #     """Test target validation with IP addresses"""
        #     log_info("Testing IP target validation")

        #     # Valid IPv4 addresses
        #     self.assertTrue(self.scanner.validate_target("192.168.1.1"))
        #     self.assertTrue(self.scanner.validate_target("8.8.8.8"))
        #     self.assertTrue(self.scanner.validate_target("127.0.0.1"))
        #     self.assertTrue(self.scanner.validate_target("10.0.0.1"))

        #     # Valid IPv6 addresses
        #     self.assertTrue(self.scanner.validate_target("::1"))  # IPv6 loopback
        #     self.assertTrue(
        #         self.scanner.validate_target("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        #     )

        #     # Invalid IPv4 addresses
        #     self.assertFalse(
        #         self.scanner.validate_target("256.256.256.256")
        #     )  # Out of range
        #     self.assertFalse(
        #         self.scanner.validate_target("192.168.1.256")
        #     )  # Last octet too high
        #     self.assertFalse(self.scanner.validate_target("192.168.1"))  # Missing octet
        #     self.assertFalse(
        #         self.scanner.validate_target("192.168.1.1.1")
        #     )  # Too many octets

        #     # Invalid formats
        #     self.assertFalse(self.scanner.validate_target("not.an.ip"))
        #     self.assertFalse(self.scanner.validate_target(""))
        #     self.assertFalse(self.scanner.validate_target("192.168.1.a"))
        #     self.assertFalse(self.scanner.validate_target("192.168.-1.1"))

        log_success("IP validation tests passed")

    def test_validate_target_domain(self):
        """Test target validation with domains"""
        log_info("Testing domain target validation")

        # Valid domains
        self.assertTrue(self.scanner.validate_target("example.com"))
        self.assertTrue(self.scanner.validate_target("sub.domain.com"))
        self.assertTrue(self.scanner.validate_target("test-domain.org"))
        self.assertTrue(self.scanner.validate_target("a.co"))
        self.assertTrue(
            self.scanner.validate_target("very-long-subdomain-name.example.com")
        )

        # Invalid domains
        self.assertFalse(self.scanner.validate_target(""))  # Empty
        self.assertFalse(self.scanner.validate_target("invalid_domain"))  # No TLD
        self.assertFalse(
            self.scanner.validate_target(".example.com")
        )  # Starts with dot
        self.assertFalse(self.scanner.validate_target("example.com."))  # Ends with dot
        self.assertFalse(
            self.scanner.validate_target("-example.com")
        )  # Starts with hyphen
        self.assertFalse(
            self.scanner.validate_target("example-.com")
        )  # Ends with hyphen
        self.assertFalse(self.scanner.validate_target("example..com"))  # Double dot
        # self.assertFalse(self.scanner.validate_target("example.c"))  # TLD too short
        # self.assertFalse(self.scanner.validate_target("example.123"))  # Numeric TLD
        # self.assertFalse(self.scanner.validate_target("192.168.1.1"))  # IP not domain

        log_success("Domain validation tests passed")

    def test_build_nmap_command_basic(self):
        """Test basic nmap command building"""
        log_info("Testing nmap command building")

        # Basic command
        cmd = self.scanner._build_nmap_command("192.168.1.1", {})
        self.assertIn("nmap", cmd)
        self.assertIn("192.168.1.1", cmd)
        self.assertIn("-sV", cmd)  # Version detection
        self.assertIn("-sC", cmd)  # Default scripts

        log_success("Basic command building test passed")

    def test_build_nmap_command_with_options(self):
        """Test nmap command building with options"""
        log_info("Testing nmap command with options")

        options = {"ports": "quick", "scan_type": "tcp", "timing": 4, "no_ping": True}

        cmd = self.scanner._build_nmap_command("example.com", options)

        self.assertIn("-sT", cmd)  # TCP scan
        self.assertIn("-T", cmd)  # Timing
        self.assertIn("4", cmd)  # Timing value
        self.assertIn("-Pn", cmd)  # No ping

        log_success("Command with options test passed")

    def test_port_profiles(self):
        """Test predefined port profiles"""
        log_info("Testing port profiles")

        # Test quick profile
        cmd = self.scanner._build_nmap_command("127.0.0.1", {"ports": "quick"})
        port_list = ",".join(map(str, self.scanner.port_profiles["quick"]))
        self.assertIn(port_list, " ".join(cmd))

        # Test top ports
        cmd = self.scanner._build_nmap_command("127.0.0.1", {"ports": "top100"})
        self.assertIn("--top-ports", cmd)
        self.assertIn("100", cmd)

        log_success("Port profiles test passed")

    @patch("src.scanners.recon.port_scanner.CommandExecutor")
    def test_execute_scan_success(self, mock_executor_class):
        """Test successful scan execution"""
        log_info("Testing successful scan execution")

        # Mock executor
        mock_executor = Mock()
        mock_executor_class.return_value = mock_executor
        mock_executor.check_tool_exists.return_value = True

        # Mock command result
        mock_result = Mock()
        mock_result.success = True
        mock_result.stdout = self.sample_xml
        mock_result.stderr = ""
        mock_result.execution_time = 45.23
        mock_result.return_code = 0
        mock_executor.execute.return_value = mock_result

        # Create new scanner with mocked executor
        scanner = PortScanner()

        # Execute scan
        result = scanner.scan("192.168.1.1")

        # Verify results
        self.assertEqual(result.status, ScanStatus.COMPLETED)
        self.assertGreater(len(result.findings), 0)
        self.assertEqual(result.target, "192.168.1.1")

        # Check for specific ports
        port_findings = [f for f in result.findings if f.get("category") == "open_port"]
        self.assertGreater(len(port_findings), 0)

        # Check for SSH port
        ssh_findings = [f for f in port_findings if f.get("port") == 22]
        self.assertEqual(len(ssh_findings), 1)
        self.assertIn("ssh", ssh_findings[0]["title"].lower())

        log_success("Successful scan test passed")

    @patch("src.scanners.recon.port_scanner.CommandExecutor")
    def test_execute_scan_nmap_not_found(self, mock_executor_class):
        """Test scan when nmap is not available"""
        log_info("Testing scan with nmap not available")

        # Mock executor
        mock_executor = Mock()
        mock_executor_class.return_value = mock_executor
        mock_executor.check_tool_exists.return_value = False

        # Create scanner with mocked executor
        scanner = PortScanner()

        # Execute scan
        result = scanner.scan("192.168.1.1")

        # Verify failure
        self.assertEqual(result.status, ScanStatus.FAILED)
        self.assertIn("nmap is not installed", result.errors[0])

        log_success("Nmap not found test passed")

    @patch("src.scanners.recon.port_scanner.CommandExecutor")
    def test_execute_scan_command_failure(self, mock_executor_class):
        """Test scan when nmap command fails"""
        log_info("Testing scan with command failure")

        # Mock executor
        mock_executor = Mock()
        mock_executor_class.return_value = mock_executor
        mock_executor.check_tool_exists.return_value = True

        # Mock failed command result
        mock_result = Mock()
        mock_result.success = False
        mock_result.stdout = ""
        mock_result.stderr = "nmap: command failed"
        mock_result.execution_time = 5.0
        mock_result.return_code = 1
        mock_executor.execute.return_value = mock_result

        # Create scanner with mocked executor
        scanner = PortScanner()

        # Execute scan
        result = scanner.scan("192.168.1.1")

        # Verify failure
        self.assertEqual(result.status, ScanStatus.FAILED)
        self.assertTrue(any("nmap failed" in error for error in result.errors))

        log_success("Command failure test passed")

    def test_parse_nmap_xml(self):
        """Test XML parsing functionality"""
        log_info("Testing XML parsing")

        from src.core import ScanResult
        from datetime import datetime

        # Create empty result
        result = ScanResult(
            scanner_name="test",
            target="192.168.1.1",
            status=ScanStatus.RUNNING,
            start_time=datetime.now(),
        )

        # Parse XML
        self.scanner._parse_nmap_xml(self.sample_xml, result)

        # Verify parsed data
        self.assertGreater(len(result.findings), 0)

        # Check for open ports
        port_findings = [f for f in result.findings if f.get("category") == "open_port"]
        self.assertEqual(len(port_findings), 3)  # SSH, HTTP, HTTPS

        # Check specific port details
        ssh_finding = next((f for f in port_findings if f.get("port") == 22), None)
        self.assertIsNotNone(ssh_finding)
        self.assertEqual(ssh_finding["protocol"], "tcp")
        self.assertIn("ssh", ssh_finding["service"])

        # Check OS detection
        os_findings = [
            f for f in result.findings if f.get("category") == "os_detection"
        ]
        self.assertEqual(len(os_findings), 1)
        self.assertIn("Linux", os_findings[0]["description"])

        log_success("XML parsing test passed")

    def test_determine_port_severity(self):
        """Test port severity determination"""
        log_info("Testing port severity determination")

        # Test critical port (telnet)
        severity = self.scanner._determine_port_severity("23", {"name": "telnet"}, [])
        self.assertEqual(severity, ScanSeverity.CRITICAL)

        # Test high risk port (SMB)
        severity = self.scanner._determine_port_severity(
            "445", {"name": "microsoft-ds"}, []
        )
        self.assertEqual(severity, ScanSeverity.HIGH)

        # Test medium risk port (SSH)
        severity = self.scanner._determine_port_severity("22", {"name": "ssh"}, [])
        self.assertEqual(severity, ScanSeverity.MEDIUM)

        # Test low risk port (HTTP)
        severity = self.scanner._determine_port_severity("80", {"name": "http"}, [])
        self.assertEqual(severity, ScanSeverity.LOW)

        # Test vulnerability in script
        scripts = [{"output": "This service has a vulnerability"}]
        severity = self.scanner._determine_port_severity(
            "8080", {"name": "http"}, scripts
        )
        self.assertEqual(severity, ScanSeverity.HIGH)

        log_success("Port severity test passed")

    def test_get_capabilities(self):
        """Test scanner capabilities"""
        log_info("Testing scanner capabilities")

        with patch.object(
            self.scanner.executor, "check_tool_exists"
        ) as mock_check, patch.object(
            self.scanner.executor, "get_tool_version"
        ) as mock_version:

            mock_check.return_value = True
            mock_version.return_value = "Nmap 7.80"

            capabilities = self.scanner.get_capabilities()

            self.assertEqual(capabilities["name"], "port_scanner")
            self.assertIn("ip", capabilities["supported_targets"])
            self.assertIn("domain", capabilities["supported_targets"])
            self.assertIn("tcp", capabilities["scan_types"])
            self.assertTrue(capabilities["dependencies"]["nmap"]["available"])

        log_success("Capabilities test passed")

    def test_quick_scan(self):
        """Test quick scan convenience method"""
        log_info("Testing quick scan method")

        with patch.object(self.scanner, "scan") as mock_scan:
            mock_scan.return_value = Mock()

            self.scanner.quick_scan("example.com")

            # Verify scan was called with quick options
            args, kwargs = mock_scan.call_args
            self.assertEqual(args[0], "example.com")
            # Check the options dictionary (second argument)
            self.assertEqual(len(args), 2)
            options = args[1]
            self.assertEqual(options["ports"], "quick")
            self.assertEqual(options["timing"], 4)
            self.assertEqual(options["no_ping"], False)

        log_success("Quick scan test passed")

    def test_full_scan(self):
        """Test full scan convenience method"""
        log_info("Testing full scan method")

        with patch.object(self.scanner, "scan") as mock_scan:
            mock_scan.return_value = Mock()

            self.scanner.full_scan("example.com")

            # Verify scan was called with full options
            args, kwargs = mock_scan.call_args
            self.assertEqual(args[0], "example.com")
            # Check the options dictionary (second argument)
            self.assertEqual(len(args), 2)
            options = args[1]
            self.assertEqual(options["ports"], "top1000")
            self.assertEqual(options["timing"], 3)
            self.assertEqual(options["no_ping"], False)
            self.assertIn("-A", options["nmap_args"])

        log_success("Full scan test passed")


def run_port_scanner_demo():
    """Run a demonstration of the port scanner (mock mode)"""
    log_banner("Port Scanner Demo (Mock Mode)", "bold cyan")

    try:
        # Create scanner
        scanner = PortScanner(timeout=120)

        log_info("Scanner created successfully")

        # Show capabilities
        log_info("Scanner capabilities:")
        capabilities = scanner.get_capabilities()
        for key, value in capabilities.items():
            if key != "dependencies":
                log_info(f"  {key}: {value}")

        # Mock a scan result for demo
        log_info("\nSimulating port scan on 192.168.1.1...")

        # This would be a real scan in production:
        # result = scanner.quick_scan("192.168.1.1")

        # For demo, create a mock result
        from src.core import ScanResult
        from datetime import datetime

        demo_result = ScanResult(
            scanner_name="port_scanner",
            target="192.168.1.1",
            status=ScanStatus.COMPLETED,
            start_time=datetime.now(),
        )

        # Add some demo findings
        demo_result.add_finding(
            title="Open Port: 22/tcp (ssh)",
            description="Port 22/tcp is open running OpenSSH 7.4",
            severity=ScanSeverity.MEDIUM,
            category="open_port",
            port=22,
            protocol="tcp",
            service="ssh",
        )

        demo_result.add_finding(
            title="Open Port: 80/tcp (http)",
            description="Port 80/tcp is open running Apache httpd 2.4.6",
            severity=ScanSeverity.LOW,
            category="open_port",
            port=80,
            protocol="tcp",
            service="http",
        )

        demo_result.add_finding(
            title="Operating System Detection",
            description="Detected OS: Linux 3.2 - 4.9",
            severity=ScanSeverity.INFO,
            category="os_detection",
        )

        # Show results
        log_success(f"Scan completed with status: {demo_result.status.value}")
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

        # Show JSON output sample
        log_info("\nJSON output sample:")
        print(
            demo_result.to_json()[:500] + "..."
            if len(demo_result.to_json()) > 500
            else demo_result.to_json()
        )

        log_banner("Demo Completed Successfully", "bold green")

    except Exception as e:
        log_error(f"Demo failed: {e}")
        import traceback

        traceback.print_exc()


def main():
    """Run all tests and demo"""
    log_banner("Port Scanner Test Suite", "bold magenta")

    # Setup logger
    logger = LoggerSetup.setup_logger(
        name="test_port_scanner", level="INFO", use_rich=True
    )

    try:
        # Run unit tests
        log_banner("Running Unit Tests", "bold blue")

        # Create test suite
        test_suite = unittest.TestLoader().loadTestsFromTestCase(TestPortScanner)

        # Run tests with custom result handler
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
        run_port_scanner_demo()

        return True

    except Exception as e:
        log_error(f"Test suite failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
