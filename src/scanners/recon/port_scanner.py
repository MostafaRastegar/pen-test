"""
Performance-Optimized Port Scanner Module - Nmap Integration with Caching
"""

import xml.etree.ElementTree as ET
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

from src.core import ScannerBase, ScanResult, ScanStatus, ScanSeverity
from src.core import CommandExecutor, validate_ip, validate_domain

from src.utils.logger import log_info, log_error, log_warning, log_debug, log_success

try:
    from src.utils.performance import cache_scan_result, get_performance_manager
except ImportError:
    # Fallback if performance module not available
    def cache_scan_result(*args, **kwargs):
        pass

    def get_performance_manager():
        return None


class PortScanner(ScannerBase):
    """
    Performance-optimized port scanner using nmap with XML output parsing and caching
    """

    def __init__(self, timeout: int = 300):
        """
        Initialize port scanner with performance optimizations

        Args:
            timeout: Scan timeout in seconds
        """
        super().__init__("port_scanner", timeout=timeout)
        self.executor = CommandExecutor(timeout=self.timeout)

        # Initialize performance manager for this scanner
        try:
            self.performance_manager = get_performance_manager()
        except Exception as e:
            log_debug(f"Performance manager not available: {e}")
            self.performance_manager = None

        # Default nmap options
        self.default_args = [
            "-sV",  # Version detection
            "-sC",  # Default scripts
            "-O",  # OS detection
            "--version-intensity",
            "5",
            "--osscan-guess",
            "-oX",
            "-",  # XML output to stdout
        ]

        # Predefined port lists
        self.port_profiles = {
            "quick": [
                21,
                22,
                23,
                25,
                53,
                80,
                110,
                111,
                135,
                139,
                143,
                443,
                993,
                995,
                1723,
                3389,
                5900,
            ],
            "top100": list(range(1, 101)),
            "top1000": "1-1000",
            "comprehensive": "1-65535",
        }

    def validate_target(self, target: str) -> bool:
        """
        Validate target format for port scanner

        Args:
            target: Target to validate

        Returns:
            bool: True if target is valid
        """
        try:
            # Check if it's a valid IP address
            if validate_ip(target):
                return True

            # Check if it's a valid domain/hostname
            if validate_domain(target):
                return True

            # Check for IP ranges (basic validation)
            if "/" in target or "-" in target:
                # Could be CIDR or range format
                return True

            return False

        except Exception as e:
            log_debug(f"Target validation failed for {target}: {e}")
            return False

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get scanner capabilities and metadata

        Returns:
            dict: Scanner capabilities information
        """
        return {
            "name": "Port Scanner",
            "version": "1.0.0",
            "description": "Network port scanner using Nmap with XML parsing",
            "author": "Auto-Pentest Framework",
            "target_types": ["ip", "domain", "hostname", "ip_range"],
            "supported_protocols": ["tcp", "udp"],
            "features": [
                "Service version detection",
                "OS fingerprinting",
                "NSE script scanning",
                "Stealth scanning",
                "Performance optimization",
                "XML output parsing",
                "Cache support",
            ],
            "port_profiles": {
                "quick": "Top 100 most common ports",
                "top1000": "Top 1000 ports",
                "comprehensive": "All 65535 ports",
            },
            "scan_types": [
                "TCP SYN scan (-sS)",
                "TCP Connect scan (-sT)",
                "UDP scan (-sU)",
                "Service detection (-sV)",
                "OS detection (-O)",
                "Script scan (-sC)",
            ],
            "performance": {
                "timing_templates": ["T1", "T2", "T3", "T4", "T5"],
                "parallel_scanning": True,
                "result_caching": True,
            },
            "dependencies": {"required": ["nmap"], "optional": ["nmap-scripts"]},
            "output_formats": ["xml", "json"],
            "estimated_time": {
                "quick": "30-60 seconds",
                "top1000": "2-5 minutes",
                "comprehensive": "10-30 minutes",
            },
        }

    def _execute_scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """
        Execute the actual port scan (implements abstract method)

        Args:
            target: Target to scan
            options: Scan options

        Returns:
            ScanResult: Scan results
        """
        # Create result object
        result = ScanResult(
            scanner_name=self.name,
            target=target,
            status=ScanStatus.RUNNING,
            start_time=datetime.now(),
        )

        try:
            # Build nmap command based on options
            cmd = self._build_nmap_command(target, options)

            log_info(f"Executing nmap command: {' '.join(cmd)}")

            # Execute command
            exec_result = self.executor.execute(cmd)

            if exec_result.success:
                # Parse XML output
                findings = self._parse_nmap_xml(exec_result.stdout)

                result.findings = findings
                result.raw_output = exec_result.stdout
                result.status = ScanStatus.COMPLETED
                result.metadata = {
                    "command": " ".join(cmd),
                    "scan_options": options,
                    "ports_scanned": self._get_ports_count(options),
                    "nmap_version": self._get_nmap_version(),
                }

                log_success(f"Port scan completed: {len(findings)} findings")

            else:
                result.status = ScanStatus.FAILED
                result.errors.append(exec_result.stderr or "Unknown error")
                log_error(f"Port scan failed: {exec_result.stderr}")

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))
            log_error(f"Port scan exception: {e}")

        finally:
            result.end_time = datetime.now()

        return result

    def _build_nmap_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        """
        Build nmap command based on options

        Args:
            target: Target to scan
            options: Scan options

        Returns:
            List[str]: Nmap command arguments
        """
        cmd = ["nmap"]

        # Add default arguments
        cmd.extend(self.default_args)

        # Port specification
        ports = options.get("ports", "quick")
        if ports in self.port_profiles:
            if ports == "quick":
                cmd.extend(["-p", ",".join(map(str, self.port_profiles["quick"]))])
            elif isinstance(self.port_profiles[ports], str):
                cmd.extend(["-p", self.port_profiles[ports]])
        else:
            cmd.extend(["-p", str(ports)])

        # Timing template
        timing = options.get("timing", 4)
        cmd.append(f"-T{timing}")

        # Additional options
        if options.get("no_ping", False):
            cmd.append("-Pn")

        if options.get("aggressive", False):
            cmd.append("-A")

        # Add custom nmap args if provided
        if "nmap_args" in options:
            if isinstance(options["nmap_args"], list):
                cmd.extend(options["nmap_args"])
            else:
                cmd.extend(str(options["nmap_args"]).split())

        # Add target
        cmd.append(target)

        return cmd

    def _parse_nmap_xml(self, xml_output: str) -> List[Dict[str, Any]]:
        """
        Parse nmap XML output and extract findings

        Args:
            xml_output: XML output from nmap

        Returns:
            List[Dict]: List of findings
        """
        findings = []

        try:
            import xml.etree.ElementTree as ET

            root = ET.fromstring(xml_output)

            for host in root.findall("host"):
                host_findings = self._parse_host(host)
                findings.extend(host_findings)

        except ET.ParseError as e:
            log_error(f"XML parsing error: {e}")
        except Exception as e:
            log_error(f"Error parsing nmap output: {e}")

        return findings

    def _parse_host(self, host_elem) -> List[Dict[str, Any]]:
        """Parse individual host element"""
        findings = []

        # Get host information
        host_ip = None
        hostname = None

        address_elem = host_elem.find("address[@addrtype='ipv4']")
        if address_elem is not None:
            host_ip = address_elem.get("addr")

        hostnames_elem = host_elem.find("hostnames/hostname[@type='PTR']")
        if hostnames_elem is not None:
            hostname = hostnames_elem.get("name")

        # Parse ports
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_finding = self._parse_port(port, host_ip, hostname)
                if port_finding:
                    findings.append(port_finding)

        return findings

    def _parse_port(
        self, port_elem, host_ip: str, hostname: str
    ) -> Optional[Dict[str, Any]]:
        """Parse individual port element"""
        try:
            protocol = port_elem.get("protocol")
            portid = port_elem.get("portid")

            state_elem = port_elem.find("state")
            if state_elem is None:
                return None

            state = state_elem.get("state")

            # Only report open ports
            if state != "open":
                return None

            # Get service information
            service_elem = port_elem.find("service")
            service_name = (
                service_elem.get("name") if service_elem is not None else "unknown"
            )
            service_product = (
                service_elem.get("product") if service_elem is not None else ""
            )
            service_version = (
                service_elem.get("version") if service_elem is not None else ""
            )

            # Build finding
            finding = {
                "title": f"Open Port: {portid}/{protocol} ({service_name})",
                "description": f"Port {portid}/{protocol} is open",
                "severity": self._assess_port_severity(int(portid), service_name).value,
                "category": "open_port",
                "host": host_ip,
                "hostname": hostname,
                "port": int(portid),
                "protocol": protocol,
                "state": state,
                "service": {
                    "name": service_name,
                    "product": service_product,
                    "version": service_version,
                },
            }

            return finding

        except Exception as e:
            log_error(f"Error parsing port: {e}")
            return None

    def _assess_port_severity(self, port: int, service: str) -> ScanSeverity:
        """Assess severity of open port"""
        # High-risk ports/services
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 1521, 3389, 5432, 5900]

        if port in high_risk_ports:
            return ScanSeverity.HIGH

        # Medium-risk services
        if service in ["ssh", "telnet", "ftp", "smtp", "pop3", "imap"]:
            return ScanSeverity.MEDIUM

        # Common web ports
        if port in [80, 443, 8080, 8443]:
            return ScanSeverity.LOW

        return ScanSeverity.INFO

    def _get_ports_count(self, options: Dict[str, Any]) -> int:
        """Get number of ports being scanned"""
        ports = options.get("ports", "quick")
        if ports == "quick":
            return len(self.port_profiles["quick"])
        elif ports == "top100":
            return 100
        elif ports == "top1000" or ports == "1-1000":
            return 1000
        elif ports == "comprehensive" or ports == "1-65535":
            return 65535
        else:
            # Try to count custom port specification
            try:
                if "-" in str(ports):
                    start, end = str(ports).split("-")
                    return int(end) - int(start) + 1
                elif "," in str(ports):
                    return len(str(ports).split(","))
                else:
                    return 1
            except:
                return 1

    def _get_nmap_version(self) -> str:
        """Get nmap version"""
        try:
            result = self.executor.execute(["nmap", "--version"])
            if result.success:
                return result.stdout.split("\n")[0]
        except:
            pass
        return "unknown"

    # Convenience methods for easy usage
    def quick_scan(self, target: str) -> ScanResult:
        """Quick scan of most common ports"""
        return self.scan(target, {"ports": "quick", "timing": 4, "no_ping": False})

    def full_scan(self, target: str) -> ScanResult:
        """Full scan with service detection"""
        return self.scan(
            target,
            {"ports": "top1000", "timing": 3, "no_ping": False, "nmap_args": ["-A"]},
        )

    def stealth_scan(self, target: str) -> ScanResult:
        """Stealth scan with slower timing"""
        return self.scan(target, {"ports": "quick", "timing": 1, "no_ping": True})
