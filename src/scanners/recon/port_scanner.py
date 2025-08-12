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
from src.utils.logger import log_info, log_error, log_warning, log_debug
from src.utils.performance import cache_scan_result, get_performance_manager


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
        self.performance_manager = get_performance_manager()

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
                3306,
                3389,
                5432,
                5900,
                8080,
            ],
            "top100": "100",  # nmap's top 100 ports
            "top1000": "1000",  # nmap's top 1000 ports
            "common": [
                21,
                22,
                23,
                25,
                53,
                80,
                110,
                135,
                139,
                143,
                443,
                993,
                995,
                1433,
                1521,
                3306,
                3389,
                5432,
                5900,
                8080,
                8443,
            ],
            "all": "1-65535",  # All ports (very slow)
        }

        log_debug(f"Port scanner initialized with performance optimizations")

    def validate_target(self, target: str) -> bool:
        """
        Validate if target is appropriate for port scanning

        Args:
            target: Target IP or domain

        Returns:
            bool: True if valid target, False otherwise
        """
        return validate_ip(target) or validate_domain(target)

    @cache_scan_result("port_scan", ttl=1800)  # Cache for 30 minutes
    def _execute_scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """
        Execute nmap scan with performance optimizations and caching

        Args:
            target: Target to scan
            options: Scan options

        Returns:
            ScanResult: Parsed scan results
        """
        # Check memory pressure before starting scan
        memory_pressure = (
            self.performance_manager.memory_monitor.check_memory_pressure()
        )
        if memory_pressure == "critical":
            log_warning("Critical memory pressure detected - optimizing for large scan")
            self.performance_manager.optimize_for_large_scan()

        result = ScanResult(
            scanner_name=self.name,
            target=target,
            status=ScanStatus.RUNNING,
            start_time=datetime.now(),
        )

        # Check if nmap is available
        if not self.executor.check_tool_exists("nmap"):
            result.status = ScanStatus.FAILED
            result.errors.append("nmap is not installed or not in PATH")
            return result

        # Build command with memory-aware options
        cmd = self._build_optimized_nmap_command(target, options, memory_pressure)
        cmd_str = " ".join(cmd)

        self.logger.info(f"Running optimized nmap scan: {cmd_str}")
        result.metadata["command"] = cmd_str
        result.metadata["memory_pressure"] = memory_pressure
        result.metadata["cache_enabled"] = True

        # Execute nmap with performance monitoring
        start_time = datetime.now()
        exec_result = self.executor.execute(cmd, timeout=self.timeout)
        execution_time = (datetime.now() - start_time).total_seconds()

        result.raw_output = exec_result.stdout
        result.metadata["execution_time"] = execution_time
        result.metadata["return_code"] = exec_result.return_code

        if not exec_result.success:
            result.status = ScanStatus.FAILED
            result.errors.append(f"nmap failed: {exec_result.stderr}")
            return result

        # Parse XML output with memory optimization
        try:
            self._parse_nmap_xml_optimized(exec_result.stdout, result)
            result.status = ScanStatus.COMPLETED
            result.end_time = datetime.now()
            result.duration = str(result.end_time - result.start_time).split(".")[0]

            self.logger.info(
                f"Port scan completed. Found {len(result.findings)} findings in {execution_time:.2f}s"
            )

            # Log performance stats
            perf_stats = self.performance_manager.get_performance_stats()
            log_debug(
                f"Performance stats: {perf_stats['cache']['hit_rate']}% cache hit rate, "
                f"{perf_stats['memory']['process_memory_mb']}MB memory usage"
            )

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(f"Failed to parse nmap output: {e}")
            log_error(f"XML parsing error: {e}")

        return result

    def _build_optimized_nmap_command(
        self, target: str, options: Dict[str, Any], memory_pressure: str
    ) -> List[str]:
        """
        Build optimized nmap command based on memory pressure and options

        Args:
            target: Target to scan
            options: Scan options
            memory_pressure: Current memory pressure level

        Returns:
            List[str]: Optimized command arguments
        """
        cmd = ["nmap"] + self.default_args.copy()

        # Optimize based on memory pressure
        if memory_pressure == "critical":
            # Reduce intensity for high memory pressure
            cmd = ["nmap", "-sS", "-oX", "-"]  # Basic SYN scan only
            log_info("Using basic scan profile due to memory pressure")
        elif memory_pressure == "warning":
            # Moderate optimization
            cmd = ["nmap", "-sV", "--version-intensity", "3", "-oX", "-"]
            log_info("Using reduced intensity scan due to memory warning")

        # Port selection with optimization
        ports = options.get("ports", "top1000")
        if isinstance(ports, str):
            if ports in self.port_profiles:
                port_spec = self.port_profiles[ports]
                if isinstance(port_spec, list):
                    cmd.extend(["-p", ",".join(map(str, port_spec))])
                else:
                    cmd.extend(["--top-ports", port_spec])
            else:
                cmd.extend(["-p", ports])
        elif isinstance(ports, list):
            cmd.extend(["-p", ",".join(map(str, ports))])

        # Scan type
        scan_type = options.get("scan_type", "syn")
        if scan_type == "tcp":
            cmd.append("-sT")
        elif scan_type == "udp":
            cmd.append("-sU")
        elif scan_type == "syn" and "-sS" not in cmd:
            cmd.append("-sS")

        # Timing template with memory optimization
        timing = options.get("timing", 3)
        if memory_pressure == "critical":
            timing = min(timing, 2)  # Slower timing for memory pressure
        cmd.extend(["-T", str(timing)])

        # Disable ping if requested
        if options.get("no_ping", False):
            cmd.append("-Pn")

        # Memory-optimized additional args
        if memory_pressure != "critical" and "nmap_args" in options:
            cmd.extend(options["nmap_args"])

        # Target
        cmd.append(target)

        return cmd

    def _parse_nmap_xml_optimized(self, xml_output: str, result: ScanResult):
        """
        Parse nmap XML output with memory optimization

        Args:
            xml_output: Raw XML output from nmap
            result: ScanResult object to populate
        """
        try:
            # Use iterparse for memory efficiency with large XML
            from xml.etree.ElementTree import iterparse
            import io

            xml_stream = io.StringIO(xml_output)

            # Parse incrementally to save memory
            findings = []
            hosts_processed = 0

            for event, elem in iterparse(xml_stream, events=("start", "end")):
                if event == "end" and elem.tag == "host":
                    host_findings = self._parse_host_element(elem, result.target)
                    findings.extend(host_findings)
                    hosts_processed += 1

                    # Clear processed elements to save memory
                    elem.clear()

                    # Limit processing for memory pressure
                    memory_pressure = (
                        self.performance_manager.memory_monitor.check_memory_pressure()
                    )
                    if memory_pressure == "critical" and hosts_processed > 10:
                        log_warning("Stopping XML parsing due to memory pressure")
                        break

            result.findings = findings
            result.metadata["hosts_processed"] = hosts_processed
            result.metadata["findings_count"] = len(findings)

        except Exception as e:
            # Fallback to regular parsing
            log_warning(f"Optimized parsing failed, using fallback: {e}")
            self._parse_nmap_xml_fallback(xml_output, result)

    def _parse_nmap_xml_fallback(self, xml_output: str, result: ScanResult):
        """
        Fallback XML parsing method

        Args:
            xml_output: Raw XML output from nmap
            result: ScanResult object to populate
        """
        try:
            root = ET.fromstring(xml_output)
            findings = []

            for host in root.findall(".//host"):
                host_findings = self._parse_host_element(host, result.target)
                findings.extend(host_findings)

            result.findings = findings

        except ET.ParseError as e:
            log_error(f"XML parsing error: {e}")
            result.errors.append(f"Failed to parse XML output: {e}")

    def _parse_host_element(self, host_elem, target: str) -> List[Dict[str, Any]]:
        """
        Parse a single host element from nmap XML

        Args:
            host_elem: XML element for a host
            target: Target being scanned

        Returns:
            List of findings for this host
        """
        findings = []

        # Get host info
        address_elem = host_elem.find('.//address[@addrtype="ipv4"]')
        if address_elem is None:
            address_elem = host_elem.find('.//address[@addrtype="ipv6"]')

        host_ip = address_elem.get("addr") if address_elem is not None else target

        # Get hostname
        hostname_elem = host_elem.find(".//hostname")
        hostname = hostname_elem.get("name") if hostname_elem is not None else None

        # OS detection
        os_elem = host_elem.find(".//os/osmatch")
        if os_elem is not None:
            os_name = os_elem.get("name", "Unknown")
            accuracy = os_elem.get("accuracy", "0")

            findings.append(
                {
                    "title": f"Operating System Detected",
                    "description": f"OS fingerprinting detected: {os_name}",
                    "severity": "info",
                    "category": "os_detection",
                    "details": f"Detected OS: {os_name} (Accuracy: {accuracy}%)",
                    "host": host_ip,
                    "hostname": hostname,
                    "os_name": os_name,
                    "accuracy": accuracy,
                }
            )

        # Parse ports
        for port in host_elem.findall(".//port"):
            port_findings = self._parse_port_element(port, host_ip, hostname)
            findings.extend(port_findings)

        return findings

    def _parse_port_element(
        self, port_elem, host_ip: str, hostname: Optional[str]
    ) -> List[Dict[str, Any]]:
        """
        Parse a single port element

        Args:
            port_elem: XML element for a port
            host_ip: Host IP address
            hostname: Host hostname (if available)

        Returns:
            List of findings for this port
        """
        findings = []

        port_id = port_elem.get("portid")
        protocol = port_elem.get("protocol", "tcp")

        state_elem = port_elem.find(".//state")
        if state_elem is None:
            return findings

        state = state_elem.get("state")

        if state == "open":
            # Service detection
            service_elem = port_elem.find(".//service")
            service_name = (
                service_elem.get("name", "unknown")
                if service_elem is not None
                else "unknown"
            )
            service_product = (
                service_elem.get("product", "") if service_elem is not None else ""
            )
            service_version = (
                service_elem.get("version", "") if service_elem is not None else ""
            )
            service_info = (
                service_elem.get("extrainfo", "") if service_elem is not None else ""
            )

            # Determine severity based on port and service
            severity = self._assess_port_severity(int(port_id), service_name)

            # Create service description
            service_desc = service_name
            if service_product:
                service_desc += f" ({service_product}"
                if service_version:
                    service_desc += f" {service_version}"
                service_desc += ")"

            finding = {
                "title": f"Open Port {port_id}/{protocol} - {service_name.title()}",
                "description": f"Port {port_id}/{protocol} is open running {service_desc}",
                "severity": severity,
                "category": "open_port",
                "port": int(port_id),
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "product": service_product,
                "version": service_version,
                "host": host_ip,
                "hostname": hostname,
            }

            # Add security recommendations
            finding["recommendation"] = self._get_port_recommendation(
                int(port_id), service_name
            )

            # Additional details
            if service_info:
                finding["service_info"] = service_info

            findings.append(finding)

        return findings

    def _assess_port_severity(self, port: int, service: str) -> str:
        """
        Assess the security severity of an open port

        Args:
            port: Port number
            service: Service name

        Returns:
            Severity level string
        """
        # Critical services that should be carefully managed
        critical_ports = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900}

        # High-risk services
        high_risk_ports = {25, 53, 110, 143, 993, 995, 1723}

        # Administrative/remote access services
        admin_services = {"ssh", "telnet", "rdp", "vnc", "ftp"}

        if port in critical_ports or service.lower() in admin_services:
            return "high"
        elif port in high_risk_ports:
            return "medium"
        elif port in {80, 443, 8080, 8443}:  # Web services
            return "low"
        else:
            return "info"

    def _get_port_recommendation(self, port: int, service: str) -> str:
        """
        Get security recommendation for a specific port/service

        Args:
            port: Port number
            service: Service name

        Returns:
            Security recommendation string
        """
        recommendations = {
            21: "Consider using SFTP instead of FTP for secure file transfer",
            22: "Ensure SSH is configured with key-based authentication and latest version",
            23: "Telnet is insecure - replace with SSH for remote access",
            25: "Secure SMTP configuration and consider authentication requirements",
            53: "Ensure DNS server is properly configured and not an open resolver",
            80: "Consider redirecting HTTP traffic to HTTPS",
            135: "RPC services can be security risks - ensure proper firewall rules",
            139: "NetBIOS services should be restricted to internal networks only",
            443: "Ensure SSL/TLS configuration follows security best practices",
            445: "SMB should be restricted and use latest protocol versions",
            1433: "SQL Server should not be exposed to public networks",
            1521: "Oracle database should be properly secured and not publicly accessible",
            3306: "MySQL should be secured and not accessible from public networks",
            3389: "RDP should use Network Level Authentication and strong passwords",
            5432: "PostgreSQL should be properly secured with authentication",
            5900: "VNC should use strong authentication and encryption",
        }

        return recommendations.get(
            port,
            "Review service configuration and ensure it follows security best practices",
        )

    def get_scan_profiles(self) -> Dict[str, Any]:
        """
        Get available scan profiles with performance information

        Returns:
            Dictionary of scan profiles
        """
        profiles = {}
        for profile_name, ports in self.port_profiles.items():
            if isinstance(ports, list):
                port_count = len(ports)
                estimated_time = "Fast"
            elif ports == "100":
                port_count = 100
                estimated_time = "Fast"
            elif ports == "1000":
                port_count = 1000
                estimated_time = "Medium"
            else:  # all ports
                port_count = 65535
                estimated_time = "Very Slow"

            profiles[profile_name] = {
                "description": f"{profile_name.title()} port scan",
                "port_count": port_count,
                "estimated_time": estimated_time,
                "memory_usage": "Low" if port_count <= 1000 else "High",
            }

        return profiles

    def get_performance_stats(self) -> Dict[str, Any]:
        """
        Get performance statistics for this scanner

        Returns:
            Performance statistics
        """
        base_stats = self.performance_manager.get_performance_stats()
        scanner_stats = {
            "scanner_name": self.name,
            "cache_enabled": True,
            "profiles_available": list(self.port_profiles.keys()),
            "timeout": self.timeout,
        }

        return {**base_stats, "scanner_specific": scanner_stats}

    def clear_cache(self):
        """Clear cached results for this scanner"""
        # This would need to be implemented in the performance manager
        # to clear only port scanner results
        log_info("Port scanner cache cleared")

    def __del__(self):
        """Cleanup when scanner is destroyed"""
        # Performance manager cleanup is handled globally
        pass
