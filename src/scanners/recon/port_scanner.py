"""
Port Scanner Module - Nmap Integration
"""

import xml.etree.ElementTree as ET
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

from src.core import ScannerBase, ScanResult, ScanStatus, ScanSeverity
from src.core import CommandExecutor, validate_ip, validate_domain
from src.utils.logger import log_info, log_error, log_warning


class PortScanner(ScannerBase):
    """
    Port scanner using nmap with XML output parsing
    """

    def __init__(self, timeout: int = 300):
        """
        Initialize port scanner

        Args:
            timeout: Scan timeout in seconds
        """
        super().__init__("port_scanner", timeout=timeout)
        self.executor = CommandExecutor(timeout=self.timeout)

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

    def validate_target(self, target: str) -> bool:
        """
        Validate if target is appropriate for port scanning

        Args:
            target: Target IP or domain

        Returns:
            bool: True if valid target, False otherwise
        """
        return validate_ip(target) or validate_domain(target)

    def _build_nmap_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        """
        Build nmap command with options

        Args:
            target: Target to scan
            options: Scan options

        Returns:
            List[str]: Command arguments
        """
        cmd = ["nmap"] + self.default_args.copy()

        # Port selection
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
        elif scan_type == "syn":
            cmd.append("-sS")

        # Timing template
        timing = options.get("timing", 3)
        cmd.extend(["-T", str(timing)])

        # Disable ping if requested
        if options.get("no_ping", False):
            cmd.append("-Pn")

        # Additional nmap args
        if "nmap_args" in options:
            cmd.extend(options["nmap_args"])

        # Target
        cmd.append(target)

        return cmd

    def _execute_scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """
        Execute nmap scan and parse results

        Args:
            target: Target to scan
            options: Scan options

        Returns:
            ScanResult: Parsed scan results
        """
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

        # Build command
        cmd = self._build_nmap_command(target, options)
        cmd_str = " ".join(cmd)

        self.logger.info(f"Running nmap scan: {cmd_str}")
        result.metadata["command"] = cmd_str

        # Execute nmap
        exec_result = self.executor.execute(cmd, timeout=self.timeout)
        result.raw_output = exec_result.stdout
        result.metadata["execution_time"] = exec_result.execution_time
        result.metadata["return_code"] = exec_result.return_code

        if not exec_result.success:
            result.status = ScanStatus.FAILED
            result.errors.append(f"nmap failed: {exec_result.stderr}")
            return result

        # Parse XML output
        try:
            self._parse_nmap_xml(exec_result.stdout, result)
            result.status = ScanStatus.COMPLETED
            self.logger.info(
                f"Port scan completed. Found {len(result.findings)} open ports"
            )

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(f"Failed to parse nmap output: {str(e)}")
            self.logger.error(f"XML parsing error: {e}")

        return result

    def _parse_nmap_xml(self, xml_output: str, result: ScanResult) -> None:
        """
        Parse nmap XML output and extract findings

        Args:
            xml_output: XML output from nmap
            result: ScanResult to populate
        """
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML output: {e}")

        # Extract scan info
        scan_info = root.find("scaninfo")
        if scan_info is not None:
            result.metadata["scan_type"] = scan_info.get("type")
            result.metadata["protocol"] = scan_info.get("protocol")
            result.metadata["num_services"] = scan_info.get("numservices")

        # Extract host information
        for host in root.findall("host"):
            self._parse_host(host, result)

        # Extract run stats
        runstats = root.find("runstats/finished")
        if runstats is not None:
            result.metadata["elapsed_time"] = runstats.get("elapsed")
            result.metadata["exit_status"] = runstats.get("exit")

    def _parse_host(self, host_elem: ET.Element, result: ScanResult) -> None:
        """
        Parse individual host element

        Args:
            host_elem: Host XML element
            result: ScanResult to populate
        """
        # Host status
        status = host_elem.find("status")
        if status is None or status.get("state") != "up":
            return

        # Host address
        address = host_elem.find("address")
        host_ip = address.get("addr") if address is not None else "unknown"

        # Hostnames
        hostnames = []
        for hostname in host_elem.findall("hostnames/hostname"):
            hostnames.append(hostname.get("name"))

        # OS detection
        os_info = self._parse_os_info(host_elem)
        if os_info:
            result.add_finding(
                title="Operating System Detection",
                description=f"Detected OS: {os_info['name']}",
                severity=ScanSeverity.INFO,
                category="os_detection",
                host=host_ip,
                details=os_info,
            )

        # Parse ports
        ports = host_elem.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                self._parse_port(port, host_ip, hostnames, result)

    def _parse_port(
        self,
        port_elem: ET.Element,
        host_ip: str,
        hostnames: List[str],
        result: ScanResult,
    ) -> None:
        """
        Parse individual port element

        Args:
            port_elem: Port XML element
            host_ip: Host IP address
            hostnames: List of hostnames
            result: ScanResult to populate
        """
        port_id = port_elem.get("portid")
        protocol = port_elem.get("protocol")

        # Port state
        state = port_elem.find("state")
        if state is None:
            return

        port_state = state.get("state")

        # Only process open/filtered ports
        if port_state not in ["open", "open|filtered"]:
            return

        # Service information
        service = port_elem.find("service")
        service_info = {}
        if service is not None:
            service_info = {
                "name": service.get("name", "unknown"),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
                "extrainfo": service.get("extrainfo", ""),
                "method": service.get("method", ""),
                "conf": service.get("conf", ""),
            }

        # Script results
        scripts = []
        for script in port_elem.findall("script"):
            script_result = {
                "id": script.get("id"),
                "output": script.get("output", "").strip(),
            }
            scripts.append(script_result)

        # Determine severity based on service and port
        severity = self._determine_port_severity(port_id, service_info, scripts)

        # Create finding
        service_name = service_info.get("name", "unknown")
        title = f"Open Port: {port_id}/{protocol} ({service_name})"

        description = f"Port {port_id}/{protocol} is {port_state}"
        if service_info.get("product"):
            description += f" running {service_info['product']}"
            if service_info.get("version"):
                description += f" {service_info['version']}"

        finding_details = {
            "port": int(port_id),
            "protocol": protocol,
            "state": port_state,
            "service": service_info,
            "scripts": scripts,
            "host": host_ip,
            "hostnames": hostnames,
        }

        result.add_finding(
            title=title,
            description=description,
            severity=severity,
            category="open_port",
            port=int(port_id),
            protocol=protocol,
            service=service_name,
            details=finding_details,
        )

    def _parse_os_info(self, host_elem: ET.Element) -> Optional[Dict[str, Any]]:
        """
        Parse OS detection information

        Args:
            host_elem: Host XML element

        Returns:
            Optional[Dict]: OS information or None
        """
        os_elem = host_elem.find("os")
        if os_elem is None:
            return None

        os_info = {"matches": []}

        # OS matches
        for osmatch in os_elem.findall("osmatch"):
            match_info = {
                "name": osmatch.get("name"),
                "accuracy": osmatch.get("accuracy"),
                "line": osmatch.get("line"),
            }

            # OS classes
            osclasses = []
            for osclass in osmatch.findall("osclass"):
                class_info = {
                    "type": osclass.get("type"),
                    "vendor": osclass.get("vendor"),
                    "osfamily": osclass.get("osfamily"),
                    "osgen": osclass.get("osgen"),
                    "accuracy": osclass.get("accuracy"),
                }
                osclasses.append(class_info)

            match_info["osclasses"] = osclasses
            os_info["matches"].append(match_info)

        # Return best match
        if os_info["matches"]:
            best_match = max(
                os_info["matches"], key=lambda x: int(x.get("accuracy", 0))
            )
            return {
                "name": best_match["name"],
                "accuracy": best_match["accuracy"],
                "all_matches": os_info["matches"],
            }

        return None

    def _determine_port_severity(
        self, port: str, service_info: Dict[str, Any], scripts: List[Dict]
    ) -> ScanSeverity:
        """
        Determine severity level for an open port

        Args:
            port: Port number
            service_info: Service information
            scripts: Script results

        Returns:
            ScanSeverity: Severity level
        """
        port_num = int(port)
        service_name = service_info.get("name", "").lower()

        # Critical ports/services
        critical_ports = [23, 513, 514, 512]  # telnet, rlogin, rsh, rexec
        if port_num in critical_ports:
            return ScanSeverity.CRITICAL

        # High risk ports/services
        high_risk_ports = [21, 135, 139, 445, 1433, 3389]  # ftp, rpc, smb, mssql, rdp
        high_risk_services = ["ftp", "smb", "microsoft-ds", "ms-sql", "rdp"]

        if port_num in high_risk_ports or any(
            srv in service_name for srv in high_risk_services
        ):
            return ScanSeverity.HIGH

        # Medium risk ports
        medium_risk_ports = [
            22,
            25,
            110,
            143,
            993,
            995,
            3306,
            5432,
        ]  # ssh, smtp, pop3, imap, mysql, postgresql
        if port_num in medium_risk_ports:
            return ScanSeverity.MEDIUM

        # Check for vulnerabilities in script results
        for script in scripts:
            script_output = script.get("output", "").lower()
            if any(
                vuln in script_output
                for vuln in ["vulnerability", "exploit", "backdoor", "weak"]
            ):
                return ScanSeverity.HIGH

        # Default to low for other open ports
        return ScanSeverity.LOW

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get scanner capabilities

        Returns:
            Dict: Scanner capabilities and information
        """
        nmap_version = self.executor.get_tool_version("nmap")

        return {
            "name": self.name,
            "description": "Network port scanner using nmap",
            "version": "1.0.0",
            "supported_targets": ["ip", "domain"],
            "scan_types": ["tcp", "syn", "udp"],
            "port_profiles": list(self.port_profiles.keys()),
            "timeout": self.timeout,
            "dependencies": {
                "nmap": {
                    "required": True,
                    "version": nmap_version,
                    "available": self.executor.check_tool_exists("nmap"),
                }
            },
            "options": {
                "ports": "Port specification (quick, top100, top1000, common, all, or custom)",
                "scan_type": "Scan type (tcp, syn, udp)",
                "timing": "Timing template (0-5)",
                "no_ping": "Skip host discovery",
                "nmap_args": "Additional nmap arguments",
            },
        }

    def quick_scan(self, target: str) -> ScanResult:
        """
        Perform a quick port scan

        Args:
            target: Target to scan

        Returns:
            ScanResult: Scan results
        """
        options = {"ports": "quick", "timing": 4, "no_ping": False}
        return self.scan(target, options)

    def full_scan(self, target: str) -> ScanResult:
        """
        Perform a comprehensive port scan

        Args:
            target: Target to scan

        Returns:
            ScanResult: Scan results
        """
        options = {
            "ports": "top1000",
            "timing": 3,
            "no_ping": False,
            "nmap_args": ["-A"],  # Aggressive scan
        }
        return self.scan(target, options)
