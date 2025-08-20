"""
Scanner Service
Handles individual scanner operations
Following Single Responsibility Principle
"""

from typing import Dict, Any, Optional
from pathlib import Path

from ..scanners.recon.port_scanner import PortScanner
from ..scanners.recon.dns_scanner import DNSScanner
from ..scanners.vulnerability.web_scanner import WebScanner
from ..scanners.vulnerability.directory_scanner import DirectoryScanner
from ..scanners.vulnerability.ssl_scanner import SSLScanner
from ..utils.target_parser import TargetParser
from ..utils.logger import log_info, log_error, log_success
from ..services.report_service import ReportService
from ..scanners.security.waf_scanner import WAFScanner


class ScannerService:
    """Service for running individual scanners"""

    def __init__(self):
        self.target_parser = TargetParser()
        self.report_service = ReportService()

    def run_port_scan(
        self,
        target: str,
        ports: str,
        scan_type: str,
        fast: bool,
        options: Dict[str, Any],
    ) -> None:
        """Run port scanning"""
        try:
            log_info(f"🔍 Starting port scan on {target}")

            # Parse target
            parsed_target = self.target_parser.parse_target(target)

            # Configure scanner
            scanner = PortScanner(timeout=options.get("timeout", 300))

            # Prepare scan options
            scan_options = {
                "ports": ports,
                "scan_type": scan_type,
                "fast_scan": fast,
                "verbose": options.get("verbose", False),
            }

            # Execute scan
            result = scanner.scan(parsed_target["host"], scan_options)

            # Display results
            self._display_scanner_results(result, "Port Scan")

            # Save results if requested
            self._save_scanner_results(result, "port_scan", options)

            log_success("✅ Port scan completed")

        except Exception as e:
            log_error(f"❌ Port scan failed: {e}")
            raise

    def run_dns_scan(
        self,
        target: str,
        subdomain_enum: bool,
        zone_transfer: bool,
        dns_bruteforce: bool,
        options: Dict[str, Any],
    ) -> None:
        """Run DNS enumeration"""
        try:
            log_info(f"🔍 Starting DNS scan on {target}")

            # Parse target
            parsed_target = self.target_parser.parse_target(target)

            # Configure scanner
            scanner = DNSScanner(timeout=options.get("timeout", 300))

            # Prepare scan options
            scan_options = {
                "subdomain_enum": subdomain_enum,
                "zone_transfer": zone_transfer,
                "dns_bruteforce": dns_bruteforce,
                "verbose": options.get("verbose", False),
            }

            # Execute scan
            result = scanner.scan(parsed_target["domain"], scan_options)

            # Display results
            self._display_scanner_results(result, "DNS Scan")

            # Save results if requested
            self._save_scanner_results(result, "dns_scan", options)

            log_success("✅ DNS scan completed")

        except Exception as e:
            log_error(f"❌ DNS scan failed: {e}")
            raise

    def run_web_scan(
        self,
        target: str,
        use_nikto: bool,
        directory_enum: bool,
        ssl_analysis: bool,
        options: Dict[str, Any],
    ) -> None:
        """Run web vulnerability scanning"""
        try:
            log_info(f"🔍 Starting web scan on {target}")

            # Parse target
            parsed_target = self.target_parser.parse_target(target)

            # Configure scanner
            scanner = WebScanner(timeout=options.get("timeout", 600))

            # Prepare scan options
            scan_options = {
                "use_nikto": use_nikto,
                "include_directory_enum": directory_enum,
                "include_ssl_analysis": ssl_analysis,
                "verbose": options.get("verbose", False),
            }

            # Execute scan
            result = scanner.scan(parsed_target["url"], scan_options)

            # Display results
            self._display_scanner_results(result, "Web Scan")

            # Save results if requested
            self._save_scanner_results(result, "web_scan", options)

            log_success("✅ Web scan completed")

        except Exception as e:
            log_error(f"❌ Web scan failed: {e}")
            raise

    def run_directory_scan(
        self,
        target: str,
        tool: str,
        wordlist: Optional[str],
        extensions: Optional[str],
        options: Dict[str, Any],
    ) -> None:
        """Run directory enumeration"""
        try:
            log_info(f"🔍 Starting directory scan on {target}")

            # Parse target
            parsed_target = self.target_parser.parse_target(target)

            # Configure scanner
            scanner = DirectoryScanner(timeout=options.get("timeout", 600))

            # Prepare scan options
            scan_options = {
                "tool": tool,
                "wordlist": wordlist,
                "extensions": extensions.split(",") if extensions else None,
                "verbose": options.get("verbose", False),
            }

            # Execute scan
            result = scanner.scan(parsed_target["url"], scan_options)

            # Display results
            self._display_scanner_results(result, "Directory Scan")

            # Save results if requested
            self._save_scanner_results(result, "directory_scan", options)

            log_success("✅ Directory scan completed")

        except Exception as e:
            log_error(f"❌ Directory scan failed: {e}")
            raise

    def run_ssl_scan(
        self,
        target: str,
        cipher_enum: bool,
        cert_info: bool,
        vulnerabilities: bool,
        options: Dict[str, Any],
    ) -> None:
        """Run SSL/TLS analysis"""
        try:
            log_info(f"🔍 Starting SSL scan on {target}")

            # Parse target
            parsed_target = self.target_parser.parse_target(target)

            # Configure scanner
            scanner = SSLScanner(timeout=options.get("timeout", 300))

            # Prepare scan options
            scan_options = {
                "cipher_enum": cipher_enum,
                "cert_info": cert_info,
                "vulnerabilities": vulnerabilities,
                "verbose": options.get("verbose", False),
            }

            # Execute scan
            result = scanner.scan(parsed_target["host"], scan_options)

            # Display results
            self._display_scanner_results(result, "SSL Scan")

            # Save results if requested
            self._save_scanner_results(result, "ssl_scan", options)

            log_success("✅ SSL scan completed")

        except Exception as e:
            log_error(f"❌ SSL scan failed: {e}")
            raise

    def run_waf_scan(
        self,
        target: str,
        aggressive: bool,
        detection_only: bool,
        timeout: int,
        options: Dict[str, Any],
    ) -> None:
        """Run WAF detection and bypass testing"""
        try:
            log_info(f"🛡️ Starting WAF detection scan on {target}")

            # Parse target
            parsed_target = self.target_parser.parse_target(target)

            # Configure scanner
            scanner = WAFScanner(timeout=timeout)

            # Prepare scan options
            scan_options = {
                "aggressive": aggressive,
                "detection_only": detection_only,
                "verbose": options.get("verbose", False),
            }

            # Execute scan
            result = scanner.scan(parsed_target["host"], scan_options)

            # Display results
            self._display_scanner_results(result, "WAF Detection")

            # Save results if requested
            self._save_scanner_results(result, "waf", options)

            log_success(f"✅ WAF detection scan completed for {target}")

        except Exception as e:
            log_error(f"WAF scan failed: {e}")
            raise

    def _display_scanner_results(self, result, scan_type: str) -> None:
        """Display scanner results in a formatted way"""
        if not result or not result.findings:
            log_info(f"📄 {scan_type}: No findings")
            return

        log_info(f"📄 {scan_type} Results:")
        log_info(f"   Found {len(result.findings)} items")

        # Show summary of findings by severity
        severities = {}
        for finding in result.findings:
            sev = finding.get("severity", "info")
            severities[sev] = severities.get(sev, 0) + 1

        for severity, count in severities.items():
            log_info(f"   {severity.upper()}: {count}")

    def _save_scanner_results(
        self, result, scan_type: str, options: Dict[str, Any]
    ) -> None:
        """Save scanner results with automatic report generation"""

        # Always generate reports for individual scanner commands
        # Set default output directory if not specified
        if not options.get("output") and not options.get("save_raw"):
            # Enable automatic saving with default location
            options["output"] = "output/reports"
            options["save_raw"] = True
            options["json_output"] = True  # Always generate JSON by default

            log_info(f"Auto-generating reports in: {options['output']}")

        if not options.get("output") and not options.get("save_raw"):
            return

        try:
            # Create single-scanner workflow result for report generation
            from ..orchestrator.workflow import WorkflowResult, ScanTask, WorkflowStatus
            from datetime import datetime

            # Create a simple task for this result
            task = ScanTask(
                scanner_name=result.scanner_name,
                scanner_class=type(None),  # Not needed for reporting
                target=result.target,
                result=result,
                status=result.status,
            )

            # Create workflow result
            workflow_result = WorkflowResult(
                workflow_id=f"single_{scan_type}_{int(datetime.now().timestamp())}",
                target=result.target,
                status=WorkflowStatus.COMPLETED,
                start_time=result.start_time,
                end_time=result.end_time,
                tasks=[task],
            )

            # Generate reports
            self.report_service.generate_reports(workflow_result, options)

        except Exception as e:
            log_error(f"Failed to save {scan_type} results: {e}")
            # Don't raise exception - continue execution even if reporting fails
