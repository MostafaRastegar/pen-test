"""
Scanner Service
Handles individual scanner operations
Following Single Responsibility Principle
Updated for Phase 2.3: Network Vulnerability Scanner (Backward Compatible)
"""

from typing import Dict, Any, Optional
from pathlib import Path

from ..scanners.recon.port_scanner import PortScanner
from ..scanners.recon.dns_scanner import DNSScanner
from ..scanners.vulnerability.web_scanner import WebScanner
from ..scanners.vulnerability.directory_scanner import DirectoryScanner
from ..scanners.vulnerability.ssl_scanner import SSLScanner
from ..utils.target_parser import TargetParser
from ..utils.logger import log_info, log_error, log_success, log_warning
from ..services.report_service import ReportService

# Optional imports for backward compatibility
try:
    from ..scanners.vulnerability.network_scanner import NetworkScanner
except ImportError:
    NetworkScanner = None
    log_warning("⚠️  NetworkScanner not available - network scanning disabled")

try:
    from ..scanners.security.waf_scanner import WAFScanner
except ImportError:
    WAFScanner = None
    log_warning("⚠️  WAFScanner not available - WAF scanning disabled")


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

    def run_network_scan(
        self,
        target: str,
        templates: str,
        rate_limit: int,
        service_analysis: bool,
        protocol_analysis: bool,
        template_path: Optional[str],
        timeout: int,
        options: Dict[str, Any],
    ) -> None:
        """Run network vulnerability scanning (Phase 2.3)"""
        try:
            # Check if NetworkScanner is available
            if NetworkScanner is None:
                log_error(
                    "❌ NetworkScanner not available. Please install required dependencies."
                )
                raise ImportError("NetworkScanner module not found")

            log_info(f"🔍 Starting network vulnerability scan on {target}")

            # Parse target
            parsed_target = self.target_parser.parse_target(target)

            # Configure scanner
            scanner = NetworkScanner(timeout=timeout)

            # Prepare scan options
            scan_options = {
                "templates": templates,
                "rate_limit": rate_limit,
                "service_analysis": service_analysis,
                "protocol_analysis": protocol_analysis,
                "template_path": template_path,
                "verbose": options.get("verbose", False),
            }

            # Execute scan
            result = scanner.scan(parsed_target.get("host", target), scan_options)

            # Display results
            self._display_scanner_results(result, "Network Vulnerability Scan")

            # Save results if requested
            self._save_scanner_results(result, "network_scan", options)

            log_success("✅ Network vulnerability scan completed")

        except ImportError as e:
            log_error(f"❌ Network scanner not available: {e}")
            raise
        except Exception as e:
            log_error(f"❌ Network vulnerability scan failed: {e}")
            raise

    def run_wordpress_scan(
        self,
        target: str,
        plugin_check: bool,
        theme_check: bool,
        user_enum: bool,
        brute_force_test: bool,
        wpscan_api_token: Optional[str],
        timeout: int,
        options: Dict[str, Any],
    ) -> None:
        """Run WordPress CMS security scanning (Phase 1.1)"""
        try:
            log_info(f"🔍 Starting WordPress scan on {target}")

            # Parse target
            parsed_target = self.target_parser.parse_target(target)

            # Try to import WordPress scanner
            try:
                from ..scanners.cms.wordpress_scanner import WordPressScanner
            except ImportError:
                log_error(
                    "❌ WordPressScanner not available. Please install required dependencies."
                )
                raise ImportError("WordPressScanner module not found")

            # Configure scanner
            scanner = WordPressScanner(timeout=timeout)

            # Prepare scan options
            scan_options = {
                "plugin_check": plugin_check,
                "theme_check": theme_check,
                "user_enum": user_enum,
                "brute_force_test": brute_force_test,
                "wpscan_api_token": wpscan_api_token,
                "verbose": options.get("verbose", False),
            }

            # Execute scan
            result = scanner.scan(parsed_target["url"], scan_options)

            # Display results
            self._display_scanner_results(result, "WordPress Security Scan")

            # Save results if requested
            self._save_scanner_results(result, "wordpress_scan", options)

            log_success("✅ WordPress scan completed")

        except ImportError as e:
            log_error(f"❌ WordPress scanner not available: {e}")
            raise
        except Exception as e:
            log_error(f"❌ WordPress scan failed: {e}")
            raise

    def run_api_scan(
        self,
        target: str,
        timeout: int,
        rate_limit_test: bool,
        graphql_test: bool,
        jwt_analysis: bool,
        owasp_only: bool,
        auth_header: Optional[str],
        swagger_url: Optional[str],
        options: Dict[str, Any],
    ) -> None:
        """Run API security scanning (Phase 2.1)"""
        try:
            log_info(f"🔍 Starting API security scan on {target}")

            # Parse target
            parsed_target = self.target_parser.parse_target(target)

            # Try to import API scanner
            try:
                from ..scanners.api.api_scanner import APISecurityScanner
            except ImportError:
                log_error(
                    "❌ APISecurityScanner not available. Please install required dependencies."
                )
                raise ImportError("APISecurityScanner module not found")

            # Configure scanner
            scanner = APISecurityScanner(timeout=timeout)

            # Prepare scan options
            scan_options = {
                "rate_limit_test": rate_limit_test,
                "graphql_test": graphql_test,
                "jwt_analysis": jwt_analysis,
                "owasp_only": owasp_only,
                "auth_header": auth_header,
                "swagger_url": swagger_url,
                "verbose": options.get("verbose", False),
            }

            # Execute scan
            result = scanner.scan(parsed_target["url"], scan_options)

            # Display results
            self._display_scanner_results(result, "API Security Scan")

            # Save results if requested
            self._save_scanner_results(result, "api_scan", options)

            log_success("✅ API security scan completed")

        except ImportError as e:
            log_error(f"❌ API scanner not available: {e}")
            raise
        except Exception as e:
            log_error(f"❌ API security scan failed: {e}")
            raise

    def run_waf_scan(
        self,
        target: str,
        aggressive: bool,
        detection_only: bool,
        timeout: int,
        options: Dict[str, Any],
    ) -> None:
        """Run WAF detection and bypass testing (Phase 2.2)"""
        try:
            # Check if WAFScanner is available
            if WAFScanner is None:
                log_error(
                    "❌ WAFScanner not available. Please install required dependencies."
                )
                raise ImportError("WAFScanner module not found")

            log_info(f"🔍 Starting WAF detection scan on {target}")

            # Parse target
            parsed_target = self.target_parser.parse_target(target)

            # Configure scanner
            scanner = WAFScanner(timeout=timeout)

            # Prepare scan options
            scan_options = {
                "aggressive": aggressive,
                "detection_only": detection_only,
                "quick_mode": options.get("quick_mode", False),
                "verbose": options.get("verbose", False),
            }

            # Execute scan
            result = scanner.scan(parsed_target["url"], scan_options)

            # Display results
            self._display_scanner_results(result, "WAF Detection Scan")

            # Save results if requested
            self._save_scanner_results(result, "waf_scan", options)

            log_success("✅ WAF detection scan completed")

        except ImportError as e:
            log_error(f"❌ WAF scanner not available: {e}")
            raise
        except Exception as e:
            log_error(f"❌ WAF detection scan failed: {e}")
            raise

    def _display_scanner_results(self, result, scan_type: str) -> None:
        """Display scanner results in a formatted way"""
        try:
            log_info(f"📊 {scan_type} Results Summary:")
            log_info(f"Target: {result.target}")
            log_info(f"Status: {result.status.value}")
            log_info(f"Findings: {len(result.findings)}")

            if result.errors:
                log_error(f"Errors: {len(result.errors)}")
                for error in result.errors:
                    log_error(f"  - {error}")

            # Display findings by severity
            if result.findings:
                severity_counts = {}
                for finding in result.findings:
                    severity = finding.get("severity", "info")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

                for severity, count in severity_counts.items():
                    log_info(f"  {severity.upper()}: {count}")

        except Exception as e:
            log_error(f"Error displaying results: {e}")

    def _save_scanner_results(
        self, result, scan_type: str, options: Dict[str, Any]
    ) -> None:
        """Save scanner results if requested"""
        try:
            if options.get("output") or options.get("save_raw"):
                output_dir = Path(options.get("output", "output/reports"))
                output_dir.mkdir(parents=True, exist_ok=True)

                # Save JSON result
                json_file = (
                    output_dir
                    / f"{scan_type}_{result.target}_{result.start_time.strftime('%Y%m%d_%H%M%S')}.json"
                )
                result.save_to_file(json_file)
                log_info(f"Results saved to: {json_file}")

                # Generate reports if requested
                if any(
                    options.get(fmt, False)
                    for fmt in [
                        "json_report",
                        "html_report",
                        "pdf_report",
                        "all_reports",
                    ]
                ):
                    self.report_service.generate_scanner_report(
                        result, scan_type, options
                    )

        except Exception as e:
            log_error(f"Error saving results: {e}")
