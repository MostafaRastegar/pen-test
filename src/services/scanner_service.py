"""
Scanner Service
Handles individual scanner operations
Following Single Responsibility Principle
Updated for Phase 2.3: Network Vulnerability Scanner (Backward Compatible)
"""

from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

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
            if (
                options.get("output")
                or options.get("save_raw")
                or any(
                    options.get(fmt, False)
                    for fmt in [
                        "json_report",
                        "html_report",
                        "pdf_report",
                        "all_reports",
                    ]
                )
            ):
                output_dir = Path(
                    options.get("output_dir", options.get("output", "output/reports"))
                )
                output_dir.mkdir(parents=True, exist_ok=True)

                # Save JSON result (raw scan data)
                if options.get("save_raw", True):
                    json_file = (
                        output_dir
                        / f"{scan_type}_{result.target.replace('/', '_').replace(':', '_')}_{result.start_time.strftime('%Y%m%d_%H%M%S')}.json"
                    )
                    result.save_to_file(json_file)
                    log_info(f"📄 Raw results saved to: {json_file}")

                # Generate formatted reports if requested
                report_generated = False

                if options.get("json_report") or options.get("all_reports"):
                    json_report_file = (
                        output_dir
                        / f"{scan_type}_report_{result.target.replace('/', '_').replace(':', '_')}_{result.start_time.strftime('%Y%m%d_%H%M%S')}.json"
                    )
                    self._generate_json_report(result, scan_type, json_report_file)
                    log_info(f"📊 JSON report saved to: {json_report_file}")
                    report_generated = True

                if options.get("html_report") or options.get("all_reports"):
                    html_report_file = (
                        output_dir
                        / f"{scan_type}_report_{result.target.replace('/', '_').replace(':', '_')}_{result.start_time.strftime('%Y%m%d_%H%M%S')}.html"
                    )
                    self._generate_html_report(result, scan_type, html_report_file)
                    log_info(f"🌐 HTML report saved to: {html_report_file}")
                    report_generated = True

                if options.get("pdf_report") or options.get("all_reports"):
                    try:
                        pdf_report_file = (
                            output_dir
                            / f"{scan_type}_report_{result.target.replace('/', '_').replace(':', '_')}_{result.start_time.strftime('%Y%m%d_%H%M%S')}.pdf"
                        )
                        self._generate_pdf_report(result, scan_type, pdf_report_file)
                        log_info(f"📑 PDF report saved to: {pdf_report_file}")
                        report_generated = True
                    except Exception as e:
                        log_warning(f"⚠️ PDF generation failed: {e}")
                        log_info(
                            "💡 Install weasyprint or wkhtmltopdf for PDF generation"
                        )

                if report_generated:
                    log_success(f"✅ Reports generated in: {output_dir}")

        except Exception as e:
            log_error(f"Error saving results: {e}")

    def _generate_json_report(self, result, scan_type: str, output_file: Path) -> None:
        """Generate formatted JSON report"""
        try:
            report_data = {
                "scan_info": {
                    "type": scan_type,
                    "target": result.target,
                    "scanner": result.scanner_name,
                    "start_time": result.start_time.isoformat(),
                    "end_time": (
                        result.end_time.isoformat() if result.end_time else None
                    ),
                    "duration": (
                        str(result.end_time - result.start_time)
                        if result.end_time
                        else None
                    ),
                    "status": result.status.value,
                },
                "summary": {
                    "total_findings": len(result.findings),
                    "severity_breakdown": self._get_severity_breakdown(result.findings),
                    "unique_vulnerabilities": len(
                        set(f.get("id", "") for f in result.findings)
                    ),
                },
                "findings": result.findings,
                "metadata": result.metadata,
                "errors": result.errors,
                "generated_at": datetime.now().isoformat(),
                "generator": "Auto-Pentest Framework v0.9.6",
            }

            with open(output_file, "w", encoding="utf-8") as f:
                import json

                json.dump(report_data, f, indent=2, ensure_ascii=False)

        except Exception as e:
            log_error(f"Failed to generate JSON report: {e}")

    def _generate_html_report(self, result, scan_type: str, output_file: Path) -> None:
        """Generate HTML report"""
        try:
            html_content = self._create_html_report_content(result, scan_type)

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

        except Exception as e:
            log_error(f"Failed to generate HTML report: {e}")

    def _generate_pdf_report(self, result, scan_type: str, output_file: Path) -> None:
        """Generate PDF report"""
        try:
            # First generate HTML
            html_content = self._create_html_report_content(result, scan_type)

            # Try different PDF libraries
            try:
                import weasyprint

                html_doc = weasyprint.HTML(string=html_content)
                html_doc.write_pdf(str(output_file))
            except ImportError:
                try:
                    import pdfkit

                    pdfkit.from_string(html_content, str(output_file))
                except ImportError:
                    raise ImportError(
                        "Neither weasyprint nor pdfkit available for PDF generation"
                    )

        except Exception as e:
            log_error(f"Failed to generate PDF report: {e}")
            raise

    def _create_html_report_content(self, result, scan_type: str) -> str:
        """Create HTML report content"""
        severity_breakdown = self._get_severity_breakdown(result.findings)

        # Calculate risk score
        risk_score = (
            severity_breakdown.get("critical", 0) * 10
            + severity_breakdown.get("high", 0) * 7
            + severity_breakdown.get("medium", 0) * 4
            + severity_breakdown.get("low", 0) * 2
            + severity_breakdown.get("info", 0) * 1
        )

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{scan_type.replace('_', ' ').title()} Report - {result.target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; }}
        .header h1 {{ color: #2c3e50; margin: 0; font-size: 2.5em; }}
        .header .subtitle {{ color: #7f8c8d; font-size: 1.2em; margin-top: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
        .summary-card h3 {{ margin: 0; font-size: 2em; }}
        .summary-card p {{ margin: 5px 0 0 0; opacity: 0.9; }}
        .severity-critical {{ background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%); }}
        .severity-high {{ background: linear-gradient(135deg, #ffa726 0%, #ff9800 100%); }}
        .severity-medium {{ background: linear-gradient(135deg, #ffeb3b 0%, #ffc107 100%); color: #333; }}
        .severity-low {{ background: linear-gradient(135deg, #66bb6a 0%, #4caf50 100%); }}
        .severity-info {{ background: linear-gradient(135deg, #42a5f5 0%, #2196f3 100%); }}
        .findings {{ margin-top: 30px; }}
        .finding {{ background: white; border-left: 5px solid #3498db; margin: 15px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .finding.critical {{ border-left-color: #e74c3c; }}
        .finding.high {{ border-left-color: #f39c12; }}
        .finding.medium {{ border-left-color: #f1c40f; }}
        .finding.low {{ border-left-color: #27ae60; }}
        .finding.info {{ border-left-color: #3498db; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .finding-title {{ font-size: 1.3em; font-weight: bold; color: #2c3e50; }}
        .severity-badge {{ padding: 5px 15px; border-radius: 20px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }}
        .severity-badge.critical {{ background: #e74c3c; color: white; }}
        .severity-badge.high {{ background: #f39c12; color: white; }}
        .severity-badge.medium {{ background: #f1c40f; color: #333; }}
        .severity-badge.low {{ background: #27ae60; color: white; }}
        .severity-badge.info {{ background: #3498db; color: white; }}
        .finding-details {{ color: #555; line-height: 1.6; }}
        .metadata {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin-top: 20px; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #bdc3c7; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{scan_type.replace('_', ' ').title()} Security Report</h1>
            <div class="subtitle">Target: {result.target} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>{len(result.findings)}</h3>
                <p>Total Findings</p>
            </div>
            <div class="summary-card severity-critical">
                <h3>{severity_breakdown.get('critical', 0)}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card severity-high">
                <h3>{severity_breakdown.get('high', 0)}</h3>
                <p>High</p>
            </div>
            <div class="summary-card severity-medium">
                <h3>{severity_breakdown.get('medium', 0)}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card severity-low">
                <h3>{severity_breakdown.get('low', 0)}</h3>
                <p>Low</p>
            </div>
            <div class="summary-card severity-info">
                <h3>{severity_breakdown.get('info', 0)}</h3>
                <p>Info</p>
            </div>
        </div>

        <div class="findings">
            <h2>Detailed Findings</h2>
"""

        # Add findings
        for i, finding in enumerate(result.findings, 1):
            severity = finding.get("severity", "info")
            html_content += f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">{i}. {finding.get('title', 'Security Finding')}</div>
                    <div class="severity-badge {severity}">{severity}</div>
                </div>
                <div class="finding-details">
                    <p><strong>ID:</strong> {finding.get('id', 'N/A')}</p>
                    <p><strong>Description:</strong> {finding.get('description', 'No description available')}</p>
                    <p><strong>Target:</strong> {finding.get('matched_at', 'N/A')}</p>
                    <p><strong>Recommendation:</strong> {finding.get('recommendation', 'Review and remediate this security issue')}</p>
                </div>
            </div>
"""

        html_content += f"""
        </div>

        <div class="metadata">
            <h3>Scan Information</h3>
            <p><strong>Scanner:</strong> {result.scanner_name}</p>
            <p><strong>Start Time:</strong> {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>End Time:</strong> {result.end_time.strftime('%Y-%m-%d %H:%M:%S') if result.end_time else 'N/A'}</p>
            <p><strong>Duration:</strong> {str(result.end_time - result.start_time) if result.end_time else 'N/A'}</p>
            <p><strong>Status:</strong> {result.status.value}</p>
        </div>

        <div class="footer">
            <p>Generated by Auto-Pentest Framework v0.9.6 | Network Vulnerability Scanner</p>
        </div>
    </div>
</body>
</html>
"""
        return html_content

    def _get_severity_breakdown(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get breakdown of findings by severity"""
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for finding in findings:
            severity = finding.get("severity", "info")
            if severity in breakdown:
                breakdown[severity] += 1

        return breakdown
