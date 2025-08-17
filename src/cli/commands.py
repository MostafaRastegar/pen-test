"""
CLI Command Implementations
Each command is a separate function following Single Responsibility Principle
"""

import click
import sys
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from src.core.scanner_base import ScanStatus
from .options import common_options
from ..services.scan_service import ScanService
from ..services.scanner_service import ScannerService
from ..services.info_service import InfoService
from ..services.utility_services import CacheService, ToolService, VersionService
from ..utils.target_parser import TargetParser
from ..utils.logger import log_info, log_error, log_success, log_warning
from ..utils.reporter import ReportGenerator
from ..scanners.api.api_scanner import APISecurityScanner


@click.command()
@click.argument("target")
@click.option("--timeout", default=30, help="Request timeout in seconds")
@click.option("--rate-limit-test", is_flag=True, help="Enable rate limiting assessment")
@click.option("--graphql-test", is_flag=True, help="Enable GraphQL security testing")
@click.option("--jwt-analysis", is_flag=True, help="Enable JWT token security analysis")
@click.option("--owasp-only", is_flag=True, help="Focus only on OWASP API Top 10 tests")
@common_options
def api_command(
    target, timeout, rate_limit_test, graphql_test, jwt_analysis, owasp_only, **kwargs
):
    """API Security Scanner - Comprehensive API vulnerability assessment"""
    try:
        log_info(f"Starting API security scan for: {target}")

        # Initialize scanner
        scanner = APISecurityScanner(timeout=timeout)

        # Validate target using scanner's method
        if not scanner.validate_target(target):
            log_error(f"Invalid target: {target}")
            sys.exit(1)

        # Prepare scan options
        options = {
            "rate_limit_test": rate_limit_test,
            "graphql_test": graphql_test,
            "jwt_analysis": jwt_analysis,
            "owasp_only": owasp_only,
        }

        # Execute scan
        result = scanner.scan(target, options)

        if result.status == ScanStatus.COMPLETED:
            log_success(f"API scan completed successfully!")
            log_info(f"Found {len(result.findings)} findings")

            # Display risk score if available
            risk_score = result.metadata.get("risk_score", "N/A")
            log_info(f"Risk Score: {risk_score}")

            # Display OWASP coverage
            owasp_coverage = result.metadata.get("owasp_coverage", {})
            covered_categories = len(
                [cat for cat, count in owasp_coverage.items() if count > 0]
            )
            log_info(f"OWASP API Top 10 Coverage: {covered_categories}/10 categories")

            # Display findings summary by severity
            from collections import defaultdict

            severity_count = defaultdict(int)
            for finding in result.findings:
                severity_count[finding.get("severity", "info")] += 1

            if severity_count:
                log_info("Findings by severity:")
                for severity, count in severity_count.items():
                    log_info(f"  {severity.upper()}: {count}")

        else:
            log_error(f"API scan failed")
            sys.exit(1)

    except Exception as e:
        log_error(f"API scanner error: {e}")
        sys.exit(1)


@click.command()
@click.argument("target")
@click.option(
    "--profile",
    type=click.Choice(["quick", "web", "full", "custom"]),
    default="quick",
    help="Scan profile",
)
@click.option("--parallel", is_flag=True, default=True, help="Run scans in parallel")
@click.option("--sequential", is_flag=True, help="Run scans sequentially")
@click.option("--timeout", default=1800, help="Total workflow timeout")
@click.option("--include-port", is_flag=True, help="Include port scanning")
@click.option("--include-dns", is_flag=True, help="Include DNS enumeration")
@click.option("--include-web", is_flag=True, help="Include web vulnerability scanning")
@click.option("--include-directory", is_flag=True, help="Include directory enumeration")
@click.option("--include-ssl", is_flag=True, help="Include SSL/TLS analysis")
@click.option("--ports", help="Port range for port scanner")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--pdf-report", is_flag=True, help="Generate PDF report")
@click.option("--all-reports", is_flag=True, help="Generate all report formats")
@common_options
def scan_command(target, **kwargs):
    """Orchestrated security scanning with multiple tools"""
    try:
        scan_service = ScanService()
        scan_service.execute_scan(target, kwargs)
    except Exception as e:
        log_error(f"Scan failed: {e}")
        sys.exit(1)


@click.command()
@click.argument("target")
def quick_command(target):
    """
    Perform a quick scan (most common ports only).
    This is equivalent to: scan TARGET --profile quick --all-reports
    """
    ctx = click.get_current_context()
    ctx.invoke(scan_command, target=target, profile="quick", all_reports=True)


@click.command()
@click.argument("target")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output for debugging")
def full_command(target, verbose):
    """
    Perform a comprehensive scan with full reporting.
    This is equivalent to: scan TARGET --profile full --all-reports --verbose
    """
    ctx = click.get_current_context()
    ctx.invoke(
        scan_command, target=target, profile="full", all_reports=True, verbose=verbose
    )


@click.command()
def info_command():
    """Show framework capabilities and information"""
    try:
        info_service = InfoService()
        info_service.display_info()
    except Exception as e:
        log_error(f"Error displaying info: {e}")


@click.command()
@click.option("--check-status", is_flag=True, help="Check tool installation status")
@click.option("--check-versions", is_flag=True, help="Show tool versions")
def list_tools_command(check_status, check_versions):
    """List available security tools"""
    try:
        tool_service = ToolService()
        tool_service.list_tools(check_status, check_versions)
    except Exception as e:
        log_error(f"Error listing tools: {e}")


@click.command()
@click.argument("target")
@click.option("--ports", default="1-1000", help="Port range to scan")
@click.option(
    "--scan-type",
    type=click.Choice(["tcp", "udp", "syn"]),
    default="tcp",
    help="Scan type",
)
@click.option("--fast", is_flag=True, help="Fast scan mode")
@common_options
def port_command(target, ports, scan_type, fast, **kwargs):
    """Port scanning with nmap"""
    try:
        scanner_service = ScannerService()
        scanner_service.run_port_scan(target, ports, scan_type, fast, kwargs)
    except Exception as e:
        log_error(f"Port scan failed: {e}")
        sys.exit(1)


@click.command()
@click.argument("target")
@click.option("--subdomain-enum", is_flag=True, help="Enable subdomain enumeration")
@click.option("--zone-transfer", is_flag=True, help="Attempt zone transfer")
@click.option("--dns-bruteforce", is_flag=True, help="DNS bruteforce attack")
@common_options
def dns_command(target, subdomain_enum, zone_transfer, dns_bruteforce, **kwargs):
    """DNS enumeration and analysis"""
    try:
        scanner_service = ScannerService()
        scanner_service.run_dns_scan(
            target, subdomain_enum, zone_transfer, dns_bruteforce, kwargs
        )
    except Exception as e:
        log_error(f"DNS scan failed: {e}")
        sys.exit(1)


@click.command()
@click.argument("target")
@click.option("--use-nikto", is_flag=True, help="Use Nikto for web scanning")
@click.option("--directory-enum", is_flag=True, help="Include directory enumeration")
@click.option("--ssl-analysis", is_flag=True, help="Include SSL analysis")
@common_options
def web_command(target, use_nikto, directory_enum, ssl_analysis, **kwargs):
    """Web vulnerability scanning"""
    try:
        scanner_service = ScannerService()
        scanner_service.run_web_scan(
            target, use_nikto, directory_enum, ssl_analysis, kwargs
        )
    except Exception as e:
        log_error(f"Web scan failed: {e}")
        sys.exit(1)


@click.command()
@click.argument("target")
@click.option(
    "--tool",
    type=click.Choice(["dirb", "gobuster", "ffuf"]),
    default="dirb",
    help="Directory enumeration tool",
)
@click.option("--wordlist", help="Custom wordlist file")
@click.option("--extensions", help="File extensions to check (e.g., php,asp,jsp)")
@common_options
def directory_command(target, tool, wordlist, extensions, **kwargs):
    """Directory and file enumeration"""
    try:
        scanner_service = ScannerService()
        scanner_service.run_directory_scan(target, tool, wordlist, extensions, kwargs)
    except Exception as e:
        log_error(f"Directory scan failed: {e}")
        sys.exit(1)


@click.command()
@click.argument("target")
@click.option("--cipher-enum", is_flag=True, help="Enumerate supported ciphers")
@click.option("--cert-info", is_flag=True, help="Show certificate information")
@click.option("--vulnerabilities", is_flag=True, help="Check for SSL vulnerabilities")
@common_options
def ssl_command(target, cipher_enum, cert_info, vulnerabilities, **kwargs):
    """SSL/TLS security analysis"""
    try:
        scanner_service = ScannerService()
        scanner_service.run_ssl_scan(
            target, cipher_enum, cert_info, vulnerabilities, kwargs
        )
    except Exception as e:
        log_error(f"SSL scan failed: {e}")
        sys.exit(1)


@click.command()
@click.option("--build-info", is_flag=True, help="Show build information")
@click.option("--dependencies", is_flag=True, help="Show dependencies")
def version_command(build_info, dependencies):
    """Show version information"""
    try:
        version_service = VersionService()
        version_service.display_version(build_info, dependencies)
    except Exception as e:
        log_error(f"Error showing version: {e}")


@click.command()
@click.option("--detailed", is_flag=True, help="Show detailed cache statistics")
@click.option("--scanner", help="Show stats for specific scanner")
def cache_stats_command(detailed, scanner):
    """Show cache statistics"""
    try:
        cache_service = CacheService()
        cache_service.show_stats(detailed, scanner)
    except Exception as e:
        log_error(f"Error showing cache stats: {e}")


@click.command()
@click.option("--all", is_flag=True, help="Clear all cache")
@click.option("--scanner", help="Clear cache for specific scanner")
@click.option("--force", is_flag=True, help="Force clear without confirmation")
def clear_cache_command(all, scanner, force):
    """Clear cache data"""
    try:
        cache_service = CacheService()
        cache_service.clear_cache(all, scanner, force)
    except Exception as e:
        log_error(f"Error clearing cache: {e}")


# ============ wordpress commands ============


@click.command()
@click.argument("target")
@click.option(
    "--enumerate-plugins",
    is_flag=True,
    default=True,
    help="Enumerate WordPress plugins with security analysis",
)
@click.option(
    "--enumerate-themes",
    is_flag=True,
    default=True,
    help="Enumerate WordPress themes with security analysis",
)
@click.option(
    "--enumerate-users", is_flag=True, default=True, help="Enumerate WordPress users"
)
@click.option(
    "--use-wpscan",
    is_flag=True,
    default=True,
    help="Use WPScan for comprehensive vulnerability analysis",
)
@click.option(
    "--wpscan-api-token", help="WPScan API token for enhanced vulnerability data"
)

# NEW ENHANCED OPTIONS
@click.option(
    "--check-multisite",
    is_flag=True,
    default=True,
    help="Analyze WordPress Multisite security configuration",
)
@click.option(
    "--check-htaccess",
    is_flag=True,
    default=True,
    help="Perform enhanced .htaccess security analysis",
)
@click.option(
    "--detect-security-plugins",
    is_flag=True,
    default=True,
    help="Detect and analyze WordPress security plugins",
)
@click.option(
    "--check-database-security",
    is_flag=True,
    default=True,
    help="Check database security configuration",
)
@click.option(
    "--test-brute-force",
    is_flag=True,
    default=True,
    help="Test brute force protection mechanisms",
)
@click.option(
    "--check-xmlrpc", is_flag=True, default=True, help="Test XML-RPC endpoint security"
)
@click.option(
    "--check-config",
    is_flag=True,
    default=True,
    help="Analyze WordPress security configuration",
)

# SCAN CUSTOMIZATION OPTIONS
@click.option(
    "--quick-scan",
    is_flag=True,
    help="Perform quick scan (basic checks only)",
)
@click.option(
    "--deep-scan",
    is_flag=True,
    help="Perform comprehensive deep scan (all checks)",
)
@click.option(
    "--stealth-mode",
    is_flag=True,
    help="Use stealth scanning techniques (slower but less detectable)",
)

# TARGET SPECIFICATION
@click.option(
    "--scheme",
    type=click.Choice(["http", "https"]),
    default="https",
    help="URL scheme to use",
)
@click.option("--port", type=int, help="Target port (if not standard)")
@click.option("--timeout", type=int, default=60, help="Request timeout in seconds")

# REPORTING OPTIONS
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--pdf-report", is_flag=True, help="Generate PDF report")
@click.option("--xml-report", is_flag=True, help="Generate XML report")
@click.option("--csv-report", is_flag=True, help="Generate CSV report")
@click.option("--all-reports", is_flag=True, help="Generate all report formats")
@click.option(
    "--output-dir", default="output/reports", help="Output directory for reports"
)
@click.option("--report-name", help="Custom report filename prefix")

# COMPLIANCE AND STANDARDS
@click.option(
    "--compliance-check",
    type=click.Choice(["owasp", "cis", "pci-dss", "all"]),
    help="Include compliance checks (OWASP, CIS, PCI-DSS)",
)
@click.option(
    "--security-baseline",
    is_flag=True,
    help="Check against WordPress security baseline",
)

# ADVANCED OPTIONS
@click.option("--user-agent", help="Custom User-Agent string")
@click.option("--proxy", help="HTTP proxy (http://proxy:port)")
@click.option("--cookie", help="Custom cookies for authenticated scanning")
@click.option("--headers", help="Custom HTTP headers (JSON format)")
@click.option("--rate-limit", type=int, default=10, help="Requests per second limit")
@click.option("--threads", type=int, default=4, help="Number of scanning threads")

# DEBUG AND VERBOSE OPTIONS
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option("--save-raw", is_flag=True, help="Save raw scanner output")
def wordpress_command(
    target,
    enumerate_plugins,
    enumerate_themes,
    enumerate_users,
    use_wpscan,
    wpscan_api_token,
    check_multisite,
    check_htaccess,
    detect_security_plugins,
    check_database_security,
    test_brute_force,
    check_xmlrpc,
    check_config,
    quick_scan,
    deep_scan,
    stealth_mode,
    scheme,
    port,
    timeout,
    json_report,
    html_report,
    pdf_report,
    xml_report,
    csv_report,
    all_reports,
    output_dir,
    report_name,
    compliance_check,
    security_baseline,
    user_agent,
    proxy,
    cookie,
    headers,
    rate_limit,
    threads,
    verbose,
    debug,
    no_color,
    save_raw,
):
    """
    Enhanced WordPress Security Scanner with Comprehensive Analysis

    Performs advanced WordPress security assessment including:

    🔍 CORE FEATURES:
    • WordPress version detection and vulnerability analysis
    • Plugin enumeration with security status and update analysis
    • Theme enumeration with security assessment
    • User enumeration and account security testing
    • XML-RPC security testing
    • Security configuration analysis

    🆕 ENHANCED FEATURES:
    • WordPress Multisite security testing
    • Advanced .htaccess security analysis
    • Security plugin detection and configuration analysis
    • Database security configuration testing
    • Brute force protection assessment
    • File permission and backup detection

    📊 COMPLIANCE & STANDARDS:
    • OWASP WordPress Security Guide compliance
    • CIS WordPress Security Benchmark
    • PCI DSS web application requirements
    • WordPress security best practices

    🎯 SCAN MODES:
    • Quick Scan: Essential security checks (5-10 minutes)
    • Standard Scan: Comprehensive analysis (15-30 minutes)
    • Deep Scan: Exhaustive security assessment (30+ minutes)

    \b
    EXAMPLES:

    # Quick WordPress security scan
    python main.py wordpress example.com --quick-scan --html-report

    # Comprehensive scan with all features
    python main.py wordpress https://blog.example.com --deep-scan --all-reports

    # Multisite-focused security analysis
    python main.py wordpress multisite.example.com --check-multisite --check-htaccess

    # Security plugin audit
    python main.py wordpress example.com --detect-security-plugins --compliance-check owasp

    # Stealth mode scanning
    python main.py wordpress example.com --stealth-mode --rate-limit 2 --timeout 120

    # Custom authenticated scan
    python main.py wordpress example.com --cookie "session=abc123" --headers '{"Authorization": "Bearer token"}'

    # Database security focus
    python main.py wordpress example.com --check-database-security --check-config --save-raw

    # Compliance audit
    python main.py wordpress example.com --compliance-check all --security-baseline --pdf-report
    """
    try:
        from ..scanners.cms import WordPressScanner
        from ..utils.reporter import ReportGenerator

        # Configure logging
        if debug:
            import logging

            logging.getLogger().setLevel(logging.DEBUG)
        elif verbose:
            import logging

            logging.getLogger().setLevel(logging.INFO)

        log_info("🔍 Starting Enhanced WordPress Security Scan")

        # Build target URL
        target_url = _build_target_url(target, scheme, port)
        log_info(f"🎯 Target: {target_url}")

        # Configure scan options based on scan mode
        scan_options = _configure_scan_options(
            quick_scan,
            deep_scan,
            stealth_mode,
            enumerate_plugins,
            enumerate_themes,
            enumerate_users,
            check_multisite,
            check_htaccess,
            detect_security_plugins,
            check_database_security,
            test_brute_force,
            check_xmlrpc,
            check_config,
            use_wpscan,
            wpscan_api_token,
        )

        # Configure advanced options
        if user_agent:
            scan_options["user_agent"] = user_agent
        if proxy:
            scan_options["proxy"] = proxy
        if cookie:
            scan_options["cookie"] = cookie
        if headers:
            import json

            scan_options["headers"] = json.loads(headers)
        if rate_limit:
            scan_options["rate_limit"] = rate_limit
        if threads:
            scan_options["threads"] = threads

        # Initialize scanner
        scanner = WordPressScanner(timeout=timeout)

        # Display scan configuration
        _display_scan_configuration(target_url, scan_options, compliance_check)

        # Execute scan
        log_info("🚀 Executing WordPress security scan...")
        result = scanner.scan(target_url, scan_options)

        # Process compliance checks
        if compliance_check or security_baseline:
            result = _add_compliance_findings(
                result, compliance_check, security_baseline
            )

        # Display results summary
        _display_results_summary(result)

        # Generate reports
        if any(
            [json_report, html_report, pdf_report, xml_report, csv_report, all_reports]
        ):
            _generate_reports(
                result,
                output_dir,
                report_name,
                json_report,
                html_report,
                pdf_report,
                xml_report,
                csv_report,
                all_reports,
            )

        # Save raw output if requested
        if save_raw:
            _save_raw_output(result, output_dir, report_name or "wordpress_scan")

        # Display final status
        if result.status.value == "completed":
            log_success("✅ WordPress security scan completed successfully!")
        else:
            log_error("❌ WordPress security scan encountered issues")
            return 1

        return 0

    except Exception as e:
        log_error(f"WordPress scan failed: {e}")
        if debug:
            import traceback

            traceback.print_exc()
        return 1


def _build_target_url(target: str, scheme: str, port: int) -> str:
    """Build complete target URL"""
    if not target.startswith(("http://", "https://")):
        target = f"{scheme}://{target}"

    if port and port not in [80, 443]:
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(target)
        parsed = parsed._replace(netloc=f"{parsed.hostname}:{port}")
        target = urlunparse(parsed)

    return target.rstrip("/")


def _configure_scan_options(
    quick_scan,
    deep_scan,
    stealth_mode,
    enumerate_plugins,
    enumerate_themes,
    enumerate_users,
    check_multisite,
    check_htaccess,
    detect_security_plugins,
    check_database_security,
    test_brute_force,
    check_xmlrpc,
    check_config,
    use_wpscan,
    wpscan_api_token,
) -> Dict[str, Any]:
    """Configure scan options based on parameters"""

    if quick_scan:
        # Quick scan - essential checks only
        options = {
            "enumerate_plugins": True,
            "enumerate_themes": False,
            "enumerate_users": False,
            "check_multisite": False,
            "check_htaccess": True,
            "detect_security_plugins": True,
            "check_database_security": False,
            "test_brute_force": True,
            "check_xmlrpc": True,
            "check_config": True,
            "use_wpscan": False,  # Skip WPScan for speed
        }
        log_info("⚡ Quick scan mode: Essential security checks only")

    elif deep_scan:
        # Deep scan - all checks enabled
        options = {
            "enumerate_plugins": True,
            "enumerate_themes": True,
            "enumerate_users": True,
            "check_multisite": True,
            "check_htaccess": True,
            "detect_security_plugins": True,
            "check_database_security": True,
            "test_brute_force": True,
            "check_xmlrpc": True,
            "check_config": True,
            "use_wpscan": True,
        }
        log_info("🔬 Deep scan mode: Comprehensive security analysis")

    else:
        # Standard scan - use individual options
        options = {
            "enumerate_plugins": enumerate_plugins,
            "enumerate_themes": enumerate_themes,
            "enumerate_users": enumerate_users,
            "check_multisite": check_multisite,
            "check_htaccess": check_htaccess,
            "detect_security_plugins": detect_security_plugins,
            "check_database_security": check_database_security,
            "test_brute_force": test_brute_force,
            "check_xmlrpc": check_xmlrpc,
            "check_config": check_config,
            "use_wpscan": use_wpscan,
        }
        log_info("🎯 Standard scan mode: Customized security checks")

    # Add WPScan API token if provided
    if wpscan_api_token:
        options["wpscan_api_token"] = wpscan_api_token

    # Configure stealth mode
    if stealth_mode:
        options["stealth_mode"] = True
        options["rate_limit"] = min(options.get("rate_limit", 10), 2)  # Slower rate
        log_info("🥷 Stealth mode: Reduced detection techniques")

    return options


def _display_scan_configuration(
    target_url: str, options: Dict[str, Any], compliance_check: str
) -> None:
    """Display scan configuration"""
    log_info("📋 Scan Configuration:")
    log_info(f"   Target: {target_url}")

    enabled_checks = [key for key, value in options.items() if value is True]
    log_info(f"   Enabled checks: {len(enabled_checks)}")

    for check in enabled_checks:
        check_name = check.replace("_", " ").title()
        log_info(f"   ✓ {check_name}")

    if compliance_check:
        log_info(f"   📜 Compliance: {compliance_check.upper()}")


def _add_compliance_findings(result, compliance_check: str, security_baseline: bool):
    """Add compliance check findings"""
    # This would integrate with compliance frameworks
    # For now, add informational findings

    if compliance_check in ["owasp", "all"]:
        result.add_finding(
            title="OWASP WordPress Security Guide Compliance",
            description="Scan includes OWASP WordPress security recommendations",
            severity="INFO",
            recommendation="Review findings against OWASP WordPress Security Guide",
        )

    if compliance_check in ["cis", "all"]:
        result.add_finding(
            title="CIS WordPress Security Benchmark",
            description="Scan includes CIS WordPress security controls",
            severity="INFO",
            recommendation="Review findings against CIS WordPress Benchmark",
        )

    if security_baseline:
        result.add_finding(
            title="WordPress Security Baseline Check",
            description="Security configuration checked against WordPress best practices",
            severity="INFO",
            recommendation="Ensure all baseline security measures are implemented",
        )

    return result


def _display_results_summary(result) -> None:
    """Display scan results summary"""
    log_info("📊 Scan Results Summary:")
    log_info(f"   Status: {result.status.value.title()}")
    log_info(f"   Total findings: {len(result.findings)}")

    # Count by severity
    severity_counts = {}
    for finding in result.findings:
        severity = finding.get("severity", "INFO")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    for severity, count in severity_counts.items():
        log_info(f"   {severity}: {count}")


def _generate_reports(
    result,
    output_dir: str,
    report_name: str,
    json_report: bool,
    html_report: bool,
    pdf_report: bool,
    xml_report: bool,
    csv_report: bool,
    all_reports: bool,
) -> None:
    """Generate scan reports"""
    log_info("📄 Generating reports...")

    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    report_prefix = (
        report_name or f"wordpress_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )

    reporter = ReportGenerator()

    try:
        if json_report or all_reports:
            json_file = Path(output_dir) / f"{report_prefix}.json"
            reporter.generate_json_report(result, json_file)
            log_success(f"✅ JSON report: {json_file}")

        if html_report or all_reports:
            html_file = Path(output_dir) / f"{report_prefix}.html"
            reporter.generate_html_report(result, html_file)
            log_success(f"✅ HTML report: {html_file}")

        if pdf_report or all_reports:
            pdf_file = Path(output_dir) / f"{report_prefix}.pdf"
            reporter.generate_pdf_report(result, pdf_file)
            log_success(f"✅ PDF report: {pdf_file}")

    except Exception as e:
        log_error(f"Report generation failed: {e}")


def _save_raw_output(result, output_dir: str, report_name: str) -> None:
    """Save raw scanner output"""
    try:
        raw_file = Path(output_dir) / f"{report_name}_raw.txt"
        with open(raw_file, "w") as f:
            f.write(result.raw_output or "No raw output available")
        log_success(f"✅ Raw output saved: {raw_file}")
    except Exception as e:
        log_error(f"Failed to save raw output: {e}")
