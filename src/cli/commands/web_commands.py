"""
Web Commands - Web Application Security Testing
FILE PATH: src/cli/commands/web_commands.py

Handles web application security testing commands (web, directory, ssl, api)
Following SOLID principles and maintaining backward compatibility
"""

import click
import sys
from typing import Dict, Any

# Service imports - verified to exist
from ...services.scanner_service import ScannerService
from ...utils.logger import log_error, log_info, log_success, log_warning
from ..options import common_options

# Conditional imports for backward compatibility
try:
    from ...scanners.api.api_scanner import APISecurityScanner

    API_SCANNER_AVAILABLE = True
except ImportError:
    APISecurityScanner = None
    API_SCANNER_AVAILABLE = False


@click.command()
@click.argument("target")
@click.option("--use-nikto", is_flag=True, help="Use Nikto for web scanning")
@click.option("--directory-enum", is_flag=True, help="Include directory enumeration")
@click.option("--ssl-analysis", is_flag=True, help="Include SSL analysis")
@common_options
def web_command(target, use_nikto, directory_enum, ssl_analysis, **kwargs):
    """Web application vulnerability scanning"""
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
    """SSL/TLS configuration analysis"""
    try:
        scanner_service = ScannerService()
        scanner_service.run_ssl_scan(
            target, cipher_enum, cert_info, vulnerabilities, kwargs
        )
    except Exception as e:
        log_error(f"SSL scan failed: {e}")
        sys.exit(1)


@click.command()
@click.argument("target")
@click.option("--timeout", default=300, help="API scan timeout in seconds")
@click.option("--rate-limit-test", is_flag=True, help="Test for rate limiting")
@click.option("--graphql-test", is_flag=True, help="Test GraphQL endpoints")
@click.option("--jwt-analysis", is_flag=True, help="Analyze JWT tokens")
@click.option("--owasp-only", is_flag=True, help="Focus only on OWASP API Top 10 tests")
@click.option(
    "--auth-header", help="Authentication header (e.g., 'Authorization: Bearer token')"
)
@click.option("--swagger-url", help="Swagger/OpenAPI documentation URL")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--pdf-report", is_flag=True, help="Generate PDF report")
@click.option("--all-reports", is_flag=True, help="Generate all report formats")
@click.option(
    "--output-dir", default="output/reports", help="Output directory for reports"
)
@common_options
def api_command(
    target,
    timeout,
    rate_limit_test,
    graphql_test,
    jwt_analysis,
    owasp_only,
    auth_header,
    swagger_url,
    json_report,
    html_report,
    pdf_report,
    all_reports,
    output_dir,
    **kwargs,
):
    """API security testing and vulnerability assessment"""
    try:
        # Check if API Scanner is available
        if APISecurityScanner is None:
            log_error(
                "❌ API Security Scanner not available. Please ensure all dependencies are installed."
            )
            sys.exit(1)

        scanner_service = ScannerService()

        # Check if run_api_scan method exists for backward compatibility
        if not hasattr(scanner_service, "run_api_scan"):
            log_error("❌ API scanning functionality not available in this version.")
            sys.exit(1)

        # Build additional options
        additional_options = {
            "json_report": json_report,
            "html_report": html_report,
            "pdf_report": pdf_report,
            "all_reports": all_reports,
            "output_dir": output_dir,
        }

        # Merge with common options
        additional_options.update(kwargs)

        # Execute API scan with correct parameter count
        log_info(f"🔍 Starting API security scan for {target}")
        scanner_service.run_api_scan(
            target,
            timeout,
            rate_limit_test,
            graphql_test,
            jwt_analysis,
            owasp_only,
            auth_header,
            swagger_url,
            additional_options,
        )
        log_success("✅ API scan completed successfully")

    except Exception as e:
        log_error(f"❌ API scan failed: {e}")
        sys.exit(1)


# Export commands for easy import
# Note: api_command only exported if available for backward compatibility
__all__ = ["web_command", "directory_command", "ssl_command"]
if API_SCANNER_AVAILABLE:
    __all__.append("api_command")
