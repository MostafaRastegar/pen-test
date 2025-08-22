"""
Network Commands - Port, DNS, and Network Scanning
FILE PATH: src/cli/commands/network_commands.py

Handles all network-related scanning commands
Following SOLID principles and maintaining backward compatibility
"""

import click
import sys
from typing import Dict, Any

# Service imports - verified to exist
from ...services.scanner_service import ScannerService
from ...utils.logger import log_error, log_info, log_success, log_warning
from ..options import common_options

# Conditional import for network scanner (backward compatibility)
try:
    from ...scanners.vulnerability.network_scanner import NetworkScanner

    NETWORK_SCANNER_AVAILABLE = True
except ImportError:
    NetworkScanner = None
    NETWORK_SCANNER_AVAILABLE = False


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
@click.option(
    "--templates",
    type=click.Choice(["default", "critical", "high", "all", "custom"]),
    default="default",
    help="Nuclei template selection",
)
@click.option("--rate-limit", default=150, help="Request rate limit per second")
@click.option(
    "--service-analysis", is_flag=True, help="Enable network service analysis"
)
@click.option(
    "--protocol-analysis", is_flag=True, help="Enable protocol security analysis"
)
@click.option("--template-path", help="Custom template path (for --templates custom)")
@click.option("--timeout", default=600, help="Scan timeout in seconds")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--pdf-report", is_flag=True, help="Generate PDF report")
@click.option("--all-reports", is_flag=True, help="Generate all report formats")
@click.option(
    "--output-dir", default="output/reports", help="Output directory for reports"
)
@click.option("--save-raw", is_flag=True, help="Save raw scan results")
@common_options
def network_command(
    target,
    templates,
    rate_limit,
    service_analysis,
    protocol_analysis,
    template_path,
    timeout,
    json_report,
    html_report,
    pdf_report,
    all_reports,
    output_dir,
    save_raw,
    **kwargs,
):
    """Network vulnerability scanning using Nuclei and custom analysis"""
    try:
        # Check if NetworkScanner is available
        if NetworkScanner is None:
            log_error(
                "❌ Network Scanner not available. Please ensure all dependencies are installed."
            )
            sys.exit(1)

        scanner_service = ScannerService()

        # Check if run_network_scan method exists for backward compatibility
        if not hasattr(scanner_service, "run_network_scan"):
            log_error(
                "❌ Network scanning functionality not available in this version."
            )
            sys.exit(1)

        # Build additional options for reports
        additional_options = {
            "json_report": json_report,
            "html_report": html_report,
            "pdf_report": pdf_report,
            "all_reports": all_reports,
            "output_dir": output_dir,
            "save_raw": save_raw,
        }

        # Merge with common options
        additional_options.update(kwargs)

        # Execute network scan with correct parameter count
        log_info(f"🔍 Starting network vulnerability scan for {target}")
        scanner_service.run_network_scan(
            target,
            templates,
            rate_limit,
            service_analysis,
            protocol_analysis,
            template_path,
            timeout,
            additional_options,
        )
        log_success("✅ Network scan completed successfully")

    except Exception as e:
        log_error(f"❌ Network scan failed: {e}")
        sys.exit(1)


# Export commands for easy import
# Note: network_command only exported if available for backward compatibility
__all__ = ["port_command", "dns_command"]
if NETWORK_SCANNER_AVAILABLE:
    __all__.append("network_command")
