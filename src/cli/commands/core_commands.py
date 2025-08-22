"""
Core Commands - Main Scanning Commands
FILE PATH: src/cli/commands/core_commands.py

Handles the main scanning workflow commands (scan, quick, full)
Following SOLID principles and maintaining backward compatibility
"""

import click
import sys
from typing import Dict, Any

# Core service imports - verified to exist
from ...services.scan_service import ScanService
from ...utils.logger import log_error, log_info
from ..options import common_options


@click.command()
@click.argument("target")
@click.option(
    "--profile",
    type=click.Choice(["quick", "standard", "full", "custom"]),
    default="standard",
    help="Scan profile selection",
)
@click.option("--parallel", is_flag=True, help="Run scans in parallel")
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


# Export commands for easy import
__all__ = ["scan_command", "quick_command", "full_command"]
