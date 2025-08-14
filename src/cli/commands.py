"""
CLI Command Implementations
Each command is a separate function following Single Responsibility Principle
"""

import click
import sys
from typing import Dict, Any, Optional
from pathlib import Path

from .options import common_options
from ..services.scan_service import ScanService
from ..services.scanner_service import ScannerService
from ..services.info_service import InfoService
from ..services.utility_services import CacheService, ToolService, VersionService
from ..utils.target_parser import TargetParser
from ..utils.logger import log_info, log_error, log_success, log_warning


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
