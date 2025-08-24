"""
CLI Commands Module
Main CLI interface using Click framework
✨ UPDATED: Added OSINT & Information Gathering Service (Phase 4.2)
"""

import click
from pathlib import Path
from ..utils.logger import LoggerSetup, log_banner, log_warning

# Import basic commands (always available)
from .commands import (
    scan_command,
    quick_command,
    full_command,
    info_command,
    list_tools_command,
    port_command,
    dns_command,
    subdomain_command,
    web_command,
    directory_command,
    ssl_command,
    version_command,
    cache_stats_command,
    clear_cache_command,
)

# ✨ NEW: Import OSINT commands (Phase 4.2)
try:
    from .commands import osint_group

    OSINT_AVAILABLE = True
except ImportError:
    osint_group = None
    OSINT_AVAILABLE = False

# Conditionally import advanced scanner commands for backward compatibility
try:
    from .commands import wordpress_command  # Phase 1.1: WordPress Scanner

    WORDPRESS_SCANNER_AVAILABLE = True
except ImportError:
    wordpress_command = None
    WORDPRESS_SCANNER_AVAILABLE = False

try:
    from .commands import api_command  # Phase 2.1: API Security Scanner

    API_SCANNER_AVAILABLE = True
except ImportError:
    api_command = None
    API_SCANNER_AVAILABLE = False

try:
    from .commands import waf_command  # Phase 2.2: WAF Detection Engine

    WAF_SCANNER_AVAILABLE = True
except ImportError:
    waf_command = None
    WAF_SCANNER_AVAILABLE = False

try:
    from .commands import network_command  # Phase 2.3: Network Vulnerability Scanner

    NETWORK_SCANNER_AVAILABLE = True
except ImportError:
    network_command = None
    NETWORK_SCANNER_AVAILABLE = False

from .options import common_options


def create_cli_app():
    """Create and configure the CLI application with backward compatibility"""

    @click.group()
    @click.version_option(version="0.9.7")  # Updated version for Phase 4.2
    @click.option("--debug", is_flag=True, help="Enable debug logging")
    @click.option("--quiet", is_flag=True, help="Quiet mode (minimal output)")
    def cli(debug, quiet):
        """
        Auto-Pentest Tool - Enhanced Automated Penetration Testing Framework

        A comprehensive tool for automated security testing and vulnerability assessment
        with professional reporting capabilities.

        ✨ NEW: OSINT & Information Gathering (Phase 4.2)

        Available Features (based on installed dependencies):
        - Core Scanners: Port, DNS, Web, Directory, SSL
        - Advanced Subdomain Enumeration: Subfinder, Amass, Sublist3r, CT logs
        - OSINT & Information Gathering: Email harvesting, Search recon, WHOIS analysis
        - WordPress Scanner (if available)
        - API Security Scanner (if available)
        - WAF Detection Engine (if available)
        - Network Vulnerability Scanner (if available)

        Use --help with individual commands to see available options.
        """
        # Setup logging based on options
        level = "DEBUG" if debug else "WARNING" if quiet else "INFO"
        LoggerSetup.setup_logger(name="auto-pentest", level=level, use_rich=True)

        if not quiet:
            log_banner("Auto-Pentest Framework v0.9.7 - Phase 4.2")

            # Show availability warnings if needed
            if not quiet and debug:
                _show_scanner_availability()

    # Core scanning commands (always available)
    cli.add_command(scan_command, name="scan")
    cli.add_command(quick_command, name="quick")
    cli.add_command(full_command, name="full")

    # Information commands (always available)
    cli.add_command(info_command, name="info")
    cli.add_command(list_tools_command, name="list-tools")
    cli.add_command(version_command, name="version")

    # Individual scanner commands (always available)
    cli.add_command(port_command, name="port")
    cli.add_command(dns_command, name="dns")
    cli.add_command(
        subdomain_command, name="subdomain"
    )  # ✨ NEW: Advanced Subdomain Enumeration
    cli.add_command(web_command, name="web")
    cli.add_command(directory_command, name="directory")
    cli.add_command(ssl_command, name="ssl")

    # Conditionally add advanced scanner commands based on availability

    # Phase 1.1: CMS-specific scanners
    if WORDPRESS_SCANNER_AVAILABLE and wordpress_command:
        cli.add_command(wordpress_command, name="wordpress")

    # Phase 2.1: API Security Scanner
    if API_SCANNER_AVAILABLE and api_command:
        cli.add_command(api_command, name="api")

    # Phase 2.2: WAF Detection Engine
    if WAF_SCANNER_AVAILABLE and waf_command:
        cli.add_command(waf_command, name="waf")

    # Phase 2.3: Network Vulnerability Scanner
    if NETWORK_SCANNER_AVAILABLE and network_command:
        cli.add_command(network_command, name="network")

    # ✨ NEW: Register OSINT commands (Phase 4.2)
    if OSINT_AVAILABLE and osint_group:
        cli.add_command(osint_group, name="osint")
        log_warning("✅ OSINT & Information Gathering commands available (Phase 4.2)")
    else:
        log_warning(
            "⚠️ OSINT commands not available - install dependencies: sudo apt install theharvester whois"
        )

    # Utility commands (always available)
    cli.add_command(cache_stats_command, name="cache-stats")
    cli.add_command(clear_cache_command, name="clear-cache")

    return cli


def _show_scanner_availability():
    """Show scanner availability status in debug mode"""
    scanners_status = [
        ("WordPress Scanner", WORDPRESS_SCANNER_AVAILABLE),
        ("API Security Scanner", API_SCANNER_AVAILABLE),
        ("WAF Detection Engine", WAF_SCANNER_AVAILABLE),
        ("Network Vulnerability Scanner", NETWORK_SCANNER_AVAILABLE),
        ("OSINT Scanner", OSINT_AVAILABLE),
        ("Advanced Subdomain Enumeration", True),  # ✨ NEW: Always available
    ]

    log_warning("🔧 Scanner Availability Status:")
    for scanner_name, available in scanners_status:
        status = "✅ Available" if available else "❌ Not Available"
        log_warning(f"   • {scanner_name}: {status}")


# Make CLI app available for main.py
cli_app = create_cli_app()


def main():
    """Main entry point for CLI"""
    try:
        cli_app()
    except KeyboardInterrupt:
        log_warning("\n🛑 Operation interrupted by user")
    except Exception as e:
        from ..utils.logger import log_error

        log_error(f"💥 CLI Error: {e}")
        raise


if __name__ == "__main__":
    main()
