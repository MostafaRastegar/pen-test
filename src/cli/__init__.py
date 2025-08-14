"""
CLI Commands Module
Main CLI interface using Click framework
"""

import click
from pathlib import Path
from .commands import (
    scan_command,
    quick_command,
    full_command,
    info_command,
    list_tools_command,
    port_command,
    dns_command,
    web_command,
    directory_command,
    ssl_command,
    version_command,
    cache_stats_command,
    clear_cache_command,
)
from .options import common_options
from ..utils.logger import LoggerSetup, log_banner


def create_cli_app():
    """Create and configure the CLI application"""

    @click.group()
    @click.version_option(version="0.9.1")
    @click.option("--debug", is_flag=True, help="Enable debug logging")
    @click.option("--quiet", is_flag=True, help="Quiet mode (minimal output)")
    def cli(debug, quiet):
        """
        Auto-Pentest Tool - Enhanced Automated Penetration Testing Framework

        A comprehensive tool for automated security testing and vulnerability assessment
        with professional reporting capabilities including PDF export.
        """
        # Setup logging based on options
        level = "DEBUG" if debug else "WARNING" if quiet else "INFO"
        LoggerSetup.setup_logger(name="auto-pentest", level=level, use_rich=True)

        if not quiet:
            log_banner("Auto-Pentest Framework v0.9.1")

    # Add all commands to the CLI group
    cli.add_command(scan_command, name="scan")
    cli.add_command(quick_command, name="quick")
    cli.add_command(full_command, name="full")
    cli.add_command(info_command, name="info")
    cli.add_command(list_tools_command, name="list-tools")
    cli.add_command(port_command, name="port")
    cli.add_command(dns_command, name="dns")
    cli.add_command(web_command, name="web")
    cli.add_command(directory_command, name="directory")
    cli.add_command(ssl_command, name="ssl")
    cli.add_command(version_command, name="version")
    cli.add_command(cache_stats_command, name="cache-stats")
    cli.add_command(clear_cache_command, name="clear-cache")

    return cli
