"""
Info Commands - Information and Version Commands
FILE PATH: src/cli/commands/info_commands.py

Handles framework information, tool listing, and version commands
Following SOLID principles and maintaining backward compatibility
"""

import click
import sys
from typing import Dict, Any

# Service imports - verified to exist
from ...services.info_service import InfoService
from ...services.utility_services import ToolService, VersionService
from ...utils.logger import log_error, log_info


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
@click.option("--build-info", is_flag=True, help="Show build information")
@click.option("--dependencies", is_flag=True, help="Show dependency versions")
def version_command(build_info, dependencies):
    """Show framework version information"""
    try:
        version_service = VersionService()
        version_service.display_version(
            build_info=build_info, dependencies=dependencies
        )
    except Exception as e:
        log_error(f"Error showing version: {e}")


# Export commands for easy import
__all__ = ["info_command", "list_tools_command", "version_command"]
