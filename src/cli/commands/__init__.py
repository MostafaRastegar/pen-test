"""
Commands Directory __init__.py - Backward Compatibility Layer
FILE PATH: src/cli/commands/__init__.py

Imports all commands from organized modules to maintain 100% backward compatibility
Following SOLID principles and clean architecture
✨ Updated with Advanced Subdomain Enumeration Service (Phase 4.1)
"""

# Core Commands (always available)
from .core_commands import (
    scan_command,
    quick_command,
    full_command,
)

# Information Commands (always available)
from .info_commands import (
    info_command,
    list_tools_command,
    version_command,
)

# Network Commands (always available)
from .network_commands import (
    port_command,
    dns_command,
    subdomain_command,  # ✨ NEW ADDITION - Advanced Subdomain Enumeration
)

# Web Commands (always available)
from .web_commands import (
    web_command,
    directory_command,
    ssl_command,
)

# Utility Commands (always available)
from .utility_commands import (
    cache_stats_command,
    clear_cache_command,
)

# Conditional imports for advanced features (backward compatibility)
try:
    from .network_commands import network_command

    NETWORK_COMMAND_AVAILABLE = True
except ImportError:
    network_command = None
    NETWORK_COMMAND_AVAILABLE = False

try:
    from .web_commands import api_command

    API_COMMAND_AVAILABLE = True
except ImportError:
    api_command = None
    API_COMMAND_AVAILABLE = False

# CMS Commands (conditionally available)
try:
    from .cms_commands import wordpress_command

    CMS_COMMANDS_AVAILABLE = True
except ImportError:
    wordpress_command = None
    CMS_COMMANDS_AVAILABLE = False

# Security Commands (conditionally available)
try:
    from .security_commands import waf_command

    SECURITY_COMMANDS_AVAILABLE = True
except ImportError:
    waf_command = None
    SECURITY_COMMANDS_AVAILABLE = False


# Export all available commands for backward compatibility
__all__ = [
    # Core commands (always available)
    "scan_command",
    "quick_command",
    "full_command",
    # Information commands (always available)
    "info_command",
    "list_tools_command",
    "version_command",
    # Network commands (always available)
    "port_command",
    "dns_command",
    "subdomain_command",  # ✨ NEW ADDITION - Advanced Subdomain Enumeration
    # Web commands (always available)
    "web_command",
    "directory_command",
    "ssl_command",
    # Utility commands (always available)
    "cache_stats_command",
    "clear_cache_command",
]

# Add conditional commands to exports if available
if NETWORK_COMMAND_AVAILABLE:
    __all__.append("network_command")

if API_COMMAND_AVAILABLE:
    __all__.append("api_command")

if CMS_COMMANDS_AVAILABLE:
    __all__.append("wordpress_command")

if SECURITY_COMMANDS_AVAILABLE:
    __all__.append("waf_command")


def get_command_availability():
    """
    Get availability status of all commands

    Returns:
        Dict[str, bool]: Command availability mapping
    """
    return {
        # Core commands (always available)
        "scan_command": True,
        "quick_command": True,
        "full_command": True,
        # Information commands (always available)
        "info_command": True,
        "list_tools_command": True,
        "version_command": True,
        # Network commands (always available)
        "port_command": True,
        "dns_command": True,
        "subdomain_command": True,  # ✨ NEW: Always available
        # Web commands (always available)
        "web_command": True,
        "directory_command": True,
        "ssl_command": True,
        # Utility commands (always available)
        "cache_stats_command": True,
        "clear_cache_command": True,
        # Conditional commands
        "network_command": NETWORK_COMMAND_AVAILABLE,
        "api_command": API_COMMAND_AVAILABLE,
        "wordpress_command": CMS_COMMANDS_AVAILABLE,
        "waf_command": SECURITY_COMMANDS_AVAILABLE,
    }


def get_available_commands():
    """
    Get list of all available command names

    Returns:
        List[str]: Available command names
    """
    availability = get_command_availability()
    return [cmd for cmd, available in availability.items() if available]


# Legacy imports for any code that might use these (backward compatibility)
import click
import sys
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime

# Re-export core dependencies for backward compatibility
try:
    from ...core.scanner_base import ScanStatus
except ImportError:
    # Fallback for older import structure
    try:
        from ...core import ScanStatus
    except ImportError:
        ScanStatus = None

# Re-export common services for backward compatibility
try:
    from ...services import (
        ScanService,
        ScannerService,
        InfoService,
        ReportService,
        SubdomainService,  # ✨ NEW ADDITION
    )
except ImportError:
    # Handle missing services gracefully
    pass

# Re-export utilities for backward compatibility
try:
    from ...utils.logger import log_info, log_error, log_success, log_warning
    from ...utils.reporter import ReportGenerator
    from ...utils.target_parser import TargetParser
except ImportError:
    # Handle missing utilities gracefully
    pass

# Re-export options for backward compatibility
try:
    from ..options import common_options
except ImportError:
    # Handle missing options gracefully
    common_options = None


# Export everything for backward compatibility
__all__.extend(
    [
        # Helper functions
        "get_command_availability",
        "get_available_commands",
        # Legacy exports (if available)
        "ScanStatus",
        "common_options",
        "ScanService",
        "ScannerService",
        "InfoService",
        "ReportService",
        "SubdomainService",  # ✨ NEW ADDITION
        "TargetParser",
        "log_info",
        "log_error",
        "log_success",
        "log_warning",
        "ReportGenerator",
    ]
)


# Compatibility function for migration verification
def verify_backward_compatibility():
    """
    Verify that all original commands are still available
    Used for testing and migration verification

    Returns:
        bool: True if all core commands are available
    """
    core_commands = [
        "scan_command",
        "quick_command",
        "full_command",
        "info_command",
        "list_tools_command",
        "version_command",
        "port_command",
        "dns_command",
        "subdomain_command",  # ✨ NEW
        "web_command",
        "directory_command",
        "ssl_command",
        "cache_stats_command",
        "clear_cache_command",
    ]

    availability = get_command_availability()

    for cmd in core_commands:
        if not availability.get(cmd, False):
            return False

    return True


# Add verification function to exports
__all__.append("verify_backward_compatibility")
