"""
Commands Directory __init__.py - Backward Compatibility Layer
FILE PATH: src/cli/commands/__init__.py

Imports all commands from organized modules to maintain 100% backward compatibility
Following SOLID principles and clean architecture
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


# Availability status for debugging and integration
def get_command_availability():
    """Get availability status of all commands"""
    return {
        "core_commands": True,  # Always available
        "info_commands": True,  # Always available
        "network_commands": True,  # Basic network commands always available
        "web_commands": True,  # Basic web commands always available
        "utility_commands": True,  # Always available
        "network_command": NETWORK_COMMAND_AVAILABLE,
        "api_command": API_COMMAND_AVAILABLE,
        "wordpress_command": CMS_COMMANDS_AVAILABLE,
        "waf_command": SECURITY_COMMANDS_AVAILABLE,
    }


# Helper function to get all available commands
def get_available_commands():
    """Get list of all available command names"""
    available = __all__.copy()
    return sorted(available)
