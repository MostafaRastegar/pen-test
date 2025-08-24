"""
Commands Directory __init__.py - Updated with OSINT Integration
FILE PATH: src/cli/commands/__init__.py

✨ UPDATED: Added OSINT & Information Gathering Commands (Phase 4.2)
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
    subdomain_command,  # ✨ NEW ADDITION - AdvancedS Subdomain Enumeration
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

# ✨ NEW: OSINT Commands Group (conditional import)
try:
    from .osint_commands import (
        osint_group,
        email_harvest_command as osint_email_command,
        search_recon_command,
        whois_analysis_command,
        comprehensive_osint_command,
        osint_info_command,
        osint_test_command,
    )

    OSINT_COMMANDS_AVAILABLE = True
except ImportError:
    osint_group = None
    osint_email_command = None
    search_recon_command = None
    whois_analysis_command = None
    comprehensive_osint_command = None
    osint_info_command = None
    osint_test_command = None
    OSINT_COMMANDS_AVAILABLE = False

# Conditional imports for advanced features (existing)
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


# All available commands export (updated with OSINT)
__all__ = [
    # Core commands (always available)
    "scan_command",
    "quick_command",
    "full_command",
    # Information commands (always available)
    "info_command",
    "list_tools_command",
    "version_command",
    # Network commands (always available + NEW OSINT)
    "port_command",
    "dns_command",
    "subdomain_command",
    "osint_command",  # ✨ NEW - Main OSINT command
    "email_harvest_command",  # ✨ NEW - Email harvesting command
    # Web commands (always available)
    "web_command",
    "directory_command",
    "ssl_command",
    # Utility commands (always available)
    "cache_stats_command",
    "clear_cache_command",
    # Helper functions
    "get_command_availability",
    "get_available_commands",
]

# ✨ NEW: Add OSINT commands to exports if available
if OSINT_COMMANDS_AVAILABLE:
    __all__.extend(
        [
            "osint_group",
            "osint_email_command",
            "search_recon_command",
            "whois_analysis_command",
            "comprehensive_osint_command",
            "osint_info_command",
            "osint_test_command",
        ]
    )


def get_command_availability():
    """
    Get availability status of all commands

    Returns:
        Dict[str, bool]: Command name -> availability status
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
        "subdomain_command": True,
        # ✨ NEW: OSINT commands availability
        "osint_command": True,  # Main OSINT command (always available in network)
        "email_harvest_command": True,  # Email harvest (always available in network)
        "osint_commands_group": OSINT_COMMANDS_AVAILABLE,  # Full OSINT group (conditional)
        # Web commands (always available)
        "web_command": True,
        "directory_command": True,
        "ssl_command": True,
        # Utility commands (always available)
        "cache_stats_command": True,
        "clear_cache_command": True,
        # Conditional commands (existing)
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


# ✨ NEW: OSINT-specific helper functions
def get_osint_command_availability():
    """Get OSINT command availability details"""
    return {
        "main_osint_command": True,  # Always available (in network commands)
        "email_harvest_command": True,  # Always available (in network commands)
        "osint_commands_group": OSINT_COMMANDS_AVAILABLE,  # Conditional (separate module)
        "service_status": OSINT_COMMANDS_AVAILABLE,
        "free_services_only": True,
        "rate_limited": True,
    }


def get_osint_usage_help():
    """Get OSINT usage help text"""
    if not OSINT_COMMANDS_AVAILABLE:
        return "OSINT commands not available. Install dependencies: sudo apt install theharvester whois"

    return """
🔍 OSINT & Information Gathering Commands (Phase 4.2):

Main Commands:
  python main.py osint <target>                    # Comprehensive OSINT scan
  python main.py email-harvest <target>           # Email harvesting only

OSINT Group Commands:
  python main.py osint email <target>             # Detailed email harvesting
  python main.py osint search <target>            # Search engine reconnaissance
  python main.py osint whois <target>             # Enhanced WHOIS analysis
  python main.py osint comprehensive <target>     # Complete OSINT gathering

Key Features:
  ✅ Free services only (no API keys required)
  ✅ Rate-limited (respectful usage)
  ✅ Multi-format reporting (JSON, HTML, TXT)
  ✅ Email harvesting with validation
  ✅ Search engine dorking patterns
  ✅ Enhanced WHOIS analysis with geolocation
  ✅ Social media profile discovery
  ✅ Certificate transparency analysis
"""


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
        SubdomainService,
    )

    # ✨ NEW: Add OSINT service to backward compatibility exports
    try:
        from ...services.osint_service import OSINTService
    except ImportError:
        OSINTService = None

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
