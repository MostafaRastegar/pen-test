"""
Auto-Pentest Framework Scanner Suite - Updated for Phase 2.3
Complete scanner module with Network Vulnerability Scanner integration

File Location: src/scanners/__init__.py
"""

# Reconnaissance scanners
from .recon.port_scanner import PortScanner
from .recon.dns_scanner import DNSScanner

# Vulnerability scanners
from .vulnerability.web_scanner import WebScanner
from .vulnerability.directory_scanner import DirectoryScanner
from .vulnerability.ssl_scanner import SSLScanner
from .vulnerability.network_scanner import NetworkScanner

# CMS-Specific scanners
from .cms import WordPressScanner

# API Security scanners
from .api.api_scanner import APISecurityScanner

# Phase 2.2: Security scanners (WAF Detection Engine)
from .security import WAFScanner


# Scanner registry for dynamic loading
SCANNER_REGISTRY = {
    # Reconnaissance scanners
    "port": PortScanner,
    "dns": DNSScanner,
    # Vulnerability scanners
    "web": WebScanner,
    "directory": DirectoryScanner,
    "ssl": SSLScanner,
    "network": NetworkScanner,  # Phase 2.3: New Network Vulnerability Scanner
    # CMS scanners
    "wordpress": WordPressScanner,
    # API Security Scanner
    "api": APISecurityScanner,
    # Phase 2.2: Security scanners
    "waf": WAFScanner,
}

# Category-based organization
SCANNERS_BY_CATEGORY = {
    "recon": {
        "port": PortScanner,
        "dns": DNSScanner,
    },
    "vulnerability": {
        "web": WebScanner,
        "directory": DirectoryScanner,
        "ssl": SSLScanner,
        "network": NetworkScanner,  # Phase 2.3: Added to vulnerability category
    },
    "cms": {
        "wordpress": WordPressScanner,
    },
    "api": {
        "api": APISecurityScanner,
    },
    # Phase 2.2: Security category
    "security": {
        "waf": WAFScanner,
    },
}

# Export all scanners
__all__ = [
    # Reconnaissance
    "PortScanner",
    "DNSScanner",
    # Vulnerability
    "WebScanner",
    "DirectoryScanner",
    "SSLScanner",
    "NetworkScanner",  # Phase 2.3: Added to exports
    # CMS
    "WordPressScanner",
    # API Security
    "APISecurityScanner",
    # Phase 2.2: Security
    "WAFScanner",
    # Registry
    "SCANNER_REGISTRY",
    "SCANNERS_BY_CATEGORY",
    # Utilities
    "get_scanner_by_name",
    "get_scanners_by_category",
    "list_available_scanners",
]


def get_scanner_by_name(name: str):
    """
    Get scanner class by name

    Args:
        name: Scanner name (e.g., 'network', 'waf', 'wordpress', 'web', 'port')

    Returns:
        Scanner class or None if not found
    """
    return SCANNER_REGISTRY.get(name.lower())


def get_scanners_by_category(category: str):
    """
    Get all scanners in a category

    Args:
        category: Category name ('recon', 'vulnerability', 'cms', 'api', 'security')

    Returns:
        Dict of scanners in category
    """
    return SCANNERS_BY_CATEGORY.get(category.lower(), {})


def list_available_scanners():
    """
    List all available scanners organized by category

    Returns:
        Dict: All scanners organized by category
    """
    return SCANNERS_BY_CATEGORY


def get_scanner_info(name: str):
    """
    Get detailed information about a specific scanner

    Args:
        name: Scanner name

    Returns:
        Dict: Scanner capabilities and information
    """
    scanner_class = get_scanner_by_name(name)
    if scanner_class:
        try:
            # Create temporary instance to get capabilities
            scanner = scanner_class()
            return scanner.get_capabilities()
        except Exception:
            return {"error": f"Could not get info for scanner: {name}"}
    return {"error": f"Scanner not found: {name}"}


def is_scanner_available(name: str) -> bool:
    """
    Check if scanner is available

    Args:
        name: Scanner name

    Returns:
        bool: True if scanner is available
    """
    return name.lower() in SCANNER_REGISTRY


# Phase 2.3 update: Network scanner count
TOTAL_SCANNERS = len(SCANNER_REGISTRY)  # Now 8 scanners (90% → 100% complete)
