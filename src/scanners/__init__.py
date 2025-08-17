"""
Auto-Pentest Framework Scanner Suite
Complete scanner module with Phase 1.1 CMS scanner integration
"""

# Reconnaissance scanners
from .recon.port_scanner import PortScanner
from .recon.dns_scanner import DNSScanner

# Vulnerability scanners
from .vulnerability.web_scanner import WebScanner
from .vulnerability.directory_scanner import DirectoryScanner
from .vulnerability.ssl_scanner import SSLScanner

# Phase 1.1: CMS-Specific Vulnerability Scanners
from .cms import WordPressScanner

# Scanner registry for dynamic loading
SCANNER_REGISTRY = {
    # Reconnaissance scanners
    "port": PortScanner,
    "dns": DNSScanner,
    # Vulnerability scanners
    "web": WebScanner,
    "directory": DirectoryScanner,
    "ssl": SSLScanner,
    # CMS scanners
    "wordpress": WordPressScanner,
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
    },
    "cms": {
        "wordpress": WordPressScanner,
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
    # CMS
    "WordPressScanner",
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
        name: Scanner name (e.g., 'wordpress', 'web', 'port')

    Returns:
        Scanner class or None if not found
    """
    return SCANNER_REGISTRY.get(name.lower())


def get_scanners_by_category(category: str):
    """
    Get all scanners in a category

    Args:
        category: Category name ('recon', 'vulnerability', 'cms')

    Returns:
        Dict of scanners in category
    """
    return SCANNERS_BY_CATEGORY.get(category.lower(), {})


def list_available_scanners():
    """
    List all available scanners with metadata

    Returns:
        Dict with scanner information
    """
    scanners_info = {}

    for category, scanners in SCANNERS_BY_CATEGORY.items():
        scanners_info[category] = {}
        for name, scanner_class in scanners.items():
            try:
                # Get scanner instance to extract capabilities
                instance = scanner_class()
                capabilities = instance.get_capabilities()
                scanners_info[category][name] = {
                    "class": scanner_class.__name__,
                    "name": capabilities.get("name", "Unknown"),
                    "description": capabilities.get("description", "No description"),
                    "version": capabilities.get("version", "1.0.0"),
                    "supported_targets": capabilities.get("supported_targets", []),
                    "scan_types": capabilities.get("scan_types", []),
                }
            except Exception as e:
                scanners_info[category][name] = {
                    "class": scanner_class.__name__,
                    "error": f"Failed to load: {str(e)}",
                }

    return scanners_info
