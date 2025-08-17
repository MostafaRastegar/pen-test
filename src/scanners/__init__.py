"""
Auto-Pentest Framework Scanner Suite - Updated for Phase 2.2
Complete scanner module with WAF Detection Engine integration

File Location: src/scanners/__init__.py
"""

# Reconnaissance scanners
from .recon.port_scanner import PortScanner
from .recon.dns_scanner import DNSScanner

# Vulnerability scanners
from .vulnerability.web_scanner import WebScanner
from .vulnerability.directory_scanner import DirectoryScanner
from .vulnerability.ssl_scanner import SSLScanner

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
    },
    "cms": {
        "wordpress": WordPressScanner,
    },
    "api": {
        "api": APISecurityScanner,
    },
    # Phase 2.2: New security category
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
        name: Scanner name (e.g., 'waf', 'wordpress', 'web', 'port')

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
        Dict: Scanner information including capabilities
    """
    scanner_class = get_scanner_by_name(name)
    if scanner_class:
        try:
            # Create temporary instance to get info
            scanner_instance = scanner_class()
            return scanner_instance.get_capabilities()
        except Exception:
            return {
                "name": name,
                "status": "error",
                "message": "Could not get scanner info",
            }

    return None


def validate_scanner_dependencies():
    """
    Validate that all scanners have their dependencies available

    Returns:
        Dict: Validation results for each scanner
    """
    validation_results = {}

    for category, scanners in SCANNERS_BY_CATEGORY.items():
        validation_results[category] = {}

        for scanner_name, scanner_class in scanners.items():
            try:
                # Create temporary instance
                scanner_instance = scanner_class()
                capabilities = scanner_instance.get_capabilities()

                validation_results[category][scanner_name] = {
                    "status": "available",
                    "capabilities": capabilities,
                }
            except Exception as e:
                validation_results[category][scanner_name] = {
                    "status": "error",
                    "error": str(e),
                }

    return validation_results
