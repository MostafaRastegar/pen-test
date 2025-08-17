"""
WordPress Core Functionality Module
Contains base functionality and utilities for WordPress scanning
"""

import requests
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from src.core import CommandExecutor, validate_url, validate_domain
from src.utils.logger import log_info, log_error, log_warning, log_success


class WordPressCore:
    """Core WordPress scanning functionality and utilities"""

    def __init__(self, scanner):
        """
        Initialize WordPress core functionality

        Args:
            scanner: Reference to main WordPressScanner instance
        """
        self.scanner = scanner
        self.executor = CommandExecutor(timeout=scanner.timeout)

        # HTTP session for WordPress requests
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "Auto-Pentest-Tool/1.0 WordPress Security Scanner"}
        )

        # WordPress detection patterns
        self.wp_indicators = {
            "wp_content": "/wp-content/",
            "wp_includes": "/wp-includes/",
            "wp_admin": "/wp-admin/",
            "wp_login": "/wp-login.php",
            "xmlrpc": "/xmlrpc.php",
            "readme": "/readme.html",
            "license": "/license.txt",
            "generator": 'name="generator" content="WordPress',
            "wp_json": "/wp-json/",
        }

        # Common WordPress paths for enumeration
        self.wp_paths = [
            "/wp-content/plugins/",
            "/wp-content/themes/",
            "/wp-content/uploads/",
            "/wp-admin/",
            "/wp-includes/",
            "/wp-json/",
            "/wp-json/wp/v2/users",
        ]

        # Security plugins signatures
        self.security_plugins = {
            "wordfence": {
                "paths": [
                    "/wp-content/plugins/wordfence/",
                    "/wp-content/mu-plugins/wordfence/",
                ],
                "indicators": ["wordfence", "wfConfig"],
                "name": "Wordfence Security",
            },
            "sucuri": {
                "paths": ["/wp-content/plugins/sucuri-scanner/"],
                "indicators": ["sucuri", "sitecheck"],
                "name": "Sucuri Security",
            },
            "ithemes": {
                "paths": ["/wp-content/plugins/better-wp-security/"],
                "indicators": ["ithemes", "better-wp-security"],
                "name": "iThemes Security",
            },
            "jetpack": {
                "paths": ["/wp-content/plugins/jetpack/"],
                "indicators": ["jetpack", "automattic"],
                "name": "Jetpack Security",
            },
            "all_in_one": {
                "paths": ["/wp-content/plugins/all-in-one-wp-security-and-firewall/"],
                "indicators": ["aiowps", "all-in-one-wp-security"],
                "name": "All In One WP Security",
            },
        }

    def validate_target(self, target: str) -> bool:
        """
        Validate if target is appropriate for WordPress scanning

        Args:
            target: Target URL or domain

        Returns:
            bool: True if valid WordPress target, False otherwise
        """
        # Accept URLs directly
        if target.startswith(("http://", "https://")):
            return validate_url(target)

        # Accept domains (will be converted to URLs)
        return validate_domain(target)

    def normalize_target_url(self, target: str) -> str:
        """
        Normalize target to proper URL format

        Args:
            target: Target URL or domain

        Returns:
            str: Normalized URL
        """
        if not target.startswith(("http://", "https://")):
            # Default to https for domain-only targets
            target = f"https://{target}"

        # Ensure URL ends without trailing slash for consistency
        return target.rstrip("/")

    def make_request(
        self, url: str, method: str = "GET", **kwargs
    ) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling

        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional request parameters

        Returns:
            Response object or None if failed
        """
        try:
            response = self.session.request(method, url, timeout=10, **kwargs)
            return response
        except requests.RequestException as e:
            log_error(f"Request failed for {url}: {e}")
            return None

    def check_url_accessibility(self, url: str) -> bool:
        """
        Check if URL is accessible

        Args:
            url: URL to check

        Returns:
            bool: True if accessible, False otherwise
        """
        response = self.make_request(url)
        return response is not None and response.status_code in [200, 301, 302, 403]

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get scanner capabilities

        Returns:
            Dict containing scanner capabilities
        """
        return {
            "name": "WordPress Security Scanner",
            "description": "Comprehensive WordPress vulnerability and security scanner",
            "version": "1.1.0",
            "supported_targets": ["wordpress_sites", "cms"],
            "scan_types": [
                "wordpress_detection",
                "version_enumeration",
                "plugin_enumeration",
                "theme_enumeration",
                "user_enumeration",
                "vulnerability_assessment",
                "security_configuration",
            ],
            "features": [
                "WPScan integration",
                "Plugin security analysis",
                "Theme security analysis",
                "User enumeration",
                "Version fingerprinting",
                "Security configuration checks",
                "XML-RPC testing",
                "Brute force protection testing",
            ],
            "dependencies": {
                "required": ["requests", "urllib3"],
                "optional": ["wpscan"],
            },
        }

    def execute_wpscan(
        self, target_url: str, options: List[str] = None
    ) -> Dict[str, Any]:
        """
        Execute WPScan command

        Args:
            target_url: Target WordPress URL
            options: Additional WPScan options

        Returns:
            Dict containing WPScan results
        """
        try:
            # Build WPScan command
            cmd = ["wpscan", "--url", target_url, "--format", "json"]

            if options:
                cmd.extend(options)

            # Execute command
            result = self.executor.execute_command(cmd)

            if result["success"] and result["stdout"]:
                try:
                    return {"success": True, "data": eval(result["stdout"])}
                except:
                    return {"success": True, "data": {"raw_output": result["stdout"]}}
            else:
                return {
                    "success": False,
                    "error": result.get("stderr", "Unknown error"),
                }

        except Exception as e:
            log_error(f"WPScan execution failed: {e}")
            return {"success": False, "error": str(e)}
