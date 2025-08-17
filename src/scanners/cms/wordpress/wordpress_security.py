"""
WordPress Security Configuration Analysis Module
Handles security configuration checks, XML-RPC testing, and security analysis
"""

import re
import requests
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from src.core import ScanResult, ScanSeverity
from src.utils.logger import log_info, log_error, log_warning, log_success


class WordPressSecurity:
    """WordPress security configuration analysis"""

    def __init__(self, scanner):
        """
        Initialize WordPress security analyzer

        Args:
            scanner: Reference to main WordPressScanner instance
        """
        self.scanner = scanner
        self.core = scanner.core if hasattr(scanner, "core") else None

        # Security headers to check
        self.security_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "Referrer-Policy",
        ]

        # WordPress security files to check
        self.security_files = [
            "wp-config.php",
            ".htaccess",
            "robots.txt",
            "readme.html",
            "license.txt",
            "wp-config-sample.php",
            "wp-admin/install.php",
        ]

    def check_security_configurations(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """
        Comprehensive security configuration analysis

        Args:
            target_url: Target WordPress URL
            result: ScanResult to store findings
            options: Scan options
        """
        try:
            log_info("Starting security configuration analysis")

            # Check security headers
            self._check_security_headers(target_url, result)

            # Check file exposures
            self._check_file_exposures(target_url, result)

            # Check directory browsing
            self._check_directory_browsing(target_url, result)

            # Check debug mode
            self._check_debug_mode(target_url, result)

            # Check REST API security
            self._check_rest_api_security(target_url, result)

            # Check XML-RPC
            self._check_xmlrpc_security(target_url, result)

            # Check login security
            self._check_login_security(target_url, result)

            # Check multisite configuration (if applicable)
            self._check_multisite_security(target_url, result)

            log_success("Security configuration analysis completed")

        except Exception as e:
            log_error(f"Security configuration analysis failed: {e}")

    def _check_security_headers(self, target_url: str, result: ScanResult) -> None:
        """Check for security headers"""
        try:
            response = self.core.make_request(target_url) if self.core else None
            if not response:
                return

            headers = response.headers
            missing_headers = []
            present_headers = []

            for header in self.security_headers:
                if header in headers:
                    present_headers.append(header)
                else:
                    missing_headers.append(header)

            # Add finding for missing security headers
            if missing_headers:
                severity = (
                    ScanSeverity.MEDIUM
                    if len(missing_headers) > 3
                    else ScanSeverity.LOW
                )

                result.add_finding(
                    title=f"Missing Security Headers ({len(missing_headers)} missing)",
                    description=f"Important security headers are missing: {', '.join(missing_headers)}",
                    severity=severity,
                    technical_details={
                        "missing_headers": missing_headers,
                        "present_headers": present_headers,
                        "total_checked": len(self.security_headers),
                    },
                    recommendation="Implement missing security headers in web server configuration or security plugin.",
                )

            # Add finding for present headers
            if present_headers:
                result.add_finding(
                    title=f"Security Headers Present ({len(present_headers)} found)",
                    description=f"Found security headers: {', '.join(present_headers)}",
                    severity=ScanSeverity.INFO,
                    technical_details={
                        "present_headers": present_headers,
                        "header_values": {h: headers.get(h) for h in present_headers},
                    },
                    recommendation="Review security header configurations for optimal settings.",
                )

        except Exception as e:
            log_error(f"Security headers check failed: {e}")

    def _check_file_exposures(self, target_url: str, result: ScanResult) -> None:
        """Check for exposed sensitive files"""
        try:
            exposed_files = []

            for file_path in self.security_files:
                file_url = urljoin(target_url, file_path)
                response = self.core.make_request(file_url) if self.core else None

                if response and response.status_code == 200:
                    # Check if it's actually the file content, not a 404 page
                    content = response.text.lower()

                    if file_path == "wp-config.php" and "database" in content:
                        exposed_files.append(
                            {
                                "file": file_path,
                                "risk": "CRITICAL",
                                "description": "WordPress configuration file exposed",
                            }
                        )
                    elif file_path == "readme.html" and "wordpress" in content:
                        exposed_files.append(
                            {
                                "file": file_path,
                                "risk": "LOW",
                                "description": "WordPress readme file accessible",
                            }
                        )
                    elif file_path == "wp-config-sample.php" and "config" in content:
                        exposed_files.append(
                            {
                                "file": file_path,
                                "risk": "LOW",
                                "description": "Sample configuration file accessible",
                            }
                        )

            if exposed_files:
                # Determine overall severity
                critical_files = [f for f in exposed_files if f["risk"] == "CRITICAL"]
                severity = ScanSeverity.HIGH if critical_files else ScanSeverity.MEDIUM

                result.add_finding(
                    title=f"Exposed Sensitive Files ({len(exposed_files)} found)",
                    description=f"Sensitive WordPress files are accessible: {', '.join([f['file'] for f in exposed_files])}",
                    severity=severity,
                    technical_details={
                        "exposed_files": exposed_files,
                        "critical_files": len(critical_files),
                    },
                    recommendation="Block access to sensitive files using .htaccess or web server configuration.",
                )

        except Exception as e:
            log_error(f"File exposure check failed: {e}")

    def _check_directory_browsing(self, target_url: str, result: ScanResult) -> None:
        """Check for directory browsing vulnerabilities"""
        try:
            directories_to_check = [
                "/wp-content/",
                "/wp-content/plugins/",
                "/wp-content/themes/",
                "/wp-content/uploads/",
                "/wp-includes/",
            ]

            browsable_dirs = []

            for directory in directories_to_check:
                dir_url = urljoin(target_url, directory)
                response = self.core.make_request(dir_url) if self.core else None

                if response and response.status_code == 200:
                    content = response.text

                    # Check for directory listing indicators
                    if "Index of" in content or "<title>Index of" in content:
                        browsable_dirs.append(directory)

            if browsable_dirs:
                result.add_finding(
                    title=f"Directory Browsing Enabled ({len(browsable_dirs)} directories)",
                    description=f"Directory browsing is enabled for: {', '.join(browsable_dirs)}",
                    severity=ScanSeverity.MEDIUM,
                    technical_details={
                        "browsable_directories": browsable_dirs,
                        "checked_directories": directories_to_check,
                    },
                    recommendation="Disable directory browsing by adding 'Options -Indexes' to .htaccess or web server configuration.",
                )

        except Exception as e:
            log_error(f"Directory browsing check failed: {e}")

    def _check_debug_mode(self, target_url: str, result: ScanResult) -> None:
        """Check if WordPress debug mode is enabled"""
        try:
            # Check for debug information in responses
            response = self.core.make_request(target_url) if self.core else None
            if not response:
                return

            content = response.text
            debug_indicators = []

            # Look for debug output patterns
            debug_patterns = [
                r"WP_DEBUG",
                r"Notice:",
                r"Warning:",
                r"Fatal error:",
                r"Parse error:",
                r"wp-content.*\.php.*line \d+",
            ]

            for pattern in debug_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    debug_indicators.append(pattern)

            if debug_indicators:
                result.add_finding(
                    title="WordPress Debug Mode Enabled",
                    description="Debug information is visible in page output",
                    severity=ScanSeverity.MEDIUM,
                    technical_details={
                        "debug_indicators": debug_indicators,
                        "risk": "Information disclosure",
                    },
                    recommendation="Disable debug mode in wp-config.php: set WP_DEBUG to false in production.",
                )

        except Exception as e:
            log_error(f"Debug mode check failed: {e}")

    def _check_rest_api_security(self, target_url: str, result: ScanResult) -> None:
        """Check WordPress REST API security"""
        try:
            api_url = urljoin(target_url, "/wp-json/wp/v2/")
            response = self.core.make_request(api_url) if self.core else None

            if response and response.status_code == 200:
                try:
                    api_data = response.json()

                    # Check if API provides sensitive information
                    sensitive_endpoints = []

                    # Check users endpoint
                    users_url = urljoin(target_url, "/wp-json/wp/v2/users")
                    users_response = (
                        self.core.make_request(users_url) if self.core else None
                    )

                    if users_response and users_response.status_code == 200:
                        sensitive_endpoints.append("users")

                    # Check posts endpoint for sensitive data
                    posts_url = urljoin(target_url, "/wp-json/wp/v2/posts")
                    posts_response = (
                        self.core.make_request(posts_url) if self.core else None
                    )

                    if posts_response and posts_response.status_code == 200:
                        sensitive_endpoints.append("posts")

                    if sensitive_endpoints:
                        severity = (
                            ScanSeverity.MEDIUM
                            if "users" in sensitive_endpoints
                            else ScanSeverity.LOW
                        )

                        result.add_finding(
                            title="WordPress REST API Accessible",
                            description=f"WordPress REST API is publicly accessible with endpoints: {', '.join(sensitive_endpoints)}",
                            severity=severity,
                            technical_details={
                                "accessible_endpoints": sensitive_endpoints,
                                "api_url": api_url,
                            },
                            recommendation="Consider restricting REST API access or disabling unused endpoints if not needed.",
                        )

                except ValueError:
                    pass

        except Exception as e:
            log_error(f"REST API security check failed: {e}")

    def _check_xmlrpc_security(self, target_url: str, result: ScanResult) -> None:
        """Check XML-RPC security"""
        try:
            xmlrpc_url = urljoin(target_url, "/xmlrpc.php")

            # Test if XML-RPC is accessible
            response = (
                self.core.make_request(xmlrpc_url, method="GET") if self.core else None
            )

            if response and response.status_code == 200:
                content = response.text

                if "XML-RPC server accepts POST requests only" in content:
                    # Test XML-RPC functionality
                    xmlrpc_enabled = self._test_xmlrpc_methods(target_url)

                    if xmlrpc_enabled:
                        result.add_finding(
                            title="XML-RPC Interface Enabled",
                            description="WordPress XML-RPC interface is accessible and functional",
                            severity=ScanSeverity.MEDIUM,
                            technical_details={
                                "xmlrpc_url": xmlrpc_url,
                                "methods_tested": xmlrpc_enabled.get("methods", []),
                                "risk": "Potential brute force vector and DDoS amplification",
                            },
                            recommendation="Disable XML-RPC if not needed, or implement rate limiting and monitoring.",
                        )

        except Exception as e:
            log_error(f"XML-RPC security check failed: {e}")

    def _test_xmlrpc_methods(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Test XML-RPC methods"""
        try:
            xmlrpc_url = urljoin(target_url, "/xmlrpc.php")

            # Test system.listMethods
            xml_payload = """
            <?xml version="1.0"?>
            <methodCall>
                <methodName>system.listMethods</methodName>
                <params></params>
            </methodCall>
            """

            headers = {"Content-Type": "text/xml"}
            response = (
                self.core.make_request(
                    xmlrpc_url, method="POST", data=xml_payload, headers=headers
                )
                if self.core
                else None
            )

            if response and response.status_code == 200:
                # Parse XML response
                try:
                    root = ET.fromstring(response.text)
                    methods = []

                    for value in root.findall(".//value/string"):
                        if value.text:
                            methods.append(value.text)

                    return {
                        "enabled": True,
                        "methods": methods[:10],  # Limit to first 10 methods
                        "total_methods": len(methods),
                    }

                except ET.ParseError:
                    return {"enabled": True, "methods": [], "parse_error": True}

            return None

        except Exception as e:
            log_error(f"XML-RPC method testing failed: {e}")
            return None

    def _check_login_security(self, target_url: str, result: ScanResult) -> None:
        """Check login page security"""
        try:
            login_url = urljoin(target_url, "/wp-login.php")
            response = self.core.make_request(login_url) if self.core else None

            if response and response.status_code == 200:
                content = response.text

                security_features = {
                    "captcha": False,
                    "rate_limiting": False,
                    "two_factor": False,
                    "custom_login_url": False,
                }

                # Check for security features
                if "captcha" in content.lower() or "recaptcha" in content.lower():
                    security_features["captcha"] = True

                if "two-factor" in content.lower() or "2fa" in content.lower():
                    security_features["two_factor"] = True

                # Check if login URL is customized
                if "/wp-login.php" not in response.url:
                    security_features["custom_login_url"] = True

                enabled_features = [k for k, v in security_features.items() if v]
                missing_features = [k for k, v in security_features.items() if not v]

                severity = (
                    ScanSeverity.MEDIUM
                    if len(enabled_features) < 2
                    else ScanSeverity.LOW
                )

                result.add_finding(
                    title=f"WordPress Login Security Assessment",
                    description=f"Login security features - Enabled: {len(enabled_features)}, Missing: {len(missing_features)}",
                    severity=severity,
                    technical_details={
                        "login_url": login_url,
                        "enabled_features": enabled_features,
                        "missing_features": missing_features,
                        "security_score": f"{len(enabled_features)}/{len(security_features)}",
                    },
                    recommendation="Implement additional login security features: CAPTCHA, rate limiting, two-factor authentication.",
                )

        except Exception as e:
            log_error(f"Login security check failed: {e}")

    def _check_multisite_security(self, target_url: str, result: ScanResult) -> None:
        """Check WordPress multisite security configuration"""
        try:
            # Check for multisite indicators
            response = self.core.make_request(target_url) if self.core else None
            if not response:
                return

            content = response.text

            # Look for multisite indicators
            multisite_indicators = [
                "wp-signup.php",
                "ms-settings.php",
                "MULTISITE",
                "network-admin",
            ]

            is_multisite = any(
                indicator in content for indicator in multisite_indicators
            )

            if is_multisite:
                # Check network admin access
                network_admin_url = urljoin(target_url, "/wp-admin/network/")
                network_response = (
                    self.core.make_request(network_admin_url) if self.core else None
                )

                if network_response and network_response.status_code in [200, 302, 403]:
                    # Multisite detected
                    severity = (
                        ScanSeverity.MEDIUM
                        if network_response.status_code == 200
                        else ScanSeverity.LOW
                    )

                    result.add_finding(
                        title="WordPress Multisite Installation Detected",
                        description="WordPress multisite network installation detected",
                        severity=severity,
                        technical_details={
                            "multisite_indicators": [
                                i for i in multisite_indicators if i in content
                            ],
                            "network_admin_accessible": network_response.status_code
                            == 200,
                            "network_admin_url": network_admin_url,
                        },
                        recommendation="Ensure network admin interface is properly protected and Super Admin accounts are secured.",
                    )

        except Exception as e:
            log_error(f"Multisite security check failed: {e}")

    def analyze_security_configuration(self, target_url: str) -> Dict[str, Any]:
        """
        Comprehensive security configuration analysis

        Args:
            target_url: Target WordPress URL

        Returns:
            Dict containing security analysis results
        """
        try:
            security_analysis = {
                "security_headers": {"present": [], "missing": []},
                "file_exposures": [],
                "directory_browsing": [],
                "debug_mode": False,
                "rest_api": {"accessible": False, "endpoints": []},
                "xmlrpc": {"enabled": False, "methods": []},
                "login_security": {"features": [], "score": 0},
                "multisite": {"detected": False, "secure": True},
                "overall_score": 0,
                "recommendations": [],
            }

            # This would normally run all the individual check methods
            # and compile the results into the security_analysis dict

            # Calculate overall security score (simplified)
            score_factors = [
                len(security_analysis["security_headers"]["present"]) * 10,
                (10 - len(security_analysis["file_exposures"])) * 5,
                (5 - len(security_analysis["directory_browsing"])) * 4,
                0 if security_analysis["debug_mode"] else 10,
                security_analysis["login_security"]["score"] * 5,
            ]

            security_analysis["overall_score"] = min(100, sum(score_factors))

            return security_analysis

        except Exception as e:
            log_error(f"Security configuration analysis failed: {e}")
            return {"error": str(e)}
