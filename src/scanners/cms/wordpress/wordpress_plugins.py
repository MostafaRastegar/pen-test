"""
WordPress Plugin Enumeration and Security Analysis Module
Handles plugin detection, enumeration, and security assessment
"""

import re
import requests
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from src.core import ScanResult, ScanSeverity
from src.utils.logger import log_info, log_error, log_warning, log_success


class WordPressPlugins:
    """WordPress plugin enumeration and security analysis"""

    def __init__(self, scanner):
        """
        Initialize WordPress plugin analyzer

        Args:
            scanner: Reference to main WordPressScanner instance
        """
        self.scanner = scanner
        self.core = scanner.core if hasattr(scanner, "core") else None

        # Common WordPress plugins for enumeration
        self.common_plugins = [
            "akismet",
            "jetpack",
            "yoast-seo",
            "contact-form-7",
            "wp-super-cache",
            "wordfence",
            "elementor",
            "woocommerce",
            "all-in-one-seo-pack",
            "google-analytics-for-wordpress",
            "wp-optimize",
            "really-simple-ssl",
            "updraftplus",
            "wp-mail-smtp",
            "classic-editor",
        ]

        # Known vulnerable plugins (simplified database)
        self.vulnerable_plugins = {
            "revslider": {
                "versions": ["<5.4.8"],
                "vulnerabilities": ["Arbitrary File Upload", "SQL Injection"],
                "cvss_score": 9.8,
            },
            "wp-file-manager": {
                "versions": ["<6.9"],
                "vulnerabilities": ["Remote Code Execution"],
                "cvss_score": 9.8,
            },
            "formcraft": {
                "versions": ["<3.2.26"],
                "vulnerabilities": ["Arbitrary File Upload"],
                "cvss_score": 9.8,
            },
        }

    def enumerate_plugins(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """
        plugin enumeration with security analysis

        Args:
            target_url: Target WordPress URL
            result: ScanResult to store findings
            options: Scan options
        """
        try:
            log_info("Starting plugin enumeration with update status")

            # Get installed plugins using multiple methods
            plugins_found = []

            # Method 1: Source code analysis
            plugins_found.extend(self._detect_plugins_from_source(target_url))

            # Method 2: Common plugin probing
            plugins_found.extend(self._probe_common_plugins(target_url))

            # Method 3: WordPress API enumeration
            plugins_found.extend(self._enumerate_via_api(target_url))

            # Remove duplicates
            unique_plugins = {}
            for plugin in plugins_found:
                plugin_name = plugin.get("name", "")
                if plugin_name and plugin_name not in unique_plugins:
                    unique_plugins[plugin_name] = plugin

            plugins_found = list(unique_plugins.values())

            # Analyze each plugin for security issues
            for plugin in plugins_found:
                self._analyze_individual_plugin(target_url, plugin, result)

            # Add summary finding
            if plugins_found:
                self._add_plugin_summary_finding(result, plugins_found)

            log_success(
                f"plugin enumeration completed. Found {len(plugins_found)} plugins"
            )

        except Exception as e:
            log_error(f"plugin enumeration failed: {e}")

    def _detect_plugins_from_source(self, target_url: str) -> List[Dict[str, Any]]:
        """Detect plugins from WordPress source code"""
        plugins = []

        try:
            response = self.core.make_request(target_url) if self.core else None
            if response and response.status_code == 200:
                content = response.text

                # Look for plugin references in HTML source
                plugin_patterns = [
                    r'/wp-content/plugins/([^/\'"]+)',
                    r'wp-content/plugins/([^/\'"]+)',
                ]

                for pattern in plugin_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        if match not in [p["name"] for p in plugins]:
                            plugin_info = {
                                "name": match,
                                "path": f"/wp-content/plugins/{match}/",
                                "version": self._detect_plugin_version(
                                    target_url, match
                                ),
                                "detection_method": "source_analysis",
                            }
                            plugins.append(plugin_info)

        except Exception as e:
            log_error(f"Plugin detection from source failed: {e}")

        return plugins

    def _probe_common_plugins(self, target_url: str) -> List[Dict[str, Any]]:
        """Probe for common WordPress plugins"""
        plugins = []

        try:
            log_info("Probing for common WordPress plugins")

            for plugin_name in self.common_plugins:
                plugin_url = urljoin(target_url, f"/wp-content/plugins/{plugin_name}/")

                response = self.core.make_request(plugin_url) if self.core else None

                # Plugin exists if we get 200, 403, or redirect
                if response and response.status_code in [200, 403, 301, 302]:
                    plugin_info = {
                        "name": plugin_name,
                        "path": f"/wp-content/plugins/{plugin_name}/",
                        "version": self._detect_plugin_version(target_url, plugin_name),
                        "detection_method": "directory_probing",
                        "response_code": response.status_code,
                    }
                    plugins.append(plugin_info)

        except Exception as e:
            log_error(f"Common plugin probing failed: {e}")

        return plugins

    def _enumerate_via_api(self, target_url: str) -> List[Dict[str, Any]]:
        """Enumerate plugins via WordPress REST API if available"""
        plugins = []

        try:
            # Try WordPress REST API endpoints
            api_endpoints = [
                "/wp-json/wp/v2/plugins",
                "/wp-json/",
            ]

            for endpoint in api_endpoints:
                api_url = urljoin(target_url, endpoint)
                response = self.core.make_request(api_url) if self.core else None

                if response and response.status_code == 200:
                    try:
                        data = response.json()

                        if isinstance(data, list):
                            # Direct plugin list
                            for item in data:
                                if isinstance(item, dict) and "plugin" in item:
                                    plugin_info = {
                                        "name": item.get("plugin", "unknown"),
                                        "version": item.get("version", "unknown"),
                                        "detection_method": "rest_api",
                                        "api_data": item,
                                    }
                                    plugins.append(plugin_info)
                        elif isinstance(data, dict):
                            # Look for plugin references in API response
                            content_str = str(data)
                            plugin_matches = re.findall(
                                r'wp-content/plugins/([^/\'"]+)', content_str
                            )
                            for match in plugin_matches:
                                plugin_info = {
                                    "name": match,
                                    "path": f"/wp-content/plugins/{match}/",
                                    "detection_method": "api_reference",
                                }
                                plugins.append(plugin_info)

                    except (ValueError, KeyError):
                        continue

        except Exception as e:
            log_error(f"API plugin enumeration failed: {e}")

        return plugins

    def _detect_plugin_version(self, target_url: str, plugin_name: str) -> str:
        """Detect specific plugin version"""
        try:
            # Try to read plugin main file or readme
            plugin_paths = [
                f"/wp-content/plugins/{plugin_name}/{plugin_name}.php",
                f"/wp-content/plugins/{plugin_name}/readme.txt",
                f"/wp-content/plugins/{plugin_name}/README.txt",
                f"/wp-content/plugins/{plugin_name}/readme.md",
            ]

            for path in plugin_paths:
                plugin_url = urljoin(target_url, path)
                response = self.core.make_request(plugin_url) if self.core else None

                if response and response.status_code == 200:
                    content = response.text
                    version_patterns = [
                        r"Version:\s*([0-9.]+)",
                        r"Stable tag:\s*([0-9.]+)",
                        r"@version\s*([0-9.]+)",
                        r"\* Version:\s*([0-9.]+)",
                    ]

                    for pattern in version_patterns:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            return match.group(1)

        except Exception as e:
            log_error(f"Plugin version detection failed for {plugin_name}: {e}")

        return "unknown"

    def _analyze_individual_plugin(
        self, target_url: str, plugin: Dict[str, Any], result: ScanResult
    ) -> None:
        """Analyze individual plugin for security issues"""
        try:
            plugin_name = plugin.get("name", "unknown")
            plugin_version = plugin.get("version", "unknown")

            # Check plugin security status
            security_status = self._check_plugin_security_status(plugin)

            # Determine severity based on security analysis
            severity = ScanSeverity.INFO
            if security_status.get("outdated", False):
                severity = ScanSeverity.MEDIUM
            if security_status.get("vulnerable", False):
                severity = ScanSeverity.HIGH
            if security_status.get("abandoned", False):
                severity = ScanSeverity.HIGH

            result.add_finding(
                title=f"WordPress Plugin: {plugin_name}",
                description=f"Plugin detected - Version: {plugin_version}",
                severity=severity,
                technical_details={
                    "plugin_name": plugin_name,
                    "version": plugin_version,
                    "path": plugin.get("path", ""),
                    "detection_method": plugin.get("detection_method", "unknown"),
                    "security_status": security_status,
                },
                recommendation=self._get_plugin_recommendations(security_status),
            )

        except Exception as e:
            log_error(
                f"Plugin analysis failed for {plugin.get('name', 'unknown')}: {e}"
            )

    def _check_plugin_security_status(self, plugin: Dict[str, Any]) -> Dict[str, Any]:
        """Check plugin security status against known vulnerabilities"""
        plugin_name = plugin.get("name", "").lower()
        plugin_version = plugin.get("version", "unknown")

        security_status = {
            "vulnerable": False,
            "outdated": False,
            "abandoned": False,
            "custom_plugin": False,
            "vulnerabilities": [],
            "risk_level": "low",
        }

        try:
            # Check against known vulnerable plugins
            if plugin_name in self.vulnerable_plugins:
                vuln_info = self.vulnerable_plugins[plugin_name]
                security_status["vulnerable"] = True
                security_status["vulnerabilities"] = vuln_info.get(
                    "vulnerabilities", []
                )
                security_status["risk_level"] = "high"

            # Check if it's a custom plugin (not in common plugins list)
            if plugin_name not in [p.lower() for p in self.common_plugins]:
                security_status["custom_plugin"] = True
                security_status["risk_level"] = "medium"

            # Basic version analysis
            if plugin_version == "unknown":
                security_status["outdated"] = True
                security_status["risk_level"] = "medium"

        except Exception as e:
            log_error(f"Security status check failed for {plugin_name}: {e}")

        return security_status

    def _get_plugin_recommendations(self, security_status: Dict[str, Any]) -> str:
        """Get security recommendations for plugin"""
        recommendations = []

        if security_status.get("vulnerable", False):
            recommendations.append(
                "URGENT: Update or remove this plugin due to known vulnerabilities"
            )

        if security_status.get("outdated", False):
            recommendations.append("Update plugin to latest version")

        if security_status.get("abandoned", False):
            recommendations.append("Consider replacing this abandoned plugin")

        if security_status.get("custom_plugin", False):
            recommendations.append("Review custom plugin code for security issues")

        if not recommendations:
            recommendations.append(
                "Keep plugin updated and monitor for security advisories"
            )

        return ". ".join(recommendations)

    def _add_plugin_summary_finding(
        self, result: ScanResult, plugins: List[Dict[str, Any]]
    ) -> None:
        """Add summary finding for all detected plugins"""
        try:
            total_plugins = len(plugins)
            vulnerable_count = 0
            outdated_count = 0
            custom_count = 0

            for plugin in plugins:
                security_status = self._check_plugin_security_status(plugin)
                if security_status.get("vulnerable", False):
                    vulnerable_count += 1
                if security_status.get("outdated", False):
                    outdated_count += 1
                if security_status.get("custom_plugin", False):
                    custom_count += 1

            # Determine overall severity
            if vulnerable_count > 0:
                severity = ScanSeverity.HIGH
            elif outdated_count > 0:
                severity = ScanSeverity.MEDIUM
            else:
                severity = ScanSeverity.LOW

            result.add_finding(
                title=f"WordPress Plugin Summary ({total_plugins} plugins detected)",
                description=f"Found {total_plugins} WordPress plugins. Vulnerable: {vulnerable_count}, Outdated: {outdated_count}, Custom: {custom_count}",
                severity=severity,
                technical_details={
                    "total_plugins": total_plugins,
                    "vulnerable_plugins": vulnerable_count,
                    "outdated_plugins": outdated_count,
                    "custom_plugins": custom_count,
                    "plugin_list": [p.get("name", "unknown") for p in plugins],
                },
                recommendation="Regularly update all plugins, remove unused plugins, and monitor security advisories for installed plugins.",
            )

        except Exception as e:
            log_error(f"Plugin summary creation failed: {e}")

    def analyze_plugin_security(self, plugins: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Comprehensive plugin security analysis

        Args:
            plugins: List of detected plugins

        Returns:
            Dict containing security analysis results
        """
        try:
            analysis_results = {
                "total_plugins": len(plugins),
                "security_summary": {
                    "high_risk": 0,
                    "medium_risk": 0,
                    "low_risk": 0,
                },
                "vulnerabilities_found": [],
                "recommendations": [],
            }

            for plugin in plugins:
                security_status = self._check_plugin_security_status(plugin)

                if security_status.get("vulnerable", False):
                    analysis_results["security_summary"]["high_risk"] += 1
                    analysis_results["vulnerabilities_found"].extend(
                        security_status.get("vulnerabilities", [])
                    )
                elif security_status.get("outdated", False) or security_status.get(
                    "custom_plugin", False
                ):
                    analysis_results["security_summary"]["medium_risk"] += 1
                else:
                    analysis_results["security_summary"]["low_risk"] += 1

            # Generate recommendations
            if analysis_results["security_summary"]["high_risk"] > 0:
                analysis_results["recommendations"].append(
                    "Immediately update or remove vulnerable plugins"
                )

            if analysis_results["security_summary"]["medium_risk"] > 0:
                analysis_results["recommendations"].append(
                    "Update outdated plugins and review custom plugins"
                )

            analysis_results["recommendations"].append(
                "Implement regular plugin update schedule and security monitoring"
            )

            return analysis_results

        except Exception as e:
            log_error(f"Plugin security analysis failed: {e}")
            return {"error": str(e)}
