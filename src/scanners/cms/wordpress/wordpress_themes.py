"""
WordPress Theme Enumeration and Security Analysis Module
Handles theme detection, enumeration, and security assessment
"""

import re
import requests
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from src.core import ScanResult, ScanSeverity
from src.utils.logger import log_info, log_error, log_warning, log_success


class WordPressThemes:
    """WordPress theme enumeration and security analysis"""

    def __init__(self, scanner):
        """
        Initialize WordPress theme analyzer

        Args:
            scanner: Reference to main WordPressScanner instance
        """
        self.scanner = scanner
        self.core = scanner.core if hasattr(scanner, "core") else None

        # Common WordPress themes for enumeration
        self.common_themes = [
            "twentytwentyfour",
            "twentytwentythree",
            "twentytwentytwo",
            "twentytwentyone",
            "twentytwenty",
            "twentynineteen",
            "twentyeighteen",
            "twentyseventeen",
            "astra",
            "hello-elementor",
            "oceanwp",
            "generatepress",
            "kadence",
            "neve",
            "storefront",
        ]

        # Known vulnerable themes (simplified database)
        self.vulnerable_themes = {
            "total": {
                "versions": ["<2.6.1"],
                "vulnerabilities": ["Cross-Site Scripting"],
                "cvss_score": 6.1,
            },
            "enfold": {
                "versions": ["<4.5.7"],
                "vulnerabilities": ["SQL Injection", "XSS"],
                "cvss_score": 8.8,
            },
            "parallax": {
                "versions": ["<1.0.9"],
                "vulnerabilities": ["Remote File Inclusion"],
                "cvss_score": 9.8,
            },
        }

    def enumerate_themes(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """
        Enhanced theme enumeration with security analysis

        Args:
            target_url: Target WordPress URL
            result: ScanResult to store findings
            options: Scan options
        """
        try:
            log_info("Starting enhanced theme enumeration")

            # Detect active theme
            active_theme = self._detect_active_theme(target_url)
            if active_theme:
                theme_security = self._analyze_theme_security(target_url, active_theme)

                severity = ScanSeverity.INFO
                if theme_security["outdated"]:
                    severity = ScanSeverity.MEDIUM
                if theme_security["vulnerable"]:
                    severity = ScanSeverity.HIGH

                result.add_finding(
                    title=f"Active WordPress Theme: {active_theme['name']}",
                    description=f"Active theme detected - Version: {active_theme.get('version', 'Unknown')}",
                    severity=severity,
                    technical_details={
                        "theme_name": active_theme["name"],
                        "version": active_theme.get("version", "Unknown"),
                        "path": active_theme["path"],
                        "security_analysis": theme_security,
                    },
                    recommendation=self._get_theme_recommendations(theme_security),
                )

            # Enumerate additional themes
            additional_themes = self._enumerate_installed_themes(target_url)
            for theme in additional_themes:
                if theme["name"] != active_theme.get("name", ""):
                    theme_security = self._analyze_theme_security(target_url, theme)

                    severity = ScanSeverity.LOW
                    if theme_security["outdated"]:
                        severity = ScanSeverity.MEDIUM
                    if theme_security["vulnerable"]:
                        severity = ScanSeverity.HIGH

                    result.add_finding(
                        title=f"Installed WordPress Theme: {theme['name']}",
                        description=f"Additional theme detected - Version: {theme.get('version', 'Unknown')}",
                        severity=severity,
                        technical_details={
                            "theme_name": theme["name"],
                            "version": theme.get("version", "Unknown"),
                            "path": theme["path"],
                            "security_analysis": theme_security,
                        },
                        recommendation="Consider removing unused themes to reduce attack surface.",
                    )

            log_success("Enhanced theme enumeration completed")

        except Exception as e:
            log_error(f"Enhanced theme enumeration failed: {e}")

    def _detect_active_theme(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Detect active WordPress theme"""
        try:
            response = self.core.make_request(target_url) if self.core else None
            if not response or response.status_code != 200:
                return None

            content = response.text

            # Method 1: Look for theme stylesheet link
            stylesheet_pattern = r'/wp-content/themes/([^/\'"]+)/style\.css'
            stylesheet_match = re.search(stylesheet_pattern, content)

            if stylesheet_match:
                theme_name = stylesheet_match.group(1)
                theme_info = {
                    "name": theme_name,
                    "path": f"/wp-content/themes/{theme_name}/",
                    "detection_method": "stylesheet_link",
                    "version": self._detect_theme_version(target_url, theme_name),
                }
                return theme_info

            # Method 2: Look for theme template references
            template_patterns = [
                r'/wp-content/themes/([^/\'"]+)/',
                r'wp-content/themes/([^/\'"]+)/',
            ]

            for pattern in template_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    # Use most common theme name
                    theme_name = max(set(matches), key=matches.count)
                    theme_info = {
                        "name": theme_name,
                        "path": f"/wp-content/themes/{theme_name}/",
                        "detection_method": "template_reference",
                        "version": self._detect_theme_version(target_url, theme_name),
                    }
                    return theme_info

            return None

        except Exception as e:
            log_error(f"Active theme detection failed: {e}")
            return None

    def _enumerate_installed_themes(self, target_url: str) -> List[Dict[str, Any]]:
        """Enumerate all installed themes"""
        themes = []

        try:
            log_info("Probing for common WordPress themes")

            for theme_name in self.common_themes:
                theme_url = urljoin(target_url, f"/wp-content/themes/{theme_name}/")

                response = self.core.make_request(theme_url) if self.core else None

                # Theme exists if we get 200, 403, or redirect
                if response and response.status_code in [200, 403, 301, 302]:
                    theme_info = {
                        "name": theme_name,
                        "path": f"/wp-content/themes/{theme_name}/",
                        "version": self._detect_theme_version(target_url, theme_name),
                        "detection_method": "directory_probing",
                        "response_code": response.status_code,
                    }
                    themes.append(theme_info)

        except Exception as e:
            log_error(f"Theme enumeration failed: {e}")

        return themes

    def _detect_theme_version(self, target_url: str, theme_name: str) -> str:
        """Detect specific theme version"""
        try:
            # Try to read theme style.css or readme files
            theme_paths = [
                f"/wp-content/themes/{theme_name}/style.css",
                f"/wp-content/themes/{theme_name}/readme.txt",
                f"/wp-content/themes/{theme_name}/README.txt",
                f"/wp-content/themes/{theme_name}/readme.md",
            ]

            for path in theme_paths:
                theme_url = urljoin(target_url, path)
                response = self.core.make_request(theme_url) if self.core else None

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
            log_error(f"Theme version detection failed for {theme_name}: {e}")

        return "unknown"

    def _analyze_theme_security(
        self, target_url: str, theme: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze theme security status"""
        theme_name = theme.get("name", "").lower()
        theme_version = theme.get("version", "unknown")

        security_analysis = {
            "vulnerable": False,
            "outdated": False,
            "custom_theme": False,
            "vulnerabilities": [],
            "risk_level": "low",
            "security_notes": [],
        }

        try:
            # Check against known vulnerable themes
            if theme_name in self.vulnerable_themes:
                vuln_info = self.vulnerable_themes[theme_name]
                security_analysis["vulnerable"] = True
                security_analysis["vulnerabilities"] = vuln_info.get(
                    "vulnerabilities", []
                )
                security_analysis["risk_level"] = "high"
                security_analysis["security_notes"].append(
                    "Known security vulnerabilities"
                )

            # Check if it's a custom theme (not in common themes list)
            if theme_name not in [t.lower() for t in self.common_themes]:
                security_analysis["custom_theme"] = True
                security_analysis["risk_level"] = "medium"
                security_analysis["security_notes"].append(
                    "Custom theme - requires manual security review"
                )

            # Check for default themes that should be removed
            default_old_themes = [
                "twentyfifteen",
                "twentysixteen",
                "twentyseventeen",
                "twentyeighteen",
                "twentynineteen",
            ]
            if theme_name in default_old_themes:
                security_analysis["outdated"] = True
                security_analysis["security_notes"].append(
                    "Old default theme - consider removal"
                )

            # Basic version analysis
            if theme_version == "unknown":
                security_analysis["outdated"] = True
                security_analysis["security_notes"].append(
                    "Version unknown - update recommended"
                )

            # Check for theme security best practices
            self._check_theme_security_features(target_url, theme, security_analysis)

        except Exception as e:
            log_error(f"Theme security analysis failed for {theme_name}: {e}")
            security_analysis["security_notes"].append(f"Analysis error: {str(e)}")

        return security_analysis

    def _check_theme_security_features(
        self, target_url: str, theme: Dict[str, Any], analysis: Dict[str, Any]
    ) -> None:
        """Check theme for security features and issues"""
        try:
            theme_name = theme.get("name", "")

            # Check for common security issues in theme files
            security_files = [
                f"/wp-content/themes/{theme_name}/functions.php",
                f"/wp-content/themes/{theme_name}/index.php",
            ]

            for file_path in security_files:
                file_url = urljoin(target_url, file_path)
                response = self.core.make_request(file_url) if self.core else None

                if response and response.status_code == 200:
                    content = response.text

                    # Check for potentially dangerous functions
                    dangerous_functions = [
                        "eval(",
                        "base64_decode(",
                        "exec(",
                        "system(",
                        "shell_exec(",
                        "passthru(",
                        "file_get_contents(",
                    ]

                    for func in dangerous_functions:
                        if func in content:
                            analysis["risk_level"] = "high"
                            analysis["security_notes"].append(
                                f"Potentially dangerous function found: {func}"
                            )

                    # Check for proper input sanitization
                    if "$_GET" in content or "$_POST" in content:
                        if "sanitize_" not in content and "esc_" not in content:
                            analysis["risk_level"] = "medium"
                            analysis["security_notes"].append(
                                "Input handling without proper sanitization"
                            )

        except Exception as e:
            log_error(f"Theme security feature check failed: {e}")

    def _get_theme_recommendations(self, security_analysis: Dict[str, Any]) -> str:
        """Get security recommendations for theme"""
        recommendations = []

        if security_analysis.get("vulnerable", False):
            recommendations.append(
                "URGENT: Update or replace theme due to known vulnerabilities"
            )

        if security_analysis.get("outdated", False):
            recommendations.append("Update theme to latest version")

        if security_analysis.get("custom_theme", False):
            recommendations.append("Conduct security review of custom theme code")

        security_notes = security_analysis.get("security_notes", [])
        if security_notes:
            recommendations.extend(security_notes)

        if not recommendations:
            recommendations.append(
                "Keep theme updated and monitor for security advisories"
            )

        return ". ".join(recommendations)

    def analyze_theme_security(self, themes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Comprehensive theme security analysis

        Args:
            themes: List of detected themes

        Returns:
            Dict containing security analysis results
        """
        try:
            analysis_results = {
                "total_themes": len(themes),
                "security_summary": {
                    "high_risk": 0,
                    "medium_risk": 0,
                    "low_risk": 0,
                },
                "vulnerabilities_found": [],
                "recommendations": [],
            }

            for theme in themes:
                # Analyze each theme (this would normally call _analyze_theme_security)
                # For summary analysis, we'll do simplified checks
                theme_name = theme.get("name", "").lower()

                if theme_name in self.vulnerable_themes:
                    analysis_results["security_summary"]["high_risk"] += 1
                    vuln_info = self.vulnerable_themes[theme_name]
                    analysis_results["vulnerabilities_found"].extend(
                        vuln_info.get("vulnerabilities", [])
                    )
                elif theme_name not in [t.lower() for t in self.common_themes]:
                    analysis_results["security_summary"]["medium_risk"] += 1
                else:
                    analysis_results["security_summary"]["low_risk"] += 1

            # Generate recommendations
            if analysis_results["security_summary"]["high_risk"] > 0:
                analysis_results["recommendations"].append(
                    "Immediately update or replace vulnerable themes"
                )

            if analysis_results["security_summary"]["medium_risk"] > 0:
                analysis_results["recommendations"].append(
                    "Review custom themes and remove unused themes"
                )

            analysis_results["recommendations"].extend(
                [
                    "Keep active theme updated to latest version",
                    "Remove inactive/unused themes to reduce attack surface",
                    "Regularly monitor theme security advisories",
                ]
            )

            return analysis_results

        except Exception as e:
            log_error(f"Theme security analysis failed: {e}")
            return {"error": str(e)}
