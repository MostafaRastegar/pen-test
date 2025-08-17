"""
WordPress Detection and Fingerprinting Module
Handles WordPress detection, version identification, and fingerprinting
"""

import re
import requests
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from src.core import ScanResult, ScanSeverity
from src.utils.logger import log_info, log_error, log_warning, log_success


class WordPressDetector:
    """WordPress detection and fingerprinting functionality"""

    def __init__(self, scanner):
        """
        Initialize WordPress detector

        Args:
            scanner: Reference to main WordPressScanner instance
        """
        self.scanner = scanner
        self.core = scanner.core if hasattr(scanner, "core") else None

    def detect_wordpress(self, target_url: str, result: ScanResult) -> bool:
        """
        Detect if target is running WordPress

        Args:
            target_url: Target URL
            result: ScanResult to store findings

        Returns:
            bool: True if WordPress detected
        """
        try:
            log_info("Detecting WordPress installation")

            wp_detected = False
            detection_methods = []

            # Method 1: Check main page for WordPress indicators
            try:
                response = self.core.make_request(target_url) if self.core else None
                if response and response.status_code == 200:
                    content = response.text.lower()

                    # Check for WordPress generators
                    if "wordpress" in content or "wp-content" in content:
                        wp_detected = True
                        detection_methods.append("Content analysis")

                    # Check for WordPress-specific meta tags
                    if "wp-includes" in content or "wp-admin" in content:
                        wp_detected = True
                        detection_methods.append("Meta tags")

            except requests.RequestException:
                pass

            # Method 2: Check for WordPress-specific paths
            wp_indicators = self.core.wp_indicators if self.core else {}
            for indicator, path in wp_indicators.items():
                try:
                    test_url = urljoin(target_url, path)
                    response = self.core.make_request(test_url) if self.core else None

                    if response and response.status_code in [200, 403, 301, 302]:
                        wp_detected = True
                        detection_methods.append(f"Path detection ({indicator})")
                        break

                except requests.RequestException:
                    continue

            # Method 3: Check wp-json API endpoint
            try:
                wp_json_url = urljoin(target_url, "/wp-json/")
                response = self.core.make_request(wp_json_url) if self.core else None

                if response and response.status_code == 200:
                    try:
                        json_data = response.json()
                        if "name" in json_data or "description" in json_data:
                            wp_detected = True
                            detection_methods.append("REST API detection")
                    except:
                        pass

            except requests.RequestException:
                pass

            # Add detection finding
            if wp_detected:
                result.add_finding(
                    title="WordPress Installation Detected",
                    description=f"WordPress CMS detected using: {', '.join(detection_methods)}",
                    severity=ScanSeverity.INFO,
                    technical_details={
                        "detection_methods": detection_methods,
                        "cms_type": "WordPress",
                        "target_url": target_url,
                    },
                    recommendation="Ensure WordPress is updated to the latest version and security hardening is implemented.",
                )

                log_success(f"WordPress detected via: {', '.join(detection_methods)}")
            else:
                log_warning(
                    "WordPress not detected - target may not be a WordPress site"
                )

            return wp_detected

        except Exception as e:
            log_error(f"WordPress detection failed: {e}")
            return False

    def detect_wordpress_version(
        self, target_url: str, result: ScanResult
    ) -> Optional[str]:
        """
        Detect WordPress version

        Args:
            target_url: Target URL
            result: ScanResult to store findings

        Returns:
            str: WordPress version if detected, None otherwise
        """
        try:
            log_info("Detecting WordPress version")

            version = None
            detection_method = None

            # Method 1: Check generator meta tag
            try:
                response = self.core.make_request(target_url) if self.core else None
                if response and response.status_code == 200:
                    content = response.text

                    # Look for WordPress generator meta tag
                    generator_match = re.search(
                        r'<meta name="generator" content="WordPress ([0-9.]+)',
                        content,
                        re.IGNORECASE,
                    )
                    if generator_match:
                        version = generator_match.group(1)
                        detection_method = "Generator meta tag"

            except requests.RequestException:
                pass

            # Method 2: Check readme.html
            if not version:
                try:
                    readme_url = urljoin(target_url, "/readme.html")
                    response = self.core.make_request(readme_url) if self.core else None

                    if response and response.status_code == 200:
                        content = response.text

                        # Look for version in readme
                        version_match = re.search(
                            r"Version ([0-9.]+)", content, re.IGNORECASE
                        )
                        if version_match:
                            version = version_match.group(1)
                            detection_method = "readme.html"

                except requests.RequestException:
                    pass

            # Method 3: Check wp-includes files
            if not version:
                version_files = [
                    "/wp-includes/version.php",
                    "/wp-admin/about.php",
                ]

                for file_path in version_files:
                    try:
                        file_url = urljoin(target_url, file_path)
                        response = (
                            self.core.make_request(file_url) if self.core else None
                        )

                        if response and response.status_code == 200:
                            content = response.text

                            # Look for version in file content
                            version_patterns = [
                                r"\$wp_version = ['\"]([0-9.]+)['\"]",
                                r"wp_version = ['\"]([0-9.]+)['\"]",
                                r"Version ([0-9.]+)",
                            ]

                            for pattern in version_patterns:
                                match = re.search(pattern, content)
                                if match:
                                    version = match.group(1)
                                    detection_method = f"File: {file_path}"
                                    break

                        if version:
                            break

                    except requests.RequestException:
                        continue

            # Method 4: Check CSS/JS files for version hints
            if not version:
                try:
                    response = self.core.make_request(target_url) if self.core else None
                    if response and response.status_code == 200:
                        content = response.text

                        # Look for version in CSS/JS file references
                        asset_matches = re.findall(
                            r'wp-(?:content|includes)/[^"\']*\?ver=([0-9.]+)', content
                        )
                        if asset_matches:
                            # Use most common version
                            version = max(set(asset_matches), key=asset_matches.count)
                            detection_method = "Asset version parameters"

                except requests.RequestException:
                    pass

            # Add version finding
            if version:
                severity = self._assess_version_security(version)

                result.add_finding(
                    title=f"WordPress Version: {version}",
                    description=f"WordPress version {version} detected via {detection_method}",
                    severity=severity,
                    technical_details={
                        "version": version,
                        "detection_method": detection_method,
                        "security_assessment": self._get_version_security_info(version),
                    },
                    recommendation=self._get_version_recommendations(version),
                )

                log_success(
                    f"WordPress version detected: {version} (via {detection_method})"
                )
            else:
                log_warning("WordPress version could not be determined")

            return version

        except Exception as e:
            log_error(f"Version detection failed: {e}")
            return None

    def _assess_version_security(self, version: str) -> ScanSeverity:
        """
        Assess security status of WordPress version

        Args:
            version: WordPress version string

        Returns:
            ScanSeverity: Security severity level
        """
        try:
            version_parts = [int(x) for x in version.split(".")]
            major, minor = version_parts[0], (
                version_parts[1] if len(version_parts) > 1 else 0
            )

            # Current stable versions (as of knowledge cutoff)
            if major >= 6 and minor >= 4:
                return ScanSeverity.LOW
            elif major >= 6 and minor >= 2:
                return ScanSeverity.MEDIUM
            elif major >= 5:
                return ScanSeverity.MEDIUM
            else:
                return ScanSeverity.HIGH

        except (ValueError, IndexError):
            return ScanSeverity.MEDIUM

    def _get_version_security_info(self, version: str) -> Dict[str, Any]:
        """
        Get security information for WordPress version

        Args:
            version: WordPress version string

        Returns:
            Dict containing security information
        """
        severity = self._assess_version_security(version)

        info = {
            "version": version,
            "risk_level": severity.value,
            "update_available": True,  # Assume updates available for security
        }

        try:
            version_parts = [int(x) for x in version.split(".")]
            major = version_parts[0]

            if major < 5:
                info["security_notes"] = (
                    "Very old version with known security vulnerabilities"
                )
                info["eol_status"] = "End of Life"
            elif major < 6:
                info["security_notes"] = "Older version, security updates recommended"
                info["eol_status"] = "Security updates only"
            else:
                info["security_notes"] = "Recent version, monitor for updates"
                info["eol_status"] = "Actively supported"

        except (ValueError, IndexError):
            info["security_notes"] = "Unable to assess version security"

        return info

    def _get_version_recommendations(self, version: str) -> str:
        """
        Get security recommendations for WordPress version

        Args:
            version: WordPress version string

        Returns:
            str: Security recommendations
        """
        severity = self._assess_version_security(version)

        if severity == ScanSeverity.HIGH:
            return (
                "URGENT: Update WordPress immediately. This version has known security vulnerabilities. "
                "Backup your site before updating and test in a staging environment."
            )
        elif severity == ScanSeverity.MEDIUM:
            return (
                "Update WordPress to the latest version. Ensure automatic updates are enabled "
                "for security releases and monitor WordPress security announcements."
            )
        else:
            return (
                "Keep WordPress updated to the latest version. Enable automatic security updates "
                "and regularly monitor for new releases."
            )
