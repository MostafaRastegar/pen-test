"""
WordPress Vulnerability Scanner Module - Refactored Modular Version
Phase 1.1 Implementation: CMS-Specific Vulnerability Scanners

This file has been refactored into multiple focused modules for better maintainability:
- wordpress_core.py: Core functionality and utilities
- wordpress_detector.py: WordPress detection and fingerprinting
- wordpress_plugins.py: Plugin enumeration and security analysis
- wordpress_themes.py: Theme enumeration and security analysis
- wordpress_users.py: User enumeration and security assessment
- wordpress_security.py: Security configuration checks

All existing functionality is preserved with the same public interface.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from src.core import ScannerBase, ScanResult, ScanStatus, ScanSeverity
from src.utils.logger import log_info, log_error, log_warning, log_success

# Import modular components
from .wordpress_core import WordPressCore
from .wordpress_detector import WordPressDetector
from .wordpress_plugins import WordPressPlugins
from .wordpress_themes import WordPressThemes
from .wordpress_users import WordPressUsers
from .wordpress_security import WordPressSecurity


class WordPressScanner(ScannerBase):
    """
    WordPress vulnerability scanner using WPScan and custom analysis

    Features:
    - Plugin vulnerability detection
    - Theme security analysis
    - User enumeration
    - Brute force protection testing
    - WordPress-specific CVE database integration
    - Version fingerprinting
    - Configuration security analysis

    This scanner has been refactored into modular components for better maintainability
    while preserving the exact same public interface and functionality.
    """

    def __init__(self, timeout: int = 300):
        """
        Initialize WordPress scanner

        Args:
            timeout: Scan timeout in seconds (default: 5 minutes)
        """
        super().__init__("wordpress_scanner", timeout=timeout)

        # Initialize core functionality first
        self.core = WordPressCore(self)

        # Initialize specialized modules
        self.detector = WordPressDetector(self)
        self.plugins = WordPressPlugins(self)
        self.themes = WordPressThemes(self)
        self.users = WordPressUsers(self)
        self.security = WordPressSecurity(self)

    def validate_target(self, target: str) -> bool:
        """
        Validate if target is appropriate for WordPress scanning

        Args:
            target: Target URL or domain

        Returns:
            bool: True if valid WordPress target, False otherwise
        """
        return self.core.validate_target(target)

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get scanner capabilities

        Returns:
            Dict containing scanner capabilities
        """
        return self.core.get_capabilities()

    def _execute_scan(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """
        Execute WordPress security scan (required by ScannerBase)

        Args:
            target: Target URL or domain
            options: Scan options

        Returns:
            ScanResult containing all findings
        """
        if options is None:
            options = {}

        # Normalize target URL
        target_url = self.core.normalize_target_url(target)

        # Create scan result
        result = ScanResult(
            scanner_name=self.name,
            target=target_url,
            status=ScanStatus.RUNNING,
            start_time=datetime.now(),
        )

        try:
            log_info(f"Starting WordPress security scan for: {target_url}")

            # Step 1: Detect WordPress installation
            wp_detected = self.detector.detect_wordpress(target_url, result)

            if not wp_detected:
                result.status = ScanStatus.COMPLETED
                result.end_time = datetime.now()
                log_warning(
                    "WordPress not detected - scan completed with limited results"
                )
                return result

            # Step 2: WordPress version detection
            self.detector.detect_wordpress_version(target_url, result)

            # Step 3: Plugin enumeration and security analysis
            if options.get("enumerate_plugins", True):
                self.plugins.enumerate_plugins(target_url, result, options)

            # Step 4: Theme enumeration and security analysis
            if options.get("enumerate_themes", True):
                self.themes.enumerate_themes(target_url, result, options)

            # Step 5: User enumeration and security assessment
            if options.get("enumerate_users", True):
                self.users.enumerate_users(target_url, result, options)

            # Step 6: Security configuration analysis
            if options.get("check_config", True):
                self.security.check_security_configurations(target_url, result, options)

            # Step 7: WPScan integration (if available and requested)
            if options.get("use_wpscan", True):
                self._integrate_wpscan(target_url, result, options)

            # Complete scan
            result.status = ScanStatus.COMPLETED
            result.end_time = datetime.now()

            scan_duration = (result.end_time - result.start_time).total_seconds()
            log_success(f"WordPress scan completed in {scan_duration:.2f} seconds")
            log_info(f"Found {len(result.findings)} security findings")

        except Exception as e:
            log_error(f"WordPress scan failed: {e}")
            result.status = ScanStatus.FAILED
            result.end_time = datetime.now()
            result.add_finding(
                title="Scan Error",
                description=f"WordPress scan encountered an error: {str(e)}",
                severity=ScanSeverity.HIGH,
                recommendation="Check target accessibility and try again",
            )

        return result

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Perform comprehensive WordPress security scan

        Args:
            target: Target URL or domain
            options: Scan options

        Returns:
            ScanResult containing all findings
        """
        if options is None:
            options = {}

        # Validate target
        if not self.validate_target(target):
            log_error(f"Invalid target: {target}")
            result = ScanResult(
                scanner_name=self.name,
                target=target,
                status=ScanStatus.FAILED,
                start_time=datetime.now(),
            )
            result.add_finding(
                title="Target Validation Failed",
                description=f"Target {target} is not valid for WordPress scanning",
                severity=ScanSeverity.HIGH,
                recommendation="Provide a valid URL or domain name",
            )
            return result

        # Execute the actual scan
        return self._execute_scan(target, options)

    def _integrate_wpscan(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """
        Integrate WPScan results if available

        Args:
            target_url: Target WordPress URL
            result: ScanResult to store findings
            options: Scan options
        """
        try:
            log_info("Attempting WPScan integration")

            # Build WPScan options
            wpscan_options = []

            if options.get("enumerate_plugins"):
                wpscan_options.extend(["--enumerate", "p"])
            if options.get("enumerate_themes"):
                wpscan_options.extend(["--enumerate", "t"])
            if options.get("enumerate_users"):
                wpscan_options.extend(["--enumerate", "u"])

            # Add API token if provided
            api_token = options.get("wpscan_api_token")
            if api_token:
                wpscan_options.extend(["--api-token", api_token])

            # Execute WPScan
            wpscan_result = self.core.execute_wpscan(target_url, wpscan_options)

            if wpscan_result.get("success"):
                self._process_wpscan_results(wpscan_result.get("data", {}), result)
            else:
                log_warning(f"WPScan execution failed: {wpscan_result.get('error')}")
                result.add_finding(
                    title="WPScan Integration Failed",
                    description=f"WPScan could not be executed: {wpscan_result.get('error')}",
                    severity=ScanSeverity.LOW,
                    recommendation="Install WPScan for enhanced vulnerability detection",
                )

        except Exception as e:
            log_error(f"WPScan integration failed: {e}")

    def _process_wpscan_results(
        self, wpscan_data: Dict[str, Any], result: ScanResult
    ) -> None:
        """
        Process and integrate WPScan results

        Args:
            wpscan_data: WPScan result data
            result: ScanResult to store findings
        """
        try:
            # Process WPScan vulnerabilities
            if isinstance(wpscan_data, dict):
                # Look for vulnerability information
                for key, value in wpscan_data.items():
                    if "vulnerabilities" in key.lower() and isinstance(value, list):
                        for vuln in value:
                            if isinstance(vuln, dict):
                                result.add_finding(
                                    title=f"WPScan Vulnerability: {vuln.get('title', 'Unknown')}",
                                    description=vuln.get(
                                        "description",
                                        "Vulnerability detected by WPScan",
                                    ),
                                    severity=ScanSeverity.HIGH,
                                    technical_details=vuln,
                                    recommendation="Review and apply security updates immediately",
                                )

        except Exception as e:
            log_error(f"WPScan result processing failed: {e}")

    # Legacy method compatibility - delegate to appropriate modules
    def detect_wordpress_version(
        self, target_url: str, result: ScanResult
    ) -> Optional[str]:
        """Legacy compatibility method"""
        return self.detector.detect_wordpress_version(target_url, result)

    def enumerate_plugins(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """Legacy compatibility method"""
        return self.plugins.enumerate_plugins(target_url, result, options)

    def enumerate_themes(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """Legacy compatibility method"""
        return self.themes.enumerate_themes(target_url, result, options)

    def enumerate_users(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """Legacy compatibility method"""
        return self.users.enumerate_users(target_url, result, options)

    def check_security_configurations(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """Legacy compatibility method"""
        return self.security.check_security_configurations(target_url, result, options)

    def analyze_plugin_security(self, plugins: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Legacy compatibility method"""
        return self.plugins.analyze_plugin_security(plugins)

    def analyze_theme_security(self, themes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Legacy compatibility method"""
        return self.themes.analyze_theme_security(themes)

    def assess_user_security(self, users: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Legacy compatibility method"""
        return self.users.assess_user_security(users)

    def analyze_security_configuration(self, target_url: str) -> Dict[str, Any]:
        """Legacy compatibility method"""
        return self.security.analyze_security_configuration(target_url)

    # Additional utility methods for backward compatibility
    def make_request(self, url: str, method: str = "GET", **kwargs):
        """Legacy compatibility method"""
        return self.core.make_request(url, method, **kwargs)

    def execute_wpscan(
        self, target_url: str, options: List[str] = None
    ) -> Dict[str, Any]:
        """Legacy compatibility method"""
        return self.core.execute_wpscan(target_url, options)
