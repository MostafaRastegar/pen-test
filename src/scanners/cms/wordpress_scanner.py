"""
WordPress Vulnerability Scanner Module - WPScan Integration
Phase 1.1 Implementation: CMS-Specific Vulnerability Scanners
"""

import json
import re
import requests
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse, urljoin

from src.core import ScannerBase, ScanResult, ScanStatus, ScanSeverity
from src.core import CommandExecutor, validate_url, validate_domain
from src.utils.logger import log_info, log_error, log_warning, log_success


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
    """

    def __init__(self, timeout: int = 300):
        """
        Initialize WordPress scanner

        Args:
            timeout: Scan timeout in seconds (default: 5 minutes)
        """
        super().__init__("wordpress_scanner", timeout=timeout)
        self.executor = CommandExecutor(timeout=self.timeout)

        # HTTP session for WordPress detection
        self.session = requests.Session()
        self.session.timeout = 30
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

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get scanner capabilities and requirements

        Returns:
            Dict containing scanner information
        """
        return {
            "name": "WordPress Scanner",
            "description": "WordPress security assessment using WPScan integration",
            "version": "1.0.0",
            "supported_targets": ["URLs", "domains"],
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
                "Plugin vulnerability detection",
                "Theme security analysis",
                "User enumeration",
                "Version fingerprinting",
                "XML-RPC testing",
                "WordPress API analysis",
                "Configuration security checks",
            ],
            "dependencies": {
                "wpscan": self._check_wpscan_available(),
                "requests": "Available",
                "json": "Available",
            },
            "estimated_time": "3-10 minutes (depending on scope)",
        }

    def _execute_scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """
        Execute WordPress vulnerability scan

        Args:
            target: Target to scan
            options: Scan configuration options

        Returns:
            ScanResult: Scan results
        """
        result = ScanResult(
            scanner_name=self.name,
            target=target,
            status=ScanStatus.RUNNING,
            start_time=datetime.now(),
        )

        try:
            # Normalize target URL
            target_url = self._normalize_target_url(target, options)
            result.target = target_url

            log_info(f"Starting WordPress scan for: {target_url}")

            # Step 1: WordPress Detection
            wp_detected = self._detect_wordpress(target_url, result)
            if not wp_detected:
                result.add_finding(
                    "WordPress Not Detected",
                    "Target does not appear to be running WordPress",
                    ScanSeverity.INFO,
                )
                log_warning("WordPress not detected, skipping specialized scans")
                result.status = ScanStatus.COMPLETED
                result.end_time = datetime.now()
                return result

            # Step 2: Version Detection
            self._detect_wp_version(target_url, result)

            # Step 3: Plugin Enumeration
            if options.get("enumerate_plugins", True):
                self._enumerate_plugins(target_url, result, options)

            # Step 4: Theme Enumeration
            if options.get("enumerate_themes", True):
                self._enumerate_themes(target_url, result, options)

            # Step 5: User Enumeration
            if options.get("enumerate_users", True):
                self._enumerate_users(target_url, result, options)

            # Step 6: WPScan Integration (if available)
            if options.get("use_wpscan", True):
                self._run_wpscan(target_url, result, options)

            # Step 7: Security Configuration Analysis
            self._analyze_security_config(target_url, result)

            # Step 8: XML-RPC Testing
            self._test_xmlrpc(target_url, result)

            result.status = ScanStatus.COMPLETED
            result.end_time = datetime.now()

            log_success(
                f"WordPress scan completed. Found {len(result.findings)} findings"
            )

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(f"WordPress scan failed: {str(e)}")
            self.logger.error(f"WordPress scan error: {e}")
            result.end_time = datetime.now()

        return result

    def _normalize_target_url(self, target: str, options: Dict[str, Any]) -> str:
        """
        Normalize target to proper URL format

        Args:
            target: Target string
            options: Scan options

        Returns:
            str: Normalized URL
        """
        if target.startswith(("http://", "https://")):
            return target.rstrip("/")

        # Default to HTTPS, fallback to HTTP if needed
        scheme = options.get("scheme", "https")
        port = options.get("port")

        if port:
            return f"{scheme}://{target}:{port}"
        else:
            return f"{scheme}://{target}"

    def _detect_wordpress(self, target_url: str, result: ScanResult) -> bool:
        """
        Detect if target is running WordPress

        Args:
            target_url: Target URL
            result: ScanResult to populate

        Returns:
            bool: True if WordPress detected
        """
        try:
            log_info("Detecting WordPress installation...")

            wp_indicators_found = []

            # Check for common WordPress paths and files
            for indicator, path in self.wp_indicators.items():
                test_url = urljoin(target_url, path)
                try:
                    response = self.session.get(
                        test_url, timeout=10, allow_redirects=False
                    )
                    if response.status_code in [200, 301, 302, 403]:
                        wp_indicators_found.append(indicator)
                        log_info(f"  ✓ Found WordPress indicator: {path}")
                except:
                    continue

            # Check HTML content for WordPress signatures
            try:
                response = self.session.get(target_url, timeout=15)
                if response.status_code == 200:
                    content = response.text.lower()

                    # WordPress generator meta tag
                    if "wp-content" in content:
                        wp_indicators_found.append("wp_content_html")
                    if "wordpress" in content:
                        wp_indicators_found.append("wordpress_html")
                    if "wp-json" in content:
                        wp_indicators_found.append("wp_json_html")

            except Exception as e:
                log_warning(f"Could not analyze HTML content: {e}")

            # Determine if WordPress is detected
            wp_detected = len(wp_indicators_found) >= 2

            if wp_detected:
                result.add_finding(
                    "WordPress Installation Detected",
                    f"WordPress installation detected. Indicators found: {', '.join(wp_indicators_found)}",
                    ScanSeverity.INFO,
                    indicators=wp_indicators_found,
                    confidence="High" if len(wp_indicators_found) >= 3 else "Medium",
                )
                log_success(
                    f"WordPress detected with {len(wp_indicators_found)} indicators"
                )
            else:
                log_info("WordPress not detected")

            return wp_detected

        except Exception as e:
            log_error(f"WordPress detection failed: {e}")
            result.errors.append(f"WordPress detection error: {str(e)}")
            return False

    def _detect_wp_version(self, target_url: str, result: ScanResult) -> Optional[str]:
        """
        Detect WordPress version

        Args:
            target_url: Target URL
            result: ScanResult to populate

        Returns:
            Optional[str]: WordPress version if detected
        """
        try:
            log_info("Detecting WordPress version...")

            version = None
            detection_method = None

            # Method 1: Check readme.html
            try:
                readme_url = urljoin(target_url, "/readme.html")
                response = self.session.get(readme_url, timeout=10)
                if response.status_code == 200:
                    # Look for version in readme
                    version_match = re.search(
                        r"Version\s+(\d+\.\d+(?:\.\d+)?)", response.text
                    )
                    if version_match:
                        version = version_match.group(1)
                        detection_method = "readme.html"
            except:
                pass

            # Method 2: Check generator meta tag
            if not version:
                try:
                    response = self.session.get(target_url, timeout=10)
                    if response.status_code == 200:
                        # Look for WordPress generator
                        gen_match = re.search(
                            r'<meta name="generator" content="WordPress ([^"]+)"',
                            response.text,
                            re.IGNORECASE,
                        )
                        if gen_match:
                            version = gen_match.group(1)
                            detection_method = "generator meta tag"
                except:
                    pass

            # Method 3: Check RSS feed
            if not version:
                try:
                    rss_url = urljoin(target_url, "/feed/")
                    response = self.session.get(rss_url, timeout=10)
                    if response.status_code == 200:
                        gen_match = re.search(
                            r"<generator>.*WordPress ([^<]+)</generator>",
                            response.text,
                            re.IGNORECASE,
                        )
                        if gen_match:
                            version = gen_match.group(1)
                            detection_method = "RSS feed"
                except:
                    pass

            if version:
                # Check if version is outdated
                severity = self._assess_version_security(version)

                result.add_finding(
                    "WordPress Version Detected",
                    f"WordPress version {version} detected via {detection_method}",
                    severity,
                    version=version,
                    detection_method=detection_method,
                    recommendation="Keep WordPress updated to the latest version",
                )
                log_success(
                    f"WordPress version detected: {version} (via {detection_method})"
                )
            else:
                result.add_finding(
                    "WordPress Version Not Detected",
                    "Could not determine WordPress version (version disclosure may be disabled)",
                    ScanSeverity.INFO,
                )
                log_info("WordPress version could not be determined")

            return version

        except Exception as e:
            log_error(f"WordPress version detection failed: {e}")
            result.errors.append(f"Version detection error: {str(e)}")
            return None

    def _enumerate_plugins(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """
        Enumerate WordPress plugins

        Args:
            target_url: Target URL
            result: ScanResult to populate
            options: Scan options
        """
        try:
            log_info("Enumerating WordPress plugins...")

            plugins_found = []

            # Method 1: Check common plugin paths
            common_plugins = [
                "akismet",
                "jetpack",
                "yoast-seo",
                "contact-form-7",
                "wordfence",
                "wp-super-cache",
                "nextgen-gallery",
                "all-in-one-seo-pack",
                "wp-smushit",
                "backwpup",
                "updraftplus",
                "elementor",
                "woocommerce",
            ]

            for plugin in common_plugins:
                plugin_url = f"{target_url}/wp-content/plugins/{plugin}/"
                try:
                    response = self.session.get(
                        plugin_url, timeout=5, allow_redirects=False
                    )
                    if response.status_code in [
                        200,
                        403,
                    ]:  # 403 often means plugin exists but is protected
                        plugins_found.append(plugin)
                        log_info(f"  ✓ Found plugin: {plugin}")
                except:
                    continue

            # Method 2: Parse HTML for plugin references
            try:
                response = self.session.get(target_url, timeout=15)
                if response.status_code == 200:
                    content = response.text

                    # Look for plugin CSS/JS includes
                    plugin_matches = re.findall(
                        r"/wp-content/plugins/([^/]+)/", content
                    )
                    for plugin in set(plugin_matches):
                        if plugin not in plugins_found:
                            plugins_found.append(plugin)

            except Exception as e:
                log_warning(f"Could not parse HTML for plugins: {e}")

            # Add findings for discovered plugins
            if plugins_found:
                result.add_finding(
                    "WordPress Plugins Detected",
                    f"Found {len(plugins_found)} WordPress plugins: {', '.join(plugins_found)}",
                    ScanSeverity.INFO,
                    plugins=plugins_found,
                    count=len(plugins_found),
                    recommendation="Keep all plugins updated and remove unused plugins",
                )
                log_success(f"Found {len(plugins_found)} WordPress plugins")
            else:
                result.add_finding(
                    "No WordPress Plugins Detected",
                    "No WordPress plugins were detected (plugin disclosure may be disabled)",
                    ScanSeverity.INFO,
                )
                log_info("No WordPress plugins detected")

        except Exception as e:
            log_error(f"Plugin enumeration failed: {e}")
            result.errors.append(f"Plugin enumeration error: {str(e)}")

    def _enumerate_themes(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """
        Enumerate WordPress themes

        Args:
            target_url: Target URL
            result: ScanResult to populate
            options: Scan options
        """
        try:
            log_info("Enumerating WordPress themes...")

            themes_found = []
            active_theme = None

            # Method 1: Check active theme via CSS includes
            try:
                response = self.session.get(target_url, timeout=15)
                if response.status_code == 200:
                    content = response.text

                    # Look for theme CSS includes
                    theme_matches = re.findall(r"/wp-content/themes/([^/]+)/", content)
                    if theme_matches:
                        active_theme = theme_matches[
                            0
                        ]  # First one is usually active theme
                        themes_found.extend(set(theme_matches))

            except Exception as e:
                log_warning(f"Could not detect active theme: {e}")

            # Method 2: Check common theme paths
            common_themes = [
                "twentytwentyfour",
                "twentytwentythree",
                "twentytwentytwo",
                "twentytwentyone",
                "twentytwenty",
                "twentynineteen",
                "astra",
                "oceanwp",
                "generatepress",
                "neve",
                "kadence",
                "blocksy",
            ]

            for theme in common_themes:
                if theme not in themes_found:
                    theme_url = f"{target_url}/wp-content/themes/{theme}/"
                    try:
                        response = self.session.get(
                            theme_url, timeout=5, allow_redirects=False
                        )
                        if response.status_code in [200, 403]:
                            themes_found.append(theme)
                            log_info(f"  ✓ Found theme: {theme}")
                    except:
                        continue

            # Add findings
            if themes_found:
                finding_desc = f"Found {len(themes_found)} WordPress themes: {', '.join(themes_found)}"
                if active_theme:
                    finding_desc += f" (Active: {active_theme})"

                result.add_finding(
                    "WordPress Themes Detected",
                    finding_desc,
                    ScanSeverity.INFO,
                    themes=themes_found,
                    active_theme=active_theme,
                    count=len(themes_found),
                    recommendation="Keep themes updated and remove unused themes",
                )
                log_success(
                    f"Found {len(themes_found)} WordPress themes"
                    + (f" (Active: {active_theme})" if active_theme else "")
                )
            else:
                result.add_finding(
                    "No WordPress Themes Detected",
                    "No WordPress themes were detected (theme disclosure may be disabled)",
                    ScanSeverity.INFO,
                )

        except Exception as e:
            log_error(f"Theme enumeration failed: {e}")
            result.errors.append(f"Theme enumeration error: {str(e)}")

    def _enumerate_users(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """
        Enumerate WordPress users

        Args:
            target_url: Target URL
            result: ScanResult to populate
            options: Scan options
        """
        try:
            log_info("Enumerating WordPress users...")

            users_found = []

            # Method 1: WordPress REST API (wp-json/wp/v2/users)
            try:
                api_url = urljoin(target_url, "/wp-json/wp/v2/users")
                response = self.session.get(api_url, timeout=10)
                if response.status_code == 200:
                    users_data = response.json()
                    if isinstance(users_data, list):
                        for user in users_data:
                            if "slug" in user:
                                users_found.append(user["slug"])
                                log_info(f"  ✓ Found user via API: {user['slug']}")
            except:
                pass

            # Method 2: Author archive enumeration (/?author=1, /?author=2, etc.)
            if not users_found:
                for user_id in range(1, 11):  # Check first 10 user IDs
                    try:
                        author_url = f"{target_url}/?author={user_id}"
                        response = self.session.get(
                            author_url, timeout=5, allow_redirects=True
                        )

                        if response.status_code == 200 and response.url != target_url:
                            # Extract username from redirected URL
                            redirected_url = response.url
                            if "/author/" in redirected_url:
                                username = redirected_url.split("/author/")[-1].rstrip(
                                    "/"
                                )
                                if username and username not in users_found:
                                    users_found.append(username)
                                    log_info(
                                        f"  ✓ Found user via author archive: {username}"
                                    )
                    except:
                        continue

            # Method 3: Check common usernames
            if not users_found:
                common_users = [
                    "admin",
                    "administrator",
                    "wp-admin",
                    "test",
                    "demo",
                    "user",
                ]
                login_url = urljoin(target_url, "/wp-login.php")

                for username in common_users:
                    try:
                        # Try to determine if username exists via login error messages
                        data = {
                            "log": username,
                            "pwd": "invalid_password_test_12345",
                            "wp-submit": "Log In",
                        }
                        response = self.session.post(login_url, data=data, timeout=10)

                        if response.status_code == 200:
                            # Different error messages can indicate if user exists
                            if "incorrect password" in response.text.lower():
                                users_found.append(username)
                                log_info(f"  ✓ Found user via login test: {username}")

                    except:
                        continue

            # Assess security implications
            if users_found:
                severity = (
                    ScanSeverity.MEDIUM if len(users_found) > 3 else ScanSeverity.LOW
                )

                result.add_finding(
                    "WordPress Users Enumerated",
                    f"Found {len(users_found)} WordPress users: {', '.join(users_found)}",
                    severity,
                    users=users_found,
                    count=len(users_found),
                    recommendation="Consider disabling user enumeration and implement strong password policies",
                )
                log_success(f"Found {len(users_found)} WordPress users")
            else:
                result.add_finding(
                    "WordPress User Enumeration Blocked",
                    "Could not enumerate WordPress users (enumeration may be disabled)",
                    ScanSeverity.INFO,
                    recommendation="This is a good security practice",
                )
                log_info("User enumeration appears to be blocked")

        except Exception as e:
            log_error(f"User enumeration failed: {e}")
            result.errors.append(f"User enumeration error: {str(e)}")

    def _run_wpscan(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """
        Run WPScan for comprehensive vulnerability assessment

        Args:
            target_url: Target URL
            result: ScanResult to populate
            options: Scan options
        """
        try:
            if not self._check_wpscan_available()["available"]:
                log_warning("WPScan not available, skipping WPScan analysis")
                return

            log_info("Running WPScan for comprehensive analysis...")

            # Build WPScan command
            cmd = [
                "wpscan",
                "--url",
                target_url,
                "--format",
                "json",
                "--no-banner",
                "--random-user-agent",
            ]

            # Add enumeration options
            if options.get("enumerate_plugins", True):
                cmd.extend(["--enumerate", "p"])
            if options.get("enumerate_themes", True):
                cmd.extend(["--enumerate", "t"])
            if options.get("enumerate_users", True):
                cmd.extend(["--enumerate", "u"])

            # Add API token if provided
            api_token = options.get("wpscan_api_token")
            if api_token:
                cmd.extend(["--api-token", api_token])

            # Execute WPScan
            wpscan_result = self.executor.execute_command(cmd, timeout=300)

            if wpscan_result.returncode == 0 and wpscan_result.stdout:
                self._parse_wpscan_output(wpscan_result.stdout, result)
                result.raw_output += f"\n--- WPScan Output ---\n{wpscan_result.stdout}"
            else:
                log_warning(f"WPScan execution issues: {wpscan_result.stderr}")
                result.errors.append(f"WPScan error: {wpscan_result.stderr}")

        except Exception as e:
            log_error(f"WPScan execution failed: {e}")
            result.errors.append(f"WPScan execution error: {str(e)}")

    def _parse_wpscan_output(self, wpscan_output: str, result: ScanResult) -> None:
        """
        Parse WPScan JSON output and extract findings

        Args:
            wpscan_output: WPScan JSON output
            result: ScanResult to populate
        """
        try:
            wpscan_data = json.loads(wpscan_output)

            # Parse vulnerabilities
            vulnerabilities = []

            # WordPress core vulnerabilities
            if "version" in wpscan_data and "vulnerabilities" in wpscan_data["version"]:
                for vuln in wpscan_data["version"]["vulnerabilities"]:
                    vulnerabilities.append(
                        {
                            "component": "WordPress Core",
                            "title": vuln.get("title", "Unknown vulnerability"),
                            "type": vuln.get("vuln_type", "Unknown"),
                            "references": vuln.get("references", {}),
                        }
                    )

            # Plugin vulnerabilities
            if "plugins" in wpscan_data:
                for plugin_name, plugin_data in wpscan_data["plugins"].items():
                    if "vulnerabilities" in plugin_data:
                        for vuln in plugin_data["vulnerabilities"]:
                            vulnerabilities.append(
                                {
                                    "component": f"Plugin: {plugin_name}",
                                    "title": vuln.get("title", "Unknown vulnerability"),
                                    "type": vuln.get("vuln_type", "Unknown"),
                                    "references": vuln.get("references", {}),
                                }
                            )

            # Theme vulnerabilities
            if "themes" in wpscan_data:
                for theme_name, theme_data in wpscan_data["themes"].items():
                    if "vulnerabilities" in theme_data:
                        for vuln in theme_data["vulnerabilities"]:
                            vulnerabilities.append(
                                {
                                    "component": f"Theme: {theme_name}",
                                    "title": vuln.get("title", "Unknown vulnerability"),
                                    "type": vuln.get("vuln_type", "Unknown"),
                                    "references": vuln.get("references", {}),
                                }
                            )

            # Add vulnerability findings
            for vuln in vulnerabilities:
                severity = self._assess_vulnerability_severity(vuln)
                result.add_finding(
                    f"WordPress Vulnerability: {vuln['title']}",
                    f"Vulnerability found in {vuln['component']}: {vuln['title']} ({vuln['type']})",
                    severity,
                    component=vuln["component"],
                    vulnerability_type=vuln["type"],
                    references=vuln["references"],
                )

            if vulnerabilities:
                log_success(f"WPScan found {len(vulnerabilities)} vulnerabilities")
            else:
                log_info("WPScan found no vulnerabilities")

        except json.JSONDecodeError:
            log_error("Failed to parse WPScan JSON output")
            result.errors.append("WPScan output parsing failed")
        except Exception as e:
            log_error(f"WPScan output analysis failed: {e}")
            result.errors.append(f"WPScan analysis error: {str(e)}")

    def _analyze_security_config(self, target_url: str, result: ScanResult) -> None:
        """
        Analyze WordPress security configuration

        Args:
            target_url: Target URL
            result: ScanResult to populate
        """
        try:
            log_info("Analyzing WordPress security configuration...")

            # Check directory browsing
            self._check_directory_browsing(target_url, result)

            # Check file permissions and exposure
            self._check_file_exposure(target_url, result)

            # Check debug mode
            self._check_debug_mode(target_url, result)

            # Check REST API exposure
            self._check_rest_api(target_url, result)

        except Exception as e:
            log_error(f"Security configuration analysis failed: {e}")
            result.errors.append(f"Security configuration error: {str(e)}")

    def _test_xmlrpc(self, target_url: str, result: ScanResult) -> None:
        """
        Test XML-RPC endpoint for security issues

        Args:
            target_url: Target URL
            result: ScanResult to populate
        """
        try:
            log_info("Testing XML-RPC endpoint...")

            xmlrpc_url = urljoin(target_url, "/xmlrpc.php")

            # Test if XML-RPC is enabled
            try:
                response = self.session.get(xmlrpc_url, timeout=10)
                if (
                    response.status_code == 405
                ):  # Method Not Allowed indicates XML-RPC is active
                    result.add_finding(
                        "XML-RPC Endpoint Enabled",
                        "XML-RPC endpoint is enabled and accessible",
                        ScanSeverity.MEDIUM,
                        endpoint=xmlrpc_url,
                        recommendation="Consider disabling XML-RPC if not needed, as it can be abused for brute force attacks",
                    )
                    log_warning("XML-RPC endpoint is enabled")

                    # Test for pingback functionality
                    self._test_xmlrpc_pingback(xmlrpc_url, result)

                elif response.status_code == 200:
                    result.add_finding(
                        "XML-RPC Endpoint Accessible",
                        "XML-RPC endpoint responds to GET requests",
                        ScanSeverity.LOW,
                        endpoint=xmlrpc_url,
                    )
                else:
                    log_info("XML-RPC endpoint appears to be disabled")

            except Exception as e:
                log_warning(f"Could not test XML-RPC endpoint: {e}")

        except Exception as e:
            log_error(f"XML-RPC testing failed: {e}")
            result.errors.append(f"XML-RPC testing error: {str(e)}")

    # Helper methods
    def _check_wpscan_available(self) -> Dict[str, Any]:
        """Check if WPScan is available"""
        try:
            result = self.executor.execute_command(["wpscan", "--version"], timeout=10)
            if result.returncode == 0:
                version = result.stdout.strip()
                return {"available": True, "version": version}
        except:
            pass
        return {"available": False, "version": "Not installed"}

    def _assess_version_security(self, version: str) -> ScanSeverity:
        """Assess WordPress version security status"""
        # This is a simplified assessment - in reality, you'd check against
        # a vulnerability database or WordPress security advisories
        try:
            major, minor = map(int, version.split(".")[:2])

            # Very basic assessment - in production, use proper CVE database
            if major < 6:
                return ScanSeverity.HIGH
            elif major == 6 and minor < 3:
                return ScanSeverity.MEDIUM
            else:
                return ScanSeverity.LOW

        except:
            return ScanSeverity.MEDIUM

    def _assess_vulnerability_severity(self, vuln: Dict[str, Any]) -> ScanSeverity:
        """Assess vulnerability severity based on type and references"""
        vuln_type = vuln.get("type", "").lower()
        title = vuln.get("title", "").lower()

        # High severity indicators
        if any(
            keyword in title
            for keyword in [
                "rce",
                "remote code execution",
                "sql injection",
                "arbitrary file",
            ]
        ):
            return ScanSeverity.CRITICAL
        elif any(
            keyword in title for keyword in ["xss", "csrf", "authentication bypass"]
        ):
            return ScanSeverity.HIGH
        elif any(keyword in title for keyword in ["disclosure", "enumeration"]):
            return ScanSeverity.MEDIUM
        else:
            return ScanSeverity.LOW

    def _check_directory_browsing(self, target_url: str, result: ScanResult) -> None:
        """Check for directory browsing vulnerabilities"""
        directories = [
            "/wp-content/",
            "/wp-content/uploads/",
            "/wp-content/plugins/",
            "/wp-content/themes/",
        ]

        for directory in directories:
            try:
                dir_url = urljoin(target_url, directory)
                response = self.session.get(dir_url, timeout=10)
                if response.status_code == 200 and "index of" in response.text.lower():
                    result.add_finding(
                        "Directory Browsing Enabled",
                        f"Directory browsing is enabled for: {directory}",
                        ScanSeverity.LOW,
                        directory=directory,
                        recommendation="Disable directory browsing by adding index.html files or server configuration",
                    )
            except:
                continue

    def _check_file_exposure(self, target_url: str, result: ScanResult) -> None:
        """Check for exposed sensitive files"""
        sensitive_files = [
            "/wp-config.php.bak",
            "/wp-config.php~",
            "/.wp-config.php.swp",
            "/wp-config.txt",
            "/error_log",
            "/debug.log",
        ]

        for file_path in sensitive_files:
            try:
                file_url = urljoin(target_url, file_path)
                response = self.session.get(file_url, timeout=5)
                if response.status_code == 200 and len(response.content) > 0:
                    result.add_finding(
                        "Sensitive File Exposed",
                        f"Sensitive file exposed: {file_path}",
                        ScanSeverity.HIGH,
                        file_path=file_path,
                        recommendation="Remove or properly protect sensitive files",
                    )
            except:
                continue

    def _check_debug_mode(self, target_url: str, result: ScanResult) -> None:
        """Check if WordPress debug mode is enabled"""
        try:
            response = self.session.get(target_url, timeout=10)
            if response.status_code == 200:
                content = response.text
                if any(
                    debug_indicator in content
                    for debug_indicator in [
                        "wp_debug",
                        "wordpress database error",
                        "debug backtrace",
                    ]
                ):
                    result.add_finding(
                        "Debug Mode Detected",
                        "WordPress debug mode appears to be enabled",
                        ScanSeverity.MEDIUM,
                        recommendation="Disable debug mode in production",
                    )
        except:
            pass

    def _check_rest_api(self, target_url: str, result: ScanResult) -> None:
        """Check WordPress REST API configuration"""
        try:
            api_url = urljoin(target_url, "/wp-json/")
            response = self.session.get(api_url, timeout=10)
            if response.status_code == 200:
                result.add_finding(
                    "WordPress REST API Enabled",
                    "WordPress REST API is accessible",
                    ScanSeverity.INFO,
                    api_endpoint=api_url,
                    recommendation="Review REST API permissions and disable if not needed",
                )
        except:
            pass

    def _test_xmlrpc_pingback(self, xmlrpc_url: str, result: ScanResult) -> None:
        """Test XML-RPC pingback functionality"""
        try:
            # Test pingback method
            pingback_xml = """<?xml version="1.0"?>
            <methodCall>
                <methodName>pingback.ping</methodName>
                <params>
                    <param><value><string>http://example.com</string></value></param>
                    <param><value><string>http://example.com</string></value></param>
                </params>
            </methodCall>"""

            headers = {"Content-Type": "text/xml"}
            response = self.session.post(
                xmlrpc_url, data=pingback_xml, headers=headers, timeout=10
            )

            if response.status_code == 200 and "fault" not in response.text.lower():
                result.add_finding(
                    "XML-RPC Pingback Enabled",
                    "XML-RPC pingback functionality is enabled (potential DDoS amplification)",
                    ScanSeverity.MEDIUM,
                    recommendation="Disable pingback functionality to prevent abuse",
                )
        except:
            pass
