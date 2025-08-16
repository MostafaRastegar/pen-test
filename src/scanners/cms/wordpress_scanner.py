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

    def _enumerate_users_rest_api(self, url: str) -> set:
        """
        Enumerate users via WordPress REST API

        Args:
            url: Target WordPress URL

        Returns:
            Set of discovered usernames
        """
        users = set()
        try:
            log_info("Enumerating users via REST API")

            # Try WordPress REST API endpoint
            api_url = urljoin(url, "/wp-json/wp/v2/users")

            response = self.session.get(api_url, timeout=10)
            if response.status_code == 200:
                try:
                    users_data = response.json()
                    if isinstance(users_data, list):
                        for user in users_data:
                            if isinstance(user, dict):
                                # Get username from slug or name
                                username = user.get("slug") or user.get("name")
                                if username:
                                    users.add(username)
                                    log_info(f"Found user via REST API: {username}")
                except (ValueError, KeyError):
                    pass

        except Exception as e:
            log_error(f"REST API user enumeration failed: {e}")

        return users

    def _enumerate_users_author_pages(self, url: str) -> set:
        """
        Enumerate users via author page enumeration

        Args:
            url: Target WordPress URL

        Returns:
            Set of discovered usernames
        """
        users = set()
        try:
            log_info("Enumerating users via author pages")

            # Try common author URL patterns
            for user_id in range(1, 11):  # Check first 10 user IDs
                try:
                    author_url = urljoin(url, f"/?author={user_id}")
                    response = self.session.get(
                        author_url, timeout=10, allow_redirects=True
                    )

                    if response.status_code == 200:
                        # Look for author information in the response
                        content = response.text.lower()

                        # Parse author name from various patterns
                        import re

                        # Pattern 1: /author/username in redirect URL
                        if "/author/" in response.url:
                            username = response.url.split("/author/")[-1].rstrip("/")
                            if username and username.isalnum():
                                users.add(username)
                                log_info(f"Found user via author page: {username}")

                        # Pattern 2: Author display name in content
                        author_patterns = [
                            r"by\s+([a-zA-Z0-9_-]+)",
                            r'author["\s>]+([a-zA-Z0-9_-]+)',
                            r"posted\s+by\s+([a-zA-Z0-9_-]+)",
                        ]

                        for pattern in author_patterns:
                            matches = re.findall(pattern, content)
                            for match in matches:
                                if len(match) > 2 and match.isalnum():
                                    users.add(match)
                                    break

                except requests.RequestException:
                    continue

        except Exception as e:
            log_error(f"Author page enumeration failed: {e}")

        return users

    def _enumerate_users_login_errors(self, url: str) -> set:
        """
        Enumerate users via login error messages

        Args:
            url: Target WordPress URL

        Returns:
            Set of discovered usernames
        """
        users = set()
        try:
            log_info("Enumerating users via login error messages")

            login_url = urljoin(url, "/wp-login.php")

            # Common usernames to test
            test_usernames = ["admin", "administrator", "user", "test", "demo", "guest"]

            for username in test_usernames:
                try:
                    login_data = {
                        "log": username,
                        "pwd": "invalid_password_test_123",
                        "wp-submit": "Log In",
                    }

                    response = self.session.post(login_url, data=login_data, timeout=10)
                    response_text = response.text.lower()

                    # Check for username-specific error messages
                    if (
                        "incorrect password" in response_text
                        or "password you entered" in response_text
                    ):
                        # Username exists (wrong password error)
                        users.add(username)
                        log_info(f"Found user via login errors: {username}")
                    elif (
                        "invalid username" in response_text
                        or "unknown username" in response_text
                    ):
                        # Username doesn't exist
                        continue

                except requests.RequestException:
                    continue

        except Exception as e:
            log_error(f"Login error enumeration failed: {e}")

        return users

    def _enumerate_users_rss_feeds(self, url: str) -> set:
        """
        Enumerate users via RSS feeds

        Args:
            url: Target WordPress URL

        Returns:
            Set of discovered usernames
        """
        users = set()
        try:
            log_info("Enumerating users via RSS feeds")

            # Common RSS feed URLs
            rss_urls = [
                urljoin(url, "/feed/"),
                urljoin(url, "/rss/"),
                urljoin(url, "/rss.xml"),
                urljoin(url, "/feed.xml"),
                urljoin(url, "/?feed=rss2"),
                urljoin(url, "/?feed=rss"),
                urljoin(url, "/?feed=atom"),
            ]

            for rss_url in rss_urls:
                try:
                    response = self.session.get(rss_url, timeout=10)
                    if response.status_code == 200:
                        content = response.text

                        # Parse XML for author information
                        import re

                        # Look for various author patterns in RSS/XML
                        author_patterns = [
                            r"<dc:creator[^>]*>([^<]+)</dc:creator>",
                            r"<author[^>]*>([^<]+)</author>",
                            r"<creator[^>]*>([^<]+)</creator>",
                            r"<managingEditor[^>]*>([^<]+)</managingEditor>",
                        ]

                        for pattern in author_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                # Clean up the match
                                username = match.strip()
                                # Extract username from email if present
                                if "@" in username:
                                    username = username.split("@")[0]

                                # Basic validation
                                if len(username) > 2 and len(username) < 50:
                                    # Remove non-alphanumeric characters except underscore and dash
                                    clean_username = re.sub(
                                        r"[^a-zA-Z0-9_-]", "", username
                                    )
                                    if clean_username:
                                        users.add(clean_username)
                                        log_info(
                                            f"Found user via RSS feed: {clean_username}"
                                        )

                        # If we found users in this feed, we can stop checking others
                        if users:
                            break

                except requests.RequestException:
                    continue

        except Exception as e:
            log_error(f"RSS feed enumeration failed: {e}")

        return users

    def _detect_wordpress(self, target_url: str, result: ScanResult) -> bool:
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
                response = self.session.get(target_url, timeout=10)
                if response.status_code == 200:
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
            for indicator, path in self.wp_indicators.items():
                try:
                    test_url = urljoin(target_url, path)
                    response = self.session.get(test_url, timeout=5)

                    if response.status_code in [200, 403, 301, 302]:
                        wp_detected = True
                        detection_methods.append(f"Path detection ({indicator})")
                        break

                except requests.RequestException:
                    continue

            # Method 3: Check WordPress REST API
            try:
                api_url = urljoin(target_url, "/wp-json/")
                response = self.session.get(api_url, timeout=5)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, dict) and "namespaces" in data:
                            wp_detected = True
                            detection_methods.append("REST API")
                    except ValueError:
                        pass
            except requests.RequestException:
                pass

            if wp_detected:
                result.add_finding(
                    title="WordPress Installation Detected",
                    description=f"WordPress detected using: {', '.join(detection_methods)}",
                    severity=ScanSeverity.INFO,
                    recommendation="Ensure WordPress is properly secured and updated",
                    technical_details={"detection_methods": detection_methods},
                )
                log_success("WordPress installation confirmed")
            else:
                log_warning("WordPress installation not clearly detected")

            return wp_detected

        except Exception as e:
            log_error(f"WordPress detection failed: {e}")
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
        self, url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """
        Enumerate WordPress users using various techniques

        Args:
            url: Target WordPress URL
            result: ScanResult to store findings
            options: Scan options
        """
        try:
            log_info("Starting WordPress user enumeration")
            users_found = set()

            # Method 1: REST API enumeration
            users_found.update(self._enumerate_users_rest_api(url))

            # Method 2: Author page enumeration
            users_found.update(self._enumerate_users_author_pages(url))

            # Method 3: Login error enumeration
            users_found.update(self._enumerate_users_login_errors(url))

            # Method 4: RSS feed enumeration
            users_found.update(self._enumerate_users_rss_feeds(url))

            # Create findings for discovered users
            for user in users_found:
                severity = (
                    ScanSeverity.MEDIUM if len(users_found) > 3 else ScanSeverity.LOW
                )

                result.add_finding(
                    title="WordPress User Discovered",
                    description=f"WordPress user '{user}' was discovered through enumeration",
                    severity=severity,
                    recommendation="Consider implementing user enumeration protection",
                    technical_details={
                        "username": user,
                        "enumeration_method": "Multiple techniques",
                        "security_impact": "Username disclosure can aid brute force attacks",
                    },
                )

            log_info(f"User enumeration completed. Found {len(users_found)} users")

        except Exception as e:
            log_error(f"User enumeration failed: {e}")
            result.add_finding(
                title="User Enumeration Error",
                description=f"Failed to enumerate users: {str(e)}",
                severity=ScanSeverity.LOW,
                recommendation="Manual user enumeration may be required",
            )

    def _test_brute_force_protection(
        self, url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """
        Test WordPress brute force protection mechanisms

        Args:
            url: Target WordPress URL
            result: ScanResult to store findings
            options: Scan options
        """
        try:
            log_info("Testing WordPress brute force protection")

            login_url = urljoin(url, "/wp-login.php")
            protection_score = 0
            protection_details = {}

            # Test 1: Rate limiting detection
            rate_limit_result = self._check_rate_limiting(login_url)
            protection_details["rate_limiting"] = rate_limit_result
            if rate_limit_result["protected"]:
                protection_score += 25

            # Test 2: Account lockout detection
            lockout_result = self._check_account_lockout(login_url)
            protection_details["account_lockout"] = lockout_result
            if lockout_result["protected"]:
                protection_score += 25

            # Test 3: CAPTCHA detection
            captcha_result = self._detect_captcha_protection(login_url)
            protection_details["captcha"] = captcha_result
            if captcha_result["protected"]:
                protection_score += 25

            # Test 4: Login response analysis
            response_analysis = self._analyze_login_responses(login_url)
            protection_details["response_analysis"] = response_analysis
            if response_analysis["secure_responses"]:
                protection_score += 25

            # Determine overall protection level
            if protection_score >= 75:
                severity = ScanSeverity.LOW
                protection_level = "Strong"
            elif protection_score >= 50:
                severity = ScanSeverity.MEDIUM
                protection_level = "Moderate"
            elif protection_score >= 25:
                severity = ScanSeverity.HIGH
                protection_level = "Weak"
            else:
                severity = ScanSeverity.CRITICAL
                protection_level = "Minimal"

            result.add_finding(
                title="WordPress Brute Force Protection Assessment",
                description=f"Brute force protection level: {protection_level} (Score: {protection_score}/100)",
                severity=severity,
                recommendation=self._get_brute_force_recommendations(
                    protection_score, protection_details
                ),
                technical_details=protection_details,
            )

            log_info(
                f"Brute force protection test completed. Protection score: {protection_score}/100"
            )

        except Exception as e:
            log_error(f"Brute force protection testing failed: {e}")
            result.add_finding(
                title="Brute Force Protection Test Error",
                description=f"Failed to test brute force protection: {str(e)}",
                severity=ScanSeverity.LOW,
                recommendation="Manual testing of login security may be required",
            )

    def _check_rate_limiting(self, login_url: str) -> Dict[str, Any]:
        """
        Check for rate limiting on login attempts

        Args:
            login_url: WordPress login URL

        Returns:
            Dict containing rate limiting analysis results
        """
        try:
            log_info("Checking rate limiting protection")

            # Perform multiple login attempts rapidly
            attempt_data = {
                "log": "nonexistent_user_test",
                "pwd": "invalid_password_test",
                "wp-submit": "Log In",
            }

            response_times = []
            status_codes = []
            response_texts = []

            # Make 10 rapid requests
            for i in range(10):
                try:
                    start_time = datetime.now()
                    response = self.session.post(
                        login_url, data=attempt_data, timeout=10, allow_redirects=False
                    )
                    end_time = datetime.now()

                    response_times.append((end_time - start_time).total_seconds())
                    status_codes.append(response.status_code)
                    response_texts.append(response.text[:500])

                except requests.RequestException:
                    status_codes.append(0)
                    response_times.append(0)

            # Analyze responses for rate limiting indicators
            rate_limited = False
            rate_limit_method = "none"

            # Check for HTTP 429 (Too Many Requests)
            if 429 in status_codes:
                rate_limited = True
                rate_limit_method = "HTTP 429"

            # Check for significant response time increases
            avg_response_time = sum(response_times) / len(response_times)
            if avg_response_time > 2.0:  # Responses taking > 2 seconds
                rate_limited = True
                rate_limit_method = "Response delay"

            # Check for rate limiting messages
            rate_limit_keywords = [
                "too many",
                "rate limit",
                "slow down",
                "wait",
                "blocked",
            ]
            for text in response_texts:
                if any(keyword in text.lower() for keyword in rate_limit_keywords):
                    rate_limited = True
                    rate_limit_method = "Response message"
                    break

            return {
                "protected": rate_limited,
                "method": rate_limit_method,
                "average_response_time": avg_response_time,
                "status_codes": status_codes,
                "details": (
                    f"Rate limiting detected via {rate_limit_method}"
                    if rate_limited
                    else "No rate limiting detected"
                ),
            }

        except Exception as e:
            log_error(f"Rate limiting check failed: {e}")
            return {
                "protected": False,
                "method": "error",
                "details": f"Error checking rate limiting: {str(e)}",
            }

    def _check_account_lockout(self, login_url: str) -> Dict[str, Any]:
        """
        Check for account lockout mechanisms

        Args:
            login_url: WordPress login URL

        Returns:
            Dict containing account lockout analysis results
        """
        try:
            log_info("Checking account lockout protection")

            # Use a common test username
            test_username = "admin"
            lockout_data = {
                "log": test_username,
                "pwd": "invalid_password_lockout_test",
                "wp-submit": "Log In",
            }

            initial_response = self.session.post(
                login_url, data=lockout_data, timeout=10
            )
            initial_text = initial_response.text

            # Make multiple failed attempts
            lockout_detected = False
            lockout_method = "none"

            for attempt in range(5):
                try:
                    response = self.session.post(
                        login_url, data=lockout_data, timeout=10
                    )
                    response_text = response.text.lower()

                    # Check for lockout messages
                    lockout_keywords = [
                        "locked",
                        "blocked",
                        "suspended",
                        "disabled",
                        "too many attempts",
                        "account locked",
                        "temporarily disabled",
                        "security lockout",
                    ]

                    if any(keyword in response_text for keyword in lockout_keywords):
                        lockout_detected = True
                        lockout_method = "Lockout message detected"
                        break

                    # Check for different response patterns
                    if len(response_text) != len(initial_text.lower()):
                        if abs(len(response_text) - len(initial_text)) > 100:
                            lockout_detected = True
                            lockout_method = "Response pattern change"
                            break

                except requests.RequestException:
                    continue

            return {
                "protected": lockout_detected,
                "method": lockout_method,
                "attempts_tested": 5,
                "details": (
                    f"Account lockout detected via {lockout_method}"
                    if lockout_detected
                    else "No account lockout detected"
                ),
            }

        except Exception as e:
            log_error(f"Account lockout check failed: {e}")
            return {
                "protected": False,
                "method": "error",
                "details": f"Error checking account lockout: {str(e)}",
            }

    def _detect_captcha_protection(self, login_url: str) -> Dict[str, Any]:
        """
        Detect CAPTCHA protection on login form

        Args:
            login_url: WordPress login URL

        Returns:
            Dict containing CAPTCHA detection results
        """
        try:
            log_info("Detecting CAPTCHA protection")

            response = self.session.get(login_url, timeout=10)
            page_content = response.text.lower()

            captcha_detected = False
            captcha_type = "none"
            captcha_indicators = []

            # Check for various CAPTCHA implementations
            captcha_patterns = {
                "reCAPTCHA": ["recaptcha", "g-recaptcha", "grecaptcha"],
                "hCaptcha": ["hcaptcha", "h-captcha"],
                "Simple CAPTCHA": ["captcha", "security code", "verification code"],
                "Math CAPTCHA": ["math captcha", "solve", "equation"],
                "Image CAPTCHA": ["image verification", "visual verification"],
            }

            for captcha_name, patterns in captcha_patterns.items():
                for pattern in patterns:
                    if pattern in page_content:
                        captcha_detected = True
                        captcha_type = captcha_name
                        captcha_indicators.append(pattern)

            # Check for CAPTCHA-related form fields
            captcha_fields = [
                "captcha",
                "recaptcha",
                "hcaptcha",
                "security_code",
                "verification",
            ]
            for field in captcha_fields:
                if f'name="{field}"' in page_content or f'id="{field}"' in page_content:
                    captcha_detected = True
                    if captcha_type == "none":
                        captcha_type = "Custom CAPTCHA"
                    captcha_indicators.append(f"Form field: {field}")

            return {
                "protected": captcha_detected,
                "type": captcha_type,
                "indicators": captcha_indicators,
                "details": (
                    f"CAPTCHA protection detected: {captcha_type}"
                    if captcha_detected
                    else "No CAPTCHA protection detected"
                ),
            }

        except Exception as e:
            log_error(f"CAPTCHA detection failed: {e}")
            return {
                "protected": False,
                "type": "error",
                "details": f"Error detecting CAPTCHA: {str(e)}",
            }

    def _analyze_login_responses(self, login_url: str) -> Dict[str, Any]:
        """
        Analyze login response patterns for security

        Args:
            login_url: WordPress login URL

        Returns:
            Dict containing login response analysis
        """
        try:
            log_info("Analyzing login response patterns")

            # Test different scenarios
            test_cases = [
                {
                    "log": "nonexistent_user",
                    "pwd": "any_password",
                    "case": "invalid_user",
                },
                {
                    "log": "admin",
                    "pwd": "wrong_password",
                    "case": "valid_user_wrong_password",
                },
                {"log": "", "pwd": "", "case": "empty_credentials"},
            ]

            responses = {}
            secure_responses = True
            issues = []

            for test_case in test_cases:
                try:
                    response = self.session.post(
                        login_url,
                        data={
                            "log": test_case["log"],
                            "pwd": test_case["pwd"],
                            "wp-submit": "Log In",
                        },
                        timeout=10,
                    )

                    responses[test_case["case"]] = {
                        "status_code": response.status_code,
                        "response_length": len(response.text),
                        "contains_error": "error" in response.text.lower(),
                    }

                    # Check for information disclosure
                    response_text = response.text.lower()
                    if (
                        "invalid username" in response_text
                        or "unknown username" in response_text
                    ):
                        secure_responses = False
                        issues.append("Username enumeration via error messages")

                    if (
                        "incorrect password" in response_text
                        and test_case["case"] == "valid_user_wrong_password"
                    ):
                        secure_responses = False
                        issues.append("Password validation confirms valid username")

                except requests.RequestException as e:
                    responses[test_case["case"]] = {"error": str(e)}

            return {
                "secure_responses": secure_responses,
                "issues": issues,
                "response_patterns": responses,
                "details": "Login responses analyzed for information disclosure"
                + (
                    f". Issues: {', '.join(issues)}" if issues else " - No issues found"
                ),
            }

        except Exception as e:
            log_error(f"Login response analysis failed: {e}")
            return {
                "secure_responses": False,
                "details": f"Error analyzing login responses: {str(e)}",
            }

    def _get_brute_force_recommendations(
        self, score: int, details: Dict[str, Any]
    ) -> str:
        """
        Generate recommendations based on brute force protection assessment

        Args:
            score: Protection score (0-100)
            details: Protection assessment details

        Returns:
            String containing recommendations
        """
        recommendations = []

        if not details.get("rate_limiting", {}).get("protected", False):
            recommendations.append("Implement rate limiting on login attempts")

        if not details.get("account_lockout", {}).get("protected", False):
            recommendations.append("Configure account lockout after failed attempts")

        if not details.get("captcha", {}).get("protected", False):
            recommendations.append("Add CAPTCHA protection to login form")

        if not details.get("response_analysis", {}).get("secure_responses", True):
            recommendations.append("Fix information disclosure in login error messages")

        if score < 50:
            recommendations.append(
                "Consider implementing a WordPress security plugin (e.g., Wordfence, Sucuri)"
            )
            recommendations.append("Enable two-factor authentication for all users")
            recommendations.append("Use strong password policies")

        if not recommendations:
            recommendations.append(
                "Maintain current security measures and monitor for new threats"
            )

        return "; ".join(recommendations)

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

    def _check_wpscan_available(self) -> Dict[str, Any]:
        """Check if WPScan is available with improved detection"""
        try:
            import shutil

            # Method 1: Check using shutil.which
            wpscan_path = shutil.which("wpscan")
            if wpscan_path:
                log_info(f"Found WPScan at: {wpscan_path}")
                try:
                    # FIXED: Use correct method name
                    result = self.executor.execute(["wpscan", "--version"], timeout=10)
                    if result.success:  # FIXED: Use .success instead of .success
                        version_line = (
                            result.stdout.strip().split("\n")[0]
                            if result.stdout
                            else "Unknown"
                        )
                        log_success(f"WPScan version: {version_line}")
                        return {
                            "available": True,
                            "version": version_line,
                            "path": wpscan_path,
                        }
                    else:
                        log_warning(
                            f"WPScan found but version check failed: {result.stderr}"
                        )
                        return {
                            "available": True,
                            "version": "Unknown",
                            "path": wpscan_path,
                        }
                except Exception as e:
                    log_warning(f"WPScan found but version check error: {e}")
                    return {
                        "available": True,
                        "version": "Unknown",
                        "path": wpscan_path,
                    }

            # Method 2: Check common paths
            common_paths = [
                "/usr/bin/wpscan",
                "/usr/local/bin/wpscan",
                "/opt/wpscan/wpscan",
                "~/.local/bin/wpscan",
                "/usr/local/rvm/gems/default/bin/wpscan",
                "/home/.rvm/gems/default/bin/wpscan",
            ]

            import os

            for path in common_paths:
                expanded_path = os.path.expanduser(path)
                if os.path.isfile(expanded_path) and os.access(expanded_path, os.X_OK):
                    log_info(f"Found WPScan at: {expanded_path}")
                    try:
                        # FIXED: Use correct method name
                        result = self.executor.execute(
                            [expanded_path, "--version"], timeout=10
                        )
                        if result.success:  # FIXED: Use .success
                            version_line = (
                                result.stdout.strip().split("\n")[0]
                                if result.stdout
                                else "Unknown"
                            )
                            log_success(f"WPScan version: {version_line}")
                            return {
                                "available": True,
                                "version": version_line,
                                "path": expanded_path,
                            }
                    except:
                        pass

            # Method 3: Check if it's a gem
            try:
                # FIXED: Use correct method name
                result = self.executor.execute(["gem", "list", "wpscan"], timeout=10)
                if (
                    result.success and "wpscan" in result.stdout.lower()
                ):  # FIXED: Use .success
                    log_info("WPScan found as Ruby gem")
                    try:
                        # FIXED: Use correct method name
                        version_result = self.executor.execute(
                            ["wpscan", "--version"], timeout=10
                        )
                        if version_result.success:  # FIXED: Use .success
                            version_line = (
                                version_result.stdout.strip().split("\n")[0]
                                if version_result.stdout
                                else "Unknown"
                            )
                            return {
                                "available": True,
                                "version": version_line,
                                "path": "gem",
                            }
                    except:
                        pass
            except:
                pass

            # Method 4: Try direct execution
            try:
                # FIXED: Use correct method name
                result = self.executor.execute(["wpscan", "--help"], timeout=5)
                if (
                    result.success and "wordpress" in result.stdout.lower()
                ):  # FIXED: Use .success
                    log_info("WPScan responds to direct execution")
                    return {"available": True, "version": "Unknown", "path": "system"}
            except:
                pass

            log_warning("WPScan not found in system")
            return {"available": False, "version": "Not installed"}

        except Exception as e:
            log_error(f"Error checking WPScan availability: {e}")
            return {"available": False, "version": f"Check failed: {str(e)}"}

    def _run_wpscan(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """Run WPScan for comprehensive vulnerability assessment"""
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

            # FIXED: Use correct method name
            wpscan_result = self.executor.execute(cmd, timeout=300)

            # FIXED: Use .success instead of .success
            if wpscan_result.success and wpscan_result.stdout:
                self._parse_wpscan_output(wpscan_result.stdout, result)
                result.raw_output += f"\n--- WPScan Output ---\n{wpscan_result.stdout}"
            else:
                log_warning(f"WPScan execution issues: {wpscan_result.stderr}")
                result.errors.append(f"WPScan error: {wpscan_result.stderr}")

        except Exception as e:
            log_error(f"WPScan execution failed: {e}")
            result.errors.append(f"WPScan execution error: {str(e)}")

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
