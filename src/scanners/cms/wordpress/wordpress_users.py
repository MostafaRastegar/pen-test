"""
WordPress User Enumeration and Security Assessment Module
Handles user discovery, enumeration, and security analysis
"""

import re
import requests
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from src.core import ScanResult, ScanSeverity
from src.utils.logger import log_info, log_error, log_warning, log_success


class WordPressUsers:
    """WordPress user enumeration and security assessment"""

    def __init__(self, scanner):
        """
        Initialize WordPress user analyzer

        Args:
            scanner: Reference to main WordPressScanner instance
        """
        self.scanner = scanner
        self.core = scanner.core if hasattr(scanner, "core") else None

        # Common usernames to check
        self.common_usernames = [
            "admin",
            "administrator",
            "root",
            "user",
            "test",
            "demo",
            "guest",
            "www",
            "wordpress",
            "wp",
            "blog",
            "editor",
            "author",
        ]

        # Weak username patterns
        self.weak_patterns = [
            r"admin\d*",
            r"user\d*",
            r"test\d*",
            r"demo\d*",
        ]

    def enumerate_users(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """
        Enhanced user enumeration with security analysis

        Args:
            target_url: Target WordPress URL
            result: ScanResult to store findings
            options: Scan options
        """
        try:
            log_info("Starting enhanced user enumeration")

            users_found = []

            # Method 1: REST API enumeration
            api_users = self._enumerate_via_rest_api(target_url)
            users_found.extend(api_users)

            # Method 2: Author page enumeration
            author_users = self._enumerate_via_author_pages(target_url)
            users_found.extend(author_users)

            # Method 3: RSS feed enumeration
            rss_users = self._enumerate_via_rss_feeds(target_url)
            users_found.extend(rss_users)

            # Method 4: Sitemap enumeration
            sitemap_users = self._enumerate_via_sitemap(target_url)
            users_found.extend(sitemap_users)

            # Remove duplicates
            unique_users = {}
            for user in users_found:
                username = user.get("username", "")
                if username and username not in unique_users:
                    unique_users[username] = user

            users_found = list(unique_users.values())

            # Analyze each user for security issues
            for user in users_found:
                self._analyze_individual_user(user, result)

            # Add summary finding
            if users_found:
                self._add_user_summary_finding(result, users_found)

            log_success(
                f"Enhanced user enumeration completed. Found {len(users_found)} users"
            )

        except Exception as e:
            log_error(f"Enhanced user enumeration failed: {e}")

    def _enumerate_via_rest_api(self, target_url: str) -> List[Dict[str, Any]]:
        """Enumerate users via WordPress REST API"""
        users = []

        try:
            # Try WordPress REST API
            api_endpoints = [
                "/wp-json/wp/v2/users",
                "/wp-json/wp/v2/users?per_page=100",
            ]

            for endpoint in api_endpoints:
                api_url = urljoin(target_url, endpoint)
                response = self.core.make_request(api_url) if self.core else None

                if response and response.status_code == 200:
                    try:
                        user_data = response.json()

                        if isinstance(user_data, list):
                            for user in user_data:
                                if isinstance(user, dict):
                                    user_info = {
                                        "username": user.get("slug", ""),
                                        "display_name": user.get("name", ""),
                                        "user_id": user.get("id", ""),
                                        "detection_method": "rest_api",
                                        "api_data": user,
                                    }
                                    users.append(user_info)

                        # If we got users from this endpoint, no need to try others
                        if users:
                            break

                    except ValueError:
                        continue

        except Exception as e:
            log_error(f"REST API user enumeration failed: {e}")

        return users

    def _enumerate_via_author_pages(self, target_url: str) -> List[Dict[str, Any]]:
        """Enumerate users via author pages (/?author=ID)"""
        users = []

        try:
            log_info("Enumerating users via author pages")

            # Try different author IDs
            for user_id in range(1, 11):  # Check first 10 users
                author_url = f"{target_url}/?author={user_id}"
                response = self.core.make_request(author_url) if self.core else None

                if response and response.status_code == 200:
                    # Check if we got redirected to author page
                    final_url = response.url

                    # Extract username from URL
                    author_match = re.search(r"/author/([^/]+)", final_url)
                    if author_match:
                        username = author_match.group(1)

                        # Extract display name from content
                        display_name = self._extract_display_name_from_content(
                            response.text
                        )

                        user_info = {
                            "username": username,
                            "display_name": display_name,
                            "user_id": str(user_id),
                            "detection_method": "author_page",
                            "author_url": final_url,
                        }
                        users.append(user_info)

        except Exception as e:
            log_error(f"Author page enumeration failed: {e}")

        return users

    def _enumerate_via_rss_feeds(self, target_url: str) -> List[Dict[str, Any]]:
        """Enumerate users via RSS feeds"""
        users = []

        try:
            # Common RSS feed URLs
            rss_feeds = [
                "/feed/",
                "/rss/",
                "/rss2/",
                "/rdf/",
                "/atom/",
                "/?feed=rss2",
                "/?feed=atom",
            ]

            for feed_path in rss_feeds:
                try:
                    feed_url = urljoin(target_url, feed_path)
                    response = self.core.make_request(feed_url) if self.core else None

                    if response and response.status_code == 200:
                        content = response.text

                        # Look for author information in RSS
                        author_patterns = [
                            r"<dc:creator><!\[CDATA\[([^\]]+)\]\]></dc:creator>",
                            r"<author>([^<]+)</author>",
                            r"<managingEditor>([^<]+)</managingEditor>",
                        ]

                        for pattern in author_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                username = match.strip()
                                if username and username not in [
                                    u["username"] for u in users
                                ]:
                                    user_info = {
                                        "username": username,
                                        "display_name": username,
                                        "detection_method": "rss_feed",
                                        "feed_url": feed_url,
                                    }
                                    users.append(user_info)

                        # If we found users in this feed, we can stop checking others
                        if users:
                            break

                except requests.RequestException:
                    continue

        except Exception as e:
            log_error(f"RSS feed enumeration failed: {e}")

        return users

    def _enumerate_via_sitemap(self, target_url: str) -> List[Dict[str, Any]]:
        """Enumerate users via sitemap"""
        users = []

        try:
            # Common sitemap URLs
            sitemap_urls = [
                "/sitemap.xml",
                "/sitemap_index.xml",
                "/wp-sitemap.xml",
                "/wp-sitemap-users-1.xml",
            ]

            for sitemap_path in sitemap_urls:
                try:
                    sitemap_url = urljoin(target_url, sitemap_path)
                    response = (
                        self.core.make_request(sitemap_url) if self.core else None
                    )

                    if response and response.status_code == 200:
                        content = response.text

                        # Look for author URLs in sitemap
                        author_urls = re.findall(
                            r"<loc>([^<]*author[^<]*)</loc>", content, re.IGNORECASE
                        )

                        for author_url in author_urls:
                            # Extract username from author URL
                            author_match = re.search(r"/author/([^/]+)", author_url)
                            if author_match:
                                username = author_match.group(1)

                                user_info = {
                                    "username": username,
                                    "display_name": username,
                                    "detection_method": "sitemap",
                                    "author_url": author_url,
                                }
                                users.append(user_info)

                except requests.RequestException:
                    continue

        except Exception as e:
            log_error(f"Sitemap enumeration failed: {e}")

        return users

    def _extract_display_name_from_content(self, content: str) -> str:
        """Extract display name from page content"""
        try:
            # Common patterns for display names
            name_patterns = [
                r"<h1[^>]*>([^<]+)</h1>",
                r"<title>([^<]*author[^<]*)</title>",
                r'class="author[^"]*"[^>]*>([^<]+)<',
            ]

            for pattern in name_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    name = match.group(1).strip()
                    # Clean up common prefixes/suffixes
                    name = re.sub(
                        r"^(Author:|Posts by|About)\s*", "", name, flags=re.IGNORECASE
                    )
                    name = re.sub(r"\s*-.*$", "", name)  # Remove site name suffix
                    return name

        except Exception as e:
            log_error(f"Display name extraction failed: {e}")

        return ""

    def _analyze_individual_user(
        self, user: Dict[str, Any], result: ScanResult
    ) -> None:
        """Analyze individual user for security issues"""
        try:
            username = user.get("username", "")
            display_name = user.get("display_name", "")

            # Assess username security
            security_assessment = self._assess_username_security(username)

            # Determine severity
            severity = ScanSeverity.INFO
            if security_assessment.get("weak_username", False):
                severity = ScanSeverity.MEDIUM
            if security_assessment.get("admin_user", False):
                severity = ScanSeverity.HIGH

            result.add_finding(
                title=f"WordPress User: {username}",
                description=f"User account detected - Display Name: {display_name}",
                severity=severity,
                technical_details={
                    "username": username,
                    "display_name": display_name,
                    "user_id": user.get("user_id", ""),
                    "detection_method": user.get("detection_method", ""),
                    "security_assessment": security_assessment,
                },
                recommendation=self._get_user_recommendations(security_assessment),
            )

        except Exception as e:
            log_error(
                f"User analysis failed for {user.get('username', 'unknown')}: {e}"
            )

    def _assess_username_security(self, username: str) -> Dict[str, Any]:
        """Assess username security"""
        assessment = {
            "weak_username": False,
            "admin_user": False,
            "common_username": False,
            "risk_level": "low",
            "security_notes": [],
        }

        try:
            username_lower = username.lower()

            # Check for admin/administrator usernames
            if username_lower in ["admin", "administrator", "root"]:
                assessment["admin_user"] = True
                assessment["risk_level"] = "high"
                assessment["security_notes"].append("Administrative username")

            # Check for common weak usernames
            if username_lower in self.common_usernames:
                assessment["common_username"] = True
                assessment["weak_username"] = True
                assessment["risk_level"] = "medium"
                assessment["security_notes"].append("Common/predictable username")

            # Check for weak patterns
            for pattern in self.weak_patterns:
                if re.match(pattern, username_lower):
                    assessment["weak_username"] = True
                    assessment["risk_level"] = "medium"
                    assessment["security_notes"].append("Weak username pattern")

            # Check username length
            if len(username) < 4:
                assessment["weak_username"] = True
                assessment["security_notes"].append("Short username")

        except Exception as e:
            log_error(f"Username security assessment failed: {e}")

        return assessment

    def _get_user_recommendations(self, assessment: Dict[str, Any]) -> str:
        """Get security recommendations for user"""
        recommendations = []

        if assessment.get("admin_user", False):
            recommendations.append(
                "CRITICAL: Change administrative username to something non-obvious"
            )

        if assessment.get("weak_username", False):
            recommendations.append(
                "Consider using stronger, less predictable usernames"
            )

        if assessment.get("common_username", False):
            recommendations.append("Use unique usernames that are not easily guessable")

        recommendations.extend(
            [
                "Implement strong password policies",
                "Enable two-factor authentication",
                "Monitor login attempts and implement account lockout",
            ]
        )

        return ". ".join(recommendations)

    def _add_user_summary_finding(
        self, result: ScanResult, users: List[Dict[str, Any]]
    ) -> None:
        """Add summary finding for all detected users"""
        try:
            total_users = len(users)
            admin_users = 0
            weak_users = 0

            for user in users:
                assessment = self._assess_username_security(user.get("username", ""))
                if assessment.get("admin_user", False):
                    admin_users += 1
                if assessment.get("weak_username", False):
                    weak_users += 1

            # Determine overall severity
            if admin_users > 0:
                severity = ScanSeverity.HIGH
            elif weak_users > 0:
                severity = ScanSeverity.MEDIUM
            else:
                severity = ScanSeverity.LOW

            result.add_finding(
                title=f"WordPress User Summary ({total_users} users detected)",
                description=f"Found {total_users} WordPress users. Admin users: {admin_users}, Weak usernames: {weak_users}",
                severity=severity,
                technical_details={
                    "total_users": total_users,
                    "admin_users": admin_users,
                    "weak_users": weak_users,
                    "user_list": [u.get("username", "unknown") for u in users],
                },
                recommendation="Review all user accounts, change weak usernames, implement strong authentication policies.",
            )

        except Exception as e:
            log_error(f"User summary creation failed: {e}")

    def assess_user_security(self, users: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Comprehensive user security assessment

        Args:
            users: List of detected users

        Returns:
            Dict containing security assessment results
        """
        try:
            assessment_results = {
                "total_users": len(users),
                "security_summary": {
                    "high_risk": 0,
                    "medium_risk": 0,
                    "low_risk": 0,
                },
                "admin_users": [],
                "weak_usernames": [],
                "recommendations": [],
            }

            for user in users:
                username = user.get("username", "")
                security_assessment = self._assess_username_security(username)

                if security_assessment.get("admin_user", False):
                    assessment_results["security_summary"]["high_risk"] += 1
                    assessment_results["admin_users"].append(username)
                elif security_assessment.get("weak_username", False):
                    assessment_results["security_summary"]["medium_risk"] += 1
                    assessment_results["weak_usernames"].append(username)
                else:
                    assessment_results["security_summary"]["low_risk"] += 1

            # Generate recommendations
            if assessment_results["admin_users"]:
                assessment_results["recommendations"].append(
                    "Change administrative usernames to non-obvious values"
                )

            if assessment_results["weak_usernames"]:
                assessment_results["recommendations"].append(
                    "Replace weak/common usernames with stronger alternatives"
                )

            assessment_results["recommendations"].extend(
                [
                    "Implement strong password policies for all users",
                    "Enable two-factor authentication",
                    "Monitor and log user authentication attempts",
                    "Implement account lockout policies",
                    "Regular user access review and cleanup",
                ]
            )

            return assessment_results

        except Exception as e:
            log_error(f"User security assessment failed: {e}")
            return {"error": str(e)}
