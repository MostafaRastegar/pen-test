# Enhanced WordPress User Security Assessment - Phase 1.3 Implementation
# File: src/scanners/cms/wordpress/wordpress_users.py (Enhanced Version)

"""
WordPress User Enumeration and Security Assessment Module
Phase 1.3 Enhancement: Comprehensive user security analysis
"""

import re
import requests
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from src.core import ScanResult, ScanSeverity
from src.utils.logger import log_info, log_error, log_warning, log_success


class WordPressUsers:
    """Enhanced WordPress user enumeration and security assessment"""

    def __init__(self, scanner):
        """
        Initialize WordPress user analyzer

        Args:
            scanner: Reference to main WordPressScanner instance
        """
        self.scanner = scanner
        self.core = scanner.core if hasattr(scanner, "core") else None

        # ENHANCED: Comprehensive username patterns
        self.common_usernames = [
            "admin",
            # "administrator",
            # "root",
            # "user",
            # "test",
            # "demo",
            # "guest",
            # "www",
            # "wordpress",
            # "wp",
            # "blog",
            # "editor",
            # "author",
            # "moderator",
            # "support",
            # "help",
            # "service",
            # "api",
            # "backup",
            # "staging",
            # "dev",
            # "developer",
            # "webmaster",
            # "manager",
            # "owner",
            # "super",
            # "superuser",
        ]

        # ENHANCED: Security-focused weak patterns
        self.weak_patterns = [
            r"admin\d*",
            r"user\d*",
            r"test\d*",
            r"demo\d*",
            r"guest\d*",
            r"temp\d*",
            r"backup\d*",
            r"support\d*",
            r"dev\d*",
            r"api\d*",
        ]

        # ENHANCED: WordPress role hierarchy and capabilities
        self.wordpress_roles = {
            "administrator": {
                "level": 10,
                "risk": "critical",
                "capabilities": [
                    "manage_options",
                    "edit_users",
                    "delete_users",
                    "activate_plugins",
                    "edit_themes",
                    "install_plugins",
                    "update_core",
                    "manage_categories",
                    "moderate_comments",
                    "manage_links",
                    "upload_files",
                    "import",
                    "unfiltered_html",
                    "edit_posts",
                    "edit_others_posts",
                    "publish_posts",
                    "edit_published_posts",
                    "delete_posts",
                    "delete_others_posts",
                ],
                "description": "Full site control - highest security risk",
            },
            "editor": {
                "level": 7,
                "risk": "high",
                "capabilities": [
                    "moderate_comments",
                    "manage_categories",
                    "manage_links",
                    "upload_files",
                    "unfiltered_html",
                    "edit_others_posts",
                    "edit_published_posts",
                    "publish_posts",
                    "delete_posts",
                    "delete_others_posts",
                    "delete_published_posts",
                    "edit_pages",
                    "read",
                    "edit_others_pages",
                    "edit_published_pages",
                    "publish_pages",
                    "delete_pages",
                    "delete_others_pages",
                    "delete_published_pages",
                ],
                "description": "Content management access - moderate security risk",
            },
            "author": {
                "level": 2,
                "risk": "medium",
                "capabilities": [
                    "upload_files",
                    "edit_posts",
                    "edit_published_posts",
                    "publish_posts",
                    "delete_posts",
                    "delete_published_posts",
                    "read",
                ],
                "description": "Content creation access - low to medium security risk",
            },
            "contributor": {
                "level": 1,
                "risk": "low",
                "capabilities": ["edit_posts", "delete_posts", "read"],
                "description": "Content contribution access - minimal security risk",
            },
            "subscriber": {
                "level": 0,
                "risk": "minimal",
                "capabilities": ["read"],
                "description": "Read-only access - minimal security risk",
            },
        }

        # ENHANCED: High-risk user characteristics
        self.high_risk_indicators = {
            "weak_usernames": ["admin", "administrator", "root", "test", "demo"],
            "generic_patterns": [r"admin\d+", r"user\d+", r"test\d+"],
            "service_accounts": ["api", "service", "system", "backup", "staging"],
            "default_accounts": ["admin", "wordpress", "wp-admin"],
            "privileged_roles": ["administrator", "editor"],
            "suspicious_names": ["hacker", "exploit", "shell", "backdoor"],
        }

        # ENHANCED: Account security checks
        self.security_checks = {
            "username_enumeration": True,
            "weak_credentials": True,
            "privilege_escalation": True,
            "role_analysis": True,
            "account_policies": True,
            "user_disclosure": True,
        }

    def enumerate_users(
        self, target_url: str, result: ScanResult, options: Dict[str, Any]
    ) -> None:
        """
        Enhanced user enumeration with comprehensive security analysis

        Args:
            target_url: Target WordPress URL
            result: ScanResult to store findings
            options: Scan options
        """
        try:
            log_info("Starting comprehensive user enumeration and security assessment")

            users_found = []
            enumeration_methods = {}

            # Method 1: REST API enumeration (Enhanced)
            api_users = self._enumerate_via_rest_api_enhanced(target_url)
            users_found.extend(api_users)
            if api_users:
                enumeration_methods["rest_api"] = len(api_users)

            # Method 2: Author page enumeration (Enhanced)
            author_users = self._enumerate_via_author_pages_enhanced(target_url)
            users_found.extend(author_users)
            if author_users:
                enumeration_methods["author_pages"] = len(author_users)

            # Method 3: RSS feed enumeration
            rss_users = self._enumerate_via_rss_feeds(target_url)
            users_found.extend(rss_users)
            if rss_users:
                enumeration_methods["rss_feeds"] = len(rss_users)

            # Method 4: Sitemap enumeration
            sitemap_users = self._enumerate_via_sitemap(target_url)
            users_found.extend(sitemap_users)
            if sitemap_users:
                enumeration_methods["sitemap"] = len(sitemap_users)

            # Method 5: ENHANCED - Login page analysis
            login_users = self._analyze_login_page_disclosure(target_url)
            users_found.extend(login_users)
            if login_users:
                enumeration_methods["login_disclosure"] = len(login_users)

            # Method 6: ENHANCED - Common username probing
            probed_users = self._probe_common_usernames(target_url)
            users_found.extend(probed_users)
            if probed_users:
                enumeration_methods["username_probing"] = len(probed_users)

            # Remove duplicates and enhance user data
            unique_users = self._deduplicate_and_enhance_users(users_found)

            # ENHANCED: Comprehensive security analysis for each user
            analyzed_users = []
            for user in unique_users:
                enhanced_user = self._perform_comprehensive_user_analysis(
                    target_url, user
                )
                analyzed_users.append(enhanced_user)

                # Add individual user findings
                self._add_individual_user_finding(result, enhanced_user, target_url)

            # ENHANCED: Generate comprehensive security assessment
            if analyzed_users:
                security_assessment = (
                    self._generate_comprehensive_user_security_assessment(
                        analyzed_users, enumeration_methods
                    )
                )
                self._add_user_security_summary_finding(result, security_assessment)

            # ENHANCED: Check for user enumeration vulnerabilities
            enum_vulns = self._assess_user_enumeration_vulnerabilities(
                enumeration_methods, target_url
            )
            if enum_vulns:
                self._add_enumeration_vulnerability_findings(result, enum_vulns)

            log_success(
                f"User security assessment completed - Analyzed {len(analyzed_users)} users via {len(enumeration_methods)} methods"
            )

        except Exception as e:
            log_error(f"Enhanced user enumeration and security assessment failed: {e}")

    def _enumerate_via_rest_api_enhanced(self, target_url: str) -> List[Dict[str, Any]]:
        """ENHANCED: REST API enumeration with detailed user info extraction"""
        users = []

        try:
            # Enhanced API endpoints
            api_endpoints = [
                "/wp-json/wp/v2/users",
                "/wp-json/wp/v2/users?per_page=100",
                "/wp-json/wp/v2/users?context=edit",
                "/wp-json/wp/v2/users?_fields=id,name,slug,roles,capabilities",
            ]

            for endpoint in api_endpoints:
                try:
                    api_url = urljoin(target_url, endpoint)
                    response = self.core.make_request(api_url) if self.core else None

                    if response and response.status_code == 200:
                        try:
                            user_data = response.json()

                            if isinstance(user_data, list):
                                for user in user_data:
                                    if isinstance(user, dict):
                                        # Enhanced user info extraction
                                        user_info = {
                                            "username": user.get("slug", ""),
                                            "display_name": user.get("name", ""),
                                            "user_id": user.get("id", ""),
                                            "roles": user.get("roles", []),
                                            "capabilities": user.get(
                                                "capabilities", {}
                                            ),
                                            "detection_method": "rest_api",
                                            "api_endpoint": endpoint,
                                            "api_data": user,
                                            "registration_date": user.get(
                                                "registered_date"
                                            ),
                                            "post_count": user.get("post_count", 0),
                                            "avatar_url": user.get("avatar_urls", {}),
                                        }
                                        users.append(user_info)

                            # Stop if we got comprehensive data
                            if users and any(u.get("roles") for u in users):
                                break

                        except ValueError:
                            continue

                except Exception as e:
                    log_warning(f"API endpoint {endpoint} failed: {e}")
                    continue

        except Exception as e:
            log_error(f"Enhanced REST API enumeration failed: {e}")

        return users

    def _enumerate_via_author_pages_enhanced(
        self, target_url: str
    ) -> List[Dict[str, Any]]:
        """ENHANCED: Author page enumeration with additional metadata"""
        users = []

        try:
            log_info("Enhanced author page enumeration")

            # Try different author ID ranges and patterns
            for user_id in range(1, 11):  # Check first 10 users
                try:
                    # Multiple author URL patterns
                    author_urls = [
                        f"/?author={user_id}",
                        f"/author/{user_id}/",
                        f"/author/user{user_id}/",
                        f"/?author_name=user{user_id}",
                    ]

                    for author_url in author_urls:
                        try:
                            full_url = urljoin(target_url, author_url)
                            response = (
                                self.core.make_request(full_url) if self.core else None
                            )

                            if response and response.status_code == 200:
                                # Extract user information from author page
                                user_info = self._extract_user_info_from_author_page(
                                    response.text, user_id
                                )
                                if user_info:
                                    user_info.update(
                                        {
                                            "user_id": user_id,
                                            "detection_method": "author_page",
                                            "author_url": author_url,
                                            "page_title": self._extract_page_title(
                                                response.text
                                            ),
                                        }
                                    )
                                    users.append(user_info)
                                    break  # Found user, no need to try other URL patterns

                        except Exception as e:
                            continue

                except Exception as e:
                    continue

        except Exception as e:
            log_error(f"Enhanced author page enumeration failed: {e}")

        return users

    def _probe_common_usernames(self, target_url: str) -> List[Dict[str, Any]]:
        """ENHANCED: Probe for common usernames using multiple techniques"""
        users = []

        try:
            log_info("Probing for common usernames")

            for username in self.common_usernames:
                # Check multiple patterns and endpoints
                username_found = False

                # Method 1: Login page username enumeration
                if self._check_username_via_login_error(target_url, username):
                    users.append(
                        {
                            "username": username,
                            "detection_method": "login_error",
                            "confidence": "high",
                            "risk_level": self._assess_username_risk(username),
                        }
                    )
                    username_found = True

                # Method 2: Password reset enumeration
                if self._check_username_via_password_reset(target_url, username):
                    if not username_found:  # Avoid duplicates
                        users.append(
                            {
                                "username": username,
                                "detection_method": "password_reset",
                                "confidence": "medium",
                                "risk_level": self._assess_username_risk(username),
                            }
                        )

        except Exception as e:
            log_error(f"Username probing failed: {e}")

        return users

    def _analyze_login_page_disclosure(self, target_url: str) -> List[Dict[str, Any]]:
        """ENHANCED: Analyze login page for user information disclosure"""
        users = []

        try:
            login_urls = ["/wp-login.php", "/wp-admin/", "/login/", "/admin/"]

            for login_url in login_urls:
                try:
                    full_url = urljoin(target_url, login_url)
                    response = self.core.make_request(full_url) if self.core else None

                    if response and response.status_code == 200:
                        # Look for disclosed usernames in login page
                        disclosed_users = self._extract_usernames_from_login_page(
                            response.text
                        )
                        for username in disclosed_users:
                            users.append(
                                {
                                    "username": username,
                                    "detection_method": "login_page_disclosure",
                                    "login_url": login_url,
                                    "risk_level": "high",  # Login page disclosure is always high risk
                                }
                            )

                except Exception as e:
                    continue

        except Exception as e:
            log_error(f"Login page analysis failed: {e}")

        return users

    def _perform_comprehensive_user_analysis(
        self, target_url: str, user: Dict[str, Any]
    ) -> Dict[str, Any]:
        """ENHANCED: Comprehensive security analysis for individual user"""
        enhanced_user = user.copy()

        # Initialize security analysis
        security_analysis = {
            "risk_level": "low",
            "security_issues": [],
            "role_analysis": {},
            "account_security": {},
            "recommendations": [],
        }

        try:
            username = user.get("username", "")

            # 1. Username security analysis
            username_analysis = self._analyze_username_security(username)
            security_analysis.update(username_analysis)

            # 2. Role and privilege analysis
            roles = user.get("roles", [])
            if roles:
                role_analysis = self._analyze_user_roles_and_privileges(roles)
                security_analysis["role_analysis"] = role_analysis

            # 3. Account security assessment
            account_analysis = self._assess_account_security(user)
            security_analysis["account_security"] = account_analysis

            # 4. User enumeration exposure analysis
            exposure_analysis = self._assess_user_exposure_risk(user)
            security_analysis.update(exposure_analysis)

            # 5. Calculate overall risk level
            overall_risk = self._calculate_user_overall_risk(security_analysis)
            security_analysis["risk_level"] = overall_risk

            # 6. Generate recommendations
            recommendations = self._generate_user_security_recommendations(
                security_analysis, user
            )
            security_analysis["recommendations"] = recommendations

        except Exception as e:
            log_error(f"User security analysis failed for {username}: {e}")
            security_analysis["security_issues"].append(f"Analysis error: {str(e)}")

        enhanced_user["security_analysis"] = security_analysis
        return enhanced_user

    def _analyze_username_security(self, username: str) -> Dict[str, Any]:
        """Analyze username for security weaknesses"""
        analysis = {
            "username_risk": "low",
            "security_issues": [],
            "username_characteristics": [],
        }

        username_lower = username.lower()

        # Check against high-risk usernames
        if username_lower in self.high_risk_indicators["weak_usernames"]:
            analysis["username_risk"] = "critical"
            analysis["security_issues"].append("High-risk default username")
            analysis["username_characteristics"].append("default_account")

        # Check against generic patterns
        for pattern in self.high_risk_indicators["generic_patterns"]:
            if re.match(pattern, username_lower):
                analysis["username_risk"] = "high"
                analysis["security_issues"].append("Generic username pattern")
                analysis["username_characteristics"].append("generic_pattern")

        # Check for service accounts
        if username_lower in self.high_risk_indicators["service_accounts"]:
            analysis["username_risk"] = "medium"
            analysis["security_issues"].append("Service account detected")
            analysis["username_characteristics"].append("service_account")

        # Check for suspicious names
        if username_lower in self.high_risk_indicators["suspicious_names"]:
            analysis["username_risk"] = "critical"
            analysis["security_issues"].append("Suspicious username detected")
            analysis["username_characteristics"].append("suspicious")

        # Username length and complexity check
        if len(username) < 4:
            analysis["security_issues"].append("Username too short")
            analysis["username_characteristics"].append("short_username")

        if username.isdigit():
            analysis["security_issues"].append("Numeric-only username")
            analysis["username_characteristics"].append("numeric_only")

        return analysis

    def _analyze_user_roles_and_privileges(self, roles: List[str]) -> Dict[str, Any]:
        """Analyze user roles and associated privileges"""
        analysis = {
            "roles": roles,
            "highest_privilege": 0,
            "risk_assessment": "low",
            "privilege_issues": [],
            "capabilities": [],
        }

        for role in roles:
            role_lower = role.lower()
            if role_lower in self.wordpress_roles:
                role_info = self.wordpress_roles[role_lower]

                # Track highest privilege level
                if role_info["level"] > analysis["highest_privilege"]:
                    analysis["highest_privilege"] = role_info["level"]
                    analysis["risk_assessment"] = role_info["risk"]

                # Collect capabilities
                analysis["capabilities"].extend(role_info.get("capabilities", []))

                # Check for privilege issues
                if role_info["level"] >= 7:  # Editor or above
                    analysis["privilege_issues"].append(f"High-privilege role: {role}")

        # Remove duplicate capabilities
        analysis["capabilities"] = list(set(analysis["capabilities"]))

        # Additional privilege analysis
        dangerous_capabilities = [
            "manage_options",
            "edit_users",
            "delete_users",
            "activate_plugins",
            "edit_themes",
            "install_plugins",
            "update_core",
            "unfiltered_html",
        ]

        for cap in dangerous_capabilities:
            if cap in analysis["capabilities"]:
                analysis["privilege_issues"].append(f"Dangerous capability: {cap}")

        return analysis

    def _assess_account_security(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """Assess account security characteristics"""
        analysis = {
            "account_age": "unknown",
            "activity_level": "unknown",
            "exposure_methods": [],
            "security_concerns": [],
        }

        # Analyze detection methods for security implications
        detection_method = user.get("detection_method", "")

        if detection_method == "rest_api":
            analysis["exposure_methods"].append("REST API enumeration")
            analysis["security_concerns"].append("User data exposed via REST API")

        if detection_method == "author_page":
            analysis["exposure_methods"].append("Author page enumeration")
            analysis["security_concerns"].append("User enumerable via author pages")

        if detection_method == "login_error":
            analysis["exposure_methods"].append("Login error messages")
            analysis["security_concerns"].append("Username confirmed via login errors")

        # Check post count for activity analysis
        post_count = user.get("post_count", 0)
        if post_count > 0:
            analysis["activity_level"] = "active"
        elif post_count == 0:
            analysis["activity_level"] = "inactive"

        return analysis

    def _assess_user_exposure_risk(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """Assess user information exposure risk"""
        analysis = {
            "exposure_risk": "low",
            "information_disclosure": [],
            "enumeration_vectors": [],
        }

        # Check what information is exposed
        if user.get("display_name"):
            analysis["information_disclosure"].append("Display name exposed")

        if user.get("roles"):
            analysis["information_disclosure"].append("User roles exposed")
            analysis["exposure_risk"] = "high"

        if user.get("capabilities"):
            analysis["information_disclosure"].append("User capabilities exposed")
            analysis["exposure_risk"] = "critical"

        if user.get("registration_date"):
            analysis["information_disclosure"].append("Registration date exposed")

        # Check enumeration vectors
        detection_method = user.get("detection_method", "")
        analysis["enumeration_vectors"].append(detection_method)

        return analysis

    def _calculate_user_overall_risk(self, security_analysis: Dict[str, Any]) -> str:
        """Calculate overall user security risk level"""
        risk_score = 0

        # Username risk scoring
        username_risk = security_analysis.get("username_risk", "low")
        if username_risk == "critical":
            risk_score += 10
        elif username_risk == "high":
            risk_score += 7
        elif username_risk == "medium":
            risk_score += 4

        # Role risk scoring
        role_analysis = security_analysis.get("role_analysis", {})
        role_risk = role_analysis.get("risk_assessment", "low")
        if role_risk == "critical":
            risk_score += 10
        elif role_risk == "high":
            risk_score += 8
        elif role_risk == "medium":
            risk_score += 5

        # Exposure risk scoring
        exposure_risk = security_analysis.get("exposure_risk", "low")
        if exposure_risk == "critical":
            risk_score += 8
        elif exposure_risk == "high":
            risk_score += 6
        elif exposure_risk == "medium":
            risk_score += 3

        # Determine overall risk
        if risk_score >= 15:
            return "critical"
        elif risk_score >= 10:
            return "high"
        elif risk_score >= 5:
            return "medium"
        else:
            return "low"

    def _generate_user_security_recommendations(
        self, security_analysis: Dict[str, Any], user: Dict[str, Any]
    ) -> List[str]:
        """Generate security recommendations for user"""
        recommendations = []

        username = user.get("username", "")
        username_risk = security_analysis.get("username_risk", "low")

        if username_risk in ["critical", "high"]:
            recommendations.append(
                f"🚨 URGENT: Change username '{username}' - high security risk"
            )

        role_analysis = security_analysis.get("role_analysis", {})
        if role_analysis.get("risk_assessment") in ["critical", "high"]:
            recommendations.append("⚠️ Review user privileges - high-risk role detected")

        if "User roles exposed" in security_analysis.get("information_disclosure", []):
            recommendations.append("🔒 Restrict REST API user enumeration")

        if "login_error" in security_analysis.get("enumeration_vectors", []):
            recommendations.append("🛡️ Implement generic login error messages")

        # General recommendations
        recommendations.extend(
            [
                "🔐 Enforce strong password policies",
                "🔄 Enable two-factor authentication",
                "📊 Monitor user account activity",
                "🗑️ Remove inactive user accounts",
            ]
        )

        return recommendations

    def _generate_comprehensive_user_security_assessment(
        self, users: List[Dict[str, Any]], enumeration_methods: Dict[str, int]
    ) -> Dict[str, Any]:
        """Generate comprehensive user security assessment"""
        assessment = {
            "total_users": len(users),
            "enumeration_summary": enumeration_methods,
            "risk_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "role_distribution": {},
            "security_issues": [],
            "recommendations": [],
            "overall_risk": "low",
        }

        # Analyze all users
        for user in users:
            security_analysis = user.get("security_analysis", {})
            risk_level = security_analysis.get("risk_level", "low")

            # Update risk breakdown
            if risk_level in assessment["risk_breakdown"]:
                assessment["risk_breakdown"][risk_level] += 1

            # Collect role information
            roles = user.get("roles", [])
            for role in roles:
                assessment["role_distribution"][role] = (
                    assessment["role_distribution"].get(role, 0) + 1
                )

            # Collect security issues
            issues = security_analysis.get("security_issues", [])
            assessment["security_issues"].extend(issues)

        # Remove duplicate security issues
        assessment["security_issues"] = list(set(assessment["security_issues"]))

        # Determine overall risk
        if assessment["risk_breakdown"]["critical"] > 0:
            assessment["overall_risk"] = "critical"
        elif assessment["risk_breakdown"]["high"] > 0:
            assessment["overall_risk"] = "high"
        elif assessment["risk_breakdown"]["medium"] > 0:
            assessment["overall_risk"] = "medium"

        # Generate recommendations
        if len(enumeration_methods) > 2:
            assessment["recommendations"].append(
                "🚨 Multiple user enumeration vectors detected"
            )

        if assessment["risk_breakdown"]["critical"] > 0:
            assessment["recommendations"].append(
                "🆘 CRITICAL: Address critical user security issues immediately"
            )

        if assessment["role_distribution"].get("administrator", 0) > 1:
            assessment["recommendations"].append(
                "⚠️ Multiple administrator accounts detected"
            )

        assessment["recommendations"].extend(
            [
                "🔒 Implement user enumeration protection",
                "🛡️ Enforce principle of least privilege",
                "📊 Regular user access review",
                "🔐 Strengthen authentication requirements",
            ]
        )

        return assessment

    def _add_individual_user_finding(
        self, result: ScanResult, user: Dict[str, Any], target_url: str
    ) -> None:
        """Add individual user security finding"""
        username = user.get("username", "Unknown")
        security_analysis = user.get("security_analysis", {})
        risk_level = security_analysis.get("risk_level", "low")

        # Map risk level to severity
        severity_map = {
            "critical": ScanSeverity.CRITICAL,
            "high": ScanSeverity.HIGH,
            "medium": ScanSeverity.MEDIUM,
            "low": ScanSeverity.LOW,
        }

        severity = severity_map.get(risk_level, ScanSeverity.LOW)

        # Generate description
        roles = user.get("roles", [])
        role_text = f" (Roles: {', '.join(roles)})" if roles else ""

        description = f"WordPress user '{username}' detected{role_text}"

        result.add_finding(
            title=f"WordPress User Analysis: {username}",
            description=description,
            severity=severity,
            technical_details={
                "username": username,
                "user_id": user.get("user_id"),
                "roles": roles,
                "detection_method": user.get("detection_method"),
                "security_analysis": security_analysis,
            },
            recommendation=" | ".join(security_analysis.get("recommendations", [])),
        )

    def _add_user_security_summary_finding(
        self, result: ScanResult, assessment: Dict[str, Any]
    ) -> None:
        """Add comprehensive user security summary finding"""
        severity_map = {
            "critical": ScanSeverity.CRITICAL,
            "high": ScanSeverity.HIGH,
            "medium": ScanSeverity.MEDIUM,
            "low": ScanSeverity.LOW,
        }

        severity = severity_map.get(assessment["overall_risk"], ScanSeverity.LOW)

        description = f"WordPress user security assessment: {assessment['total_users']} users analyzed"

        result.add_finding(
            title="WordPress User Security Assessment Summary",
            description=description,
            severity=severity,
            technical_details=assessment,
            recommendation=" | ".join(assessment["recommendations"]),
        )

    def _assess_user_enumeration_vulnerabilities(
        self, enumeration_methods: Dict[str, int], target_url: str
    ) -> Dict[str, Any]:
        """Assess user enumeration vulnerabilities"""
        vulnerabilities = {
            "enumeration_vectors": enumeration_methods,
            "vulnerability_count": len(enumeration_methods),
            "risk_level": "low",
            "security_issues": [],
        }

        # Assess each enumeration method
        if "rest_api" in enumeration_methods:
            vulnerabilities["security_issues"].append(
                "REST API user enumeration enabled"
            )

        if "author_pages" in enumeration_methods:
            vulnerabilities["security_issues"].append(
                "Author page enumeration possible"
            )

        if "login_error" in enumeration_methods:
            vulnerabilities["security_issues"].append(
                "Login error message user enumeration"
            )

        if "rss_feeds" in enumeration_methods:
            vulnerabilities["security_issues"].append("RSS feed user disclosure")

        # Determine risk level
        if len(enumeration_methods) >= 3:
            vulnerabilities["risk_level"] = "high"
        elif len(enumeration_methods) >= 2:
            vulnerabilities["risk_level"] = "medium"

        return vulnerabilities

    def _add_enumeration_vulnerability_findings(
        self, result: ScanResult, vulnerabilities: Dict[str, Any]
    ) -> None:
        """Add user enumeration vulnerability findings"""
        if vulnerabilities["vulnerability_count"] > 0:
            severity_map = {
                "high": ScanSeverity.HIGH,
                "medium": ScanSeverity.MEDIUM,
                "low": ScanSeverity.LOW,
            }

            severity = severity_map.get(vulnerabilities["risk_level"], ScanSeverity.LOW)

            result.add_finding(
                title="WordPress User Enumeration Vulnerabilities",
                description=f"Multiple user enumeration vectors detected ({vulnerabilities['vulnerability_count']} methods)",
                severity=severity,
                technical_details=vulnerabilities,
                recommendation="🔒 Implement user enumeration protection | 🛡️ Disable author page enumeration | 🚫 Use generic login error messages",
            )

    # Helper methods for enumeration techniques
    def _check_username_via_login_error(self, target_url: str, username: str) -> bool:
        """Check if username exists via login error messages"""
        try:
            login_url = urljoin(target_url, "/wp-login.php")
            data = {
                "log": username,
                "pwd": "invalid_password_123",
                "wp-submit": "Log In",
            }

            response = (
                self.core.session.post(login_url, data=data) if self.core else None
            )

            if response and response.status_code == 200:
                # Look for different error messages indicating username exists
                content = response.text.lower()
                username_exists_indicators = [
                    "incorrect password",
                    "password is incorrect",
                    f"password for {username.lower()}",
                    "lost your password",
                ]

                return any(
                    indicator in content for indicator in username_exists_indicators
                )

        except Exception:
            pass

        return False

    def _check_username_via_password_reset(
        self, target_url: str, username: str
    ) -> bool:
        """Check if username exists via password reset"""
        try:
            reset_url = urljoin(target_url, "/wp-login.php?action=lostpassword")
            data = {"user_login": username}

            response = (
                self.core.session.post(reset_url, data=data) if self.core else None
            )

            if response and response.status_code == 200:
                content = response.text.lower()
                # Look for success message indicating username exists
                success_indicators = [
                    "check your email",
                    "reset link",
                    "password reset",
                ]

                return any(indicator in content for indicator in success_indicators)

        except Exception:
            pass

        return False

    def _extract_usernames_from_login_page(self, content: str) -> List[str]:
        """Extract usernames disclosed in login page"""
        usernames = []

        # Look for various patterns that might disclose usernames
        patterns = [
            r'value="([^"]+)"[^>]*name="log"',
            r'placeholder="([^"]+)"[^>]*name="log"',
            r"welcome back[,\s]+([a-zA-Z0-9_-]+)",
            r"logged in as[,\s]+([a-zA-Z0-9_-]+)",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            usernames.extend(matches)

        return [u for u in usernames if u and len(u) > 2]

    def _extract_user_info_from_author_page(
        self, content: str, user_id: int
    ) -> Optional[Dict[str, Any]]:
        """Extract user information from author page"""
        try:
            # Extract username and display name from page content
            patterns = {
                "username": [
                    r"author[/-]([a-zA-Z0-9_-]+)",
                    r"user[/-]([a-zA-Z0-9_-]+)",
                    r"/([a-zA-Z0-9_-]+)/?$",
                ],
                "display_name": [
                    r"<title>([^<]+)\s*(?:-|–|Posts by|Author:)",
                    r"<h1[^>]*>([^<]+)</h1>",
                    r"author[^>]*>([^<]+)<",
                ],
            }

            user_info = {}

            for field, field_patterns in patterns.items():
                for pattern in field_patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        user_info[field] = match.group(1).strip()
                        break

            if user_info:
                return user_info

        except Exception:
            pass

        return None

    def _extract_page_title(self, content: str) -> str:
        """Extract page title"""
        try:
            match = re.search(r"<title>([^<]+)</title>", content, re.IGNORECASE)
            return match.group(1).strip() if match else ""
        except:
            return ""

    def _assess_username_risk(self, username: str) -> str:
        """Assess risk level of username"""
        username_lower = username.lower()

        if username_lower in ["admin", "administrator", "root"]:
            return "critical"
        elif username_lower in ["test", "demo", "guest", "user"]:
            return "high"
        elif any(re.match(pattern, username_lower) for pattern in self.weak_patterns):
            return "medium"
        else:
            return "low"

    def _deduplicate_and_enhance_users(
        self, users: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Remove duplicates and enhance user data"""
        unique_users = {}

        for user in users:
            username = user.get("username", "")
            if not username:
                continue

            if username in unique_users:
                # Merge data from multiple sources
                existing = unique_users[username]

                # Prefer more detailed detection methods
                if user.get("roles") and not existing.get("roles"):
                    existing.update(user)
                elif user.get("capabilities") and not existing.get("capabilities"):
                    existing.update(user)

                # Combine detection methods
                existing_methods = existing.get("detection_methods", [])
                if isinstance(existing_methods, str):
                    existing_methods = [existing_methods]
                new_method = user.get("detection_method", "")
                if new_method and new_method not in existing_methods:
                    existing_methods.append(new_method)
                existing["detection_methods"] = existing_methods

            else:
                # New user
                detection_method = user.get("detection_method", "")
                user["detection_methods"] = (
                    [detection_method] if detection_method else []
                )
                unique_users[username] = user

        return list(unique_users.values())

    # Legacy compatibility methods (preserved from original implementation)
    def _enumerate_via_rss_feeds(self, target_url: str) -> List[Dict[str, Any]]:
        """Enumerate users via RSS feeds (existing implementation preserved)"""
        users = []

        try:
            # Common RSS feed URLs
            rss_feeds = [
                "/feed/",
                "/rss/",
                "/rss.xml",
                "/feed.xml",
                "/?feed=rss",
                "/?feed=rss2",
                "/comments/feed/",
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
        """Enumerate users via sitemap (existing implementation preserved)"""
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

                        # Look for author/user URLs in sitemap
                        user_url_patterns = [
                            r"<loc>([^<]*?/author/[^<]*?)</loc>",
                            r"<loc>([^<]*?/user/[^<]*?)</loc>",
                        ]

                        for pattern in user_url_patterns:
                            matches = re.findall(pattern, content)
                            for match in matches:
                                # Extract username from URL
                                username_match = re.search(
                                    r"/(author|user)/([^/]+)", match
                                )
                                if username_match:
                                    username = username_match.group(2)
                                    if username not in [u["username"] for u in users]:
                                        user_info = {
                                            "username": username,
                                            "detection_method": "sitemap",
                                            "sitemap_url": sitemap_url,
                                            "user_url": match,
                                        }
                                        users.append(user_info)

                except requests.RequestException:
                    continue

        except Exception as e:
            log_error(f"Sitemap enumeration failed: {e}")

        return users

    # Legacy compatibility method
    def assess_user_security(self, users: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Legacy compatibility method for user security assessment

        Args:
            users: List of detected users

        Returns:
            Dict containing user security analysis results
        """
        try:
            # Use the new comprehensive assessment method
            enumeration_methods = {"legacy_call": len(users)}

            # Enhance users with security analysis
            enhanced_users = []
            for user in users:
                enhanced_user = self._perform_comprehensive_user_analysis("", user)
                enhanced_users.append(enhanced_user)

            # Generate comprehensive assessment
            assessment = self._generate_comprehensive_user_security_assessment(
                enhanced_users, enumeration_methods
            )

            return assessment

        except Exception as e:
            log_error(f"User security assessment failed: {e}")
            return {"error": str(e)}
