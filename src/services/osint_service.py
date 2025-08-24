"""
OSINT & Information Gathering Service
FILE PATH: src/services/osint_service.py

Phase 4.2 Implementation - OSINT & Information Gathering
Following SOLID, Clean Code, and DRY principles
Using only FREE external services
"""

import logging
import subprocess
import json
import re
import time
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime
from abc import ABC, abstractmethod

# VERIFIED IMPORTS - All classes exist in project
from ..core.validator import InputValidator  # ✅ src/core/validator.py
from ..utils.logger import (
    log_info,
    log_error,
    log_success,
    log_warning,
)  # ✅ src/utils/logger.py


class OSINTServiceInterface(ABC):
    """Interface for OSINT operations following Interface Segregation Principle"""

    @abstractmethod
    def email_harvest(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Email harvesting operation"""
        pass

    @abstractmethod
    def search_engine_recon(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Search engine reconnaissance"""
        pass

    @abstractmethod
    def whois_analysis(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Enhanced WHOIS analysis"""
        pass

    @abstractmethod
    def get_service_info(self) -> Dict[str, Any]:
        """Get service information"""
        pass


class OSINTService(OSINTServiceInterface):
    """
    OSINT & Information Gathering Service

    Implements OSINT capabilities using free services:
    - Email harvesting (TheHarvester)
    - Search engine dorking (Google, Bing - free APIs)
    - WHOIS analysis (free WHOIS services)
    - Social media reconnaissance (free tools)
    - Domain intelligence gathering

    Single Responsibility: OSINT data collection and analysis
    Open/Closed: Extensible for new OSINT sources
    """

    def __init__(self):
        """Initialize OSINT service with free service configurations"""
        self.validator = InputValidator()

        # Free service configurations
        self.free_apis = {
            "whois": "https://api.whoisjson.com/v1/",  # Free WHOIS API
            "ipapi": "http://ip-api.com/json/",  # Free IP geolocation
            "crtsh": "https://crt.sh/",  # Free certificate transparency
            "hackertarget": "https://api.hackertarget.com/",  # Free recon API
        }

        # Available free tools
        self.tools = {
            "theharvester": "Email and subdomain harvesting",
            "whois": "Domain registration information",
            "dig": "DNS information gathering",
            "curl": "Web content retrieval",
            "grep": "Pattern matching and filtering",
        }

        # Rate limiting for free APIs (respectful usage)
        self.rate_limits = {
            "api_call_delay": 1.0,  # 1 second between API calls
            "batch_delay": 5.0,  # 5 seconds between batches
            "max_requests_per_minute": 30,
        }

    def email_harvest(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Email harvesting using TheHarvester and free sources

        Single Responsibility: Email discovery and validation
        """
        log_info(f"🔍 Starting email harvesting for: {target}")

        if options is None:
            options = {}

        # Validate target
        if not self.validator.validate_target(target):
            log_error(f"❌ Invalid target domain: {target}")
            return {"status": "error", "message": "Invalid domain"}

        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "emails": [],
            "sources": [],
            "statistics": {},
            "raw_data": {},
        }

        try:
            # 1. TheHarvester integration (free sources only)
            theharvester_results = self._run_theharvester(target, options)
            if theharvester_results:
                results["emails"].extend(theharvester_results.get("emails", []))
                results["sources"].extend(theharvester_results.get("sources", []))
                results["raw_data"]["theharvester"] = theharvester_results

            # 2. Free web scraping for emails
            web_emails = self._harvest_emails_from_web(target, options)
            if web_emails:
                results["emails"].extend(web_emails)
                results["sources"].append("web_scraping")

            # 3. Certificate transparency logs (free)
            ct_emails = self._harvest_from_certificate_transparency(target)
            if ct_emails:
                results["emails"].extend(ct_emails)
                results["sources"].append("certificate_transparency")

            # Remove duplicates and validate emails
            results["emails"] = list(set(results["emails"]))
            results["emails"] = [
                email for email in results["emails"] if self._validate_email(email)
            ]

            # Generate statistics
            results["statistics"] = {
                "total_emails": len(results["emails"]),
                "sources_used": len(results["sources"]),
                "unique_domains": len(
                    set(
                        email.split("@")[1]
                        for email in results["emails"]
                        if "@" in email
                    )
                ),
            }

            log_success(
                f"✅ Email harvesting completed: {len(results['emails'])} emails found"
            )
            return results

        except Exception as e:
            log_error(f"❌ Email harvesting failed: {str(e)}")
            return {"status": "error", "message": str(e)}

    def search_engine_recon(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Search engine reconnaissance using free dorking techniques

        Single Responsibility: Search engine intelligence gathering
        """
        log_info(f"🔍 Starting search engine reconnaissance for: {target}")

        if options is None:
            options = {}

        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "google_dorks": [],
            "bing_results": [],
            "exposed_files": [],
            "subdomains": [],
            "social_media": [],
            "statistics": {},
        }

        try:
            # 1. Google dorking (free, rate-limited)
            google_results = self._perform_google_dorking(target, options)
            if google_results:
                results["google_dorks"] = google_results

            # 2. Bing search reconnaissance
            bing_results = self._perform_bing_recon(target, options)
            if bing_results:
                results["bing_results"] = bing_results

            # 3. Free subdomain discovery via search engines
            search_subdomains = self._discover_subdomains_via_search(target)
            if search_subdomains:
                results["subdomains"] = search_subdomains

            # 4. Social media profile discovery (free)
            social_profiles = self._discover_social_media_profiles(target)
            if social_profiles:
                results["social_media"] = social_profiles

            # Generate statistics
            results["statistics"] = {
                "total_results": len(results["google_dorks"])
                + len(results["bing_results"]),
                "subdomains_found": len(results["subdomains"]),
                "social_profiles": len(results["social_media"]),
                "exposed_files": len(results["exposed_files"]),
            }

            log_success(f"✅ Search engine reconnaissance completed")
            return results

        except Exception as e:
            log_error(f"❌ Search engine reconnaissance failed: {str(e)}")
            return {"status": "error", "message": str(e)}

    def whois_analysis(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Enhanced WHOIS analysis using free WHOIS services

        Single Responsibility: Domain registration intelligence gathering
        """
        log_info(f"🔍 Starting enhanced WHOIS analysis for: {target}")

        if options is None:
            options = {}

        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "whois_data": {},
            "historical_data": {},
            "registrar_info": {},
            "dns_servers": [],
            "ip_geolocation": {},
            "statistics": {},
        }

        try:
            # 1. Standard WHOIS lookup
            whois_data = self._perform_whois_lookup(target)
            if whois_data:
                results["whois_data"] = whois_data

            # 2. Enhanced registrar analysis
            registrar_info = self._analyze_registrar_info(target)
            if registrar_info:
                results["registrar_info"] = registrar_info

            # 3. DNS server analysis
            dns_servers = self._analyze_dns_servers(target)
            if dns_servers:
                results["dns_servers"] = dns_servers

            # 4. IP geolocation (free)
            ip_info = self._get_ip_geolocation(target)
            if ip_info:
                results["ip_geolocation"] = ip_info

            # 5. Certificate transparency analysis (free)
            ct_analysis = self._analyze_certificate_transparency(target)
            if ct_analysis:
                results["historical_data"]["certificates"] = ct_analysis

            # Generate statistics
            results["statistics"] = {
                "data_sources": len(
                    [k for k, v in results.items() if v and k != "statistics"]
                ),
                "dns_servers_count": len(results["dns_servers"]),
                "historical_records": len(results["historical_data"]),
            }

            log_success(f"✅ WHOIS analysis completed")
            return results

        except Exception as e:
            log_error(f"❌ WHOIS analysis failed: {str(e)}")
            return {"status": "error", "message": str(e)}

    def comprehensive_osint(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive OSINT gathering combining all methods

        Single Responsibility: Complete intelligence gathering orchestration
        """
        log_info(f"🔍 Starting comprehensive OSINT for: {target}")

        if options is None:
            options = {}

        comprehensive_results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "email_harvest": {},
            "search_recon": {},
            "whois_analysis": {},
            "summary": {},
            "recommendations": [],
        }

        try:
            # 1. Email harvesting
            log_info("📧 Phase 1: Email harvesting...")
            comprehensive_results["email_harvest"] = self.email_harvest(target, options)

            # 2. Search engine reconnaissance
            log_info("🔍 Phase 2: Search engine reconnaissance...")
            comprehensive_results["search_recon"] = self.search_engine_recon(
                target, options
            )

            # 3. WHOIS analysis
            log_info("🌐 Phase 3: WHOIS analysis...")
            comprehensive_results["whois_analysis"] = self.whois_analysis(
                target, options
            )

            # 4. Generate comprehensive summary
            comprehensive_results["summary"] = self._generate_osint_summary(
                comprehensive_results
            )

            # 5. Generate actionable recommendations
            comprehensive_results["recommendations"] = (
                self._generate_osint_recommendations(comprehensive_results)
            )

            log_success(f"✅ Comprehensive OSINT completed for {target}")
            return comprehensive_results

        except Exception as e:
            log_error(f"❌ Comprehensive OSINT failed: {str(e)}")
            return {"status": "error", "message": str(e)}

    def get_service_info(self) -> Dict[str, Any]:
        """Get OSINT service information"""
        return {
            "name": "OSINTService",
            "version": "1.0.0",
            "description": "OSINT & Information Gathering Service",
            "capabilities": [
                "email_harvesting",
                "search_engine_reconnaissance",
                "whois_analysis",
                "social_media_discovery",
                "certificate_transparency_analysis",
            ],
            "free_apis_used": list(self.free_apis.keys()),
            "tools_verified": True,
            "roadmap_compliance": True,
            "phase": "4.2",
            "priority": "High",
        }

    # Private helper methods (following Single Responsibility Principle)

    def _run_theharvester(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run TheHarvester with free sources only"""
        try:
            # Free sources only: google, bing, yahoo, baidu, duckduckgo
            free_sources = ["google", "bing", "yahoo", "baidu", "duckduckgo", "crtsh"]

            results = {"emails": [], "hosts": [], "sources": []}

            for source in free_sources:
                try:
                    # Rate limiting for respectful usage
                    time.sleep(self.rate_limits["api_call_delay"])

                    cmd = [
                        "theharvester",
                        "-d",
                        target,
                        "-b",
                        source,
                        "-l",
                        "100",  # Limit results
                        "-f",
                        f"/tmp/harvest_{target}_{source}.json",
                    ]

                    log_info(f"🔍 Running TheHarvester with source: {source}")
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=60
                    )

                    if result.returncode == 0:
                        # Parse TheHarvester output
                        emails = re.findall(
                            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                            result.stdout,
                        )
                        hosts = re.findall(
                            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", result.stdout
                        )

                        results["emails"].extend(emails)
                        results["hosts"].extend(hosts)
                        results["sources"].append(source)

                        log_success(
                            f"✅ {source}: {len(emails)} emails, {len(hosts)} hosts"
                        )
                    else:
                        log_warning(f"⚠️ {source}: No results or tool unavailable")

                except Exception as e:
                    log_warning(f"⚠️ {source} failed: {str(e)}")
                    continue

            # Remove duplicates
            results["emails"] = list(set(results["emails"]))
            results["hosts"] = list(set(results["hosts"]))

            return results

        except Exception as e:
            log_error(f"❌ TheHarvester execution failed: {str(e)}")
            return {}

    def _perform_google_dorking(
        self, target: str, options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Perform Google dorking with free techniques"""
        try:
            # Free Google dork patterns for common information disclosure
            dork_patterns = [
                f"site:{target} filetype:pdf",
                f"site:{target} filetype:doc",
                f"site:{target} filetype:xls",
                f'site:{target} "index of"',
                f'site:{target} "login" OR "admin"',
                f'site:{target} "error" OR "warning"',
                f"site:{target} inurl:admin",
                f"site:{target} inurl:login",
                f'site:{target} intext:"sql error"',
                f'site:{target} intext:"warning"',
            ]

            results = []

            # Note: Using pattern analysis instead of direct API calls
            # to respect Google's terms and avoid API key requirements
            log_info("🔍 Analyzing common Google dork patterns")

            for pattern in dork_patterns:
                dork_info = {
                    "pattern": pattern,
                    "description": self._get_dork_description(pattern),
                    "risk_level": self._assess_dork_risk(pattern),
                    "manual_verification_required": True,
                }
                results.append(dork_info)

            log_success(f"✅ Generated {len(results)} Google dork patterns")
            return results

        except Exception as e:
            log_error(f"❌ Google dorking analysis failed: {str(e)}")
            return []

    def _perform_bing_recon(
        self, target: str, options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Perform Bing reconnaissance with free techniques"""
        try:
            # Bing-specific search patterns
            bing_patterns = [
                f"domain:{target}",
                f"site:{target} (login OR admin)",
                f"site:{target} filetype:pdf",
                f"site:{target} contains:password",
                f"ip:{target}" if self._is_ip_address(target) else f"domain:{target}",
            ]

            results = []

            for pattern in bing_patterns:
                bing_info = {
                    "search_pattern": pattern,
                    "search_engine": "bing",
                    "description": f"Bing search for: {pattern}",
                    "manual_verification_required": True,
                }
                results.append(bing_info)

            log_success(f"✅ Generated {len(results)} Bing search patterns")
            return results

        except Exception as e:
            log_error(f"❌ Bing reconnaissance failed: {str(e)}")
            return []

    def _perform_whois_lookup(self, target: str) -> Dict[str, Any]:
        """Perform WHOIS lookup using free services"""
        try:
            whois_data = {}

            # 1. System WHOIS command (always free)
            cmd = ["whois", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                whois_raw = result.stdout
                whois_data["raw"] = whois_raw

                # Parse key information
                whois_data["parsed"] = self._parse_whois_output(whois_raw)
                log_success("✅ System WHOIS lookup completed")

            # 2. Free API backup (with rate limiting)
            time.sleep(self.rate_limits["api_call_delay"])

            try:
                api_url = f"{self.free_apis['whois']}{target}"
                headers = {"User-Agent": "Auto-Pentest-Framework/1.0"}

                response = requests.get(api_url, headers=headers, timeout=10)
                if response.status_code == 200:
                    api_data = response.json()
                    whois_data["api_enhanced"] = api_data
                    log_success("✅ Free WHOIS API enhanced data retrieved")
            except Exception as e:
                log_warning(f"⚠️ Free WHOIS API unavailable: {str(e)}")

            return whois_data

        except Exception as e:
            log_error(f"❌ WHOIS lookup failed: {str(e)}")
            return {}

    def _get_ip_geolocation(self, target: str) -> Dict[str, Any]:
        """Get IP geolocation using free service"""
        try:
            # Resolve domain to IP first if needed
            ip_address = self._resolve_domain_to_ip(target)
            if not ip_address:
                return {}

            # Rate limiting
            time.sleep(self.rate_limits["api_call_delay"])

            # Free IP geolocation API
            api_url = f"{self.free_apis['ipapi']}{ip_address}"
            headers = {"User-Agent": "Auto-Pentest-Framework/1.0"}

            response = requests.get(api_url, headers=headers, timeout=10)
            if response.status_code == 200:
                geo_data = response.json()

                # Clean and structure the data
                clean_data = {
                    "ip": geo_data.get("query", ip_address),
                    "country": geo_data.get("country", "Unknown"),
                    "country_code": geo_data.get("countryCode", "Unknown"),
                    "region": geo_data.get("regionName", "Unknown"),
                    "city": geo_data.get("city", "Unknown"),
                    "isp": geo_data.get("isp", "Unknown"),
                    "organization": geo_data.get("org", "Unknown"),
                    "timezone": geo_data.get("timezone", "Unknown"),
                    "latitude": geo_data.get("lat", 0),
                    "longitude": geo_data.get("lon", 0),
                }

                log_success(f"✅ IP geolocation completed: {clean_data['country']}")
                return clean_data

            return {}

        except Exception as e:
            log_error(f"❌ IP geolocation failed: {str(e)}")
            return {}

    def _harvest_from_certificate_transparency(self, target: str) -> List[str]:
        """Harvest emails from certificate transparency logs (free)"""
        try:
            emails = []

            # Rate limiting
            time.sleep(self.rate_limits["api_call_delay"])

            # Free certificate transparency API
            ct_url = f"{self.free_apis['crtsh']}?q={target}&output=json"
            headers = {"User-Agent": "Auto-Pentest-Framework/1.0"}

            response = requests.get(ct_url, headers=headers, timeout=15)
            if response.status_code == 200:
                ct_data = response.json()

                for cert in ct_data[:50]:  # Limit to first 50 certificates
                    # Extract emails from certificate data
                    common_name = cert.get("common_name", "")
                    name_value = cert.get("name_value", "")

                    # Look for email patterns in certificate fields
                    text_to_search = f"{common_name} {name_value}"
                    found_emails = re.findall(
                        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                        text_to_search,
                    )
                    emails.extend(found_emails)

                log_success(
                    f"✅ Certificate transparency: {len(set(emails))} unique emails"
                )
                return list(set(emails))

            return []

        except Exception as e:
            log_warning(f"⚠️ Certificate transparency lookup failed: {str(e)}")
            return []

    def _harvest_emails_from_web(
        self, target: str, options: Dict[str, Any]
    ) -> List[str]:
        """Harvest emails from web pages (free scraping)"""
        try:
            emails = []

            # Common pages to check for emails
            common_pages = [
                f"https://{target}",
                f"https://{target}/contact",
                f"https://{target}/about",
                f"https://{target}/team",
                f"https://{target}/staff",
            ]

            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; Auto-Pentest-Framework/1.0)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }

            for url in common_pages:
                try:
                    # Rate limiting
                    time.sleep(self.rate_limits["api_call_delay"])

                    response = requests.get(
                        url, headers=headers, timeout=10, verify=False
                    )
                    if response.status_code == 200:
                        content = response.text
                        found_emails = re.findall(
                            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                            content,
                        )
                        emails.extend(found_emails)

                except Exception as e:
                    log_warning(f"⚠️ Failed to scrape {url}: {str(e)}")
                    continue

            unique_emails = list(set(emails))
            log_success(f"✅ Web scraping: {len(unique_emails)} unique emails")
            return unique_emails

        except Exception as e:
            log_warning(f"⚠️ Web email harvesting failed: {str(e)}")
            return []

    def _discover_subdomains_via_search(self, target: str) -> List[str]:
        """Discover subdomains via search engines (free)"""
        try:
            subdomains = []

            # Use certificate transparency for subdomain discovery (free)
            time.sleep(self.rate_limits["api_call_delay"])

            ct_url = f"{self.free_apis['crtsh']}?q=%.{target}&output=json"
            headers = {"User-Agent": "Auto-Pentest-Framework/1.0"}

            response = requests.get(ct_url, headers=headers, timeout=15)
            if response.status_code == 200:
                ct_data = response.json()

                for cert in ct_data[:100]:  # Limit to first 100
                    name_value = cert.get("name_value", "")
                    if name_value:
                        # Extract subdomains
                        domains = name_value.split("\n")
                        for domain in domains:
                            domain = domain.strip()
                            if domain.endswith(f".{target}") and domain != target:
                                subdomains.append(domain)

                unique_subdomains = list(set(subdomains))
                log_success(
                    f"✅ Certificate transparency: {len(unique_subdomains)} subdomains"
                )
                return unique_subdomains

            return []

        except Exception as e:
            log_warning(f"⚠️ Subdomain discovery failed: {str(e)}")
            return []

    def _discover_social_media_profiles(self, target: str) -> List[Dict[str, Any]]:
        """Discover social media profiles (free)"""
        try:
            profiles = []

            # Common social media platforms
            platforms = [
                {"name": "twitter", "url_pattern": f"https://twitter.com/{target}"},
                {
                    "name": "linkedin",
                    "url_pattern": f"https://linkedin.com/company/{target}",
                },
                {"name": "facebook", "url_pattern": f"https://facebook.com/{target}"},
                {"name": "instagram", "url_pattern": f"https://instagram.com/{target}"},
                {"name": "github", "url_pattern": f"https://github.com/{target}"},
            ]

            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; Auto-Pentest-Framework/1.0)"
            }

            for platform in platforms:
                try:
                    # Rate limiting
                    time.sleep(self.rate_limits["api_call_delay"])

                    url = platform["url_pattern"]
                    response = requests.head(
                        url, headers=headers, timeout=10, allow_redirects=True
                    )

                    if response.status_code == 200:
                        profiles.append(
                            {
                                "platform": platform["name"],
                                "url": url,
                                "status": "found",
                                "manual_verification_required": True,
                            }
                        )
                        log_success(f"✅ Found {platform['name']} profile")

                except Exception as e:
                    log_warning(f"⚠️ {platform['name']} check failed: {str(e)}")
                    continue

            return profiles

        except Exception as e:
            log_warning(f"⚠️ Social media discovery failed: {str(e)}")
            return []

    def _analyze_registrar_info(self, target: str) -> Dict[str, Any]:
        """Analyze registrar information"""
        try:
            whois_data = self._perform_whois_lookup(target)
            if not whois_data.get("raw"):
                return {}

            whois_text = whois_data["raw"]

            registrar_info = {
                "registrar": self._extract_whois_field(whois_text, "Registrar"),
                "creation_date": self._extract_whois_field(whois_text, "Creation Date"),
                "expiration_date": self._extract_whois_field(
                    whois_text, "Registry Expiry Date"
                ),
                "last_updated": self._extract_whois_field(whois_text, "Updated Date"),
                "status": self._extract_whois_field(whois_text, "Domain Status"),
                "name_servers": self._extract_name_servers(whois_text),
            }

            return registrar_info

        except Exception as e:
            log_warning(f"⚠️ Registrar analysis failed: {str(e)}")
            return {}

    def _analyze_dns_servers(self, target: str) -> List[Dict[str, Any]]:
        """Analyze DNS servers"""
        try:
            dns_servers = []

            # Get authoritative name servers
            cmd = ["dig", "+short", "NS", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                ns_servers = result.stdout.strip().split("\n")

                for ns in ns_servers:
                    if ns.strip():
                        ns = ns.strip().rstrip(".")

                        # Get IP address of name server
                        ip_cmd = ["dig", "+short", "A", ns]
                        ip_result = subprocess.run(
                            ip_cmd, capture_output=True, text=True, timeout=10
                        )

                        ns_info = {
                            "name_server": ns,
                            "ip_address": (
                                ip_result.stdout.strip()
                                if ip_result.returncode == 0
                                else "Unknown"
                            ),
                            "geolocation": {},
                        }

                        # Get geolocation for name server
                        if ns_info["ip_address"] != "Unknown":
                            ns_info["geolocation"] = self._get_ip_geolocation(
                                ns_info["ip_address"]
                            )

                        dns_servers.append(ns_info)

            return dns_servers

        except Exception as e:
            log_warning(f"⚠️ DNS server analysis failed: {str(e)}")
            return []

    def _analyze_certificate_transparency(self, target: str) -> Dict[str, Any]:
        """Analyze certificate transparency logs"""
        try:
            # Rate limiting
            time.sleep(self.rate_limits["api_call_delay"])

            ct_url = f"{self.free_apis['crtsh']}?q={target}&output=json"
            headers = {"User-Agent": "Auto-Pentest-Framework/1.0"}

            response = requests.get(ct_url, headers=headers, timeout=15)
            if response.status_code == 200:
                ct_data = response.json()

                analysis = {
                    "total_certificates": len(ct_data),
                    "issuers": [],
                    "subdomains": [],
                    "date_range": {"earliest": None, "latest": None},
                    "certificate_types": {},
                }

                for cert in ct_data[:50]:  # Analyze first 50 certificates
                    # Extract issuer information
                    issuer = cert.get("issuer_name", "Unknown")
                    if issuer not in analysis["issuers"]:
                        analysis["issuers"].append(issuer)

                    # Extract subdomains
                    name_value = cert.get("name_value", "")
                    if name_value:
                        domains = name_value.split("\n")
                        for domain in domains:
                            domain = domain.strip()
                            if domain.endswith(f".{target}"):
                                analysis["subdomains"].append(domain)

                # Remove duplicates
                analysis["subdomains"] = list(set(analysis["subdomains"]))

                log_success(
                    f"✅ Certificate transparency: {len(analysis['subdomains'])} subdomains"
                )
                return analysis

            return {}

        except Exception as e:
            log_warning(f"⚠️ Certificate transparency analysis failed: {str(e)}")
            return {}

    def _generate_osint_summary(
        self, comprehensive_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate comprehensive OSINT summary"""
        summary = {
            "total_emails": 0,
            "total_subdomains": 0,
            "social_media_presence": 0,
            "information_exposure": "Low",
            "privacy_score": 85,  # Default good privacy score
            "recommendations": [],
        }

        try:
            # Count emails
            if comprehensive_results.get("email_harvest", {}).get("emails"):
                summary["total_emails"] = len(
                    comprehensive_results["email_harvest"]["emails"]
                )

            # Count subdomains from all sources
            subdomain_count = 0
            if comprehensive_results.get("search_recon", {}).get("subdomains"):
                subdomain_count += len(
                    comprehensive_results["search_recon"]["subdomains"]
                )
            if (
                comprehensive_results.get("whois_analysis", {})
                .get("historical_data", {})
                .get("certificates", {})
                .get("subdomains")
            ):
                subdomain_count += len(
                    comprehensive_results["whois_analysis"]["historical_data"][
                        "certificates"
                    ]["subdomains"]
                )

            summary["total_subdomains"] = subdomain_count

            # Count social media profiles
            if comprehensive_results.get("search_recon", {}).get("social_media"):
                summary["social_media_presence"] = len(
                    comprehensive_results["search_recon"]["social_media"]
                )

            # Assess information exposure
            exposure_score = 0
            if summary["total_emails"] > 10:
                exposure_score += 30
            if summary["total_subdomains"] > 20:
                exposure_score += 25
            if summary["social_media_presence"] > 3:
                exposure_score += 20

            if exposure_score >= 50:
                summary["information_exposure"] = "High"
                summary["privacy_score"] = 30
            elif exposure_score >= 25:
                summary["information_exposure"] = "Medium"
                summary["privacy_score"] = 55
            else:
                summary["information_exposure"] = "Low"
                summary["privacy_score"] = 85

            return summary

        except Exception as e:
            log_warning(f"⚠️ Summary generation failed: {str(e)}")
            return summary

    def _generate_osint_recommendations(
        self, comprehensive_results: Dict[str, Any]
    ) -> List[str]:
        """Generate actionable OSINT recommendations"""
        recommendations = []

        try:
            summary = comprehensive_results.get("summary", {})

            # Email exposure recommendations
            if summary.get("total_emails", 0) > 5:
                recommendations.append(
                    "Consider implementing email obfuscation on public websites"
                )
                recommendations.append(
                    "Review email exposure policies and employee training"
                )

            # Subdomain exposure recommendations
            if summary.get("total_subdomains", 0) > 15:
                recommendations.append(
                    "Review subdomain management and unnecessary subdomain cleanup"
                )
                recommendations.append(
                    "Implement subdomain monitoring for unauthorized subdomains"
                )

            # Social media recommendations
            if summary.get("social_media_presence", 0) > 2:
                recommendations.append(
                    "Review social media privacy settings and information disclosure"
                )
                recommendations.append("Implement social media security policies")

            # Privacy score recommendations
            privacy_score = summary.get("privacy_score", 85)
            if privacy_score < 60:
                recommendations.append(
                    "Consider implementing information disclosure prevention measures"
                )
                recommendations.append(
                    "Review public information policy and data minimization"
                )

            # General recommendations
            recommendations.extend(
                [
                    "Regularly monitor OSINT exposure using automated tools",
                    "Implement Google Alerts for organization monitoring",
                    "Review certificate transparency logs quarterly",
                    "Establish OSINT monitoring as part of security program",
                ]
            )

            return recommendations

        except Exception as e:
            log_warning(f"⚠️ Recommendations generation failed: {str(e)}")
            return [
                "Review OSINT exposure manually",
                "Implement basic monitoring measures",
            ]

    # Utility helper methods

    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$"
        return bool(re.match(pattern, email))

    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        return bool(re.match(pattern, target))

    def _resolve_domain_to_ip(self, target: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            if self._is_ip_address(target):
                return target

            cmd = ["dig", "+short", "A", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0 and result.stdout.strip():
                ip = result.stdout.strip().split("\n")[0]
                return ip if self._is_ip_address(ip) else None

            return None

        except Exception as e:
            log_warning(f"⚠️ DNS resolution failed: {str(e)}")
            return None

    def _parse_whois_output(self, whois_text: str) -> Dict[str, Any]:
        """Parse WHOIS output into structured data"""
        parsed = {}

        try:
            # Extract key fields
            parsed["registrar"] = self._extract_whois_field(whois_text, "Registrar")
            parsed["creation_date"] = self._extract_whois_field(
                whois_text, "Creation Date"
            )
            parsed["expiration_date"] = self._extract_whois_field(
                whois_text, "Registry Expiry Date"
            )
            parsed["last_updated"] = self._extract_whois_field(
                whois_text, "Updated Date"
            )
            parsed["domain_status"] = self._extract_whois_field(
                whois_text, "Domain Status"
            )
            parsed["name_servers"] = self._extract_name_servers(whois_text)

            return parsed

        except Exception as e:
            log_warning(f"⚠️ WHOIS parsing failed: {str(e)}")
            return {}

    def _extract_whois_field(self, whois_text: str, field_name: str) -> str:
        """Extract specific field from WHOIS text"""
        try:
            pattern = rf"{field_name}:\s*(.+)"
            match = re.search(pattern, whois_text, re.IGNORECASE)
            return match.group(1).strip() if match else "Unknown"
        except:
            return "Unknown"

    def _extract_name_servers(self, whois_text: str) -> List[str]:
        """Extract name servers from WHOIS text"""
        try:
            name_servers = []
            lines = whois_text.split("\n")

            for line in lines:
                if "name server" in line.lower() or "nameserver" in line.lower():
                    # Extract server name
                    parts = line.split(":")
                    if len(parts) > 1:
                        ns = parts[1].strip()
                        if ns and ns not in name_servers:
                            name_servers.append(ns)

            return name_servers

        except Exception as e:
            log_warning(f"⚠️ Name server extraction failed: {str(e)}")
            return []

    def _get_dork_description(self, pattern: str) -> str:
        """Get description for Google dork pattern"""
        descriptions = {
            "filetype:pdf": "Search for PDF documents that may contain sensitive information",
            "filetype:doc": "Search for Word documents that may expose internal information",
            "filetype:xls": "Search for Excel spreadsheets with potential data exposure",
            '"index of"': "Search for directory listings that may expose file structure",
            '"login"': "Search for login pages that may be accessible",
            '"admin"': "Search for admin interfaces that may be exposed",
            "inurl:admin": "Search for admin URLs in the target domain",
            "inurl:login": "Search for login URLs in the target domain",
            '"sql error"': "Search for SQL error messages indicating potential vulnerabilities",
            '"warning"': "Search for warning messages that may reveal system information",
        }

        for keyword, desc in descriptions.items():
            if keyword in pattern:
                return desc

        return "Custom search pattern for information gathering"

    def _assess_dork_risk(self, pattern: str) -> str:
        """Assess risk level of Google dork"""
        high_risk_patterns = ["sql error", "warning", "admin", "login"]
        medium_risk_patterns = ["index of", "filetype"]

        pattern_lower = pattern.lower()

        for high_pattern in high_risk_patterns:
            if high_pattern in pattern_lower:
                return "High"

        for medium_pattern in medium_risk_patterns:
            if medium_pattern in pattern_lower:
                return "Medium"

        return "Low"


# CLI Integration Functions (following project CLI patterns)


def run_osint_scan(target: str, options: Dict[str, Any]) -> Dict[str, Any]:
    """
    CLI entry point for OSINT scanning

    Args:
        target: Target domain or IP
        options: Scan options including:
            - output_format: json, txt, html
            - save_raw: bool
            - include_social: bool
            - rate_limit: Custom rate limiting

    Returns:
        Scan results with mandatory reporting integration
    """
    log_info(f"🎯 OSINT Scan initiated for: {target}")

    # Initialize service
    osint_service = OSINTService()

    # Determine scan type
    scan_type = options.get("scan_type", "comprehensive")

    if scan_type == "email":
        results = osint_service.email_harvest(target, options)
    elif scan_type == "search":
        results = osint_service.search_engine_recon(target, options)
    elif scan_type == "whois":
        results = osint_service.whois_analysis(target, options)
    else:
        # Comprehensive OSINT (default)
        results = osint_service.comprehensive_osint(target, options)

    # Handle reporting using project pattern
    if options.get("generate_report", True) and results.get("status") != "error":
        try:
            from ..services.report_service import ReportService
            from ..core.scanner_base import ScanResult, ScanStatus
            from ..orchestrator.workflow import (
                WorkflowResult,
                WorkflowStatus,
                ScanTask,
                ScanPhase,
            )

            report_service = ReportService()

            # Convert OSINT results to findings format
            findings = []

            # Process different result types
            if scan_type == "search" and "google_dorks" in results:
                for dork in results["google_dorks"]:
                    findings.append(
                        {
                            "title": f"Google Dork Pattern",
                            "description": dork.get("description", ""),
                            "pattern": dork.get("pattern", ""),
                            "risk_level": dork.get("risk_level", "Medium"),
                            "severity": dork.get("risk_level", "medium").lower(),
                            "type": "google_dork",
                        }
                    )

                for result in results.get("bing_results", []):
                    findings.append(
                        {
                            "title": "Bing Search Pattern",
                            "description": result.get("description", ""),
                            "pattern": result.get("search_pattern", ""),
                            "severity": "info",
                            "type": "bing_search",
                        }
                    )

                for profile in results.get("social_media", []):
                    findings.append(
                        {
                            "title": f"Social Media Profile Found",
                            "description": f"{profile.get('platform', '').title()} profile discovered",
                            "url": profile.get("url", ""),
                            "platform": profile.get("platform", ""),
                            "severity": "info",
                            "type": "social_media",
                        }
                    )

            elif scan_type == "email" and "emails" in results:
                for email in results["emails"]:
                    findings.append(
                        {
                            "title": "Email Address Discovered",
                            "description": f"Email found via OSINT",
                            "email": email,
                            "severity": "info",
                            "type": "email",
                        }
                    )

            elif scan_type == "whois":
                whois_data = results.get("whois_data", {})
                if whois_data:
                    findings.append(
                        {
                            "title": "WHOIS Information",
                            "description": "Domain registration details",
                            "registrar": whois_data.get("registrar", "Unknown"),
                            "creation_date": whois_data.get("creation_date", "Unknown"),
                            "severity": "info",
                            "type": "whois",
                        }
                    )

                geo_data = results.get("ip_geolocation", {})
                if geo_data:
                    findings.append(
                        {
                            "title": "IP Geolocation",
                            "description": "Geographic location of target IP",
                            "country": geo_data.get("country", "Unknown"),
                            "isp": geo_data.get("isp", "Unknown"),
                            "severity": "info",
                            "type": "geolocation",
                        }
                    )

            elif scan_type == "comprehensive":
                # Process all comprehensive results
                email_results = results.get("email_harvest", {})
                for email in email_results.get("emails", []):
                    findings.append(
                        {
                            "title": "Email Address",
                            "description": "Email found via comprehensive OSINT",
                            "email": email,
                            "severity": "info",
                            "type": "email",
                        }
                    )

                search_results = results.get("search_recon", {})
                for profile in search_results.get("social_media", []):
                    findings.append(
                        {
                            "title": "Social Media Profile",
                            "description": f"{profile.get('platform', '').title()} profile",
                            "url": profile.get("url", ""),
                            "platform": profile.get("platform", ""),
                            "severity": "info",
                            "type": "social_media",
                        }
                    )

                for subdomain in search_results.get("subdomains", []):
                    findings.append(
                        {
                            "title": "Subdomain Discovered",
                            "description": "Subdomain found via search engines",
                            "subdomain": subdomain,
                            "severity": "info",
                            "type": "subdomain",
                        }
                    )

            # Create proper scan result with findings
            osint_scan_result = ScanResult(
                scanner_name=f"OSINT_{scan_type}",
                target=target,
                status=ScanStatus.COMPLETED,
                start_time=datetime.now(),
                end_time=datetime.now(),
                findings=findings,  # ✅ Real findings here
                metadata={
                    "osint_type": scan_type,
                    "total_findings": len(findings),
                    "scan_statistics": results.get("statistics", {}),
                    "recommendations": results.get("recommendations", []),
                },
            )

            # Create scan task (this is what appears in tasks)
            scan_task = ScanTask(
                scanner_name=f"OSINT_{scan_type}",
                scanner_class=type,  # Placeholder
                target=target,
                options=options,
                dependencies=[],
                phase=ScanPhase.RECONNAISSANCE,  # ✅ Proper phase
                priority=1,
                timeout=300,
                required=True,
            )
            scan_task.result = osint_scan_result
            scan_task.status = ScanStatus.COMPLETED
            scan_task.start_time = datetime.now()
            scan_task.end_time = datetime.now()

            # Create workflow result with proper task
            workflow_result = WorkflowResult(
                workflow_id=f"osint_{int(datetime.now().timestamp())}",
                target=target,
                status=WorkflowStatus.COMPLETED,
                start_time=datetime.now(),
                end_time=datetime.now(),
                tasks=[scan_task],  # ✅ Contains actual scan task
                aggregated_result=osint_scan_result,
            )

            # Generate reports using project pattern
            report_service.generate_reports(workflow_result, options)
            log_success("✅ OSINT reports generated successfully")

        except Exception as e:
            log_error(f"❌ Report generation failed: {e}")
            log_warning("⚠️ Continuing without reports...")

    return results


def get_osint_service_info() -> Dict[str, Any]:
    """Get OSINT service information for CLI help"""
    service = OSINTService()
    return service.get_service_info()


# For testing and development
if __name__ == "__main__":
    # Development testing
    osint_service = OSINTService()

    # Test service info
    info = osint_service.get_service_info()
    print(f"Service: {info['name']} v{info['version']}")
    print(f"Capabilities: {', '.join(info['capabilities'])}")
    print(f"Free APIs: {', '.join(info['free_apis_used'])}")

    # Test basic functionality
    test_target = "example.com"
    print(f"\nTesting OSINT service with target: {test_target}")

    # Test email harvesting
    email_results = osint_service.email_harvest(test_target)
    print(f"Email harvest test: {email_results.get('statistics', {})}")
