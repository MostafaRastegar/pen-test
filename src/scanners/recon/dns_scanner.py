"""
DNS Scanner Module - DNS Enumeration and Analysis
"""

import socket
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

from src.core import ScannerBase, ScanResult, ScanStatus, ScanSeverity
from src.core import CommandExecutor, validate_domain, validate_ip
from src.utils.logger import log_info, log_error, log_warning


class DNSScanner(ScannerBase):
    """
    DNS scanner for domain enumeration and analysis
    """

    def __init__(self, timeout: int = 180):
        """
        Initialize DNS scanner

        Args:
            timeout: Scan timeout in seconds
        """
        super().__init__("dns_scanner", timeout=timeout)
        self.executor = CommandExecutor(timeout=self.timeout)

        # DNS record types to enumerate
        self.record_types = [
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "NS",
            "TXT",
            "SOA",
            "PTR",
            "SRV",
            "CAA",
            "DNSKEY",
            "DS",
        ]

        # Common subdomains for brute force
        self.common_subdomains = [
            "www",
            "mail",
            "ftp",
            "admin",
            "test",
            "dev",
            "staging",
            "api",
            "app",
            "blog",
            "shop",
            "cdn",
            "static",
            "media",
            "support",
            "help",
            "docs",
            "portal",
            "secure",
            "vpn",
            "remote",
            "server",
            "host",
            "gateway",
            "proxy",
            "backup",
        ]

        # DNS servers to test
        self.dns_servers = [
            "8.8.8.8",  # Google
            "8.8.4.4",  # Google
            "1.1.1.1",  # Cloudflare
            "1.0.0.1",  # Cloudflare
            "208.67.222.222",  # OpenDNS
            "208.67.220.220",  # OpenDNS
        ]

    def validate_target(self, target: str) -> bool:
        """
        Validate if target is appropriate for DNS scanning

        Args:
            target: Target domain or IP

        Returns:
            bool: True if valid target, False otherwise
        """
        return validate_domain(target) or validate_ip(target)

    def _execute_scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """
        Execute DNS scan and analysis

        Args:
            target: Target domain or IP to scan
            options: Scan options

        Returns:
            ScanResult: Parsed scan results
        """
        result = ScanResult(
            scanner_name=self.name,
            target=target,
            status=ScanStatus.RUNNING,
            start_time=datetime.now(),
        )

        try:
            # Determine if target is IP or domain
            if validate_ip(target):
                self._scan_ip(target, options, result)
            else:
                self._scan_domain(target, options, result)

            result.status = ScanStatus.COMPLETED
            self.logger.info(
                f"DNS scan completed. Found {len(result.findings)} findings"
            )

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(f"DNS scan failed: {str(e)}")
            self.logger.error(f"DNS scan error: {e}")

        return result

    def _scan_domain(
        self, domain: str, options: Dict[str, Any], result: ScanResult
    ) -> None:
        """
        Scan domain for DNS information

        Args:
            domain: Domain to scan
            options: Scan options
            result: ScanResult to populate
        """
        # Basic DNS record enumeration
        self._enumerate_dns_records(domain, result)

        # DNS server analysis
        self._analyze_dns_servers(domain, result)

        # Zone transfer attempt
        if options.get("zone_transfer", True):
            self._attempt_zone_transfer(domain, result)

        # Subdomain enumeration
        if options.get("subdomain_enum", True):
            method = options.get("subdomain_method", "wordlist")
            self._enumerate_subdomains(domain, method, result)

        # DNS security checks
        self._check_dns_security(domain, result)

    def _scan_ip(self, ip: str, options: Dict[str, Any], result: ScanResult) -> None:
        """
        Scan IP for reverse DNS information

        Args:
            ip: IP address to scan
            options: Scan options
            result: ScanResult to populate
        """
        # Reverse DNS lookup
        self._reverse_dns_lookup(ip, result)

        # PTR record analysis
        self._analyze_ptr_records(ip, result)

    def _enumerate_dns_records(self, domain: str, result: ScanResult) -> None:
        """
        Enumerate standard DNS records for domain

        Args:
            domain: Domain to enumerate
            result: ScanResult to populate
        """
        for record_type in self.record_types:
            try:
                records = self._query_dns_record(domain, record_type)
                if records:
                    self._process_dns_records(domain, record_type, records, result)

            except Exception as e:
                self.logger.debug(f"Failed to query {record_type} for {domain}: {e}")

    def _query_dns_record(
        self, domain: str, record_type: str, dns_server: Optional[str] = None
    ) -> List[str]:
        """
        Query specific DNS record type

        Args:
            domain: Domain to query
            record_type: DNS record type
            dns_server: Optional DNS server to use

        Returns:
            List[str]: DNS records found
        """
        try:
            resolver = dns.resolver.Resolver()
            if dns_server:
                resolver.nameservers = [dns_server]

            answers = resolver.resolve(domain, record_type)
            return [str(answer) for answer in answers]

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.Timeout,
            Exception,
        ):
            return []

    def _process_dns_records(
        self, domain: str, record_type: str, records: List[str], result: ScanResult
    ) -> None:
        """
        Process and categorize DNS records

        Args:
            domain: Source domain
            record_type: Type of DNS record
            records: List of record values
            result: ScanResult to populate
        """
        for record in records:
            severity = self._determine_record_severity(record_type, record)

            # Create finding
            result.add_finding(
                title=f"DNS Record: {record_type}",
                description=f"{domain} has {record_type} record: {record}",
                severity=severity,
                category="dns_record",
                record_type=record_type,
                domain=domain,
                value=record,
                details={
                    "domain": domain,
                    "record_type": record_type,
                    "value": record,
                    "timestamp": datetime.now().isoformat(),
                },
            )

            # Additional analysis for specific record types
            if record_type == "MX":
                self._analyze_mx_record(domain, record, result)
            elif record_type == "NS":
                self._analyze_ns_record(domain, record, result)
            elif record_type == "TXT":
                self._analyze_txt_record(domain, record, result)
            elif record_type == "A" or record_type == "AAAA":
                self._analyze_ip_record(domain, record, result)

    def _analyze_dns_servers(self, domain: str, result: ScanResult) -> None:
        """
        Analyze DNS servers for the domain

        Args:
            domain: Domain to analyze
            result: ScanResult to populate
        """
        try:
            ns_records = self._query_dns_record(domain, "NS")

            for ns in ns_records:
                # Test each name server
                self._test_nameserver(ns.rstrip("."), domain, result)

        except Exception as e:
            self.logger.error(f"DNS server analysis failed: {e}")

    def _test_nameserver(
        self, nameserver: str, domain: str, result: ScanResult
    ) -> None:
        """
        Test individual nameserver

        Args:
            nameserver: Nameserver to test
            domain: Domain being tested
            result: ScanResult to populate
        """
        try:
            # Get IP of nameserver
            ns_ips = self._query_dns_record(nameserver, "A")

            for ns_ip in ns_ips:
                # Test response time
                start_time = datetime.now()
                test_records = self._query_dns_record(domain, "A", ns_ip)
                response_time = (datetime.now() - start_time).total_seconds()

                # Analyze nameserver
                result.add_finding(
                    title=f"Nameserver Analysis: {nameserver}",
                    description=f"Nameserver {nameserver} ({ns_ip}) response time: {response_time:.3f}s",
                    severity=ScanSeverity.INFO,
                    category="nameserver_analysis",
                    nameserver=nameserver,
                    ip=ns_ip,
                    response_time=response_time,
                    details={
                        "nameserver": nameserver,
                        "ip": ns_ip,
                        "response_time": response_time,
                        "responsive": len(test_records) > 0,
                    },
                )

        except Exception as e:
            self.logger.debug(f"Nameserver test failed for {nameserver}: {e}")

    def _attempt_zone_transfer(self, domain: str, result: ScanResult) -> None:
        """
        Attempt DNS zone transfer

        Args:
            domain: Domain to attempt zone transfer
            result: ScanResult to populate
        """
        try:
            ns_records = self._query_dns_record(domain, "NS")

            for ns in ns_records:
                ns_clean = ns.rstrip(".")
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_clean, domain))

                    # Zone transfer successful - this is a security issue
                    zone_records = []
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                zone_records.append(
                                    f"{name}.{domain} {rdataset.rdtype.name} {rdata}"
                                )

                    result.add_finding(
                        title="DNS Zone Transfer Vulnerability",
                        description=f"Zone transfer successful from {ns_clean}. Retrieved {len(zone_records)} records.",
                        severity=ScanSeverity.HIGH,
                        category="zone_transfer",
                        nameserver=ns_clean,
                        records_count=len(zone_records),
                        details={
                            "nameserver": ns_clean,
                            "domain": domain,
                            "records_retrieved": len(zone_records),
                            "sample_records": zone_records[:10],  # First 10 records
                        },
                    )

                except Exception as e:
                    # Zone transfer failed (expected)
                    self.logger.debug(f"Zone transfer failed for {ns_clean}: {e}")

        except Exception as e:
            self.logger.error(f"Zone transfer attempt failed: {e}")

    def _enumerate_subdomains(
        self, domain: str, method: str, result: ScanResult
    ) -> None:
        """
        Enumerate subdomains using various methods

        Args:
            domain: Parent domain
            method: Enumeration method (wordlist, bruteforce)
            result: ScanResult to populate
        """
        if method == "wordlist":
            self._wordlist_subdomain_enum(domain, result)
        elif method == "bruteforce":
            self._bruteforce_subdomain_enum(domain, result)

    def _wordlist_subdomain_enum(self, domain: str, result: ScanResult) -> None:
        """
        Enumerate subdomains using wordlist

        Args:
            domain: Parent domain
            result: ScanResult to populate
        """
        found_subdomains = []

        for subdomain in self.common_subdomains:
            full_domain = f"{subdomain}.{domain}"

            try:
                # Try to resolve subdomain
                records = self._query_dns_record(full_domain, "A")
                if records:
                    found_subdomains.append((full_domain, records))

                    result.add_finding(
                        title=f"Subdomain Found: {full_domain}",
                        description=f"Subdomain {full_domain} resolves to: {', '.join(records)}",
                        severity=ScanSeverity.INFO,
                        category="subdomain",
                        subdomain=full_domain,
                        parent_domain=domain,
                        ip_addresses=records,
                        details={
                            "subdomain": full_domain,
                            "parent_domain": domain,
                            "ip_addresses": records,
                            "method": "wordlist",
                        },
                    )

            except Exception as e:
                self.logger.debug(f"Subdomain lookup failed for {full_domain}: {e}")

        if found_subdomains:
            result.metadata["subdomains_found"] = len(found_subdomains)

    def _bruteforce_subdomain_enum(self, domain: str, result: ScanResult) -> None:
        """
        Bruteforce subdomain enumeration (basic implementation)

        Args:
            domain: Parent domain
            result: ScanResult to populate
        """
        # Extended wordlist for brute force
        extended_subdomains = self.common_subdomains + [
            "db",
            "database",
            "sql",
            "mysql",
            "postgres",
            "redis",
            "cache",
            "cdn",
            "assets",
            "img",
            "images",
            "video",
            "download",
            "upload",
            "files",
            "docs",
            "documentation",
            "api1",
            "api2",
            "v1",
            "v2",
            "beta",
            "alpha",
            "demo",
        ]

        found_count = 0
        for subdomain in extended_subdomains:
            full_domain = f"{subdomain}.{domain}"

            try:
                records = self._query_dns_record(full_domain, "A")
                if records:
                    found_count += 1
                    result.add_finding(
                        title=f"Subdomain Found: {full_domain}",
                        description=f"Subdomain {full_domain} resolves to: {', '.join(records)}",
                        severity=ScanSeverity.INFO,
                        category="subdomain",
                        subdomain=full_domain,
                        parent_domain=domain,
                        ip_addresses=records,
                        details={
                            "subdomain": full_domain,
                            "parent_domain": domain,
                            "ip_addresses": records,
                            "method": "bruteforce",
                        },
                    )

            except Exception:
                pass  # Expected for non-existent subdomains

        result.metadata["bruteforce_subdomains_found"] = found_count

    def _check_dns_security(self, domain: str, result: ScanResult) -> None:
        """
        Check DNS security configurations

        Args:
            domain: Domain to check
            result: ScanResult to populate
        """
        # Check for DNSSEC
        self._check_dnssec(domain, result)

        # Check for CAA records
        self._check_caa_records(domain, result)

        # Check for SPF/DMARC
        self._check_email_security(domain, result)

    def _check_dnssec(self, domain: str, result: ScanResult) -> None:
        """
        Check DNSSEC configuration

        Args:
            domain: Domain to check
            result: ScanResult to populate
        """
        try:
            # Check for DNSKEY records
            dnskey_records = self._query_dns_record(domain, "DNSKEY")
            ds_records = self._query_dns_record(domain, "DS")

            if dnskey_records or ds_records:
                result.add_finding(
                    title="DNSSEC Enabled",
                    description=f"Domain {domain} has DNSSEC configured",
                    severity=ScanSeverity.INFO,
                    category="dns_security",
                    security_feature="DNSSEC",
                    status="enabled",
                    details={
                        "domain": domain,
                        "dnskey_records": len(dnskey_records),
                        "ds_records": len(ds_records),
                    },
                )
            else:
                result.add_finding(
                    title="DNSSEC Not Configured",
                    description=f"Domain {domain} does not have DNSSEC configured",
                    severity=ScanSeverity.LOW,
                    category="dns_security",
                    security_feature="DNSSEC",
                    status="disabled",
                    details={
                        "domain": domain,
                        "recommendation": "Consider enabling DNSSEC",
                    },
                )

        except Exception as e:
            self.logger.debug(f"DNSSEC check failed: {e}")

    def _check_caa_records(self, domain: str, result: ScanResult) -> None:
        """
        Check CAA (Certificate Authority Authorization) records

        Args:
            domain: Domain to check
            result: ScanResult to populate
        """
        try:
            caa_records = self._query_dns_record(domain, "CAA")

            if caa_records:
                result.add_finding(
                    title="CAA Records Found",
                    description=f"Domain {domain} has CAA records configured",
                    severity=ScanSeverity.INFO,
                    category="dns_security",
                    security_feature="CAA",
                    records=caa_records,
                    details={
                        "domain": domain,
                        "caa_records": caa_records,
                        "purpose": "Certificate authority authorization",
                    },
                )
            else:
                result.add_finding(
                    title="No CAA Records",
                    description=f"Domain {domain} has no CAA records",
                    severity=ScanSeverity.LOW,
                    category="dns_security",
                    security_feature="CAA",
                    status="not_configured",
                    details={
                        "domain": domain,
                        "recommendation": "Consider adding CAA records to restrict certificate issuance",
                    },
                )

        except Exception as e:
            self.logger.debug(f"CAA check failed: {e}")

    def _check_email_security(self, domain: str, result: ScanResult) -> None:
        """
        Check email security records (SPF, DMARC, DKIM)

        Args:
            domain: Domain to check
            result: ScanResult to populate
        """
        # Check SPF
        txt_records = self._query_dns_record(domain, "TXT")
        spf_found = False
        dmarc_found = False

        for record in txt_records:
            if record.startswith('"v=spf1') or record.startswith("v=spf1"):
                spf_found = True
                result.add_finding(
                    title="SPF Record Found",
                    description=f"Domain {domain} has SPF record configured",
                    severity=ScanSeverity.INFO,
                    category="email_security",
                    security_feature="SPF",
                    record=record,
                    details={"domain": domain, "spf_record": record},
                )

        # Check DMARC
        dmarc_records = self._query_dns_record(f"_dmarc.{domain}", "TXT")
        for record in dmarc_records:
            if "v=DMARC1" in record:
                dmarc_found = True
                result.add_finding(
                    title="DMARC Record Found",
                    description=f"Domain {domain} has DMARC record configured",
                    severity=ScanSeverity.INFO,
                    category="email_security",
                    security_feature="DMARC",
                    record=record,
                    details={"domain": domain, "dmarc_record": record},
                )

        # Report missing email security
        if not spf_found:
            result.add_finding(
                title="Missing SPF Record",
                description=f"Domain {domain} does not have SPF record",
                severity=ScanSeverity.MEDIUM,
                category="email_security",
                security_feature="SPF",
                status="missing",
                details={
                    "domain": domain,
                    "risk": "Email spoofing vulnerability",
                    "recommendation": "Add SPF record to prevent email spoofing",
                },
            )

        if not dmarc_found:
            result.add_finding(
                title="Missing DMARC Record",
                description=f"Domain {domain} does not have DMARC record",
                severity=ScanSeverity.MEDIUM,
                category="email_security",
                security_feature="DMARC",
                status="missing",
                details={
                    "domain": domain,
                    "risk": "Email authentication weakness",
                    "recommendation": "Add DMARC record for email authentication",
                },
            )

    def _reverse_dns_lookup(self, ip: str, result: ScanResult) -> None:
        """
        Perform reverse DNS lookup

        Args:
            ip: IP address to lookup
            result: ScanResult to populate
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]

            result.add_finding(
                title=f"Reverse DNS: {hostname}",
                description=f"IP {ip} has reverse DNS record: {hostname}",
                severity=ScanSeverity.INFO,
                category="reverse_dns",
                ip=ip,
                hostname=hostname,
                details={
                    "ip": ip,
                    "hostname": hostname,
                    "lookup_method": "reverse_dns",
                },
            )

        except socket.herror:
            result.add_finding(
                title="No Reverse DNS",
                description=f"IP {ip} has no reverse DNS record",
                severity=ScanSeverity.LOW,
                category="reverse_dns",
                ip=ip,
                details={"ip": ip, "status": "no_reverse_dns"},
            )
        except Exception as e:
            self.logger.debug(f"Reverse DNS lookup failed for {ip}: {e}")

    def _analyze_ptr_records(self, ip: str, result: ScanResult) -> None:
        """
        Analyze PTR records for IP

        Args:
            ip: IP address to analyze
            result: ScanResult to populate
        """
        try:
            ptr_query = dns.reversename.from_address(ip)
            ptr_records = self._query_dns_record(str(ptr_query), "PTR")

            for ptr in ptr_records:
                result.add_finding(
                    title=f"PTR Record: {ptr}",
                    description=f"IP {ip} has PTR record: {ptr}",
                    severity=ScanSeverity.INFO,
                    category="ptr_record",
                    ip=ip,
                    ptr_record=ptr,
                    details={
                        "ip": ip,
                        "ptr_record": ptr.rstrip("."),
                        "record_type": "PTR",
                    },
                )

        except Exception as e:
            self.logger.debug(f"PTR record analysis failed for {ip}: {e}")

    def _analyze_mx_record(
        self, domain: str, mx_record: str, result: ScanResult
    ) -> None:
        """
        Analyze MX record for additional information

        Args:
            domain: Source domain
            mx_record: MX record value
            result: ScanResult to populate
        """
        try:
            # Extract mail server from MX record
            parts = mx_record.split()
            if len(parts) >= 2:
                priority = parts[0]
                mail_server = parts[1].rstrip(".")

                # Get IP of mail server
                mail_ips = self._query_dns_record(mail_server, "A")

                result.metadata.setdefault("mail_servers", []).append(
                    {
                        "domain": domain,
                        "priority": priority,
                        "server": mail_server,
                        "ips": mail_ips,
                    }
                )

        except Exception as e:
            self.logger.debug(f"MX record analysis failed: {e}")

    def _analyze_ns_record(
        self, domain: str, ns_record: str, result: ScanResult
    ) -> None:
        """
        Analyze NS record for additional information

        Args:
            domain: Source domain
            ns_record: NS record value
            result: ScanResult to populate
        """
        try:
            ns_server = ns_record.rstrip(".")
            ns_ips = self._query_dns_record(ns_server, "A")

            result.metadata.setdefault("name_servers", []).append(
                {"domain": domain, "server": ns_server, "ips": ns_ips}
            )

        except Exception as e:
            self.logger.debug(f"NS record analysis failed: {e}")

    def _analyze_txt_record(
        self, domain: str, txt_record: str, result: ScanResult
    ) -> None:
        """
        Analyze TXT record for interesting information

        Args:
            domain: Source domain
            txt_record: TXT record value
            result: ScanResult to populate
        """
        # Check for interesting TXT record patterns
        interesting_patterns = [
            (r"v=spf1", "SPF Record"),
            (r"v=DMARC1", "DMARC Record"),
            (r"google-site-verification", "Google Site Verification"),
            (r"facebook-domain-verification", "Facebook Domain Verification"),
            (r"MS=", "Microsoft Domain Verification"),
            (r"_globalsign-domain-verification", "GlobalSign Verification"),
        ]

        for pattern, description in interesting_patterns:
            if re.search(pattern, txt_record, re.IGNORECASE):
                result.add_finding(
                    title=f"Interesting TXT Record: {description}",
                    description=f"Found {description} in TXT record",
                    severity=ScanSeverity.INFO,
                    category="txt_analysis",
                    txt_type=description,
                    record=txt_record,
                    details={
                        "domain": domain,
                        "type": description,
                        "record": txt_record,
                    },
                )

    def _analyze_ip_record(self, domain: str, ip: str, result: ScanResult) -> None:
        """
        Analyze A/AAAA record for additional information

        Args:
            domain: Source domain
            ip: IP address from record
            result: ScanResult to populate
        """
        try:
            # Check if IP is in private range
            import ipaddress

            ip_obj = ipaddress.ip_address(ip)

            if ip_obj.is_private:
                result.add_finding(
                    title="Private IP Address",
                    description=f"Domain {domain} resolves to private IP: {ip}",
                    severity=ScanSeverity.MEDIUM,
                    category="ip_analysis",
                    domain=domain,
                    ip=ip,
                    ip_type="private",
                    details={
                        "domain": domain,
                        "ip": ip,
                        "type": "private",
                        "concern": "Domain resolving to private IP may indicate misconfiguration",
                    },
                )

        except Exception as e:
            self.logger.debug(f"IP analysis failed for {ip}: {e}")

    def _determine_record_severity(
        self, record_type: str, record_value: str
    ) -> ScanSeverity:
        """
        Determine severity level for DNS record

        Args:
            record_type: Type of DNS record
            record_value: Value of the record

        Returns:
            ScanSeverity: Severity level
        """
        # Most DNS records are informational
        if record_type in ["A", "AAAA", "CNAME", "NS", "SOA"]:
            return ScanSeverity.INFO

        # MX records can be useful for attackers
        if record_type == "MX":
            return ScanSeverity.LOW

        # TXT records might contain sensitive info
        if record_type == "TXT":
            sensitive_patterns = ["password", "secret", "key", "token", "api"]
            if any(pattern in record_value.lower() for pattern in sensitive_patterns):
                return ScanSeverity.MEDIUM
            return ScanSeverity.INFO

        return ScanSeverity.INFO

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get scanner capabilities

        Returns:
            Dict: Scanner capabilities and information
        """
        # Check for required tools
        tools_available = {
            "dig": self.executor.check_tool_exists("dig"),
            "nslookup": self.executor.check_tool_exists("nslookup"),
            "host": self.executor.check_tool_exists("host"),
        }

        return {
            "name": self.name,
            "description": "DNS enumeration and security analysis",
            "version": "1.0.0",
            "supported_targets": ["domain", "ip"],
            "scan_types": [
                "dns_records",
                "zone_transfer",
                "subdomain_enum",
                "security_check",
            ],
            "record_types": self.record_types,
            "subdomain_methods": ["wordlist", "bruteforce"],
            "timeout": self.timeout,
            "dependencies": {
                "python_dns": "dnspython library",
                "socket": "Python socket library",
                "tools": tools_available,
            },
            "options": {
                "zone_transfer": "Attempt DNS zone transfer",
                "subdomain_enum": "Enable subdomain enumeration",
                "subdomain_method": "Subdomain enumeration method (wordlist/bruteforce)",
                "dns_servers": "Custom DNS servers to use",
            },
            "features": [
                "DNS record enumeration",
                "Reverse DNS lookup",
                "Zone transfer testing",
                "Subdomain discovery",
                "DNSSEC checking",
                "Email security analysis (SPF/DMARC)",
                "CAA record analysis",
                "DNS server testing",
            ],
        }

    def quick_dns_scan(self, target: str) -> ScanResult:
        """
        Perform a quick DNS scan (basic records only)

        Args:
            target: Target domain or IP

        Returns:
            ScanResult: Scan results
        """
        options = {"zone_transfer": False, "subdomain_enum": False}
        return self.scan(target, options)

    def full_dns_scan(self, target: str) -> ScanResult:
        """
        Perform a comprehensive DNS scan

        Args:
            target: Target domain or IP

        Returns:
            ScanResult: Scan results
        """
        options = {
            "zone_transfer": True,
            "subdomain_enum": True,
            "subdomain_method": "bruteforce",
        }
        return self.scan(target, options)
