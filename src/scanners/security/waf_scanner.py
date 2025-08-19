"""
WAF Detection Engine - Phase 2.2 Implementation
Web Application Firewall Detection and Bypass Testing Scanner

This scanner implements comprehensive WAF detection capabilities including:
- Major WAF vendor identification (Cloudflare, AWS WAF, Akamai, F5, etc.)
- Behavioral fingerprinting and response pattern analysis
- Bypass technique testing with adaptive payload generation
- Real-time evasion technique adaptation
- WAF effectiveness assessment and reporting

File Location: src/scanners/security/waf_scanner.py
"""

import re
import time
import random
import base64
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.scanner_base import ScannerBase, ScanResult, ScanStatus, ScanSeverity
from core.validator import validate_url, validate_domain, validate_ip
from utils.logger import log_info, log_error, log_warning, log_success


class WAFScanner(ScannerBase):
    """
    Web Application Firewall Detection and Bypass Testing Scanner

    Features:
    - WAF vendor identification through behavioral analysis
    - HTTP response pattern matching and fingerprinting
    - Bypass technique testing with multiple evasion methods
    - Adaptive payload generation based on WAF responses
    - Real-time technique effectiveness tracking
    - Comprehensive WAF security assessment reporting
    """

    def __init__(self, timeout: int = 300):
        """
        Initialize WAF scanner

        Args:
            timeout: Scan timeout in seconds
        """
        super().__init__("waf_scanner", timeout=timeout)

        # Configure HTTP session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # User agents for testing
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Auto-Pentest-WAF-Scanner/1.0",
        ]

        # Initialize WAF detection signatures
        self._init_waf_signatures()

        # Initialize bypass payloads
        self._init_bypass_payloads()

        # Detection results tracking
        self.detection_results = {
            "waf_detected": False,
            "waf_vendors": [],
            "confidence_score": 0.0,
            "bypass_success": False,
            "effective_payloads": [],
            "blocked_payloads": [],
        }

    def validate_target(self, target: str) -> bool:
        """
        Validate if target is appropriate for WAF scanning

        Args:
            target: Target URL, domain, or IP

        Returns:
            bool: True if valid target, False otherwise
        """
        # Accept URLs directly
        if target.startswith(("http://", "https://")):
            return validate_url(target)

        # Accept domains and IPs (will be converted to URLs)
        return validate_domain(target) or validate_ip(target)

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get scanner capabilities and metadata

        Returns:
            Dict: Scanner capabilities information
        """
        return {
            "name": "WAF Detection Engine",
            "description": "Web Application Firewall detection and bypass testing",
            "version": "1.0.0",
            "category": "security",
            "targets": ["url", "domain", "ip"],
            "waf_vendors": list(self.waf_signatures.keys()),
            "bypass_techniques": len(self.bypass_payloads),
            "detection_methods": [
                "response_header_analysis",
                "error_message_fingerprinting",
                "behavioral_pattern_analysis",
                "timing_based_detection",
                "payload_response_analysis",
            ],
        }

    def _execute_scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """
        Execute WAF detection and bypass testing scan

        Args:
            target: Target URL to scan
            options: Scanning options and configurations

        Returns:
            ScanResult: Comprehensive WAF analysis results
        """
        log_info(f"Starting WAF detection scan for: {target}")
        start_time = datetime.now()

        # Initialize result
        result = ScanResult(
            scanner_name=self.name,
            target=target,
            status=ScanStatus.RUNNING,
            start_time=start_time,
        )

        try:
            # Normalize target URL
            target_url = self._normalize_target_url(target)

            # Check if detection-only mode is enabled
            detection_only = options.get("detection_only", False)
            if detection_only:
                log_info("Detection-only mode enabled - skipping bypass testing")

            # Phase 1: Basic WAF Detection (always run)
            log_info("Phase 1: Basic WAF detection and fingerprinting")
            basic_detection = self._perform_basic_waf_detection(target_url)

            # Phase 2: Advanced Behavioral Analysis (always run)
            log_info("Phase 2: Advanced behavioral pattern analysis")
            behavioral_analysis = self._perform_behavioral_analysis(target_url)

            # Initialize containers for optional phases
            bypass_results = {"findings": [], "summary": {}}
            effectiveness_assessment = {"findings": [], "summary": {}}

            # Phase 3: Bypass Technique Testing (skip if detection-only)
            if not detection_only:
                log_info("Phase 3: Bypass technique testing and evaluation")
                bypass_results = self._test_bypass_techniques(target_url)
            else:
                log_info("Phase 3: Skipped (detection-only mode)")

            # Phase 4: WAF Effectiveness Assessment (skip if detection-only)
            if not detection_only:
                log_info("Phase 4: WAF effectiveness and security assessment")
                effectiveness_assessment = self._assess_waf_effectiveness(target_url)
            else:
                log_info("Phase 4: Skipped (detection-only mode)")

            # Compile comprehensive findings
            findings = []
            findings.extend(basic_detection.get("findings", []))
            findings.extend(behavioral_analysis.get("findings", []))
            findings.extend(bypass_results.get("findings", []))
            findings.extend(effectiveness_assessment.get("findings", []))

            # Add findings to result
            for finding in findings:
                result.add_finding(**finding)

            # Calculate overall risk score
            risk_score = self._calculate_waf_risk_score(findings)

            # Add metadata
            result.metadata.update(
                {
                    "scan_type": "waf_detection",
                    "target_url": target_url,
                    "detection_only": detection_only,  # Add this flag to metadata
                    "waf_detected": self.detection_results["waf_detected"],
                    "detected_wafs": self.detection_results["waf_vendors"],
                    "confidence_score": self.detection_results["confidence_score"],
                    "bypass_success_rate": (
                        self._calculate_bypass_success_rate()
                        if not detection_only
                        else 0
                    ),
                    "risk_score": risk_score,
                    "scan_phases": {
                        "basic_detection": basic_detection.get("summary", {}),
                        "behavioral_analysis": behavioral_analysis.get("summary", {}),
                        "bypass_testing": (
                            bypass_results.get("summary", {})
                            if not detection_only
                            else {"skipped": True}
                        ),
                        "effectiveness_assessment": (
                            effectiveness_assessment.get("summary", {})
                            if not detection_only
                            else {"skipped": True}
                        ),
                    },
                }
            )

            result.status = ScanStatus.COMPLETED
            result.end_time = datetime.now()

            # Log completion message
            if detection_only:
                log_success(
                    f"WAF detection scan completed for {target} (detection-only mode)"
                )
            else:
                log_success(f"WAF detection scan completed for {target}")

        except Exception as e:
            log_error(f"WAF scanner error: {e}")
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))
            result.end_time = datetime.now()

        return result

    def _init_waf_signatures(self):
        """Initialize WAF detection signatures and patterns"""
        self.waf_signatures = {
            "cloudflare": {
                "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
                "error_codes": [1020, 1025, 1102],
                "error_messages": [
                    "attention required",
                    "cloudflare ray id",
                    "please enable javascript",
                    "checking your browser",
                ],
                "response_patterns": [r"cloudflare", r"cf-ray", r"__cfduid"],
            },
            "aws_waf": {
                "headers": ["x-amzn-requestid", "x-amzn-errortype"],
                "error_codes": [403, 502],
                "error_messages": ["aws", "forbidden", "request blocked"],
                "response_patterns": [r"aws", r"amazon", r"x-amzn"],
            },
            "akamai": {
                "headers": ["akamai-origin-hop", "x-akamai-edgescape"],
                "error_codes": [403, 406],
                "error_messages": ["akamai", "reference #", "access denied"],
                "response_patterns": [r"akamai", r"reference #\d+", r"edgescape"],
            },
            "f5_big_ip": {
                "headers": ["x-waf-event-info", "bigipserver"],
                "error_codes": [403, 412],
                "error_messages": ["f5", "big-ip", "the request is blocked"],
                "response_patterns": [r"f5", r"big-?ip", r"asm_mode"],
            },
            "imperva": {
                "headers": ["x-iinfo"],
                "error_codes": [403, 406],
                "error_messages": [
                    "imperva",
                    "incapsula",
                    "blocked by website protection",
                ],
                "response_patterns": [r"imperva", r"incapsula", r"visid_incap"],
            },
            "fortinet": {
                "headers": ["fortigate"],
                "error_codes": [403, 405],
                "error_messages": ["fortigate", "fortiweb", "blocked by fortinet"],
                "response_patterns": [r"fortinet", r"fortigate", r"fortiweb"],
            },
            "sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache"],
                "error_codes": [403, 406],
                "error_messages": ["sucuri", "website firewall", "access denied"],
                "response_patterns": [r"sucuri", r"website firewall", r"sucuri\.net"],
            },
            "mod_security": {
                "headers": ["mod_security"],
                "error_codes": [403, 406, 501],
                "error_messages": ["mod_security", "modsecurity", "not acceptable"],
                "response_patterns": [
                    r"mod_security",
                    r"modsecurity",
                    r"apache.*mod_security",
                ],
            },
        }

    def _init_bypass_payloads(self):
        """Initialize bypass testing payloads"""
        self.bypass_payloads = {
            "sql_injection": [
                # Basic SQL injection
                "' OR '1'='1",
                "1' OR '1'='1'--",
                "admin'--",
                # Encoded payloads
                "%27%20OR%20%271%27%3D%271",
                "&#x27;&#x20;OR&#x20;&#x27;1&#x27;&#x3D;&#x27;1",
                # Case variation
                "' oR '1'='1",
                "' Or '1'='1",
                # Comment variations
                "' OR '1'='1'/*",
                "' OR '1'='1'#",
                # Unicode bypass
                "' OR '1'='1'%00",
                "' \xa0OR\xa0'1'='1",
                # Double encoding
                "%2527%2520OR%2520%25271%2527%253D%25271",
            ],
            "xss": [
                # Basic XSS
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                # Encoded XSS
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "&#60;script&#62;alert(1)&#60;/script&#62;",
                # Case variation
                "<ScRiPt>alert(1)</ScRiPt>",
                "<SCRIPT>alert(1)</SCRIPT>",
                # Event handlers
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                # Unicode bypass
                "<script>alert\u0028 1\u0029</script>",
                "<script>alert\x28 1\x29</script>",
                # Filter bypass
                "<script>alert`1`</script>",
                "<script>alert(String.fromCharCode(49))</script>",
            ],
            "lfi": [
                # Basic LFI
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                # Encoded LFI
                "%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",
                "..%252f..%252f..%252fetc%252fpasswd",
                # Double encoding
                "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                # Null byte
                "../../../etc/passwd%00",
                "../../../etc/passwd%00.jpg",
                # UTF-8 bypass
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
            ],
            "command_injection": [
                # Basic command injection
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                # Encoded
                "%3B%20ls%20-la",
                "%7C%20whoami",
                # Backticks
                "`ls -la`",
                "$(whoami)",
                # Alternative separators
                "\n ls -la",
                "\r\n whoami",
                # Unicode
                "\u003b ls -la",
                "\u007c whoami",
            ],
        }

    def _normalize_target_url(self, target: str) -> str:
        """Normalize target to full URL format"""
        if not target.startswith(("http://", "https://")):
            # Try HTTPS first, fallback to HTTP
            target = f"https://{target}"
        return target

    def _perform_basic_waf_detection(self, target_url: str) -> Dict[str, Any]:
        """Perform basic WAF detection through headers and responses"""
        findings = []
        detected_wafs = []
        confidence_scores = {}

        try:
            # Send basic request
            response = self.session.get(
                target_url,
                headers={"User-Agent": random.choice(self.user_agents)},
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )

            # Analyze response headers
            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
            response_text = response.text.lower()

            for waf_name, signatures in self.waf_signatures.items():
                confidence = 0
                detection_evidence = []

                # Check headers
                for header_sig in signatures.get("headers", []):
                    if header_sig.lower() in str(headers_lower):
                        confidence += 30
                        detection_evidence.append(f"Header: {header_sig}")

                # Check error messages in response
                for error_msg in signatures.get("error_messages", []):
                    if error_msg.lower() in response_text:
                        confidence += 25
                        detection_evidence.append(f"Error message: {error_msg}")

                # Check response patterns
                for pattern in signatures.get("response_patterns", []):
                    if re.search(pattern, response_text, re.IGNORECASE):
                        confidence += 20
                        detection_evidence.append(f"Pattern: {pattern}")

                # Check status codes (less reliable, lower weight)
                if response.status_code in signatures.get("error_codes", []):
                    confidence += 10
                    detection_evidence.append(f"Status code: {response.status_code}")

                if confidence >= 30:  # Minimum confidence threshold
                    detected_wafs.append(waf_name)
                    confidence_scores[waf_name] = confidence

                    # Create finding for detected WAF
                    findings.append(
                        {
                            "title": f"WAF Detected: {waf_name.title()}",
                            "description": f"Web Application Firewall '{waf_name}' detected with {confidence}% confidence",
                            "severity": ScanSeverity.INFO,
                            "category": "waf_detection",
                            "waf_vendor": waf_name,
                            "confidence": confidence,
                            "evidence": detection_evidence,
                            "detection_method": "basic_analysis",
                        }
                    )

            # Update detection results
            if detected_wafs:
                self.detection_results["waf_detected"] = True
                self.detection_results["waf_vendors"].extend(detected_wafs)
                self.detection_results["confidence_score"] = max(
                    confidence_scores.values()
                )

                # Create summary finding
                findings.append(
                    {
                        "title": "WAF Protection Detected",
                        "description": f"Web Application Firewall protection detected. Vendors: {', '.join(detected_wafs)}",
                        "severity": ScanSeverity.LOW,
                        "category": "waf_summary",
                        "detected_wafs": detected_wafs,
                        "max_confidence": max(confidence_scores.values()),
                    }
                )

        except requests.exceptions.RequestException as e:
            log_warning(f"Basic WAF detection request failed: {e}")
            findings.append(
                {
                    "title": "WAF Detection Request Failed",
                    "description": f"Failed to perform basic WAF detection: {e}",
                    "severity": ScanSeverity.INFO,
                    "category": "scan_error",
                }
            )

        return {
            "findings": findings,
            "detected_wafs": detected_wafs,
            "confidence_scores": confidence_scores,
            "summary": {
                "wafs_detected": len(detected_wafs),
                "max_confidence": (
                    max(confidence_scores.values()) if confidence_scores else 0
                ),
            },
        }

    def _perform_behavioral_analysis(self, target_url: str) -> Dict[str, Any]:
        """Perform advanced behavioral pattern analysis"""
        findings = []
        behavioral_indicators = {}

        try:
            # Test 1: Response time analysis with malicious payloads
            timing_analysis = self._analyze_response_timing(target_url)
            findings.extend(timing_analysis.get("findings", []))

            # Test 2: Error message fingerprinting
            error_fingerprinting = self._fingerprint_error_messages(target_url)
            findings.extend(error_fingerprinting.get("findings", []))

            # Test 3: Rate limiting detection
            rate_limiting = self._detect_rate_limiting(target_url)
            findings.extend(rate_limiting.get("findings", []))

            # Test 4: Custom header analysis
            header_analysis = self._analyze_custom_headers(target_url)
            findings.extend(header_analysis.get("findings", []))

        except Exception as e:
            log_warning(f"Behavioral analysis failed: {e}")

        return {
            "findings": findings,
            "behavioral_indicators": behavioral_indicators,
            "summary": {
                "tests_performed": 4,
                "indicators_found": len(behavioral_indicators),
            },
        }

    def _test_bypass_techniques(self, target_url: str) -> Dict[str, Any]:
        """Test various bypass techniques against detected WAF"""
        findings = []
        bypass_results = {
            "total_payloads": 0,
            "successful_bypasses": 0,
            "blocked_payloads": 0,
            "error_responses": 0,
        }

        try:
            for attack_type, payloads in self.bypass_payloads.items():
                log_info(f"Testing {attack_type} bypass techniques")

                for payload in payloads:
                    bypass_results["total_payloads"] += 1

                    # Test payload
                    test_result = self._test_single_payload(
                        target_url, payload, attack_type
                    )

                    if test_result["bypassed"]:
                        bypass_results["successful_bypasses"] += 1
                        self.detection_results["effective_payloads"].append(
                            {
                                "payload": payload,
                                "type": attack_type,
                                "response_code": test_result["status_code"],
                            }
                        )

                        findings.append(
                            {
                                "title": f"WAF Bypass Successful - {attack_type.upper()}",
                                "description": f"Payload bypassed WAF protection: {payload[:100]}...",
                                "severity": ScanSeverity.HIGH,
                                "category": "waf_bypass",
                                "attack_type": attack_type,
                                "payload": payload,
                                "response_code": test_result["status_code"],
                                "bypass_method": test_result["method"],
                            }
                        )

                    elif test_result["blocked"]:
                        bypass_results["blocked_payloads"] += 1
                        self.detection_results["blocked_payloads"].append(
                            {
                                "payload": payload,
                                "type": attack_type,
                                "response_code": test_result["status_code"],
                            }
                        )

                    else:
                        bypass_results["error_responses"] += 1

                    # Add delay to avoid rate limiting
                    time.sleep(random.uniform(0.5, 2.0))

            # Calculate bypass success rate
            if bypass_results["total_payloads"] > 0:
                success_rate = (
                    bypass_results["successful_bypasses"]
                    / bypass_results["total_payloads"]
                ) * 100
                self.detection_results["bypass_success"] = (
                    success_rate > 10
                )  # 10% threshold

                findings.append(
                    {
                        "title": "WAF Bypass Testing Summary",
                        "description": f"Bypass success rate: {success_rate:.1f}% ({bypass_results['successful_bypasses']}/{bypass_results['total_payloads']})",
                        "severity": (
                            ScanSeverity.MEDIUM
                            if success_rate > 20
                            else ScanSeverity.LOW
                        ),
                        "category": "bypass_summary",
                        "success_rate": success_rate,
                        "total_tests": bypass_results["total_payloads"],
                        "successful_bypasses": bypass_results["successful_bypasses"],
                    }
                )

        except Exception as e:
            log_error(f"Bypass testing failed: {e}")

        return {
            "findings": findings,
            "bypass_results": bypass_results,
            "summary": {
                "total_payloads_tested": bypass_results["total_payloads"],
                "successful_bypasses": bypass_results["successful_bypasses"],
                "success_rate": (
                    bypass_results["successful_bypasses"]
                    / max(bypass_results["total_payloads"], 1)
                )
                * 100,
            },
        }

    def _assess_waf_effectiveness(self, target_url: str) -> Dict[str, Any]:
        """Assess overall WAF effectiveness and security posture"""
        findings = []
        effectiveness_score = 0

        try:
            # Factor 1: Detection capability (did we identify the WAF?)
            if self.detection_results["waf_detected"]:
                effectiveness_score += 20
                findings.append(
                    {
                        "title": "WAF Detection Capability",
                        "description": "WAF presence is detectable, which may aid attackers in fingerprinting",
                        "severity": ScanSeverity.LOW,
                        "category": "waf_assessment",
                        "assessment_factor": "detectability",
                    }
                )

            # Factor 2: Bypass resistance
            bypass_rate = self._calculate_bypass_success_rate()
            if bypass_rate < 5:
                effectiveness_score += 40
            elif bypass_rate < 15:
                effectiveness_score += 25
            elif bypass_rate < 30:
                effectiveness_score += 10

            # Factor 3: Error message disclosure
            if self._check_information_disclosure(target_url):
                findings.append(
                    {
                        "title": "Information Disclosure in Error Messages",
                        "description": "WAF error messages may disclose sensitive information",
                        "severity": ScanSeverity.MEDIUM,
                        "category": "waf_assessment",
                        "assessment_factor": "information_disclosure",
                    }
                )
            else:
                effectiveness_score += 20

            # Factor 4: Rate limiting implementation
            if self._has_rate_limiting(target_url):
                effectiveness_score += 20

            # Generate overall assessment
            if effectiveness_score >= 80:
                assessment = "Excellent"
                severity = ScanSeverity.INFO
            elif effectiveness_score >= 60:
                assessment = "Good"
                severity = ScanSeverity.LOW
            elif effectiveness_score >= 40:
                assessment = "Moderate"
                severity = ScanSeverity.MEDIUM
            else:
                assessment = "Poor"
                severity = ScanSeverity.HIGH

            findings.append(
                {
                    "title": f"WAF Effectiveness Assessment: {assessment}",
                    "description": f"Overall WAF effectiveness score: {effectiveness_score}/100",
                    "severity": severity,
                    "category": "waf_effectiveness",
                    "effectiveness_score": effectiveness_score,
                    "assessment_level": assessment,
                }
            )

        except Exception as e:
            log_error(f"WAF effectiveness assessment failed: {e}")

        return {
            "findings": findings,
            "effectiveness_score": effectiveness_score,
            "summary": {
                "assessment_level": (
                    assessment if "assessment" in locals() else "Unknown"
                ),
                "score": effectiveness_score,
            },
        }

    def _analyze_response_timing(self, target_url: str) -> Dict[str, Any]:
        """Analyze response timing patterns to detect WAF behavior"""
        findings = []

        try:
            # Baseline timing
            start_time = time.time()
            normal_response = self.session.get(target_url, timeout=self.timeout)
            normal_time = time.time() - start_time

            # Test with malicious payload
            start_time = time.time()
            malicious_response = self.session.get(
                target_url,
                params={"test": "<script>alert(1)</script>"},
                timeout=self.timeout,
            )
            malicious_time = time.time() - start_time

            # Analyze timing difference
            time_diff = abs(malicious_time - normal_time)

            if time_diff > 2.0:  # Significant delay suggests WAF processing
                findings.append(
                    {
                        "title": "WAF Response Timing Anomaly Detected",
                        "description": f"Significant timing difference detected: {time_diff:.2f}s",
                        "severity": ScanSeverity.INFO,
                        "category": "timing_analysis",
                        "normal_time": normal_time,
                        "malicious_time": malicious_time,
                        "time_difference": time_diff,
                    }
                )

        except Exception as e:
            log_warning(f"Timing analysis failed: {e}")

        return {"findings": findings}

    def _fingerprint_error_messages(self, target_url: str) -> Dict[str, Any]:
        """Fingerprint WAF through error message analysis"""
        findings = []

        # Test payloads designed to trigger WAF errors
        test_payloads = [
            "' UNION SELECT 1,2,3--",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "; cat /etc/passwd",
        ]

        try:
            for payload in test_payloads:
                response = self.session.get(
                    target_url,
                    params={"test": payload},
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                # Analyze error messages for WAF signatures
                if response.status_code in [403, 406, 501]:
                    error_content = response.text.lower()

                    # Check for WAF-specific error patterns
                    for waf_name, signatures in self.waf_signatures.items():
                        for error_msg in signatures.get("error_messages", []):
                            if error_msg.lower() in error_content:
                                findings.append(
                                    {
                                        "title": f"WAF Error Message Fingerprint: {waf_name.title()}",
                                        "description": f"WAF error message detected for {waf_name}: {error_msg}",
                                        "severity": ScanSeverity.INFO,
                                        "category": "error_fingerprint",
                                        "waf_vendor": waf_name,
                                        "payload": payload,
                                        "error_pattern": error_msg,
                                    }
                                )

                time.sleep(1)  # Rate limiting

        except Exception as e:
            log_warning(f"Error message fingerprinting failed: {e}")

        return {"findings": findings}

    def _detect_rate_limiting(self, target_url: str) -> Dict[str, Any]:
        """Detect rate limiting mechanisms"""
        findings = []

        try:
            # Send multiple rapid requests
            response_codes = []
            for i in range(10):
                response = self.session.get(target_url, timeout=self.timeout)
                response_codes.append(response.status_code)
                time.sleep(0.1)  # Very short delay

            # Check for rate limiting indicators
            rate_limit_codes = [429, 503, 502]
            if any(code in rate_limit_codes for code in response_codes):
                findings.append(
                    {
                        "title": "Rate Limiting Detected",
                        "description": "WAF implements rate limiting protection",
                        "severity": ScanSeverity.INFO,
                        "category": "rate_limiting",
                        "response_codes": response_codes,
                        "rate_limit_detected": True,
                    }
                )

        except Exception as e:
            log_warning(f"Rate limiting detection failed: {e}")

        return {"findings": findings}

    def _analyze_custom_headers(self, target_url: str) -> Dict[str, Any]:
        """Analyze custom headers that may indicate WAF presence"""
        findings = []

        try:
            response = self.session.get(target_url, timeout=self.timeout)
            headers = response.headers

            # Common WAF-related headers
            waf_headers = [
                "x-waf-event-info",
                "x-sucuri-id",
                "cf-ray",
                "x-amzn-requestid",
                "akamai-origin-hop",
                "server",
                "x-cache",
                "x-served-by",
            ]

            detected_headers = []
            for header in waf_headers:
                if header.lower() in [h.lower() for h in headers.keys()]:
                    detected_headers.append(header)

            if detected_headers:
                findings.append(
                    {
                        "title": "WAF-Related Headers Detected",
                        "description": f"Headers suggesting WAF presence: {', '.join(detected_headers)}",
                        "severity": ScanSeverity.INFO,
                        "category": "header_analysis",
                        "detected_headers": detected_headers,
                    }
                )

        except Exception as e:
            log_warning(f"Custom header analysis failed: {e}")

        return {"findings": findings}

    def _test_single_payload(
        self, target_url: str, payload: str, attack_type: str
    ) -> Dict[str, Any]:
        """Test a single bypass payload"""
        try:
            # Test different injection points
            test_methods = [
                {"method": "GET", "params": {"test": payload}},
                {"method": "POST", "data": {"test": payload}},
                {"method": "GET", "headers": {"X-Test": payload}},
            ]

            for test_method in test_methods:
                method = test_method["method"]

                if method == "GET":
                    if "params" in test_method:
                        response = self.session.get(
                            target_url,
                            params=test_method["params"],
                            timeout=self.timeout,
                        )
                    else:
                        response = self.session.get(
                            target_url,
                            headers=test_method["headers"],
                            timeout=self.timeout,
                        )
                else:
                    response = self.session.post(
                        target_url, data=test_method["data"], timeout=self.timeout
                    )

                # Analyze response to determine if bypassed
                if self._is_payload_bypassed(response, payload):
                    return {
                        "bypassed": True,
                        "blocked": False,
                        "status_code": response.status_code,
                        "method": test_method["method"],
                    }
                elif self._is_payload_blocked(response):
                    return {
                        "bypassed": False,
                        "blocked": True,
                        "status_code": response.status_code,
                        "method": test_method["method"],
                    }

            # If no clear bypass or block detected
            return {
                "bypassed": False,
                "blocked": False,
                "status_code": response.status_code if "response" in locals() else 0,
                "method": "unknown",
            }

        except Exception as e:
            log_warning(f"Payload testing failed: {e}")
            return {
                "bypassed": False,
                "blocked": False,
                "status_code": 0,
                "method": "error",
            }

    def _is_payload_bypassed(self, response: requests.Response, payload: str) -> bool:
        """Check if payload successfully bypassed WAF"""
        # Success indicators
        if response.status_code == 200:
            # Check if payload is reflected in response (basic check)
            if payload in response.text:
                return True
            # Check for SQL error messages (indicates injection worked)
            sql_errors = [
                "mysql",
                "postgresql",
                "oracle",
                "sql syntax",
                "database error",
            ]
            if any(error in response.text.lower() for error in sql_errors):
                return True

        return False

    def _is_payload_blocked(self, response: requests.Response) -> bool:
        """Check if payload was blocked by WAF"""
        # Common WAF block indicators
        block_codes = [403, 406, 412, 501]
        if response.status_code in block_codes:
            return True

        # Check for block messages
        block_messages = ["blocked", "forbidden", "access denied", "not acceptable"]
        if any(msg in response.text.lower() for msg in block_messages):
            return True

        return False

    def _calculate_bypass_success_rate(self) -> float:
        """Calculate bypass success rate"""
        total_payloads = len(self.detection_results["effective_payloads"]) + len(
            self.detection_results["blocked_payloads"]
        )
        if total_payloads == 0:
            return 0.0
        return (
            len(self.detection_results["effective_payloads"]) / total_payloads
        ) * 100

    def _check_information_disclosure(self, target_url: str) -> bool:
        """Check if WAF discloses sensitive information in error messages"""
        try:
            response = self.session.get(
                target_url, params={"test": "' OR 1=1--"}, timeout=self.timeout
            )

            # Check for information disclosure patterns
            disclosure_patterns = [
                r"server.*version",
                r"database.*error",
                r"sql.*syntax",
                r"warning.*line",
                r"notice.*undefined",
                r"fatal.*error",
            ]

            for pattern in disclosure_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True

        except Exception:
            pass

        return False

    def _has_rate_limiting(self, target_url: str) -> bool:
        """Check if WAF implements rate limiting"""
        try:
            # Send burst of requests
            for i in range(20):
                response = self.session.get(target_url, timeout=self.timeout)
                if response.status_code in [429, 503]:
                    return True
                time.sleep(0.05)  # Very short delay

        except Exception:
            pass

        return False

    def _calculate_waf_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate overall WAF-related risk score"""
        if not findings:
            return 0.0

        severity_weights = {
            ScanSeverity.CRITICAL: 10,
            ScanSeverity.HIGH: 7,
            ScanSeverity.MEDIUM: 4,
            ScanSeverity.LOW: 2,
            ScanSeverity.INFO: 1,
        }

        total_score = sum(
            severity_weights.get(finding.get("severity", ScanSeverity.INFO), 1)
            for finding in findings
        )

        # Normalize to 0-100 scale
        max_possible_score = len(findings) * 10
        risk_score = (
            (total_score / max_possible_score) * 100 if max_possible_score > 0 else 0
        )

        return round(risk_score, 2)


# This scanner will be registered in the main scanner registry
# No additional registration code needed - follows existing pattern
