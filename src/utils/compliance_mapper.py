"""
Compliance Mapper - src/utils/compliance_mapper.py

Maps security findings to compliance frameworks (PCI DSS, NIST, ISO27001)
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json


class ComplianceMapper:
    """
    Maps security findings to compliance framework requirements
    """

    def __init__(self):
        self.frameworks = {
            "pci_dss": {
                "name": "Payment Card Industry Data Security Standard",
                "version": "v4.0",
                "description": "Security standard for organizations that handle credit card information",
                "requirements": self._get_pci_requirements(),
                "categories": [
                    "Build and Maintain",
                    "Protect",
                    "Detect and Respond",
                    "Policies",
                ],
            },
            "nist": {
                "name": "NIST Cybersecurity Framework",
                "version": "v1.1",
                "description": "Framework for improving critical infrastructure cybersecurity",
                "requirements": self._get_nist_requirements(),
                "categories": ["Identify", "Protect", "Detect", "Respond", "Recover"],
            },
            "iso27001": {
                "name": "ISO/IEC 27001:2013",
                "version": "2013",
                "description": "International standard for information security management systems",
                "requirements": self._get_iso27001_requirements(),
                "categories": [
                    "Security Policy",
                    "Organization",
                    "Asset Management",
                    "Access Control",
                    "Cryptography",
                ],
            },
        }

    def _get_pci_requirements(self) -> Dict[str, Dict]:
        """PCI DSS v4.0 requirements mapping"""
        return {
            "1.1.1": {
                "title": "Firewall Configuration Standards",
                "description": "Establish firewall and router configuration standards",
                "category": "Build and Maintain",
                "level": "requirement",
                "testing_procedures": [
                    "Review firewall configuration",
                    "Verify rule documentation",
                ],
                "finding_types": [
                    "open_ports",
                    "firewall_config",
                    "network_segmentation",
                ],
            },
            "2.2.1": {
                "title": "Vendor Default Passwords",
                "description": "Change vendor-supplied defaults before installing system on network",
                "category": "Build and Maintain",
                "level": "requirement",
                "testing_procedures": [
                    "Test for default passwords",
                    "Review authentication configuration",
                ],
                "finding_types": [
                    "default_credentials",
                    "weak_passwords",
                    "authentication",
                ],
            },
            "4.2.1": {
                "title": "Encryption in Transit",
                "description": "Strong cryptography and security protocols protect PAN during transmission",
                "category": "Protect",
                "level": "requirement",
                "testing_procedures": [
                    "Verify encryption protocols",
                    "Test cipher strength",
                ],
                "finding_types": [
                    "ssl_tls",
                    "encryption",
                    "certificate_issues",
                    "weak_ciphers",
                ],
            },
            "6.2.4": {
                "title": "Custom Software Security",
                "description": "Public-facing web applications protected against attacks",
                "category": "Protect",
                "level": "requirement",
                "testing_procedures": [
                    "Web application testing",
                    "Code review",
                    "Vulnerability assessment",
                ],
                "finding_types": [
                    "web_vulnerabilities",
                    "injection",
                    "xss",
                    "csrf",
                    "sql_injection",
                ],
            },
            "6.3.1": {
                "title": "Web Application Security",
                "description": "Web applications developed in accordance with secure coding guidelines",
                "category": "Protect",
                "level": "requirement",
                "testing_procedures": ["Security testing", "Code analysis"],
                "finding_types": [
                    "web_application",
                    "insecure_coding",
                    "input_validation",
                ],
            },
            "11.3.1": {
                "title": "Penetration Testing",
                "description": "External and internal penetration testing performed",
                "category": "Detect and Respond",
                "level": "requirement",
                "testing_procedures": [
                    "Penetration test execution",
                    "Vulnerability scanning",
                ],
                "finding_types": [
                    "penetration_test",
                    "vulnerability_scan",
                    "security_testing",
                ],
            },
            "11.3.2": {
                "title": "Network Vulnerability Scans",
                "description": "Network vulnerability scans performed",
                "category": "Detect and Respond",
                "level": "requirement",
                "testing_procedures": ["Network scanning", "Vulnerability assessment"],
                "finding_types": [
                    "network_vulnerabilities",
                    "port_scan",
                    "service_detection",
                ],
            },
        }

    def _get_nist_requirements(self) -> Dict[str, Dict]:
        """NIST Cybersecurity Framework mapping"""
        return {
            "ID.AM-1": {
                "title": "Asset Management",
                "description": "Physical devices and systems within the organization are inventoried",
                "category": "Identify",
                "level": "subcategory",
                "references": ["CIS CSC 1", "ISO 27001:2013 A.8.1.1"],
                "finding_types": [
                    "asset_discovery",
                    "network_mapping",
                    "service_enumeration",
                ],
            },
            "ID.AM-3": {
                "title": "Communication and Data Flows",
                "description": "Organizational communication and data flows are mapped",
                "category": "Identify",
                "level": "subcategory",
                "references": ["ISO 27001:2013 A.13.2.1"],
                "finding_types": [
                    "network_topology",
                    "data_flows",
                    "communication_paths",
                ],
            },
            "PR.AC-1": {
                "title": "Access Control",
                "description": "Identities and credentials are issued, managed, verified, revoked",
                "category": "Protect",
                "level": "subcategory",
                "references": ["CIS CSC 16", "ISO 27001:2013 A.9.2.1"],
                "finding_types": [
                    "authentication",
                    "authorization",
                    "access_control",
                    "credential_management",
                ],
            },
            "PR.AC-6": {
                "title": "Network Integrity",
                "description": "Network integrity is protected",
                "category": "Protect",
                "level": "subcategory",
                "references": ["ISO 27001:2013 A.13.1.1"],
                "finding_types": [
                    "network_security",
                    "network_segmentation",
                    "firewall_config",
                ],
            },
            "PR.DS-2": {
                "title": "Data in Transit",
                "description": "Data-in-transit is protected",
                "category": "Protect",
                "level": "subcategory",
                "references": ["CIS CSC 14", "ISO 27001:2013 A.8.2.3"],
                "finding_types": [
                    "encryption",
                    "ssl_tls",
                    "data_protection",
                    "secure_transmission",
                ],
            },
            "DE.CM-1": {
                "title": "Network Monitoring",
                "description": "The network is monitored to detect potential cybersecurity events",
                "category": "Detect",
                "level": "subcategory",
                "references": ["CIS CSC 12", "ISO 27001:2013 A.12.4.1"],
                "finding_types": [
                    "network_monitoring",
                    "intrusion_detection",
                    "anomaly_detection",
                ],
            },
            "DE.CM-8": {
                "title": "Vulnerability Scans",
                "description": "Vulnerability scans are performed",
                "category": "Detect",
                "level": "subcategory",
                "references": ["ISO 27001:2013 A.12.6.1"],
                "finding_types": [
                    "vulnerability_scanning",
                    "security_assessment",
                    "penetration_testing",
                ],
            },
        }

    def _get_iso27001_requirements(self) -> Dict[str, Dict]:
        """ISO 27001:2013 Annex A controls mapping"""
        return {
            "A.9.1.2": {
                "title": "Access to Networks and Network Services",
                "description": "Access to networks and network services shall be controlled",
                "category": "Access Control",
                "level": "control",
                "objective": "To prevent unauthorized access to networks and network services",
                "finding_types": [
                    "network_access",
                    "authentication",
                    "authorization",
                    "access_control",
                ],
            },
            "A.10.1.1": {
                "title": "Cryptographic Controls",
                "description": "A policy on the use of cryptographic controls shall be developed",
                "category": "Cryptography",
                "level": "control",
                "objective": "To ensure proper and effective use of cryptography",
                "finding_types": [
                    "encryption",
                    "cryptography",
                    "key_management",
                    "ssl_tls",
                ],
            },
            "A.12.6.1": {
                "title": "Management of Technical Vulnerabilities",
                "description": "Information about technical vulnerabilities shall be obtained in a timely fashion",
                "category": "Operations Security",
                "level": "control",
                "objective": "To prevent exploitation of technical vulnerabilities",
                "finding_types": [
                    "vulnerability_management",
                    "patch_management",
                    "security_updates",
                ],
            },
            "A.13.1.1": {
                "title": "Network Controls",
                "description": "Networks shall be controlled and protected",
                "category": "Communications Security",
                "level": "control",
                "objective": "To ensure the protection of information in networks",
                "finding_types": [
                    "network_security",
                    "network_segmentation",
                    "firewall_config",
                ],
            },
            "A.13.2.1": {
                "title": "Information Transfer Policies",
                "description": "Formal transfer policies shall be established",
                "category": "Communications Security",
                "level": "control",
                "objective": "To maintain the security of information transferred",
                "finding_types": [
                    "data_transfer",
                    "secure_protocols",
                    "information_exchange",
                ],
            },
            "A.14.2.1": {
                "title": "Secure Development Policy",
                "description": "Rules for secure development shall be established",
                "category": "System Acquisition",
                "level": "control",
                "objective": "To ensure security is designed and implemented within development lifecycle",
                "finding_types": [
                    "secure_development",
                    "code_security",
                    "application_security",
                ],
            },
        }

    def map_findings_to_compliance(
        self, findings: List[Dict], framework: str
    ) -> Dict[str, Any]:
        """
        Map security findings to compliance framework requirements

        Args:
            findings: List of security findings
            framework: Compliance framework (pci_dss, nist, iso27001)

        Returns:
            Dict: Compliance mapping results
        """
        if framework not in self.frameworks:
            raise ValueError(f"Unsupported framework: {framework}")

        framework_data = self.frameworks[framework]
        requirements = framework_data["requirements"]

        # Initialize mapping results
        mapping_results = {
            "framework": framework_data,
            "summary": {
                "total_requirements": len(requirements),
                "requirements_with_findings": 0,
                "total_findings": len(findings),
                "mapped_findings": 0,
                "compliance_score": 0.0,
            },
            "requirement_mappings": {},
            "unmapped_findings": [],
            "recommendations": [],
        }

        # Map findings to requirements
        for finding in findings:
            finding_type = self._categorize_finding(finding)
            mapped = False

            for req_id, requirement in requirements.items():
                if finding_type in requirement.get("finding_types", []):
                    if req_id not in mapping_results["requirement_mappings"]:
                        mapping_results["requirement_mappings"][req_id] = {
                            "requirement": requirement,
                            "findings": [],
                            "status": "non_compliant",
                            "risk_level": "low",
                        }

                    mapping_results["requirement_mappings"][req_id]["findings"].append(
                        finding
                    )

                    # Update risk level based on finding severity
                    severity = finding.get("severity", "low").lower()
                    current_risk = mapping_results["requirement_mappings"][req_id][
                        "risk_level"
                    ]
                    if severity in ["critical", "high"] or current_risk == "low":
                        mapping_results["requirement_mappings"][req_id][
                            "risk_level"
                        ] = self._get_risk_level(severity)

                    mapped = True
                    mapping_results["summary"]["mapped_findings"] += 1
                    break

            if not mapped:
                mapping_results["unmapped_findings"].append(finding)

        # Calculate compliance metrics
        mapping_results["summary"]["requirements_with_findings"] = len(
            mapping_results["requirement_mappings"]
        )

        # Calculate compliance score (simplified)
        total_reqs = mapping_results["summary"]["total_requirements"]
        non_compliant_reqs = len(
            [
                r
                for r in mapping_results["requirement_mappings"].values()
                if r["status"] == "non_compliant"
            ]
        )

        compliance_score = max(0, (total_reqs - non_compliant_reqs) / total_reqs * 100)
        mapping_results["summary"]["compliance_score"] = round(compliance_score, 1)

        # Generate recommendations
        mapping_results["recommendations"] = self._generate_compliance_recommendations(
            mapping_results["requirement_mappings"], framework
        )

        return mapping_results

    def _categorize_finding(self, finding: Dict) -> str:
        """Categorize a finding based on its content"""
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        category = finding.get("category", "").lower()

        # Simple categorization logic
        if any(
            term in title + description
            for term in ["ssl", "tls", "certificate", "encryption"]
        ):
            return "ssl_tls"
        elif any(
            term in title + description for term in ["port", "service", "network"]
        ):
            return "network_vulnerabilities"
        elif any(
            term in title + description for term in ["web", "http", "application"]
        ):
            return "web_vulnerabilities"
        elif any(
            term in title + description
            for term in ["authentication", "password", "login"]
        ):
            return "authentication"
        elif any(term in title + description for term in ["directory", "file", "path"]):
            return "directory_traversal"
        elif "dns" in title + description:
            return "dns_security"
        else:
            return "general_security"

    def _get_risk_level(self, severity: str) -> str:
        """Convert severity to risk level"""
        severity_map = {
            "critical": "high",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "low",
        }
        return severity_map.get(severity.lower(), "low")

    def _generate_compliance_recommendations(
        self, mappings: Dict, framework: str
    ) -> List[str]:
        """Generate compliance-specific recommendations"""
        recommendations = []

        high_risk_count = len(
            [r for r in mappings.values() if r["risk_level"] == "high"]
        )
        medium_risk_count = len(
            [r for r in mappings.values() if r["risk_level"] == "medium"]
        )

        if high_risk_count > 0:
            recommendations.append(
                f"IMMEDIATE ACTION REQUIRED: {high_risk_count} high-risk compliance violations found. "
                "Address these issues immediately to maintain compliance."
            )

        if medium_risk_count > 0:
            recommendations.append(
                f"MEDIUM PRIORITY: {medium_risk_count} medium-risk compliance issues identified. "
                "Plan remediation within the next compliance cycle."
            )

        if framework == "pci_dss":
            recommendations.extend(
                [
                    "Conduct quarterly vulnerability scans as required by PCI DSS 11.2.1",
                    "Ensure annual penetration testing covers all requirements in PCI DSS 11.3",
                    "Document all remediation activities for audit trail",
                ]
            )
        elif framework == "nist":
            recommendations.extend(
                [
                    "Implement continuous monitoring for Detect function",
                    "Review and update incident response procedures",
                    "Conduct regular risk assessments",
                ]
            )
        elif framework == "iso27001":
            recommendations.extend(
                [
                    "Update Information Security Policy to address identified gaps",
                    "Conduct management review of compliance status",
                    "Plan for next surveillance audit",
                ]
            )

        return recommendations


def generate_compliance_html_template(
    mapping_data: Dict[str, Any], framework: str
) -> str:
    """Generate comprehensive HTML compliance report"""
    framework_info = mapping_data["framework"]
    summary = mapping_data["summary"]
    requirements = mapping_data["requirement_mappings"]

    # Get compliance status color
    score = summary["compliance_score"]
    if score >= 90:
        status_color = "#22c55e"  # Green
        status_text = "COMPLIANT"
    elif score >= 70:
        status_color = "#f59e0b"  # Yellow
        status_text = "PARTIALLY COMPLIANT"
    else:
        status_color = "#ef4444"  # Red
        status_text = "NON-COMPLIANT"

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Assessment Report - {framework_info['name']}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8fafc;
            color: #1e293b;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 2.5em;
            font-weight: 700;
        }}
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        .compliance-status {{
            background: {status_color};
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 1.5em;
            font-weight: bold;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8fafc;
        }}
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #1e40af;
            margin-bottom: 10px;
        }}
        .summary-card .label {{
            color: #64748b;
            font-weight: 500;
        }}
        .content {{
            padding: 40px;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #1e40af;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
            margin-bottom: 25px;
        }}
        .requirement {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .requirement-header {{
            background: #1e40af;
            color: white;
            padding: 15px 20px;
            font-weight: 600;
        }}
        .requirement-content {{
            padding: 20px;
        }}
        .finding {{
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 10px;
        }}
        .finding-title {{
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 5px;
        }}
        .severity {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }}
        .severity.critical {{ background: #dc2626; }}
        .severity.high {{ background: #ea580c; }}
        .severity.medium {{ background: #d97706; }}
        .severity.low {{ background: #16a34a; }}
        .severity.info {{ background: #0891b2; }}
        .risk-level {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
            margin-left: 10px;
        }}
        .risk-level.high {{
            background: #fecaca;
            color: #dc2626;
        }}
        .risk-level.medium {{
            background: #fed7aa;
            color: #ea580c;
        }}
        .risk-level.low {{
            background: #bbf7d0;
            color: #16a34a;
        }}
        .recommendations {{
            background: #fffbeb;
            border: 1px solid #f59e0b;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }}
        .recommendations h3 {{
            color: #d97706;
            margin-top: 0;
        }}
        .recommendations ul {{
            margin: 0;
            padding-left: 20px;
        }}
        .recommendations li {{
            margin-bottom: 10px;
            line-height: 1.6;
        }}
        .footer {{
            background: #1e293b;
            color: white;
            padding: 30px;
            text-align: center;
            margin-top: 40px;
        }}
        .progress-bar {{
            width: 100%;
            height: 20px;
            background: #e2e8f0;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .progress-fill {{
            height: 100%;
            background: {status_color};
            width: {score}%;
            transition: width 0.3s ease;
        }}
        @media print {{
            body {{ margin: 0; }}
            .container {{ box-shadow: none; }}
            .no-print {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Compliance Assessment Report</h1>
            <div class="subtitle">{framework_info['name']} {framework_info['version']}</div>
            <div style="margin-top: 20px; opacity: 0.9;">
                Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
            </div>
        </div>

        <div class="compliance-status">
            {status_text} - {score}% Compliance Score
            <div class="progress-bar">
                <div class="progress-fill"></div>
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <div class="number">{summary['total_requirements']}</div>
                <div class="label">Total Requirements</div>
            </div>
            <div class="summary-card">
                <div class="number">{summary['requirements_with_findings']}</div>
                <div class="label">Non-Compliant</div>
            </div>
            <div class="summary-card">
                <div class="number">{summary['total_findings']}</div>
                <div class="label">Security Findings</div>
            </div>
            <div class="summary-card">
                <div class="number">{summary['mapped_findings']}</div>
                <div class="label">Mapped Findings</div>
            </div>
        </div>

        <div class="content">
            <div class="section">
                <h2>Framework Overview</h2>
                <p><strong>Standard:</strong> {framework_info['name']} {framework_info['version']}</p>
                <p><strong>Description:</strong> {framework_info['description']}</p>
                <p><strong>Categories:</strong> {', '.join(framework_info['categories'])}</p>
            </div>

            <div class="section">
                <h2>Compliance Requirements Assessment</h2>
"""

    # Add requirement details
    for req_id, req_data in requirements.items():
        requirement = req_data["requirement"]
        findings = req_data["findings"]
        risk_level = req_data["risk_level"]

        html += f"""
                <div class="requirement">
                    <div class="requirement-header">
                        {req_id}: {requirement['title']}
                        <span class="risk-level {risk_level}">Risk: {risk_level.upper()}</span>
                    </div>
                    <div class="requirement-content">
                        <p><strong>Description:</strong> {requirement['description']}</p>
                        <p><strong>Category:</strong> {requirement['category']}</p>

                        <h4>Associated Findings ({len(findings)}):</h4>
"""

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            html += f"""
                        <div class="finding">
                            <div class="finding-title">{finding.get('title', 'Unknown Finding')}</div>
                            <span class="severity {severity}">{severity.upper()}</span>
                            <p>{finding.get('description', 'No description available')}</p>
                        </div>
"""

        html += """
                    </div>
                </div>
"""

    # Add recommendations
    recommendations = mapping_data.get("recommendations", [])
    if recommendations:
        html += f"""
            <div class="section">
                <div class="recommendations">
                    <h3>Compliance Recommendations</h3>
                    <ul>
"""
        for rec in recommendations:
            html += f"<li>{rec}</li>"

        html += """
                    </ul>
                </div>
            </div>
"""

    html += f"""
        </div>

        <div class="footer">
            <p>This compliance assessment was generated by Auto-Pentest Framework</p>
            <p>Report ID: COMP-{framework.upper()}-{int(datetime.now().timestamp())}</p>
            <p><em>Note: This automated assessment provides initial compliance insights.
            Professional compliance audit is recommended for certification purposes.</em></p>
        </div>
    </div>
</body>
</html>
"""

    return html
