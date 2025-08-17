"""
Enhanced Reporter - Generate professional HTML, PDF and text reports
"""

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from pathlib import Path
from collections import defaultdict
import base64

try:
    from jinja2 import Environment, FileSystemLoader, Template

    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

# PDF generation dependencies
try:
    import weasyprint

    PDF_AVAILABLE = True
    PDF_LIB = "weasyprint"
except ImportError:
    try:
        import pdfkit

        PDF_AVAILABLE = True
        PDF_LIB = "pdfkit"
    except ImportError:
        PDF_AVAILABLE = False
        PDF_LIB = None

from src.core import ScanResult, ScanSeverity
from src.utils.logger import log_info, log_error, log_warning, log_success


class ReportGenerator:
    """
    Professional report generator with multiple output formats including PDF
    """

    def __init__(
        self, template_dir: Optional[Path] = None, branding: Optional[Dict] = None
    ):
        """
        Initialize report generator

        Args:
            template_dir: Directory containing report templates
            branding: Custom branding options (logo, colors, company name)
        """
        self.template_dir = (
            template_dir or Path(__file__).parent.parent.parent / "templates"
        )
        self.version = "0.9.1"

        # Custom branding support
        self.branding = branding or {
            "company_name": "Auto-Pentest Framework",
            "company_logo": None,
            "primary_color": "#667eea",
            "secondary_color": "#764ba2",
            "accent_color": "#f093fb",
        }

        # Initialize Jinja2 environment if available
        if JINJA2_AVAILABLE and self.template_dir.exists():
            self.jinja_env = Environment(
                loader=FileSystemLoader(str(self.template_dir)), autoescape=True
            )
        else:
            self.jinja_env = None
            if not JINJA2_AVAILABLE:
                log_warning(
                    "Jinja2 not available, HTML reports will use basic templates"
                )

        # PDF generation setup
        if not PDF_AVAILABLE:
            log_warning(
                "PDF generation not available. Install 'weasyprint' or 'pdfkit' for PDF export"
            )

    def generate_html_report(
        self,
        results: Union[ScanResult, List[ScanResult]],
        output_path: Path,
        title: Optional[str] = None,
    ) -> bool:
        """
        Generate professional HTML report

        Args:
            results: Scan results (single or multiple)
            output_path: Output file path
            title: Optional custom title

        Returns:
            bool: Success status
        """
        try:
            # Ensure results is a list
            if isinstance(results, ScanResult):
                results = [results]

            # Aggregate data from all results
            report_data = self._aggregate_report_data(results, title)

            # Generate HTML
            if self.jinja_env:
                html_content = self._generate_html_with_template(report_data)
            else:
                html_content = self._generate_html_basic(report_data)

            # Write to file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            log_success(f"HTML report generated: {output_path}")
            return True

        except Exception as e:
            log_error(f"Failed to generate HTML report: {e}")
            return False

    def generate_pdf_report(
        self,
        results: Union[ScanResult, List[ScanResult]],
        output_path: Path,
        title: Optional[str] = None,
    ) -> bool:
        """
        Generate professional PDF report

        Args:
            results: Scan results (single or multiple)
            output_path: Output file path
            title: Optional custom title

        Returns:
            bool: Success status
        """
        if not PDF_AVAILABLE:
            log_error("PDF generation not available. Install 'weasyprint' or 'pdfkit'")
            return False

        try:
            # First generate HTML content
            if isinstance(results, ScanResult):
                results = [results]

            report_data = self._aggregate_report_data(results, title)

            # Generate PDF-optimized HTML
            html_content = self._generate_pdf_html(report_data)

            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Generate PDF based on available library
            if PDF_LIB == "weasyprint":
                self._generate_pdf_weasyprint(html_content, output_path)
            elif PDF_LIB == "pdfkit":
                self._generate_pdf_pdfkit(html_content, output_path)

            log_success(f"PDF report generated: {output_path}")
            return True

        except Exception as e:
            log_error(f"Failed to generate PDF report: {e}")
            return False

    def generate_executive_summary(
        self, results: Union[ScanResult, List[ScanResult]], output_path: Path
    ) -> bool:
        """
        Generate executive summary report

        Args:
            results: Scan results
            output_path: Output file path

        Returns:
            bool: Success status
        """
        try:
            if isinstance(results, ScanResult):
                results = [results]

            summary = self._create_executive_summary(results)

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(summary)

            log_success(f"Executive summary generated: {output_path}")
            return True

        except Exception as e:
            log_error(f"Failed to generate executive summary: {e}")
            return False

    def generate_json_report(
        self, results: Union[ScanResult, List[ScanResult]], output_path: Path
    ) -> bool:
        """
        Generate detailed JSON report

        Args:
            results: Scan results
            output_path: Output file path

        Returns:
            bool: Success status
        """
        try:
            if isinstance(results, ScanResult):
                results = [results]

            # Convert results to dict format
            report_data = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "version": self.version,
                    "target": results[0].target if results else "unknown",
                    "scan_count": len(results),
                },
                "scan_results": [result.to_dict() for result in results],
                "aggregated_data": self._aggregate_report_data(results),
            }

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, default=str)

            log_success(f"JSON report generated: {output_path}")
            return True

        except Exception as e:
            log_error(f"Failed to generate JSON report: {e}")
            return False

    def generate_compliance_report(
        self,
        results: Union[ScanResult, List[ScanResult]],
        output_path: Path,
        compliance_type: str = "pci_dss",
    ) -> bool:
        """
        Generate compliance-specific report

        Args:
            results: Scan results
            output_path: Output file path
            compliance_type: Type of compliance (pci_dss, nist, iso27001)

        Returns:
            bool: Success status
        """
        try:
            if isinstance(results, ScanResult):
                results = [results]

            compliance_data = self._create_compliance_mapping(results, compliance_type)

            # Generate compliance-specific HTML
            html_content = self._generate_compliance_html(
                compliance_data, compliance_type
            )

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            log_success(
                f"Compliance report ({compliance_type}) generated: {output_path}"
            )
            return True

        except Exception as e:
            log_error(f"Failed to generate compliance report: {e}")
            return False

    def _aggregate_report_data(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Aggregate scan results into report data structure"""
        if not results:
            return {}

        first_result = results[0]
        scan_start = min(result.start_time for result in results)
        scan_end = max(
            result.end_time for result in results if result.end_time is not None
        )

        # Aggregate findings
        all_findings = []
        scanners_used = []
        targets = set()

        for result in results:
            if result.findings:
                all_findings.extend(result.findings)
            scanners_used.append(result.scanner_name)
            targets.add(result.target)

        # Count findings by severity - FIXED VERSION
        severity_counts = defaultdict(int)
        for finding in all_findings:
            severity = self._safe_severity_conversion(finding.get("severity", "info"))
            severity_counts[severity] += 1

        # Group findings by category
        findings_by_category = defaultdict(list)
        for finding in all_findings:
            category = finding.get("category", "Other")
            findings_by_category[category].append(finding)

        # Calculate overall risk
        critical_count = severity_counts.get("critical", 0)
        high_count = severity_counts.get("high", 0)
        medium_count = severity_counts.get("medium", 0)

        if critical_count > 0:
            overall_risk = "Critical"
        elif high_count >= 3:
            overall_risk = "High"
        elif high_count > 0 or medium_count >= 5:
            overall_risk = "Medium"
        elif medium_count > 0:
            overall_risk = "Low"
        else:
            overall_risk = "Informational"

        return {
            "title": title or f"Security Assessment Report - {first_result.target}",
            "target": first_result.target,
            "targets": list(targets),
            "scan_start": scan_start.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_end": scan_end.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": str(scan_end - scan_start).split(".")[0],
            "total_findings": len(all_findings),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": severity_counts.get("low", 0),
            "info_count": severity_counts.get("info", 0),
            "overall_risk": overall_risk,
            "findings_by_category": dict(findings_by_category),
            "scanners_used": list(set(scanners_used)),
            "version": "0.9.4",
            "report_id": f"RPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        }

    def _generate_pdf_html(self, data: Dict[str, Any]) -> str:
        """Generate PDF-optimized HTML content"""
        # Similar to HTML generation but with print-friendly styles
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{data.get('title', 'Security Assessment Report')}</title>
    <style>
        @media print {{
            body {{ margin: 0; font-family: Arial, sans-serif; }}
            .page-break {{ page-break-before: always; }}
            .no-print {{ display: none; }}
        }}
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background: white;
            color: #333;
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: {data.get('branding', {}).get('primary_color', '#667eea')};
            color: white;
            border-radius: 8px;
        }}
        .summary {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .finding {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-bottom: 10px;
            padding: 10px;
        }}
        .critical {{ border-left: 5px solid #dc3545; }}
        .high {{ border-left: 5px solid #fd7e14; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #28a745; }}
        .info {{ border-left: 5px solid #17a2b8; }}
        .severity {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            color: white;
            font-size: 12px;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{data.get('title', 'Security Assessment Report')}</h1>
        <p>Report ID: {data.get('report_id', 'N/A')} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Target: {data.get('target', 'Unknown')}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Overall Risk Level:</strong> {data.get('overall_risk', 'Unknown')}</p>
        <p><strong>Total Findings:</strong> {data.get('total_findings', 0)}</p>
        <p><strong>Scan Duration:</strong> {data.get('duration', 'Unknown')}</p>
        <p><strong>Scanners Used:</strong> {', '.join(data.get('scanners_used', []))}</p>

        <h3>Findings Breakdown</h3>
        <ul>
            <li>Critical: {data.get('critical_count', 0)}</li>
            <li>High: {data.get('high_count', 0)}</li>
            <li>Medium: {data.get('medium_count', 0)}</li>
            <li>Low: {data.get('low_count', 0)}</li>
            <li>Informational: {data.get('info_count', 0)}</li>
        </ul>
    </div>

    <div class="page-break"></div>

    <h2>Detailed Findings</h2>
"""

        # Add findings
        for category, findings in data.get("findings_by_category", {}).items():
            html += f"<h3>{category}</h3>"
            for finding in findings:
                severity = self._safe_severity_conversion(
                    finding.get("severity", "info")
                )
                html += f"""
    <div class="finding {severity}">
        <h4>{finding.get('title', 'Unknown Finding')}</h4>
        <span class="severity" style="background-color: {self._get_severity_color(severity)}">
            {severity.upper()}
        </span>
        <p><strong>Description:</strong> {finding.get('description', 'No description available')}</p>
        {f"<p><strong>Details:</strong> {finding.get('details', '')}</p>" if finding.get('details') else ""}
        {f"<p><strong>Recommendation:</strong> {finding.get('recommendation', '')}</p>" if finding.get('recommendation') else ""}
    </div>
"""

        html += f"""
    <div class="page-break"></div>

    <div style="text-align: center; margin-top: 50px; color: #666; font-size: 12px;">
        <p>Generated by {data.get('branding', {}).get('company_name', 'Auto-Pentest Framework')} v{data.get('version', 'Unknown')}</p>
        <p>This report is confidential and intended solely for the use of the specified recipient.</p>
    </div>
</body>
</html>
"""
        return html

    def _generate_pdf_weasyprint(self, html_content: str, output_path: Path):
        """Generate PDF using WeasyPrint"""
        weasyprint.HTML(string=html_content).write_pdf(str(output_path))

    def _generate_pdf_pdfkit(self, html_content: str, output_path: Path):
        """Generate PDF using pdfkit"""
        options = {
            "page-size": "A4",
            "margin-top": "0.75in",
            "margin-right": "0.75in",
            "margin-bottom": "0.75in",
            "margin-left": "0.75in",
            "encoding": "UTF-8",
            "no-outline": None,
        }
        pdfkit.from_string(html_content, str(output_path), options=options)

    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }
        return colors.get(severity.lower(), "#6c757d")

    def _create_compliance_mapping(
        self, results: List[ScanResult], compliance_type: str
    ) -> Dict[str, Any]:
        """Create compliance-specific mapping of findings"""
        # Import compliance mapper here to avoid circular imports
        try:
            from .compliance_mapper import ComplianceMapper
        except ImportError:
            # Fallback to basic mapping if compliance_mapper not available
            return self._create_basic_compliance_mapping(results, compliance_type)

        # Collect all findings from results
        all_findings = []
        for result in results:
            if result.findings:
                all_findings.extend(result.findings)

        # Use comprehensive compliance mapper
        mapper = ComplianceMapper()
        mapping_data = mapper.map_findings_to_compliance(all_findings, compliance_type)

        return mapping_data

    def _create_basic_compliance_mapping(
        self, results: List[ScanResult], compliance_type: str
    ) -> Dict[str, Any]:
        """Basic compliance mapping fallback"""
        compliance_mappings = {
            "pci_dss": {
                "name": "PCI DSS v4.0",
                "version": "v4.0",
                "description": "Payment Card Industry Data Security Standard",
                "requirements": {
                    "6.2.4": "Custom software security",
                    "6.3.1": "Web application security",
                    "6.3.2": "Authentication controls",
                    "11.3.1": "Penetration testing",
                    "11.3.2": "Network vulnerability scans",
                },
            },
            "nist": {
                "name": "NIST Cybersecurity Framework",
                "version": "v1.1",
                "description": "Framework for improving critical infrastructure cybersecurity",
                "requirements": {
                    "ID.AM": "Asset Management",
                    "PR.AC": "Access Control",
                    "PR.DS": "Data Security",
                    "DE.CM": "Security Continuous Monitoring",
                    "RS.AN": "Analysis",
                },
            },
            "iso27001": {
                "name": "ISO/IEC 27001:2013",
                "version": "2013",
                "description": "International standard for information security management systems",
                "requirements": {
                    "A.9.1.2": "Access to Networks and Network Services",
                    "A.10.1.1": "Cryptographic Controls",
                    "A.12.6.1": "Management of Technical Vulnerabilities",
                    "A.13.1.1": "Network Controls",
                },
            },
        }

        mapping = compliance_mappings.get(compliance_type, {})

        return {
            "framework": mapping,
            "compliance_type": compliance_type,
            "summary": {
                "total_requirements": len(mapping.get("requirements", {})),
                "total_findings": sum(len(r.findings) for r in results),
                "compliance_score": 75.0,  # Placeholder
            },
            "requirement_mappings": {},
            "recommendations": [
                f"This is a basic {compliance_type.upper()} compliance assessment.",
                "For detailed compliance mapping, ensure compliance_mapper module is available.",
                "Conduct manual review for comprehensive compliance evaluation.",
            ],
        }

    def _generate_compliance_html(
        self, compliance_data: Dict[str, Any], compliance_type: str
    ) -> str:
        """Generate compliance-specific HTML report"""
        try:
            # Try to use comprehensive compliance template
            from .compliance_mapper import generate_compliance_html_template

            return generate_compliance_html_template(compliance_data, compliance_type)
        except ImportError:
            # Fallback to basic compliance template
            return self._generate_basic_compliance_html(
                compliance_data, compliance_type
            )

    def _generate_basic_compliance_html(
        self, compliance_data: Dict[str, Any], compliance_type: str
    ) -> str:
        """Generate basic compliance HTML report fallback"""
        framework_info = compliance_data.get("framework", {})

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Compliance Report - {framework_info.get('name', 'Unknown Framework')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ text-align: center; margin-bottom: 40px; background: #f8f9fa; padding: 20px; }}
        .compliance-section {{ margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; }}
        .warning {{ background: #fff3cd; padding: 15px; border: 1px solid #ffeaa7; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Compliance Assessment Report</h1>
        <h2>{framework_info.get('name', 'Unknown Framework')}</h2>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="warning">
        <strong>Note:</strong> This is a basic compliance template.
        For comprehensive compliance mapping, install the full compliance module.
    </div>

    <div class="compliance-section">
        <h3>Framework Information</h3>
        <p><strong>Standard:</strong> {framework_info.get('name', 'N/A')}</p>
        <p><strong>Version:</strong> {framework_info.get('version', 'N/A')}</p>
        <p><strong>Description:</strong> {framework_info.get('description', 'N/A')}</p>
    </div>

    <div class="compliance-section">
        <h3>Assessment Summary</h3>
        <ul>
            <li>Total Requirements: {compliance_data.get('summary', {}).get('total_requirements', 0)}</li>
            <li>Total Findings: {compliance_data.get('summary', {}).get('total_findings', 0)}</li>
            <li>Estimated Compliance Score: {compliance_data.get('summary', {}).get('compliance_score', 0)}%</li>
        </ul>
    </div>

    <div class="compliance-section">
        <h3>Recommendations</h3>
        <ul>
"""

        for recommendation in compliance_data.get("recommendations", []):
            html += f"<li>{recommendation}</li>"

        html += f"""
        </ul>
    </div>

    <div style="text-align: center; margin-top: 40px; color: #666; font-size: 12px;">
        <p>Generated by Auto-Pentest Framework v{self.version}</p>
        <p>Report ID: COMP-{compliance_type.upper()}-{int(datetime.now().timestamp())}</p>
    </div>
</body>
</html>
"""
        return html

    def _generate_html_with_template(self, data: Dict[str, Any]) -> str:
        """Generate HTML using Jinja2 template"""
        try:
            template = self.jinja_env.get_template("report_html.jinja2")
            return template.render(**data)
        except Exception as e:
            log_warning(f"Template rendering failed, using basic HTML: {e}")
            return self._generate_html_basic(data)

    def _generate_html_basic(self, data: Dict[str, Any]) -> str:
        """Generate basic HTML report without templates"""
        primary_color = data.get("branding", {}).get("primary_color", "#667eea")
        secondary_color = data.get("branding", {}).get("secondary_color", "#764ba2")

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{data.get('title', 'Security Assessment Report')}</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; padding: 30px; background: linear-gradient(135deg, {primary_color} 0%, {secondary_color} 100%); color: white; border-radius: 10px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-item {{ text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        .findings {{ margin-bottom: 30px; }}
        .finding {{ background: white; border: 1px solid #ddd; border-radius: 8px; margin-bottom: 15px; padding: 15px; }}
        .critical {{ border-left: 5px solid #dc3545; }}
        .high {{ border-left: 5px solid #fd7e14; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #28a745; }}
        .info {{ border-left: 5px solid #17a2b8; }}
        .severity {{ display: inline-block; padding: 4px 8px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; }}
        .footer {{ text-align: center; margin-top: 40px; padding: 20px; color: #666; border-top: 1px solid #eee; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{data.get('title', 'Security Assessment Report')}</h1>
            <p>Report ID: {data.get('report_id', 'N/A')} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Target: {data.get('target', 'Unknown')} | Duration: {data.get('duration', 'Unknown')}</p>
        </div>

        <div class="summary">
            <h2>Executive Summary</h2>
            <p><strong>Overall Risk Level:</strong> <span style="color: {self._get_risk_color(data.get('overall_risk', 'Unknown'))}">{data.get('overall_risk', 'Unknown')}</span></p>

            <div class="stats">
                <div class="stat-item">
                    <div class="stat-number" style="color: #dc3545">{data.get('critical_count', 0)}</div>
                    <div>Critical</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number" style="color: #fd7e14">{data.get('high_count', 0)}</div>
                    <div>High</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number" style="color: #ffc107">{data.get('medium_count', 0)}</div>
                    <div>Medium</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number" style="color: #28a745">{data.get('low_count', 0)}</div>
                    <div>Low</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number" style="color: #17a2b8">{data.get('info_count', 0)}</div>
                    <div>Info</div>
                </div>
            </div>

            <p><strong>Scanners Used:</strong> {', '.join(data.get('scanners_used', []))}</p>
        </div>

        <div class="findings">
            <h2>Detailed Findings</h2>
"""

        # Add findings by category
        for category, findings in data.get("findings_by_category", {}).items():
            html += f"<h3>{category}</h3>"
            for finding in findings:
                severity = self._safe_severity_conversion(
                    finding.get("severity", "info")
                )
                html += f"""
            <div class="finding {severity}">
                <h4>{finding.get('title', 'Unknown Finding')}</h4>
                <span class="severity" style="background-color: {self._get_severity_color(severity)}">
                    {severity.upper()}
                </span>
                <p><strong>Description:</strong> {finding.get('description', 'No description available')}</p>
                {f"<p><strong>Details:</strong> {finding.get('details', '')}</p>" if finding.get('details') else ""}
                {f"<p><strong>Recommendation:</strong> {finding.get('recommendation', '')}</p>" if finding.get('recommendation') else ""}
            </div>
"""

        html += f"""
        </div>

        <div class="footer">
            <p>Generated by {data.get('branding', {}).get('company_name', 'Auto-Pentest Framework')} v{data.get('version', 'Unknown')}</p>
            <p>This report contains confidential information and should be handled accordingly.</p>
            <p><em>Disclaimer:</em> This automated scan provides initial security insights.
            Manual testing and expert review are recommended for comprehensive security evaluation.</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level"""
        colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
            "Informational": "#17a2b8",
        }
        return colors.get(risk_level, "#6c757d")

    def _create_executive_summary(self, results: List[ScanResult]) -> str:
        """Create executive summary text"""
        if not results:
            return "No scan results available."

        data = self._aggregate_report_data(results)

        summary = f"""
EXECUTIVE SUMMARY
================

Report ID: {data.get('report_id', 'N/A')}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target: {data.get('target', 'Unknown')}
Duration: {data.get('duration', 'Unknown')}

RISK ASSESSMENT
===============
Overall Risk Level: {data.get('overall_risk', 'Unknown')}

FINDINGS SUMMARY
================
Total Findings: {data.get('total_findings', 0)}
- Critical: {data.get('critical_count', 0)}
- High: {data.get('high_count', 0)}
- Medium: {data.get('medium_count', 0)}
- Low: {data.get('low_count', 0)}
- Informational: {data.get('info_count', 0)}

SCANNERS UTILIZED
=================
{chr(10).join('- ' + scanner for scanner in data.get('scanners_used', []))}

RECOMMENDATIONS
===============
"""

        if data.get("critical_count", 0) > 0:
            summary += f"IMMEDIATE ACTION REQUIRED: {data.get('critical_count')} critical vulnerabilities found.\n"

        if data.get("high_count", 0) > 0:
            summary += f"HIGH PRIORITY: Address {data.get('high_count')} high-severity issues.\n"

        if data.get("medium_count", 0) > 0:
            summary += f"MEDIUM PRIORITY: Review and address {data.get('medium_count')} medium-severity findings.\n"

        summary += f"""

NEXT STEPS
==========
1. Review detailed findings in the comprehensive report
2. Prioritize remediation based on risk levels
3. Implement security controls for identified vulnerabilities
4. Schedule regular security assessments
5. Consider additional manual testing for critical systems

DISCLAIMER
==========
This automated assessment provides initial security insights.
Manual testing and expert review are recommended for comprehensive security evaluation.

Generated by Auto-Pentest Framework v{data.get('version', 'Unknown')}
"""

        return summary

    def get_findings_summary(
        self, results: Union[ScanResult, List[ScanResult]]
    ) -> Dict[str, Any]:
        """Get a quick summary of findings"""
        if isinstance(results, ScanResult):
            results = [results]

        all_findings = []
        for result in results:
            if result.findings:
                all_findings.extend(result.findings)

        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)

        for finding in all_findings:
            severity = self._safe_severity_conversion(finding.get("severity", "info"))
            category = finding.get("category", "unknown")
            severity_counts[severity] += 1
            category_counts[category] += 1

        return {
            "total_findings": len(all_findings),
            "severity_breakdown": dict(severity_counts),
            "category_breakdown": dict(category_counts),
            "scanners_used": [r.scanner_name for r in results],
            "targets_scanned": list(set(r.target for r in results)),
        }

    def _safe_severity_conversion(self, severity_value):
        """Safely convert severity to string, handling both enum objects and strings"""
        if hasattr(severity_value, "value"):
            # It's a ScanSeverity enum object
            return severity_value.value.lower()
        elif isinstance(severity_value, str):
            # It's already a string
            return severity_value.lower()
        else:
            # Fallback for unknown types
            return str(severity_value).lower()


def generate_comprehensive_report(
    results: Union[ScanResult, List[ScanResult]],
    output_dir: Path,
    report_name: Optional[str] = None,
    include_pdf: bool = False,
    branding: Optional[Dict] = None,
) -> Dict[str, Path]:
    """
    Generate comprehensive report in multiple formats

    Args:
        results: Scan results
        output_dir: Output directory
        report_name: Optional report name prefix
        include_pdf: Whether to generate PDF report
        branding: Custom branding options

    Returns:
        Dict: Generated report files
    """
    reporter = ReportGenerator(branding=branding)

    if isinstance(results, ScanResult):
        results = [results]

    # Generate report name if not provided
    if not report_name:
        target = results[0].target if results else "unknown"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"security_report_{target.replace('://', '_').replace('/', '_')}_{timestamp}"

    output_dir.mkdir(parents=True, exist_ok=True)
    generated_files = {}

    # HTML Report
    html_path = output_dir / f"{report_name}.html"
    if reporter.generate_html_report(results, html_path):
        generated_files["html"] = html_path

    # PDF Report (if requested and available)
    if include_pdf:
        pdf_path = output_dir / f"{report_name}.pdf"
        if reporter.generate_pdf_report(results, pdf_path):
            generated_files["pdf"] = pdf_path

    # Executive Summary
    exec_path = output_dir / f"{report_name}_executive_summary.txt"
    if reporter.generate_executive_summary(results, exec_path):
        generated_files["executive"] = exec_path

    # JSON Report
    json_path = output_dir / f"{report_name}.json"
    if reporter.generate_json_report(results, json_path):
        generated_files["json"] = json_path

    return generated_files
