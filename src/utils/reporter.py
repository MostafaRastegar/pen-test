"""
Enhanced Reporter - Generate professional HTML and text reports
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

from src.core import ScanResult, ScanSeverity
from src.utils.logger import log_info, log_error, log_warning, log_success


class ReportGenerator:
    """
    Professional report generator with multiple output formats
    """

    def __init__(self, template_dir: Optional[Path] = None):
        """
        Initialize report generator

        Args:
            template_dir: Directory containing report templates
        """
        self.template_dir = (
            template_dir or Path(__file__).parent.parent.parent / "templates"
        )
        self.version = "0.9.0"

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

    def _aggregate_report_data(
        self, results: List[ScanResult], title: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Aggregate data from multiple scan results

        Args:
            results: List of scan results
            title: Optional custom title

        Returns:
            Dict: Aggregated report data
        """
        if not results:
            return {}

        # Basic metadata
        first_result = results[0]
        all_findings = []
        scanners_used = []

        # Aggregate findings and metadata
        for result in results:
            if result.findings:
                all_findings.extend(result.findings)
            scanners_used.append(result.scanner_name)

        # Calculate timing
        start_times = [r.start_time for r in results if r.start_time]
        end_times = [r.end_time for r in results if r.end_time]

        if start_times and end_times:
            scan_start = min(start_times)
            scan_end = max(end_times)
            duration = scan_end - scan_start
        else:
            scan_start = datetime.now()
            duration = timedelta(0)

        # Count findings by severity
        severity_counts = defaultdict(int)
        for finding in all_findings:
            severity = finding.get("severity", "info")
            severity_counts[severity] += 1

        # Group findings by category
        findings_by_category = defaultdict(list)
        for finding in all_findings:
            category = finding.get("category", "unknown")
            findings_by_category[category].append(finding)

        # Calculate risk level
        if severity_counts.get("critical", 0) > 0:
            overall_risk = "Critical"
        elif severity_counts.get("high", 0) > 0:
            overall_risk = "High"
        elif severity_counts.get("medium", 0) > 0:
            overall_risk = "Medium"
        elif severity_counts.get("low", 0) > 0:
            overall_risk = "Low"
        else:
            overall_risk = "Informational"

        return {
            "title": title or f"Security Assessment - {first_result.target}",
            "target": first_result.target,
            "scan_date": scan_start.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_duration": str(duration).split(".")[0],  # Remove microseconds
            "scanners_used": list(set(scanners_used)),
            "total_findings": len(all_findings),
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
            "medium_count": severity_counts.get("medium", 0),
            "low_count": severity_counts.get("low", 0),
            "info_count": severity_counts.get("info", 0),
            "overall_risk": overall_risk,
            "findings_by_category": dict(findings_by_category),
            "version": self.version,
            "report_id": f"APT-{int(scan_start.timestamp())}",
        }

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
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report - {data.get('target', 'Unknown')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; padding: 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .findings {{ margin-bottom: 30px; }}
        .finding {{ background: white; border: 1px solid #ddd; border-radius: 8px; margin-bottom: 15px; padding: 20px; }}
        .critical {{ border-left: 5px solid #e74c3c; }}
        .high {{ border-left: 5px solid #f39c12; }}
        .medium {{ border-left: 5px solid #f1c40f; }}
        .low {{ border-left: 5px solid #27ae60; }}
        .info {{ border-left: 5px solid #3498db; }}
        .severity {{ display: inline-block; padding: 4px 12px; border-radius: 15px; font-weight: bold; font-size: 0.8em; }}
        .severity.critical {{ background: #e74c3c; color: white; }}
        .severity.high {{ background: #f39c12; color: white; }}
        .severity.medium {{ background: #f1c40f; color: #2c3e50; }}
        .severity.low {{ background: #27ae60; color: white; }}
        .severity.info {{ background: #3498db; color: white; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .metadata {{ background: #ecf0f1; padding: 15px; border-radius: 8px; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <p>Target: {data.get('target', 'Unknown')} | Generated: {data.get('scan_date', 'Unknown')}</p>
        </div>

        <div class="summary">
            <h2>Executive Summary</h2>
            <p><strong>Total Findings:</strong> {data.get('total_findings', 0)}</p>
            <p><strong>Overall Risk Level:</strong> {data.get('overall_risk', 'Unknown')}</p>
            <p><strong>Scanners Used:</strong> {', '.join(data.get('scanners_used', []))}</p>
            <p><strong>Scan Duration:</strong> {data.get('scan_duration', 'Unknown')}</p>

            <h3>Risk Breakdown</h3>
            <ul>
                <li>Critical: {data.get('critical_count', 0)}</li>
                <li>High: {data.get('high_count', 0)}</li>
                <li>Medium: {data.get('medium_count', 0)}</li>
                <li>Low: {data.get('low_count', 0)}</li>
                <li>Informational: {data.get('info_count', 0)}</li>
            </ul>
        </div>
"""

        # Add findings by category
        findings_by_category = data.get("findings_by_category", {})
        for category, findings in findings_by_category.items():
            html += f"""
        <div class="findings">
            <h2>{category.replace('_', ' ').title()} ({len(findings)} findings)</h2>
"""
            for finding in findings:
                severity = finding.get("severity", "info")
                html += f"""
            <div class="finding {severity}">
                <h3>{finding.get('title', 'Unknown Finding')}
                    <span class="severity {severity}">{severity.upper()}</span>
                </h3>
                <p>{finding.get('description', 'No description available')}</p>
"""
                if finding.get("recommendation"):
                    html += f"<p><strong>Recommendation:</strong> {finding.get('recommendation')}</p>"

                html += "</div>"

            html += "</div>"

        # Add metadata
        html += f"""
        <div class="metadata">
            <h3>Scan Information</h3>
            <p><strong>Report ID:</strong> {data.get('report_id', 'Unknown')}</p>
            <p><strong>Generated by:</strong> Auto-Pentest Framework v{data.get('version', 'Unknown')}</p>
        </div>
    </div>
</body>
</html>"""

        return html

    def _create_executive_summary(self, results: List[ScanResult]) -> str:
        """Create executive summary text"""
        data = self._aggregate_report_data(results)

        summary = f"""
EXECUTIVE SUMMARY - SECURITY ASSESSMENT
{'=' * 50}

Target: {data.get('target', 'Unknown')}
Assessment Date: {data.get('scan_date', 'Unknown')}
Duration: {data.get('scan_duration', 'Unknown')}
Report ID: {data.get('report_id', 'Unknown')}

RISK ASSESSMENT
{'-' * 20}
Overall Risk Level: {data.get('overall_risk', 'Unknown')}
Total Security Findings: {data.get('total_findings', 0)}

Risk Breakdown:
• Critical Issues: {data.get('critical_count', 0)}
• High Risk Issues: {data.get('high_count', 0)}
• Medium Risk Issues: {data.get('medium_count', 0)}
• Low Risk Issues: {data.get('low_count', 0)}
• Informational: {data.get('info_count', 0)}

SCAN COVERAGE
{'-' * 20}
Assessment Methods: {', '.join(data.get('scanners_used', []))}
Total Scan Modules: {len(data.get('scanners_used', []))}

SUMMARY OF FINDINGS
{'-' * 20}
"""

        # Add top findings by category
        findings_by_category = data.get("findings_by_category", {})
        for category, findings in findings_by_category.items():
            if findings:
                summary += f"\n{category.replace('_', ' ').title()}:\n"
                # Show top 3 findings per category
                for finding in findings[:3]:
                    severity = finding.get("severity", "info").upper()
                    title = finding.get("title", "Unknown")
                    summary += f"  [{severity}] {title}\n"

                if len(findings) > 3:
                    summary += f"  ... and {len(findings) - 3} more findings\n"

        # Add recommendations
        critical_count = data.get("critical_count", 0)
        high_count = data.get("high_count", 0)

        summary += f"""

RECOMMENDATIONS
{'-' * 20}
"""

        if critical_count > 0:
            summary += f"• IMMEDIATE ACTION REQUIRED: {critical_count} critical security issues require immediate attention\n"

        if high_count > 0:
            summary += f"• HIGH PRIORITY: {high_count} high-risk issues should be addressed within 30 days\n"

        if critical_count == 0 and high_count == 0:
            summary += "• No critical or high-risk issues identified\n"
            summary += "• Continue monitoring and maintain current security posture\n"

        summary += f"""
• Review the detailed technical report for specific remediation steps
• Consider implementing additional security monitoring
• Schedule regular security assessments

This assessment was conducted using automated tools and may not identify all potential security issues.
Manual testing and expert review are recommended for comprehensive security evaluation.

Generated by Auto-Pentest Framework v{data.get('version', 'Unknown')}
"""

        return summary

    def get_findings_summary(
        self, results: Union[ScanResult, List[ScanResult]]
    ) -> Dict[str, Any]:
        """
        Get a quick summary of findings

        Args:
            results: Scan results

        Returns:
            Dict: Summary statistics
        """
        if isinstance(results, ScanResult):
            results = [results]

        all_findings = []
        for result in results:
            if result.findings:
                all_findings.extend(result.findings)

        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)

        for finding in all_findings:
            severity = finding.get("severity", "info")
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


def generate_comprehensive_report(
    results: Union[ScanResult, List[ScanResult]],
    output_dir: Path,
    report_name: Optional[str] = None,
) -> Dict[str, Path]:
    """
    Generate comprehensive report in multiple formats

    Args:
        results: Scan results
        output_dir: Output directory
        report_name: Optional report name prefix

    Returns:
        Dict: Generated report files
    """
    reporter = ReportGenerator()

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

    # Executive Summary
    exec_path = output_dir / f"{report_name}_executive_summary.txt"
    if reporter.generate_executive_summary(results, exec_path):
        generated_files["executive"] = exec_path

    # JSON Report
    json_path = output_dir / f"{report_name}.json"
    if reporter.generate_json_report(results, json_path):
        generated_files["json"] = json_path

    return generated_files
