"""
Report Service
Handles all report generation operations
Following Single Responsibility Principle
"""

import json
from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime

from ..utils.reporter import ReportGenerator, generate_comprehensive_report
from ..utils.logger import log_info, log_error, log_success, log_warning


class ReportService:
    """Service for generating various types of reports"""

    def __init__(self):
        self.report_generator = ReportGenerator()
        self.output_dir = Path("output/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_reports(self, workflow_result, options: Dict[str, Any]) -> None:
        """
        Generate reports based on options

        Args:
            workflow_result: Completed workflow result with results
            options: Report generation options
        """
        try:
            # Determine which reports to generate
            reports_to_generate = self._get_report_types(options)

            if not reports_to_generate:
                log_info("📄 No reports requested")
                return

            log_info(f"📄 Generating {len(reports_to_generate)} report type(s)")

            # Generate each requested report type
            for report_type in reports_to_generate:
                self._generate_single_report(workflow_result, report_type, options)

            log_success("✅ All reports generated successfully")

        except Exception as e:
            log_error(f"❌ Report generation failed: {e}")
            raise

    def _get_report_types(self, options: Dict[str, Any]) -> List[str]:
        """Determine which report types to generate"""
        report_types = []

        if options.get("all_reports") or options.get("all_formats"):
            return ["json", "html", "pdf", "txt", "csv"]

        if options.get("json_report") or options.get("json_output"):
            report_types.append("json")
        if options.get("html_report") or options.get("html_output"):
            report_types.append("html")
        if options.get("pdf_report") or options.get("pdf_output"):
            report_types.append("pdf")
        if options.get("txt_output"):
            report_types.append("txt")
        if options.get("csv_output"):
            report_types.append("csv")

        # Default to JSON if no specific format requested
        if not report_types and options.get("output"):
            report_types.append("json")

        return report_types

    def _generate_single_report(
        self, workflow_result, report_type: str, options: Dict[str, Any]
    ) -> None:
        """Generate a single report of specified type"""
        try:
            log_info(f"📄 Generating {report_type.upper()} report...")

            # Get output filename
            output_file = self._get_output_filename(
                workflow_result, report_type, options
            )

            # Generate report based on type
            if report_type == "json":
                self._generate_json_report(workflow_result, output_file, options)
            elif report_type == "html":
                self._generate_html_report(workflow_result, output_file, options)
            elif report_type == "pdf":
                self._generate_pdf_report(workflow_result, output_file, options)
            elif report_type == "txt":
                self._generate_txt_report(workflow_result, output_file, options)
            elif report_type == "csv":
                self._generate_csv_report(workflow_result, output_file, options)
            else:
                log_warning(f"Unknown report type: {report_type}")
                return

            log_success(f"✅ {report_type.upper()} report saved: {output_file}")

        except Exception as e:
            log_error(f"❌ Failed to generate {report_type} report: {e}")
            raise

    def _get_output_filename(
        self, workflow_result, report_type: str, options: Dict[str, Any]
    ) -> Path:
        """Generate output filename"""
        # Get base directory
        if options.get("output"):
            base_dir = Path(options["output"])
        else:
            base_dir = self.output_dir

        base_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename - properly clean target name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_name = workflow_result.target

        # Clean target name for filename
        target_name = target_name.replace("https://", "").replace("http://", "")
        target_name = target_name.replace(".", "_").replace(":", "_").replace("/", "_")

        filename = f"scan_{target_name}_{timestamp}.{report_type}"

        return base_dir / filename

    def _generate_json_report(
        self, workflow_result, output_file: Path, options: Dict[str, Any]
    ) -> None:
        """Generate JSON report"""
        # Convert WorkflowResult to format expected by ReportGenerator
        scan_results = []
        for task in workflow_result.tasks:
            if task.result:
                scan_results.append(task.result)

        # If no scan results, create a simple report manually
        if not scan_results:
            report_data = {
                "metadata": {
                    "target": workflow_result.target,
                    "workflow_id": workflow_result.workflow_id,
                    "status": workflow_result.status.value,
                    "start_time": workflow_result.start_time.isoformat(),
                    "end_time": (
                        workflow_result.end_time.isoformat()
                        if workflow_result.end_time
                        else None
                    ),
                    "total_tasks": len(workflow_result.tasks),
                    "total_findings": 0,
                },
                "findings": [],
                "tasks": [],
            }
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        else:
            # Use ReportGenerator for proper results
            success = self.report_generator.generate_json_report(
                scan_results, output_file
            )
            if not success:
                raise RuntimeError("JSON report generation failed")

    def _generate_html_report(
        self, workflow_result, output_file: Path, options: Dict[str, Any]
    ) -> None:
        """Generate HTML report"""
        # Convert WorkflowResult to format expected by ReportGenerator
        scan_results = []
        for task in workflow_result.tasks:
            if task.result:
                scan_results.append(task.result)

        if scan_results:
            title = f"Security Assessment Report - {workflow_result.target}"
            success = self.report_generator.generate_html_report(
                scan_results, output_file, title
            )
            if not success:
                raise RuntimeError("HTML report generation failed")
        else:
            # Generate simple HTML for empty results
            html_content = self._generate_empty_html_report(workflow_result)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

    def _generate_pdf_report(
        self, workflow_result, output_file: Path, options: Dict[str, Any]
    ) -> None:
        """Generate PDF report"""
        try:
            # Convert WorkflowResult to format expected by ReportGenerator
            scan_results = []
            for task in workflow_result.tasks:
                if task.result:
                    scan_results.append(task.result)

            # Try to generate PDF report
            if scan_results:
                title = f"Security Assessment Report - {workflow_result.target}"
                success = self.report_generator.generate_pdf_report(
                    scan_results, output_file, title
                )
                if not success:
                    raise RuntimeError("PDF generation failed")
            else:
                # Generate simple PDF for empty results
                self._generate_empty_pdf_report(workflow_result, output_file)

        except ImportError as e:
            log_warning("PDF generation dependencies not available")
            log_info("Install: pip install weasyprint or pip install pdfkit")
            # Fall back to HTML report
            html_file = output_file.with_suffix(".html")
            self._generate_html_report(workflow_result, html_file, options)
            log_info(f"Generated HTML report instead: {html_file}")
        except Exception as e:
            log_error(f"PDF generation failed: {e}")
            raise

    def _generate_txt_report(
        self, workflow_result, output_file: Path, options: Dict[str, Any]
    ) -> None:
        """Generate plain text report"""
        # Convert WorkflowResult to format expected by ReportGenerator
        scan_results = []
        for task in workflow_result.tasks:
            if task.result:
                scan_results.append(task.result)

        if scan_results:
            # ReportGenerator doesn't have generate_txt_report, so create manually
            txt_content = self._generate_txt_from_results(scan_results, workflow_result)
        else:
            txt_content = self._generate_empty_txt_report(workflow_result)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(txt_content)

    def _generate_csv_report(
        self, workflow_result, output_file: Path, options: Dict[str, Any]
    ) -> None:
        """Generate CSV report"""
        # Convert WorkflowResult to format expected by ReportGenerator
        scan_results = []
        for task in workflow_result.tasks:
            if task.result:
                scan_results.append(task.result)

        if scan_results:
            # ReportGenerator doesn't have generate_csv_report, so create manually
            csv_content = self._generate_csv_from_results(scan_results, workflow_result)
        else:
            csv_content = self._generate_empty_csv_report(workflow_result)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(csv_content)

    def generate_quick_summary(self, workflow_result) -> str:
        """Generate a quick text summary for console output"""
        try:
            summary = []
            summary.append(f"📊 Scan Summary for {workflow_result.target}")
            summary.append("=" * 50)

            total_findings = 0
            findings_by_severity = {}

            for task in workflow_result.tasks:
                if task.result and task.result.findings:
                    total_findings += len(task.result.findings)

                    for finding in task.result.findings:
                        severity = finding.get("severity", "info")
                        findings_by_severity[severity] = (
                            findings_by_severity.get(severity, 0) + 1
                        )

            summary.append(f"Total Findings: {total_findings}")

            if findings_by_severity:
                summary.append("\nFindings by Severity:")
                for severity in ["critical", "high", "medium", "low", "info"]:
                    if severity in findings_by_severity:
                        summary.append(
                            f"  {severity.upper()}: {findings_by_severity[severity]}"
                        )

            summary.append(
                f"\nScan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )

            return "\n".join(summary)

        except Exception as e:
            log_error(f"Failed to generate summary: {e}")
            return f"Scan completed for {workflow_result.target}"

    def _generate_empty_html_report(self, workflow_result) -> str:
        """Generate simple HTML for empty results"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {workflow_result.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; }}
                .content {{ margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
                <p><strong>Target:</strong> {workflow_result.target}</p>
                <p><strong>Workflow ID:</strong> {workflow_result.workflow_id}</p>
                <p><strong>Status:</strong> {workflow_result.status.value}</p>
            </div>
            <div class="content">
                <h2>Scan Results</h2>
                <p>No findings were detected during this scan.</p>
                <p>Total tasks executed: {len(workflow_result.tasks)}</p>
            </div>
        </body>
        </html>
        """

    def _generate_empty_txt_report(self, workflow_result) -> str:
        """Generate simple text for empty results"""
        return f"""Security Scan Report
Target: {workflow_result.target}
Workflow ID: {workflow_result.workflow_id}
Status: {workflow_result.status.value}
Start Time: {workflow_result.start_time}
End Time: {workflow_result.end_time}

Scan Results:
No findings were detected during this scan.
Total tasks executed: {len(workflow_result.tasks)}
"""

    def _generate_empty_csv_report(self, workflow_result) -> str:
        """Generate simple CSV for empty results"""
        return f"""Target,Scanner,Severity,Finding,Description
{workflow_result.target},summary,info,"No findings","No security issues detected"
"""

    def _generate_empty_pdf_report(self, workflow_result, output_file: Path) -> None:
        """Generate simple PDF for empty results by creating HTML first"""
        html_content = self._generate_empty_html_report(workflow_result)
        html_file = output_file.with_suffix(".html")

        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        # Try to convert HTML to PDF
        try:
            import weasyprint

            weasyprint.HTML(filename=str(html_file)).write_pdf(str(output_file))
            html_file.unlink()  # Remove temporary HTML file
        except ImportError:
            log_info(f"Generated HTML report instead: {html_file}")
            # Keep HTML file as fallback

    def _generate_txt_from_results(self, scan_results, workflow_result) -> str:
        """Generate text report from scan results"""
        lines = []
        lines.append(f"Security Scan Report")
        lines.append("=" * 50)
        lines.append(f"Target: {workflow_result.target}")
        lines.append(f"Workflow ID: {workflow_result.workflow_id}")
        lines.append(f"Status: {workflow_result.status.value}")
        lines.append(f"Start Time: {workflow_result.start_time}")
        lines.append(f"End Time: {workflow_result.end_time}")
        lines.append("")

        total_findings = 0
        for result in scan_results:
            if result.findings:
                total_findings += len(result.findings)
                lines.append(f"Scanner: {result.scanner_name}")
                lines.append(f"Target: {result.target}")
                lines.append(f"Findings: {len(result.findings)}")
                lines.append("-" * 30)

                for finding in result.findings:
                    lines.append(f"  Title: {finding.get('title', 'Unknown')}")
                    lines.append(f"  Severity: {finding.get('severity', 'info')}")
                    lines.append(
                        f"  Description: {finding.get('description', 'No description')}"
                    )
                    lines.append("")
                lines.append("")

        lines.append(f"Total Findings: {total_findings}")
        return "\n".join(lines)

    def _generate_csv_from_results(self, scan_results, workflow_result) -> str:
        """Generate CSV report from scan results"""
        lines = []
        lines.append("Target,Scanner,Severity,Finding,Description")

        for result in scan_results:
            if result.findings:
                for finding in result.findings:
                    target = workflow_result.target
                    scanner = result.scanner_name
                    severity = finding.get("severity", "info")
                    title = finding.get("title", "Unknown").replace(",", ";")
                    description = finding.get("description", "No description").replace(
                        ",", ";"
                    )

                    lines.append(
                        f'"{target}","{scanner}","{severity}","{title}","{description}"'
                    )

        if len(lines) == 1:  # Only header
            lines.append(
                f'"{workflow_result.target}","summary","info","No findings","No security issues detected"'
            )

        return "\n".join(lines)
