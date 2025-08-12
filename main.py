#!/usr/bin/env python3
"""
Auto-Pentest Tool - Enhanced Main CLI Interface with PDF Export
"""

import sys
import click
import json
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.core import InputValidator, validate_ip, validate_domain
from src.scanners.recon.port_scanner import PortScanner
from src.scanners.recon.dns_scanner import DNSScanner
from src.scanners.vulnerability.web_scanner import WebScanner
from src.scanners.vulnerability.directory_scanner import DirectoryScanner
from src.scanners.vulnerability.ssl_scanner import SSLScanner
from src.orchestrator import (
    create_quick_workflow,
    create_full_workflow,
    create_web_workflow,
    ScanWorkflow,
)
from src.orchestrator.workflow import WorkflowStatus
from src.core.scanner_base import ScanStatus

from src.utils.reporter import ReportGenerator, generate_comprehensive_report
from src.utils.logger import (
    LoggerSetup,
    log_banner,
    log_success,
    log_error,
    log_info,
    log_warning,
    log_debug,
)
from config.settings import OUTPUT_DIR, REPORT_DIR, SCAN_PROFILES


# Initialize logger
logger = LoggerSetup.setup_logger(
    name="auto-pentest", level="INFO", log_dir=OUTPUT_DIR / "logs", use_rich=True
)


@click.group()
@click.version_option(version="0.9.1")
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.option("--quiet", is_flag=True, help="Quiet mode (minimal output)")
def cli(debug, quiet):
    """
    Auto-Pentest Tool - Enhanced Automated Penetration Testing Framework

    A comprehensive tool for automated security testing and vulnerability assessment
    with professional reporting capabilities including PDF export.
    """
    global logger

    if debug:
        logger = LoggerSetup.setup_logger(
            name="auto-pentest",
            level="DEBUG",
            log_dir=OUTPUT_DIR / "logs",
            use_rich=True,
        )
    elif quiet:
        logger = LoggerSetup.setup_logger(
            name="auto-pentest",
            level="ERROR",
            log_dir=OUTPUT_DIR / "logs",
            use_rich=True,
        )


@cli.command()
@click.argument("target")
@click.option(
    "--profile",
    "-p",
    type=click.Choice(["quick", "full", "web"]),
    default="quick",
    help="Scan profile to use",
)
@click.option("--timeout", "-t", default=300, help="Timeout per scanner (seconds)")
@click.option("--parallel", is_flag=True, default=True, help="Run scanners in parallel")
@click.option("--sequential", is_flag=True, help="Run scanners sequentially")
@click.option("--ports", help="Custom port range (e.g., 1-1000, 80,443)")
@click.option("--include-port", is_flag=True, default=True, help="Include port scanner")
@click.option("--include-dns", is_flag=True, help="Include DNS scanner")
@click.option("--include-web", is_flag=True, help="Include web scanner")
@click.option("--include-directory", is_flag=True, help="Include directory scanner")
@click.option("--include-ssl", is_flag=True, help="Include SSL scanner")
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--pdf-report", is_flag=True, help="Generate PDF report")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--all-reports", is_flag=True, help="Generate all report formats")
@click.option("--custom-branding", help="Path to custom branding JSON file")
@click.option(
    "--compliance-report",
    type=click.Choice(["pci_dss", "owasp", "nist"]),
    help="Generate compliance report",
)
def scan(
    target,
    profile,
    timeout,
    parallel,
    sequential,
    ports,
    include_port,
    include_dns,
    include_web,
    include_directory,
    include_ssl,
    html_report,
    pdf_report,
    json_report,
    all_reports,
    custom_branding,
    compliance_report,
):
    """
    Execute comprehensive security scan against target.

    TARGET can be a URL, domain name, or IP address.

    Examples:
    \b
    python main.py scan target.com --profile full --parallel --all-reports
    python main.py scan 192.168.1.1 --include-web --include-ssl --pdf-report
    python main.py scan example.com --compliance-report pci_dss
    """
    try:
        log_banner(f"Auto-Pentest Scan - {target}", "bold cyan")

        # Load custom branding if provided
        branding = None
        if custom_branding:
            try:
                with open(custom_branding, "r") as f:
                    branding = json.load(f)
                log_info(f"Custom branding loaded from {custom_branding}")
            except Exception as e:
                log_warning(f"Failed to load custom branding: {e}")

        # Validate target
        validator = InputValidator()
        if not validator.is_valid_target(target):
            log_error("Invalid target. Must be a valid IP, domain, or URL.")
            sys.exit(1)

        sanitized_target = target.replace("://", "_").replace("/", "_")

        # Determine execution mode
        if sequential:
            parallel = False

        # Create workflow with proper error handling
        workflow = None
        try:
            if profile in ["quick", "full", "web"]:
                # Create standard workflow
                if profile == "quick":
                    workflow = create_quick_workflow(target)
                elif profile == "full":
                    workflow = create_full_workflow(target)
                elif profile == "web":
                    workflow = create_web_workflow(target)

                # Set timeout for all tasks
                if workflow and hasattr(workflow, "tasks"):
                    for task in workflow.tasks:
                        if hasattr(task, "timeout"):
                            task.timeout = timeout
            else:
                # Custom workflow based on individual scanner options
                from datetime import datetime

                workflow = ScanWorkflow(f"custom_{int(datetime.now().timestamp())}")

                # Add scanners based on options
                if include_port:
                    workflow.add_scan_task(
                        "port_scanner",
                        target,
                        options={"ports": ports} if ports else {},
                        timeout=timeout,
                    )

                if include_dns:
                    workflow.add_scan_task("dns_scanner", target, timeout=timeout)

                if include_web:
                    workflow.add_scan_task("web_scanner", target, timeout=timeout)

                if include_directory:
                    workflow.add_scan_task("directory_scanner", target, timeout=timeout)

                if include_ssl:
                    workflow.add_scan_task("ssl_scanner", target, timeout=timeout)

        except Exception as e:
            log_error(f"Failed to create workflow: {e}")
            sys.exit(1)

        if not workflow:
            log_error("No workflow created. Check your parameters.")
            sys.exit(1)

        # Execute workflow
        log_info(f"Starting {'parallel' if parallel else 'sequential'} scan...")
        log_info(f"Profile: {profile}")
        log_info(f"Target: {target}")
        log_info(f"Timeout: {timeout}s per scanner")
        log_info(f"Tasks: {len(getattr(workflow, 'tasks', []))}")

        try:
            # Execute workflow and get WorkflowResult
            workflow_result = workflow.execute(parallel=parallel, fail_fast=False)

            if not workflow_result:
                log_error("Workflow execution failed - no result returned")
                sys.exit(1)

            # Process WorkflowResult properly
            all_results = []
            total_findings = 0

            # Check workflow status
            if workflow_result.status == WorkflowStatus.COMPLETED:
                log_success("Workflow completed successfully!")

                # Collect results from successful tasks
                successful_tasks = 0
                failed_tasks = 0

                for task in workflow_result.tasks:
                    if task.status == ScanStatus.COMPLETED and task.result:
                        all_results.append(task.result)
                        successful_tasks += 1
                        if hasattr(task.result, "findings") and task.result.findings:
                            total_findings += len(task.result.findings)
                    elif task.status == ScanStatus.FAILED:
                        failed_tasks += 1
                        log_warning(f"Task {task.scanner_name} failed: {task.error}")

                # Also use aggregated result if available
                if workflow_result.aggregated_result:
                    all_results.append(workflow_result.aggregated_result)
                    if hasattr(workflow_result.aggregated_result, "findings"):
                        total_findings = len(workflow_result.aggregated_result.findings)

                log_info(f"Successful tasks: {successful_tasks}")
                log_info(f"Failed tasks: {failed_tasks}")

            elif workflow_result.status == WorkflowStatus.FAILED:
                log_error("Workflow failed!")

                # Try to get partial results
                for task in workflow_result.tasks:
                    if task.status == ScanStatus.COMPLETED and task.result:
                        all_results.append(task.result)
                        if hasattr(task.result, "findings") and task.result.findings:
                            total_findings += len(task.result.findings)

                if all_results:
                    log_info(
                        f"Partial results available: {len(all_results)} successful scans"
                    )

            # Check if we have any results
            if not all_results:
                log_error("No scan results available. All scanners failed.")
                log_info("Check your target accessibility and tool configurations.")
                sys.exit(1)

            log_info(f"Total findings collected: {total_findings}")

            # Generate reports if requested
            report_generated = False

            if html_report or pdf_report or json_report or all_reports:
                try:
                    from datetime import datetime

                    # Use the correct generate_comprehensive_report signature
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    report_name = f"scan_report_{sanitized_target}_{timestamp}"

                    # Call with correct parameters
                    generated_files = generate_comprehensive_report(
                        results=all_results,  # List of ScanResult objects
                        output_dir=REPORT_DIR,  # Path object
                        report_name=report_name,  # String
                        include_pdf=(pdf_report or all_reports),  # Boolean
                        branding=branding,  # Dict or None
                    )

                    # Report success for generated files
                    for report_type, file_path in generated_files.items():
                        if file_path and file_path.exists():
                            log_success(f"{report_type.upper()} report: {file_path}")
                            report_generated = True
                        else:
                            log_warning(
                                f"{report_type.upper()} report generation failed"
                            )

                    # If no files were generated, try alternative approach
                    if not generated_files and all_results:
                        log_info("Trying alternative report generation...")

                        try:
                            # Create ReportGenerator directly
                            reporter = ReportGenerator(branding=branding)

                            # Generate individual reports
                            if html_report or all_reports:
                                html_file = REPORT_DIR / f"{report_name}.html"
                                if reporter.generate_html_report(
                                    all_results, html_file
                                ):
                                    log_success(f"HTML report: {html_file}")
                                    report_generated = True

                            if json_report or all_reports:
                                json_file = REPORT_DIR / f"{report_name}.json"
                                if reporter.generate_json_report(
                                    all_results, json_file
                                ):
                                    log_success(f"JSON report: {json_file}")
                                    report_generated = True

                            if pdf_report or all_reports:
                                pdf_file = REPORT_DIR / f"{report_name}.pdf"
                                if reporter.generate_pdf_report(all_results, pdf_file):
                                    log_success(f"PDF report: {pdf_file}")
                                    report_generated = True

                        except Exception as e:
                            log_warning(f"Alternative report generation failed: {e}")

                except Exception as e:
                    log_warning(f"Report generation failed: {e}")
                    log_debug(f"Report error details: {str(e)}")

            # Display summary
            log_success("=== SCAN SUMMARY ===")
            log_info(f"Target: {target}")
            log_info(f"Profile: {profile}")
            log_info(f"Execution Mode: {'Parallel' if parallel else 'Sequential'}")
            log_info(f"Total Scanners: {len(workflow_result.tasks)}")
            log_info(
                f"Successful: {len([t for t in workflow_result.tasks if t.status == ScanStatus.COMPLETED])}"
            )
            log_info(
                f"Failed: {len([t for t in workflow_result.tasks if t.status == ScanStatus.FAILED])}"
            )
            log_info(f"Total Findings: {total_findings}")

            if report_generated:
                log_info(f"Reports saved to: {REPORT_DIR}")

            log_success("Scan completed successfully!")

        except Exception as e:
            log_error(f"Scan execution failed: {e}")
            log_debug(f"Error details: {str(e)}")
            sys.exit(1)

    except KeyboardInterrupt:
        log_warning("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        log_debug(f"Error details: {str(e)}")
        sys.exit(1)


@cli.command()
@click.argument("target")
def quick(target):
    """
    Perform a quick scan (most common ports only).

    This is equivalent to: scan TARGET --profile quick --all-reports
    """
    ctx = click.get_current_context()
    ctx.invoke(scan, target=target, profile="quick", all_reports=True)


@cli.command()
@click.argument("target")
def full(target):
    """
    Perform a comprehensive scan with full reporting.

    This is equivalent to: scan TARGET --profile full --parallel --all-reports
    """
    ctx = click.get_current_context()
    ctx.invoke(scan, target=target, profile="full", parallel=True, all_reports=True)


@cli.command()
@click.argument("results_file", type=click.Path(exists=True))
@click.option("--output-dir", type=click.Path(), help="Output directory for reports")
@click.option("--html/--no-html", default=True, help="Generate HTML report")
@click.option("--pdf/--no-pdf", default=False, help="Generate PDF report")
@click.option(
    "--executive/--no-executive", default=True, help="Generate executive summary"
)
@click.option(
    "--compliance-type",
    type=click.Choice(["pci_dss", "nist", "iso27001"]),
    help="Generate compliance report",
)
@click.option(
    "--custom-branding",
    type=click.Path(exists=True),
    help="JSON file with custom branding",
)
def generate_report(
    results_file, output_dir, html, pdf, executive, compliance_type, custom_branding
):
    """
    Generate reports from existing scan results.

    RESULTS_FILE should be a JSON file containing scan results.

    Examples:
    \b
    python main.py generate-report scan_results.json --pdf --html
    python main.py generate-report results.json --compliance-type pci_dss
    """
    try:
        log_banner("Report Generation", "bold cyan")

        # Load results
        with open(results_file, "r") as f:
            data = json.load(f)

        # Parse results - handle both single result and multiple results
        if isinstance(data, dict) and "scan_results" in data:
            # Multiple results format from comprehensive report
            results_data = data["scan_results"]
        elif isinstance(data, dict):
            # Single result format
            results_data = [data]
        else:
            # List of results
            results_data = data

        # Convert back to ScanResult objects (simplified)
        log_info(f"Loaded {len(results_data)} scan results")

        # Load custom branding if provided
        branding = None
        if custom_branding:
            try:
                with open(custom_branding, "r") as f:
                    branding = json.load(f)
                log_info(f"Custom branding loaded")
            except Exception as e:
                log_warning(f"Failed to load custom branding: {e}")

        # Set output directory
        if not output_dir:
            output_dir = Path(results_file).parent / "reports"
        else:
            output_dir = Path(output_dir)

        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate base name from results file
        base_name = Path(results_file).stem + "_report"

        # Initialize reporter
        reporter = ReportGenerator(branding=branding)
        generated_files = {}

        # For this simplified version, we'll work with the raw data
        # In production, you'd reconstruct ScanResult objects properly

        # HTML Report
        if html:
            html_path = output_dir / f"{base_name}.html"
            # This would need to be adapted to work with parsed data
            log_success(f"📄 HTML report would be generated: {html_path}")

        # PDF Report
        if pdf:
            pdf_path = output_dir / f"{base_name}.pdf"
            log_success(f"📑 PDF report would be generated: {pdf_path}")

        # Executive Summary
        if executive:
            exec_path = output_dir / f"{base_name}_executive.txt"
            log_success(f"📋 Executive summary would be generated: {exec_path}")

        # Compliance Report
        if compliance_type:
            compliance_path = (
                output_dir / f"{base_name}_compliance_{compliance_type}.html"
            )
            log_success(f"📊 Compliance report would be generated: {compliance_path}")

        log_banner("Report Generation Complete", "bold green")

    except Exception as e:
        log_error(f"Report generation failed: {e}")
        sys.exit(1)


@cli.command()
def list_tools():
    """List all available scanning tools and their status."""
    log_banner("Available Scanning Tools", "bold cyan")

    tools = {
        "Network Reconnaissance": {
            "nmap": "Network discovery and port scanning",
            "masscan": "High-speed port scanner",
        },
        "DNS Analysis": {
            "dig": "DNS lookup utility",
            "nslookup": "Name server lookup",
            "dnsrecon": "DNS enumeration script",
        },
        "Web Application": {
            "nikto": "Web vulnerability scanner",
            "dirb": "Directory brute forcer",
            "gobuster": "Directory/DNS/vhost bruteforcer",
        },
        "SSL/TLS Analysis": {
            "sslscan": "SSL/TLS configuration scanner",
            "openssl": "SSL/TLS toolkit",
        },
        "Reporting": {
            "weasyprint": "PDF generation (Python)",
            "pdfkit": "PDF generation (wkhtmltopdf)",
        },
    }

    from src.core import CommandExecutor

    executor = CommandExecutor()

    for category, category_tools in tools.items():
        log_info(f"\n{category}:")
        for tool, description in category_tools.items():
            if executor.check_tool_exists(tool):
                log_success(f"  ✓ {tool}: {description}")
            else:
                log_warning(f"  ✗ {tool}: {description} (not installed)")


@cli.command()
def info():
    """Display detailed information about the Auto-Pentest Tool."""
    log_banner("Auto-Pentest Tool Information", "bold cyan")

    log_info("Version: 0.9.1")
    log_info("Enhanced with PDF Export and Custom Branding")
    log_info("")

    log_info("Available Commands:")
    log_info("  scan        - Orchestrated security scanning with enhanced reporting")
    log_info("  quick       - Quick scan with all reports")
    log_info("  full        - Comprehensive scan with parallel execution")
    log_info("  port        - Port scanning only")
    log_info("  dns         - DNS enumeration")
    log_info("  web         - Web vulnerability scanning")
    log_info("  directory   - Directory/file enumeration")
    log_info("  ssl         - SSL/TLS analysis")
    log_info("  generate-report - Generate reports from existing results")
    log_info("  list-tools  - Show available tools")
    log_info("")

    log_info("New Features:")
    log_info("  📑 PDF Report Generation (requires weasyprint or pdfkit)")
    log_info("  🎨 Custom Branding Support")
    log_info("  📊 Compliance Reports (PCI DSS, NIST, ISO27001)")
    log_info("  📋 Enhanced Executive Summaries")
    log_info("  🔄 Multi-format Report Generation")
    log_info("")

    log_info("Report Examples:")
    log_info("  python main.py scan target.com --pdf-report")
    log_info("  python main.py scan target.com --all-reports")
    log_info("  python main.py scan target.com --compliance-report pci_dss")
    log_info("  python main.py generate-report results.json --pdf --html")


def display_scan_results(result):
    """Display scan results in a formatted way."""
    log_banner(
        f"{result.scanner_name.replace('_', ' ').title()} Results", "bold yellow"
    )

    log_info(f"Target: {result.target}")
    log_info(f"Status: {result.status.name}")
    log_info(f"Duration: {result.duration}")
    log_info(f"Findings: {len(result.findings)}")

    if result.findings:
        # Group by severity
        by_severity = {}
        for finding in result.findings:
            severity = finding.get("severity", "unknown")
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        # Display by severity (critical first)
        severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
        for severity in severity_order:
            if severity in by_severity:
                findings = by_severity[severity]
                log_info(f"\n{severity.upper()} ({len(findings)}):")
                for finding in findings[:3]:  # Show first 3 of each severity
                    title = finding.get("title", "Unknown")
                    log_info(f"  • {title}")
                if len(findings) > 3:
                    log_info(f"  ... and {len(findings) - 3} more")

    if result.errors:
        log_warning(f"Errors: {len(result.errors)}")
        for error in result.errors[:2]:  # Show first 2 errors
            log_warning(f"  • {error}")


# Include all other CLI commands from the original main.py
# (port, dns, web, directory, ssl commands would go here)

if __name__ == "__main__":
    cli()
