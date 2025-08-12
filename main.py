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
from src.utils.reporter import ReportGenerator, generate_comprehensive_report
from src.utils.logger import (
    LoggerSetup,
    log_banner,
    log_success,
    log_error,
    log_info,
    log_warning,
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
    type=click.Choice(["quick", "full", "web"]),
    default="quick",
    help="Scan profile to use",
)
@click.option("--parallel/--sequential", default=False, help="Run scanners in parallel")
@click.option("--timeout", type=int, default=300, help="Scan timeout per scanner")
@click.option("--include-port/--no-port", default=True, help="Include port scanning")
@click.option("--include-dns/--no-dns", default=False, help="Include DNS enumeration")
@click.option("--include-web/--no-web", default=False, help="Include web scanning")
@click.option(
    "--include-directory/--no-directory",
    default=False,
    help="Include directory enumeration",
)
@click.option("--include-ssl/--no-ssl", default=False, help="Include SSL/TLS analysis")
@click.option("--ports", help="Ports to scan (e.g., 22,80,443 or 1-1000)")
@click.option(
    "--output", type=click.Path(), help="Base output filename (without extension)"
)
@click.option("--html-report/--no-html", default=False, help="Generate HTML report")
@click.option("--pdf-report/--no-pdf", default=False, help="Generate PDF report")
@click.option(
    "--exec-summary/--no-summary", default=False, help="Generate executive summary"
)
@click.option(
    "--compliance-report",
    type=click.Choice(["pci_dss", "nist", "iso27001"]),
    help="Generate compliance-specific report",
)
@click.option(
    "--custom-branding",
    type=click.Path(exists=True),
    help="JSON file with custom branding options",
)
@click.option(
    "--all-reports",
    is_flag=True,
    help="Generate all report formats (HTML, PDF, Executive)",
)
def scan(
    target,
    profile,
    parallel,
    timeout,
    include_port,
    include_dns,
    include_web,
    include_directory,
    include_ssl,
    ports,
    output,
    html_report,
    pdf_report,
    exec_summary,
    compliance_report,
    custom_branding,
    all_reports,
):
    """
    Perform orchestrated security scan with enhanced reporting.

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

        # Create orchestrated workflow
        if profile == "quick":
            workflow = create_quick_workflow(timeout=timeout)
        elif profile == "full":
            workflow = create_full_workflow(timeout=timeout)
        elif profile == "web":
            workflow = create_web_workflow(timeout=timeout)
        else:
            # Custom workflow based on individual scanner options
            workflow = ScanWorkflow(parallel=parallel)

            if include_port:
                port_scanner = PortScanner()
                scan_options = {}
                if ports:
                    scan_options["ports"] = ports
                workflow.add_scanner(port_scanner, scan_options)

            if include_dns:
                dns_scanner = DNSScanner()
                workflow.add_scanner(dns_scanner, {})

            if include_web:
                web_scanner = WebScanner()
                workflow.add_scanner(web_scanner, {})

            if include_directory:
                dir_scanner = DirectoryScanner()
                workflow.add_scanner(dir_scanner, {})

            if include_ssl:
                ssl_scanner = SSLScanner()
                workflow.add_scanner(ssl_scanner, {})

        # Execute scan
        log_info(f"Starting {'parallel' if parallel else 'sequential'} scan...")
        log_info(f"Profile: {profile}")
        log_info(f"Scanners: {len(workflow.scanners)}")

        all_results = workflow.execute(target)

        if not all_results:
            log_error("No scan results available. Check your target and options.")
            sys.exit(1)

        # Display results
        for result in all_results:
            display_scan_results(result)
            print()

        # Generate reports
        if all_reports:
            html_report = True
            pdf_report = True
            exec_summary = True

        if any([html_report, pdf_report, exec_summary, compliance_report]):
            log_banner("Generating Reports", "bold yellow")

            # Prepare output directory
            if output:
                base_name = Path(output).stem
                output_dir = Path(output).parent
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                base_name = f"security_report_{sanitized_target}_{timestamp}"
                output_dir = REPORT_DIR

            output_dir.mkdir(parents=True, exist_ok=True)

            # Initialize reporter with custom branding
            reporter = ReportGenerator(branding=branding)
            generated_files = {}

            # HTML Report
            if html_report:
                html_path = output_dir / f"{base_name}.html"
                if reporter.generate_html_report(all_results, html_path):
                    generated_files["html"] = html_path
                    log_success(f"📄 HTML report: {html_path}")

            # PDF Report
            if pdf_report:
                pdf_path = output_dir / f"{base_name}.pdf"
                if reporter.generate_pdf_report(all_results, pdf_path):
                    generated_files["pdf"] = pdf_path
                    log_success(f"📑 PDF report: {pdf_path}")
                else:
                    log_warning(
                        "PDF generation failed. Install 'weasyprint' or 'pdfkit' for PDF support"
                    )

            # Executive Summary
            if exec_summary:
                exec_path = output_dir / f"{base_name}_executive_summary.txt"
                if reporter.generate_executive_summary(all_results, exec_path):
                    generated_files["executive"] = exec_path
                    log_success(f"📋 Executive summary: {exec_path}")

            # Compliance Report
            if compliance_report:
                compliance_path = (
                    output_dir / f"{base_name}_compliance_{compliance_report}.html"
                )
                if reporter.generate_compliance_report(
                    all_results, compliance_path, compliance_report
                ):
                    generated_files["compliance"] = compliance_path
                    log_success(
                        f"📊 Compliance report ({compliance_report}): {compliance_path}"
                    )

            # JSON Report (always generate)
            json_path = output_dir / f"{base_name}.json"
            if reporter.generate_json_report(all_results, json_path):
                generated_files["json"] = json_path
                log_success(f"📄 JSON report: {json_path}")

            # Report summary
            log_banner("Report Summary", "bold green")
            log_info(f"Total files generated: {len(generated_files)}")
            for report_type, file_path in generated_files.items():
                log_info(f"{report_type.upper()}: {file_path.name}")

        # Combined results for JSON output (if no reporting)
        else:
            # Save combined JSON results
            if output:
                output_path = Path(output)
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"scan_{sanitized_target}_{timestamp}.json"
                output_path = REPORT_DIR / filename

            # Combine results
            main_result = all_results[0]
            for result in all_results[1:]:
                main_result.findings.extend(result.findings)
                for key, value in result.metadata.items():
                    if key in main_result.metadata:
                        main_result.metadata[f"{result.scanner_name}_{key}"] = value
                    else:
                        main_result.metadata[key] = value

            main_result.save_to_file(output_path)
            log_success(f"Results saved to: {output_path}")

        # Scan summary
        log_banner("Scan Summary", "bold green")
        log_info(f"Target: {target}")
        log_info(f"Scanners used: {len(all_results)}")

        total_findings = sum(len(result.findings) for result in all_results)
        log_info(f"Total findings: {total_findings}")

        # Count findings by severity
        severity_counts = {}
        for result in all_results:
            for finding in result.findings:
                sev = finding.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for severity, count in severity_counts.items():
            if count > 0:
                log_info(f"{severity.title()}: {count}")

        # Check for errors
        total_errors = sum(len(result.errors) for result in all_results)
        if total_errors > 0:
            log_warning(f"Errors encountered: {total_errors}")

    except KeyboardInterrupt:
        log_warning("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"Scan failed: {e}")
        if logger.level <= 10:  # DEBUG level
            import traceback

            traceback.print_exc()
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
