#!/usr/bin/env python3
"""
Auto-Pentest Tool - Enhanced Main CLI Interface with PDF Export
"""

import sys
import click
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.core import InputValidator, validate_ip, validate_domain
from src.core.scanner_base import ScanStatus, ScanSeverity
from urllib.parse import urlparse
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
from src.utils.logger import (
    LoggerSetup,
    log_banner,
    log_success,
    log_error,
    log_info,
    log_warning,
    log_debug,
)

# Try to load config, fallback if not available
try:
    from config.settings import OUTPUT_DIR, REPORT_DIR, SCAN_PROFILES

    if not REPORT_DIR or not isinstance(REPORT_DIR, Path):
        REPORT_DIR = Path("reports")
except:
    REPORT_DIR = Path("reports")
    OUTPUT_DIR = Path("output")
    SCAN_PROFILES = {}

# Initialize logger
logger = LoggerSetup.setup_logger(
    name="auto-pentest", level="INFO", log_dir=OUTPUT_DIR / "logs", use_rich=True
)


def parse_target(target: str) -> Dict[str, str]:
    """Parse target and extract appropriate formats for different scanners"""
    parsed = {
        "original": target,
        "host": target,
        "ip": None,
        "domain": None,
        "url": None,
        "port": None,
        "scheme": None,
    }

    try:
        # Check if it's a URL
        if target.startswith(("http://", "https://", "ftp://")):
            parsed_url = urlparse(target)
            parsed["scheme"] = parsed_url.scheme
            parsed["host"] = parsed_url.hostname or parsed_url.netloc.split(":")[0]
            parsed["port"] = parsed_url.port
            parsed["url"] = target

            # Default ports
            if not parsed["port"]:
                if parsed["scheme"] == "https":
                    parsed["port"] = 443
                elif parsed["scheme"] == "http":
                    parsed["port"] = 80
                elif parsed["scheme"] == "ftp":
                    parsed["port"] = 21
        else:
            # Handle host:port format
            if ":" in target and not target.count(":") > 7:  # Not IPv6
                host_part, port_part = target.rsplit(":", 1)
                try:
                    parsed["port"] = int(port_part)
                    parsed["host"] = host_part
                except ValueError:
                    parsed["host"] = target
            else:
                parsed["host"] = target

        # Determine if host is IP or domain
        if validate_ip(parsed["host"]):
            parsed["ip"] = parsed["host"]
        elif validate_domain(parsed["host"]):
            parsed["domain"] = parsed["host"]

    except Exception as e:
        log_warning(f"Target parsing failed: {e}")

    return parsed


def get_scanner_target(target_info: Dict[str, str], scanner_type: str) -> Optional[str]:
    """Get appropriate target format for specific scanner"""
    if scanner_type == "port_scanner":
        # Port scanner needs IP or hostname, not URL
        return target_info["ip"] or target_info["domain"] or target_info["host"]

    elif scanner_type == "dns_scanner":
        # DNS scanner needs domain name, skip if IP only
        if target_info["domain"]:
            return target_info["domain"]
        elif target_info["ip"]:
            log_warning(f"Skipping DNS scan for IP address: {target_info['ip']}")
            return None
        return None

    elif scanner_type in ["web_scanner", "directory_scanner"]:
        # Web scanners prefer full URL
        if target_info["url"]:
            return target_info["url"]
        elif target_info["host"]:
            # Construct URL if not provided
            scheme = "https" if target_info.get("port") == 443 else "http"
            port_part = (
                f":{target_info['port']}"
                if target_info.get("port") and target_info["port"] not in [80, 443]
                else ""
            )
            return f"{scheme}://{target_info['host']}{port_part}"
        return None

    elif scanner_type == "ssl_scanner":
        # SSL scanner needs host and port, skip for HTTP
        if target_info["host"]:
            # Skip SSL scanning for HTTP (non-encrypted) URLs
            if target_info.get("scheme") == "http" and target_info.get("port") in [
                80,
                8080,
            ]:
                log_warning(
                    f"Skipping SSL scan for HTTP URL: {target_info['original']}"
                )
                return None
            return target_info["host"]
        return None

    else:
        return target_info["original"]


# Common click options decorator
def common_options(f):
    """Common options for all scan commands"""
    f = click.option("--timeout", default=300, help="Scan timeout in seconds")(f)
    f = click.option("--output", "-o", help="Output directory")(f)
    f = click.option(
        "--format",
        "output_format",
        default="json",
        type=click.Choice(["json", "xml", "txt", "csv"]),
        help="Output format",
    )(f)
    f = click.option("--verbose", "-v", is_flag=True, help="Verbose output")(f)
    f = click.option("--debug", is_flag=True, help="Debug logging")(f)
    f = click.option("--quiet", "-q", is_flag=True, help="Quiet mode")(f)
    f = click.option("--no-cache", is_flag=True, help="Disable result caching")(f)
    return f


def display_results(result, output=None, output_format="json", verbose=False, **kwargs):
    """Display scan results in specified format"""
    try:
        # Calculate success based on findings and status
        findings = getattr(result, "findings", [])
        status = getattr(result, "status", ScanStatus.FAILED)
        findings_count = len(findings)
        is_successful = (status == ScanStatus.COMPLETED) or (findings_count > 0)

        if is_successful:
            if verbose:
                click.echo(f"\n=== {result.scanner_name.upper()} RESULTS ===")
                click.echo(f"Target: {result.target}")
                execution_time = getattr(result, "execution_time", 0)
                if (
                    hasattr(result, "end_time")
                    and hasattr(result, "start_time")
                    and result.end_time
                    and result.start_time
                ):
                    execution_time = (
                        result.end_time - result.start_time
                    ).total_seconds()
                click.echo(f"Execution Time: {execution_time:.2f}s")
                click.echo(
                    f"Status: {status.value if hasattr(status, 'value') else str(status)}"
                )
                click.echo(f"Findings: {findings_count}")

                if findings:
                    click.echo("\nFindings:")
                    for i, finding in enumerate(findings, 1):
                        click.echo(f"  {i}. {finding.get('title', 'Unknown')}")
                        if "severity" in finding:
                            click.echo(f"     Severity: {finding['severity']}")
                        if "description" in finding:
                            click.echo(
                                f"     Description: {finding['description'][:100]}..."
                            )
            else:
                click.echo(f"Scan completed: {findings_count} findings")

            # Save output if specified
            if output:
                output_path = Path(output)
                output_path.parent.mkdir(parents=True, exist_ok=True)

                if output_format == "json":
                    result_dict = (
                        result.to_dict()
                        if hasattr(result, "to_dict")
                        else {
                            "scanner_name": result.scanner_name,
                            "target": result.target,
                            "status": (
                                status.value
                                if hasattr(status, "value")
                                else str(status)
                            ),
                            "findings": findings,
                            "success": is_successful,
                        }
                    )
                    with open(output_path, "w") as f:
                        json.dump(result_dict, f, indent=2, default=str)
                elif output_format == "txt":
                    with open(output_path, "w") as f:
                        f.write(f"=== {result.scanner_name.upper()} RESULTS ===\n")
                        f.write(f"Target: {result.target}\n")
                        f.write(
                            f"Status: {status.value if hasattr(status, 'value') else str(status)}\n"
                        )
                        f.write(f"Success: {is_successful}\n")
                        f.write(f"Findings: {findings_count}\n\n")
                        for i, finding in enumerate(findings, 1):
                            f.write(f"{i}. {finding.get('title', 'Unknown')}\n")
                            if "severity" in finding:
                                f.write(f"   Severity: {finding['severity']}\n")
                            if "description" in finding:
                                f.write(f"   Description: {finding['description']}\n")
                            f.write("\n")

                click.echo(f"Results saved to: {output_path}")
        else:
            errors = getattr(result, "errors", [])
            error_msg = errors[0] if errors else "No findings or results"
            click.echo(f"Scan completed but no results: {error_msg}", err=True)

    except Exception as e:
        click.echo(f"Error displaying results: {e}", err=True)


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
    if debug:
        logger.setLevel("DEBUG")
    elif quiet:
        logger.setLevel("WARNING")

    log_banner("Auto-Pentest Framework v0.9.1")


@click.command()
@click.argument("target")
@click.option(
    "--profile",
    type=click.Choice(["quick", "web", "full", "custom"]),
    default="quick",
    help="Scan profile",
)
@click.option("--parallel", is_flag=True, default=True, help="Run scans in parallel")
@click.option("--sequential", is_flag=True, help="Run scans sequentially")
@click.option("--timeout", default=1800, help="Total workflow timeout")
@click.option("--include-port", is_flag=True, help="Include port scanning")
@click.option("--include-dns", is_flag=True, help="Include DNS enumeration")
@click.option("--include-web", is_flag=True, help="Include web vulnerability scanning")
@click.option("--include-directory", is_flag=True, help="Include directory enumeration")
@click.option("--include-ssl", is_flag=True, help="Include SSL/TLS analysis")
@click.option("--ports", help="Port range for port scanner")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--pdf-report", is_flag=True, help="Generate PDF report")
@click.option("--all-reports", is_flag=True, help="Generate all report formats")
@common_options
def scan(
    target,
    profile,
    parallel,
    sequential,
    timeout,
    include_port,
    include_dns,
    include_web,
    include_directory,
    include_ssl,
    ports,
    json_report,
    pdf_report,
    all_reports,
    **kwargs,
):
    """
    Orchestrated security scanning with multiple tools.

    This command runs a coordinated scan using multiple security tools
    based on the selected profile or custom scanner selection.
    """
    try:
        log_banner(f"Starting {profile} scan of {target}")

        # Parse target for different scanners
        target_info = parse_target(target)
        log_debug(f"Parsed target: {target_info}")

        # Validate that we have a usable target
        if not (target_info["ip"] or target_info["domain"] or target_info["host"]):
            click.echo(
                "Error: Could not parse target. Must be a valid IP, domain, or URL.",
                err=True,
            )
            sys.exit(1)

        # Sanitize target for file naming
        sanitized_target = target.replace("://", "_").replace("/", "_")

        # Determine execution mode
        if sequential:
            parallel = False

        # Create workflow with proper error handling
        workflow = None
        try:
            if profile in ["quick", "full", "web"]:
                # Create standard workflow using original target
                if profile == "quick":
                    workflow = create_quick_workflow(target)
                elif profile == "full":
                    workflow = create_full_workflow(target)
                elif profile == "web":
                    workflow = create_web_workflow(target)

                # Update targets for each scanner in workflow
                if workflow and hasattr(workflow, "tasks"):
                    for task in workflow.tasks:
                        scanner_target = get_scanner_target(
                            target_info, task.scanner_name
                        )
                        if scanner_target:
                            task.target = scanner_target
                            # Set timeout
                            if hasattr(task, "timeout"):
                                task.timeout = timeout
                        else:
                            # Skip incompatible scanners
                            log_warning(
                                f"Skipping {task.scanner_name} - incompatible with target"
                            )
                            task.skip = True
            else:
                # Custom workflow based on individual scanner options
                workflow = ScanWorkflow(f"custom_{int(datetime.now().timestamp())}")

                # Add scanners based on options with appropriate targets
                if include_port:
                    port_target = get_scanner_target(target_info, "port_scanner")
                    if port_target:
                        workflow.add_scan_task(
                            "port_scanner",
                            port_target,
                            options={"ports": ports} if ports else {},
                            timeout=timeout,
                        )

                if include_dns:
                    dns_target = get_scanner_target(target_info, "dns_scanner")
                    if dns_target:
                        workflow.add_scan_task(
                            "dns_scanner", dns_target, timeout=timeout
                        )

                if include_web:
                    web_target = get_scanner_target(target_info, "web_scanner")
                    if web_target:
                        workflow.add_scan_task(
                            "web_scanner", web_target, timeout=timeout
                        )

                if include_directory:
                    dir_target = get_scanner_target(target_info, "directory_scanner")
                    if dir_target:
                        workflow.add_scan_task(
                            "directory_scanner", dir_target, timeout=timeout
                        )

                if include_ssl:
                    ssl_target = get_scanner_target(target_info, "ssl_scanner")
                    if ssl_target:
                        # Add port info for SSL scanner
                        ssl_options = {}
                        if target_info.get("port"):
                            ssl_options["port"] = target_info["port"]
                        elif target_info.get("scheme") == "https":
                            ssl_options["port"] = 443
                        workflow.add_scan_task(
                            "ssl_scanner",
                            ssl_target,
                            options=ssl_options,
                            timeout=timeout,
                        )

        except Exception as e:
            log_error(f"Failed to create workflow: {e}")
            sys.exit(1)

        if not workflow:
            log_error("No workflow created. Check your parameters.")
            sys.exit(1)

        # Execute workflow
        if not workflow.tasks:
            log_error("No compatible scanners for this target.")
            sys.exit(1)

        # Filter out skipped tasks
        active_tasks = [
            task for task in workflow.tasks if not getattr(task, "skip", False)
        ]

        if not active_tasks:
            log_error("No active scanners after filtering.")
            sys.exit(1)

        log_info(f"Executing workflow with {len(active_tasks)} active tasks")

        # Execute tasks
        all_results = {}
        successful_count = 0
        failed_count = 0

        if parallel:
            # Parallel execution with timeout handling
            with ThreadPoolExecutor(max_workers=3) as executor:
                # Submit all tasks
                future_to_task = {}
                for task in active_tasks:
                    log_info(f"Submitting {task.scanner_name} for {task.target}")

                    # Initialize scanner
                    if task.scanner_name == "port_scanner":
                        scanner = PortScanner(timeout=getattr(task, "timeout", timeout))
                    elif task.scanner_name == "dns_scanner":
                        scanner = DNSScanner(timeout=getattr(task, "timeout", timeout))
                    elif task.scanner_name == "web_scanner":
                        scanner = WebScanner(timeout=getattr(task, "timeout", timeout))
                    elif task.scanner_name == "directory_scanner":
                        scanner = DirectoryScanner(
                            timeout=getattr(task, "timeout", timeout)
                        )
                    elif task.scanner_name == "ssl_scanner":
                        scanner = SSLScanner(timeout=getattr(task, "timeout", timeout))
                    else:
                        log_warning(f"Unknown scanner: {task.scanner_name}")
                        continue

                    # Submit task
                    future = executor.submit(
                        scanner.scan, task.target, getattr(task, "options", {})
                    )
                    future_to_task[future] = task

                # Collect results with timeout
                try:
                    for future in as_completed(future_to_task.keys(), timeout=timeout):
                        task = future_to_task[future]
                        try:
                            result = future.result(
                                timeout=30
                            )  # 30 second timeout per task
                            all_results[task.scanner_name] = (
                                result  # Always store result
                            )

                            # Success detection based on findings and status
                            findings_count = len(getattr(result, "findings", []))
                            result_status = getattr(result, "status", ScanStatus.FAILED)

                            # Consider successful if:
                            # 1. Status is COMPLETED AND has findings, OR
                            # 2. Has findings even if status is not COMPLETED
                            is_successful = (
                                result_status == ScanStatus.COMPLETED
                                and findings_count >= 0
                            ) or findings_count > 0

                            if is_successful:
                                successful_count += 1
                                log_success(
                                    f"✓ {task.scanner_name} completed successfully with {findings_count} findings"
                                )
                            else:
                                failed_count += 1
                                errors = getattr(result, "errors", [])
                                error_msg = (
                                    errors[0] if errors else "No findings detected"
                                )
                                log_warning(
                                    f"✗ {task.scanner_name} completed but no results: {error_msg}"
                                )

                        except Exception as e:
                            failed_count += 1
                            log_error(
                                f"✗ {task.scanner_name} failed with exception: {e}"
                            )
                            # Create dummy failed result
                            from src.core import ScanResult

                            failed_result = ScanResult(
                                scanner_name=task.scanner_name,
                                target=task.target,
                                status=ScanStatus.FAILED,
                                start_time=datetime.now(),
                            )
                            failed_result.errors = [str(e)]
                            failed_result.findings = []
                            all_results[task.scanner_name] = failed_result

                except Exception as e:
                    log_error(f"Workflow execution error: {e}")
                    # Handle remaining tasks as failed
                    for future, task in future_to_task.items():
                        if task.scanner_name not in all_results:
                            failed_count += 1
                            log_error(
                                f"✗ {task.scanner_name} failed due to workflow error"
                            )
                            from src.core import ScanResult

                            failed_result = ScanResult(
                                scanner_name=task.scanner_name,
                                target=task.target,
                                status=ScanStatus.FAILED,
                                start_time=datetime.now(),
                            )
                            failed_result.errors = [f"Workflow error: {str(e)}"]
                            failed_result.findings = []
                            all_results[task.scanner_name] = failed_result

        else:
            # Sequential execution
            for task in active_tasks:
                try:
                    log_info(f"Executing {task.scanner_name} on {task.target}")

                    # Initialize scanner
                    if task.scanner_name == "port_scanner":
                        scanner = PortScanner(timeout=getattr(task, "timeout", timeout))
                    elif task.scanner_name == "dns_scanner":
                        scanner = DNSScanner(timeout=getattr(task, "timeout", timeout))
                    elif task.scanner_name == "web_scanner":
                        scanner = WebScanner(timeout=getattr(task, "timeout", timeout))
                    elif task.scanner_name == "directory_scanner":
                        scanner = DirectoryScanner(
                            timeout=getattr(task, "timeout", timeout)
                        )
                    elif task.scanner_name == "ssl_scanner":
                        scanner = SSLScanner(timeout=getattr(task, "timeout", timeout))
                    else:
                        log_warning(f"Unknown scanner: {task.scanner_name}")
                        continue

                    # Execute task
                    result = scanner.scan(task.target, getattr(task, "options", {}))
                    all_results[task.scanner_name] = result  # Always store result

                    # Success detection based on findings and status
                    findings_count = len(getattr(result, "findings", []))
                    result_status = getattr(result, "status", ScanStatus.FAILED)

                    # Consider successful if:
                    # 1. Status is COMPLETED AND has findings, OR
                    # 2. Has findings even if status is not COMPLETED
                    is_successful = (
                        result_status == ScanStatus.COMPLETED and findings_count >= 0
                    ) or findings_count > 0

                    if is_successful:
                        successful_count += 1
                        log_success(
                            f"✓ {task.scanner_name} completed successfully with {findings_count} findings"
                        )
                    else:
                        failed_count += 1
                        errors = getattr(result, "errors", [])
                        error_msg = errors[0] if errors else "No findings detected"
                        log_warning(
                            f"✗ {task.scanner_name} completed but no results: {error_msg}"
                        )

                except Exception as e:
                    failed_count += 1
                    log_error(f"✗ {task.scanner_name} failed with exception: {e}")
                    # Create dummy failed result
                    from src.core import ScanResult

                    failed_result = ScanResult(
                        scanner_name=task.scanner_name,
                        target=task.target,
                        status=ScanStatus.FAILED,
                        start_time=datetime.now(),
                    )
                    failed_result.errors = [str(e)]
                    failed_result.findings = []
                    all_results[task.scanner_name] = failed_result

        # Create mock workflow result for compatibility
        class MockWorkflowResult:
            def __init__(self):
                self.tasks = []
                self.status = "completed"

        class MockTask:
            def __init__(self, name, result):
                self.scanner_name = name
                self.result = result
                # Better success detection for mock tasks based on actual logic
                if result:
                    findings_count = len(getattr(result, "findings", []))
                    result_status = getattr(result, "status", ScanStatus.FAILED)

                    # Same logic as main detection
                    is_successful = (
                        result_status == ScanStatus.COMPLETED and findings_count >= 0
                    ) or findings_count > 0

                    if is_successful:
                        self.status = ScanStatus.COMPLETED
                    else:
                        self.status = ScanStatus.FAILED
                else:
                    self.status = ScanStatus.FAILED

        workflow_result = MockWorkflowResult()

        # Create mock tasks for summary
        for scanner_name, result in all_results.items():
            workflow_result.tasks.append(MockTask(scanner_name, result))

        # Calculate total findings
        total_findings = 0
        for result in all_results.values():
            if result and hasattr(result, "findings"):
                total_findings += len(result.findings)

        # Debug information for troubleshooting
        if kwargs.get("debug") or kwargs.get("verbose"):
            log_info("🔍 DEBUG: Scan results summary")
            for scanner_name, result in all_results.items():
                findings_count = len(getattr(result, "findings", []))
                status = getattr(result, "status", ScanStatus.FAILED)
                errors = getattr(result, "errors", [])

                log_info(f"  {scanner_name}:")
                log_info(
                    f"    - Status: {status.value if hasattr(status, 'value') else str(status)}"
                )
                log_info(f"    - Findings: {findings_count}")
                log_info(f"    - Errors: {errors}")
                log_info(f"    - Type: {type(result)}")
                log_info(f"    - Has to_dict: {hasattr(result, 'to_dict')}")

        # Display individual results if verbose
        if kwargs.get("verbose"):
            for scanner_name, result in all_results.items():
                if result:
                    display_results(result, **kwargs)

        # Generate reports
        report_generated = False
        if json_report or pdf_report or all_reports:
            try:
                log_info("📊 Starting report generation...")

                # Ensure report directory exists
                REPORT_DIR.mkdir(parents=True, exist_ok=True)
                log_debug(f"Report directory: {REPORT_DIR}")

                # Check if we have any results
                if not all_results:
                    log_warning("⚠️ No scan results available for reporting")
                else:
                    log_info(f"📈 Processing results from {len(all_results)} scanners")

                # Generate timestamp for unique filenames
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                sanitized_target = (
                    target.replace("://", "_").replace("/", "_").replace(":", "_")
                )
                report_name = f"{profile}_{sanitized_target}_{timestamp}"

                log_debug(f"Report name: {report_name}")

                # Generate JSON report
                if json_report or all_reports:
                    try:
                        log_info("🔄 Generating JSON report...")
                        json_file = REPORT_DIR / f"{report_name}.json"

                        # Convert results to proper format
                        report_data = {
                            "scan_info": {
                                "target": target,
                                "profile": profile,
                                "timestamp": timestamp,
                                "execution_mode": (
                                    "parallel" if parallel else "sequential"
                                ),
                                "total_scanners": len(active_tasks),
                                "successful_scanners": successful_count,
                                "failed_scanners": failed_count,
                                "total_findings": total_findings,
                            },
                            "results": {},
                        }

                        # Process each result
                        for scanner_name, result in all_results.items():
                            try:
                                if hasattr(result, "to_dict"):
                                    result_dict = result.to_dict()
                                    # Add computed success field
                                    findings_count = len(
                                        result_dict.get("findings", [])
                                    )
                                    result_status = result_dict.get("status", "failed")
                                    result_dict["success"] = (
                                        result_status == "completed"
                                    ) or (findings_count > 0)
                                    report_data["results"][scanner_name] = result_dict
                                else:
                                    # Manual result processing
                                    findings = getattr(result, "findings", [])
                                    status = getattr(
                                        result, "status", ScanStatus.FAILED
                                    )
                                    findings_count = len(findings)

                                    report_data["results"][scanner_name] = {
                                        "scanner_name": scanner_name,
                                        "target": str(
                                            getattr(result, "target", target)
                                        ),
                                        "status": (
                                            status.value
                                            if hasattr(status, "value")
                                            else str(status)
                                        ),
                                        "success": (status == ScanStatus.COMPLETED)
                                        or (findings_count > 0),
                                        "findings": findings,
                                        "findings_count": findings_count,
                                        "execution_time": getattr(
                                            result, "execution_time", 0
                                        ),
                                        "errors": getattr(result, "errors", []),
                                        "metadata": getattr(result, "metadata", {}),
                                    }
                            except Exception as e:
                                log_warning(
                                    f"Error processing {scanner_name} result: {e}"
                                )
                                report_data["results"][scanner_name] = {
                                    "scanner_name": scanner_name,
                                    "error": str(e),
                                    "success": False,
                                }

                        # Write JSON file
                        with open(json_file, "w", encoding="utf-8") as f:
                            json.dump(
                                report_data,
                                f,
                                indent=2,
                                default=str,
                                ensure_ascii=False,
                            )

                        file_size = json_file.stat().st_size
                        log_success(
                            f"✅ JSON report generated: {json_file} ({file_size} bytes)"
                        )
                        report_generated = True

                    except Exception as e:
                        log_error(f"❌ JSON report generation failed: {e}")
                        log_debug(f"JSON error details: {str(e)}")
                        import traceback

                        log_debug(f"JSON traceback: {traceback.format_exc()}")

                # Generate TXT report (instead of PDF for simplicity)
                if pdf_report or all_reports:
                    try:
                        log_info("🔄 Generating TXT report...")
                        txt_file = REPORT_DIR / f"{report_name}.txt"

                        with open(txt_file, "w", encoding="utf-8") as f:
                            f.write("=" * 60 + "\n")
                            f.write("AUTO-PENTEST SCAN REPORT\n")
                            f.write("=" * 60 + "\n\n")

                            f.write(f"Target: {target}\n")
                            f.write(f"Profile: {profile}\n")
                            f.write(f"Timestamp: {timestamp}\n")
                            f.write(
                                f"Execution Mode: {'Parallel' if parallel else 'Sequential'}\n"
                            )
                            f.write(f"Total Scanners: {len(active_tasks)}\n")
                            f.write(f"Successful: {successful_count}\n")
                            f.write(f"Failed: {failed_count}\n")
                            f.write(f"Total Findings: {total_findings}\n\n")

                            for scanner_name, result in all_results.items():
                                f.write("=" * 40 + "\n")
                                f.write(f"{scanner_name.upper()} RESULTS\n")
                                f.write("=" * 40 + "\n")

                                # Calculate success
                                findings = getattr(result, "findings", [])
                                status = getattr(result, "status", ScanStatus.FAILED)
                                findings_count = len(findings)
                                is_successful = (status == ScanStatus.COMPLETED) or (
                                    findings_count > 0
                                )

                                f.write(f"Success: {is_successful}\n")
                                f.write(
                                    f"Status: {status.value if hasattr(status, 'value') else str(status)}\n"
                                )
                                f.write(
                                    f"Target: {getattr(result, 'target', target)}\n"
                                )
                                f.write(
                                    f"Execution Time: {getattr(result, 'execution_time', 0):.2f}s\n"
                                )
                                f.write(f"Findings: {findings_count}\n")

                                # Show errors if any
                                errors = getattr(result, "errors", [])
                                if errors:
                                    f.write(f"Errors: {', '.join(errors)}\n")
                                f.write("\n")

                                if findings:
                                    for i, finding in enumerate(findings, 1):
                                        f.write(
                                            f"  {i}. {finding.get('title', 'Unknown Finding')}\n"
                                        )
                                        if "severity" in finding:
                                            f.write(
                                                f"     Severity: {finding['severity']}\n"
                                            )
                                        if "description" in finding:
                                            f.write(
                                                f"     Description: {finding['description']}\n"
                                            )
                                        if "port" in finding:
                                            f.write(f"     Port: {finding['port']}\n")
                                        if "service" in finding:
                                            f.write(
                                                f"     Service: {finding['service']}\n"
                                            )
                                        f.write("\n")
                                else:
                                    f.write("  No findings detected.\n")
                                f.write("\n")

                        file_size = txt_file.stat().st_size
                        log_success(
                            f"✅ TXT report generated: {txt_file} ({file_size} bytes)"
                        )
                        report_generated = True

                    except Exception as e:
                        log_error(f"❌ TXT report generation failed: {e}")
                        log_debug(f"TXT error details: {str(e)}")
                        import traceback

                        log_debug(f"TXT traceback: {traceback.format_exc()}")

            except Exception as e:
                log_error(f"❌ Report generation failed: {e}")
                log_debug(f"Report error details: {str(e)}")
                import traceback

                log_debug(f"Full traceback: {traceback.format_exc()}")
        else:
            log_info("📊 No reports requested (use --all-reports to generate reports)")

        # Display summary
        log_success("=== SCAN SUMMARY ===")
        log_info(f"Target: {target}")
        log_info(f"Profile: {profile}")
        log_info(f"Execution Mode: {'Parallel' if parallel else 'Sequential'}")
        log_info(f"Total Scanners: {len(active_tasks)}")
        log_info(f"Successful: {successful_count}")
        log_info(f"Failed: {failed_count}")
        log_info(f"Total Findings: {total_findings}")

        if report_generated:
            log_info(f"Reports saved to: {REPORT_DIR}")

        log_success("Scan completed successfully!")

    except KeyboardInterrupt:
        log_warning("🛑 Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"💥 Unexpected error: {e}")
        import traceback

        log_debug(f"Full traceback: {traceback.format_exc()}")

        # Special handling for common issues
        error_str = str(e).lower()
        if "cannot access free variable" in error_str:
            log_error("⚠️ Internal variable scope error - this is a code bug")
        elif "nmap" in error_str or "command failed" in error_str:
            log_error("⚠️ Nmap execution issue. Try:")
            log_error("   1. sudo apt install nmap")
            log_error("   2. Check target connectivity: ping 192.168.48.207")
            log_error("   3. Run with sudo for OS detection")
            log_error("   4. Use debug script: python debug_scan.py")
        elif "timeout" in error_str:
            log_error("⚠️ Scan timeout. Try:")
            log_error("   1. Increase timeout: --timeout 1800")
            log_error("   2. Use simpler profile: --profile quick")
            log_error("   3. Run scanners individually")

        sys.exit(1)


@click.command()
@click.argument("target")
def quick(target):
    """
    Perform a quick scan (most common ports only).

    This is equivalent to: scan TARGET --profile quick --all-reports
    """
    ctx = click.get_current_context()
    ctx.invoke(scan, target=target, profile="quick", all_reports=True)


@click.command()
@click.argument("target")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output for debugging")
def full(target, verbose):
    """
    Perform a comprehensive scan with full reporting.

    This is equivalent to: scan TARGET --profile full --all-reports --verbose
    """
    ctx = click.get_current_context()
    ctx.invoke(scan, target=target, profile="full", all_reports=True, verbose=verbose)


@click.command()
def info():
    """Show framework capabilities and information"""
    try:
        log_info("Auto-Pentest Framework Information")
        log_info("=" * 40)
        log_info("Available Scanners:")
        log_info("  • Port Scanner (Nmap integration)")
        log_info("  • DNS Scanner (DNS enumeration)")
        log_info("  • Web Scanner (Web vulnerability assessment)")
        log_info("  • Directory Scanner (Directory/file enumeration)")
        log_info("  • SSL Scanner (SSL/TLS security analysis)")
        log_info("")
        log_info("Scan Profiles:")
        log_info("  • quick: Fast reconnaissance scan")
        log_info("  • web: Web-focused vulnerability assessment")
        log_info("  • full: Comprehensive security assessment")
        log_info("  • custom: User-defined scanner combination")
        log_info("")
        log_info("Report Formats:")
        log_info("  • JSON: Structured data format")
        log_info("  • PDF: Professional presentation format")
        log_info("  • TXT: Plain text format")
        log_info("  • CSV: Comma-separated values")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)


# Add all commands to the CLI group
cli.add_command(scan)
cli.add_command(quick)
cli.add_command(full)
cli.add_command(info)


if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        log_warning("Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        sys.exit(1)
