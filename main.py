#!/usr/bin/env python3
"""
Auto-Pentest Tool - Main CLI Interface
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
@click.version_option(version="0.1.0")
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.option("--quiet", is_flag=True, help="Quiet mode (minimal output)")
def cli(debug, quiet):
    """
    Auto-Pentest Tool - Automated Penetration Testing Framework

    A comprehensive tool for automated security testing and vulnerability assessment.
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
@click.option(
    "--ports",
    help="Ports to scan (quick, top100, top1000, common, all, or custom like 80,443,8080)",
)
@click.option("--timeout", type=int, default=300, help="Scan timeout in seconds")
@click.option(
    "--output", type=click.Path(), help="Output file for results (JSON format)"
)
@click.option("--no-ping", is_flag=True, help="Skip host discovery (assume host is up)")
@click.option(
    "--timing",
    type=click.IntRange(0, 5),
    default=3,
    help="Nmap timing template (0=slowest, 5=fastest)",
)
@click.option("--include-dns", is_flag=True, help="Include DNS enumeration in scan")
def scan(target, profile, ports, timeout, output, no_ping, timing, include_dns):
    """
    Perform a security scan on the specified target.

    TARGET can be an IP address, domain name, or URL.

    Examples:
    \b
        auto-pentest scan 192.168.1.1
        auto-pentest scan example.com --profile full
        auto-pentest scan 192.168.1.0/24 --ports 80,443,8080
        auto-pentest scan target.com --output results.json
        auto-pentest scan example.com --include-dns
    """
    log_banner(f"Auto-Pentest Scan - {target}", "bold cyan")

    try:
        # Validate target
        validator = InputValidator()
        is_valid, target_type, sanitized_target = validator.validate_target(target)

        if not is_valid:
            log_error(f"Invalid target: {target}")
            log_info("Target must be an IP address, domain name, or URL")
            sys.exit(1)

        log_info(f"Target: {sanitized_target} (Type: {target_type})")
        log_info(f"Profile: {profile}")

        # Prepare scan options
        scan_options = {"timing": timing, "no_ping": no_ping}

        # Handle ports
        if ports:
            scan_options["ports"] = ports
        elif profile in SCAN_PROFILES:
            # Use profile defaults (could extend this later)
            if profile == "quick":
                scan_options["ports"] = "quick"
            elif profile == "full":
                scan_options["ports"] = "top1000"

        log_info(f"Scan options: {scan_options}")

        # Results storage
        all_results = []

        # Port scanning (always included)
        log_info("Starting port scan...")

        # Create port scanner
        port_scanner = PortScanner(timeout=timeout)

        # Check if nmap is available
        if not port_scanner.executor.check_tool_exists("nmap"):
            log_error("nmap is required but not found!")
            log_info("Please install nmap: sudo apt install nmap")
            sys.exit(1)

        # Execute port scan
        port_result = port_scanner.scan(sanitized_target, scan_options)
        all_results.append(port_result)

        # DNS scanning (if target is domain and DNS is included)
        if (target_type == "domain" and include_dns) or profile == "full":
            log_info("Starting DNS enumeration...")

            dns_scanner = DNSScanner(timeout=timeout)

            # DNS scan options
            dns_options = {}
            if profile == "full":
                dns_options = {
                    "zone_transfer": True,
                    "subdomain_enum": True,
                    "subdomain_method": "bruteforce",
                }
            else:
                dns_options = {
                    "zone_transfer": True,
                    "subdomain_enum": True,
                    "subdomain_method": "wordlist",
                }

            dns_result = dns_scanner.scan(sanitized_target, dns_options)
            all_results.append(dns_result)

        # Display results
        for result in all_results:
            display_scan_results(result)
            print()  # Add spacing between scanners

        # Combine results for saving
        main_result = all_results[0]  # Use port scan as main result

        # Add findings from other scanners
        for result in all_results[1:]:
            main_result.findings.extend(result.findings)
            # Merge metadata
            for key, value in result.metadata.items():
                if key in main_result.metadata:
                    # Handle conflicts by prefixing with scanner name
                    main_result.metadata[f"{result.scanner_name}_{key}"] = value
                else:
                    main_result.metadata[key] = value

        # Save results
        if output:
            output_path = Path(output)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{sanitized_target.replace('/', '_')}_{timestamp}.json"
            output_path = REPORT_DIR / filename

        main_result.save_to_file(output_path)
        log_success(f"Results saved to: {output_path}")

        # Summary
        log_banner("Scan Summary", "bold green")
        log_info(f"Target: {main_result.target}")
        log_info(f"Scanners used: {len(all_results)}")
        log_info(f"Total findings: {len(main_result.findings)}")

        # Count findings by severity
        from src.core import ScanSeverity

        severity_counts = {}
        for finding in main_result.findings:
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
@click.option("--zone-transfer", is_flag=True, help="Attempt DNS zone transfer")
@click.option("--subdomain-enum", is_flag=True, help="Enable subdomain enumeration")
@click.option(
    "--subdomain-method",
    type=click.Choice(["wordlist", "bruteforce"]),
    default="wordlist",
    help="Subdomain enumeration method",
)
@click.option("--timeout", type=int, default=180, help="DNS scan timeout in seconds")
@click.option(
    "--output", type=click.Path(), help="Output file for results (JSON format)"
)
def dns(target, zone_transfer, subdomain_enum, subdomain_method, timeout, output):
    """
    Perform DNS enumeration and analysis on the target domain.

    TARGET should be a domain name (e.g., example.com).

    Examples:
    \b
        auto-pentest dns example.com
        auto-pentest dns example.com --zone-transfer --subdomain-enum
        auto-pentest dns example.com --subdomain-method bruteforce
        auto-pentest dns example.com --output dns_results.json
    """
    log_banner(f"DNS Enumeration - {target}", "bold cyan")

    try:
        # Validate target
        validator = InputValidator()
        is_valid, target_type, sanitized_target = validator.validate_target(target)

        if not is_valid:
            log_error(f"Invalid target: {target}")
            sys.exit(1)

        if target_type not in ["domain", "ip"]:
            log_error("DNS scanning requires a domain name or IP address")
            sys.exit(1)

        log_info(f"Target: {sanitized_target} (Type: {target_type})")

        # Prepare DNS scan options
        dns_options = {
            "zone_transfer": zone_transfer,
            "subdomain_enum": subdomain_enum,
            "subdomain_method": subdomain_method,
        }

        log_info(f"DNS scan options: {dns_options}")

        # Create DNS scanner
        dns_scanner = DNSScanner(timeout=timeout)

        log_info("Starting DNS enumeration...")

        # Execute DNS scan
        result = dns_scanner.scan(sanitized_target, dns_options)

        # Display results
        display_scan_results(result)

        # Save results
        if output:
            output_path = Path(output)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dns_{sanitized_target}_{timestamp}.json"
            output_path = REPORT_DIR / filename

        result.save_to_file(output_path)
        log_success(f"Results saved to: {output_path}")

        # Summary
        log_banner("DNS Scan Summary", "bold green")
        log_info(f"Target: {result.target}")
        log_info(f"Status: {result.status.value}")
        log_info(f"Total findings: {len(result.findings)}")

        # Count findings by category
        categories = {}
        for finding in result.findings:
            category = finding.get("category", "unknown")
            categories[category] = categories.get(category, 0) + 1

        for category, count in categories.items():
            if count > 0:
                log_info(f"{category.replace('_', ' ').title()}: {count}")

        if result.errors:
            log_warning(f"Errors encountered: {len(result.errors)}")

    except KeyboardInterrupt:
        log_warning("DNS scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"DNS scan failed: {e}")
        if logger.level <= 10:  # DEBUG level
            import traceback

            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.argument("target")
def quick(target):
    """
    Perform a quick scan (most common ports only).

    This is equivalent to: scan TARGET --profile quick
    """
    ctx = click.get_current_context()
    ctx.invoke(scan, target=target, profile="quick")


@cli.command()
@click.argument("target")
def full(target):
    """
    Perform a comprehensive scan (top 1000 ports + aggressive options).

    This is equivalent to: scan TARGET --profile full
    """
    ctx = click.get_current_context()
    ctx.invoke(scan, target=target, profile="full")


@cli.command()
def list_tools():
    """
    List available tools and their status.
    """
    log_banner("Tool Status Check", "bold blue")

    from src.core import CommandExecutor

    executor = CommandExecutor()

    tools = {
        "nmap": "Network port scanner",
        "dig": "DNS lookup utility",
        "nslookup": "DNS lookup utility (alternative)",
        "host": "DNS lookup utility (alternative)",
        "nikto": "Web vulnerability scanner",
        "sqlmap": "SQL injection tester",
        "dirb": "Directory/file brute forcer",
        "subfinder": "Subdomain discovery tool",
        "sslscan": "SSL/TLS configuration scanner",
    }

    # Check Python DNS library
    try:
        import dns.resolver

        log_success("✓ dnspython: Python DNS library (INSTALLED)")
    except ImportError:
        log_error("✗ dnspython: Python DNS library (NOT INSTALLED)")
        log_info("  Install with: pip install dnspython")

    print()  # Add spacing

    for tool, description in tools.items():
        if executor.check_tool_exists(tool):
            version = executor.get_tool_version(tool)
            version_str = version.split("\n")[0] if version else "unknown version"
            log_success(f"✓ {tool}: {description} ({version_str})")
        else:
            log_error(f"✗ {tool}: {description} (NOT INSTALLED)")

    log_info("\nTo install missing tools on Ubuntu/Debian:")
    log_info("sudo apt update && sudo apt install -y nmap nikto sqlmap dirb dnsutils")
    log_info("pip install dnspython  # For DNS scanning functionality")


@cli.command()
@click.argument("result_file", type=click.Path(exists=True))
@click.option(
    "--format",
    type=click.Choice(["summary", "detailed", "json"]),
    default="summary",
    help="Output format",
)
def report(result_file, format):
    """
    Generate a report from scan results.

    RESULT_FILE should be a JSON file generated by a previous scan.
    """
    log_banner("Generating Report", "bold magenta")

    try:
        # Load results
        with open(result_file, "r") as f:
            data = json.load(f)

        log_info(f"Loaded results from: {result_file}")

        if format == "json":
            click.echo(json.dumps(data, indent=2))
        elif format == "detailed":
            display_detailed_report(data)
        else:
            display_summary_report(data)

    except Exception as e:
        log_error(f"Failed to generate report: {e}")
        sys.exit(1)


@cli.command()
def info():
    """
    Show information about the Auto-Pentest tool.
    """
    log_banner("Auto-Pentest Tool Information", "bold cyan")

    log_info("Version: 0.1.0")
    log_info("Author: Auto-Pentest Framework")
    log_info("Description: Automated Penetration Testing Tool")

    log_info("\nSupported Scan Types:")
    log_info("  • Port Scanning (nmap)")
    log_info("  • DNS Enumeration (dnspython)")
    log_info("  • [Coming Soon] Web Vulnerability Scanning")
    log_info("  • [Coming Soon] Subdomain Discovery")
    log_info("  • [Coming Soon] SSL/TLS Analysis")

    log_info("\nAvailable Commands:")
    log_info("  • scan - Comprehensive security scan")
    log_info("  • dns - DNS enumeration and analysis")
    log_info("  • quick - Quick port scan")
    log_info("  • full - Full comprehensive scan")
    log_info("  • list-tools - Check tool availability")
    log_info("  • report - Generate reports from results")

    log_info("\nOutput Directories:")
    log_info(f"  • Logs: {OUTPUT_DIR / 'logs'}")
    log_info(f"  • Reports: {REPORT_DIR}")
    log_info(f"  • Raw Output: {OUTPUT_DIR / 'raw'}")

    log_info("\nFor help with a specific command:")
    log_info("  auto-pentest COMMAND --help")


def display_scan_results(result):
    """
    Display scan results in a formatted way

    Args:
        result: ScanResult object
    """
    log_banner("Scan Results", "bold yellow")

    # Basic info
    log_info(f"Scanner: {result.scanner_name}")
    log_info(f"Target: {result.target}")
    log_info(f"Status: {result.status.value}")

    if result.end_time:
        duration = result.end_time - result.start_time
        log_info(f"Duration: {duration}")

    # Findings by category
    if result.findings:
        # Group findings by category
        categories = {}
        for finding in result.findings:
            category = finding.get("category", "unknown")
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)

        for category, findings in categories.items():
            log_banner(
                f"{category.replace('_', ' ').title()} ({len(findings)})", "bold white"
            )

            for finding in findings:
                severity = finding.get("severity", "info")
                severity_colors = {
                    "critical": "bold red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "green",
                    "info": "cyan",
                }
                color = severity_colors.get(severity, "white")

                title = finding.get("title", "Unknown Finding")
                description = finding.get("description", "")

                from rich.console import Console

                console = Console()
                console.print(f"  [{color}]{severity.upper()}[/{color}] {title}")
                if description:
                    console.print(f"    {description}", style="dim")

                # Show port details for port findings
                if category == "open_port":
                    port = finding.get("port")
                    protocol = finding.get("protocol", "tcp")
                    service = finding.get("service", "unknown")
                    if port:
                        console.print(
                            f"    Port: {port}/{protocol} Service: {service}",
                            style="dim cyan",
                        )
    else:
        log_info("No findings detected")

    # Errors
    if result.errors:
        log_warning(f"Errors encountered ({len(result.errors)}):")
        for error in result.errors:
            log_error(f"  {error}")


def display_summary_report(data):
    """Display summary report from JSON data"""
    log_info(f"Scan Target: {data.get('target', 'Unknown')}")
    log_info(f"Scanner: {data.get('scanner_name', 'Unknown')}")
    log_info(f"Status: {data.get('status', 'Unknown')}")
    log_info(f"Findings: {data.get('findings_count', 0)}")

    if data.get("duration"):
        log_info(f"Duration: {data['duration']}")


def display_detailed_report(data):
    """Display detailed report from JSON data"""
    display_summary_report(data)

    log_banner("Detailed Findings", "bold white")

    findings = data.get("findings", [])
    for i, finding in enumerate(findings, 1):
        severity = finding.get("severity", "info")
        title = finding.get("title", f"Finding {i}")
        description = finding.get("description", "No description")

        click.echo(f"\n{i}. [{severity.upper()}] {title}")
        click.echo(f"   {description}")

        # Show additional details
        details = finding.get("details", {})
        if details:
            for key, value in details.items():
                if key not in ["host", "hostnames"]:  # Skip verbose fields
                    click.echo(f"   {key}: {value}")


if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        log_warning("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        sys.exit(1)
