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
from src.scanners.vulnerability.web_scanner import WebScanner
from src.scanners.vulnerability.directory_scanner import DirectoryScanner
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
    "--tool",
    type=click.Choice(["dirb", "gobuster", "auto"]),
    default="auto",
    help="Scanner tool to use",
)
@click.option(
    "--wordlist",
    default="common",
    help="Wordlist to use (small, common, big, or custom path)",
)
@click.option(
    "--extensions/--no-extensions", default=True, help="Include file extensions in scan"
)
@click.option("--extension-list", help="Custom extension list (comma-separated)")
@click.option(
    "--threads", type=int, default=10, help="Number of threads (gobuster only)"
)
@click.option(
    "--timeout", type=int, default=300, help="Directory scan timeout in seconds"
)
@click.option(
    "--output", type=click.Path(), help="Output file for results (JSON format)"
)
@click.option(
    "--scheme",
    type=click.Choice(["http", "https"]),
    default="https",
    help="URL scheme to use",
)
@click.option("--port", type=int, help="Custom port number")
def directory(
    target,
    tool,
    wordlist,
    extensions,
    extension_list,
    threads,
    timeout,
    output,
    scheme,
    port,
):
    """
    Perform directory and file enumeration on the target.

    TARGET can be a URL, domain name, or IP address.

    Examples:
    \b
        auto-pentest directory https://example.com
        auto-pentest directory example.com --tool gobuster --wordlist big
        auto-pentest directory 192.168.1.1 --no-extensions
        auto-pentest directory target.com --extension-list php,asp,jsp
    """
    log_banner(f"Directory Enumeration - {target}", "bold cyan")

    try:
        # Create directory scanner
        dir_scanner = DirectoryScanner(timeout=timeout)

        log_info(f"Target: {target}")
        log_info(f"Tool: {tool}")
        log_info(f"Wordlist: {wordlist}")

        # Prepare scan options
        scan_options = {
            "tool": tool,
            "wordlist": wordlist,
            "extensions": extensions,
            "threads": threads,
            "scheme": scheme,
        }

        if port:
            scan_options["port"] = port
        if extension_list:
            scan_options["extension_list"] = extension_list.split(",")

        log_info(f"Directory scan options: {scan_options}")

        # Check dependencies
        capabilities = dir_scanner.get_capabilities()
        dirb_available = capabilities["dependencies"]["dirb"]["available"]
        gobuster_available = capabilities["dependencies"]["gobuster"]["available"]

        if tool == "dirb" and not dirb_available:
            log_error("Dirb not found!")
            log_info("Install with: sudo apt install dirb")
            sys.exit(1)
        elif tool == "gobuster" and not gobuster_available:
            log_error("Gobuster not found!")
            log_info("Install with: sudo apt install gobuster")
            sys.exit(1)
        elif tool == "auto" and not (dirb_available or gobuster_available):
            log_error("Neither dirb nor gobuster found!")
            log_info("Install with: sudo apt install dirb gobuster")
            sys.exit(1)

        log_info("Starting directory enumeration...")

        # Execute directory scan
        result = dir_scanner.scan(target, scan_options)

        # Display results
        display_scan_results(result)

        # Save results
        if output:
            output_path = Path(output)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Clean target for filename
            clean_target = (
                target.replace("://", "_").replace("/", "_").replace(":", "_")
            )
            filename = f"directory_{clean_target}_{timestamp}.json"
            output_path = REPORT_DIR / filename

        result.save_to_file(output_path)
        log_success(f"Results saved to: {output_path}")

        # Summary
        log_banner("Directory Scan Summary", "bold green")
        log_info(f"Target: {result.target}")
        log_info(f"Status: {result.status.value}")
        log_info(f"Total findings: {len(result.findings)}")
        log_info(f"Tool used: {result.metadata.get('tool_used', 'unknown')}")

        # Count findings by type
        directories = len(
            [f for f in result.findings if f.get("item_type") == "directory"]
        )
        files = len([f for f in result.findings if f.get("item_type") == "file"])
        interesting = len(
            [f for f in result.findings if f.get("is_interesting", False)]
        )

        if directories > 0:
            log_info(f"Directories found: {directories}")
        if files > 0:
            log_info(f"Files found: {files}")
        if interesting > 0:
            log_warning(f"Interesting items: {interesting}")

        if result.errors:
            log_warning(f"Errors encountered: {len(result.errors)}")

    except KeyboardInterrupt:
        log_warning("Directory scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"Directory scan failed: {e}")
        if logger.level <= 10:  # DEBUG level
            import traceback

            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.argument("target")
@click.option(
    "--scheme",
    type=click.Choice(["http", "https"]),
    default="https",
    help="URL scheme to use",
)
@click.option("--port", type=int, help="Custom port number")
@click.option(
    "--use-nikto/--no-nikto", default=True, help="Enable/disable Nikto scanning"
)
@click.option("--timeout", type=int, default=180, help="Web scan timeout in seconds")
@click.option(
    "--output", type=click.Path(), help="Output file for results (JSON format)"
)
@click.option("--user-agent", help="Custom User-Agent string")
@click.option(
    "--follow-redirects/--no-follow-redirects",
    default=True,
    help="Follow HTTP redirects",
)
def web(target, scheme, port, use_nikto, timeout, output, user_agent, follow_redirects):
    """
    Perform web vulnerability scanning on the target.

    TARGET can be a URL, domain name, or IP address.

    Examples:
    \b
        auto-pentest web https://example.com
        auto-pentest web example.com --scheme http --port 8080
        auto-pentest web 192.168.1.1 --no-nikto
        auto-pentest web target.com --output web_results.json
    """
    log_banner(f"Web Vulnerability Scan - {target}", "bold cyan")

    try:
        # Create web scanner
        web_scanner = WebScanner(timeout=timeout)

        log_info(f"Target: {target}")
        log_info(f"Scheme: {scheme}")
        if port:
            log_info(f"Port: {port}")

        # Prepare scan options
        scan_options = {
            "scheme": scheme,
            "use_nikto": use_nikto,
            "follow_redirects": follow_redirects,
        }

        if port:
            scan_options["port"] = port
        if user_agent:
            scan_options["user_agent"] = user_agent

        log_info(f"Web scan options: {scan_options}")

        # Check dependencies
        capabilities = web_scanner.get_capabilities()
        nikto_available = capabilities["dependencies"]["nikto"]["available"]

        if use_nikto and not nikto_available:
            log_warning("Nikto not found! Continuing without Nikto scan...")
            scan_options["use_nikto"] = False
        elif use_nikto and nikto_available:
            log_info("✓ Nikto available - will perform vulnerability scan")

        log_info("Starting web vulnerability scan...")

        # Execute web scan
        result = web_scanner.scan(target, scan_options)

        # Display results
        display_scan_results(result)

        # Save results
        if output:
            output_path = Path(output)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Clean target for filename
            clean_target = (
                target.replace("://", "_").replace("/", "_").replace(":", "_")
            )
            filename = f"web_{clean_target}_{timestamp}.json"
            output_path = REPORT_DIR / filename

        result.save_to_file(output_path)
        log_success(f"Results saved to: {output_path}")

        # Summary
        log_banner("Web Scan Summary", "bold green")
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
        log_warning("Web scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"Web scan failed: {e}")
        if logger.level <= 10:  # DEBUG level
            import traceback

            traceback.print_exc()
        sys.exit(1)


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
@click.option("--include-web", is_flag=True, help="Include web vulnerability scanning")
@click.option("--include-directory", is_flag=True, help="Include directory enumeration")
def scan(
    target,
    profile,
    ports,
    timeout,
    output,
    no_ping,
    timing,
    include_dns,
    include_web,
    include_directory,
):
    """
    Perform a security scan on the specified target.

    TARGET can be an IP address, domain name, or URL.

    Examples:
    \b
        auto-pentest scan 192.168.1.1
        auto-pentest scan example.com --profile full
        auto-pentest scan 192.168.1.0/24 --ports 80,443,8080
        auto-pentest scan target.com --output results.json
        auto-pentest scan example.com --include-dns --include-web
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

        # Determine what to scan based on profile and options
        scan_ports = profile != "web" and not (
            include_web and not include_dns and not ports and not include_directory
        )
        scan_dns = (target_type == "domain" and include_dns) or profile == "full"
        scan_web = include_web or profile in ["web", "full"]
        scan_directory = include_directory or profile == "full"

        # Port scanning (unless web-only profile)
        if scan_ports:
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
        if scan_dns:
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

        # Web scanning (if requested or web profile)
        if scan_web:
            log_info("Starting web vulnerability scan...")

            web_scanner = WebScanner(timeout=timeout)

            # Web scan options
            web_options = {"scheme": "https"}
            if profile == "web":
                web_options["use_nikto"] = True
                web_options["follow_redirects"] = True
            elif profile == "full":
                web_options["use_nikto"] = True
                web_options["follow_redirects"] = True
            else:
                web_options["use_nikto"] = False  # Quick web scan

            web_result = web_scanner.scan(sanitized_target, web_options)
            all_results.append(web_result)

        # Directory scanning (if requested or full profile)
        if scan_directory:
            log_info("Starting directory enumeration...")

            dir_scanner = DirectoryScanner(timeout=timeout)

            # Directory scan options
            dir_options = {"scheme": "https"}
            if profile == "full":
                dir_options["wordlist"] = "big"
                dir_options["extensions"] = True
                dir_options["tool"] = "auto"
            else:
                dir_options["wordlist"] = "common"
                dir_options["extensions"] = False
                dir_options["tool"] = "auto"

            dir_result = dir_scanner.scan(sanitized_target, dir_options)
            all_results.append(dir_result)

        # Handle case where no scans were performed
        if not all_results:
            log_error("No scans were performed. Check your options.")
            sys.exit(1)

        # Display results
        for result in all_results:
            display_scan_results(result)
            print()  # Add spacing between scanners

        # Combine results for saving
        main_result = all_results[0]  # Use first scan as main result

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
        "dirb": "Directory/file brute forcer",
        "gobuster": "Fast directory/DNS/vhost fuzzer",
        "sqlmap": "SQL injection tester",
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

    # Check requests library
    try:
        import requests

        log_success("✓ requests: Python HTTP library (INSTALLED)")
    except ImportError:
        log_error("✗ requests: Python HTTP library (NOT INSTALLED)")
        log_info("  Install with: pip install requests")

    print()  # Add spacing

    for tool, description in tools.items():
        if executor.check_tool_exists(tool):
            version = executor.get_tool_version(tool)
            version_str = version.split("\n")[0] if version else "unknown version"
            log_success(f"✓ {tool}: {description} ({version_str})")
        else:
            log_error(f"✗ {tool}: {description} (NOT INSTALLED)")

    log_info("\nTo install missing tools on Ubuntu/Debian:")
    log_info(
        "sudo apt update && sudo apt install -y nmap nikto sqlmap dirb gobuster dnsutils"
    )
    log_info("pip install dnspython requests  # For DNS and web scanning")


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
    log_info("  • Web Vulnerability Scanning (nikto + custom)")
    log_info("  • Directory Enumeration (dirb/gobuster)")
    log_info("  • [Coming Soon] Subdomain Discovery")
    log_info("  • [Coming Soon] SSL/TLS Analysis")

    log_info("\nAvailable Commands:")
    log_info("  • scan - Comprehensive security scan")
    log_info("  • web - Web vulnerability scanning")
    log_info("  • directory - Directory and file enumeration")
    log_info("  • dns - DNS enumeration and analysis")
    log_info("  • quick - Quick port scan")
    log_info("  • full - Full comprehensive scan")
    log_info("  • list-tools - Check tool availability")
    log_info("  • info - Show this information")

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


if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        log_warning("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        sys.exit(1)
