"""
Network Commands - Port, DNS, and Network Scanning
FILE PATH: src/cli/commands/network_commands.py

Handles all network-related scanning commands
Following SOLID principles and maintaining backward compatibility
✨ ONLY ADDED: subdomain_command (Phase 4.1)
"""

import click
import sys
from typing import Dict, Any

# Service imports - verified to exist
from ...services.scanner_service import ScannerService
from ...utils.logger import log_error, log_info, log_success, log_warning
from ..options import common_options

# Conditional import for network scanner (backward compatibility)
try:
    from ...scanners.vulnerability.network_scanner import NetworkScanner

    NETWORK_SCANNER_AVAILABLE = True
except ImportError:
    NetworkScanner = None
    NETWORK_SCANNER_AVAILABLE = False


@click.command()
@click.argument("target")
@click.option("--ports", default="1-1000", help="Port range to scan")
@click.option(
    "--scan-type",
    type=click.Choice(["tcp", "udp", "syn"]),
    default="tcp",
    help="Scan type",
)
@click.option("--fast", is_flag=True, help="Fast scan mode")
@common_options
def port_command(target, ports, scan_type, fast, **kwargs):
    """Port scanning with nmap"""
    try:
        scanner_service = ScannerService()
        scanner_service.run_port_scan(target, ports, scan_type, fast, kwargs)
    except Exception as e:
        log_error(f"Port scan failed: {e}")
        sys.exit(1)


@click.command()
@click.argument("target")
@click.option("--subdomain-enum", is_flag=True, help="Enable subdomain enumeration")
@click.option("--zone-transfer", is_flag=True, help="Attempt zone transfer")
@click.option("--dns-bruteforce", is_flag=True, help="DNS bruteforce attack")
@common_options
def dns_command(target, subdomain_enum, zone_transfer, dns_bruteforce, **kwargs):
    """DNS enumeration and analysis"""
    try:
        scanner_service = ScannerService()
        scanner_service.run_dns_scan(
            target, subdomain_enum, zone_transfer, dns_bruteforce, kwargs
        )
    except Exception as e:
        log_error(f"DNS scan failed: {e}")
        sys.exit(1)


@click.command()
@click.argument("domain")
@click.option(
    "--tools",
    type=click.Choice(["subfinder", "amass", "sublist3r", "ct_logs", "all"]),
    multiple=True,
    default=["subfinder", "amass"],
    help="Subdomain enumeration tools to use (can specify multiple)",
)
@click.option(
    "--passive-only", is_flag=True, help="Use only passive enumeration methods"
)
@click.option(
    "--use-wordlist",
    is_flag=True,
    default=True,
    help="Enable wordlist-based enumeration",
)
@click.option(
    "--wordlist-size",
    type=click.Choice(["small", "medium", "large"]),
    default="medium",
    help="Wordlist size for enumeration",
)
@click.option(
    "--verify-alive", is_flag=True, help="Verify that discovered subdomains are alive"
)
@click.option(
    "--recursive-depth", type=int, default=1, help="Recursive subdomain discovery depth"
)
@click.option(
    "--rate-limit",
    type=float,
    default=1.0,
    help="Rate limit between requests (seconds)",
)
@click.option(
    "--max-results",
    type=int,
    default=10000,
    help="Maximum number of subdomains to discover",
)
# Report generation options (MANDATORY for CLI services)
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--txt-report", is_flag=True, help="Generate TXT report")
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--all-reports", is_flag=True, help="Generate all report formats")
@click.option(
    "--output-dir",
    type=click.Path(),
    default="output/subdomains",
    help="Output directory for results and reports",
)
@common_options
def subdomain_command(
    domain,
    tools,
    passive_only,
    use_wordlist,
    wordlist_size,
    verify_alive,
    recursive_depth,
    rate_limit,
    max_results,
    json_report,
    txt_report,
    html_report,
    all_reports,
    output_dir,
    **kwargs,
):
    """
    Advanced subdomain enumeration using multiple tools

    Integrates Subfinder, Amass, Sublist3r, and Certificate Transparency logs
    for comprehensive subdomain discovery and analysis.

    Examples:
        \b
        # Basic subdomain enumeration
        python main.py subdomain example.com

        \b
        # Use all available tools with reports
        python main.py subdomain example.com --tools all --all-reports

        \b
        # Passive-only enumeration with JSON output
        python main.py subdomain example.com --passive-only --json-report

        \b
        # Custom configuration with specific tools
        python main.py subdomain example.com --tools subfinder --tools amass --verify-alive --html-report
    """
    try:
        log_info(f"🔍 Starting advanced subdomain enumeration for: {domain}")

        # Import service (verified import path)
        from ...services.subdomain_service import SubdomainService

        # Prepare enumeration options
        enumeration_options = {
            "tools": (
                list(tools)
                if tools != ("all",)
                else ["subfinder", "amass", "sublist3r", "ct_logs"]
            ),
            "passive_only": passive_only,
            "use_wordlist": use_wordlist,
            "wordlist_size": wordlist_size,
            "verify_alive": verify_alive,
            "recursive_depth": recursive_depth,
            "rate_limit": rate_limit,
            "max_results": max_results,
            "output_dir": output_dir,
            # Report generation options (MANDATORY)
            "json_report": json_report,
            "txt_report": txt_report,
            "html_report": html_report,
            "all_reports": all_reports,
            # Include common options
            **kwargs,
        }

        # Initialize and execute subdomain service
        subdomain_service = SubdomainService()

        log_info(
            f"📋 Configuration: {len(enumeration_options['tools'])} tools selected"
        )

        # Execute enumeration
        result = subdomain_service.enumerate_subdomains(domain, enumeration_options)

        # Display results summary
        _display_subdomain_results(result)

        # Success message
        log_success(
            f"✅ Subdomain enumeration completed: {result['statistics']['total_unique_subdomains']} unique subdomains discovered"
        )

        # Report generation confirmation
        if result.get("report_generated", {}).get("generated", False):
            report_formats = result["report_generated"]["formats"]
            log_success(f"📄 Reports generated: {', '.join(report_formats).upper()}")

    except KeyboardInterrupt:
        log_warning("🛑 Subdomain enumeration interrupted by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"💥 Subdomain enumeration failed: {e}")
        sys.exit(1)


def _display_subdomain_results(result: Dict[str, Any]) -> None:
    """
    Display subdomain enumeration results in a formatted way

    Args:
        result: SubdomainService result dictionary
    """
    stats = result.get("statistics", {})
    subdomains = result.get("unique_subdomains", [])

    # Display header
    log_info("=" * 60)
    log_info("🔍 SUBDOMAIN ENUMERATION RESULTS")
    log_info("=" * 60)

    # Display statistics
    log_info(f"📊 STATISTICS:")
    log_info(f"   • Target Domain: {result.get('domain', 'Unknown')}")
    log_info(f"   • Unique Subdomains: {stats.get('total_unique_subdomains', 0)}")
    log_info(f"   • Tools Used: {stats.get('tools_used', 0)}")
    log_info(f"   • Successful Tools: {stats.get('successful_tools', 0)}")

    # Display tool contributions
    if "tool_contributions" in stats:
        log_info(f"🔧 TOOL CONTRIBUTIONS:")
        for tool, count in stats["tool_contributions"].items():
            log_info(f"   • {tool.upper()}: {count} subdomains")

    # Display subdomain levels
    if "subdomain_levels" in stats:
        levels = stats["subdomain_levels"]
        log_info(f"📊 SUBDOMAIN LEVELS:")
        log_info(f"   • Level 1: {levels.get('1', 0)} subdomains")
        log_info(f"   • Level 2: {levels.get('2', 0)} subdomains")
        log_info(f"   • Level 3: {levels.get('3', 0)} subdomains")
        log_info(f"   • Level 4+: {levels.get('4+', 0)} subdomains")

    # Display first 20 subdomains for preview
    if subdomains:
        log_info(f"📋 DISCOVERED SUBDOMAINS (showing first 20):")
        display_count = min(20, len(subdomains))
        for i, subdomain in enumerate(subdomains[:display_count], 1):
            log_info(f"   {i:2d}. {subdomain}")

        if len(subdomains) > 20:
            log_info(f"   ... and {len(subdomains) - 20} more subdomains")
            log_info("   💡 Use --json-report or --txt-report to see complete results")

    # Display errors if any
    errors = result.get("errors", [])
    if errors:
        log_warning(f"⚠️ ENUMERATION WARNINGS:")
        for error in errors:
            log_warning(f"   • {error}")

    log_info("=" * 60)


@click.command()
@click.argument("target")
@click.option(
    "--templates",
    type=click.Choice(["default", "critical", "high", "all", "custom"]),
    default="default",
    help="Nuclei template selection",
)
@click.option("--rate-limit", default=150, help="Request rate limit per second")
@click.option(
    "--service-analysis", is_flag=True, help="Enable network service analysis"
)
@click.option(
    "--protocol-analysis", is_flag=True, help="Enable protocol security analysis"
)
@click.option("--template-path", help="Custom template path (for --templates custom)")
@click.option("--timeout", default=600, help="Scan timeout in seconds")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@common_options
def network_command(
    target,
    templates,
    rate_limit,
    service_analysis,
    protocol_analysis,
    template_path,
    timeout,
    json_report,
    html_report,
    **kwargs,
):
    """Network vulnerability scanning using Nuclei and custom analysis"""
    try:
        # Check if NetworkScanner is available
        if NetworkScanner is None:
            log_error(
                "❌ Network Scanner not available. Please ensure all dependencies are installed."
            )
            sys.exit(1)

        scanner_service = ScannerService()

        # Check if run_network_scan method exists for backward compatibility
        if not hasattr(scanner_service, "run_network_scan"):
            log_error(
                "❌ Network scanning functionality not available in this version."
            )
            sys.exit(1)

        # Build additional options for reports
        additional_options = {
            "json_report": json_report,
            "html_report": html_report,
            # "pdf_report": pdf_report,
            # "all_reports": all_reports,
            # "output_dir": output_dir,
            # "save_raw": save_raw,
        }

        # Merge with common options
        additional_options.update(kwargs)

        # Execute network scan with correct parameter count
        log_info(f"🔍 Starting network vulnerability scan for {target}")
        scanner_service.run_network_scan(
            target,
            templates,
            rate_limit,
            service_analysis,
            protocol_analysis,
            template_path,
            timeout,
            additional_options,
        )
        log_success("✅ Network scan completed successfully")

    except Exception as e:
        log_error(f"❌ Network scan failed: {e}")
        sys.exit(1)


# Export all network commands for import
# ✨ ONLY ADDED subdomain_command to exports
__all__ = [
    "port_command",
    "dns_command",
    "subdomain_command",  # ✨ ONLY THIS ADDED
    "network_command",  # ⚠️ UNCHANGED
]
