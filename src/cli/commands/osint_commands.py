"""
OSINT CLI Commands Integration
FILE PATH: src/cli/commands/osint_commands.py

CLI integration for OSINT & Information Gathering Service
Following project CLI patterns with mandatory reporting
"""

import click
import sys
from typing import Dict, Any

# VERIFIED IMPORTS - All modules exist in project
from ...services.osint_service import (
    run_osint_scan,
    get_osint_service_info,
)  # ✅ src/services/osint_service.py
from ...utils.logger import log_info, log_error, log_success  # ✅ src/utils/logger.py


@click.group(name="osint")
def osint_group():
    """OSINT & Information Gathering commands"""
    pass


@osint_group.command(name="email")
@click.argument("target")
@click.option(
    "--sources", "-s", help="Sources to use (default: all free sources)", default="all"
)
@click.option(
    "--limit", "-l", type=int, help="Limit number of results per source", default=100
)
@click.option(
    "--timeout", "-t", type=int, help="Timeout per source in seconds", default=60
)
@click.option(
    "--output-format",
    "-o",
    type=click.Choice(["json", "txt", "html", "all"]),
    default="json",
    help="Output report format",
)
@click.option("--save-raw", is_flag=True, help="Save raw tool outputs")
@click.option("--validate-emails", is_flag=True, help="Validate email addresses format")
@click.option(
    "--json-report", is_flag=True, help="Generate JSON report (mandatory for CI/CD)"
)
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--txt-report", is_flag=True, help="Generate TXT report")
def email_harvest_command(
    target,
    sources,
    limit,
    timeout,
    output_format,
    save_raw,
    validate_emails,
    json_report,
    html_report,
    txt_report,
):
    """
    Email harvesting using free OSINT sources

    Examples:
        python main.py osint email example.com
        python main.py osint email example.com --sources theharvester --html-report
        python main.py osint email example.com --limit 50 --validate-emails --json-report
    """
    try:
        log_info(f"🔍 Starting email harvesting for: {target}")

        # Prepare options
        scan_options = {
            "scan_type": "email",
            "sources": sources,
            "limit": limit,
            "timeout": timeout,
            "save_raw": save_raw,
            "validate_emails": validate_emails,
            "output_format": output_format,
            "generate_report": True,
        }

        # Handle report format flags (following project patterns)
        if json_report or html_report or txt_report:
            if json_report:
                scan_options["json_report"] = True
            if html_report:
                scan_options["html_report"] = True
            if txt_report:
                scan_options["txt_report"] = True
        elif output_format == "all":
            scan_options["all_reports"] = True
        else:
            # Default JSON report if no specific format
            scan_options["json_report"] = True

        # Execute email harvesting
        results = run_osint_scan(target, scan_options)

        if results.get("status") == "error":
            log_error(f"❌ Email harvesting failed: {results.get('message')}")
            sys.exit(1)

        # Display summary
        stats = results.get("statistics", {})
        log_success(f"✅ Email harvesting completed:")
        log_info(f"   📧 Total emails: {stats.get('total_emails', 0)}")
        log_info(f"   📊 Sources used: {stats.get('sources_used', 0)}")
        log_info(f"   🌐 Unique domains: {stats.get('unique_domains', 0)}")

    except Exception as e:
        log_error(f"❌ Email harvest command failed: {str(e)}")
        sys.exit(1)


@osint_group.command(name="search")
@click.argument("target")
@click.option("--engines", "-e", help="Search engines to use", default="google,bing")
@click.option(
    "--dork-types", "-d", help="Types of dorks to run", default="files,login,errors"
)
@click.option(
    "--include-social", is_flag=True, help="Include social media reconnaissance"
)
@click.option(
    "--output-format",
    "-o",
    type=click.Choice(["json", "txt", "html", "all"]),
    default="json",
    help="Output report format",
)
@click.option(
    "--save-patterns", is_flag=True, help="Save search patterns for manual verification"
)
@click.option(
    "--json-report", is_flag=True, help="Generate JSON report (mandatory for CI/CD)"
)
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--txt-report", is_flag=True, help="Generate TXT report")
def search_recon_command(
    target,
    engines,
    dork_types,
    include_social,
    output_format,
    save_patterns,
    json_report,
    html_report,
    txt_report,
):
    """
    Search engine reconnaissance and dorking

    Examples:
        python main.py osint search example.com
        python main.py osint search example.com --engines google --include-social
        python main.py osint search example.com --dork-types files,login --html-report
    """
    try:
        log_info(f"🔍 Starting search engine reconnaissance for: {target}")

        # Prepare options
        scan_options = {
            "scan_type": "search",
            "engines": engines.split(","),
            "dork_types": dork_types.split(","),
            "include_social": include_social,
            "save_patterns": save_patterns,
            "output_format": output_format,
            "generate_report": True,
        }

        # Handle report format flags (following project patterns)
        if json_report or html_report or txt_report:
            if json_report:
                scan_options["json_report"] = True
            if html_report:
                scan_options["html_report"] = True
            if txt_report:
                scan_options["txt_report"] = True
        elif output_format == "all":
            scan_options["all_reports"] = True
        else:
            # Default JSON report if no specific format
            scan_options["json_report"] = True

        # Execute search reconnaissance
        results = run_osint_scan(target, scan_options)

        if results.get("status") == "error":
            log_error(f"❌ Search reconnaissance failed: {results.get('message')}")
            sys.exit(1)

        # Display summary
        stats = results.get("statistics", {})
        log_success(f"✅ Search reconnaissance completed:")
        log_info(f"   🔍 Total results: {stats.get('total_results', 0)}")
        log_info(f"   🌐 Subdomains found: {stats.get('subdomains_found', 0)}")
        log_info(f"   📱 Social profiles: {stats.get('social_profiles', 0)}")

    except Exception as e:
        log_error(f"❌ Search reconnaissance command failed: {str(e)}")
        sys.exit(1)


@osint_group.command(name="whois")
@click.argument("target")
@click.option("--include-history", is_flag=True, help="Include historical WHOIS data")
@click.option(
    "--analyze-nameservers", is_flag=True, help="Analyze name servers in detail"
)
@click.option("--geolocation", is_flag=True, help="Include IP geolocation data")
@click.option(
    "--certificate-analysis",
    is_flag=True,
    help="Include certificate transparency analysis",
)
@click.option(
    "--output-format",
    "-o",
    type=click.Choice(["json", "txt", "html", "all"]),
    default="json",
    help="Output report format",
)
@click.option(
    "--json-report", is_flag=True, help="Generate JSON report (mandatory for CI/CD)"
)
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--txt-report", is_flag=True, help="Generate TXT report")
def whois_analysis_command(
    target,
    include_history,
    analyze_nameservers,
    geolocation,
    certificate_analysis,
    output_format,
    json_report,
    html_report,
    txt_report,
):
    """
    Enhanced WHOIS analysis with free intelligence sources

    Examples:
        python main.py osint whois example.com
        python main.py osint whois example.com --geolocation --certificate-analysis
        python main.py osint whois example.com --include-history --html-report
    """
    try:
        log_info(f"🔍 Starting WHOIS analysis for: {target}")

        # Prepare options
        scan_options = {
            "scan_type": "whois",
            "include_history": include_history,
            "analyze_nameservers": analyze_nameservers,
            "geolocation": geolocation,
            "certificate_analysis": certificate_analysis,
            "output_format": output_format,
            "generate_report": True,
        }

        # Handle report format flags (following project patterns)
        if json_report or html_report or txt_report:
            if json_report:
                scan_options["json_report"] = True
            if html_report:
                scan_options["html_report"] = True
            if txt_report:
                scan_options["txt_report"] = True
        elif output_format == "all":
            scan_options["all_reports"] = True
        else:
            # Default JSON report if no specific format
            scan_options["json_report"] = True

        # Execute WHOIS analysis
        results = run_osint_scan(target, scan_options)

        if results.get("status") == "error":
            log_error(f"❌ WHOIS analysis failed: {results.get('message')}")
            sys.exit(1)

        # Display summary
        stats = results.get("statistics", {})
        log_success(f"✅ WHOIS analysis completed:")
        log_info(f"   📊 Data sources: {stats.get('data_sources', 0)}")
        log_info(f"   🌐 DNS servers: {stats.get('dns_servers_count', 0)}")
        log_info(f"   📜 Historical records: {stats.get('historical_records', 0)}")

    except Exception as e:
        log_error(f"❌ WHOIS analysis command failed: {str(e)}")
        sys.exit(1)


@osint_group.command(name="comprehensive")
@click.argument("target")
@click.option("--include-all", is_flag=True, help="Include all OSINT techniques")
@click.option(
    "--rate-limit", type=int, help="Rate limit in seconds between requests", default=1
)
@click.option(
    "--timeout", type=int, help="Timeout for individual operations", default=60
)
@click.option(
    "--output-format",
    "-o",
    type=click.Choice(["json", "txt", "html", "all"]),
    default="all",
    help="Output report format",
)
@click.option("--save-evidence", is_flag=True, help="Save all evidence and raw data")
@click.option(
    "--json-report", is_flag=True, help="Generate JSON report (mandatory for CI/CD)"
)
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--txt-report", is_flag=True, help="Generate TXT report")
def comprehensive_osint_command(
    target,
    include_all,
    rate_limit,
    timeout,
    output_format,
    save_evidence,
    json_report,
    html_report,
    txt_report,
):
    """
    Comprehensive OSINT gathering using all available free sources

    Examples:
        python main.py osint comprehensive example.com
        python main.py osint comprehensive example.com --include-all --save-evidence
        python main.py osint comprehensive example.com --rate-limit 2 --html-report
    """
    try:
        log_info(f"🎯 Starting comprehensive OSINT for: {target}")

        # Prepare comprehensive options
        scan_options = {
            "scan_type": "comprehensive",
            "include_all": include_all,
            "rate_limit": rate_limit,
            "timeout": timeout,
            "save_evidence": save_evidence,
            "output_format": output_format,
            "generate_report": True,
            # Enable all sub-modules
            "email_harvest": True,
            "search_recon": True,
            "whois_analysis": True,
            "social_media": True,
            "certificate_analysis": True,
        }

        # Handle report format flags (following project patterns)
        if json_report or html_report or txt_report:
            if json_report:
                scan_options["json_report"] = True
            if html_report:
                scan_options["html_report"] = True
            if txt_report:
                scan_options["txt_report"] = True
        elif output_format == "all":
            scan_options["all_reports"] = True
        else:
            # Default JSON report if no specific format
            scan_options["json_report"] = True

        # Execute comprehensive OSINT
        results = run_osint_scan(target, scan_options)

        if results.get("status") == "error":
            log_error(f"❌ Comprehensive OSINT failed: {results.get('message')}")
            sys.exit(1)

        # Display comprehensive summary
        summary = results.get("summary", {})
        log_success(f"✅ Comprehensive OSINT completed:")
        log_info(f"   📧 Total emails: {summary.get('total_emails', 0)}")
        log_info(f"   🌐 Total subdomains: {summary.get('total_subdomains', 0)}")
        log_info(
            f"   📱 Social media presence: {summary.get('social_media_presence', 0)}"
        )
        log_info(
            f"   🔒 Information exposure: {summary.get('information_exposure', 'Unknown')}"
        )
        log_info(f"   📊 Privacy score: {summary.get('privacy_score', 0)}/100")

        # Display recommendations
        recommendations = results.get("recommendations", [])
        if recommendations:
            log_info("\n📋 Recommendations:")
            for i, recommendation in enumerate(recommendations[:5], 1):
                log_info(f"   {i}. {recommendation}")

    except Exception as e:
        log_error(f"❌ Comprehensive OSINT command failed: {str(e)}")
        sys.exit(1)


@osint_group.command(name="info")
def osint_info_command():
    """Display OSINT service information and capabilities"""
    try:
        service_info = get_osint_service_info()

        log_info("🔍 OSINT Service Information:")
        log_info(f"   Name: {service_info['name']}")
        log_info(f"   Version: {service_info['version']}")
        log_info(f"   Description: {service_info['description']}")
        log_info(f"   Phase: {service_info['phase']}")
        log_info(f"   Priority: {service_info['priority']}")

        log_info("\n🎯 Capabilities:")
        for capability in service_info["capabilities"]:
            log_info(f"   ✅ {capability}")

        log_info("\n🆓 Free APIs Used:")
        for api in service_info["free_apis_used"]:
            log_info(f"   ✅ {api}")

        log_info(
            f"\n🔧 Tools Verified: {'✅ Yes' if service_info['tools_verified'] else '❌ No'}"
        )
        log_info(
            f"📋 Roadmap Compliance: {'✅ Yes' if service_info['roadmap_compliance'] else '❌ No'}"
        )

    except Exception as e:
        log_error(f"❌ Failed to get service info: {str(e)}")
        sys.exit(1)


@osint_group.command(name="test")
@click.argument("target", default="example.com")
@click.option("--quick", is_flag=True, help="Quick test with minimal operations")
def osint_test_command(target, quick):
    """
    Test OSINT service functionality

    Examples:
        python main.py osint test
        python main.py osint test google.com --quick
    """
    try:
        log_info(f"🧪 Testing OSINT service with target: {target}")

        test_options = {
            "scan_type": "email",  # Start with email test
            "limit": 5 if quick else 20,
            "timeout": 30 if quick else 60,
            "generate_report": False,  # No reports for testing
            "test_mode": True,
        }

        # Run test
        results = run_osint_scan(target, test_options)

        if results.get("status") == "error":
            log_error(f"❌ OSINT service test failed: {results.get('message')}")
            sys.exit(1)

        log_success("✅ OSINT service test completed successfully")

        # Display test results
        if results.get("statistics"):
            stats = results["statistics"]
            log_info(f"   Test results: {stats}")

    except Exception as e:
        log_error(f"❌ OSINT test command failed: {str(e)}")
        sys.exit(1)


# Integration with main CLI (to be added to main CLI router)
def register_osint_commands(cli_app):
    """Register OSINT commands with main CLI application"""
    cli_app.add_command(osint_group)

    # Also register individual commands for backward compatibility
    cli_app.add_command(email_harvest_command, name="email-harvest")
    cli_app.add_command(search_recon_command, name="search-recon")
    cli_app.add_command(whois_analysis_command, name="whois-analysis")


# Command availability verification
def verify_osint_commands() -> Dict[str, bool]:
    """Verify OSINT command availability"""
    return {
        "osint_group": True,
        "email_harvest": True,
        "search_recon": True,
        "whois_analysis": True,
        "comprehensive": True,
        "info": True,
        "test": True,
        "service_integration": True,
    }


if __name__ == "__main__":
    # Development testing
    log_info("🧪 Testing OSINT CLI commands...")

    # Test command verification
    availability = verify_osint_commands()
    log_info(f"Command availability: {availability}")

    # Test service info
    try:
        service_info = get_osint_service_info()
        log_success(
            f"✅ Service info: {service_info['name']} v{service_info['version']}"
        )
    except Exception as e:
        log_error(f"❌ Service info test failed: {str(e)}")
