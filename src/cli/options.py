"""
Enhanced Options - Organized CLI Options Following DRY Principle
FILE PATH: src/cli/options.py

Organized option groups to eliminate repetition and improve maintainability
Following DRY principle and clean architecture
"""

import click
from functools import wraps
from typing import Callable, Any


# === CORE OPTION GROUPS ===


def common_options(func: Callable) -> Callable:
    """Common options for all scanner commands - DRY principle"""

    @click.option("--output", help="Output directory")
    @click.option(
        "--format",
        type=click.Choice(["json", "txt", "csv"]),
        default="json",
        help="Output format",
    )
    @click.option("--verbose", "-v", is_flag=True, help="Verbose output")
    @click.option("--debug", is_flag=True, help="Debug output")
    @click.option("--no-color", is_flag=True, help="Disable colored output")
    @click.option("--save-raw", is_flag=True, help="Save raw tool output")
    @click.option("--custom-branding", help="Custom branding for reports")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def reporting_options(func: Callable) -> Callable:
    """Comprehensive reporting options - eliminates repetition across commands"""

    @click.option("--json-report", is_flag=True, help="Generate JSON report")
    @click.option("--html-report", is_flag=True, help="Generate HTML report")
    @click.option("--pdf-report", is_flag=True, help="Generate PDF report")
    @click.option("--txt-report", is_flag=True, help="Generate TXT report")
    @click.option("--csv-report", is_flag=True, help="Generate CSV report")
    @click.option("--all-reports", is_flag=True, help="Generate all report formats")
    @click.option(
        "--output-dir", default="output/reports", help="Output directory for reports"
    )
    @click.option("--report-template", help="Custom report template")
    @click.option("--report-title", help="Custom report title")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def scanner_options(func: Callable) -> Callable:
    """Common scanner configuration options"""

    @click.option("--timeout", default=300, help="Scanner timeout in seconds")
    @click.option("--threads", default=10, help="Number of threads")
    @click.option("--rate-limit", help="Rate limiting (requests per second)")
    @click.option("--user-agent", help="Custom User-Agent string")
    @click.option("--proxy", help="Proxy URL (http://proxy:port)")
    @click.option("--retry-count", default=3, help="Number of retries on failure")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def network_options(func: Callable) -> Callable:
    """Network scanning specific options"""

    @click.option("--ports", default="1-65535", help="Port range to scan")
    @click.option(
        "--scan-type",
        type=click.Choice(["tcp", "udp", "syn", "connect"]),
        default="syn",
        help="Network scan type",
    )
    @click.option("--fast", is_flag=True, help="Fast scan mode (top 1000 ports)")
    @click.option("--service-detection", is_flag=True, help="Enable service detection")
    @click.option("--os-detection", is_flag=True, help="Enable OS detection")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def web_options(func: Callable) -> Callable:
    """Web scanning specific options"""

    @click.option("--scan-depth", default=3, help="Web crawling depth")
    @click.option("--max-pages", default=100, help="Maximum pages to scan")
    @click.option("--follow-redirects", is_flag=True, help="Follow HTTP redirects")
    @click.option(
        "--check-forms", is_flag=True, help="Analyze forms for vulnerabilities"
    )
    @click.option("--check-headers", is_flag=True, help="Check security headers")
    @click.option(
        "--technology-detection", is_flag=True, help="Detect web technologies"
    )
    @click.option("--cookie-jar", help="Path to cookie jar file")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def dns_options(func: Callable) -> Callable:
    """DNS enumeration specific options"""

    @click.option("--subdomain-enum", is_flag=True, help="Enable subdomain enumeration")
    @click.option("--zone-transfer", is_flag=True, help="Attempt DNS zone transfer")
    @click.option("--dns-bruteforce", is_flag=True, help="DNS bruteforce attack")
    @click.option("--dns-wordlist", help="Custom DNS wordlist path")
    @click.option("--dns-servers", help="Custom DNS servers (comma-separated)")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def ssl_options(func: Callable) -> Callable:
    """SSL/TLS analysis specific options"""

    @click.option("--check-cert", is_flag=True, help="Check certificate validity")
    @click.option("--check-protocols", is_flag=True, help="Check supported protocols")
    @click.option("--check-ciphers", is_flag=True, help="Check cipher suites")
    @click.option(
        "--check-vulnerabilities", is_flag=True, help="Check for SSL vulnerabilities"
    )
    @click.option(
        "--cert-transparency", is_flag=True, help="Check certificate transparency logs"
    )
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


# === COMPOSITE OPTION GROUPS ===


def full_scan_options(func: Callable) -> Callable:
    """Complete scanning options - combines multiple option groups"""

    @reporting_options
    @scanner_options
    @network_options
    @web_options
    @common_options
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def network_scan_options(func: Callable) -> Callable:
    """Network-focused scanning options"""

    @reporting_options
    @scanner_options
    @network_options
    @dns_options
    @common_options
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def web_scan_options(func: Callable) -> Callable:
    """Web-focused scanning options"""

    @reporting_options
    @scanner_options
    @web_options
    @ssl_options
    @common_options
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


# === SPECIALIZED OPTIONS ===


def api_options(func: Callable) -> Callable:
    """API testing specific options"""

    @click.option("--swagger-url", help="Swagger/OpenAPI documentation URL")
    @click.option(
        "--api-format",
        type=click.Choice(["rest", "graphql", "soap", "grpc"]),
        default="rest",
        help="API format",
    )
    @click.option("--auth-header", help="Authentication header")
    @click.option("--api-key", help="API key for authentication")
    @click.option(
        "--test-methods",
        default="GET,POST,PUT,DELETE,PATCH",
        help="HTTP methods to test",
    )
    @click.option("--fuzz-parameters", is_flag=True, help="Enable parameter fuzzing")
    @click.option("--check-auth", is_flag=True, help="Test authentication mechanisms")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def workflow_options(func: Callable) -> Callable:
    """Workflow execution options"""

    @click.option(
        "--profile",
        type=click.Choice(["quick", "standard", "full", "custom"]),
        default="standard",
        help="Scan profile selection",
    )
    @click.option("--parallel", is_flag=True, help="Run scans in parallel")
    @click.option("--sequential", is_flag=True, help="Run scans sequentially")
    @click.option("--workflow-timeout", default=1800, help="Total workflow timeout")
    @click.option(
        "--continue-on-error", is_flag=True, help="Continue workflow on scanner errors"
    )
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


# === UTILITY FUNCTIONS ===


def get_option_groups():
    """Get list of available option groups"""
    return {
        "common": "Basic options for all commands",
        "reporting": "Report generation options",
        "scanner": "Scanner configuration options",
        "network": "Network scanning options",
        "web": "Web application testing options",
        "dns": "DNS enumeration options",
        "ssl": "SSL/TLS analysis options",
        "api": "API testing options",
        "workflow": "Workflow execution options",
    }


def validate_option_combination(options: dict) -> bool:
    """Validate option combinations for logical consistency"""
    # Example validations
    if options.get("parallel") and options.get("sequential"):
        return False

    if options.get("fast") and options.get("scan_depth", 0) > 1:
        return False

    return True


# Export all option decorators for easy import
__all__ = [
    # Core option groups
    "common_options",
    "reporting_options",
    "scanner_options",
    "network_options",
    "web_options",
    "dns_options",
    "ssl_options",
    # Composite option groups
    "full_scan_options",
    "network_scan_options",
    "web_scan_options",
    # Specialized options
    "api_options",
    "workflow_options",
    # Utility functions
    "get_option_groups",
    "validate_option_combination",
]
