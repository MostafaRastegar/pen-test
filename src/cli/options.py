"""
Common CLI Options
Reusable options following DRY principle
"""

import click
from functools import wraps


def common_options(func):
    """Common options decorator for all scanner commands"""

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


def reporting_options(func):
    """Reporting specific options"""

    @click.option("--json-output", is_flag=True, help="Generate JSON report")
    @click.option("--html-output", is_flag=True, help="Generate HTML report")
    @click.option("--pdf-output", is_flag=True, help="Generate PDF report")
    @click.option("--csv-output", is_flag=True, help="Generate CSV report")
    @click.option("--txt-output", is_flag=True, help="Generate TXT report")
    @click.option("--all-formats", is_flag=True, help="Generate all report formats")
    @click.option("--report-template", help="Custom report template")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def scanner_options(func):
    """Scanner specific options"""

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


def workflow_options(func):
    """Workflow orchestration options"""

    @click.option(
        "--execution-mode",
        type=click.Choice(["parallel", "sequential", "mixed"]),
        default="parallel",
        help="Execution mode",
    )
    @click.option("--max-workers", default=4, help="Maximum number of worker threads")
    @click.option("--fail-fast", is_flag=True, help="Stop on first failure")
    @click.option("--continue-on-error", is_flag=True, help="Continue on errors")
    @click.option("--phase-timeout", default=1800, help="Per-phase timeout")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def target_options(func):
    """Target specification options"""

    @click.option("--target-file", help="File containing multiple targets")
    @click.option("--exclude", help="Targets to exclude")
    @click.option("--include-private", is_flag=True, help="Include private IP ranges")
    @click.option("--resolve-hostnames", is_flag=True, help="Resolve hostnames to IPs")
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper
