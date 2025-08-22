"""
CMS Commands - WordPress and CMS Security Testing
FILE PATH: src/cli/commands/cms_commands.py

Handles CMS-specific security testing commands
Following SOLID principles and maintaining backward compatibility
"""

import click
import sys
from typing import Dict, Any

# Service imports - verified to exist
from ...services.scanner_service import ScannerService
from ...utils.logger import log_error, log_info, log_success, log_warning
from ..options import common_options

# Conditional import for WordPress scanner (backward compatibility)
try:
    from ...scanners.cms import WordPressScanner

    WORDPRESS_SCANNER_AVAILABLE = True
except ImportError:
    WordPressScanner = None
    WORDPRESS_SCANNER_AVAILABLE = False


@click.command()
@click.argument("target")
@click.option(
    "--plugin-check", is_flag=True, default=True, help="Check for vulnerable plugins"
)
@click.option(
    "--theme-check", is_flag=True, default=True, help="Check for vulnerable themes"
)
@click.option(
    "--user-enum", is_flag=True, default=True, help="Enumerate WordPress users"
)
@click.option(
    "--brute-force-test",
    is_flag=True,
    help="Test common username/password combinations",
)
@click.option(
    "--wpscan-api-token", help="WPScan API token for enhanced vulnerability data"
)
@click.option("--timeout", default=600, help="WordPress scan timeout in seconds")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--pdf-report", is_flag=True, help="Generate PDF report")
@click.option("--all-reports", is_flag=True, help="Generate all report formats")
@click.option(
    "--output-dir", default="output/reports", help="Output directory for reports"
)
@common_options
def wordpress_command(
    target,
    plugin_check,
    theme_check,
    user_enum,
    brute_force_test,
    wpscan_api_token,
    timeout,
    json_report,
    html_report,
    pdf_report,
    all_reports,
    output_dir,
    **kwargs,
):
    """WordPress security scanning and vulnerability assessment"""
    try:
        # Check if WordPress Scanner is available
        if WordPressScanner is None:
            log_error(
                "❌ WordPress Scanner not available. Please ensure all dependencies are installed."
            )
            sys.exit(1)

        scanner_service = ScannerService()

        # Check if run_wordpress_scan method exists for backward compatibility
        if not hasattr(scanner_service, "run_wordpress_scan"):
            log_error(
                "❌ WordPress scanning functionality not available in this version."
            )
            sys.exit(1)

        # Build additional options
        additional_options = {
            "json_report": json_report,
            "html_report": html_report,
            "pdf_report": pdf_report,
            "all_reports": all_reports,
            "output_dir": output_dir,
        }

        # Merge with common options
        additional_options.update(kwargs)

        # Execute WordPress scan with correct parameter count
        log_info(f"🔍 Starting WordPress security scan for {target}")
        scanner_service.run_wordpress_scan(
            target,
            plugin_check,
            theme_check,
            user_enum,
            brute_force_test,
            wpscan_api_token,
            timeout,
            additional_options,
        )
        log_success("✅ WordPress scan completed successfully")

    except Exception as e:
        log_error(f"❌ WordPress scan failed: {e}")
        sys.exit(1)


# Export commands for easy import
# Note: wordpress_command only exported if available for backward compatibility
__all__ = []
if WORDPRESS_SCANNER_AVAILABLE:
    __all__.append("wordpress_command")
