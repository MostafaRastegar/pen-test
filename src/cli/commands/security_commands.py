"""
Security Commands - WAF Detection and Security Analysis
FILE PATH: src/cli/commands/security_commands.py

Handles security-focused commands like WAF detection and bypass testing
Following SOLID principles and maintaining backward compatibility
"""

import click
import sys
from typing import Dict, Any

# Service imports - verified to exist
from ...services.scanner_service import ScannerService
from ...utils.logger import log_error, log_info, log_success, log_warning
from ..options import common_options

# Conditional import for WAF scanner (backward compatibility)
try:
    from ...scanners.security import WAFScanner

    WAF_SCANNER_AVAILABLE = True
except ImportError:
    WAFScanner = None
    WAF_SCANNER_AVAILABLE = False


@click.command()
@click.argument("target")
@click.option("--aggressive", is_flag=True, help="Use aggressive WAF detection methods")
@click.option(
    "--detection-only", is_flag=True, help="Only detect WAF, don't test bypasses"
)
@click.option("--timeout", default=300, help="WAF scan timeout in seconds")
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--pdf-report", is_flag=True, help="Generate PDF report")
@click.option("--all-reports", is_flag=True, help="Generate all report formats")
@click.option(
    "--output-dir", default="output/reports", help="Output directory for reports"
)
@common_options
def waf_command(
    target,
    aggressive,
    detection_only,
    timeout,
    json_report,
    html_report,
    pdf_report,
    all_reports,
    output_dir,
    **kwargs,
):
    """WAF detection and bypass testing"""
    try:
        # Check if WAF Scanner is available
        if WAFScanner is None:
            log_error(
                "❌ WAF Scanner not available. Please ensure all dependencies are installed."
            )
            sys.exit(1)

        scanner_service = ScannerService()

        # Check if run_waf_scan method exists for backward compatibility
        if not hasattr(scanner_service, "run_waf_scan"):
            log_error("❌ WAF scanning functionality not available in this version.")
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

        # Execute WAF scan with correct parameter count
        log_info(f"🔍 Starting WAF detection scan for {target}")
        scanner_service.run_waf_scan(
            target, aggressive, detection_only, timeout, additional_options
        )
        log_success("✅ WAF scan completed successfully")

    except Exception as e:
        log_error(f"❌ WAF scan failed: {e}")
        sys.exit(1)


# Export commands for easy import
# Note: waf_command only exported if available for backward compatibility
__all__ = []
if WAF_SCANNER_AVAILABLE:
    __all__.append("waf_command")
