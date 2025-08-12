#!/usr/bin/env python3
"""
Test PDF Generation - Verify PDF export functionality
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.core import ScanResult, ScanStatus, ScanSeverity
from src.utils.reporter import ReportGenerator
from src.utils.logger import (
    LoggerSetup,
    log_banner,
    log_success,
    log_error,
    log_info,
    log_warning,
)
from datetime import datetime


def create_sample_scan_result():
    """Create a sample scan result for testing"""
    result = ScanResult(
        scanner_name="test_scanner",
        target="test.example.com",
        start_time=datetime.now(),
        status=ScanStatus.COMPLETED,
    )

    # Add some sample findings
    findings = [
        {
            "title": "Open SSH Port",
            "description": "SSH service is running on port 22",
            "severity": "info",
            "category": "Network Services",
            "details": "SSH (Secure Shell) service detected on port 22. This is normal for servers that require remote administration.",
            "recommendation": "Ensure SSH is properly configured with key-based authentication and disable password authentication.",
        },
        {
            "title": "HTTP Service Detected",
            "description": "Web server running on port 80",
            "severity": "low",
            "category": "Web Services",
            "details": "HTTP web server detected. Consider redirecting HTTP traffic to HTTPS.",
            "recommendation": "Configure HTTP to HTTPS redirect for better security.",
        },
        {
            "title": "SSL Certificate Issue",
            "description": "SSL certificate is self-signed",
            "severity": "medium",
            "category": "SSL/TLS",
            "details": "The SSL certificate is self-signed and not trusted by browsers.",
            "recommendation": "Install a valid SSL certificate from a trusted Certificate Authority.",
        },
        {
            "title": "Outdated Web Server",
            "description": "Web server version appears to be outdated",
            "severity": "high",
            "category": "Web Services",
            "details": "The web server version contains known security vulnerabilities.",
            "recommendation": "Update the web server to the latest stable version.",
        },
        {
            "title": "Critical Security Flaw",
            "description": "Critical vulnerability in web application",
            "severity": "critical",
            "category": "Web Application",
            "details": "A critical security vulnerability that could allow remote code execution.",
            "recommendation": "Apply security patches immediately and consider taking the service offline until fixed.",
        },
    ]

    result.findings = findings
    result.metadata = {
        "scan_type": "comprehensive",
        "tool_version": "1.0.0",
        "scan_options": "default",
    }

    result.end_time = datetime.now()
    result.status = ScanStatus.COMPLETED

    return result


def test_pdf_availability():
    """Test if PDF generation libraries are available"""
    log_banner("PDF Library Availability Test", "bold cyan")

    try:
        import weasyprint

        log_success("✓ WeasyPrint available")
        return "weasyprint"
    except ImportError:
        log_warning("⚠ WeasyPrint not available")

    try:
        import pdfkit

        log_success("✓ PDFKit available")
        return "pdfkit"
    except ImportError:
        log_warning("⚠ PDFKit not available")

    log_error("✗ No PDF generation libraries available")
    log_info("Install with: pip install weasyprint  OR  pip install pdfkit")
    return None


def test_html_generation():
    """Test HTML report generation"""
    log_banner("HTML Report Generation Test", "bold yellow")

    try:
        # Create sample data
        result = create_sample_scan_result()

        # Initialize reporter
        reporter = ReportGenerator()

        # Generate HTML report
        output_path = Path("test_output") / "test_report.html"
        output_path.parent.mkdir(exist_ok=True)

        success = reporter.generate_html_report(
            [result], output_path, "Test Security Report"
        )

        if success and output_path.exists():
            log_success(f"✓ HTML report generated: {output_path}")
            log_info(f"File size: {output_path.stat().st_size} bytes")
            return True
        else:
            log_error("✗ HTML report generation failed")
            return False

    except Exception as e:
        log_error(f"✗ HTML generation error: {e}")
        return False


def test_pdf_generation():
    """Test PDF report generation"""
    log_banner("PDF Report Generation Test", "bold green")

    pdf_lib = test_pdf_availability()
    if not pdf_lib:
        log_warning("Skipping PDF test - no PDF libraries available")
        return False

    try:
        # Create sample data
        result = create_sample_scan_result()

        # Initialize reporter
        reporter = ReportGenerator()

        # Generate PDF report
        output_path = Path("test_output") / "test_report.pdf"
        output_path.parent.mkdir(exist_ok=True)

        log_info(f"Generating PDF using {pdf_lib}...")
        success = reporter.generate_pdf_report(
            [result], output_path, "Test Security Report"
        )

        if success and output_path.exists():
            log_success(f"✓ PDF report generated: {output_path}")
            log_info(f"File size: {output_path.stat().st_size} bytes")
            return True
        else:
            log_error("✗ PDF report generation failed")
            return False

    except Exception as e:
        log_error(f"✗ PDF generation error: {e}")
        log_info("This might be due to missing system dependencies")
        log_info(
            "For WeasyPrint: sudo apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0"
        )
        log_info("For PDFKit: sudo apt install wkhtmltopdf")
        return False


def test_custom_branding():
    """Test custom branding functionality"""
    log_banner("Custom Branding Test", "bold magenta")

    try:
        # Custom branding configuration
        branding = {
            "company_name": "Test Security Inc.",
            "primary_color": "#2563eb",
            "secondary_color": "#1e40af",
            "accent_color": "#3b82f6",
        }

        # Create sample data
        result = create_sample_scan_result()

        # Initialize reporter with custom branding
        reporter = ReportGenerator(branding=branding)

        # Generate branded HTML report
        output_path = Path("test_output") / "test_branded_report.html"
        success = reporter.generate_html_report(
            [result], output_path, "Branded Security Report"
        )

        if success and output_path.exists():
            log_success(f"✓ Branded HTML report generated: {output_path}")

            # Check if branding is applied
            with open(output_path, "r") as f:
                content = f.read()
                if "Test Security Inc." in content and "#2563eb" in content:
                    log_success("✓ Custom branding applied successfully")
                    return True
                else:
                    log_warning("⚠ Custom branding may not be fully applied")
                    return False
        else:
            log_error("✗ Branded report generation failed")
            return False

    except Exception as e:
        log_error(f"✗ Custom branding error: {e}")
        return False


def test_executive_summary():
    """Test executive summary generation"""
    log_banner("Executive Summary Test", "bold blue")

    try:
        # Create sample data
        result = create_sample_scan_result()

        # Initialize reporter
        reporter = ReportGenerator()

        # Generate executive summary
        output_path = Path("test_output") / "test_executive_summary.txt"
        success = reporter.generate_executive_summary([result], output_path)

        if success and output_path.exists():
            log_success(f"✓ Executive summary generated: {output_path}")

            # Check content
            with open(output_path, "r") as f:
                content = f.read()
                if "EXECUTIVE SUMMARY" in content and "CRITICAL" in content:
                    log_success("✓ Executive summary content looks good")
                    return True
                else:
                    log_warning("⚠ Executive summary content may be incomplete")
                    return False
        else:
            log_error("✗ Executive summary generation failed")
            return False

    except Exception as e:
        log_error(f"✗ Executive summary error: {e}")
        return False


def test_comprehensive_reporting():
    """Test comprehensive report generation"""
    log_banner("Comprehensive Reporting Test", "bold red")

    try:
        from src.utils.reporter import generate_comprehensive_report

        # Create sample data
        result = create_sample_scan_result()

        # Custom branding
        branding = {
            "company_name": "Comprehensive Test Co.",
            "primary_color": "#059669",
        }

        # Generate comprehensive report
        output_dir = Path("test_output") / "comprehensive"
        generated_files = generate_comprehensive_report(
            [result],
            output_dir,
            "comprehensive_test",
            include_pdf=True,
            branding=branding,
        )

        log_success(f"✓ Generated {len(generated_files)} report files")
        for report_type, file_path in generated_files.items():
            log_info(f"  {report_type}: {file_path}")

        return len(generated_files) > 0

    except Exception as e:
        log_error(f"✗ Comprehensive reporting error: {e}")
        return False


def cleanup_test_files():
    """Clean up test files"""
    log_info("Cleaning up test files...")

    import shutil

    test_dir = Path("test_output")
    if test_dir.exists():
        shutil.rmtree(test_dir)
        log_info("✓ Test files cleaned up")


def main():
    """Run all PDF generation tests"""
    # Setup logging
    logger = LoggerSetup.setup_logger(name="pdf-test", level="INFO", use_rich=True)

    log_banner("Auto-Pentest PDF Generation Test Suite", "bold white")

    # Track test results
    tests = []

    # Run tests
    tests.append(("HTML Generation", test_html_generation()))
    tests.append(("PDF Generation", test_pdf_generation()))
    tests.append(("Custom Branding", test_custom_branding()))
    tests.append(("Executive Summary", test_executive_summary()))
    tests.append(("Comprehensive Reporting", test_comprehensive_reporting()))

    # Results summary
    log_banner("Test Results Summary", "bold white")

    passed = 0
    total = len(tests)

    for test_name, result in tests:
        if result:
            log_success(f"✓ {test_name}")
            passed += 1
        else:
            log_error(f"✗ {test_name}")

    log_info(f"\nPassed: {passed}/{total} tests")

    if passed == total:
        log_success("🎉 All tests passed! PDF generation is ready to use.")
    elif passed >= total - 1:
        log_warning("⚠ Most tests passed. Minor issues may exist.")
    else:
        log_error("❌ Multiple test failures. Please check your installation.")

    # Cleanup
    cleanup_test_files()

    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
