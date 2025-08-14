"""
Info Service
Displays framework information and capabilities
"""

from ..utils.logger import log_info


class InfoService:
    """Service for displaying framework information"""

    def display_info(self) -> None:
        """Display comprehensive framework information"""
        log_info("Auto-Pentest Framework Information")
        log_info("=" * 40)

        self._display_scanners()
        self._display_profiles()
        self._display_reports()
        self._display_features()

    def _display_scanners(self) -> None:
        """Display available scanners"""
        log_info("Available Scanners:")
        log_info("  • Port Scanner (Nmap integration)")
        log_info("  • DNS Scanner (DNS enumeration)")
        log_info("  • Web Scanner (Web vulnerability assessment)")
        log_info("  • Directory Scanner (Directory/file enumeration)")
        log_info("  • SSL Scanner (SSL/TLS security analysis)")
        log_info("")

    def _display_profiles(self) -> None:
        """Display scan profiles"""
        log_info("Scan Profiles:")
        log_info("  • quick: Fast reconnaissance scan")
        log_info("  • web: Web-focused vulnerability assessment")
        log_info("  • full: Comprehensive security assessment")
        log_info("  • custom: User-defined scanner combination")
        log_info("")

    def _display_reports(self) -> None:
        """Display report formats"""
        log_info("Report Formats:")
        log_info("  • JSON: Structured data format")
        log_info("  • PDF: Professional presentation format")
        log_info("  • TXT: Plain text format")
        log_info("  • CSV: Comma-separated values")
        log_info("  • HTML: Web-based report")
        log_info("")

    def _display_features(self) -> None:
        """Display framework features"""
        log_info("Key Features:")
        log_info("  • Parallel and sequential execution")
        log_info("  • Comprehensive reporting")
        log_info("  • Custom branding support")
        log_info("  • Flexible target formats")
        log_info("  • Professional PDF exports")
        log_info("  • CLI and workflow orchestration")
