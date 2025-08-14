"""
Utility Services
Small services for version, tools, cache management
"""

import subprocess
import sys
from pathlib import Path
from typing import Optional

from ..utils.logger import log_info, log_error, log_success, log_warning


class VersionService:
    """Service for version information"""

    def display_version(
        self, build_info: bool = False, dependencies: bool = False
    ) -> None:
        """Display version information"""
        log_info("Auto-Pentest Framework v0.9.1")

        if build_info:
            self._display_build_info()

        if dependencies:
            self._display_dependencies()

    def _display_build_info(self) -> None:
        """Display build information"""
        log_info("\nBuild Information:")
        log_info(f"  Python: {sys.version}")
        log_info(f"  Platform: {sys.platform}")

    def _display_dependencies(self) -> None:
        """Display dependencies"""
        log_info("\nKey Dependencies:")
        deps = ["click", "pyyaml", "requests", "dnspython", "colorama", "rich"]
        for dep in deps:
            try:
                __import__(dep)
                log_info(f"  ✅ {dep}")
            except ImportError:
                log_warning(f"  ❌ {dep} (missing)")


class ToolService:
    """Service for tool management"""

    def __init__(self):
        self.tools = {
            "nmap": "Network discovery and port scanning",
            "nikto": "Web server vulnerability scanning",
            "dirb": "Directory and file enumeration",
            "gobuster": "Fast directory enumeration",
            "sslscan": "SSL/TLS configuration analysis",
            "dig": "DNS lookup utility",
            "openssl": "SSL/TLS toolkit",
        }

    def list_tools(
        self, check_status: bool = False, check_versions: bool = False
    ) -> None:
        """List available tools"""
        log_info("Security Tools:")

        for tool, description in self.tools.items():
            status = ""

            if check_status:
                if self._check_tool_available(tool):
                    status = " ✅"
                else:
                    status = " ❌"

            if check_versions and status == " ✅":
                version = self._get_tool_version(tool)
                if version:
                    status += f" ({version})"

            log_info(f"  • {tool}: {description}{status}")

    def _check_tool_available(self, tool: str) -> bool:
        """Check if tool is available"""
        try:
            result = subprocess.run(
                ["which", tool], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except:
            return False

    def _get_tool_version(self, tool: str) -> Optional[str]:
        """Get tool version"""
        version_commands = {
            "nmap": ["nmap", "--version"],
            "nikto": ["nikto", "-Version"],
            "dirb": ["dirb"],
            "gobuster": ["gobuster", "version"],
            "sslscan": ["sslscan", "--version"],
            "dig": ["dig", "-v"],
            "openssl": ["openssl", "version"],
        }

        cmd = version_commands.get(tool, [tool, "--version"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                lines = result.stdout.split("\n")
                for line in lines[:3]:
                    if any(
                        keyword in line.lower()
                        for keyword in ["version", "v", tool.lower()]
                    ):
                        return line.strip()[:30]
        except:
            pass

        return None


class CacheService:
    """Service for cache management"""

    def __init__(self):
        self.cache_dir = Path("output/cache")

    def show_stats(self, detailed: bool = False, scanner: Optional[str] = None) -> None:
        """Show cache statistics"""
        if not self.cache_dir.exists():
            log_info("📊 Cache: No cache directory found")
            return

        log_info("📊 Cache Statistics:")

        total_size = self._calculate_cache_size()
        log_info(f"  Total size: {self._format_size(total_size)}")

        if detailed:
            self._show_detailed_stats(scanner)

    def clear_cache(
        self, all: bool = False, scanner: Optional[str] = None, force: bool = False
    ) -> None:
        """Clear cache data"""
        if not self.cache_dir.exists():
            log_info("📊 Cache: No cache to clear")
            return

        if not force:
            confirmation = input("Are you sure you want to clear cache? (y/N): ")
            if confirmation.lower() != "y":
                log_info("Cache clear cancelled")
                return

        try:
            if all:
                import shutil

                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                log_success("✅ All cache cleared")
            elif scanner:
                scanner_cache = self.cache_dir / scanner
                if scanner_cache.exists():
                    import shutil

                    shutil.rmtree(scanner_cache)
                    log_success(f"✅ Cache cleared for {scanner}")
                else:
                    log_warning(f"No cache found for {scanner}")
            else:
                log_error("Specify --all or --scanner option")

        except Exception as e:
            log_error(f"Failed to clear cache: {e}")

    def _calculate_cache_size(self) -> int:
        """Calculate total cache size"""
        total = 0
        try:
            for file_path in self.cache_dir.rglob("*"):
                if file_path.is_file():
                    total += file_path.stat().st_size
        except:
            pass
        return total

    def _format_size(self, size: int) -> str:
        """Format size in human readable format"""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _show_detailed_stats(self, scanner: Optional[str]) -> None:
        """Show detailed cache statistics"""
        try:
            if scanner:
                scanner_dir = self.cache_dir / scanner
                if scanner_dir.exists():
                    files = list(scanner_dir.rglob("*"))
                    log_info(f"  {scanner}: {len(files)} files")
            else:
                for scanner_dir in self.cache_dir.iterdir():
                    if scanner_dir.is_dir():
                        files = list(scanner_dir.rglob("*"))
                        size = sum(f.stat().st_size for f in files if f.is_file())
                        log_info(
                            f"  {scanner_dir.name}: {len(files)} files, {self._format_size(size)}"
                        )
        except Exception as e:
            log_error(f"Error showing detailed stats: {e}")
