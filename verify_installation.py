#!/usr/bin/env python3
"""
Auto-Pentest Framework v0.9.1 - Installation Verification Script

This script performs comprehensive verification of the Auto-Pentest Framework installation,
checking all dependencies, tools, configurations, and basic functionality.

Usage: python verify_installation.py [--detailed] [--fix-issues]
"""

import os
import sys
import subprocess
import json
import shutil
import platform
import socket
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import importlib.util


# Color codes for output formatting
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


def print_header(text: str, char: str = "=", color: str = Colors.CYAN):
    """Print formatted header"""
    line = char * len(text)
    print(f"\n{color}{Colors.BOLD}{line}")
    print(f"{text}")
    print(f"{line}{Colors.END}")


def print_success(text: str):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")


def print_error(text: str):
    """Print error message"""
    print(f"{Colors.RED}❌ {text}{Colors.END}")


def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")


def print_info(text: str):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.END}")


def print_step(text: str):
    """Print step message"""
    print(f"{Colors.PURPLE}🔍 {text}{Colors.END}")


class InstallationVerifier:
    """Comprehensive installation verification"""

    def __init__(self, detailed: bool = False, fix_issues: bool = False):
        self.detailed = detailed
        self.fix_issues = fix_issues
        self.results = {
            "python_environment": {},
            "python_dependencies": {},
            "system_tools": {},
            "project_structure": {},
            "configuration": {},
            "functionality": {},
            "performance": {},
            "summary": {},
        }
        self.issues_found = []
        self.fixes_applied = []

    def run_verification(self) -> bool:
        """Run complete verification process"""
        print_header(
            "🚀 Auto-Pentest Framework v0.9.1 - Installation Verification",
            "=",
            Colors.CYAN,
        )
        print_info(f"System: {platform.system()} {platform.release()}")
        print_info(f"Python: {sys.version}")
        print_info(f"Architecture: {platform.machine()}")

        # Run all verification steps
        steps = [
            ("Python Environment", self._verify_python_environment),
            ("Python Dependencies", self._verify_python_dependencies),
            ("System Tools", self._verify_system_tools),
            ("Project Structure", self._verify_project_structure),
            ("Configuration Files", self._verify_configuration),
            ("Basic Functionality", self._verify_functionality),
            ("Performance Features", self._verify_performance),
        ]

        total_passed = 0
        total_tests = 0

        for step_name, step_func in steps:
            print_header(f"{step_name} Verification", "-", Colors.YELLOW)
            passed, total = step_func()
            total_passed += passed
            total_tests += total

            if passed == total:
                print_success(f"{step_name}: All {total} checks passed")
            elif passed > total * 0.8:
                print_warning(f"{step_name}: {passed}/{total} checks passed (Good)")
            else:
                print_error(
                    f"{step_name}: {passed}/{total} checks passed (Issues found)"
                )

        # Generate summary
        self._generate_summary(total_passed, total_tests)

        # Apply fixes if requested
        if self.fix_issues and self.issues_found:
            self._apply_fixes()

        return total_passed >= total_tests * 0.8

    def _verify_python_environment(self) -> Tuple[int, int]:
        """Verify Python environment"""
        passed = 0
        total = 0

        # Check Python version
        total += 1
        python_version = sys.version_info
        if python_version >= (3, 8):
            print_success(
                f"Python version: {python_version.major}.{python_version.minor}.{python_version.micro}"
            )
            passed += 1
            self.results["python_environment"]["version"] = "OK"
        else:
            print_error(
                f"Python version {python_version.major}.{python_version.minor} is too old (required: 3.8+)"
            )
            self.issues_found.append("Python version too old")
            self.results["python_environment"]["version"] = "FAIL"

        # Check virtual environment
        total += 1
        if hasattr(sys, "real_prefix") or (
            hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
        ):
            print_success("Virtual environment: Active")
            passed += 1
            self.results["python_environment"]["venv"] = "OK"
        else:
            print_warning("Virtual environment: Not detected (recommended)")
            self.issues_found.append("Virtual environment not active")
            self.results["python_environment"]["venv"] = "WARNING"

        # Check pip
        total += 1
        try:
            import pip

            print_success(f"pip: Available (version {pip.__version__})")
            passed += 1
            self.results["python_environment"]["pip"] = "OK"
        except ImportError:
            print_error("pip: Not available")
            self.issues_found.append("pip not available")
            self.results["python_environment"]["pip"] = "FAIL"

        # Check write permissions
        total += 1
        try:
            test_file = Path("test_write_permission.tmp")
            test_file.write_text("test")
            test_file.unlink()
            print_success("Write permissions: OK")
            passed += 1
            self.results["python_environment"]["permissions"] = "OK"
        except Exception as e:
            print_error(f"Write permissions: Failed ({e})")
            self.issues_found.append("No write permissions")
            self.results["python_environment"]["permissions"] = "FAIL"

        return passed, total

    def _verify_python_dependencies(self) -> Tuple[int, int]:
        """Verify Python package dependencies"""
        passed = 0
        total = 0

        # Core dependencies
        core_deps = [
            ("click", "Command line interface"),
            ("rich", "Rich console output"),
            ("jinja2", "Template engine"),
            ("pyyaml", "YAML configuration"),
            ("python-dotenv", "Environment variables"),
            ("requests", "HTTP requests"),
            ("dnspython", "DNS operations"),
            ("validators", "Input validation"),
        ]

        for dep, description in core_deps:
            total += 1
            try:
                module = importlib.import_module(dep.replace("-", "_"))
                version = getattr(module, "__version__", "unknown")
                print_success(f"{dep}: {version} ({description})")
                passed += 1
                self.results["python_dependencies"][dep] = "OK"
            except ImportError:
                print_error(f"{dep}: Missing ({description})")
                self.issues_found.append(f"Missing dependency: {dep}")
                self.results["python_dependencies"][dep] = "FAIL"

        # PDF generation dependencies
        pdf_deps = [
            ("weasyprint", "PDF generation (WeasyPrint)"),
            ("pdfkit", "PDF generation (PDFKit)"),
        ]

        pdf_available = False
        for dep, description in pdf_deps:
            total += 1
            try:
                importlib.import_module(dep)
                print_success(f"{dep}: Available ({description})")
                passed += 1
                pdf_available = True
                self.results["python_dependencies"][dep] = "OK"
            except ImportError:
                print_warning(f"{dep}: Not available ({description})")
                self.results["python_dependencies"][dep] = "WARNING"

        if not pdf_available:
            print_error("No PDF generation library available")
            self.issues_found.append("No PDF generation support")

        # Testing dependencies
        test_deps = [
            ("pytest", "Testing framework"),
            ("pytest_cov", "Coverage testing"),
        ]

        for dep, description in test_deps:
            total += 1
            try:
                importlib.import_module(dep.replace("-", "_"))
                print_success(f"{dep}: Available ({description})")
                passed += 1
                self.results["python_dependencies"][dep] = "OK"
            except ImportError:
                print_warning(f"{dep}: Not available ({description})")
                self.results["python_dependencies"][dep] = "WARNING"

        return passed, total

    def _verify_system_tools(self) -> Tuple[int, int]:
        """Verify system security tools"""
        passed = 0
        total = 0

        required_tools = [
            ("nmap", "Network port scanner"),
            ("nikto", "Web vulnerability scanner"),
            ("dirb", "Directory brute forcer"),
            ("gobuster", "Directory/DNS brute forcer"),
            ("sslscan", "SSL/TLS analyzer"),
        ]

        optional_tools = [
            ("dig", "DNS lookup utility"),
            ("openssl", "SSL/TLS toolkit"),
            ("curl", "HTTP client"),
            ("wget", "Web downloader"),
        ]

        # Check required tools
        for tool, description in required_tools:
            total += 1
            tool_path = shutil.which(tool)
            if tool_path:
                try:
                    # Get version information
                    version_cmd = self._get_version_command(tool)
                    result = subprocess.run(
                        version_cmd, capture_output=True, text=True, timeout=10
                    )
                    version_info = self._parse_version_output(
                        tool, result.stdout + result.stderr
                    )
                    print_success(f"{tool}: {tool_path} ({version_info})")
                    passed += 1
                    self.results["system_tools"][tool] = "OK"
                except Exception as e:
                    print_warning(f"{tool}: Found but version check failed ({e})")
                    self.results["system_tools"][tool] = "WARNING"
            else:
                print_error(f"{tool}: Not found ({description})")
                self.issues_found.append(f"Missing tool: {tool}")
                self.results["system_tools"][tool] = "FAIL"

        # Check optional tools
        for tool, description in optional_tools:
            total += 1
            tool_path = shutil.which(tool)
            if tool_path:
                print_success(f"{tool}: {tool_path} ({description})")
                passed += 1
                self.results["system_tools"][tool] = "OK"
            else:
                print_warning(f"{tool}: Not found ({description}) - Optional")
                self.results["system_tools"][tool] = "WARNING"

        return passed, total

    def _verify_project_structure(self) -> Tuple[int, int]:
        """Verify project file structure"""
        passed = 0
        total = 0

        required_files = [
            "main.py",
            "requirements.txt",
            "config/settings.py",
            "config/tools_config.yaml",
            "src/core/scanner_base.py",
            "src/core/executor.py",
            "src/core/validator.py",
            "src/utils/logger.py",
            "src/utils/reporter.py",
            "src/scanners/recon/port_scanner.py",
            "src/scanners/recon/dns_scanner.py",
            "src/scanners/vulnerability/web_scanner.py",
            "src/scanners/vulnerability/directory_scanner.py",
            "src/scanners/vulnerability/ssl_scanner.py",
            "src/orchestrator/orchestrator.py",
            "src/orchestrator/scheduler.py",
            "templates/report_html.jinja2",
        ]

        required_dirs = [
            "src",
            "config",
            "templates",
            "output",
            "output/logs",
            "output/reports",
            "output/cache",
            "tests",
        ]

        # Check required files
        for file_path in required_files:
            total += 1
            path = Path(file_path)
            if path.exists() and path.is_file():
                size = path.stat().st_size
                print_success(f"File: {file_path} ({size} bytes)")
                passed += 1
                self.results["project_structure"][f"file_{file_path}"] = "OK"
            else:
                print_error(f"File missing: {file_path}")
                self.issues_found.append(f"Missing file: {file_path}")
                self.results["project_structure"][f"file_{file_path}"] = "FAIL"

        # Check required directories
        for dir_path in required_dirs:
            total += 1
            path = Path(dir_path)
            if path.exists() and path.is_dir():
                print_success(f"Directory: {dir_path}")
                passed += 1
                self.results["project_structure"][f"dir_{dir_path}"] = "OK"

                # Create missing subdirectories if possible
                if self.fix_issues and dir_path == "output":
                    for subdir in ["logs", "reports", "cache", "raw"]:
                        subpath = path / subdir
                        if not subpath.exists():
                            subpath.mkdir(parents=True, exist_ok=True)
                            self.fixes_applied.append(f"Created directory: {subpath}")
            else:
                print_error(f"Directory missing: {dir_path}")
                self.issues_found.append(f"Missing directory: {dir_path}")
                self.results["project_structure"][f"dir_{dir_path}"] = "FAIL"

                # Create missing directory if fix mode is enabled
                if self.fix_issues:
                    try:
                        Path(dir_path).mkdir(parents=True, exist_ok=True)
                        print_success(f"Created directory: {dir_path}")
                        self.fixes_applied.append(f"Created directory: {dir_path}")
                        passed += 1
                        self.results["project_structure"][f"dir_{dir_path}"] = "FIXED"
                    except Exception as e:
                        print_error(f"Failed to create directory {dir_path}: {e}")

        return passed, total

    def _verify_configuration(self) -> Tuple[int, int]:
        """Verify configuration files"""
        passed = 0
        total = 0

        # Check .env file
        total += 1
        env_file = Path(".env")
        if env_file.exists():
            print_success(".env: Configuration file exists")
            passed += 1
            self.results["configuration"]["env_file"] = "OK"
        else:
            env_example = Path(".env.example")
            if env_example.exists():
                print_warning(".env: Not found, but .env.example exists")
                if self.fix_issues:
                    try:
                        shutil.copy(".env.example", ".env")
                        print_success("Created .env from .env.example")
                        self.fixes_applied.append("Created .env file")
                        passed += 1
                        self.results["configuration"]["env_file"] = "FIXED"
                    except Exception as e:
                        print_error(f"Failed to create .env: {e}")
                        self.results["configuration"]["env_file"] = "FAIL"
                else:
                    self.results["configuration"]["env_file"] = "WARNING"
            else:
                print_error(".env: Configuration file missing")
                self.issues_found.append("Missing .env configuration")
                self.results["configuration"]["env_file"] = "FAIL"

        # Check settings.py
        total += 1
        settings_file = Path("config/settings.py")
        if settings_file.exists():
            try:
                # Try to import settings
                sys.path.insert(0, str(Path("config").resolve()))
                import settings

                print_success("settings.py: Configuration loaded successfully")
                passed += 1
                self.results["configuration"]["settings"] = "OK"
            except Exception as e:
                print_error(f"settings.py: Configuration error ({e})")
                self.issues_found.append("Configuration syntax error")
                self.results["configuration"]["settings"] = "FAIL"
        else:
            print_error("settings.py: Configuration file missing")
            self.issues_found.append("Missing settings.py")
            self.results["configuration"]["settings"] = "FAIL"

        # Check tools_config.yaml
        total += 1
        tools_config = Path("config/tools_config.yaml")
        if tools_config.exists():
            try:
                import yaml

                with open(tools_config) as f:
                    config = yaml.safe_load(f)
                print_success("tools_config.yaml: YAML syntax valid")
                passed += 1
                self.results["configuration"]["tools_config"] = "OK"
            except Exception as e:
                print_error(f"tools_config.yaml: YAML syntax error ({e})")
                self.issues_found.append("YAML configuration error")
                self.results["configuration"]["tools_config"] = "FAIL"
        else:
            print_error("tools_config.yaml: Configuration file missing")
            self.issues_found.append("Missing tools_config.yaml")
            self.results["configuration"]["tools_config"] = "FAIL"

        return passed, total

    def _verify_functionality(self) -> Tuple[int, int]:
        """Verify basic functionality"""
        passed = 0
        total = 0

        # Test main.py execution
        total += 1
        try:
            result = subprocess.run(
                [sys.executable, "main.py", "--help"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                print_success("main.py: CLI interface working")
                passed += 1
                self.results["functionality"]["cli"] = "OK"
            else:
                print_error(f"main.py: CLI failed (exit code {result.returncode})")
                if self.detailed:
                    print_info(f"STDERR: {result.stderr[:200]}...")
                self.issues_found.append("CLI interface broken")
                self.results["functionality"]["cli"] = "FAIL"
        except Exception as e:
            print_error(f"main.py: Execution failed ({e})")
            self.issues_found.append("Cannot execute main.py")
            self.results["functionality"]["cli"] = "FAIL"

        # Test core module imports
        total += 1
        try:
            sys.path.insert(0, str(Path("src").resolve()))
            from core.scanner_base import ScannerBase
            from core.executor import CommandExecutor
            from core.validator import InputValidator

            print_success("Core modules: Import successful")
            passed += 1
            self.results["functionality"]["core_imports"] = "OK"
        except Exception as e:
            print_error(f"Core modules: Import failed ({e})")
            self.issues_found.append("Core module import error")
            self.results["functionality"]["core_imports"] = "FAIL"

        # Test scanner imports
        total += 1
        try:
            from scanners.recon.port_scanner import PortScanner
            from scanners.recon.dns_scanner import DNSScanner
            from scanners.vulnerability.web_scanner import WebScanner

            print_success("Scanner modules: Import successful")
            passed += 1
            self.results["functionality"]["scanner_imports"] = "OK"
        except Exception as e:
            print_error(f"Scanner modules: Import failed ({e})")
            self.issues_found.append("Scanner module import error")
            self.results["functionality"]["scanner_imports"] = "FAIL"

        # Test report generation
        total += 1
        try:
            from utils.reporter import Reporter

            print_success("Reporter module: Import successful")
            passed += 1
            self.results["functionality"]["reporter"] = "OK"
        except Exception as e:
            print_error(f"Reporter module: Import failed ({e})")
            self.issues_found.append("Reporter module error")
            self.results["functionality"]["reporter"] = "FAIL"

        # Test network connectivity (optional)
        total += 1
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=5)
            print_success("Network connectivity: Internet accessible")
            passed += 1
            self.results["functionality"]["network"] = "OK"
        except Exception:
            print_warning("Network connectivity: Limited or no internet access")
            self.results["functionality"]["network"] = "WARNING"

        return passed, total

    def _verify_performance(self) -> Tuple[int, int]:
        """Verify performance features"""
        passed = 0
        total = 0

        # Test cache directory
        total += 1
        cache_dir = Path("output/cache")
        if cache_dir.exists() and cache_dir.is_dir():
            # Test cache write permissions
            try:
                test_cache = cache_dir / "test_cache.tmp"
                test_cache.write_text("test")
                test_cache.unlink()
                print_success("Cache system: Directory accessible")
                passed += 1
                self.results["performance"]["cache"] = "OK"
            except Exception as e:
                print_error(f"Cache system: Write permission failed ({e})")
                self.issues_found.append("Cache directory not writable")
                self.results["performance"]["cache"] = "FAIL"
        else:
            print_error("Cache system: Directory missing")
            self.issues_found.append("Cache directory missing")
            self.results["performance"]["cache"] = "FAIL"

        # Test log directory
        total += 1
        log_dir = Path("output/logs")
        if log_dir.exists() and log_dir.is_dir():
            try:
                test_log = log_dir / "test_log.tmp"
                test_log.write_text("test")
                test_log.unlink()
                print_success("Logging system: Directory accessible")
                passed += 1
                self.results["performance"]["logging"] = "OK"
            except Exception as e:
                print_error(f"Logging system: Write permission failed ({e})")
                self.issues_found.append("Log directory not writable")
                self.results["performance"]["logging"] = "FAIL"
        else:
            print_error("Logging system: Directory missing")
            self.issues_found.append("Log directory missing")
            self.results["performance"]["logging"] = "FAIL"

        # Test memory availability
        total += 1
        try:
            import psutil

            memory = psutil.virtual_memory()
            available_gb = memory.available / (1024**3)
            if available_gb >= 2:
                print_success(f"Memory: {available_gb:.1f}GB available (sufficient)")
                passed += 1
                self.results["performance"]["memory"] = "OK"
            else:
                print_warning(f"Memory: {available_gb:.1f}GB available (low)")
                self.results["performance"]["memory"] = "WARNING"
        except ImportError:
            print_info("Memory check: psutil not available (optional)")
            self.results["performance"]["memory"] = "SKIPPED"
        except Exception as e:
            print_warning(f"Memory check: Failed ({e})")
            self.results["performance"]["memory"] = "WARNING"

        return passed, total

    def _generate_summary(self, total_passed: int, total_tests: int):
        """Generate verification summary"""
        print_header("📊 Verification Summary", "=", Colors.GREEN)

        success_rate = (total_passed / total_tests) * 100 if total_tests > 0 else 0

        print_info(f"Total Tests: {total_tests}")
        print_info(f"Passed: {total_passed}")
        print_info(f"Success Rate: {success_rate:.1f}%")

        if success_rate >= 95:
            print_success("🎉 EXCELLENT! Installation is complete and fully functional")
            status = "EXCELLENT"
        elif success_rate >= 85:
            print_success("✅ GOOD! Installation is functional with minor issues")
            status = "GOOD"
        elif success_rate >= 70:
            print_warning("⚠️  ACCEPTABLE! Installation works but has some issues")
            status = "ACCEPTABLE"
        else:
            print_error("❌ POOR! Installation has significant issues")
            status = "POOR"

        self.results["summary"] = {
            "total_tests": total_tests,
            "passed": total_passed,
            "success_rate": success_rate,
            "status": status,
            "issues_found": len(self.issues_found),
            "fixes_applied": len(self.fixes_applied),
        }

        # Show issues found
        if self.issues_found:
            print_header("🚨 Issues Found", "-", Colors.RED)
            for i, issue in enumerate(self.issues_found, 1):
                print_error(f"{i}. {issue}")

        # Show fixes applied
        if self.fixes_applied:
            print_header("🔧 Fixes Applied", "-", Colors.GREEN)
            for i, fix in enumerate(self.fixes_applied, 1):
                print_success(f"{i}. {fix}")

        # Recommendations
        self._generate_recommendations()

    def _generate_recommendations(self):
        """Generate recommendations based on verification results"""
        print_header("💡 Recommendations", "-", Colors.BLUE)

        if self.issues_found:
            print_step("To resolve issues:")

            if "Python version too old" in self.issues_found:
                print_info("• Upgrade Python to version 3.8 or higher")
                print_info("  sudo apt install python3.9 python3.9-venv")

            if "Virtual environment not active" in self.issues_found:
                print_info("• Create and activate virtual environment:")
                print_info("  python3 -m venv venv && source venv/bin/activate")

            if any("Missing dependency" in issue for issue in self.issues_found):
                print_info("• Install missing Python dependencies:")
                print_info("  pip install -r requirements.txt")

            if any("Missing tool" in issue for issue in self.issues_found):
                print_info("• Install missing security tools:")
                print_info("  sudo apt install nmap nikto dirb gobuster sslscan")

            if "No PDF generation support" in self.issues_found:
                print_info("• Install PDF generation support:")
                print_info("  pip install weasyprint")
                print_info("  sudo apt install libpango-1.0-0 libharfbuzz0b")

            print_info(
                "• Run verification again with --fix-issues to auto-fix some issues"
            )
            print_info(
                "• Check the troubleshooting guide: docs/troubleshooting_guide.md"
            )
        else:
            print_success("🎯 No issues found! Your installation is ready for use.")
            print_info("Next steps:")
            print_info("• Read the user manual: docs/user_manual.md")
            print_info("• Try a test scan: python main.py quick scanme.nmap.org")
            print_info("• Configure custom branding if needed")

    def _get_version_command(self, tool: str) -> List[str]:
        """Get version command for tool"""
        version_commands = {
            "nmap": ["nmap", "--version"],
            "nikto": ["nikto", "-Version"],
            "dirb": ["dirb"],
            "gobuster": ["gobuster", "version"],
            "sslscan": ["sslscan", "--version"],
            "dig": ["dig", "-v"],
            "openssl": ["openssl", "version"],
            "curl": ["curl", "--version"],
            "wget": ["wget", "--version"],
        }
        return version_commands.get(tool, [tool, "--version"])

    def _parse_version_output(self, tool: str, output: str) -> str:
        """Parse version from tool output"""
        lines = output.split("\n")
        for line in lines[:3]:  # Check first 3 lines
            if any(
                keyword in line.lower() for keyword in ["version", "v", tool.lower()]
            ):
                return line.strip()[:50]  # Limit length
        return "version unknown"

    def _apply_fixes(self):
        """Apply automatic fixes for common issues"""
        print_header("🔧 Applying Automatic Fixes", "-", Colors.YELLOW)

        # Note: Most fixes are already applied during verification
        # This is for additional fixes that need to be done at the end

        if self.fixes_applied:
            print_success(f"Applied {len(self.fixes_applied)} automatic fixes")
        else:
            print_info("No automatic fixes were needed or possible")

    def save_results(self, filename: str = "verification_results.json"):
        """Save verification results to file"""
        results_file = Path("output") / filename
        results_file.parent.mkdir(exist_ok=True)

        with open(results_file, "w") as f:
            json.dump(self.results, f, indent=2)

        print_info(f"Verification results saved to: {results_file}")


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Auto-Pentest Framework Installation Verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python verify_installation.py                    # Basic verification
  python verify_installation.py --detailed         # Detailed output
  python verify_installation.py --fix-issues       # Auto-fix issues
  python verify_installation.py --detailed --fix-issues
        """,
    )

    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Show detailed output including error messages",
    )

    parser.add_argument(
        "--fix-issues",
        action="store_true",
        help="Automatically fix issues where possible",
    )

    parser.add_argument(
        "--save-results",
        action="store_true",
        help="Save verification results to JSON file",
    )

    args = parser.parse_args()

    # Run verification
    verifier = InstallationVerifier(detailed=args.detailed, fix_issues=args.fix_issues)

    try:
        success = verifier.run_verification()

        if args.save_results:
            verifier.save_results()

        # Exit with appropriate code
        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print_error("\n🚫 Verification interrupted by user")
        sys.exit(2)
    except Exception as e:
        print_error(f"\n💥 Verification failed with error: {e}")
        if args.detailed:
            import traceback

            traceback.print_exc()
        sys.exit(3)


if __name__ == "__main__":
    main()
