#!/usr/bin/env python3
"""
Comprehensive Test Runner for Auto-Pentest Framework
Provides different test execution modes and comprehensive reporting
"""

import sys
import os
import argparse
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Any
import json

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Rich not available - using basic output")


class TestRunner:
    """Comprehensive test runner with multiple execution modes"""

    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
        self.project_root = Path(__file__).parent
        self.test_results = {}

    def print_banner(self, text: str, style: str = "bold blue"):
        """Print formatted banner"""
        if self.console:
            self.console.print(Panel(text, style=style))
        else:
            print(f"\n{'='*60}")
            print(f" {text}")
            print("=" * 60)

    def print_info(self, text: str):
        """Print info message"""
        if self.console:
            self.console.print(f"ℹ️  {text}", style="blue")
        else:
            print(f"INFO: {text}")

    def print_success(self, text: str):
        """Print success message"""
        if self.console:
            self.console.print(f"✅ {text}", style="green")
        else:
            print(f"SUCCESS: {text}")

    def print_error(self, text: str):
        """Print error message"""
        if self.console:
            self.console.print(f"❌ {text}", style="red")
        else:
            print(f"ERROR: {text}")

    def print_warning(self, text: str):
        """Print warning message"""
        if self.console:
            self.console.print(f"⚠️  {text}", style="yellow")
        else:
            print(f"WARNING: {text}")

    def run_unit_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run unit tests"""
        self.print_banner("Running Unit Tests", "bold green")

        cmd = [
            "python",
            "-m",
            "pytest",
            "tests/unit/",
            "-m",
            "unit",
            "--tb=short",
            "--durations=10",
        ]

        if verbose:
            cmd.append("-v")
        else:
            cmd.append("-q")

        return self._execute_test_command(cmd, "unit_tests")

    def run_integration_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run integration tests"""
        self.print_banner("Running Integration Tests", "bold yellow")

        cmd = [
            "python",
            "-m",
            "pytest",
            "tests/integration/",
            "-m",
            "integration",
            "--tb=short",
        ]

        if verbose:
            cmd.append("-v")
        else:
            cmd.append("-q")

        return self._execute_test_command(cmd, "integration_tests")

    def run_scanner_tests(
        self, scanner_name: str = None, verbose: bool = False
    ) -> Dict[str, Any]:
        """Run scanner-specific tests"""
        if scanner_name:
            self.print_banner(
                f"Running {scanner_name.title()} Scanner Tests", "bold cyan"
            )
            test_pattern = f"tests/unit/scanners/test_{scanner_name}_*.py"
        else:
            self.print_banner("Running All Scanner Tests", "bold cyan")
            test_pattern = "tests/unit/scanners/"

        cmd = ["python", "-m", "pytest", test_pattern, "-m", "scanner", "--tb=short"]

        if verbose:
            cmd.append("-v")

        return self._execute_test_command(cmd, f"scanner_tests_{scanner_name or 'all'}")

    def run_performance_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run performance tests"""
        self.print_banner("Running Performance Tests", "bold magenta")

        cmd = [
            "python",
            "-m",
            "pytest",
            "tests/",
            "-m",
            "performance",
            "--tb=short",
            "--durations=0",
        ]

        if verbose:
            cmd.append("-v")

        return self._execute_test_command(cmd, "performance_tests")

    def run_security_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run security-focused tests"""
        self.print_banner("Running Security Tests", "bold red")

        cmd = ["python", "-m", "pytest", "tests/", "-m", "security", "--tb=short"]

        if verbose:
            cmd.append("-v")

        return self._execute_test_command(cmd, "security_tests")

    def run_coverage_analysis(self) -> Dict[str, Any]:
        """Run comprehensive coverage analysis"""
        self.print_banner("Running Coverage Analysis", "bold blue")

        cmd = [
            "python",
            "-m",
            "pytest",
            "tests/unit/",
            "--cov=src",
            "--cov-report=html:coverage_html",
            "--cov-report=term-missing",
            "--cov-report=json:coverage.json",
            "--cov-fail-under=85",
            "-q",
        ]

        result = self._execute_test_command(cmd, "coverage_analysis")

        # Parse coverage data if available
        coverage_file = self.project_root / "coverage.json"
        if coverage_file.exists():
            try:
                with open(coverage_file) as f:
                    coverage_data = json.load(f)
                    result["coverage_percentage"] = coverage_data["totals"][
                        "percent_covered"
                    ]
                    self.print_info(
                        f"Overall coverage: {result['coverage_percentage']:.1f}%"
                    )
            except Exception as e:
                self.print_warning(f"Could not parse coverage data: {e}")

        return result

    def run_all_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run complete test suite"""
        self.print_banner("Running Complete Test Suite", "bold white")

        all_results = {}
        total_start_time = time.time()

        # Run test categories
        test_categories = [
            ("Unit Tests", lambda: self.run_unit_tests(verbose)),
            ("Integration Tests", lambda: self.run_integration_tests(verbose)),
            ("Scanner Tests", lambda: self.run_scanner_tests(verbose=verbose)),
            ("Performance Tests", lambda: self.run_performance_tests(verbose)),
            ("Security Tests", lambda: self.run_security_tests(verbose)),
            ("Coverage Analysis", lambda: self.run_coverage_analysis()),
        ]

        for category_name, test_func in test_categories:
            self.print_info(f"Starting {category_name}...")
            try:
                result = test_func()
                all_results[category_name.lower().replace(" ", "_")] = result

                if result["success"]:
                    self.print_success(f"{category_name} completed successfully")
                else:
                    self.print_error(f"{category_name} failed")

            except Exception as e:
                self.print_error(f"{category_name} encountered error: {e}")
                all_results[category_name.lower().replace(" ", "_")] = {
                    "success": False,
                    "error": str(e),
                    "execution_time": 0,
                }

        total_time = time.time() - total_start_time

        # Generate summary
        all_results["summary"] = self._generate_test_summary(all_results, total_time)

        return all_results

    def run_quick_smoke_tests(self) -> Dict[str, Any]:
        """Run quick smoke tests for CI/CD"""
        self.print_banner("Running Quick Smoke Tests", "bold green")

        cmd = [
            "python",
            "-m",
            "pytest",
            "tests/unit/core/",
            "tests/unit/scanners/test_port_scanner.py::TestPortScanner::test_scanner_initialization",
            "tests/unit/scanners/test_dns_scanner.py::TestDNSScanner::test_scanner_initialization",
            "--tb=line",
            "-q",
            "--maxfail=5",
        ]

        return self._execute_test_command(cmd, "smoke_tests")

    def _execute_test_command(self, cmd: List[str], test_name: str) -> Dict[str, Any]:
        """Execute test command and capture results"""
        start_time = time.time()

        try:
            self.print_info(f"Executing: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            execution_time = time.time() - start_time

            test_result = {
                "success": result.returncode == 0,
                "returncode": result.returncode,
                "execution_time": execution_time,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd),
            }

            # Parse test output for metrics
            if "passed" in result.stdout or "failed" in result.stdout:
                test_result.update(self._parse_pytest_output(result.stdout))

            self.test_results[test_name] = test_result

            if test_result["success"]:
                self.print_success(f"{test_name} completed in {execution_time:.2f}s")
            else:
                self.print_error(f"{test_name} failed (exit code: {result.returncode})")
                if result.stderr:
                    self.print_error(f"Error output: {result.stderr[:200]}...")

            return test_result

        except subprocess.TimeoutExpired:
            self.print_error(f"{test_name} timed out after 5 minutes")
            return {
                "success": False,
                "error": "timeout",
                "execution_time": time.time() - start_time,
            }
        except Exception as e:
            self.print_error(f"{test_name} failed with exception: {e}")
            return {
                "success": False,
                "error": str(e),
                "execution_time": time.time() - start_time,
            }

    def _parse_pytest_output(self, output: str) -> Dict[str, Any]:
        """Parse pytest output for test metrics"""
        metrics = {}

        # Look for test results summary
        lines = output.split("\n")
        for line in lines:
            if "passed" in line and (
                "failed" in line or "error" in line or "skipped" in line
            ):
                # Parse line like "5 passed, 2 failed, 1 skipped in 3.45s"
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "passed" and i > 0:
                        metrics["passed"] = int(parts[i - 1])
                    elif part == "failed" and i > 0:
                        metrics["failed"] = int(parts[i - 1])
                    elif part == "skipped" and i > 0:
                        metrics["skipped"] = int(parts[i - 1])
                    elif part == "error" and i > 0:
                        metrics["errors"] = int(parts[i - 1])
                break

        return metrics

    def _generate_test_summary(
        self, results: Dict[str, Any], total_time: float
    ) -> Dict[str, Any]:
        """Generate comprehensive test summary"""
        summary = {
            "total_execution_time": total_time,
            "categories_run": len(results),
            "successful_categories": 0,
            "failed_categories": 0,
            "total_tests_passed": 0,
            "total_tests_failed": 0,
            "overall_success": True,
        }

        for category, result in results.items():
            if category == "summary":
                continue

            if result.get("success", False):
                summary["successful_categories"] += 1
            else:
                summary["failed_categories"] += 1
                summary["overall_success"] = False

            # Aggregate test counts
            summary["total_tests_passed"] += result.get("passed", 0)
            summary["total_tests_failed"] += result.get("failed", 0)

        return summary

    def print_final_summary(self, results: Dict[str, Any]):
        """Print final test execution summary"""
        if "summary" not in results:
            return

        summary = results["summary"]

        self.print_banner("Test Execution Summary", "bold white")

        if self.console:
            # Create rich table
            table = Table(title="Test Results Summary")
            table.add_column("Category", style="cyan")
            table.add_column("Status", style="bold")
            table.add_column("Time", style="magenta")
            table.add_column("Tests", style="green")

            for category, result in results.items():
                if category == "summary":
                    continue

                status = "✅ PASS" if result.get("success") else "❌ FAIL"
                time_str = f"{result.get('execution_time', 0):.2f}s"

                passed = result.get("passed", 0)
                failed = result.get("failed", 0)
                tests_str = f"{passed} passed"
                if failed > 0:
                    tests_str += f", {failed} failed"

                table.add_row(
                    category.replace("_", " ").title(), status, time_str, tests_str
                )

            self.console.print(table)

        # Print overall summary
        if summary["overall_success"]:
            self.print_success(f"🎉 ALL TESTS PASSED!")
            self.print_success(
                f"Total: {summary['total_tests_passed']} tests passed in {summary['total_execution_time']:.2f}s"
            )
        else:
            self.print_error(f"❌ SOME TESTS FAILED")
            self.print_error(
                f"Passed: {summary['total_tests_passed']}, Failed: {summary['total_tests_failed']}"
            )

        # Print next steps
        self.print_info("\nNext steps:")
        if summary["overall_success"]:
            self.print_info("✅ All tests passed - ready for production!")
            self.print_info("📊 Check coverage report: open coverage_html/index.html")
            self.print_info("🚀 Ready to deploy!")
        else:
            self.print_info("🔧 Fix failing tests before deployment")
            self.print_info("📋 Check detailed output above for specific failures")
            self.print_info("🔍 Run failed tests individually for detailed debugging")


def main():
    """Main test runner entry point"""
    parser = argparse.ArgumentParser(description="Auto-Pentest Test Runner")
    parser.add_argument(
        "mode",
        choices=[
            "unit",
            "integration",
            "scanner",
            "performance",
            "security",
            "coverage",
            "all",
            "smoke",
        ],
        help="Test execution mode",
    )

    parser.add_argument(
        "--scanner",
        choices=["port", "dns", "web", "directory", "ssl"],
        help="Specific scanner to test (for scanner mode)",
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    parser.add_argument("--output", type=str, help="Save results to JSON file")

    args = parser.parse_args()

    runner = TestRunner()

    # Execute tests based on mode
    if args.mode == "unit":
        results = runner.run_unit_tests(args.verbose)
    elif args.mode == "integration":
        results = runner.run_integration_tests(args.verbose)
    elif args.mode == "scanner":
        results = runner.run_scanner_tests(args.scanner, args.verbose)
    elif args.mode == "performance":
        results = runner.run_performance_tests(args.verbose)
    elif args.mode == "security":
        results = runner.run_security_tests(args.verbose)
    elif args.mode == "coverage":
        results = runner.run_coverage_analysis()
    elif args.mode == "all":
        results = runner.run_all_tests(args.verbose)
    elif args.mode == "smoke":
        results = runner.run_quick_smoke_tests()

    # Print summary
    if args.mode == "all":
        runner.print_final_summary(results)

    # Save results if requested
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        runner.print_info(f"Results saved to {args.output}")

    # Exit with appropriate code
    if args.mode == "all":
        sys.exit(0 if results.get("summary", {}).get("overall_success", False) else 1)
    else:
        sys.exit(0 if results.get("success", False) else 1)


if __name__ == "__main__":
    main()
