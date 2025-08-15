#!/usr/bin/env python3
"""
Fast Test Runner for Auto-Pentest Framework
Multiple options for running tests quickly
"""

import sys
import subprocess
import time
from pathlib import Path


def run_command(cmd, description="Running command"):
    """Run a command and measure time"""
    print(f"⚡ {description}...")
    start_time = time.time()

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        elapsed = time.time() - start_time

        if result.returncode == 0:
            print(f"✅ Completed in {elapsed:.2f}s")
            if result.stdout:
                print(result.stdout)
        else:
            print(f"❌ Failed in {elapsed:.2f}s")
            if result.stderr:
                print(result.stderr)

        return result.returncode == 0

    except Exception as e:
        print(f"💥 Error: {e}")
        return False


def main():
    """Main test runner with multiple options"""
    print("🚀 AUTO-PENTEST FAST TEST RUNNER")
    print("=" * 50)

    if len(sys.argv) < 2:
        print(
            """
Usage: python run_tests_fast.py [option]

Options:
  quick       - Super fast core tests only (30s)
  parallel    - Parallel execution with pytest-xdist (2-3min)
  single      - Single specific test file (1-2min)
  validation  - Only validation tests (30s)
  mock        - Only mocked tests (45s)
  orchestrator- Safe orchestrator concept tests (30s)
  cli         - CLI interface tests (45s)
  reporter    - Report generation tests (30s)
  all         - All tests sequential (5-10min)

Examples:
  python run_tests_fast.py quick
  python run_tests_fast.py parallel
  python run_tests_fast.py orchestrator
  python run_tests_fast.py cli
  python run_tests_fast.py reporter
  python run_tests_fast.py single test_core_framework.py
        """
        )
        return

    option = sys.argv[1].lower()

    # Check if in correct directory
    if not Path("tests").exists():
        print("❌ Please run from project root directory (where 'tests' folder exists)")
        return

    # Install pytest-xdist if needed for parallel execution
    if option == "parallel":
        print("📦 Checking pytest-xdist...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pytest-xdist"],
            capture_output=True,
        )

    if option == "quick":
        print("⚡ QUICK TESTS - Core functionality only")
        success = run_command(
            "python tests/test_core_framework.py", "Running core framework tests"
        )
        if success and Path("tests/test_web_scanner_fast.py").exists():
            run_command(
                "python tests/test_web_scanner_fast.py",
                "Running fast web scanner tests",
            )

    elif option == "parallel":
        print("🔀 PARALLEL TESTS - Using all CPU cores")
        run_command(
            "python -m pytest tests/ -n auto --tb=short -q",
            "Running all tests in parallel",
        )

    elif option == "single":
        if len(sys.argv) < 3:
            print(
                "❌ Please specify test file: python run_tests_fast.py single test_file.py"
            )
            return

        test_file = sys.argv[2]
        if not test_file.startswith("test_"):
            test_file = f"test_{test_file}"
        if not test_file.endswith(".py"):
            test_file = f"{test_file}.py"

        print(f"📋 SINGLE TEST - {test_file}")
        run_command(f"python -m pytest tests/{test_file} -v", f"Running {test_file}")

    elif option == "validation":
        print("✅ VALIDATION TESTS - Quick validation checks")
        commands = [
            ("python -m pytest tests/ -k 'validation' -v", "Validation tests"),
            ("python -m pytest tests/ -k 'initialization' -v", "Initialization tests"),
            ("python -m pytest tests/ -k 'capabilities' -v", "Capabilities tests"),
        ]

        for cmd, desc in commands:
            run_command(cmd, desc)

    elif option == "mock":
        print("🎭 MOCK TESTS - Only mocked/stubbed tests")
        run_command(
            "python -m pytest tests/ -k 'mock or Mock' -v", "Running mocked tests only"
        )

    elif option == "reporter":
        print("📊 REPORTER TESTS - Report generation testing")
        run_command("python tests/test_reporter.py", "Running reporter tests")

    elif option == "cli":
        print("💻 CLI TESTS - Command line interface testing")
        run_command("python tests/test_cli_interface.py", "Running CLI interface tests")

    elif option == "orchestrator":
        print("🎭 ORCHESTRATOR TESTS - Safe orchestrator concept testing")
        run_command(
            "python tests/test_orchestrator_safe.py", "Running safe orchestrator tests"
        )

    elif option == "all":
        print("📚 ALL TESTS - Sequential execution")
        test_files = [
            "test_core_framework.py",
            "test_port_scanner.py",
            "test_dns_scanner.py",
            "test_web_scanner.py",
            "test_directory_scanner.py",
            "test_ssl_scanner.py",
            "test_orchestrator_safe.py",
            "test_cli_interface.py",
            "test_reporter.py",
        ]

        for test_file in test_files:
            if Path(f"tests/{test_file}").exists():
                run_command(f"python tests/{test_file}", f"Running {test_file}")

    else:
        print(f"❌ Unknown option: {option}")
        print("Use 'python run_tests_fast.py' to see available options")


if __name__ == "__main__":
    main()
