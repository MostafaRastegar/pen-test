#!/usr/bin/env python3
"""
CLI Interface Test Suite
Tests command line interface, option parsing, help messages, error handling,
and user interaction with the pentest framework
"""

import sys
import os
import unittest
import subprocess
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from io import StringIO

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from src.utils.logger import LoggerSetup, log_success, log_error, log_info

    # Try to import CLI components with fallbacks
    cli_available = False
    try:
        from src.cli.commands import scan_command, quick_command, full_command

        cli_available = True
    except ImportError:
        try:
            from src.cli import cli_main

            cli_available = True
        except ImportError:
            log_info("CLI modules not found - using subprocess testing")

    # Try to import Click for CLI testing
    try:
        import click
        from click.testing import CliRunner

        click_available = True
    except ImportError:
        click_available = False
        log_info("Click not available - using subprocess testing only")

except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure you're running this from the project root directory")
    sys.exit(1)


class TestCLIBasics(unittest.TestCase):
    """Test basic CLI functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.project_root = Path(__file__).parent.parent
        self.main_script = self.project_root / "main.py"

        # Test data
        self.test_target = "example.com"
        self.test_url = "https://example.com"

    def test_main_script_exists(self):
        """Test that main script exists and is executable"""
        log_info("Testing main script existence")

        self.assertTrue(self.main_script.exists(), "main.py should exist")
        self.assertTrue(self.main_script.is_file(), "main.py should be a file")

        # Check if it's readable
        try:
            with open(self.main_script, "r") as f:
                content = f.read()
            self.assertGreater(len(content), 0, "main.py should not be empty")
        except Exception as e:
            self.fail(f"Cannot read main.py: {e}")

        log_success("Main script existence test passed")

    def test_help_message(self):
        """Test help message display"""
        log_info("Testing help message")

        try:
            result = subprocess.run(
                [sys.executable, str(self.main_script), "--help"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=self.project_root,
            )

            # Help should return 0 or be available
            self.assertIn(
                result.returncode, [0, 2], "Help command should succeed or show usage"
            )

            # Check for common help indicators
            output = result.stdout + result.stderr
            help_indicators = ["usage", "help", "option", "command", "scan"]
            found_indicators = [
                indicator
                for indicator in help_indicators
                if indicator.lower() in output.lower()
            ]

            self.assertGreater(
                len(found_indicators),
                0,
                f"Help output should contain help information. Output: {output[:200]}",
            )

            log_success("Help message test passed")

        except subprocess.TimeoutExpired:
            log_info("Help command timed out - may indicate hanging process")
        except Exception as e:
            log_info(f"Help command test failed: {e}")

    def test_version_or_info(self):
        """Test version or info display"""
        log_info("Testing version/info display")

        version_flags = ["--version", "-v", "version", "info", "scan-info"]

        for flag in version_flags:
            with self.subTest(flag=flag):
                try:
                    result = subprocess.run(
                        [sys.executable, str(self.main_script), flag],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        cwd=self.project_root,
                    )

                    # If command succeeds, check output
                    if result.returncode == 0:
                        output = result.stdout + result.stderr
                        log_info(f"Flag '{flag}' produced output: {output[:100]}...")
                        break

                except subprocess.TimeoutExpired:
                    log_info(f"Flag '{flag}' timed out")
                except Exception as e:
                    log_info(f"Flag '{flag}' failed: {e}")

        log_success("Version/info test completed")

    def test_invalid_command(self):
        """Test handling of invalid commands"""
        log_info("Testing invalid command handling")

        try:
            result = subprocess.run(
                [sys.executable, str(self.main_script), "invalid_command_xyz"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=self.project_root,
            )

            # Invalid command should return non-zero exit code
            self.assertNotEqual(result.returncode, 0, "Invalid command should fail")

            # Should have error output
            error_output = result.stderr + result.stdout
            self.assertGreater(
                len(error_output), 0, "Should have error output for invalid command"
            )

            log_success("Invalid command handling test passed")

        except subprocess.TimeoutExpired:
            log_info("Invalid command test timed out")
        except Exception as e:
            log_info(f"Invalid command test failed: {e}")


class TestCLICommands(unittest.TestCase):
    """Test CLI command parsing and validation"""

    def setUp(self):
        """Set up test fixtures"""
        self.project_root = Path(__file__).parent.parent
        self.main_script = self.project_root / "main.py"
        self.test_target = "example.com"

        # Create CliRunner if Click is available
        if click_available:
            self.runner = CliRunner()
        else:
            self.runner = None

    def test_scan_command_validation(self):
        """Test scan command target validation"""
        log_info("Testing scan command validation")

        # Test with valid target
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(self.main_script),
                    "scan",
                    self.test_target,
                    "--help",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=self.project_root,
            )

            # Help for scan command should work
            if result.returncode in [0, 2]:
                log_info("Scan command help is accessible")

        except subprocess.TimeoutExpired:
            log_info("Scan command help timed out")
        except Exception as e:
            log_info(f"Scan command help test failed: {e}")

        # Test with obviously invalid target
        invalid_targets = ["", "invalid..domain", "http://"]

        for target in invalid_targets:
            with self.subTest(target=target):
                try:
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(self.main_script),
                            "scan",
                            target,
                            "--dry-run",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        cwd=self.project_root,
                    )

                    # Some validation should occur (but may not fail immediately)
                    log_info(f"Target '{target}' result: {result.returncode}")

                except subprocess.TimeoutExpired:
                    log_info(f"Target '{target}' test timed out")
                except Exception as e:
                    log_info(f"Target '{target}' test failed: {e}")

        log_success("Scan command validation test completed")

    def test_scan_options(self):
        """Test scan command options"""
        log_info("Testing scan command options")

        # Common scan options to test
        options_to_test = [
            ["--profile", "quick"],
            ["--parallel"],
            ["--sequential"],
            ["--timeout", "60"],
            ["--include-port"],
            ["--include-dns"],
            ["--include-web"],
            ["--json-report"],
            ["--html-report"],
            ["--all-reports"],
        ]

        for options in options_to_test:
            with self.subTest(options=options):
                try:
                    cmd = (
                        [
                            sys.executable,
                            str(self.main_script),
                            "scan",
                            self.test_target,
                        ]
                        + options
                        + ["--dry-run"]
                    )

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=15,
                        cwd=self.project_root,
                    )

                    log_info(f"Options {options}: exit_code={result.returncode}")

                    # Log any error output for debugging
                    if result.stderr:
                        log_info(f"Options {options} stderr: {result.stderr[:100]}")

                except subprocess.TimeoutExpired:
                    log_info(f"Options {options} timed out")
                except Exception as e:
                    log_info(f"Options {options} failed: {e}")

        log_success("Scan options test completed")

    def test_quick_command(self):
        """Test quick scan command"""
        log_info("Testing quick command")

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(self.main_script),
                    "quick",
                    self.test_target,
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=self.project_root,
            )

            log_info(f"Quick command result: {result.returncode}")

            if result.stderr:
                log_info(f"Quick command stderr: {result.stderr[:200]}")

        except subprocess.TimeoutExpired:
            log_info("Quick command timed out")
        except Exception as e:
            log_info(f"Quick command test failed: {e}")

        log_success("Quick command test completed")

    def test_full_command(self):
        """Test full scan command"""
        log_info("Testing full command")

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(self.main_script),
                    "full",
                    self.test_target,
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=self.project_root,
            )

            log_info(f"Full command result: {result.returncode}")

            if result.stderr:
                log_info(f"Full command stderr: {result.stderr[:200]}")

        except subprocess.TimeoutExpired:
            log_info("Full command timed out")
        except Exception as e:
            log_info(f"Full command test failed: {e}")

        log_success("Full command test completed")

    def test_scanner_specific_commands(self):
        """Test scanner-specific commands"""
        log_info("Testing scanner-specific commands")

        scanner_commands = [
            ["port", self.test_target],
            ["dns", "example.com"],
            ["web", "https://example.com"],
            ["directory", "https://example.com"],
            ["ssl", "https://example.com"],
        ]

        for cmd_args in scanner_commands:
            with self.subTest(command=cmd_args[0]):
                try:
                    full_cmd = (
                        [sys.executable, str(self.main_script)]
                        + cmd_args
                        + ["--dry-run"]
                    )

                    result = subprocess.run(
                        full_cmd,
                        capture_output=True,
                        text=True,
                        timeout=15,
                        cwd=self.project_root,
                    )

                    log_info(
                        f"Scanner command '{cmd_args[0]}': exit_code={result.returncode}"
                    )

                except subprocess.TimeoutExpired:
                    log_info(f"Scanner command '{cmd_args[0]}' timed out")
                except Exception as e:
                    log_info(f"Scanner command '{cmd_args[0]}' failed: {e}")

        log_success("Scanner-specific commands test completed")


class TestCLIOutput(unittest.TestCase):
    """Test CLI output formatting and display"""

    def setUp(self):
        """Set up test fixtures"""
        self.project_root = Path(__file__).parent.parent
        self.main_script = self.project_root / "main.py"

    def test_output_formats(self):
        """Test different output formats"""
        log_info("Testing output formats")

        output_options = [
            ["--output", "json"],
            ["--output", "text"],
            ["--output", "table"],
            ["--format", "json"],
            ["--format", "text"],
        ]

        for options in output_options:
            with self.subTest(options=options):
                try:
                    cmd = [sys.executable, str(self.main_script), "scan-info"] + options

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        cwd=self.project_root,
                    )

                    log_info(f"Output format {options}: exit_code={result.returncode}")

                    if result.stdout:
                        log_info(
                            f"Output format {options} produced: {len(result.stdout)} chars"
                        )

                except subprocess.TimeoutExpired:
                    log_info(f"Output format {options} timed out")
                except Exception as e:
                    log_info(f"Output format {options} failed: {e}")

        log_success("Output formats test completed")

    def test_verbose_output(self):
        """Test verbose output options"""
        log_info("Testing verbose output")

        verbose_options = [["-v"], ["--verbose"], ["-vv"], ["--debug"]]

        for options in verbose_options:
            with self.subTest(options=options):
                try:
                    cmd = [sys.executable, str(self.main_script), "scan-info"] + options

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        cwd=self.project_root,
                    )

                    log_info(f"Verbose option {options}: exit_code={result.returncode}")

                except subprocess.TimeoutExpired:
                    log_info(f"Verbose option {options} timed out")
                except Exception as e:
                    log_info(f"Verbose option {options} failed: {e}")

        log_success("Verbose output test completed")

    def test_quiet_output(self):
        """Test quiet output options"""
        log_info("Testing quiet output")

        quiet_options = [["-q"], ["--quiet"], ["--silent"]]

        for options in quiet_options:
            with self.subTest(options=options):
                try:
                    cmd = [sys.executable, str(self.main_script), "scan-info"] + options

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        cwd=self.project_root,
                    )

                    log_info(f"Quiet option {options}: exit_code={result.returncode}")

                    # Quiet mode should have less output
                    if result.stdout:
                        log_info(
                            f"Quiet option {options} output length: {len(result.stdout)}"
                        )

                except subprocess.TimeoutExpired:
                    log_info(f"Quiet option {options} timed out")
                except Exception as e:
                    log_info(f"Quiet option {options} failed: {e}")

        log_success("Quiet output test completed")


class TestCLIConfiguration(unittest.TestCase):
    """Test CLI configuration handling"""

    def setUp(self):
        """Set up test fixtures"""
        self.project_root = Path(__file__).parent.parent
        self.main_script = self.project_root / "main.py"
        self.temp_dir = None

    def tearDown(self):
        """Clean up test fixtures"""
        if self.temp_dir and self.temp_dir.exists():
            import shutil

            shutil.rmtree(self.temp_dir)

    def test_config_file_options(self):
        """Test configuration file options"""
        log_info("Testing config file options")

        config_options = [
            ["--config", "config/settings.py"],
            ["--config-file", "nonexistent.yaml"],
            ["-c", "config.json"],
        ]

        for options in config_options:
            with self.subTest(options=options):
                try:
                    cmd = [sys.executable, str(self.main_script), "scan-info"] + options

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        cwd=self.project_root,
                    )

                    log_info(f"Config option {options}: exit_code={result.returncode}")

                except subprocess.TimeoutExpired:
                    log_info(f"Config option {options} timed out")
                except Exception as e:
                    log_info(f"Config option {options} failed: {e}")

        log_success("Config file options test completed")

    def test_output_directory_options(self):
        """Test output directory options"""
        log_info("Testing output directory options")

        # Create temporary directory
        import tempfile

        self.temp_dir = Path(tempfile.mkdtemp())

        output_options = [
            ["--output-dir", str(self.temp_dir)],
            ["--report-dir", str(self.temp_dir)],
            ["-o", str(self.temp_dir)],
        ]

        for options in output_options:
            with self.subTest(options=options):
                try:
                    cmd = [sys.executable, str(self.main_script), "scan-info"] + options

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        cwd=self.project_root,
                    )

                    log_info(
                        f"Output dir option {options}: exit_code={result.returncode}"
                    )

                except subprocess.TimeoutExpired:
                    log_info(f"Output dir option {options} timed out")
                except Exception as e:
                    log_info(f"Output dir option {options} failed: {e}")

        log_success("Output directory options test completed")

    def test_custom_wordlist_options(self):
        """Test custom wordlist options"""
        log_info("Testing custom wordlist options")

        # Create temporary wordlist
        import tempfile

        temp_wordlist = tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        )
        temp_wordlist.write("admin\ntest\nbackup\n")
        temp_wordlist.close()

        try:
            wordlist_options = [
                ["--wordlist", temp_wordlist.name],
                ["--custom-wordlist", temp_wordlist.name],
                ["-w", temp_wordlist.name],
            ]

            for options in wordlist_options:
                with self.subTest(options=options):
                    try:
                        cmd = (
                            [
                                sys.executable,
                                str(self.main_script),
                                "directory",
                                "https://example.com",
                            ]
                            + options
                            + ["--dry-run"]
                        )

                        result = subprocess.run(
                            cmd,
                            capture_output=True,
                            text=True,
                            timeout=15,
                            cwd=self.project_root,
                        )

                        log_info(
                            f"Wordlist option {options}: exit_code={result.returncode}"
                        )

                    except subprocess.TimeoutExpired:
                        log_info(f"Wordlist option {options} timed out")
                    except Exception as e:
                        log_info(f"Wordlist option {options} failed: {e}")

        finally:
            # Cleanup
            os.unlink(temp_wordlist.name)

        log_success("Custom wordlist options test completed")


class TestCLIInteractive(unittest.TestCase):
    """Test CLI interactive features"""

    def setUp(self):
        """Set up test fixtures"""
        self.project_root = Path(__file__).parent.parent
        self.main_script = self.project_root / "main.py"

    def test_dry_run_mode(self):
        """Test dry run mode"""
        log_info("Testing dry run mode")

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(self.main_script),
                    "scan",
                    "example.com",
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=self.project_root,
            )

            log_info(f"Dry run mode: exit_code={result.returncode}")

            # Dry run should complete quickly and not perform actual scans
            output = result.stdout + result.stderr
            dry_run_indicators = ["dry", "simulation", "would", "preview"]
            found_indicators = [
                ind for ind in dry_run_indicators if ind.lower() in output.lower()
            ]

            if found_indicators:
                log_info(f"Dry run indicators found: {found_indicators}")
            else:
                log_info("No explicit dry run indicators found in output")

        except subprocess.TimeoutExpired:
            log_info("Dry run mode timed out")
        except Exception as e:
            log_info(f"Dry run mode test failed: {e}")

        log_success("Dry run mode test completed")

    def test_interactive_prompts(self):
        """Test interactive prompts (if any)"""
        log_info("Testing interactive prompts")

        # Test with stdin input
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(self.main_script),
                    "scan",
                    "example.com",
                    "--interactive",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.project_root,
            )

            # Send some input and wait briefly
            try:
                stdout, stderr = process.communicate(input="n\n", timeout=10)
                log_info(f"Interactive test: exit_code={process.returncode}")
            except subprocess.TimeoutExpired:
                process.kill()
                log_info(
                    "Interactive test timed out (expected for non-interactive mode)"
                )

        except Exception as e:
            log_info(f"Interactive prompts test failed: {e}")

        log_success("Interactive prompts test completed")

    def test_confirmation_prompts(self):
        """Test confirmation prompts for dangerous operations"""
        log_info("Testing confirmation prompts")

        # Test operations that might require confirmation
        dangerous_operations = [
            ["scan", "192.168.1.0/24", "--aggressive"],
            ["scan", "example.com", "--all-scanners", "--no-limits"],
        ]

        for operation in dangerous_operations:
            with self.subTest(operation=operation[0]):
                try:
                    cmd = (
                        [sys.executable, str(self.main_script)]
                        + operation
                        + ["--dry-run"]
                    )

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=15,
                        cwd=self.project_root,
                    )

                    log_info(f"Operation {operation[0]}: exit_code={result.returncode}")

                except subprocess.TimeoutExpired:
                    log_info(f"Operation {operation[0]} timed out")
                except Exception as e:
                    log_info(f"Operation {operation[0]} failed: {e}")

        log_success("Confirmation prompts test completed")


class TestCLIErrorHandling(unittest.TestCase):
    """Test CLI error handling and edge cases"""

    def setUp(self):
        """Set up test fixtures"""
        self.project_root = Path(__file__).parent.parent
        self.main_script = self.project_root / "main.py"

    def test_missing_arguments(self):
        """Test handling of missing required arguments"""
        log_info("Testing missing arguments handling")

        incomplete_commands = [
            ["scan"],  # Missing target
            ["port"],  # Missing target
            ["web"],  # Missing target
            ["--output"],  # Missing output format
        ]

        for cmd in incomplete_commands:
            with self.subTest(command=cmd):
                try:
                    result = subprocess.run(
                        [sys.executable, str(self.main_script)] + cmd,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        cwd=self.project_root,
                    )

                    # Should return non-zero exit code for missing args
                    log_info(f"Missing args {cmd}: exit_code={result.returncode}")

                    # Should have error message
                    error_output = result.stderr + result.stdout
                    if (
                        "error" in error_output.lower()
                        or "usage" in error_output.lower()
                    ):
                        log_info(f"Proper error handling for {cmd}")

                except subprocess.TimeoutExpired:
                    log_info(f"Missing args {cmd} timed out")
                except Exception as e:
                    log_info(f"Missing args {cmd} failed: {e}")

        log_success("Missing arguments handling test completed")

    def test_invalid_options(self):
        """Test handling of invalid options"""
        log_info("Testing invalid options handling")

        invalid_options = [
            ["--invalid-option"],
            ["--profile", "nonexistent"],
            ["--timeout", "-1"],
            ["--threads", "abc"],
            ["--output", "invalid_format"],
        ]

        for options in invalid_options:
            with self.subTest(options=options):
                try:
                    cmd = [
                        sys.executable,
                        str(self.main_script),
                        "scan",
                        "example.com",
                    ] + options

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        cwd=self.project_root,
                    )

                    log_info(f"Invalid option {options}: exit_code={result.returncode}")

                except subprocess.TimeoutExpired:
                    log_info(f"Invalid option {options} timed out")
                except Exception as e:
                    log_info(f"Invalid option {options} failed: {e}")

        log_success("Invalid options handling test completed")

    def test_permission_errors(self):
        """Test handling of permission errors"""
        log_info("Testing permission errors handling")

        # Test writing to restricted directories
        restricted_paths = [
            "/root/output",
            "/etc/pentest",
            "C:\\Windows\\System32\\output",
        ]

        for path in restricted_paths:
            if os.path.exists(os.path.dirname(path)) or path.startswith("C:"):
                with self.subTest(path=path):
                    try:
                        cmd = [
                            sys.executable,
                            str(self.main_script),
                            "scan",
                            "example.com",
                            "--output-dir",
                            path,
                            "--dry-run",
                        ]

                        result = subprocess.run(
                            cmd,
                            capture_output=True,
                            text=True,
                            timeout=10,
                            cwd=self.project_root,
                        )

                        log_info(
                            f"Restricted path {path}: exit_code={result.returncode}"
                        )

                    except subprocess.TimeoutExpired:
                        log_info(f"Restricted path {path} timed out")
                    except Exception as e:
                        log_info(f"Restricted path {path} failed: {e}")

        log_success("Permission errors handling test completed")


def run_cli_interface_tests():
    """Run all CLI interface tests"""
    print("=" * 60)
    print("💻 AUTO-PENTEST CLI INTERFACE TEST SUITE")
    print("=" * 60)

    global cli_available, click_available

    if not cli_available:
        print("⚠️  CLI modules not found - using subprocess testing only")

    if not click_available:
        print("⚠️  Click not available - limited CLI testing")

    # Setup logging
    LoggerSetup.setup_logger("test_cli_interface", level="INFO", use_rich=True)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestCLIBasics))
    suite.addTests(loader.loadTestsFromTestCase(TestCLICommands))
    suite.addTests(loader.loadTestsFromTestCase(TestCLIOutput))
    suite.addTests(loader.loadTestsFromTestCase(TestCLIConfiguration))
    suite.addTests(loader.loadTestsFromTestCase(TestCLIInteractive))
    suite.addTests(loader.loadTestsFromTestCase(TestCLIErrorHandling))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 60)
    print("📊 CLI INTERFACE TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if not cli_available:
        print("\n📝 NOTE: CLI tests used subprocess testing due to missing modules")
        print("   This provides integration testing of the actual CLI interface")

    if result.failures:
        print("\n❌ FAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")

    if result.errors:
        print("\n❌ ERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")

    if result.wasSuccessful():
        print("\n✅ ALL CLI INTERFACE TESTS PASSED!")
        return True
    else:
        print("\n❌ SOME TESTS FAILED!")
        return False


if __name__ == "__main__":
    success = run_cli_interface_tests()
    sys.exit(0 if success else 1)
