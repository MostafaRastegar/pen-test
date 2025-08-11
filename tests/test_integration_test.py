#!/usr/bin/env python3
"""
Auto-Pentest Project Test Script
Complete integration test for the project
"""

import sys
import subprocess
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.utils.logger import LoggerSetup, log_banner, log_success, log_error, log_info, log_warning
from src.core import CommandExecutor, InputValidator
from src.scanners.recon.port_scanner import PortScanner


def test_system_requirements():
    """Test system requirements and tool availability"""
    log_banner("System Requirements Check", "bold blue")

    # Test Python version
    python_version = sys.version_info
    if python_version >= (3, 8):
        log_success(f"✓ Python {python_version.major}.{python_version.minor}.{python_version.micro}")
    else:
        log_error(f"✗ Python version too old: {python_version.major}.{python_version.minor}")
        return False

    # Test tool availability
    executor = CommandExecutor()
    required_tools = ["nmap"]
    optional_tools = ["nikto", "sqlmap", "dirb", "subfinder"]

    all_good = True

    log_info("Required tools:")
    for tool in required_tools:
        if executor.check_tool_exists(tool):
            version = executor.get_tool_version(tool)
            version_str = version.split('\n')[0] if version else "unknown"
            log_success(f"  ✓ {tool}: {version_str}")
        else:
            log_error(f"  ✗ {tool}: NOT FOUND")
            all_good = False

    log_info("Optional tools:")
    for tool in optional_tools:
        if executor.check_tool_exists(tool):
            version = executor.get_tool_version(tool)
            version_str = version.split('\n')[0] if version else "unknown"
            log_success(f"  ✓ {tool}: {version_str}")
        else:
            log_warning(f"  ! {tool}: NOT FOUND (optional)")

    return all_good


def test_core_modules():
    """Test core framework modules"""
    log_banner("Core Modules Test", "bold green")

    try:
        # Test command executor
        log_info("Testing CommandExecutor...")
        executor = CommandExecutor(timeout=10)

        result = executor.execute("echo 'Hello World'")
        if result.success and "Hello World" in result.stdout:
            log_success("✓ CommandExecutor working")
        else:
            log_error("✗ CommandExecutor failed")
            return False

        # Test input validator
        log_info("Testing InputValidator...")
        validator = InputValidator()

        # Test IP validation
        if validator.validate_target("192.168.1.1")[0]:
            log_success("✓ IP validation working")
        else:
            log_error("✗ IP validation failed")
            return False

        # Test domain validation
        if validator.validate_target("example.com")[0]:
            log_success("✓ Domain validation working")
        else:
            log_error("✗ Domain validation failed")
            return False

        log_success("All core modules working!")
        return True

    except Exception as e:
        log_error(f"Core modules test failed: {e}")
        return False


def test_port_scanner():
    """Test port scanner functionality"""
    log_banner("Port Scanner Test", "bold cyan")

    try:
        # Create scanner
        scanner = PortScanner(timeout=60)
        log_info("✓ PortScanner created")

        # Test capabilities
        capabilities = scanner.get_capabilities()
        log_info(f"✓ Scanner capabilities: {len(capabilities)} items")

        # Test command building
        cmd = scanner._build_nmap_command("127.0.0.1", {"ports": "quick"})
        if "nmap" in cmd and "127.0.0.1" in cmd:
            log_success("✓ Command building working")
        else:
            log_error("✗ Command building failed")
            return False

        # Test XML parsing with sample data
        sample_xml = '''<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="127.0.0.1"/>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="7.4"/>
            </port>
        </ports>
    </host>
</nmaprun>'''

        from src.core import ScanResult, ScanStatus
        from datetime import datetime

        test_result = ScanResult(
            scanner_name="test",
            target="127.0.0.1",
            status=ScanStatus.RUNNING,
            start_time=datetime.now()
        )

        scanner._parse_nmap_xml(sample_xml, test_result)

        if len(test_result.findings) > 0:
            log_success("✓ XML parsing working")
        else:
            log_error("✗ XML parsing failed")
            return False

        log_success("Port scanner tests passed!")
        return True

    except Exception as e:
        log_error(f"Port scanner test failed: {e}")
        return False


def test_cli_interface():
    """Test CLI interface"""
    log_banner("CLI Interface Test", "bold magenta")

    try:
        # Test help command
        log_info("Testing CLI help...")
        result = subprocess.run([sys.executable, "main.py", "--help"],
                              capture_output=True, text=True, timeout=10)

        if result.returncode == 0 and "Auto-Pentest" in result.stdout:
            log_success("✓ CLI help working")
        else:
            log_error("✗ CLI help failed")
            return False

        # Test list-tools command
        log_info("Testing list-tools command...")
        result = subprocess.run([sys.executable, "main.py", "list-tools"],
                              capture_output=True, text=True, timeout=15)

        if result.returncode == 0:
            log_success("✓ list-tools command working")
        else:
            log_error("✗ list-tools command failed")
            return False

        # Test info command
        log_info("Testing info command...")
        result = subprocess.run([sys.executable, "main.py", "info"],
                              capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            log_success("✓ info command working")
        else:
            log_error("✗ info command failed")
            return False

        log_success("CLI interface tests passed!")
        return True

    except Exception as e:
        log_error(f"CLI interface test failed: {e}")
        return False


def test_real_scan():
    """Test a real scan (if nmap is available)"""
    log_banner("Real Scan Test", "bold yellow")

    try:
        executor = CommandExecutor()

        if not executor.check_tool_exists("nmap"):
            log_warning("! Skipping real scan test - nmap not available")
            return True

        log_info("Testing real scan on localhost...")

        # Use CLI to run a real scan
        result = subprocess.run([
            sys.executable, "main.py", "scan", "127.0.0.1",
            "--ports", "22,80,443", "--timeout", "30"
        ], capture_output=True, text=True, timeout=45)

        if result.returncode == 0:
            log_success("✓ Real scan completed successfully")

            # Check if output file was created
            from config.settings import REPORT_DIR
            report_files = list(REPORT_DIR.glob("scan_127.0.0.1_*.json"))

            if report_files:
                log_success(f"✓ Report file created: {report_files[0].name}")

                # Validate JSON content
                with open(report_files[0], 'r') as f:
                    scan_data = json.load(f)

                if scan_data.get('target') == '127.0.0.1':
                    log_success("✓ Report content valid")
                else:
                    log_error("✗ Report content invalid")
                    return False
            else:
                log_error("✗ No report file created")
                return False
        else:
            log_error(f"✗ Real scan failed: {result.stderr}")
            return False

        log_success("Real scan test passed!")
        return True

    except Exception as e:
        log_error(f"Real scan test failed: {e}")
        return False


def test_project_structure():
    """Test project file structure"""
    log_banner("Project Structure Test", "bold white")

    required_files = [
        "main.py",
        "requirements.txt",
        "config/settings.py",
        "config/tools_config.yaml",
        "src/core/scanner_base.py",
        "src/core/executor.py",
        "src/core/validator.py",
        "src/utils/logger.py",
        "src/scanners/recon/port_scanner.py",
        "tests/core/test_core.py"
    ]

    required_dirs = [
        "src/",
        "config/",
        "tests/",
        "output/",
        "output/logs/",
        "output/reports/"
    ]

    all_good = True

    log_info("Checking required files...")
    for file_path in required_files:
        if Path(file_path).exists():
            log_success(f"  ✓ {file_path}")
        else:
            log_error(f"  ✗ {file_path}")
            all_good = False

    log_info("Checking required directories...")
    for dir_path in required_dirs:
        if Path(dir_path).exists():
            log_success(f"  ✓ {dir_path}")
        else:
            log_error(f"  ✗ {dir_path}")
            all_good = False

    if all_good:
        log_success("Project structure is complete!")
    else:
        log_error("Project structure has missing components!")

    return all_good


def run_comprehensive_test():
    """Run all tests in sequence"""
    log_banner("Auto-Pentest Comprehensive Test Suite", "bold red")

    tests = [
        ("Project Structure", test_project_structure),
        ("System Requirements", test_system_requirements),
        ("Core Modules", test_core_modules),
        ("Port Scanner", test_port_scanner),
        ("CLI Interface", test_cli_interface),
        ("Real Scan", test_real_scan)
    ]

    results = {}

    for test_name, test_func in tests:
        log_info(f"\n{'='*60}")
        log_info(f"Running: {test_name}")
        log_info('='*60)

        try:
            result = test_func()
            results[test_name] = result

            if result:
                log_success(f"✅ {test_name}: PASSED")
            else:
                log_error(f"❌ {test_name}: FAILED")

        except Exception as e:
            log_error(f"❌ {test_name}: ERROR - {e}")
            results[test_name] = False

    # Summary
    log_banner("Test Results Summary", "bold blue")

    passed = sum(1 for result in results.values() if result)
    total = len(results)

    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        log_info(f"{status} {test_name}")

    log_info(f"\nOverall: {passed}/{total} tests passed")

    if passed == total:
        log_banner("🎉 ALL TESTS PASSED! 🎉", "bold green")
        log_info("The Auto-Pentest project is ready to use!")

        log_info("\nNext steps:")
        log_info("1. python main.py list-tools  # Check tool availability")
        log_info("2. python main.py quick 127.0.0.1  # Try a quick scan")
        log_info("3. python main.py --help  # Explore all options")

        return True
    else:
        log_banner("⚠️  SOME TESTS FAILED ⚠️", "bold yellow")
        log_info("Please fix the failed tests before using the tool.")
        return False


def main():
    """Main test function"""
    # Setup logger
    logger = LoggerSetup.setup_logger(
        name="project_test",
        level="INFO",
        use_rich=True
    )

    try:
        success = run_comprehensive_test()
        return 0 if success else 1

    except KeyboardInterrupt:
        log_warning("\nTest interrupted by user")
        return 1
    except Exception as e:
        log_error(f"Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())