#!/usr/bin/env python3
"""
WordPress Scanner Integration Test
Tests the complete integration of WordPress scanner into the Auto-Pentest Framework
Phase 1.1 Implementation Validation
"""

import sys
import subprocess
from pathlib import Path
from unittest.mock import patch, Mock

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.utils.logger import (
    LoggerSetup,
    log_banner,
    log_success,
    log_error,
    log_info,
    log_warning,
)


def test_wordpress_scanner_import():
    """Test WordPress scanner import and basic functionality"""
    log_banner("WordPress Scanner Import Test", "bold blue")

    try:
        # Test direct import
        from src.scanners.cms.wordpress_scanner import WordPressScanner

        log_success("✅ Direct import successful")

        # Test registry import
        from src.scanners import get_scanner_by_name, SCANNER_REGISTRY

        # Check if WordPress scanner is in registry
        if "wordpress" in SCANNER_REGISTRY:
            log_success("✅ WordPress scanner registered in SCANNER_REGISTRY")
        else:
            log_error("❌ WordPress scanner NOT found in SCANNER_REGISTRY")
            return False

        # Test scanner instantiation
        scanner = WordPressScanner()
        log_success("✅ WordPress scanner instantiation successful")

        # Test capabilities
        capabilities = scanner.get_capabilities()
        required_fields = ["name", "description", "scan_types", "features"]

        for field in required_fields:
            if field in capabilities:
                log_success(f"✅ Capability field '{field}' present")
            else:
                log_error(f"❌ Missing capability field: {field}")
                return False

        # Test target validation
        valid_targets = ["https://example.com", "example.com", "192.168.1.1"]
        for target in valid_targets:
            if scanner.validate_target(target):
                log_success(f"✅ Target validation passed: {target}")
            else:
                log_error(f"❌ Target validation failed: {target}")
                return False

        log_success("WordPress scanner import test completed successfully")
        return True

    except Exception as e:
        log_error(f"WordPress scanner import test failed: {e}")
        return False


def test_cli_integration():
    """Test CLI integration of WordPress scanner"""
    log_banner("CLI Integration Test", "bold green")

    try:
        # Test help command for WordPress scanner
        log_info("Testing WordPress command help...")
        result = subprocess.run(
            [sys.executable, "main.py", "wordpress", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            if "WordPress security scanning" in result.stdout:
                log_success("✅ WordPress CLI help command working")
            else:
                log_error("❌ WordPress CLI help content incorrect")
                return False
        else:
            log_error(f"❌ WordPress CLI help failed (exit code: {result.returncode})")
            log_error(f"STDERR: {result.stderr}")
            return False

        # Test main CLI help includes WordPress
        log_info("Testing main CLI help includes WordPress...")
        result = subprocess.run(
            [sys.executable, "main.py", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            if "wordpress" in result.stdout.lower():
                log_success("✅ WordPress command listed in main CLI help")
            else:
                log_warning("⚠️  WordPress command not prominently listed in main CLI")

        log_success("CLI integration test completed successfully")
        return True

    except Exception as e:
        log_error(f"CLI integration test failed: {e}")
        return False


def test_orchestrator_integration():
    """Test orchestrator integration with WordPress scanner"""
    log_banner("Orchestrator Integration Test", "bold yellow")

    try:
        # Test workflow builder
        from src.orchestrator.workflow_builder import WorkflowBuilder

        builder = WorkflowBuilder()

        # Check if add_wordpress_scanner method exists
        if hasattr(builder, "add_wordpress_scanner"):
            log_success("✅ WorkflowBuilder has add_wordpress_scanner method")

            # Test adding WordPress scanner to workflow
            builder.add_wordpress_scanner(
                enumerate_plugins=True, enumerate_themes=True, use_wpscan=True
            )

            if len(builder.scanners) > 0:
                wordpress_scanner = builder.scanners[-1]  # Last added
                if wordpress_scanner["type"] == "wordpress":
                    log_success("✅ WordPress scanner added to workflow builder")
                else:
                    log_error("❌ WordPress scanner not properly added")
                    return False
            else:
                log_error("❌ No scanners added to workflow builder")
                return False
        else:
            log_error("❌ WorkflowBuilder missing add_wordpress_scanner method")
            return False

        # Test CMS workflow functions
        try:
            from src.orchestrator.workflow import (
                create_cms_workflow,
                create_wordpress_workflow,
            )

            log_success("✅ CMS workflow functions available")
        except ImportError as e:
            log_warning(f"⚠️  CMS workflow functions not available: {e}")

        log_success("Orchestrator integration test completed successfully")
        return True

    except Exception as e:
        log_error(f"Orchestrator integration test failed: {e}")
        return False


def test_configuration_integration():
    """Test configuration file integration"""
    log_banner("Configuration Integration Test", "bold magenta")

    try:
        # Check if tools_config.yaml includes WPScan
        config_file = Path("config/tools_config.yaml")

        if not config_file.exists():
            log_warning("⚠️  tools_config.yaml not found")
            return True  # Not critical for basic functionality

        with open(config_file, "r") as f:
            config_content = f.read()

        if "wpscan" in config_content.lower():
            log_success("✅ WPScan configuration found in tools_config.yaml")
        else:
            log_warning("⚠️  WPScan configuration not found in tools_config.yaml")

        # Test YAML parsing
        try:
            import yaml

            with open(config_file, "r") as f:
                config_data = yaml.safe_load(f)

            if "tools" in config_data and "wpscan" in config_data["tools"]:
                wpscan_config = config_data["tools"]["wpscan"]
                log_success("✅ WPScan YAML configuration parsed successfully")
                log_info(f"   Name: {wpscan_config.get('name', 'N/A')}")
                log_info(f"   Binary: {wpscan_config.get('binary', 'N/A')}")
            else:
                log_warning("⚠️  WPScan not found in parsed YAML configuration")

        except Exception as e:
            log_error(f"❌ Configuration parsing failed: {e}")
            return False

        log_success("Configuration integration test completed successfully")
        return True

    except Exception as e:
        log_error(f"Configuration integration test failed: {e}")
        return False


def test_scanner_registry():
    """Test scanner registry functionality"""
    log_banner("Scanner Registry Test", "bold cyan")

    try:
        from src.scanners import (
            SCANNER_REGISTRY,
            SCANNERS_BY_CATEGORY,
            get_scanner_by_name,
            get_scanners_by_category,
            list_available_scanners,
        )

        # Test registry contents
        if "wordpress" in SCANNER_REGISTRY:
            log_success("✅ WordPress scanner in SCANNER_REGISTRY")
        else:
            log_error("❌ WordPress scanner missing from SCANNER_REGISTRY")
            return False

        # Test category organization
        if "cms" in SCANNERS_BY_CATEGORY:
            cms_scanners = SCANNERS_BY_CATEGORY["cms"]
            if "wordpress" in cms_scanners:
                log_success("✅ WordPress scanner in CMS category")
            else:
                log_error("❌ WordPress scanner missing from CMS category")
                return False
        else:
            log_error("❌ CMS category missing from SCANNERS_BY_CATEGORY")
            return False

        # Test utility functions
        wordpress_scanner_class = get_scanner_by_name("wordpress")
        if wordpress_scanner_class:
            log_success("✅ get_scanner_by_name('wordpress') works")
        else:
            log_error("❌ get_scanner_by_name('wordpress') failed")
            return False

        cms_scanners = get_scanners_by_category("cms")
        if cms_scanners and "wordpress" in cms_scanners:
            log_success("✅ get_scanners_by_category('cms') includes WordPress")
        else:
            log_error("❌ get_scanners_by_category('cms') missing WordPress")
            return False

        # Test list function
        available_scanners = list_available_scanners()
        if "cms" in available_scanners and "wordpress" in available_scanners["cms"]:
            log_success("✅ list_available_scanners includes WordPress")
        else:
            log_error("❌ list_available_scanners missing WordPress")
            return False

        log_success("Scanner registry test completed successfully")
        return True

    except Exception as e:
        log_error(f"Scanner registry test failed: {e}")
        return False


def test_project_structure_update():
    """Test that project structure includes new files"""
    log_banner("Project Structure Update Test", "bold white")

    required_files = [
        "src/scanners/cms/__init__.py",
        "src/scanners/cms/wordpress_scanner.py",
    ]

    optional_files = [
        "tests/test_wordpress_scanner.py",
        "config/tools_config.yaml",
    ]

    all_good = True

    log_info("Checking required new files...")
    for file_path in required_files:
        if Path(file_path).exists():
            log_success(f"✅ {file_path}")
        else:
            log_error(f"❌ {file_path}")
            all_good = False

    log_info("Checking optional new files...")
    for file_path in optional_files:
        if Path(file_path).exists():
            log_success(f"✅ {file_path}")
        else:
            log_warning(f"⚠️  {file_path}")

    if all_good:
        log_success("Project structure update test completed successfully")
    else:
        log_error("Project structure update test failed - missing required files")

    return all_good


def test_mock_wordpress_scan():
    """Test WordPress scanner with mocked responses"""
    log_banner("Mock WordPress Scan Test", "bold red")

    try:
        from src.scanners.cms.wordpress_scanner import WordPressScanner
        from src.core import ScanResult, ScanStatus
        from datetime import datetime

        scanner = WordPressScanner()

        # Mock the HTTP session to simulate WordPress responses
        with patch(
            "src.scanners.cms.wordpress_scanner.requests.Session"
        ) as mock_session:
            # Mock WordPress detection response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = """
            <html>
            <head>
                <meta name="generator" content="WordPress 6.3.1" />
                <link rel="stylesheet" href="/wp-content/themes/twentytwentythree/style.css" />
            </head>
            </html>
            """
            mock_response.headers = {"Server": "Apache/2.4.41"}

            mock_session_instance = Mock()
            mock_session_instance.get.return_value = mock_response
            mock_session.return_value = mock_session_instance

            # Mock WPScan not available for this test
            with patch.object(scanner, "_check_wpscan_available") as mock_wpscan:
                mock_wpscan.return_value = {"available": False}

                # Execute scan
                scan_options = {
                    "enumerate_plugins": True,
                    "enumerate_themes": True,
                    "enumerate_users": False,  # Skip user enum in mock test
                    "use_wpscan": False,
                }

                result = scanner._execute_scan("https://example.com", scan_options)

                # Validate results
                if result.status == ScanStatus.COMPLETED:
                    log_success("✅ Mock WordPress scan completed successfully")
                else:
                    log_error(
                        f"❌ Mock WordPress scan failed with status: {result.status}"
                    )
                    if result.errors:
                        log_error(f"   Errors: {result.errors}")
                    return False

                if len(result.findings) > 0:
                    log_success(
                        f"✅ Mock scan generated {len(result.findings)} findings"
                    )

                    # Check for WordPress detection finding
                    wp_detected = any(
                        "WordPress" in f.get("title", "") for f in result.findings
                    )
                    if wp_detected:
                        log_success("✅ WordPress detection finding present")
                    else:
                        log_warning("⚠️  WordPress detection finding not found")
                else:
                    log_warning("⚠️  No findings generated in mock scan")

        log_success("Mock WordPress scan test completed successfully")
        return True

    except Exception as e:
        log_error(f"Mock WordPress scan test failed: {e}")
        import traceback

        log_error(traceback.format_exc())
        return False


def run_wordpress_integration_tests():
    """Run all WordPress integration tests"""
    log_banner("WordPress Scanner Integration Test Suite", "bold white on red")

    tests = [
        ("WordPress Scanner Import", test_wordpress_scanner_import),
        ("CLI Integration", test_cli_integration),
        ("Orchestrator Integration", test_orchestrator_integration),
        ("Configuration Integration", test_configuration_integration),
        ("Scanner Registry", test_scanner_registry),
        ("Project Structure Update", test_project_structure_update),
        ("Mock WordPress Scan", test_mock_wordpress_scan),
    ]

    results = {}

    for test_name, test_func in tests:
        log_info(f"\n{'='*60}")
        log_info(f"Running: {test_name}")
        log_info("=" * 60)

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
    log_banner("Integration Test Results Summary", "bold blue")

    passed = sum(1 for result in results.values() if result)
    total = len(results)

    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        log_info(f"{status} {test_name}")

    log_info(f"\nOverall: {passed}/{total} tests passed")

    if passed == total:
        log_banner("🎉 ALL INTEGRATION TESTS PASSED! 🎉", "bold green")
        log_info("WordPress Scanner is successfully integrated!")
        log_info("\nNext Steps:")
        log_info("1. Test with a real WordPress site")
        log_info("2. Install WPScan for full functionality")
        log_info("3. Configure WPScan API token for vulnerability data")
        return True
    else:
        log_banner("⚠️  SOME INTEGRATION TESTS FAILED ⚠️", "bold yellow")
        log_info("Please address the failed tests before proceeding")
        return False


if __name__ == "__main__":
    # Setup logging
    LoggerSetup.setup_console_logging()

    # Run integration tests
    success = run_wordpress_integration_tests()

    # Exit with appropriate code
    sys.exit(0 if success else 1)
