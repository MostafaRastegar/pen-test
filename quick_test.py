#!/usr/bin/env python3
"""
Quick test script for debugging issues
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from main import parse_target, get_scanner_target
from src.scanners.recon.port_scanner import PortScanner


def test_report_generation():
    """Test report generation independently"""
    print("=== TESTING REPORT GENERATION ===")

    # Create reports directory
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    print(f"✓ Reports directory: {reports_dir.absolute()}")

    # Create test data
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Test JSON report
    try:
        json_file = reports_dir / f"test_{timestamp}.json"
        test_data = {
            "scan_info": {"target": "test", "timestamp": timestamp},
            "results": {
                "test_scanner": {
                    "success": True,
                    "findings": [{"title": "Test Finding", "severity": "info"}],
                }
            },
        }

        with open(json_file, "w") as f:
            json.dump(test_data, f, indent=2)

        file_size = json_file.stat().st_size
        print(f"✓ JSON report created: {json_file} ({file_size} bytes)")

        # Read it back
        with open(json_file, "r") as f:
            data = json.load(f)
        print(f"✓ JSON report readable: {len(data)} sections")

    except Exception as e:
        print(f"✗ JSON report failed: {e}")
        return False

    # Test TXT report
    try:
        txt_file = reports_dir / f"test_{timestamp}.txt"

        with open(txt_file, "w") as f:
            f.write("=== TEST REPORT ===\n")
            f.write(f"Generated: {timestamp}\n")
            f.write("This is a test report\n")

        file_size = txt_file.stat().st_size
        print(f"✓ TXT report created: {txt_file} ({file_size} bytes)")

    except Exception as e:
        print(f"✗ TXT report failed: {e}")
        return False

    return True


def test_scanner_results():
    """Test scanner result structure"""
    print("\n=== TESTING SCANNER RESULTS ===")

    try:
        scanner = PortScanner(timeout=30)
        target = "127.0.0.1"  # Safe target
        options = {"ports": "22,80", "service_detection": False}

        print(f"Testing scanner with: {target}")
        result = scanner.scan(target, options)

        print(f"Result type: {type(result)}")
        print(f"Has success attr: {hasattr(result, 'success')}")
        print(f"Success value: {getattr(result, 'success', 'NO ATTR')}")
        print(f"Has findings attr: {hasattr(result, 'findings')}")
        print(f"Findings count: {len(getattr(result, 'findings', []))}")
        print(f"Has error_message: {hasattr(result, 'error_message')}")
        print(f"Error message: {getattr(result, 'error_message', 'None')}")

        # Test to_dict if available
        if hasattr(result, "to_dict"):
            print("✓ Result has to_dict method")
            try:
                dict_result = result.to_dict()
                print(f"✓ to_dict() works: {len(dict_result)} keys")
            except Exception as e:
                print(f"✗ to_dict() failed: {e}")
        else:
            print("✗ Result has no to_dict method")

        return result

    except Exception as e:
        print(f"✗ Scanner test failed: {e}")
        import traceback

        print(f"Traceback: {traceback.format_exc()}")
        return None


def test_target_parsing():
    """Test target parsing"""
    print("\n=== TESTING TARGET PARSING ===")

    test_target = "http://192.168.48.207"
    print(f"Testing target: {test_target}")

    try:
        target_info = parse_target(test_target)
        print(f"✓ Target parsed: {target_info}")

        # Test scanner targets
        for scanner_type in ["port_scanner", "web_scanner", "directory_scanner"]:
            scanner_target = get_scanner_target(target_info, scanner_type)
            print(f"  {scanner_type}: {scanner_target}")

        return True

    except Exception as e:
        print(f"✗ Target parsing failed: {e}")
        return False


def main():
    print("Quick Test and Debug Tool")
    print("=" * 40)

    # Test each component
    target_ok = test_target_parsing()
    scanner_result = test_scanner_results()
    report_ok = test_report_generation()

    print("\n=== SUMMARY ===")
    print(f"Target parsing: {'✓' if target_ok else '✗'}")
    print(f"Scanner result: {'✓' if scanner_result else '✗'}")
    print(f"Report generation: {'✓' if report_ok else '✗'}")

    if scanner_result:
        # Test success detection logic
        findings_count = len(getattr(scanner_result, "findings", []))
        result_success = getattr(scanner_result, "success", False)
        is_successful = result_success or findings_count > 0

        print(f"\nSuccess Detection Test:")
        print(f"  Result success: {result_success}")
        print(f"  Findings count: {findings_count}")
        print(f"  Would be considered successful: {is_successful}")

    print("\nRecommendations:")
    if not target_ok:
        print("- Check target parsing logic")
    if not scanner_result:
        print("- Check scanner execution and result structure")
    if not report_ok:
        print("- Check file permissions and directory creation")

    if target_ok and scanner_result and report_ok:
        print("✅ All components working - main issue might be in workflow execution")

    print(f"\nRun the actual scan with verbose mode:")
    print(f"python main.py full http://192.168.48.207 --verbose")


if __name__ == "__main__":
    main()
