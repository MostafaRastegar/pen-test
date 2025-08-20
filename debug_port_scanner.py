#!/usr/bin/env python3
"""
Debug script for port scanner to find why it returns 0 findings
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def test_target_parsing():
    """Test target parsing"""
    print("🎯 Testing Target Parsing")
    print("=" * 30)

    from src.utils.target_parser import TargetParser

    parser = TargetParser()
    target = "https://example.com"

    parsed = parser.parse_target(target)
    print(f"Original: {parsed['original']}")
    print(f"Host: {parsed['host']}")
    print(f"Domain: {parsed['domain']}")
    print(f"URL: {parsed['url']}")
    print(f"IP: {parsed['ip']}")
    print(f"Port: {parsed['port']}")

    return parsed


def test_port_scanner_direct():
    """Test port scanner directly"""
    print("\n🔍 Testing Port Scanner Directly")
    print("=" * 35)

    try:
        from src.scanners.recon.port_scanner import PortScanner
        from src.utils.logger import log_info, log_error

        # Test with clean hostname
        target = "example.com"
        print(f"Testing port scanner with: {target}")

        scanner = PortScanner(timeout=60)

        # Test with basic options
        options = {"ports": "80,443,22,21,25,53,110,143,993,995", "scan_type": "tcp"}

        print(f"Options: {options}")
        print("Starting scan...")

        result = scanner.scan(target, options)

        print(f"Scan status: {result.status}")
        print(f"Findings count: {len(result.findings)}")
        print(
            f"Raw output length: {len(result.raw_output) if result.raw_output else 0}"
        )
        print(f"Errors: {result.errors}")

        if result.raw_output:
            print("\nRaw nmap output (first 500 chars):")
            print("-" * 40)
            print(result.raw_output[:500])
            print("-" * 40)

        if result.findings:
            print(f"\nFindings ({len(result.findings)}):")
            for i, finding in enumerate(result.findings[:5]):  # Show first 5
                print(f"  {i+1}. {finding.get('title', 'No title')}")
                print(f"     Port: {finding.get('port', 'Unknown')}")
                print(f"     State: {finding.get('state', 'Unknown')}")
                print(f"     Service: {finding.get('service', 'Unknown')}")
        else:
            print("\n❌ No findings detected")

        return result

    except Exception as e:
        print(f"❌ Port scanner test failed: {e}")
        import traceback

        traceback.print_exc()
        return None


def test_nmap_command():
    """Test nmap command execution"""
    print("\n⚙️ Testing Nmap Command")
    print("=" * 25)

    try:
        from src.core.executor import CommandExecutor

        executor = CommandExecutor(timeout=60)

        # Test basic nmap command
        target = "example.com"
        nmap_cmd = f"nmap -sV -sC -p 80,443,22 {target}"

        print(f"Executing: {nmap_cmd}")

        result = executor.execute(nmap_cmd)

        print(f"Return code: {result.return_code}")
        print(f"Success: {result.success}")
        print(f"Stdout length: {len(result.stdout) if result.stdout else 0}")
        print(f"Stderr length: {len(result.stderr) if result.stderr else 0}")

        if result.stdout:
            print("\nNmap stdout (first 500 chars):")
            print("-" * 40)
            print(result.stdout[:500])
            print("-" * 40)

        if result.stderr:
            print("\nNmap stderr:")
            print("-" * 20)
            print(result.stderr)
            print("-" * 20)

        return result

    except Exception as e:
        print(f"❌ Nmap command test failed: {e}")
        import traceback

        traceback.print_exc()
        return None


def test_workflow_creation():
    """Test workflow creation with new target format"""
    print("\n🔄 Testing Workflow Creation")
    print("=" * 30)

    try:
        from src.services.scan_service import ScanService

        scan_service = ScanService()

        # Test target parsing
        target = "https://example.com"
        parsed_target = scan_service._validate_and_parse_target(target)

        print(f"Parsed target: {parsed_target}")

        # Test workflow creation
        options = {"profile": "quick", "parallel": True, "timeout": 300}

        workflow = scan_service._create_workflow(parsed_target, options)

        print(f"Workflow ID: {workflow.workflow_id}")
        print(f"Tasks count: {len(workflow.tasks)}")

        for task in workflow.tasks:
            print(f"  Task: {task.scanner_name}")
            print(f"  Target: {task.target}")
            print(f"  Options: {task.options}")

        return workflow

    except Exception as e:
        print(f"❌ Workflow creation test failed: {e}")
        import traceback

        traceback.print_exc()
        return None


def main():
    """Run all debug tests"""
    print("🐛 Port Scanner Debug Session")
    print("=" * 40)

    # Test 1: Target parsing
    parsed_target = test_target_parsing()

    # Test 2: Direct port scanner
    scan_result = test_port_scanner_direct()

    # Test 3: Raw nmap command
    nmap_result = test_nmap_command()

    # Test 4: Workflow creation
    workflow = test_workflow_creation()

    print("\n🔍 Debug Summary")
    print("=" * 20)
    print(f"Target parsing: {'✅' if parsed_target else '❌'}")
    print(f"Port scanner: {'✅' if scan_result else '❌'}")
    print(f"Nmap command: {'✅' if nmap_result and nmap_result.success else '❌'}")
    print(f"Workflow creation: {'✅' if workflow else '❌'}")

    if scan_result:
        print(f"\nPort scan findings: {len(scan_result.findings)}")
        if scan_result.findings == 0:
            print("⚠️ Port scanner returned 0 findings")
            print("   This could be due to:")
            print("   1. Target has no open ports")
            print("   2. Firewall blocking scan")
            print("   3. Nmap output parsing issue")
            print("   4. Network connectivity problem")


if __name__ == "__main__":
    main()
