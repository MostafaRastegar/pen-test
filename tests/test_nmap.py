#!/usr/bin/env python3
"""
Test nmap command execution directly
"""

import subprocess
import sys
from pathlib import Path


def test_nmap_basic():
    """Test basic nmap functionality"""
    print("=== TESTING NMAP BASIC ===")

    # Test if nmap is available
    try:
        result = subprocess.run(
            ["nmap", "--version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print("✓ Nmap is available")
            print(f"Version: {result.stdout.split()[2]}")
        else:
            print("✗ Nmap version check failed")
            return False
    except Exception as e:
        print(f"✗ Nmap not found: {e}")
        return False

    return True


def test_nmap_scan():
    """Test actual nmap scan"""
    print("\n=== TESTING NMAP SCAN ===")

    target = "192.168.48.207"

    # Simple ping scan first
    try:
        print(f"Testing ping scan: {target}")
        cmd = ["nmap", "-sn", target]
        print(f"Command: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(f"Return code: {result.returncode}")
        print(f"Stdout: {result.stdout[:200]}...")
        print(f"Stderr: {result.stderr[:200]}...")

        if result.returncode == 0:
            print("✓ Ping scan successful")
        else:
            print("✗ Ping scan failed")

    except Exception as e:
        print(f"✗ Ping scan exception: {e}")

    # Port scan
    try:
        print(f"\nTesting port scan: {target}")
        cmd = ["nmap", "-p", "80,443", target]
        print(f"Command: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        print(f"Return code: {result.returncode}")
        print(f"Stdout: {result.stdout[:500]}...")
        print(f"Stderr: {result.stderr[:200]}...")

        if result.returncode == 0:
            print("✓ Port scan successful")
        else:
            print("✗ Port scan failed")

    except Exception as e:
        print(f"✗ Port scan exception: {e}")


def test_permissions():
    """Test nmap permissions"""
    print("\n=== TESTING PERMISSIONS ===")

    import os

    print(f"Running as UID: {os.getuid()}")
    print(f"Running as GID: {os.getgid()}")

    # Test if we can run nmap with privileges
    try:
        result = subprocess.run(
            ["nmap", "-O", "--osscan-guess", "127.0.0.1"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        print(f"OS detection return code: {result.returncode}")
        if "requires root privileges" in result.stderr:
            print("⚠️ OS detection requires root privileges")
        elif result.returncode == 0:
            print("✓ OS detection works")
        else:
            print(f"✗ OS detection failed: {result.stderr[:200]}")
    except Exception as e:
        print(f"OS detection test error: {e}")


def test_target_reachability():
    """Test if target is reachable"""
    print("\n=== TESTING TARGET REACHABILITY ===")

    target = "192.168.48.207"

    # Test ping
    try:
        result = subprocess.run(
            ["ping", "-c", "3", target], capture_output=True, text=True, timeout=15
        )
        print(f"Ping return code: {result.returncode}")
        if result.returncode == 0:
            print(f"✓ Target {target} is reachable")
        else:
            print(f"✗ Target {target} is not reachable")
            print(f"Ping stderr: {result.stderr}")
    except Exception as e:
        print(f"Ping test error: {e}")


if __name__ == "__main__":
    print("Nmap Debugging Tool")
    print("=" * 40)

    test_nmap_basic()
    test_permissions()
    test_target_reachability()
    test_nmap_scan()

    print("\n=== RECOMMENDATIONS ===")
    print("1. Make sure nmap is installed: sudo apt install nmap")
    print("2. For OS detection, run as root: sudo python main.py ...")
    print("3. Check network connectivity to target")
    print("4. Try simpler nmap commands first")
