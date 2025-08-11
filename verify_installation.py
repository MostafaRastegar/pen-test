#!/usr/bin/env python3
"""
Quick installation verification script
"""

import sys
import subprocess
from pathlib import Path


def check_python_version():
    """Check Python version"""
    version = sys.version_info
    if version >= (3, 8):
        print(f"✅ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"❌ Python version too old: {version.major}.{version.minor}")
        return False


def check_dependencies():
    """Check Python dependencies"""
    required_packages = [
        "click",
        "rich",
        "dnspython",
        "requests",
        "pyyaml",
        "colorama",
        "validators",
    ]

    missing = []
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package} (missing)")
            missing.append(package)

    return len(missing) == 0


def check_system_tools():
    """Check system tools"""
    tools = ["nmap", "dig", "nslookup"]

    all_good = True
    for tool in tools:
        result = subprocess.run(["which", tool], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {tool}: {result.stdout.strip()}")
        else:
            print(f"❌ {tool}: not found")
            all_good = False

    return all_good


def check_project_structure():
    """Check project files"""
    required_files = [
        "main.py",
        "requirements.txt",
        "src/core/scanner_base.py",
        "src/core/executor.py",
        "src/utils/logger.py",
        "config/settings.py",
    ]

    missing = []
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} (missing)")
            missing.append(file_path)

    return len(missing) == 0


def main():
    """Main verification function"""
    print("🔍 Auto-Pentest Installation Verification")
    print("=" * 50)

    checks = [
        ("Python Version", check_python_version),
        ("Python Dependencies", check_dependencies),
        ("System Tools", check_system_tools),
        ("Project Structure", check_project_structure),
    ]

    all_passed = True
    for check_name, check_func in checks:
        print(f"\n{check_name}:")
        if not check_func():
            all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 All checks passed! Installation successful!")
        print("\nNext steps:")
        print("1. python main.py --help")
        print("2. python main.py list-tools")
        print("3. python main.py scan 127.0.0.1")
    else:
        print("❌ Some checks failed. Please fix the issues above.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
