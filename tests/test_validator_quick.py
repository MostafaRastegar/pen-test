#!/usr/bin/env python3
"""
Quick validator test to debug IP validation issues
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.core.validator import validate_ip, validate_domain


def test_ip_validation():
    """Test IP validation with detailed output"""
    print("🔍 Testing IP Validation")
    print("=" * 30)

    test_cases = [
        ("192.168.1.1", True, "Valid private IP"),
        ("8.8.8.8", True, "Valid public IP"),
        ("127.0.0.1", True, "Valid loopback IP"),
        ("::1", True, "Valid IPv6 loopback"),
        ("256.256.256.256", False, "Invalid IP - octets too high"),
        ("192.168.1.256", False, "Invalid IP - last octet too high"),
        ("192.168.1", False, "Invalid IP - missing octet"),
        ("192.168.1.1.1", False, "Invalid IP - too many octets"),
        ("not.an.ip", False, "Invalid IP - not numeric"),
        ("", False, "Invalid IP - empty string"),
        ("192.168.1.a", False, "Invalid IP - letter in octet"),
        ("192.168.-1.1", False, "Invalid IP - negative octet"),
    ]

    passed = 0
    total = len(test_cases)

    for ip, expected, description in test_cases:
        try:
            result = validate_ip(ip)
            status = "✅" if result == expected else "❌"
            print(
                f"{status} {ip:20} | Expected: {expected:5} | Got: {result:5} | {description}"
            )

            if result == expected:
                passed += 1
            else:
                print(f"   ⚠️  MISMATCH: Expected {expected}, got {result}")

        except Exception as e:
            print(f"💥 {ip:20} | ERROR: {e}")

    print(
        f"\n📊 IP Validation: {passed}/{total} tests passed ({passed/total*100:.1f}%)"
    )
    return passed == total


def test_domain_validation():
    """Test domain validation with detailed output"""
    print("\n🔍 Testing Domain Validation")
    print("=" * 30)

    test_cases = [
        ("example.com", True, "Valid domain"),
        ("sub.example.com", True, "Valid subdomain"),
        ("test-domain.org", True, "Valid domain with hyphen"),
        ("a.co", True, "Short valid domain"),
        ("192.168.1.1", False, "IP address, not domain"),
        ("", False, "Empty string"),
        ("invalid_domain", False, "No TLD"),
        (".example.com", False, "Starts with dot"),
        ("example.com.", False, "Ends with dot"),
        ("-example.com", False, "Starts with hyphen"),
        ("example-.com", False, "Ends with hyphen"),
        ("example..com", False, "Double dot"),
        ("example.c", False, "TLD too short"),
        ("example.123", False, "Numeric TLD"),
    ]

    passed = 0
    total = len(test_cases)

    for domain, expected, description in test_cases:
        try:
            result = validate_domain(domain)
            status = "✅" if result == expected else "❌"
            print(
                f"{status} {domain:20} | Expected: {expected:5} | Got: {result:5} | {description}"
            )

            if result == expected:
                passed += 1
            else:
                print(f"   ⚠️  MISMATCH: Expected {expected}, got {result}")

        except Exception as e:
            print(f"💥 {domain:20} | ERROR: {e}")

    print(
        f"\n📊 Domain Validation: {passed}/{total} tests passed ({passed/total*100:.1f}%)"
    )
    return passed == total


def test_edge_cases():
    """Test edge cases that might cause issues"""
    print("\n🔍 Testing Edge Cases")
    print("=" * 30)

    edge_cases = [
        # IP edge cases
        ("0.0.0.0", "IP", True, "Zero IP"),
        ("255.255.255.255", "IP", True, "Broadcast IP"),
        ("   192.168.1.1   ", "IP", True, "IP with whitespace"),
        # Domain edge cases
        ("EXAMPLE.COM", "Domain", True, "Uppercase domain"),
        ("example-with-many-hyphens.com", "Domain", True, "Domain with many hyphens"),
        ("a" * 63 + ".com", "Domain", True, "Max length label"),
        ("a" * 64 + ".com", "Domain", False, "Label too long"),
    ]

    passed = 0
    total = len(edge_cases)

    for test_input, test_type, expected, description in edge_cases:
        try:
            if test_type == "IP":
                result = validate_ip(test_input)
            else:
                result = validate_domain(test_input)

            status = "✅" if result == expected else "❌"
            print(
                f"{status} {test_input[:20]:20} | Expected: {expected:5} | Got: {result:5} | {description}"
            )

            if result == expected:
                passed += 1

        except Exception as e:
            print(f"💥 {test_input[:20]:20} | ERROR: {e}")

    print(f"\n📊 Edge Cases: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    return passed == total


def main():
    """Main test function"""
    print("🧪 Quick Validator Test")
    print("=" * 50)

    try:
        ip_ok = test_ip_validation()
        domain_ok = test_domain_validation()
        edge_ok = test_edge_cases()

        print("\n" + "=" * 50)
        print("📋 Summary:")
        print(f"   IP Validation: {'✅ PASS' if ip_ok else '❌ FAIL'}")
        print(f"   Domain Validation: {'✅ PASS' if domain_ok else '❌ FAIL'}")
        print(f"   Edge Cases: {'✅ PASS' if edge_ok else '❌ FAIL'}")

        if ip_ok and domain_ok and edge_ok:
            print("\n🎉 All validation tests passed!")
            return 0
        else:
            print("\n❌ Some validation tests failed")
            print("   Check the validator implementation in src/core/validator.py")
            return 1

    except Exception as e:
        print(f"\n💥 Test failed with error: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
