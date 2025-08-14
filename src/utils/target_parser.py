"""
Target Parser Utility
Handles target parsing and format conversion
Following Single Responsibility Principle
"""

from typing import Dict
from urllib.parse import urlparse

from ..core.validator import validate_ip, validate_domain, validate_url


class TargetParser:
    """Utility class for parsing and converting target formats"""

    def parse_target(self, target: str) -> Dict[str, str]:
        """
        Parse target and extract appropriate formats for different scanners

        Args:
            target: Input target (IP, domain, or URL)

        Returns:
            Dict containing different target formats
        """
        parsed = {
            "original": target,
            "host": target,
            "domain": target,
            "url": target,
            "ip": None,
            "port": None,
            "scheme": "http",
        }

        # Handle URL format
        if target.startswith(("http://", "https://", "ftp://")):
            parsed_url = urlparse(target)
            parsed["scheme"] = parsed_url.scheme
            parsed["host"] = parsed_url.hostname or parsed_url.netloc
            parsed["port"] = parsed_url.port
            parsed["url"] = target
            parsed["domain"] = parsed["host"]

            # Clean up host if it has port
            if ":" in parsed["host"] and not validate_ip(parsed["host"]):
                parsed["host"] = parsed["host"].split(":")[0]

        # Handle IP:port format
        elif ":" in target and not target.count(":") > 1:  # Not IPv6
            host, port = target.split(":", 1)
            if port.isdigit():
                parsed["host"] = host
                parsed["port"] = int(port)
                parsed["url"] = f"http://{target}"
                if validate_ip(host):
                    parsed["ip"] = host
                    parsed["domain"] = host
                else:
                    parsed["domain"] = host

        # Handle plain IP or domain
        else:
            parsed["host"] = target
            parsed["url"] = f"http://{target}"

            if validate_ip(target):
                parsed["ip"] = target
                parsed["domain"] = target
            else:
                parsed["domain"] = target

        # Ensure we have all required formats
        if not parsed["domain"]:
            parsed["domain"] = parsed["host"]

        if not parsed["url"].startswith(("http://", "https://")):
            parsed["url"] = f"http://{parsed['host']}"
            if parsed["port"]:
                parsed["url"] = f"http://{parsed['host']}:{parsed['port']}"

        return parsed

    def extract_host(self, target: str) -> str:
        """Extract just the host/IP from any target format"""
        parsed = self.parse_target(target)
        return parsed["host"]

    def extract_domain(self, target: str) -> str:
        """Extract domain name from any target format"""
        parsed = self.parse_target(target)
        return parsed["domain"]

    def extract_url(self, target: str, default_scheme: str = "http") -> str:
        """Extract URL from any target format"""
        parsed = self.parse_target(target)

        if parsed["url"].startswith(("http://", "https://")):
            return parsed["url"]

        # Build URL with scheme
        url = f"{default_scheme}://{parsed['host']}"
        if parsed["port"]:
            url += f":{parsed['port']}"

        return url

    def is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        host = self.extract_host(target)
        return validate_ip(host)

    def is_domain_name(self, target: str) -> bool:
        """Check if target is a domain name"""
        host = self.extract_host(target)
        return validate_domain(host)

    def is_url(self, target: str) -> bool:
        """Check if target is a URL"""
        return validate_url(target)

    def normalize_target(self, target: str) -> str:
        """Normalize target to a standard format"""
        parsed = self.parse_target(target)

        # Return the most appropriate normalized format
        if parsed["port"] and parsed["port"] != 80:
            return f"{parsed['host']}:{parsed['port']}"
        else:
            return parsed["host"]

    def get_target_type(self, target: str) -> str:
        """Determine the type of target"""
        if self.is_url(target):
            return "url"
        elif self.is_ip_address(target):
            return "ip"
        elif self.is_domain_name(target):
            return "domain"
        else:
            return "unknown"

    def format_for_scanner(self, target: str, scanner_type: str) -> str:
        """
        Format target appropriately for specific scanner type

        Args:
            target: Input target
            scanner_type: Type of scanner (port, dns, web, etc.)

        Returns:
            Formatted target string
        """
        parsed = self.parse_target(target)

        formatters = {
            "port": lambda p: p["host"],
            "dns": lambda p: p["domain"],
            "web": lambda p: p["url"],
            "directory": lambda p: p["url"],
            "ssl": lambda p: f"{p['host']}:{p.get('port', 443)}",
            "default": lambda p: p["host"],
        }

        formatter = formatters.get(scanner_type, formatters["default"])
        return formatter(parsed)
