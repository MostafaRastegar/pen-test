"""
Input validation utilities for Auto-Pentest Tool
"""

import re
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Optional, Union, List, Tuple
from pathlib import Path
import logging


logger = logging.getLogger('validator')


class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass


def validate_ip(ip_string: str, allow_private: bool = True) -> bool:
    """
    Validate IP address (IPv4 or IPv6)
    
    Args:
        ip_string: IP address string to validate
        allow_private: Whether to allow private IP addresses
        
    Returns:
        bool: True if valid IP, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        
        if not allow_private and ip_obj.is_private:
            logger.warning(f"Private IP address not allowed: {ip_string}")
            return False
            
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_ip_range(ip_range: str) -> bool:
    """
    Validate IP range in CIDR notation
    
    Args:
        ip_range: IP range string (e.g., "192.168.1.0/24")
        
    Returns:
        bool: True if valid range, False otherwise
    """
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_domain(domain: str, check_dns: bool = False) -> bool:
    """
    Validate domain name
    
    Args:
        domain: Domain name to validate
        check_dns: Whether to perform DNS resolution check
        
    Returns:
        bool: True if valid domain, False otherwise
    """
    # Basic regex for domain validation
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'  # Subdomain(s)
        r'*[a-zA-Z0-9]'  # Domain name
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'  # TLD
    )
    
    if not domain_pattern.match(domain):
        return False
    
    # Optional DNS resolution check
    if check_dns:
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            logger.warning(f"Domain DNS resolution failed: {domain}")
            return False
    
    return True


def validate_url(url: str, allowed_schemes: Optional[List[str]] = None) -> bool:
    """
    Validate URL
    
    Args:
        url: URL to validate
        allowed_schemes: List of allowed URL schemes (default: ['http', 'https'])
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    allowed_schemes = allowed_schemes or ['http', 'https']
    
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in allowed_schemes:
            logger.warning(f"URL scheme not allowed: {parsed.scheme}")
            return False
        
        # Check netloc (domain/IP)
        if not parsed.netloc:
            return False
        
        # Extract host and port
        if ':' in parsed.netloc:
            host, port = parsed.netloc.rsplit(':', 1)
            try:
                port_num = int(port)
                if not (1 <= port_num <= 65535):
                    return False
            except ValueError:
                return False
        else:
            host = parsed.netloc
        
        # Validate host (can be IP or domain)
        if not (validate_ip(host) or validate_domain(host)):
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"URL validation error: {e}")
        return False


def validate_port(port: Union[int, str]) -> bool:
    """
    Validate port number
    
    Args:
        port: Port number to validate
        
    Returns:
        bool: True if valid port, False otherwise
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def validate_port_range(port_range: str) -> Tuple[bool, Optional[Tuple[int, int]]]:
    """
    Validate port range (e.g., "80-443")
    
    Args:
        port_range: Port range string
        
    Returns:
        Tuple[bool, Optional[Tuple[int, int]]]: (is_valid, (start_port, end_port))
    """
    try:
        if '-' in port_range:
            start, end = port_range.split('-', 1)
            start_port = int(start)
            end_port = int(end)
            
            if (1 <= start_port <= 65535 and 
                1 <= end_port <= 65535 and 
                start_port <= end_port):
                return True, (start_port, end_port)
        else:
            port = int(port_range)
            if 1 <= port <= 65535:
                return True, (port, port)
                
    except (ValueError, TypeError):
        pass
    
    return False, None


def validate_email(email: str) -> bool:
    """
    Validate email address
    
    Args:
        email: Email address to validate
        
    Returns:
        bool: True if valid email, False otherwise
    """
    email_pattern = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    return bool(email_pattern.match(email))


def validate_file_path(file_path: Union[str, Path], 
                      must_exist: bool = False,
                      must_be_file: bool = True) -> bool:
    """
    Validate file path
    
    Args:
        file_path: File path to validate
        must_exist: Whether file must exist
        must_be_file: Whether path must be a file (not directory)
        
    Returns:
        bool: True if valid path, False otherwise
    """
    try:
        path = Path(file_path)
        
        if must_exist and not path.exists():
            logger.warning(f"Path does not exist: {file_path}")
            return False
        
        if must_exist and must_be_file and not path.is_file():
            logger.warning(f"Path is not a file: {file_path}")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Path validation error: {e}")
        return False


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize filename for safe filesystem operations
    
    Args:
        filename: Filename to sanitize
        max_length: Maximum allowed length
        
    Returns:
        str: Sanitized filename
    """
    # Remove/replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove control characters
    filename = ''.join(char for char in filename if ord(char) >= 32)
    
    # Limit length
    if len(filename) > max_length:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        if ext:
            max_name_length = max_length - len(ext) - 1
            filename = f"{name[:max_name_length]}.{ext}"
        else:
            filename = filename[:max_length]
    
    # Avoid reserved names (Windows)
    reserved_names = ['CON', 'PRN', 'AUX', 'NUL'] + \
                    [f'COM{i}' for i in range(1, 10)] + \
                    [f'LPT{i}' for i in range(1, 10)]
    
    name_without_ext = filename.split('.')[0].upper()
    if name_without_ext in reserved_names:
        filename = f"_{filename}"
    
    return filename


class InputValidator:
    """
    Main input validator class
    """
    
    def __init__(self):
        """Initialize validator"""
        self.logger = logging.getLogger('InputValidator')
        
    def validate_target(self, target: str) -> Tuple[bool, str, str]:
        """
        Validate and identify target type
        
        Args:
            target: Target string (IP, domain, URL, etc.)
            
        Returns:
            Tuple[bool, str, str]: (is_valid, target_type, sanitized_target)
        """
        target = target.strip()
        
        # Check URL
        if target.startswith(('http://', 'https://')):
            if validate_url(target):
                return True, 'url', target
            else:
                return False, 'invalid', target
        
        # Check IP range
        if '/' in target and validate_ip_range(target):
            return True, 'ip_range', target
        
        # Check IP
        if validate_ip(target):
            return True, 'ip', target
        
        # Check domain
        if validate_domain(target):
            return True, 'domain', target
        
        return False, 'invalid', target
    
    def validate_scan_options(self, options: dict) -> Tuple[bool, dict, List[str]]:
        """
        Validate scan options
        
        Args:
            options: Dictionary of scan options
            
        Returns:
            Tuple[bool, dict, List[str]]: (is_valid, sanitized_options, errors)
        """
        errors = []
        sanitized = options.copy()
        
        # Validate port specifications
        if 'ports' in options:
            ports = options['ports']
            if isinstance(ports, str):
                is_valid, port_range = validate_port_range(ports)
                if not is_valid:
                    errors.append(f"Invalid port range: {ports}")
                else:
                    sanitized['ports'] = port_range
            elif isinstance(ports, (list, tuple)):
                valid_ports = []
                for port in ports:
                    if validate_port(port):
                        valid_ports.append(int(port))
                    else:
                        errors.append(f"Invalid port: {port}")
                sanitized['ports'] = valid_ports
        
        # Validate timeout
        if 'timeout' in options:
            try:
                timeout = int(options['timeout'])
                if timeout <= 0:
                    errors.append("Timeout must be positive")
                elif timeout > 3600:
                    errors.append("Timeout too large (max 3600s)")
                else:
                    sanitized['timeout'] = timeout
            except (ValueError, TypeError):
                errors.append(f"Invalid timeout: {options['timeout']}")
        
        # Validate threads
        if 'threads' in options:
            try:
                threads = int(options['threads'])
                if threads <= 0:
                    errors.append("Threads must be positive")
                elif threads > 100:
                    errors.append("Too many threads (max 100)")
                else:
                    sanitized['threads'] = threads
            except (ValueError, TypeError):
                errors.append(f"Invalid threads: {options['threads']}")
        
        is_valid = len(errors) == 0
        return is_valid, sanitized, errors
    
    def validate_wordlist(self, wordlist_path: Union[str, Path]) -> bool:
        """
        Validate wordlist file
        
        Args:
            wordlist_path: Path to wordlist file
            
        Returns:
            bool: True if valid wordlist, False otherwise
        """
        if not validate_file_path(wordlist_path, must_exist=True, must_be_file=True):
            return False
        
        try:
            path = Path(wordlist_path)
            
            # Check file size (max 100MB)
            if path.stat().st_size > 100 * 1024 * 1024:
                self.logger.warning(f"Wordlist too large: {wordlist_path}")
                return False
            
            # Check if it's a text file
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                # Read first line to verify it's text
                f.readline()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Wordlist validation error: {e}")
            return False