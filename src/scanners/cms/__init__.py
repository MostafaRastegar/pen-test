"""
CMS Scanner Module
Content Management System vulnerability scanners

This module contains specialized scanners for various CMS platforms:
- WordPress Scanner: Comprehensive WordPress security analysis
"""

from .wordpress_scanner import WordPressScanner

__all__ = [
    "WordPressScanner",
]
