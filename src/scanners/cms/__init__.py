"""
CMS Vulnerability Scanners Module

This module contains specialized scanners for Content Management Systems:
- WordPress Scanner (WPScan integration)
- Drupal Scanner (planned)
- Joomla Scanner (planned)
"""

from .wordpress_scanner import WordPressScanner

__all__ = ["WordPressScanner"]

# Version info
__version__ = "1.0.0"
__author__ = "Auto-Pentest Framework"
