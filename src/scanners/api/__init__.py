"""
API Security Scanner Module
Phase 2.1 Implementation - API Security Testing Suite

This module provides comprehensive API security testing capabilities including:
- REST API vulnerability assessment
- GraphQL security testing
- OWASP API Security Top 10 compliance testing
- JWT token security analysis
- Authentication and authorization testing
- Rate limiting assessment
"""

from .api_scanner import APISecurityScanner

__all__ = ["APISecurityScanner"]

# Scanner metadata for registry
SCANNER_INFO = {
    "name": "API Security Scanner",
    "category": "api",
    "description": "Comprehensive API vulnerability assessment tool",
    "version": "1.0.0",
    "author": "Auto-Pentest Framework",
    "scanner_class": APISecurityScanner,
    "requirements": ["requests", "jwt"],
    "targets": ["url", "api_endpoint"],
    "owasp_compliance": "OWASP API Security Top 10 (2023)",
}
