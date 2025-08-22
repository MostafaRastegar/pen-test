"""
Utility Commands - Cache and System Utilities
FILE PATH: src/cli/commands/utility_commands.py

Handles utility commands like cache management and system operations
Following SOLID principles and maintaining backward compatibility
"""

import click
import sys
from typing import Dict, Any

# Service imports - verified to exist
from ...services.utility_services import CacheService
from ...utils.logger import log_error, log_info, log_success


@click.command()
@click.option("--detailed", is_flag=True, help="Show detailed cache statistics")
@click.option("--scanner", help="Show stats for specific scanner")
def cache_stats_command(detailed, scanner):
    """Show cache statistics and information"""
    try:
        cache_service = CacheService()
        cache_service.show_stats(detailed=detailed, scanner=scanner)
    except Exception as e:
        log_error(f"Error showing cache stats: {e}")


@click.command()
@click.option("--all", is_flag=True, help="Clear all cache")
@click.option("--scanner", help="Clear cache for specific scanner")
@click.option("--force", is_flag=True, help="Force clear without confirmation")
def clear_cache_command(all, scanner, force):
    """Clear cache data"""
    try:
        cache_service = CacheService()
        cache_service.clear_cache(all=all, scanner=scanner, force=force)
    except Exception as e:
        log_error(f"Error clearing cache: {e}")


# Export commands for easy import
__all__ = ["cache_stats_command", "clear_cache_command"]
