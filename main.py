#!/usr/bin/env python3
"""
Auto-Pentest Tool - Main Entry Point
Refactored for better maintainability following SOLID principles
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.cli import create_cli_app
from src.utils.logger import LoggerSetup, log_error


def main():
    """Main entry point with error handling"""
    try:
        # Setup basic logging
        logger = LoggerSetup.setup_logger(
            name="auto-pentest", level="INFO", use_rich=True
        )

        # Create and run CLI application
        cli_app = create_cli_app()
        cli_app()

    except KeyboardInterrupt:
        log_error("🛑 Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"💥 Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
