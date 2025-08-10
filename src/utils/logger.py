"""
Logging configuration and utilities for Auto-Pentest Tool
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
import json


# Custom theme for rich console
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "debug": "dim white"
})

console = Console(theme=custom_theme)


class JsonFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_obj = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        if record.exc_info:
            log_obj['exception'] = self.formatException(record.exc_info)
        
        if hasattr(record, 'extra_data'):
            log_obj['extra'] = record.extra_data
            
        return json.dumps(log_obj, default=str)


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[41m',  # Red background
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors"""
        log_color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{log_color}{record.levelname}{self.RESET}"
        record.msg = f"{log_color}{record.msg}{self.RESET}"
        return super().format(record)


class LoggerSetup:
    """Logger setup and configuration"""
    
    @staticmethod
    def setup_logger(
        name: str = 'auto-pentest',
        level: str = 'INFO',
        log_dir: Optional[Path] = None,
        console_output: bool = True,
        file_output: bool = True,
        json_format: bool = False,
        use_rich: bool = True
    ) -> logging.Logger:
        """
        Setup and configure logger
        
        Args:
            name: Logger name
            level: Logging level
            log_dir: Directory for log files
            console_output: Enable console output
            file_output: Enable file output
            json_format: Use JSON format for file logs
            use_rich: Use rich handler for console output
            
        Returns:
            logging.Logger: Configured logger
        """
        # Create logger
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, level.upper()))
        logger.handlers = []  # Clear existing handlers
        
        # Console handler
        if console_output:
            if use_rich:
                console_handler = RichHandler(
                    console=console,
                    show_time=True,
                    show_path=False,
                    markup=True,
                    rich_tracebacks=True,
                    tracebacks_show_locals=True
                )
                console_handler.setFormatter(
                    logging.Formatter('%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
                )
            else:
                console_handler = logging.StreamHandler(sys.stdout)
                console_handler.setFormatter(
                    ColoredFormatter(
                        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S'
                    )
                )
            
            console_handler.setLevel(getattr(logging, level.upper()))
            logger.addHandler(console_handler)
        
        # File handler
        if file_output and log_dir:
            log_dir = Path(log_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Main log file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_file = log_dir / f'{name}_{timestamp}.log'
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5
            )
            
            if json_format:
                file_handler.setFormatter(JsonFormatter())
            else:
                file_handler.setFormatter(
                    logging.Formatter(
                        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S'
                    )
                )
            
            file_handler.setLevel(logging.DEBUG)  # Capture all levels in file
            logger.addHandler(file_handler)
            
            # Error log file
            error_file = log_dir / f'{name}_errors_{timestamp}.log'
            error_handler = logging.FileHandler(error_file)
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s\n%(exc_info)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
            )
            logger.addHandler(error_handler)
        
        return logger
    
    @staticmethod
    def get_child_logger(parent_logger: logging.Logger, child_name: str) -> logging.Logger:
        """
        Get a child logger
        
        Args:
            parent_logger: Parent logger
            child_name: Child logger name
            
        Returns:
            logging.Logger: Child logger
        """
        return parent_logger.getChild(child_name)


class LogContext:
    """Context manager for temporary logging changes"""
    
    def __init__(self, logger: logging.Logger, level: Optional[str] = None):
        """
        Initialize log context
        
        Args:
            logger: Logger to modify
            level: Temporary log level
        """
        self.logger = logger
        self.new_level = level
        self.old_level = None
        
    def __enter__(self):
        """Enter context"""
        if self.new_level:
            self.old_level = self.logger.level
            self.logger.setLevel(getattr(logging, self.new_level.upper()))
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context"""
        if self.old_level is not None:
            self.logger.setLevel(self.old_level)


def log_banner(text: str, style: str = "bold cyan"):
    """
    Print a banner in the console
    
    Args:
        text: Banner text
        style: Rich style string
    """
    console.rule(f"[{style}]{text}[/{style}]")


def log_success(message: str):
    """Log success message"""
    console.print(f"✅ {message}", style="success")


def log_error(message: str):
    """Log error message"""
    console.print(f"❌ {message}", style="error")


def log_warning(message: str):
    """Log warning message"""
    console.print(f"⚠️ {message}", style="warning")


def log_info(message: str):
    """Log info message"""
    console.print(f"ℹ️ {message}", style="info")


def log_debug(message: str):
    """Log debug message"""
    console.print(f"🔍 {message}", style="debug")


def create_progress_bar(description: str = "Processing..."):
    """
    Create a progress bar
    
    Args:
        description: Progress bar description
        
    Returns:
        Progress: Rich progress bar
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    )


# Create default logger
default_logger = LoggerSetup.setup_logger()