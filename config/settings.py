"""
Configuration settings for Auto-Pentest tool
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', BASE_DIR / 'output'))
LOG_DIR = OUTPUT_DIR / 'logs'
REPORT_DIR = OUTPUT_DIR / 'reports'
RAW_OUTPUT_DIR = OUTPUT_DIR / 'raw'

# Create directories if they don't exist
for directory in [OUTPUT_DIR, LOG_DIR, REPORT_DIR, RAW_OUTPUT_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# General settings
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# Scan settings
MAX_THREADS = int(os.getenv('MAX_THREADS', 10))
TIMEOUT = int(os.getenv('TIMEOUT', 30))
RATE_LIMIT = int(os.getenv('RATE_LIMIT', 100))

# Tool configurations
TOOL_PATHS = {
    'nmap': os.getenv('NMAP_PATH', 'nmap'),
    'sqlmap': os.getenv('SQLMAP_PATH', 'sqlmap'),
    'nikto': os.getenv('NIKTO_PATH', 'nikto'),
    'dirb': os.getenv('DIRB_PATH', 'dirb'),
}

# Scan profiles
SCAN_PROFILES = {
    'quick': {
        'name': 'Quick Scan',
        'modules': ['port_scan', 'dns_enum'],
        'aggressive': False
    },
    'full': {
        'name': 'Full Scan',
        'modules': ['port_scan', 'dns_enum', 'subdomain', 'web_vuln', 'ssl_scan'],
        'aggressive': True
    },
    'web': {
        'name': 'Web Application Scan',
        'modules': ['web_vuln', 'ssl_scan', 'directory_fuzzing'],
        'aggressive': False
    }
}