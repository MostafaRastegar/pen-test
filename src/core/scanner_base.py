"""
Base scanner class for all scanning modules
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum
import logging
import json
from pathlib import Path


class ScanStatus(Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanSeverity(Enum):
    """Vulnerability severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanResult:
    """Standard scan result structure"""
    scanner_name: str
    target: str
    status: ScanStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            'scanner_name': self.scanner_name,
            'target': self.target,
            'status': self.status.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': str(self.end_time - self.start_time) if self.end_time else None,
            'findings': self.findings,
            'findings_count': len(self.findings),
            'raw_output': self.raw_output,
            'errors': self.errors,
            'metadata': self.metadata
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert result to JSON string"""
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    def save_to_file(self, output_path: Path) -> None:
        """Save result to file"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(self.to_json())
    
    def add_finding(self, 
                   title: str,
                   description: str,
                   severity: ScanSeverity = ScanSeverity.INFO,
                   **kwargs) -> None:
        """Add a finding to results"""
        finding = {
            'title': title,
            'description': description,
            'severity': severity.value,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        self.findings.append(finding)
    
    def get_findings_by_severity(self, severity: ScanSeverity) -> List[Dict]:
        """Get findings filtered by severity"""
        return [f for f in self.findings if f.get('severity') == severity.value]


class ScannerBase(ABC):
    """Abstract base class for all scanners"""
    
    def __init__(self, name: str, timeout: int = 300):
        """
        Initialize scanner
        
        Args:
            name: Scanner name
            timeout: Scan timeout in seconds
        """
        self.name = name
        self.timeout = timeout
        self.logger = logging.getLogger(f"scanner.{name}")
        self._result: Optional[ScanResult] = None
        self._is_running = False
        
    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """
        Validate if target is appropriate for this scanner
        
        Args:
            target: Target to validate (IP, domain, URL, etc.)
            
        Returns:
            bool: True if valid, False otherwise
        """
        pass
    
    @abstractmethod
    def _execute_scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """
        Execute the actual scan (to be implemented by subclasses)
        
        Args:
            target: Target to scan
            options: Scan options
            
        Returns:
            ScanResult: Scan results
        """
        pass
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Main scan method with error handling and logging
        
        Args:
            target: Target to scan
            options: Optional scan options
            
        Returns:
            ScanResult: Scan results
        """
        options = options or {}
        
        # Validate target
        if not self.validate_target(target):
            raise ValueError(f"Invalid target '{target}' for scanner {self.name}")
        
        # Initialize result
        self._result = ScanResult(
            scanner_name=self.name,
            target=target,
            status=ScanStatus.PENDING,
            start_time=datetime.now()
        )
        
        try:
            self._is_running = True
            self._result.status = ScanStatus.RUNNING
            self.logger.info(f"Starting {self.name} scan on {target}")
            
            # Execute scan
            self._result = self._execute_scan(target, options)
            
            # Update status if not already set
            if self._result.status == ScanStatus.RUNNING:
                self._result.status = ScanStatus.COMPLETED
                
            self._result.end_time = datetime.now()
            self.logger.info(f"Completed {self.name} scan on {target}")
            
        except Exception as e:
            self.logger.error(f"Error during {self.name} scan: {str(e)}")
            self._result.status = ScanStatus.FAILED
            self._result.errors.append(str(e))
            self._result.end_time = datetime.now()
            raise
            
        finally:
            self._is_running = False
            
        return self._result
    
    def is_running(self) -> bool:
        """Check if scan is currently running"""
        return self._is_running
    
    def get_result(self) -> Optional[ScanResult]:
        """Get current scan result"""
        return self._result
    
    @abstractmethod
    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get scanner capabilities and info
        
        Returns:
            Dict containing scanner capabilities
        """
        pass
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name='{self.name}', timeout={self.timeout})"