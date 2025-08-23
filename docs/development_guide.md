# 🎯 Service Development Strategic Workflow
## Auto-Pentest Framework - خط قرمز توسعه پروژه

### 📋 **نسخه**: v1.1 | **تاریخ**: 2024 | **وضعیت**: به‌روزرسانی شده - Post CLI Refactoring
### 📁 **مسیر فایل**: docs/development_guide.md

---

## 🗺️ **فرآیند توسعه استراتژیک - اجباری**

### **مرحله 0: مطالعه مستندات مرجع (الزامی)**
```bash
📋 ترتیب مطالعه اجباری:
1️⃣ features_roadmap.md          # نقشه راه و برنامه‌ریزی پروژه
2️⃣ docs/tools-list.md           # ابزارها و پکیج‌های مجاز
3️⃣ docs/development_guide.md    # این سند راهبردی
4️⃣ src/cli/README.md           # ✨ جدید: راهنمای CLI Architecture
```

#### **Step 0.1: مطالعه نقشه راه پروژه**
```python
# فایل مرجع: features_roadmap.md
"""
قبل از شروع هر توسعه‌ای، باید:
- وضعیت فعلی فیچرها بررسی شود
- اولویت‌بندی فیچرها مشخص شود  
- phase های مختلف توسعه شناسایی شود
- dependencies بین فیچرها مشخص شود
- تصمیم نهایی برای فیچر مورد نظر گرفته شود
"""

# مثال فرآیند تصمیم‌گیری:
FEATURE_ANALYSIS = {
    "requested_feature": "vulnerability_assessment_service",
    "roadmap_status": "Phase 3: Enterprise Framework",
    "priority": "High", 
    "dependencies": ["report_service", "scanner_services"],
    "approval_status": "Ready for implementation"
}
```

#### **Step 0.2: انتخاب ابزارها و پکیج‌ها**
```python
# فایل مرجع: docs/tools-list.md
"""
همه ابزارها و کتابخانه‌هایی که در پروژه مجاز هستند:
- Python packages مجاز
- External tools مورد استفاده
- Security tools مجاز
- Development dependencies
- Testing frameworks
- Documentation tools
"""

# مثال انتخاب ابزار:
ALLOWED_TOOLS = {
    "vulnerability_assessment": {
        "python_packages": ["cvss", "vulnerability-db"],
        "external_tools": ["nuclei", "nmap"],
        "testing_tools": ["pytest", "unittest"],
        "documentation": ["sphinx", "markdown"]
    }
}

# 🚨 فقط ابزارهای موجود در tools-list.md مجاز هستند
# استفاده از ابزار غیرمجاز = Code rejection
```

#### **Step 0.3: تأیید نهایی توسعه**
```bash
✅ Checklist قبل از شروع:
□ Feature در roadmap تأیید شده
□ اولویت مشخص است
□ Dependencies بررسی شده
□ ابزارهای مورد نیاز در tools-list موجود است
□ منابع توسعه آماده است
□ Timeline مشخص شده است

❌ بدون تکمیل این checklist شروع توسعه ممنوع است
```

---

## 🚨 **خط قرمزهای پروژه - غیرقابل تفاوت**

### **1. Backward Compatibility (سختگیرانه)**
- هیچ تغییری نباید API موجود را بشکند
- هیچ Service موجود نباید رفتار غیرمنتظره‌ای داشته باشد
- تمام CLI Commands موجود باید بدون تغییر کار کنند
- فایل‌های Configuration موجود باید همچنان معتبر باشند

### **2. Code Quality & Architecture (کیفیت کد و معماری)**
- **Method/Class Verification**: هر متود یا کلاسی که استفاده می‌شود باید از وجودش در پروژه مطمئن باشید
- **No Weird Additions**: اضافه‌کاری‌های عجیب و غیرضروری ممنوع است
- **Clean Code**: کد باید خوانا، ساده و قابل نگهداری باشد
- **SOLID Principles**: اصول Single Responsibility, Open/Closed, Liskov Substitution, Interface Segregation, Dependency Inversion
- **DRY Principle**: Don't Repeat Yourself - عدم تکرار کد
- **File Path Documentation**: آدرس کامل همه فایل‌های ایجاد/ویرایش شده باید ارائه شود

### **3. Development Workflow (گردش کار توسعه)**
- **File Creation Approval**: برای ایجاد فایل‌های طولانی باید اجازه گرفته شود
- **Code Review Process**: هر فایل قبل از ادامه کار باید بررسی شود
- **Progressive Development**: توسعه مرحله‌ای و تدریجی
- **Documentation First**: مستندسازی همزمان با توسعه

### **4. CLI Service Requirements (الزامات سرویس‌های CLI)**
- **Reporting System Mandatory**: همه سرویس‌های CLI باید سیستم گزارش‌دهی داشته باشند
- **Multiple Report Formats**: حداقل JSON و TXT، ترجیحاً HTML و PDF
- **Report Integration**: ادغام با ReportService موجود
- **Consistent Output Format**: فرمت خروجی یکسان برای همه سرویس‌ها

### **5. Simplicity First (سادگی در اولویت)**
- هر Service باید یک مسئولیت اصلی داشته باشد
- Interface ها باید ساده و قابل فهم باشند
- Dependencies باید حداقل باشند
- پیچیدگی غیرضروری ممنوع است

### **6. Testing Mandatory (تست اجباری)**
- هر Service جدید باید تست کامل داشته باشد
- تغییر هر Service موجود باید تست Regression داشته باشد
- Integration Test برای تمام Services اجباری است
- Performance Test برای Services کلیدی الزامی است

---

## 🏗️ **ساختار فعلی پروژه - الگوی مرجع (Post CLI Refactoring)**

### **Architecture Pattern (Updated)**
```
CLI (main.py) 
    ↓
Commands (src/cli/commands/) ← ✨ ساختار جدید
    ↓
Services (src/services/)
    ↓
Orchestrator (src/orchestrator/)
    ↓
Scanners (src/scanners/)
    ↓
Core Framework (src/core/)
```

### **🆕 CLI Commands Structure**
```python
src/cli/
├── __init__.py                    # ثابت (تغییرات حداقلی)
├── commands/                      # ✨ دایرکتوری جدید
│   ├── __init__.py               # لایه سازگاری معکوس
│   ├── core_commands.py          # فرمان‌های اصلی (scan, quick, full)
│   ├── info_commands.py          # اطلاعات (info, list-tools, version)
│   ├── network_commands.py       # شبکه (port, dns, network, subdomians)
│   ├── web_commands.py           # وب (web, directory, ssl, api)
│   ├── cms_commands.py           # CMS (wordpress)
│   ├── security_commands.py      # امنیت (waf)
│   └── utility_commands.py       # ابزار (cache-stats, clear-cache)
├── options.py                     # ✨ بهبود یافته با DRY
└── commands.py                    # ✨ لایه سازگاری معکوس
```

### **Service Layer Structure (ثابت)**
```python
src/services/
├── __init__.py              # Service exports
├── scan_service.py          # اصلی: مدیریت workflow ها
├── scanner_service.py       # اصلی: اجرای scanner های مجزا
├── report_service.py        # اصلی: تولید گزارشات
├── subdomain_service.py
├── info_service.py          # اصلی: اطلاعات سیستم
└── utility_services.py      # کمکی: Version, Tool, Cache
```

### **Service Categories**
1. **Core Services**: مدیریت workflow و scanner ها
2. **Business Services**: منطق کسب‌وکار اصلی
3. **Utility Services**: عملکردهای کمکی و پشتیبانی
4. **Integration Services**: ادغام با ابزارهای خارجی

---

## 🆕 **روال اضافه کردن Service جدید**

### **Phase 1: Analysis & Design (تحلیل و طراحی)**

#### **Step 1.1: Requirements Analysis with Roadmap Integration**
```bash
# 1. مراجعه به نقشه راه پروژه
FILE_REFERENCE: features_roadmap.md
"""
بررسی‌های اجباری:
- آیا این فیچر در roadmap وجود دارد؟
- در کدام Phase قرار دارد؟
- وضعیت فعلی چیست؟ (Planned/In Progress/Completed)
- Dependencies آن چیست؟
- اولویت آن چقدر است؟
"""

# 2. تطبیق با phase فعلی پروژه
CURRENT_PHASE_ANALYSIS = {
    "current_phase": "Phase 3: Enterprise Framework",
    "feature_phase": "Phase 3: Enterprise Framework",
    "alignment": "✅ مطابق",
    "can_proceed": True
}

# ❌ اگر feature در phase آینده است، توسعه متوقف می‌شود
```

#### **Step 1.2: Tools Analysis with Compliance**
```bash
# 1. بررسی ابزارهای مورد نیاز
FILE_REFERENCE: docs/tools-list.md

TOOL_COMPLIANCE_CHECK = {
    "required_tools": ["specific_tool", "another_tool"],
    "python_packages": ["package1", "package2"],
    "external_dependencies": ["external_tool"],
    "all_approved": True,  # ✅ همه در tools-list.md موجود
    "approval_status": "Approved"
}

# ❌ اگر ابزار غیرمجاز نیاز باشد، توسعه متوقف می‌شود
```

#### **Step 1.3: Interface Design with Verification**
```python
# ✅ MANDATORY: Verify all imports before design

# مثال طراحی Interface:
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

# VERIFY: Classes exist before using
from ..core.validator import InputValidator  # ✅ src/core/validator.py
from ..utils.logger import log_info, log_error  # ✅ src/utils/logger.py
from ..services.report_service import ReportService  # ✅ src/services/report_service.py

class ServiceNameInterface(ABC):
    """Interface following Interface Segregation Principle"""
    
    @abstractmethod
    def primary_operation(self, input_data: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Primary service operation"""
        pass
    
    @abstractmethod
    def get_service_info(self) -> Dict[str, Any]:
        """Get service information"""
        pass
```

### **Phase 2: Implementation (پیاده‌سازی)**

#### **Step 2.1: Service Implementation with Standards**
```python
"""
Service Name Implementation
FILE PATH: src/services/service_name.py

Following SOLID, Clean Code, and DRY principles
With mandatory reporting integration for CLI services
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from abc import ABC, abstractmethod

# VERIFY ALL IMPORTS EXIST
from ..core.validator import InputValidator  # ✅ src/core/validator.py
from ..utils.logger import log_info, log_error, log_success  # ✅ src/utils/logger.py
from ..services.report_service import ReportService  # ✅ src/services/report_service.py

# Type definitions for clarity (Clean Code)
ServiceResult = Dict[str, Any]
ServiceOptions = Optional[Dict[str, Any]]


class ServiceName(ServiceNameInterface):
    """
    Service implementation following all principles
    
    SOLID: Single responsibility for specific functionality
    Clean Code: Clear names and simple structure
    DRY: Reuses existing components
    """
    
    def __init__(self, config: ServiceOptions = None):
        """
        Initialize with dependency injection (Dependency Inversion Principle)
        
        Args:
            config: Optional service configuration
        """
        self.config = config or {}
        self.validator = InputValidator()  # ✅ VERIFIED: exists
        self.report_service = ReportService()  # ✅ VERIFIED: exists
        self.logger = self._setup_logger()
        
        # Validate configuration
        self._validate_configuration()
    
    def primary_operation(self, input_data: str, options: ServiceOptions = None) -> ServiceResult:
        """
        Primary service operation with full error handling
        
        Args:
            input_data: Input data to process
            options: Operation options including report preferences
            
        Returns:
            ServiceResult: Operation result with metadata
            
        Raises:
            ValueError: If input validation fails
            RuntimeError: If operation fails
        """
        start_time = datetime.now()
        
        try:
            # Input validation (Single Responsibility)
            if not self.validator.validate_input(input_data):
                raise ValueError(f"Invalid input: {input_data}")
            
            log_info(f"Starting operation: {self.__class__.__name__}")
            
            # Main operation logic
            result = self._execute_operation(input_data, options or {})
            
            # Generate reports if requested (MANDATORY for CLI services)
            report_result = self._handle_report_generation(result, options or {})
            result["report_generated"] = report_result
            
            # Add metadata
            result["metadata"] = self._generate_metadata()
            result["execution_time"] = (datetime.now() - start_time).total_seconds()
            
            log_success(f"Operation completed: {self.__class__.__name__}")
            return result
            
        except ValueError as e:
            log_error(f"Validation error: {e}")
            raise
        except Exception as e:
            log_error(f"Operation failed: {e}")
            raise RuntimeError(f"Service operation failed: {e}")
    
    def _execute_operation(self, input_data: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the main operation logic (Single Responsibility)"""
        # Implementation specific to service
        return {
            "status": "success",
            "data": input_data,
            "processed": True
        }
    
    def _handle_report_generation(self, result: Dict[str, Any], options: Dict[str, Any]) -> bool:
        """
        MANDATORY: Handle report generation for CLI services
        
        Args:
            result: Service operation result
            options: CLI options including report format preferences
            
        Returns:
            bool: True if reports were generated
        """
        # Check if reports are requested
        requested_formats = []
        if options.get("json_report"):
            requested_formats.append("json")
        if options.get("txt_report"):
            requested_formats.append("txt")
        if options.get("html_report"):
            requested_formats.append("html")
        if options.get("all_reports"):
            requested_formats = ["json", "txt", "html"]
        
        if not requested_formats:
            return {"generated": False, "formats": []}
        
        # Generate reports using existing service (DRY)
        generated_reports = []
        for format_type in requested_formats:
            try:
                # VERIFY: Method exists or use alternative
                if hasattr(self.report_service, 'generate_service_report'):
                    report_path = self.report_service.generate_service_report(
                        service_name=self.__class__.__name__,
                        result_data=result,
                        format_type=format_type,
                        output_dir=options.get("output_dir", "output/reports")
                    )
                else:
                    # Use existing method with adaptation
                    report_path = self.report_service.generate_report(
                        result, format_type, options.get("output_dir", "output/reports")
                    )
                
                generated_reports.append({
                    "format": format_type,
                    "path": report_path,
                    "size": self._get_file_size(report_path)
                })
                
            except Exception as e:
                log_error(f"Failed to generate {format_type} report: {e}")
        
        return {
            "generated": len(generated_reports) > 0,
            "formats": [r["format"] for r in generated_reports],
            "files": generated_reports
        }
    
    def _validate_configuration(self) -> None:
        """Validate service configuration (Single Responsibility)"""
        # Validate config structure
        if not isinstance(self.config, dict):
            raise ValueError("Configuration must be a dictionary")
    
    def _setup_logger(self) -> logging.Logger:
        """Setup service logger (Single Responsibility)"""
        return logging.getLogger(f"service.{self.__class__.__name__}")
    
    def _generate_metadata(self) -> Dict[str, Any]:
        """Generate operation metadata (Single Responsibility)"""
        return {
            "service_name": self.__class__.__name__,
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
    
    def _get_file_size(self, file_path: str) -> int:
        """Get file size helper (Clean Code: Descriptive name)"""
        try:
            from pathlib import Path
            return Path(file_path).stat().st_size
        except:
            return 0
    
    def get_service_info(self) -> Dict[str, Any]:
        """Get service information (Interface Segregation)"""
        return {
            "name": self.__class__.__name__,
            "version": "1.0.0",
            "description": "Service description",
            "capabilities": ["primary_operation"],
            "dependencies": ["InputValidator", "ReportService"],
            "report_formats": ["json", "txt", "html"],
            "cli_integration": True,
            "follows_principles": ["SOLID", "Clean Code", "DRY"]
        }
```

#### **Step 2.2: Service Registration**
```python
# File: src/services/__init__.py
"""
Services Module - Add new service export
"""

from .scan_service import ScanService
from .scanner_service import ScannerService
from .report_service import ReportService
from .info_service import InfoService
from .utility_services import VersionService, ToolService, CacheService
from .new_service import NewService  # NEW ADDITION

__all__ = [
    "ScanService",
    "ScannerService", 
    "ReportService",
    "InfoService",
    "VersionService",
    "ToolService",
    "CacheService",
    "NewService",  # NEW ADDITION
]
```

### **Phase 3: CLI Integration (Post-Refactoring)**

#### **Step 3.1: تعیین فایل مناسب برای Command**
```python
# ✨ تحلیل ماهیت Command
COMMAND_CATEGORIZATION = {
    # Core workflow commands
    "scan_related": "src/cli/commands/core_commands.py",
    
    # Information and system commands  
    "info_related": "src/cli/commands/info_commands.py",
    
    # Network security commands
    "network_related": "src/cli/commands/network_commands.py",
    
    # Web application security
    "web_related": "src/cli/commands/web_commands.py",
    
    # CMS-specific security
    "cms_related": "src/cli/commands/cms_commands.py",
    
    # Security analysis (WAF, etc.)
    "security_related": "src/cli/commands/security_commands.py",
    
    # Utility and maintenance
    "utility_related": "src/cli/commands/utility_commands.py"
}

# مثال تصمیم‌گیری:
new_command_analysis = {
    "command_name": "new_service_command",
    "purpose": "New service operation", 
    "category": "utility_related",
    "target_file": "src/cli/commands/utility_commands.py"
}
```

#### **Step 3.2: CLI Command Implementation با Enhanced Options**
```python
# File: src/cli/commands/utility_commands.py (بر اساس categorization)
import click
import sys
from ..services.new_service import NewService  # ✅ VERIFY: src/services/new_service.py exists
from ..utils.logger import log_info, log_error, log_success  # ✅ VERIFY: src/utils/logger.py exists

# ✨ استفاده از enhanced options
from ..options import (
    common_options,           # گزینه‌های عمومی
    reporting_options,        # گزینه‌های گزارش‌گیری کامل
    scanner_options,          # پیکربندی scanner (در صورت نیاز)
)

@click.command()
@click.argument("input_data")
@click.option("--config", help="Configuration option")
@reporting_options          # ✨ JSON, HTML, PDF, TXT, CSV
@common_options            # گزینه‌های عمومی
def new_command(input_data, config, **kwargs):
    """
    New service command implementation with mandatory reporting
    
    FILE PATH: src/cli/commands/utility_commands.py
    """
    try:
        # Initialize service (SOLID: Dependency Injection)
        service = NewService()
        
        # Prepare options (Clean Code: Clear parameter passing)
        options = {
            "config": config,
        }
        
        # Add report options from enhanced options
        options.update(kwargs)  # includes all reporting options
        
        # Execute service operation
        result = service.primary_operation(input_data, options)
        
        # Log operation result
        if result.get("report_generated", {}).get("generated", False):
            log_success(f"Operation completed with reports generated")
        else:
            log_success(f"Operation completed: {result['status']}")
        
    except ValueError as e:
        log_error(f"Invalid input: {e}")
        sys.exit(1)
    except Exception as e:
        log_error(f"Command failed: {e}")
        sys.exit(1)

# Update __all__ export
__all__.append("new_command")
```

#### **Step 3.3: به‌روزرسانی commands/__init__.py**
```python
# File: src/cli/commands/__init__.py

# Add new import
from .utility_commands import (
    cache_stats_command,
    clear_cache_command,
    new_command,  # ✨ NEW
)

# Conditional availability check
try:
    from .utility_commands import new_command
    NEW_COMMAND_AVAILABLE = True
except ImportError:
    new_command = None
    NEW_COMMAND_AVAILABLE = False

# Update exports
__all__ = [
    # ... existing commands
    "new_command",  # ✨ NEW
]

# Update availability function
def get_command_availability():
    return {
        # ... existing
        "new_command": NEW_COMMAND_AVAILABLE,  # ✨ NEW
    }
```

#### **Step 3.4: CLI Registration (automatic)**
```python
# File: src/cli/__init__.py
# Import automatic through commands/__init__.py
from .commands import new_command

# Conditional registration (backward compatibility)
if new_command and NEW_COMMAND_AVAILABLE:
    cli.add_command(new_command, name="new")
```

### **Phase 4: Testing (تست)**

#### **Step 4.1: Unit Tests**
```python
# File: tests/services/test_new_service.py
import unittest
from unittest.mock import Mock, patch
from src.services.new_service import NewService

class TestNewService(unittest.TestCase):
    """Test suite for NewService"""
    
    def setUp(self):
        """Set up test environment"""
        self.service = NewService()
    
    def test_primary_operation_success(self):
        """Test successful operation"""
        result = self.service.primary_operation("test_input")
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["data"], "test_input")
        self.assertIn("timestamp", result["metadata"])
    
    def test_primary_operation_invalid_input(self):
        """Test invalid input handling"""
        with self.assertRaises(ValueError):
            self.service.primary_operation("")
    
    def test_service_info(self):
        """Test service information"""
        info = self.service.get_service_info()
        
        self.assertIn("name", info)
        self.assertIn("version", info)
        self.assertIn("capabilities", info)

if __name__ == "__main__":
    unittest.main()
```

#### **Step 4.2: CLI Integration Tests**
```python
# File: tests/cli/test_new_command.py
import pytest
from click.testing import CliRunner
from src.cli.commands.utility_commands import new_command

class TestNewCommand:
    """Test suite for new CLI command"""
    
    def setup_method(self):
        """Set up test environment"""
        self.runner = CliRunner()
    
    def test_command_help(self):
        """Test command help output"""
        result = self.runner.invoke(new_command, ['--help'])
        assert result.exit_code == 0
        assert "New service command" in result.output
    
    def test_command_execution(self):
        """Test command execution"""
        result = self.runner.invoke(new_command, ['test_input'])
        assert result.exit_code == 0
    
    def test_report_options(self):
        """Test report generation options"""
        result = self.runner.invoke(new_command, [
            'test_input', 
            '--json-report',
            '--output-dir', '/tmp/test'
        ])
        assert result.exit_code == 0
```

#### **Step 4.3: Integration Tests**
```python
# File: tests/integration/test_new_service_integration.py
import unittest
from src.services.new_service import NewService
from src.cli.commands.utility_commands import new_command

class TestNewServiceIntegration(unittest.TestCase):
    """Integration tests for NewService"""
    
    def test_cli_integration(self):
        """Test CLI integration"""
        # Test command execution without errors
        # Verify output format
        # Check backward compatibility
        pass
    
    def test_service_compatibility(self):
        """Test compatibility with existing services"""
        # Verify no conflicts with existing services
        # Test data flow between services
        pass

if __name__ == "__main__":
    unittest.main()
```

---

## 🔄 **روال تغییر Service موجود**

### **Phase 1: Impact Analysis (تحلیل تأثیر)**

#### **Step 1.1: Backward Compatibility Assessment**
```bash
# 1. API Change Analysis
- آیا method signature تغییر می‌کند؟
- آیا return type تغییر می‌کند؟
- آیا behavior تغییر می‌کند؟

# 2. Dependency Analysis  
- کدام Services از این Service استفاده می‌کنند؟
- کدام CLI Commands تأثیر می‌بینند؟
- کدام Tests باید بروزرسانی شوند؟

# 3. Configuration Analysis
- آیا Configuration جدید لازم است؟
- آیا Environment Variables تغییر می‌کند؟
```

#### **Step 1.2: Change Documentation**
```python
# File: CHANGELOG.md - Document all changes
## [Version] - Date
### Changed
- Modified ServiceName.method_name()
  - BREAKING: Changed parameter type from X to Y
  - COMPATIBILITY: Added backward compatibility layer
  - MIGRATION: See migration guide below

### Migration Guide
- Old usage: `service.method(old_param)`
- New usage: `service.method(new_param)`
- Backward compatibility: Supported until version X.X
```

### **Phase 2: Implementation with Compatibility (پیاده‌سازی سازگار)**

#### **Step 2.1: Backward Compatible Changes**
```python
# Example: Adding new parameter with default value
class ExistingService:
    def existing_method(self, 
                       existing_param: str, 
                       new_param: Optional[str] = None,  # NEW with default
                       **kwargs) -> Dict[str, Any]:
        """
        Existing method with new functionality
        
        Args:
            existing_param: Original parameter (unchanged)
            new_param: New parameter with default for compatibility
            **kwargs: For future extensibility
        """
        # Handle backward compatibility
        if new_param is None:
            new_param = "default_value"  # Maintain old behavior
        
        # Implement new logic
        return self._enhanced_logic(existing_param, new_param)
```

#### **Step 2.2: Deprecation Pattern**
```python
import warnings
from typing import Optional

class ExistingService:
    def old_method(self, param: str) -> Dict[str, Any]:
        """
        DEPRECATED: Use new_method() instead
        Will be removed in version 2.0
        """
        warnings.warn(
            "old_method is deprecated, use new_method instead",
            DeprecationWarning,
            stacklevel=2
        )
        return self.new_method(param)
    
    def new_method(self, param: str, enhanced_param: Optional[str] = None) -> Dict[str, Any]:
        """New enhanced method"""
        # New implementation
        pass
```

### **Phase 3: Testing Modified Service (تست سرویس تغییریافته)**

#### **Step 3.1: Regression Testing**
```python
# File: tests/regression/test_service_changes.py
class TestServiceChanges(unittest.TestCase):
    """Regression tests for service modifications"""
    
    def test_old_api_still_works(self):
        """Test that old API calls still function"""
        # Test old method calls
        # Verify old return formats
        # Check backward compatibility
        pass
    
    def test_new_functionality(self):
        """Test new functionality works correctly"""
        # Test new features
        # Verify enhanced capabilities
        # Check performance improvements
        pass
```

---

## 🆕 **روال اضافه کردن CLI Command جدید (Post-Refactoring)**

### **Phase 1: Command Analysis & File Selection**

#### **Step 1.1: تعیین فایل مناسب برای Command**
```python
# بر اساس COMMAND_CATEGORIZATION که قبلاً تعریف شد
# انتخاب فایل مناسب بر اساس ماهیت command
```

### **Phase 2: Enhanced Options Implementation**

#### **Step 2.1: استفاده از Enhanced Options**
```python
# در src/cli/options.py بهبود یافته:

@common_options          # گزینه‌های پایه
@reporting_options       # JSON, HTML, PDF, TXT, CSV reports
@scanner_options         # timeout, threads, rate-limit, user-agent, proxy
@network_options         # ports, scan-type, fast, service-detection
@web_options            # scan-depth, max-pages, follow-redirects
@dns_options            # subdomain-enum, zone-transfer, dns-bruteforce
@ssl_options            # check-cert, check-protocols, check-ciphers
@api_options            # swagger-url, api-format, auth-header

# Composite options
@full_scan_options      # همه گزینه‌ها
@network_scan_options   # ترکیب network + dns + reporting
@web_scan_options       # ترکیب web + ssl + reporting
```

#### **Step 2.2: Options Validation**
```python
from ..options import validate_option_combination

def command_function(**kwargs):
    # Validate option combination
    if not validate_option_combination(kwargs):
        log_error("❌ Invalid option combination")
        sys.exit(1)
```

---

## 🔄 **روال تغییر Command موجود (Post-Refactoring)**

### **File Location & Modification**
```python
# یافتن فایل مربوطه
COMMAND_LOCATIONS = {
    "scan_command": "src/cli/commands/core_commands.py",
    "port_command": "src/cli/commands/network_commands.py", 
    "web_command": "src/cli/commands/web_commands.py",
    "info_command": "src/cli/commands/info_commands.py",
    "wordpress_command": "src/cli/commands/cms_commands.py",
    "waf_command": "src/cli/commands/security_commands.py",
    # ... و غیره
}

# ویرایش در فایل مناسب
# FILE: src/cli/commands/network_commands.py
def port_command(...):  # تغییر در فایل مربوطه
    # Enhanced implementation
```

### **Backward Compatibility Verification**
```python
# اطمینان از عدم شکستن imports موجود
# این import ها باید همچنان کار کنند:
from src.cli.commands import port_command          # ✅ از طریق __init__.py
from src.cli.commands.network_commands import port_command  # ✅ مستقیم
```

---

## 🚀 **Deployment & Validation (استقرار و اعتبارسنجی)**

### **Pre-deployment Checklist with Compliance Verification**
```bash
# 1. Code Quality
- [ ] All tests passing
- [ ] Code review completed
- [ ] Documentation updated
- [ ] Backward compatibility verified

# 2. Compliance Check
python -c "
import sys
sys.path.append('.')

# Check roadmap compliance
print('📋 Checking roadmap compliance...')
# Verify feature is in approved roadmap

# Check tools compliance  
print('🛠️ Checking tools compliance...')
# Verify all tools are in approved list

# Check method verification
print('⚙️ Checking method verification...')
# Verify all imported methods exist

print('✅ All compliance checks passed')
"

# 3. Backup current version
git tag -a v$(current_version) -m "Pre-deployment backup"

# 4. Deploy new service
git merge feature/new-service

# 5. Run validation tests
python -m pytest tests/ -v --tb=short

# 6. Verify CLI functionality
python main.py --help
python main.py info

# 7. Test critical workflows
python main.py scan test-target --profile quick

# 8. Verify roadmap status update
echo "📋 Update features_roadmap.md status to 'Completed'"
```

### **Post-deployment Validation with Standards Check**
```bash
# Comprehensive system test
python verify_installation.py

# Service-specific validation
python -c "
from src.services.new_service import NewService
service = NewService()
info = service.get_service_info()
print(f'✅ Service: {info[\"name\"]}')
print(f'✅ Tools verified: {info.get(\"tools_verified\", False)}')
print(f'✅ Roadmap compliance: {info.get(\"roadmap_compliance\", False)}')
"

# Integration validation
python main.py new test-input --config test --json-report

# Performance baseline
python -m pytest tests/performance/ --benchmark-only

# Compliance final check
echo "📋 Final compliance verification:"
echo "  ✅ features_roadmap.md updated"
echo "  ✅ docs/tools-list.md compliance verified"
echo "  ✅ docs/development_guide.md followed"
```

### **Compliance Documentation Template**
```markdown
# Service Deployment Report
**Service Name**: NewService
**Deployment Date**: [Date]
**File Path**: src/services/new_service.py

## Compliance Verification
### Roadmap Compliance ✅
- **Phase**: Phase X from features_roadmap.md
- **Priority**: High/Medium/Low
- **Dependencies**: [List verified dependencies]
- **Status Update**: features_roadmap.md updated to "Completed"

### Tools Compliance ✅  
- **Reference**: docs/tools-list.md
- **Approved Tools Used**: [List all tools]
- **Unauthorized Tools**: None
- **Tool Verification**: All tools verified available

### Development Guide Compliance ✅
- **Reference**: docs/development_guide.md
- **SOLID Principles**: Applied
- **DRY Principle**: Applied  
- **Clean Code**: Applied
- **File Paths**: Documented
- **CLI Integration**: With mandatory reporting
- **Testing**: >90% coverage

## Validation Results
- **Unit Tests**: ✅ Passed
- **Integration Tests**: ✅ Passed
- **Performance Tests**: ✅ Within limits
- **CLI Tests**: ✅ All options functional
- **Report Generation**: ✅ JSON, TXT, HTML working

## Post-Deployment Actions
- [ ] Update features_roadmap.md status
- [ ] Archive development branch
- [ ] Update project documentation
- [ ] Notify team of new capability
```

---

## 📚 **Documentation Requirements (الزامات مستندسازی)**

### **Service Documentation Template**
```python
"""
Service Name Documentation

## Overview
Brief description of service purpose and functionality.

## Usage
```python
from src.services.service_name import ServiceName

service = ServiceName()
result = service.primary_method("input")
```

## API Reference

### ServiceName.primary_method(param)
Description of the method.

**Parameters:**
- param (str): Parameter description

**Returns:**
- Dict[str, Any]: Result dictionary with keys:
  - status: Operation status
  - data: Result data
  - metadata: Additional information

**Raises:**
- ValueError: If input validation fails
- RuntimeError: If operation fails

## Configuration
Service configuration options and examples.

## Examples
Practical usage examples with expected outputs.

## Compatibility
Backward compatibility information and migration notes.
"""
```

### **README Update Template**
```markdown
## Services

### ServiceName
Brief description of the service functionality.

**Usage:**
```bash
python main.py new-command input-data --option value
```

**Features:**
- Feature 1
- Feature 2
- Feature 3

**Dependencies:**
- Dependency 1
- Dependency 2
```

---

## 🎯 **Success Criteria (معیارهای موفقیت)**

### **For New Services**
1. ✅ All unit tests pass with >90% coverage
2. ✅ Integration tests pass without breaking existing functionality  
3. ✅ CLI integration works seamlessly
4. ✅ Documentation is complete and accurate
5. ✅ Performance meets baseline requirements
6. ✅ Code review approval from team leads

### **For Modified Services**
1. ✅ All regression tests pass
2. ✅ Backward compatibility maintained
3. ✅ Migration path documented (if needed)
4. ✅ Performance impact assessed and acceptable
5. ✅ All dependent services continue working
6. ✅ User impact minimized

### **For System Integration**
1. ✅ End-to-end workflows function correctly
2. ✅ No memory leaks or resource issues
3. ✅ CLI help and documentation updated
4. ✅ Configuration compatibility maintained
5. ✅ Logging and monitoring function properly

---

## 🚨 **Violation Consequences (پیامدهای نقض)**

### **Critical Violations (نقض‌های حیاتی)**
- **Breaking backward compatibility** without approval → **Code rejection**
- **Missing tests** for new services → **Code rejection**  
- **Security vulnerabilities** → **Immediate fix required**
- **Performance regression >20%** → **Code rejection**
- **Using non-existent methods/classes** → **Code rejection**
- **Missing CLI report integration** for services → **Code rejection**

### **Major Violations (نقض‌های اصلی)**
- **SOLID principles violation** → **Refactoring required**
- **DRY principle violation** (code duplication) → **Code consolidation required**
- **Clean Code violations** (unclear names, complex methods) → **Code cleanup required**
- **Incomplete documentation** → **Documentation completion required**
- **Missing error handling** → **Error handling implementation required**
- **Missing file path documentation** → **Path documentation required**

### **Minor Violations (نقض‌های جزئی)**
- **Code style issues** → **Code formatting required**
- **Missing type hints** → **Type annotation required**
- **Incomplete logging** → **Logging enhancement required**
- **Unnecessary complexity** → **Simplification required**

### **Process Violations (نقض‌های فرآیندی)**
- **Creating long files without approval** → **Development halt until review**
- **Skipping verification steps** → **Re-implementation required**
- **Inadequate testing coverage** → **Additional test implementation**
- **Missing integration validation** → **Full integration test required**

---

## 📋 **Quick Reference Checklist**

### **New Service Development with Full Compliance**
```bash
□ 📋 ROADMAP COMPLIANCE
  □ features_roadmap.md reviewed and feature approved
  □ Phase identification completed
  □ Priority level confirmed
  □ Dependencies mapped and verified
  □ Timeline estimation completed

□ 🛠️ TOOLS COMPLIANCE  
  □ docs/tools-list.md reviewed for approved tools
  □ All required tools listed in approved list
  □ No unauthorized packages/tools used
  □ Tool version compatibility verified
  □ External tool availability confirmed

□ 📚 DEVELOPMENT GUIDE COMPLIANCE
  □ docs/development_guide.md followed completely
  □ All imported classes/methods verified to exist
  □ SOLID principles implemented
  □ DRY principle followed (no code duplication)
  □ Clean Code standards met
  □ File creation approval obtained (for long files)

□ 🏗️ IMPLEMENTATION QUALITY
  □ Requirements analysis completed
  □ Interface design approved  
  □ Implementation follows template with reporting
  □ CLI integration with mandatory report options added
  □ All file paths documented in code comments

□ 🧪 TESTING & VALIDATION
  □ Unit tests implemented (>90% coverage)
  □ Integration tests implemented
  □ Tools compliance tests passing
  □ CLI functionality verified
  □ Report generation tested (JSON, TXT, HTML)

□ 📖 DOCUMENTATION & REVIEW
  □ Documentation written and accurate
  □ Code review completed
  □ Performance validated
  □ Backward compatibility verified
  □ No weird additions or unnecessary complexity

□ 🚀 DEPLOYMENT READINESS
  □ Deployment checklist completed
  □ features_roadmap.md ready for status update
  □ Team notification prepared
```

### **Existing Service Modification with Compliance**
```bash
□ 📋 IMPACT ANALYSIS WITH ROADMAP
  □ Modification aligns with roadmap direction
  □ Phase requirements still satisfied
  □ Dependencies impact assessed
  □ Priority level maintained or updated

□ 🛠️ TOOLS IMPACT ASSESSMENT
  □ New tools (if any) approved in docs/tools-list.md
  □ Existing tool usage still compliant
  □ Tool version changes documented
  □ External tool impact evaluated

□ 📚 DEVELOPMENT STANDARDS
  □ Backward compatibility maintained
  □ SOLID principles preserved
  □ Clean Code standards upheld
  □ DRY principle not violated
  □ Method/class verification completed
  □ API documentation complete

□ 🛠️ TOOLS & COMPLIANCE
  □ Only approved tools used (docs/tools-list.md)
  □ Tool verification code implemented
  □ External dependencies managed properly
  □ Configuration follows project standards
```

### **CLI Service Requirements Checklist (Post-Refactoring)**
```bash
□ 📁 FILE ORGANIZATION
  □ Command در فایل مناسب قرار گرفته (core/info/network/web/cms/security/utility)
  □ Import statements در فایل صحیح هستند
  □ __all__ exports به‌روزرسانی شده
  □ commands/__init__.py به‌روزرسانی شده

□ 🎛️ OPTIONS COMPLIANCE  
  □ از option groups موجود در options.py استفاده شده
  □ تکرار options وجود ندارد
  □ reporting_options برای CLI commands اضافه شده
  □ validate_option_combination استفاده شده (در صورت نیاز)

□ 📊 REPORT GENERATION (MANDATORY)
  □ JSON report option implemented
  □ TXT report option implemented  
  □ HTML report option implemented
  □ All reports option implemented
  □ Output directory option provided

□ 🔧 INTEGRATION & FUNCTIONALITY
  □ Report generation integrated with ReportService
  □ CLI command properly registered in main.py
  □ Help text includes report options
  □ Error handling for report generation
  □ Success/failure logging for reports

□ 🔗 BACKWARD COMPATIBILITY
  □ Import های قدیمی همچنان کار می‌کنند
  □ CLI registration به‌روزرسانی شده
  □ Conditional imports برای optional features
  □ __init__.py های مربوطه به‌روزرسانی شده

□ ⚙️ METHOD VERIFICATION (اجباری)
  □ تمام method signatures تأیید شده
  □ Parameter count ها صحیح هستند
  □ hasattr checks برای optional methods اضافه شده
  □ Error handling برای missing features

□ 📋 QUALITY & STANDARDS
  □ Report format validation
  □ File path reporting in results
  □ Consistent output format with other services
  □ Performance impact acceptable
  □ Memory usage within limits
```

### **Pre-Deployment Final Check with Full Compliance**
```bash
□ 🧪 TESTING SUITE
  □ python -m pytest tests/ -v (all tests pass)
  □ python main.py --help (CLI help works)
  □ python main.py info (info command works)
  □ python -c "from src.services.new_service import NewService; print('Import OK')"

□ 📋 COMPLIANCE VERIFICATION
  □ features_roadmap.md compliance verified
  □ docs/tools-list.md compliance verified  
  □ docs/development_guide.md compliance verified
  □ All file paths documented and verified
  □ No import errors or missing dependencies

□ 🔄 COMPATIBILITY & PERFORMANCE
  □ Backward compatibility maintained
  □ Performance within acceptable limits
  □ Memory usage optimized
  □ Resource utilization efficient

□ 📖 DOCUMENTATION & APPROVAL
  □ Code review approval obtained
  □ Documentation complete and accurate
  □ Team notification prepared
  □ Deployment plan finalized

□ 🚀 ROADMAP UPDATE READINESS
  □ features_roadmap.md status update prepared
  □ Phase completion documented
  □ Next phase dependencies verified
  □ Success metrics defined
```

---

## 📚 **مراجع و فایل‌های مستند**

### **فایل‌های اصلی پروژه (الزامی مطالعه)**
```bash
📋 فایل‌های مرجع اصلی:
├── features_roadmap.md              # نقشه راه پروژه و برنامه‌ریزی
├── docs/tools-list.md               # ابزارها و پکیج‌های مجاز
├── docs/development_guide.md        # این سند راهبردی
├── docs/user_manual.md              # راهنمای کاربری
└── docs/api_documentation.md        # مستندات API

🔄 ترتیب مطالعه اجباری:
1. features_roadmap.md → تعیین فیچر و اولویت
2. docs/tools-list.md → انتخاب ابزارهای مجاز  
3. docs/development_guide.md → اجرای فرآیند توسعه
```

### **نحوه مدیریت فایل‌های مرجع**
```bash
# بروزرسانی نقشه راه پروژه
git checkout main
vi features_roadmap.md
# وضعیت فیچر را از "Planned" به "In Progress" تغییر دهید
# پس از تکمیل به "Completed" تغییر دهید

# بروزرسانی لیست ابزارها (در صورت نیاز)
vi docs/tools-list.md
# اضافه کردن ابزار جدید نیاز به تأیید دارد

# بروزرسانی راهنمای توسعه
vi docs/development_guide.md
# این سند تنها با تأیید team lead قابل تغییر است
```

### **الزامات نگهداری مستندات**
```python
"""
📋 مسئولیت‌های نگهداری:

1. features_roadmap.md:
   - بروزرسانی وضعیت فیچرها
   - اضافه کردن فیچرهای جدید
   - تنظیم اولویت‌بندی

2. docs/tools-list.md:
   - تأیید ابزارهای جدید
   - حذف ابزارهای deprecated
   - بروزرسانی نسخه‌ها

3. docs/development_guide.md:
   - حفظ استانداردهای توسعه  
   - بروزرسانی فرآیندها
   - اضافه کردن best practices

🚨 هر تغییری در این فایل‌ها باید:
- دلیل مشخصی داشته باشد
- تأیید team lead را داشته باشد  
- با کل تیم هماهنگ شده باشد
- در git به صورت مجزا commit شود
"""
```

---

**🎯 این سند راهبردی خط قرمز توسعه پروژه Auto-Pentest Framework است و باید در تمام مراحل توسعه و تغییر سرویس‌ها به‌دقت رعایت شود.**

**📋 مراجع اصلی:**
- **features_roadmap.md**: نقشه راه و برنامه‌ریزی پروژه
- **docs/tools-list.md**: ابزارها و پکیج‌های مجاز 
- **docs/development_guide.md**: این سند راهبردی

**🔄 فرآیند**: roadmap → tools → development → implementation → testing → deployment → documentation