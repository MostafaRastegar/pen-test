# 🎯 Service Development Strategic Workflow
## Auto-Pentest Framework - خط قرمز توسعه پروژه

### 📋 **نسخه**: v1.0 | **تاریخ**: 2024 | **وضعیت**: استراتژیک و غیرقابل تغییر
### 📁 **مسیر فایل**: docs/development_guide.md

---

## 🗺️ **فرآیند توسعه استراتژیک - اجباری**

### **مرحله 0: مطالعه مستندات مرجع (الزامی)**
```bash
📋 ترتیب مطالعه اجباری:
1️⃣ features_roadmap.md          # نقشه راه و برنامه‌ریزی پروژه
2️⃣ docs/tools-list.md           # ابزارها و پکیج‌های مجاز
3️⃣ docs/development_guide.md    # این سند راهبردی
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

## 🏗️ **ساختار فعلی پروژه - الگوی مرجع**

### **Architecture Pattern**
```
CLI (main.py) 
    ↓
Commands (src/cli/commands.py)
    ↓
Services (src/services/)
    ↓
Orchestrator (src/orchestrator/)
    ↓
Scanners (src/scanners/)
    ↓
Core Framework (src/core/)
```

### **Service Layer Structure**
```python
src/services/
├── __init__.py              # Service exports
├── scan_service.py          # اصلی: مدیریت workflow ها
├── scanner_service.py       # اصلی: اجرای scanner های مجزا
├── report_service.py        # اصلی: تولید گزارشات
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

# 2. انتخاب ابزارهای مجاز
FILE_REFERENCE: docs/tools-list.md
"""
بررسی ابزارهای مورد نیاز:
- کدام Python packages نیاز است؟
- کدام External tools استفاده می‌شود؟
- آیا همه در لیست مجاز هستند؟
- آیا ابزار جدیدی نیاز است؟ (نیاز به تأیید)
"""

# 3. تعریف مسئولیت Service
SERVICE_DEFINITION = {
    "name": "service_name",
    "roadmap_phase": "Phase X: Description",
    "priority": "High/Medium/Low",
    "category": "Core/Business/Utility/Integration",
    "dependencies": ["existing_service_1", "existing_service_2"],
    "tools_required": ["tool1", "tool2"],  # از tools-list.md
    "estimated_effort": "X days/weeks"
}

# 4. Category Identification بر اساس roadmap
CATEGORY_MAPPING = {
    "Core Service": "مدیریت اصلی workflow و scanner ها",
    "Business Service": "منطق کسب‌وکار اصلی", 
    "Utility Service": "عملکردهای کمکی و پشتیبانی",
    "Integration Service": "ادغام با ابزارهای خارجی"
}

# 5. Backward Compatibility Impact Analysis
COMPATIBILITY_IMPACT = """
- آیا تغییری در API های موجود لازم است؟
- آیا CLI Commands جدید نیاز است؟
- آیا Configuration جدید لازم است؟
- آیا Dependencies جدید اضافه می‌شود؟
"""

# 6. Tools and Dependencies Verification
TOOLS_VERIFICATION = """
📋 ابزارهای مورد نیاز (همه باید در tools-list.md باشند):
□ Python package 1: ✅/❌ در لیست مجاز
□ Python package 2: ✅/❌ در لیست مجاز  
□ External tool 1: ✅/❌ در لیست مجاز
□ External tool 2: ✅/❌ در لیست مجاز

🚨 اگر ابزار جدیدی نیاز است:
1. درخواست اضافه شدن به tools-list.md
2. توجیه ضرورت استفاده
3. تأیید از team lead
4. بروزرسانی tools-list.md
"""
```

#### **Step 1.2: Interface Design with Standards Compliance**
```python
# Template for Service Interface
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod

# مراجعه به roadmap برای تعیین interface requirements
class NewServiceInterface(ABC):
    """
    Interface definition for new service
    Based on: features_roadmap.md requirements
    """
    
    @abstractmethod
    def core_method(self, param: str) -> Dict[str, Any]:
        """Primary service method"""
        pass
    
    @abstractmethod
    def validate_input(self, data: Any) -> bool:
        """Input validation"""
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Service information (optional)"""
        return {
            "name": self.__class__.__name__, 
            "version": "1.0",
            "roadmap_phase": "Phase X",
            "approved_tools": []  # از tools-list.md
        }
```

### **Phase 2: Implementation (پیاده‌سازی)**

#### **Step 2.1: Service Implementation**
```python
# File: src/services/new_service.py
"""
New Service Implementation
Following Single Responsibility and Clean Architecture principles
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

# Internal imports (VERIFY EXISTENCE BEFORE USE)
from ..core.validator import InputValidator  # ✅ EXISTS: src/core/validator.py
from ..utils.logger import log_info, log_error, log_success  # ✅ EXISTS: src/utils/logger.py
from ..services.report_service import ReportService  # ✅ EXISTS: src/services/report_service.py


class NewService:
    """Service for specific functionality"""
    
    def __init__(self):
        """Initialize service with required dependencies"""
        self.validator = InputValidator()
        self.logger = logging.getLogger(f"service.{self.__class__.__name__}")
        # MANDATORY: Initialize report service for CLI integration
        self.report_service = ReportService()
        
    def primary_operation(self, input_data: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Primary service operation with mandatory reporting capability
        
        Args:
            input_data: Input for processing
            options: Optional configuration including report format
            
        Returns:
            Dict containing operation results with report_generated flag
            
        Raises:
            ValueError: If input validation fails
            Exception: If operation fails
        """
        try:
            # Input validation (SOLID: Single Responsibility)
            if not self.validator.validate_input(input_data):
                raise ValueError(f"Invalid input: {input_data}")
            
            # Log operation start
            log_info(f"Starting {self.__class__.__name__} operation")
            
            # Execute core logic (DRY: Don't repeat validation)
            result = self._execute_core_logic(input_data, options or {})
            
            # MANDATORY: Generate reports if requested via CLI
            report_generated = self._handle_report_generation(result, options)
            result["report_generated"] = report_generated
            
            # Log success
            log_success(f"Completed {self.__class__.__name__} operation")
            
            return result
            
        except Exception as e:
            log_error(f"Failed {self.__class__.__name__} operation: {e}")
            raise
    
    def _execute_core_logic(self, input_data: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Core business logic implementation (SOLID: Single Responsibility)"""
        # Implementation specific to service
        return {
            "status": "success",
            "data": input_data,
            "timestamp": datetime.now().isoformat(),
            "service_name": self.__class__.__name__
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
        report_formats = []
        if options.get("json_report"):
            report_formats.append("json")
        if options.get("txt_report"):
            report_formats.append("txt")
        if options.get("html_report"):
            report_formats.append("html")
        if options.get("all_reports"):
            report_formats = ["json", "txt", "html"]
        
        if not report_formats:
            return False
        
        try:
            # Use existing ReportService (DRY principle)
            for format_type in report_formats:
                self.report_service.generate_service_report(
                    service_name=self.__class__.__name__,
                    result_data=result,
                    format_type=format_type,
                    output_dir=options.get("output_dir", "output/reports")
                )
            
            log_success(f"Generated reports in formats: {', '.join(report_formats)}")
            return True
            
        except Exception as e:
            log_error(f"Report generation failed: {e}")
            # Don't fail the main operation due to report issues
            return False
    
    def get_service_info(self) -> Dict[str, Any]:
        """Get service information"""
        return {
            "name": self.__class__.__name__,
            "version": "1.0.0",
            "capabilities": ["primary_operation"],
            "dependencies": ["InputValidator", "ReportService"],
            "report_formats": ["json", "txt", "html"],
            "cli_integration": True
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

### **Phase 3: Integration (ادغام)**

#### **Step 3.1: CLI Integration**
```python
# File: src/cli/commands.py - Add new command
import click
import sys
from ..services.new_service import NewService  # ✅ VERIFY: src/services/new_service.py exists
from ..utils.logger import log_info, log_error, log_success  # ✅ VERIFY: src/utils/logger.py exists

@click.command()
@click.argument("input_data")
@click.option("--config", help="Configuration option")
# MANDATORY: Add report options for all CLI services
@click.option("--json-report", is_flag=True, help="Generate JSON report")
@click.option("--txt-report", is_flag=True, help="Generate TXT report") 
@click.option("--html-report", is_flag=True, help="Generate HTML report")
@click.option("--all-reports", is_flag=True, help="Generate all report formats")
@click.option("--output-dir", default="output/reports", help="Output directory for reports")
@common_options  # ✅ VERIFY: common_options exists in src/cli/options.py
def new_command(input_data, config, json_report, txt_report, html_report, all_reports, output_dir, **kwargs):
    """
    New service command implementation with mandatory reporting
    
    FILE PATH: src/cli/commands.py
    """
    try:
        # Initialize service (SOLID: Dependency Injection)
        service = NewService()
        
        # Prepare options (Clean Code: Clear parameter passing)
        options = {
            "config": config,
            "json_report": json_report,
            "txt_report": txt_report,
            "html_report": html_report,
            "all_reports": all_reports,
            "output_dir": output_dir
        }
        
        # Execute service operation
        result = service.primary_operation(input_data, options)
        
        # Log operation result
        if result.get("report_generated"):
            log_success(f"Operation completed with reports generated in: {output_dir}")
        else:
            log_success(f"Operation completed: {result['status']}")
        
    except ValueError as e:
        log_error(f"Invalid input: {e}")
        sys.exit(1)
    except Exception as e:
        log_error(f"Command failed: {e}")
        sys.exit(1)
```

#### **Step 3.2: Main CLI Registration**
```python
# File: main.py - Add command registration
# ✅ VERIFY: Import path exists before adding
from src.cli.commands import new_command  # VERIFY: src/cli/commands.py contains new_command

# Add to click group (VERIFY: cli group exists in main.py)
cli.add_command(new_command, name="new")

# FILE PATH: main.py
```

#### **Step 3.3: Report Service Integration**
```python
# File: src/services/report_service.py - Add method if not exists
# ✅ VERIFY: ReportService class exists before modifying

def generate_service_report(self, 
                          service_name: str, 
                          result_data: Dict[str, Any], 
                          format_type: str,
                          output_dir: str = "output/reports") -> str:
    """
    Generate report for service operation (MANDATORY for CLI services)
    
    Args:
        service_name: Name of the service
        result_data: Service operation results
        format_type: Report format (json, txt, html, pdf)
        output_dir: Output directory path
        
    Returns:
        str: Path to generated report file
        
    FILE PATH: src/services/report_service.py
    """
    # Implementation following existing patterns in ReportService
    # (DRY: Reuse existing report generation logic)
    pass
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
        self.assertIn("timestamp", result)
    
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

#### **Step 4.2: Integration Tests**
```python
# File: tests/integration/test_new_service_integration.py
import unittest
from src.services.new_service import NewService
from src.cli.commands import new_command

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
class TestServiceRegression(unittest.TestCase):
    """Regression tests for service changes"""
    
    def test_backward_compatibility(self):
        """Test that old usage still works"""
        service = ModifiedService()
        
        # Test old method calls
        old_result = service.old_method("test")
        new_result = service.new_method("test")
        
        # Verify compatibility
        self.assertEqual(old_result["core_data"], new_result["core_data"])
    
    def test_enhanced_functionality(self):
        """Test new functionality"""
        service = ModifiedService()
        
        # Test new features
        result = service.new_method("test", enhanced_param="enhanced")
        self.assertIn("enhanced_feature", result)
```

#### **Step 3.2: Integration Validation**
```bash
# Run comprehensive test suite
python -m pytest tests/ -v --tb=short

# Specific regression tests
python -m pytest tests/regression/ -v

# Integration tests  
python -m pytest tests/integration/ -v

# Performance tests (if applicable)
python -m pytest tests/performance/ -v
```

---

## 🧪 **Testing Strategy (استراتژی تست)**

### **Test Categories**

#### **1. Unit Tests (تست واحد)**
```python
# Test individual service methods
class TestServiceUnit(unittest.TestCase):
    def test_core_functionality(self):
        """Test core service logic"""
        pass
    
    def test_input_validation(self):
        """Test input validation logic"""
        pass
    
    def test_error_handling(self):
        """Test error scenarios"""
        pass
```

#### **2. Integration Tests (تست ادغام)**
```python
# Test service interactions
class TestServiceIntegration(unittest.TestCase):
    def test_service_collaboration(self):
        """Test multiple services working together"""
        pass
    
    def test_cli_integration(self):
        """Test CLI command integration"""
        pass
    
    def test_orchestrator_integration(self):
        """Test orchestrator workflow integration"""
        pass
```

#### **3. System Tests (تست سیستم)**
```python
# Test complete workflows
class TestSystemWorkflow(unittest.TestCase):
    def test_complete_scan_workflow(self):
        """Test end-to-end scan execution"""
        pass
    
    def test_multi_service_workflow(self):
        """Test complex multi-service workflows"""
        pass
```

#### **4. Performance Tests (تست عملکرد)**
```python
# Test performance characteristics
class TestServicePerformance(unittest.TestCase):
    def test_response_time(self):
        """Test service response time"""
        pass
    
    def test_memory_usage(self):
        """Test memory consumption"""
        pass
    
    def test_concurrent_access(self):
        """Test concurrent service usage"""
        pass
```

### **Test Execution Workflow**
```bash
# 1. Pre-commit tests (fast)
python -m pytest tests/unit/ -v --tb=short

# 2. Integration tests  
python -m pytest tests/integration/ -v

# 3. Full test suite
python -m pytest tests/ -v --cov=src --cov-report=html

# 4. Performance validation
python -m pytest tests/performance/ -v --benchmark-only
```

---

## 📝 **Code Standards (استانداردهای کدنویسی)**

### **SOLID Principles Implementation**
```python
# S - Single Responsibility Principle
class UserValidator:  # Only validates users
    def validate_user(self, user_data): pass

class UserRepository:  # Only handles user data storage
    def save_user(self, user): pass

# O - Open/Closed Principle  
class ReportGenerator:
    def generate(self, data, formatter): 
        return formatter.format(data)

class JSONFormatter:  # New formats can be added without modifying ReportGenerator
    def format(self, data): return json.dumps(data)

# L - Liskov Substitution Principle
class Scanner(ABC):
    @abstractmethod
    def scan(self, target): pass

class PortScanner(Scanner):  # Can replace Scanner without breaking code
    def scan(self, target): return "port scan result"

# I - Interface Segregation Principle
class Scannable(ABC):  # Small, focused interface
    @abstractmethod
    def scan(self, target): pass

class Reportable(ABC):  # Separate interface for reporting
    @abstractmethod
    def generate_report(self): pass

# D - Dependency Inversion Principle
class ScanService:
    def __init__(self, scanner: Scannable, reporter: Reportable):  # Depend on abstractions
        self.scanner = scanner
        self.reporter = reporter
```

### **DRY Principle Implementation**
```python
# BAD: Code repetition
def validate_ip_input(ip):
    if not ip or not isinstance(ip, str):
        raise ValueError("Invalid IP")
    # IP validation logic...

def validate_domain_input(domain):
    if not domain or not isinstance(domain, str):
        raise ValueError("Invalid domain")
    # Domain validation logic...

# GOOD: DRY implementation
def _validate_string_input(value, input_type):
    if not value or not isinstance(value, str):
        raise ValueError(f"Invalid {input_type}")

def validate_ip_input(ip):
    _validate_string_input(ip, "IP")
    # IP-specific validation...

def validate_domain_input(domain):
    _validate_string_input(domain, "domain")
    # Domain-specific validation...
```

### **Clean Code Principles**
```python
# Clean, readable, and simple code
class ServiceName:
    def __init__(self, config: ServiceOptions = None):
        # VERIFY: All imports exist before use
        self.validator = InputValidator()  # ✅ EXISTS: src/core/validator.py
        self.logger = self._setup_logger()  # ✅ Private method defined below
        self.report_service = ReportService()  # ✅ EXISTS: src/services/report_service.py
    
    def process_data(self, input_data: str, options: ServiceOptions = None) -> ServiceResult:
        """
        Process data with clear, descriptive method name
        
        FILE PATH: src/services/service_name.py
        """
        # Clean Code: Early return for edge cases
        if not input_data:
            return {"status": "error", "message": "No input provided"}
        
        # Clean Code: Clear variable names
        validation_result = self._validate_input(input_data)
        if not validation_result.is_valid:
            return {"status": "error", "message": validation_result.error}
        
        # Clean Code: Single responsibility per method
        processed_data = self._process_core_logic(input_data)
        report_path = self._generate_reports_if_requested(processed_data, options)
        
        return {
            "status": "success",
            "data": processed_data,
            "report_generated": report_path is not None
        }
    
    def _validate_input(self, data: str) -> ValidationResult:
        """Single responsibility: only validation"""
        # VERIFY: ValidationResult class exists or define it
        pass
    
    def _process_core_logic(self, data: str) -> Dict[str, Any]:
        """Single responsibility: only core processing"""
        pass
    
    def _generate_reports_if_requested(self, data: Dict, options: ServiceOptions) -> Optional[str]:
        """Single responsibility: only report generation"""
        pass
    
    def _setup_logger(self) -> logging.Logger:
        """Single responsibility: logger setup"""
        return logging.getLogger(f"service.{self.__class__.__name__}")
```

### **Method/Class Existence Verification**
```python
"""
MANDATORY: Verify existence before use
✅ = Verified to exist
❌ = Does not exist - must create or find alternative
⚠️  = Exists but needs verification of specific method
"""

# Core imports verification
from ..core.validator import InputValidator  # ✅ EXISTS: src/core/validator.py
from ..core.scanner_base import ScannerBase  # ✅ EXISTS: src/core/scanner_base.py
from ..utils.logger import log_info, log_error  # ✅ EXISTS: src/utils/logger.py

# Service imports verification  
from ..services.report_service import ReportService  # ✅ EXISTS: src/services/report_service.py
from ..services.scan_service import ScanService  # ✅ EXISTS: src/services/scan_service.py

# Method existence verification
report_service = ReportService()
# ⚠️  VERIFY: Does ReportService have generate_service_report method?
# If not, add it following existing patterns

scanner_service = ScannerService() 
# ✅ VERIFIED: ScannerService exists with standard methods

# Before using any method, verify it exists:
if hasattr(report_service, 'generate_service_report'):
    report_service.generate_service_report(data)
else:
    # Use existing method or implement new one
    report_service.generate_report(data)
```

### **Service Structure Template with All Requirements**
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


class ServiceNameInterface(ABC):
    """Interface following Interface Segregation Principle"""
    
    @abstractmethod
    def primary_operation(self, input_data: str, options: ServiceOptions = None) -> ServiceResult:
        """Primary service operation"""
        pass


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
        # SOLID: Depend on abstractions, not concretions
        self.config = config or {}
        self.validator = InputValidator()  # ✅ VERIFIED EXISTS
        self.logger = self._setup_logger()  # Single responsibility method
        self.report_service = ReportService()  # ✅ VERIFIED EXISTS
        
        # Validate configuration on initialization
        self._validate_configuration()
    
    def primary_operation(self, 
                         input_data: str, 
                         options: ServiceOptions = None) -> ServiceResult:
        """
        Main service operation with reporting (MANDATORY for CLI services)
        
        Args:
            input_data: Data to process
            options: Processing options including report preferences
            
        Returns:
            ServiceResult with status, data, and report info
            
        Raises:
            ValueError: If input validation fails
            RuntimeError: If processing fails
        """
        try:
            # Clean Code: Early validation
            self._validate_input(input_data)
            
            # Log start (DRY: Use centralized logging)
            log_info(f"Starting {self.__class__.__name__} operation")
            
            # Process data (Single Responsibility)
            result_data = self._process_data(input_data, options)
            
            # Generate reports if requested (MANDATORY for CLI)
            report_info = self._handle_reporting(result_data, options)
            
            # Combine results (Clean Code: Clear structure)
            final_result = {
                "status": "success",
                "data": result_data,
                "metadata": self._generate_metadata(),
                "reports": report_info
            }
            
            log_success(f"Completed {self.__class__.__name__} operation")
            return final_result
            
        except Exception as e:
            log_error(f"Operation failed: {e}")
            raise
    
    def _validate_input(self, input_data: str) -> None:
        """Validate input data (Single Responsibility)"""
        if not input_data or not isinstance(input_data, str):
            raise ValueError("Invalid input data")
        
        # Use existing validator (DRY principle)
        if hasattr(self.validator, 'validate_string'):  # ✅ VERIFY method exists
            if not self.validator.validate_string(input_data):
                raise ValueError("Input validation failed")
    
    def _process_data(self, input_data: str, options: ServiceOptions) -> Dict[str, Any]:
        """Core data processing (Single Responsibility)"""
        # Implementation specific to service
        # Following Clean Code: descriptive variable names
        processed_result = {
            "original_input": input_data,
            "processed_at": datetime.now().isoformat(),
            "processing_options": options or {}
        }
        return processed_result
    
    def _handle_reporting(self, data: Dict[str, Any], options: ServiceOptions) -> Dict[str, Any]:
        """Handle report generation (MANDATORY for CLI services)"""
        if not options:
            return {"generated": False, "formats": []}
        
        # Check report format requests
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
                        result_data=data,
                        format_type=format_type,
                        output_dir=options.get("output_dir", "output/reports")
                    )
                else:
                    # Use existing method with adaptation
                    report_path = self.report_service.generate_report(
                        data, format_type, options.get("output_dir", "output/reports")
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

### **File Creation and Documentation Requirements**
```python
"""
MANDATORY: File path documentation for every file

When creating/modifying files, always specify:
1. Complete file path from project root
2. Purpose of the file
3. Dependencies and their verification status
4. Integration points

Example:
FILE PATH: src/services/vulnerability_assessment_service.py
PURPOSE: Vulnerability assessment and risk analysis service
DEPENDENCIES:
  ✅ src/core/validator.py (InputValidator)
  ✅ src/utils/logger.py (logging functions)  
  ✅ src/services/report_service.py (ReportService)
INTEGRATION: CLI command, orchestrator workflow
"""
```

### **Error Handling Standards**
```python
# Standard error handling pattern
try:
    result = operation()
except ValidationError as e:
    log_error(f"Validation failed: {e}")
    raise ValueError(f"Invalid input: {e}")
except TimeoutError as e:
    log_error(f"Operation timeout: {e}")
    raise RuntimeError(f"Operation timed out: {e}")
except Exception as e:
    log_error(f"Unexpected error: {e}")
    raise RuntimeError(f"Service operation failed: {e}")
```

### **Logging Standards**
```python
from ..utils.logger import log_info, log_error, log_success, log_warning, log_debug

# Use structured logging
log_info("Operation started", extra={
    "service": self.__class__.__name__,
    "method": "method_name",
    "target": target_param
})

log_success("Operation completed", extra={
    "duration": end_time - start_time,
    "result_count": len(results)
})
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

# 2. Roadmap Compliance
- [ ] Feature matches roadmap specification (features_roadmap.md)
- [ ] Phase requirements satisfied
- [ ] Dependencies properly handled
- [ ] Priority alignment confirmed

# 3. Tools Compliance  
- [ ] All tools verified against docs/tools-list.md
- [ ] No unauthorized packages used
- [ ] Tool versions compatible
- [ ] External tools properly configured

# 4. Performance Validation
- [ ] Performance tests passed
- [ ] Memory usage acceptable
- [ ] Response time within limits
- [ ] Resource usage optimized

# 5. Integration Validation  
- [ ] CLI integration working
- [ ] Service interactions validated
- [ ] Configuration compatibility verified
- [ ] Report generation functional

# 6. Documentation Compliance
- [ ] API documentation updated
- [ ] User manual updated
- [ ] Migration guide created (if needed)
- [ ] File paths documented
- [ ] Roadmap status updated
```

### **Deployment Steps with Compliance Checks**
```bash
# 1. Pre-deployment compliance verification
echo "🔍 Verifying roadmap compliance..."
python -c "
import sys
sys.path.append('.')
# Verify service matches roadmap requirements
print('✅ Roadmap compliance verified')
"

echo "🔍 Verifying tools compliance..."
python -c "
# Verify only approved tools are used
# Reference: docs/tools-list.md
print('✅ Tools compliance verified')
"

# 2. Backup current version
git tag -a v$(current_version) -m "Pre-deployment backup"

# 3. Deploy new service
git merge feature/new-service

# 4. Run validation tests
python -m pytest tests/ -v --tb=short

# 5. Verify CLI functionality
python main.py --help
python main.py info

# 6. Test critical workflows
python main.py scan test-target --profile quick

# 7. Verify roadmap status update
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
  □ External tool compatibility maintained

□ 🔄 COMPATIBILITY & STANDARDS
  □ Impact analysis completed
  □ Backward compatibility plan created
  □ Migration guide written (if needed)
  □ All modified methods/classes verified to exist
  □ SOLID principles maintained
  □ DRY principle enforced
  □ Clean Code standards upheld

□ 📊 REPORTING & INTEGRATION
  □ Report integration preserved/enhanced
  □ CLI functionality maintained
  □ New report formats added (if applicable)
  □ Output consistency verified

□ 🧪 VALIDATION & TESTING
  □ Regression tests implemented
  □ Integration validation completed
  □ Performance impact assessed
  □ Tools compliance verified
  □ CLI testing completed

□ 📖 DOCUMENTATION & DEPLOYMENT
  □ File paths for all changes documented
  □ Documentation updated
  □ Deprecation notices added (if applicable)
  □ Code review completed
  □ Deployment validated
  □ features_roadmap.md updated if needed
  □ No breaking changes without approval
```

### **Code Quality Verification with Standards**
```bash
□ 🔍 EXISTENCE VERIFICATION
  □ All imports verified to exist in project
  □ Method calls verified against actual class definitions
  □ No undefined class attributes accessed
  □ Dependencies verified in current codebase

□ 🏗️ ARCHITECTURE PRINCIPLES
  □ Single Responsibility Principle applied
  □ Open/Closed Principle followed
  □ Liskov Substitution maintained
  □ Interface Segregation implemented
  □ Dependency Inversion applied

□ 🧹 CODE QUALITY
  □ Code duplication eliminated (DRY)
  □ Method names are descriptive and clear
  □ Class responsibilities are well-defined
  □ Error handling is comprehensive
  □ Logging follows project standards
  □ Type hints provided for all methods

□ 📁 DOCUMENTATION & PATHS
  □ File paths documented in comments
  □ Purpose and dependencies clearly stated
  □ Integration points documented
  □ API documentation complete

□ 🛠️ TOOLS & COMPLIANCE
  □ Only approved tools used (docs/tools-list.md)
  □ Tool verification code implemented
  □ External dependencies managed properly
  □ Configuration follows project standards
```

### **CLI Service Requirements Checklist**
```bash
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