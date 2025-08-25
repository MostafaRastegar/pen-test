# 🎯 Development Guide - Auto-Pentest Framework
## Strategic Guidelines for Consistent Development

### 📋 **Version**: v2.0 | **Path**: docs/development_guide.md

---

## 🗺️ **Pre-Development Requirements**

### **Step 1: Reference Documentation Review**
```bash
1. features_roadmap.md          # Feature approval and priority
2. docs/tools-list.md           # Approved tools and packages only
3. Current codebase structure   # Understand existing architecture
```

### **Step 2: Development Approval**
- Feature exists in roadmap with appropriate phase/priority
- All required tools are in approved tools list
- Dependencies verified and available
- Timeline and scope defined

---

## 🚨 **Development Rules (Non-Negotiable)**

### **1. Backward Compatibility**
- Never break existing APIs, CLI commands, or configurations
- All existing services must continue working without changes

### **2. Code Quality Standards**
- **Verify before use**: Check all methods/classes exist before implementation
- **SOLID principles**: Single responsibility, clean interfaces
- **DRY**: No code duplication
- **Clean code**: Clear naming, simple logic, proper documentation
- **File paths**: Document all created/modified file paths in code comments

### **3. Service Requirements**
- Each service has one primary responsibility
- All CLI services must include reporting system (JSON, TXT minimum)
- Integration with existing ReportService
- Proper error handling and logging

### **4. MANDATORY: Report Service Integration**
**⚠️ CRITICAL REMINDER: هر سرویس جدید باید به سیستم گزارش‌گیری متصل شود!**
- Every new service MUST integrate with `ReportService`
- All scan results MUST generate reports in multiple formats
- Use `_handle_report_generation()` method pattern
- Support JSON, HTML, PDF, TXT formats minimum
- Connect service output directly to ReportService.generate_reports()

### **4. Development Workflow**
- **Get approval for long files** (>100 lines) before creation
- Progressive development with regular validation
- Test-driven approach with >90% coverage
- Document while coding, not after

---

## ⚠️ **CRITICAL: Import and Method Verification**

### **🔍 MANDATORY VERIFICATION BEFORE ANY DEVELOPMENT**
```
تمامی مواردی که در این فایل ها import کردی و استفاده کردی را یکی یکی بررسی کن 
ببین متود هایی از درون آنها صدا زدی آیا وجود دارند یا خیر.
میخوام که تک تک بررسی بشه و مطمن بشی.
```

### **Verification Checklist:**
- [ ] **Every import statement** - Verify the module/package exists and is available
- [ ] **Every method call** - Check method exists in the imported class/module
- [ ] **Every class instantiation** - Confirm class exists and constructor parameters are correct  
- [ ] **Every attribute access** - Verify object attributes exist and are accessible
- [ ] **Every function call** - Check function signature matches your usage

### **How to Verify:**
1. **Check official documentation** of imported libraries
2. **Inspect source code** of custom modules before using them
3. **Test imports** in Python REPL before implementation
4. **Verify version compatibility** of external packages
5. **Double-check custom classes** exist in project codebase

---

## ✅ **Implementation Checklist**

### **Before Starting**
- [ ] Feature approved in roadmap
- [ ] Tools verified in approved list
- [ ] Dependencies mapped
- [ ] Architecture plan reviewed

### **During Development**
- [ ] Use only approved tools from docs/tools-list.md
- [ ] Follow SOLID and DRY principles
- [ ] **VERIFY ALL IMPORTS AND METHODS EXIST** ⚠️
- [ ] **INTEGRATE WITH ReportService** ⚠️ (Import + _handle_report_generation method)
- [ ] Implement proper error handling
- [ ] Add comprehensive logging
- [ ] Document file paths in comments

### **Before Completion**
- [ ] All functionality tested (unit + integration)
- [ ] CLI integration working with report options
- [ ] Documentation complete and accurate
- [ ] Backward compatibility verified
- [ ] Performance acceptable
- [ ] Code review standards met

---

## 🛠️ **Service Development Template**

### **Standard Service Structure**
```python
"""
File: services/[service_name]_service.py
Purpose: [Clear single responsibility]
Dependencies: [List all dependencies with verification]
CLI Integration: Yes/No
Reporting: JSON, TXT, [additional formats]
"""

# MANDATORY IMPORT - Always include ReportService
from ..services.report_service import ReportService  # ✅ VERIFIED

class ServiceName:
    """Single responsibility service implementation"""
    
    def __init__(self):
        # Verify all dependencies exist
        # Initialize with minimal complexity
        self.report_service = ReportService()  # ⚠️ MANDATORY FOR ALL SERVICES
        
    def main_function(self):
        # Core functionality
        # Proper error handling
        # Logging at appropriate levels
        
        # ⚠️ MANDATORY: Always return results for reporting
        return {
            "status": "success",
            "results": {...},
            "metadata": {...}
        }
    
    def _handle_report_generation(self, result: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """
        ⚠️ MANDATORY: Handle report generation for CLI services
        Following DRY principle by reusing ReportService
        """
        if not options.get("generate_reports"):
            return {"generated": False}
            
        # Generate reports using ReportService
        self.report_service.generate_reports(result, options)
        
        return {"generated": True, "formats": self._get_requested_formats(options)}
        
    def generate_report(self, format='json'):
        # Integration with ReportService
        # Support multiple formats
```

### **CLI Integration Pattern**
```python
# Add to cli/cli_main.py or appropriate CLI module
@click.command()
@click.option('--output-format', type=click.Choice(['json', 'txt', 'html']), 
              default='json', help='Report format')
@click.option('--output-file', help='Output file path')
def service_command():
    """Service description and usage"""
    # Implementation with mandatory reporting options
```

---

## 🧪 **Testing Requirements**

### **Test Coverage Standards**
- **Unit tests**: >90% coverage for all new services
- **Integration tests**: All CLI commands and workflows
- **Regression tests**: Verify no existing functionality broken

### **Test Structure**
```python
# tests/test_[service_name].py
class TestServiceName:
    def test_basic_functionality(self):
        # Core functionality tests
        
    def test_error_handling(self):
        # Error scenarios
        
    def test_cli_integration(self):
        # CLI command execution
        
    def test_reporting(self):
        # Report generation in all formats
```

---

## 📋 **File Management Standards**

### **File Creation Rules**
- **Long files (>100 lines)**: Get approval before creation
- **File paths**: Always specify complete paths
- **Documentation**: Include file purpose and dependencies in header
- **Naming**: Clear, descriptive names following project conventions

### **Modification Guidelines**
- **Existing files**: Maintain existing patterns and interfaces
- **New additions**: Follow established architectural patterns
- **Dependencies**: Verify all imports and method calls exist
- **Testing**: Update or add tests for all modifications

---

## 🚫 **Common Pitfalls to Avoid**

1. **Using non-existent methods/classes** → Always verify before use
2. **Forgetting ReportService integration** → Every service MUST connect to reporting system
3. **Creating unnecessary complexity** → Keep it simple and focused
4. **Skipping error handling** → Every external call needs error handling
5. **Missing CLI integration** → All services need CLI access with reporting
6. **Ignoring existing patterns** → Study and follow current code structure
7. **Breaking changes** → Never modify existing APIs without approval
8. **Incomplete testing** → Test all paths, especially error scenarios

---

## 📚 **Quick Reference**

### **Essential Files to Check**
- `features_roadmap.md` - Feature approval status
- `docs/tools-list.md` - Approved tools only
- `services/` - Existing service patterns
- `cli/` - CLI integration patterns
- `tests/` - Testing patterns and coverage

### **Development Flow**
```
Reference Check → Approval → Plan → Implement → Test → Document → Review → Deploy
```

### **Key Principles**
- **Consistency**: Follow existing patterns
- **Quality**: Clean, tested, documented code
- **Compatibility**: Never break existing functionality
- **Simplicity**: One responsibility per service
- **Integration**: CLI + Reporting for all services
- **⚠️ REPORTING**: Every service MUST integrate with ReportService

---

**This guide ensures consistent, high-quality development across all framework features.**
