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

### **4. Development Workflow**
- **Get approval for long files** (>100 lines) before creation
- Progressive development with regular validation
- Test-driven approach with >90% coverage
- Document while coding, not after

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
- [ ] Verify all imported methods/classes exist
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

class ServiceName:
    """Single responsibility service implementation"""
    
    def __init__(self):
        # Verify all dependencies exist
        # Initialize with minimal complexity
        
    def main_function(self):
        # Core functionality
        # Proper error handling
        # Logging at appropriate levels
        
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
2. **Creating unnecessary complexity** → Keep it simple and focused
3. **Skipping error handling** → Every external call needs error handling
4. **Missing CLI integration** → All services need CLI access with reporting
5. **Ignoring existing patterns** → Study and follow current code structure
6. **Breaking changes** → Never modify existing APIs without approval
7. **Incomplete testing** → Test all paths, especially error scenarios

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

---

**This guide ensures consistent, high-quality development across all framework features.**