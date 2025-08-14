"""
Scan Service
Handles scan orchestration and workflow management
Following Single Responsibility and Dependency Inversion principles
"""

import sys
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from ..utils.target_parser import TargetParser
from ..utils.logger import log_info, log_error, log_success, log_warning, log_debug
from ..orchestrator import (
    create_quick_workflow,
    create_full_workflow,
    create_web_workflow,
    ScanWorkflow,
)
from ..orchestrator.workflow import WorkflowStatus, ScanPhase
from ..services.report_service import ReportService
from ..core.validator import InputValidator


class ScanService:
    """Service for managing scan operations"""

    def __init__(self):
        self.validator = InputValidator()
        self.target_parser = TargetParser()
        self.report_service = ReportService()

    def execute_scan(self, target: str, options: Dict[str, Any]) -> None:
        """
        Execute a complete scan workflow

        Args:
            target: Target to scan
            options: Scan options from CLI
        """
        try:
            log_info(f"🎯 Starting scan for target: {target}")

            # Validate and parse target
            parsed_target = self._validate_and_parse_target(target)

            # Create workflow based on profile
            workflow = self._create_workflow(parsed_target, options)

            # Execute workflow
            workflow_result = self._execute_workflow(workflow, options)

            # Generate reports
            self._generate_reports(workflow_result, options)

            log_success("✅ Scan completed successfully")

        except KeyboardInterrupt:
            log_warning("🛑 Scan interrupted by user")
            sys.exit(1)
        except Exception as e:
            log_error(f"💥 Scan failed: {e}")
            self._handle_scan_error(e)
            sys.exit(1)

    def _validate_and_parse_target(self, target: str) -> Dict[str, str]:
        """Validate and parse target"""
        if not self.validator.is_valid_target(target):
            raise ValueError(f"Invalid target: {target}")

        parsed = self.target_parser.parse_target(target)
        log_info(f"📍 Parsed target: {parsed['host']}")
        return parsed

    def _create_workflow(
        self, target: Dict[str, str], options: Dict[str, Any]
    ) -> ScanWorkflow:
        """Create workflow based on profile"""
        profile = options.get("profile", "quick")

        log_info(f"🔧 Creating {profile} workflow")

        workflow_creators = {
            "quick": self._create_quick_workflow,
            "web": self._create_web_workflow,
            "full": self._create_full_workflow,
            "custom": self._create_custom_workflow,
        }

        creator = workflow_creators.get(profile)
        if not creator:
            raise ValueError(f"Unknown profile: {profile}")

        return creator(target, self._extract_workflow_options(options))

    def _create_quick_workflow(self, target: Dict[str, str], options: Dict[str, Any]):
        """Create quick workflow with proper target formats"""
        from ..orchestrator.workflow import ScanWorkflow
        from datetime import datetime

        workflow_id = f"quick_{int(datetime.now().timestamp())}"
        workflow = ScanWorkflow(workflow_id)

        # Add port scanner with correct target format and proper options
        port_options = {
            "ports": "quick",  # Use predefined quick profile
            "timing": 4,
            "no_ping": False,
        }

        workflow.add_scan_task(
            "port_scanner",
            target["host"],  # Use host, not original URL
            options=port_options,
            timeout=options.get("timeout", 300),
        )

        return workflow

    def _create_web_workflow(self, target: Dict[str, str], options: Dict[str, Any]):
        """Create web workflow with proper target formats"""
        from ..orchestrator.workflow import ScanWorkflow
        from datetime import datetime

        workflow_id = f"web_{int(datetime.now().timestamp())}"
        workflow = ScanWorkflow(workflow_id)

        # Add port scanner for web ports
        port_options = {"ports": "80,443,8080,8443", "timing": 4, "no_ping": False}

        workflow.add_scan_task(
            "port_scanner", target["host"], options=port_options, priority=10
        )

        # Add web scanner
        web_options = {"use_nikto": True, "include_headers": True}

        workflow.add_scan_task(
            "web_scanner",
            target["url"],  # Web scanner needs URL
            options=web_options,
            dependencies=["port_scanner"],
            priority=8,
        )

        # Add directory scanner
        dir_options = {"wordlist": "common", "extensions": ["php", "asp", "jsp", "txt"]}

        workflow.add_scan_task(
            "directory_scanner",
            target["url"],  # Directory scanner needs URL
            options=dir_options,
            dependencies=["web_scanner"],
            priority=6,
        )

        # Add SSL scanner
        ssl_options = {"port": 443, "cipher_enum": True, "cert_info": True}

        workflow.add_scan_task(
            "ssl_scanner",
            target["host"],  # SSL scanner needs host
            options=ssl_options,
            dependencies=["port_scanner"],
            priority=7,
        )

        return workflow

    def _create_full_workflow(self, target: Dict[str, str], options: Dict[str, Any]):
        """Create full workflow with proper target formats"""
        from ..orchestrator.workflow import ScanWorkflow
        from datetime import datetime

        workflow_id = f"full_{int(datetime.now().timestamp())}"
        workflow = ScanWorkflow(workflow_id)

        # Phase 1: Reconnaissance
        port_options = {
            "ports": "top1000",
            "timing": 3,
            "no_ping": False,
            "aggressive": True,
        }

        workflow.add_scan_task(
            "port_scanner", target["host"], options=port_options, priority=10
        )

        dns_options = {
            "subdomain_enum": True,
            "zone_transfer": True,
            "dns_bruteforce": True,
        }

        workflow.add_scan_task(
            "dns_scanner",
            target["domain"],  # DNS needs domain
            options=dns_options,
            priority=9,
        )

        # Phase 2: Web vulnerability assessment
        web_options = {
            "use_nikto": True,
            "include_headers": True,
            "technology_detection": True,
        }

        workflow.add_scan_task(
            "web_scanner",
            target["url"],
            options=web_options,
            dependencies=["port_scanner"],
            priority=8,
        )

        dir_options = {
            "wordlist": "comprehensive",
            "extensions": ["php", "asp", "jsp", "txt", "bak", "old"],
            "recursive": True,
        }

        workflow.add_scan_task(
            "directory_scanner",
            target["url"],
            options=dir_options,
            dependencies=["web_scanner"],
            priority=6,
        )

        ssl_options = {
            "port": 443,
            "cipher_enum": True,
            "cert_info": True,
            "vulnerabilities": True,
        }

        workflow.add_scan_task(
            "ssl_scanner",
            target["host"],
            options=ssl_options,
            dependencies=["port_scanner"],
            priority=7,
        )

        return workflow

    def _create_custom_workflow(
        self, target: Dict[str, str], options: Dict[str, Any]
    ) -> ScanWorkflow:
        """Create custom workflow based on selected scanners"""
        from ..orchestrator.workflow_builder import WorkflowBuilder

        builder = WorkflowBuilder()

        # Add scanners based on options
        if options.get("include_port"):
            builder.add_port_scanner(
                ports=options.get("ports", "quick"),
                scan_type=options.get("scan_type", "tcp"),
            )
        if options.get("include_dns"):
            builder.add_dns_scanner(subdomain_enum=options.get("subdomain_enum", True))
        if options.get("include_web"):
            builder.add_web_scanner(use_nikto=options.get("use_nikto", True))
        if options.get("include_directory"):
            builder.add_directory_scanner(tool=options.get("directory_tool", "dirb"))
        if options.get("include_ssl"):
            builder.add_ssl_scanner(cipher_enum=options.get("cipher_enum", True))

        # Set workflow options
        builder.set_options(
            timeout=options.get("timeout", 300),
            parallel=not options.get("sequential", False),
        )

        return builder.build(target)

    def _extract_workflow_options(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """Extract workflow-specific options"""
        return {
            "parallel": not options.get("sequential", False),
            "timeout": options.get("timeout", 1800),
            "execution_mode": "parallel" if options.get("parallel") else "sequential",
            "fail_fast": options.get("fail_fast", False),
        }

    def _execute_workflow(self, workflow: ScanWorkflow, options: Dict[str, Any]):
        """Execute the workflow"""
        log_info("🚀 Executing workflow...")

        # Determine execution mode
        parallel_mode = not options.get("sequential", False)
        fail_fast = options.get("fail_fast", False)

        # Execute workflow
        result = workflow.execute(parallel=parallel_mode, fail_fast=fail_fast)

        # Check status
        if result.status != WorkflowStatus.COMPLETED:
            raise RuntimeError(f"Workflow failed with status: {result.status}")

        log_success(f"✅ Workflow completed: {len(result.tasks)} tasks executed")
        return result

    def _generate_reports(self, workflow_result, options: Dict[str, Any]) -> None:
        """Generate reports based on options"""
        if not self._should_generate_reports(options):
            return

        log_info("📄 Generating reports...")

        try:
            self.report_service.generate_reports(workflow_result, options)
            log_success("✅ Reports generated successfully")
        except Exception as e:
            log_error(f"❌ Report generation failed: {e}")
            # Don't fail the entire scan if only reports fail

    def _should_generate_reports(self, options: Dict[str, Any]) -> bool:
        """Check if reports should be generated"""
        report_options = [
            "json_report",
            "html_report",
            "pdf_report",
            "all_reports",
            "csv_output",
            "txt_output",
        ]
        return any(options.get(opt, False) for opt in report_options)

    def _handle_scan_error(self, error: Exception) -> None:
        """Handle scan errors with helpful messages"""
        error_str = str(error).lower()

        if "nmap" in error_str or "command failed" in error_str:
            log_error("⚠️ Nmap execution issue. Try:")
            log_error("   1. sudo apt install nmap")
            log_error("   2. Check target connectivity")
            log_error("   3. Run with sudo for OS detection")
        elif "timeout" in error_str:
            log_error("⚠️ Scan timeout. Try:")
            log_error("   1. Increase timeout: --timeout 1800")
            log_error("   2. Use simpler profile: --profile quick")
            log_error("   3. Run scanners individually")
        elif "permission" in error_str:
            log_error("⚠️ Permission issue. Try:")
            log_error("   1. Run with sudo")
            log_error("   2. Check file permissions")
        elif "network" in error_str or "connection" in error_str:
            log_error("⚠️ Network issue. Try:")
            log_error("   1. Check internet connection")
            log_error("   2. Verify target is reachable")
            log_error("   3. Check firewall settings")

        log_debug(f"Full error details: {error}")
