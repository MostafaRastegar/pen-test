"""
Workflow Orchestrator - Manages scan pipelines and execution flow
"""

import asyncio
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable
from enum import Enum
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

from src.core import ScannerBase, ScanResult, ScanStatus, ScanSeverity
from src.scanners.recon.port_scanner import PortScanner
from src.scanners.recon.dns_scanner import DNSScanner
from src.scanners.vulnerability.web_scanner import WebScanner
from src.scanners.vulnerability.directory_scanner import DirectoryScanner
from src.scanners.vulnerability.ssl_scanner import SSLScanner
from src.utils.logger import log_info, log_error, log_warning, log_success


class WorkflowStatus(Enum):
    """Workflow execution status"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanPhase(Enum):
    """Different phases of scanning"""

    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    REPORTING = "reporting"


@dataclass
class ScanTask:
    """Individual scan task definition"""

    scanner_name: str
    scanner_class: type
    target: str
    options: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    phase: ScanPhase = ScanPhase.RECONNAISSANCE
    priority: int = 1
    timeout: int = 300
    required: bool = True

    # Runtime fields
    status: ScanStatus = ScanStatus.PENDING
    result: Optional[ScanResult] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error: Optional[str] = None


@dataclass
class WorkflowResult:
    """Complete workflow execution result"""

    workflow_id: str
    target: str
    status: WorkflowStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    tasks: List[ScanTask] = field(default_factory=list)
    aggregated_result: Optional[ScanResult] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_results_by_phase(self, phase: ScanPhase) -> List[ScanResult]:
        """Get scan results filtered by phase"""
        return [
            task.result
            for task in self.tasks
            if task.phase == phase and task.result is not None
        ]

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Get all findings from all successful scans"""
        findings = []
        for task in self.tasks:
            if task.result and task.result.findings:
                findings.extend(task.result.findings)
        return findings

    def get_findings_by_severity(self, severity: ScanSeverity) -> List[Dict[str, Any]]:
        """Get findings filtered by severity"""
        return [
            f for f in self.get_all_findings() if f.get("severity") == severity.value
        ]


class ScanWorkflow:
    """
    Orchestrates multiple scanners in a coordinated workflow
    """

    def __init__(self, workflow_id: str, max_workers: int = 5):
        """
        Initialize workflow orchestrator

        Args:
            workflow_id: Unique workflow identifier
            max_workers: Maximum number of concurrent scanner threads
        """
        self.workflow_id = workflow_id
        self.max_workers = max_workers

        # Available scanners
        self.available_scanners = {
            "port_scanner": PortScanner,
            "dns_scanner": DNSScanner,
            "web_scanner": WebScanner,
            "directory_scanner": DirectoryScanner,
            "ssl_scanner": SSLScanner,
        }

        # Workflow state
        self.tasks: List[ScanTask] = []
        self.status = WorkflowStatus.PENDING
        self.progress_callback: Optional[Callable] = None

    def add_scan_task(
        self,
        scanner_name: str,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        dependencies: Optional[List[str]] = None,
        phase: ScanPhase = ScanPhase.RECONNAISSANCE,
        priority: int = 1,
        timeout: int = 300,
        required: bool = True,
    ) -> ScanTask:
        """
        Add a scan task to the workflow

        Args:
            scanner_name: Name of scanner to use
            target: Target to scan
            options: Scanner-specific options
            dependencies: List of scanner names this task depends on
            phase: Scan phase this task belongs to
            priority: Task priority (higher = earlier execution)
            timeout: Task timeout in seconds
            required: Whether task failure should fail the workflow

        Returns:
            ScanTask: Created scan task
        """
        if scanner_name not in self.available_scanners:
            raise ValueError(f"Unknown scanner: {scanner_name}")

        task = ScanTask(
            scanner_name=scanner_name,
            scanner_class=self.available_scanners[scanner_name],
            target=target,
            options=options or {},
            dependencies=dependencies or [],
            phase=phase,
            priority=priority,
            timeout=timeout,
            required=required,
        )

        self.tasks.append(task)
        return task

    def create_standard_workflow(
        self,
        target: str,
        profile: str = "full",
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Create a standard scan workflow based on profile

        Args:
            target: Target to scan
            profile: Scan profile (quick, full, web)
            options: Global options to apply to all scanners
        """
        options = options or {}

        if profile == "quick":
            # Quick workflow: port scan only
            self.add_scan_task(
                "port_scanner",
                target,
                options={"ports": "quick", **options},
                phase=ScanPhase.RECONNAISSANCE,
                priority=10,
            )

        elif profile == "web":
            # Web-focused workflow
            self.add_scan_task(
                "port_scanner",
                target,
                options={"ports": "80,443,8080,8443", **options},
                phase=ScanPhase.RECONNAISSANCE,
                priority=10,
            )

            self.add_scan_task(
                "web_scanner",
                target,
                options={"use_nikto": True, **options},
                dependencies=["port_scanner"],
                phase=ScanPhase.VULNERABILITY_ASSESSMENT,
                priority=8,
            )

            self.add_scan_task(
                "directory_scanner",
                target,
                options={"wordlist": "common", **options},
                dependencies=["web_scanner"],
                phase=ScanPhase.VULNERABILITY_ASSESSMENT,
                priority=6,
            )

            self.add_scan_task(
                "ssl_scanner",
                target,
                options={"port": 443, **options},
                dependencies=["port_scanner"],
                phase=ScanPhase.VULNERABILITY_ASSESSMENT,
                priority=7,
            )

        elif profile == "full":
            # Comprehensive workflow

            # Phase 1: Reconnaissance
            self.add_scan_task(
                "port_scanner",
                target,
                options={"ports": "top1000", **options},
                phase=ScanPhase.RECONNAISSANCE,
                priority=10,
            )

            self.add_scan_task(
                "dns_scanner",
                target,
                options={"zone_transfer": True, "subdomain_enum": True, **options},
                phase=ScanPhase.RECONNAISSANCE,
                priority=9,
                required=False,  # DNS might not always work
            )

            # Phase 2: Vulnerability Assessment
            self.add_scan_task(
                "web_scanner",
                target,
                options={"use_nikto": True, **options},
                dependencies=["port_scanner"],
                phase=ScanPhase.VULNERABILITY_ASSESSMENT,
                priority=8,
            )

            self.add_scan_task(
                "directory_scanner",
                target,
                options={"wordlist": "big", "extensions": True, **options},
                dependencies=["web_scanner"],
                phase=ScanPhase.VULNERABILITY_ASSESSMENT,
                priority=6,
            )

            self.add_scan_task(
                "ssl_scanner",
                target,
                options={"port": 443, "use_sslscan": True, **options},
                dependencies=["port_scanner"],
                phase=ScanPhase.VULNERABILITY_ASSESSMENT,
                priority=7,
            )

    def set_progress_callback(self, callback: Callable[[str, int, int], None]) -> None:
        """
        Set progress callback function

        Args:
            callback: Function that receives (task_name, completed, total)
        """
        self.progress_callback = callback

    def _notify_progress(self, task_name: str) -> None:
        """Notify progress callback if set"""
        if self.progress_callback:
            completed = len(
                [
                    t
                    for t in self.tasks
                    if t.status in [ScanStatus.COMPLETED, ScanStatus.FAILED]
                ]
            )
            total = len(self.tasks)
            self.progress_callback(task_name, completed, total)

    def _get_ready_tasks(self) -> List[ScanTask]:
        """Get tasks that are ready to execute (dependencies met)"""
        ready_tasks = []

        for task in self.tasks:
            if task.status != ScanStatus.PENDING:
                continue

            # Check if all dependencies are completed
            dependencies_met = True
            for dep_name in task.dependencies:
                dep_task = next(
                    (t for t in self.tasks if t.scanner_name == dep_name), None
                )
                if not dep_task or dep_task.status != ScanStatus.COMPLETED:
                    dependencies_met = False
                    break

            if dependencies_met:
                ready_tasks.append(task)

        # Sort by priority (higher first)
        ready_tasks.sort(key=lambda t: t.priority, reverse=True)
        return ready_tasks

    def _execute_task(self, task: ScanTask) -> ScanTask:
        """
        Execute a single scan task

        Args:
            task: Task to execute

        Returns:
            ScanTask: Updated task with results
        """
        try:
            task.status = ScanStatus.RUNNING
            task.start_time = datetime.now()

            log_info(f"Executing {task.scanner_name} on {task.target}")

            # Create scanner instance
            scanner = task.scanner_class(timeout=task.timeout)

            # Execute scan
            result = scanner.scan(task.target, task.options)

            task.result = result
            task.status = (
                ScanStatus.COMPLETED
                if result.status == ScanStatus.COMPLETED
                else ScanStatus.FAILED
            )
            task.end_time = datetime.now()

            log_success(
                f"Completed {task.scanner_name}: {len(result.findings)} findings"
            )

        except Exception as e:
            task.status = ScanStatus.FAILED
            task.error = str(e)
            task.end_time = datetime.now()
            log_error(f"Failed {task.scanner_name}: {e}")

        self._notify_progress(task.scanner_name)
        return task

    def execute(self, parallel: bool = True, fail_fast: bool = False) -> WorkflowResult:
        """
        Execute the workflow

        Args:
            parallel: Whether to execute tasks in parallel where possible
            fail_fast: Whether to stop on first required task failure

        Returns:
            WorkflowResult: Complete workflow results
        """
        self.status = WorkflowStatus.RUNNING
        start_time = datetime.now()

        log_info(f"Starting workflow {self.workflow_id} with {len(self.tasks)} tasks")

        try:
            if parallel:
                self._execute_parallel(fail_fast)
            else:
                self._execute_sequential(fail_fast)

            # Aggregate results
            aggregated_result = self._aggregate_results()

            # Determine final status
            failed_required = [
                t for t in self.tasks if t.required and t.status == ScanStatus.FAILED
            ]
            final_status = (
                WorkflowStatus.FAILED if failed_required else WorkflowStatus.COMPLETED
            )

            self.status = final_status

            workflow_result = WorkflowResult(
                workflow_id=self.workflow_id,
                target=self.tasks[0].target if self.tasks else "unknown",
                status=final_status,
                start_time=start_time,
                end_time=datetime.now(),
                tasks=self.tasks.copy(),
                aggregated_result=aggregated_result,
                metadata={
                    "total_tasks": len(self.tasks),
                    "successful_tasks": len(
                        [t for t in self.tasks if t.status == ScanStatus.COMPLETED]
                    ),
                    "failed_tasks": len(
                        [t for t in self.tasks if t.status == ScanStatus.FAILED]
                    ),
                    "total_findings": (
                        len(aggregated_result.findings) if aggregated_result else 0
                    ),
                    "execution_mode": "parallel" if parallel else "sequential",
                },
            )

            log_success(
                f"Workflow {self.workflow_id} completed: {workflow_result.metadata}"
            )
            return workflow_result

        except Exception as e:
            self.status = WorkflowStatus.FAILED
            log_error(f"Workflow {self.workflow_id} failed: {e}")

            return WorkflowResult(
                workflow_id=self.workflow_id,
                target=self.tasks[0].target if self.tasks else "unknown",
                status=WorkflowStatus.FAILED,
                start_time=start_time,
                end_time=datetime.now(),
                tasks=self.tasks.copy(),
                metadata={"error": str(e)},
            )

    def _execute_sequential(self, fail_fast: bool) -> None:
        """Execute tasks sequentially respecting dependencies"""
        remaining_tasks = self.tasks.copy()

        while remaining_tasks:
            ready_tasks = [t for t in remaining_tasks if t in self._get_ready_tasks()]

            if not ready_tasks:
                # No tasks ready - check for circular dependencies or failed dependencies
                pending_tasks = [
                    t for t in remaining_tasks if t.status == ScanStatus.PENDING
                ]
                if pending_tasks:
                    log_error(
                        "Possible circular dependency or failed dependency detected"
                    )
                    for task in pending_tasks:
                        task.status = ScanStatus.FAILED
                        task.error = "Dependency not met"
                break

            # Execute the highest priority ready task
            task = ready_tasks[0]
            self._execute_task(task)
            remaining_tasks.remove(task)

            # Check fail_fast condition
            if fail_fast and task.required and task.status == ScanStatus.FAILED:
                log_error(
                    f"Required task {task.scanner_name} failed, stopping workflow"
                )
                break

    def _execute_parallel(self, fail_fast: bool) -> None:
        """Execute tasks in parallel respecting dependencies"""
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            remaining_tasks = self.tasks.copy()
            running_futures = {}

            while remaining_tasks or running_futures:
                # Submit ready tasks
                ready_tasks = [
                    t for t in remaining_tasks if t in self._get_ready_tasks()
                ]

                for task in ready_tasks:
                    if len(running_futures) < self.max_workers:
                        future = executor.submit(self._execute_task, task)
                        running_futures[future] = task
                        remaining_tasks.remove(task)

                # Wait for at least one task to complete
                if running_futures:
                    completed_futures = as_completed(
                        running_futures.keys(), timeout=1.0
                    )

                    for future in completed_futures:
                        task = running_futures.pop(future)

                        try:
                            # Task is already updated by _execute_task
                            result_task = future.result()
                        except Exception as e:
                            task.status = ScanStatus.FAILED
                            task.error = str(e)
                            log_error(f"Task execution error: {e}")

                        # Check fail_fast condition
                        if (
                            fail_fast
                            and task.required
                            and task.status == ScanStatus.FAILED
                        ):
                            log_error(
                                f"Required task {task.scanner_name} failed, cancelling workflow"
                            )
                            # Cancel remaining futures
                            for f in running_futures.keys():
                                f.cancel()
                            return

                        break  # Process one completion at a time

    def _aggregate_results(self) -> Optional[ScanResult]:
        """Aggregate all scan results into a single result"""
        successful_tasks = [
            t for t in self.tasks if t.result and t.status == ScanStatus.COMPLETED
        ]

        if not successful_tasks:
            return None

        # Use the first successful result as base
        base_result = successful_tasks[0].result
        aggregated = ScanResult(
            scanner_name="workflow_aggregator",
            target=base_result.target,
            status=ScanStatus.COMPLETED,
            start_time=min(t.start_time for t in successful_tasks if t.start_time),
        )

        # Aggregate findings from all scanners
        for task in successful_tasks:
            if task.result and task.result.findings:
                aggregated.findings.extend(task.result.findings)

        # Aggregate metadata
        for task in successful_tasks:
            if task.result and task.result.metadata:
                for key, value in task.result.metadata.items():
                    aggregated.metadata[f"{task.scanner_name}_{key}"] = value

        aggregated.end_time = datetime.now()
        aggregated.metadata["workflow_id"] = self.workflow_id
        aggregated.metadata["scanners_used"] = [
            t.scanner_name for t in successful_tasks
        ]

        return aggregated


def create_quick_workflow(
    target: str, workflow_id: Optional[str] = None
) -> ScanWorkflow:
    """Create a quick scan workflow (port scan only)"""
    workflow_id = workflow_id or f"quick_{int(datetime.now().timestamp())}"
    workflow = ScanWorkflow(workflow_id)
    workflow.create_standard_workflow(target, "quick")
    return workflow


def create_full_workflow(
    target: str, workflow_id: Optional[str] = None
) -> ScanWorkflow:
    """Create a comprehensive scan workflow"""
    workflow_id = workflow_id or f"full_{int(datetime.now().timestamp())}"
    workflow = ScanWorkflow(workflow_id)
    workflow.create_standard_workflow(target, "full")
    return workflow


def create_web_workflow(target: str, workflow_id: Optional[str] = None) -> ScanWorkflow:
    """Create a web-focused scan workflow"""
    workflow_id = workflow_id or f"web_{int(datetime.now().timestamp())}"
    workflow = ScanWorkflow(workflow_id)
    workflow.create_standard_workflow(target, "web")
    return workflow
