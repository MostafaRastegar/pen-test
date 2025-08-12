"""
Task Scheduler - Manages resource allocation and task scheduling
"""

import threading
import queue
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable
from enum import Enum
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, Future
import psutil
import logging

from src.utils.logger import log_info, log_error, log_warning, log_success


class TaskPriority(Enum):
    """Task priority levels"""

    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


class TaskState(Enum):
    """Task execution states"""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class ResourceLimits:
    """System resource limits for task execution"""

    max_cpu_percent: float = 80.0
    max_memory_percent: float = 80.0
    max_concurrent_tasks: int = 5
    max_network_tasks: int = 3
    max_io_tasks: int = 2


@dataclass
class ScheduledTask:
    """Scheduled task with metadata"""

    task_id: str
    name: str
    function: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    timeout: Optional[int] = None
    resource_type: str = "cpu"  # cpu, network, io
    max_retries: int = 0

    # Runtime fields
    state: TaskState = TaskState.QUEUED
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Any = None
    error: Optional[str] = None
    retry_count: int = 0
    future: Optional[Future] = None


class TaskScheduler:
    """
    Advanced task scheduler with resource management and priority queuing
    """

    def __init__(
        self,
        resource_limits: Optional[ResourceLimits] = None,
        monitoring_interval: float = 1.0,
    ):
        """
        Initialize task scheduler

        Args:
            resource_limits: System resource limits
            monitoring_interval: Resource monitoring interval in seconds
        """
        self.resource_limits = resource_limits or ResourceLimits()
        self.monitoring_interval = monitoring_interval

        # Task queues by priority
        self.task_queues = {
            priority: queue.PriorityQueue() for priority in TaskPriority
        }

        # Active tasks tracking
        self.active_tasks: Dict[str, ScheduledTask] = {}
        self.completed_tasks: Dict[str, ScheduledTask] = {}

        # Resource tracking
        self.resource_usage = {"cpu": 0, "network": 0, "io": 0}

        # Thread management
        self.executor = ThreadPoolExecutor(
            max_workers=self.resource_limits.max_concurrent_tasks,
            thread_name_prefix="scheduler",
        )

        # Control flags
        self.running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        self.monitor_thread: Optional[threading.Thread] = None

        # Callbacks
        self.task_callbacks: Dict[str, List[Callable]] = {
            "started": [],
            "completed": [],
            "failed": [],
            "timeout": [],
        }

        self.logger = logging.getLogger("scheduler")

    def start(self) -> None:
        """Start the scheduler"""
        if self.running:
            return

        self.running = True

        # Start scheduler thread
        self.scheduler_thread = threading.Thread(
            target=self._scheduler_loop, name="scheduler_main", daemon=True
        )
        self.scheduler_thread.start()

        # Start resource monitor thread
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop, name="scheduler_monitor", daemon=True
        )
        self.monitor_thread.start()

        log_info("Task scheduler started")

    def stop(self, wait_for_completion: bool = True) -> None:
        """Stop the scheduler"""
        if not self.running:
            return

        self.running = False

        if wait_for_completion:
            # Cancel all queued tasks
            self._cancel_queued_tasks()

            # Wait for active tasks to complete
            self._wait_for_active_tasks()

        # Shutdown executor
        self.executor.shutdown(wait=wait_for_completion)

        log_info("Task scheduler stopped")

    def submit_task(
        self,
        task_id: str,
        name: str,
        function: Callable,
        args: tuple = (),
        kwargs: Optional[Dict[str, Any]] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        timeout: Optional[int] = None,
        resource_type: str = "cpu",
        max_retries: int = 0,
    ) -> ScheduledTask:
        """
        Submit a task for execution

        Args:
            task_id: Unique task identifier
            name: Human-readable task name
            function: Function to execute
            args: Function arguments
            kwargs: Function keyword arguments
            priority: Task priority
            timeout: Task timeout in seconds
            resource_type: Resource type (cpu, network, io)
            max_retries: Maximum retry attempts

        Returns:
            ScheduledTask: Created task object
        """
        if task_id in self.active_tasks or task_id in self.completed_tasks:
            raise ValueError(f"Task {task_id} already exists")

        task = ScheduledTask(
            task_id=task_id,
            name=name,
            function=function,
            args=args,
            kwargs=kwargs or {},
            priority=priority,
            timeout=timeout,
            resource_type=resource_type,
            max_retries=max_retries,
        )

        # Add to appropriate priority queue
        # Use negative creation time as secondary sort key for FIFO within priority
        priority_value = (priority.value, -time.time())
        self.task_queues[priority].put((priority_value, task))

        log_info(f"Submitted task {task_id} ({name}) with priority {priority.name}")
        return task

    def get_task_status(self, task_id: str) -> Optional[ScheduledTask]:
        """Get status of a specific task"""
        if task_id in self.active_tasks:
            return self.active_tasks[task_id]
        elif task_id in self.completed_tasks:
            return self.completed_tasks[task_id]
        else:
            # Check queues
            for priority_queue in self.task_queues.values():
                # Note: This is inefficient but needed for status checking
                # In production, might want to maintain a separate index
                pass
        return None

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a task"""
        task = self.get_task_status(task_id)
        if not task:
            return False

        if task.state == TaskState.RUNNING and task.future:
            task.future.cancel()
            task.state = TaskState.CANCELLED
            self._cleanup_task(task)
            return True
        elif task.state == TaskState.QUEUED:
            task.state = TaskState.CANCELLED
            return True

        return False

    def get_queue_status(self) -> Dict[str, int]:
        """Get current queue status"""
        return {
            priority.name: self.task_queues[priority].qsize()
            for priority in TaskPriority
        }

    def get_system_status(self) -> Dict[str, Any]:
        """Get current system and scheduler status"""
        try:
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent

            return {
                "scheduler_running": self.running,
                "active_tasks": len(self.active_tasks),
                "completed_tasks": len(self.completed_tasks),
                "queue_status": self.get_queue_status(),
                "resource_usage": self.resource_usage.copy(),
                "system_resources": {
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory_percent,
                    "cpu_limit": self.resource_limits.max_cpu_percent,
                    "memory_limit": self.resource_limits.max_memory_percent,
                },
                "resource_limits": {
                    "max_concurrent": self.resource_limits.max_concurrent_tasks,
                    "max_network": self.resource_limits.max_network_tasks,
                    "max_io": self.resource_limits.max_io_tasks,
                },
            }
        except Exception as e:
            self.logger.error(f"Error getting system status: {e}")
            return {"error": str(e)}

    def add_callback(
        self, event: str, callback: Callable[[ScheduledTask], None]
    ) -> None:
        """Add event callback"""
        if event in self.task_callbacks:
            self.task_callbacks[event].append(callback)

    def _scheduler_loop(self) -> None:
        """Main scheduler loop"""
        while self.running:
            try:
                # Check if we can start more tasks
                if self._can_start_task():
                    task = self._get_next_task()
                    if task:
                        self._start_task(task)

                # Clean up completed tasks
                self._cleanup_completed_tasks()

                time.sleep(0.1)  # Small delay to prevent busy waiting

            except Exception as e:
                self.logger.error(f"Scheduler loop error: {e}")
                time.sleep(1)

    def _monitor_loop(self) -> None:
        """Resource monitoring loop"""
        while self.running:
            try:
                self._update_resource_usage()
                self._check_task_timeouts()
                time.sleep(self.monitoring_interval)
            except Exception as e:
                self.logger.error(f"Monitor loop error: {e}")
                time.sleep(5)

    def _can_start_task(self) -> bool:
        """Check if we can start a new task based on resource limits"""
        try:
            # Check system resources
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent

            if cpu_percent > self.resource_limits.max_cpu_percent:
                return False

            if memory_percent > self.resource_limits.max_memory_percent:
                return False

            # Check concurrent task limits
            if len(self.active_tasks) >= self.resource_limits.max_concurrent_tasks:
                return False

            # Check resource-specific limits
            network_tasks = sum(
                1 for t in self.active_tasks.values() if t.resource_type == "network"
            )
            if network_tasks >= self.resource_limits.max_network_tasks:
                return False

            io_tasks = sum(
                1 for t in self.active_tasks.values() if t.resource_type == "io"
            )
            if io_tasks >= self.resource_limits.max_io_tasks:
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error checking resource limits: {e}")
            return False

    def _get_next_task(self) -> Optional[ScheduledTask]:
        """Get the next task to execute based on priority"""
        for priority in TaskPriority:
            try:
                if not self.task_queues[priority].empty():
                    _, task = self.task_queues[priority].get_nowait()
                    if task.state == TaskState.QUEUED:  # Skip cancelled tasks
                        return task
            except queue.Empty:
                continue
        return None

    def _start_task(self, task: ScheduledTask) -> None:
        """Start executing a task"""
        try:
            task.state = TaskState.RUNNING
            task.started_at = datetime.now()
            self.active_tasks[task.task_id] = task

            # Submit to thread pool
            future = self.executor.submit(self._execute_task, task)
            task.future = future

            # Update resource usage
            self.resource_usage[task.resource_type] += 1

            log_info(f"Started task {task.task_id} ({task.name})")

            # Call started callbacks
            for callback in self.task_callbacks["started"]:
                try:
                    callback(task)
                except Exception as e:
                    self.logger.error(f"Callback error: {e}")

        except Exception as e:
            task.state = TaskState.FAILED
            task.error = str(e)
            self.logger.error(f"Failed to start task {task.task_id}: {e}")

    def _execute_task(self, task: ScheduledTask) -> Any:
        """Execute a task function"""
        try:
            # Execute the actual function
            result = task.function(*task.args, **task.kwargs)

            task.result = result
            task.state = TaskState.COMPLETED
            task.completed_at = datetime.now()

            log_success(f"Completed task {task.task_id} ({task.name})")

            # Call completed callbacks
            for callback in self.task_callbacks["completed"]:
                try:
                    callback(task)
                except Exception as e:
                    self.logger.error(f"Callback error: {e}")

            return result

        except Exception as e:
            task.state = TaskState.FAILED
            task.error = str(e)
            task.completed_at = datetime.now()

            log_error(f"Task {task.task_id} failed: {e}")

            # Check for retry
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.state = TaskState.QUEUED
                log_info(
                    f"Retrying task {task.task_id} (attempt {task.retry_count + 1})"
                )

                # Re-queue the task
                priority_value = (task.priority.value, -time.time())
                self.task_queues[task.priority].put((priority_value, task))
            else:
                # Call failed callbacks
                for callback in self.task_callbacks["failed"]:
                    try:
                        callback(task)
                    except Exception as cb_e:
                        self.logger.error(f"Callback error: {cb_e}")

            raise

        finally:
            self._cleanup_task(task)

    def _cleanup_task(self, task: ScheduledTask) -> None:
        """Clean up task resources"""
        try:
            # Remove from active tasks
            if task.task_id in self.active_tasks:
                del self.active_tasks[task.task_id]

            # Update resource usage
            if task.resource_type in self.resource_usage:
                self.resource_usage[task.resource_type] = max(
                    0, self.resource_usage[task.resource_type] - 1
                )

            # Move to completed tasks
            if task.state in [
                TaskState.COMPLETED,
                TaskState.FAILED,
                TaskState.CANCELLED,
            ]:
                self.completed_tasks[task.task_id] = task

        except Exception as e:
            self.logger.error(f"Error cleaning up task {task.task_id}: {e}")

    def _cleanup_completed_tasks(self) -> None:
        """Clean up old completed tasks to prevent memory leaks"""
        cutoff_time = datetime.now() - timedelta(hours=1)  # Keep for 1 hour

        to_remove = []
        for task_id, task in self.completed_tasks.items():
            if task.completed_at and task.completed_at < cutoff_time:
                to_remove.append(task_id)

        for task_id in to_remove:
            del self.completed_tasks[task_id]

    def _update_resource_usage(self) -> None:
        """Update current resource usage statistics"""
        try:
            # Reset counters and recount from active tasks
            self.resource_usage = {"cpu": 0, "network": 0, "io": 0}

            for task in self.active_tasks.values():
                if task.state == TaskState.RUNNING:
                    self.resource_usage[task.resource_type] += 1

        except Exception as e:
            self.logger.error(f"Error updating resource usage: {e}")

    def _check_task_timeouts(self) -> None:
        """Check for timed out tasks"""
        current_time = datetime.now()

        for task in list(self.active_tasks.values()):
            if (
                task.timeout
                and task.started_at
                and current_time - task.started_at > timedelta(seconds=task.timeout)
            ):

                log_warning(f"Task {task.task_id} timed out after {task.timeout}s")

                if task.future:
                    task.future.cancel()

                task.state = TaskState.TIMEOUT
                task.completed_at = current_time
                task.error = f"Task timed out after {task.timeout} seconds"

                self._cleanup_task(task)

                # Call timeout callbacks
                for callback in self.task_callbacks["timeout"]:
                    try:
                        callback(task)
                    except Exception as e:
                        self.logger.error(f"Callback error: {e}")

    def _cancel_queued_tasks(self) -> None:
        """Cancel all queued tasks"""
        for priority_queue in self.task_queues.values():
            while not priority_queue.empty():
                try:
                    _, task = priority_queue.get_nowait()
                    task.state = TaskState.CANCELLED
                    self.completed_tasks[task.task_id] = task
                except queue.Empty:
                    break

    def _wait_for_active_tasks(self, timeout: Optional[int] = None) -> None:
        """Wait for all active tasks to complete"""
        start_time = time.time()

        while self.active_tasks:
            if timeout and time.time() - start_time > timeout:
                log_warning("Timeout waiting for active tasks to complete")
                break

            time.sleep(0.5)


# Global scheduler instance
_global_scheduler: Optional[TaskScheduler] = None


def get_global_scheduler() -> TaskScheduler:
    """Get or create the global scheduler instance"""
    global _global_scheduler
    if _global_scheduler is None:
        _global_scheduler = TaskScheduler()
        _global_scheduler.start()
    return _global_scheduler


def shutdown_global_scheduler() -> None:
    """Shutdown the global scheduler"""
    global _global_scheduler
    if _global_scheduler:
        _global_scheduler.stop()
        _global_scheduler = None
