#!/usr/bin/env python3
"""
Quick patch to fix workflow _execute_parallel method
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def patch_workflow():
    """Patch the workflow._execute_parallel method"""
    print("🔧 Patching workflow._execute_parallel method...")

    try:
        from src.orchestrator.workflow import ScanWorkflow
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from src.core.scanner_base import ScanStatus
        from src.utils.logger import log_info, log_error, log_success
        from datetime import datetime

        def new_execute_parallel(self, fail_fast: bool) -> None:
            """FIXED: Execute tasks in parallel respecting dependencies"""
            # For simple workflows (like quick scan), just execute all ready tasks
            ready_tasks = self._get_ready_tasks()

            if not ready_tasks:
                log_error("No ready tasks to execute")
                return

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all ready tasks
                futures_to_tasks = {}

                for task in ready_tasks:
                    log_info(f"Submitting {task.scanner_name} for execution")
                    future = executor.submit(self._execute_task, task)
                    futures_to_tasks[future] = task

                # Wait for all tasks to complete with proper timeout
                timeout_total = max(
                    300, len(futures_to_tasks) * 60
                )  # At least 5 minutes, or 1 minute per task

                try:
                    # Use as_completed with reasonable timeout
                    completed_count = 0
                    for future in as_completed(
                        futures_to_tasks.keys(), timeout=timeout_total
                    ):
                        task = futures_to_tasks[future]
                        completed_count += 1

                        try:
                            # Get the result (task is already updated by _execute_task)
                            result_task = future.result(
                                timeout=10
                            )  # 10 second timeout for getting result
                            log_success(
                                f"Task {task.scanner_name} completed ({completed_count}/{len(futures_to_tasks)})"
                            )

                        except Exception as e:
                            # Update task status if not already set
                            if task.status == ScanStatus.RUNNING:
                                task.status = ScanStatus.FAILED
                                task.error = str(e)
                                task.end_time = datetime.now()
                            log_error(f"Task {task.scanner_name} failed: {e}")

                        # Check fail_fast condition
                        if (
                            fail_fast
                            and task.required
                            and task.status == ScanStatus.FAILED
                        ):
                            log_error(
                                f"Required task {task.scanner_name} failed, stopping workflow"
                            )
                            # Cancel remaining futures
                            for remaining_future in futures_to_tasks.keys():
                                if not remaining_future.done():
                                    remaining_future.cancel()
                            break

                    log_info(
                        f"Parallel execution completed: {completed_count}/{len(futures_to_tasks)} tasks finished"
                    )

                except Exception as e:
                    log_error(f"Parallel execution failed: {e}")
                    # Mark all unfinished tasks as failed
                    for future, task in futures_to_tasks.items():
                        if not future.done():
                            future.cancel()
                            if task.status in [ScanStatus.RUNNING, ScanStatus.PENDING]:
                                task.status = ScanStatus.FAILED
                                task.error = (
                                    f"Cancelled due to workflow error: {str(e)}"
                                )
                                task.end_time = datetime.now()

        # Monkey patch the method
        ScanWorkflow._execute_parallel = new_execute_parallel
        print("✅ Workflow patched successfully!")
        return True

    except Exception as e:
        print(f"❌ Failed to patch workflow: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_patched_workflow():
    """Test the patched workflow"""
    print("\n🧪 Testing Patched Workflow")
    print("=" * 30)

    try:
        from src.services.scan_service import ScanService

        scan_service = ScanService()

        # Test target parsing
        target = "https://chibino.ir"
        parsed_target = scan_service._validate_and_parse_target(target)

        print(f"✅ Target parsed: {parsed_target['host']}")

        # Test workflow creation
        options = {"profile": "quick", "parallel": True, "timeout": 300}

        workflow = scan_service._create_workflow(parsed_target, options)
        print(f"✅ Workflow created: {workflow.workflow_id}")
        print(f"✅ Tasks: {len(workflow.tasks)}")

        # Test execution (this should now work)
        print("🚀 Testing workflow execution...")
        result = workflow.execute(parallel=True, fail_fast=False)

        print(f"✅ Workflow status: {result.status}")
        print(
            f"✅ Tasks completed: {len([t for t in result.tasks if t.status.value == 'completed'])}"
        )
        print(
            f"✅ Total findings: {sum(len(t.result.findings) for t in result.tasks if t.result)}"
        )

        return True

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Main function"""
    print("🩹 Quick Workflow Patch")
    print("=" * 25)

    # Patch the workflow
    if patch_workflow():
        # Test the patch
        if test_patched_workflow():
            print("\n🎉 Patch successful! You can now run:")
            print("python main.py quick https://chibino.ir")
        else:
            print("\n❌ Patch applied but test failed")
    else:
        print("\n❌ Patch failed")


if __name__ == "__main__":
    main()
