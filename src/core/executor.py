"""
Command executor for running system commands safely
"""

import subprocess
import asyncio
import logging
import shlex
import signal
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union, AsyncIterator
from pathlib import Path
import threading
import queue
import time


@dataclass
class CommandResult:
    """Result from command execution"""
    command: str
    return_code: int
    stdout: str
    stderr: str
    execution_time: float
    timed_out: bool = False
    
    @property
    def success(self) -> bool:
        """Check if command executed successfully"""
        return self.return_code == 0 and not self.timed_out
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'command': self.command,
            'return_code': self.return_code,
            'stdout': self.stdout,
            'stderr': self.stderr,
            'execution_time': self.execution_time,
            'timed_out': self.timed_out,
            'success': self.success
        }


class CommandExecutor:
    """
    Secure command executor with timeout and resource management
    """
    
    def __init__(self, 
                 timeout: int = 30,
                 max_output_size: int = 10 * 1024 * 1024,  # 10MB
                 working_dir: Optional[Path] = None):
        """
        Initialize command executor
        
        Args:
            timeout: Default timeout in seconds
            max_output_size: Maximum output size in bytes
            working_dir: Working directory for commands
        """
        self.timeout = timeout
        self.max_output_size = max_output_size
        self.working_dir = working_dir or Path.cwd()
        self.logger = logging.getLogger('executor')
        
    def execute(self, 
                command: Union[str, List[str]], 
                timeout: Optional[int] = None,
                input_data: Optional[str] = None,
                env: Optional[dict] = None,
                shell: bool = False) -> CommandResult:
        """
        Execute a command synchronously
        
        Args:
            command: Command to execute (string or list)
            timeout: Override default timeout
            input_data: Input to pass to stdin
            env: Environment variables
            shell: Whether to use shell execution (use with caution)
            
        Returns:
            CommandResult: Execution result
        """
        timeout = timeout or self.timeout
        start_time = time.time()
        
        # Prepare command
        if isinstance(command, str):
            cmd_str = command
            if not shell:
                command = shlex.split(command)
        else:
            cmd_str = ' '.join(command)
        
        self.logger.debug(f"Executing command: {cmd_str}")
        
        # Prepare environment
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)
        
        try:
            # Execute command
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input_data else None,
                env=cmd_env,
                cwd=self.working_dir,
                shell=shell,
                text=True,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            try:
                stdout, stderr = process.communicate(
                    input=input_data,
                    timeout=timeout
                )
                return_code = process.returncode
                timed_out = False
                
            except subprocess.TimeoutExpired:
                self.logger.warning(f"Command timed out after {timeout}s: {cmd_str}")
                
                # Kill process group
                if os.name != 'nt':
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                else:
                    process.terminate()
                
                # Wait a bit then force kill if needed
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    if os.name != 'nt':
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    else:
                        process.kill()
                    stdout, stderr = process.communicate()
                
                return_code = process.returncode or -1
                timed_out = True
                
        except Exception as e:
            self.logger.error(f"Error executing command: {e}")
            stdout = ""
            stderr = str(e)
            return_code = -1
            timed_out = False
        
        execution_time = time.time() - start_time
        
        # Truncate output if too large
        if len(stdout) > self.max_output_size:
            stdout = stdout[:self.max_output_size] + "\n... [OUTPUT TRUNCATED]"
        if len(stderr) > self.max_output_size:
            stderr = stderr[:self.max_output_size] + "\n... [OUTPUT TRUNCATED]"
        
        result = CommandResult(
            command=cmd_str,
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            execution_time=execution_time,
            timed_out=timed_out
        )
        
        if result.success:
            self.logger.debug(f"Command executed successfully in {execution_time:.2f}s")
        else:
            self.logger.warning(f"Command failed with code {return_code}")
            
        return result
    
    async def execute_async(self,
                          command: Union[str, List[str]],
                          timeout: Optional[int] = None,
                          input_data: Optional[str] = None,
                          env: Optional[dict] = None) -> CommandResult:
        """
        Execute a command asynchronously
        
        Args:
            command: Command to execute
            timeout: Override default timeout
            input_data: Input to pass to stdin
            env: Environment variables
            
        Returns:
            CommandResult: Execution result
        """
        timeout = timeout or self.timeout
        start_time = time.time()
        
        # Prepare command
        if isinstance(command, str):
            cmd_str = command
            command = shlex.split(command)
        else:
            cmd_str = ' '.join(command)
        
        self.logger.debug(f"Executing async command: {cmd_str}")
        
        # Prepare environment
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)
        
        try:
            # Create subprocess
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                env=cmd_env,
                cwd=self.working_dir
            )
            
            try:
                # Wait for completion with timeout
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(input=input_data.encode() if input_data else None),
                    timeout=timeout
                )
                stdout = stdout_bytes.decode('utf-8', errors='replace')
                stderr = stderr_bytes.decode('utf-8', errors='replace')
                return_code = process.returncode
                timed_out = False
                
            except asyncio.TimeoutError:
                self.logger.warning(f"Async command timed out after {timeout}s: {cmd_str}")
                process.terminate()
                await asyncio.sleep(2)
                
                if process.returncode is None:
                    process.kill()
                    
                stdout = ""
                stderr = "Command timed out"
                return_code = -1
                timed_out = True
                
        except Exception as e:
            self.logger.error(f"Error executing async command: {e}")
            stdout = ""
            stderr = str(e)
            return_code = -1
            timed_out = False
        
        execution_time = time.time() - start_time
        
        # Truncate output if too large
        if len(stdout) > self.max_output_size:
            stdout = stdout[:self.max_output_size] + "\n... [OUTPUT TRUNCATED]"
        if len(stderr) > self.max_output_size:
            stderr = stderr[:self.max_output_size] + "\n... [OUTPUT TRUNCATED]"
        
        return CommandResult(
            command=cmd_str,
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            execution_time=execution_time,
            timed_out=timed_out
        )
    
    def execute_streaming(self,
                         command: Union[str, List[str]],
                         timeout: Optional[int] = None,
                         env: Optional[dict] = None) -> AsyncIterator[str]:
        """
        Execute command and stream output line by line
        
        Args:
            command: Command to execute
            timeout: Override default timeout
            env: Environment variables
            
        Yields:
            str: Output lines as they arrive
        """
        timeout = timeout or self.timeout
        
        # Prepare command
        if isinstance(command, str):
            command = shlex.split(command)
        
        # Prepare environment
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)
        
        # Create process
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=cmd_env,
            cwd=self.working_dir,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Stream output
        start_time = time.time()
        for line in process.stdout:
            if time.time() - start_time > timeout:
                process.terminate()
                yield f"[TIMEOUT] Command exceeded {timeout}s timeout"
                break
            yield line.rstrip()
        
        process.wait()
    
    def check_tool_exists(self, tool_name: str) -> bool:
        """
        Check if a tool/command exists in the system
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            bool: True if tool exists, False otherwise
        """
        result = self.execute(f"which {tool_name}", timeout=5)
        return result.success and result.stdout.strip() != ""
    
    def get_tool_version(self, tool_name: str, version_flag: str = "--version") -> Optional[str]:
        """
        Get version of a tool
        
        Args:
            tool_name: Name of the tool
            version_flag: Flag to get version (default: --version)
            
        Returns:
            Optional[str]: Version string or None if failed
        """
        result = self.execute(f"{tool_name} {version_flag}", timeout=5)
        if result.success:
            return result.stdout.strip()
        return None