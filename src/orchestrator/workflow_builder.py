"""
Workflow Builder - SIMPLIFIED VERSION
Builder pattern for creating custom workflows
"""

from typing import Dict, Any
from datetime import datetime


class WorkflowBuilder:
    """Builder for creating custom scan workflows - SIMPLIFIED"""

    def __init__(self):
        self.scanners = []
        self.options = {}

    def add_port_scanner(self, ports: str = "quick", scan_type: str = "tcp"):
        """Add port scanner to workflow"""
        self.scanners.append(
            {
                "type": "port",
                "options": {
                    "ports": ports,
                    "scan_type": scan_type,
                    "timing": 4,
                    "no_ping": False,
                },
            }
        )
        return self

    def add_dns_scanner(self, subdomain_enum: bool = True):
        """Add DNS scanner to workflow"""
        self.scanners.append(
            {
                "type": "dns",
                "options": {
                    "subdomain_enum": subdomain_enum,
                    "zone_transfer": False,
                    "dns_bruteforce": False,
                },
            }
        )
        return self

    def add_web_scanner(self, use_nikto: bool = True):
        """Add web scanner to workflow"""
        self.scanners.append(
            {
                "type": "web",
                "options": {"use_nikto": use_nikto, "include_headers": True},
            }
        )
        return self

    def add_directory_scanner(self, tool: str = "dirb"):
        """Add directory scanner to workflow"""
        self.scanners.append(
            {"type": "directory", "options": {"tool": tool, "wordlist": "common"}}
        )
        return self

    def add_ssl_scanner(self, cipher_enum: bool = True):
        """Add SSL scanner to workflow"""
        self.scanners.append(
            {"type": "ssl", "options": {"cipher_enum": cipher_enum, "cert_info": True}}
        )
        return self

    def set_options(self, **options):
        """Set workflow options"""
        self.options.update(options)
        return self

    def build(self, target: Dict[str, str]):
        """Build the workflow - SIMPLIFIED"""
        from .workflow import ScanWorkflow

        # Create workflow
        workflow_id = f"custom_{int(datetime.now().timestamp())}"
        workflow = ScanWorkflow(workflow_id)

        # Add configured scanners as tasks
        for scanner_config in self.scanners:
            scanner_name = scanner_config["type"] + "_scanner"
            scanner_options = scanner_config["options"]

            # Determine appropriate target format for this scanner
            if scanner_config["type"] == "port":
                scan_target = target["host"]
            elif scanner_config["type"] == "dns":
                scan_target = target["domain"]
            elif scanner_config["type"] in ["web", "directory"]:
                scan_target = target["url"]
            elif scanner_config["type"] == "ssl":
                scan_target = target["host"]
            else:
                scan_target = target["original"]

            # Add task to workflow
            workflow.add_scan_task(
                scanner_name=scanner_name,
                target=scan_target,
                options=scanner_options,
                timeout=self.options.get("timeout", 300),
            )

        return workflow

    def build(self, target: Dict[str, str]) -> ScanWorkflow:
        """Build the workflow"""
        from datetime import datetime

        # Create workflow
        workflow_id = f"custom_{int(datetime.now().timestamp())}"
        workflow = ScanWorkflow(workflow_id)

        # Add configured scanners as tasks
        for scanner_config in self.scanners:
            scanner_name = scanner_config["type"] + "_scanner"
            scanner_class = scanner_config["scanner"]
            scanner_options = scanner_config["options"]

            # Determine appropriate target format for this scanner
            if scanner_config["type"] == "port":
                scan_target = target["host"]
            elif scanner_config["type"] == "dns":
                scan_target = target["domain"]
            elif scanner_config["type"] in ["web", "directory"]:
                scan_target = target["url"]
            elif scanner_config["type"] == "ssl":
                scan_target = target["host"]
            else:
                scan_target = target["original"]

            # Add task to workflow
            workflow.add_scan_task(
                scanner_name=scanner_name,
                target=scan_target,
                options=scanner_options,
                timeout=self.options.get("timeout", 300),
            )

        return workflow

    """
Workflow Builder
Builder pattern for creating custom workflows
"""


from typing import Dict, Any, List
from .workflow import ScanWorkflow
from ..scanners.recon.port_scanner import PortScanner
from ..scanners.recon.dns_scanner import DNSScanner
from ..scanners.vulnerability.web_scanner import WebScanner
from ..scanners.vulnerability.directory_scanner import DirectoryScanner
from ..scanners.vulnerability.ssl_scanner import SSLScanner


class WorkflowBuilder:
    """Builder for creating custom scan workflows"""

    def __init__(self):
        self.scanners = []
        self.options = {}

    def add_port_scanner(
        self, ports: str = "1-1000", scan_type: str = "tcp"
    ) -> "WorkflowBuilder":
        """Add port scanner to workflow"""
        self.scanners.append(
            {
                "type": "port",
                "scanner": PortScanner,
                "options": {"ports": ports, "scan_type": scan_type},
            }
        )
        return self

    def add_dns_scanner(self, subdomain_enum: bool = True) -> "WorkflowBuilder":
        """Add DNS scanner to workflow"""
        self.scanners.append(
            {
                "type": "dns",
                "scanner": DNSScanner,
                "options": {"subdomain_enum": subdomain_enum},
            }
        )
        return self

    def add_web_scanner(self, use_nikto: bool = True) -> "WorkflowBuilder":
        """Add web scanner to workflow"""
        self.scanners.append(
            {"type": "web", "scanner": WebScanner, "options": {"use_nikto": use_nikto}}
        )
        return self

    def add_directory_scanner(self, tool: str = "dirb") -> "WorkflowBuilder":
        """Add directory scanner to workflow"""
        self.scanners.append(
            {
                "type": "directory",
                "scanner": DirectoryScanner,
                "options": {"tool": tool},
            }
        )
        return self

    def add_ssl_scanner(self, cipher_enum: bool = True) -> "WorkflowBuilder":
        """Add SSL scanner to workflow"""
        self.scanners.append(
            {
                "type": "ssl",
                "scanner": SSLScanner,
                "options": {"cipher_enum": cipher_enum},
            }
        )
        return self

    def set_options(self, **options) -> "WorkflowBuilder":
        """Set workflow options"""
        self.options.update(options)
        return self

    def build(self, target: Dict[str, str]) -> ScanWorkflow:

        from datetime import datetime

        # Create workflow
        workflow_id = f"custom_{int(datetime.now().timestamp())}"
        workflow = ScanWorkflow(workflow_id)

        # Add configured scanners as tasks
        for scanner_config in self.scanners:
            scanner_name = scanner_config["type"] + "_scanner"
            scanner_options = scanner_config["options"]

            # Determine appropriate target format for this scanner
            if scanner_config["type"] == "port":
                scan_target = target["host"]
            elif scanner_config["type"] == "dns":
                scan_target = target["domain"]
            elif scanner_config["type"] in ["web", "directory"]:
                scan_target = target["url"]
            elif scanner_config["type"] == "ssl":
                scan_target = target["host"]
            else:
                scan_target = target["original"]

            # Add task to workflow
            workflow.add_scan_task(
                scanner_name=scanner_name,
                target=scan_target,
                options=scanner_options,
                timeout=self.options.get("timeout", 300),
            )

        return workflow
