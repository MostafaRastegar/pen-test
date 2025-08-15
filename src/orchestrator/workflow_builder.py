"""
Workflow Builder - SIMPLIFIED VERSION
Builder pattern for creating custom workflows
"""

from typing import Dict, Any
from datetime import datetime
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

    def add_wordpress_scanner(
        self,
        enumerate_plugins: bool = True,
        enumerate_themes: bool = True,
        enumerate_users: bool = True,
        use_wpscan: bool = True,
        wpscan_api_token: str = None,
    ):
        """Add WordPress scanner to workflow"""
        self.scanners.append(
            {
                "type": "wordpress",
                "options": {
                    "enumerate_plugins": enumerate_plugins,
                    "enumerate_themes": enumerate_themes,
                    "enumerate_users": enumerate_users,
                    "use_wpscan": use_wpscan,
                    "wpscan_api_token": wpscan_api_token,
                    "check_xmlrpc": True,
                    "check_config": True,
                },
            }
        )
        return self

    def add_cms_scanner(self, cms_type: str = "auto", **cms_options):
        """Add CMS-specific scanner to workflow"""
        if cms_type == "wordpress" or cms_type == "auto":
            self.add_wordpress_scanner(**cms_options)
        # Future: add other CMS scanners (Drupal, Joomla)
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
