"""MCP-008: Resource Traversal - Resources allowing path traversal."""

from __future__ import annotations

import re

from .base import BaseCheck
from ..client import MCPClient
from ..models import Finding, Severity, ToolInfo, ResourceInfo, PromptInfo


class ResourceTraversal(BaseCheck):
    id = "MCP-008"
    name = "Resource Traversal"
    severity = Severity.HIGH
    description = "Detects resources that may allow path traversal to access unauthorized files"

    async def run(
        self,
        client: MCPClient,
        tools: list[ToolInfo],
        resources: list[ResourceInfo],
        prompts: list[PromptInfo],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for resource in resources:
            uri = resource.uri

            # Check for template parameters in URI that could allow traversal
            if "{" in uri and "}" in uri:
                # URI template with parameters
                template_params = re.findall(r"\{([^}]+)\}", uri)
                for param in template_params:
                    param_lower = param.lower()
                    if any(kw in param_lower for kw in ["path", "file", "name", "dir", "folder"]):
                        findings.append(
                            self.finding(
                                description="Resource URI template accepts file path parameter",
                                evidence=f'Resource "{resource.name}" URI template: {uri} (parameter: {param})',
                                remediation=(
                                    "Validate path parameters: reject '..', absolute paths, and symlinks. "
                                    "Use a chroot or allowlist of permitted paths."
                                ),
                                resource_uri=uri,
                            )
                        )

            # Check for file:// protocol
            if uri.startswith("file://"):
                findings.append(
                    self.finding(
                        description="Resource uses file:// protocol (direct filesystem access)",
                        evidence=f'Resource "{resource.name}" URI: {uri}',
                        remediation="Avoid file:// URIs. Use application-level resource access with proper authorization.",
                        resource_uri=uri,
                    )
                )

            # Check if resource exposes sensitive paths
            sensitive_patterns = [
                (r"/etc/", "System configuration directory"),
                (r"/proc/", "Process information"),
                (r"/sys/", "System directory"),
                (r"\.env", "Environment file"),
                (r"\.ssh/", "SSH directory"),
                (r"\.aws/", "AWS credentials"),
                (r"\.git/", "Git repository internals"),
                (r"password", "Potential password file"),
                (r"secret", "Potential secrets file"),
                (r"token", "Potential token file"),
            ]

            for pattern, label in sensitive_patterns:
                if re.search(pattern, uri, re.IGNORECASE):
                    findings.append(
                        self.finding(
                            description=f"Resource may expose sensitive content: {label}",
                            evidence=f'Resource "{resource.name}" URI: {uri}',
                            remediation=f"Review resource access. {label} should not be directly exposed via MCP resources.",
                            resource_uri=uri,
                            severity=Severity.CRITICAL,
                        )
                    )

        return findings
