"""Base class for all security checks."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..client import MCPClient
from ..models import Finding, PromptInfo, ResourceInfo, Severity, ToolInfo


class BaseCheck(ABC):
    """Base class for MCP security checks."""

    id: str
    name: str
    severity: Severity
    description: str

    @abstractmethod
    async def run(
        self,
        client: MCPClient,
        tools: list[ToolInfo],
        resources: list[ResourceInfo],
        prompts: list[PromptInfo],
        *,
        aggressive: bool = False,
    ) -> list[Finding]:
        """Execute the check and return findings."""
        ...

    def finding(
        self,
        description: str,
        evidence: str,
        remediation: str,
        tool_name: str | None = None,
        resource_uri: str | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        """Create a Finding from this check."""
        return Finding(
            check_id=self.id,
            check_name=self.name,
            severity=severity or self.severity,
            description=description,
            evidence=evidence,
            remediation=remediation,
            tool_name=tool_name,
            resource_uri=resource_uri,
        )
