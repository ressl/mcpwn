"""MCP-007: Insecure Transport - MCP servers without TLS or authentication."""

from __future__ import annotations

from .base import BaseCheck
from ..client import MCPClient
from ..models import Finding, Severity, ToolInfo, ResourceInfo, PromptInfo


class InsecureTransport(BaseCheck):
    id = "MCP-007"
    name = "Insecure Transport"
    severity = Severity.MEDIUM
    description = "Detects MCP servers using insecure transport (no TLS, no auth)"

    async def run(
        self,
        client: MCPClient,
        tools: list[ToolInfo],
        resources: list[ResourceInfo],
        prompts: list[PromptInfo],
    ) -> list[Finding]:
        # This check is primarily run during connection setup
        # The actual transport analysis happens in scanner.py
        # This is a placeholder for the check registry
        return []

    def check_url(self, url: str) -> list[Finding]:
        """Check SSE URL for transport security issues."""
        findings: list[Finding] = []

        if url.startswith("http://"):
            findings.append(
                self.finding(
                    description="MCP server uses unencrypted HTTP transport",
                    evidence=f"Server URL: {url}",
                    remediation="Use HTTPS for MCP SSE connections. Unencrypted transport exposes all tool calls and data in transit.",
                )
            )

        if "localhost" not in url and "127.0.0.1" not in url and url.startswith("http://"):
            findings.append(
                self.finding(
                    description="Remote MCP server without TLS",
                    evidence=f"Non-local server URL without HTTPS: {url}",
                    remediation="Remote MCP servers MUST use TLS. Configure HTTPS on the server.",
                    severity=Severity.HIGH,
                )
            )

        return findings
