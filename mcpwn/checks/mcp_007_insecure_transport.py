"""MCP-007: Insecure Transport - MCP servers without TLS or authentication."""

from __future__ import annotations

from ..client import MCPClient
from ..models import Finding, PromptInfo, ResourceInfo, Severity, ToolInfo
from .base import BaseCheck


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
        *,
        aggressive: bool = False,
    ) -> list[Finding]:
        # This check is primarily run during connection setup
        # The actual transport analysis happens in scanner.py
        # This is a placeholder for the check registry
        return []

    def check_url(self, url: str) -> list[Finding]:
        """Check a remote endpoint URL for transport security issues."""
        findings: list[Finding] = []
        scheme = url.split("://", 1)[0].lower() if "://" in url else ""

        if scheme in ("http", "ws"):
            transport = "HTTP" if scheme == "http" else "WebSocket"
            secure = "HTTPS" if scheme == "http" else "WSS"
            findings.append(
                self.finding(
                    description=f"MCP server uses unencrypted {transport} transport",
                    evidence=f"Server URL: {url}",
                    remediation=(
                        f"Use {secure} for MCP connections. Unencrypted transport "
                        "exposes all tool calls and data in transit."
                    ),
                )
            )

            if "localhost" not in url and "127.0.0.1" not in url:
                findings.append(
                    self.finding(
                        description="Remote MCP server without TLS",
                        evidence=f"Non-local server URL without {secure}: {url}",
                        remediation="Remote MCP servers MUST use TLS. Configure TLS on the server.",
                        severity=Severity.HIGH,
                    )
                )

        return findings
