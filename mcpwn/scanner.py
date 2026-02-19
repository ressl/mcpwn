"""Main scanner orchestration."""

from __future__ import annotations

import time
from typing import Callable

from .client import MCPClient
from .checks.base import BaseCheck
from .checks.registry import get_checks
from .checks.mcp_007_insecure_transport import InsecureTransport
from .models import Finding, Severity, ScanTarget, ScanResult


class Scanner:
    """Orchestrates MCP security scans."""

    def __init__(
        self,
        check_ids: list[str] | None = None,
        min_severity: Severity = Severity.LOW,
        timeout: int = 30,
        on_finding: Callable[[Finding], None] | None = None,
    ) -> None:
        self.checks = get_checks(check_ids)
        self.min_severity = min_severity
        self.timeout = timeout
        self.on_finding = on_finding

    async def scan_stdio(self, command: str) -> ScanResult:
        """Scan an MCP server via stdio transport."""
        target = ScanTarget(transport="stdio", command=command)
        return await self._scan(target)

    async def scan_sse(self, url: str) -> ScanResult:
        """Scan an MCP server via SSE transport."""
        target = ScanTarget(transport="sse", url=url)

        # Pre-connection transport check
        transport_check = InsecureTransport()
        transport_findings = transport_check.check_url(url)
        result = await self._scan(target)
        result.findings = transport_findings + result.findings
        return result

    async def _scan(self, target: ScanTarget) -> ScanResult:
        """Execute the scan against a target."""
        start = time.time()
        result = ScanResult(target=target)
        client = MCPClient()

        try:
            if target.transport == "stdio" and target.command:
                ctx = client.connect_stdio(target.command)
            elif target.transport == "sse" and target.url:
                ctx = client.connect_sse(target.url)
            else:
                result.errors.append("Invalid target configuration")
                return result

            async with ctx as connected_client:
                target.tools = connected_client.tools
                target.resources = connected_client.resources
                target.prompts = connected_client.prompts

                for check in self.checks:
                    try:
                        findings = await check.run(
                            connected_client,
                            connected_client.tools,
                            connected_client.resources,
                            connected_client.prompts,
                        )
                        for finding in findings:
                            if finding.severity >= self.min_severity:
                                result.findings.append(finding)
                                if self.on_finding:
                                    self.on_finding(finding)
                    except Exception as e:
                        result.errors.append(f"Check {check.id} failed: {e}")

        except Exception as e:
            result.errors.append(f"Connection failed: {e}")

        result.duration_seconds = time.time() - start

        # Sort findings by severity (critical first)
        result.findings.sort(key=lambda f: f.severity.rank, reverse=True)

        return result
