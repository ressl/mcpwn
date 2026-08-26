import asyncio
import time
from typing import Callable

from .checks.mcp_007_insecure_transport import InsecureTransport
from .checks.registry import get_checks
from .client import MCPClient
from .models import Finding, ScanResult, ScanTarget, Severity


class Scanner:
    """Orchestrates MCP security scans."""

    def __init__(
        self,
        check_ids: list[str] | None = None,
        min_severity: Severity = Severity.LOW,
        timeout: int = 30,
        aggressive: bool = False,
        disabled: set[str] | None = None,
        options: dict[str, dict] | None = None,
        on_finding: Callable[[Finding], None] | None = None,
    ) -> None:
        self.checks = get_checks(check_ids, disabled=disabled, options=options)
        self.min_severity = min_severity
        self.timeout = timeout
        self.aggressive = aggressive
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

    async def scan_http(self, url: str) -> ScanResult:
        """Scan an MCP server via Streamable HTTP transport."""
        target = ScanTarget(transport="http", url=url)

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
            elif target.transport == "http" and target.url:
                ctx = client.connect_http(target.url)
            else:
                result.errors.append("Invalid target configuration")
                return result

            async with ctx as connected_client:
                target.tools = connected_client.tools
                target.resources = connected_client.resources
                target.prompts = connected_client.prompts
                result.errors.extend(connected_client.enumeration_errors)

                for check in self.checks:
                    try:
                        findings = await asyncio.wait_for(
                            check.run(
                                connected_client,
                                connected_client.tools,
                                connected_client.resources,
                                connected_client.prompts,
                                aggressive=self.aggressive,
                            ),
                            timeout=self.timeout,
                        )
                        for finding in findings:
                            if finding.severity >= self.min_severity:
                                result.findings.append(finding)
                                if self.on_finding:
                                    self.on_finding(finding)
                    except asyncio.TimeoutError:
                        result.errors.append(
                            f"Check {check.id} timed out after {self.timeout}s"
                        )
                    except Exception as e:
                        result.errors.append(f"Check {check.id} failed: {e}")

        except Exception as e:
            result.errors.append(f"Connection failed: {e}")

        result.duration_seconds = time.time() - start

        # Sort findings by severity (critical first)
        result.findings.sort(key=lambda f: f.severity.rank, reverse=True)

        return result
