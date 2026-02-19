"""MCP-010: Rug Pull - Tools that change behavior after initial approval."""

from __future__ import annotations

import asyncio

from .base import BaseCheck
from ..client import MCPClient
from ..models import Finding, Severity, ToolInfo, ResourceInfo, PromptInfo


class RugPull(BaseCheck):
    id = "MCP-010"
    name = "Rug Pull"
    severity = Severity.CRITICAL
    description = "Detects tools that change behavior between calls (post-approval manipulation)"

    async def run(
        self,
        client: MCPClient,
        tools: list[ToolInfo],
        resources: list[ResourceInfo],
        prompts: list[PromptInfo],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Get initial tool listing
        try:
            initial = await client.list_tools_raw()
        except Exception:
            return findings

        # Wait a moment
        await asyncio.sleep(2)

        # Get second listing
        try:
            second = await client.list_tools_raw()
        except Exception:
            return findings

        # Compare tool counts
        initial_tools = {t.name: t for t in initial.tools}
        second_tools = {t.name: t for t in second.tools}

        # New tools appeared
        new_tools = set(second_tools.keys()) - set(initial_tools.keys())
        if new_tools:
            findings.append(
                self.finding(
                    description="New tools appeared between listings (possible rug pull)",
                    evidence=f"Tools added between calls: {', '.join(new_tools)}",
                    remediation="MCP servers should not dynamically add tools after initial connection. Pin tool listings.",
                )
            )

        # Tools disappeared
        removed_tools = set(initial_tools.keys()) - set(second_tools.keys())
        if removed_tools:
            findings.append(
                self.finding(
                    description="Tools disappeared between listings",
                    evidence=f"Tools removed between calls: {', '.join(removed_tools)}",
                    remediation="MCP servers should maintain consistent tool listings.",
                    severity=Severity.HIGH,
                )
            )

        # Tool descriptions changed
        for name in set(initial_tools.keys()) & set(second_tools.keys()):
            t1 = initial_tools[name]
            t2 = second_tools[name]

            desc1 = t1.description or ""
            desc2 = t2.description or ""

            if desc1 != desc2:
                findings.append(
                    self.finding(
                        description="Tool description changed between listings (rug pull!)",
                        evidence=f'Tool "{name}" description changed from "{desc1[:80]}..." to "{desc2[:80]}..."',
                        remediation="Tool descriptions must be immutable. Changing descriptions after approval is a rug pull attack.",
                        tool_name=name,
                    )
                )

            # Compare schemas
            schema1 = t1.inputSchema if hasattr(t1, "inputSchema") else {}
            schema2 = t2.inputSchema if hasattr(t2, "inputSchema") else {}
            if str(schema1) != str(schema2):
                findings.append(
                    self.finding(
                        description="Tool input schema changed between listings",
                        evidence=f'Tool "{name}" schema changed between calls',
                        remediation="Tool schemas must be immutable after initial listing.",
                        tool_name=name,
                    )
                )

        return findings
