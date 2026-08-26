"""MCP-002: Prompt Injection via Tools - Tool outputs that inject into LLM context."""

from __future__ import annotations

import re
from uuid import uuid4

from ..client import MCPClient
from ..models import Finding, PromptInfo, ResourceInfo, Severity, ToolInfo
from .base import BaseCheck
from .util import build_benign_args, extract_text

OUTPUT_INJECTION_PATTERNS = [
    (r"system\s*:\s*", "System prompt in output"),
    (r"<\s*system\s*>", "System tag in output"),
    (r"\[INST\]", "Instruction tag in output"),
    (r"<<SYS>>", "Llama system tag in output"),
    (r"Human:\s*", "Anthropic role tag in output"),
    (r"Assistant:\s*", "Anthropic role tag in output"),
    (r"you\s+are\s+now\s+", "Role reassignment in output"),
    (r"ignore\s+previous\s+instructions?", "Instruction override in output"),
    (r"call\s+the\s+tool\s+", "Tool invocation request in output"),
    (r"use_mcp_tool", "MCP tool call in output"),
    (r"execute\s+command", "Command execution request in output"),
]

class PromptInjection(BaseCheck):
    id = "MCP-002"
    name = "Prompt Injection via Tools"
    severity = Severity.CRITICAL
    description = "Detects tool outputs that could inject prompts into LLM context"

    async def run(
        self,
        client: MCPClient,
        tools: list[ToolInfo],
        resources: list[ResourceInfo],
        prompts: list[PromptInfo],
        *,
        aggressive: bool = False,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for tool in tools:
            # Build test arguments from schema
            test_args = build_benign_args(tool)
            if test_args is None:
                continue

            # Call the tool with benign input
            try:
                result = await client.call_tool(tool.name, test_args)
            except Exception:
                continue

            if result is None:
                continue

            # Extract text content from result
            text = extract_text(result)
            if not text:
                continue

            # Check output for injection patterns
            for pattern, label in OUTPUT_INJECTION_PATTERNS:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    findings.append(
                        self.finding(
                            description=f"Tool output contains prompt injection: {label}",
                            evidence=(
                                f'Tool "{tool.name}" returned: '
                                f'"...{text[max(0, match.start() - 30):match.end() + 30]}..."'
                            ),
                            remediation=(
                                "Sanitize tool outputs to remove any content that "
                                "could be interpreted as LLM instructions."
                            ),
                            tool_name=tool.name,
                        )
                    )

        # Active probe: check if any tool reflects input into its output
        if aggressive:
            findings.extend(await self._probe_reflection(client, tools))

        return findings

    async def _probe_reflection(
        self, client: MCPClient, tools: list[ToolInfo]
    ) -> list[Finding]:
        """Aggressive-only: send a sentinel token and look for reflection."""
        findings: list[Finding] = []

        for tool in tools:
            base_args = build_benign_args(tool)
            if base_args is None:
                continue

            token = f"mcpwn_reflect_{uuid4().hex[:8]}"
            args = dict(base_args)
            placed = False
            for name, schema in tool.input_schema.get("properties", {}).items():
                if schema.get("type") == "string" and name in args:
                    args[name] = token
                    placed = True
            if not placed:
                continue

            try:
                result = await client.call_tool(tool.name, args)
            except Exception:
                continue

            text = extract_text(result) if result is not None else ""
            if token in text:
                findings.append(
                    self.finding(
                        description="Tool reflects input into output (injection vector)",
                        evidence=(
                            f'Tool "{tool.name}" echoed sentinel token "{token}" '
                            "in its output"
                        ),
                        remediation=(
                            "Tool outputs that echo raw input allow prompt-injection "
                            "payloads to be reflected into the LLM context. Sanitize "
                            "or escape returned values."
                        ),
                        tool_name=tool.name,
                        severity=Severity.HIGH,
                    )
                )

        return findings
