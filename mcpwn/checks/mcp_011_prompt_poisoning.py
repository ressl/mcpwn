"""MCP-011: Prompt Poisoning - Malicious instructions hidden in prompt definitions."""

from __future__ import annotations

import re

from ..client import MCPClient
from ..models import Finding, PromptInfo, ResourceInfo, Severity, ToolInfo
from .base import BaseCheck
from .mcp_001_tool_poisoning import INJECTION_PATTERNS, INVISIBLE_CHARS


class PromptPoisoning(BaseCheck):
    id = "MCP-011"
    name = "Prompt Poisoning"
    severity = Severity.HIGH
    description = "Detects malicious instructions hidden in prompt definitions"

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

        for prompt in prompts:
            fields = [("name", prompt.name), ("description", prompt.description)]
            for arg in prompt.arguments:
                fields.append(("argument name", str(arg.get("name", ""))))
                fields.append(("argument description", str(arg.get("description", ""))))

            for field_name, field_value in fields:
                if not field_value:
                    continue

                # Check for injection patterns
                for pattern, label in INJECTION_PATTERNS:
                    match = re.search(pattern, field_value, re.IGNORECASE)
                    if match:
                        findings.append(
                            self.finding(
                                description=f"Prompt {field_name} contains suspicious pattern: {label}",
                                evidence=f'Matched: "{match.group()}" in prompt "{prompt.name}"',
                                remediation=(
                                    "Review and sanitize prompt definitions. "
                                    "Remove any instruction-like content."
                                ),
                            )
                        )

                # Check for invisible Unicode characters
                for char, char_name in INVISIBLE_CHARS:
                    if char in field_value:
                        idx = field_value.index(char)
                        context = field_value[max(0, idx - 20) : idx + 20]
                        findings.append(
                            self.finding(
                                description=(
                                    f"Prompt {field_name} contains invisible "
                                    f"Unicode character: {char_name}"
                                ),
                                evidence=(
                                    f"Found {char_name} (U+{ord(char):04X}) in "
                                    f'prompt "{prompt.name}" near: "{context}"'
                                ),
                                remediation=(
                                    "Remove invisible Unicode characters from "
                                    "prompt definitions."
                                ),
                            )
                        )
                        break  # One finding per field for invisible chars

        return findings
