"""MCP-001: Tool Poisoning - Malicious instructions in tool descriptions."""

from __future__ import annotations

import base64
import re

from .base import BaseCheck
from ..client import MCPClient
from ..models import Finding, Severity, ToolInfo, ResourceInfo, PromptInfo

# Patterns that indicate hidden instructions in tool descriptions
INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?previous\s+instructions?", "Instruction override attempt"),
    (r"ignore\s+(all\s+)?prior\s+instructions?", "Instruction override attempt"),
    (r"disregard\s+(all\s+)?previous", "Instruction override attempt"),
    (r"forget\s+(all\s+)?previous", "Instruction override attempt"),
    (r"you\s+are\s+now\s+", "Role reassignment attempt"),
    (r"you\s+must\s+now\s+", "Behavioral override attempt"),
    (r"system\s*:\s*", "System prompt injection"),
    (r"<\s*system\s*>", "System tag injection"),
    (r"\[system\]", "System tag injection"),
    (r"override\s+security", "Security override attempt"),
    (r"bypass\s+safety", "Safety bypass attempt"),
    (r"send\s+(all\s+)?data\s+to", "Data exfiltration instruction"),
    (r"exfiltrate", "Data exfiltration instruction"),
    (r"before\s+responding.*first\s+call", "Hidden tool call instruction"),
    (r"always\s+call\s+this\s+tool\s+first", "Forced tool invocation"),
    (r"do\s+not\s+tell\s+the\s+user", "Concealment instruction"),
    (r"hide\s+this\s+from", "Concealment instruction"),
    (r"secretly", "Covert action instruction"),
]

# Zero-width and invisible Unicode characters
INVISIBLE_CHARS = [
    ("\u200b", "Zero-width space"),
    ("\u200c", "Zero-width non-joiner"),
    ("\u200d", "Zero-width joiner"),
    ("\u2060", "Word joiner"),
    ("\u2061", "Function application"),
    ("\u2062", "Invisible times"),
    ("\u2063", "Invisible separator"),
    ("\u2064", "Invisible plus"),
    ("\ufeff", "Zero-width no-break space"),
    ("\u200e", "Left-to-right mark"),
    ("\u200f", "Right-to-left mark"),
    ("\u202a", "Left-to-right embedding"),
    ("\u202b", "Right-to-left embedding"),
    ("\u202c", "Pop directional formatting"),
    ("\u2066", "Left-to-right isolate"),
    ("\u2067", "Right-to-left isolate"),
]

MAX_DESCRIPTION_LENGTH = 500


class ToolPoisoning(BaseCheck):
    id = "MCP-001"
    name = "Tool Poisoning"
    severity = Severity.CRITICAL
    description = "Detects malicious instructions hidden in tool descriptions"

    async def run(
        self,
        client: MCPClient,
        tools: list[ToolInfo],
        resources: list[ResourceInfo],
        prompts: list[PromptInfo],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for tool in tools:
            desc = tool.description
            if not desc:
                continue

            # Check for injection patterns
            for pattern, label in INJECTION_PATTERNS:
                match = re.search(pattern, desc, re.IGNORECASE)
                if match:
                    findings.append(
                        self.finding(
                            description=f"Tool description contains suspicious pattern: {label}",
                            evidence=f'Matched: "{match.group()}" in tool "{tool.name}"',
                            remediation="Review and sanitize the tool description. Remove any instruction-like content.",
                            tool_name=tool.name,
                        )
                    )

            # Check for invisible Unicode characters
            for char, char_name in INVISIBLE_CHARS:
                if char in desc:
                    # Extract surrounding context
                    idx = desc.index(char)
                    context = desc[max(0, idx - 20) : idx + 20]
                    findings.append(
                        self.finding(
                            description=f"Tool description contains invisible Unicode character: {char_name}",
                            evidence=f'Found {char_name} (U+{ord(char):04X}) in tool "{tool.name}" near: "{context}"',
                            remediation="Remove invisible Unicode characters from tool descriptions.",
                            tool_name=tool.name,
                        )
                    )
                    break  # One finding per tool for invisible chars

            # Check for HTML/Markdown comments hiding instructions
            comment_patterns = [
                (r"<!--(.+?)-->", "HTML comment"),
                (r"\[//\]:\s*#\s*\((.+?)\)", "Markdown comment"),
            ]
            for pattern, label in comment_patterns:
                match = re.search(pattern, desc, re.DOTALL)
                if match:
                    findings.append(
                        self.finding(
                            description=f"Tool description contains hidden {label}",
                            evidence=f'Hidden content in tool "{tool.name}": "{match.group(1)[:100]}"',
                            remediation=f"Remove {label}s from tool descriptions.",
                            tool_name=tool.name,
                        )
                    )

            # Check for base64-encoded content
            b64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
            for match in re.finditer(b64_pattern, desc):
                try:
                    decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
                    if any(c.isalpha() for c in decoded) and len(decoded) > 10:
                        findings.append(
                            self.finding(
                                description="Tool description contains Base64-encoded content",
                                evidence=f'Decoded content in tool "{tool.name}": "{decoded[:100]}"',
                                remediation="Remove encoded content from tool descriptions. All instructions should be plaintext.",
                                tool_name=tool.name,
                            )
                        )
                except Exception:
                    pass

            # Check for excessively long descriptions
            if len(desc) > MAX_DESCRIPTION_LENGTH:
                findings.append(
                    self.finding(
                        description="Excessively long tool description may hide instructions",
                        evidence=f'Tool "{tool.name}" description is {len(desc)} chars (max recommended: {MAX_DESCRIPTION_LENGTH})',
                        remediation="Keep tool descriptions concise. Long descriptions increase the risk of hidden content.",
                        tool_name=tool.name,
                        severity=Severity.MEDIUM,
                    )
                )

        return findings
