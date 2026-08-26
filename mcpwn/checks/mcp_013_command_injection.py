"""MCP-013: Command Injection - Tools that execute shell metacharacters in arguments."""

from __future__ import annotations

import re
from uuid import uuid4

from ..client import MCPClient
from ..models import Finding, PromptInfo, ResourceInfo, Severity, ToolInfo
from .base import BaseCheck
from .util import build_benign_args, extract_text

PAYLOADS = [
    "; echo {token}",
    "$(echo {token})",
    "`echo {token}`",
    "| echo {token}",
]


class CommandInjection(BaseCheck):
    id = "MCP-013"
    name = "Command Injection"
    severity = Severity.CRITICAL
    description = "Detects tools vulnerable to command injection via shell metacharacters"

    async def run(
        self,
        client: MCPClient,
        tools: list[ToolInfo],
        resources: list[ResourceInfo],
        prompts: list[PromptInfo],
        *,
        aggressive: bool = False,
    ) -> list[Finding]:
        # Active probe: never runs in safe mode
        if not aggressive:
            return []

        findings: list[Finding] = []

        for tool in tools:
            base_args = build_benign_args(tool)
            if base_args is None:
                continue

            string_params = [
                name
                for name, schema in tool.input_schema.get("properties", {}).items()
                if schema.get("type") == "string"
            ]

            token = f"mcpwn_pwned_{uuid4().hex[:8]}"
            for param in string_params:
                for payload in PAYLOADS:
                    args = dict(base_args)
                    args[param] = payload.format(token=token)

                    try:
                        result = await client.call_tool(tool.name, args)
                    except Exception:
                        continue

                    text = extract_text(result) if result is not None else ""
                    if self._is_shell_execution(text, token, args):
                        findings.append(
                            self.finding(
                                description="Confirmed command injection",
                                evidence=(
                                    f'Tool "{tool.name}" parameter "{param}" '
                                    f'reflected token with payload "{payload.format(token=token)}"'
                                ),
                                remediation=(
                                    "Do not pass tool arguments to shell "
                                    "interpreters. Use subprocess with a "
                                    "fixed argument list and never shell=True."
                                ),
                                tool_name=tool.name,
                            )
                        )
                        break  # One finding per tool
                else:
                    continue
                break  # Found injection for this tool

        return findings

    @staticmethod
    def _is_shell_execution(text: str, token: str, args: dict) -> bool:
        """Whether output is evidence of shell execution rather than input echo.

        Requires the token plus one of:
        - the token (or command echo containing it) on a shell prompt line
          (``$``, ``>``, ``#``), or
        - the token on its own line (bare command output).

        Tools that merely serialize their arguments (``str(args)`` in the
        output) or embed the value in prose are excluded — echoing input is
        not command execution.
        """
        if token not in text:
            return False
        if str(args) in text:
            return False
        escaped = re.escape(token)
        if re.search(rf"(?:^|\n)\s*[$#>][^\n]*{escaped}", text):
            return True
        if re.search(rf"(?:^|\n)\s*{escaped}\s*$", text, re.MULTILINE):
            return True
        return False
