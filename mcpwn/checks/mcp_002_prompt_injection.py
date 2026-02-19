"""MCP-002: Prompt Injection via Tools - Tool outputs that inject into LLM context."""

from __future__ import annotations

import re

from .base import BaseCheck
from ..client import MCPClient
from ..models import Finding, Severity, ToolInfo, ResourceInfo, PromptInfo

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

# Benign test inputs for different tool types
BENIGN_INPUTS: dict[str, dict] = {
    "default": {"input": "test"},
    "search": {"query": "hello world"},
    "fetch": {"url": "https://example.com"},
    "read": {"path": "/tmp/test.txt"},
    "execute": {"command": "echo test"},
    "query": {"sql": "SELECT 1"},
}


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
    ) -> list[Finding]:
        findings: list[Finding] = []

        for tool in tools:
            # Build test arguments from schema
            test_args = self._build_test_args(tool)
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
            text = self._extract_text(result)
            if not text:
                continue

            # Check output for injection patterns
            for pattern, label in OUTPUT_INJECTION_PATTERNS:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    findings.append(
                        self.finding(
                            description=f"Tool output contains prompt injection: {label}",
                            evidence=f'Tool "{tool.name}" returned: "...{text[max(0, match.start()-30):match.end()+30]}..."',
                            remediation="Sanitize tool outputs to remove any content that could be interpreted as LLM instructions.",
                            tool_name=tool.name,
                        )
                    )

        return findings

    def _build_test_args(self, tool: ToolInfo) -> dict | None:
        """Build test arguments from tool schema."""
        schema = tool.input_schema
        if not schema:
            return {}

        properties = schema.get("properties", {})
        required = schema.get("required", [])

        if not properties and not required:
            return {}

        args = {}
        for prop_name, prop_schema in properties.items():
            prop_type = prop_schema.get("type", "string")
            if prop_type == "string":
                args[prop_name] = "test"
            elif prop_type == "integer":
                args[prop_name] = 1
            elif prop_type == "number":
                args[prop_name] = 1.0
            elif prop_type == "boolean":
                args[prop_name] = True
            elif prop_type == "array":
                args[prop_name] = []
            elif prop_type == "object":
                args[prop_name] = {}

        return args if args else {}

    def _extract_text(self, result) -> str:
        """Extract text content from MCP tool result."""
        if isinstance(result, str):
            return result
        if hasattr(result, "content"):
            parts = []
            for item in result.content:
                if hasattr(item, "text"):
                    parts.append(item.text)
            return "\n".join(parts)
        return str(result)
