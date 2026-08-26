"""MCP-006: Missing Input Validation - Tool parameters without proper schema validation."""

from __future__ import annotations

from ..client import MCPClient
from ..models import Finding, PromptInfo, ResourceInfo, Severity, ToolInfo
from .base import BaseCheck


class InputValidation(BaseCheck):
    id = "MCP-006"
    name = "Missing Input Validation"
    severity = Severity.MEDIUM
    description = "Detects tool parameters without proper schema validation"

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
            schema = tool.input_schema
            if not schema:
                findings.append(
                    self.finding(
                        description="Tool has no input schema defined",
                        evidence=f'Tool "{tool.name}" has no inputSchema',
                        remediation=(
                            "Define a JSON Schema for all tool inputs with "
                            "type, constraints, and descriptions."
                        ),
                        tool_name=tool.name,
                    )
                )
                continue

            props = schema.get("properties", {})
            required = set(schema.get("required", []))

            if not props:
                continue

            for param_name, param_schema in props.items():
                issues = []

                # Missing type
                if "type" not in param_schema:
                    issues.append("no type defined")

                param_type = param_schema.get("type", "")

                # String without constraints
                if param_type == "string":
                    if "maxLength" not in param_schema and "enum" not in param_schema and "pattern" not in param_schema:
                        issues.append("string without maxLength/enum/pattern")

                # Number without bounds
                if param_type in ("integer", "number"):
                    if "minimum" not in param_schema and "maximum" not in param_schema:
                        issues.append("number without min/max bounds")

                # Array without item schema
                if param_type == "array":
                    if "items" not in param_schema:
                        issues.append("array without items schema")
                    if "maxItems" not in param_schema:
                        issues.append("array without maxItems")

                # Missing description
                if "description" not in param_schema:
                    issues.append("no description")

                # Not in required list
                if param_name not in required and len(issues) > 0:
                    issues.append("optional (not in required)")

                if issues:
                    findings.append(
                        self.finding(
                            description=f"Parameter lacks validation: {', '.join(issues)}",
                            evidence=f'Tool "{tool.name}" parameter "{param_name}": {", ".join(issues)}',
                            remediation=(
                                "Add proper JSON Schema constraints: type, "
                                "maxLength/pattern for strings, min/max for "
                                "numbers, items/maxItems for arrays."
                            ),
                            tool_name=tool.name,
                            severity=(
                                Severity.LOW
                                if len(issues) == 1 and "no description" in issues
                                else Severity.MEDIUM
                            ),
                        )
                    )

        return findings
