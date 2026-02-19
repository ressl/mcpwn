"""MCP-005: Excessive Permissions - Tools with overly broad capabilities."""

from __future__ import annotations

import re

from .base import BaseCheck
from ..client import MCPClient
from ..models import Finding, Severity, ToolInfo, ResourceInfo, PromptInfo

DANGEROUS_CAPABILITIES = {
    "file_write": {
        "keywords": ["write_file", "create_file", "save_file", "write", "overwrite", "append_file"],
        "description_hints": ["write to", "create file", "save to disk", "modify file"],
        "severity": Severity.HIGH,
        "label": "File write access",
    },
    "file_delete": {
        "keywords": ["delete_file", "remove_file", "unlink", "rm", "rmdir"],
        "description_hints": ["delete", "remove file", "unlink"],
        "severity": Severity.HIGH,
        "label": "File deletion access",
    },
    "command_exec": {
        "keywords": ["run_command", "execute", "exec", "shell", "system", "eval", "spawn", "subprocess"],
        "description_hints": ["execute command", "run shell", "system command", "arbitrary command", "run code"],
        "severity": Severity.CRITICAL,
        "label": "Command/code execution",
    },
    "network": {
        "keywords": ["fetch_url", "http_request", "curl", "wget", "download", "upload"],
        "description_hints": ["make http", "send request", "fetch url", "network access"],
        "severity": Severity.HIGH,
        "label": "Network access",
    },
    "database": {
        "keywords": ["query_db", "sql", "execute_query", "raw_query", "run_sql"],
        "description_hints": ["execute sql", "raw query", "database query", "run sql"],
        "severity": Severity.HIGH,
        "label": "Raw database access",
    },
    "env_access": {
        "keywords": ["get_env", "environment", "env_var", "getenv"],
        "description_hints": ["environment variable", "read env", "access env"],
        "severity": Severity.HIGH,
        "label": "Environment variable access",
    },
}


class ExcessivePermissions(BaseCheck):
    id = "MCP-005"
    name = "Excessive Permissions"
    severity = Severity.HIGH
    description = "Detects tools with overly broad or dangerous capabilities"

    async def run(
        self,
        client: MCPClient,
        tools: list[ToolInfo],
        resources: list[ResourceInfo],
        prompts: list[PromptInfo],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for tool in tools:
            tool_lower = tool.name.lower()
            desc_lower = tool.description.lower()

            for cap_name, cap_info in DANGEROUS_CAPABILITIES.items():
                matched = False
                match_source = ""

                # Check tool name
                for keyword in cap_info["keywords"]:
                    if keyword in tool_lower:
                        matched = True
                        match_source = f'tool name matches "{keyword}"'
                        break

                # Check description
                if not matched:
                    for hint in cap_info["description_hints"]:
                        if hint in desc_lower:
                            matched = True
                            match_source = f'description contains "{hint}"'
                            break

                if matched:
                    # Check if there are any restrictions in the schema
                    has_restrictions = self._check_restrictions(tool)
                    sev = cap_info["severity"]
                    if has_restrictions:
                        sev = Severity.MEDIUM

                    findings.append(
                        self.finding(
                            description=f"Tool has {cap_info['label']}{' (with some restrictions)' if has_restrictions else ' (unrestricted)'}",
                            evidence=f'Tool "{tool.name}": {match_source}',
                            remediation=(
                                f"Restrict {cap_info['label'].lower()}. "
                                "Use allowlists, sandboxing, or least-privilege principles."
                            ),
                            tool_name=tool.name,
                            severity=sev,
                        )
                    )

        return findings

    def _check_restrictions(self, tool: ToolInfo) -> bool:
        """Check if tool schema has any restrictions."""
        props = tool.input_schema.get("properties", {})
        for prop_schema in props.values():
            if any(k in prop_schema for k in ["enum", "pattern", "maxLength", "maximum", "const"]):
                return True
        return False
