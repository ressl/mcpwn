"""MCP-004: SSRF via Tools - Tools that can make requests to internal services."""

from __future__ import annotations

import re

from .base import BaseCheck
from ..client import MCPClient
from ..models import Finding, Severity, ToolInfo, ResourceInfo, PromptInfo

URL_PARAM_NAMES = {"url", "uri", "endpoint", "host", "target", "address", "server", "link", "href", "src", "destination"}

DANGEROUS_PROTOCOLS = ["file://", "gopher://", "dict://", "ftp://", "ldap://", "sftp://"]


class SSRF(BaseCheck):
    id = "MCP-004"
    name = "SSRF via Tools"
    severity = Severity.HIGH
    description = "Detects tools that accept URL parameters which could be abused for SSRF"

    async def run(
        self,
        client: MCPClient,
        tools: list[ToolInfo],
        resources: list[ResourceInfo],
        prompts: list[PromptInfo],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for tool in tools:
            props = tool.input_schema.get("properties", {})

            for param_name, param_schema in props.items():
                param_lower = param_name.lower()
                param_type = param_schema.get("type", "")
                param_desc = str(param_schema.get("description", "")).lower()
                param_format = param_schema.get("format", "")

                # Check if parameter looks like it accepts URLs
                is_url_param = (
                    param_lower in URL_PARAM_NAMES
                    or param_format in ("uri", "url")
                    or "url" in param_desc
                    or "endpoint" in param_desc
                )

                if not is_url_param or param_type != "string":
                    continue

                # Check for restrictions
                has_pattern = "pattern" in param_schema
                has_enum = "enum" in param_schema

                if has_pattern or has_enum:
                    # Has some restriction, lower severity
                    findings.append(
                        self.finding(
                            description="Tool accepts URL parameter with partial restrictions",
                            evidence=f'Tool "{tool.name}" parameter "{param_name}" accepts URLs (has {"pattern" if has_pattern else "enum"} restriction)',
                            remediation="Ensure URL restrictions cover internal IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x) and dangerous protocols.",
                            tool_name=tool.name,
                            severity=Severity.MEDIUM,
                        )
                    )
                else:
                    # No restrictions at all
                    findings.append(
                        self.finding(
                            description="Tool accepts unrestricted URL parameter (SSRF risk)",
                            evidence=f'Tool "{tool.name}" parameter "{param_name}" accepts arbitrary URLs without validation',
                            remediation=(
                                "Add URL validation: block internal IP ranges (127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, "
                                "192.168.0.0/16, 169.254.169.254), block dangerous protocols (file://, gopher://), "
                                "and use an allowlist of permitted domains."
                            ),
                            tool_name=tool.name,
                        )
                    )

            # Also check tool description for fetch/request capabilities
            desc_lower = tool.description.lower()
            if any(kw in desc_lower for kw in ["fetch", "request", "download", "http", "curl", "wget"]):
                if not any(kw in desc_lower for kw in ["restrict", "allowlist", "whitelist", "internal only"]):
                    # Only flag if not already found via parameter analysis
                    if not any(f.tool_name == tool.name for f in findings):
                        findings.append(
                            self.finding(
                                description="Tool has network fetch capability",
                                evidence=f'Tool "{tool.name}" description indicates HTTP request capability',
                                remediation="Ensure network-capable tools restrict access to internal networks and cloud metadata endpoints.",
                                tool_name=tool.name,
                                severity=Severity.MEDIUM,
                            )
                        )

        return findings
