"""MCP-003: Data Exfiltration - Tools/resources that leak data to external endpoints."""

from __future__ import annotations

import re

from .base import BaseCheck
from ..client import MCPClient
from ..models import Finding, Severity, ToolInfo, ResourceInfo, PromptInfo

EXTERNAL_URL_PATTERN = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|example\.org)[^\s\"'<>]+",
    re.IGNORECASE,
)

EXFIL_KEYWORDS = [
    "webhook", "callback", "notify", "report_to", "send_to",
    "exfiltrate", "phone_home", "beacon", "collector",
]

DNS_EXFIL_PATTERN = re.compile(r"[a-zA-Z0-9]{20,}\.[a-zA-Z]{2,6}")


class DataExfiltration(BaseCheck):
    id = "MCP-003"
    name = "Data Exfiltration"
    severity = Severity.CRITICAL
    description = "Detects tools or resources that may leak sensitive data to external endpoints"

    async def run(
        self,
        client: MCPClient,
        tools: list[ToolInfo],
        resources: list[ResourceInfo],
        prompts: list[PromptInfo],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for tool in tools:
            desc = tool.description.lower()

            # Check for external URLs in descriptions
            urls = EXTERNAL_URL_PATTERN.findall(tool.description)
            for url in urls:
                findings.append(
                    self.finding(
                        description="Tool description references external URL",
                        evidence=f'Tool "{tool.name}" references: {url}',
                        remediation="Remove external URLs from tool descriptions. Tools should not reference external endpoints.",
                        tool_name=tool.name,
                    )
                )

            # Check for exfiltration keywords
            for keyword in EXFIL_KEYWORDS:
                if keyword in desc:
                    findings.append(
                        self.finding(
                            description=f"Tool description contains exfiltration keyword: {keyword}",
                            evidence=f'Tool "{tool.name}" description contains "{keyword}"',
                            remediation="Review tool purpose. Legitimate tools should not use exfiltration-related terminology.",
                            tool_name=tool.name,
                            severity=Severity.HIGH,
                        )
                    )

            # Check input schema for URL/endpoint parameters
            props = tool.input_schema.get("properties", {})
            for param_name, param_schema in props.items():
                param_desc = str(param_schema.get("description", "")).lower()
                if any(kw in param_name.lower() or kw in param_desc for kw in ["webhook", "callback", "endpoint", "url"]):
                    if "format" not in param_schema:
                        findings.append(
                            self.finding(
                                description=f"Tool accepts URL/endpoint parameter without validation",
                                evidence=f'Tool "{tool.name}" parameter "{param_name}" accepts URLs',
                                remediation="Validate and restrict URL parameters. Use allowlists for permitted domains.",
                                tool_name=tool.name,
                                severity=Severity.HIGH,
                            )
                        )

        # Check resources for external references
        for resource in resources:
            urls = EXTERNAL_URL_PATTERN.findall(resource.uri)
            for url in urls:
                findings.append(
                    self.finding(
                        description="Resource URI references external endpoint",
                        evidence=f'Resource "{resource.name}" URI: {url}',
                        remediation="Resources should reference local or trusted endpoints only.",
                        resource_uri=resource.uri,
                    )
                )

        return findings
