"""MCP-003: Data Exfiltration - Tools/resources that leak data to external endpoints."""

from __future__ import annotations

import re
from uuid import uuid4

from ..client import MCPClient
from ..models import Finding, PromptInfo, ResourceInfo, Severity, ToolInfo
from .base import BaseCheck
from .util import build_benign_args, extract_text

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

    def __init__(self, callback_host: str | None = None) -> None:
        super().__init__()
        self.callback_host = callback_host

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
            desc = tool.description.lower()

            # Check for external URLs in descriptions
            urls = EXTERNAL_URL_PATTERN.findall(tool.description)
            for url in urls:
                findings.append(
                    self.finding(
                        description="Tool description references external URL",
                        evidence=f'Tool "{tool.name}" references: {url}',
                        remediation=(
                            "Remove external URLs from tool descriptions. "
                            "Tools should not reference external endpoints."
                        ),
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
                            remediation=(
                                "Review tool purpose. Legitimate tools should not "
                                "use exfiltration-related terminology."
                            ),
                            tool_name=tool.name,
                            severity=Severity.HIGH,
                        )
                    )

            # Check input schema for URL/endpoint parameters
            props = tool.input_schema.get("properties", {})
            for param_name, param_schema in props.items():
                param_desc = str(param_schema.get("description", "")).lower()
                if any(
                    kw in param_name.lower() or kw in param_desc for kw in ["webhook", "callback", "endpoint", "url"]
                ):
                    if "format" not in param_schema:
                        findings.append(
                            self.finding(
                                description="Tool accepts URL/endpoint parameter without validation",
                                evidence=f'Tool "{tool.name}" parameter "{param_name}" accepts URLs',
                                remediation=(
                                    "Validate and restrict URL parameters. "
                                    "Use allowlists for permitted domains."
                                ),
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

        # Active probe: plant a canary and look for cross-tool data flow
        if aggressive:
            findings.extend(await self._probe_canary(client, tools, resources))

        return findings

    async def _probe_canary(
        self,
        client: MCPClient,
        tools: list[ToolInfo],
        resources: list[ResourceInfo],
    ) -> list[Finding]:
        """Aggressive-only: detect data flow between tools via a canary token."""
        findings: list[Finding] = []

        planted: list[tuple[str, str]] = []
        for tool in tools:
            base_args = build_benign_args(tool)
            if base_args is None:
                continue

            props = tool.input_schema.get("properties", {})
            string_params = [name for name, schema in props.items() if schema.get("type") == "string"]
            if not string_params:
                continue

            canary = f"mcpwn_canary_{uuid4().hex[:8]}"
            args = dict(base_args)

            # Callback exfiltration test: URL-ish params get a callback URL
            if self.callback_host:
                for param in string_params:
                    param_desc = str(props[param].get("description", "")).lower()
                    if (
                        param.lower() in {"url", "uri", "endpoint", "webhook", "callback", "host", "target"}
                        or "url" in param_desc
                    ):
                        args[param] = f"https://{self.callback_host}/{canary}"

            # Plant the canary into the first string param
            args[string_params[0]] = canary

            try:
                await client.call_tool(tool.name, args)
            except Exception:
                continue

            planted.append((tool.name, canary))

        # Look for the canary in foreign tool outputs and resources
        for tool in tools:
            base_args = build_benign_args(tool)
            if base_args is None:
                continue
            try:
                result = await client.call_tool(tool.name, base_args)
            except Exception:
                continue
            text = extract_text(result) if result is not None else ""
            for tool_a, canary in planted:
                if tool_a != tool.name and canary in text:
                    findings.append(
                        self.finding(
                            description="Data flows between tools: canary crossed tool boundary",
                            evidence=(
                                f"Canary planted in {tool_a} appeared in "
                                f'output of tool "{tool.name}"'
                            ),
                            remediation=(
                                "Tools must not share or propagate unauthenticated "
                                "data between each other. Audit the data flow."
                            ),
                            tool_name=tool.name,
                            severity=Severity.HIGH,
                        )
                    )

        for resource in resources:
            result = await client.read_resource(resource.uri)
            text = extract_text(result) if result is not None else ""
            for tool_a, canary in planted:
                if canary in text:
                    findings.append(
                        self.finding(
                            description="Data flows between tools: canary crossed tool boundary",
                            evidence=(
                                f"Canary planted in {tool_a} appeared in "
                                f'resource "{resource.name}"'
                            ),
                            remediation=(
                                "Tools must not share or propagate unauthenticated "
                                "data between each other. Audit the data flow."
                            ),
                            resource_uri=resource.uri,
                            severity=Severity.HIGH,
                        )
                    )

        return findings
