"""MCP-004: SSRF via Tools - Tools that can make requests to internal services."""

from __future__ import annotations

import re

from ..client import MCPClient
from ..models import Finding, PromptInfo, ResourceInfo, Severity, ToolInfo
from .base import BaseCheck
from .util import build_benign_args, extract_text

URL_PARAM_NAMES = {
    "url", "uri", "endpoint", "host", "target", "address",
    "server", "link", "href", "src", "destination",
}

DANGEROUS_PROTOCOLS = ["file://", "gopher://", "dict://", "ftp://", "ldap://", "sftp://"]

# Active probes (aggressive mode only)
PROBE_URLS = [
    ("http://127.0.0.1/", "loopback interface"),
    ("http://169.254.169.254/latest/meta-data/", "cloud metadata endpoint"),
    ("file:///etc/passwd", "local file read"),
]

MARKERS = [
    (r"root:.*:0:0:", "Unix passwd content"),
    (r"ami-id|instance-id|local-hostname", "cloud metadata content"),
]


class SSRF(BaseCheck):
    id = "MCP-004"
    name = "SSRF via Tools"
    severity = Severity.HIGH
    description = "Detects tools that accept URL parameters which could be abused for SSRF"

    def __init__(self, internal_ranges: list[str] | None = None) -> None:
        super().__init__()
        self.internal_ranges = internal_ranges or [
            "127.0.0.1",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.169.254",
        ]

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
            props = tool.input_schema.get("properties", {})

            for param_name, param_schema in props.items():
                if not self._is_url_param(param_name, param_schema):
                    continue

                # Check for restrictions
                has_pattern = "pattern" in param_schema
                has_enum = "enum" in param_schema

                if has_pattern or has_enum:
                    # Has some restriction, lower severity
                    findings.append(
                        self.finding(
                            description="Tool accepts URL parameter with partial restrictions",
                            evidence=(
                                f'Tool "{tool.name}" parameter "{param_name}" accepts URLs '
                                f'(has {"pattern" if has_pattern else "enum"} restriction)'
                            ),
                            remediation=(
                                "Ensure URL restrictions cover internal IP ranges "
                                "(10.x, 172.16.x, 192.168.x, 169.254.x) and dangerous protocols."
                            ),
                            tool_name=tool.name,
                            severity=Severity.MEDIUM,
                        )
                    )
                else:
                    # No restrictions at all
                    findings.append(
                        self.finding(
                            description="Tool accepts unrestricted URL parameter (SSRF risk)",
                            evidence=(
                                f'Tool "{tool.name}" parameter "{param_name}" accepts '
                                "arbitrary URLs without validation"
                            ),
                            remediation=(
                                "Add URL validation: block internal IP ranges "
                                f"({', '.join(self.internal_ranges)}), block dangerous "
                                "protocols (file://, gopher://), and use an allowlist "
                                "of permitted domains."
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
                                remediation=(
                                    "Ensure network-capable tools restrict access to internal "
                                    "networks and cloud metadata endpoints."
                                ),
                                tool_name=tool.name,
                                severity=Severity.MEDIUM,
                            )
                        )

        # Active probes: attempt to trigger SSRF against internal endpoints
        if aggressive:
            findings.extend(await self._probe(client, tools))

        return findings

    def _is_url_param(self, param_name: str, param_schema: dict) -> bool:
        """Whether the schema entry looks like a string parameter accepting URLs."""
        param_lower = param_name.lower()
        param_type = param_schema.get("type", "")
        param_desc = str(param_schema.get("description", "")).lower()
        param_format = param_schema.get("format", "")
        return bool(
            (
                param_lower in URL_PARAM_NAMES
                or param_format in ("uri", "url")
                or "url" in param_desc
                or "endpoint" in param_desc
            )
            and param_type == "string"
        )

    async def _probe(self, client: MCPClient, tools: list[ToolInfo]) -> list[Finding]:
        """Aggressive-only: call URL-accepting tools with internal probe URLs."""
        findings: list[Finding] = []

        for tool in tools:
            props = tool.input_schema.get("properties", {})
            url_params = [name for name, schema in props.items() if self._is_url_param(name, schema)]
            if not url_params:
                continue

            for param in url_params:
                for probe_url, label in PROBE_URLS:
                    args = dict(build_benign_args(tool) or {})
                    args[param] = probe_url
                    try:
                        result = await client.call_tool(tool.name, args)
                    except Exception:
                        continue

                    text = extract_text(result) if result is not None else ""
                    for marker, marker_label in MARKERS:
                        if re.search(marker, text):
                            findings.append(
                                self.finding(
                                    description=f"Confirmed SSRF: tool fetched {label}",
                                    evidence=(
                                        f'Tool "{tool.name}" parameter "{param}" '
                                        f"probed with {probe_url} and returned content "
                                        f"matching {marker_label}"
                                    ),
                                    remediation=(
                                        "Immediately restrict this tool: block access to "
                                        "internal IP ranges and dangerous protocols."
                                    ),
                                    tool_name=tool.name,
                                    severity=Severity.CRITICAL,
                                )
                            )
                            break

        return findings
