"""MCP-012: Secrets in Resources - Resources that expose credentials or secret material."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from ..client import MCPClient
from ..models import Finding, PromptInfo, ResourceInfo, Severity, ToolInfo
from .base import BaseCheck
from .util import extract_text

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "Private key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"github_pat_[A-Za-z0-9_]{22,}", "GitHub fine-grained token"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI-style API key"),
    (
        r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}",
        "Hardcoded credential",
    ),
]

MAX_RESOURCES_SCANNED = 50
MAX_CONTENT_CHARS = 1_000_000
MAX_READ_CONCURRENCY = 10


class SecretsInResources(BaseCheck):
    id = "MCP-012"
    name = "Secrets in Resources"
    severity = Severity.CRITICAL
    description = "Detects resources that expose credentials or secret material"

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

        to_read = resources[:MAX_RESOURCES_SCANNED]
        sem = asyncio.Semaphore(MAX_READ_CONCURRENCY)

        async def read_safe(resource: ResourceInfo) -> Any:
            async with sem:
                return await client.read_resource(resource.uri)

        contents = await asyncio.gather(
            *(read_safe(r) for r in to_read),
            return_exceptions=True,
        )

        for resource, result in zip(to_read, contents):
            # Scan the resource description (available without reading)
            text = resource.description

            # Read resource content (benign in safe mode)
            if isinstance(result, BaseException):
                extra_text = ""
            elif result is not None:
                extra_text = extract_text(result)
            else:
                extra_text = ""
            if extra_text:
                text = f"{text}\n{extra_text}"
            text = text[:MAX_CONTENT_CHARS]

            for pattern, label in SECRET_PATTERNS:
                match = re.search(pattern, text)
                if match:
                    redacted = f"{match.group(0)[:8]}..."
                    findings.append(
                        self.finding(
                            description=f"Resource exposes {label}",
                            evidence=(
                                f'{label} in resource "{resource.name}" '
                                f'({resource.uri}): "{redacted}"'
                            ),
                            remediation=(
                                "Remove secrets from MCP resources. Store "
                                "credentials in a secret manager and reference "
                                "them indirectly."
                            ),
                            resource_uri=resource.uri,
                        )
                    )

        return findings
