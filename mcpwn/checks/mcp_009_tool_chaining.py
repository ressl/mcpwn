"""MCP-009: Tool Call Chaining - Tool combinations that escalate privileges."""

from __future__ import annotations

from itertools import combinations

from .base import BaseCheck
from ..client import MCPClient
from ..models import Finding, Severity, ToolInfo, ResourceInfo, PromptInfo

# Dangerous tool capability pairs
DANGEROUS_CHAINS = [
    ({"read_file", "read", "cat", "get_file", "load"}, {"exec", "execute", "run_command", "shell", "eval", "run"}, "Read + Execute = Code injection"),
    ({"fetch", "fetch_url", "http_get", "download", "request"}, {"write_file", "write", "save", "create_file"}, "Fetch + Write = Arbitrary file write"),
    ({"list_directory", "ls", "list_files", "glob", "find"}, {"read_file", "read", "cat", "get_file"}, "List + Read = Full filesystem read"),
    ({"read_file", "read", "cat"}, {"fetch_url", "http_post", "send", "upload"}, "Read + Send = Data exfiltration"),
    ({"query_db", "sql", "execute_query"}, {"write_file", "write"}, "DB Query + Write = Data dump"),
    ({"get_env", "environment"}, {"fetch_url", "http_post", "send"}, "Env Read + Send = Secret exfiltration"),
]


class ToolChaining(BaseCheck):
    id = "MCP-009"
    name = "Tool Call Chaining"
    severity = Severity.HIGH
    description = "Detects tool combinations that could escalate privileges when chained"

    async def run(
        self,
        client: MCPClient,
        tools: list[ToolInfo],
        resources: list[ResourceInfo],
        prompts: list[PromptInfo],
    ) -> list[Finding]:
        findings: list[Finding] = []
        tool_names = {t.name.lower() for t in tools}
        tool_descs = {t.name.lower(): t.description.lower() for t in tools}

        for set_a, set_b, chain_desc in DANGEROUS_CHAINS:
            # Find matching tools for each set
            matches_a = []
            matches_b = []

            for tool_name in tool_names:
                desc = tool_descs.get(tool_name, "")

                # Match by name
                if tool_name in set_a or any(kw in tool_name for kw in set_a):
                    matches_a.append(tool_name)
                elif tool_name in set_b or any(kw in tool_name for kw in set_b):
                    matches_b.append(tool_name)
                else:
                    # Match by description keywords
                    for kw in set_a:
                        if kw in desc:
                            matches_a.append(tool_name)
                            break
                    for kw in set_b:
                        if kw in desc:
                            matches_b.append(tool_name)
                            break

            if matches_a and matches_b:
                for a in matches_a:
                    for b in matches_b:
                        findings.append(
                            self.finding(
                                description=f"Dangerous tool chain: {chain_desc}",
                                evidence=f'Tools "{a}" + "{b}" can be chained for privilege escalation',
                                remediation=(
                                    "Implement tool-level authorization. Consider: "
                                    "1) Restricting which tools can be called together, "
                                    "2) Adding confirmation prompts for dangerous sequences, "
                                    "3) Sandboxing tool execution environments."
                                ),
                                tool_name=f"{a} + {b}",
                            )
                        )

        return findings
