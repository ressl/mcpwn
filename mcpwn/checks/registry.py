"""Auto-discover and register all checks."""

from __future__ import annotations

from typing import Any

from .base import BaseCheck
from .mcp_001_tool_poisoning import ToolPoisoning
from .mcp_002_prompt_injection import PromptInjection
from .mcp_003_data_exfiltration import DataExfiltration
from .mcp_004_ssrf import SSRF
from .mcp_005_excessive_permissions import ExcessivePermissions
from .mcp_006_input_validation import InputValidation
from .mcp_007_insecure_transport import InsecureTransport
from .mcp_008_resource_traversal import ResourceTraversal
from .mcp_009_tool_chaining import ToolChaining
from .mcp_010_rug_pull import RugPull
from .mcp_011_prompt_poisoning import PromptPoisoning
from .mcp_012_secrets_in_resources import SecretsInResources
from .mcp_013_command_injection import CommandInjection

CHECK_MAP: dict[str, type[BaseCheck]] = {
    "MCP-001": ToolPoisoning,
    "MCP-002": PromptInjection,
    "MCP-003": DataExfiltration,
    "MCP-004": SSRF,
    "MCP-005": ExcessivePermissions,
    "MCP-006": InputValidation,
    "MCP-007": InsecureTransport,
    "MCP-008": ResourceTraversal,
    "MCP-009": ToolChaining,
    "MCP-010": RugPull,
    "MCP-011": PromptPoisoning,
    "MCP-012": SecretsInResources,
    "MCP-013": CommandInjection,
}


def get_checks(
    filter_ids: list[str] | None = None,
    *,
    disabled: set[str] | None = None,
    options: dict[str, dict[str, Any]] | None = None,
) -> list[BaseCheck]:
    """Get checks, optionally filtered by IDs, minus disabled, with per-check options."""
    ids = filter_ids if filter_ids is not None else list(CHECK_MAP)
    all_options = options or {}
    return [
        CHECK_MAP[cid](**all_options.get(cid, {}))
        for cid in ids
        if cid in CHECK_MAP and cid not in (disabled or set())
    ]
