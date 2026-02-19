"""Auto-discover and register all checks."""

from __future__ import annotations

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

ALL_CHECKS: list[BaseCheck] = [
    ToolPoisoning(),
    PromptInjection(),
    DataExfiltration(),
    SSRF(),
    ExcessivePermissions(),
    InputValidation(),
    InsecureTransport(),
    ResourceTraversal(),
    ToolChaining(),
    RugPull(),
]

CHECK_MAP: dict[str, BaseCheck] = {check.id: check for check in ALL_CHECKS}


def get_checks(filter_ids: list[str] | None = None) -> list[BaseCheck]:
    """Get checks, optionally filtered by IDs."""
    if filter_ids is None:
        return ALL_CHECKS
    return [CHECK_MAP[cid] for cid in filter_ids if cid in CHECK_MAP]
