"""Shared helpers for security checks."""

from __future__ import annotations

from typing import Any

from ..models import ToolInfo


def build_benign_args(tool: ToolInfo) -> dict | None:
    """Build benign test arguments from a tool's input schema.

    Returns None when no arguments can be constructed (e.g. a properties
    mapping whose values are not typed permissively). Mirrors the exact
    logic formerly private to ``PromptInjection._build_test_args``.
    """
    schema = tool.input_schema
    if not schema:
        return {}

    properties = schema.get("properties", {})
    required = schema.get("required", [])

    if not properties and not required:
        return {}

    args: dict[str, Any] = {}
    for prop_name, prop_schema in properties.items():
        prop_type = prop_schema.get("type", "string")
        if prop_type == "string":
            args[prop_name] = "test"
        elif prop_type == "integer":
            args[prop_name] = 1
        elif prop_type == "number":
            args[prop_name] = 1.0
        elif prop_type == "boolean":
            args[prop_name] = True
        elif prop_type == "array":
            args[prop_name] = []
        elif prop_type == "object":
            args[prop_name] = {}

    return args if args else {}


def extract_text(result: Any) -> str:
    """Extract text content from an MCP tool/resource result.

    Handles raw strings, results with a ``content`` list of text-bearing
    items, and falls back to stringification for anything else.
    """
    if isinstance(result, str):
        return result
    for attr in ("content", "contents"):
        if hasattr(result, attr):
            parts = []
            for item in getattr(result, attr):
                if hasattr(item, "text"):
                    parts.append(item.text)
            if parts or attr == "contents":
                return "\n".join(parts)
    return str(result)
