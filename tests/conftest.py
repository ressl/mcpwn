"""Shared fixtures for mcpwn tests."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

VULNERABLE_SERVER = Path(__file__).parent.parent / "examples" / "vulnerable_server.py"


class StubClient:
    """Minimal MCPClient stand-in implementing the surface the checks use."""

    def __init__(
        self,
        tool_responses: dict[str, Any | Callable[[dict], Any]] | None = None,
        resource_responses: dict[str, Any] | None = None,
        tool_listings: list[Any] | None = None,
    ) -> None:
        self.tool_responses = tool_responses or {}
        self.resource_responses = resource_responses or {}
        self.tool_listings = list(tool_listings or [])
        self.calls: list[tuple[str, dict]] = []

    @property
    def tools(self):
        return []

    @property
    def resources(self):
        return []

    @property
    def prompts(self):
        return []

    async def call_tool(self, name: str, arguments: dict | None = None) -> Any:
        args = arguments or {}
        self.calls.append((name, args))
        resp = self.tool_responses.get(name)
        if callable(resp):
            return resp(args)
        return resp

    async def read_resource(self, uri: str) -> Any:
        return self.resource_responses.get(uri)

    async def list_tools_raw(self) -> Any:
        if not self.tool_listings:
            return SimpleNamespace(tools=[])
        return self.tool_listings.pop(0)


@pytest.fixture
def stub_client() -> StubClient:
    return StubClient()
