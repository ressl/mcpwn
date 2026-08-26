"""Unit tests for the MCP client wrapper internals."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from mcpwn.client import MCPClient


class BoomSession:
    """Session whose tools listing always fails."""

    async def list_tools(self):
        raise RuntimeError("boom")

    async def list_resources(self):
        return SimpleNamespace(resources=[])

    async def list_prompts(self):
        return SimpleNamespace(prompts=[])


@pytest.mark.asyncio
async def test_enumerate_records_failures():
    client = MCPClient()
    client._session = BoomSession()  # noqa: SLF001
    await client._enumerate()  # noqa: SLF001
    assert client.enumeration_errors == ["Failed to list tools"]
    assert client.tools == []
    assert client.resources == []
    assert client.prompts == []


@pytest.mark.asyncio
async def test_enumerate_clean_no_errors():
    class OkSession:
        async def list_tools(self):
            return SimpleNamespace(tools=[])

        async def list_resources(self):
            return SimpleNamespace(resources=[])

        async def list_prompts(self):
            return SimpleNamespace(prompts=[])

    client = MCPClient()
    client._session = OkSession()  # noqa: SLF001
    await client._enumerate()  # noqa: SLF001
    assert client.enumeration_errors == []
