"""MCP client wrapper for connecting to and interacting with MCP servers."""

from __future__ import annotations

import asyncio
import shlex
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client

from .models import ToolInfo, ResourceInfo, PromptInfo


class MCPClient:
    """Wrapper around MCP SDK for security scanning."""

    def __init__(self) -> None:
        self._session: ClientSession | None = None
        self._tools: list[ToolInfo] = []
        self._resources: list[ResourceInfo] = []
        self._prompts: list[PromptInfo] = []

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("Not connected. Use connect_stdio() or connect_sse().")
        return self._session

    @asynccontextmanager
    async def connect_stdio(self, command: str) -> AsyncGenerator[MCPClient, None]:
        """Connect to an MCP server via stdio transport."""
        parts = shlex.split(command)
        server_params = StdioServerParameters(command=parts[0], args=parts[1:])

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                self._session = session
                await session.initialize()
                await self._enumerate()
                yield self
                self._session = None

    @asynccontextmanager
    async def connect_sse(self, url: str) -> AsyncGenerator[MCPClient, None]:
        """Connect to an MCP server via SSE transport."""
        async with sse_client(url) as (read, write):
            async with ClientSession(read, write) as session:
                self._session = session
                await session.initialize()
                await self._enumerate()
                yield self
                self._session = None

    async def _enumerate(self) -> None:
        """Enumerate all tools, resources, and prompts."""
        self._tools = []
        self._resources = []
        self._prompts = []

        try:
            result = await self.session.list_tools()
            for tool in result.tools:
                self._tools.append(
                    ToolInfo(
                        name=tool.name,
                        description=tool.description or "",
                        input_schema=tool.inputSchema if hasattr(tool, "inputSchema") else {},
                    )
                )
        except Exception:
            pass

        try:
            result = await self.session.list_resources()
            for res in result.resources:
                self._resources.append(
                    ResourceInfo(
                        uri=str(res.uri),
                        name=res.name or "",
                        description=res.description or "" if hasattr(res, "description") else "",
                        mime_type=res.mimeType or "" if hasattr(res, "mimeType") else "",
                    )
                )
        except Exception:
            pass

        try:
            result = await self.session.list_prompts()
            for prompt in result.prompts:
                self._prompts.append(
                    PromptInfo(
                        name=prompt.name,
                        description=prompt.description or "" if hasattr(prompt, "description") else "",
                    )
                )
        except Exception:
            pass

    @property
    def tools(self) -> list[ToolInfo]:
        return self._tools

    @property
    def resources(self) -> list[ResourceInfo]:
        return self._resources

    @property
    def prompts(self) -> list[PromptInfo]:
        return self._prompts

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Call a tool and return the result."""
        try:
            result = await asyncio.wait_for(
                self.session.call_tool(name, arguments=arguments or {}),
                timeout=10.0,
            )
            return result
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            return str(e)

    async def read_resource(self, uri: str) -> Any:
        """Read a resource by URI."""
        try:
            result = await asyncio.wait_for(
                self.session.read_resource(uri),
                timeout=10.0,
            )
            return result
        except Exception as e:
            return str(e)

    async def list_tools_raw(self) -> Any:
        """Get raw tool listing for comparison."""
        return await self.session.list_tools()
