"""MCP client wrapper for connecting to and interacting with MCP servers."""

from __future__ import annotations

import asyncio
import shlex
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from .models import PromptInfo, ResourceInfo, ToolInfo

CONNECT_TIMEOUT = 30.0


class MCPClient:
    """Wrapper around MCP SDK for security scanning."""

    def __init__(self) -> None:
        self._session: ClientSession | None = None
        self._tools: list[ToolInfo] = []
        self._resources: list[ResourceInfo] = []
        self._prompts: list[PromptInfo] = []
        self.enumeration_errors: list[str] = []

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
                await asyncio.wait_for(session.initialize(), timeout=CONNECT_TIMEOUT)
                await asyncio.wait_for(self._enumerate(), timeout=CONNECT_TIMEOUT)
                yield self
                self._session = None

    @asynccontextmanager
    async def connect_sse(self, url: str) -> AsyncGenerator[MCPClient, None]:
        """Connect to an MCP server via SSE transport."""
        async with sse_client(url) as (read, write):
            async with ClientSession(read, write) as session:
                self._session = session
                await asyncio.wait_for(session.initialize(), timeout=CONNECT_TIMEOUT)
                await asyncio.wait_for(self._enumerate(), timeout=CONNECT_TIMEOUT)
                yield self
                self._session = None

    @asynccontextmanager
    async def connect_http(self, url: str) -> AsyncGenerator[MCPClient, None]:
        """Connect to an MCP server via Streamable HTTP transport."""
        async with streamable_http_client(url) as (read, write):
            async with ClientSession(read, write) as session:
                self._session = session
                await asyncio.wait_for(session.initialize(), timeout=CONNECT_TIMEOUT)
                await asyncio.wait_for(self._enumerate(), timeout=CONNECT_TIMEOUT)
                yield self
                self._session = None

    async def _enumerate(self) -> None:
        """Enumerate all tools, resources, and prompts."""
        self._tools = []
        self._resources = []
        self._prompts = []
        self.enumeration_errors = []

        try:
            tools_result = await self.session.list_tools()
            for tool in tools_result.tools:
                self._tools.append(
                    ToolInfo(
                        name=tool.name,
                        description=tool.description or "",
                        input_schema=(
                            getattr(tool, "input_schema", None)
                            or getattr(tool, "inputSchema", None)
                            or {}
                        ),
                    )
                )
        except Exception:
            self.enumeration_errors.append("Failed to list tools")

        try:
            resources_result = await self.session.list_resources()
            for res in resources_result.resources:
                self._resources.append(
                    ResourceInfo(
                        uri=str(res.uri),
                        name=res.name or "",
                        description=res.description or "" if hasattr(res, "description") else "",
                        mime_type=(
                            getattr(res, "mime_type", None)
                            or getattr(res, "mimeType", None)
                            or ""
                        ),
                    )
                )
        except Exception:
            self.enumeration_errors.append("Failed to list resources")

        try:
            prompts_result = await self.session.list_prompts()
            for prompt in prompts_result.prompts:
                args = []
                if hasattr(prompt, "arguments") and prompt.arguments:
                    args = [
                        {
                            "name": arg.name,
                            "description": arg.description or "" if hasattr(arg, "description") else "",
                        }
                        for arg in prompt.arguments
                    ]
                self._prompts.append(
                    PromptInfo(
                        name=prompt.name,
                        description=prompt.description or "",
                        arguments=args,
                    )
                )
        except Exception:
            self.enumeration_errors.append("Failed to list prompts")

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
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None

    async def list_tools_raw(self) -> Any:
        """Get raw tool listing for comparison."""
        return await self.session.list_tools()
