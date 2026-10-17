"""Backend tool servers: launched as subprocesses and used through the MCP client."""

import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path

from mcp import Client, StdioServerParameters, types

ROOT = Path(__file__).resolve().parent.parent
CALL_TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True)
class BackendSpec:
    name: str
    script: Path


DEFAULT_BACKENDS = [
    BackendSpec("files", ROOT / "tools" / "files_server.py"),
    BackendSpec("email", ROOT / "tools" / "email_server.py"),
    BackendSpec("notes", ROOT / "tools" / "notes_server.py"),
]


class DuplicateToolError(RuntimeError):
    """Two backends expose the same tool name (tool shadowing)."""


@dataclass
class Backends:
    specs: list[BackendSpec] = field(default_factory=lambda: list(DEFAULT_BACKENDS))
    _stack: AsyncExitStack = field(default_factory=AsyncExitStack)
    _clients: dict[str, Client] = field(default_factory=dict)
    _routes: dict[str, str] = field(default_factory=dict)

    async def start(self) -> None:
        for spec in self.specs:
            params = StdioServerParameters(
                command=sys.executable, args=[str(spec.script)], cwd=str(ROOT)
            )
            client = await self._stack.enter_async_context(Client(params))
            self._clients[spec.name] = client
        await self.list_tools()  # prime the routing table

    async def close(self) -> None:
        await self._stack.aclose()

    async def list_tools(self) -> list[tuple[str, types.Tool]]:
        """Ask every backend for its tools. Fails closed on duplicate names."""
        merged: list[tuple[str, types.Tool]] = []
        routes: dict[str, str] = {}
        for name, client in self._clients.items():
            result = await client.list_tools()
            for tool in result.tools:
                if tool.name in routes:
                    raise DuplicateToolError(
                        f"tool '{tool.name}' exposed by both '{routes[tool.name]}' and '{name}'"
                    )
                routes[tool.name] = name
                merged.append((name, tool))
        self._routes = routes
        return merged

    def server_for(self, tool_name: str) -> str | None:
        return self._routes.get(tool_name)

    async def call(
        self, server: str, tool_name: str, arguments: dict | None
    ) -> types.CallToolResult:
        client = self._clients[server]
        return await client.call_tool(
            tool_name, arguments, read_timeout_seconds=CALL_TIMEOUT_SECONDS
        )
