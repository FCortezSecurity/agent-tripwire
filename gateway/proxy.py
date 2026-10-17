"""The gateway: an MCP server to the agent, an MCP client to the real tool servers."""

import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path

import anyio
from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server

from gateway.backends import ROOT, Backends
from gateway.canaries import CANARY_SERVER, CanaryRegistry
from gateway.events import Event, EventLogger, EventType


def _tool_fingerprint(tool: types.Tool) -> str:
    """Hash of everything the model trusts about a tool. Used to spot rug pulls."""
    material = json.dumps(
        {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(material.encode()).hexdigest()


def _result_text(result: types.CallToolResult) -> str:
    parts = [c.text for c in result.content if isinstance(c, types.TextContent)]
    return "\n".join(parts)


class Gateway:
    def __init__(
        self, backends: Backends, logger: EventLogger, canaries: CanaryRegistry | None = None
    ):
        self.backends = backends
        self.logger = logger
        self.canaries = canaries or CanaryRegistry()
        self.session_id = uuid.uuid4().hex[:12]
        self._call_index = 0

    def _next_index(self) -> int:
        index = self._call_index
        self._call_index += 1
        return index

    def _log(self, event_type: EventType, **fields) -> None:
        self.logger.write(
            Event(
                session_id=self.session_id,
                call_index=self._next_index(),
                event_type=event_type,
                **fields,
            )
        )

    async def on_list_tools(self, ctx: ServerRequestContext, params) -> types.ListToolsResult:
        merged = await self.backends.list_tools()
        merged += [(CANARY_SERVER, tool) for tool in self.canaries.decoy_tools()]
        self._log(
            EventType.TOOLS_LIST,
            tools=[
                {
                    "server": server,
                    "name": tool.name,
                    "description": tool.description,
                    "sha256": _tool_fingerprint(tool),
                }
                for server, tool in merged
            ],
        )
        return types.ListToolsResult(tools=[tool for _, tool in merged])

    async def on_call_tool(
        self, ctx: ServerRequestContext, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        name = params.name
        arguments = params.arguments or {}
        if self.canaries.is_decoy_tool(name):
            return self._handle_decoy_tool(name, arguments)
        server = self.backends.server_for(name)
        if server is None:
            await self.backends.list_tools()  # refresh once in case tools changed
            server = self.backends.server_for(name)
        self._log(EventType.TOOL_CALL, server=server, tool_name=name, arguments=arguments)
        self._check_canaries(name, arguments, server)

        if server is None:
            return self._error_result(name, None, f"unknown tool '{name}'")

        started = time.perf_counter()
        try:
            result = await self.backends.call(server, name, arguments)
        except Exception as exc:  # noqa: BLE001  fail closed, never hang the agent
            return self._error_result(name, server, f"backend error: {type(exc).__name__}")

        text = _result_text(result)
        self._log(
            EventType.TOOL_RESULT,
            server=server,
            tool_name=name,
            is_error=bool(result.is_error),
            result_text=text,
            result_size=len(text),
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return result

    def _check_canaries(self, name: str, arguments: dict, server: str | None) -> None:
        for hit in self.canaries.inspect_call(name, arguments):
            self._log(
                EventType.CANARY_HIT,
                server=server,
                tool_name=name,
                arguments=arguments,
                canary_id=hit.canary_id,
                reason=f"{hit.kind}: {hit.reason}",
            )

    def _handle_decoy_tool(self, name: str, arguments: dict) -> types.CallToolResult:
        """Log the call and the canary hit, then answer plausibly so the intruder keeps going."""
        self._log(EventType.TOOL_CALL, server=CANARY_SERVER, tool_name=name, arguments=arguments)
        self._check_canaries(name, arguments, CANARY_SERVER)
        text = self.canaries.fake_response(name)
        self._log(
            EventType.TOOL_RESULT,
            server=CANARY_SERVER,
            tool_name=name,
            is_error=False,
            result_text=text,
            result_size=len(text),
        )
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

    def _error_result(self, name: str, server: str | None, message: str) -> types.CallToolResult:
        self._log(
            EventType.TOOL_RESULT,
            server=server,
            tool_name=name,
            is_error=True,
            result_text=message,
            result_size=len(message),
        )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=message)], is_error=True
        )


async def run(log_path: Path, backends: Backends | None = None) -> None:
    backends = backends or Backends()
    await backends.start()
    try:
        gateway = Gateway(backends, EventLogger(log_path))
        server = Server(
            "agent-tripwire",
            on_list_tools=gateway.on_list_tools,
            on_call_tool=gateway.on_call_tool,
        )
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    finally:
        await backends.close()


def main() -> None:
    log_path = Path(os.environ.get("TRIPWIRE_LOG", ROOT / "logs" / "events.jsonl"))
    print(f"agent-tripwire gateway starting, logging to {log_path}", file=sys.stderr)
    anyio.run(run, log_path)
