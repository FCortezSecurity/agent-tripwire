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
from gateway.canaries import CANARY_SERVER, CanaryRegistry, normalize_path
from gateway.events import Decision, Event, EventLogger, EventType
from gateway.policy import (
    Policy,
    PolicyState,
    Verdict,
    evaluate,
    load_policy,
    observe_call,
    result_taints,
)

BLOCKED_MESSAGE = "This action is not permitted by security policy."
DEFAULT_POLICY = ROOT / "policies" / "default.yaml"


def _tool_fingerprint(tool: types.Tool) -> str:
    """Hash the tool definition to detect changes to its trusted interface."""
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


def _normalized_path(arguments: dict) -> str | None:
    value = arguments.get("path", arguments.get("directory"))
    return normalize_path(str(value)) if value is not None else None


def _result_text(result: types.CallToolResult) -> str:
    parts = [c.text for c in result.content if isinstance(c, types.TextContent)]
    return "\n".join(parts)


class Gateway:
    def __init__(
        self,
        backends: Backends,
        logger: EventLogger,
        canaries: CanaryRegistry | None = None,
        policy: Policy | None = None,
        mode: str = "monitor",
    ):
        if mode not in {"monitor", "enforce"}:
            raise ValueError(f"mode must be 'monitor' or 'enforce', not {mode!r}")

        self.backends = backends
        self.logger = logger
        self.canaries = canaries or CanaryRegistry()
        self.policy = policy or Policy()
        self.mode = mode
        self.state = PolicyState()

        # Tool name -> fingerprint of the first observed definition.
        self._pins: dict[str, str] = {}

        # Tool names whose definitions have changed since first observation.
        self._changed: set[str] = set()

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

        if self.policy.pin_tools:
            merged = self._apply_pins(merged)

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

    def _apply_pins(self, merged: list) -> list:
        """Pin the first definition observed and detect later changes."""
        visible = []

        for server, tool in merged:
            fingerprint = _tool_fingerprint(tool)
            first_seen = self._pins.setdefault(tool.name, fingerprint)

            if first_seen != fingerprint and tool.name not in self._changed:
                self._changed.add(tool.name)
                self._log(
                    EventType.POLICY_DECISION,
                    server=server,
                    tool_name=tool.name,
                    decision=Decision.DENY,
                    rule_id="pin.changed",
                    reason="tool definition changed after first use",
                    mode=self.mode,
                )

            if tool.name in self._changed and self.mode == "enforce":
                continue

            visible.append((server, tool))

        return visible

    async def _recheck_pin(self, name: str) -> None:
        """Recheck a tool's live definition immediately before execution."""
        if not self.policy.pin_tools:
            return

        live = await self.backends.list_tools()
        matching = [(server, tool) for server, tool in live if tool.name == name]

        if not matching:
            if name not in self._changed:
                self._changed.add(name)
                self._log(
                    EventType.POLICY_DECISION,
                    tool_name=name,
                    decision=Decision.DENY,
                    rule_id="pin.changed",
                    reason="pinned tool disappeared from backend",
                    mode=self.mode,
                )
            return

        self._apply_pins(matching)

    async def on_call_tool(
        self,
        ctx: ServerRequestContext,
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        name = params.name
        arguments = params.arguments or {}

        if self.canaries.is_decoy_tool(name):
            return self._handle_decoy_tool(name, arguments)

        server = self.backends.server_for(name)

        if server is None:
            await self.backends.list_tools()
            server = self.backends.server_for(name)

        self._log(
            EventType.TOOL_CALL,
            server=server,
            tool_name=name,
            arguments=arguments,
            path_normalized=_normalized_path(arguments),
        )

        self._check_canaries(name, arguments, server)

        if server is None:
            return self._error_result(name, None, f"unknown tool '{name}'")

        try:
            await self._recheck_pin(name)
        except Exception as exc:  # noqa: BLE001
            # Do not execute the tool if its definition cannot be verified.
            return self._error_result(
                name,
                server,
                f"tool verification failed: {type(exc).__name__}",
            )

        verdict = self._decide(name, arguments)

        self._log(
            EventType.POLICY_DECISION,
            server=server,
            tool_name=name,
            decision=verdict.decision,
            rule_id=verdict.rule_id,
            reason=verdict.reason,
            mode=self.mode,
        )

        self.state.calls += 1

        if verdict.decision is Decision.DENY and self.mode == "enforce":
            return self._error_result(name, server, BLOCKED_MESSAGE)

        started = time.perf_counter()

        try:
            result = await self.backends.call(server, name, arguments)
        except Exception as exc:  # noqa: BLE001
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

        self._observe_result(name, arguments, server, result, text)
        return result

    def _decide(self, name: str, arguments: dict) -> Verdict:
        if name in self._changed:
            return Verdict(
                Decision.DENY,
                "pin.changed",
                "tool definition changed after first use",
            )

        return evaluate(self.policy, name, arguments, self.state)

    def _observe_result(
        self,
        name: str,
        arguments: dict,
        server: str,
        result: types.CallToolResult,
        text: str,
    ) -> None:
        """Update session state from a completed call: flow rules and taint."""
        if result.is_error:
            return

        for flow_id in observe_call(self.policy, self.state, arguments):
            self._log(
                EventType.POLICY_DECISION,
                server=server,
                tool_name=name,
                decision=Decision.FLAG,
                rule_id=f"flow.{flow_id}.set",
                reason=("session read restricted data; outbound recipients now limited"),
                mode=self.mode,
            )

        if not self.state.tainted and result_taints(self.policy, text):
            self.state.tainted = True
            self._log(
                EventType.POLICY_DECISION,
                server=server,
                tool_name=name,
                decision=Decision.FLAG,
                rule_id="taint.set",
                reason=("secret-looking content returned; outbound tools now restricted"),
                mode=self.mode,
            )

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
        """Log a decoy call and answer plausibly so the intruder keeps going."""
        self._log(
            EventType.TOOL_CALL,
            server=CANARY_SERVER,
            tool_name=name,
            arguments=arguments,
        )

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
            content=[types.TextContent(type="text", text=message)],
            is_error=True,
        )


async def run(
    log_path: Path,
    policy_path: Path,
    mode: str,
    backends: Backends | None = None,
) -> None:
    policy = load_policy(policy_path)
    backends = backends or Backends()
    await backends.start()

    try:
        gateway = Gateway(
            backends,
            EventLogger(log_path),
            policy=policy,
            mode=mode,
        )

        server = Server(
            "agent-tripwire",
            on_list_tools=gateway.on_list_tools,
            on_call_tool=gateway.on_call_tool,
        )

        async with stdio_server() as (read, write):
            await server.run(
                read,
                write,
                server.create_initialization_options(),
            )
    finally:
        await backends.close()


def main() -> None:
    log_path = Path(os.environ.get("TRIPWIRE_LOG", ROOT / "logs" / "events.jsonl"))
    policy_path = Path(os.environ.get("TRIPWIRE_POLICY", DEFAULT_POLICY))
    mode = os.environ.get("TRIPWIRE_MODE", "monitor")

    print(
        f"agent-tripwire gateway starting in {mode} mode, log: {log_path}",
        file=sys.stderr,
    )

    anyio.run(run, log_path, policy_path, mode)
