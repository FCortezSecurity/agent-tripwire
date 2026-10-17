"""Detections that need more than one event. Plain Sigma matches single events, so
sequences are written in Python here, with the equivalent Splunk search in the README."""

from collections.abc import Callable
from dataclasses import dataclass

OUTBOUND_TOOLS = {"send_email"}
WINDOW_CALLS = 4  # how many tool calls after a trigger count as "soon after"

Matcher = Callable[[dict], bool]


@dataclass(frozen=True)
class Correlation:
    code: str
    title: str
    level: str
    check: Callable[[list[dict], dict[str, Matcher]], bool]


def sensitive_read_then_outbound(events: list[dict], is_sensitive: Matcher) -> bool:
    calls = [e for e in events if e["event_type"] == "tool_call"]
    for i, call in enumerate(calls):
        if not is_sensitive(call):
            continue
        following = calls[i + 1 : i + 1 + WINDOW_CALLS]
        if any(c["tool_name"] in OUTBOUND_TOOLS for c in following):
            return True
    return False


def injection_then_action(events: list[dict], is_injection: Matcher, is_sensitive: Matcher) -> bool:
    """Injection-style text in a tool result, then an outbound or sensitive call soon after."""
    calls_since: int | None = None
    for event in events:
        if event["event_type"] == "tool_result" and is_injection(event):
            calls_since = 0
        elif event["event_type"] == "tool_call" and calls_since is not None:
            calls_since += 1
            if calls_since > WINDOW_CALLS:
                calls_since = None
            elif event["tool_name"] in OUTBOUND_TOOLS or is_sensitive(event):
                return True
    return False


CORRELATIONS = [
    Correlation(
        code="TW-101",
        title="TW-101 Sensitive file read followed by an outbound call",
        level="high",
        check=lambda events, m: sensitive_read_then_outbound(events, m["sensitive"]),
    ),
    Correlation(
        code="TW-102",
        title="TW-102 Injection-style text followed by an outbound or sensitive call",
        level="high",
        check=lambda events, m: injection_then_action(events, m["injection"], m["sensitive"]),
    ),
]
