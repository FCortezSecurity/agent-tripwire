"""Detections that need more than one event. Plain Sigma matches single events, so
sequences are written in Python here, with the equivalent Splunk search in docs."""

from collections.abc import Callable
from dataclasses import dataclass

OUTBOUND_TOOLS = {"send_email"}
WINDOW_CALLS = 4  # how many tool calls after a sensitive read count as "soon after"


@dataclass(frozen=True)
class Correlation:
    code: str
    title: str
    level: str
    check: Callable[[list[dict], Callable[[dict], bool]], bool]


def sensitive_read_then_outbound(events: list[dict], is_sensitive: Callable[[dict], bool]) -> bool:
    calls = [e for e in events if e["event_type"] == "tool_call"]
    for i, call in enumerate(calls):
        if not is_sensitive(call):
            continue
        following = calls[i + 1 : i + 1 + WINDOW_CALLS]
        if any(c["tool_name"] in OUTBOUND_TOOLS for c in following):
            return True
    return False


CORRELATIONS = [
    Correlation(
        code="TW-101",
        title="TW-101 Sensitive file read followed by an outbound call",
        level="high",
        check=sensitive_read_then_outbound,
    ),
]
