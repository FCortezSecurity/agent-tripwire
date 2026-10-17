from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

MAX_RESULT_CHARS = 4000


class EventType(StrEnum):
    TOOLS_LIST = "tools_list"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    POLICY_DECISION = "policy_decision"
    CANARY_HIT = "canary_hit"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    FLAG = "flag"


class Event(BaseModel):
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    session_id: str
    call_index: int
    event_type: EventType
    server: str | None = None
    tool_name: str | None = None
    arguments: dict[str, Any] | None = None
    tools: list[dict[str, Any]] | None = None
    is_error: bool | None = None
    result_text: str | None = None
    result_size: int | None = None
    latency_ms: float | None = None
    decision: Decision | None = None
    rule_id: str | None = None
    canary_id: str | None = None
    reason: str | None = None

    @field_validator("result_text")
    @classmethod
    def truncate_result(cls, value: str | None) -> str | None:
        if value is not None and len(value) > MAX_RESULT_CHARS:
            return value[:MAX_RESULT_CHARS]
        return value


class EventLogger:
    """Append events to a JSON Lines file, one event per line."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: Event) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(event.model_dump_json() + "\n")
