from gateway.events import Decision, Event, EventLogger, EventType


def test_event_roundtrip(tmp_path):
    logger = EventLogger(tmp_path / "events.jsonl")
    logger.write(
        Event(
            session_id="s1",
            call_index=0,
            event_type=EventType.TOOL_CALL,
            tool_name="read_file",
            arguments={"path": "docs/report.txt"},
        )
    )
    line = (tmp_path / "events.jsonl").read_text(encoding="utf-8").strip()
    parsed = Event.model_validate_json(line)
    assert parsed.tool_name == "read_file"
    assert parsed.arguments == {"path": "docs/report.txt"}


def test_long_results_are_truncated():
    event = Event(
        session_id="s1",
        call_index=1,
        event_type=EventType.TOOL_RESULT,
        result_text="x" * 10000,
        result_size=10000,
        decision=Decision.ALLOW,
    )
    assert len(event.result_text) == 4000
    assert event.result_size == 10000
