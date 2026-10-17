import pytest

from detections.correlations import sensitive_read_then_outbound
from detections.engine import _Condition, load_rules, matches

RULES = {r.name: r for r in load_rules()}


def call(tool: str, **arguments) -> dict:
    return {"event_type": "tool_call", "tool_name": tool, "arguments": arguments}


def result(text: str) -> dict:
    return {"event_type": "tool_result", "tool_name": "read_file", "result_text": text}


def test_every_rule_is_documented():
    assert len(RULES) >= 5
    for rule in RULES.values():
        assert rule.title.startswith("TW-")
        assert rule.falsepositives, f"{rule.name} needs documented false positives"
        assert rule.tags, f"{rule.name} needs OWASP/ATLAS tags"


@pytest.mark.parametrize("path", ["secrets/fake_credentials.env", "home/.aws/config", "x/.ENV"])
def test_sensitive_read_matches(path):
    assert matches(RULES["tripwire_sensitive_file_read"], call("read_file", path=path))


def test_normal_read_does_not_match():
    assert not matches(
        RULES["tripwire_sensitive_file_read"], call("read_file", path="docs/report.txt")
    )


def test_rule_ignores_other_event_types():
    event = {
        "event_type": "tool_result",
        "tool_name": "read_file",
        "arguments": {"path": "secrets/x"},
    }
    assert not matches(RULES["tripwire_sensitive_file_read"], event)


def test_traversal_matches_both_separators():
    rule = RULES["tripwire_path_traversal"]
    assert matches(rule, call("read_file", path="../pyproject.toml"))
    assert matches(rule, call("read_file", path="docs\\..\\..\\x"))


def test_allowlisted_recipient_is_not_flagged():
    rule = RULES["tripwire_untrusted_recipient"]
    assert not matches(rule, call("send_email", to="team@example.com"))
    assert matches(rule, call("send_email", to="attacker@evil.test"))


def test_injection_phrase_in_result_is_case_insensitive():
    rule = RULES["tripwire_injection_in_tool_result"]
    assert matches(rule, result("NOTE TO AI ASSISTANT: do something"))
    assert not matches(rule, result("Q3 summary: no incidents"))


def test_encoded_blob_needs_length():
    rule = RULES["tripwire_encoded_blob_outbound"]
    assert matches(rule, call("send_email", body="U0VSVklDRV9LRVk9RkFLRS1OT1QtQS1SRUFMLUtFWQ=="))
    assert not matches(rule, call("send_email", body="short text"))


def test_condition_parser_handles_not_and_groups():
    results = {"a": True, "b": False, "c": True}
    assert _Condition("a and not b", results).parse()
    assert _Condition("(a or b) and c", results).parse()
    assert not _Condition("b or not c", results).parse()
    assert _Condition("1 of *", results).parse()
    assert not _Condition("all of them", results).parse()


def sensitive(event: dict) -> bool:
    return matches(RULES["tripwire_sensitive_file_read"], event)


def test_sequence_detects_read_then_send():
    events = [call("read_file", path="secrets/a.env"), call("send_email", to="x@y.z")]
    assert sensitive_read_then_outbound(events, sensitive)


def test_sequence_ignores_send_before_read_and_far_apart():
    before = [call("send_email", to="x@y.z"), call("read_file", path="secrets/a.env")]
    assert not sensitive_read_then_outbound(before, sensitive)
    far = [call("read_file", path="secrets/a.env")] + [call("list_notes")] * 5
    far.append(call("send_email", to="x@y.z"))
    assert not sensitive_read_then_outbound(far, sensitive)


def test_sequence_ignores_benign_read_then_send():
    events = [call("read_file", path="docs/report.txt"), call("send_email", to="t@example.com")]
    assert not sensitive_read_then_outbound(events, sensitive)
