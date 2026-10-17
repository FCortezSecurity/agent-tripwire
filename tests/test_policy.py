from pathlib import Path

import pytest
from pydantic import ValidationError

from gateway.policy import Policy, PolicyState, evaluate, load_policy, result_taints

POLICY = load_policy(Path(__file__).resolve().parent.parent / "policies" / "default.yaml")


def verdict(tool: str, state: PolicyState | None = None, **arguments):
    return evaluate(POLICY, tool, arguments, state or PolicyState())


def allowed(tool: str, **arguments) -> bool:
    return verdict(tool, **arguments).decision == "allow"


def test_default_policy_file_is_valid_and_default_deny():
    assert POLICY.default == "deny"
    assert POLICY.taint is not None


def test_unlisted_tool_is_denied_by_default():
    result = verdict("admin_export_credentials", service="payments")
    assert result.decision == "deny"
    assert result.rule_id == "policy.default_deny"


@pytest.mark.parametrize("path", ["docs/report.txt", "./docs/report.txt", "docs/sub/a.txt"])
def test_reads_inside_docs_are_allowed(path):
    assert allowed("read_file", path=path)


@pytest.mark.parametrize(
    "path",
    [
        "secrets/fake_credentials.env",
        "../pyproject.toml",
        "docs/../secrets/fake_credentials.env",
        "docs\\..\\secrets\\x.env",
        "/etc/passwd",
        "secrets/backup_admin_credentials.env",
    ],
)
def test_reads_outside_docs_are_denied(path):
    assert not allowed("read_file", path=path)


@pytest.mark.parametrize("to", ["a@example.com", "b@partner-example.org", "C@EXAMPLE.COM"])
def test_approved_recipients_are_allowed(to):
    assert allowed("send_email", to=to, body="hi")


@pytest.mark.parametrize(
    "to",
    ["x@evil.test", "x@example.com.evil.test", "x@evil.test@example.com.", "no-at-sign", ""],
)
def test_other_recipients_are_denied(to):
    assert not allowed("send_email", to=to, body="hi")


def test_encoded_blob_in_body_is_denied_but_hex_hash_is_allowed():
    blob = "U0VSVklDRV9LRVk9RkFLRS1OT1QtQS1SRUFMLUtFWQ=="
    assert not allowed("send_email", to="a@example.com", body=blob)
    assert allowed(
        "send_email", to="a@example.com", body="build 9f2c4b7e1a3d5c6b8e0f1a2b3c4d5e6f7a8b9c0d"
    )


def test_body_length_limit():
    assert not allowed("send_email", to="a@example.com", body="x" * 2001)


def test_listing_cannot_escape_the_workspace():
    assert allowed("list_files", directory=".")
    assert allowed("list_files", directory="docs")
    assert not allowed("list_files", directory="..")
    assert not allowed("list_files", directory="docs/../../x")


def test_taint_blocks_outbound_but_not_reads():
    state = PolicyState(tainted=True)
    blocked = verdict("send_email", state, to="a@example.com", body="hi")
    assert blocked.decision == "deny"
    assert blocked.rule_id == "taint.send_email"
    assert verdict("read_file", state, path="docs/report.txt").decision == "allow"


@pytest.mark.parametrize(
    "text, expected",
    [
        ("SERVICE_KEY=FAKE-NOT-A-REAL-KEY", True),
        ("password: hunter2", True),
        ("Credential rotation policy: rotate every 90 days.", False),
        ("Q3 summary: traffic up 12 percent.", False),
    ],
)
def test_result_taints(text, expected):
    assert result_taints(POLICY, text) is expected


def test_call_budget():
    assert verdict("get_note", PolicyState(calls=49), note_id="1").decision == "allow"
    over = verdict("get_note", PolicyState(calls=50), note_id="1")
    assert over.decision == "deny"
    assert over.rule_id == "session.max_calls"


def test_typos_in_a_policy_are_rejected():
    with pytest.raises(ValidationError):
        Policy.model_validate({"defualt": "allow"})
    with pytest.raises(ValidationError):
        Policy.model_validate(
            {"tools": {"read_file": {"arguments": {"path": {"alow_prefixes": []}}}}}
        )


def test_missing_policy_file_fails_closed(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_policy(tmp_path / "nope.yaml")


# --- evasion round 1 ---

from gateway.policy import observe_call


@pytest.mark.parametrize(
    "text",
    [
        "db login -> user: svc_app, pwd: FAKE-PWD-0042",
        "passwd=abc123",
        "passphrase: correct horse",
        "Authorization bearer: abc.def.ghi",
        "-----BEGIN RSA PRIVATE KEY-----",
        "credentials: svc / hunter2",
    ],
)
def test_broadened_taint_patterns_catch_more_secret_formats(text):
    assert result_taints(POLICY, text)


@pytest.mark.parametrize(
    "text",
    [
        "Credential rotation policy: rotate service credentials every 90 days.",
        "Action items: update the roadmap, review the budget.",
        "Compensation review (internal only). Band changes pending.",
    ],
)
def test_broadened_patterns_still_leave_ordinary_text_alone(text):
    assert not result_taints(POLICY, text)


def test_policy_and_sigma_rule_use_the_same_secret_pattern():
    from detections.engine import load_rules

    rule = next(r for r in load_rules() if r.name == "tripwire_secret_content_in_result")
    sigma_pattern = rule.selections["selection_secret"]["result_text|re"]
    assert POLICY.taint.patterns == [sigma_pattern]


def test_reading_internal_data_restricts_recipients_afterwards():
    state = PolicyState()
    assert observe_call(POLICY, state, {"path": "docs/./internal/review.txt"}) == [
        "internal-stays-internal"
    ]
    partner = verdict("send_email", state, to="contact@partner-example.org", body="hi")
    assert partner.decision == "deny"
    assert partner.rule_id == "flow.internal-stays-internal"
    assert verdict("send_email", state, to="team@example.com", body="hi").decision == "allow"


def test_flow_rule_does_not_apply_before_internal_data_is_read():
    state = PolicyState()
    observe_call(POLICY, state, {"path": "docs/report.txt"})
    assert (
        verdict("send_email", state, to="contact@partner-example.org", body="hi").decision
        == "allow"
    )
