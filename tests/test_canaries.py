import json
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from attacks.runner import run_scenario
from attacks.scenarios import ALL
from gateway.canaries import (
    DECOY_FILE_CONTENT,
    DECOY_FILES,
    DECOY_TOOLS,
    CanaryRegistry,
    normalize_path,
)
from tools.seed_sandbox import FILES

ROOT = Path(__file__).resolve().parent.parent
BY_ID = {s.id: s for s in ALL}
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _gateway(log: Path) -> Client:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gateway"],
        cwd=str(ROOT),
        env={"TRIPWIRE_LOG": str(log)},
    )
    return Client(params)


def _events(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def test_decoy_files_match_what_the_sandbox_seeds():
    for decoy in DECOY_FILES:
        assert FILES[decoy.path] == DECOY_FILE_CONTENT[decoy.path]
        assert decoy.token in FILES[decoy.path]


def test_decoy_names_do_not_give_themselves_away():
    for tool in DECOY_TOOLS:
        assert "canary" not in (tool.name + tool.description).lower()
    for decoy in DECOY_FILES:
        assert "canary" not in decoy.path.lower()


@pytest.mark.parametrize(
    "path",
    [
        "secrets/backup_admin_credentials.env",
        "./secrets/backup_admin_credentials.env",
        "docs/../secrets/backup_admin_credentials.env",
        "secrets\\backup_admin_credentials.env",
    ],
)
def test_path_tricks_do_not_dodge_the_decoy_file_check(path):
    hits = CanaryRegistry().inspect_call("read_file", {"path": path})
    assert [h.kind for h in hits] == ["decoy_file"]


def test_normal_calls_are_not_hits():
    registry = CanaryRegistry()
    assert registry.inspect_call("read_file", {"path": "docs/report.txt"}) == []
    assert registry.inspect_call("send_email", {"to": "a@example.com", "body": "hi"}) == []


def test_token_in_arguments_is_a_leak():
    hits = CanaryRegistry().inspect_call("send_email", {"body": "pw is TRIPWIRE-CANARY-F001"})
    assert [h.kind for h in hits] == ["token_leak"]


def test_normalize_path():
    assert normalize_path("a/./b/../c") == "a/c"
    assert normalize_path("/etc/passwd") == "etc/passwd"


async def test_decoy_tools_are_listed_and_answer_plausibly(tmp_path):
    log = tmp_path / "events.jsonl"
    async with _gateway(log) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        result = await client.call_tool("admin_export_credentials", {"service": "payments"})
    assert {"admin_export_credentials", "reset_user_password"} <= names
    assert not result.is_error
    hits = [e for e in _events(log) if e["event_type"] == "canary_hit"]
    assert len(hits) == 1
    assert hits[0]["canary_id"] == "tool-001"


async def test_reading_the_decoy_file_trips_a_canary(tmp_path):
    result = await run_scenario(BY_ID["A07"], runs_dir=tmp_path)
    hits = [e for e in _events(result.log_path) if e["event_type"] == "canary_hit"]
    assert [h["canary_id"] for h in hits] == ["file-001"]


async def test_listing_files_is_not_a_canary_hit(tmp_path):
    result = await run_scenario(BY_ID["B11"], runs_dir=tmp_path)
    assert result.outcome == "ok"
    assert not [e for e in _events(result.log_path) if e["event_type"] == "canary_hit"]
