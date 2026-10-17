import json
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session", autouse=True)
def seeded_sandbox():
    subprocess.run([sys.executable, str(ROOT / "tools" / "seed_sandbox.py")], check=True)


def _gateway(log: Path) -> Client:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gateway"],
        cwd=str(ROOT),
        env={"TRIPWIRE_LOG": str(log)},
    )
    return Client(params)


def _direct() -> Client:
    params = StdioServerParameters(
        command=sys.executable, args=[str(ROOT / "tools" / "files_server.py")], cwd=str(ROOT)
    )
    return Client(params)


def _events(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


async def test_gateway_lists_all_backend_tools(tmp_path):
    async with _gateway(tmp_path / "events.jsonl") as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert {"read_file", "list_files", "write_file", "send_email", "get_note"} <= names


async def test_gateway_results_match_direct_results(tmp_path):
    args = {"path": "docs/report.txt"}
    async with _direct() as direct:
        expected = await direct.call_tool("read_file", args)
    async with _gateway(tmp_path / "events.jsonl") as gateway:
        actual = await gateway.call_tool("read_file", args)
    assert actual.content[0].text == expected.content[0].text
    assert actual.is_error == expected.is_error


async def test_tool_errors_are_forwarded_and_logged(tmp_path):
    log = tmp_path / "events.jsonl"
    async with _gateway(log) as client:
        result = await client.call_tool("read_file", {"path": "../pyproject.toml"})
    assert result.is_error
    results = [e for e in _events(log) if e["event_type"] == "tool_result"]
    assert results[-1]["is_error"] is True


async def test_every_call_is_logged_with_increasing_index(tmp_path):
    log = tmp_path / "events.jsonl"
    async with _gateway(log) as client:
        await client.list_tools()
        await client.call_tool("get_note", {"note_id": "1"})
    events = _events(log)
    assert [e["event_type"] for e in events] == ["tools_list", "tool_call", "tool_result"]
    assert [e["call_index"] for e in events] == [0, 1, 2]
    assert len({e["session_id"] for e in events}) == 1
    assert events[0]["tools"][0]["sha256"]


async def test_unknown_tool_fails_closed(tmp_path):
    async with _gateway(tmp_path / "events.jsonl") as client:
        await client.list_tools()
        result = await client.call_tool("does_not_exist", {})
    assert result.is_error
