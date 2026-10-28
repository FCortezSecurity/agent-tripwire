"""Latency benchmark: the same tool call made directly and through the gateway.

Run from the repo root with the virtualenv active:

    python benchmarks/latency.py

It times one small `read_file` call in three conditions (direct, gateway in
monitor mode, gateway in enforce mode), interleaved in short sessions so that
machine noise affects all three alike. Startup time and warm-up calls are not
counted. Results are written to docs/results/latency-results.md.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import date
from importlib.metadata import version
from pathlib import Path

from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parent.parent
TOOL = "read_file"
ARGS = {"path": "docs/report.txt"}
WARMUP_CALLS = 2


def direct_params() -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[str(ROOT / "tools" / "files_server.py")],
        cwd=str(ROOT),
    )


def gateway_params(mode: str, log: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "gateway"],
        cwd=str(ROOT),
        env={"TRIPWIRE_LOG": str(log), "TRIPWIRE_MODE": mode},
    )


async def timed_session(params: StdioServerParameters, calls: int, label: str) -> list[float]:
    """Start one session, warm it up, then time `calls` calls. Returns milliseconds."""
    samples: list[float] = []
    async with Client(params) as client:
        await client.list_tools()
        for _ in range(WARMUP_CALLS + calls):
            start = time.perf_counter_ns()
            result = await client.call_tool(TOOL, ARGS)
            elapsed_ms = (time.perf_counter_ns() - start) / 1e6
            if result.is_error:
                text = result.content[0].text if result.content else "no message"
                raise RuntimeError(
                    f"{label}: the call failed or was denied ({text}). If the policy's "
                    "session call budget was reached, rerun with a smaller --session-size."
                )
            samples.append(elapsed_ms)
    return samples[WARMUP_CALLS:]


async def collect(calls: int, session_size: int) -> dict[str, list[float]]:
    conditions: dict[str, list[float]] = {
        "direct": [],
        "gateway (monitor)": [],
        "gateway (enforce)": [],
    }
    sessions = -(-calls // session_size)
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(sessions):
            n = min(session_size, calls - i * session_size)
            print(f"session {i + 1}/{sessions}: {n} timed calls per condition", flush=True)
            conditions["direct"] += await timed_session(direct_params(), n, "direct")
            for mode in ("monitor", "enforce"):
                label = f"gateway ({mode})"
                log = Path(tmp) / f"{mode}-{i}.jsonl"
                conditions[label] += await timed_session(gateway_params(mode, log), n, label)
    return conditions


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "n": len(values),
        "median": statistics.median(values),
        "mean": statistics.fmean(values),
        "p95": statistics.quantiles(values, n=100, method="inclusive")[94],
    }


def render(stats: dict[str, dict[str, float]], calls: int, session_size: int) -> str:
    base = stats["direct"]
    lines = [
        "# Gateway latency overhead",
        "",
        f"Measured on {date.today().isoformat()} with `benchmarks/latency.py`.",
        "",
        "## Per-call latency",
        "",
        "| Condition | Calls | Median (ms) | Mean (ms) | p95 (ms) |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, s in stats.items():
        lines.append(
            f"| {name} | {int(s['n'])} | {s['median']:.1f} | {s['mean']:.1f} | {s['p95']:.1f} |"
        )
    lines += [
        "",
        "## Overhead added by the gateway",
        "",
        "| Mode | Median overhead (ms) | p95 overhead (ms) |",
        "|---|---:|---:|",
    ]
    for name in ("gateway (monitor)", "gateway (enforce)"):
        s = stats[name]
        lines.append(
            f"| {name.removeprefix('gateway (').removesuffix(')')} "
            f"| {s['median'] - base['median']:.1f} | {s['p95'] - base['p95']:.1f} |"
        )
    lines += [
        "",
        "## Method and caveats",
        "",
        f"- One tool (`{TOOL}`) reading one small file, over stdio on a single machine.",
        (
            f"- {calls} timed calls per condition, in fresh sessions of {session_size} calls. "
            f"Startup and {WARMUP_CALLS} warm-up calls per session are excluded."
        ),
        "- Conditions are interleaved session by session so machine noise affects all three.",
        (
            "- The gateway figure includes its extra process hop: it is itself an MCP server "
            "that forwards to the real tool server, so it pays for policy, logging, and one "
            "more round trip."
        ),
        (
            "- Overhead is the difference between the gateway's and the direct call's median "
            "(or p95), not a per-call delta."
        ),
        (
            "- This is a single-client latency check, not a throughput or load test, and it "
            "was not run against a real model or real third-party tools."
        ),
        "",
        "## Environment",
        "",
        f"- Python {platform.python_version()} on {platform.platform()}",
        f"- mcp {version('mcp')}",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--calls", type=int, default=200, help="timed calls per condition")
    parser.add_argument("--session-size", type=int, default=20, help="timed calls per session")
    parser.add_argument("--out", default=str(ROOT / "docs" / "results" / "latency-results.md"))
    args = parser.parse_args()

    subprocess.run([sys.executable, str(ROOT / "tools" / "seed_sandbox.py")], check=True)

    samples = asyncio.run(collect(args.calls, args.session_size))
    stats = {name: summarize(values) for name, values in samples.items()}

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(stats, args.calls, args.session_size), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(samples, indent=2), encoding="utf-8")
    print(f"\nWrote {out} and {out.with_suffix('.json').name}")


if __name__ == "__main__":
    main()
