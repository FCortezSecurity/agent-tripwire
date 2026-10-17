"""Run scenarios through the gateway and record one event log per scenario.

Usage:
    python -m attacks.runner            run everything
    python -m attacks.runner A02 B06    run selected scenarios
"""

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import anyio
from mcp import Client, StdioServerParameters

from attacks.scenarios import ALL, Scenario
from tools.seed_sandbox import seed

ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = ROOT / "logs" / "runs"  # monitor mode; enforce mode writes to logs/runs-enforce
OUTBOX = ROOT / "logs" / "outbox.jsonl"


@dataclass
class RunResult:
    scenario: Scenario
    log_path: Path
    tool_errors: int
    exfiltrated: bool  # the attacker reached their goal

    @property
    def outcome(self) -> str:
        if self.scenario.kind == "benign":
            return "ok" if self.tool_errors == 0 else "broken"
        return "SUCCEEDED" if self.exfiltrated else "failed"


def _outbox_lines() -> list[str]:
    if not OUTBOX.exists():
        return []
    return OUTBOX.read_text(encoding="utf-8").splitlines()


def _attack_succeeded(scenario: Scenario, log_path: Path, outbox_before: int) -> bool:
    if scenario.goal == "call":  # the attacker only needed the tool call to go through
        events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        results = [e for e in events if e["event_type"] == "tool_result"]
        # a decoy tool "answering" is the trap working, not the attacker winning
        return bool(results) and not results[-1]["is_error"] and results[-1]["server"] != "canary"
    if not scenario.marker:
        return False
    if scenario.goal == "exfil":
        return any(scenario.marker in line for line in _outbox_lines()[outbox_before:])
    events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    return any(
        e["event_type"] == "tool_result"
        and not e["is_error"]
        and scenario.marker in (e["result_text"] or "")
        for e in events
    )


def _gateway_env(log_path: Path, mode: str, policy_path: Path | None) -> dict[str, str]:
    # The MCP client only forwards a safe subset of the environment, so pass these explicitly.
    env = {"TRIPWIRE_LOG": str(log_path), "TRIPWIRE_MODE": mode}
    if policy_path:
        env["TRIPWIRE_POLICY"] = str(policy_path)
    return env


async def run_scenario(
    scenario: Scenario,
    runs_dir: Path = RUNS_DIR,
    mode: str = "monitor",
    policy_path: Path | None = None,
) -> RunResult:
    runs_dir.mkdir(parents=True, exist_ok=True)
    log_path = runs_dir / f"{scenario.id}.jsonl"
    log_path.unlink(missing_ok=True)
    seed(extra=scenario.plant)  # clean sandbox for every run
    outbox_before = len(_outbox_lines())

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gateway"],
        cwd=str(ROOT),
        env=_gateway_env(log_path, mode, policy_path),
    )
    errors = 0
    async with Client(params) as client:
        await client.list_tools()  # a real agent lists tools first
        for step in scenario.steps:
            result = await client.call_tool(step.tool, step.arguments)
            errors += 1 if result.is_error else 0

    succeeded = _attack_succeeded(scenario, log_path, outbox_before)
    return RunResult(scenario, log_path, errors, succeeded)


async def run_all(selected: list[Scenario], mode: str = "monitor") -> list[RunResult]:
    runs_dir = RUNS_DIR if mode == "monitor" else ROOT / "logs" / f"runs-{mode}"
    return [await run_scenario(sc, runs_dir=runs_dir, mode=mode) for sc in selected]


def main() -> None:
    args = sys.argv[1:]
    mode = "monitor"
    if "--mode" in args:
        index = args.index("--mode")
        mode = args[index + 1]
        del args[index : index + 2]
    selected = [s for s in ALL if not args or s.id in set(args)]
    results = anyio.run(run_all, selected, mode)

    print(f"\nmode: {mode}")
    print(f"{'ID':<5}{'KIND':<8}{'THREAT':<8}{'OUTCOME':<11}NAME")
    for r in results:
        s = r.scenario
        print(f"{s.id:<5}{s.kind:<8}{s.threat:<8}{r.outcome:<11}{s.name}")
    print(f"\nlogs written to {results[0].log_path.parent}")


if __name__ == "__main__":
    main()
