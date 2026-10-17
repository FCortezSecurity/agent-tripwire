"""Run every scenario in monitor mode and in enforce mode and compare the outcomes.

Usage:  python -m attacks.compare
Writes: docs/results/policy-results.md
"""

import anyio

from attacks.runner import ROOT, RunResult, run_all
from attacks.scenarios import ALL

REPORT = ROOT / "docs" / "results" / "policy-results.md"


def build_report(monitor: list[RunResult], enforce: list[RunResult]) -> str:
    mon = {r.scenario.id: r for r in monitor}
    enf = {r.scenario.id: r for r in enforce}
    attacks = [s for s in ALL if s.kind == "attack"]
    benign = [s for s in ALL if s.kind == "benign"]

    def won(results: dict, s) -> bool:
        return results[s.id].outcome == "SUCCEEDED"

    mon_wins = sum(won(mon, s) for s in attacks)
    enf_wins = sum(won(enf, s) for s in attacks)
    broken = [s for s in benign if enf[s.id].outcome != "ok"]

    lines = [
        "# Policy results: monitor vs enforce",
        "",
        f"- Attacks that succeeded in monitor mode (no blocking): **{mon_wins} of {len(attacks)}**",
        f"- Attacks that succeeded in enforce mode: **{enf_wins} of {len(attacks)}**",
        f"- Benign tasks still working in enforce mode: **{len(benign) - len(broken)} of {len(benign)}**",
        "",
        "## Attacks",
        "",
        "| ID | Threat | Monitor | Enforce | Name |",
        "|----|--------|---------|---------|------|",
    ]
    for s in attacks:
        lines.append(
            f"| {s.id} | {s.threat} | {mon[s.id].outcome} | {enf[s.id].outcome} | {s.name} |"
        )
    lines += [
        "",
        "## Benign tasks (utility)",
        "",
        "| ID | Monitor | Enforce | Name |",
        "|----|---------|---------|------|",
    ]
    for s in benign:
        lines.append(f"| {s.id} | {mon[s.id].outcome} | {enf[s.id].outcome} | {s.name} |")
    if broken:
        lines += ["", "## Benign tasks broken by the policy", ""]
        lines += [f"- {s.id}: {s.name}" for s in broken]
    return "\n".join(lines) + "\n"


def main() -> None:
    async def both() -> tuple[list[RunResult], list[RunResult]]:
        return await run_all(ALL, "monitor"), await run_all(ALL, "enforce")

    monitor, enforce = anyio.run(both)
    report = build_report(monitor, enforce)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(report, encoding="utf-8")
    print(report)
    print(f"report written to {REPORT}")


if __name__ == "__main__":
    main()
