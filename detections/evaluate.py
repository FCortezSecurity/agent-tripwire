"""Score the detections against the recorded scenario logs.

Usage:  python -m detections.evaluate
Needs:  python -m attacks.runner   (creates logs/runs/*.jsonl)
"""

import json
from pathlib import Path

from attacks.scenarios import ALL
from detections.correlations import CORRELATIONS
from detections.engine import Rule, load_rules, matches

ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = ROOT / "logs" / "runs"
REPORT = ROOT / "docs" / "results" / "detection-results.md"


def load_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def fired_codes(events: list[dict], rules: list[Rule]) -> set[str]:
    fired = {r.code for r in rules if any(matches(r, e) for e in events)}
    sensitive = next(r for r in rules if r.name == "tripwire_sensitive_file_read")
    for corr in CORRELATIONS:
        if corr.check(events, lambda e: matches(sensitive, e)):
            fired.add(corr.code)
    return fired


def evaluate(runs_dir: Path = RUNS_DIR) -> dict[str, set[str]]:
    rules = load_rules()
    return {
        s.id: fired_codes(load_events(runs_dir / f"{s.id}.jsonl"), rules)
        for s in ALL
        if (runs_dir / f"{s.id}.jsonl").exists()
    }


def build_report(fired: dict[str, set[str]]) -> str:
    rules = load_rules()
    codes = [r.code for r in rules] + [c.code for c in CORRELATIONS]
    titles = {r.code: r.title for r in rules} | {c.code: c.title for c in CORRELATIONS}
    attacks = [s for s in ALL if s.kind == "attack" and s.id in fired]
    benign = [s for s in ALL if s.kind == "benign" and s.id in fired]

    detected = [s for s in attacks if fired[s.id]]
    missed = [s for s in attacks if not fired[s.id]]
    false_pos = [s for s in benign if fired[s.id]]

    lines = ["# Detection results", ""]
    lines += [
        f"- Attack scenarios detected: **{len(detected)} of {len(attacks)}**",
        f"- Benign scenarios with a false alert: **{len(false_pos)} of {len(benign)}**",
        "",
        "## Per-scenario alerts",
        "",
        "| ID | Kind | Threat | Rules that fired | Name |",
        "|----|------|--------|------------------|------|",
    ]
    for s in ALL:
        if s.id in fired:
            alerts = ", ".join(sorted(fired[s.id])) or "none"
            lines.append(f"| {s.id} | {s.kind} | {s.threat} | {alerts} | {s.name} |")

    lines += [
        "",
        "## Per-rule performance",
        "",
        "| Rule | Attacks hit | False positives |",
        "|---|---|---|",
    ]
    for code in codes:
        hits = [s.id for s in attacks if code in fired[s.id]]
        fps = [s.id for s in benign if code in fired[s.id]]
        lines.append(f"| {titles[code]} | {', '.join(hits) or '-'} | {', '.join(fps) or '-'} |")

    if missed:
        lines += ["", "## Missed attacks", ""]
        lines += [f"- {s.id}: {s.name}" for s in missed]
    return "\n".join(lines) + "\n"


def main() -> None:
    fired = evaluate()
    if not fired:
        raise SystemExit("no logs found: run `python -m attacks.runner` first")
    report = build_report(fired)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(report, encoding="utf-8")
    print(report)
    print(f"report written to {REPORT}")


if __name__ == "__main__":
    main()
