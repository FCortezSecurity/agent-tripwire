"""Convert the Sigma rules to Splunk and Elasticsearch queries with pySigma.

Usage:  python -m detections.convert
Writes: docs/results/sigma-conversion.md

The queries are generated, not executed. Nothing here proves they return the same
events as the Python evaluator (detections/engine.py) on a live Splunk or Elasticsearch.
Sequence rules live in correlations.py as Python code and are not converted.
"""

import re
from dataclasses import dataclass, field
from importlib.metadata import version
from pathlib import Path

import yaml
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.exceptions import SigmaError
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation
from sigma.rule import SigmaRule

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = Path(__file__).resolve().parent / "rules"
REPORT = ROOT / "docs" / "results" / "sigma-conversion.md"

BACKENDS = {"Splunk": SplunkBackend, "Elasticsearch": LuceneBackend}

# The Python evaluator only runs a rule on events whose type equals the rule's logsource
# category. The pipeline below adds the same filter to the generated queries. The canary
# rule is left out because it already selects on event_type itself.
EVENT_TYPE_CATEGORIES = ("tool_call", "tool_result")

# Constructs that PCRE (Splunk) accepts but Lucene regular expressions (Elasticsearch) do not.
PCRE_ONLY = (
    (re.compile(r"\(\?[=!<]"), "lookahead or lookbehind"),
    (re.compile(r"\(\?[a-zA-Z]+\)"), "inline flags such as (?i)"),
    (re.compile(r"\\[sSdDwWbB]"), "shorthand classes such as \\s"),
)


@dataclass(frozen=True)
class Conversion:
    file: str
    name: str
    title: str
    level: str
    queries: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    caveats: dict[str, list[str]] = field(default_factory=dict)


def build_pipeline() -> ProcessingPipeline:
    items = [
        ProcessingItem(
            identifier=f"agent_tripwire_event_type_{category}",
            transformation=AddConditionTransformation({"event_type": category}),
            rule_conditions=[LogsourceCondition(product="agent_tripwire", category=category)],
        )
        for category in EVENT_TYPE_CATEGORIES
    ]
    return ProcessingPipeline(name="agent-tripwire", priority=10, items=items)


def convert_text(text: str, backend_class: type) -> str:
    """Convert one rule. A fresh rule is parsed each time because pipelines edit it in place."""
    rule = SigmaRule.from_yaml(text)
    backend = backend_class(processing_pipeline=build_pipeline())
    return "\n".join(backend.convert_rule(rule))


def regex_patterns(doc: dict) -> list[str]:
    """Collect the patterns of every field that uses the `re` modifier."""
    patterns: list[str] = []
    for name, selection in doc["detection"].items():
        if name == "condition":
            continue
        for item in selection if isinstance(selection, list) else [selection]:
            if not isinstance(item, dict):
                continue
            for key, value in item.items():
                if "re" in key.split("|")[1:]:
                    patterns += [str(p) for p in (value if isinstance(value, list) else [value])]
    return patterns


def elasticsearch_caveats(doc: dict) -> list[str]:
    reasons: list[str] = []
    for pattern in regex_patterns(doc):
        for compiled, reason in PCRE_ONLY:
            if compiled.search(pattern) and reason not in reasons:
                reasons.append(reason)
    return reasons


def convert_all(rules_dir: Path = RULES_DIR) -> list[Conversion]:
    conversions = []
    for path in sorted(rules_dir.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
        conversion = Conversion(
            file=path.name,
            name=doc["name"],
            title=doc["title"],
            level=doc.get("level", "medium"),
        )
        for label, backend_class in BACKENDS.items():
            try:
                conversion.queries[label] = convert_text(text, backend_class)
            except SigmaError as exc:
                conversion.errors[label] = f"{type(exc).__name__}: {exc}"
        reasons = elasticsearch_caveats(doc)
        if reasons:
            conversion.caveats["Elasticsearch"] = reasons
        conversions.append(conversion)
    return conversions


def status(conversion: Conversion, label: str) -> str:
    if label in conversion.errors:
        return "FAILED"
    if label in conversion.caveats:
        return "converted, needs review"
    return "converted"


def build_report(conversions: list[Conversion]) -> str:
    total = len(conversions)
    lines = ["# Sigma conversion results", ""]
    for label in BACKENDS:
        ok = sum(label not in c.errors for c in conversions)
        review = sum(label in c.caveats and label not in c.errors for c in conversions)
        lines.append(f"- {label}: **{ok} of {total}** rules converted, {review} need review")
    lines += [
        "",
        "Queries are generated with pySigma and have not been run on a live Splunk or",
        "Elasticsearch. This page shows that the rules are valid Sigma and convertible, not",
        "that the converted queries match the same events as the Python evaluator.",
        "",
        "## Summary",
        "",
        "| Rule | Level | Splunk | Elasticsearch |",
        "|---|---|---|---|",
    ]
    for c in conversions:
        cells = " | ".join(status(c, label) for label in BACKENDS)
        lines.append(f"| {c.title} | {c.level} | {cells} |")

    notes = [
        f"- **{c.title.split(' ')[0]}** ({label}): {'; '.join(c.caveats[label])}"
        for c in conversions
        for label in c.caveats
    ]
    if notes:
        lines += [
            "",
            "## Needs review",
            "",
            "These regular expressions use PCRE features that Lucene regular expressions do",
            "not support, so the Elasticsearch query is likely to fail or behave differently",
            "and should be rewritten before use. The Splunk query uses PCRE and keeps them.",
            "",
            *notes,
        ]

    lines += ["", "## Queries", ""]
    for c in conversions:
        lines += [f"### {c.title}", ""]
        for label in BACKENDS:
            lines.append(f"**{label}**")
            lines.append("")
            lines.append("```text")
            lines.append(c.queries.get(label) or f"not converted: {c.errors.get(label)}")
            lines += ["```", ""]

    lines += [
        "## Method and limits",
        "",
        "- A pipeline adds an `event_type` filter for `tool_call` and `tool_result` rules, so",
        "  each query only looks at the same events as the Python evaluator.",
        "- Field names are kept as written (for example `arguments.path`). They assume the",
        "  JSONL log is ingested with its JSON fields extracted, and, for Elasticsearch,",
        "  mapped as `keyword` so wildcard matches behave as expected.",
        "- No index or sourcetype is set. Add one for your deployment.",
        "- Sequence detections (`correlations.py`) are Python code and are not converted.",
        (
            f"- Versions: pySigma {version('pysigma')}, "
            f"pySigma-backend-splunk {version('pysigma-backend-splunk')}, "
            f"pySigma-backend-elasticsearch {version('pysigma-backend-elasticsearch')}."
        ),
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    conversions = convert_all()
    report = build_report(conversions)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(report, encoding="utf-8")
    print(report)
    print(f"report written to {REPORT}")
    if any(c.errors for c in conversions):
        raise SystemExit("some rules failed to convert; see the report")


if __name__ == "__main__":
    main()
