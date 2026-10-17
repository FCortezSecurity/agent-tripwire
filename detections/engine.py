"""A small evaluator for single-event Sigma rules, run against the gateway's JSONL logs.

It supports the subset of Sigma these rules use: field modifiers (contains, startswith,
endswith, re, all), selections as maps or lists of maps, and conditions with and, or, not,
parentheses, and "1 of" / "all of" patterns. Rules are standard Sigma YAML, so they can
also be converted for Splunk with pySigma.
"""

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

RULES_DIR = Path(__file__).resolve().parent / "rules"


@dataclass(frozen=True)
class Rule:
    name: str
    title: str
    level: str
    category: str
    selections: dict[str, Any]
    condition: str
    falsepositives: list[str]
    tags: list[str]

    @property
    def code(self) -> str:
        return self.title.split(" ")[0]


def load_rules(directory: Path = RULES_DIR) -> list[Rule]:
    rules = []
    for path in sorted(directory.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        detection = dict(doc["detection"])
        condition = detection.pop("condition")
        rules.append(
            Rule(
                name=doc["name"],
                title=doc["title"],
                level=doc.get("level", "medium"),
                category=doc["logsource"]["category"],
                selections=detection,
                condition=condition,
                falsepositives=doc.get("falsepositives", []),
                tags=doc.get("tags", []),
            )
        )
    return rules


def flatten(event: dict) -> dict[str, Any]:
    """Turn nested arguments into dotted keys, e.g. arguments.path."""
    flat = {k: v for k, v in event.items() if not isinstance(v, (dict, list))}
    for key, value in (event.get("arguments") or {}).items():
        flat[f"arguments.{key}"] = value
    return flat


def _match_value(actual: Any, op: str, expected: Any) -> bool:
    if actual is None:
        return expected is None
    if op == "re":
        return re.search(str(expected), str(actual)) is not None
    a, e = str(actual).lower(), str(expected).lower()
    if op == "contains":
        return e in a
    if op == "startswith":
        return a.startswith(e)
    if op == "endswith":
        return a.endswith(e)
    return a == e


def _match_field(flat: dict, key: str, expected: Any) -> bool:
    field, *mods = key.split("|")
    op = next((m for m in mods if m in {"contains", "startswith", "endswith", "re"}), "eq")
    values = expected if isinstance(expected, list) else [expected]
    results = [_match_value(flat.get(field), op, v) for v in values]
    return all(results) if "all" in mods else any(results)


def _match_selection(flat: dict, selection: Any) -> bool:
    if isinstance(selection, list):
        return any(_match_selection(flat, item) for item in selection)
    return all(_match_field(flat, k, v) for k, v in selection.items())


class _Condition:
    """Recursive-descent parser and evaluator for Sigma condition strings."""

    def __init__(self, text: str, results: dict[str, bool]):
        self.tokens = re.findall(r"\(|\)|[^\s()]+", text)
        self.pos = 0
        self.results = results

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def parse(self) -> bool:
        value = self._or()
        if self._peek() is not None:
            raise ValueError(f"unexpected token {self._peek()!r}")
        return value

    def _or(self) -> bool:
        value = self._and()
        while self._peek() == "or":
            self._next()
            value = self._and() or value
        return value

    def _and(self) -> bool:
        value = self._not()
        while self._peek() == "and":
            self._next()
            value = self._not() and value
        return value

    def _not(self) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        token = self._next()
        if token == "(":
            value = self._or()
            self._next()  # closing parenthesis
            return value
        if token in {"1", "all"} and self._peek() == "of":
            self._next()
            pattern = self._next()
            names = [n for n in self.results if pattern == "them" or fnmatch.fnmatch(n, pattern)]
            hits = [self.results[n] for n in names]
            return any(hits) if token == "1" else bool(hits) and all(hits)
        return self.results[token]


def matches(rule: Rule, event: dict) -> bool:
    if event["event_type"] != rule.category:
        return False
    flat = flatten(event)
    results = {name: _match_selection(flat, sel) for name, sel in rule.selections.items()}
    return _Condition(rule.condition, results).parse()
