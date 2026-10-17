"""Policy engine: decides whether a tool call is allowed.

Design, borrowed from firewalls:
  - default deny: a tool that is not listed is blocked
  - allowlists beat denylists: say where a tool MAY read, not where it may not
  - first violation wins, and every verdict carries the rule that caused it
  - pure function: (policy, call, session state) -> verdict, so it is easy to test

Taint (a simple information-flow rule): once a tool result contains secret-looking content,
the session is tainted and outbound tools are blocked, whatever path or recipient is used.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from gateway.canaries import normalize_path
from gateway.events import Decision


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")  # a typo in the policy file must not pass silently


class ArgumentRule(_Strict):
    kind: Literal["string", "path", "email"] = "string"
    allow_prefixes: list[str] | None = None  # path must start with one of these
    allowed_domains: list[str] | None = None  # email domain must be exactly one of these
    deny_patterns: list[str] = Field(default_factory=list)  # regex, case sensitive unless (?i)
    max_length: int | None = None


class ToolRule(_Strict):
    allow: bool = True
    arguments: dict[str, ArgumentRule] = Field(default_factory=dict)


class TaintRule(_Strict):
    patterns: list[str]  # regex matched against tool results
    deny_tools: list[str]  # tools blocked once the session is tainted


class Policy(_Strict):
    default: Literal["allow", "deny"] = "deny"
    max_calls_per_session: int | None = None
    pin_tools: bool = True  # detect tool definitions that change after first sight
    tools: dict[str, ToolRule] = Field(default_factory=dict)
    taint: TaintRule | None = None


def load_policy(path: Path) -> Policy:
    """Load and validate a policy file. Raises on any problem, so the gateway fails closed."""
    return Policy.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


@dataclass
class PolicyState:
    calls: int = 0
    tainted: bool = False


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    rule_id: str
    reason: str


def _allow(rule_id: str = "policy.allow", reason: str = "allowed by policy") -> Verdict:
    return Verdict(Decision.ALLOW, rule_id, reason)


def _deny(rule_id: str, reason: str) -> Verdict:
    return Verdict(Decision.DENY, rule_id, reason)


def _check_argument(tool: str, name: str, value: object, rule: ArgumentRule) -> Verdict | None:
    """Return a deny verdict if the argument breaks its rule, otherwise None."""
    text = str(value)
    domain = ""
    if rule.kind == "path":
        text = normalize_path(text)
    elif rule.kind == "email":
        domain = text.rsplit("@", 1)[-1].strip().lower() if "@" in text else ""
    where = f"arg.{tool}.{name}"

    if rule.max_length is not None and len(text) > rule.max_length:
        return _deny(f"{where}.max_length", f"{name} longer than {rule.max_length} characters")
    if rule.allow_prefixes is not None and not any(text.startswith(p) for p in rule.allow_prefixes):
        return _deny(f"{where}.allow_prefixes", f"{name} is outside the allowed locations")
    if rule.allowed_domains is not None and domain not in {d.lower() for d in rule.allowed_domains}:
        return _deny(f"{where}.allowed_domains", f"{name} domain is not approved")
    for pattern in rule.deny_patterns:
        if re.search(pattern, text):
            return _deny(f"{where}.deny_pattern", f"{name} matches a blocked pattern")
    return None


def evaluate(policy: Policy, tool: str, arguments: dict, state: PolicyState) -> Verdict:
    if policy.max_calls_per_session is not None and state.calls >= policy.max_calls_per_session:
        return _deny("session.max_calls", "call budget for this session is used up")

    rule = policy.tools.get(tool)
    if rule is None:
        if policy.default == "deny":
            return _deny("policy.default_deny", f"tool '{tool}' is not in the policy")
        return _allow("policy.default_allow", "tool not listed, default is allow")
    if not rule.allow:
        return _deny(f"tool.{tool}.disabled", f"tool '{tool}' is disabled")

    if state.tainted and policy.taint and tool in policy.taint.deny_tools:
        return _deny(f"taint.{tool}", "session saw secret-looking content, outbound blocked")

    for name, arg_rule in rule.arguments.items():
        if name in arguments:
            violation = _check_argument(tool, name, arguments[name], arg_rule)
            if violation:
                return violation
    return _allow()


def result_taints(policy: Policy, result_text: str) -> bool:
    if not policy.taint:
        return False
    return any(re.search(p, result_text) for p in policy.taint.patterns)
