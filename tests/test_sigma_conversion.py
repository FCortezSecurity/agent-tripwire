"""Every Sigma rule must convert to Splunk and Elasticsearch with pySigma."""

from pathlib import Path

import yaml

from detections.convert import BACKENDS, RULES_DIR, convert_all
from detections.engine import load_rules

# Regexes that use PCRE-only features; Lucene (Elasticsearch) regexes cannot express them.
PCRE_RULES = {"tripwire_encoded_blob_outbound", "tripwire_secret_content_in_result"}


def test_every_rule_converts_on_every_backend():
    conversions = convert_all()
    assert conversions, "no rules found"
    failures = {c.file: c.errors for c in conversions if c.errors}
    assert not failures, failures
    for c in conversions:
        for label in BACKENDS:
            assert c.queries[label].strip(), f"{c.file}: empty {label} query"


def test_converted_rules_match_the_rules_the_python_engine_loads():
    converted = {c.name for c in convert_all()}
    assert converted == {r.name for r in load_rules()}


def test_event_type_filter_is_added_to_call_and_result_rules():
    by_file = {c.file: c for c in convert_all()}
    for path in sorted(RULES_DIR.glob("*.yml")):
        category = yaml.safe_load(path.read_text(encoding="utf-8"))["logsource"]["category"]
        for label in BACKENDS:
            query = by_file[path.name].queries[label]
            assert "event_type" in query and category in query, (path.name, label)


def test_pcre_only_regexes_are_flagged_for_elasticsearch():
    flagged = {c.name for c in convert_all() if "Elasticsearch" in c.caveats}
    assert PCRE_RULES <= flagged


def test_a_rule_that_cannot_convert_is_reported_not_hidden(tmp_path: Path):
    bad = (
        "title: TW-999 Broken rule\n"
        "name: tripwire_broken\n"
        "logsource:\n"
        "  product: agent_tripwire\n"
        "  category: tool_call\n"
        "detection:\n"
        "  selection:\n"
        "    tool_name|nosuchmodifier: read_file\n"
        "  condition: selection\n"
    )
    (tmp_path / "tw_999_broken.yml").write_text(bad, encoding="utf-8")
    (conversion,) = convert_all(tmp_path)
    assert set(conversion.errors) == set(BACKENDS)
