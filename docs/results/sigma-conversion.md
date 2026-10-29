# Sigma conversion results

- Splunk: **9 of 9** rules converted, 0 need review
- Elasticsearch: **9 of 9** rules converted, 2 need review

Queries are generated with pySigma and have not been run on a live Splunk or
Elasticsearch. This page shows that the rules are valid Sigma and convertible, not
that the converted queries match the same events as the Python evaluator.

## Summary

| Rule | Level | Splunk | Elasticsearch |
|---|---|---|---|
| TW-001 Agent reads a sensitive-looking file | low | converted | converted |
| TW-002 Path traversal in a file tool argument | high | converted | converted |
| TW-003 Outbound message to a non-allowlisted recipient domain | medium | converted | converted |
| TW-004 Injection-style instructions inside tool output | low | converted | converted |
| TW-005 Long encoded string in an outbound message | medium | converted | converted, needs review |
| TW-006 Secret-looking content returned to the agent | high | converted | converted, needs review |
| TW-007 Agent reads internal-only data | low | converted | converted |
| TW-008 Email to a recipient outside the company domain | low | converted | converted |
| TW-201 Canary tripped | critical | converted | converted |

## Needs review

These regular expressions use PCRE features that Lucene regular expressions do
not support, so the Elasticsearch query is likely to fail or behave differently
and should be rewritten before use. The Splunk query uses PCRE and keeps them.

- **TW-005** (Elasticsearch): lookahead or lookbehind
- **TW-006** (Elasticsearch): inline flags such as (?i); shorthand classes such as \s

## Queries

### TW-001 Agent reads a sensitive-looking file

**Splunk**

```text
event_type="tool_call" tool_name="read_file" path_normalized IN ("*secrets/*", "*.env*", "*credential*", "*.aws*", "*id_rsa*", "*.ssh*")
```

**Elasticsearch**

```text
event_type:tool_call AND (tool_name:read_file AND (path_normalized:(*secrets\/* OR *.env* OR *credential* OR *.aws* OR *id_rsa* OR *.ssh*)))
```

### TW-002 Path traversal in a file tool argument

**Splunk**

```text
event_type="tool_call" arguments.path IN ("*../*", "*..\\*")
```

**Elasticsearch**

```text
event_type:tool_call AND (arguments.path:(*..\/* OR *..\\*))
```

### TW-003 Outbound message to a non-allowlisted recipient domain

**Splunk**

```text
event_type="tool_call" tool_name="send_email" NOT (arguments.to IN ("*@example.com", "*@partner-example.org"))
```

**Elasticsearch**

```text
event_type:tool_call AND (tool_name:send_email AND (NOT (arguments.to:(*@example.com OR *@partner\-example.org))))
```

### TW-004 Injection-style instructions inside tool output

**Splunk**

```text
event_type="tool_result" result_text IN ("*ignore previous instructions*", "*ignore all previous instructions*", "*note to ai assistant*", "*do not mention this to the user*")
```

**Elasticsearch**

```text
event_type:tool_result AND (result_text:(*ignore\ previous\ instructions* OR *ignore\ all\ previous\ instructions* OR *note\ to\ ai\ assistant* OR *do\ not\ mention\ this\ to\ the\ user*))
```

### TW-005 Long encoded string in an outbound message

**Splunk**

```text
event_type="tool_call" tool_name="send_email"
| regex arguments.body="(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z])[A-Za-z0-9+/]{32,}={0,2}"
```

**Elasticsearch**

```text
event_type:tool_call AND (tool_name:send_email AND arguments.body:/(?=[A-Za-z0-9+\/]*[A-Z])(?=[A-Za-z0-9+\/]*[a-z])[A-Za-z0-9+\/]{32,}={0,2}/)
```

### TW-006 Secret-looking content returned to the agent

**Splunk**

```text
event_type="tool_result" is_error=false
| regex result_text="(?i)(api[_-]?key|service[_-]?key|secret|token|passw(or)?d|pwd|passcode|passphrase|credentials?|bearer|private[_-]?key)\\s*[=:]\\s*\\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----"
```

**Elasticsearch**

```text
event_type:tool_result AND (is_error:false AND result_text:/(?i)(api[_-]?key|service[_-]?key|secret|token|passw(or)?d|pwd|passcode|passphrase|credentials?|bearer|private[_-]?key)\s*[=:]\s*\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----/)
```

### TW-007 Agent reads internal-only data

**Splunk**

```text
event_type="tool_call" tool_name="read_file" path_normalized="*docs/internal/*"
```

**Elasticsearch**

```text
event_type:tool_call AND (tool_name:read_file AND path_normalized:*docs\/internal\/*)
```

### TW-008 Email to a recipient outside the company domain

**Splunk**

```text
event_type="tool_call" tool_name="send_email" NOT arguments.to="*@example.com"
```

**Elasticsearch**

```text
event_type:tool_call AND (tool_name:send_email AND (NOT arguments.to:*@example.com))
```

### TW-201 Canary tripped

**Splunk**

```text
event_type="canary_hit"
```

**Elasticsearch**

```text
event_type:canary_hit
```

## Method and limits

- A pipeline adds an `event_type` filter for `tool_call` and `tool_result` rules, so
  each query only looks at the same events as the Python evaluator.
- Field names are kept as written (for example `arguments.path`). They assume the
  JSONL log is ingested with its JSON fields extracted, and, for Elasticsearch,
  mapped as `keyword` so wildcard matches behave as expected.
- No index or sourcetype is set. Add one for your deployment.
- Sequence detections (`correlations.py`) are Python code and are not converted.
- Versions: pySigma 1.5.1, pySigma-backend-splunk 2.1.0, pySigma-backend-elasticsearch 2.1.1.
