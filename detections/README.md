# Detections

Sigma rules for Agent Tripwire event logs (`logs/*.jsonl`), plus a local evaluator.

## Log source

`product: agent_tripwire`, with `category` set to the event type: `tool_call`,
`tool_result`, or `tools_list`.

| Field | Meaning |
|---|---|
| `event_type` | tool_call, tool_result, tools_list |
| `session_id`, `call_index` | one session per gateway run; index counts events in order |
| `tool_name`, `server` | which tool and which backend |
| `arguments.<name>` | tool arguments, flattened (for example `arguments.path`) |
| `result_text`, `result_size`, `is_error` | tool output, truncated to 4000 characters |

## Rules

| Code | Name | Level | Scenario |
|---|---|---|---|
| TW-001 | Sensitive file read (path name) | low (signal) | S5 |
| TW-002 | Path traversal | high | S5 |
| TW-003 | Untrusted outbound recipient | medium | S4 |
| TW-004 | Injection phrases in tool output | low (signal) | S2 |
| TW-005 | Encoded blob in outbound message | medium | S4 |
| TW-006 | Secret-looking content returned to the agent | high | S5, S6 |
| TW-101 | Sensitive read followed by outbound call (sequence) | high | S4, S6 |
| TW-102 | Injection phrases followed by outbound or sensitive call (sequence) | high | S2 |

Rules at level **low** are signals: they add context and feed the sequence rules, but they
do not alert by themselves. Medium and above alert.

ATLAS and OWASP tags are best-effort. Verify technique IDs on atlas.mitre.org before
publishing.

## Running

```
python -m attacks.runner        # record logs for every scenario
python -m detections.evaluate   # score the rules, write docs/results/detection-results.md
```

## TW-101 in Splunk (untested draft)

Plain Sigma matches one event at a time, so the sequence rule lives in Python. A Splunk
equivalent, assuming events are indexed as JSON with fields extracted:

```
index=agent_tripwire event_type=tool_call
| eval sensitive=if(tool_name="read_file" AND match(lower('arguments.path'), "secrets/|\.env|credential|\.aws|id_rsa|\.ssh"), 1, 0)
| eval outbound=if(tool_name="send_email", 1, 0)
| sort 0 session_id call_index
| streamstats current=f window=4 max(sensitive) as recent_sensitive by session_id
| where outbound=1 AND recent_sensitive=1
```
