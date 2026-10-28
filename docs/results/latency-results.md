# Gateway latency overhead

Measured on 2026-10-28 with `benchmarks/latency.py`.

## Per-call latency

| Condition | Calls | Median (ms) | Mean (ms) | p95 (ms) |
|---|---:|---:|---:|---:|
| direct | 200 | 2.3 | 2.5 | 3.5 |
| gateway (monitor) | 200 | 12.7 | 12.7 | 15.7 |
| gateway (enforce) | 200 | 12.7 | 12.7 | 15.6 |

## Overhead added by the gateway

| Mode | Median overhead (ms) | p95 overhead (ms) |
|---|---:|---:|
| monitor | 10.4 | 12.3 |
| enforce | 10.4 | 12.2 |

## Method and caveats

- One tool (`read_file`) reading one small file, over stdio on a single machine.
- 200 timed calls per condition, in fresh sessions of 20 calls. Startup and 2 warm-up calls per session are excluded.
- Conditions are interleaved session by session so machine noise affects all three.
- The gateway figure includes its extra process hop: it is itself an MCP server that forwards to the real tool server, so it pays for policy, logging, and one more round trip.
- Overhead is the difference between the gateway's and the direct call's median (or p95), not a per-call delta.
- This is a single-client latency check, not a throughput or load test, and it was not run against a real model or real third-party tools.

## Environment

- Python 3.14.6 on Windows-11-10.0.26300-SP0
- mcp 2.3.0
