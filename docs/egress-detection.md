# Cross-call Base64 egress detection

This page holds the details of the gateway's egress detector, moved out of the main README to keep it short.

## What it does

The gateway keeps bounded fingerprints of token-like strings observed in successful tool results. When the agent sends email, the detector checks eligible Base64 content against those fingerprints across successive calls to the same recipient, so a token split into fragments across several messages can still be matched.

| Mode | Behavior on a match |
|---|---|
| `enforce` | The outbound call is blocked before the backend runs |
| `monitor` | The suspected match is logged and the call is allowed |

## Tests

The detector has focused unit and integration tests for:

- A token split across successive outbound email calls.
- Enforce mode blocking a matching final fragment before backend execution.
- Monitor mode logging a suspected match while allowing the call.
- Recipient separation, unrelated Base64 content, malformed input, and bounded detector state.

## Chunking probe

A separate probe tested one synthetic token across **28 fixed chunk sizes**. The detector caught the token in all 28 cases.

This is a narrow test of one token and those chunking patterns. It is not a general detection-rate measurement.

## Known gaps

- Alternating recipients
- An intervening benign message
- Text prefixes mixed into chunks
- Out-of-order chunks
- URL-safe Base64
- Hex encoding
- Other outbound channels
- Tokens the gateway has not observed
- Bounded state, which limits how much history the detector can retain

## Why it exists

Per-call checks passed when a secret was split across several emails, because no single message looked suspicious. This detector was added to cover that case after feedback on the project. It is targeted at that pattern and is not general-purpose DLP.
