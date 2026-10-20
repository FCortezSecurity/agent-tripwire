# Policy engine

The gateway can run in two modes, set with `TRIPWIRE_MODE`:

- `monitor` (default): every call is evaluated and the verdict is logged as a
  `policy_decision` event, but nothing is blocked. Use it to see what a policy would do.
- `enforce`: calls that the policy denies are blocked. The agent receives a generic
  message ("This action is not permitted by security policy.") and never learns which
  rule fired. The log keeps the full reason.

`TRIPWIRE_POLICY` points at a policy file (default `policies/default.yaml`). An invalid or
missing policy stops the gateway from starting: it fails closed.

## Design principles

| Principle | How it shows up |
|---|---|
| Default deny | A tool that is not in the policy is blocked. Decoy tools are never listed in it |
| Allowlist over denylist | `read_file` may read `docs/` only. Listing what is forbidden would miss paths nobody thought of |
| Every verdict has a reason | `rule_id` such as `arg.send_email.to.allowed_domains` or `taint.send_email` |
| Pure decision function | `evaluate(policy, tool, arguments, state)` has no side effects, so it is easy to test |
| Strict config | Unknown keys are rejected, so a typo cannot silently weaken the policy |
| Fail closed | Bad policy, backend crash, or timeout never results in "allow" |

## What the default policy enforces

- `read_file` and `write_file`: paths must be inside `docs/` after normalization
  (`./`, `../`, and backslashes cannot dodge it)
- `list_files`: no parent-directory listing
- `send_email`: recipient domain must match exactly (`example.com` or `partner-example.org`,
  not `example.com.evil.test`), body length limit, and no long mixed-case encoded strings
- Session call budget of 50
- **Taint:** once any tool result looks like a secret, outbound tools are blocked for the
  rest of the session
- **Flow rule:** after reading `docs/internal/`, email may only go to `example.com`, even
  though `partner-example.org` is normally approved
- **Tool pinning:** the gateway records a tool's name, description, and schema when first observed, then rechecks the live definition immediately before each call. A changed definition is logged as `pin.changed`. In `enforce` mode, the changed tool is hidden from listings and its calls are blocked; in `monitor` mode, the change is logged but calls are allowed to continue. This catches definition changes even when the client does not request the tool list again (rug pull, S7).

## Why taint exists (ablation)

Scenario A10 reads a secret that sits in an allowed folder and emails it to an approved
domain. Every path and recipient check passes. With the taint rule removed the attack
succeeds; with it, the email is denied. Scenario A09 uses an unapproved recipient and is
blocked by the domain allowlist alone.

## Policy files

- `policies/default.yaml` is the current policy.
- `policies/baseline.yaml` is the Phase 4 policy, kept unchanged so the evasion round's
  "before" results stay reproducible (`--policy policies/baseline.yaml`).

## Known limitations

- Taint matches secret-looking text with a regex. Secrets in other formats, or content
  encoded before the tool returns it, would not taint the session.
- Taint is session-wide, so a legitimate task that reads a config file with a password in
  it loses email for the rest of that session. That is a deliberate utility trade-off.
- Allowlists have to be maintained. A new approved partner means a policy edit.
- Results so far use a scripted agent. They show the policy blocks these action
  sequences, not how often a real model would attempt them.
- The path allowlist depends on tool arguments being named `path` or `directory`. A new
  tool needs its own rules, or default deny will block it.

## Adding a tool

Add an entry under `tools:` with rules for each argument that matters. Until you do, the
gateway denies it. Run `python -m attacks.compare` afterwards to check that benign tasks
still work and attacks are still blocked.
