# Runbook 05: Notifications (WS-8)

## Scope

Implement the remaining v0.2 milestone item: notifications for actionable
Hagrid events, while preserving the repo's local-first security posture.

WS-8 should stay intentionally narrow:

- explicit opt-in only
- webhook delivery only
- high-signal command outcomes only
- no secret values in payloads
- no effect on the primary command exit code if delivery fails

## Prerequisites

- WS-7 merged and pushed (`8f54f75` on `origin/main`)
- existing CI workflow green enough to trust build/clippy/test gating
- no new background daemon requirements for this stream

## Proposed Implementation Steps

### 1. Notification Config

Add notification config loading in `src/config/mod.rs`.

Suggested file: `~/.hagrid/notifications.toml`

Suggested schema:

```toml
enabled = true
timeout_ms = 2000

[[webhook]]
name = "local-dev"
url = "http://127.0.0.1:8787/hagrid"
events = ["drift_detected", "policy_violations", "rotation_failure"]
```

Behavior requirements:

- missing config file is a no-op
- `enabled = false` is a no-op
- malformed config returns a normal command error only when notifications are
  explicitly enabled

### 2. Notification Module

Create a dedicated module, e.g. `src/notify/mod.rs`, with:

- config models
- event envelope models
- delivery function(s)
- payload sanitization guardrails

The envelope should include only metadata such as:

- event kind
- timestamp
- command name
- exit code
- counts and summary text
- group labels, policy names, reference IDs, fingerprint prefixes, file paths
  when useful

It must never include:

- secret values
- raw stdin input
- full rotated values

### 3. Delivery Transport

Implement explicit-opt-in webhook POST delivery with JSON payloads.

Transport requirements:

- short timeout
- best-effort delivery
- failure logged to stderr
- no retry loop in WS-8
- no effect on the command's primary exit code

### 4. Emitters

Hook notifications into high-signal command outcomes only:

- `hagrid drift`
  - emit when drift is detected
- `hagrid audit`
  - emit when policy violations are reported
- `hagrid rotate`
  - emit on partial failure or full failure

Do not emit notifications from `watch` in WS-8. That would be too noisy and
would couple a daemon loop to network behavior before the basic sink contract
is proven.

### 5. Documentation

Update:

- `docs/spec.md`
- `docs/README.md` if active execution docs change
- `docs/runbooks/05-notifications.md`
- `docs/handoffs/dev-agent-05-notifications.md`
- ADR only if needed for transport/failure semantics

## Verification

```bash
cargo build
cargo clippy --all-targets -- -D warnings
cargo test
```

## Test Expectations

Add coverage for:

- config absent -> no-op
- config disabled -> no-op
- payload contains no secret values
- delivery to a local test HTTP server succeeds
- sink failure does not alter exit code for:
  - `drift`
  - `audit`
  - `rotate`

## Review Constraints

- No network calls by default.
- Notification delivery must be explicit opt-in.
- No secret values in payloads, logs, or test snapshots.
- Sink failure isolation is mandatory.
- Avoid watch-mode integration in this stream.
