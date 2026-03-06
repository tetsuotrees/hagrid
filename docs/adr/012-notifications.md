# ADR-012: Opt-In Webhook Notifications

## Status

Accepted

## Context

Hagrid is a local-first tool with a strict "no network calls by default" posture.
Users need visibility into actionable outcomes (drift detected, policy violations,
rotation failures) without polling or manual checks. A notification mechanism must
exist that preserves failure isolation — notification delivery problems must never
alter command exit codes or interfere with primary functionality.

## Decision

### Opt-in webhook model

Notifications are configured via `~/.hagrid/notifications.toml`. The file is
entirely optional; absence means notifications are disabled. An explicit
`enabled = true` flag must be set, and at least one `[[webhook]]` entry must
exist for any delivery to occur.

```toml
enabled = true
timeout_ms = 2000

[[webhook]]
name = "local-dev"
url = "http://127.0.0.1:8787/hagrid"
events = ["drift_detected", "policy_violations", "rotation_failure"]
```

### Typed event kinds

A `EventKind` enum with serde `snake_case` rename handles internal matching.
Config `events` lists match against serialized strings. An empty `events` list
on a webhook subscribes to all event kinds.

### Failure isolation by construction

- `load_notification_config_from_path` returns `NotificationConfig` (not
  `Result`). On any error it logs to stderr and returns the default disabled
  config.
- `dispatch_with_config` catches serialization and delivery errors, logs them
  to stderr, and returns `()`.
- CLI handlers compute exit codes before calling dispatch, so notification
  failures cannot alter them.

### Payload safety

Payload builders live in the `notify` module and accept domain types
(`DriftCheckResult`, `PolicyResult`, `RotateResult`). They explicitly select
safe fields — no secret values, no identity keys, no member fingerprints.
This is tested by asserting on serialized JSON output.

### Sync HTTP client (ureq)

`ureq` v2 provides sync HTTP with minimal dependency footprint (~5 deps,
~250KB). This matches Hagrid's synchronous CLI execution model. No async
runtime is required. Delivery has a configurable timeout (default 2000ms)
and no retry loop.

## Alternatives Considered

- **Async HTTP (reqwest)**: Would require a tokio runtime. Overhead not
  justified for best-effort webhook delivery in a CLI tool.
- **Plugin/sink abstraction**: Over-engineered for a single transport type.
  Can be added later if needed.
- **Notification on every command**: Too noisy. Only high-signal outcomes
  (drift detected, violations found, rotation failures) warrant notification.

## Consequences

- Default Hagrid execution makes zero network calls (preserved).
- Users who want notifications must create and enable the config file.
- Delivery failures are silent except for stderr warnings.
- Watch mode notifications are explicitly out of scope to avoid coupling
  a daemon loop to network behavior before the basic contract is proven.
