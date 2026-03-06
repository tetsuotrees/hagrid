# Dev Agent Handoff: WS-8 Notifications

Date: 2026-03-06  
Prepared by: Review/Planning Agent  
Executor: Dev Agent

## Mission

Implement WS-8 notifications for actionable Hagrid events.

The goal is to complete the remaining v0.2 milestone item with a minimal,
explicit-opt-in notification path that is safe by default and does not weaken
the repo's local-first posture.

## Current Baseline

- WS-5 policy/audit is merged and pushed
- WS-6 watch mode + D-1 dedup is merged and pushed
- WS-7 transactional rotation is merged and pushed
- latest pushed commit: `8f54f75`
- `cargo test` currently passes with 175 test invocations across all targets
- CI workflow exists at `.github/workflows/ci.yml`

## Scope In

- notification config loading
- notification event models/envelopes
- explicit-opt-in webhook delivery
- event emission from:
  - `hagrid drift`
  - `hagrid audit`
  - `hagrid rotate`
- tests for opt-in gating, payload safety, and delivery-failure isolation
- docs/spec/runbook updates required by shipped behavior

## Scope Out

- watch-mode notifications
- MCP server work
- background workers or daemons beyond existing command execution
- provider-managed rotation
- vault integration

## Required Deliverables

1. Notification module in `src/notify/` or equivalent.
2. Notification config support in `src/config/mod.rs`.
3. Command integration for `drift`, `audit`, and `rotate`.
4. Tests proving:
   - no-op when notifications are unconfigured
   - no-op when notifications are disabled
   - payloads exclude secret values
   - local webhook delivery works
   - sink failures do not alter primary command exit codes
5. Documentation updates:
   - `docs/spec.md`
   - `docs/runbooks/05-notifications.md`
   - `docs/handoffs/dev-agent-05-notifications.md`
   - ADR if required by the final transport/failure design

## Acceptance Criteria

- `cargo build` succeeds
- `cargo clippy --all-targets -- -D warnings` is clean
- `cargo test` passes across all targets
- default command execution makes no notification network calls
- notification delivery is explicit opt-in only
- emitted payloads contain no secret values
- notification delivery failures do not change command exit codes
- at least one end-to-end test demonstrates webhook receipt

## Required Review Constraints

1. No network calls by default. Missing or disabled config must be a no-op.
2. Notification payloads must not include plaintext secret values.
3. Delivery failures must not change the primary command's exit code.
4. `watch` must stay out of scope for WS-8.
5. Docs/spec/ADR must match shipped behavior exactly.

## Execution Guidance

1. Follow `docs/runbooks/05-notifications.md`.
2. Keep commits focused:
   - commit A: notification engine + config + tests
   - commit B: docs/spec/runbook/handoff updates
3. Prefer a minimal sink model over a broad plugin system.
4. If the chosen transport introduces a durable architectural rule, add an ADR.

## Report Back Format

Provide:

- commit hashes
- exact verification command outcomes
- any new config file format introduced
- open risks or deferred follow-ups
- whether the branch is ready to push
