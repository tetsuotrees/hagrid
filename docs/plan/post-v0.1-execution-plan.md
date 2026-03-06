# Post-v0.1 Execution Plan

Status date: 2026-03-06

This plan now tracks the repo after WS-7 landed on `origin/main`. The release,
CI, policy, watch, and rotation streams are complete. The next scoped delivery
for v0.2 is notifications.

## Current Baseline

- `origin/main` at `8f54f75` (`WS-7: add transactional rotation workflow`)
- `.github/workflows/ci.yml` exists and runs build, clippy, and test
- `cargo test` currently passes with 175 test invocations across all targets
- Completed v0.2 features:
  - WS-5: policy engine + `hagrid audit`
  - WS-6: watch mode + D-1 dedup refinement
  - WS-7: transactional rotation workflow

## Completed Streams

### WS-1 and WS-2: Release + CI

Completed. Release metadata, release notes, CI workflow, and branch-protection
documentation are in place.

### WS-3: Dogfooding and Signal Intake

Completed. Findings were captured in
`docs/reports/dogfooding-2026-03-04.md` and fed back into follow-up work.

### WS-4: Follow-up Cleanup

Completed. CLI disambiguation coverage and documentation consistency updates
landed before the v0.2 feature streams.

### WS-5: Policy Engine

Completed. `hagrid audit` shipped with exit code 4 for violations and coverage
for policy matching, git checks, max-age handling, and disambiguation.

### WS-6: Watch Mode

Completed. `hagrid watch` shipped with debounced re-scan behavior and D-1
dedup to prefer structural findings over duplicate `RawLine` entries.

### WS-7: Rotation Workflow

Completed. `hagrid rotate-info` and `hagrid rotate` shipped with path-aware
JSON/TOML mutation, same-file transaction semantics, rollback on
verification/index failure, and exit code 5 for partial failure.

## Active Next Stream

### WS-8: Notifications

Objective:

- complete the remaining v0.2 milestone item with a minimal, explicit-opt-in
  notification path for actionable Hagrid events

Scope:

- add notification configuration loading
- add a notification event envelope that never includes secret values
- add explicit-opt-in webhook delivery
- emit notifications for:
  - drift detection
  - policy violations
  - rotation failure or partial failure
- keep notification failures isolated from the primary command outcome

Scope out:

- watch-mode event streaming or per-file watch notifications
- MCP server work
- provider-managed rotation or vault integration
- background daemons beyond existing command execution

Required deliverables:

1. `src/notify/mod.rs` (or equivalent) with notification models and delivery.
2. Notification config support in `src/config/mod.rs`.
3. Command integration for `drift`, `audit`, and `rotate`.
4. Tests covering opt-in gating, payload redaction, delivery, and sink-failure
   isolation.
5. Docs:
   - technical spec update
   - runbook
   - handoff
   - ADR if the transport or failure model introduces a new architecture decision

Exit criteria:

- `cargo build` passes
- `cargo clippy --all-targets -- -D warnings` passes
- `cargo test` passes across all targets
- default operation performs no notification delivery and makes no network calls
- notification payloads contain no secret values
- delivery failures are reported but do not change the primary command exit code
- at least one end-to-end test proves a configured sink receives an event

## Sequence

1. Execute WS-8 next.
2. After WS-8, reassess whether v0.2 is ready for release hardening or needs a
   short cleanup stream.

## Ownership and Handoff

- Dev Agent owns execution of WS-8.
- Review/Planning Agent validates acceptance criteria, reviews correctness and
  safety, and updates this plan after each stream.
- Every stream must include a handoff doc under `docs/handoffs/` before work
  starts.

## Reporting Cadence

- End-of-stream summary:
  - changes made
  - verification commands and outcomes
  - open risks
  - next recommended stream
