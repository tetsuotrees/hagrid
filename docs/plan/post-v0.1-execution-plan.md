# Post-v0.1 Execution Plan

Status date: 2026-03-07

This plan now tracks the repo after the `v0.2.0` release landed on
`origin/main`. The v0.2 feature and release-hardening streams are complete.
The next scoped delivery opens the v0.3 line with a read-only TUI foundation.

## Current Baseline

- `origin/main` at `f7c50cd` (`Docs: fix v0.2.0 release metadata`)
- tag `v0.2.0` points to `f7c50cd`
- `.github/workflows/ci.yml` exists and runs build, clippy, and test
- `cargo test` currently passes with 190 test invocations across all targets
- Released in `v0.2.0`:
  - WS-5: policy engine + `hagrid audit`
  - WS-6: watch mode + D-1 dedup refinement
  - WS-7: transactional rotation workflow
  - WS-8: explicit-opt-in webhook notifications

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

### WS-8: Notifications

Completed. `hagrid` now supports explicit-opt-in webhook notifications for
drift, audit, and rotation failures with failure isolation, per-webhook event
filtering, and payloads that exclude secret values.

### WS-9: v0.2 Release Hardening

Completed. `v0.2.0` release notes, changelog, version metadata, and release
verification are in place. The CI check-name concern was verified as a repo
policy behavior, not a workflow naming mismatch.

## Active Next Stream

### WS-10: TUI Foundation

Objective:

- open the v0.3 line with a local-only terminal UI
- provide a read-only inspection surface over the existing index and group data
- keep the first TUI slice narrow enough to stabilize state, layout, and
  navigation before any mutation workflows are added

Scope:

- add `hagrid tui`
- add a TUI module/app state layer that reads existing index/group/suggestion
  data without shelling out to CLI subcommands
- show a summary/dashboard plus navigable list/detail views for key inventory
  data (for example groups, ungrouped refs, or suggestions)
- implement keyboard navigation, refresh, and quit behavior
- add tests for app-state transitions, data loading, and non-secret rendering
- update docs/spec/runbook/handoff to reflect the shipped TUI behavior

Scope out:

- mutation flows from the TUI (`group`, `ungroup`, `forget`, `rotate`, etc.)
- watch-mode embedding inside the TUI
- notification configuration or delivery from the TUI
- v0.3 MCP server work
- provider-managed rotation or vault integration
- watch-mode notifications

Required deliverables:

1. TUI command wiring in `src/main.rs` and a new `src/tui/` module (or
   equivalent).
2. A read-only dashboard/list/detail flow over existing Hagrid data.
3. Tests covering navigation/state transitions and safe rendering.
4. Docs:
   - technical spec update
   - runbook
   - handoff
   - ADR only if the final TUI architecture introduces a durable rule

Exit criteria:

- `cargo build` passes
- `cargo clippy --all-targets -- -D warnings` passes
- `cargo test` passes across all targets
- `hagrid tui` launches and exits cleanly
- the TUI renders metadata only and never displays secret values
- the TUI remains local-only with no network calls
- the first slice is read-only; destructive or mutating actions remain out of
  scope

## Sequence

1. Execute WS-10 next.
2. After WS-10, reassess TUI ergonomics and whether a second TUI slice is
   needed before exposing write actions.
3. Revisit ADR-007 against the current upstream MCP protocol before staging the
   MCP server stream.

## Ownership and Handoff

- Dev Agent owns execution of WS-10.
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
