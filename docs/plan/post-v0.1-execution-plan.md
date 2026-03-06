# Post-v0.1 Execution Plan

Status date: 2026-03-06

This plan now tracks the repo after WS-8 landed on `origin/main`. The v0.2
feature streams are complete. The next scoped delivery is a short release-
hardening pass to prepare `v0.2.0`.

## Current Baseline

- `origin/main` at `bf0b2e8` (`WS-8: stabilize webhook notification tests`)
- `.github/workflows/ci.yml` exists and runs build, clippy, and test
- `cargo test` currently passes with 190 test invocations across all targets
- Completed v0.2 features:
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

## Active Next Stream

### WS-9: v0.2 Release Hardening

Objective:

- prepare a release candidate for `v0.2.0`
- close release-blocking documentation, verification, and CI-gating gaps
- leave the repo ready for tag/publish on explicit user approval

Scope:

- cut `v0.2.0` release documentation:
  - `CHANGELOG.md`
  - `docs/releases/v0.2.0.md`
- verify and, if needed, fix CI or branch-protection check-name mismatch so the
  required status check matches the actual workflow result
- rerun build/clippy/test and a small CLI smoke pass for shipped v0.2 commands
- patch any small release-blocking test or documentation gaps found during
  hardening
- document the exact release procedure and any remaining non-blocking follow-up

Scope out:

- new user-facing features beyond release blockers
- v0.3 TUI work
- v0.3 MCP server work
- provider-managed rotation or vault integration
- watch-mode notifications
- automatic tagging/publishing without explicit user approval

Required deliverables:

1. `CHANGELOG.md` with a `0.2.0` release entry.
2. `docs/releases/v0.2.0.md` with release notes and verification checklist.
3. Any workflow or documentation updates needed to align required CI checks with
   the real workflow.
4. Any targeted test/docs fixes required to make release claims accurate.
5. A release-ready handoff summarizing final verification and remaining risks.

Exit criteria:

- `cargo build` passes
- `cargo clippy --all-targets -- -D warnings` passes
- `cargo test` passes across all targets
- release notes accurately describe shipped v0.2 commands, security posture, and
  known limitations
- the CI required-check mismatch is resolved or documented with an explicit
  blocker/escalation note
- the repo is ready to tag `v0.2.0` once the user explicitly approves release

## Sequence

1. Execute WS-9 next.
2. After WS-9, request explicit approval for `v0.2.0` tag/publish work.
3. After `v0.2.0`, open v0.3 planning for TUI + MCP server.

## Ownership and Handoff

- Dev Agent owns execution of WS-9.
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
