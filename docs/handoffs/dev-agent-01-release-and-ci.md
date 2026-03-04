# Dev Agent Handoff: Stream 01 (Release + CI)

Date: 2026-03-04  
Prepared by: Review/Planning Agent  
Executor: Dev Agent

## Mission

Complete WS-1 and WS-2 from `docs/plan/post-v0.1-execution-plan.md`:

- ship v0.1.0 release metadata and artifacts
- enforce CI quality gates on `main`

## Scope In

- release docs (`CHANGELOG.md`, release notes)
- CI workflow (`.github/workflows/ci.yml`)
- branch protection/status check enablement
- release tag and GitHub release creation

## Scope Out

- feature work for v0.2 (`audit`, watcher, rotate)
- scanner/parser behavior changes unless blocking release
- architectural changes requiring new ADRs

## Required Deliverables

1. `CHANGELOG.md` with `0.1.0` entry.
2. Release notes doc (`docs/releases/v0.1.0.md` preferred).
3. CI workflow in `.github/workflows/ci.yml` running build/clippy/test on macOS.
4. Pushed tag `v0.1.0`.
5. Published GitHub release using prepared notes.

## Acceptance Criteria

- local verification commands all pass:
  - `cargo build`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo test`
- CI workflow reports green on latest `main`.
- branch protection requires CI checks before merge.
- tag points to the intended release commit.

## Execution Steps

1. Follow `docs/runbooks/01-release-and-ci-bootstrap.md` exactly.
2. Keep commits focused:
  - commit A: release docs
  - commit B: CI workflow/policy docs (can combine with A if small)
  - commit C: tag/release metadata adjustments if needed
3. Do not rewrite history after release tag is published.

## Report Back Format

Provide a single summary with:

- commit hashes
- CI run links and status
- release URL
- exact verification command outcomes
- any open follow-up issues

## Escalation Triggers

Escalate immediately if:

- SQLCipher/Keychain behavior differs in CI from local
- tests require secret material or external services
- branch protection cannot be configured with current permissions

