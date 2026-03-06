# Runbook 06: v0.2 Release Hardening (WS-9)

**Status: Complete**

## Purpose

Prepare a release candidate for `v0.2.0` after the v0.2 feature streams
landed. This stream is intentionally narrow: release docs, verification,
required-check alignment, and small release-blocking cleanup only.

## Baseline

- `origin/main` at `bf0b2e8` (`WS-8: stabilize webhook notification tests`)
- `cargo test` passes with 190 test invocations across all targets
- Shipped v0.2 features:
  - `hagrid audit`
  - `hagrid watch`
  - `hagrid rotate-info`
  - `hagrid rotate`
  - opt-in webhook notifications

## Scope

In scope:

- release notes and changelog prep for `v0.2.0`
- release-candidate verification (`build`, `clippy`, `test`)
- CI/required-check alignment so the expected gate matches the actual workflow
- small release-blocking test or docs fixes discovered during hardening
- release-ready handoff with exact remaining risks

Out of scope:

- new product features
- v0.3 TUI or MCP work
- watch-mode notifications
- provider-managed rotation or vault integration
- automatic release tagging or publishing without explicit user approval

## Required Outputs

1. `CHANGELOG.md` updated with a `0.2.0` section dated for release day.
2. `docs/releases/v0.2.0.md` with:
   - summary
   - highlights
   - included commands
   - security notes
   - known limitations
   - verification checklist
3. Any workflow/doc changes needed to align required CI checks with the real
   workflow result.
4. Optional small test/docs patches only if needed to make release claims true.

## Procedure

1. Re-verify the current baseline.

```bash
cargo build
cargo clippy --all-targets -- -D warnings
cargo test
```

2. Prepare release documentation.

- move current `CHANGELOG.md` unreleased entries into a `0.2.0` section
- draft `docs/releases/v0.2.0.md`
- make sure the notes reflect shipped behavior only:
  - notifications are explicit opt-in only
  - watch-mode notifications are not included
  - rotation supports per-file rollback and partial-failure exit code 5
  - default operation makes no network calls

3. Audit CI gating.

- inspect `.github/workflows/ci.yml` job and workflow names
- inspect the expected required status check name in repo settings if access is
  available
- if the names differ, align whichever layer is practical:
  - workflow/job naming in repo
  - branch-protection documentation
- if repo settings cannot be changed with available permissions, document the
  exact mismatch and treat release publication as blocked until resolved

4. Run a focused release smoke pass.

Suggested commands:

```bash
cargo run -- scan --path tests/fixtures
cargo run -- audit
cargo run -- drift
cargo run -- rotate-info <fixture-group> --json
```

Notes:

- prefer non-interactive commands in this stream
- only add more smoke coverage if a release claim depends on it

5. Patch only release blockers.

Release blockers include:

- incorrect release docs
- failing verification
- misleading workflow/check naming
- small test instability that makes release verification unreliable

Do not expand scope into new features.

6. Commit in focused chunks.

- commit A: release docs (`CHANGELOG.md`, `docs/releases/v0.2.0.md`)
- commit B: CI/check alignment or other small hardening fixes
- commit C: handoff updates if they do not fit cleanly into A/B

7. Stop before push/tag/release unless explicitly requested.

This stream prepares the release candidate. Tagging and publishing `v0.2.0`
still require an explicit user request.

## Acceptance Checklist

- [ ] `cargo build` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo test` passes across all targets
- [ ] release notes match shipped v0.2 behavior
- [ ] known limitations are stated plainly
- [ ] CI required-check naming is aligned or the blocker is documented
- [ ] branch is ready for explicit release approval

## Failure Handling

- verification fails:
  - fix the smallest blocking issue first
  - rerun the full verification set
- required-check mismatch cannot be fixed with current permissions:
  - document the exact expected check name and blocker
  - do not tag or publish
- release notes conflict with spec/ADR behavior:
  - fix docs before treating the branch as release-ready

## Evidence to Return

- commit hashes
- exact verification command outcomes
- CI/check-name status and any blocker details
- whether the branch is ready for explicit `v0.2.0` tag/publish approval
