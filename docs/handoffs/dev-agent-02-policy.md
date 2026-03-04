# Dev-Agent Handoff: WS-5 Policy Engine

## Summary

WS-5 adds a policy engine and `hagrid audit` command. It also closes the WS-4
caveat by extracting `resolve_target()` with full CLI-level disambiguation tests.

## Delivered Artifacts

### Commit A — resolve_target extraction
- `src/cli/mod.rs`: Added `TargetResolution` enum and `resolve_target()` function
- `src/cli/show.rs`: Refactored to `run_with_conn()` using `resolve_target()`
- `src/cli/forget.rs`: Refactored to `run_with_conn()` using `resolve_target()`
- `tests/cli_disambiguation_tests.rs`: 7 tests (5 helper + 2 handler wiring)

### Commit B — Policy engine + audit
- `src/policy/mod.rs`: Full policy engine with 4 rule evaluators
- `src/cli/audit.rs`: CLI handler with human/JSON output and exit codes
- `src/main.rs`: `Commands::Audit` variant + match arm
- `src/lib.rs`: `pub mod policy`
- `src/config/mod.rs`: `policies_path()`
- `tests/policy_tests.rs`: 25 integration tests

### Commit C — Documentation
- `docs/spec.md`: Added audit command and policy engine section
- `CHANGELOG.md`: Unreleased entries for all changes
- `README.md`: Added `hagrid audit` to quickstart
- `docs/adr/009-policy-engine.md`: Architecture decisions
- `docs/adr/README.md`: ADR-009 entry
- `docs/runbooks/02-policy-engine.md`: Build/test/verify steps
- `docs/handoffs/dev-agent-02-policy.md`: This file

## Acceptance Criteria

| # | Criterion | Status |
|---|-----------|--------|
| 1 | `cargo build` succeeds | Pass |
| 2 | `cargo clippy --all-targets -- -D warnings` clean | Pass |
| 3 | `cargo test` — all 134 tests pass | Pass |
| 4 | `hagrid audit` works with no policies file (exit 0) | Pass |
| 5 | `hagrid audit --json` produces valid JSON output | Pass |
| 6 | `max_references` dedupes by `(file_path, fingerprint)` | Tested |
| 7 | `no_git` skips non-repo files, errors on missing git | Tested |
| 8 | `require_vault` returns Warn with stub message | Tested |
| 9 | `*` wildcard matches refs with `provider_pattern=None` | Tested |
| 10 | `warn_at_days > max_age_days` returns InvalidConfig | Tested |
| 11 | Evaluation scoped to `ScanStatus::Present` only | Tested |
| 12 | Exit codes: 4 (violations), 0 (warn/pass), 1 (fatal) | Tested |
| 13 | `resolve_target()` extracted with handler-level tests | Tested |

## Review Feedback Resolution

All 13 items from the WS-5 review feedback table have been addressed:

1. CLI-path disambiguation tests (helper + handler level)
2. `max_references` deduplication by `(file_path, fingerprint)`
3. `no_git` robust handling (non-repo → skip, missing git → error)
4. `require_vault` returns Warn, not Pass
5. Matching on `provider_pattern` only
6. Exit-code precedence tests (3 tests)
7. `*` wildcard matches all refs unconditionally
8. Handler-level tests via `run_with_conn()`
9. Runbook and handoff docs created
10. Evaluation scoped to `ScanStatus::Present`
11. Deterministic git identity in temp repos
12. `run_with_conn()` entrypoints for CI testing
13. `warn_at_days <= max_age_days` validation

## Next Steps

- **WS-6**: Watch mode (file system monitoring for real-time scanning)
- **WS-7**: Rotation tracking and provider-aware age policies
- Future: implement `require_vault` when vault integration lands
