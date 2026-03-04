# Runbook 02: Policy Engine (WS-5)

## Overview

This runbook covers the policy engine implementation added in WS-5. The policy
engine evaluates secret references against configurable rules and reports
violations via `hagrid audit`.

## Build and Verify

```bash
# Full build
cargo build

# Lint check
cargo clippy --all-targets -- -D warnings

# Run all tests (existing + new policy + CLI disambiguation)
cargo test
```

Expected: ~134 test invocations pass (102 existing + 7 CLI disambiguation + 25 policy).

## Key Files

| File | Purpose |
|------|---------|
| `src/policy/mod.rs` | Policy engine: loading, matching, evaluation |
| `src/cli/audit.rs` | CLI handler for `hagrid audit [--json]` |
| `src/cli/mod.rs` | `resolve_target()` extraction + `TargetResolution` enum |
| `src/cli/show.rs` | Refactored to use `resolve_target()` via `run_with_conn()` |
| `src/cli/forget.rs` | Refactored to use `resolve_target()` via `run_with_conn()` |
| `src/config/mod.rs` | Added `policies_path()` |
| `tests/policy_tests.rs` | 25 policy integration tests |
| `tests/cli_disambiguation_tests.rs` | 7 CLI-level disambiguation tests |

## Manual Verification

### 1. Create a test policies file

```bash
mkdir -p ~/.hagrid
cat > ~/.hagrid/policies.toml << 'EOF'
[[policy]]
name = "limit-aws-sprawl"
match = "aws_*"
max_references = 3

[[policy]]
name = "no-secrets-in-git"
match = "*"
no_git = true

[[policy]]
name = "rotation-reminder"
match = "*"
max_age_days = 90
warn_at_days = 60
EOF
```

### 2. Run audit

```bash
# Human-readable output
hagrid audit

# JSON output for CI integration
hagrid audit --json
```

### 3. Verify exit codes

```bash
hagrid audit; echo "Exit: $?"
# Expected: 0 (all pass) or 4 (violations found)
```

## Troubleshooting

- **"No policies defined"**: Ensure `~/.hagrid/policies.toml` exists and
  contains `[[policy]]` entries.
- **`warn_at_days > max_age_days` error**: Fix the policy file so that
  `warn_at_days <= max_age_days`.
- **`git binary not found`**: The `no_git` rule requires `git` to be in PATH.
  Install git or remove `no_git` rules.

## Architecture Notes

- Policy evaluation is read-only; it queries the database but never modifies it.
- The `require_vault` rule is a stub that always returns `Warn`. It will be
  implemented when vault integration is added in a future workstream.
- `resolve_target()` in `cli/mod.rs` is the single disambiguation function
  used by both `show` and `forget`. This closes the WS-4 caveat about
  handler-level testing.
