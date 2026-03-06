# Runbook 04: Rotation Workflow (WS-7)

## Scope

Implement `hagrid rotate-info` and `hagrid rotate` commands for interactive
secret rotation across group members, with format-aware replacement, atomic
writes, and verification.

## Prerequisites

- WS-6 (watch mode) merged and CI green.
- `rpassword = "5"` added to Cargo.toml.

## Implementation Steps

### 1. Rotation Engine (`src/rotate/mod.rs`)

Core types and functions:

- `MemberInfo`: per-member state (identity_key, file_path, location, fingerprint)
- `RotateInfoReport` / `RotateInfoMember`: serializable report types
- `FileRotateResult` / `RotateResult`: per-file and aggregate result types
- `RotateError`: thiserror enum (GroupNotFound, NoMembers, FingerprintMismatch, etc.)
- `gather_rotate_info()`: load group + members from DB
- `build_info_report()`: compute unique fingerprints, drift flag
- `find_current_value()`: re-scan file, match by identity_key across all LocationKinds
- `replace_in_file()`: dispatch to format-specific replacement
- `replace_json_path_aware()`: JSON parse/mutate/serialize via pointer_mut()
- `replace_toml_path_aware()`: TOML parse/navigate dotted path/mutate/serialize
- `replace_line_targeted()`: EnvVar/ShellExport/RawLine line-number replacement
- `atomic_write()`: .hagrid-tmp + rename, timestamped backup collision handling
- `verify_rotation()`: re-scan and fingerprint verification
- `execute_rotation()`: per-file transaction grouping, rollback-on-failure,
  continue-and-report

### 2. CLI Handlers

`src/cli/rotate_info.rs`:
- `pub fn run(group_label, json) -> i32`
- Human-readable or JSON output

`src/cli/rotate.rs`:
- `pub fn run(group_label, backup) -> i32`
- Interactive flow: display info → prompt new value → confirm → rotate → report

### 3. Wiring

- `src/main.rs`: Commands::RotateInfo, Commands::Rotate, match arms
- `src/lib.rs`: `pub mod rotate`
- `src/cli/mod.rs`: `pub mod rotate; pub mod rotate_info;`

### 4. Model Change

- `LocationKind` derives `Hash` (needed for mixed-kind detection)
- `db::get_group_members()` made `pub`

## Verification

```bash
cargo build
cargo clippy --all-targets -- -D warnings
cargo test
```

All local validation commands pass.

## Test Coverage

| Test | What It Verifies |
|------|-----------------|
| `test_gather_info_valid_group` | Loads group + members correctly |
| `test_gather_info_nonexistent_group` | Returns GroupNotFound |
| `test_build_info_report` | Report shows correct drift/synced status |
| `test_find_current_value_env` | Extracts from .env by identity match |
| `test_find_current_value_json` | Extracts from .json by identity match |
| `test_find_current_value_stale_fingerprint` | FingerprintMismatch when file changed |
| `test_replace_env_preserves_quotes` | `KEY="old"` -> `KEY="new"` |
| `test_replace_env_unquoted` | `KEY=old` -> `KEY=new` |
| `test_replace_shell_export` | `export KEY="old"` -> `export KEY="new"` |
| `test_replace_json_path_aware` | Parse -> pointer_mut -> mutate -> serialize |
| `test_replace_json_nested_path` | `/nested/token` path navigation works |
| `test_replace_toml_path_aware` | Parse -> dotted path -> mutate -> serialize |
| `test_replace_toml_nested` | `database.password` path navigation |
| `test_replace_discriminator_mismatch` | Hard-fail when discriminator wrong |
| `test_replace_value_not_found` | Error when value gone |
| `test_atomic_write_creates_file` | Temp+rename, content correct |
| `test_atomic_write_preserves_permissions` | Mode preserved (unix) |
| `test_atomic_write_with_backup` | .bak created |
| `test_atomic_write_backup_collision` | Timestamped .bak when collision |
| `test_verify_rotation_success` | Re-scan confirms correct fingerprint |
| `test_execute_full_flow` | End-to-end single file rotation |
| `test_execute_multi_member_same_file` | Two members in same file rotate successfully together |
| `test_execute_same_file_extraction_failure_aborts_entire_file` | Same-file preflight failure leaves file untouched |
| `test_execute_undetectable_value_rolls_back_file` | Verification failure restores original file |
| `test_execute_partial_failure_continues` | One file can fail preflight while another still rotates |
| `test_exit_code_all_succeed` | Exit 0 when all pass |
| `test_exit_code_partial_failure` | Exit 5 when partial |
| `test_exit_code_all_fail_returns_1` | Exit 1 when all fail |
| `test_replace_json_two_paths_same_old_value` | Same old value at different JSON paths |
| `test_replace_toml_two_paths_same_old_value` | Same old value at different TOML paths |
| `test_mixed_location_kinds_rejected` | RawLine + structural in same file rejected |
