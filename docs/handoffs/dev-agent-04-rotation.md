# Dev-Agent Handoff: WS-7 Rotation Workflow

## What Was Built

### Rotation Engine (`src/rotate/mod.rs`)

- `gather_rotate_info()`: loads group + members from DB by group label
- `build_info_report()`: serializable report with drift detection
- `find_current_value()`: re-scans file, matches by computed identity_key
  across ALL LocationKinds (not just RawLine). Handles stale RawLine
  references and fingerprint mismatches.
- `replace_in_file()`: format-aware replacement dispatching by LocationKind:
  - **JSON**: `serde_json::Value::pointer_mut()` for path-aware mutation
  - **TOML**: dotted-path navigation for path-aware mutation
  - **EnvVar/ShellExport/RawLine**: line-targeted `replacen()` with
    discriminator validation
- `execute_rotation()`: per-file transaction model. Groups members by
  file_path, reads once, applies all replacements, single atomic write,
  verifies all members, and persists the new fingerprints in one DB
  transaction. Same-file preflight failures abort the file before write;
  verification or DB persistence failures restore the original file before
  continuing to the next file.
- `atomic_write()`: `.hagrid-tmp` + `fs::rename`, preserves permissions.
  Timestamped `.bak.<YYYYMMDDHHMMSS>` on backup collision.
- `verify_rotation()`: re-scans file and verifies fingerprint matches
  expected new value.

### CLI Handlers

- `src/cli/rotate_info.rs`: `hagrid rotate-info <group-label> [--json]`
  - Human output: group label, status, member table with fingerprint prefixes
  - JSON output: serialized RotateInfoReport
- `src/cli/rotate.rs`: `hagrid rotate <group-label> [--backup]`
  - Interactive flow: display group info, prompt new value via rpassword
    (no echo), confirm match, preview files, confirm rotation, execute,
    display results
  - Uses `Zeroizing<String>` for in-memory secret handling
  - Exit codes: 0 (all ok), 5 (partial), 1 (all fail/fatal)

### Model Changes

- `LocationKind` derives `Hash` (needed for HashSet in mixed-kind detection)
- `db::get_group_members()` made `pub` (was private, needed by rotate module)

### Wiring

- `src/main.rs`: `mod rotate`, `Commands::RotateInfo`, `Commands::Rotate`, match arms
- `src/lib.rs`: `pub mod rotate`
- `src/cli/mod.rs`: `pub mod rotate; pub mod rotate_info;`

## Dependencies Added

- `rpassword = "5"` in Cargo.toml

## Test Inventory

All in `tests/rotate_tests.rs`:

| Test | Category |
|------|----------|
| `test_gather_info_valid_group` | Info gathering |
| `test_gather_info_nonexistent_group` | Error handling |
| `test_build_info_report` | Report building |
| `test_find_current_value_env` | Value extraction (EnvVar) |
| `test_find_current_value_json` | Value extraction (JSON) |
| `test_find_current_value_stale_fingerprint` | Stale detection |
| `test_replace_env_preserves_quotes` | EnvVar replacement |
| `test_replace_env_unquoted` | EnvVar replacement |
| `test_replace_shell_export` | ShellExport replacement |
| `test_replace_json_path_aware` | JSON path-aware replacement |
| `test_replace_json_nested_path` | JSON nested path |
| `test_replace_toml_path_aware` | TOML path-aware replacement |
| `test_replace_toml_nested` | TOML nested path |
| `test_replace_discriminator_mismatch` | Error: wrong discriminator |
| `test_replace_value_not_found` | Error: value gone |
| `test_atomic_write_creates_file` | Atomic write mechanics |
| `test_atomic_write_preserves_permissions` | Permission preservation |
| `test_atomic_write_with_backup` | Backup creation |
| `test_atomic_write_backup_collision` | Timestamped backup |
| `test_verify_rotation_success` | Post-write verification |
| `test_execute_full_flow` | End-to-end single file |
| `test_execute_multi_member_same_file` | Per-file transaction |
| `test_execute_same_file_extraction_failure_aborts_entire_file` | Same-file rollback guard |
| `test_execute_undetectable_value_rolls_back_file` | Verification rollback guard |
| `test_execute_partial_failure_continues` | Cross-file failure |
| `test_exit_code_all_succeed` | Exit code 0 |
| `test_exit_code_partial_failure` | Exit code 5 |
| `test_exit_code_all_fail_returns_1` | Exit code 1 |
| `test_replace_json_two_paths_same_old_value` | JSON multi-path regression |
| `test_replace_toml_two_paths_same_old_value` | TOML multi-path regression |
| `test_mixed_location_kinds_rejected` | Mixed kind guard |

## Acceptance Criteria

- [x] `cargo build` succeeds
- [x] `cargo clippy --all-targets -- -D warnings` clean
- [x] `cargo test` passes locally
- [x] Format-aware replacement: JSON via pointer_mut, TOML via dotted path
- [x] Per-file transaction: same-file preflight failure aborts the whole file
- [x] Verification/index persistence failure restores original file content
- [x] Cross-file failure: continue-and-report, exit 5 for partial
- [x] Exit code precedence: 1 > 5 > 0
- [x] Stale RawLine detection with guidance
- [x] Mixed LocationKind guard
- [x] Backup collision handling (timestamped)
- [x] Zeroizing<String> for new secret value
- [x] No secret values in logs or output

## Known Limitations

- TOML comments are lost during rotation (limitation of `toml` crate's
  serializer). Future improvement: switch to `toml_edit` for comment
  preservation.
- JSON formatting may change slightly after rotation (pretty-printed via
  `serde_json`).
- `hagrid rotate` requires stdin (interactive). Non-interactive rotation
  (e.g., piped input) is not yet supported.
- Stale RawLine detection only works when the fingerprint is still present
  in the file (line shifted but value unchanged).
