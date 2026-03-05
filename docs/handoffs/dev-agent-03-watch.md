# Dev-Agent Handoff: WS-6 Watch Mode

## What Was Built

### D-1 Dedup Refinement (`src/scan/engine.rs`)

- Added `scan_single_file()` public API: wraps `scan_file_inner()` + `dedup_findings()`.
- Extended `dedup_findings()` with a second pass that drops RawLine findings
  when a structurally-richer finding exists for the same `(file_path, secret_value)`.
- Renamed internal `scan_file()` to `scan_file_inner()` (private).

### Watch Engine (`src/watch/mod.rs`)

- `process_file_change()`: testable core.
  - Applies walker filters (binary, excluded dir, hard-excluded, max size).
  - Scans at Standard depth via `scan_single_file()`.
  - Upserts findings; no removal marking.
  - Returns `FileChangeResult` with counts and errors.
- `run_watch()`: blocking event loop.
  - Uses `notify::RecommendedWatcher` on all existing scan roots.
  - 500ms debounce via mpsc channel + `recv_timeout`.
  - Only processes Create/Modify events (upsert-only).
  - Reports to stderr.

### CLI Handler (`src/cli/watch.rs`)

- `pub fn run() -> i32`: opens DB, loads config, delegates to `run_watch()`.

### Walker Changes (`src/scan/walker.rs`)

- `should_include_file()`, `is_in_excluded_dir()`, `is_likely_binary()` made `pub`.

### Wiring

- `src/main.rs`: `mod watch`, `Commands::Watch`, match arm.
- `src/lib.rs`: `pub mod watch`.
- `src/cli/mod.rs`: `pub mod watch`.

## Dependencies Added

- `notify = "6"` in Cargo.toml.

## Test Inventory (13 new tests)

All in `tests/watch_tests.rs`:

| Test | Category |
|------|----------|
| `test_watch_detects_new_file` | File change detection |
| `test_watch_idempotent_events` | Idempotent repeated events |
| `test_watch_deleted_file_noop` | Deleted file handling |
| `test_watch_binary_file_skipped` | Filter: binary |
| `test_watch_excluded_dir_skipped` | Filter: excluded dir |
| `test_watch_permission_denied_handled` | Permission denied |
| `test_watch_upsert_only_no_removal` | Upsert-only DB writes |
| `test_d1_dedup_standard_coalesces_rawline_and_structural` | D-1 regression |
| `test_d1_dedup_lite_unaffected` | D-1 regression (Lite) |
| `test_d1_standard_lte_lite_or_equal_after_dedup` | D-1 relationship |
| `test_watch_scan_single_file_consistent_with_full_scan` | API consistency |
| `test_watch_symlink_loop_handled` | Symlink safety |

## Acceptance Criteria

- [x] `cargo build` succeeds
- [x] `cargo clippy --all-targets -- -D warnings` clean
- [x] All 149 tests pass (136 existing + 13 new)
- [x] D-1: Standard depth produces 1 finding per secret in structured files (not 2)
- [x] Watch mode: upsert-only, no removal marking
- [x] Watch mode: debounced events (500ms)
- [x] Watch mode: binary/excluded/hard-excluded files filtered
- [x] Watch mode: symlink loops handled without hang or panic

## Known Limitations

- Watch mode does not remove references for deleted files. Run `hagrid scan` to
  reconcile removals.
- The `run_watch()` event loop is not directly testable (it blocks). Integration
  tests exercise `process_file_change()` directly.
- `notify` v6 is used (not v8) for stability. Upgrade to v8 can be done in a
  future workstream.
