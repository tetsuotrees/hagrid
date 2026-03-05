# Runbook 03: Watch Mode (WS-6)

## Scope

Implement `hagrid watch` daemon mode with debounced file events, scoped
re-scan triggers, and safe DB write behavior. Also implement D-1 dedup
refinement for Standard depth.

## Prerequisites

- WS-5 (policy engine) merged and CI green.
- `notify = "6"` added to Cargo.toml.

## Implementation Steps

### 1. D-1 Dedup Fix (`src/scan/engine.rs`)

Add second pass to `dedup_findings()`:
- Build a set of `(file_path, secret_value)` keys from non-RawLine findings.
- Drop RawLine findings whose key appears in the structural set.
- Preserves existing pass-1 dedup (exact discriminator match).

### 2. Public Scanner API (`src/scan/engine.rs`)

Extract `scan_single_file()` as public wrapper:
- Calls internal `scan_file_inner()` + `dedup_findings()`.
- Used by watch module for per-file re-scans.

### 3. Walker Functions (`src/scan/walker.rs`)

Make `should_include_file()`, `is_in_excluded_dir()`, `is_likely_binary()` pub
so the watch module can apply the same filters.

### 4. Watch Engine (`src/watch/mod.rs`)

- `process_file_change()`: testable core function.
  - Checks file existence, applies walker filters.
  - Calls `scan_single_file()` at Standard depth.
  - Upserts findings (no `mark_unseen_as_removed`).
- `run_watch()`: event loop.
  - Creates `notify::RecommendedWatcher` on scan roots.
  - Receives Create/Modify events via mpsc channel.
  - Debounces with 500ms timer.
  - Calls `process_file_change()` for each pending file.

### 5. CLI Handler (`src/cli/watch.rs`)

- `pub fn run() -> i32`: opens DB, loads config, calls `run_watch()`.

### 6. Wiring

- `src/main.rs`: add `mod watch`, `Commands::Watch`, match arm.
- `src/lib.rs`: add `pub mod watch`.
- `src/cli/mod.rs`: add `pub mod watch`.

## Verification

```bash
cargo build
cargo clippy --all-targets -- -D warnings
cargo test
```

All existing tests must pass. New tests: ~13 (watch + D-1 dedup).

## Test Coverage

| Test | What It Verifies |
|------|-----------------|
| `test_watch_detects_new_file` | File with secret produces findings + DB upsert |
| `test_watch_idempotent_events` | Same file processed twice gives same results |
| `test_watch_deleted_file_noop` | Non-existent file is a no-op |
| `test_watch_binary_file_skipped` | Binary extensions are filtered |
| `test_watch_excluded_dir_skipped` | node_modules etc. are excluded |
| `test_watch_permission_denied_handled` | Unreadable files don't panic |
| `test_watch_upsert_only_no_removal` | Processing file B doesn't remove file A's refs |
| `test_d1_dedup_standard_coalesces_*` | Standard coalesces RawLine + structural |
| `test_d1_dedup_lite_unaffected` | Lite mode unchanged |
| `test_d1_standard_lte_lite_*` | Standard/Lite relationship verified |
| `test_watch_scan_single_file_*` | scan_single_file matches full scan |
| `test_watch_symlink_loop_handled` | Symlink loops don't hang or panic |
