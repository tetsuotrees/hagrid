# ADR-010: Watch Mode

## Status

Accepted

## Context

After v0.1 shipped the batch `hagrid scan` command, dogfooding revealed that
secrets change between manual scans and drift goes undetected until the next
explicit run. A persistent watch mode closes this feedback loop.

Additionally, dogfooding identified the D-1 issue: in Standard depth, each
secret in a structured file produces two findings (one RawLine from pattern
matching, one structural from parsing), leading to duplicate references.

## Decisions

### Watch architecture

- **notify crate (v6)** for cross-platform filesystem event delivery.
- **Debounced event processing** with a 500ms window to coalesce rapid writes
  (editors often write temp files, rename, then delete).
- **Upsert-only DB writes** -- watch mode never calls `mark_unseen_as_removed`.
  This prevents flapping when files are temporarily locked or being rewritten.
  Full removals remain the responsibility of `hagrid scan`.
- **Standard depth** for all watch re-scans to get structural findings.
- **Same exclusion filters** as the batch scanner (binary, excluded dirs,
  hard-excluded paths, max file size).
- **stderr reporting** for all watch output (stdin/stdout reserved for future
  structured output modes).

### scan_single_file API

Extracted `scan_single_file()` as a public function from the scan engine.
It wraps the internal `scan_file_inner()` + `dedup_findings()` to provide
a clean entry point for per-file scanning. The batch `scan()` function
continues to call `scan_file_inner()` directly (dedup is applied once to
the full batch).

### D-1 dedup refinement

Added a second pass to `dedup_findings()` that drops RawLine findings when
a structurally-richer finding (EnvVar, JsonPath, TomlKey, ShellExport) exists
for the same `(file_path, secret_value)`. The structural finding carries the
key name as its discriminator (e.g., `OPENAI_API_KEY`) which is strictly more
informative than a line number (`line:2`).

### Testability

The core logic lives in `process_file_change()`, a pure function that takes
a file path, DB connection, keys, patterns, and config. The watch event loop
(`run_watch`) is a thin wrapper that feeds events into this function.
Integration tests exercise `process_file_change()` directly.

## Consequences

- Watch mode provides near-real-time secret index updates without manual scans.
- Upsert-only semantics mean `hagrid status` may show stale "Present" refs for
  deleted files until the next `hagrid scan`. This is an intentional trade-off
  to avoid false removals during file rewrites.
- D-1 fix reduces finding count in Standard depth for structured files. The
  `test_scan_lite_vs_standard` assertion (`standard >= lite`) continues to
  hold because unstructured files still produce RawLine-only findings.
