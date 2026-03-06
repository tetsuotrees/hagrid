# Changelog

All notable changes to this project should be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

### Added

- opt-in webhook notifications for high-signal command outcomes (`~/.hagrid/notifications.toml`)
  - `drift_detected` — emitted when `hagrid drift` finds group drift
  - `policy_violations` — emitted when `hagrid audit` finds violations
  - `rotation_failure` — emitted when `hagrid rotate` has partial or full failure
  - typed `EventKind` enum with serde snake_case serialization
  - configurable timeout, per-webhook event filtering, empty events = subscribe to all
  - failure-isolated: config errors and delivery failures log to stderr, never alter exit codes
  - payloads exclude secret values, identity keys, and member fingerprints
- ADR-012: Opt-in webhook notification model and failure isolation
- `hagrid rotate-info <group-label> [--json]` for pre-rotation group inspection
- `hagrid rotate <group-label> [--backup]` for interactive secret rotation across group members
  - format-aware replacement: JSON (path-aware via pointer_mut), TOML (dotted-path), EnvVar/ShellExport (line-targeted with discriminator validation)
  - per-file transaction model: multiple members in same file share single atomic write, and verification/index failures restore the original file
  - cross-file continue-and-report: partial failures produce exit code 5
  - secure value input via `rpassword` with `Zeroizing<String>`
  - atomic writes (.hagrid-tmp + rename) with optional timestamped backup
  - post-write verification via re-scan
- exit code 5 for partial rotation failure
- ADR-011: Rotation workflow design decisions
- `hagrid watch` command for persistent file-change monitoring with debounced re-scan
- `scan_single_file()` public API for per-file scanning (used by watch mode)
- `hagrid audit [--json]` command for policy-based secret evaluation
- policy engine with configurable rules (`~/.hagrid/policies.toml`)
  - `max_references`: limit secret sprawl (dedupes by file_path + fingerprint)
  - `no_git`: detect secrets in git-tracked files
  - `max_age_days` / `warn_at_days`: staleness thresholds with warning tier
  - `require_vault`: stub (returns warning, implementation deferred)
- glob-based pattern matching on `provider_pattern` (`*` matches all refs)
- exit code 4 for policy violations
- ADR-009: Policy engine design decisions
- ADR-010: Watch mode design decisions

### Fixed

- D-1: Standard depth scan now coalesces duplicate RawLine + structural findings for the same secret/location (keeps the structurally-richer finding)

### Changed

- extracted `resolve_target()` into `cli/mod.rs` for shared show/forget disambiguation
- `show` and `forget` handlers expose `run_with_conn()` for deterministic CI testing
- walker filter functions (`should_include_file`, `is_in_excluded_dir`, `is_likely_binary`) made public for reuse by watch module

## [0.1.0] - 2026-03-04

### Added

- initial Hagrid CLI implementation (`init`, `scan`, `status`, `list`, `show`, `suggest`, `group`, `ungroup`, `drift`, `forget`, `export`)
- deterministic reference identity and keyed HMAC fingerprinting
- SQLCipher-backed encrypted index with Keychain-backed master secret and HKDF key hierarchy
- scanning pipeline with pattern matching, entropy checks, and structural parsers (`json`, `toml`, `.env`, shell)
- suggestion engine (exact-fingerprint and heuristic suggestions) with deduplication
- group management and drift detection with degraded/empty handling
- documentation set: threat model, spec summary, ADR set, execution planning docs
