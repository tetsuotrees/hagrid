# Changelog

All notable changes to this project should be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

### Added

- `hagrid audit [--json]` command for policy-based secret evaluation
- policy engine with configurable rules (`~/.hagrid/policies.toml`)
  - `max_references`: limit secret sprawl (dedupes by file_path + fingerprint)
  - `no_git`: detect secrets in git-tracked files
  - `max_age_days` / `warn_at_days`: staleness thresholds with warning tier
  - `require_vault`: stub (returns warning, implementation deferred)
- glob-based pattern matching on `provider_pattern` (`*` matches all refs)
- exit code 4 for policy violations
- ADR-009: Policy engine design decisions

### Changed

- extracted `resolve_target()` into `cli/mod.rs` for shared show/forget disambiguation
- `show` and `forget` handlers expose `run_with_conn()` for deterministic CI testing

## [0.1.0] - 2026-03-04

### Added

- initial Hagrid CLI implementation (`init`, `scan`, `status`, `list`, `show`, `suggest`, `group`, `ungroup`, `drift`, `forget`, `export`)
- deterministic reference identity and keyed HMAC fingerprinting
- SQLCipher-backed encrypted index with Keychain-backed master secret and HKDF key hierarchy
- scanning pipeline with pattern matching, entropy checks, and structural parsers (`json`, `toml`, `.env`, shell)
- suggestion engine (exact-fingerprint and heuristic suggestions) with deduplication
- group management and drift detection with degraded/empty handling
- documentation set: threat model, spec summary, ADR set, execution planning docs

