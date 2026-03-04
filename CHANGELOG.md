# Changelog

All notable changes to this project should be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

## [0.1.0] - 2026-03-04

### Added

- initial Hagrid CLI implementation (`init`, `scan`, `status`, `list`, `show`, `suggest`, `group`, `ungroup`, `drift`, `forget`, `export`)
- deterministic reference identity and keyed HMAC fingerprinting
- SQLCipher-backed encrypted index with Keychain-backed master secret and HKDF key hierarchy
- scanning pipeline with pattern matching, entropy checks, and structural parsers (`json`, `toml`, `.env`, shell)
- suggestion engine (exact-fingerprint and heuristic suggestions) with deduplication
- group management and drift detection with degraded/empty handling
- documentation set: threat model, spec summary, ADR set, execution planning docs

