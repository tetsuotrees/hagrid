# Hagrid Technical Specification

Version: v4 (final) -- v0.1 implementation

## Overview

Hagrid ("Keeper of Keys") is a local-first, Rust CLI + TUI for secret lifecycle
management on a single machine. It uses an **index/observer model** -- it never
stores secret values, only keyed HMAC fingerprints and metadata.

**Platform:** macOS-only for v0.1. Linux Keyring support tracked for v0.4+.

## Key Hierarchy

A single master secret (32 random bytes) is stored in macOS Keychain
(service: `hagrid`, account: `master-secret`). All other keys are derived via
HKDF-SHA256:

- `identity_key`    = HKDF(master, info="hagrid-identity-v1")
- `fingerprint_key` = HKDF(master, info="hagrid-fingerprint-v1")
- `db_key`          = HKDF(master, info="hagrid-db-v1")

## Core Data Model

- **SecretReference** -- a single discovered secret location (file + discriminator).
  Identity is deterministic: HMAC-SHA256(identity_key, path|kind|discriminator|source).
- **Suggestion** -- auto-detected potential grouping (exact fingerprint, structural,
  or provider match). Has confidence score and status (Pending/Accepted/Rejected).
- **SecretGroup** -- user-confirmed group of related references. Participates in
  drift detection.
- **DriftEvent** -- recorded when group members have divergent fingerprints.

## Scan Depths

- **Lite** -- regex pattern matching only, fingerprint extraction.
- **Standard** (default) -- Lite + structural parsing (JSON, TOML, .env, shell rc)
  + heuristic grouping suggestions + entropy analysis.
- **Deep** (v0.3+) -- Standard + LLM/agent integration hooks. Requires opt-in.

## CLI Commands (v0.1)

    hagrid init
    hagrid scan [--depth lite|standard] [--path <path>] [--json]
    hagrid status [--json]
    hagrid list [--ungrouped] [--json]
    hagrid show <group-label|ref-id> [--json]
    hagrid suggest [--review] [--json]
    hagrid group <label> <ref-id>...
    hagrid ungroup <ref-id>
    hagrid drift [--json]
    hagrid forget <ref-id|group-label>
    hagrid export [--format json|csv]

## Exit Codes

- 0 -- success
- 1 -- fatal runtime error (DB locked, Keychain unavailable, etc.)
- 2 -- usage error (invalid flags, unknown command)
- 3 -- drift detected (`hagrid drift`)
- 4 -- policy violation (`hagrid audit`, v0.2)

## Security Invariants

1. No secret values in the index -- only keyed HMAC fingerprints.
2. No network calls by default -- MCP/webhooks require explicit opt-in.
3. Minimal memory exposure -- zeroize crate for transiting values.
4. Encrypted database -- SQLCipher with HKDF-derived key.

## Architectural Decisions

See `docs/adr/` for detailed records:

- ADR-001: Fingerprint format (keyed HMAC-SHA256)
- ADR-002: Reference identity (deterministic with location discriminator)
- ADR-003: Key hierarchy (master secret + HKDF derivation)
- ADR-004: DB encryption (SQLCipher)
- ADR-005: Grouping flow (suggestion queue -> confirmed groups)
- ADR-006: DB constraints (unique keys, label rules, deduplication)
- ADR-007: MCP naming (hagrid_* namespace, v0.3)
- ADR-008: Platform scope (macOS-only v0.1)

## Milestone Plan

- **v0.1** -- Scan + Suggest + Group + Drift (current)
- **v0.2** -- Policy + Watch + Rotate + Notifications
- **v0.3** -- TUI + MCP server
- **v0.4+** -- Provider-aware rotation, Linux support, plugins
