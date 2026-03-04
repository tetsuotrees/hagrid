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

## CLI Commands (v0.2)

    hagrid audit [--json]

### Policy Engine

The `hagrid audit` command evaluates secrets against configurable policy rules
defined in `~/.hagrid/policies.toml`. Each policy rule specifies:

- `name` -- human-readable rule name
- `match` -- glob pattern(s) matched against `provider_pattern` (string or array; `"*"` matches all refs including those with no provider)
- `max_references` -- maximum allowed unique references (deduped by file_path + fingerprint)
- `no_git` -- violation if matched secrets appear in git-tracked files
- `max_age_days` / `warn_at_days` -- staleness thresholds
- `require_vault` -- stub (returns warning, not yet implemented)

Policy evaluation scopes to `ScanStatus::Present` references only. Exit code 4
indicates policy violations; warnings-only or all-pass returns 0.

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
- ADR-009: Policy engine (glob matching, evaluation scope, exit codes)

## Milestone Plan

- **v0.1** -- Scan + Suggest + Group + Drift (current)
- **v0.2** -- Policy + Watch + Rotate + Notifications
- **v0.3** -- TUI + MCP server
- **v0.4+** -- Provider-aware rotation, Linux support, plugins

## Execution References

Execution is coordinated through these documents:

- [../README.md](../README.md): high-level product and usage context
- [docs/README.md](README.md): documentation map and agent coordination contract
- [docs/plan/post-v0.1-execution-plan.md](plan/post-v0.1-execution-plan.md): cross-workstream sequencing and acceptance criteria
- [docs/runbooks/01-release-and-ci-bootstrap.md](runbooks/01-release-and-ci-bootstrap.md): first workstream procedure
- [docs/handoffs/dev-agent-01-release-and-ci.md](handoffs/dev-agent-01-release-and-ci.md): first workstream execution packet for the dev agent
- [docs/runbooks/02-policy-engine.md](runbooks/02-policy-engine.md): policy engine execution runbook
- [docs/handoffs/dev-agent-02-policy.md](handoffs/dev-agent-02-policy.md): policy engine handoff packet
