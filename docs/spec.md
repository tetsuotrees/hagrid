# Hagrid Technical Specification

Version: v6 -- v0.2 released, v0.3 TUI foundation shipped

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
    hagrid watch
    hagrid rotate-info <group-label> [--json]
    hagrid rotate <group-label> [--backup]

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

### Watch Mode

The `hagrid watch` command starts a persistent daemon that monitors configured
scan roots for file changes using OS-level filesystem events (`notify` crate).
On detected Create/Modify events:

1. Events are debounced (500ms window) to coalesce rapid writes.
2. Each changed file is scanned at Standard depth via `scan_single_file()`.
3. Findings are upserted into the database (upsert-only -- no `mark_unseen_as_removed`).
4. Progress is reported to stderr.

Watch mode applies the same exclusion filters as full scan (binary files,
excluded dirs, hard-excluded paths, max file size). Deleted files are ignored
(not treated as removal events).

### Rotation Workflow

The `hagrid rotate-info <group-label>` command displays the current state of
a secret group: member files, locations, fingerprints, and drift status.

The `hagrid rotate <group-label>` command interactively rotates a secret value
across all present members of a group:

1. Displays group info and files to be modified.
2. Prompts for new secret value via `rpassword` (no terminal echo).
3. Confirms value (enter twice).
4. Previews files and asks for confirmation.
5. Executes rotation with format-aware replacement:
   - JSON: path-aware via `serde_json::Value::pointer_mut()`
   - TOML: path-aware via dotted-path navigation
   - EnvVar/ShellExport: line-targeted with discriminator validation
   - RawLine: line-targeted `replacen()`
6. Members are grouped by file_path for per-file transactions. A file is
   written at most once per rotation attempt, and same-file preflight failures
   abort the entire file.
7. Each file is verified via re-scan after write. Verification or index-update
   failure restores the original file content before continuing.
8. Cross-file failures continue to next file (continue-and-report).

Exit code 5 indicates partial failure (>= 1 succeeded AND >= 1 failed).

### Notifications

Hagrid supports explicit-opt-in webhook notifications for high-signal command
outcomes. Configuration lives in `~/.hagrid/notifications.toml`:

```toml
enabled = true
timeout_ms = 2000

[[webhook]]
name = "local-dev"
url = "http://127.0.0.1:8787/hagrid"
events = ["drift_detected", "policy_violations", "rotation_failure"]
```

Behavior:
- Missing file or `enabled = false` → no-op (zero network calls)
- Malformed file → warning to stderr, no-op (never alters exit codes)
- Empty `events` list on a webhook → subscribe to all event kinds
- Delivery failures → warning to stderr, no effect on command exit code
- Payloads contain metadata only (group labels, counts, file paths) — no
  secret values, identity keys, or member fingerprints

Emitters:
- `hagrid drift` → `drift_detected` when drift is found (exit code 3)
- `hagrid audit` → `policy_violations` when violations are found (exit code 4)
- `hagrid rotate` → `rotation_failure` on partial (exit code 5) or full failure (exit code 1)

## TUI (v0.3)

    hagrid tui

### Terminal UI

The `hagrid tui` command launches an interactive terminal interface for browsing
Hagrid's inventory. Built with `ratatui` + `crossterm`.

Layout:
- **Header** -- summary counts (refs, groups, ungrouped, pending suggestions, drift)
- **Groups section** -- list of confirmed groups with status and member count
- **Ungrouped section** -- list of ungrouped present references with display ID,
  file path, discriminator, and provider
- **Detail pane** -- expanded view of the selected group or reference
- **Footer** -- context-sensitive keybinding hints

Keybindings:
- `j` / `Down` -- move selection down
- `k` / `Up` -- move selection up
- `Tab` -- switch between Groups and Ungrouped sections
- `Enter` -- open detail view for selected item
- `Backspace` / `Esc` (in detail) -- return to list view
- `r` -- refresh data from database
- `q` / `Esc` (in list) / `Ctrl-c` -- quit

Constraints:
- Read-only -- no mutation flows (group, ungroup, rotate, etc.)
- Metadata only -- never displays secret values; fingerprints are truncated
- Local only -- no network calls
- Data is loaded directly from the database via library code (no subprocess shelling)

### D-1 Dedup Refinement

In Standard depth, the scan engine now applies a second dedup pass that removes
RawLine findings when a structurally-richer finding (EnvVar, JsonPath, TomlKey,
ShellExport) exists for the same `(file_path, secret_value)`. This prevents
dual-reference behavior where both the pattern matcher and structural parser
report the same secret.

## Exit Codes

- 0 -- success
- 1 -- fatal runtime error (DB locked, Keychain unavailable, etc.)
- 2 -- usage error (invalid flags, unknown command)
- 3 -- drift detected (`hagrid drift`)
- 4 -- policy violation (`hagrid audit`, v0.2)
- 5 -- partial rotation failure (`hagrid rotate`, v0.2)

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
- ADR-010: Watch mode (debounced events, upsert-only, scan_single_file)
- ADR-011: Rotation workflow (format-aware replacement, per-file transactions)
- ADR-012: Notifications (opt-in webhooks, failure isolation, payload safety)

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
- [docs/runbooks/03-watch-mode.md](runbooks/03-watch-mode.md): watch mode execution runbook
- [docs/handoffs/dev-agent-03-watch.md](handoffs/dev-agent-03-watch.md): watch mode handoff packet
- [docs/runbooks/04-rotation.md](runbooks/04-rotation.md): rotation workflow execution runbook
- [docs/handoffs/dev-agent-04-rotation.md](handoffs/dev-agent-04-rotation.md): rotation workflow handoff packet
- [docs/runbooks/05-notifications.md](runbooks/05-notifications.md): notifications execution runbook
- [docs/handoffs/dev-agent-05-notifications.md](handoffs/dev-agent-05-notifications.md): notifications handoff packet
- [docs/runbooks/06-release-hardening.md](runbooks/06-release-hardening.md): v0.2 release-hardening runbook
- [docs/handoffs/dev-agent-06-release-hardening.md](handoffs/dev-agent-06-release-hardening.md): v0.2 release-hardening handoff
- [docs/runbooks/07-tui-foundation.md](runbooks/07-tui-foundation.md): TUI foundation execution runbook
- [docs/handoffs/dev-agent-07-tui-foundation.md](handoffs/dev-agent-07-tui-foundation.md): TUI foundation handoff packet
