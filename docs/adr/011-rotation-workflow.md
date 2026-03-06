# ADR-011: Rotation Workflow

## Status

Accepted

## Context

Hagrid tracks secret references but cannot rotate them. Users need a way to
replace a secret value across all files in a group, with safety guarantees:
atomic writes, verification, and clear partial-failure reporting.

## Decision

### Format-Aware Replacement

Replacement dispatches by `LocationKind`:

- **EnvVar / ShellExport**: line-targeted `replacen()` with discriminator
  validation. Preserves surrounding quotes.
- **JsonPath**: parse full file as `serde_json::Value`, navigate via
  `pointer_mut()` (RFC 6901 discriminator), verify old value, mutate,
  `to_string_pretty()`. Formatting may change; no data loss (JSON has no
  comments).
- **TomlKey**: parse as `toml::Value`, navigate dotted path (e.g.,
  `database.password`), verify, mutate, `to_string_pretty()`. Comments are
  lost (TOML crate limitation). Acceptable for rotation; future improvement
  via `toml_edit`.
- **RawLine**: line-targeted `replacen()` without discriminator validation.

### Per-File Transaction

Members are grouped by `file_path`. For each file: read once, extract all
old values, apply all replacements to one in-memory buffer, single atomic
write, verify all members, then persist the new fingerprints in one database
transaction. If any member preflight fails, the file is not written. If
post-write verification or DB persistence fails, the original file content is
restored before moving on. This prevents self-interference when multiple group
members share a file and avoids leaving partially-rotated files behind.

### Cross-File Failure Behavior

Continue-and-report: if rotation fails for one file, continue to remaining
files. Report all results. Rationale: stopping on first failure leaves users
without visibility into which files could have been rotated.

### Exit Codes

- 0: all targeted present members succeeded
- 1: fatal error OR all targeted members failed
- 5: partial failure (>= 1 succeeded AND >= 1 failed)

Precedence: 1 > 5 > 0.

### Identity Matching

`find_current_value()` iterates ALL findings from a re-scan, computing
`compute_identity()` for each and comparing to the member's stored
`identity_key`. This is LocationKind-agnostic -- it does not depend on
RawLine.

### Stale Reference Detection

If no identity match is found for a RawLine member, the system checks
whether the stored fingerprint matches any finding in the file. If so, it
returns `StaleLineReference` with guidance to run `hagrid scan`.

### Mixed LocationKind Guard

If a file contains both RawLine and structural members, rotation hard-fails
with `MixedLocationKinds` error and guidance to run `hagrid scan` to
consolidate references.

### Secure Value Handling

New secret value is read via `rpassword` (no terminal echo) and wrapped in
`Zeroizing<String>`. The value is never logged or printed.

## Consequences

- Users can rotate secrets across all group members in one command.
- Atomic writes (tmp + rename) prevent partial file corruption.
- Failed same-file verification or DB persistence rolls the file back to its
  original content before reporting failure.
- Backup collision handling uses timestamped `.bak.<YYYYMMDDHHMMSS>`.
- JSON/TOML formatting may change on rotation (acceptable trade-off for
  correctness over cosmetics).
- TOML comments are lost on rotation (known limitation).
