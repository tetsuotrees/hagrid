# ADR-009: Policy Engine

**Status:** Accepted
**Date:** 2026-03-04

## Context

Hagrid v0.1 indexes and groups secret references but provides no mechanism
for enforcing organizational or personal hygiene rules (e.g., "no more than
3 copies of an AWS key," "no secrets in git-tracked files"). Users need a
declarative way to define and evaluate policies against their secret index.

## Decision

### Separate policy file

Policies are defined in `~/.hagrid/policies.toml`, separate from the main
`config.toml`. This keeps scan configuration and policy rules decoupled and
allows policies to be version-controlled independently.

### Glob matching on `provider_pattern` only

Policy `match` patterns use glob syntax (`*`, `?`) and are evaluated against
the `provider_pattern` field of each `SecretReference`. We do not match
against `display_label` or other fields to keep semantics clear and
predictable. The `provider_pattern` is set by the scan engine based on
detected secret type (e.g., `openai_api_key`, `aws_secret_access_key`).

### Wildcard `*` matches all refs unconditionally

When `match = "*"` is specified, the rule applies to all references including
those with `provider_pattern = None`. This is a special case; non-wildcard
patterns require a non-null `provider_pattern` to match.

### Evaluation scoped to `ScanStatus::Present` refs

Policy evaluation filters to `Present` references only. `Removed` and `Error`
references are excluded. This prevents stale or disappeared secrets from
triggering policy violations.

### `max_references` deduplicates by `(file_path, fingerprint)`

The same secret value appearing at the same file path (but with different
discriminators, e.g., two JSON keys pointing to the same value) counts as
one reference for `max_references` purposes. This prevents overcounting from
dual-reference behavior in structural parsers.

### `require_vault` deferred as Warn stub

The `require_vault` rule requires vault integration (1Password, Bitwarden,
etc.) which is not yet implemented. Rather than silently passing, the rule
returns `Severity::Warn` with an explicit "not yet implemented" message so
users are aware it's a stub.

### Exit code 4 for violations

`hagrid audit` returns exit code 4 when any policy violation is found,
matching the exit code already reserved in the spec. Exit code 0 is returned
for warnings-only or all-pass. Exit code 1 indicates a fatal runtime error.

### Validation: `warn_at_days <= max_age_days`

If both `warn_at_days` and `max_age_days` are specified and `warn_at_days >
max_age_days`, policy loading returns an `InvalidConfig` error. This prevents
a confusing configuration where the warning threshold exceeds the violation
threshold.

## Consequences

- Users can define policies in TOML and run `hagrid audit` in CI pipelines
  or git hooks.
- Policy results are available in both human-readable and JSON formats.
- Future rule types (e.g., `require_vault`, `require_rotation`) can be added
  by implementing new evaluator functions without changing the loading or
  matching infrastructure.
- The `*` wildcard special case means all-encompassing policies are possible
  without requiring every secret to have a `provider_pattern`.
