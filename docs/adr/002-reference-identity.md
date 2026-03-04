# ADR-002: Reference Identity

## Status

Accepted

## Context

Each secret reference discovered during a scan needs a stable identity so
that Hagrid can track it across scans, detect changes, and maintain grouping
relationships. The identity must be:

- Deterministic -- the same reference in the same location produces the same
  identity across scans.
- Unique -- two different references never collide.
- Stable -- renaming unrelated files or adding new secrets does not change
  existing identities.

A naive approach (database auto-increment IDs) would make identities unstable
across re-initialization. UUID v4 would be unique but not deterministic --
a re-scan would create duplicate entries.

## Decision

Reference identity is computed as:

```
identity_key = HKDF-SHA256(master_secret, info="hagrid-identity-v1")
identity     = HMAC-SHA256(identity_key, normalized_path | location_kind | location_discriminator | source_kind)
```

Where:

- `normalized_path` -- absolute path with home directory replaced by `~`,
  trailing slashes removed.
- `location_kind` -- one of: `file`, `env`, `keychain`, `plist`, etc.
- `location_discriminator` -- additional context within a location (e.g.,
  the key name within a `.env` file, the variable name for an environment
  variable).
- `source_kind` -- the scanner that discovered the reference (e.g.,
  `dotenv`, `json`, `yaml`, `keychain`).

The pipe character (`|`) is used as a separator. Fields are UTF-8 encoded.

For display, the identity is shown as a short hash prefix: `ref:a7c3e1`.
The prefix auto-extends on collision (e.g., `ref:a7c3e1b2`) to maintain
uniqueness in any given output context.

## Consequences

- References are stable across scans as long as the file path and location
  within the file remain the same. Moving a secret to a different file
  creates a new reference (the old one is marked stale).
- The identity is installation-specific (derived from the master secret),
  so identities cannot be correlated across machines.
- The `ref:` display prefix is reserved and must not be used as a group
  label prefix (see ADR-006).
- Rekeying the master secret invalidates all identities and requires a
  full re-scan with re-grouping. This is consistent with the rekeying
  policy in ADR-003.
