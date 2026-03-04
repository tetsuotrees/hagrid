# ADR-003: Key Hierarchy

## Status

Accepted

## Context

Hagrid needs cryptographic keys for three distinct purposes:

1. Computing reference identities (ADR-002).
2. Computing value fingerprints (ADR-001).
3. Encrypting the SQLite database at rest (ADR-004).

Using a single key for all three purposes would create unnecessary coupling
and make it impossible to reason about the security properties of each
operation independently. Using three independent keys would require storing
and managing three separate secrets.

## Decision

Hagrid uses a single master secret with three derived keys:

```
master_secret  = 32 random bytes (generated once during `hagrid init`)
identity_key   = HKDF-SHA256(master_secret, info="hagrid-identity-v1")
fingerprint_key = HKDF-SHA256(master_secret, info="hagrid-fingerprint-v1")
db_key         = HKDF-SHA256(master_secret, info="hagrid-db-v1")
```

The master secret is stored in the macOS Keychain under the service name
`com.hagrid.master` and account `hagrid`. It is never written to the
filesystem.

Key derivation uses HKDF-SHA256 with no salt (the master secret has
sufficient entropy) and distinct info strings for domain separation. The
info strings include a version suffix (`-v1`) to support future algorithm
changes without ambiguity.

Derived keys are computed at runtime when needed and are not persisted. They
exist in memory only for the duration of the operation that requires them.

### Rekeying

Rekeying is a rare, forward-only operation triggered by explicit user
command (`hagrid rekey`). The process:

1. Generate a new 32-byte master secret.
2. Derive new identity, fingerprint, and database keys.
3. Re-encrypt the database with the new db_key.
4. Re-scan all references to recompute fingerprints and identities.
5. Store the new master secret in Keychain, replacing the old one.
6. The old master secret is irrecoverably lost after this operation.

Rekeying invalidates all existing fingerprints, identities, and group
relationships. It is effectively a fresh start with history preserved only
in the re-scanned state.

## Consequences

- A single Keychain entry is the root of trust for all Hagrid
  cryptographic operations.
- Losing Keychain access (or the master secret) means losing the ability
  to read the database or validate fingerprints. Recovery requires
  `hagrid init --force` to start fresh.
- The version suffix in info strings allows future key derivation changes
  (e.g., `hagrid-fingerprint-v2`) without colliding with existing keys.
- HKDF provides strong domain separation -- compromising one derived key
  does not reveal the master secret or other derived keys.
