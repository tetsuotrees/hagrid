# ADR-001: Fingerprint Format

## Status

Accepted

## Context

Hagrid needs a way to detect whether two secret references hold the same
value without storing the value itself. The fingerprint must be:

- Deterministic (same value produces the same fingerprint within an
  installation).
- One-way (the value cannot be recovered from the fingerprint).
- Installation-specific (fingerprints from one machine are meaningless on
  another, preventing cross-machine correlation attacks).

We considered plain SHA-256 hashes, but these are globally deterministic --
an attacker with a candidate value could confirm it against a stolen index.

## Decision

Fingerprints are computed as HMAC-SHA256 using a fingerprint key derived from
the master secret via HKDF-SHA256:

```
fingerprint_key = HKDF-SHA256(master_secret, info="hagrid-fingerprint-v1")
fingerprint     = HMAC-SHA256(fingerprint_key, secret_value)
```

Storage and display rules:

- The full 64-character hex digest is stored in the database.
- No visible prefix (like `sha256:`) is stored -- the algorithm is implicit
  and versioned via the HKDF info string.
- Display contexts (CLI output, logs) show a 16-character truncation of the
  hex digest for readability. The truncation is for display only; all
  comparisons use the full digest.

The fingerprint is installation-specific because the fingerprint key is
derived from a per-installation master secret. The same API key on two
different machines will produce different fingerprints.

## Consequences

- Fingerprint comparison is a constant-time 32-byte equality check in the
  database, which is fast and simple.
- If the master secret is lost or rekeyed, all fingerprints must be
  recomputed by re-scanning. This is acceptable because rekeying is a rare,
  forward-only operation (see ADR-003).
- Cross-machine fingerprint comparison is impossible by design. This is a
  feature, not a limitation -- it means a stolen index database reveals
  nothing about secret values without the master secret.
- The 16-character display truncation provides ~64 bits of collision
  resistance for human-facing output. Collisions at the display level are
  cosmetic; the database always uses the full digest.
