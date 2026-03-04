# Hagrid Threat Model

## Scope

Hagrid is a local-first, single-machine secret lifecycle observer. It indexes
where secrets live and detects drift, sprawl, and staleness. It never stores
secret values -- only HMAC fingerprints and metadata.

This document describes what Hagrid protects against, what it does not, and
the data handling invariants that support those boundaries.

## What Hagrid Protects Against

### Secret drift

Grouped references are expected to share the same fingerprint. When a secret
is rotated in one location but not others, Hagrid flags the mismatch. This
catches partial rotations before they cause runtime failures.

### Secret sprawl

Hagrid maintains a full inventory of every discovered secret reference,
including its location kind (file, environment variable, keychain entry, etc.)
and file path. This makes it possible to answer "where does this API key
appear?" in seconds rather than hours.

### Staleness

Each reference tracks when its fingerprint last changed. Configurable
staleness thresholds surface secrets that haven't been rotated within an
expected window.

### Accidental commit

During scanning, Hagrid identifies secrets that exist inside version-controlled
directories and flags them, allowing the user to remediate before the secret
reaches a remote repository.

### Lack of visibility

Without tooling, developers have no consolidated view of the secrets scattered
across dotfiles, environment configs, credential stores, and application
configs on a single machine. Hagrid provides that view.

## What Hagrid Does NOT Protect Against

### Machine compromise

If an attacker has local access (interactive shell, malware, physical access),
Hagrid's index and Keychain-stored master secret offer no additional security
barrier beyond what the OS provides. The index itself contains only
fingerprints, but the original secrets are still on disk in their source
locations.

### Network attacks

Hagrid makes no network calls by default. It has no opinion on transport
security, TLS configuration, or secret transmission. Future MCP integration
(v0.3+) uses a local Unix socket and requires explicit opt-in.

### Key generation strength

Hagrid observes secrets; it does not generate or evaluate their cryptographic
quality. A weak password and a strong 256-bit key look the same to Hagrid's
fingerprinting layer.

### Team/org sharing

Hagrid is a single-machine tool. It has no multi-user model, no syncing, and
no shared state. Organizations needing secret management across teams should
use dedicated secret managers (Vault, AWS Secrets Manager, 1Password, etc.)
and can use Hagrid as a local companion for visibility.

## Data Handling Invariants

### No secret values in the index

The database stores HMAC-SHA256 fingerprints computed with an HKDF-derived
fingerprint key. The fingerprint is a one-way transform -- secret values
cannot be recovered from it. The fingerprint key itself is derived from the
master secret and never written to disk (it is derived at runtime from the
Keychain-stored master).

### No network by default

Hagrid performs no DNS lookups, HTTP requests, or socket connections during
normal operation. The only planned network-adjacent feature is a local Unix
socket for MCP integration, gated behind an explicit `--mcp` flag and
disabled by default.

### Zeroize for transiting values

Secret values are read from their source locations during scanning and
immediately fingerprinted. The plaintext value is not retained. Rotation
workflows that must hold a value briefly use `Zeroizing<String>` from the
`zeroize` crate, which overwrites memory on drop.

### Encrypted database

The SQLite index database is encrypted at rest using SQLCipher. The database
encryption key is derived from the master secret via HKDF-SHA256 with a
dedicated info string (`hagrid-db-v1`). The master secret itself is stored
in the macOS Keychain, not on the filesystem.

## In-Memory Handling

During a scan operation:

1. Hagrid reads a secret value from its source location.
2. The value is passed to the HMAC-SHA256 function with the derived
   fingerprint key.
3. The resulting fingerprint (hex digest) is stored in the index.
4. The original value is dropped (or zeroized if held in a `Zeroizing`
   wrapper).

At no point is the secret value written to the database, logged, or persisted
in any Hagrid-controlled storage.

For rotation workflows, the value may be held slightly longer while the user
confirms the operation. These values use `Zeroizing<String>` to ensure
memory is overwritten when the value goes out of scope.

## Log Safety

Hagrid uses structured JSON logging via `tracing` and `tracing-subscriber`.
Log output includes reference IDs, fingerprint prefixes, file paths, and
operation metadata. It never includes secret values. Log format and field
names are designed so that accidental inclusion of a secret value would
require an explicit, reviewable code change.

## Crash Dump Considerations

During a scan, secret values briefly exist in process memory between the
read and the fingerprint computation. If the process crashes or is killed
during this window, the value could appear in a core dump. Mitigations:

- The window is minimized by performing the HMAC immediately after read.
- `Zeroizing<String>` is used for any value that persists beyond a single
  expression.
- Core dumps are disabled by default on macOS for release builds. Users on
  systems with core dumps enabled should be aware of this residual risk.
