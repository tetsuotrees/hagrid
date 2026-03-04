# ADR-004: Database Encryption

## Status

Accepted

## Context

Hagrid's SQLite database contains HMAC fingerprints, file paths, location
metadata, group labels, and timestamps. While the fingerprints are one-way
and cannot reveal secret values, the metadata itself is sensitive:

- File paths reveal where secrets are stored on the machine.
- Group labels reveal the logical purpose of secrets (e.g., "stripe-prod-key").
- Timestamps reveal rotation patterns.

An unencrypted database on disk would expose this metadata to any process or
user with read access to `~/.hagrid/`.

We considered application-layer encryption (encrypting individual fields),
but this complicates queries and indexing. Full-database encryption with
SQLCipher provides transparent protection without application complexity.

## Decision

The Hagrid index database uses SQLCipher for encryption at rest. SQLCipher
is compiled into the binary via the `rusqlite` crate's `bundled-sqlcipher`
feature.

The database encryption key is derived from the master secret:

```
db_key = HKDF-SHA256(master_secret, info="hagrid-db-v1")
```

The Keychain stores the master secret, not the db_key directly. This ensures
that the db_key is never persisted and is derived fresh on each database
open.

On database open, Hagrid:

1. Reads the master secret from the Keychain.
2. Derives the db_key via HKDF.
3. Passes the db_key to SQLCipher via `PRAGMA key`.
4. Drops the db_key from memory after the connection is established.

SQLCipher handles page-level encryption transparently after the key is set.

## Consequences

- The database file is opaque without the master secret. Copying the file
  to another machine without the Keychain entry renders it unreadable.
- SQLCipher adds a small performance overhead (~5-15% for typical
  operations) due to page-level AES encryption. This is negligible for
  Hagrid's workload.
- The `bundled-sqlcipher` feature statically links SQLCipher, avoiding
  system library version conflicts at the cost of a larger binary.
- Database tooling (e.g., `sqlite3` CLI) cannot open the database without
  SQLCipher support and the correct key. Debugging requires Hagrid's own
  CLI or a SQLCipher-enabled shell.
- Backup of the database file alone is insufficient for disaster recovery;
  the Keychain entry must also be backed up (or the master secret exported
  separately).
