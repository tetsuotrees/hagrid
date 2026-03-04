# ADR-006: Database Constraints

## Status

Accepted

## Context

As the database schema stabilized, several uniqueness and naming constraints
emerged as necessary to prevent subtle bugs and maintain data integrity.
These constraints are enforced at the database level (SQLite UNIQUE
constraints and CHECK constraints) rather than only in application code, to
prevent corruption from bugs or future refactoring.

## Decision

The following constraints are enforced in the database schema:

### Unique identity key per reference

Each reference row has a unique `identity_key` column (the HMAC-based
identity from ADR-002). This prevents duplicate entries for the same
logical reference. If a scan discovers a reference whose identity already
exists, the existing row is updated rather than duplicated.

```sql
CREATE TABLE references (
    id INTEGER PRIMARY KEY,
    identity_key TEXT NOT NULL UNIQUE,
    ...
);
```

### Unique case-sensitive group labels

Group labels are unique and case-sensitive. `stripe-prod` and `Stripe-Prod`
are distinct labels. This avoids ambiguity in CLI commands that accept group
labels as arguments.

```sql
CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    label TEXT NOT NULL UNIQUE,
    ...
);
```

### Group label prefix restriction

Group labels must not start with `ref:` (case-insensitive check). This
prefix is reserved for reference identity display (ADR-002). Without this
restriction, a group named `ref:a7c3e1` would be ambiguous with the
reference display ID `ref:a7c3e1`.

```sql
CHECK (label NOT LIKE 'ref:%' AND label NOT LIKE 'REF:%')
```

### Suggestion deduplication

Suggestions are deduplicated by the combination of `reason` and a sorted,
canonical representation of the `reference_ids` involved. This prevents
the same grouping suggestion from being created multiple times across
repeated scans.

```sql
CREATE UNIQUE INDEX idx_suggestions_dedup
    ON suggestions (reason, sorted_reference_ids);
```

## Consequences

- Database-level constraints catch bugs that application-level validation
  might miss, especially during concurrent operations or future code changes.
- The `ref:` prefix restriction is a minor naming limitation for users, but
  it prevents a class of ambiguity bugs in CLI argument parsing.
- Case-sensitive group labels match filesystem behavior on macOS (APFS is
  case-sensitive by default in recent versions) and avoid the complexity of
  case-insensitive collation in SQLite.
- Suggestion deduplication requires computing a canonical form of the
  reference ID set (sorted, comma-joined) before insertion. This is a small
  cost for preventing duplicate noise.
