# ADR-005: Grouping Flow

## Status

Accepted

## Context

Hagrid's core value proposition is detecting drift between secret references
that are supposed to hold the same value. To do this, references must be
grouped. However, automatic grouping is inherently heuristic -- two `.env`
files might have a `DATABASE_URL` key that refer to completely different
databases.

False positive groupings would cause noisy, incorrect drift alerts. This
undermines trust in the tool and leads users to ignore real drift.

We considered fully manual grouping (user specifies every group), but this
creates too much friction for initial adoption. We also considered fully
automatic grouping with no confirmation, but this produces the false positive
problem described above.

## Decision

Grouping uses a two-phase flow:

### Phase 1: Suggestions

During scanning, Hagrid auto-detects candidate groupings based on heuristics:

- Same key name across different `.env` files.
- Same Keychain service name with matching account patterns.
- Name similarity above a configurable threshold.

Each suggestion includes:

- A set of reference IDs that might belong together.
- A reason string describing why the grouping was suggested.
- A confidence score (0.0 to 1.0) reflecting heuristic strength.

Suggestions are stored in the database but do not participate in drift
detection.

### Phase 2: Confirmation

The user reviews suggestions via `hagrid suggest --review` and accepts,
rejects, or modifies them. Accepted suggestions become confirmed groups
with a user-assigned label.

Only confirmed groups participate in drift detection. Rejected suggestions
are marked as dismissed and not re-surfaced unless the underlying references
change.

## Consequences

- New users get immediate value from suggestions without needing to
  understand the full grouping model upfront.
- False positive groupings never cause spurious drift alerts because
  unconfirmed suggestions are inert.
- The confirmation step is a lightweight review, not a configuration
  burden -- the user is accepting or rejecting pre-built candidates.
- Suggestions can be re-generated after a re-scan. Dismissed suggestions
  are only re-surfaced if the reference set changes (new references added
  or existing ones removed).
- Confidence scores allow future UI improvements (e.g., auto-accepting
  high-confidence suggestions with `--auto-accept=0.95`).
