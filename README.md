# Hagrid -- Keeper of Keys

Local-first, Rust CLI for secret lifecycle management on a single machine.

Hagrid is an **index/observer** tool. It never stores secret values -- only
HMAC fingerprints and metadata. It watches where secrets live, detects drift
between grouped references, and surfaces staleness, sprawl, and accidental
exposure risks.

## Platform

macOS-only for v0.1 (uses macOS Keychain via the `security-framework` crate).
Linux support is planned for v0.4+.

## Trust Model

### What Hagrid protects against

- **Drift** -- detecting when grouped secrets fall out of sync across files,
  environment variables, and credential stores.
- **Sprawl** -- surfacing how many locations reference a given secret and where
  they are.
- **Staleness** -- tracking rotation age and flagging secrets that haven't
  changed in a configurable window.
- **Accidental commit** -- scanning for secrets that appear in version-controlled
  files.
- **Lack of visibility** -- providing a single inventory of all secret
  references on a machine.

### What Hagrid does NOT protect against

- **Machine compromise** -- if an attacker has local access, Hagrid's index
  offers no additional barrier.
- **Network attacks** -- Hagrid makes no network calls by default and has no
  opinion about transport security.
- **Key generation strength** -- Hagrid observes secrets; it does not generate
  or evaluate their cryptographic quality.
- **Team/org sharing** -- Hagrid is a single-machine tool with no multi-user
  or syncing capabilities.

## Quickstart

Install from crates.io or build from source:

```bash
cargo install hagrid
# or
git clone https://github.com/tetsuotrees/hagrid.git
cd hagrid && cargo build --release
```

Initialize, scan, and explore:

```bash
hagrid init                        # Create ~/.hagrid/ and store master secret in Keychain
hagrid scan                        # Discover secret references across known locations
hagrid suggest --review            # Review auto-detected grouping suggestions
hagrid group "my-token" ref:a1 ref:b2  # Confirm a group from references
hagrid list                        # List all secrets and groups
hagrid drift                       # Check for fingerprint mismatches within groups
```

## Security Invariants

1. **No secret values in the index.** The database stores HMAC-SHA256
   fingerprints, never plaintext or ciphertext secret values.
2. **No network calls by default.** Hagrid is a local-only tool. Future MCP
   integration (v0.3) requires explicit opt-in.
3. **Minimal memory exposure.** Values read during scanning are fingerprinted
   and immediately dropped. Rotation paths use `Zeroizing<String>` to clear
   memory on drop.
4. **Encrypted database.** The SQLite database is encrypted with SQLCipher
   using a key derived from the master secret via HKDF-SHA256.

## Architecture

See [docs/README.md](docs/README.md) for the full documentation map.

- [docs/spec.md](docs/spec.md): technical scope and command surface
- [docs/threat-model.md](docs/threat-model.md): security boundaries
- [docs/adr/README.md](docs/adr/README.md): architectural decision records
- [docs/plan/post-v0.1-execution-plan.md](docs/plan/post-v0.1-execution-plan.md): post-v0.1 execution plan
- [docs/runbooks/01-release-and-ci-bootstrap.md](docs/runbooks/01-release-and-ci-bootstrap.md): first execution stream runbook

## License

MIT
