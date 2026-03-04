# ADR-008: Platform Scope

## Status

Accepted

## Context

Hagrid's master secret storage depends on a platform-specific secure
credential store. The two primary targets are:

- **macOS Keychain** -- via the `security-framework` crate.
- **Linux Secret Service (freedesktop.org)** -- via the `secret-service`
  crate, which communicates with GNOME Keyring, KWallet, or compatible
  implementations over D-Bus.

Supporting both platforms from the start would double the surface area for
credential storage code, complicate testing (CI would need both macOS and
Linux runners with keyring services), and slow down the initial release.

Windows Credential Manager is a possible future target but is not under
consideration for the near term.

## Decision

Hagrid v0.1 supports **macOS only**.

The credential storage layer uses the `security-framework` crate to interact
with the macOS Keychain. The master secret is stored as a generic password
item with:

- Service: `com.hagrid.master`
- Account: `hagrid`

The credential storage interface is abstracted behind a trait
(`SecretStore`) to allow future platform backends without changing the rest
of the codebase.

Linux support via the `secret-service` crate is planned for **v0.4+**. The
`SecretStore` trait will gain a Linux implementation that uses D-Bus to
communicate with the user's Secret Service provider.

### Platform detection

At compile time, the appropriate `SecretStore` implementation is selected
via conditional compilation (`#[cfg(target_os = "macos")]`). Attempting to
compile for an unsupported platform produces a clear error message rather
than a runtime failure.

## Consequences

- v0.1 users must be on macOS. This is acceptable for the initial release
  given the primary user base.
- The `SecretStore` trait abstraction means Linux support is an additive
  change -- no existing code needs modification, only a new trait
  implementation and conditional compilation gate.
- CI for v0.1 only needs macOS runners, simplifying the pipeline.
- Linux users who discover the project before v0.4 will see a compile-time
  error with a message explaining the platform limitation and linking to the
  tracking issue for Linux support.
- The `secret-service` crate requires a running D-Bus session and a Secret
  Service provider. Headless Linux servers without a desktop environment may
  need additional configuration (e.g., `gnome-keyring-daemon` in standalone
  mode). This complexity is deferred to the v0.4 release planning.
