# Stella

Stella is an experimental open Layer-2 virtual LAN protocol and Rust reference
implementation. Its initial scope includes:

- Layer-2 compatibility for LAN-style games and applications;
- a self-hosted centralized control plane;
- direct peer data paths over replaceable transports;
- protocol-level authentication independent of the carrying network.

The project is in pre-standard development and is not usable for production
networking yet. The self-hosted controller and authenticated TAP-to-UDP client
data plane are implemented on Windows and macOS. Windows uses pre-installed
TAP-Windows adapters; macOS uses persistent built-in feth pairs with BPF receive
and AF_NDRV transmit through Stella's own backend. A narrow root helper owns
only the feth lifecycle and frame I/O; `stella-client` remains unprivileged.
Windows end-to-end verification has passed with two real adapters. macOS
includes root-only lifecycle and helper-backed two-node verification, but this
checkout has not recorded a privileged run yet.

## Release Compatibility

Version 0.2.0 removes the public `stella_control::CorrelationTracker` type and
`stella_control::MAX_CORRELATIONS` constant. They were unused within the
workspace and are no longer supported; downstream consumers must maintain any
request-correlation limits themselves.

## Workspace checks

```sh
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
bun run docs:build
```

The normative protocol source is under [`protocol/`](protocol/README.md). The
VitePress site is generated from `docs/` and synchronizes protocol pages before
each development or production build. Controller setup and operation are
documented in [`docs/guide/server-deployment.md`](docs/guide/server-deployment.md).
macOS feth setup and privileged verification are documented in
[`docs/guide/macos-development.md`](docs/guide/macos-development.md).
