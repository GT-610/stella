# Stella

Stella is an experimental open Layer-2 virtual LAN protocol and Rust reference
implementation focused on:

- Layer-2 compatibility for LAN-style games and applications;
- a self-hosted centralized control plane;
- direct peer data paths over replaceable transports;
- protocol-level authentication independent of the carrying network.

The project is in pre-standard development and is not usable for production
networking yet. Windows is the first implementation target.

## Workspace checks

```powershell
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
bun run docs:build
```

The normative protocol source is under [`protocol/`](protocol/README.md). The
VitePress site is generated from `docs/` and synchronizes protocol pages before
each development or production build.
