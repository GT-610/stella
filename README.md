# Stella

Stella is an experimental open Layer-2 virtual LAN protocol and Rust reference
implementation. Its initial scope includes:

- Layer-2 compatibility for LAN-style games and applications;
- a self-hosted centralized control plane;
- direct peer data paths over replaceable transports;
- protocol-level authentication independent of the carrying network.

The project is in pre-standard development and is not usable for production
networking yet. The Windows core libraries, self-hosted controller, client
control plane, and authenticated TAP-to-UDP Layer-2 data path are implemented;
end-to-end Windows interoperability validation remains in progress.

## Workspace checks

```powershell
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
bun run docs:build
```

The normative protocol source is under [`protocol/`](protocol/README.md). The
VitePress site is generated from `docs/` and synchronizes protocol pages before
each development or production build. Controller setup and operation are
documented in [`docs/guide/server-deployment.md`](docs/guide/server-deployment.md).
