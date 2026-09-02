# Architecture Decision Records

ADRs describe decisions that constrain the Stella protocol or its reference
implementation. Accepted records are immutable except for spelling or link
fixes. A changed decision is documented by a new ADR that supersedes the old
one.

Statuses used in this directory are `Proposed`, `Accepted`, `Superseded`, and
`Rejected`.

## Index

- [0001: Use Rust](./0001-use-rust.md)
- [0002: Use a centralized controller](./0002-centralized-controller.md)
- [0003: Make the data transport pluggable](./0003-pluggable-data-transport.md)
- [0004: Use native TAP backends](./0004-native-tap-backends.md)
- [0005: Use a Cargo workspace](./0005-cargo-workspace.md)
- [0006: Define reference-code license boundaries](./0006-license-boundaries.md)
- [0007: Run the control plane over TLS 1.3 and TCP](./0007-control-plane-over-tls.md)
- [0008: Use explicit wire encoding](./0008-explicit-wire-encoding.md)
- [0009: Use the Stella version 0.1 cryptographic suite](./0009-cryptographic-suite.md)
- [0010: Use head-end replication for flooded traffic](./0010-head-end-flooding.md)
- [0011: Use TOML for local configuration](./0011-toml-configuration.md)
- [0012: Use preinstalled TAP-Windows adapters](./0012-preinstalled-tap-windows-adapters.md)
- [0013: Share control-channel mechanics in a dedicated crate](./0013-shared-control-channel-crate.md)
- [0014: Store controller authority state in redb](./0014-redb-controller-state.md)
- [0015: Protect controller identity files with native ACLs](./0015-protect-controller-identity-files.md)
- [0016: Initialize controller TLS identity explicitly](./0016-initialize-controller-tls-identity.md)
- [0017: Persist peer leases with endpoint sets](./0017-persist-peer-leases-with-endpoints.md)
- [0018: Bound controller runtime admission and shutdown](./0018-bound-controller-runtime.md)
- [0019: Authenticate control sessions before authority use](./0019-authenticate-control-sessions-before-authority-use.md)
- [0020: Serve authenticated control requests from atomic views](./0020-serve-authenticated-control-requests-from-atomic-views.md)
- [0021: Refresh membership grants on monotonic deadlines](./0021-refresh-membership-grants-on-monotonic-deadlines.md)
- [0022: Rebuild client forwarding state from the controller](./0022-rebuild-client-state-from-controller.md)
- [0023: Bound the Windows client data runtime](./0023-bound-windows-client-data-runtime.md)
- [0024: Use ICE and STUN for automatic peer connectivity](./0024-use-ice-for-connectivity.md)
- [0025: Maintain a warm relay fallback](./0025-maintain-warm-relay-fallback.md)
- [0026: Bind peer sessions to validated paths](./0026-bind-sessions-to-validated-paths.md)
- [0027: Distribute connectivity separately from membership records](./0027-separate-connectivity-from-membership-records.md)
- [0028: Migrate authority state before storing connectivity generations](./0028-migrate-connectivity-authority-state.md)
- [0029: Tunnel secure WebSocket relay through an explicit HTTP proxy](./0029-tunnel-websocket-through-http-proxy.md)
- [0030: Bootstrap controller TLS through the local HTTP proxy](./0030-bootstrap-control-through-http-proxy.md)
- [0031: Bound relay carrier establishment](./0031-bound-relay-carrier-establishment.md)
- [0032: Bound relay DNS preparation](./0032-bound-relay-dns-preparation.md)
- [0033: Preserve the reachable relay carrier on refresh](./0033-preserve-relay-carrier-on-refresh.md)
- [0034: Recover relay without restarting direct sessions](./0034-recover-relay-without-restarting-direct-sessions.md)
