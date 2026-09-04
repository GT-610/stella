# Development

Stella is developed specification first. A protocol or public API change is
complete only when its normative text, architecture decision, implementation,
and tests agree.

## Repository areas

- `protocol/spec/` is the normative protocol source.
- `protocol/adr/` records durable decisions and tradeoffs.
- `crates/` contains the Rust workspace.
- `docs/` contains the rendered guide and synchronized protocol reading copy.
- `tests/` contains integration and end-to-end scenarios as they are added.

The build command runs `docs:sync` before VitePress so generated files under
`docs/protocol/` match the normative protocol source. Do not edit those
generated files directly.

[Reference implementation architecture](./architecture.md) describes crate and
runtime boundaries; [Protocol codec implementation](./protocol-codec.md) covers
wire parsing; and [Cryptography implementation](./cryptography.md) covers secret
ownership, key derivation, packet protection, and replay handling.
[Datagram transport implementation](./transport.md) documents the object-safe
transport contract, UDP socket behavior, cancellation, and truncation defense.
[Windows TAP implementation](./tap-windows.md) covers adapter selection,
complete-frame I/O, MTU handling, and cancellation. [macOS feth TAP
implementation](./tap-macos.md) covers visible/peer roles, BPF receive,
AF_NDRV transmit, persistent reuse, helper privilege separation, locking, and
root-only native verification;
[Control-channel
implementation](./control-channel.md) covers framed async I/O, message ownership,
sequencing, correlation, and exporter-bound proof inputs.
For TLS service boundaries, transactional authority state, administrative commands,
and session behavior, see [Controller implementation](./controller.md). The
[Client control plane](./client-control.md) documents persistent trust,
authentication, atomic peer state, heartbeats, reconnect, and fail-closed
forwarding behavior. [Client data plane](./client-data-plane.md) covers
TAP worker ownership, authenticated peer routing, keepalives, endpoint pinning,
and rekey behavior.
