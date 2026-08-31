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

See [Reference implementation architecture](./architecture.md) for crate and
runtime boundaries, [Protocol codec implementation](./protocol-codec.md) for
wire parsing, and [Cryptography implementation](./cryptography.md) for secret
ownership, key derivation, packet protection, and replay handling. See
[Datagram transport implementation](./transport.md) for the object-safe
transport contract, UDP socket behavior, cancellation, and truncation defense.
See [Windows TAP implementation](./tap-windows.md) for adapter selection,
complete-frame I/O, MTU handling, and cancellation.
See [Control-channel implementation](./control-channel.md) for framed async I/O,
message ownership, sequencing, correlation, and exporter-bound proof inputs.
See [Controller implementation](./controller.md) for TLS service boundaries,
transactional authority state, administrative commands, and session behavior.
See [Windows client control plane](./client-control.md) for persistent trust,
authentication, atomic peer state, heartbeats, reconnect, and fail-closed
forwarding behavior.
