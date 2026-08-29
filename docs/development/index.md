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
runtime boundaries.
