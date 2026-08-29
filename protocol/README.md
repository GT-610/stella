# Stella Protocol

This directory is the normative home of the Stella protocol specification.
The specification is published under CC BY-SA 4.0. Implementations may use
the protocol independently of the Rust workspace.

Stella is currently a pre-standard protocol. The first interoperable draft is
identified as `0.1`; incompatible wire changes are expected until the draft is
declared stable.

## Directory layout

- `spec/` contains the normative protocol text.
- `adr/` records architectural decisions and their rationale.

The rendered documentation under `docs/protocol/` is a synchronized reading
copy. If the two disagree, files in this directory are authoritative.
