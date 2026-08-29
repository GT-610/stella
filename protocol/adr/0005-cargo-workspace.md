# ADR 0005: Organize the implementation as a Cargo workspace

- Status: Accepted
- Date: 2026-08-29

## Context

Protocol parsing, cryptography, transport, TAP access, controller behavior, and
client orchestration have different safety boundaries and testing needs.

## Decision

Use one Cargo workspace containing narrowly scoped library crates for protocol,
TAP, transport, cryptography, and shared types, plus separate server and client
binaries. Dependency versions and lints are managed at the workspace root.
Crates must not form dependency cycles.

## Consequences

Platform code and pure parsing logic can be compiled and tested independently.
The workspace has more manifests, but dependency direction and public API
ownership remain visible.
