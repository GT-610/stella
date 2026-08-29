# ADR 0006: Separate implementation and specification licenses

- Status: Accepted
- Date: 2026-08-29

## Context

The implementation should remain free software, while the protocol must be
readable and reimplementable by independent projects. Reference repositories in
`.vscode/` have different licenses and include material that is not available
for reuse.

## Decision

Stella implementation code is licensed under GPL-3.0. Protocol specification
documents are licensed under CC BY-SA 4.0. Reference projects may be consulted
only for architectural understanding. No source is copied, rewritten, or
derived from ZeroTier nonfree or otherwise incompatible material.

If a design is materially inspired by a reference project, its ADR names the
high-level mechanism. The Stella wire format and implementation remain
independent.

## Consequences

License boundaries are explicit and compatible implementations can be built
from the public specification. Contributors must review provenance carefully,
and the `.vscode/` reference tree remains excluded from commits.
