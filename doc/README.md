# Documentation

This directory contains the public project documentation that should travel with the repository.

It is intended for:

- project vision and scope
- architecture decisions
- MVP design notes
- protocol design notes
- onboarding contributors and community discussion

## Structure

- `project-definition.md`
  - project purpose, goals, scope, and non-goals

- `architecture/README.md`
  - architecture document index

- `architecture/control-plane.md`
  - control-plane decision and why the project chooses self-hosted centralized coordination

- `architecture/mvp-architecture.md`
  - the MVP system model, first supported packet classes, and implementation order

- `architecture/session-handshake-and-traversal.md`
  - peer establishment, NAT traversal, relay fallback, and path strategy

- `protocol/README.md`
  - protocol document index

- `protocol/probe-packet-format.md`
  - first protocol sketch for peer probing and direct-path activation

## Notes

- These files are meant to be stable enough for public reading and contributor reference.
- They can still evolve, but they should reflect current project thinking rather than raw brainstorming.
- Recommended reading order:
  1. `project-definition.md`
  2. `architecture/control-plane.md`
  3. `architecture/mvp-architecture.md`
  4. `architecture/session-handshake-and-traversal.md`
  5. `protocol/probe-packet-format.md`
