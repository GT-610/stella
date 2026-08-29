# ADR 0003: Make the data transport pluggable

- Status: Accepted
- Date: 2026-08-29

## Context

Some deployments have directly reachable UDP endpoints; others already use a
private overlay such as Tailscale. Stella should provide Layer-2 semantics
without owning every possible reachability or NAT traversal mechanism.

## Decision

The data plane depends on a datagram transport interface rather than a concrete
socket type. The first implementation provides UDP. A transport supplies
endpoint representation, bounded datagram send and receive, and local
capability information. It does not authenticate Stella identities, authorize
membership, interpret Ethernet frames, or weaken packet authentication.

## Consequences

The same protocol can run over public UDP, a private IP overlay, or a future
transport. The abstraction introduces capability negotiation and MTU concerns,
and every transport must preserve packet boundaries or emulate them exactly.
