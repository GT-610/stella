# ADR 0002: Use a centralized self-hosted controller

- Status: Accepted
- Date: 2026-08-29

## Context

Virtual networks need a single understandable authority for membership,
revocation, policy, version negotiation, and peer discovery. Decentralized
consensus and global discovery would expand the threat model and are not goals
of the first implementation.

## Decision

Every deployment has one logical, self-hosted controller authority. The
controller authenticates nodes and issues current network and peer state. It
may later be replicated for availability without changing the single-authority
semantics.

After discovery, eligible peers exchange data directly. The controller is not
on the normal unicast data path. Relay service is reserved for a future
protocol extension.

## Consequences

Policy and revocation have a clear source of truth, and deployments are easy to
reason about. Controller outage delays new sessions and policy changes, while
existing sessions may continue only for their bounded lease. The controller is
a high-value trust and availability target.
