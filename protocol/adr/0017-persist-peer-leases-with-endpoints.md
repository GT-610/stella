# ADR 0017: Persist peer leases with endpoint sets

- Status: Accepted
- Date: 2026-08-30

## Context

The controller must distinguish an authorized member from an online member.
An online member may deliberately publish an empty endpoint set, while an
authorized member whose control lease expired must disappear from peer
snapshots. Endpoint publication, heartbeat refresh, administrative suspension,
node disablement, and lease expiry can race unless one authority transaction
owns both the persisted availability record and the network snapshot revision.

Endpoint and liveness changes are visible peer metadata, but they do not grant
or revoke authorization. Advancing the controller epoch for a heartbeat would
invalidate otherwise valid grants and data sessions unnecessarily.

## Decision

The reference controller stores one versioned endpoint-lease record for each
online `(network_id, node_id)` pair. Its redb key is the 16-byte network ID
followed by the 16-byte node ID. The bounded value contains an internal magic
and version, zero reserved bytes, the last controller-observed activity time,
both identifiers, and the canonical protocol endpoint-set encoding. Endpoint
sets contain zero through eight entries; an empty set is retained because it
means online but unavailable for direct sessions. Absence of the record means
the member is offline.

Only an enabled node with an active membership may publish or refresh a lease.
Replacing a different endpoint set, creating an online record, withdrawing an
online record, or expiring one advances the network snapshot revision exactly
once and leaves the controller epoch unchanged. Republishing an identical set
or refreshing it through a heartbeat updates only the observed activity time.
The stored time never moves backwards when the controller clock regresses.

Lease expiry uses the network's signed `peer_lease_seconds` policy. One cleanup
transaction removes every expired record found at its cutoff and advances each
affected network revision once, regardless of how many peers expired in that
network. Leaving or suspending membership and disabling a node remove related
endpoint-lease records in the same transaction as their existing authority
change, so no additional revision is consumed.

Startup verification decodes every endpoint set canonically and confirms the
key, embedded identifiers, node, network, enabled state, and active membership.
Malformed or orphaned endpoint-lease state prevents the controller from
serving.

## Consequences

Peer availability survives controller restart and expires deterministically
without conflating liveness with authorization. Heartbeats do not create
unbounded revision churn, while every externally visible availability or
endpoint change has a unique snapshot revision. Persisting wall-clock seconds
means a backward clock adjustment may extend a lease temporarily, but it can
never shorten an already observed lease; operators still need a reasonably
synchronized host clock for grants and diagnostics.

