# ADR 0010: Use bounded head-end replication for flood traffic

- Status: Accepted
- Date: 2026-08-29

## Context

Ethernet compatibility requires broadcast, multicast, and unknown-unicast
delivery. Candidate designs included controller relay, underlay IP multicast,
an elected broadcast proxy, spanning distribution trees, and sender-side
replication to current peers.

Controller relay places application traffic and bandwidth on the control
authority. Underlay multicast is rarely portable across public networks and
private overlays. Proxies and trees scale better but introduce election,
failure recovery, loop prevention, and trust mechanisms that are disproportionate
for the first LAN-game-oriented release.

## Decision

Version 0.1 uses head-end replication: the node that reads a flood-eligible
Ethernet frame from its TAP adapter sends one independently protected data
packet to every other eligible member in the controller's current peer
snapshot.

Frames received from a Stella peer are written only to the local TAP adapter;
they are never forwarded to another peer. This split-horizon rule prevents
overlay loops without a distributed spanning tree.

The controller assigns each network a `max_flood_peers` policy. The reference
controller defaults to 64 total members and permits an administrator to raise
the value no higher than 256 in protocol version 0.1. It refuses an additional
membership rather than silently omitting a flood recipient. A node also rejects
a peer snapshot larger than the authorized limit.

Each node applies separate token buckets to locally originated broadcast,
multicast, and unknown-unicast frames. The controller supplies policy ceilings;
the reference defaults are 1,000 flood frames per second with a burst of 2,000
per network. Rate-limited frames are dropped and counted, not queued without a
bound.

Known unicast is never deliberately flooded. Unknown unicast may be flooded
only while no unexpired authenticated forwarding entry exists. Multicast
optimization such as IGMP or MLD snooping is reserved for a future extension;
version 0.1 preserves compatibility by flooding multicast.

## Consequences

The behavior is deterministic, direct, underlay independent, and easy for
independent clients to reproduce. It scales linearly in sender bandwidth and
CPU, so version 0.1 explicitly targets small virtual LANs. Larger deployments
require a future negotiated replication mechanism rather than unilateral
optimization that could break broadcast semantics.
