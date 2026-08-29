# Stella Virtual Network Model

- Status: Draft
- Protocol version: 0.1
- Last updated: 2026-08-29

## 1. Scope

This document defines virtual-network lifecycle, membership state, TAP
attachment, isolation, forwarding databases, MAC learning, conflict handling,
frame classification, policy application, and controller authority.

## 2. Virtual network semantics

One Stella virtual network is one isolated Ethernet broadcast domain. It has:

- one random 16-byte network ID;
- one controller authority and current non-zero epoch;
- one canonical 64-byte network policy;
- a bounded set of authorized node memberships;
- a per-network peer snapshot revision;
- no implicit IP subnet, DHCP server, DNS service, gateway, or VLAN mapping.

Stella transports Ethernet. IPv4, IPv6, ARP, DHCP, NetBIOS, IPX, and other
payloads are visible only as Ethernet frame bytes. Address assignment above
Layer 2 is an administrator or application concern.

Version 0.1 does not join networks controlled by different controller
identities into one broadcast domain.

## 3. Controller authority

The controller is authoritative for:

- network creation, deletion, name, and policy;
- node enrollment and membership authorization;
- epoch, grant, and revocation state;
- member identity keys and current endpoint metadata;
- snapshot revisions and liveness visibility.

The controller is not authoritative for learned source MAC locations. Each node
maintains its own forwarding database from authenticated data traffic. This
keeps steady-state Ethernet forwarding off the controller and avoids making a
stale central MAC table a data-path dependency.

Network creation and deletion are administrative operations, not peer protocol
messages. Deletion increments authority state, revokes every membership,
withdraws peer data, and retains a tombstone so the network ID is never reused.

## 4. Membership state

For one `(node_id, network_id)` pair the controller stores one of:

| State | Meaning |
| --- | --- |
| `ABSENT` | No authorization exists |
| `AUTHORIZED` | Membership exists but the node has no current control lease or endpoints |
| `ONLINE` | Authorized with a current control lease; endpoints may still be empty |
| `SUSPENDED` | Administrative temporary denial; no valid grant is issued |
| `REVOKED` | Authorization was removed and retained as audit/tombstone state |

`AUTHORIZED` and `ONLINE` may receive grants. `SUSPENDED`, `REVOKED`, and
`ABSENT` may not participate. Transition into or out of an authorization state
changes the controller epoch. Liveness transitions between `AUTHORIZED` and
`ONLINE` change snapshot revision but not epoch.

A node's local network runtime is independently in one of:

```text
Stopped -> Joining -> Active -> Draining -> Stopped
                      |    ^
                      v    |
                   Degraded
```

- `Joining` has no TAP forwarding until grant, policy, and snapshot validate.
- `Active` has valid local authorization and current controller state.
- `Degraded` has lost control connectivity but may use unexpired grants and
  established sessions.
- `Draining` stops TAP ingress, rejects new sessions, removes peer state, and
  closes the adapter.

Grant expiry, revocation, a higher invalidating epoch, or fatal policy mismatch
moves directly to `Draining`; it is not a degraded condition.

## 5. TAP attachment

Version 0.1 uses one TAP adapter per active network. Adapter sharing across
network IDs is forbidden because it would merge Ethernet broadcast domains and
weaken key, MAC, and policy isolation.

The adapter:

- carries Ethernet frames without FCS;
- is configured to the network's supported Layer-3 MTU, normally 1,500 when
  `max_frame_size` is 1,514;
- has one stable locally administered unicast MAC generated for that node and
  network unless the administrator selects an existing compatible adapter;
- is opened only after local identity and configuration validation;
- does not begin forwarding until network activation is atomic.

The default adapter MAC is derived for stable local configuration, not
authentication:

```text
digest = SHA-256(
    UTF8("stella tap mac v1") || node_id || network_id
)
mac = digest[0..6]
mac[0] = (mac[0] | 0x02) & 0xfe
```

This produces a locally administered unicast address. A collision detected from
authenticated traffic places the address in conflict state and requires an
administrator-selected override or regenerated identity; Stella does not
silently change the host adapter MAC while active.

## 6. Isolation requirements

Every mutable data-plane object is keyed by network ID before any shorter key:

- membership and policy;
- peer identity and endpoints;
- peer sessions and replay windows;
- forwarding and local-MAC entries;
- frame IDs and reassembly buffers;
- flood token buckets and counters;
- TAP handle and shutdown state.

A packet for an unknown network is dropped before session lookup. A session key
derived for one network cannot authenticate another because the signed
transcript includes the network ID. No forwarding entry or reassembly fragment
is moved between networks.

## 7. Local and remote MAC state

Each node maintains:

- a local MAC set learned from valid frames read from its TAP adapter;
- a remote forwarding database mapping unicast source MAC to peer node ID;
- a contested-MAC table used after conflicting remote claims.

The TAP adapter's primary MAC is a permanent local entry while active. Other
unicast source MACs read from TAP may be learned as local dynamic entries for
`mac_age_seconds`. This supports an intentionally bridged host while keeping
state bounded.

Reference limits per network are 32 local dynamic MACs, 4,096 remote entries,
and 256 remote entries per peer. When full, the oldest unrefreshed dynamic entry
is evicted. Permanent local entries are never evicted by network input.

All-zero, broadcast, or multicast source addresses are invalid and never
learned.

## 8. Remote MAC learning

A remote source MAC is eligible for learning only after:

1. the packet and complete frame authenticate under a current peer session;
2. reassembly and Ethernet metadata validation succeed;
3. the peer has `SEND_DATA` permission;
4. the source is valid unicast and not in the local MAC set;
5. the frame is accepted for TAP delivery.

An existing entry from the same peer refreshes its age. A new unclaimed source
creates an entry. Entry lifetime is `mac_age_seconds` since its last accepted
frame and is never extended by control messages or failed data.

Removing a peer, expiring its grant, replacing its session after the grace
period, or applying a newer controller epoch immediately removes its remote MAC
entries.

## 9. MAC conflict handling

If a valid frame claims a source MAC currently mapped to another peer, the node:

1. removes the forwarding entry;
2. marks the MAC contested for 30 seconds;
3. delivers the current valid frame to TAP subject to normal receive policy;
4. treats outbound traffic to that MAC as unknown unicast during the contest;
5. does not learn either remote claimant until the contest expires.

After expiry, the next eligible authenticated source may be learned. Another
conflict restarts the contest. This behavior prevents a transient move from
silently redirecting all unicast to one claimant while preserving delivery by
bounded flooding.

A remote frame whose source is a current local MAC is dropped and counted as a
local-address conflict. It is never allowed to overwrite local ownership.

Membership permits a malicious node to inject arbitrary Layer-2 traffic, so
this rule limits accidental or opportunistic redirection but is not a substitute
for network admission policy.

## 10. TAP-originated forwarding decision

After validating a complete frame from TAP, the node evaluates destination in
this order:

1. If destination is a current local MAC, do not send it to the overlay.
2. If destination is broadcast, replicate to all eligible peers.
3. If destination is multicast, replicate to all eligible peers.
4. If destination is valid unicast with an unexpired, uncontested remote entry
   whose peer has an established eligible session, send to that peer only.
5. Otherwise treat it as unknown unicast and replicate to all eligible peers.

An eligible peer is in the current snapshot, has a valid `RECEIVE_DATA` grant,
matches policy and epoch, and has an established session. A peer without an
established session is not silently omitted forever: the discovery logic starts
or retries a session, while the current frame is dropped for that peer and
counted. Stella does not create an unbounded wait queue for Ethernet frames.

The sender applies flood rate policy before per-peer packet construction. One
accepted flood frame consumes one token regardless of peer count; it then
produces one independently protected packet stream per eligible peer.

## 11. Transport-originated forwarding decision

A complete authenticated peer frame is:

1. checked against peer send permission and local receive permission;
2. checked against frame size and optional administrator MAC policy;
3. considered for remote MAC learning;
4. written once to the network TAP adapter.

It is never forwarded to another peer. This split-horizon invariant is
mandatory even when the host has bridged its TAP adapter to another interface.
Any further physical bridging is operating-system behavior outside Stella.

## 12. Policy updates

Policy is an atomic signed-and-digested object. A policy update changes the
controller epoch, issues new grants, invalidates peer sessions, and replaces
the local runtime only after every field validates.

Reducing `max_frame_size` drops larger queued or incomplete frames. Reducing
flood limits replaces token buckets without preserving excess tokens. Changing
confidentiality causes a complete rekey. A client that cannot enforce a policy
does not join or remain partially active.

## 13. Shutdown ordering

To stop or leave one network, a client:

1. disables new TAP reads and peer handshakes;
2. cancels bounded frame queues;
3. removes peer sessions and secret keys;
4. removes forwarding and reassembly state;
5. closes the TAP handle and restores configuration it owns;
6. reports leave state to the controller when the control channel is available.

Process shutdown performs this sequence for every network before closing the
control connection. A crash may skip cleanup; the next start reconciles owned
adapter state and the controller eventually withdraws liveness through leases.

## 14. Required tests

Network-model tests cover:

- isolation of identical MAC, frame ID, and session values across networks;
- activation and teardown with no forwarding window outside `Active`;
- broadcast, multicast, known-unicast, and unknown-unicast decisions;
- FDB learning only after complete authentication and reassembly;
- aging, limits, peer removal, and epoch invalidation;
- local MAC protection and remote MAC conflict quarantine;
- flood rate behavior and no unbounded frame queue;
- one TAP adapter per network and restoration on graceful shutdown.
