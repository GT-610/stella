# Stella Broadcast, Multicast, and Unknown Unicast

- Status: Draft
- Protocol version: 0.1
- Last updated: 2026-08-29

## 1. Scope

This document defines Ethernet flood classification, bounded head-end
replication, ARP and discovery behavior, multicast handling, unknown unicast,
rate control, peer eligibility, loss behavior, and loop prevention.

## 2. Flood classes

A valid TAP-originated frame enters the flood path when its destination is:

- broadcast: `ff:ff:ff:ff:ff:ff`;
- multicast: group bit set and not the broadcast address;
- unknown unicast: group bit clear, not local, and no usable unexpired remote
  forwarding entry exists.

Classification uses the destination bytes in the Ethernet frame, not an outer
IP address, EtherType, or caller-provided hint. Known unicast never deliberately
enters the flood path.

Version 0.1 floods all Ethernet multicast. It does not implement IGMP snooping,
MLD snooping, multicast membership proxies, or underlay IP multicast.

## 3. Replication set

The sender takes one atomic peer snapshot for each accepted flood frame. The
replication set contains every other current network member that:

- has a valid grant matching network, controller, epoch, and policy;
- has `RECEIVE_DATA` permission;
- has an established peer session under that state;
- is not locally suspended, expired, or being removed.

Peer snapshot changes during replication apply to the next TAP frame. This
prevents a frame from being partly evaluated under two revisions.

For each selected peer, the sender creates one or more independently protected
fragments using that peer session's key, session ID, sequence numbers, and
transport endpoint. A packet or ciphertext is never copied verbatim between
peers.

The controller and control connection are not in the data path. Version 0.1 has
no controller relay fallback.

## 4. Membership bound

The controller refuses membership that would make total authorized flood
participants exceed network `max_flood_peers`. The reference default is 64 and
the protocol maximum is 256.

A client rejects a snapshot beyond the signed limit. It does not truncate the
peer list or replicate to an arbitrary subset, because silent omission would
break Ethernet broadcast semantics in a topology-dependent way.

An authorized peer without an established session cannot receive the current
frame. The sender increments a per-peer `flood_no_session` counter and ensures
discovery is active, but it does not hold an unbounded frame queue. Ethernet and
UDP are best effort; later frames may succeed after session establishment.

## 5. Rate control

Each network has separate local-origin token buckets for:

- broadcast;
- multicast;
- unknown unicast.

Each bucket uses the signed `flood_rate` and `flood_burst` as ceilings. The
reference implementation initializes a bucket full. Using monotonic elapsed
time, it replenishes:

```text
tokens = min(flood_burst, tokens + elapsed_seconds * flood_rate)
```

One accepted Ethernet frame consumes one token before replication, regardless
of frame size, fragment count, or peer count. When no token is available, the
complete frame is dropped before encryption and counted by class. Tokens and
elapsed arithmetic use sufficient precision and saturating bounds; wall-clock
changes do not affect them.

Receivers also apply an independent per-peer flood safety limit. The reference
ceiling is twice the signed local rate with twice the burst. Exceeding it drops
the authenticated frame before TAP delivery but does not tear down a session
unless sustained abuse triggers local administrative policy.

No flood queue grows without a fixed capacity. When an implementation uses a
bounded worker queue, overflow drops the newest complete TAP frame and records
the reason.

## 6. Broadcast behavior

Ethernet broadcast bytes are preserved exactly. Stella does not inspect an IPv4
broadcast address or rewrite a Layer-3 checksum.

Important broadcast protocols therefore work naturally:

- an ARP request is replicated to every eligible peer;
- a DHCPv4 discovery or request is replicated to every eligible peer;
- NetBIOS name service and browser broadcasts are replicated unchanged;
- application and LAN-game UDP broadcasts are replicated unchanged;
- an all-ones destination carrying an uncommon EtherType is treated identically.

Stella does not provide proxy ARP, DHCP service, broadcast address translation,
or duplicate-response suppression. If a network contains multiple DHCP or game
servers, the host applications see their normal Ethernet behavior.

## 7. ARP

ARP is not a Stella control protocol. Nodes neither answer ARP for remote peers
nor distribute IP-to-MAC bindings through the controller.

Typical flow is:

1. Host A writes a broadcast ARP request to its TAP adapter.
2. Stella A replicates the unchanged Ethernet frame to eligible peers.
3. Stella B writes it to TAP B.
4. Host B generates a unicast ARP reply.
5. Stella B sends the reply by learned unicast when possible, or unknown-unicast
   replication before its forwarding entry exists.

ARP source and target fields are not used for Stella identity or authorization.
Malformed ARP that is still a valid Ethernet frame is an operating-system
policy concern unless an administrator configures a Layer-2 filter outside the
base protocol.

## 8. IPv6 multicast and neighbor discovery

IPv6 neighbor discovery, router discovery, duplicate-address detection, mDNS,
and many applications use Ethernet multicast. Version 0.1 replicates those
frames to all eligible peers without interpreting IPv6 extension headers or
multicast scope.

Stella does not act as an IPv6 router, multicast listener, or neighbor proxy.
Solicited-node multicast remains a normal Ethernet multicast frame. Future MLD
snooping may reduce recipients only through an explicitly negotiated extension
that preserves fallback compatibility.

## 9. Unknown unicast

Unknown unicast occurs when no current uncontested forwarding entry selects a
peer. Causes include first contact, MAC aging, peer rekey, contested MACs, or
lost learning traffic.

The sender replicates the frame to every eligible peer. Receivers write it to
their TAP adapters; their host networking stacks decide whether the destination
is local. Stella nodes do not forward the received frame onward.

Learning from authenticated source traffic normally converts later replies to
known unicast. A contested MAC remains unknown for its conflict interval.

The protocol does not provide a configuration that silently drops all unknown
unicast in version 0.1 because doing so would break transparent switch behavior.
An administrator may apply an explicit local filter outside an interoperable
network, but cannot advertise that behavior as standard Stella 0.1.

## 10. Duplicate and loss behavior

One sender transmits one logical copy per peer snapshot member. UDP loss may
remove a copy or fragment; Stella does not retransmit Ethernet data. A complete
duplicate fragment is ignored by replay and reassembly rules. A duplicate
complete packet with the same sequence number is a replay and is not written to
TAP twice.

If any fragment is missing, reassembly times out and the entire frame is
dropped. Later Ethernet protocols may retry according to their own semantics.

Session changes during fragmentation do not mix keys. A frame whose fragments
cannot all be emitted under one still-valid session is abandoned for that peer.

## 11. Loop prevention

The mandatory split-horizon invariant is:

```text
only TAP-originated frames are eligible for peer forwarding
```

A frame received from a Stella transport is authenticated, reassembled,
validated, and written once to local TAP. It never re-enters peer selection,
even if its destination is broadcast or multicast.

An operating-system bridge may copy that frame back into a TAP read path. The
network model's local/remote MAC checks, normal bridge behavior, and rate limits
reduce damage, but administrators are responsible for avoiding external
physical Layer-2 loops. Stella version 0.1 does not run STP.

## 12. Ordering and fairness

Stella does not guarantee ordering between different peers or transports.
Within one peer session, packets receive increasing sequence numbers, but UDP
and independent fragment processing may reorder them.

An implementation SHOULD rotate or fairly schedule peer send work so a slow or
blocked socket destination cannot starve other peers. One peer's full bounded
queue drops only that peer's copy. It does not block the TAP reader indefinitely
or prevent copies to healthy peers.

## 13. Observability

Per-network counters distinguish:

- accepted broadcast, multicast, and unknown-unicast frames;
- rate-limited frames by class;
- intended peer copies;
- peers omitted because no current session exists;
- per-peer send, MTU, and queue failures;
- receive safety-limit drops;
- reassembly timeout and replay drops.

Counters do not contain payload bytes. Logs sample repeated storm events and do
not emit one line per dropped broadcast.

## 14. Required tests

Broadcast tests include:

- ARP request and unicast reply across two peers;
- IPv4 limited broadcast and application UDP broadcast;
- IPv6 neighbor discovery and multicast;
- unknown unicast before learning and known unicast afterward;
- exact recipient set under snapshot replacement;
- independent ciphertext and sequence spaces per peer;
- token-bucket refill, burst, class separation, and overflow;
- missing session, fragment loss, duplicate, replay, and reassembly timeout;
- split horizon with broadcast received from a peer;
- fairness when one peer send path is blocked.
