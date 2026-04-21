# Probe Packet Format

## 1. Purpose

This document defines the first protocol skeleton for:

- peer path probing
- direct session establishment
- path confirmation
- relay-aware session bootstrap

It is intentionally narrower than the full overlay packet protocol.

Its purpose is to let nodes:

- discover whether a candidate endpoint is reachable
- prove which peer sent a probe
- confirm bidirectional reachability
- activate a direct path without involving Layer 2 forwarding logic

## 2. Design Goals

The probe protocol should be:

- datagram-friendly
- small
- authenticated
- replay-resistant enough for session setup
- independent from the Layer 2 payload format
- usable over direct UDP and, when needed, through relay-assisted coordination

The probe protocol is not intended to:

- carry ordinary Ethernet frames
- provide bulk data transport
- implement a fully reliable control stream

## 3. Why Probe Traffic Needs Its Own Format

Normal overlay data packets should not be reused as hole-punch traffic.

Probe traffic has different requirements:

- it needs to be valid before a direct path is established
- it needs to identify the sender and intended session context
- it needs to confirm candidate endpoint success
- it should be cheap enough to send repeatedly during punch windows

Keeping probe traffic separate gives us:

- clearer logs
- simpler validation rules
- easier NAT debugging
- flexibility to evolve the data plane later

## 4. Protocol Layering

The recommended initial layering is:

1. outer UDP datagram
2. probe header
3. authenticated probe body

The probe protocol should sit below:

- peer session activation
- encrypted frame transport

And above:

- raw socket send/receive

## 5. Basic Packet Types

The MVP probe protocol should define these packet types:

1. `PROBE_INIT`
   - first packet sent to a candidate endpoint

2. `PROBE_ACK`
   - sent in response to a valid `PROBE_INIT`

3. `PROBE_CONFIRM`
   - sent after receiving a valid `PROBE_ACK` to confirm bidirectional reachability

4. `KEEPALIVE`
   - low-cost packet used to keep a direct path alive once active

5. `PATH_DEGRADE_HINT`
   - optional future packet for informing a peer that this path is unhealthy

Only the first four are needed for MVP.

## 6. Handshake Model

The recommended direct-path handshake is a lightweight 3-step exchange:

1. `PROBE_INIT`
2. `PROBE_ACK`
3. `PROBE_CONFIRM`

This is useful because:

- a single packet receipt is not always enough to trust path activation
- symmetric NAT punch windows benefit from both sides sending
- the final confirm lets both peers mark the path as truly active

This is conceptually similar to treating path establishment as:

- reachability attempt
- authenticated response
- activation confirmation

## 7. Required Packet Fields

Every probe packet should contain at least:

- protocol version
- packet type
- sender node ID
- intended remote node ID
- session bootstrap ID
- packet sequence number or nonce
- timestamp
- path ID or candidate ID
- authentication tag or signature-derived authenticator

These fields allow:

- basic protocol negotiation
- sender identification
- correlation across retries
- anti-confusion between different peers or sessions
- per-path tracking

## 8. Recommended Header Shape

The exact binary layout can change later, but the MVP should aim for a compact fixed header.

Suggested logical structure:

- magic bytes
- version
- packet type
- flags
- sender node ID
- target node ID
- session bootstrap ID
- path candidate ID
- sequence or nonce
- timestamp
- authenticator

The body for MVP can remain minimal or even empty for some packet types.

## 9. Identity Binding

Probe packets must be bound to node identity.

This is necessary so a node can answer:

- who sent this probe
- whether this probe matches the expected peer
- whether this packet is part of the current session bootstrap

Recommended model:

- long-term node identity exists already from control-plane registration
- controller distributes the peer's public identity material
- probe packets include enough authenticated material to prove that the sender is the expected peer

For MVP, this can be done with:

- a signed or MAC-authenticated handshake token derived from controller-issued bootstrap data

This avoids needing a full heavy handshake at the hole-punch layer.

## 10. Session Bootstrap ID

Each controller-assisted peer establishment should create a short-lived bootstrap context.

This context should have a `session bootstrap ID`.

Why:

- multiple probe attempts may occur over time for the same peer pair
- peers may re-probe while a relay path is active
- old packets should not activate stale paths

The bootstrap ID should therefore:

- be unique per peer-establishment attempt window
- expire quickly
- be included in all probe packets for that attempt

## 11. Candidate And Path IDs

The protocol should distinguish between:

- a peer
- a session bootstrap
- a specific candidate path

This means probe packets should carry a candidate or path identifier so the receiver can log and score:

- which remote endpoint worked
- which local socket received it
- which path later became preferred

This will matter for:

- multi-interface systems
- mapped-port vs STUN endpoint comparison
- future multipath support

## 12. Authenticity Model

The probe protocol should not trust unauthenticated packets.

At minimum, the receiver should be able to verify:

- the packet is for this node
- the packet belongs to a known bootstrap context
- the sender is the expected peer for that bootstrap
- the packet was not trivially forged

Recommended MVP approach:

- controller issues a short-lived per-peer bootstrap secret or token set
- probe packets include an HMAC or AEAD-based authenticator using this short-lived material

Why this is attractive:

- cheaper than full asymmetric signatures on every probe packet
- good enough for rapid repeated probing
- naturally expires with bootstrap context

Long-term identity still matters, but short-lived bootstrap secrets are a better fit for active probe traffic.

## 13. Replay Handling

The probe protocol should include basic replay handling.

For MVP, sufficient measures are:

- session bootstrap ID
- short packet lifetime
- sequence or nonce tracking within the bootstrap window

We do not need industrial-strength anti-replay logic at this stage, but we should not let stale probe packets reactivate dead paths.

## 14. Packet Semantics

### 14.1 PROBE_INIT

Purpose:

- test whether a candidate endpoint can receive traffic
- initiate a punch window

Receiver behavior:

- validate packet
- record candidate observation
- send `PROBE_ACK`

### 14.2 PROBE_ACK

Purpose:

- confirm that the remote side received the probe
- prove reverse-path response is possible

Receiver behavior:

- validate packet
- record RTT sample if possible
- mark path as promising
- send `PROBE_CONFIRM`

### 14.3 PROBE_CONFIRM

Purpose:

- finalize direct path activation

Receiver behavior:

- validate packet
- mark path active
- start keepalive schedule

### 14.4 KEEPALIVE

Purpose:

- keep NAT mapping alive
- refresh path health

Receiver behavior:

- validate packet
- refresh path liveness

## 15. Path Activation Rule

A direct path should not become `direct_active` on first packet sighting alone.

Recommended MVP rule:

- mark as `candidate_seen` on valid `PROBE_INIT`
- mark as `candidate_replied` on `PROBE_ACK`
- mark as `direct_active` only after successful `PROBE_CONFIRM` or an equivalent bidirectional success rule

This gives cleaner path semantics and fewer false positives.

## 16. Multi-Candidate Probing

During a punch window, a node may send probes to multiple candidate endpoints for the same peer.

This is expected.

The receiver should therefore:

- tolerate multiple candidate IDs for the same bootstrap
- keep the best successful path
- retain alternates as backup candidates

The sender should:

- stop aggressive probing once a preferred direct path is established
- continue low-rate validation of alternates only if useful

## 17. Timeouts And Retry Policy

The protocol document should define logical timers even if exact values remain implementation-tunable.

Recommended timer categories:

- bootstrap lifetime
- initial probe retry interval
- total direct-probe budget before relay fallback
- keepalive interval
- path idle timeout
- reprobe interval while relayed

We do not need exact constants in this document, but the state machine should assume they exist.

## 18. Relay Interaction

Relay should help session establishment, but should not replace the probe protocol.

Recommended behavior:

- controller provides relay metadata
- relay can carry coordination traffic if needed
- direct probe packets are still sent over UDP candidate endpoints
- once relay is active, nodes may continue background direct probing

Optional later enhancement:

- relay-assisted `call me maybe`-style nudges
- relay-carried probe coordination messages

This is conceptually similar to Tailscale's use of relay-assisted discovery messages without making relay the final preferred path.

## 19. Logging Requirements

Every probe event should be easy to log.

Recommended per-event fields:

- local node ID
- remote node ID
- session bootstrap ID
- packet type
- candidate/path ID
- local socket
- remote observed endpoint
- validation result
- RTT sample if available
- state transition caused by the packet

This will be essential for real-world game debugging.

## 20. Error Handling

Probe packets should fail closed.

If validation fails, the packet should be dropped and counted.

Useful drop reasons:

- unknown bootstrap ID
- wrong target node ID
- bad authenticator
- expired bootstrap
- stale sequence
- malformed packet

These reasons should be visible in diagnostics.

## 21. Relationship To Future Data Packets

The probe protocol should lead into, but remain separate from, the ordinary session data format.

After direct activation, peers should transition to a data session abstraction that can carry:

- Layer 2 frames
- future control messages
- optional reliability metadata

The probe protocol therefore should not attempt to become the full data protocol.

## 22. Recommended MVP Summary

The MVP probe protocol should implement:

- `PROBE_INIT`
- `PROBE_ACK`
- `PROBE_CONFIRM`
- `KEEPALIVE`
- controller-issued short-lived bootstrap context
- authenticated compact probe headers
- candidate/path identification
- explicit activation only after bidirectional confirmation

This gives us a clean and extensible base for direct-path establishment.

## 23. Immediate Follow-Up

After this document, the next useful protocol documents are:

1. `controller-api.md`
   - how bootstrap IDs, candidate lists, and relay metadata are distributed

2. `overlay-packet-format.md`
   - how ordinary post-handshake session packets carry Layer 2 frames

3. `path-state-machine.md`
   - exact timers, transitions, and relay/direct switching logic
