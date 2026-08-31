# ADR 0024: Use ICE and STUN for automatic peer connectivity

- Status: Accepted
- Date: 2026-08-31

## Context

Version 0.1 distributes administrator-configured numeric UDP endpoints. That is
sufficient on a routed underlay, but it does not discover NAT mappings,
coordinate simultaneous UDP traffic, distinguish a usable candidate from a
published address, or recover when a mapping changes. Requiring port forwarding
would exclude the home, campus, carrier-grade NAT, and symmetric-NAT deployments
that Stella is intended to connect.

NAT traversal has subtle timing, nomination, role, retransmission, and
anti-amplification requirements. A Stella-specific collection of unrelated
probes would repeat well-known ICE and STUN mechanisms while making independent
implementations harder to validate.

## Decision

Stella 0.2 uses the candidate, connectivity-check, pair-priority, nomination,
and consent concepts from ICE as specified by RFC 8445. Server-reflexive
candidate discovery uses STUN as specified by RFC 8489. The reference
implementation will evaluate maintained implementations of those standards
before adding a new dependency; this ADR selects protocol behavior, not a
particular library.

Each client gathers bounded candidate generations from the same UDP socket that
will carry direct Stella packets. A generation can include host, globally
routable IPv6, server-reflexive, automatically mapped, peer-reflexive, and relay
candidates. Manual port forwarding is never required. PCP, NAT-PMP, and UPnP may
add mapped candidates, but failure or absence of those mechanisms is normal.

The authenticated controller is the signaling channel for short-lived ICE
credentials and candidate generations between authorized peers. It does not
declare a path successful. Both peers run connectivity checks, and a candidate
pair becomes usable only after bidirectional checks and nomination. Node-ID
ordering supplies a deterministic role tie breaker when a library does not
already provide a stronger random ICE tie breaker.

Candidate addresses remain untrusted routing hints. ICE credentials prove only
possession of one short-lived connectivity generation. A nominated pair cannot
authorize membership or deliver Ethernet frames until the normal Stella peer
handshake authenticates both identities, grants, network context, and packet
keys.

## Consequences

Ordinary endpoint-independent and port-restricted NATs can establish direct UDP
paths without administrator action. Global IPv6, same-LAN, Tailscale, EasyTier,
and other locally routed addresses can participate as host candidates without a
transport-specific trust shortcut.

Direct connectivity is not guaranteed. Symmetric NAT, UDP blocking, or policy
firewalls can make every UDP candidate pair fail, so an independently reachable
relay is a required part of the target architecture rather than an optional
future optimization.

Candidate exchange reveals address metadata to the controller and authorized
peer. Implementations must bound candidate counts, generations, checks, retries,
and allocations, and must not create protocol or reassembly state from an
unauthenticated STUN packet.
