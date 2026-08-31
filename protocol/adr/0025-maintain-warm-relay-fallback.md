# ADR 0025: Maintain a warm relay fallback

- Status: Accepted
- Date: 2026-08-31

## Context

ICE cannot make every pair of networks directly reachable. Symmetric NAT,
carrier policy, campus filtering, and complete UDP blocking require an outbound
connection to a reachable service. Waiting for every direct attempt to time out
before opening that connection produces long and unpredictable game startup
delays.

The existing controller connection carries ordered authority messages. Mixing
high-volume data with that stream would introduce head-of-line blocking,
complicate admission limits, and allow data congestion to delay revocation and
heartbeat processing.

## Decision

Every active Stella 0.2 client maintains at least one bounded relay allocation
or connection while it is online. Direct ICE checks and relay readiness proceed
in parallel. A peer may exchange protected data over the relay immediately and
upgrade to a nominated direct path later without waiting for a new membership
operation.

The first standards-based relay profile is TURN. A deployment must offer a
client-to-relay carrier over TLS on TCP port 443 in addition to any UDP carrier.
The controller issues short-lived relay credentials scoped by deployment,
identity, expiry, and resource policy. A co-located TURN service or a separately
scaled relay process is permitted, but relay traffic never shares the ordered
controller application stream.

For networks that permit only HTTPS through an explicit proxy or protocol-aware
firewall, the reference deployment will also provide a secure WebSocket carrier
on TCP 443. It preserves bounded datagram records and the same authorization and
quota model; it is a fallback carrier, not a different Stella security mode.

The relay routes complete Stella datagrams and is not given peer session keys.
It authenticates clients, applies permissions, rate limits, allocation bounds,
idle expiry, and backpressure, but it does not decrypt, parse, learn, or modify
Ethernet frames. Relayed packets still require the complete Stella peer
handshake and normal replay protection.

## Consequences

Nodes behind incompatible NATs or UDP-blocking firewalls retain connectivity as
long as they can establish the permitted outbound relay carrier. A warm relay
provides predictable connection latency and a safe path during direct-path
probing, network changes, and NAT rebinding.

Relayed traffic consumes server bandwidth and adds stream head-of-line blocking
when TLS/TCP or WebSocket is used. Stella therefore prefers a healthy direct
path, keeps relay queues bounded, and continues low-rate direct checks while a
relay path is selected.

Operators must provision relay bandwidth and a certificate/deployment profile
appropriate to the target firewall. Multiple regional relays and latency-aware
selection are compatible future extensions; one co-located relay is sufficient
for the first 32-node default and 100-node validation ceiling.
