# ADR 0038: Keep bounded relay hot standby paths

- Status: Accepted
- Date: 2026-09-13
- Supersedes: ADR 0025's single-allocation deployment baseline

## Context

A single warm relay removes the direct-connectivity timeout from startup, but
it remains one live failure point. Restarting that relay, losing one carrier,
or changing firewall policy withdraws the only relay candidate while the client
creates a replacement. Direct sessions survive that event, but relay-only peers
temporarily lose their usable path.

Reliable relay carriers also make one send await stream I/O and permission work.
If the native data runtime waits for that operation, a slow TCP, TLS, or secure
WebSocket carrier delays unrelated direct UDP, TAP, control, and relay work.

## Decision

The reference client keeps at most two distinct warm relay paths, identified by
the exact `(relay-id, carrier)` pair. Selection retains controller priority and
the UDP, TCP, TLS, then secure WebSocket fallback order. Duplicate numeric
addresses for one path identity do not consume the second slot.

Both allocations are published as strictly ordered relay candidates and receive
traffic concurrently. Outbound relay routing selects the allocation whose
relay identity and carrier exactly match the peer endpoint. Permissions are
prepared only on that matching allocation.

Failure removes only the affected relay path. Direct sessions and the other
warm relay remain installed while a background task replenishes the empty slot
with bounded carrier deadlines and full-jitter reconnect backoff. Connectivity
generation rotation advertises the surviving set immediately.

Each allocation has a bounded client command queue. The data runtime enqueues a
complete datagram without waiting for relay socket or stream I/O. Queue overflow
drops the new relayed datagram, while an asynchronous delivery failure stops the
affected allocation and reaches the normal relay recovery path.

## Consequences

Relay-only nodes can continue through an already established alternate carrier
or service while one allocation is replaced. Slow reliable relay I/O no longer
blocks direct traffic or another allocation in the client event loop.

The second allocation consumes relay state and keepalive bandwidth even when it
is not selected by a peer session. Deployments must account for that bounded
cost. Two paths improve availability but do not provide latency-aware regional
selection; measured path scoring remains a separate decision.
