# ADR 0023: Bound the Windows client data runtime

- Status: Accepted
- Date: 2026-08-31

## Context

An active Windows client must combine authoritative controller snapshots,
TAP-Windows blocking I/O, one UDP socket, peer handshakes, protected packet
sessions, and Layer-2 switching without allowing one slow component to create
unbounded memory growth or to weaken authentication. TAP reads cannot run on a
Tokio executor thread, while UDP, controller updates, heartbeat deadlines, and
maintenance timers must remain concurrently responsive.

Peer endpoint sets are delivery candidates rather than established path
authority. Accepting a protected packet from any currently advertised endpoint
would silently migrate a session and could redirect replies without completing
a fresh handshake. Rekey also needs to absorb datagrams reordered around the
new session confirmation without retaining revoked authority.

## Decision

One `ClientDataRuntime` owns one bounded UDP socket and one isolated
`NetworkDataPlane` per active network. Each network owns exactly one selected
TAP-Windows adapter and a dedicated blocking worker thread. TAP-to-runtime
events and runtime-to-TAP writes use bounded queues. Queue overflow drops the
affected frame and reports a typed diagnostic; it never grows an unbounded
backlog. Cancellation uses the TAP device cancellation handle, and shutdown
waits for every worker to disconnect and release its adapter.

The active client loop selects among controller updates, heartbeat deadlines,
100-millisecond data maintenance ticks, UDP datagrams, and TAP events. A
controller snapshot is reconciled before later frames use it. Epoch, policy,
grant, peer, or endpoint changes erase affected sessions and forwarding state.
Malformed or unauthenticated peer datagrams are dropped without reconnecting
the authenticated controller session; transport, TAP, or worker failures end
the active session and trigger the normal fail-closed reconnect path.

Handshake replies use the observed authorized source tuple. Once confirmation
completes, the session is pinned to that exact IP address and UDP port until a
new handshake. Data fragments and keepalives share one authenticated sequence
and replay window. Fifteen seconds without authenticated path activity emits a
keepalive; three unanswered probes retire the path and restart discovery.

Routine rekey starts ten seconds before the session lifetime deadline or at the
protected-packet limit. The old session stops sending while replacement keys
are negotiated. After confirmation it remains receive-only for at most 30
seconds, then its keys and replay state are erased. Revocation, grant, policy,
epoch, endpoint, and keepalive failures remove active and retired sessions
immediately without grace.

## Consequences

The Windows runtime has explicit ownership, congestion, cancellation, and
shutdown behavior. A stalled TAP consumer cannot consume arbitrary memory, and
an unexpected source tuple cannot migrate an established session. Reordered
datagrams may survive routine rekey, while authority changes remain
fail-closed.

The first implementation uses one blocking thread per active TAP adapter and
one shared UDP receive buffer. Queue overflow is observable packet loss rather
than backpressure into the operating-system TAP path. Future batching or IOCP
work may change the internal mechanism, but it must preserve these bounds,
path-pinning rules, and shutdown semantics.

An adapter's local IP MTU may remain below the signed network frame ceiling;
the ceiling constrains accepted Ethernet frames but does not require the
runtime to raise a conservative host setting. An adapter above the ceiling is
lowered before activation, and failure to enforce that upper bound remains
fatal.
