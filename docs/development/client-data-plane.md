# Client data plane

The native Windows and macOS data runtime connects validated controller state
to a complete-frame TAP backend and direct authenticated UDP peer paths.
Normative packet bytes and timers remain in the protocol specification; this
page describes reference implementation ownership and failure behavior.

## Runtime ownership

One active control session owns one `ClientDataRuntime`. The runtime binds the
configured UDP address once and creates one `NetworkDataPlane` and one exact
TAP worker for every active network snapshot. A network is not created unless
its durable configuration names a matching Windows adapter or complete macOS
feth pair.

The owner binds UDP and opens every TAP endpoint before it publishes its
receive-ready endpoint set. The publication response is reconciled before the
I/O loop becomes active. A peer that has joined but has not published a usable
endpoint is skipped until a later control update; it cannot prevent this node
from becoming reachable. ICE candidate enumeration excludes the configured TAP
interface and, on macOS, its packet-I/O peer.

The runtime never raises an existing IP MTU merely to reach the network frame
ceiling. It keeps a lower value, which remains safe because the signed policy
is a maximum rather than a required local size. Windows updates both IP-family
rows under the TAP-Windows driver ceiling. macOS reads the visible feth MTU on
open and uses `tun-rs` to apply explicit changes to both sides of the pair.

The top-level loop concurrently handles controller updates, heartbeat
deadlines, 100-millisecond data maintenance, UDP reception, and TAP events.
Control reconciliation removes withdrawn networks first, recreates TAP state
when the signed frame-size policy changes, and clears affected sessions and MAC
learning on epoch, grant, peer, policy, or endpoint changes.

## TAP worker boundary

Native TAP reads and writes are blocking operations and run on a dedicated
thread per adapter or pair. Two bounded channels cross that boundary:

- at most 256 TAP events wait for the async runtime;
- at most 64 authenticated frames wait for one TAP writer.

Incoming TAP frames may be dropped when the event queue is full. A full write
queue reports a typed congestion error and drops that frame. Neither direction
creates an unbounded queue. A cancellation handle interrupts a pending read
when a write or shutdown needs the worker. Shutdown joins the thread after
Windows sets media-disconnected or macOS sets the host-visible feth down and
releases the pair lock. The persistent macOS pair is not deleted.

## Peer sessions and forwarding

The smaller node ID initiates the four-message signed X25519 handshake. Replies
are sent to the observed source address after that source is confirmed to be in
the controller-provided endpoint set. The completed session is then pinned to
that exact IP and UDP port; another advertised tuple must complete a new
handshake rather than migrating the session in place.

Authenticated data enters the per-network switch only after session, epoch,
policy, sequence, tag, fragmentation, and Ethernet metadata validation. Remote
frames may be delivered to TAP but are never forwarded directly to another
peer. Local broadcast, multicast, and unknown unicast use bounded head-end
replication; learned unicast selects one established peer.

Data fragments and keepalives share one send sequence and one 1,024-packet
receive replay window. Keepalives are authenticated with empty plaintext, echo
validated probe IDs, and do not affect Ethernet learning. Three unanswered
15-second probes retire the path and start a new handshake.

## Rekey and failure handling

Routine rekey begins ten seconds before session lifetime expiry or when the
protected-packet counter reaches its limit. The old session becomes send
disabled. After replacement confirmation it remains receive-only for 30
seconds so reordered packets can complete, then its keys, replay window, and
reassembly state are erased.

Authority changes and path failure have no grace period. They immediately
remove active and retired sessions plus learned MAC entries. Signed
`SESSION_REJECT` messages are verified against the exact outgoing initiation;
stale epoch, expired grant, policy mismatch, and session collision diagnostics
cannot authorize state and apply bounded retry delay only.

Malformed, unauthenticated, replayed, wrong-session, or wrong-endpoint peer
datagrams are dropped without restarting the controller connection. A Relay
actor or stream failure withdraws only the Relay candidate and starts one
background replacement task. Direct sessions, TAP workers, the UDP socket, and
the controller session continue running while replacement attempts use bounded
DNS and carrier deadlines plus full-jitter backoff from one to 30 seconds. A
successful replacement publishes a fresh local connectivity generation.

A UDP socket, TAP device, or worker failure still closes the data runtime and
erases its forwarding state. A transient control-plane failure leaves an
otherwise healthy runtime active within its existing authorization bounds;
replacement after a data-runtime failure requires a fresh controller
activation.

## Verification

Unit tests cover protected fragmentation, replay commitment, keepalive echo and
timeout, exact endpoint pinning, broadcast and learned unicast, signed session
rejection, and the 30-second old-session receive window. The Windows scenario
under `tests/two-node-lan/` uses two TAP-Windows adapters. The macOS scenario
uses two real feth pairs, verifies the same ARP, IPv4 broadcast/multicast,
bidirectional traffic, and LAN discovery, then restarts the clients to verify
persistent pair reuse.
