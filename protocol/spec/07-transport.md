# Stella Data Transport

- Status: Draft
- Protocol version: 0.1
- Last updated: 2026-08-29

## 1. Scope

This document defines the replaceable datagram transport contract, the version
0.1 UDP transport, endpoint semantics, path-size handling, socket behavior,
backpressure, keepalive integration, errors, and use over private underlays.

Transport delivers Stella datagrams. It does not authenticate nodes, authorize
networks, parse Ethernet, select flood recipients, or provide a reliable byte
stream.

## 2. Required transport semantics

A Stella transport provides:

- one complete received datagram and its numeric source endpoint;
- atomic send of one complete datagram to one endpoint;
- local listening endpoints suitable for controller publication;
- a conservative maximum datagram size;
- cancellation and bounded shutdown;
- typed transient, permanent, address, permission, and size errors.

It preserves datagram boundaries exactly. A transport that internally uses a
stream must add its own authenticated, bounded record layer below Stella and
present only complete datagrams; no such transport is standardized in version
0.1.

Delivery may lose, duplicate, reorder, or delay datagrams. Stella data-plane
security and replay handling assume all of those are possible.

## 3. UDP transport

Version 0.1 transport kind 1 is UDP over IPv4 or IPv6. A node binds one or more
explicit sockets and publishes numeric endpoint records through the controller.

The implementation:

- enables normal UDP checksums and does not request checksum disablement;
- uses separate IPv4 and IPv6 sockets unless a dual-stack socket has been
  verified to report unambiguous source families;
- treats one successful receive call as one Stella datagram;
- rejects truncated datagrams instead of parsing the visible prefix;
- never concatenates Stella packets into one UDP datagram;
- never splits one Stella packet across multiple UDP datagrams;
- accepts datagrams only after the common length checks and later Stella
  authentication succeed.

The absolute UDP payload ceiling advertised by Stella is 65,507 bytes. The
protocol frame ceiling is much smaller, and implementations normally advertise
1,200 bytes.

## 4. Path datagram size

The sender's effective maximum for a peer is the minimum of:

- local transport send limit;
- remote endpoint receive limit;
- remote handshake `max_datagram_size`;
- administrator-configured ceiling;
- any smaller size learned from a local socket size error.

Version 0.1 begins at 1,200 bytes unless the deployment explicitly configures a
verified larger path. This value is safe for common IPv6 and overlay paths and
leaves Stella to fragment Ethernet frames without relying on IP fragmentation.

UDP sockets SHOULD request do-not-fragment behavior where the operating system
supports it consistently. On a `message too long` or equivalent path-size
error, the transport lowers its local ceiling, abandons the affected logical
Ethernet frame for that peer, republishes capability when necessary, and
establishes a new session. It does not retry the same protected fragment under
a different size or nonce.

ICMP path errors are hints, not identity or authorization. A value below the
minimum needed for the 88-byte keepalive header plus tag is a path failure.

## 5. Fragment interaction

For `DATA`, maximum fragment bytes are:

```text
effective_max_datagram - actual_header_length - 16
```

The result must be positive. The sender creates authenticated Stella fragments
as defined by the wire format. Transport never sees a partial Stella packet and
never reassembles Ethernet frames.

One frame uses one peer session and one effective size. If the size changes
mid-frame, remaining fragments are not sent and the complete logical frame is
counted as a path-size drop for that peer.

## 6. Endpoint and source handling

Endpoint records are numeric and include address, port, priority, and receive
limit. Transport routing or socket success does not validate a Stella peer.

The receiver supplies the exact source IP and port to discovery and session
logic. A handshake response is sent to the authenticated initiation's observed
source. An established version 0.1 session accepts packets only from its pinned
source tuple.

The UDP socket may receive packets for many networks and peers. Demultiplexing
starts with bounded common-header parsing, then network, sender, and session
lookup. No endpoint alone selects a key.

## 7. Authenticated keepalive

When a session has sent no `DATA` or keepalive for 15 seconds, it sends a
protected `KEEPALIVE`. A received keepalive requests a response when its probe
has not already been echoed. Data or keepalive receipt updates inbound liveness;
successful local send does not prove remote receipt.

Keepalive uses the normal directional data key, nonce prefix, sequence space,
replay window, epoch, and endpoint pin. It contains no Ethernet frame and never
affects MAC learning or TAP state.

Three unanswered intervals mark the path unavailable. A transport may send
more frequent underlay-specific packets internally, but those packets are not
Stella liveness proof and cannot keep authorization active.

## 8. Queueing and backpressure

The client uses bounded queues between TAP classification, cryptographic packet
construction, and transport send. Recommended reference bounds per network are
256 complete TAP frames and per peer are 128 protected datagrams, subject to a
memory ceiling.

Known-unicast overflow drops that frame for its peer. Flood replication handles
each peer independently; a full queue for one peer does not block others.
Control messages and peer handshakes do not share an unbounded queue with data
frames.

The UDP receiver processes or hands off each datagram through a bounded path.
When overloaded, it drops new datagrams before allocating large reassembly
state. Backpressure never blocks the operating-system receive loop indefinitely.

## 9. Cancellation and shutdown

Transport receive and send operations are cancellable. Shutdown:

1. stops accepting new TAP frames;
2. cancels session discovery and keepalive timers;
3. drains no more than the configured short deadline;
4. closes sockets to wake pending receives;
5. erases queued protected packets and session keys in upper layers.

UDP has no connection close handshake. A node SHOULD withdraw endpoints over
the control plane before closing when graceful shutdown time permits.

## 10. Error classes

Transport reports at least:

- invalid or unsupported endpoint;
- bind permission or address failure;
- endpoint unreachable or route failure;
- datagram too large;
- receive truncation;
- transient operating-system resource exhaustion;
- local shutdown or cancellation;
- permanent socket failure.

Errors include safe operating-system codes and endpoint metadata but no frame
payload, key, token, or decrypted data. Repeated identical errors are sampled.

Transient errors use bounded retry. Permanent bind failure prevents endpoint
publication. Size errors trigger the path behavior above. Authentication errors
belong to the protocol layer, not transport.

## 11. Windows UDP behavior

The reference Windows backend uses overlapped or Tokio-managed Winsock I/O and
does not block asynchronous runtime workers. It accounts for `WSAEMSGSIZE` as a
size/truncation signal, uses explicit socket cancellation during shutdown, and
publishes only addresses belonging to currently usable interfaces.

Windows Firewall rules are an installation concern. The client reports the
bound protocol, address, and port needed by an administrator but does not
silently disable or broadly weaken the firewall.

## 12. Tailscale carriage

Tailscale integration uses the same UDP transport bound to or routed through a
tailnet address. There is no Tailscale-specific wire format or trust shortcut.
The endpoint record remains UDP, and the effective datagram size remains
conservative because the tailnet adds its own encapsulation.

The Stella controller may itself be reached over Tailscale, but that does not
replace TLS certificate validation or Stella controller proofs.

## 13. Future transports

A future transport receives a new endpoint kind and ADR. It must preserve:

- complete bounded datagrams;
- numeric or canonical endpoint representation;
- source endpoint reporting;
- per-datagram size limits;
- cancellation and bounded queues;
- the untrusted-delivery security model.

Peers advertise supported endpoint kinds through a versioned extension before
using them. An implementation never guesses that an unknown endpoint record is
UDP-compatible.

## 14. Required tests

Transport tests cover:

- IPv4 and IPv6 loopback datagram boundaries;
- truncation and exact maximum-size behavior;
- loss, duplication, and reordering simulation;
- effective-size selection and Stella fragmentation;
- size-error reduction without nonce reuse;
- source tuple reporting and established-session pinning;
- keepalive echo, replay, timeout, and no MAC learning;
- queue overflow isolation between peers;
- cancellation of pending Windows receives and graceful socket close;
- UDP over a Tailscale-style private address route.
