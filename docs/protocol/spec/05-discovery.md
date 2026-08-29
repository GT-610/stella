# Stella Peer Discovery and Reachability

- Status: Draft
- Protocol version: 0.1
- Last updated: 2026-08-29

## 1. Scope

This document defines controller-assisted peer discovery, endpoint publication,
candidate ordering, session initiation, endpoint validation, liveness, address
changes, and failure behavior. Version 0.1 does not implement STUN, TURN, ICE,
port mapping, controller data relay, or a separate discovery service.

## 2. Discovery inputs

For each authorized peer, the controller supplies:

- node ID and Ed25519 public key;
- signed membership grant;
- zero through eight numeric UDP endpoints;
- controller epoch and snapshot revision;
- canonical network policy.

The peer record is authorization metadata only after its grant and controller
state validate. Endpoints are untrusted delivery candidates. DNS names are not
distributed in peer records; the publishing node resolves or selects its own
numeric addresses before publication.

## 3. Endpoint publication

A node publishes endpoints only after it has bound and is ready to receive on
them. Each endpoint includes address family, numeric address, UDP port,
priority, and maximum receivable Stella datagram.

The node SHOULD publish only addresses that another network member could route
to in the intended underlay. Private, link-local, or tailnet addresses are valid
when the deployment uses that reachability domain. A controller MAY enforce an
administrative allowlist but MUST NOT rewrite a published address and treat the
result as identity.

Wildcard, multicast, broadcast, port zero, and IPv4-mapped IPv6 encodings are
invalid. A link-local IPv6 address requires an operating-system scope identifier
that the version 0.1 wire endpoint cannot carry, so it is not published unless
the deployment maps it to an unambiguous interface out of band.

The default maximum datagram is 1,200 bytes. A node advertises a larger value
only when its configured transport path is known to support it without IP
fragmentation. Advertisement is a receive ceiling, not proof of end-to-end path
MTU.

An empty endpoint set means the member is authorized but currently unavailable
for direct data sessions.

## 4. Candidate ordering

The controller preserves the publisher's endpoint priority. A client sorts
candidates by:

1. ascending priority;
2. locally routable before locally unroutable;
3. IPv6 and IPv4 according to the host's current route preference;
4. address bytes and port for deterministic tie breaking.

The client does not infer higher trust from address scope or priority. A public
address, private address, and Tailscale address all require the same Stella
handshake.

## 5. Initiation election

The lexicographically smaller node ID is the preferred initiator. It begins
candidate attempts immediately after both peers have current grants and at
least one endpoint.

The larger node waits one second. If it has neither established a session nor
received a valid initiation, it may initiate using the smaller node's published
candidates. This fallback handles asymmetric reachability and lost control
updates without making either endpoint authoritative.

If simultaneous authenticated initiations occur, both nodes keep the exchange
whose initiator has the smaller node ID and abandon the other. Cached responses
remain available long enough to answer retransmissions, but abandoned exchange
keys are erased.

## 6. Candidate attempts

One logical handshake uses one handshake ID, session ID, ephemeral key, nonce,
timestamp, and signed `SESSION_INIT`. The initiator MAY send that identical
datagram to multiple candidate endpoints.

It sends first to every candidate at the best priority, staggering address
families by 250 ms. If no authenticated response arrives after one second, it
tries the next priority. Overall retransmission and timeout follow the security
specification.

The first fully authenticated `SESSION_RESPONSE` that matches the initiation
wins. Its source IP and port become the candidate session's validated remote
endpoint. Other responses for the same initiation are ignored after their
structure and hash are checked; they do not create parallel sessions.

The responder sends its response to the source IP and port from which the valid
initiation arrived, even when that tuple differs from the initiator's published
record. This permits ordinary return traffic through an existing UDP mapping
but is not a general NAT traversal guarantee.

## 7. Endpoint validation and pinning

An endpoint becomes validated only through a complete signed handshake and key
confirmation. After establishment, version 0.1 pins the session to the exact
remote IP and UDP port that completed it.

A correctly authenticated `DATA` or keepalive packet arriving from a different
source tuple is not accepted into the existing session. The receiver records a
rate-limited possible rebinding event and starts a new handshake using current
controller candidates. Version 0.1 does not migrate a session in place.

This rule prevents an authenticated packet copied through an unexpected relay
from silently redirecting return traffic. Deployments with address mobility use
short endpoint update and re-handshake delays.

## 8. Liveness

Controller heartbeat identifies whether a node is online, but it is not proof
that a particular peer path works. An established peer session maintains path
liveness with authenticated Stella keepalive packets when no data has been sent
for 15 seconds.

A keepalive echoes the most recent peer probe identifier. Three unanswered
keepalive intervals mark the path unavailable. The node stops sending TAP frames
to that session, removes its forwarding entries after the normal session
teardown rules, and starts candidate discovery again.

Receiving authenticated data also proves inbound path activity and may defer a
new keepalive. It does not acknowledge previous outbound Ethernet frames;
Stella data delivery remains datagram best effort.

## 9. Endpoint updates

A node republishes its complete endpoint set when:

- a listening address or port changes;
- Windows network-change notification invalidates an interface or route;
- the transport's receive datagram limit changes;
- an administrator enables or disables an underlay;
- the node is shutting down and can withdraw endpoints cleanly.

Updates replace, rather than patch, the prior set. The controller increments
snapshot revision and distributes a peer delta. Peers keep an established
session when its exact endpoint remains present and policy is unchanged;
otherwise they perform a new handshake.

A local interface address observed by the controller's TCP peer socket is not
automatically a usable UDP endpoint. Version 0.1 has no server-reflexive address
discovery.

## 10. Tailscale and other private underlays

To carry Stella over Tailscale, nodes bind UDP on their tailnet addresses or a
route that reaches them and publish those numeric addresses. Stella does not
call Tailscale APIs, consume WireGuard keys, or inherit tailnet identity.

Tailscale encryption is defense in depth. Stella still verifies grants,
handshakes, epochs, replay windows, and packet tags. The same principle applies
to another VPN or private routed network.

## 11. Failure and retry

Failure state is tracked per peer and endpoint, with bounded exponential
backoff from one to 30 seconds and full jitter. An authenticated endpoint or
grant update resets relevant backoff. Random unauthenticated traffic does not.

A peer with no working session remains in the authorized snapshot but is not an
eligible data recipient. Frames are not queued indefinitely waiting for it.
Counters distinguish no endpoint, handshake timeout, authentication failure,
path MTU failure, keepalive timeout, stale epoch, and local resource limit.

Repeated signature or grant failure prompts a fresh control snapshot. It does
not cause the node to trust a new key, lower its version, disable encryption, or
try an undocumented transport.

## 12. Security and privacy considerations

The controller learns published endpoints and network membership. Network
members learn one another's endpoint candidates. Version 0.1 does not hide this
metadata.

Nodes rate-limit initiation by endpoint and node ID, cap incomplete handshakes,
and never allocate reassembly state from unauthenticated discovery traffic.
Endpoint records received over TLS are still validated because a compromised
or buggy controller must not trigger unsafe socket operations.

## 13. Required tests

Discovery tests cover:

- deterministic candidate ordering and address-family staggering;
- preferred and fallback initiator behavior;
- simultaneous initiation tie breaking;
- identical initiation across multiple candidates and first valid response;
- response-to-observed-source behavior;
- endpoint pinning and rejection of source-tuple changes;
- endpoint replacement, withdrawal, and snapshot revision gaps;
- keepalive success, timeout, and data-driven liveness refresh;
- Tailscale-style private numeric endpoints with full Stella authentication;
- bounded backoff and no frame accumulation while unreachable.
