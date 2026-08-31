# Stella Automatic Connectivity

- Status: Draft
- Protocol version: 0.2 extension
- Last updated: 2026-08-31

## 1. Scope

This document defines automatic peer reachability for Stella 0.2. It covers
candidate generations, STUN discovery, ICE connectivity checks, direct-path
nomination, relay readiness, path binding, failover, recovery, privacy, and
resource bounds. It does not change Ethernet forwarding, network membership, or
peer packet protection.

Version 0.1 static UDP endpoint discovery remains valid when both peers
negotiate 0.1. A 0.2 implementation does not reinterpret a 0.1 endpoint set as
an ICE candidate generation.

## 2. Required outcome

An ordinary client deployment requires no inbound firewall rule, static public
address, or manual port forwarding. After authenticating to the controller, a
client:

1. opens its direct UDP socket and relay carriers;
2. gathers a bounded local candidate generation;
3. exchanges that generation only with authorized network peers;
4. performs direct connectivity checks while the relay is already usable;
5. establishes a Stella peer session over the best validated path;
6. falls back to relay when no direct pair works;
7. continues bounded direct checks while relayed; and
8. recovers from address, interface, NAT mapping, and relay changes.

Direct connectivity is preferred for latency and server cost. Relay
connectivity is a correctness requirement, not a failure of protocol security.

## 3. Components and trust boundaries

The connectivity system contains:

- a candidate gatherer on each node;
- the authenticated controller as signaling service;
- one or more STUN services;
- an ICE agent per active peer relationship;
- one or more TURN or Stella-compatible relay services;
- a path manager below the Stella peer handshake; and
- the existing authenticated Stella data plane above it.

STUN, ICE, TURN, local routing, and a relay are untrusted delivery mechanisms.
They never grant network membership, select packet keys, bypass the Stella peer
handshake, or authorize an Ethernet frame.

## 4. Connectivity generations

One local connectivity generation contains:

- a random non-zero 64-bit generation identifier;
- ICE username fragment and password with RFC 8445 entropy;
- a random 64-bit ICE role tie breaker;
- one through 32 candidates in descending preference;
- the generation creation and expiry times;
- the maximum Stella datagram accepted through each candidate; and
- relay carrier and relay-service identity for each ready relay candidate.

Credentials and candidates are replaced atomically. A new generation does not
patch or inherit candidates from an older generation. A node keeps the prior
generation only for the bounded overlap needed to complete checks already in
flight, and never longer than 30 seconds.

Generation identifiers are diagnostic correlation values, not secrets. ICE
passwords and relay credentials are secrets and must be redacted from logs,
errors, status output, and debug formatting.

## 5. Candidate types

Stella 0.2 uses these ICE candidate classes:

| Class | Source | Normal preference |
| --- | --- | --- |
| host | Usable local interface address on the data socket | Highest on the same routed domain |
| server-reflexive | Address returned by STUN for the data socket | Preferred public direct path |
| mapped | Address created automatically by PCP, NAT-PMP, or UPnP | Direct path, below verified global IPv6 |
| peer-reflexive | Address learned by a successful ICE check | Same trust as the check that created it |
| relay | TURN or Stella relay allocation | Guaranteed fallback when its carrier is reachable |

Loopback, unspecified, multicast, broadcast, port zero, and administratively
disabled interfaces are not candidates. IPv6 link-local addresses are omitted
unless the signaling representation carries an unambiguous scope identifier.

Private, tailnet, EasyTier, VPN, and same-LAN addresses may be host candidates.
Their scope affects priority and expected reachability, never identity or
authorization.

## 6. Candidate gathering

The client binds the UDP socket before gathering. STUN binding transactions and
direct Stella packets use that same socket so the discovered mapping describes
the path that will carry data.

Gathering runs in parallel:

1. enumerate permitted host addresses;
2. request server-reflexive addresses from at least one configured STUN service;
3. optionally request automatic mappings using PCP, NAT-PMP, or UPnP;
4. establish at least one relay allocation or carrier; and
5. publish the complete generation after initial relay readiness or the bounded
   startup deadline, whichever occurs first.

Late candidates replace the published generation. They do not mutate an
already published encoding in place.

A STUN response is accepted only when its transaction ID, message integrity,
fingerprint requirements, source service, address family, length, and timeout
match the outstanding transaction. STUN never allocates Stella handshake or
frame-reassembly state.

## 7. Controller signaling

Only an authenticated node with active membership may publish connectivity for
that network. The controller stores the latest complete generation under the
same bounded online lease as peer reachability and distributes it in atomic
snapshots and deltas.

The controller validates sizes, counts, address encodings, credential bounds,
expiry, and strictly ordered candidate priority. It does not rewrite a candidate
and treat the rewritten address as authoritative. It may remove candidates
prohibited by deployment policy and reports that rejection to the publisher.

Connectivity credentials are visible only to the controller and authorized
peers in the same network. Leaving, suspension, disablement, lease expiry, or a
newer generation invalidates pending checks for the prior state.

The 0.2 control-message and nested-value registries encode generation,
credentials, candidates, and relay configuration as the explicit bounded
binary records in `02-control-plane.md` and `12-relay.md`. Connectivity changes
share the network snapshot revision stream but remain separate from stable
membership records as required by ADR 0027.

## 8. ICE roles and checks

Peers run RFC 8445 connectivity checks for component 1, which represents the
complete Stella datagram path. The peer with the greater ICE tie breaker is
controlling. An equal tie breaker is regenerated. Node-ID ordering is used only
as a deterministic implementation fallback when an ICE library cannot expose a
valid tie breaker.

Candidate pairs are formed only from compatible address families and carriers.
Checks are paced and bounded; no peer may cause an unbounded cross product or
transaction table. The reference limits are 32 local candidates, 32 remote
candidates, 100 active checks per peer, and 256 active checks across one client.

Ordinary ICE triggered checks and peer-reflexive discovery are allowed. A
successful inbound check creates no Stella session. The controlling peer
nominates one pair only after bidirectional success. Aggressive nomination is
not used in the first implementation.

## 9. Path creation and Stella handshake

A nominated candidate pair produces a local `PathId` and path generation. The
path records transport kind, exact send and receive metadata, conservative
datagram size, nomination time, and liveness state.

The preferred Stella handshake initiator starts the normal signed peer
handshake over the nominated path. A complete handshake binds the resulting
session to the `PathId`, path generation, network, peer, and negotiated packet
size. Packets received through another path cannot enter that session.

ICE success without a Stella handshake is reported as `reachable`, not
`connected`. A relay allocation without a Stella handshake is `relay-ready`,
not a peer session.

## 10. Path ranking

The default ranking is:

1. same-LAN host path;
2. global IPv6 direct path;
3. automatically mapped or server-reflexive UDP direct path;
4. other policy-permitted direct path;
5. UDP relay;
6. TURN over TCP or TLS;
7. secure WebSocket relay.

Within a class, lower measured round-trip time and lower observed loss win after
a stability margin. A path is not switched solely for a sub-10-millisecond
improvement. Operators may disable a carrier but cannot configure a path to
bypass Stella authentication.

## 11. Relay-first readiness and direct upgrade

Relay establishment begins at client startup rather than after direct timeout.
When both peers have a relay path but direct checks are incomplete, they may run
the Stella handshake over relay and begin data exchange.

Direct checks continue at a low bounded rate. When a better direct path is
nominated, peers establish a fresh Stella session there. After confirmation,
new sends use the direct session and the old relay session follows the normal
receive-only rekey grace before erasure. The relay allocation remains warm while
the network is active.

## 12. Failure, rebinding, and recovery

Authenticated Stella data and keepalive packets prove path activity. Three
unanswered keepalive intervals fail the active path. ICE consent freshness may
fail a path earlier but cannot extend membership or Stella session expiry.

On path failure the client:

1. stops selecting the failed session for new TAP frames;
2. selects an already confirmed alternate session when available;
3. otherwise handshakes on the ready relay path;
4. starts or refreshes direct checks; and
5. drops frames rather than creating an unbounded recovery queue.

An unexpected source tuple or relay channel does not migrate a session in
place. It may create a peer-reflexive candidate after valid ICE processing, but
Stella still requires nomination and a fresh peer handshake.

Interface changes, resume from sleep, STUN mapping changes, relay reconnects,
and repeated path errors create a new local generation. Backoff is per peer and
path class, uses full jitter, and is bounded between one and 30 seconds.

## 13. Security and abuse controls

- ICE and relay credentials are random, short-lived, and scoped to one node or
  peer relationship.
- STUN and ICE processing enforce message integrity, fingerprints where
  required, transaction matching, pacing, and anti-amplification bounds.
- A controller does not distribute candidate generations across networks.
- A malicious member cannot make another node probe arbitrary multicast,
  broadcast, unspecified, privileged, or administratively denied endpoints.
- Candidate, check, relay, queue, and diagnostic storage have hard limits.
- Connectivity errors contain no ICE password, relay secret, frame bytes,
  decrypted payload, or session key.

## 14. Required tests

The 0.2 connectivity suite covers:

- host, global IPv6, server-reflexive, mapped, peer-reflexive, and relay
  candidate gathering;
- exact same-socket STUN mapping behavior;
- candidate replacement, expiry, filtering, and redaction;
- controlling-role conflict and regular nomination;
- endpoint-independent, address-dependent, port-dependent, double, and
  symmetric NAT simulation;
- complete UDP blocking with relay success;
- direct failure, relay fallback, later direct upgrade, and direct-to-relay
  recovery;
- NAT rebinding and interface replacement without in-place session migration;
- 32-node normal operation and a 100-node bounded stress run; and
- unchanged version 0.1 static-UDP interoperability.
