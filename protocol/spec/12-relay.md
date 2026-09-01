# Stella Relay Profile

- Status: Draft
- Protocol version: 0.2 extension
- Last updated: 2026-08-31

## 1. Scope

This document defines the relay requirements for Stella 0.2. It specifies relay
readiness, TURN usage, TLS and secure WebSocket carriers, credentials,
permissions, datagram boundaries, path behavior, resource limits, deployment,
and failure handling.

The relay is an untrusted transport service. All relayed Ethernet traffic is
protected end to end by the normal Stella peer session.

## 2. Service model

A deployment publishes one or more relay services through the authenticated
controller. Each service advertises:

- stable relay identifier;
- numeric addresses and optional DNS name;
- supported TURN UDP, TURN TCP, TURN TLS, and secure WebSocket carriers;
- TLS server name and trust material;
- maximum relayed Stella datagram size;
- allocation and idle timeouts;
- relative regional preference; and
- short-lived opaque client credentials.

Relay configuration is authority metadata from the controller, not a network
membership grant. The client validates every address, size, name, expiry, and
carrier before connecting.

### 2.1 Version 0.2 relay-service encoding

`RELAY_SERVICE_LIST` begins with `count u8` from 1 through 8 and three zero
bytes, followed by exactly `count` self-sized relay service records. Records are
strictly sorted by numeric priority and then relay ID.

Each service record begins with this 68-byte header:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | complete record length, a multiple of four |
| 2 | 1 | numeric address count, 0 through 8 |
| 3 | 1 | SHA-256 SPKI pin count, 0 through 4 |
| 4 | 16 | stable non-zero relay ID |
| 20 | 2 | carrier bit mask |
| 22 | 2 | service priority, zero highest |
| 24 | 4 | maximum relayed Stella datagram, 1,200 through 65,507 |
| 28 | 4 | advertised allocation lifetime, 60 through 3,600 seconds |
| 32 | 4 | idle timeout, 30 through 3,600 seconds |
| 36 | 8 | credential issue Unix time |
| 44 | 8 | exclusive credential expiry Unix time |
| 52 | 1 | DNS hostname length, 0 through 253 |
| 53 | 1 | TLS server-name length, 0 through 253 |
| 54 | 1 | credential username length, 1 through 128 |
| 55 | 1 | credential secret length, 16 through 128 |
| 56 | 1 | region-label length, 0 through 32 |
| 57 | 1 | TLS trust requirements |
| 58 | 2 | zero reserved |
| 60 | 2 | TURN/UDP port or zero |
| 62 | 2 | TURN/TCP port or zero |
| 64 | 2 | TURN/TLS port or zero |
| 66 | 2 | secure WebSocket port or zero |
| 68 | variable | strings, padding, addresses, then SPKI pins |

Carrier-mask bits 0 through 3 mean TURN/UDP, TURN/TCP, TURN/TLS, and secure
WebSocket respectively. At least one bit is set and all higher bits are zero.
The port corresponding to a set bit is non-zero; every other carrier port is
zero. The WebSocket path and subprotocol remain the fixed values in section 4.

The variable strings occur without terminators in header order: DNS hostname,
TLS server name, credential username, credential secret, and region label.
Zero bytes then pad the combined string area to a four-byte boundary. Hostname,
TLS name, username, and region use printable ASCII without control characters;
DNS and TLS names use canonical lower-case A-label form. The credential secret
is opaque and may contain any byte. Neither credential field appears in debug,
status, error, or ordinary trace output.

TLS trust value 0 is permitted only when neither TLS nor WebSocket is offered.
Bit 0 requires normal Web PKI validation against the advertised TLS name. Bit 1
requires one advertised SHA-256 SPKI pin to match. No other bits are defined;
when both bits are set both checks are required. Pin count is non-zero exactly
when bit 1 is set. TLS name is non-empty whenever bit 0 is set.

Each numeric relay address is a 20-byte record containing address family `u8`,
address priority `u8`, zero reserved `u16`, and a 16-byte address slot encoded
as in `02-control-plane.md`. Records are sorted by priority, family, and address.
At least one numeric address or a DNS hostname is present. Numeric addresses are
unicast and never establish relay identity; TLS validation and relay
authentication remain mandatory where applicable.

The exact address records are followed by `pin_count` raw 32-byte SHA-256 SPKI
digests in strictly increasing byte order. The service record ends immediately
after the final pin. Credential expiry is greater than issue time and no more
than 600 seconds later. Relay IDs, service endpoints, and credentials are
validated as one complete replacement configuration before use.

## 3. TURN profile

The standards-based relay follows TURN and its current updates. One active
client allocation represents one relayed candidate for ICE component 1.
Permissions and channel bindings are created only for currently authorized
peer candidates.

The first reference deployment supports:

- TURN over UDP when outbound UDP is available;
- TURN over TCP for UDP-restricted networks; and
- TURN over TLS on TCP port 443 for strict firewalls.

The client-to-server carrier may be a stream, but the TURN layer presents exact
datagrams to ICE and Stella. Partial, oversized, truncated, or trailing bytes
are rejected before Stella parsing.

### 3.1 TURN record boundary

The reference codec accepts the RFC 8489 20-byte STUN header with magic cookie
`0x2112a442`, a 96-bit transaction ID, and a four-byte-aligned 16-bit body
length. It registers Binding, Allocate, Refresh, Send, Data,
CreatePermission, and ChannelBind methods and all four STUN classes. Other
methods are rejected by the first profile rather than guessed.

The initial attribute registry includes MAPPED-ADDRESS, USERNAME,
MESSAGE-INTEGRITY, ERROR-CODE, UNKNOWN-ATTRIBUTES, CHANNEL-NUMBER, LIFETIME,
XOR-PEER-ADDRESS, DATA, REALM, NONCE, XOR-RELAYED-ADDRESS,
REQUESTED-TRANSPORT, DONT-FRAGMENT, MESSAGE-INTEGRITY-SHA256,
PASSWORD-ALGORITHM, USERHASH, XOR-MAPPED-ADDRESS, SOFTWARE, ALTERNATE-SERVER,
and FINGERPRINT. Extension attribute values remain length bounded. Unknown
comprehension-required attributes are reported to TURN behavior code; unknown
optional attributes may be ignored according to the relevant RFC. Attribute
padding is ignored on receipt and emitted as zero.

TURN ChannelData uses the standard channel range `0x4000` through `0x7fff`, a
16-bit unpadded data length, and one complete relayed datagram per record. UDP
records end immediately after the declared bytes. TCP and TLS records add only
the standard four-byte alignment padding. Stream demultiplexing examines the
two high bits and declared length before allocating or reading the complete
record; prefixes `10` and `11` are invalid.

## 4. Secure WebSocket carrier

An HTTPS deployment may expose `/stella/turn/v1` with WebSocket subprotocol
`stella-turn.v1`. Authentication occurs before upgrade using controller-issued
credentials, TLS trust, and the same allocation policy as the TURN listener.

Each binary WebSocket message contains exactly one complete TURN message or one
complete TURN ChannelData record. Fragmented WebSocket messages are
reassembled only up to the configured relay-record limit. Text messages,
compression extensions, mixed records, empty messages, and records with
trailing bytes are rejected.

The WebSocket carrier exists for HTTP-aware firewalls and explicit proxies. It
does not alter ICE candidate semantics, Stella packet protection, peer
permissions, or replay handling.

## 5. Credentials and authorization

Relay credentials are generated or delegated by the controller after node
authentication. They contain or resolve to:

- node identity;
- deployment and relay identity;
- issued-at and expiry times;
- allocation and bandwidth class; and
- a random secret or password with at least 128 bits of entropy.

Credentials normally expire within ten minutes and are renewed over the
authenticated control plane. The relay does not accept network join tokens,
enrollment tokens, controller private keys, or Stella peer session keys.

Allocation authentication proves which node owns relay resources. It does not
prove that a destination node is a current network peer. The controller and
client restrict TURN permissions to active peer candidates, and the destination
still rejects every packet lacking a valid Stella session.

## 6. Warm allocation lifecycle

The client starts relay allocation concurrently with control authentication and
direct candidate gathering. Before publishing a relay candidate, it confirms:

- carrier authentication;
- allocation address and lifetime;
- conservative datagram size;
- ability to refresh before expiry; and
- bounded send and receive queues.

An allocation is refreshed before half of its remaining lifetime elapses, with
jitter to avoid synchronized load. Refresh failure marks the candidate draining,
creates a replacement allocation, and republishes the local connectivity
generation. Existing sessions may receive through the old allocation only
during their bounded grace.

## 7. Datagram routing and path binding

The relay forwards one complete opaque Stella datagram to one authorized relay
or peer candidate. It does not combine packets, split one packet, infer an
Ethernet destination, replicate a broadcast, or select a Stella key.

Head-end flooding remains at the sending Stella node, which creates a separately
protected packet for every peer. This preserves pairwise keys and keeps the
relay outside Ethernet semantics.

A relayed candidate pair receives a local `PathId`. The normal Stella handshake
must complete through that path before data is accepted. Moving between direct
and relay paths creates a fresh Stella session as required by the connectivity
specification.

## 8. Queueing and backpressure

Per allocation, the reference limits are:

- 256 queued datagrams total;
- 128 queued datagrams per destination peer;
- one megabyte of queued encoded data;
- 65,507 bytes absolute datagram ceiling; and
- a lower advertised default of 1,200 bytes.

The first reached limit wins. Overflow drops new data datagrams for the affected
destination and increments a safe counter. Control, allocation refresh, and
permission traffic use separate bounded queues and cannot be starved by game
data.

Stream carriers inherently introduce head-of-line blocking. Implementations do
not build an unbounded reorder layer above them. Direct paths remain preferred,
and one slow destination cannot block another destination's queue indefinitely.

## 9. Abuse prevention

The relay enforces:

- authenticated allocation creation;
- per-node allocation count, byte, packet, and concurrent-peer limits;
- permission and channel expiry;
- source and destination validation;
- idle timeouts and bounded refresh;
- safe logging without credentials or packet bytes; and
- rejection before allocation of oversized or malformed records.

The relay cannot prevent an authorized member from sending traffic allowed by
its Stella network policy, but it can independently rate-limit that member's
relay resources. Relay policy never weakens controller revocation or Stella
flood limits.

## 10. Availability and selection

A client keeps at least one relay ready while any virtual network is active.
When multiple relays exist, it prefers an operator-compatible region with a
healthy carrier and lower measured latency. It may keep a second allocation as
standby, subject to deployment resource policy.

Relay failure triggers bounded reconnect with full jitter. Direct sessions
continue unaffected. If no direct session exists, the client reports degraded
connectivity and drops rather than indefinitely queues TAP frames.

## 11. Deployment profile

The first self-hosted profile permits controller, STUN, and relay services on
one machine, but each has separate listeners, admission limits, and shutdown
paths. TURN TLS and WebSocket normally use a DNS name and certificate accepted
by target networks. Raw controller TLS pinning remains an independent trust
mechanism.

For common rooms of up to 32 nodes, one relay is sufficient. A 100-node test is
the validation ceiling, not a promise that every peer can continuously send
maximum-rate flooded traffic through one small server.

## 12. Required tests

Relay tests cover:

- credential creation, expiry, redaction, and renewal;
- TURN UDP, TCP, and TLS allocation and channel data;
- secure WebSocket binary record boundaries and proxy carriage;
- permission denial and destination isolation;
- exact datagram preservation and oversize rejection;
- queue, bandwidth, allocation, and idle limits;
- relay handshake, encrypted L2 data, and replay rejection;
- direct-to-relay failover and relay-to-direct upgrade;
- relay restart and replacement allocation; and
- 32-node normal and 100-node bounded stress scenarios.
