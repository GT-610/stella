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
PRIORITY, USE-CANDIDATE, FINGERPRINT, ICE-CONTROLLED, and ICE-CONTROLLING.
Extension attribute values remain length bounded. Unknown
comprehension-required attributes are reported to TURN behavior code; unknown
optional attributes may be ignored according to the relevant RFC. Attribute
padding is ignored on receipt and emitted as zero.

TURN ChannelData uses the standard channel range `0x4000` through `0x7fff`, a
16-bit unpadded data length, and one complete relayed datagram per record. UDP
records end immediately after the declared bytes. TCP and TLS records add only
the standard four-byte alignment padding. Stream demultiplexing examines the
two high bits and declared length before allocating or reading the complete
record; prefixes `10` and `11` are invalid.

### 3.2 TURN authentication profile

The first Stella relay profile uses the TURN long-term credential mechanism
with `MESSAGE-INTEGRITY-SHA256` only. It does not emit or accept the legacy
SHA-1 `MESSAGE-INTEGRITY` attribute. `PASSWORD-ALGORITHM` is present in every
authentication challenge and authenticated request, names algorithm `0x0002`
(SHA-256), and has an empty parameter block. `USERHASH` is not used by version
0.2 because the controller-issued username already contains only an expiry and
an opaque node identifier.

The canonical realm is the printable ASCII string
`stella-relay:<relay-id>`, where `<relay-id>` is the lower-case canonical
32-hex-digit relay identifier. A controller-issued credential uses the
USERNAME value `<expires-at>:<node-id>` and its opaque credential secret as the
long-term password. The 32-byte integrity key is:

```text
SHA-256(USERNAME || ":" || REALM || ":" || PASSWORD)
```

All concatenated values are their exact attribute or credential bytes. The
password never appears in a TURN record. The HMAC is HMAC-SHA-256 and the
`MESSAGE-INTEGRITY-SHA256` value is the complete 32-byte output.

An unauthenticated Allocate request receives error 401 with exactly one REALM,
NONCE, and PASSWORD-ALGORITHM attribute. The reference relay uses a 120-second
stateless nonce encoded as unpadded base64url of:

```text
expires-at-be64 || HMAC-SHA-256(
    relay-credential-key,
    "stella turn nonce v1\0" || relay-id || expires-at-be64
)
```

Expiry is exclusive. A missing or invalid nonce receives 401; an otherwise
authenticated request carrying an expired nonce receives 438 and a replacement
NONCE. Nonces are relay-scoped but deliberately not bound to an observed IP
address or port, so a NAT rebinding does not invalidate an allocation request.

Authenticated requests contain exactly one USERNAME, REALM, NONCE,
PASSWORD-ALGORITHM, and MESSAGE-INTEGRITY-SHA256. Duplicate authentication
attributes, a mismatched realm, an unsupported password algorithm, malformed
credential username, expired credential, or invalid HMAC are rejected without
logging credential bytes or distinguishing forged passwords from unknown
users. All method attributes protected by the request occur before
MESSAGE-INTEGRITY-SHA256. Only a single four-byte FINGERPRINT may follow it.

For integrity calculation, the STUN header length is temporarily the body
length through the end of the MESSAGE-INTEGRITY-SHA256 attribute. HMAC input is
the message from byte zero through the attribute immediately before
MESSAGE-INTEGRITY-SHA256; the integrity attribute header and value are not HMAC
input. A following FINGERPRINT is therefore outside the integrity calculation.

### 3.3 Address and error attributes

XOR-PEER-ADDRESS, XOR-RELAYED-ADDRESS, and XOR-MAPPED-ADDRESS use the standard
STUN address value. Byte 0 is zero, byte 1 is family `0x01` for IPv4 or `0x02`
for IPv6, and bytes 2 through 3 are the port XOR the most-significant 16 bits of
the magic cookie. IPv4 addresses are XORed with the 32-bit magic cookie. IPv6
addresses are XORed with the concatenation of the magic cookie and the 96-bit
transaction ID. Other families, non-zero reserved bytes, zero ports,
unspecified addresses, multicast addresses, and trailing bytes are rejected by
the Stella profile.

ERROR-CODE begins with two zero bytes, then a class byte whose upper five bits
are zero, then a decimal number byte. The represented status is
`class * 100 + number` and is limited to 300 through 699. The remaining reason
phrase is printable UTF-8 without control characters and is at most 127 bytes.
The reference relay uses stable standard reason phrases and never includes
credentials, packet bytes, or internal error details.

### 3.4 Initial UDP method behavior

The first executable relay implements TURN over UDP. Binding requests do not
require authentication and receive XOR-MAPPED-ADDRESS. Allocate supports only
UDP requested transport value `17,0,0,0`. A successful authenticated Allocate
creates one allocation for the client transport address and returns
XOR-RELAYED-ADDRESS, XOR-MAPPED-ADDRESS, LIFETIME, SOFTWARE, and
MESSAGE-INTEGRITY-SHA256. The granted lifetime is the smaller of the requested
non-zero lifetime and the deployment limit; omitting LIFETIME requests the
deployment limit. A second non-retransmitted Allocate on the same client
transport receives 437.

Refresh requires the allocation owner and the normal authenticated request
attributes. A zero LIFETIME deletes the allocation; any other value renews it
up to the deployment limit. CreatePermission accepts one or more unique
XOR-PEER-ADDRESS values, refreshes those peer-IP permissions for 300 seconds,
and is bounded by the per-allocation peer limit. ChannelBind requires exactly
one CHANNEL-NUMBER and one XOR-PEER-ADDRESS, creates the corresponding
permission, and binds the exact peer socket address for 600 seconds. Channel
numbers and peer addresses are one-to-one within an allocation.

Send indications and client ChannelData records are accepted only from an
active allocation. Their peer IP must have an unexpired permission, and their
datagram must not exceed the deployment's advertised maximum. ChannelData also
requires a live matching channel binding. Peer datagrams received on an
allocation socket are returned as ChannelData when an exact live binding
exists, otherwise as a Data indication containing XOR-PEER-ADDRESS and DATA.
Datagrams from peer IPs without a live permission are dropped.

UDP request responses are cached by client transport address and transaction
ID for 40 seconds so a retransmission does not create a second allocation or
repeat a mutation. The cache is bounded and never stores indications or packet
payload diagnostics. Authenticated success and error responses include
MESSAGE-INTEGRITY-SHA256; an initial 401 challenge cannot include integrity.
Malformed requests receive 400, unknown comprehension-required attributes 420,
missing allocations 437, wrong credential ownership 441, unsupported
transport 442, and exhausted capacity 486. Indications and ChannelData that
cannot be accepted are silently dropped as required by their one-way nature.

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
