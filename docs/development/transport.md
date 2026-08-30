# Datagram transport implementation

This page defines how `stella-transport` implements the replaceable bounded
datagram contract and the version 0.1 UDP backend. The normative endpoint,
path-size, and shutdown requirements remain in the transport specification.

## Abstraction boundary

`DatagramTransport` carries complete untrusted Stella datagrams. It reports the
numeric source endpoint of each receive, sends one datagram atomically, exposes
local endpoints and conservative capabilities, and supports bounded
cancellation. It does not parse Stella headers, select a peer key, authenticate
an endpoint, fragment Ethernet frames, or retry a protected packet.

The trait is object-safe so the client can select a transport at runtime. Its
asynchronous methods return a boxed `Future` type defined by the crate rather
than depending on an async-trait macro. The allocation is at the control edge
of one socket operation; packet bytes remain caller-owned.

Every receive either returns exactly one complete datagram or an error. Loss,
duplication, reordering, and delay remain expected transport behavior.

## UDP instance model

One `UdpTransport` owns one Tokio UDP socket bound to one explicit IPv4 or IPv6
address. A node that listens on both families constructs two instances and lets
the client aggregate their endpoints. Keeping sockets single-family prevents a
dual-stack wildcard from producing ambiguous mapped addresses.

`UdpConfig` contains:

- the numeric bind address, including port zero when the operating system may
  choose a port;
- one advertised and enforced maximum datagram size from 1,200 through 65,507
  bytes.

The default limit is 1,200 bytes. Binding does not enumerate interfaces or
publish wildcard addresses; the client and controller layers decide which
usable concrete addresses to advertise.

Send rejects a non-UDP endpoint, an address-family mismatch, and a datagram
larger than the configured limit before calling Winsock. A successful UDP send
must report the entire datagram length. A partial count is treated as a
permanent socket failure rather than retried with the same protected nonce.

## Truncation defense

Tokio's portable receive API cannot report truncation uniformly: Winsock
normally reports `WSAEMSGSIZE`, while some Unix APIs return the visible prefix.
The backend therefore receives into one reusable 65,535-byte scratch buffer
owned by the socket and guarded against concurrent receives.

After a complete receive:

1. a datagram above Stella's configured limit is dropped with a size error;
2. caller output smaller than the complete datagram receives a typed
   buffer-too-small error and remains unchanged;
3. otherwise the exact bytes are copied once to caller storage and returned
   with the numeric source endpoint.

This deliberately trades one bounded copy for platform-independent correctness
and ensures a truncated prefix never reaches `stella-proto`. Future platform
batch APIs may remove that copy only if they preserve the same guarantee.

## Cancellation and shutdown

Each operation subscribes to a Tokio watch channel before awaiting socket I/O.
Shutdown publishes an idempotent terminal value. Pending receive and send
futures wake, discard any unpublished scratch bytes, and return `Shutdown`.
New operations reject immediately.

Dropping the transport releases the socket handle. The shutdown signal is the
bounded wake-up mechanism; the owning client drops transport instances after
its short drain deadline so Winsock resources close deterministically.

## Errors

`TransportError` contains no datagram bytes. It distinguishes:

- invalid configuration or unsupported endpoint kind;
- bound-socket and destination address-family mismatch;
- configured or path datagram size failure;
- complete receive larger than caller output;
- local shutdown;
- operating-system I/O with a stable operation and error class.

I/O classes are permission, address, unreachable, resource exhaustion,
transient, and permanent. The original `std::io::Error` remains the source so
Windows callers can inspect safe Winsock codes such as `WSAEMSGSIZE` without
parsing display text.

## Tests

Loopback tests cover IPv4 and IPv6 when available, exact datagram boundaries,
numeric source reporting, the configured maximum, caller-buffer failure without
partial exposure, endpoint-family rejection, and cancellation of a pending
receive. Test datagrams are opaque bytes so transport behavior cannot
accidentally depend on a Stella packet type.
