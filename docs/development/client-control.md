# Windows client control plane

`stella-client` owns controller trust, the persistent node identity, desired
network membership, live authorization state, reconnect behavior, and the
boundary that enables or disables data-plane forwarding. Normative message
bytes and state transitions remain in the protocol specification.

## Persistent inputs

The client uses strict versioned TOML. Paths are resolved relative to the
configuration file, unknown fields are rejected, and credentials are never
accepted inline in the file. Persistent configuration includes:

- the numeric controller TCP address and TLS server name;
- the expected Stella controller ID and one or more `sha256/` SPKI pins;
- the protected node PKCS#8 identity path and display name;
- the UDP bind address and explicitly advertised numeric endpoints;
- one TAP-Windows adapter selection and desired network ID per network entry.

An explicit initialization command creates the node identity with create-new
semantics. On Windows its DACL is protected from inheritance and grants access
only to the owning account and LocalSystem. Initialization never replaces an
existing identity or configuration.

Enrollment and join tokens are ephemeral command inputs. The CLI decodes them
into redacted zeroizing values, never logs them, and never stores them in TOML.
After a successful join, the network ID is durable intent; reconnect joins that
existing membership without a token.

The version 1 Windows configuration schema is:

```toml
version = 1

[controller]
address = "203.0.113.10:44900"
tls_name = "controller.example.net"
id = "0123456789abcdef0123456789abcdef"
spki_pins = ["sha256/BASE64_SHA256_SPKI_DIGEST="]

[identity]
node_key = "secrets/node.pk8"
display_name = "Gaming PC"

[transport]
udp_bind = "0.0.0.0:45100"

[[transport.advertised_endpoints]]
address = "192.0.2.20:45100"
priority = 10
max_datagram_size = 1200

[[networks]]
id = "fedcba9876543210fedcba9876543210"
tap_adapter = "Stella LAN"

[logging]
filter = "info,stella_client=info"
```

Relative paths are rooted beside the configuration file. Endpoint and network
entries are normalized into protocol order, duplicate network IDs are rejected,
and unknown keys, including any attempted inline enrollment or join token, make
the complete file invalid. The `networks` array may be absent immediately after
`init`; each successful `join` adds one durable entry.

## Connection authentication

The TLS client enables only TLS 1.3 and disables early data. Its certificate
verifier checks the configured server name, certificate validity interval,
server-auth usage, and a constant-time match against one configured SHA-256
SPKI pin. Pin rotation is an explicit overlap in which both old and new pins
are configured.

After TLS completes, the client:

1. validates `SERVER_HELLO`, advertised version, nonce, controller ID, public
   key, and current-time field;
2. sends `CLIENT_HELLO` with a fresh non-zero nonce and its persistent node
   identity;
3. derives the TLS exporter and verifies the correlated controller proof;
4. sends the exporter-bound node proof and, only when needed, enrollment
   material;
5. accepts active state only after a correlated status-zero `AUTH_RESULT`.

The configured controller ID must match both the hello field and the ID derived
from the controller public key. Certificate pinning and the Stella proof are
independent checks; neither silently substitutes for the other.

If a connection fails after `NODE_AUTH` with an enrollment token but before an
authentication result, the next attempt omits the token. Authentication
success means the previous enrollment committed. `ENROLLMENT_REQUIRED` means
it did not commit and allows the retained token to be sent on a later attempt.

## Active connection loop

One task owns the framed reader, writer, inbound and outbound sequences, and
correlation tracker. It selects among:

- the next controller message;
- the next heartbeat deadline;
- bounded local endpoint or membership commands;
- process shutdown.

Every outbound request registers its message ID before transmission. A direct
response must consume that correlation exactly once. Unsolicited snapshots,
deltas, grant refreshes, errors, and shutdown notices require correlation zero.
All malformed direction, sequence, correlation, or field combinations close
the connection.

After authentication the client rejoins each configured network in stable ID
order. A successful join result is validated but does not enable forwarding by
itself; the following complete snapshot must also validate and atomically
activate the network. The client then publishes the complete endpoint set on
which its UDP transport is already receiving.

## Atomic network state

For each active network, memory owns the exact local membership grant,
canonical policy, controller epoch, accepted snapshot revision, and a
node-ID-keyed peer map. Validation includes:

- controller signature, controller ID, node identity, time interval, epoch,
  policy digest, and permissions for every grant;
- exact network and receiving-node context for the peer list;
- endpoint syntax and bounded peer counts;
- a complete snapshot revision or exactly the next delta revision.

A candidate snapshot is decoded into temporary owned state and swapped only
after every record validates. A gap, invalid signature, expired grant, policy
inconsistency, or unknown delta target leaves the prior state unchanged and
requests a full snapshot. A higher epoch first disables the old forwarding
view.

`GRANT_REFRESH` replaces the local grant only after the same validation. A
changed serial tells the data plane to rekey peer sessions. Expiry disables the
network even while TLS remains connected.

## Heartbeat, reconnect, and shutdown

The heartbeat interval is the smallest active network policy interval, or 30
seconds with no active networks. Only one heartbeat may be outstanding. The
acknowledgement must echo its counter and carries authoritative revisions used
for reconciliation. Three missed acknowledgements reconnect the control
session.

Any connection or protocol failure closes forwarding immediately, clears live
network and peer-session state, and reconnects with full-jitter exponential
backoff from 250 milliseconds through 30 seconds. A new connection rebuilds
all authority state; grants and snapshots are never loaded from disk. A clean
`SERVER_SHUTDOWN` uses its advertised deadline as the earliest reconnect time.

On local shutdown the data plane stops accepting TAP frames, the client
withdraws its endpoint sets when time permits, closes TLS, cancels TAP I/O, and
joins all owned tasks within a bounded deadline.
