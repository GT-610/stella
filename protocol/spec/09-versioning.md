# Stella Versioning and Compatibility

- Status: Draft
- Protocol version: 0.1
- Last updated: 2026-08-29

## 1. Scope

This document defines protocol version numbers, cryptographic suite selection,
compatibility, extensions, negotiation, downgrade prevention, rolling upgrades,
object and configuration versions, registry changes, and deprecation.

## 2. Version tuple

An interoperable Stella protocol selection is:

```text
(protocol_major, protocol_minor, cryptographic_suite)
```

The version 0.1 mandatory selection is `(0, 1, 0x0001)`. Major and minor are
one-byte unsigned integers. Suite is a two-byte unsigned integer.

The leading zero means pre-standard maturity; it does not disable negotiation,
validation, downgrade protection, or compatibility rules.

## 3. Major and minor meaning

A new major version is required when an implementation that knows only the old
major cannot safely parse, authenticate, or preserve the new semantics. Examples
include changing common header meaning, signature input construction, mandatory
security assumptions, identity derivation, or membership authority.

A new minor version may add behavior while retaining a complete, explicitly
selectable older-minor mode. Examples include a registered non-critical field,
new optional control event, or optional transport kind whose absence preserves
version 0.1 behavior.

Minor numbers are not automatically wire-compatible. Peers always select one
exact tuple and then send that exact major and minor in headers. A version 0.2
implementation talking to a 0.1 implementation selects 0.1 and follows all 0.1
rules; it does not send 0.2 headers and hope unknown fields are skipped.

## 4. Supported-version advertisement

The controller advertises one to 32 unique tuples in preference order through
`SERVER_HELLO`. The client maintains its own supported set and selects the first
controller tuple it supports exactly.

The client MUST NOT select:

- a tuple absent from the controller list;
- a version it only partially implements;
- a suite disabled by local security policy;
- an experimental or private tuple unless explicitly configured for that
  deployment.

If there is no intersection, the client sends no node proof or secret and closes
with an unsupported-version result when framing permits.

The selected tuple appears in `CLIENT_HELLO` and the TLS-exporter-bound
controller and node proofs. Selected major and minor appear in every later
control and peer-handshake header. Suite `0x0001` is the only suite defined for
version 0.1 and is therefore implicit in its peer header and key schedule.

## 5. Network compatibility

A controller admits a node into an active peer snapshot only when the node's
selected tuple is supported by that network's current protocol policy. Version
0.1 networks require `(0, 1, 0x0001)`.

The controller does not distribute mutually incompatible peers and expect them
to discover failure through UDP. A node rejects a snapshot record whose grant
or required behavior cannot be represented under the selected tuple.

One node may connect to different controllers with different tuples in separate
process or runtime contexts. Version state, sessions, keys, parsers, and TAP
networks remain isolated.

## 6. Peer negotiation

Version 0.1 peer handshakes do not perform an independent offer exchange. Their
header uses the tuple already authorized by the controller for the network and
advertised in compatible peer state. Both signatures cover those header bytes.

A peer handshake with a different major or minor is rejected before expensive
cryptography. A different suite has no valid version 0.1 key schedule and is
rejected. A node does not retry the same peer with a lower tuple after a
signature, grant, transcript, confirmation, or data-tag failure.

Future multi-suite peer negotiation must bind both complete offer lists and the
selection into signatures. It cannot reinterpret version 0.1 reserved bytes.

## 7. Downgrade prevention

TLS protects the controller's supported list in transit. Exporter-bound proofs
cover the selected version. Peer signatures and transcript hashes cover data
headers containing the selected version. Network grants and policy bind the
required confidentiality behavior.

Therefore an implementation treats any of these as a security failure rather
than a reason to fall back:

- proof verification failure;
- unsupported field marked critical;
- selected tuple changing within a connection or session;
- peer using another version than the controller-authorized network state;
- encrypted policy received as authenticate-only;
- malformed new-version message presented as an old version.

Automatic fallback is allowed only after a clean unsupported-version result
whose offered list was authenticated in the same TLS connection, and only to a
tuple that was in both original supported sets. Version 0.1's client selection
already chooses the best common tuple, so no second connection fallback is
normally needed.

## 8. Header and TLV extensions

Every packet or message first validates its selected base version. Extension
parsing then follows these rules:

- `header_length` bounds the exact extension region;
- every extension or field is length-delimited and four-byte aligned;
- padding is zero and included in authentication or signatures;
- unknown non-critical types are skipped after complete bounds validation;
- unknown critical types reject the complete packet or message;
- a reserved base-header bit is never repurposed without selecting a version
  that defines it;
- an extension cannot change the meaning of bytes outside its declared value.

Non-critical means safe to ignore while retaining base-version semantics. A
feature is critical when ignoring it could change authorization, security,
delivery recipients, frame bytes, accounting, or state-machine transitions.

## 9. Registry allocation

The Stella specification repository maintains append-only registries for:

- protocol versions and suites;
- data packet and control message types;
- common and type-specific flags;
- header extensions and body fields;
- endpoint kinds, status codes, permissions, and rejection reasons;
- signed-object format versions.

An assigned numeric meaning is never reused, including after rejection or
deprecation. New allocations document owner, status, criticality, exact syntax,
state impact, security analysis, and test vectors.

Experimental/private ranges are not guaranteed stable and MUST NOT be enabled
by default. Two deployments using the same private number may be incompatible.

## 10. Signed-object versions

Membership grants, network policy, and future signed objects have their own
format version and magic. Their version is not inferred solely from the current
control connection.

An implementation verifies an object's format before signature semantics. An
unknown signed-object format is rejected even when its total length appears
parseable. A new protocol version may continue to use an older object format
only when its specification explicitly says so.

Signature domain strings include their version and never change meaning. A new
canonical byte layout uses a new domain string and format version.

## 11. Configuration and persistence versions

Human-readable TOML configuration, controller database schema, cached peer
state, and key-file encoding are implementation artifacts with versions
separate from the wire protocol.

Upgrading a binary may migrate those artifacts explicitly. It MUST NOT infer a
wire protocol upgrade from a configuration migration. Unknown future
configuration fields remain errors under the strict version 0.1 reference
schema.

Persisted untrusted network data is revalidated on load. Session keys, replay
windows, incomplete handshakes, and reassembly buffers are not restored across
process restart in version 0.1.

## 12. Rolling upgrades

A safe controller rollout follows:

1. deploy binaries that understand both old and new tuples while networks still
   require the old tuple;
2. verify all required nodes advertise the new tuple;
3. update one network's protocol policy, which changes controller epoch;
4. issue new grants and snapshots and establish new peer sessions;
5. retain old tuple support for rollback until the administrator's deadline;
6. disable old support only after no network depends on it.

A node that cannot support the new policy leaves the active snapshot rather
than operating partially. Existing lower-version sessions receive no grace
after the invalidating epoch is applied.

For a compatible implementation rollout that does not change the selected
tuple or policy, nodes may restart independently and rejoin through normal
leases and discovery.

## 13. Deprecation and security retirement

Deprecation first adds warnings and administrative visibility, then removes a
tuple from network policy, and only later removes parser or code support.

A cryptographic emergency may accelerate retirement. The controller publishes
only secure supported tuples, increments affected epochs, revokes grants, and
requires new sessions. Clients do not override a controller's removal of a
suite merely to preserve connectivity.

Security notices identify affected tuple, object formats, keys, migration
steps, and the earliest safe interoperability boundary.

## 14. Compatibility test matrix

For every supported tuple, the project tests:

- exact same-version controller, client, and peer operation;
- newest implementation selecting each retained older tuple;
- no-common-version failure before credentials are disclosed;
- selected-version binding in controller and node proofs;
- peer mismatch rejection before session allocation;
- unknown non-critical skip and unknown critical rejection;
- reserved bit, padding, and length failures;
- downgrade attempts after signature or tag failure;
- rolling epoch transition and removal of incompatible nodes;
- signed-object version mismatch.

Passing a newer implementation's own tests is not evidence of backward
compatibility; the matrix includes stored vectors and, where available, the
last released older implementation.
