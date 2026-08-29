# Stella Identity and Membership

- Status: Draft
- Protocol version: 0.1
- Last updated: 2026-08-29

## 1. Scope

This document defines long-term Stella identities, enrollment credentials,
virtual-network identifiers, signed membership grants, time validity, key
storage requirements, rotation, and revocation. It does not define TLS
certificates or peer ephemeral session keys except where they bind to a
long-term identity.

## 2. Identity model

Stella has three distinct identifiers:

- a controller identifier names one Stella authority signing key;
- a node identifier names one node Ed25519 public key;
- a network identifier names one virtual Ethernet broadcast domain.

Identifiers are exactly 16 bytes and are compared as opaque byte strings. They
are serialized in network byte order only when interpreted for display; the
protocol does not assign integer arithmetic to them.

Long-term signing keys and TLS keys have separate roles. A controller's Stella
signing key signs membership and policy objects. Its TLS private key
authenticates the configured control endpoint. Deployments SHOULD keep these
keys separate so either can rotate without silently changing the other role.

## 3. Node identity

A node generates an Ed25519 key pair locally using operating-system
cryptographic randomness. The 32-byte public key is encoded in the standard
compressed Ed25519 form. The 32-byte private seed and expanded private material
MUST NOT be transmitted.

The node identifier is:

```text
node_digest = SHA-256(
    UTF8("stella node id v1") || ed25519_public_key
)
node_id = node_digest[0..16]
```

The domain string has no trailing NUL. A receiver given both ID and public key
MUST recompute the ID and compare all 16 bytes in constant time before using the
key.

Two different public keys producing the same node ID are a fatal identity
collision. A controller MUST reject the later registration and alert its
administrator. Version 0.1 does not define collision aliases.

### 3.1 Key possession

Possession is proved only by a valid Ed25519 signature over a domain-separated,
fresh transcript. Knowledge of a node ID or public key is never proof of
identity. The control authentication transcript and peer session transcript are
defined in their respective specifications.

### 3.2 Rotation

Changing the long-term Ed25519 key creates a new node ID in version 0.1. The
controller treats this as a new identity that requires enrollment and network
authorization. An administrator may transfer policy from the old identity, but
that administrative action is not an automatic protocol operation.

The old identity is revoked before or at the same affected network epochs that
enable the replacement. Existing peer sessions using the old identity become
invalid when nodes apply those epochs and always expire at their existing grant
deadline.

## 4. Controller identity

The controller has an Ed25519 signing key independent of its TLS certificate.
Its identifier is:

```text
controller_digest = SHA-256(
    UTF8("stella controller id v1") || ed25519_public_key
)
controller_id = controller_digest[0..16]
```

The controller sends its 32-byte Stella public key inside the TLS-protected
`SERVER_HELLO` message and signs a transcript bound to the TLS exporter. A
client recomputes the controller ID, verifies the signature, and compares the
ID with its configuration or previously accepted state.

A controller signing-key change creates a new controller ID. It requires an
explicit client trust update; it is never accepted through unauthenticated
trust-on-first-use. A planned rotation may be authorized by a cross-signed
rotation object in a future version. Version 0.1 uses an administrator-provided
new controller ID.

## 5. Virtual network identifier

A controller creates a network ID as 16 uniformly random bytes. The all-zero
identifier is reserved and MUST NOT be assigned. The controller checks its own
database for collision before committing a new network.

Network IDs are not derived from names, controller IDs, or passwords. A network
name is display metadata and changing it does not change the network ID.
Possession of a network ID grants no access.

The canonical text form is 32 lowercase hexadecimal characters without braces
or separators. Parsers MAY accept uppercase input but MUST emit lowercase.

## 6. Enrollment credentials

Enrollment associates a previously unknown node key with controller-managed
metadata. The reference controller supports administrator-created enrollment
tokens containing 32 random bytes.

The user-facing token encoding is unpadded base64url. A decoded token MUST be
exactly 32 bytes. The controller stores only:

```text
SHA-256(UTF8("stella enrollment token v1") || token)
```

and token policy metadata. It compares the digest in constant time. Tokens are
single-use by default, have an explicit expiry, and MAY be restricted to a
specific network or node public key. A successful registration consumes a
single-use token atomically. Failed attempts do not reveal whether a token,
network, or public key was the mismatching field.

Tokens are transmitted only inside the authenticated TLS channel after server
authentication and version negotiation. They MUST NOT appear in command-line
process listings, logs, URLs, crash reports, or the main TOML configuration.
The CLI accepts a credential file or protected prompt input.

Enrollment is not membership. It allows the controller to recognize a node;
the controller still evaluates each requested network join.

## 7. Membership grant

A membership grant is a controller-signed, portable authorization for one node
in one network and controller epoch. It lets peers validate a session handshake
without trusting endpoint metadata as authorization.

The grant is exactly 240 bytes:

| Offset | Size | Field | Validation |
| ---: | ---: | --- | --- |
| 0 | 4 | `magic` | ASCII `SML1`, bytes `53 4d 4c 31` |
| 4 | 1 | `format_version` | `1` |
| 5 | 1 | `confidentiality_policy` | `0` authenticate-only, `1` encrypt |
| 6 | 2 | `permissions` | Defined bit mask; reserved bits zero |
| 8 | 2 | `total_length` | `240` |
| 10 | 2 | `reserved` | Zero |
| 12 | 16 | `network_id` | Authorized virtual network |
| 28 | 16 | `node_id` | Authorized node identity |
| 44 | 32 | `node_public_key` | Ed25519 public key matching `node_id` |
| 76 | 16 | `controller_id` | Signing controller identity |
| 92 | 8 | `controller_epoch` | Exact epoch of this authorization |
| 100 | 8 | `not_before` | Inclusive Unix time in seconds |
| 108 | 8 | `not_after` | Exclusive Unix time in seconds |
| 116 | 2 | `max_frame_size` | Network policy, 1,514 through 9,216 |
| 118 | 2 | `max_flood_peers` | Network policy, 2 through 256 |
| 120 | 4 | `flood_rate` | Maximum local flood frames per second |
| 124 | 4 | `flood_burst` | Maximum local flood token-bucket burst |
| 128 | 32 | `policy_digest` | SHA-256 of canonical network policy bytes |
| 160 | 16 | `grant_serial` | Non-zero random serial unique to the controller |
| 176 | 64 | `signature` | Ed25519 signature by the controller |

The signature input is:

```text
UTF8("stella membership grant v1") || grant[0..176]
```

It excludes the signature field and has no trailing NUL. Ed25519 verification
uses the controller public key whose derived ID equals `controller_id`.

### 7.1 Permission bits

| Bit | Mask | Name | Meaning |
| ---: | ---: | --- | --- |
| 0 | `0x0001` | `SEND_DATA` | Node may originate Ethernet frames |
| 1 | `0x0002` | `RECEIVE_DATA` | Node may receive Ethernet frames |
| 2-15 | | Reserved | Must be zero |

A normal member has both bits. A sender grant without `SEND_DATA` cannot
authenticate a peer session that sends `DATA`. A local grant without
`RECEIVE_DATA` cannot be used to accept peer data.

### 7.2 Time validity

`not_before` MUST be less than `not_after`. A grant lifetime MUST NOT exceed 24
hours; the reference controller defaults to 15 minutes and refreshes grants
over the control connection.

A verifier with wall-clock time `now` accepts a grant only when:

```text
now + 30 >= not_before
now < not_after + 30
```

where additions are checked for overflow. The 30-second allowance handles
small clock skew; it does not extend peer session keys beyond their own limits.
A node whose clock is not trustworthy refuses new peer sessions and reports a
clock error rather than ignoring validity.

### 7.3 Policy consistency

The controller sends canonical network policy bytes through the control plane.
Their SHA-256 digest MUST equal `policy_digest`. Both peers' grants for one
session MUST have the same network ID, controller ID, controller epoch,
confidentiality policy, frame limit, flood limit, and policy digest.

`flood_rate` and `flood_burst` in a node's own grant are ceilings for traffic it
originates. A peer does not rely on another node to enforce them and MAY apply a
stricter receive limit.

## 8. Controller epoch

Each virtual network under a controller maintains a monotonically increasing
unsigned 64-bit epoch. Epoch zero is reserved. The controller increments that
network's epoch whenever a change must invalidate its distributed
authorization, including:

- membership addition, removal, suspension, or permission change;
- network security or forwarding policy change;
- controller signing-key migration preparation;
- administrator-requested global session invalidation.

Ordinary endpoint changes and heartbeats do not require an epoch change. They
use peer snapshot revisions instead.

A node applies epochs monotonically per `(controller_id, network_id)` and
persists the highest accepted value. It rejects control or peer state below
that value. Receiving a higher authenticated epoch invalidates all lower-epoch
membership grants, peer handshakes, sessions, MAC entries, and incomplete
reassembly state for the affected network.

Epoch exhaustion is a fatal condition for that network. The value MUST NOT
wrap.

## 9. Revocation

Revocation is represented by a newer controller epoch and updated peer state.
The controller MAY additionally distribute revoked grant serials within the
current epoch for emergency invalidation, but a peer cannot depend on receiving
that optional optimization.

Therefore authorization has two bounds:

1. connected nodes apply authenticated revocation as soon as the newer epoch is
   received;
2. disconnected nodes stop accepting a grant at its `not_after` deadline.

The reference 15-minute grant lifetime is the default maximum disconnected
revocation delay. Administrators requiring a shorter bound configure shorter
grants at the cost of greater controller dependence.

## 10. Private-key storage

Long-term keys are serialized as standards-compatible PKCS#8 objects. Secret
files are written atomically and never overwritten in place without a backup or
explicit rotation operation.

On Windows, the reference implementation stores identity files beneath a
user-selected state directory and applies an ACL granting access only to the
owning user and `SYSTEM`. Service installations may grant the configured
service identity instead. If an existing key file is writable by an unrelated
principal, the client refuses to use it unless an explicit recovery command
repairs the ACL.

Keys are zeroized from temporary mutable buffers. The implementation does not
claim that every operating-system or allocator copy can be erased. Debug output
for a secret type MUST redact its contents.

Backing up a private key preserves the same node identity and must be protected
as strongly as the original. Copying one identity to concurrently running
nodes is unsupported because it breaks endpoint, sequence, and accountability
assumptions.

## 11. Validation checklist

Before accepting a membership grant, an implementation verifies all of the
following in a stable order:

1. exact 240-byte length and magic;
2. supported format version and zero reserved fields/bits;
3. valid enum, limits, permissions, and time ordering;
4. node ID derived from the included node public key;
5. configured controller ID derived from its trusted public key;
6. controller signature over the canonical 176-byte body;
7. current time with the defined skew allowance;
8. non-stale controller epoch and non-revoked serial;
9. network and policy consistency with authenticated controller state;
10. permission suitability for the requested operation.

Any failure rejects the grant without partially updating membership or peer
state.
