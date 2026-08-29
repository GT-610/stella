# Stella Data-Plane Wire Format

- Status: Draft
- Protocol version: 0.1
- Last updated: 2026-08-29

## 1. Scope

This document defines the common Stella datagram envelope and the protected
Ethernet data packet. Peer session handshake bodies are defined in
`08-security.md`. All offsets in this document are zero based. All multi-byte
integers are unsigned and encoded in network byte order.

Stella transports complete Ethernet frames excluding the Ethernet frame check
sequence (FCS). An implementation MUST NOT synthesize, carry, or verify an FCS
unless a future negotiated extension says otherwise.

## 2. Datagram processing order

A receiver processes every datagram in this order:

1. Check that at least the 32-byte common header is present.
2. Validate magic, version, packet type, flags, lengths, and reserved fields.
3. Validate the complete type-specific header and extension area without
   allocating from attacker-controlled lengths.
4. Resolve the network, sender, controller epoch, session, and directional key.
5. Apply replay-window prechecks without committing replay state.
6. Authenticate and, when selected, decrypt the protected payload.
7. Commit replay state.
8. Validate fragment metadata and update bounded reassembly state.
9. After a complete frame exists, validate Ethernet metadata, update eligible
   forwarding state, and deliver the frame to TAP.

Failure at any step discards the datagram. A receiver MAY increment a bounded
diagnostic counter, but it MUST NOT include unauthenticated payload bytes or
secret material in logs or error responses.

## 3. Common datagram header

Every Stella data-plane datagram begins with this 32-byte header:

| Offset | Size | Field | Value and validation |
| ---: | ---: | --- | --- |
| 0 | 4 | `magic` | ASCII `STLA`, bytes `53 54 4c 41` |
| 4 | 1 | `version_major` | `0` for version 0.1 |
| 5 | 1 | `version_minor` | `1` for version 0.1 |
| 6 | 1 | `packet_type` | Value from the packet type registry |
| 7 | 1 | `flags` | Type-specific flags; all reserved bits are zero |
| 8 | 2 | `header_length` | Entire header in bytes, including this common header and extensions |
| 10 | 2 | `reserved` | Zero |
| 12 | 4 | `payload_length` | Bytes after the header and before any type-defined trailer |
| 16 | 16 | `network_id` | Target virtual network identifier |

`header_length` MUST be a multiple of four, MUST be at least 32, and MUST NOT
exceed 1,024. The datagram length MUST exactly match the formula for its packet
type; trailing bytes are an error.

The common header does not by itself prove that a network exists or that the
sender is a member. Receivers perform those checks using authenticated session
or signature state.

### 3.1 Packet type registry

| Value | Name | Header/body definition |
| ---: | --- | --- |
| `0x01` | `DATA` | This document |
| `0x10` | `SESSION_INIT` | Security specification |
| `0x11` | `SESSION_RESPONSE` | Security specification |
| `0x12` | `SESSION_CONFIRM` | Security specification |
| `0x13` | `SESSION_REJECT` | Security specification |
| `0x00`, `0x02`-`0x0f`, `0x14`-`0x7f` | Reserved | Reject in version 0.1 |
| `0x80`-`0xff` | Experimental/private | Reject unless explicitly enabled outside an interoperable network |

An implementation MUST NOT reinterpret a reserved type as another type after
parsing has begun.

## 4. Header extensions

Bytes between a packet type's fixed header and `header_length` form a sequence
of aligned TLVs:

| Offset within TLV | Size | Field | Meaning |
| ---: | ---: | --- | --- |
| 0 | 2 | `extension_type` | Registered type; bit 15 is the critical bit |
| 2 | 2 | `extension_length` | Value length in bytes, excluding this prefix and padding |
| 4 | variable | `value` | Extension-defined bytes |
| after value | 0-3 | `padding` | Zero bytes to the next four-byte boundary |

Extension type zero is invalid. Types `0x0001` through `0x7fff` are
non-critical; an unknown type in that range is skipped after full bounds and
padding validation. Types `0x8001` through `0xffff` are critical; an unknown
critical type causes the packet to be rejected. No extensions are registered
for version 0.1.

An extension whose prefix, value, or padding crosses `header_length` is
invalid. Non-zero padding is invalid. A known extension defines whether it may
repeat; otherwise a duplicate known extension is invalid.

## 5. `DATA` packet

### 5.1 Fixed header

`DATA` uses a 104-byte fixed header. Its first 32 bytes are the common header.

| Offset | Size | Field | Value and validation |
| ---: | ---: | --- | --- |
| 0 | 32 | `common` | Common header with `packet_type = 0x01` |
| 32 | 16 | `sender_node_id` | Authenticated sending node |
| 48 | 8 | `session_id` | Non-zero peer session identifier |
| 56 | 8 | `sequence_number` | Directional packet sequence number |
| 64 | 8 | `controller_epoch` | Epoch authorizing this peer session |
| 72 | 8 | `frame_id` | Identifier shared by every fragment of one Ethernet frame |
| 80 | 2 | `frame_length` | Complete Ethernet frame length before fragmentation |
| 82 | 2 | `fragment_offset` | Byte offset of this fragment in the frame |
| 84 | 2 | `fragment_length` | Protected fragment bytes in this packet |
| 86 | 2 | `reserved_1` | Zero |
| 88 | 6 | `source_mac` | Source address copied from Ethernet bytes 6 through 11 |
| 94 | 6 | `destination_mac` | Destination address copied from Ethernet bytes 0 through 5 |
| 100 | 2 | `outer_ether_type` | Ethernet bytes 12 and 13, without interpretation |
| 102 | 2 | `reserved_2` | Zero |

For version 0.1:

- `header_length` MUST be at least 104;
- `payload_length` MUST equal `fragment_length`;
- `flags & 0xfe` MUST be zero;
- flag bit `0x01` is `ENCRYPTED`;
- both reserved fields MUST be zero;
- `session_id`, `sequence_number`, and `frame_id` MUST be non-zero;
- `controller_epoch` MUST match the active peer session;
- `sender_node_id` MUST match the authenticated session direction.

The 16-byte ChaCha20-Poly1305 tag immediately follows the fragment payload and
is not included in `payload_length`.

The exact datagram length is therefore:

```text
header_length + fragment_length + 16
```

### 5.2 Canonical fixed-header example

The following is a structural example only; it omits fragment bytes and the
authentication tag. It represents an unextended, authenticate-only `DATA`
header for network bytes `00..0f`, sender bytes `10..1f`, session 1, sequence
2, epoch 3, frame ID 4, and one unfragmented 14-byte Ethernet frame.

```text
0000  53 54 4c 41 00 01 01 00 00 68 00 00 00 00 00 0e
0010  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
0020  10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
0030  00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 02
0040  00 00 00 00 00 00 00 03 00 00 00 00 00 00 00 04
0050  00 0e 00 00 00 0e 00 00 02 00 00 00 00 02
005e  02 00 00 00 00 01 08 00 00 00
```

The split at `005e` is for readability and has no wire meaning. Implementations
SHOULD generate equivalent fixed-header vectors directly from the field table
and MUST treat the table as authoritative if presentation wrapping differs.

## 6. Ethernet frame rules

The reassembled bytes are one Ethernet frame from destination MAC through the
end of payload, without preamble, start delimiter, inter-packet gap, or FCS.

The protocol hard limits are:

| Property | Limit |
| --- | ---: |
| Minimum complete frame | 14 bytes |
| Maximum complete frame | 9,216 bytes |
| Minimum fragment | 1 byte |
| Maximum fragment | `transport_max_datagram - header_length - 16` |

Each virtual network advertises a `max_frame_size` between 1,514 and 9,216
bytes. A node MUST reject a frame larger than the smaller of that policy and
its local TAP capability. The reference Windows configuration defaults to
1,514 bytes, which represents an Ethernet frame carrying a 1,500-byte MTU
without an FCS. Networks that need an 802.1Q tag set at least 1,518.

After reassembly, a receiver MUST verify:

- bytes 0 through 5 equal `destination_mac` from every fragment;
- bytes 6 through 11 equal `source_mac` from every fragment;
- bytes 12 and 13 equal `outer_ether_type` from every fragment;
- the source MAC is neither multicast nor all zero;
- the destination and source do not violate an explicit network policy;
- the complete length equals `frame_length`.

The outer EtherType field is a verbatim copy. Values at or below 1,500 retain
their IEEE 802.3 length interpretation. Values such as `0x8100` and `0x88a8`
indicate that VLAN tag bytes remain inside the unchanged frame. Stella does not
strip, insert, or reinterpret VLAN tags in version 0.1.

Broadcast is destination `ff:ff:ff:ff:ff:ff`. Any other destination with the
group bit set is multicast. Other destinations are unicast. These rules are
used by the sender's forwarding decision and are not encoded in a trusted flag.

## 7. Fragmentation

Stella fragments at its data-packet layer so a full Ethernet frame does not
depend on IP fragmentation. The sender determines the largest fragment that
fits the transport's current datagram limit after the Stella header and tag.

For every fragment:

```text
0 < fragment_length
fragment_offset < frame_length
fragment_offset + fragment_length <= frame_length
```

The addition MUST be checked without integer wrap. A frame is unfragmented when
`fragment_offset` is zero and `fragment_length == frame_length`.

All fragments of one frame MUST carry identical values for network,
sender, session, controller epoch, frame ID, frame length, source MAC,
destination MAC, outer EtherType, encryption flag, and extension sequence.
Each fragment has a distinct increasing session `sequence_number` and is
authenticated independently.

The sender assigns a monotonically increasing non-zero `frame_id` within a
session direction. Wrap is forbidden; the session rekeys before exhaustion.
Fragment offsets need not arrive in order. Senders SHOULD create contiguous
non-overlapping fragments and SHOULD send them in ascending offset order.

### 7.1 Receiver reassembly

Reassembly state is keyed by:

```text
(network_id, sender_node_id, session_id, frame_id)
```

The reference limits per peer session are:

- at most 64 incomplete frames;
- at most 1 MiB of allocated reassembly storage;
- a three-second lifetime from the first accepted fragment;
- at most 128 authenticated fragments for one frame.

Networks MAY lower these limits but MUST NOT raise the protocol hard maximum
frame size. When a limit would be exceeded, the receiver drops the oldest
incomplete frame for that peer or rejects the new frame according to a stable
local policy; it MUST NOT create an unbounded queue.

An exact duplicate range with identical authenticated bytes is ignored. Any
partial overlap, conflicting metadata, conflicting duplicate, or range outside
the declared frame length discards the entire incomplete frame. Timeout also
discards the entire incomplete frame. No partial Ethernet frame is written to
TAP.

## 8. Packet protection

The session security specification derives a 32-byte directional key and a
four-byte nonce prefix. The 12-byte nonce for one `DATA` packet is:

```text
nonce_prefix || sequence_number
```

where the sequence number is its eight-byte wire representation.

### 8.1 Encrypted mode

When `ENCRYPTED` is set:

- AEAD associated data is every byte from offset zero through
  `header_length - 1`, including extension padding;
- AEAD plaintext is this fragment of the Ethernet frame;
- the packet carries ciphertext of the same length followed by the 16-byte tag.

### 8.2 Authenticate-only mode

When `ENCRYPTED` is clear:

- AEAD associated data is the entire header followed by the plaintext fragment;
- AEAD plaintext is empty;
- the packet carries the unchanged fragment followed by the 16-byte tag
  produced for the empty plaintext.

Header and fragment concatenation is conceptual; an implementation may use a
scatter/gather AEAD API or one bounded temporary buffer. It MUST produce the
same bytes as direct concatenation.

In both modes the receiver authenticates before exposing payload bytes to
reassembly, MAC learning, TAP, or diagnostics. A tag failure does not reveal
whether any inner field would otherwise have been valid.

## 9. Replay handling

Each session direction starts with sequence number 1. Senders increment by one
for every protected packet, including every fragment, and never transmit zero.
Lost sequence numbers are not reused.

Receivers maintain a 1,024-packet sliding window. A sequence number is a replay
candidate when it is older than the window or already marked. The receiver MAY
drop an obvious candidate before AEAD work, but it commits a new sequence
number to the window only after successful authentication. Authentication
failure MUST NOT advance the highest accepted number.

Packets from an expired session, stale controller epoch, revoked member, or
unknown network are rejected even if their tag would otherwise verify.

## 10. Forwarding and learning implications

A sender creates a separate protected packet stream for each destination peer.
Flood replication therefore uses each peer session's distinct key, nonce
prefix, session ID, and sequence numbers.

A receiver may learn `source_mac -> sender_node_id` only after the complete
frame has been authenticated, reassembled, and validated. It MUST NOT learn
from a handshake packet, failed tag, incomplete frame, or a frame whose source
is multicast or zero.

Version 0.1 never forwards a transport-originated frame to another transport
peer. After validation it is written to the local network TAP adapter only.

## 11. Malformed input requirements

At minimum, the decoder returns distinct typed errors for:

- truncated common or type-specific header;
- invalid magic or unsupported version;
- unknown packet type or reserved flag;
- invalid, unaligned, or excessive header length;
- payload or total-length mismatch;
- non-zero reserved field or padding;
- invalid or unknown critical extension;
- invalid frame or fragment length;
- integer overflow in range calculation;
- inconsistent Ethernet metadata;
- unknown, stale, or directionally invalid session;
- replay candidate;
- authentication failure;
- reassembly conflict or resource-limit rejection.

Network input MUST NOT cause a panic, out-of-bounds access, integer wrap,
unbounded allocation, or attacker-controlled blocking log volume.

## 12. IANA-style protocol registries

Until a formal registry exists, the Stella specification repository owns these
registries:

- packet types;
- common and type-specific flag bits;
- header extension types;
- protocol major and minor versions.

Changing an assigned meaning is forbidden. New critical semantics require a
new specification entry and compatibility analysis. Experimental values MUST
NOT appear in default production configuration or be sent to a peer that has
not explicitly enabled the same experiment.
