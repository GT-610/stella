# Protocol codec implementation

This page defines how `stella-common` and `stella-proto` implement the normative
wire specification without making Rust memory layout part of the protocol.

## Boundaries

`stella-common` owns small semantic value types that have no parser state:

- node, controller, network, and grant identifiers;
- MAC addresses and Ethernet destination classification;
- checked hexadecimal display and parsing.

`stella-proto` owns every canonical byte layout:

- common data-plane and control-plane headers;
- data fragments and authenticated keepalive headers;
- aligned header extensions and control body TLVs;
- membership grants and canonical network policy;
- peer handshake bodies and control nested records.

The codec does not open sockets, read clocks, generate randomness, verify
signatures, derive keys, decrypt payloads, or update runtime state. Those
operations consume validated codec values in higher layers.

## Decode model

All input is untrusted. Decoders use a checked slice cursor with explicit
big-endian integer reads. They never cast input bytes to a Rust structure and
never index beyond a previously validated bound.

Decoded packet values borrow payload, extension, signature, and ciphertext
slices from the input when ownership is unnecessary. Fixed-size identifiers
and headers are copied into small value types. A successful decode consumes the
exact supplied record; unexpected trailing bytes are errors.

Parsing is split into two stages where security state is required:

1. structural decode validates magic, version, type, sizes, flags, reserved
   bytes, TLV alignment, and inner range arithmetic;
2. semantic callers resolve membership and keys, authenticate bytes, then call
   post-authentication Ethernet or state validation.

No parser reports unauthenticated Ethernet contents through logs or display
implementations.

## Encode model

Each wire value exposes an exact encoded length and writes into caller-provided
bounded storage. Encoding first validates semantic invariants so it cannot emit
a byte sequence the corresponding strict decoder would reject.

Variable-length collections are checked against protocol limits before their
encoded size is calculated. Size arithmetic uses checked operations. Encoders
zero every reserved and alignment byte explicitly.

Cryptographic callers reserve space for tags and signatures but own the actual
primitive operation. The codec returns or exposes the exact header and body
ranges used as associated data or signature input.

## Errors

`stella-proto` uses one non-exhaustive typed error with stable categories for:

- truncation and unexpected trailing bytes;
- invalid magic, version, type, flag, or enum;
- unaligned, excessive, or inconsistent lengths;
- integer overflow and range violation;
- non-zero reserved or padding bytes;
- unknown critical or duplicate fields;
- invalid identifier, grant, policy, endpoint, fragment, and nested record.

Errors contain safe offsets and field names, never borrowed payload contents.

## Testing

Every public codec has:

- a canonical fixed-byte example;
- minimum and maximum boundary tests;
- one-bit and field-specific invalid cases;
- exact round-trip tests;
- arbitrary-input decoding that must never panic;
- property tests for encode/decode symmetry and checked length calculations.

`stella-proto` targets complete line coverage. Coverage exclusions are limited
to compiler-generated code and are documented rather than silently ignored.

The protocol documentation remains authoritative. A mismatch found while
implementing a vector is fixed in the specification or recorded as errata
before code is made to accept an undocumented alternative.
