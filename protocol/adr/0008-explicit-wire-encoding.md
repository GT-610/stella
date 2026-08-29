# ADR 0008: Use explicit checked wire encoding

- Status: Accepted
- Date: 2026-08-29

## Context

Stella needs byte-exact formats that can be implemented in languages with
different alignment, enum, and object-layout rules. Parsers consume hostile
datagrams and control messages. Candidate Rust strategies included mapping
structures with `zerocopy` or `bytemuck`, using a general serialization
framework, and manually encoding documented fields.

Memory-layout mapping makes padding, alignment, endianness, and versioning easy
to get wrong. General serialization can be safe but may leave canonical bytes,
unknown fields, and allocation behavior dependent on a library rather than the
protocol specification.

## Decision

All Stella wire fields have an explicit byte offset, width, byte order, and
validation rule in the normative specification. Multi-byte integers use
network byte order. Flags reserve unknown bits as zero unless a specification
explicitly defines an ignore rule. Variable-length values carry bounded
unsigned lengths. Text, where permitted, is well-formed UTF-8 without a NUL
terminator.

The Rust codec uses checked slice cursors and integer `from_be_bytes` and
`to_be_bytes` operations. It may borrow validated input slices to avoid copies,
but it does not cast untrusted bytes to Rust structures and does not expose an
on-wire structure through `repr(C)` or `repr(packed)`.

Control-plane extensibility uses four-byte-aligned TLVs with explicit critical
and non-critical type ranges. Data-plane extensions use the header length and
the same alignment rule. Unknown critical fields cause rejection; unknown
non-critical fields are skipped after their bounds and padding are validated.

Serde is permitted for human-readable configuration and controller persistence
only. It is not a Stella wire encoding.

Every decoder returns a typed error for truncation, overflow, unsupported
versions, invalid enum values, unknown critical fields, non-zero reserved bits,
and semantic inconsistency. Production decoders contain no `unwrap` or panic
path. Unit vectors and property tests cover round trips and arbitrary input.

## Consequences

The specification, rather than a Rust dependency, determines interoperability.
The implementation has more codec code and must review each offset carefully,
but it gains canonical bytes, bounded allocation, portable test vectors, and
clear malformed-input behavior.
