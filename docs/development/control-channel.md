# Control-channel implementation

`stella-control` contains the connection mechanics shared by the controller
and client. Normative bytes remain defined in the control-plane specification
and encoded by `stella-proto`.

## Boundary

The crate owns four related concerns:

1. `RecordReader` reads a fixed four-byte prefix, validates the protocol bounds,
   then reads exactly one owned record body.
2. `RecordWriter` writes one encoded prefix and complete message body to an
   ordered asynchronous byte stream.
3. `MessageBuilder` owns field bytes, sorts nothing implicitly, and delegates
   canonical header and TLV validation to `stella-proto`.
4. Connection state allocates outbound message IDs, verifies exact inbound
   sequence, and tracks at most 256 outstanding correlations.

The reader and writer are generic over Tokio `AsyncRead` and `AsyncWrite`.
They therefore work with split TLS streams, TCP test streams, and in-memory
duplex streams without knowing how the carrier was established.

Controller authorization, token consumption, network state, certificate trust,
TCP connection policy, and reconnect behavior do not belong in this crate.

## Allocation and ownership

The four-byte length is read into stack storage. Lengths below the 32-byte
control header or above 1,048,576 bytes fail before allocating the body. EOF at
a record boundary is reported separately from truncated prefix or body input.

Decoded messages own their record bytes. Views into a record are recreated
only while processing that owner, so no slice borrowed from an I/O buffer can
outlive the operation or cross an `.await`. Outbound fields are also owned;
credential-bearing builders redact values from `Debug` output.

## Sequencing and correlation

Each direction begins at message ID 1. Sending reserves exactly one ID only
after a complete message can be encoded. Receiving accepts exactly the expected
ID and advances only after the full message passes structural validation.
Zero, gaps, duplicates, lower values, and wrap are fatal connection errors.

A request registers its non-zero message ID in a bounded set. A direct response
must remove the matching ID exactly once. Unknown, duplicate, or already
completed correlations are protocol errors. Unsolicited messages and requests
must carry correlation zero.

## TLS exporter proofs

The TLS stack supplies exporter bytes using label
`EXPORTER-Stella-Control-v1`. `stella-control` builds the exact controller and
node proof transcripts from the selected protocol entry, both nonces,
identities, public keys, and exporter bytes. Signature generation and
verification use `stella-crypto`; TLS exporter access and certificate policy
remain with the caller.

Transcript helpers take typed fixed-size inputs and return owned bytes. They do
not accept pre-concatenated arbitrary data, which prevents callers from
silently changing field order or omitting a binding.

## Required tests

Tests split every possible prefix boundary and representative body boundaries,
coalesce multiple records into one read, truncate each framing component,
exercise minimum and maximum lengths, reject a one-byte oversize declaration,
and verify write output byte for byte. State tests cover sequence gaps, wrap,
correlation exhaustion, duplicate responses, and connection reset. Fixed
vectors cover both proof transcripts.
