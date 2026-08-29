# ADR 0007: Run the control plane over TLS 1.3 and TCP

- Status: Accepted
- Date: 2026-08-29

## Context

The control plane carries identity challenges, join credentials, membership,
peer endpoints, policy, and revocation state. It needs reliable ordered
delivery, controller authentication, node authentication, confidentiality,
integrity, replay protection, and explicit protocol version negotiation.

The evaluated options were gRPC over HTTP/2, a custom binary protocol over TLS,
and QUIC. gRPC gives excellent tooling but makes the protobuf schema and HTTP/2
stack part of a small protocol's interoperability surface. QUIC gives stream
multiplexing and migration but adds UDP deployment constraints and duplicates
capabilities that the low-volume control channel does not initially require.

## Decision

Version 0.1 uses a long-lived TCP connection protected exclusively by TLS 1.3.
The Rust implementation uses `rustls` and `tokio-rustls`; it does not enable
TLS 1.2, early data, renegotiation, or application fallback to plaintext.

The controller presents a normal TLS server certificate. A deployment may use
a public or private CA, or a self-signed certificate whose SPKI SHA-256
fingerprint is explicitly pinned in client configuration. Disabling
certificate validation is not a supported mode.

Node authentication occurs inside the protected channel with an Ed25519
signature over a controller nonce and the complete authentication transcript.
The controller proves possession of its TLS certificate private key during the
TLS handshake; the node proves possession of its Stella identity key during
application authentication. Together these provide mutual authentication at
the Stella control-plane boundary without requiring a client X.509 PKI.

Control messages use the Stella explicit binary encoding from ADR 0008. Each
message is preceded by a four-byte unsigned big-endian length that covers the
message body but not the prefix. Version 0.1 rejects a zero-length body and any
body larger than 1 MiB before allocating or reading it in full.

TLS and Stella versions are independent. A successful TLS connection does not
authorize any Stella action until application version negotiation and node
authentication complete.

## Consequences

The design uses a mature standard security channel while preserving a small,
language-neutral application protocol. TCP head-of-line blocking is acceptable
for low-rate control messages and simplifies reconnect and ordering semantics.

The implementation must handle partial reads, bounded buffering, certificate
rotation, pin rollover, timeouts, and application-level authentication failure.
Future protocol versions may add QUIC as another control carrier only after a
new ADR and an explicit carrier negotiation mechanism.
