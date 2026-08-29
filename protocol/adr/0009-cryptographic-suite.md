# ADR 0009: Use the Stella 0.1 cryptographic suite

- Status: Accepted
- Date: 2026-08-29

## Context

Stella must authenticate nodes, isolate networks, protect control messages,
authenticate every data packet, optionally conceal Ethernet frames, resist
replay, and retain security when the carrying network is compromised. The
project must not implement cryptographic primitives.

## Decision

Protocol version 0.1 defines one mandatory suite:

- Ed25519 for long-term node identity signatures and controller-signed Stella
  objects;
- X25519 with fresh ephemeral keys for peer data-session key agreement;
- SHA-256 for transcript and identifier hashing;
- HKDF-SHA256 for domain-separated key and nonce-prefix derivation;
- ChaCha20-Poly1305 with a 128-bit tag for data-packet authentication and
  optional encryption;
- TLS 1.3 through `rustls` for control-channel protection;
- operating-system cryptographic randomness through `getrandom`.

The Rust implementation uses established crates including `ed25519-dalek`,
`x25519-dalek`, `sha2`, `hkdf`, `chacha20poly1305`, `zeroize`, and `getrandom`.
It does not implement elliptic-curve arithmetic, hashes, KDFs, ciphers, tags,
or random generators.

A node identifier is the first 16 bytes of:

```text
SHA-256("stella node id v1" || ed25519_public_key)
```

The ASCII domain string is encoded without a trailing NUL. Long-term private
keys never cross the network. Peer handshakes sign both ephemeral X25519 keys,
both node identifiers, the network identifier, the controller epoch, and the
negotiated version. HKDF derives independent send keys and four-byte nonce
prefixes for each direction. A packet nonce is:

```text
nonce_prefix[4] || sequence_number_be[8]
```

Sequence numbers never repeat under one directional key. A session rekeys
before one hour, before 2^32 protected packets in either direction, or after a
membership or controller-epoch change, whichever occurs first.

Encrypted mode authenticates the complete Stella header as AEAD associated
data and encrypts the Ethernet frame. Authenticate-only mode leaves the frame
visible, places the complete header and frame in AEAD associated data, uses an
empty plaintext, and transmits the resulting tag. Both modes therefore use the
same mandatory primitive and nonce rules.

Receivers maintain a 1,024-packet sliding replay window per direction and
session. They authenticate a packet before committing replay state or learning
a source MAC address.

## Consequences

The suite is implementable with widely deployed, memory-safe libraries and
provides forward secrecy for peer data sessions. Authenticate-only mode avoids
a second MAC construction but still requires unique nonces and rekeying.

Ed25519 and X25519 are not post-quantum secure. Adding another suite requires
versioned negotiation, downgrade protection, test vectors, and a superseding
ADR; version 0.1 does not allow an implementation-defined algorithm choice.
