# Cryptography implementation

This page defines how `stella-crypto` implements the mandatory version 0.1
suite from ADR 0009. The protocol specification remains authoritative for
every domain string, byte range, nonce, and lifetime rule.

## Primitive dependencies

The crate delegates primitive operations to maintained implementations whose
current releases support the workspace Rust 1.85 baseline:

- `ed25519-dalek` for Ed25519 signing and verification;
- `x25519-dalek` for ephemeral X25519 agreement and contributory checks;
- `sha2` and `hkdf` for SHA-256 and HKDF-SHA256;
- `chacha20poly1305` for detached ChaCha20-Poly1305 tags;
- `getrandom` for operating-system randomness;
- `zeroize` for owned secret buffers and `subtle` for constant-time identifier
  comparison.

Stella never implements curve arithmetic, hashing, HMAC, HKDF, ChaCha20, or
Poly1305 itself. Features that weaken validation or enable legacy signature
acceptance remain disabled.

## Identity keys and signatures

An identity signing key is an owned, non-cloneable secret. It can be generated
from the operating-system RNG or restored from an explicit 32-byte seed wrapper.
Secret wrappers redact `Debug`, expose bytes only through an intentionally named
method, and zeroize on drop. Public keys and signatures are fixed-size public
values.

Persistent controller and node identities use unencrypted PKCS#8 DER rather
than a raw seed file. Encoding and strict algorithm-aware decoding are delegated
to `ed25519-dalek`; inputs are bounded to 4 KiB before parsing. The owned DER
wrapper is non-cloneable, redacts diagnostics, and zeroizes its buffer on drop.
Filesystem access, atomic creation, and Windows ACL checks stay at the
application boundary rather than inside the cryptographic crate.

Node and controller IDs are derived by hashing their distinct normative domain
prefix followed by the compressed Ed25519 public key, then taking the first 16
bytes. Verification recomputes that value and compares all bytes in constant
time. Signing helpers accept a domain and bounded byte segments so callers can
authenticate the exact ranges exposed by `stella-proto` without accidentally
omitting extensions or reserved bytes.

## Ephemeral agreement and session derivation

Every peer exchange owns a fresh non-cloneable X25519 secret. Agreement consumes
the local secret and rejects a non-contributory all-zero shared secret before
HKDF. The raw shared secret and HKDF state are short-lived and zeroized.

One derivation call accepts the exact transcript hash and produces six distinct
outputs from the same HKDF extract:

- two 32-byte directional data keys;
- two four-byte directional nonce prefixes;
- initiator and responder 32-byte confirmation keys.

Each expansion uses the exact `info` string from the security specification.
The returned session-secret object is non-cloneable, redacts `Debug`, and moves
directional material into send/receive owners according to handshake role.

## Packet protection

A directional protector owns one ChaCha20-Poly1305 key and four-byte nonce
prefix. It constructs the 12-byte nonce as the prefix followed by the
big-endian protected-packet sequence number and rejects sequence zero.

Encrypted mode authenticates the complete Stella header and encrypts the
fragment. Authenticate-only mode leaves the fragment unchanged and authenticates
the bounded concatenation of header and fragment as associated data for empty
plaintext. Decryption uses temporary bounded storage and copies plaintext to the
caller only after successful tag verification.

Confirmation keys use an all-zero nonce exactly once per transcript and accept
the domain, transcript hash, header, and payload prefix as explicit associated
data segments.

## Replay window

The receive direction keeps a 1,024-bit sliding bitmap keyed by distance from
the highest authenticated sequence. A precheck classifies zero, duplicate, and
too-old candidates without changing state. Commit repeats the check and updates
the bitmap only after authentication succeeds. A failed tag therefore cannot
advance the highest sequence or mark a slot.

## Errors and tests

`CryptoError` distinguishes randomness failure, malformed public keys or
signatures, signature failure, non-contributory agreement, KDF failure,
authentication failure, invalid sequence numbers, and replay candidates. Error
values never contain key, seed, plaintext, ciphertext, or tag bytes.

Tests exercise published Ed25519, X25519, HKDF-SHA256, and
ChaCha20-Poly1305 vectors through the selected libraries, plus deterministic
Stella identity, transcript, nonce, packet, replay-boundary, failed-tag, secret
redaction, and observable zeroization behavior.
