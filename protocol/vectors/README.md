# Complete session interoperability fixture

`session-v1.txt` and `session-v1-keys.txt` are newline-delimited `name=hex`
records. All integers inside encoded messages use the protocol byte order.
The fixture covers signed INIT/RESPONSE, both confirmations, transcript hash,
policy, original Ethernet frame, encrypted DATA and KEEPALIVE. The key file
contains the X25519 shared secret, HKDF PRK, two data keys, two nonce prefixes
and two confirmation keys.

Inputs are public test data: Ed25519 seeds are 32 repetitions of decimal 99
(controller), 11 (initiator) and 12 (responder); X25519 private inputs repeat
7 and 9; handshake nonces repeat 13 and 14. Grant serials are 21 and 22,
handshake ID is 41, session ID is 42, and validation time is 1788000000 Unix
seconds. The encoded grants and headers contain the remaining identifiers,
expiry, epoch and policy digest. Do not use these keys in a deployment.

Run the independent verifier with Python 3 and the `cryptography` package:

```sh
python -m pip install cryptography
python protocol/vectors/verify.py
```

It verifies controller and node signatures, transcript hashing, X25519,
HKDF-SHA256, confirmation HMACs, AEAD tags and plaintext. Every unmodified
fixture must validate. Rust tests reconstruct the exact bytes using internal
test fixtures, then flip one bit at every byte offset of INIT, RESPONSE, both
confirmations, DATA and KEEPALIVE; each mutation must fail before the original
packet is accepted. No production key-export or authentication-bypass API is
introduced for these vectors.
