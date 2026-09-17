"""Independently verify the public session-v1 fixture (requires cryptography)."""

from pathlib import Path
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ROOT = Path(__file__).resolve().parent


def read_values(name):
    return {
        key: bytes.fromhex(value)
        for key, value in (
            line.split("=", 1) for line in (ROOT / name).read_text().splitlines()
        )
    }


def verify():
    vector = read_values("session-v1.txt")
    initiation, response = vector["init"], vector["response"]
    controller = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([99]) * 32)
    for message, seed, domain in (
        (initiation, 11, b"stella session init v1"),
        (response, 12, b"stella session response v1"),
    ):
        key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        key.public_key().verify(message[-64:], domain + message[:-64])
        grant = message[96:336]
        controller.public_key().verify(
            grant[-64:], b"stella membership grant v1" + grant[:-64]
        )
        assert hashlib.sha256(vector["policy"]).digest() in grant[:-64]
    transcript = hashlib.sha256(
        b"stella session transcript v1" + initiation + response
    ).digest()
    assert transcript == vector["transcript_hash"]
    alice = x25519.X25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    bob = x25519.X25519PrivateKey.from_private_bytes(bytes([9]) * 32)
    shared = alice.exchange(bob.public_key())
    prk = hmac.digest(transcript, shared, "sha256")
    keys = {"shared_secret": shared, "hkdf_prk": prk}
    for name, label, size in (
        ("i2r_key", b"stella data i2r key v1", 32),
        ("r2i_key", b"stella data r2i key v1", 32),
        ("i2r_nonce", b"stella data i2r nonce v1", 4),
        ("r2i_nonce", b"stella data r2i nonce v1", 4),
        ("confirm_i_key", b"stella confirm initiator v1", 32),
        ("confirm_r_key", b"stella confirm responder v1", 32),
    ):
        keys[name] = hmac.digest(prk, label + b"\x01", "sha256")[:size]
    for name in ("confirm_i", "confirm_r"):
        record = vector[name]
        aad = b"stella session confirm v1" + transcript + record[:-16]
        assert ChaCha20Poly1305(keys[name + "_key"]).decrypt(
            bytes(12), record[-16:], aad
        ) == b""
    for name, header_size, expected in (
        ("data", 104, vector["frame"]), ("keepalive", 88, b""),
    ):
        record = vector[name]
        nonce = keys["i2r_nonce"] + record[56:64]
        assert ChaCha20Poly1305(keys["i2r_key"]).decrypt(
            nonce, record[header_size:], record[:header_size]
        ) == expected
    return keys


if __name__ == "__main__":
    keys = verify()
    assert keys == read_values("session-v1-keys.txt")
    print("Verified Ed25519 grants and handshake, X25519/HKDF keys, confirmations, DATA and KEEPALIVE.")
