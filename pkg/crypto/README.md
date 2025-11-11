# Crypto Module

This module provides cryptographic functionality for the Stella network project, implementing secure communication protocols compatible with ZeroTier network standards. It includes key exchange, encryption, authentication, and hashing mechanisms.

## Core Features

### Key Generation and Management
- Curve25519 key pair generation
- P256 (NIST) elliptic curve key pair generation
- Shared secret derivation using ECDH (Elliptic Curve Diffie-Hellman)
- Key validation and integrity checking

### Encryption
- Salsa20/12 stream cipher implementation
- Authenticated encryption with Poly1305
- Multiple cipher suite support
- ZeroTier-compatible encryption modes

### Authentication and Hashing
- SHA-512 hashing
- Poly1305 message authentication codes
- Constant-time comparison functions
- Data integrity verification

## File Structure

```
pkg/crypto/
├── crypto.go      # Core cryptographic implementations
└── crypto_test.go # Unit tests for cryptographic functions
```

## Usage Examples

### Key Pair Generation

```go
import "github.com/stella/virtual-switch/pkg/crypto"

// Generate Curve25519 key pair (ZeroTier default)
keyPair, err := crypto.GenerateKeyPair()
if err != nil {
    // Handle error
}

// Access public and private keys
publicKey := keyPair.Public
privateKey := keyPair.Private

// Generate P256 key pair (alternative)
p256KeyPair, err := crypto.GenerateP256KeyPair()
if err != nil {
    // Handle error
}
```

### Shared Secret Derivation

```go
// Alice and Bob each generate their own key pairs
aliceKeyPair, _ := crypto.GenerateKeyPair()
bobKeyPair, _ := crypto.GenerateKeyPair()

// Alice derives shared secret using her private key and Bob's public key
aliceSharedSecret, err := crypto.DeriveSharedSecret(aliceKeyPair.Private, bobKeyPair.Public)

// Bob derives shared secret using his private key and Alice's public key
bobSharedSecret, err := crypto.DeriveSharedSecret(bobKeyPair.Private, aliceKeyPair.Public)

// Both secrets should be identical
aliceSharedSecret == bobSharedSecret
```

### Encryption and Decryption

```go
// Prepare encryption key and nonce
key := make([]byte, 32)
nonce := make([]byte, 8)
// (In real usage, generate secure random values for key and nonce)

// Plaintext message
plaintext := []byte("This is a confidential message")

// Encrypt using Salsa20/12
ciphertext, err := crypto.EncryptSalsa2012(plaintext, key, nonce)

// Decrypt the ciphertext
decrypted, err := crypto.DecryptSalsa2012(ciphertext, key, nonce)

// With Poly1305 authentication
authCiphertext, err := crypto.EncryptSalsa2012WithPoly1305(plaintext, key, nonce)
authDecrypted, err := crypto.DecryptSalsa2012WithPoly1305(authCiphertext, key, nonce)
```

### Hashing and Authentication

```go
// Compute SHA-512 hash
message := []byte("Message to hash")
hash := crypto.Hash(message) // 64-byte hash

// Poly1305 authentication
polyKey := make([]byte, 32) // 32-byte authentication key
mac, err := crypto.Poly1305Authenticate(message, polyKey)

// Verify MAC
isValid := crypto.Poly1305Verify(message, polyKey, mac)
```

## ZeroTier Compatibility

### Compatibility Scope
This module implements cryptographic protocols compatible with ZeroTier One versions 1.8.0 through 1.12.x. It supports the core encryption and key exchange mechanisms used by ZeroTier networks.

### Version Requirements
- ZeroTier: 1.8.0 or newer
- Go: 1.20 or newer
- Dependencies: golang.org/x/crypto (curve25519, poly1305)

### Cipher Suites

The module implements the following ZeroTier-compatible cipher suites:

1. **CipherC25519_POLY1305_NONE** (0)
   - Curve25519 for key exchange
   - No data encryption (used for plaintext communication)

2. **CipherC25519_POLY1305_SALSA2012** (1)
   - Curve25519 for key exchange
   - Poly1305 for authentication
   - Salsa20/12 for encryption
   - Primary cipher suite used by ZeroTier

3. **CipherAES_GMAC_SIV** (2)
   - Alternative cipher suite placeholder
   - Implementation may vary

### Implementation Notes
- Curve25519 key exchange follows RFC 7748
- Salsa20/12 implementation uses 12 rounds (standard Salsa20 uses 20)
- Shared secrets are hashed with SHA-512 to ensure fixed output length
- Constant-time comparison functions prevent timing attacks

## Security Considerations

- Always use secure random sources for key and nonce generation
- Never reuse the same nonce with the same encryption key
- Verify authentication tags before processing decrypted data
- Use constant-time comparison functions for secret data comparison
- Implement proper key rotation policies in your application

## Testing

To run the cryptographic tests:

```bash
cd /home/gt610/code/stella
go test ./pkg/crypto/... -v
```

## Troubleshooting

### Common Issues

1. **Key size errors**: Ensure Curve25519 keys are exactly 32 bytes
2. **Nonce size errors**: Salsa20/12 nonces must be exactly 8 bytes
3. **Authentication failures**: Check if the correct key was used for verification
4. **Encryption/decryption mismatches**: Verify the same key and nonce are used for both operations

### Performance Considerations

- Salsa20/12 is faster than AES on many platforms, especially with hardware acceleration
- For large data transfers, consider buffering to improve performance
- SHA-512 is CPU-intensive; use it appropriately in your application