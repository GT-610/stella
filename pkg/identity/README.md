# Identity Module

This module provides identity authentication functionality for the Stella network project, implementing ZeroTier-compatible node identity management with cryptographic verification capabilities.

## Core Features

### Identity Management
- Node identity generation with cryptographic key pairs
- Identity serialization and deserialization
- Address derivation from public keys (ZeroTier-compatible)
- Private key management with secure handling

### Authentication
- Identity validation and integrity checking
- Address verification against public keys
- Shared secret derivation for secure communication
- Public/private key authentication mechanisms

### Serialization
- Compact string representation of identities
- Base64 encoding for key storage
- Optional private key inclusion in serialized form
- Human-readable address formats

## File Structure

```
pkg/identity/
└── identity.go  # Core identity implementation
```

## Usage Examples

### Creating a New Identity

```go
import "github.com/stella/virtual-switch/pkg/identity"

// Generate a new identity with public and private keys
id, err := identity.NewIdentity()
if err != nil {
    // Handle error
}

// Access identity components
address := id.Address
publicKey := id.PublicKey
privateKey := id.PrivateKey

// Check if identity has private key
hasPrivate := id.HasPrivateKey()
```

### Creating an Identity from Public Key

```go
// Create identity from only public key (no private key)
publicKey := []byte{...} // Some public key
publicIdentity, err := identity.NewIdentityFromPublic(publicKey)
if err != nil {
    // Handle error
}
```

### Serializing and Deserializing Identities

```go
// Serialize identity to string
identityStr := id.Serialize()

// Deserialize identity from string
restoredId, err := identity.NewIdentityFromString(identityStr)
if err != nil {
    // Handle error
}
```

### Identity Validation

```go
// Validate that address matches public key
isValid := id.Validate()

// If validation fails, the identity may be compromised
if !isValid {
    // Handle invalid identity
}
```

### Secure Communication with Shared Secrets

```go
// Establish secure communication between two identities
myIdentity, _ := identity.NewIdentity()
peerIdentity, _ := identity.NewIdentity()

// Derive shared secret for encryption
sharedSecret, err := myIdentity.GetSharedSecret(peerIdentity)
if err != nil {
    // Handle error
}

// Use sharedSecret for encryption/decryption
// (See crypto module for encryption usage)
```

## ZeroTier Compatibility

### Compatibility Scope
This module implements the node identity system used by ZeroTier One, ensuring full compatibility with ZeroTier networks and nodes. Identities created with this module can be used to authenticate and communicate with ZeroTier nodes.

### Version Requirements
- ZeroTier: 1.8.0 or newer
- All identity formats and key derivations follow ZeroTier specifications

### Implementation Details
- Identities consist of a 5-byte address and Curve25519 key pair
- Addresses are cryptographically derived from public keys
- Serialization format matches ZeroTier's identity string format
- Shared secret derivation uses the same algorithm as ZeroTier

### Configuration Requirements
- No special configuration needed for basic operation
- For interoperability with ZeroTier nodes, use only the provided identity generation methods

## Security Considerations

- Store private keys securely and avoid transmitting them unnecessarily
- Validate identities before trusting them in your application
- Use the `String()` method (rather than `Serialize()`) for logging and display to avoid exposing private keys
- Implement proper key rotation and identity management policies

## Testing

To test the identity module:

```bash
cd /home/gt610/code/stella
go test ./pkg/identity/... -v
```

## Best Practices

- Generate a single identity per node rather than multiple identities
- Store serialized identities with private keys in secure storage
- Validate identities received from other nodes
- Use the shared secret mechanism for secure node-to-node communication
- Implement identity revocation mechanisms if needed

## Troubleshooting

### Common Issues

1. **Invalid identity string format**: Ensure the string follows the format `<address>:<base64-public-key>[:<base64-private-key>]`
2. **Identity validation failures**: This could indicate tampering or corruption - discard the identity
3. **Address mismatch errors**: When deriving addresses, ensure you're using the correct public key
4. **Private key handling**: Never log or transmit private keys in plaintext

### Error Handling

Pay special attention to errors returned from identity creation and validation functions, as these often indicate security issues that should be addressed immediately.