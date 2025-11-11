# Address Module

This module provides address representation functionality for the Stella network project, implementing both ZeroTier-style network addresses and Ethernet MAC addresses with interoperability features.

## Core Features

### ZeroTier Address Support
- Implements ZeroTier's 5-byte address format
- Address derivation from public keys (following ZeroTier's specification)
- Hexadecimal string conversion and byte array handling
- Address comparison and equality operations

### MAC Address Support
- Ethernet MAC address representation and manipulation
- MAC address generation from ZeroTier addresses
- Random MAC address generation with proper bit formatting
- Broadcast and multicast address detection
- String formatting and parsing (with various delimiter formats)

## File Structure

```
pkg/address/
├── address.go  # ZeroTier-style network address implementation
└── mac.go      # Ethernet MAC address implementation
```

## Usage Examples

### Working with ZeroTier Addresses

```go
import "github.com/stella/virtual-switch/pkg/address"

// Create address from hex string
ztAddr, err := address.NewAddressFromString("a1b2c3d4e5")
if err != nil {
    // Handle error
}

// Get string representation
strAddr := ztAddr.String() // "a1b2c3d4e5"

// Get byte representation
byteAddr := ztAddr.Bytes()

// Derive address from public key (ZeroTier standard)
publicKey := []byte{...} // Your public key
derivedAddr := address.NewAddressFromPublicKey(publicKey)

// Compare addresses
addr1 := address.NewAddressFromString("1122334455")
addr2 := address.NewAddressFromString("1122334455")
isEqual := addr1.Equals(addr2) // true
```

### Working with MAC Addresses

```go
// Create MAC from string
mac, err := address.NewMACFromString("00:11:22:33:44:55")
if err != nil {
    // Handle error
}

// Create MAC from ZeroTier address
macFromZT := address.NewMACFromZTAddress(ztAddr)

// Generate random MAC address
randomMAC := address.NewRandomMAC()

// Check MAC address properties
isBroadcast := mac.IsBroadcast()
isMulticast := mac.IsMulticast()

// Get string representation
strMAC := mac.String() // "00:11:22:33:44:55"
```

## ZeroTier Compatibility

### Compatibility Scope
This module implements the address format and derivation mechanism used by ZeroTier One, ensuring compatibility with ZeroTier networks and nodes.

### Version Requirements
- ZeroTier: 1.8.0 or newer
- All address derivation and formatting follows ZeroTier specifications

### Implementation Details
- ZeroTier addresses are 5 bytes in length
- Addresses are derived from the first 5 bytes of a cryptographic hash of the public key
- MAC addresses are derived from ZeroTier addresses by prefixing with 0x02 (locally administered)

### Configuration Requirements
- No special configuration needed for basic operation
- For interoperability, use only the provided address derivation functions

## Testing

To test the address module:

```bash
cd /home/gt610/code/stella
go test ./pkg/address/... -v
```

## Best Practices

- Always validate addresses before use
- When deriving MAC addresses from ZeroTier addresses, use the provided `NewMACFromZTAddress` function
- For comparison operations, use the `Compare` or `Equals` methods rather than direct byte comparison
- Store addresses using their byte representation for efficiency

## Troubleshooting

### Common Issues

1. **Invalid address format**: Ensure hexadecimal strings are properly formatted with the correct length
2. **MAC address conflicts**: When generating random MACs, the module properly sets the locally administered bit to avoid conflicts
3. **Compatibility problems**: Always use the public key derivation function for generating ZeroTier-compatible addresses

### Error Handling

Pay special attention to error returns from address creation functions, especially when parsing strings from external sources.