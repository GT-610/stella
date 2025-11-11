# Packet Module

## Overview
The Packet module in Stella provides the core functionality for creating, parsing, and manipulating ZeroTier protocol packets. It implements the packet structure, fragmentation logic, and protocol constants required for ZeroTier network communication.

## Core Features

### 1. Packet Structure
- **Header Management**: Supports packet headers with source/destination addresses, flags, cipher suites, and hop counts
- **Payload Handling**: Efficiently manages packet payloads with proper bounds checking
- **Protocol Verbs**: Implements ZeroTier protocol verbs (HELLO, FRAME, WHOIS, etc.)
- **Validation**: Provides packet validation to ensure protocol compliance

### 2. Fragmentation Support
- **Fragment Creation**: Splits large packets into manageable fragments
- **Fragment Parsing**: Processes incoming fragments for reassembly
- **Fragment Validation**: Ensures fragment integrity and correctness

### 3. Protocol Constants
- **Version Management**: Supports protocol versions 4 through 13 (current)
- **Cipher Suites**: Implements Curve25519+Poly1305+Salsa20/12 and AES-GMAC+SIV
- **Header Flags**: Handles fragmentation, trusted path, and extended cipher flags

## File Structure

```
pkg/packet/
├── packet.go          # Core packet implementation, structure, and operations
└── packet_test.go     # Unit tests (if available)
```

## Usage Examples

### Creating a New Packet

```go
package main

import (
    "github.com/stella/virtual-switch/pkg/address"
    "github.com/stella/virtual-switch/pkg/packet"
)

func main() {
    // Create source and destination addresses
    srcAddr, _ := address.NewAddressFromBytes([]byte{0x01, 0x23, 0x45, 0x67, 0x89})
    dstAddr, _ := address.NewAddressFromBytes([]byte{0x98, 0x76, 0x54, 0x32, 0x10})
    
    // Create a new packet
    pkt, err := packet.NewPacket(dstAddr, srcAddr)
    if err != nil {
        panic(err)
    }
    
    // Set packet verb
    pkt.SetVerb(packet.VerbHELLO)
    
    // Set payload
    payload := []byte{0x01, 0x02, 0x03} // Example payload
    pkt.SetPayload(payload)
    
    // Use the packet...
}
```

### Parsing a Packet from Data

```go
// Parse a packet from received data
data := []byte{...} // Raw packet data received from network
pkt, err := packet.NewPacketFromData(data)
if err != nil {
    // Handle error
    return
}

// Validate the packet
if !pkt.IsValid() {
    // Reject invalid packet
    return
}

// Access packet properties
srcAddr := pkt.Source()
dstAddr := pkt.Destination()
verb := pkt.Verb()
payload := pkt.Payload()
```

### Working with Fragments

```go
// Fragment a large packet
packet := &packet.Packet{...} // Large packet
fragmentSize := 512
fragments := make([]*packet.Fragment, 0)

for i := 0; i < len(packet.Data); i += fragmentSize {
    end := i + fragmentSize
    if end > len(packet.Data) {
        end = len(packet.Data)
    }
    
    frag, err := packet.NewFragment(packet, i, end-i, i/fragmentSize, (len(packet.Data)+fragmentSize-1)/fragmentSize)
    if err != nil {
        // Handle error
        break
    }
    fragments = append(fragments, frag)
}

// Parse a received fragment
fragmentData := []byte{...} // Received fragment data
fragment, err := packet.NewFragmentFromData(fragmentData)
if err != nil {
    // Handle error
    return
}

// Validate fragment
if !fragment.IsValid() {
    // Reject invalid fragment
    return
}
```

## ZeroTier Compatibility

### Compatibility Range
This module fully implements the ZeroTier packet format and protocol constants, making it compatible with ZeroTier One v1.4.0 through v1.10.x.

### Version Requirements
- Compatible with ZeroTier One v1.4.0+
- Supports protocol versions 4 through 13 (current)
- Implements all standard packet verbs and flags

### Implementation Details
- **Protocol Version**: Current protocol version 13 with minimum supported version 4
- **Maximum Packet Size**: 2048 bytes (ProtoMaxPacketLength)
- **Maximum Hop Count**: 7 hops (ProtocolMaxHops)
- **Supported Cipher Suites**: 
  - CipherC25519_POLY1305_SALSA2012 (default)
  - CipherAES_GMAC_SIV

### Known Limitations
- This module handles packet structure and fragmentation, but does not implement reassembly logic
- Crypto operations (encryption/decryption) are handled by the crypto module
- Frame encoding/decoding for Ethernet frames is managed elsewhere in the codebase

## Testing

### Running Tests
To run the tests for the Packet module:

```bash
go test ./pkg/packet/... -v
```

## Best Practices

### Packet Handling
- Always validate packets before processing them using the `IsValid()` method
- Use the appropriate protocol verb for each message type
- Be mindful of the maximum packet size (2048 bytes) to avoid fragmentation when possible
- Properly handle hop count to prevent packet loops

### Fragmentation
- Consider the overhead of fragmentation when designing protocols
- Implement proper fragment reassembly with timeout handling
- Track fragment IDs to avoid reassembly of duplicate fragments

## Troubleshooting

### Common Issues

#### Invalid Packet
- **Symptom**: `IsValid()` returns false
- **Solution**: Check that all required fields are properly set, especially addresses
- **Check**: Ensure packet size meets minimum requirements

#### Fragmentation Errors
- **Symptom**: Fragment creation fails
- **Solution**: Verify fragment parameters are within valid ranges
- **Check**: Ensure fragment count does not exceed 16

#### Protocol Compatibility
- **Symptom**: Communication failures with certain ZeroTier versions
- **Solution**: Verify that the correct protocol version and cipher suite are being used
- **Check**: Ensure packet verbs match what the receiving node expects