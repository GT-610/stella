# Transport Module

## Overview

The transport module provides a flexible network communication framework that handles packet transmission, connection management, and node discovery in a ZeroTier-compatible architecture. It abstracts the underlying network protocols, offering a unified interface for sending and receiving data while ensuring secure and reliable communication between nodes.

## Core Features

### Transport Interface
- **Protocol Abstraction**: Defines a common interface for different transport implementations (UDP, TCP)
- **Connection Management**: Tracks connection states and handles establishment/termination
- **Packet Handling**: Processes incoming and outgoing data with configurable handlers
- **Timeout Control**: Sets read/write timeouts for reliable communication

### UDP Transport Implementation
- **Secure Communication**: Built-in encryption using Curve25519 and Salsa2012
- **Reliable Delivery**: Packet acknowledgment and exponential backoff retransmission
- **Efficient Buffering**: Configurable buffer sizes for optimal performance
- **Test Mode**: Support for testing without actual network operations

### Node Discovery
- **Peer Management**: Tracks discovered nodes with metadata (latency, connection status)
- **Heartbeat System**: Maintains active connections with periodic pings
- **Expired Node Cleanup**: Automatically removes inactive peers
- **Active Discovery**: Initiates discovery of specific nodes

### Connection Management
- **Connection Pooling**: Maintains a collection of active connections
- **Event Notification**: Listener system for connection events (connected, disconnected, error)
- **Connection Lookup**: Retrieve connections by remote address
- **Dynamic Creation**: Automatically creates connections when needed

## File Structure

```
transport/
├── base.go          # Base implementation of Transport interface
├── discovery.go     # Node discovery protocol implementation
├── factory.go       # Transport creation factory
├── interface.go     # Core interfaces and type definitions
├── manager.go       # Connection management implementation
├── udp.go           # UDP transport implementation with encryption
└── udp_test.go      # Tests for UDP transport
```

## Interfaces

### Transport
The main interface for all transport implementations:

```go
type Transport interface {
    Init(config map[string]interface{}) error
    Start(handler PacketHandler) error
    Stop() error
    Send(dstAddr net.Addr, data []byte) error
    GetState() ConnectionState
    SetReadTimeout(timeout time.Duration) error
    SetWriteTimeout(timeout time.Duration) error
    GetLocalAddr() net.Addr
}
```

### Connection
Represents a specific connection between two endpoints:

```go
type Connection interface {
    Connect(remoteAddr net.Addr) error
    Disconnect() error
    Send(data []byte) error
    Receive(buffer []byte) (int, error)
    GetState() ConnectionState
    GetRemoteAddr() net.Addr
    GetLocalAddr() net.Addr
    SetReadTimeout(timeout time.Duration) error
    SetWriteTimeout(timeout time.Duration) error
}
```

### ConnectionManager
Manages multiple connections:

```go
type ConnectionManager interface {
    CreateConnection(remoteAddr net.Addr) (Connection, error)
    GetConnection(remoteAddr net.Addr) Connection
    CloseConnection(remoteAddr net.Addr) error
    CloseAllConnections() error
    GetConnections() []Connection
    AddConnectionListener(listener ConnectionListener) error
    RemoveConnectionListener(listener ConnectionListener) error
}
```

### DiscoveryManager
Handles node discovery and peer management:

```go
type DiscoveryManager struct {
    // Methods for peer discovery and management
    Start() error
    Stop() error
    SendDiscoveryHello(addr net.Addr) error
    SendDiscoveryPing(addr net.Addr) error
    HandleDiscoveryMessage(addr net.Addr, data []byte) error
    GetPeerByAddress(addr string) (*DiscoveredPeer, bool)
    GetAllPeers() []*DiscoveredPeer
    DiscoverNode(addr net.Addr) error
}
```

## Usage Examples

### Creating a UDP Transport

```go
import (
    "net"
    "github.com/stella/virtual-switch/pkg/transport"
)

// Initialize transport configuration
config := map[string]interface{}{
    "port":            9993,
    "bufferSize":      4096,
    "maxRetries":      3,
    "retryInterval":   500 * time.Millisecond,
    "retryExponential": true,
}

// Create transport instance
udpTransport, err := transport.NewTransport(transport.TransportTypeUDP, config)
if err != nil {
    // Handle error
}

// Start transport with packet handler
udpTransport.Start(func(srcAddr net.Addr, data []byte) error {
    // Process received packet
    fmt.Printf("Received packet from %s: %d bytes\n", srcAddr.String(), len(data))
    return nil
})

// Send data to a remote address
remoteAddr, _ := net.ResolveUDPAddr("udp", "192.168.1.1:9993")
err = udpTransport.Send(remoteAddr, []byte("Hello, World!"))

// Stop transport when done
udpTransport.Stop()
```

### Using Connection Manager

```go
// Create connection manager
connManager := transport.NewConnectionManager(udpTransport)

// Create connection to remote address
remoteAddr, _ := net.ResolveUDPAddr("udp", "192.168.1.1:9993")
conn, err := connManager.CreateConnection(remoteAddr)

// Send data through connection
conn.Send([]byte("Hello via connection!"))

// Add connection event listener
connManager.AddConnectionListener(func(conn transport.Connection, event transport.ConnectionEvent, data []byte, err error) {
    switch event {
    case transport.EventConnected:
        fmt.Println("Connection established")
    case transport.EventDisconnected:
        fmt.Println("Connection closed")
    case transport.EventError:
        fmt.Printf("Connection error: %v\n", err)
    }
})

// Close all connections when done
connManager.CloseAllConnections()
```

### Setting Up Node Discovery

```go
import (
    "github.com/stella/virtual-switch/pkg/identity"
    "github.com/stella/virtual-switch/pkg/transport"
)

// Create local identity
localIdentity := identity.NewIdentity()

// Create discovery manager
discoveryManager := transport.NewDiscoveryManager(localIdentity, udpTransport)

// Start discovery service
discoveryManager.Start()

// Actively discover a node
remoteAddr, _ := net.ResolveUDPAddr("udp", "192.168.1.1:9993")
err = discoveryManager.DiscoverNode(remoteAddr)

// Get all discovered peers
peers := discoveryManager.GetAllPeers()
for _, peer := range peers {
    fmt.Printf("Discovered peer: %s, Latency: %d ms\n", 
               peer.Address.String(), peer.Latency)
}

// Stop discovery service when done
discoveryManager.Stop()
```

## ZeroTier Compatibility

### Compatibility Range
This transport module is designed to be fully compatible with ZeroTier network protocol, specifically supporting:

- ZeroTier protocol version 1.4.x and 1.6.x
- Node discovery mechanisms
- Secure encrypted communication using Curve25519 and Salsa2012
- Connection establishment and maintenance

### Version Requirements
- Compatible with ZeroTier One clients version 1.4.6 and newer
- Protocol version 1 (defined as `DiscoveryProtocolVersion` in discovery.go)

### Configuration for ZeroTier Compatibility

```go
// ZeroTier compatible configuration
ztConfig := map[string]interface{}{
    "port":            9993,  // Default ZeroTier port
    "enableEncryption": true, // Required for ZeroTier compatibility
    "maxRetries":      3,     // Matches ZeroTier's retry behavior
    "retryExponential": true, // ZeroTier uses exponential backoff
}

// Set peer public key for encryption
transport.SetPeerPublicKey("192.168.1.1:9993", []byte{...}) // ZeroTier node public key
```

### Implementation Details
- Uses the same packet format and encryption algorithms as ZeroTier
- Implements compatible node discovery protocol with Hello/Response/Ping/Pong messages
- Supports the same connection lifecycle states

## Security Considerations

- **Default Encryption**: By default, the UDP transport uses Curve25519 for key exchange and Salsa2012 for encryption
- **Peer Authentication**: Ensure you set the correct peer public keys before communicating
- **Transport Error Handling**: Always check for errors when sending data
- **Connection States**: Monitor connection states to detect disconnections
- **Packet Validation**: Implement proper packet validation in your handler

## Testing

The UDP transport implementation includes a test mode that allows testing without actual network operations:

```go
testConfig := map[string]interface{}{
    "test_mode": true,
}
transport, _ := transport.NewTransport(transport.TransportTypeUDP, testConfig)
```

For comprehensive testing, refer to `udp_test.go` for examples of unit tests.

## Best Practices

1. **Error Handling**: Always check and handle errors from transport operations
2. **Resource Management**: Call `Stop()` on transports and managers when done to release resources
3. **Connection Reuse**: Use the connection manager to reuse connections instead of creating new ones
4. **Timeout Configuration**: Set appropriate timeouts for your network environment
5. **Event Listening**: Use connection listeners to respond to connection state changes
6. **Graceful Shutdown**: Implement proper shutdown procedures to close all connections

## Troubleshooting

### Common Issues

1. **Connection Failures**
   - Check if ports are properly opened
   - Verify firewall settings
   - Ensure encryption is properly configured with correct public keys

2. **Packet Loss**
   - Increase buffer size
   - Adjust retry settings (increase maxRetries or retryInterval)
   - Enable exponential backoff

3. **Performance Issues**
   - Optimize buffer size based on your network conditions
   - Minimize packet size when possible
   - Use connection pooling through the connection manager

4. **Discovery Problems**
   - Verify network connectivity
   - Check if the remote node is running and reachable
   - Ensure the correct port is being used (default: 9993)

### Debugging Tips

- Implement detailed logging in your packet handlers
- Monitor connection states and events
- Track discovery process and peer information
- Use the built-in timeout and retry mechanisms
- Check for firewall or NAT traversal issues if operating behind NAT