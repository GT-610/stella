# Topology Management Module

The topology module provides comprehensive network topology management for the Stella virtual switch, maintaining critical information about nodes, paths, and their relationships within the network. It is specifically designed with ZeroTier compatibility in mind, enabling seamless integration with ZeroTier networks while providing efficient topology maintenance and optimization capabilities.

## Core Features

### TopologyManager
- **Node Lifecycle Management**: Creates, updates, retrieves, and removes network nodes
- **Path Management**: Maintains communication paths between nodes with state tracking
- **Concurrent Safety**: Uses read-write locks for thread-safe operations
- **Automatic Maintenance**: Performs periodic cleanup of stale nodes and paths
- **Metrics Collection**: Gathers statistics on network health, including node count, path status, and latency
- **Update Notification**: Provides channels for receiving topology changes in real-time
- **ZeroTier Compatibility**: Includes support for trusted path identifiers and protocol-specific features

## File Structure

```
pkg/topology/
├── topology.go             # Core TopologyManager implementation
├── topology_test.go        # Unit tests
```

> Note: The current implementation includes the core TopologyManager functionality. Additional components like pathfinding and topology discovery may be implemented in future versions or integrated through other modules.

## Usage Examples

### Creating and Starting the Topology Manager

```go
import (
    "github.com/google/uuid"
    "github.com/stella/virtual-switch/pkg/topology"
)

// Create topology manager
tm := topology.NewTopologyManager()

// Start topology manager
tm.Start()

// Add node
node := &topology.Node{
    ID:           uuid.New(),
    Address:      "192.168.1.100:9993",
    PublicKey:    "node-public-key",
    LastSeen:     time.Now(),
    Version:      "1.0.0",
    Latency:      15,
    IsTrusted:    true,
    MTU:          2800,
    TrustedPathID: 1234567890,
}
tm.AddNode(node)

// Add path
path := &topology.Path{
    Source:      node.ID,
    Destination: anotherNode.ID,
    Address:     "192.168.1.101:9993",
    Active:      true,
    LastActive:  time.Now(),
    Latency:     20,
    Trusted:     true,
}
tm.AddPath(path)

// Get path between nodes
path, exists := tm.GetPath(sourceNode.ID, destNode.ID)
if exists {
    fmt.Printf("Found path with latency: %dms\n", path.Latency)
}

// Monitor topology updates
go func() {
    for update := range tm.GetUpdateChannel() {
        fmt.Printf("Topology update: %s\n", update.Type)
    }
}()

// Monitor metrics
go func() {
    for metrics := range tm.GetMetricsChannel() {
        fmt.Printf("Metrics: %d nodes, %d paths, avg latency %.2fms\n", 
                   metrics.TotalNodes, metrics.TotalPaths, metrics.AvgLatency)
    }
}()

// Stop topology manager when done
tm.Stop()
```

## ZeroTier Compatibility

### Compatibility Scope
The topology module is specifically designed to maintain compatibility with ZeroTier networks by supporting:

- ZeroTier node identifier format and addressing scheme
- Trusted path tracking with `TrustedPathID` field
- Compatible network topology representation
- Proper MTU handling for ZeroTier's 2800-byte default
- Node state management compatible with ZeroTier's trust model

### Version Requirements
- **ZeroTier Protocol Compatibility**: ZeroTier One 1.4.x and newer
- **Go Version**: Go 1.18 or newer

### Configuration Requirements
For optimal integration with ZeroTier networks:

- Set `MTU` to 2800 for ZeroTier compatibility
- Properly configure the `IsTrusted` flag for known trusted nodes
- Maintain `TrustedPathID` values for secure path tracking
- Ensure node addresses follow the IP:port format used by ZeroTier
- Set appropriate node version strings for protocol compatibility

### Implementation Details
The module includes specific fields to support ZeroTier compatibility:

- `TrustedPathID` in the `Node` struct for tracking secure communication paths
- Trust state management through the `IsTrusted` flag
- MTU configuration support matching ZeroTier's default settings
- Node identification using UUID format compatible with ZeroTier's addressing system

## Testing

To run the unit tests for the topology module:

```bash
cd /home/gt610/code/stella
go test ./pkg/topology/... -v
```

## Monitoring

The topology manager provides comprehensive metrics through the `GetMetricsChannel()` method:

- **TotalNodes**: Total number of nodes in the topology
- **ActiveNodes**: Number of nodes active within the last 2 minutes
- **TotalPaths**: Total number of communication paths
- **ActivePaths**: Number of active paths
- **AvgLatency**: Average network latency across all active nodes and paths
- **Timestamp**: Time when metrics were collected

Metrics are automatically collected every minute and published to the metrics channel. Applications can subscribe to this channel to receive real-time updates on network health.

## Troubleshooting

### Common Issues

1. **Nodes not being discovered**: Check UDP connectivity and firewall settings
2. **Path quality issues**: Verify network conditions and adjust latency thresholds
3. **Compatibility problems with ZeroTier nodes**: Ensure MTU is set correctly to 2800

### Best Practices

- Run topology manager as a singleton within the application
- Configure appropriate update intervals based on network size
- Monitor topology metrics regularly for early detection of issues
- Properly handle node failures and implement recovery mechanisms