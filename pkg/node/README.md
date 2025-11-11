# Node Module

## Overview
The Node module in Stella provides the core functionality for managing virtual switch nodes. It handles the complete lifecycle of a node, including initialization, configuration, identity management, logging, and integration with other modules.

## Core Features

### 1. Node Lifecycle Management
- **Initialization**: Creates and initializes new nodes with proper identity
- **Startup/Shutdown**: Controls the running state of the node
- **State Management**: Tracks and transitions between different node states
- **Error Handling**: Manages and reports errors during node operation

### 2. Configuration Management
- **Default Configuration**: Provides sensible defaults for all settings
- **Configuration Loading/Saving**: Persists configuration to JSON files
- **Identity Management**: Handles loading and saving of node identities

### 3. Logging System
- **Multiple Log Levels**: Supports debug, info, warn, error, and fatal levels
- **Custom Formatting**: Includes timestamps and log level indicators
- **Configurable Verbosity**: Allows setting the minimum log level

### 4. Integration Management
- **Complete Node Setup**: Creates and initializes nodes with configuration
- **Run-time Management**: Handles starting, monitoring, and shutting down nodes
- **Status Reporting**: Provides comprehensive status information

## File Structure

```
pkg/node/
├── node.go            # Core node implementation and state management
├── lifecycle.go       # Lifecycle management (startup, shutdown, main loop)
├── config.go          # Configuration loading, saving, and management
├── log.go             # Logging implementation
├── integration.go     # Integration utilities for node management
└── node_test.go       # Unit tests
```

## Usage Examples

### Creating and Running a Node

```go
package main

import (
    "github.com/stella/virtual-switch/pkg/node"
)

func main() {
    // Run a node with configuration from a specific file
    n, err := node.RunNodeWithConfig("/path/to/config.json")
    if err != nil {
        panic(err)
    }
    defer func() {
        // Get node status before shutdown
        status := node.GetNodeStatus(n)
        // Shut down the node gracefully
        node.ShutdownNode(n, nil) // Pass config if available
    }()
    
    // Wait for signals or continue execution
    // ...
}
```

### Manual Node Creation and Management

```go
// Create and initialize a node with a new identity
n, config, err := node.CreateAndInitNode("/path/to/config.json")
if err != nil {
    panic(err)
}

// Start the node
if err := n.Start(config); err != nil {
    panic(err)
}

// Check node status
status := node.GetNodeStatus(n)

// Stop the node gracefully
if err := node.ShutdownNode(n, config); err != nil {
    panic(err)
}
```

### Custom Configuration

```go
// Create a custom configuration
config := node.DefaultConfig()
config.BindAddr = ":9994"  // Use a different port
config.LogLevel = "debug"  // Increase logging verbosity

// Save the configuration
if err := config.Save(); err != nil {
    panic(err)
}

// Load an identity
identity, err := config.LoadIdentity()
if err != nil {
    panic(err)
}
```

## ZeroTier Compatibility

### Compatibility Range
The Node module is designed to be compatible with ZeroTier One v1.4.0 and above, providing similar functionality for node lifecycle and configuration management.

### Version Requirements
- Compatible with ZeroTier One v1.4.0+
- Implementation follows the ZeroTier node architecture but with Stella-specific modifications

### Configuration Compatibility
The configuration structure supports ZeroTier-compatible fields such as:
- Node identity (address and keys)
- Binding address and port (default: :9993, matching ZeroTier)
- Data directory structure
- Controller URL configuration

### Known Limitations
- While following similar patterns, this implementation is not a direct drop-in replacement for ZeroTier One's node implementation
- Some advanced ZeroTier node features may not be available or implemented differently

## Testing

### Running Tests
To run the tests for the Node module:

```bash
go test ./pkg/node/... -v
```

## Best Practices

### Configuration Management
- Store configuration files in a secure location with appropriate permissions
- Use a unique data directory for each node instance
- Back up the identity file regularly as it contains the cryptographic identity of the node

### Error Handling
- Always check for errors when creating, starting, or stopping nodes
- Implement proper shutdown procedures to avoid corrupted state
- Use the `GetNodeStatus()` function to monitor node health

## Troubleshooting

### Common Issues

#### Configuration File Not Found
- **Solution**: The module will create a default configuration if the file doesn't exist
- **Verify**: Check that the parent directory has appropriate write permissions

#### Identity Loading Failures
- **Symptom**: Errors when loading identity.json
- **Solution**: Verify the file is not corrupted and has correct JSON format
- **Recovery**: A new identity will be created if the existing one is invalid

#### Port Binding Errors
- **Symptom**: Errors when starting the node related to address already in use
- **Solution**: Change the `BindAddr` in the configuration to use a different port

#### Node Won't Start
- **Check**: Verify configuration settings are valid
- **Check**: Ensure data directory exists and has appropriate permissions
- **Check**: Examine logs with increased verbosity (debug level) for detailed information