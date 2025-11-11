# Switcher Module

## Overview
The Switcher module in Stella provides a software-based Ethernet switch implementation that handles packet forwarding, VLAN management, MAC address learning, and multicast traffic optimization. It's designed to work seamlessly with ZeroTier's virtual network infrastructure.

## Core Features

### 1. Packet Forwarding
- **Intelligent Flooding**: Efficiently forwards unicast packets to the appropriate ports
- **Broadcast Handling**: Properly distributes broadcast traffic within the network
- **Port State Management**: Respects port states (up/down) when forwarding packets
- **MTU Enforcement**: Supports configurable MTU settings for each port

### 2. VLAN Support
- **VLAN Management**: Create, update, and remove VLAN configurations
- **Port Modes**: Supports Access, Trunk, and Hybrid port modes
- **VLAN Isolation**: Ensures traffic isolation between different VLANs
- **Native VLAN**: Handles untagged frames on trunk ports

### 3. MAC Address Learning
- **Dynamic Learning**: Automatically learns MAC addresses from incoming traffic
- **MAC Table Management**: Maintains a configurable-size MAC address table
- **Address Aging**: Implements time-based aging of dynamic MAC entries
- **Table Capacity**: Handles table overflow with intelligent oldest-entry replacement

### 4. Multicast Optimization
- **IGMP Snooping**: Parses and processes IGMP messages to optimize multicast traffic
- **Multicast Group Management**: Tracks which ports have requested which multicast groups
- **Selective Forwarding**: Only forwards multicast traffic to ports that have requested it
- **Member Aging**: Automatically removes inactive multicast group members

## File Structure

```
pkg/switcher/
├── switcher.go        # Core switch implementation
├── port.go            # Port management and configuration
├── vlan.go            # VLAN configuration and management
├── mactable.go        # MAC address table implementation
├── multicast.go       # Multicast group management
├── igmp.go            # IGMP protocol handling and message parsing
├── vxlan.go           # VXLAN support (if available)
└── switcher_test.go   # Unit tests (if available)
```

## Usage Examples

### Creating and Managing a Switch

```go
package main

import (
    "github.com/stella/virtual-switch/pkg/switcher"
)

func main() {
    // Create a new switch
    sw, err := switcher.NewSwitcher("switch1", "Main Network Switch")
    if err != nil {
        panic(err)
    }
    
    // Start the switch
    if err := sw.Start(); err != nil {
        panic(err)
    }
    defer sw.Stop()
    
    // Create and configure ports
    port1 := switcher.NewPort("port1", "Server Connection")
    port1.MTU = 1500
    port1.State = switcher.PortStateUp
    
    // Add port to switch
    if err := sw.AddPort(port1); err != nil {
        panic(err)
    }
    
    // Configure VLAN
    vlanManager := sw.GetVlanManager()
    vlan2, err := switcher.NewVlanConfig(2, "Department VLAN")
    if err != nil {
        panic(err)
    }
    vlanManager.AddVlan(vlan2)
    
    // Set port VLAN mode
    port2 := switcher.NewPort("port2", "Department Access")
    port2.VlanMode = switcher.VlanModeAccess
    port2.AccessVlanID = 2
    
    sw.AddPort(port2)
}
```

### Handling Packet Forwarding

```go
// Assuming you have a switch instance and a received packet
func handleNetworkPacket(sw *switcher.Switcher, portID string, pkt *packet.Packet) {
    // Process the packet through the switch
    err := sw.HandlePacket(portID, pkt)
    if err != nil {
        // Handle error
        log.Printf("Error processing packet: %v", err)
    }
}

// Configure a port to receive packets from a network interface
func configurePortForInterface(port *switcher.Port, networkInterface NetworkInterface) {
    // Set up packet receiving
    networkInterface.OnPacketReceived(func(rawData []byte) {
        // Parse raw data into a packet
        pkt, err := packet.NewPacketFromData(rawData)
        if err != nil {
            return
        }
        
        // Send packet to switch via this port
        port.SendPacket(pkt)
    })
    
    // Set up packet sending
    port.SetPacketHandler(func(pkt *packet.Packet) error {
        // Send packet out through the network interface
        return networkInterface.SendPacket(pkt.Data)
    })
}
```

### Multicast Configuration

```go
// Access and manage multicast functionality
func configureMulticastFeatures(sw *switcher.Switcher) {
    // Get the multicast manager (access through switcher implementation)
    // This is illustrative as the actual access method may vary
    multicastManager := sw.GetMulticastManager()
    
    // Add a static multicast group membership
    multicastMac, _ := address.NewMACFromBytes([]byte{0x01, 0x00, 0x5E, 0x01, 0x02, 0x03})
    multicastManager.AddMember(1, *multicastMac, 0, "port1")
    
    // IGMP snooping is automatically handled when packets are processed
}
```

## ZeroTier Compatibility

### Compatibility Range
The Switcher module is designed to be compatible with ZeroTier One v1.4.0 and above, providing similar functionality for virtual network switching and packet forwarding.

### Version Requirements
- Compatible with ZeroTier One v1.4.0+
- Implements switching functionality that works with ZeroTier's virtual networking model
- Supports standard Ethernet frame formats as used by ZeroTier

### Configuration Compatibility
- **MTU Settings**: Compatible with ZeroTier's default MTU of 2800 bytes
- **VLAN Support**: Implements standard 802.1Q VLAN tagging compatible with ZeroTier
- **Multicast Handling**: Works with ZeroTier's multicast optimization mechanisms

### Implementation Details
- The switcher module operates at Layer 2, similar to how ZeroTier handles Ethernet frame switching
- Supports standard Ethernet frame formats and protocols
- Implements IGMP snooping for efficient multicast traffic handling
- Provides VLAN isolation that can work alongside ZeroTier's network segmentation

### Known Limitations
- While providing similar functionality, this is not a direct replacement for ZeroTier's internal switching logic
- Some advanced ZeroTier features may have different implementation details
- The switcher operates independently and requires proper integration with other Stella modules

## Testing

### Running Tests
To run the tests for the Switcher module:

```bash
go test ./pkg/switcher/... -v
```

## Best Practices

### Switch Configuration
- Start with a well-defined network topology before implementing the switch
- Configure appropriate MTU settings that match your network requirements
- Use VLANs strategically to segment traffic logically
- Set up appropriate port modes (Access/Trunk/Hybrid) based on connection requirements

### Performance Optimization
- Configure the MAC address table size based on your network scale
- Monitor and adjust aging timeouts for optimal performance
- Enable IGMP snooping to reduce unnecessary multicast traffic
- Consider network traffic patterns when designing your VLAN structure

### Security Considerations
- Use VLAN isolation to separate sensitive traffic
- Implement proper access controls for switch management
- Monitor for unusual MAC address activities that might indicate spoofing
- Regularly review multicast group memberships

## Troubleshooting

### Common Issues

#### Packet Forwarding Problems
- **Symptom**: Packets not being delivered to the correct destination
- **Solution**: Check port states and ensure they're in the `PortStateUp` state
- **Check**: Verify VLAN configurations match on connected ports

#### MAC Address Learning Failures
- **Symptom**: New devices not being properly discovered
- **Solution**: Verify MAC table size is sufficient for your network
- **Check**: Ensure aging timeouts aren't too short for your environment

#### Multicast Traffic Issues
- **Symptom**: Multicast applications not working correctly
- **Solution**: Verify IGMP snooping is functioning by checking group memberships
- **Check**: Ensure multicast packets are being properly recognized and processed

#### VLAN Isolation Problems
- **Symptom**: Cross-VLAN traffic when it shouldn't occur
- **Solution**: Verify VLAN configurations on all relevant ports
- **Check**: Ensure trunk ports have proper allowed VLAN lists configured