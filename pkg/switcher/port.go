package switcher

import (
	"errors"
	"sync"

	"github.com/stella/virtual-switch/pkg/packet"
)

// PortState represents port states
type PortState int

const (
	PortStateDown PortState = iota
	PortStateUp
	PortStateError
)

// Port represents a network switch port
type Port struct {
	// Basic information
	ID          string
	Name        string
	Description string
	State       PortState
	MTU         int
	Speed       int
	Duplex      bool // true for full duplex

	// VLAN configuration
	VlanMode       VlanMode // Port VLAN mode
	AccessVlanID   uint16   // VLAN ID in Access mode
	AllowedVlans   map[uint16]bool // Allowed VLAN list in Trunk mode
	NativeVlanID   uint16   // Native VLAN ID (for untagged frames)

	// Connection callbacks
	packetHandler func(*packet.Packet) error

	// Synchronization control
	mutex sync.RWMutex
}

// NewPort creates a new port
func NewPort(id string, name string) *Port {
	return &Port{
		ID:          id,
		Name:        name,
		Description: "Virtual Switch Port",
		State:       PortStateDown,
		MTU:         1500,
		Speed:       1000,
		Duplex:      true,
		// Default VLAN configuration
		VlanMode:     VlanModeAccess,
		AccessVlanID: 1,        // Default VLAN 1
		AllowedVlans: make(map[uint16]bool),
		NativeVlanID: 1,        // Default Native VLAN 1
	}
}

// GetState returns the port state
func (p *Port) GetState() PortState {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.State
}

// SendPacket sends a packet through the port
func (p *Port) SendPacket(pkt *packet.Packet) error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if p.State != PortStateUp {
		return errors.New("port is down")
	}

	if p.packetHandler == nil {
		return errors.New("packet handler not set")
	}

	return p.packetHandler(pkt)
}

// Close shuts down the port
func (p *Port) Close() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.State = PortStateDown
	p.packetHandler = nil
}

// SetPacketHandler sets the packet processing callback
func (p *Port) SetPacketHandler(handler func(*packet.Packet) error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.packetHandler = handler
}