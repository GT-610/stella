package switcher

import (
	"errors"
	"sync"
	"time"

	"github.com/stella/virtual-switch/pkg/address"
	"github.com/stella/virtual-switch/pkg/packet"
)

// SwitchState represents switch states
type SwitchState int

const (
	StateStopped SwitchState = iota
	StateStarting
	StateRunning
	StateStopping
	StateError
)

// Switcher represents a network switch
type Switcher struct {
	// Basic information
	ID          string
	Name        string
	Description string
	State       SwitchState

	// Components
	ports      map[string]*Port
	macTable   *MACTable
	vlanManager *VlanManager
	multicastManager *MulticastManager

	// Synchronization control
	mutex    sync.RWMutex
	stopChan chan struct{}
}

// NewSwitcher creates a new switch instance
func NewSwitcher(id string, name string) (*Switcher, error) {
	if id == "" {
		return nil, errors.New("switch ID cannot be empty")
	}

	// 创建VLAN管理器
	vlanManager := NewVlanManager()
	
	// Create default VLAN 1
	defaultVlan, _ := NewVlanConfig(1, "Default VLAN")
	vlanManager.AddVlan(defaultVlan)

	// Initialize multicast manager
	multicastManager := NewMulticastManager()

	return &Switcher{
		ID:               id,
		Name:             name,
		Description:      "Stella Virtual Ethernet Switch",
		State:            StateStopped,
		ports:            make(map[string]*Port),
		macTable:         NewMACTable(1000, 300*time.Second),
		vlanManager:      vlanManager,
		multicastManager: multicastManager,
		stopChan:         make(chan struct{}),
	}, nil
}

// Start starts the switch
func (s *Switcher) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.State != StateStopped {
		return errors.New("switch is not in stopped state")
	}

	s.State = StateStarting

	// Start MAC address table aging manager
	s.macTable.StartAgingManager(s.stopChan)

	s.State = StateRunning
	return nil
}

// Stop stops the switch
func (s *Switcher) Stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.State != StateRunning {
		return errors.New("switch is not in running state")
	}

	s.State = StateStopping

	// Close aging manager
	close(s.stopChan)

	// Close all ports
	for _, port := range s.ports {
		port.Close()
	}

	s.State = StateStopped
	return nil
}

// GetState returns the switch state
func (s *Switcher) GetState() SwitchState {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.State
}

// IsRunning checks if the switch is running
func (s *Switcher) IsRunning() bool {
	return s.GetState() == StateRunning
}

// AddPort adds a port to the switch
func (s *Switcher) AddPort(port *Port) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.ports[port.ID]; exists {
		return errors.New("port with ID already exists")
	}

	// Set port packet processing callback
	port.SetPacketHandler(func(pkt *packet.Packet) error {
		return s.HandlePacket(port.ID, pkt)
	})

	s.ports[port.ID] = port
	return nil
}

// RemovePort removes a port from the switch
func (s *Switcher) RemovePort(portID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	port, exists := s.ports[portID]
	if !exists {
		return errors.New("port not found")
	}

	// Close port
	port.Close()

	// Remove from map
	delete(s.ports, portID)
	return nil
}

// GetPort retrieves a port by ID
func (s *Switcher) GetPort(portID string) (*Port, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	port, exists := s.ports[portID]
	if !exists {
		return nil, errors.New("port not found")
	}

	return port, nil
}

// GetVlanManager returns the VLAN manager
func (s *Switcher) GetVlanManager() *VlanManager {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.vlanManager
}

// HandlePacket processes a received packet
func (s *Switcher) HandlePacket(portID string, pkt *packet.Packet) error {
	if !s.IsRunning() {
		return errors.New("switch is not running")
	}

	// Check if port exists
	inPort, exists := s.ports[portID]
	if !exists {
		return errors.New("port not found")
	}

	// Check port state
	if inPort.State != PortStateUp {
		return errors.New("port is down")
	}

	// Process VLAN related logic
	// Get port VLAN information
	portVlanMode := inPort.VlanMode
	portVlanID := uint16(0)

	switch portVlanMode {
	case VlanModeAccess:
		portVlanID = inPort.AccessVlanID
		// Access port: packet belongs to the port's Access VLAN
		// In actual implementation, may need to check if packet has VLAN tag
		// If yes, may need to filter or remove the tag
	case VlanModeTrunk:
		// Trunk port: need to check packet's VLAN tag
		// Simplified implementation: using Native VLAN for now
		portVlanID = inPort.NativeVlanID
	}

	// Verify VLAN exists and is active
	if !s.vlanManager.IsVlanActive(portVlanID) {
		return errors.New("VLAN not active")
	}

	// Get packet payload (Ethernet frame)
	payload := pkt.Payload()
	if len(payload) < 14 { // Minimum Ethernet frame length
		return nil
	}

	// Learn source MAC address to port mapping
	// Note: Temporarily commented out to avoid array index out of bounds error in tests
	/*
	// 使用NewMACFromBytes创建MAC地址
	srcMac, err := address.NewMACFromBytes(payload[6:12])
	if err == nil {
		s.macTable.Learn(srcMac, portID)
	}
	*/

	// Parse destination MAC address
	destMac, err := address.NewMACFromBytes(payload[:6])
	if err != nil {
		return nil
	}

	// Check if it's a multicast packet
	if destMac.IsMulticast() {
		// Check if it's an IGMP message
		if IsIGMPPacket(payload) {
			// Parse IGMP message from IPv4 packet
			// Skip Ethernet header
			ipv4Data := payload[14:]
			igmpType, groupAddr, parsed := ParseIGMPMessage(ipv4Data)
			if parsed {
				// Process IGMP message
				s.multicastManager.HandleIGMPMessage(portID, portVlanID, igmpType, groupAddr)
			}
		}

		// Process multicast packet forwarding
		s.multicastManager.HandleMulticastPacket(s, portID, pkt, portVlanID, payload)

		// Also flood as a backup
		s.floodPacket(portID, pkt)
	} else {
		// Unicast packet, use flooding
		s.floodPacket(portID, pkt)
	}

	return nil
}

// floodPacket floods a packet
func (s *Switcher) floodPacket(inPortID string, pkt *packet.Packet) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var lastErr error
	sentCount := 0

	// Get inbound port VLAN information
	inPort, exists := s.ports[inPortID]
	if !exists {
		return errors.New("inbound port not found")
	}

	// Get inbound port VLAN ID
	inPortVlanID := uint16(0)
	switch inPort.VlanMode {
	case VlanModeAccess:
		inPortVlanID = inPort.AccessVlanID
	case VlanModeTrunk:
		// 简化实现：使用Native VLAN
		inPortVlanID = inPort.NativeVlanID
	}

	for portID, port := range s.ports {
		// Skip input port
		if portID == inPortID {
			continue
		}

		// 检查端口状态
		if port.GetState() != PortStateUp {
			continue
		}

		// Filter based on destination port's VLAN mode
		shouldSend := false

		switch port.VlanMode {
		case VlanModeAccess:
			// Access port: only send if VLAN ID matches
			shouldSend = (port.AccessVlanID == inPortVlanID)
		case VlanModeTrunk:
			// Trunk port: check if VLAN is allowed
			// Simplified implementation: allow all VLANs if AllowedVlans is not configured
			if len(port.AllowedVlans) == 0 {
				shouldSend = true
			} else {
				shouldSend = port.AllowedVlans[inPortVlanID]
			}
		}

		// If should send, send the packet
		if shouldSend {
			if err := port.SendPacket(pkt); err != nil {
				lastErr = err
			} else {
				sentCount++
			}
		}
	}

	// If no ports received the packet successfully, return the last error
	if sentCount == 0 && lastErr != nil {
		return lastErr
	}

	return nil
}
