package switcher

import (
	"sync"
	"time"

	"github.com/stella/virtual-switch/pkg/address"
	"github.com/stella/virtual-switch/pkg/packet"
)

// MulticastGroup definition
type MulticastGroup struct {
	Mac address.MAC
	Adi uint32 // Additional Distinguishing Information
}

// MulticastGroupMember
type MulticastGroupMember struct {
	PortID    string
	Timestamp int64
}

// multicastGroupStatus
type multicastGroupStatus struct {
	Members   []MulticastGroupMember
	LastQuery int64
}

// multicastGroupKey
type multicastGroupKey struct {
	VlanID   uint16
	GroupMac address.MAC
	GroupAdi uint32
}

// MulticastManager manages multicast groups, IGMP snooping, and multicast packet forwarding
type MulticastManager struct {
	groups    map[multicastGroupKey]*multicastGroupStatus // Multicast group status mapping
	agingTime time.Duration                               // Member aging time
	mutex     sync.RWMutex                                // Read-write lock for concurrent access
}

// NewMulticastManager creates a new multicast manager instance
func NewMulticastManager() *MulticastManager {
	return &MulticastManager{
		groups:    make(map[multicastGroupKey]*multicastGroupStatus),
		agingTime: 3 * time.Minute, // 默认3分钟老化时间
	}
}

// AddMember adds or updates a multicast group member
func (m *MulticastManager) AddMember(vlanID uint16, groupMac address.MAC, adi uint32, portID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := multicastGroupKey{
		VlanID:   vlanID,
		GroupMac: groupMac,
		GroupAdi: adi,
	}

	now := time.Now().UnixNano()

	if status, exists := m.groups[key]; exists {
		// Check if member already exists
		for i, member := range status.Members {
			if member.PortID == portID {
				// Update timestamp
				status.Members[i].Timestamp = now
				return
			}
		}
		// Add new member
		status.Members = append(status.Members, MulticastGroupMember{
			PortID:    portID,
			Timestamp: now,
		})
	} else {
		// Create new multicast group
		m.groups[key] = &multicastGroupStatus{
			Members: []MulticastGroupMember{
				{
					PortID:    portID,
					Timestamp: now,
				},
			},
			LastQuery: now,
		}
	}
}

// RemoveMember removes a multicast group member
func (m *MulticastManager) RemoveMember(vlanID uint16, groupMac address.MAC, adi uint32, portID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := multicastGroupKey{
		VlanID:   vlanID,
		GroupMac: groupMac,
		GroupAdi: adi,
	}

	if status, exists := m.groups[key]; exists {
		for i, member := range status.Members {
			if member.PortID == portID {
				// Remove member
				status.Members = append(status.Members[:i], status.Members[i+1:]...)
				// If no members left, delete the entire group
				if len(status.Members) == 0 {
					delete(m.groups, key)
				}
				return
			}
		}
	}
}

// GetMemberPorts retrieves all member port IDs of a multicast group
func (m *MulticastManager) GetMemberPorts(vlanID uint16, groupMac address.MAC, excludePortID string) []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Find matching multicast group
	var result []string
	for key, status := range m.groups {
		if key.VlanID == vlanID && key.GroupMac.Equals(&groupMac) {
			for _, member := range status.Members {
				if member.PortID != excludePortID {
					result = append(result, member.PortID)
				}
			}
		}
	}

	return result
}

// IsMember checks if a port is a member of a multicast group
func (m *MulticastManager) IsMember(portID string, vlanID uint16, groupMac address.MAC) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Find matching multicast group
	for key, status := range m.groups {
		if key.VlanID == vlanID && key.GroupMac.Equals(&groupMac) {
			for _, member := range status.Members {
				if member.PortID == portID {
					return true
				}
			}
		}
	}

	return false
}

// CleanupAgedMembers cleans up expired multicast group members
func (m *MulticastManager) CleanupAgedMembers() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now().UnixNano()
	for key, status := range m.groups {
		// Filter out active members
		var activeMembers []MulticastGroupMember
		for _, member := range status.Members {
			if now-m.agingTime.Nanoseconds() < member.Timestamp {
				activeMembers = append(activeMembers, member)
			}
		}

		if len(activeMembers) == 0 {
			// If no active members, delete the group
			delete(m.groups, key)
		} else {
			// Update member list
			status.Members = activeMembers
		}
	}
}

// HandleMulticastPacket processes multicast packets
func (m *MulticastManager) HandleMulticastPacket(switcher *Switcher, portID string, pkt *packet.Packet, vlanID uint16, ethFrame []byte) error {
	// Parse the destination MAC address of the Ethernet frame
	if len(ethFrame) < 6 {
		return nil // Invalid Ethernet frame
	}

	// 使用NewMACFromBytes创建MAC地址
	destMac, err := address.NewMACFromBytes(ethFrame[:6])
	if err != nil {
		return nil // Invalid MAC address
	}

	// Check if it's a multicast MAC address
	if !destMac.IsMulticast() {
		return nil // Not a multicast address
	}

	// Get the ports that should receive this multicast packet
	memberPorts := m.GetMemberPorts(vlanID, *destMac, portID)

	// Forward packet to all destination ports
	for _, destPortID := range memberPorts {
		if destPort, err := switcher.GetPort(destPortID); err == nil {
			destPort.SendPacket(pkt)
		}
	}

	return nil
}
