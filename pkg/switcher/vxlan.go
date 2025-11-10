package switcher

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/stella/virtual-switch/pkg/packet"
)

// VXLAN related constants
const (
	// VxlanUdpPort is the standard VXLAN UDP port
	VxlanUdpPort = 4789

	// VxlanHeaderLength is the length of VXLAN header
	VxlanHeaderLength = 8

	// VxlanFlagIbit is the flag bit indicating valid VNI in VXLAN header
	VxlanFlagIbit = 0x08

	// MaxVxlanVni is the maximum value for VXLAN Network Identifier
	MaxVxlanVni = 0xffffff
)

// VxlanEncapsulator handles VXLAN encapsulation and decapsulation
type VxlanEncapsulator struct {
	// Additional configuration parameters can be added, like UDP port
	UdpPort uint16
}

// NewVxlanEncapsulator creates a new VXLAN encapsulator
func NewVxlanEncapsulator() *VxlanEncapsulator {
	return &VxlanEncapsulator{
		UdpPort: VxlanUdpPort,
	}
}

// VlanIdToVni converts a VLAN ID to a VNI (Virtual Network Identifier)
// VLAN ID range: 1-4094
// VNI range: 0-16777215
func VlanIdToVni(vlanId uint16) uint32 {
		// Simple mapping: extend VLAN ID to 24-bit VNI
	// More complex mapping rules might be used in real applications
	return uint32(vlanId)
}

// VniToVlanId converts a VNI to a VLAN ID
func VniToVlanId(vni uint32) (uint16, error) {
	if vni > MaxVlanID {
		return 0, errors.New("VNI exceeds maximum VLAN ID")
	}
	return uint16(vni), nil
}

// EncapsulatePacket encapsulates a packet in VXLAN format
// Note: This is a simplified implementation, actual VXLAN encapsulation requires UDP/IP headers
func (v *VxlanEncapsulator) EncapsulatePacket(pkt *packet.Packet, vlanId uint16) ([]byte, error) {
	// Validate VLAN ID
	if vlanId < 1 || vlanId > MaxVlanID {
		return nil, fmt.Errorf("invalid VLAN ID: %d", vlanId)
	}

	// Get original packet content
	payload := pkt.Payload()
	if len(payload) == 0 {
		return nil, errors.New("empty packet payload")
	}

	// Calculate VNI
	vni := VlanIdToVni(vlanId)

	// Create VXLAN header
	vxlanHeader := make([]byte, VxlanHeaderLength)

	// Set flag bits (only set I bit, indicating VNI is valid)
	vxlanHeader[0] = VxlanFlagIbit

	// Set VNI (occupies last 24 bits, first 8 bits reserved)
	binary.BigEndian.PutUint32(vxlanHeader[4:], vni<<8)

	// Combine VXLAN header and original Ethernet frame
	vxlanPacket := append(vxlanHeader, payload...)

	return vxlanPacket, nil
}

// DecapsulatePacket decapsulates a VXLAN packet
func (v *VxlanEncapsulator) DecapsulatePacket(data []byte) ([]byte, uint16, error) {
	// Check packet length
	if len(data) < VxlanHeaderLength {
		return nil, 0, errors.New("VXLAN packet too short")
	}

	// Check I flag bit
	if (data[0] & VxlanFlagIbit) == 0 {
		return nil, 0, errors.New("VXLAN packet missing I flag")
	}

	// Extract VNI (last 24 bits)
	vni := binary.BigEndian.Uint32(data[4:]) >> 8

	// Convert VNI to VLAN ID
	vlanId, err := VniToVlanId(vni)
	if err != nil {
		return nil, 0, err
	}

	// Extract original Ethernet frame
	ethFrame := data[VxlanHeaderLength:]

	return ethFrame, vlanId, nil
}

// IsVxlanPacket checks if the data represents a VXLAN packet
func (v *VxlanEncapsulator) IsVxlanPacket(data []byte) bool {
	// Basic length check and flag bit check
	return len(data) >= VxlanHeaderLength && (data[0]&VxlanFlagIbit) != 0
}