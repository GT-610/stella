package switcher

import (
	"encoding/binary"
	"net"

	"github.com/stella/virtual-switch/pkg/address"
)

// IGMP message type constants
const (
	IGMPTypeMembershipQuery    = 0x11
	IGMPTypeMembershipReportV1 = 0x12
	IGMPTypeMembershipReportV2 = 0x16
	IGMPTypeMembershipReportV3 = 0x22
	IGMPTypeLeaveGroup         = 0x17
)

// IGMP header structure
type IGMPHeader struct {
	Type        uint8
	MaxRespTime uint8
	Checksum    uint16
}

// IGMP membership query message structure
type IGMPMembershipQuery struct {
	Header       IGMPHeader
	GroupAddress [4]byte
}

// IGMP membership report message structure
type IGMPMembershipReport struct {
	Header       IGMPHeader
	GroupAddress [4]byte
}

// IGMP leave group message structure
type IGMPLeaveGroup struct {
	Header       IGMPHeader
	GroupAddress [4]byte
}

// Calculate IGMP checksum
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	// Add overflow part
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	return uint16(^sum)
}

// Validate IGMP checksum
func validateChecksum(data []byte) bool {
	return calculateChecksum(data) == 0
}

// Parse IGMP message from IPv4 packet
func ParseIGMPMessage(ipv4Data []byte) (uint8, [4]byte, bool) {
	// IPv4 header length
	ipHeaderLen := int((ipv4Data[0] & 0x0F) << 2)
	if ipHeaderLen < 20 || len(ipv4Data) < ipHeaderLen {
		return 0, [4]byte{}, false
	}

	// Extract IGMP message
	igmpData := ipv4Data[ipHeaderLen:]
	if len(igmpData) < 8 {
		return 0, [4]byte{}, false
	}

	// 验证校验和
	if !validateChecksum(igmpData) {
		return 0, [4]byte{}, false
	}

	// Parse IGMP header
	var header IGMPHeader
	header.Type = igmpData[0]
	header.MaxRespTime = igmpData[1]
	header.Checksum = binary.BigEndian.Uint16(igmpData[2:4])

	// Extract group address
	var groupAddr [4]byte
	copy(groupAddr[:], igmpData[4:8])

	return header.Type, groupAddr, true
}

// Handle IGMP message
func (m *MulticastManager) HandleIGMPMessage(portID string, vlanID uint16, igmpType uint8, groupAddr [4]byte) {
	// Convert IPv4 multicast address to MAC address
	multicastMac := IPv4ToMulticastMac(groupAddr)

	// Handle based on IGMP message type
	switch igmpType {
	case IGMPTypeMembershipReportV1, IGMPTypeMembershipReportV2, IGMPTypeMembershipReportV3:
		// Membership report, add port to multicast group
		m.AddMember(vlanID, multicastMac, 0, portID)
	case IGMPTypeLeaveGroup:
		// Leave group, remove port from multicast group
		m.RemoveMember(vlanID, multicastMac, 0, portID)

	case IGMPTypeMembershipQuery:
		// Handle query message
		// We don't need special handling for query messages as hosts should automatically send reports
		// We just need to ensure query messages are properly forwarded to all ports
	}
}

// IPv4ToMulticastMac converts an IPv4 multicast address to an Ethernet multicast MAC address
func IPv4ToMulticastMac(ipv4Addr [4]byte) address.MAC {
	// Conversion rule from IPv4 multicast address to Ethernet multicast MAC address:
	// The first 3 bytes of MAC address are fixed as 01:00:5E, the highest bit of the 4th byte is 0,
	// and the last 3 bytes use the last 23 bits of the IPv4 address
	var mac address.MAC
	// Set MAC address bytes correctly, avoiding slice operations
	macBytes := []byte{0x01, 0x00, 0x5E, ipv4Addr[1] & 0x7F, ipv4Addr[2], ipv4Addr[3]}
	// Create MAC address using NewMACFromBytes
	macPtr, _ := address.NewMACFromBytes(macBytes)
	if macPtr != nil {
		mac = *macPtr
	}
	return mac
}

// MulticastMacToIPv4 converts an Ethernet multicast MAC address to an IPv4 multicast address (if possible)
func MulticastMacToIPv4(mac address.MAC) (net.IP, bool) {
	// Check if it's an IPv4 multicast MAC address (starting with 01:00:5E)
	macBytes := mac.Bytes()
	if macBytes[0] != 0x01 || macBytes[1] != 0x00 || macBytes[2] != 0x5E {
		return nil, false
	}

	// Create IPv4 address
	ipv4Addr := make(net.IP, 4)
	ipv4Addr[0] = 224 // IPv4多播地址范围：224.0.0.0 - 239.255.255.255
	ipv4Addr[1] = macBytes[3]
	ipv4Addr[2] = macBytes[4]
	ipv4Addr[3] = macBytes[5]

	return ipv4Addr, true
}

// IsIGMPPacket checks if a packet contains an IGMP message
func IsIGMPPacket(ethFrame []byte) bool {
	// Validate Ethernet frame length
	if len(ethFrame) < 14+20 { // 以太网头部(14) + 最小IPv4头部(20)
		return false
	}

	// Parse the Ethernet type of the Ethernet frame
	etherType := binary.BigEndian.Uint16(ethFrame[12:14])

	// Check if it's an IPv4 packet
	if etherType != 0x0800 { // IPv4
		return false
	}

	// Parse IPv4 header
	ipHeader := ethFrame[14 : 14+20]
	protocol := ipHeader[9] // 第10个字节是协议字段

	// Check if it's IGMP protocol
	if protocol != 2 { // IGMP
		return false
	}

	return true
}
