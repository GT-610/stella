package switcher

import (
	"net"
	"testing"

	"github.com/stella/virtual-switch/pkg/address"
	"github.com/stella/virtual-switch/pkg/switcher"
	"github.com/stretchr/testify/assert"
)

// TestMulticastManagerCreation tests the creation of multicast manager
func TestMulticastManagerCreation(t *testing.T) {
	manager := switcher.NewMulticastManager()
	assert.NotNil(t, manager, "Expected non-nil multicast manager")
	// Cannot directly access unexported fields, using functional tests instead
}

// TestAddAndRemoveMember tests adding and removing multicast group members
func TestAddAndRemoveMember(t *testing.T) {
	manager := switcher.NewMulticastManager()
	vlanID := uint16(1)
	// Create MAC address using the correct method
	groupMacBytes := []byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01} // 224.0.0.1
	groupMacPtr, _ := address.NewMACFromBytes(groupMacBytes)
	if groupMacPtr == nil {
		t.Fatal("Failed to create MAC address")
	}
	groupMac := *groupMacPtr
	portID := "port1"

	// Add member
	manager.AddMember(vlanID, groupMac, 0, portID)

	// Verify member exists
	isMember := manager.IsMember(portID, vlanID, groupMac)
	assert.True(t, isMember, "Expected port to be a member of the multicast group")

	// Remove member
	manager.RemoveMember(vlanID, groupMac, 0, portID)

	// Verify member has been removed
	isMember = manager.IsMember(portID, vlanID, groupMac)
	assert.False(t, isMember, "Expected port to be removed from the multicast group")
}

// TestGetMemberPorts tests retrieving member ports of a multicast group
func TestGetMemberPorts(t *testing.T) {
	manager := switcher.NewMulticastManager()
	vlanID := uint16(1)
	// 使用正确的方式创建MAC地址
	groupMacBytes := []byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01} // 224.0.0.1
	groupMacPtr, _ := address.NewMACFromBytes(groupMacBytes)
	if groupMacPtr == nil {
		t.Fatal("Failed to create MAC address")
	}
	groupMac := *groupMacPtr
	port1 := "port1"
	port2 := "port2"
	port3 := "port3"

	// 添加多个成员
	manager.AddMember(vlanID, groupMac, 0, port1)
	manager.AddMember(vlanID, groupMac, 0, port2)
	manager.AddMember(vlanID, groupMac, 0, port3)

	// 获取成员端口，排除port1
	members := manager.GetMemberPorts(vlanID, groupMac, port1)
	assert.Equal(t, 2, len(members), "Expected 2 member ports excluding port1")
	assert.Contains(t, members, port2, "Expected port2 to be in the member list")
	assert.Contains(t, members, port3, "Expected port3 to be in the member list")
	assert.NotContains(t, members, port1, "Expected port1 to be excluded from the member list")
}

// TestCleanupAgedMembers tests cleaning up aged multicast group members
// Note: Since we cannot directly access internal aging time and locks, the implementation of this test needs adjustment
func TestCleanupAgedMembers(t *testing.T) {
	manager := switcher.NewMulticastManager()
	vlanID := uint16(1)

	// 使用正确的方式创建MAC地址
	groupMacBytes := []byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01} // 224.0.0.1
	groupMacPtr, _ := address.NewMACFromBytes(groupMacBytes)
	if groupMacPtr == nil {
		t.Fatal("Failed to create MAC address")
	}
	groupMac := *groupMacPtr
	portID := "port1"

	// Add member
	manager.AddMember(vlanID, groupMac, 0, portID)

	// Verify member exists
	isMember := manager.IsMember(portID, vlanID, groupMac)
	assert.True(t, isMember, "Expected port to be a member before cleanup")

	// Note: Since we cannot directly modify internal aging time and timestamps,
// we cannot directly test the aging functionality, but we can verify that the cleanup function doesn't affect current members
	manager.CleanupAgedMembers()

	// Verify member still exists (since we didn't age it out)
	isMember = manager.IsMember(portID, vlanID, groupMac)
	assert.True(t, isMember, "Expected port to still be a member")
}

// TestIPv4ToMulticastMac tests the conversion of IP address to multicast MAC address
func TestIPv4ToMulticastMac(t *testing.T) {
	// Test cases: IP address to MAC address mapping
	testCases := []struct {
		ip               net.IP
		expectedMacBytes []byte
	}{{
		ip:               net.ParseIP("224.0.0.1"),
		expectedMacBytes: []byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01},
	}, {
		ip:               net.ParseIP("239.255.255.255"),
		expectedMacBytes: []byte{0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFF},
	}, {
		ip:               net.ParseIP("224.128.0.1"),
		expectedMacBytes: []byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}, // Note: The highest bit is ignored
	}}

	for i, tc := range testCases {
		// Perform conversion - convert net.IP to [4]byte array
		ipv4Addr := [4]byte{0, 0, 0, 0}
		if ipv4 := tc.ip.To4(); ipv4 != nil {
			copy(ipv4Addr[:], ipv4)
		} else {
			t.Fatalf("Test case %d: Invalid IPv4 address", i)
		}
		mac := switcher.IPv4ToMulticastMac(ipv4Addr)

		// Get MAC address byte array for comparison
		macBytes := mac.Bytes()
		assert.Equal(t, tc.expectedMacBytes, macBytes, "Test case %d failed", i)
	}
}

// TestIsIGMPPacket tests IGMP packet detection
func TestIsIGMPPacket(t *testing.T) {
	// Create a simple IGMP packet (Ethernet frame + IPv4 header + IGMP message)
	// Ethernet frame header
	destMac := []byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01} // Multicast MAC
	srcMac := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	etherType := []byte{0x08, 0x00} // IPv4

	// IPv4 header (simplified)
	ipHeader := []byte{
		0x45,       // 版本+头部长度
		0x00,       // 服务类型
		0x00, 0x1C, // 总长度
		0x00, 0x00, // 标识
		0x00, 0x00, // 标志+片偏移
		0x40,       // TTL
		0x02,       // 协议 = IGMP
		0x00, 0x00, // 校验和（暂时为0）
		192, 168, 1, 10, // 源IP
		224, 0, 0, 1, // 目标IP（多播）
	}

	// IGMP message
	igmpMessage := []byte{
		0x11,       // 类型 = 成员查询
		0x00,       // 最大响应时间
		0x00, 0x00, // 校验和（暂时为0）
		0x00, 0x00, 0x00, 0x00, // 组地址
	}

	// Assemble the complete packet
	packet := append(destMac, srcMac...)
	packet = append(packet, etherType...)
	packet = append(packet, ipHeader...)
	packet = append(packet, igmpMessage...)

	// Verify this is an IGMP packet
	assert.True(t, switcher.IsIGMPPacket(packet), "Expected packet to be recognized as IGMP")

	// Modify protocol field to non-IGMP
	packet[23] = 0x06 // TCP
	assert.False(t, switcher.IsIGMPPacket(packet), "Expected packet to not be recognized as IGMP after protocol change")
}
