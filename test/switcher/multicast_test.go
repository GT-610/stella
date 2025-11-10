// Copyright 2023 The Stella Authors
// SPDX-License-Identifier: Apache-2.0

package switcher

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stella/virtual-switch/pkg/address"
	"github.com/stella/virtual-switch/pkg/switcher"
)

// TestMulticastManagerCreation 测试多播管理器的创建
func TestMulticastManagerCreation(t *testing.T) {
	manager := switcher.NewMulticastManager()
	assert.NotNil(t, manager, "Expected non-nil multicast manager")
	// 不能直接访问未导出字段，使用功能测试替代
}

// TestAddAndRemoveMember 测试添加和移除多播组成员
func TestAddAndRemoveMember(t *testing.T) {
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

	// 添加成员
	manager.AddMember(vlanID, groupMac, 0, portID)

	// 验证成员存在
	isMember := manager.IsMember(portID, vlanID, groupMac)
	assert.True(t, isMember, "Expected port to be a member of the multicast group")

	// 移除成员
	manager.RemoveMember(vlanID, groupMac, 0, portID)

	// 验证成员已移除
	isMember = manager.IsMember(portID, vlanID, groupMac)
	assert.False(t, isMember, "Expected port to be removed from the multicast group")
}

// TestGetMemberPorts 测试获取多播组的成员端口
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

// TestCleanupAgedMembers 测试清理过期的多播组成员
// 注意：由于我们无法直接访问内部的老化时间和锁，这个测试的实现方式需要调整
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

	// 添加成员
	manager.AddMember(vlanID, groupMac, 0, portID)

	// 验证成员存在
	isMember := manager.IsMember(portID, vlanID, groupMac)
	assert.True(t, isMember, "Expected port to be a member before cleanup")

	// 注意：由于无法直接修改内部的老化时间和时间戳，
	// 我们无法直接测试老化功能，但可以验证清理函数不会影响当前成员
	manager.CleanupAgedMembers()

	// 验证成员仍然存在（因为我们没有让它过期）
	isMember = manager.IsMember(portID, vlanID, groupMac)
	assert.True(t, isMember, "Expected port to still be a member")
}



// TestIPv4ToMulticastMac 测试IP地址到多播MAC地址的转换
func TestIPv4ToMulticastMac(t *testing.T) {
	// 测试用例：IP地址到MAC地址的映射
	testCases := []struct {
		ip      net.IP
		expectedMacBytes []byte
	}{{
		ip:      net.ParseIP("224.0.0.1"),
		expectedMacBytes: []byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01},
	}, {
		ip:      net.ParseIP("239.255.255.255"),
		expectedMacBytes: []byte{0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFF},
	}, {
		ip:      net.ParseIP("224.128.0.1"),
		expectedMacBytes: []byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}, // 注意：最高位被忽略
	}}

	for i, tc := range testCases {
		// 执行转换 - 将net.IP转换为[4]byte数组
		ipv4Addr := [4]byte{0, 0, 0, 0}
		if ipv4 := tc.ip.To4(); ipv4 != nil {
			copy(ipv4Addr[:], ipv4)
		} else {
			t.Fatalf("Test case %d: Invalid IPv4 address", i)
		}
		mac := switcher.IPv4ToMulticastMac(ipv4Addr)

		// 获取MAC地址的字节数组进行比较
		macBytes := mac.Bytes()
		assert.Equal(t, tc.expectedMacBytes, macBytes, "Test case %d failed", i)
	}
}

// TestIsIGMPPacket 测试IGMP数据包检测
func TestIsIGMPPacket(t *testing.T) {
	// 创建一个简单的IGMP数据包（以太网帧 + IPv4头部 + IGMP消息）
	// 以太网帧头部
	destMac := []byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01} // 多播MAC
	srcMac := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	etherType := []byte{0x08, 0x00} // IPv4

	// IPv4头部（简化版）
	ipHeader := []byte{
		0x45,                     // 版本+头部长度
		0x00,                     // 服务类型
		0x00, 0x1C,               // 总长度
		0x00, 0x00,               // 标识
		0x00, 0x00,               // 标志+片偏移
		0x40,                     // TTL
		0x02,                     // 协议 = IGMP
		0x00, 0x00,               // 校验和（暂时为0）
		192, 168, 1, 10,          // 源IP
		224, 0, 0, 1,             // 目标IP（多播）
	}

	// IGMP消息
	igmpMessage := []byte{
		0x11,                     // 类型 = 成员查询
		0x00,                     // 最大响应时间
		0x00, 0x00,               // 校验和（暂时为0）
		0x00, 0x00, 0x00, 0x00,   // 组地址
	}

	// 组装完整的数据包
	packet := append(destMac, srcMac...)
	packet = append(packet, etherType...)
	packet = append(packet, ipHeader...)
	packet = append(packet, igmpMessage...)

	// 验证这是IGMP数据包
	assert.True(t, switcher.IsIGMPPacket(packet), "Expected packet to be recognized as IGMP")

	// 修改协议字段为非IGMP
	packet[23] = 0x06 // TCP
	assert.False(t, switcher.IsIGMPPacket(packet), "Expected packet to not be recognized as IGMP after protocol change")
}