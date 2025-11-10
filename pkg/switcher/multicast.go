// Copyright 2023 The Stella Authors
// SPDX-License-Identifier: Apache-2.0

package switcher

import (
	"sync"
	"time"

	"github.com/stella/virtual-switch/pkg/address"
	"github.com/stella/virtual-switch/pkg/packet"
)

// 多播组定义
type MulticastGroup struct {
	Mac  address.MAC
	Adi  uint32 // 额外区分信息(Additional Distinguishing Information)
}

// 多播组成员
type MulticastGroupMember struct {
	PortID    string
	Timestamp int64
}

// 多播组状态
type multicastGroupStatus struct {
	Members   []MulticastGroupMember
	LastQuery int64
}

// 多播组键
type multicastGroupKey struct {
	VlanID    uint16
	GroupMac  address.MAC
	GroupAdi  uint32
}

// MulticastManager 多播管理器
// 负责管理多播组、IGMP监听和多播数据包转发
type MulticastManager struct {
	groups     map[multicastGroupKey]*multicastGroupStatus // 多播组状态映射
	agingTime  time.Duration                              // 成员老化时间
	mutex      sync.RWMutex                               // 读写锁，保护并发访问
}

// NewMulticastManager 创建新的多播管理器实例
func NewMulticastManager() *MulticastManager {
	return &MulticastManager{
		groups:    make(map[multicastGroupKey]*multicastGroupStatus),
		agingTime: 3 * time.Minute, // 默认3分钟老化时间
	}
}

// 添加或更新多播组成员
func (m *MulticastManager) AddMember(vlanID uint16, groupMac address.MAC, adi uint32, portID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := multicastGroupKey{
		VlanID:    vlanID,
		GroupMac:  groupMac,
		GroupAdi:  adi,
	}

	now := time.Now().UnixNano()

	if status, exists := m.groups[key]; exists {
		// 检查成员是否已存在
		for i, member := range status.Members {
			if member.PortID == portID {
				// 更新时间戳
				status.Members[i].Timestamp = now
				return
			}
		}
		// 添加新成员
		status.Members = append(status.Members, MulticastGroupMember{
			PortID:    portID,
			Timestamp: now,
		})
	} else {
		// 创建新的多播组
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

// 移除多播组成员
func (m *MulticastManager) RemoveMember(vlanID uint16, groupMac address.MAC, adi uint32, portID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := multicastGroupKey{
		VlanID:    vlanID,
		GroupMac:  groupMac,
		GroupAdi:  adi,
	}

	if status, exists := m.groups[key]; exists {
		for i, member := range status.Members {
			if member.PortID == portID {
				// 移除成员
				status.Members = append(status.Members[:i], status.Members[i+1:]...)
				// 如果没有成员了，删除整个组
				if len(status.Members) == 0 {
					delete(m.groups, key)
				}
				return
			}
		}
	}
}

// 获取多播组的所有成员端口ID
func (m *MulticastManager) GetMemberPorts(vlanID uint16, groupMac address.MAC, excludePortID string) []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 查找匹配的多播组
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

// 检查端口是否是多播组成员
func (m *MulticastManager) IsMember(portID string, vlanID uint16, groupMac address.MAC) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 查找匹配的多播组
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

// 清理过期的多播组成员
func (m *MulticastManager) CleanupAgedMembers() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now().UnixNano()
	for key, status := range m.groups {
		// 过滤出未过期的成员
		var activeMembers []MulticastGroupMember
		for _, member := range status.Members {
			if now-m.agingTime.Nanoseconds() < member.Timestamp {
				activeMembers = append(activeMembers, member)
			}
		}

		if len(activeMembers) == 0 {
			// 如果没有活跃成员，删除组
			delete(m.groups, key)
		} else {
			// 更新成员列表
			status.Members = activeMembers
		}
	}
}

// 处理多播数据包
func (m *MulticastManager) HandleMulticastPacket(switcher *Switcher, portID string, pkt *packet.Packet, vlanID uint16, ethFrame []byte) error {
	// 解析以太网帧的目标MAC地址
	if len(ethFrame) < 6 {
		return nil // 无效的以太网帧
	}

	// 使用NewMACFromBytes创建MAC地址
	destMac, err := address.NewMACFromBytes(ethFrame[:6])
	if err != nil {
		return nil // 无效的MAC地址
	}

	// 检查是否是多播MAC地址
	if !destMac.IsMulticast() {
		return nil // 不是多播地址
	}

	// 获取应该接收此多播数据包的端口
	memberPorts := m.GetMemberPorts(vlanID, *destMac, portID)

	// 转发数据包到所有目标端口
	for _, destPortID := range memberPorts {
		if destPort, err := switcher.GetPort(destPortID); err == nil {
			destPort.SendPacket(pkt)
		}
	}

	return nil
}