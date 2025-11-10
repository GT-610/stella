// Copyright 2023 The Stella Authors
// SPDX-License-Identifier: Apache-2.0

package switcher

import (
	"encoding/binary"
	"net"

	"github.com/stella/virtual-switch/pkg/address"
)

// IGMP消息类型常量
const (
	IGMPTypeMembershipQuery       = 0x11
	IGMPTypeMembershipReportV1    = 0x12
	IGMPTypeMembershipReportV2    = 0x16
	IGMPTypeMembershipReportV3    = 0x22
	IGMPTypeLeaveGroup            = 0x17
)

// IGMP头部结构
type IGMPHeader struct {
	Type        uint8
	MaxRespTime uint8
	Checksum    uint16
}

// IGMP成员关系查询消息结构
type IGMPMembershipQuery struct {
	Header      IGMPHeader
	GroupAddress [4]byte
}

// IGMP成员关系报告消息结构
type IGMPMembershipReport struct {
	Header      IGMPHeader
	GroupAddress [4]byte
}

// IGMP离开组消息结构
type IGMPLeaveGroup struct {
	Header      IGMPHeader
	GroupAddress [4]byte
}

// 计算IGMP校验和
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	// 将溢出部分相加
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	return uint16(^sum)
}

// 验证IGMP校验和
func validateChecksum(data []byte) bool {
	return calculateChecksum(data) == 0
}

// 解析IPv4数据包中的IGMP消息
func ParseIGMPMessage(ipv4Data []byte) (uint8, [4]byte, bool) {
	// IPv4头部长度
	ipHeaderLen := int((ipv4Data[0] & 0x0F) << 2)
	if ipHeaderLen < 20 || len(ipv4Data) < ipHeaderLen {
		return 0, [4]byte{}, false
	}

	// 提取IGMP消息
	igmpData := ipv4Data[ipHeaderLen:]
	if len(igmpData) < 8 {
		return 0, [4]byte{}, false
	}

	// 验证校验和
	if !validateChecksum(igmpData) {
		return 0, [4]byte{}, false
	}

	// 解析IGMP头部
	var header IGMPHeader
	header.Type = igmpData[0]
	header.MaxRespTime = igmpData[1]
	header.Checksum = binary.BigEndian.Uint16(igmpData[2:4])

	// 提取组地址
	var groupAddr [4]byte
	copy(groupAddr[:], igmpData[4:8])

	return header.Type, groupAddr, true
}

// 处理IGMP消息
func (m *MulticastManager) HandleIGMPMessage(portID string, vlanID uint16, igmpType uint8, groupAddr [4]byte) {
	// 将IPv4多播地址转换为MAC地址
	multicastMac := IPv4ToMulticastMac(groupAddr)
	
	// 根据IGMP消息类型处理
	switch igmpType {
	case IGMPTypeMembershipReportV1, IGMPTypeMembershipReportV2, IGMPTypeMembershipReportV3:
		// 成员报告，添加端口到多播组
		m.AddMember(vlanID, multicastMac, 0, portID)
	case IGMPTypeLeaveGroup:
		// 离开组，从多播组中移除端口
		m.RemoveMember(vlanID, multicastMac, 0, portID)

	case IGMPTypeMembershipQuery:
		// 处理查询消息
		// 我们不需要特殊处理查询消息，因为主机应该自动发送报告
		// 我们只需要确保查询消息被正确转发到所有端口
	}
}

// 将IPv4多播地址转换为以太网多播MAC地址
func IPv4ToMulticastMac(ipv4Addr [4]byte) address.MAC {
	// IPv4多播地址到以太网多播MAC地址的转换规则：
	// MAC地址的前3个字节固定为01:00:5E，第4个字节的最高位为0，
	// 最后3个字节使用IPv4地址的最后23位
	var mac address.MAC
	// 使用正确的方式设置MAC地址字节，避免切片操作
	macBytes := []byte{0x01, 0x00, 0x5E, ipv4Addr[1] & 0x7F, ipv4Addr[2], ipv4Addr[3]}
	// 使用NewMACFromBytes创建MAC地址
	macPtr, _ := address.NewMACFromBytes(macBytes)
	if macPtr != nil {
		mac = *macPtr
	}
	return mac
}

// 将以太网多播MAC地址转换为IPv4多播地址（如果可能）
func MulticastMacToIPv4(mac address.MAC) (net.IP, bool) {
	// 检查是否是IPv4多播MAC地址（01:00:5E开头）
	macBytes := mac.Bytes()
	if macBytes[0] != 0x01 || macBytes[1] != 0x00 || macBytes[2] != 0x5E {
		return nil, false
	}

	// 创建IPv4地址
	ipv4Addr := make(net.IP, 4)
	ipv4Addr[0] = 224 // IPv4多播地址范围：224.0.0.0 - 239.255.255.255
	ipv4Addr[1] = macBytes[3]
	ipv4Addr[2] = macBytes[4]
	ipv4Addr[3] = macBytes[5]

	return ipv4Addr, true
}

// 检查数据包是否包含IGMP消息
func IsIGMPPacket(ethFrame []byte) bool {
	// 验证以太网帧长度
	if len(ethFrame) < 14+20 { // 以太网头部(14) + 最小IPv4头部(20)
		return false
	}

	// 解析以太网帧的以太网类型
	etherType := binary.BigEndian.Uint16(ethFrame[12:14])

	// 检查是否是IPv4数据包
	if etherType != 0x0800 { // IPv4
		return false
	}

	// 解析IPv4头部
	ipHeader := ethFrame[14 : 14+20]
	protocol := ipHeader[9] // 第10个字节是协议字段

	// 检查是否是IGMP协议
	if protocol != 2 { // IGMP
		return false
	}

	return true
}