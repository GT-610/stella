package switcher

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/stella/virtual-switch/pkg/packet"
)

// VXLAN相关常量
const (
	// VXLAN UDP端口
	VxlanUdpPort = 4789

	// VXLAN头部长度
	VxlanHeaderLength = 8

	// VXLAN flags中VNI有效的标志位
	VxlanFlagIbit = 0x08

	// 最大VXLAN标识符(VNI)值
	MaxVxlanVni = 0xffffff
)

// VXLAN封装器结构
type VxlanEncapsulator struct {
	// 可以添加额外的配置参数，如UDP端口等
	UdpPort uint16
}

// 创建新的VXLAN封装器
func NewVxlanEncapsulator() *VxlanEncapsulator {
	return &VxlanEncapsulator{
		UdpPort: VxlanUdpPort,
	}
}

// 将VLAN ID转换为VNI (Virtual Network Identifier)
// VLAN ID范围: 1-4094
// VNI范围: 0-16777215
func VlanIdToVni(vlanId uint16) uint32 {
	// 简单映射：将VLAN ID扩展为24位VNI
	// 实际应用中可能有更复杂的映射规则
	return uint32(vlanId)
}

// 将VNI转换为VLAN ID
func VniToVlanId(vni uint32) (uint16, error) {
	if vni > MaxVlanID {
		return 0, errors.New("VNI exceeds maximum VLAN ID")
	}
	return uint16(vni), nil
}

// 封装数据包为VXLAN格式
// 注意：这是一个简化的实现，实际的VXLAN封装需要UDP/IP头
func (v *VxlanEncapsulator) EncapsulatePacket(pkt *packet.Packet, vlanId uint16) ([]byte, error) {
	// 验证VLAN ID
	if vlanId < 1 || vlanId > MaxVlanID {
		return nil, fmt.Errorf("invalid VLAN ID: %d", vlanId)
	}

	// 获取原始数据包内容
	payload := pkt.Payload()
	if len(payload) == 0 {
		return nil, errors.New("empty packet payload")
	}

	// 计算VNI
	vni := VlanIdToVni(vlanId)

	// 创建VXLAN头部
	vxlanHeader := make([]byte, VxlanHeaderLength)

	// 设置标志位（只设置I位，表示VNI有效）
	vxlanHeader[0] = VxlanFlagIbit

	// 设置VNI（占用后24位，前8位保留）
	binary.BigEndian.PutUint32(vxlanHeader[4:], vni<<8)

	// 组合VXLAN头部和原始以太网帧
	vxlanPacket := append(vxlanHeader, payload...)

	return vxlanPacket, nil
}

// 解封装VXLAN数据包
func (v *VxlanEncapsulator) DecapsulatePacket(data []byte) ([]byte, uint16, error) {
	// 检查数据包长度
	if len(data) < VxlanHeaderLength {
		return nil, 0, errors.New("VXLAN packet too short")
	}

	// 检查I标志位
	if (data[0] & VxlanFlagIbit) == 0 {
		return nil, 0, errors.New("VXLAN packet missing I flag")
	}

	// 提取VNI（后24位）
	vni := binary.BigEndian.Uint32(data[4:]) >> 8

	// 转换VNI为VLAN ID
	vlanId, err := VniToVlanId(vni)
	if err != nil {
		return nil, 0, err
	}

	// 提取原始以太网帧
	ethFrame := data[VxlanHeaderLength:]

	return ethFrame, vlanId, nil
}

// 检查是否是VXLAN数据包
func (v *VxlanEncapsulator) IsVxlanPacket(data []byte) bool {
	// 基本长度检查和标志位检查
	return len(data) >= VxlanHeaderLength && (data[0]&VxlanFlagIbit) != 0
}