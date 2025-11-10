package switcher

import (
	"errors"
	"sync"

	"github.com/stella/virtual-switch/pkg/packet"
)

// 端口状态枚举
type PortState int

const (
	PortStateDown PortState = iota
	PortStateUp
	PortStateError
)

// 端口结构体
type Port struct {
	// 基本信息
	ID          string
	Name        string
	Description string
	State       PortState
	MTU         int
	Speed       int
	Duplex      bool // true for full duplex

	// VLAN配置
	VlanMode       VlanMode // 端口VLAN模式
	AccessVlanID   uint16   // Access模式下的VLAN ID
	AllowedVlans   map[uint16]bool // Trunk模式下允许的VLAN列表
	NativeVlanID   uint16   // Native VLAN ID（用于未标记帧）

	// 连接回调
	packetHandler func(*packet.Packet) error

	// 同步控制
	mutex sync.RWMutex
}

// 创建新端口
func NewPort(id string, name string) *Port {
	return &Port{
		ID:          id,
		Name:        name,
		Description: "Virtual Switch Port",
		State:       PortStateDown,
		MTU:         1500,
		Speed:       1000,
		Duplex:      true,
		// VLAN默认配置
		VlanMode:     VlanModeAccess,
		AccessVlanID: 1,        // 默认VLAN 1
		AllowedVlans: make(map[uint16]bool),
		NativeVlanID: 1,        // 默认Native VLAN 1
	}
}

// 获取端口状态
func (p *Port) GetState() PortState {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.State
}

// 发送数据包
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

// 关闭端口
func (p *Port) Close() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.State = PortStateDown
	p.packetHandler = nil
}

// 设置数据包处理回调
func (p *Port) SetPacketHandler(handler func(*packet.Packet) error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.packetHandler = handler
}