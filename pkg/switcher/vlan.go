package switcher

import (
	"errors"
	"sync"
)

// 端口VLAN模式枚举
type VlanMode int

const (
	// Access端口模式 - 只能属于一个VLAN
	VlanModeAccess VlanMode = iota
	// Trunk端口模式 - 可以传输多个VLAN的流量
	VlanModeTrunk
	// Hybrid端口模式 - 混合模式，支持Access和Trunk特性
	VlanModeHybrid
)

// 最大VLAN ID
const MaxVlanID = 4094

// VLAN配置结构
type VlanConfig struct {
	ID          uint16      // VLAN ID (1-4094)
	Name        string      // VLAN名称
	Description string      // VLAN描述
	Enabled     bool        // 是否启用
}

// VLAN管理器
type VlanManager struct {
	vlans     map[uint16]*VlanConfig // VLAN配置映射
	mutex     sync.RWMutex          // 并发控制锁
}

// 创建新的VLAN管理器
func NewVlanManager() *VlanManager {
	return &VlanManager{
		vlans: make(map[uint16]*VlanConfig),
	}
}

// 创建新的VLAN配置
func NewVlanConfig(id uint16, name string) (*VlanConfig, error) {
	// 验证VLAN ID
	if id == 0 || id > MaxVlanID {
		return nil, errors.New("invalid VLAN ID, must be between 1 and 4094")
	}

	return &VlanConfig{
		ID:          id,
		Name:        name,
		Description: "",
		Enabled:     true,
	}, nil
}

// 添加VLAN
func (vm *VlanManager) AddVlan(vlan *VlanConfig) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// 检查VLAN是否已存在
	if _, exists := vm.vlans[vlan.ID]; exists {
		return errors.New("VLAN already exists")
	}

	vm.vlans[vlan.ID] = vlan
	return nil
}

// 删除VLAN
func (vm *VlanManager) RemoveVlan(id uint16) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// 检查VLAN是否存在
	if _, exists := vm.vlans[id]; !exists {
		return errors.New("VLAN not found")
	}

	delete(vm.vlans, id)
	return nil
}

// 获取VLAN配置
func (vm *VlanManager) GetVlan(id uint16) (*VlanConfig, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	vlan, exists := vm.vlans[id]
	if !exists {
		return nil, errors.New("VLAN not found")
	}

	return vlan, nil
}

// 获取所有VLAN配置
func (vm *VlanManager) GetAllVlans() []*VlanConfig {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	vlans := make([]*VlanConfig, 0, len(vm.vlans))
	for _, vlan := range vm.vlans {
		vlans = append(vlans, vlan)
	}

	return vlans
}

// 更新VLAN配置
func (vm *VlanManager) UpdateVlan(vlan *VlanConfig) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// 检查VLAN是否存在
	if _, exists := vm.vlans[vlan.ID]; !exists {
		return errors.New("VLAN not found")
	}

	vm.vlans[vlan.ID] = vlan
	return nil
}

// 检查VLAN是否存在且启用
func (vm *VlanManager) IsVlanActive(id uint16) bool {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	vlan, exists := vm.vlans[id]
	return exists && vlan.Enabled
}