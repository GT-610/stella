package switcher

import (
	"errors"
	"sync"
)

// VlanMode represents port VLAN modes
type VlanMode int

const (
	// VlanModeAccess - Can belong to only one VLAN
	VlanModeAccess VlanMode = iota
	// VlanModeTrunk - Can carry multiple VLAN traffic
	VlanModeTrunk
	// VlanModeHybrid - Hybrid mode, supports both Access and Trunk features
	VlanModeHybrid
)

// MaxVlanID is the maximum VLAN ID allowed
const MaxVlanID = 4094

// VlanConfig represents a VLAN configuration
type VlanConfig struct {
	ID          uint16      // VLAN ID (1-4094)
	Name        string      // VLAN name
	Description string      // VLAN description
	Enabled     bool        // Whether enabled
}

// VlanManager manages VLAN configurations
type VlanManager struct {
	vlans     map[uint16]*VlanConfig // VLAN configuration map
	mutex     sync.RWMutex          // Concurrency control lock
}

// NewVlanManager creates a new VLAN manager
func NewVlanManager() *VlanManager {
	return &VlanManager{
		vlans: make(map[uint16]*VlanConfig),
	}
}

// NewVlanConfig creates a new VLAN configuration
func NewVlanConfig(id uint16, name string) (*VlanConfig, error) {
	// Validate VLAN ID
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

// AddVlan adds a VLAN configuration
func (vm *VlanManager) AddVlan(vlan *VlanConfig) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// Check if VLAN already exists
	if _, exists := vm.vlans[vlan.ID]; exists {
		return errors.New("VLAN already exists")
	}

	vm.vlans[vlan.ID] = vlan
	return nil
}

// RemoveVlan removes a VLAN configuration
func (vm *VlanManager) RemoveVlan(id uint16) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// Check if VLAN exists
	if _, exists := vm.vlans[id]; !exists {
		return errors.New("VLAN not found")
	}

	delete(vm.vlans, id)
	return nil
}

// GetVlan retrieves a VLAN configuration
func (vm *VlanManager) GetVlan(id uint16) (*VlanConfig, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	vlan, exists := vm.vlans[id]
	if !exists {
		return nil, errors.New("VLAN not found")
	}

	return vlan, nil
}

// GetAllVlans retrieves all VLAN configurations
func (vm *VlanManager) GetAllVlans() []*VlanConfig {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	vlans := make([]*VlanConfig, 0, len(vm.vlans))
	for _, vlan := range vm.vlans {
		vlans = append(vlans, vlan)
	}

	return vlans
}

// UpdateVlan updates a VLAN configuration
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

// IsVlanActive checks if a VLAN exists and is enabled
func (vm *VlanManager) IsVlanActive(id uint16) bool {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	vlan, exists := vm.vlans[id]
	return exists && vlan.Enabled
}