package switcher

import (
	"testing"

	"github.com/stella/virtual-switch/pkg/switcher"
	"github.com/stretchr/testify/assert"
)

// TestVlanManagerCreation 测试VLAN管理器创建
func TestVlanManagerCreation(t *testing.T) {
	vlanManager := switcher.NewVlanManager()
	assert.NotNil(t, vlanManager, "Expected non-nil VLAN manager")
}

// TestVlanConfigCreation 测试VLAN配置创建
func TestVlanConfigCreation(t *testing.T) {
	// 测试有效的VLAN ID
	vlan, err := switcher.NewVlanConfig(100, "Test VLAN 100")
	assert.NoError(t, err, "Expected no error creating VLAN with valid ID")
	assert.Equal(t, uint16(100), vlan.ID, "Expected VLAN ID to be 100")
	assert.Equal(t, "Test VLAN 100", vlan.Name, "Expected VLAN name to match")
	assert.True(t, vlan.Enabled, "Expected VLAN to be enabled by default")

	// 测试无效的VLAN ID（0）
	vlan, err = switcher.NewVlanConfig(0, "Invalid VLAN")
	assert.Error(t, err, "Expected error creating VLAN with ID 0")
	assert.Nil(t, vlan, "Expected nil VLAN for invalid ID")

	// 测试无效的VLAN ID（超过最大值）
	vlan, err = switcher.NewVlanConfig(4095, "Invalid VLAN")
	assert.Error(t, err, "Expected error creating VLAN with ID > 4094")
	assert.Nil(t, vlan, "Expected nil VLAN for invalid ID")
}

// TestAddAndRemoveVlan 测试添加和删除VLAN
func TestAddAndRemoveVlan(t *testing.T) {
	vlanManager := switcher.NewVlanManager()

	// 添加VLAN
	vlan, _ := switcher.NewVlanConfig(100, "Test VLAN 100")
	err := vlanManager.AddVlan(vlan)
	assert.NoError(t, err, "Expected no error adding VLAN")

	// 检查是否添加成功
	addedVlan, err := vlanManager.GetVlan(100)
	assert.NoError(t, err, "Expected to find added VLAN")
	assert.Equal(t, vlan, addedVlan, "Expected VLAN objects to be the same")

	// 尝试添加相同ID的VLAN
	anotherVlan, _ := switcher.NewVlanConfig(100, "Another VLAN 100")
	err = vlanManager.AddVlan(anotherVlan)
	assert.Error(t, err, "Expected error adding duplicate VLAN")

	// 删除VLAN
	err = vlanManager.RemoveVlan(100)
	assert.NoError(t, err, "Expected no error removing VLAN")

	// 检查是否删除成功
	_, err = vlanManager.GetVlan(100)
	assert.Error(t, err, "Expected to not find removed VLAN")

	// 尝试删除不存在的VLAN
	err = vlanManager.RemoveVlan(999)
	assert.Error(t, err, "Expected error removing non-existent VLAN")
}

// TestGetAllVlans 测试获取所有VLAN
func TestGetAllVlans(t *testing.T) {
	vlanManager := switcher.NewVlanManager()

	// 添加多个VLAN
	vlan1, _ := switcher.NewVlanConfig(100, "VLAN 100")
	vlan2, _ := switcher.NewVlanConfig(200, "VLAN 200")
	vlan3, _ := switcher.NewVlanConfig(300, "VLAN 300")

	vlanManager.AddVlan(vlan1)
	vlanManager.AddVlan(vlan2)
	vlanManager.AddVlan(vlan3)

	// 获取所有VLAN
	allVlans := vlanManager.GetAllVlans()
	assert.Len(t, allVlans, 3, "Expected to get 3 VLANs")

	// 检查是否包含所有添加的VLAN
	vlanMap := make(map[uint16]*switcher.VlanConfig)
	for _, vlan := range allVlans {
		vlanMap[vlan.ID] = vlan
	}

	assert.Contains(t, vlanMap, uint16(100), "Expected to find VLAN 100")
	assert.Contains(t, vlanMap, uint16(200), "Expected to find VLAN 200")
	assert.Contains(t, vlanMap, uint16(300), "Expected to find VLAN 300")
}

// TestUpdateVlan 测试更新VLAN配置
func TestUpdateVlan(t *testing.T) {
	vlanManager := switcher.NewVlanManager()

	// 添加VLAN
	vlan, _ := switcher.NewVlanConfig(100, "Original VLAN")
	vlanManager.AddVlan(vlan)

	// 更新VLAN配置
	updatedVlan := &switcher.VlanConfig{
		ID:          100,
		Name:        "Updated VLAN",
		Description: "Updated description",
		Enabled:     false,
	}

	err := vlanManager.UpdateVlan(updatedVlan)
	assert.NoError(t, err, "Expected no error updating VLAN")

	// 检查更新是否成功
	retrievedVlan, _ := vlanManager.GetVlan(100)
	assert.Equal(t, "Updated VLAN", retrievedVlan.Name, "Expected updated name")
	assert.Equal(t, "Updated description", retrievedVlan.Description, "Expected updated description")
	assert.False(t, retrievedVlan.Enabled, "Expected VLAN to be disabled")

	// 尝试更新不存在的VLAN
	nonExistentVlan := &switcher.VlanConfig{
		ID:          999,
		Name:        "Non-existent VLAN",
		Description: "",
		Enabled:     true,
	}

	err = vlanManager.UpdateVlan(nonExistentVlan)
	assert.Error(t, err, "Expected error updating non-existent VLAN")
}

// TestIsVlanActive 测试检查VLAN是否活动
func TestIsVlanActive(t *testing.T) {
	vlanManager := switcher.NewVlanManager()

	// 添加启用的VLAN
	enabledVlan, _ := switcher.NewVlanConfig(100, "Enabled VLAN")
	enabledVlan.Enabled = true
	vlanManager.AddVlan(enabledVlan)

	// 添加禁用的VLAN
	disabledVlan, _ := switcher.NewVlanConfig(200, "Disabled VLAN")
	disabledVlan.Enabled = false
	vlanManager.AddVlan(disabledVlan)

	// 检查VLAN活动状态
	assert.True(t, vlanManager.IsVlanActive(100), "Expected VLAN 100 to be active")
	assert.False(t, vlanManager.IsVlanActive(200), "Expected VLAN 200 to be inactive")
	assert.False(t, vlanManager.IsVlanActive(300), "Expected non-existent VLAN to be inactive")
}

// TestPortVlanConfig 测试端口VLAN配置
func TestPortVlanConfig(t *testing.T) {
	// 创建端口
	port := switcher.NewPort("port1", "Test Port")

	// 检查默认VLAN配置
	assert.Equal(t, switcher.VlanModeAccess, port.VlanMode, "Expected default VLAN mode to be Access")
	assert.Equal(t, uint16(1), port.AccessVlanID, "Expected default Access VLAN to be 1")
	assert.Equal(t, uint16(1), port.NativeVlanID, "Expected default Native VLAN to be 1")
	assert.NotNil(t, port.AllowedVlans, "Expected AllowedVlans map to be initialized")

	// 修改VLAN模式为Trunk
	port.VlanMode = switcher.VlanModeTrunk
	port.NativeVlanID = 10

	// 添加允许的VLAN
	port.AllowedVlans[10] = true
	port.AllowedVlans[20] = true
	port.AllowedVlans[30] = true

	// 验证配置
	assert.Equal(t, switcher.VlanModeTrunk, port.VlanMode, "Expected VLAN mode to be Trunk")
	assert.Equal(t, uint16(10), port.NativeVlanID, "Expected Native VLAN to be 10")
	assert.True(t, port.AllowedVlans[10], "Expected VLAN 10 to be allowed")
	assert.True(t, port.AllowedVlans[20], "Expected VLAN 20 to be allowed")
	assert.True(t, port.AllowedVlans[30], "Expected VLAN 30 to be allowed")
	assert.False(t, port.AllowedVlans[40], "Expected VLAN 40 to be not allowed")
}

// TestVxlanVniConversion 测试VLAN ID与VNI的转换
func TestVxlanVniConversion(t *testing.T) {
	// 测试有效的转换
	vni := switcher.VlanIdToVni(100)
	assert.Equal(t, uint32(100), vni, "Expected VNI to match VLAN ID")

	vlanId, err := switcher.VniToVlanId(100)
	assert.NoError(t, err, "Expected no error converting VNI to VLAN ID")
	assert.Equal(t, uint16(100), vlanId, "Expected VLAN ID to match VNI")

	// 测试无效的VNI转换
	_, err = switcher.VniToVlanId(5000) // 超过最大VLAN ID
	assert.Error(t, err, "Expected error converting invalid VNI")
}

// TestVxlanEncapsulation 测试VXLAN封装（基本功能）
func TestVxlanEncapsulation(t *testing.T) {
	encapsulator := switcher.NewVxlanEncapsulator()

	// 这里我们只测试封装器的存在性，因为完整的封装需要真实的数据包结构
	assert.NotNil(t, encapsulator, "Expected non-nil VXLAN encapsulator")
	assert.Equal(t, uint16(4789), encapsulator.UdpPort, "Expected default UDP port 4789")
}