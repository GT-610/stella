package switcher

import (
	"testing"

	"github.com/stella/virtual-switch/pkg/switcher"
	"github.com/stretchr/testify/assert"
)

// TestVlanManagerCreation tests VLAN manager creation
func TestVlanManagerCreation(t *testing.T) {
	vlanManager := switcher.NewVlanManager()
	assert.NotNil(t, vlanManager, "Expected non-nil VLAN manager")
}

// TestVlanConfigCreation tests VLAN configuration creation
func TestVlanConfigCreation(t *testing.T) {
	// Test valid VLAN ID
	vlan, err := switcher.NewVlanConfig(100, "Test VLAN 100")
	assert.NoError(t, err, "Expected no error creating VLAN with valid ID")
	assert.Equal(t, uint16(100), vlan.ID, "Expected VLAN ID to be 100")
	assert.Equal(t, "Test VLAN 100", vlan.Name, "Expected VLAN name to match")
	assert.True(t, vlan.Enabled, "Expected VLAN to be enabled by default")

	// Test invalid VLAN ID (0)
	vlan, err = switcher.NewVlanConfig(0, "Invalid VLAN")
	assert.Error(t, err, "Expected error creating VLAN with ID 0")
	assert.Nil(t, vlan, "Expected nil VLAN for invalid ID")

	// Test invalid VLAN ID (exceeds maximum)
	vlan, err = switcher.NewVlanConfig(4095, "Invalid VLAN")
	assert.Error(t, err, "Expected error creating VLAN with ID > 4094")
	assert.Nil(t, vlan, "Expected nil VLAN for invalid ID")
}

// TestAddAndRemoveVlan tests adding and removing VLANs
func TestAddAndRemoveVlan(t *testing.T) {
	vlanManager := switcher.NewVlanManager()

	// Add VLAN
	vlan, _ := switcher.NewVlanConfig(100, "Test VLAN 100")
	err := vlanManager.AddVlan(vlan)
	assert.NoError(t, err, "Expected no error adding VLAN")

	// Check if added successfully
	addedVlan, err := vlanManager.GetVlan(100)
	assert.NoError(t, err, "Expected to find added VLAN")
	assert.Equal(t, vlan, addedVlan, "Expected VLAN objects to be the same")

	// Try adding VLAN with same ID
	anotherVlan, _ := switcher.NewVlanConfig(100, "Another VLAN 100")
	err = vlanManager.AddVlan(anotherVlan)
	assert.Error(t, err, "Expected error adding duplicate VLAN")

	// Remove VLAN
	err = vlanManager.RemoveVlan(100)
	assert.NoError(t, err, "Expected no error removing VLAN")

	// Check if removed successfully
	_, err = vlanManager.GetVlan(100)
	assert.Error(t, err, "Expected to not find removed VLAN")

	// Try removing non-existent VLAN
	err = vlanManager.RemoveVlan(999)
	assert.Error(t, err, "Expected error removing non-existent VLAN")
}

// TestGetAllVlans tests retrieving all VLANs
func TestGetAllVlans(t *testing.T) {
	vlanManager := switcher.NewVlanManager()

	// Add multiple VLANs
	vlan1, _ := switcher.NewVlanConfig(100, "VLAN 100")
	vlan2, _ := switcher.NewVlanConfig(200, "VLAN 200")
	vlan3, _ := switcher.NewVlanConfig(300, "VLAN 300")

	vlanManager.AddVlan(vlan1)
	vlanManager.AddVlan(vlan2)
	vlanManager.AddVlan(vlan3)

	// Get all VLANs
	allVlans := vlanManager.GetAllVlans()
	assert.Len(t, allVlans, 3, "Expected to get 3 VLANs")

	// Check if all added VLANs are included
	vlanMap := make(map[uint16]*switcher.VlanConfig)
	for _, vlan := range allVlans {
		vlanMap[vlan.ID] = vlan
	}

	assert.Contains(t, vlanMap, uint16(100), "Expected to find VLAN 100")
	assert.Contains(t, vlanMap, uint16(200), "Expected to find VLAN 200")
	assert.Contains(t, vlanMap, uint16(300), "Expected to find VLAN 300")
}

// TestUpdateVlan tests updating VLAN configuration
func TestUpdateVlan(t *testing.T) {
	vlanManager := switcher.NewVlanManager()

	// Add VLAN
	vlan, _ := switcher.NewVlanConfig(100, "Original VLAN")
	vlanManager.AddVlan(vlan)

	// Update VLAN configuration
	updatedVlan := &switcher.VlanConfig{
		ID:          100,
		Name:        "Updated VLAN",
		Description: "Updated description",
		Enabled:     false,
	}

	err := vlanManager.UpdateVlan(updatedVlan)
	assert.NoError(t, err, "Expected no error updating VLAN")

	// Check if update was successful
	retrievedVlan, _ := vlanManager.GetVlan(100)
	assert.Equal(t, "Updated VLAN", retrievedVlan.Name, "Expected updated name")
	assert.Equal(t, "Updated description", retrievedVlan.Description, "Expected updated description")
	assert.False(t, retrievedVlan.Enabled, "Expected VLAN to be disabled")

	// Try updating non-existent VLAN
	nonExistentVlan := &switcher.VlanConfig{
		ID:          999,
		Name:        "Non-existent VLAN",
		Description: "",
		Enabled:     true,
	}

	err = vlanManager.UpdateVlan(nonExistentVlan)
	assert.Error(t, err, "Expected error updating non-existent VLAN")
}

// TestIsVlanActive tests checking if a VLAN is active
func TestIsVlanActive(t *testing.T) {
	vlanManager := switcher.NewVlanManager()

	// Add enabled VLAN
	enabledVlan, _ := switcher.NewVlanConfig(100, "Enabled VLAN")
	enabledVlan.Enabled = true
	vlanManager.AddVlan(enabledVlan)

	// Add disabled VLAN
	disabledVlan, _ := switcher.NewVlanConfig(200, "Disabled VLAN")
	disabledVlan.Enabled = false
	vlanManager.AddVlan(disabledVlan)

	// Check VLAN active status
	assert.True(t, vlanManager.IsVlanActive(100), "Expected VLAN 100 to be active")
	assert.False(t, vlanManager.IsVlanActive(200), "Expected VLAN 200 to be inactive")
	assert.False(t, vlanManager.IsVlanActive(300), "Expected non-existent VLAN to be inactive")
}

// TestPortVlanConfig tests port VLAN configuration
func TestPortVlanConfig(t *testing.T) {
	// Create port
	port := switcher.NewPort("port1", "Test Port")

	// Check default VLAN configuration
	assert.Equal(t, switcher.VlanModeAccess, port.VlanMode, "Expected default VLAN mode to be Access")
	assert.Equal(t, uint16(1), port.AccessVlanID, "Expected default Access VLAN to be 1")
	assert.Equal(t, uint16(1), port.NativeVlanID, "Expected default Native VLAN to be 1")
	assert.NotNil(t, port.AllowedVlans, "Expected AllowedVlans map to be initialized")

	// Change VLAN mode to Trunk
	port.VlanMode = switcher.VlanModeTrunk
	port.NativeVlanID = 10

	// Add allowed VLANs
	port.AllowedVlans[10] = true
	port.AllowedVlans[20] = true
	port.AllowedVlans[30] = true

	// Verify configuration
	assert.Equal(t, switcher.VlanModeTrunk, port.VlanMode, "Expected VLAN mode to be Trunk")
	assert.Equal(t, uint16(10), port.NativeVlanID, "Expected Native VLAN to be 10")
	assert.True(t, port.AllowedVlans[10], "Expected VLAN 10 to be allowed")
	assert.True(t, port.AllowedVlans[20], "Expected VLAN 20 to be allowed")
	assert.True(t, port.AllowedVlans[30], "Expected VLAN 30 to be allowed")
	assert.False(t, port.AllowedVlans[40], "Expected VLAN 40 to be not allowed")
}

// TestVxlanVniConversion tests conversion between VLAN ID and VNI
func TestVxlanVniConversion(t *testing.T) {
	// Test valid conversion
	vni := switcher.VlanIdToVni(100)
	assert.Equal(t, uint32(100), vni, "Expected VNI to match VLAN ID")

	vlanId, err := switcher.VniToVlanId(100)
	assert.NoError(t, err, "Expected no error converting VNI to VLAN ID")
	assert.Equal(t, uint16(100), vlanId, "Expected VLAN ID to match VNI")

	// Test invalid VNI conversion
	_, err = switcher.VniToVlanId(5000) // exceeds maximum VLAN ID
	assert.Error(t, err, "Expected error converting invalid VNI")
}

// TestVxlanEncapsulation tests VXLAN encapsulation (basic functionality)
func TestVxlanEncapsulation(t *testing.T) {
	encapsulator := switcher.NewVxlanEncapsulator()

	// Here we only test the existence of the encapsulator, as complete encapsulation requires real packet structures
	assert.NotNil(t, encapsulator, "Expected non-nil VXLAN encapsulator")
	assert.Equal(t, uint16(4789), encapsulator.UdpPort, "Expected default UDP port 4789")
}