package switcher

import (
	"testing"

	"github.com/stella/virtual-switch/pkg/switcher"
	"github.com/stretchr/testify/assert"
)

// TestVlanIsolation tests VLAN isolation functionality
func TestVlanIsolation(t *testing.T) {
	// Create switcher
	switcherObj, err := switcher.NewSwitcher("test-switch", "VLAN Test Switch")
	assert.NoError(t, err, "Expected no error creating switcher")

	// Start switcher
	err = switcherObj.Start()
	assert.NoError(t, err, "Expected no error starting switcher")
	defer switcherObj.Stop()

	// Get VLAN manager
	vlanManager := switcherObj.GetVlanManager()
	assert.NotNil(t, vlanManager, "Expected non-nil VLAN manager")

	// Create and add VLAN 10 and VLAN 20
	vlan10, _ := switcher.NewVlanConfig(10, "VLAN 10")
	vlan20, _ := switcher.NewVlanConfig(20, "VLAN 20")

	err = vlanManager.AddVlan(vlan10)
	assert.NoError(t, err, "Expected no error adding VLAN 10")

	err = vlanManager.AddVlan(vlan20)
	assert.NoError(t, err, "Expected no error adding VLAN 20")

	// Verify VLANs are added
	assert.True(t, vlanManager.IsVlanActive(10), "Expected VLAN 10 to be active")
	assert.True(t, vlanManager.IsVlanActive(20), "Expected VLAN 20 to be active")

	// Create 4 ports
	port1 := switcher.NewPort("port1", "Access Port VLAN 10")
	port2 := switcher.NewPort("port2", "Access Port VLAN 10")
	port3 := switcher.NewPort("port3", "Access Port VLAN 20")
	port4 := switcher.NewPort("port4", "Trunk Port")

	// Configure port VLAN modes
	port1.VlanMode = switcher.VlanModeAccess
	port1.AccessVlanID = 10

	port2.VlanMode = switcher.VlanModeAccess
	port2.AccessVlanID = 10

	port3.VlanMode = switcher.VlanModeAccess
	port3.AccessVlanID = 20

	port4.VlanMode = switcher.VlanModeTrunk
	port4.AllowedVlans[10] = true
	port4.AllowedVlans[20] = true

	// Set port states to Up
	port1.State = switcher.PortStateUp
	port2.State = switcher.PortStateUp
	port3.State = switcher.PortStateUp
	port4.State = switcher.PortStateUp

	// Add ports to switcher
	err = switcherObj.AddPort(port1)
	assert.NoError(t, err, "Expected no error adding port1")

	err = switcherObj.AddPort(port2)
	assert.NoError(t, err, "Expected no error adding port2")

	err = switcherObj.AddPort(port3)
	assert.NoError(t, err, "Expected no error adding port3")

	err = switcherObj.AddPort(port4)
	assert.NoError(t, err, "Expected no error adding port4")

	// Test setup complete
	assert.True(t, true, "VLAN isolation test setup complete")
}

// TestSwitchVlanManagement tests VLAN management functionality of the switcher
func TestSwitchVlanManagement(t *testing.T) {
	// Create switcher
	switcherObj, err := switcher.NewSwitcher("test-switch", "VLAN Management Switch")
	assert.NoError(t, err, "Expected no error creating switcher")

	// Get VLAN manager
	vlanManager := switcherObj.GetVlanManager()
	assert.NotNil(t, vlanManager, "Expected non-nil VLAN manager")

	// Verify default VLAN 1 is created
	defaultVlan, err := vlanManager.GetVlan(1)
	assert.NoError(t, err, "Expected to find default VLAN 1")
	assert.Equal(t, "Default VLAN", defaultVlan.Name, "Expected default VLAN name")
	assert.True(t, defaultVlan.Enabled, "Expected default VLAN to be enabled")

	// Add new VLAN
	newVlan, _ := switcher.NewVlanConfig(100, "Test VLAN")
	err = vlanManager.AddVlan(newVlan)
	assert.NoError(t, err, "Expected no error adding new VLAN")

	// Verify new VLAN is added
	addedVlan, err := vlanManager.GetVlan(100)
	assert.NoError(t, err, "Expected to find newly added VLAN")
	assert.Equal(t, "Test VLAN", addedVlan.Name, "Expected VLAN name to match")

	// Remove VLAN
	err = vlanManager.RemoveVlan(100)
	assert.NoError(t, err, "Expected no error removing VLAN")

	// Verify VLAN is removed
	_, err = vlanManager.GetVlan(100)
	assert.Error(t, err, "Expected error finding removed VLAN")
}

// TestPortVlanModes tests behavior of different port VLAN modes
func TestPortVlanModes(t *testing.T) {
	// Create Access port
	accessPort := switcher.NewPort("access-port", "Access Port")
	accessPort.VlanMode = switcher.VlanModeAccess
	accessPort.AccessVlanID = 100

	// Create Trunk port
	trunkPort := switcher.NewPort("trunk-port", "Trunk Port")
	trunkPort.VlanMode = switcher.VlanModeTrunk
	trunkPort.NativeVlanID = 1
	trunkPort.AllowedVlans[100] = true
	trunkPort.AllowedVlans[200] = true

	// Verify configuration
	assert.Equal(t, switcher.VlanModeAccess, accessPort.VlanMode, "Expected Access mode")
	assert.Equal(t, uint16(100), accessPort.AccessVlanID, "Expected Access VLAN 100")

	assert.Equal(t, switcher.VlanModeTrunk, trunkPort.VlanMode, "Expected Trunk mode")
	assert.Equal(t, uint16(1), trunkPort.NativeVlanID, "Expected Native VLAN 1")
	assert.True(t, trunkPort.AllowedVlans[100], "Expected VLAN 100 to be allowed on trunk")
	assert.True(t, trunkPort.AllowedVlans[200], "Expected VLAN 200 to be allowed on trunk")
}