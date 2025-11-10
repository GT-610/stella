package switcher

import (
	"testing"
	"time"

	"github.com/stella/virtual-switch/pkg/packet"
	"github.com/stella/virtual-switch/pkg/switcher"
)

// TestSwitcherCreation tests switch creation functionality
func TestSwitcherCreation(t *testing.T) {
	switcherObj, err := switcher.NewSwitcher("switch1", "Test Switch")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if switcherObj == nil {
		t.Fatal("Expected switcher to be created, got nil")
	}

	if switcherObj.ID != "switch1" {
		t.Errorf("Expected ID 'switch1', got '%s'", switcherObj.ID)
	}

	if switcherObj.GetState() != switcher.StateStopped {
		t.Errorf("Expected initial state StateStopped, got %v", switcherObj.GetState())
	}
}

// TestSwitcherStartStop tests switch start and stop functionality
func TestSwitcherStartStop(t *testing.T) {
	switcherObj, err := switcher.NewSwitcher("switch2", "Test Switch")
	if err != nil {
		t.Fatalf("Expected no error creating switcher, got %v", err)
	}

	// Test starting
	err = switcherObj.Start()
	if err != nil {
		t.Fatalf("Expected no error starting switcher, got %v", err)
	}

	if switcherObj.GetState() != switcher.StateRunning {
		t.Errorf("Expected state StateRunning after start, got %v", switcherObj.GetState())
	}

	if !switcherObj.IsRunning() {
		t.Error("Expected IsRunning() to return true after start")
	}

	// Test stopping
	err = switcherObj.Stop()
	if err != nil {
		t.Fatalf("Expected no error stopping switcher, got %v", err)
	}

	if switcherObj.GetState() != switcher.StateStopped {
		t.Errorf("Expected state StateStopped after stop, got %v", switcherObj.GetState())
	}
}

// TestPortManagement tests port management functionality
func TestPortManagement(t *testing.T) {
	switcherObj, err := switcher.NewSwitcher("switch3", "Test Switch")
	if err != nil {
		t.Fatalf("Expected no error creating switcher, got %v", err)
	}

	// Create ports
	port1 := switcher.NewPort("port1", "Test Port 1")
	port2 := switcher.NewPort("port2", "Test Port 2")

	// Add port
	err = switcherObj.AddPort(port1)
	if err != nil {
		t.Fatalf("Expected no error adding port1, got %v", err)
	}

	// Test adding duplicate port
	err = switcherObj.AddPort(port1)
	if err == nil {
		t.Fatal("Expected error adding duplicate port, got nil")
	}

	// Add second port
	err = switcherObj.AddPort(port2)
	if err != nil {
		t.Fatalf("Expected no error adding port2, got %v", err)
	}

	// Get port
	retrievedPort, err := switcherObj.GetPort("port1")
	if err != nil {
		t.Fatalf("Expected no error retrieving port1, got %v", err)
	}

	if retrievedPort.ID != "port1" {
		t.Errorf("Expected retrieved port ID 'port1', got '%s'", retrievedPort.ID)
	}

	// Test getting nonexistent port
	_, err = switcherObj.GetPort("nonexistent")
	if err == nil {
		t.Fatal("Expected error retrieving nonexistent port, got nil")
	}

	// Remove port
	err = switcherObj.RemovePort("port1")
	if err != nil {
		t.Fatalf("Expected no error removing port1, got %v", err)
	}

	// Test removing nonexistent port
	err = switcherObj.RemovePort("nonexistent")
	if err == nil {
		t.Fatal("Expected error removing nonexistent port, got nil")
	}
}

// TestPacketHandling tests packet processing functionality - simplified version
func TestPacketHandlingBasic(t *testing.T) {
	switcherObj, err := switcher.NewSwitcher("switch4", "Test Switch")
	if err != nil {
		t.Fatalf("Expected no error creating switcher, got %v", err)
	}

	// Start switch
	err = switcherObj.Start()
	if err != nil {
		t.Fatalf("Expected no error starting switcher, got %v", err)
	}
	defer switcherObj.Stop() // Ensure switch is stopped at test completion

	// Create and add port
	port := switcher.NewPort("port1", "Test Port 1")
	err = switcherObj.AddPort(port)
	if err != nil {
		t.Fatalf("Expected no error adding port, got %v", err)
	}

	// Test processing packet for nonexistent port
	mockPacket := &packet.Packet{}
	err = switcherObj.HandlePacket("nonexistent", mockPacket)
	if err == nil {
		t.Fatal("Expected error handling packet for nonexistent port, got nil")
	}

	// Test after stopping switch
	switcherObj.Stop()
	err = switcherObj.HandlePacket("port1", mockPacket)
	if err == nil {
		t.Fatal("Expected error handling packet when switcher is stopped, got nil")
	}
}

// TestMACTableLearning tests MAC address table learning functionality
func TestMACTableLearning(t *testing.T) {
	// Create MAC table
	macTable := switcher.NewMACTable(100, 300*time.Second)

	// Test learning MAC address
	result := macTable.LearnMAC("00:11:22:33:44:55", "port1")
	if !result {
		t.Error("Expected MAC learning to succeed")
	}

	// Test learning the same MAC address again
	result = macTable.LearnMAC("00:11:22:33:44:55", "port1")
	if !result {
		t.Error("Expected updating existing MAC entry to succeed")
	}
}

// TestMACTableCapacityHandling tests MAC address table capacity handling
func TestMACTableCapacityHandling(t *testing.T) {
	// Create a MAC table with capacity of 3
	macTable := switcher.NewMACTable(3, 300*time.Second)

	// Add 3 MAC addresses to fill the table
	result1 := macTable.LearnMAC("00:00:00:00:00:01", "port1")
	result2 := macTable.LearnMAC("00:00:00:00:00:02", "port2")
	result3 := macTable.LearnMAC("00:00:00:00:00:03", "port3")
	
	if !result1 || !result2 || !result3 {
		t.Error("Expected all initial MAC learning to succeed")
	}

	// Add 4th MAC address, should replace the oldest entry
	result4 := macTable.LearnMAC("00:00:00:00:00:04", "port4")
	if !result4 {
		t.Error("Expected MAC learning to succeed when replacing oldest entry")
	}

	// Add 5th MAC address, should continue to replace oldest entry
	result5 := macTable.LearnMAC("00:00:00:00:00:05", "port5")
	if !result5 {
		t.Error("Expected MAC learning to succeed for second replacement")
	}
}
