package switcher

import (
	"testing"
	"time"

	"github.com/stella/virtual-switch/pkg/packet"
	"github.com/stella/virtual-switch/pkg/switcher"
)

// TestSwitcherCreation 测试交换机创建功能
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

// TestSwitcherStartStop 测试交换机启动和停止功能
func TestSwitcherStartStop(t *testing.T) {
	switcherObj, err := switcher.NewSwitcher("switch2", "Test Switch")
	if err != nil {
		t.Fatalf("Expected no error creating switcher, got %v", err)
	}

	// 测试启动
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

	// 测试停止
	err = switcherObj.Stop()
	if err != nil {
		t.Fatalf("Expected no error stopping switcher, got %v", err)
	}

	if switcherObj.GetState() != switcher.StateStopped {
		t.Errorf("Expected state StateStopped after stop, got %v", switcherObj.GetState())
	}
}

// TestPortManagement 测试端口管理功能
func TestPortManagement(t *testing.T) {
	switcherObj, err := switcher.NewSwitcher("switch3", "Test Switch")
	if err != nil {
		t.Fatalf("Expected no error creating switcher, got %v", err)
	}

	// 创建端口
	port1 := switcher.NewPort("port1", "Test Port 1")
	port2 := switcher.NewPort("port2", "Test Port 2")

	// 添加端口
	err = switcherObj.AddPort(port1)
	if err != nil {
		t.Fatalf("Expected no error adding port1, got %v", err)
	}

	// 测试添加重复端口
	err = switcherObj.AddPort(port1)
	if err == nil {
		t.Fatal("Expected error adding duplicate port, got nil")
	}

	// 添加第二个端口
	err = switcherObj.AddPort(port2)
	if err != nil {
		t.Fatalf("Expected no error adding port2, got %v", err)
	}

	// 获取端口
	retrievedPort, err := switcherObj.GetPort("port1")
	if err != nil {
		t.Fatalf("Expected no error retrieving port1, got %v", err)
	}

	if retrievedPort.ID != "port1" {
		t.Errorf("Expected retrieved port ID 'port1', got '%s'", retrievedPort.ID)
	}

	// 测试获取不存在的端口
	_, err = switcherObj.GetPort("nonexistent")
	if err == nil {
		t.Fatal("Expected error retrieving nonexistent port, got nil")
	}

	// 移除端口
	err = switcherObj.RemovePort("port1")
	if err != nil {
		t.Fatalf("Expected no error removing port1, got %v", err)
	}

	// 测试移除不存在的端口
	err = switcherObj.RemovePort("nonexistent")
	if err == nil {
		t.Fatal("Expected error removing nonexistent port, got nil")
	}
}

// TestPacketHandling 测试数据包处理功能 - 简化版本
func TestPacketHandlingBasic(t *testing.T) {
	switcherObj, err := switcher.NewSwitcher("switch4", "Test Switch")
	if err != nil {
		t.Fatalf("Expected no error creating switcher, got %v", err)
	}

	// 启动交换机
	err = switcherObj.Start()
	if err != nil {
		t.Fatalf("Expected no error starting switcher, got %v", err)
	}
	defer switcherObj.Stop() // 确保测试结束时停止交换机

	// 创建端口并添加
	port := switcher.NewPort("port1", "Test Port 1")
	err = switcherObj.AddPort(port)
	if err != nil {
		t.Fatalf("Expected no error adding port, got %v", err)
	}

	// 测试处理不存在的端口
	mockPacket := &packet.Packet{}
	err = switcherObj.HandlePacket("nonexistent", mockPacket)
	if err == nil {
		t.Fatal("Expected error handling packet for nonexistent port, got nil")
	}

	// 停止交换机后测试
	switcherObj.Stop()
	err = switcherObj.HandlePacket("port1", mockPacket)
	if err == nil {
		t.Fatal("Expected error handling packet when switcher is stopped, got nil")
	}
}

// TestMACTableLearning 测试MAC地址表学习功能
func TestMACTableLearning(t *testing.T) {
	// 创建MAC表
	macTable := switcher.NewMACTable(100, 300*time.Second)

	// 测试学习MAC地址
	result := macTable.LearnMAC("00:11:22:33:44:55", "port1")
	if !result {
		t.Error("Expected MAC learning to succeed")
	}

	// 测试再次学习同一个MAC地址
	result = macTable.LearnMAC("00:11:22:33:44:55", "port1")
	if !result {
		t.Error("Expected updating existing MAC entry to succeed")
	}
}

// TestMACTableCapacityHandling 测试MAC地址表容量限制处理
func TestMACTableCapacityHandling(t *testing.T) {
	// 创建一个容量为3的MAC表
	macTable := switcher.NewMACTable(3, 300*time.Second)

	// 添加3个MAC地址，填满表
	result1 := macTable.LearnMAC("00:00:00:00:00:01", "port1")
	result2 := macTable.LearnMAC("00:00:00:00:00:02", "port2")
	result3 := macTable.LearnMAC("00:00:00:00:00:03", "port3")
	
	if !result1 || !result2 || !result3 {
		t.Error("Expected all initial MAC learning to succeed")
	}

	// 添加第4个MAC地址，应该替换最旧的条目
	result4 := macTable.LearnMAC("00:00:00:00:00:04", "port4")
	if !result4 {
		t.Error("Expected MAC learning to succeed when replacing oldest entry")
	}

	// 添加第5个MAC地址，应该继续替换最旧的条目
	result5 := macTable.LearnMAC("00:00:00:00:00:05", "port5")
	if !result5 {
		t.Error("Expected MAC learning to succeed for second replacement")
	}
}
