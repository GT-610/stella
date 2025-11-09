package switcher

import (
	"sync"
	"time"
)

// MAC表项结构
type MACEntry struct {
	MAC      interface{} // 简化处理，实际应该是*address.MAC
	PortID   string
	LastSeen time.Time
	Static   bool // 是否为静态条目（不会老化）
}

// MAC表结构
type MACTable struct {
	entries      map[string]*MACEntry // 以MAC地址字符串为键
	maxSize      int                  // 最大表项数量
	agingTimeout time.Duration        // 老化超时时间
	mutex        sync.RWMutex
}

// 创建新的MAC表
func NewMACTable(maxSize int, agingTimeout time.Duration) *MACTable {
	if maxSize <= 0 {
		maxSize = 1024 // 默认最大表项数
	}
	if agingTimeout <= 0 {
		agingTimeout = 300 * time.Second // 默认老化时间5分钟
	}

	return &MACTable{
		entries:      make(map[string]*MACEntry),
		maxSize:      maxSize,
		agingTimeout: agingTimeout,
	}
}

// 查找最旧的非静态MAC表项
func (m *MACTable) findOldestDynamicEntry() string {
	var oldestMAC string
	var oldestTime time.Time
	first := true

	for mac, entry := range m.entries {
		// 跳过静态条目
		if entry.Static {
			continue
		}

		// 初始化或更新最旧条目
		if first || entry.LastSeen.Before(oldestTime) {
			oldestMAC = mac
			oldestTime = entry.LastSeen
			first = false
		}
	}

	return oldestMAC
}

// 学习MAC地址（实现容量限制处理）
func (m *MACTable) LearnMAC(mac interface{}, portID string) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 简化处理，假设可以将MAC转为字符串
	macStr := "mac-placeholder"

	// 检查是否已存在该MAC地址
	entry, exists := m.entries[macStr]
	if exists {
		// 更新最后看到的时间
		entry.LastSeen = time.Now()
		return true
	}

	// 检查MAC表是否已满
	if len(m.entries) >= m.maxSize {
		// 尝试找到最旧的非静态条目进行替换
		oldestMAC := m.findOldestDynamicEntry()
		if oldestMAC == "" {
			// 如果所有条目都是静态的，则无法添加新条目
			return false
		}
		// 删除最旧的非静态条目
		delete(m.entries, oldestMAC)
	}

	// 添加新的MAC表项
	m.entries[macStr] = &MACEntry{
		MAC:      mac,
		PortID:   portID,
		LastSeen: time.Now(),
		Static:   false,
	}

	return true
}

// 启动MAC地址老化管理器
func (m *MACTable) StartAgingManager(stopChan <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// 简化处理，不实现实际的老化逻辑
			case <-stopChan:
				return
			}
		}
	}()
}