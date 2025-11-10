package switcher

import (
	"sync"
	"time"
)

// MACEntry represents a MAC table entry
type MACEntry struct {
	MAC      interface{} // Simplified handling, should be *address.MAC in reality
	PortID   string
	LastSeen time.Time
	Static   bool // Whether it's a static entry (won't age)
}

// MACTable represents a MAC address table
type MACTable struct {
	entries      map[string]*MACEntry // Keyed by MAC address string
	maxSize      int                  // Maximum number of entries
	agingTimeout time.Duration        // Aging timeout duration
	mutex        sync.RWMutex
}

// NewMACTable creates a new MAC address table
func NewMACTable(maxSize int, agingTimeout time.Duration) *MACTable {
	if maxSize <= 0 {
		maxSize = 1024 // Default maximum number of entries
	}
	if agingTimeout <= 0 {
		agingTimeout = 300 * time.Second // Default aging time 5 minutes
	}

	return &MACTable{
		entries:      make(map[string]*MACEntry),
		maxSize:      maxSize,
		agingTimeout: agingTimeout,
	}
}

// findOldestDynamicEntry finds the oldest non-static MAC table entry
func (m *MACTable) findOldestDynamicEntry() string {
	var oldestMAC string
	var oldestTime time.Time
	first := true

	for mac, entry := range m.entries {
		// Skip static entries
		if entry.Static {
			continue
		}

		// Initialize or update the oldest entry
		if first || entry.LastSeen.Before(oldestTime) {
			oldestMAC = mac
			oldestTime = entry.LastSeen
			first = false
		}
	}

	return oldestMAC
}

// LearnMAC learns a MAC address (with capacity limit handling)
func (m *MACTable) LearnMAC(mac interface{}, portID string) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Simplified handling, assuming MAC can be converted to string
	macStr := "mac-placeholder"

	// Check if the MAC address already exists
	entry, exists := m.entries[macStr]
	if exists {
		// Update last seen time
		entry.LastSeen = time.Now()
		return true
	}

	// Check if MAC table is full
	if len(m.entries) >= m.maxSize {
		// Try to find the oldest non-static entry for replacement
		oldestMAC := m.findOldestDynamicEntry()
		if oldestMAC == "" {
			// If all entries are static, cannot add new entry
			return false
		}
		// Delete the oldest non-static entry
		delete(m.entries, oldestMAC)
	}

	// Add new MAC table entry
	m.entries[macStr] = &MACEntry{
		MAC:      mac,
		PortID:   portID,
		LastSeen: time.Now(),
		Static:   false,
	}

	return true
}

// StartAgingManager starts the MAC address aging manager
func (m *MACTable) StartAgingManager(stopChan <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Simplified handling, actual aging logic not implemented
			case <-stopChan:
				return
			}
		}
	}()
}