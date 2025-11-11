// Package topology provides network topology management for Stella
package topology

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// IntegrationManager manages the integration of topology with other components
// such as transport, switcher, and provides compatibility with ZeroTier

type IntegrationManager struct {
	topology    *TopologyManager
	pathFinder  *PathFinder
	discoverer  *TopologyDiscoverer
	initialized bool
	rwm         sync.RWMutex
	config      *IntegrationConfig
}

// IntegrationConfig contains configuration for topology integration

type IntegrationConfig struct {
	NodeID        uuid.UUID // Unique identifier for the local node
	LocalAddress  string    // Local network address
	DiscoveryPort int       // Port for topology discovery
	TrustedPathID uint64    // Trusted path ID for ZeroTier compatibility
	MTU           int       // Maximum transmission unit
}

// NewIntegrationManager creates a new topology integration manager
func NewIntegrationManager(config *IntegrationConfig) *IntegrationManager {
	return &IntegrationManager{
		config: config,
	}
}

// Initialize initializes the topology integration components
func (im *IntegrationManager) Initialize() error {
	im.rwm.Lock()
	defer im.rwm.Unlock()

	if im.initialized {
		return fmt.Errorf("topology integration manager already initialized")
	}

	// Create topology manager
	im.topology = NewTopologyManager()
	if err := im.topology.Start(); err != nil {
		return fmt.Errorf("failed to start topology manager: %w", err)
	}

	// Create path finder
	im.pathFinder = NewPathFinder(im.topology)

	// Create and start topology discoverer
	im.discoverer = NewTopologyDiscoverer(
		im.topology,
		im.config.NodeID,
		im.config.LocalAddress,
		im.config.DiscoveryPort,
	)

	// Register the local node in the topology
	localNode := &Node{
		ID:           im.config.NodeID,
		Address:      im.config.LocalAddress,
		LastSeen:     time.Now(),
		Version:      "1.0",
		IsTrusted:    true,
		MTU:          im.config.MTU,
		TrustedPathID: im.config.TrustedPathID,
	}

	if err := im.topology.AddNode(localNode); err != nil {
		return fmt.Errorf("failed to add local node to topology: %w", err)
	}

	im.initialized = true
	return nil
}

// StartDiscovery starts the topology discovery process
func (im *IntegrationManager) StartDiscovery() error {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return fmt.Errorf("topology integration manager not initialized")
	}

	return im.discoverer.Start()
}

// StopDiscovery stops the topology discovery process
func (im *IntegrationManager) StopDiscovery() error {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return fmt.Errorf("topology integration manager not initialized")
	}

	return im.discoverer.Stop()
}

// Shutdown gracefully shuts down all topology components
func (im *IntegrationManager) Shutdown() error {
	im.rwm.Lock()
	defer im.rwm.Unlock()

	if !im.initialized {
		return fmt.Errorf("topology integration manager not initialized")
	}

	// Stop discovery first
	_ = im.discoverer.Stop()

	// Stop topology manager
	if err := im.topology.Stop(); err != nil {
		return fmt.Errorf("failed to stop topology manager: %w", err)
	}

	im.initialized = false
	return nil
}

// AddNodeFromTransport adds a node to the topology based on transport layer information
func (im *IntegrationManager) AddNodeFromTransport(nodeID uuid.UUID, address string, publicKey string) error {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return fmt.Errorf("topology integration manager not initialized")
	}

	node := &Node{
		ID:        nodeID,
		Address:   address,
		PublicKey: publicKey,
		LastSeen:  time.Now(),
		Version:   "1.0",
		IsTrusted: false, // Default to untrusted until verified
		MTU:       im.config.MTU,
	}

	return im.topology.AddNode(node)
}

// AddPathFromTransport adds a path to the topology based on transport layer information
func (im *IntegrationManager) AddPathFromTransport(sourceID, destID uuid.UUID, address string, latency int) error {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return fmt.Errorf("topology integration manager not initialized")
	}

	// Check if source node is trusted
	sourceNode, exists := im.topology.GetNode(sourceID)
	trusted := false
	if exists {
		trusted = sourceNode.IsTrusted
	}

	path := &Path{
		Source:      sourceID,
		Destination: destID,
		Address:     address,
		Active:      true,
		LastActive:  time.Now(),
		Latency:     latency,
		Trusted:     trusted,
	}

	return im.topology.AddPath(path)
}

// GetBestPath gets the best path between two nodes for packet routing
func (im *IntegrationManager) GetBestPath(sourceID, destID uuid.UUID) (*Path, error) {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return nil, fmt.Errorf("topology integration manager not initialized")
	}

	// Try to get an optimal path directly
	path, quality := im.pathFinder.FindOptimalPath(sourceID, destID)
	if path != nil && quality > 0 {
		return path, nil
	}

	// If no direct path, try to find a multi-hop path
	pathIDs, err := im.pathFinder.FindShortestPath(sourceID, destID)
	if err != nil || pathIDs == nil || len(pathIDs) < 2 {
		return nil, fmt.Errorf("no path found between nodes")
	}

	// Get the first hop path
	firstHopPath, exists := im.topology.GetPath(pathIDs[0], pathIDs[1])
	if !exists {
		return nil, fmt.Errorf("no direct path found for first hop")
	}

	return firstHopPath, nil
}

// GetAllNodes returns all nodes in the topology
func (im *IntegrationManager) GetAllNodes() []*Node {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return nil
	}

	return im.topology.GetAllNodes()
}

// GetNode gets a specific node by ID
func (im *IntegrationManager) GetNode(nodeID uuid.UUID) (*Node, bool) {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return nil, false
	}

	return im.topology.GetNode(nodeID)
}

// UpdateNodeLatency updates the latency for a node
func (im *IntegrationManager) UpdateNodeLatency(nodeID uuid.UUID, latency int) error {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return fmt.Errorf("topology integration manager not initialized")
	}

	node, exists := im.topology.GetNode(nodeID)
	if !exists {
		return fmt.Errorf("node not found")
	}

	node.Latency = latency
	node.LastSeen = time.Now()

	return im.topology.AddNode(node)
}

// MarkNodeAsTrusted marks a node as trusted (important for ZeroTier compatibility)
func (im *IntegrationManager) MarkNodeAsTrusted(nodeID uuid.UUID) error {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return fmt.Errorf("topology integration manager not initialized")
	}

	node, exists := im.topology.GetNode(nodeID)
	if !exists {
		return fmt.Errorf("node not found")
	}

	node.IsTrusted = true
	return im.topology.AddNode(node)
}

// GetTopologyManager returns the underlying topology manager
func (im *IntegrationManager) GetTopologyManager() *TopologyManager {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return nil
	}

	return im.topology
}

// GetPathFinder returns the underlying path finder
func (im *IntegrationManager) GetPathFinder() *PathFinder {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return nil
	}

	return im.pathFinder
}

// GetUpdateChannel returns the channel for topology updates
func (im *IntegrationManager) GetUpdateChannel() <-chan *TopologyUpdate {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return nil
	}

	return im.topology.GetUpdateChannel()
}

// DiscoverSpecificPeer attempts to discover a specific peer node
func (im *IntegrationManager) DiscoverSpecificPeer(address string) error {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return fmt.Errorf("topology integration manager not initialized")
	}

	return im.discoverer.DiscoverSpecificNode(address)
}

// ShareTopologyWithPeer shares topology information with a specific peer
func (im *IntegrationManager) ShareTopologyWithPeer(nodeID uuid.UUID) error {
	im.rwm.RLock()
	defer im.rwm.RUnlock()

	if !im.initialized {
		return fmt.Errorf("topology integration manager not initialized")
	}

	return im.discoverer.ShareTopologyData(nodeID)
}

// ZeroTierCompatibilityHelper provides helper methods for ZeroTier compatibility
func (im *IntegrationManager) ZeroTierCompatibilityHelper() *ZeroTierCompatibilityHelper {
	return &ZeroTierCompatibilityHelper{
		integration: im,
	}
}

// ZeroTierCompatibilityHelper helps maintain compatibility with ZeroTier

type ZeroTierCompatibilityHelper struct {
	integration *IntegrationManager
}

// ConvertToZeroTierPath converts a Stella path to ZeroTier compatible format
func (zth *ZeroTierCompatibilityHelper) ConvertToZeroTierPath(path *Path) map[string]interface{} {
	return map[string]interface{}{
		"address":      path.Address,
		"active":       path.Active,
		"latency":      path.Latency,
		"trusted":      path.Trusted,
		"trustedPathId": zth.getTrustedPathID(path),
	}
}

// ConvertFromZeroTierPath converts ZeroTier path data to a Stella path
func (zth *ZeroTierCompatibilityHelper) ConvertFromZeroTierPath(sourceID, destID uuid.UUID, data map[string]interface{}) *Path {
	path := &Path{
		Source:      sourceID,
		Destination: destID,
		Active:      true,
		LastActive:  time.Now(),
		Trusted:     false,
	}

	if addr, ok := data["address"].(string); ok {
		path.Address = addr
	}

	if active, ok := data["active"].(bool); ok {
		path.Active = active
	}

	if latency, ok := data["latency"].(float64); ok {
		path.Latency = int(latency)
	}

	if trusted, ok := data["trusted"].(bool); ok {
		path.Trusted = trusted
	}

	return path
}

// getTrustedPathID gets the trusted path ID for ZeroTier compatibility
func (zth *ZeroTierCompatibilityHelper) getTrustedPathID(path *Path) uint64 {
	// Use the local trusted path ID if this is a trusted path
	if path.Trusted {
		return zth.integration.config.TrustedPathID
	}
	return 0
}

// GetZeroTierWorldConfig gets the default world configuration compatible with ZeroTier
func (zth *ZeroTierCompatibilityHelper) GetZeroTierWorldConfig() map[string]interface{} {
	// This would be populated with actual ZeroTier world configuration data
	// For now, we return a placeholder
	return map[string]interface{}{
		"identity":       zth.integration.config.NodeID.String(),
		"trustedPathId": zth.integration.config.TrustedPathID,
		"mtu":            zth.integration.config.MTU,
	}
}