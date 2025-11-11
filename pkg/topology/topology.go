// Package topology provides network topology management for Stella
package topology

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Node represents a peer node in the network topology
type Node struct {
	ID           uuid.UUID // Unique identifier for the node
	Address      string    // Network address (IP:port)
	PublicKey    string    // Public key for authentication
	LastSeen     time.Time // Last time the node was seen
	Version      string    // Protocol version
	Latency      int       // Current latency in milliseconds
	IsTrusted    bool      // Whether the node is trusted
	MTU          int       // Maximum transmission unit
	TrustedPathID uint64    // Trusted path identifier for compatibility with ZeroTier
}

// Path represents a communication path between nodes
type Path struct {
	Source      uuid.UUID // Source node ID
	Destination uuid.UUID // Destination node ID
	Address     string    // Endpoint address (IP:port)
	Active      bool      // Whether the path is active
	LastActive  time.Time // Last time the path was active
	Latency     int       // Path latency
	Trusted     bool      // Whether this is a trusted path
}

// TopologyManager manages the network topology including nodes and paths
type TopologyManager struct {
	nodes     map[uuid.UUID]*Node     // Map of nodes by ID
	paths     map[string]*Path        // Map of paths by key (source-dest-address)
	rwm       sync.RWMutex            // Read-write lock for concurrent access
	ctx       context.Context         // Context for managing lifecycle
	cancel    context.CancelFunc      // Cancel function for context
	updateCh  chan *TopologyUpdate    // Channel for topology updates
	metricsCh chan *TopologyMetrics   // Channel for metrics
}

// TopologyUpdate represents an update to the network topology
type TopologyUpdate struct {
	Type      string    // Type of update: "node", "path", "topology"
	Node      *Node     // Updated node, if any
	Path      *Path     // Updated path, if any
	Timestamp time.Time // Time of update
}

// TopologyMetrics represents metrics about the network topology
type TopologyMetrics struct {
	TotalNodes    int       // Total number of nodes
	TotalPaths    int       // Total number of paths
	ActiveNodes   int       // Number of active nodes
	ActivePaths   int       // Number of active paths
	AvgLatency    float64   // Average network latency
	Timestamp     time.Time // Time of metrics collection
}

// NewTopologyManager creates a new topology manager instance
func NewTopologyManager() *TopologyManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &TopologyManager{
		nodes:     make(map[uuid.UUID]*Node),
		paths:     make(map[string]*Path),
		ctx:       ctx,
		cancel:    cancel,
		updateCh:  make(chan *TopologyUpdate, 100),
		metricsCh: make(chan *TopologyMetrics, 10),
	}
}

// Start begins the topology manager operations
func (tm *TopologyManager) Start() error {
	// Start maintenance goroutines
	go tm.maintenanceLoop()
	go tm.metricsLoop()
	return nil
}

// Stop gracefully stops the topology manager
func (tm *TopologyManager) Stop() error {
	tm.cancel()
	close(tm.updateCh)
	close(tm.metricsCh)
	return nil
}

// AddNode adds or updates a node in the topology
func (tm *TopologyManager) AddNode(node *Node) error {
	tm.rwm.Lock()
	defer tm.rwm.Unlock()

	// Update last seen time
	node.LastSeen = time.Now()
	
	// Store the node
	tm.nodes[node.ID] = node
	
	// Send update notification
	tm.updateCh <- &TopologyUpdate{
		Type:      "node",
		Node:      node,
		Timestamp: time.Now(),
	}
	
	return nil
}

// GetNode retrieves a node by ID
func (tm *TopologyManager) GetNode(nodeID uuid.UUID) (*Node, bool) {
	tm.rwm.RLock()
	defer tm.rwm.RUnlock()
	
	node, exists := tm.nodes[nodeID]
	return node, exists
}

// RemoveNode removes a node from the topology
func (tm *TopologyManager) RemoveNode(nodeID uuid.UUID) error {
	tm.rwm.Lock()
	defer tm.rwm.Unlock()
	
	// Remove all paths involving this node
	for key, path := range tm.paths {
		if path.Source == nodeID || path.Destination == nodeID {
			delete(tm.paths, key)
		}
	}
	
	// Remove the node
	delete(tm.nodes, nodeID)
	
	// Send update notification
	tm.updateCh <- &TopologyUpdate{
		Type:      "node",
		Timestamp: time.Now(),
	}
	
	return nil
}

// AddPath adds or updates a path in the topology
func (tm *TopologyManager) AddPath(path *Path) error {
	tm.rwm.Lock()
	defer tm.rwm.Unlock()
	
	// Update path state
	path.LastActive = time.Now()
	
	// Create path key
	key := tm.createPathKey(path.Source, path.Destination, path.Address)
	
	// Store the path
	tm.paths[key] = path
	
	// Send update notification
	tm.updateCh <- &TopologyUpdate{
		Type:      "path",
		Path:      path,
		Timestamp: time.Now(),
	}
	
	return nil
}

// GetPath retrieves a path between two nodes
func (tm *TopologyManager) GetPath(source, dest uuid.UUID) (*Path, bool) {
	tm.rwm.RLock()
	defer tm.rwm.RUnlock()
	
	// Find the best active path between source and destination
	for _, path := range tm.paths {
		if path.Source == source && path.Destination == dest && path.Active {
			return path, true
		}
	}
	
	return nil, false
}

// GetAllNodes returns all nodes in the topology
func (tm *TopologyManager) GetAllNodes() []*Node {
	tm.rwm.RLock()
	defer tm.rwm.RUnlock()
	
	nodes := make([]*Node, 0, len(tm.nodes))
	for _, node := range tm.nodes {
		nodes = append(nodes, node)
	}
	
	return nodes
}

// GetAllPaths returns all paths in the topology
func (tm *TopologyManager) GetAllPaths() []*Path {
	tm.rwm.RLock()
	defer tm.rwm.RUnlock()
	
	paths := make([]*Path, 0, len(tm.paths))
	for _, path := range tm.paths {
		paths = append(paths, path)
	}
	
	return paths
}

// GetUpdateChannel returns the channel for receiving topology updates
func (tm *TopologyManager) GetUpdateChannel() <-chan *TopologyUpdate {
	return tm.updateCh
}

// GetMetricsChannel returns the channel for receiving topology metrics
func (tm *TopologyManager) GetMetricsChannel() <-chan *TopologyMetrics {
	return tm.metricsCh
}

// createPathKey creates a unique key for a path
func (tm *TopologyManager) createPathKey(source, dest uuid.UUID, address string) string {
	return source.String() + "-" + dest.String() + "-" + address
}

// maintenanceLoop periodically performs topology maintenance tasks
func (tm *TopologyManager) maintenanceLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-tm.ctx.Done():
			return
		case <-ticker.C:
			tm.cleanupStaleNodes()
			tm.cleanupStalePaths()
		}
	}
}

// metricsLoop periodically collects and publishes topology metrics
func (tm *TopologyManager) metricsLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-tm.ctx.Done():
			return
		case <-ticker.C:
			metrics := tm.collectMetrics()
			select {
			case tm.metricsCh <- metrics:
			default:
				// Channel full, drop metrics
			}
		}
	}
}

// cleanupStaleNodes removes nodes that haven't been seen for a long time
func (tm *TopologyManager) cleanupStaleNodes() {
	tm.rwm.Lock()
	defer tm.rwm.Unlock()
	
	staleTime := time.Now().Add(-5 * time.Minute)
	for id, node := range tm.nodes {
		if node.LastSeen.Before(staleTime) && !node.IsTrusted {
			delete(tm.nodes, id)
		}
	}
}

// cleanupStalePaths removes paths that haven't been active for a long time
func (tm *TopologyManager) cleanupStalePaths() {
	tm.rwm.Lock()
	defer tm.rwm.Unlock()
	
	staleTime := time.Now().Add(-5 * time.Minute)
	for key, path := range tm.paths {
		if path.LastActive.Before(staleTime) && !path.Trusted {
			delete(tm.paths, key)
		}
	}
}

// collectMetrics gathers statistics about the current topology
func (tm *TopologyManager) collectMetrics() *TopologyMetrics {
	tm.rwm.RLock()
	defer tm.rwm.RUnlock()
	
	activeNodes := 0
	activePaths := 0
	totalLatency := 0
	latencyCount := 0
	
	// Count active nodes
	activeThreshold := time.Now().Add(-2 * time.Minute)
	for _, node := range tm.nodes {
		if node.LastSeen.After(activeThreshold) {
			activeNodes++
			if node.Latency > 0 {
				totalLatency += node.Latency
				latencyCount++
			}
		}
	}
	
	// Count active paths
	for _, path := range tm.paths {
		if path.Active {
			activePaths++
			if path.Latency > 0 {
				totalLatency += path.Latency
				latencyCount++
			}
		}
	}
	
	// Calculate average latency
	avgLatency := 0.0
	if latencyCount > 0 {
		avgLatency = float64(totalLatency) / float64(latencyCount)
	}
	
	return &TopologyMetrics{
		TotalNodes:  len(tm.nodes),
		TotalPaths:  len(tm.paths),
		ActiveNodes: activeNodes,
		ActivePaths: activePaths,
		AvgLatency:  avgLatency,
		Timestamp:   time.Now(),
	}
}