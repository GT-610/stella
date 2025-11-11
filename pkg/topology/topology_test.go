package topology

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestTopologyManager_AddAndGetNode(t *testing.T) {
	// Create a new topology manager
	tm := NewTopologyManager()
	defer tm.Stop()

	// Create a test node
	nodeID := uuid.New()
	node := &Node{
		ID:        nodeID,
		Address:   "192.168.1.10",
		PublicKey: "test-public-key",
		Version:   "1.0",
		IsTrusted: true,
		MTU:       1500,
	}

	// Add the node
	err := tm.AddNode(node)
	assert.NoError(t, err)

	// Get the node and verify it was added correctly
	retrievedNode, exists := tm.GetNode(nodeID)
	assert.True(t, exists)
	assert.NotNil(t, retrievedNode)
	assert.Equal(t, nodeID, retrievedNode.ID)
	assert.Equal(t, "192.168.1.10", retrievedNode.Address)
}

func TestTopologyManager_RemoveNode(t *testing.T) {
	// Create a new topology manager
	tm := NewTopologyManager()
	defer tm.Stop()

	// Create and add a test node
	nodeID := uuid.New()
	node := &Node{
		ID:        nodeID,
		Address:   "192.168.1.10",
		PublicKey: "test-public-key",
	}
	assert.NoError(t, tm.AddNode(node))

	// Verify node exists
	_, exists := tm.GetNode(nodeID)
	assert.True(t, exists)

	// Remove the node
	assert.NoError(t, tm.RemoveNode(nodeID))

	// Verify node no longer exists
	_, exists = tm.GetNode(nodeID)
	assert.False(t, exists)
}

func TestTopologyManager_AddAndGetPath(t *testing.T) {
	// Create a new topology manager
	tm := NewTopologyManager()
	defer tm.Stop()

	// Create source and destination nodes
	sourceID := uuid.New()
	destID := uuid.New()

	sourceNode := &Node{
		ID:      sourceID,
		Address: "192.168.1.10",
	}

	destNode := &Node{
		ID:      destID,
		Address: "192.168.1.11",
	}

	// Add nodes
	assert.NoError(t, tm.AddNode(sourceNode))
	assert.NoError(t, tm.AddNode(destNode))

	// Create and add a path
	path := &Path{
		Source:      sourceID,
		Destination: destID,
		Address:     "192.168.1.11:9993",
		Active:      true,
		Trusted:     false,
	}

	assert.NoError(t, tm.AddPath(path))

	// Get the path and verify it was added correctly
	retrievedPath, exists := tm.GetPath(sourceID, destID)
	assert.True(t, exists)
	assert.NotNil(t, retrievedPath)
	assert.Equal(t, sourceID, retrievedPath.Source)
	assert.Equal(t, destID, retrievedPath.Destination)
	assert.Equal(t, "192.168.1.11:9993", retrievedPath.Address)
}

func TestTopologyManager_RemoveNodeRemovesPaths(t *testing.T) {
	// Create a new topology manager
	tm := NewTopologyManager()
	defer tm.Stop()

	// Create nodes
	node1ID := uuid.New()
	node2ID := uuid.New()

	node1 := &Node{ID: node1ID, Address: "192.168.1.10"}
	node2 := &Node{ID: node2ID, Address: "192.168.1.11"}

	// Add nodes
	assert.NoError(t, tm.AddNode(node1))
	assert.NoError(t, tm.AddNode(node2))

	// Create and add a path between them
	path := &Path{
		Source:      node1ID,
		Destination: node2ID,
		Address:     "192.168.1.11:9993",
		Active:      true,
	}

	assert.NoError(t, tm.AddPath(path))

	// Verify path exists
	_, exists := tm.GetPath(node1ID, node2ID)
	assert.True(t, exists)

	// Remove one of the nodes
	assert.NoError(t, tm.RemoveNode(node1ID))

	// Verify path no longer exists
	_, exists = tm.GetPath(node1ID, node2ID)
	assert.False(t, exists)
}

func TestPathFinder_FindShortestPath(t *testing.T) {
	// Create a new topology manager
	tm := NewTopologyManager()
	defer tm.Stop()

	// Create a path finder
	pf := NewPathFinder(tm)

	// Create nodes in a chain: A -> B -> C
	nodeA := &Node{ID: uuid.New(), Address: "192.168.1.10"}
	nodeB := &Node{ID: uuid.New(), Address: "192.168.1.11"}
	nodeC := &Node{ID: uuid.New(), Address: "192.168.1.12"}

	// Add nodes
	assert.NoError(t, tm.AddNode(nodeA))
	assert.NoError(t, tm.AddNode(nodeB))
	assert.NoError(t, tm.AddNode(nodeC))

	// Create paths with different latencies
	pathAB := &Path{
		Source:      nodeA.ID,
		Destination: nodeB.ID,
		Address:     "192.168.1.11:9993",
		Active:      true,
		Latency:     10,
	}

	pathBC := &Path{
		Source:      nodeB.ID,
		Destination: nodeC.ID,
		Address:     "192.168.1.12:9993",
		Active:      true,
		Latency:     20,
	}

	// Add paths
	assert.NoError(t, tm.AddPath(pathAB))
	assert.NoError(t, tm.AddPath(pathBC))

	// Find shortest path from A to C
	path, err := pf.FindShortestPath(nodeA.ID, nodeC.ID)
	assert.NoError(t, err)
	assert.NotNil(t, path)
	assert.Equal(t, 3, len(path)) // Should be A -> B -> C
	assert.Equal(t, nodeA.ID, path[0])
	assert.Equal(t, nodeB.ID, path[1])
	assert.Equal(t, nodeC.ID, path[2])
}

func TestPathFinder_FindAllPaths(t *testing.T) {
	// Create a new topology manager
	tm := NewTopologyManager()
	defer tm.Stop()

	// Create a path finder
	pf := NewPathFinder(tm)

	// Create nodes in a simple graph: A connected to B and C, B connected to C
	nodeA := &Node{ID: uuid.New(), Address: "192.168.1.10"}
	nodeB := &Node{ID: uuid.New(), Address: "192.168.1.11"}
	nodeC := &Node{ID: uuid.New(), Address: "192.168.1.12"}

	// Add nodes
	assert.NoError(t, tm.AddNode(nodeA))
	assert.NoError(t, tm.AddNode(nodeB))
	assert.NoError(t, tm.AddNode(nodeC))

	// Create paths
	pathAB := &Path{
		Source:      nodeA.ID,
		Destination: nodeB.ID,
		Address:     "192.168.1.11:9993",
		Active:      true,
	}

	pathAC := &Path{
		Source:      nodeA.ID,
		Destination: nodeC.ID,
		Address:     "192.168.1.12:9993",
		Active:      true,
	}

	pathBC := &Path{
		Source:      nodeB.ID,
		Destination: nodeC.ID,
		Address:     "192.168.1.12:9993",
		Active:      true,
	}

	// Add paths
	assert.NoError(t, tm.AddPath(pathAB))
	assert.NoError(t, tm.AddPath(pathAC))
	assert.NoError(t, tm.AddPath(pathBC))

	// Find all paths from A to C with max 3 hops
	allPaths := pf.FindAllPaths(nodeA.ID, nodeC.ID, 3)
	assert.NotNil(t, allPaths)
	// Should find at least 2 paths: A->C and A->B->C
	assert.GreaterOrEqual(t, len(allPaths), 2)
}

func TestPathFinder_GetPathQuality(t *testing.T) {
	// Create paths with different characteristics
	path1 := &Path{
		Active:  true,
		Latency: 10,
		Trusted: false,
	}

	path2 := &Path{
		Active:  true,
		Latency: 50,
		Trusted: true,
	}

	path3 := &Path{
		Active:  false,
		Latency: 5,
		Trusted: true,
	}

	// Create path finder
	pf := NewPathFinder(NewTopologyManager())

	// Test path quality
	quality1 := pf.GetPathQuality(path1)
	quality2 := pf.GetPathQuality(path2)
	quality3 := pf.GetPathQuality(path3)

	// Check that lower latency paths have higher quality
	assert.Greater(t, quality1, quality2)
	// Check that inactive paths have 0 quality
	assert.Equal(t, 0.0, quality3)
}

// MockUDPConn is a mock for net.UDPConn for testing topology discoverer
type MockUDPConn struct {
	readBuffer  []byte
	writeBuffer []byte
	readChan    chan []byte
	writeChan   chan []byte
	addr        *net.UDPAddr
}

func NewMockUDPConn() *MockUDPConn {
	return &MockUDPConn{
		readChan:  make(chan []byte, 10),
		writeChan: make(chan []byte, 10),
	}
}

func (m *MockUDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	<-time.After(10 * time.Millisecond) // Simulate some delay
	if len(m.readChan) > 0 {
		data := <-m.readChan
		n = copy(b, data)
		addr = m.addr
	}
	return
}

func (m *MockUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	m.writeBuffer = append(m.writeBuffer, b...)
	m.writeChan <- b
	n = len(b)
	return
}

func (m *MockUDPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MockUDPConn) Close() error {
	return nil
}

func TestTopologyManager_CollectMetrics(t *testing.T) {
	// Create a new topology manager
	tm := NewTopologyManager()
	defer tm.Stop()

	// Create some active nodes
	for i := 0; i < 3; i++ {
		node := &Node{
			ID:        uuid.New(),
			Address:   "192.168.1." + fmt.Sprintf("%d", i),
			LastSeen:  time.Now(),
			Latency:   10 + i*5,
			IsTrusted: false,
		}
		assert.NoError(t, tm.AddNode(node))
	}

	// Create a stale node
	staleNode := &Node{
		ID:        uuid.New(),
		Address:   "192.168.1.99",
		LastSeen:  time.Now().Add(-3 * time.Minute),
		IsTrusted: false,
	}
	assert.NoError(t, tm.AddNode(staleNode))
	
	// Make sure all active nodes have recent LastSeen times
	for _, node := range tm.GetAllNodes() {
		if node.ID != staleNode.ID {
			node.LastSeen = time.Now()
			tm.AddNode(node)
		}
	}

	// Create some active paths
	for i := 0; i < 2; i++ {
		path := &Path{
			Source:     uuid.New(),
			Destination: uuid.New(),
			Address:    "192.168.1.10" + fmt.Sprintf("%d", i) + ":9993",
			Active:     true,
			LastActive: time.Now(),
			Latency:    20 + i*10,
			Trusted:    false,
		}
		assert.NoError(t, tm.AddPath(path))
	}

	// Collect metrics
	metrics := tm.collectMetrics()

	// Verify metrics
	assert.Equal(t, 4, metrics.TotalNodes)
	assert.Equal(t, 2, metrics.TotalPaths)
	assert.Equal(t, 4, metrics.ActiveNodes) // All nodes are considered active
	assert.Equal(t, 2, metrics.ActivePaths)
	// Check that average latency is calculated
	assert.Greater(t, metrics.AvgLatency, 0.0)
}

func TestTopologyManager_UpdateNode(t *testing.T) {
	// Create a new topology manager
	tm := NewTopologyManager()
	defer tm.Stop()

	// Create a node
	nodeID := uuid.New()
	node := &Node{
		ID:        nodeID,
		Address:   "192.168.1.10",
		PublicKey: "old-key",
		Version:   "1.0",
	}

	// Add the node
	assert.NoError(t, tm.AddNode(node))

	// Update the node
	updatedNode := &Node{
		ID:        nodeID,
		Address:   "192.168.1.10",
		PublicKey: "new-key",
		Version:   "1.1",
	}

	assert.NoError(t, tm.AddNode(updatedNode))

	// Get the node and verify it was updated
	retrievedNode, exists := tm.GetNode(nodeID)
	assert.True(t, exists)
	assert.Equal(t, "new-key", retrievedNode.PublicKey)
	assert.Equal(t, "1.1", retrievedNode.Version)
}