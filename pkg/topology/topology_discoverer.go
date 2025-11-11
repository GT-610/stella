// Package topology provides network topology management for Stella
package topology

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
)

// TopologyDiscoverer handles automatic discovery of network topology
type TopologyDiscoverer struct {
	topology     *TopologyManager
	localNodeID  uuid.UUID
	localAddress string
	discoveryPort int
	ctx          context.Context
	cancel       context.CancelFunc
	udpConn      *net.UDPConn
	mux          sync.RWMutex
	discoveryInterval time.Duration
	helloTimeout      time.Duration
	broadcastAddress  string
}

// DiscoveryMessageType defines the type of discovery message
type DiscoveryMessageType int

const (
	DiscoveryMessageHello    DiscoveryMessageType = iota // Hello message to discover peers
	DiscoveryMessageResponse                             // Response to hello message
	DiscoveryMessageUpdate                               // Update message with topology information
)

// DiscoveryMessage represents a message used for topology discovery
type DiscoveryMessage struct {
	Type        DiscoveryMessageType `json:"type"`
	SenderID    uuid.UUID            `json:"sender_id"`
	SenderAddr  string               `json:"sender_addr"`
	Version     string               `json:"version"`
	Timestamp   int64                `json:"timestamp"`
	NodeInfo    *Node                `json:"node_info,omitempty"`
	TopologyData map[string]interface{} `json:"topology_data,omitempty"`
}

// NewTopologyDiscoverer creates a new topology discoverer instance
func NewTopologyDiscoverer(topology *TopologyManager, nodeID uuid.UUID, address string, port int) *TopologyDiscoverer {
	ctx, cancel := context.WithCancel(context.Background())
	return &TopologyDiscoverer{
		topology:          topology,
		localNodeID:       nodeID,
		localAddress:      address,
		discoveryPort:     port,
		ctx:               ctx,
		cancel:            cancel,
		discoveryInterval: 30 * time.Second,
		helloTimeout:      5 * time.Second,
		broadcastAddress:  fmt.Sprintf("255.255.255.255:%d", port),
	}
}

// Start begins the topology discovery process
func (td *TopologyDiscoverer) Start() error {
	// Create UDP socket for discovery
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", td.discoveryPort))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	td.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to bind UDP socket: %w", err)
	}

	// Start message processing goroutine
	go td.messageProcessingLoop()

	// Start periodic discovery
	go td.periodicDiscoveryLoop()

	// Start initial discovery immediately
	go td.SendHello()

	return nil
}

// Stop gracefully stops the topology discoverer
func (td *TopologyDiscoverer) Stop() error {
	td.cancel()
	if td.udpConn != nil {
		return td.udpConn.Close()
	}
	return nil
}

// SendHello sends a hello message to discover other nodes
func (td *TopologyDiscoverer) SendHello() error {
	// Get local node information
	localNode, exists := td.topology.GetNode(td.localNodeID)
	if !exists {
		// Create local node if it doesn't exist
		localNode = &Node{
			ID:        td.localNodeID,
			Address:   td.localAddress,
			LastSeen:  time.Now(),
			Version:   "1.0",
			IsTrusted: true,
			MTU:       1500,
		}
		err := td.topology.AddNode(localNode)
		if err != nil {
			return err
		}
	}

	// Create hello message
	helloMsg := DiscoveryMessage{
		Type:       DiscoveryMessageHello,
		SenderID:   td.localNodeID,
		SenderAddr: td.localAddress,
		Version:    "1.0",
		Timestamp:  time.Now().Unix(),
		NodeInfo:   localNode,
	}

	// Serialize message
	data, err := json.Marshal(helloMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal hello message: %w", err)
	}

	// Send broadcast message
	broadcastAddr, err := net.ResolveUDPAddr("udp", td.broadcastAddress)
	if err != nil {
		return fmt.Errorf("failed to resolve broadcast address: %w", err)
	}

	_, err = td.udpConn.WriteToUDP(data, broadcastAddr)
	if err != nil {
		// Don't fail if broadcast fails, it might not be supported
		fmt.Printf("Warning: failed to send broadcast: %v\n", err)
	}

	// Also send to known nodes
	nodes := td.topology.GetAllNodes()
	for _, node := range nodes {
		if node.ID != td.localNodeID {
			nodeAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", node.Address, td.discoveryPort))
			if err == nil {
				td.udpConn.WriteToUDP(data, nodeAddr)
			}
		}
	}

	return nil
}

// messageProcessingLoop continuously processes incoming discovery messages
func (td *TopologyDiscoverer) messageProcessingLoop() {
	buffer := make([]byte, 65536)

	for {
		select {
		case <-td.ctx.Done():
			return
		default:
			// Set read deadline to allow periodic context checks
			td.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, remoteAddr, err := td.udpConn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout is expected, continue to check context
					continue
				}
				fmt.Printf("Error reading from UDP: %v\n", err)
				continue
			}

			// Process the message
			go td.processDiscoveryMessage(buffer[:n], remoteAddr)
		}
	}
}

// periodicDiscoveryLoop periodically sends hello messages
func (td *TopologyDiscoverer) periodicDiscoveryLoop() {
	ticker := time.NewTicker(td.discoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-td.ctx.Done():
			return
		case <-ticker.C:
			err := td.SendHello()
			if err != nil {
				fmt.Printf("Error sending periodic hello: %v\n", err)
			}
		}
	}
}

// processDiscoveryMessage processes an incoming discovery message
func (td *TopologyDiscoverer) processDiscoveryMessage(data []byte, remoteAddr *net.UDPAddr) {
	var msg DiscoveryMessage
	err := json.Unmarshal(data, &msg)
	if err != nil {
		fmt.Printf("Failed to unmarshal discovery message: %v\n", err)
		return
	}

	// Ignore messages from ourselves
	if msg.SenderID == td.localNodeID {
		return
	}

	switch msg.Type {
	case DiscoveryMessageHello:
		td.handleHelloMessage(&msg, remoteAddr)
	case DiscoveryMessageResponse:
		td.handleResponseMessage(&msg)
	case DiscoveryMessageUpdate:
		td.handleUpdateMessage(&msg)
	default:
		fmt.Printf("Unknown discovery message type: %d\n", msg.Type)
	}
}

// handleHelloMessage processes a hello message
func (td *TopologyDiscoverer) handleHelloMessage(msg *DiscoveryMessage, remoteAddr *net.UDPAddr) {
	// Update or add the node to topology
	if msg.NodeInfo != nil {
		// Update node address if it's not set but we have the remote address
		if msg.NodeInfo.Address == "" {
			msg.NodeInfo.Address = remoteAddr.IP.String()
		}
		
		// Ensure node ID matches the sender ID
		msg.NodeInfo.ID = msg.SenderID
		msg.NodeInfo.LastSeen = time.Now()
		
		err := td.topology.AddNode(msg.NodeInfo)
		if err != nil {
			fmt.Printf("Failed to add node to topology: %v\n", err)
		}
		
		// Create a path between local node and this node
		path := &Path{
			Source:     td.localNodeID,
			Destination: msg.SenderID,
			Address:    remoteAddr.String(),
			Active:     true,
			LastActive: time.Now(),
			Latency:    0, // Will be updated with actual measurements
			Trusted:    false,
		}
		
		err = td.topology.AddPath(path)
		if err != nil {
			fmt.Printf("Failed to add path to topology: %v\n", err)
		}
	}
	
	// Send a response
	td.sendResponse(msg.SenderID, remoteAddr)
}

// handleResponseMessage processes a response message
func (td *TopologyDiscoverer) handleResponseMessage(msg *DiscoveryMessage) {
	// Update or add the node to topology
	if msg.NodeInfo != nil {
		msg.NodeInfo.ID = msg.SenderID
		msg.NodeInfo.LastSeen = time.Now()
		
		err := td.topology.AddNode(msg.NodeInfo)
		if err != nil {
			fmt.Printf("Failed to add node from response: %v\n", err)
		}
	}
}

// handleUpdateMessage processes an update message with topology information
func (td *TopologyDiscoverer) handleUpdateMessage(msg *DiscoveryMessage) {
	// This would be expanded to handle more complex topology data sharing
	// For now, we'll just update the node information
	if msg.NodeInfo != nil {
		msg.NodeInfo.ID = msg.SenderID
		msg.NodeInfo.LastSeen = time.Now()
		
		err := td.topology.AddNode(msg.NodeInfo)
		if err != nil {
			fmt.Printf("Failed to update node from topology update: %v\n", err)
		}
	}
}

// sendResponse sends a response to a hello message
func (td *TopologyDiscoverer) sendResponse(targetID uuid.UUID, remoteAddr *net.UDPAddr) {
	// Get local node information
	localNode, exists := td.topology.GetNode(td.localNodeID)
	if !exists {
		return
	}

	// Create response message
	responseMsg := DiscoveryMessage{
		Type:       DiscoveryMessageResponse,
		SenderID:   td.localNodeID,
		SenderAddr: td.localAddress,
		Version:    "1.0",
		Timestamp:  time.Now().Unix(),
		NodeInfo:   localNode,
	}

	// Serialize message
	data, err := json.Marshal(responseMsg)
	if err != nil {
		fmt.Printf("Failed to marshal response message: %v\n", err)
		return
	}

	// Send response to the remote address
	_, err = td.udpConn.WriteToUDP(data, remoteAddr)
	if err != nil {
		fmt.Printf("Failed to send response: %v\n", err)
	}
}

// DiscoverSpecificNode sends a directed hello to a specific node
func (td *TopologyDiscoverer) DiscoverSpecificNode(nodeAddress string) error {
	// Create hello message
	helloMsg := DiscoveryMessage{
		Type:       DiscoveryMessageHello,
		SenderID:   td.localNodeID,
		SenderAddr: td.localAddress,
		Version:    "1.0",
		Timestamp:  time.Now().Unix(),
	}

	// Get local node information
	localNode, exists := td.topology.GetNode(td.localNodeID)
	if exists {
		helloMsg.NodeInfo = localNode
	}

	// Serialize message
	data, err := json.Marshal(helloMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal hello message: %w", err)
	}

	// Send to specific node
	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", nodeAddress, td.discoveryPort))
	if err != nil {
		return fmt.Errorf("failed to resolve target address: %w", err)
	}

	_, err = td.udpConn.WriteToUDP(data, targetAddr)
	return err
}

// ShareTopologyData shares topology information with a specific node
func (td *TopologyDiscoverer) ShareTopologyData(targetID uuid.UUID) error {
	// Get the target node
	targetNode, exists := td.topology.GetNode(targetID)
	if !exists {
		return fmt.Errorf("target node not found")
	}

	// Create update message with topology data
	updateMsg := DiscoveryMessage{
		Type:        DiscoveryMessageUpdate,
		SenderID:    td.localNodeID,
		SenderAddr:  td.localAddress,
		Version:     "1.0",
		Timestamp:   time.Now().Unix(),
		TopologyData: map[string]interface{}{
			"node_count": len(td.topology.GetAllNodes()),
			"path_count": len(td.topology.GetAllPaths()),
		},
	}

	// Serialize message
	data, err := json.Marshal(updateMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal update message: %w", err)
	}

	// Send to target node
	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetNode.Address, td.discoveryPort))
	if err != nil {
		return fmt.Errorf("failed to resolve target address: %w", err)
	}

	_, err = td.udpConn.WriteToUDP(data, targetAddr)
	return err
}