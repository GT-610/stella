package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/stella/virtual-switch/pkg/identity"
)

// DiscoveryProtocolVersion defines the version of the node discovery protocol
const DiscoveryProtocolVersion uint8 = 1

// Node discovery message types
const (
	DiscoveryTypeHello uint8 = iota
	DiscoveryTypeResponse
	DiscoveryTypePing
	DiscoveryTypePong
)

// DiscoveryManager is responsible for node discovery and peer management
// Implements ZeroTier-compatible node discovery mechanism

type DiscoveryManager struct {
	// Local node identity
	localIdentity *identity.Identity

	// Transport layer reference for sending discovery messages
	transport Transport

	// List of known peers, keyed by node address string
	peers map[string]*DiscoveredPeer

	// Lock to protect concurrent access to peers map
	mu sync.RWMutex

	// Context for canceling the discovery manager
	ctx    context.Context
	cancel context.CancelFunc

	// Random number generator for generating random delays
	rand *rand.Rand

	// Start time
	startTime time.Time

	// Discovery timeout duration
	discoveryTimeout time.Duration

	// Heartbeat interval
	heartbeatInterval time.Duration

	// Maximum retry attempts
	maxRetries int
}

// DiscoveredPeer represents a peer found through the discovery protocol

type DiscoveredPeer struct {
	// Node identity information
	Identity *identity.Identity

	// Network address information
	Address net.Addr

	// Last time the node was seen
	LastSeen time.Time

	// Connection status
	Connected bool

	// Latency estimate (milliseconds)
	Latency int64
}

// NewDiscoveryManager 创建一个新的节点发现管理器
func NewDiscoveryManager(localIdentity *identity.Identity, transport Transport) *DiscoveryManager {
	ctx, cancel := context.WithCancel(context.Background())

	// Set seed for random number generator
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)

	return &DiscoveryManager{
		localIdentity:     localIdentity,
		transport:         transport,
		peers:             make(map[string]*DiscoveredPeer),
		ctx:               ctx,
		cancel:            cancel,
		rand:              random,
		startTime:         time.Now(),
		discoveryTimeout:  30 * time.Second,
		heartbeatInterval: 60 * time.Second,
		maxRetries:        3,
	}
}

// Start 启动节点发现服务
func (dm *DiscoveryManager) Start() error {
	// Start goroutine for cleaning up expired peers periodically
	go dm.cleanupExpiredPeers()

	// Start heartbeat checking
	go dm.heartbeatChecker()

	return nil
}

// Stop 停止节点发现服务
func (dm *DiscoveryManager) Stop() error {
	dm.cancel()
	return nil
}

// SendDiscoveryHello 向指定地址发送发现Hello消息
func (dm *DiscoveryManager) SendDiscoveryHello(addr net.Addr) error {
	// Construct Hello message
	message := dm.buildDiscoveryMessage(DiscoveryTypeHello)

	// Send message through transport layer
	return dm.transport.Send(addr, message)
}

// SendDiscoveryPing 向指定地址发送Ping消息
func (dm *DiscoveryManager) SendDiscoveryPing(addr net.Addr) error {
	// Construct Ping message
	message := dm.buildDiscoveryMessage(DiscoveryTypePing)

	// 通过传输层发送消息
	return dm.transport.Send(addr, message)
}

// HandleDiscoveryMessage 处理接收到的发现消息
func (dm *DiscoveryManager) HandleDiscoveryMessage(addr net.Addr, data []byte) error {
	// Verify message length includes at least the header
	if len(data) < 3 { // 版本(1) + 类型(1) + 时间戳(8)
		return fmt.Errorf("discovery message too short")
	}

	// Parse message header
	version := data[0]
	msgType := data[1]

	// Verify version
	if version != DiscoveryProtocolVersion {
		return fmt.Errorf("unsupported discovery protocol version: %d", version)
	}

	// Handle different message types
	switch msgType {
	case DiscoveryTypeHello:
		return dm.handleHelloMessage(addr, data)
	case DiscoveryTypeResponse:
		return dm.handleResponseMessage(addr, data)
	case DiscoveryTypePing:
		return dm.handlePingMessage(addr, data)
	case DiscoveryTypePong:
		return dm.handlePongMessage(addr, data)
	default:
		return fmt.Errorf("unknown discovery message type: %d", msgType)
	}
}

// GetPeerByAddress 根据地址获取对等节点信息
func (dm *DiscoveryManager) GetPeerByAddress(addr string) (*DiscoveredPeer, bool) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	peer, exists := dm.peers[addr]
	return peer, exists
}

// GetAllPeers 获取所有已知的对等节点
func (dm *DiscoveryManager) GetAllPeers() []*DiscoveredPeer {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	peers := make([]*DiscoveredPeer, 0, len(dm.peers))
	for _, peer := range dm.peers {
		peers = append(peers, peer)
	}

	return peers
}

// buildDiscoveryMessage 构建发现消息
func (dm *DiscoveryManager) buildDiscoveryMessage(msgType uint8) []byte {
	// 消息格式: 版本(1) + 类型(1) + 时间戳(8) + 节点身份信息(变长)
	timestamp := uint64(time.Now().UnixNano() / int64(time.Millisecond))

	// 构建消息头部
	header := make([]byte, 10) // 1 + 1 + 8
	header[0] = DiscoveryProtocolVersion
	header[1] = msgType
	binary.BigEndian.PutUint64(header[2:], timestamp)

	// Add identity information
// Simplified handling here, in actual implementation need to add public key, etc.
	message := append(header, dm.localIdentity.PublicKey...)

	return message
}

// handleHelloMessage processes Hello messages
func (dm *DiscoveryManager) handleHelloMessage(addr net.Addr, data []byte) error {
	// Extract peer's public key
	if len(data) < 10 { // At least include the header
		return fmt.Errorf("invalid hello message format")
	}

	// Extract public key (assuming starts at index 10, actual implementation needs adjustment based on format)
	publicKey := data[10:]

	// Create peer identity
	peerIdentity, err := identity.NewIdentityFromPublic(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create peer identity: %v", err)
	}

	// Save peer information
	dm.addOrUpdatePeer(peerIdentity, addr, false)

	// Send response message
	response := dm.buildDiscoveryMessage(DiscoveryTypeResponse)
	return dm.transport.Send(addr, response)
}

// handleResponseMessage processes Response messages
func (dm *DiscoveryManager) handleResponseMessage(addr net.Addr, data []byte) error {
	// 提取对方公钥
	if len(data) < 10 {
		return fmt.Errorf("invalid response message format")
	}

	publicKey := data[10:]

	// 创建对方身份
	peerIdentity, err := identity.NewIdentityFromPublic(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create peer identity: %v", err)
	}

	// 保存对等节点信息
	dm.addOrUpdatePeer(peerIdentity, addr, true)

	return nil
}

// handlePingMessage processes Ping messages
func (dm *DiscoveryManager) handlePingMessage(addr net.Addr, _ []byte) error {
	// Send Pong response
	pong := dm.buildDiscoveryMessage(DiscoveryTypePong)
	return dm.transport.Send(addr, pong)
}

// handlePongMessage processes Pong messages
func (dm *DiscoveryManager) handlePongMessage(addr net.Addr, data []byte) error {
	// Parse timestamp
	if len(data) < 10 {
		return fmt.Errorf("invalid pong message format")
	}

	timestamp := binary.BigEndian.Uint64(data[2:10])
	now := uint64(time.Now().UnixNano() / int64(time.Millisecond))

	// Calculate latency
	latency := now - timestamp

	// Update peer information
	dm.mu.Lock()
	defer dm.mu.Unlock()

	peerAddr := addr.String()
	if peer, exists := dm.peers[peerAddr]; exists {
		peer.LastSeen = time.Now()
		peer.Latency = int64(latency)
		peer.Connected = true
	}

	return nil
}

// addOrUpdatePeer adds or updates peer information
func (dm *DiscoveryManager) addOrUpdatePeer(peerIdentity *identity.Identity, addr net.Addr, connected bool) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	peerAddr := addr.String()
	peer, exists := dm.peers[peerAddr]

	if !exists {
		// Create new peer record
		peer = &DiscoveredPeer{
			Identity:  peerIdentity,
			Address:   addr,
			LastSeen:  time.Now(),
			Connected: connected,
			Latency:   -1, // Not measured
		}
		dm.peers[peerAddr] = peer
	} else {
		// Update existing record
		peer.Identity = peerIdentity
		peer.Address = addr
		peer.LastSeen = time.Now()
		if connected {
			peer.Connected = true
		}
	}
}

// cleanupExpiredPeers periodically cleans up expired peers
func (dm *DiscoveryManager) cleanupExpiredPeers() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dm.mu.Lock()
			now := time.Now()
			for addr, peer := range dm.peers {
				// If no message is received within discovery timeout, remove the node
				if now.Sub(peer.LastSeen) > dm.discoveryTimeout {
					delete(dm.peers, addr)
				}
			}
			dm.mu.Unlock()
		case <-dm.ctx.Done():
			return
		}
	}
}

// heartbeatChecker periodically sends heartbeats to known nodes
func (dm *DiscoveryManager) heartbeatChecker() {
	ticker := time.NewTicker(dm.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dm.mu.RLock()
			peers := make([]*DiscoveredPeer, 0, len(dm.peers))
			for _, peer := range dm.peers {
				peers = append(peers, peer)
			}
			dm.mu.RUnlock()

			// Send Ping message to each peer
			for _, peer := range peers {
				// Add random delay to avoid network storms
				delay := time.Duration(dm.rand.Intn(1000)) * time.Millisecond
				go func(p *DiscoveredPeer) {
					time.Sleep(delay)
					dm.SendDiscoveryPing(p.Address)
				}(peer)
			}
		case <-dm.ctx.Done():
			return
		}
	}
}

// DiscoverNode actively discovers a node at the specified address
func (dm *DiscoveryManager) DiscoverNode(addr net.Addr) error {
	// Send Hello message
	err := dm.SendDiscoveryHello(addr)
	if err != nil {
		return err
	}

	// Wait for response
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	peerAddr := addr.String()

	// Check if node has been discovered
	for i := 0; i < dm.maxRetries; i++ {
		<-timer.C
		// Check if node has been found
		dm.mu.RLock()
		_, found := dm.peers[peerAddr]
		dm.mu.RUnlock()

		if found {
			return nil
		}

		// Retry sending Hello message
		if i < dm.maxRetries-1 {
			err = dm.SendDiscoveryHello(addr)
			if err != nil {
				return err
			}
			timer.Reset(5 * time.Second)
		}
	}

	return fmt.Errorf("failed to discover node at %s after %d attempts", addr, dm.maxRetries)
}
