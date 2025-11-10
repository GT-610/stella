// Copyright 2023 The Stella Authors
// SPDX-License-Identifier: Apache-2.0

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

// DiscoveryProtocolVersion 定义了节点发现协议的版本
const DiscoveryProtocolVersion uint8 = 1

// 节点发现消息类型
const (
	DiscoveryTypeHello uint8 = iota
	DiscoveryTypeResponse
	DiscoveryTypePing
	DiscoveryTypePong
)

// DiscoveryManager 负责节点发现和对等节点管理
// 实现与ZeroTier兼容的节点发现机制

type DiscoveryManager struct {
	// 本地节点身份
	localIdentity *identity.Identity

	// 传输层引用，用于发送发现消息
	transport Transport

	// 已知对等节点列表，键为节点地址字符串
	peers map[string]*DiscoveredPeer

	// 锁保护peers映射的并发访问
	mu sync.RWMutex

	// 上下文，用于取消发现管理器
	ctx context.Context
	cancel context.CancelFunc

	// 随机数生成器，用于生成随机延迟
	rand *rand.Rand

	// 启动时间
	startTime time.Time

	// 发现超时时间
	discoveryTimeout time.Duration

	// 心跳间隔
	heartbeatInterval time.Duration

	// 重试次数
	maxRetries int
}

// DiscoveredPeer 表示通过发现协议找到的对等节点

type DiscoveredPeer struct {
	// 节点身份信息
	Identity *identity.Identity

	// 网络地址信息
	Address net.Addr

	// 最后一次看到该节点的时间
	LastSeen time.Time

	// 连接状态
	Connected bool

	// 延迟估计（毫秒）
	Latency int64
}

// NewDiscoveryManager 创建一个新的节点发现管理器
func NewDiscoveryManager(localIdentity *identity.Identity, transport Transport) *DiscoveryManager {
	ctx, cancel := context.WithCancel(context.Background())

	// 为随机数生成器设置种子
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
	// 启动定期清理过期节点的goroutine
	go dm.cleanupExpiredPeers()

	// 启动心跳检测
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
	// 构造Hello消息
	message := dm.buildDiscoveryMessage(DiscoveryTypeHello)

	// 通过传输层发送消息
	return dm.transport.Send(addr, message)
}

// SendDiscoveryPing 向指定地址发送Ping消息
func (dm *DiscoveryManager) SendDiscoveryPing(addr net.Addr) error {
	// 构造Ping消息
	message := dm.buildDiscoveryMessage(DiscoveryTypePing)

	// 通过传输层发送消息
	return dm.transport.Send(addr, message)
}

// HandleDiscoveryMessage 处理接收到的发现消息
func (dm *DiscoveryManager) HandleDiscoveryMessage(addr net.Addr, data []byte) error {
	// 验证消息长度至少包含头部
	if len(data) < 3 { // 版本(1) + 类型(1) + 时间戳(8)
		return fmt.Errorf("discovery message too short")
	}

	// 解析消息头
	version := data[0]
	msgType := data[1]

	// 验证版本
	if version != DiscoveryProtocolVersion {
		return fmt.Errorf("unsupported discovery protocol version: %d", version)
	}

	// 处理不同类型的消息
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

	// 添加身份信息
	// 这里简化处理，在实际实现中需要添加公钥等信息
	message := append(header, dm.localIdentity.PublicKey...)

	return message
}

// handleHelloMessage 处理Hello消息
func (dm *DiscoveryManager) handleHelloMessage(addr net.Addr, data []byte) error {
	// 提取对方公钥
	if len(data) < 10 { // 至少包含头部
		return fmt.Errorf("invalid hello message format")
	}

	// 提取公钥 (假设从索引10开始，实际实现需要根据格式调整)
	publicKey := data[10:]

	// 创建对方身份
	peerIdentity, err := identity.NewIdentityFromPublic(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create peer identity: %v", err)
	}

	// 保存对等节点信息
	dm.addOrUpdatePeer(peerIdentity, addr, false)

	// 发送响应消息
	response := dm.buildDiscoveryMessage(DiscoveryTypeResponse)
	return dm.transport.Send(addr, response)
}

// handleResponseMessage 处理Response消息
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

// handlePingMessage 处理Ping消息
func (dm *DiscoveryManager) handlePingMessage(addr net.Addr, data []byte) error {
	// 发送Pong响应
	pong := dm.buildDiscoveryMessage(DiscoveryTypePong)
	return dm.transport.Send(addr, pong)
}

// handlePongMessage 处理Pong消息
func (dm *DiscoveryManager) handlePongMessage(addr net.Addr, data []byte) error {
	// 解析时间戳
	if len(data) < 10 {
		return fmt.Errorf("invalid pong message format")
	}

	timestamp := binary.BigEndian.Uint64(data[2:10])
	now := uint64(time.Now().UnixNano() / int64(time.Millisecond))

	// 计算延迟
	latency := now - timestamp

	// 更新对等节点信息
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

// addOrUpdatePeer 添加或更新对等节点信息
func (dm *DiscoveryManager) addOrUpdatePeer(peerIdentity *identity.Identity, addr net.Addr, connected bool) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	peerAddr := addr.String()
	peer, exists := dm.peers[peerAddr]

	if !exists {
		// 创建新的对等节点记录
		peer = &DiscoveredPeer{
			Identity:  peerIdentity,
			Address:   addr,
			LastSeen:  time.Now(),
			Connected: connected,
			Latency:   -1, // 未测量
		}
		dm.peers[peerAddr] = peer
	} else {
		// 更新现有记录
		peer.Identity = peerIdentity
		peer.Address = addr
		peer.LastSeen = time.Now()
		if connected {
			peer.Connected = true
		}
	}
}

// cleanupExpiredPeers 定期清理过期的对等节点
func (dm *DiscoveryManager) cleanupExpiredPeers() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dm.mu.Lock()
			now := time.Now()
			for addr, peer := range dm.peers {
				// 如果超过发现超时时间没有收到消息，则删除该节点
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

// heartbeatChecker 定期向已知节点发送心跳
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

			// 向每个对等节点发送Ping消息
			for _, peer := range peers {
				// 添加随机延迟，避免网络风暴
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

// DiscoverNode 主动发现指定地址的节点
func (dm *DiscoveryManager) DiscoverNode(addr net.Addr) error {
	// 发送Hello消息
	err := dm.SendDiscoveryHello(addr)
	if err != nil {
		return err
	}

	// 等待响应
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	peerAddr := addr.String()

	// 检查节点是否被发现
	for i := 0; i < dm.maxRetries; i++ {
		select {
		case <-timer.C:
			// 检查是否已找到节点
			dm.mu.RLock()
			_, found := dm.peers[peerAddr]
			dm.mu.RUnlock()

			if found {
				return nil
			}

			// 重试发送Hello消息
			if i < dm.maxRetries-1 {
				err = dm.SendDiscoveryHello(addr)
				if err != nil {
					return err
				}
				timer.Reset(5 * time.Second)
			}
		}
	}

	return fmt.Errorf("failed to discover node at %s after %d attempts", addr, dm.maxRetries)
}