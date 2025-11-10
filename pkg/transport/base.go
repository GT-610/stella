package transport

import (
	"net"
	"sync"
	"time"
)

// BaseTransport implements common functionality for transport protocols
// It provides basic implementations for shared Transport interface methods
// and manages state, timeouts, and basic concurrency control

type BaseTransport struct {
	state        ConnectionState
	localAddr    net.Addr
	readTimeout  time.Duration
	writeTimeout time.Duration
	mu           sync.RWMutex
	handler      PacketHandler
	closed       bool
}

// NewBaseTransport creates a new base transport instance
func NewBaseTransport() *BaseTransport {
	return &BaseTransport{
		state:        StateDisconnected,
		readTimeout:  30 * time.Second,
		writeTimeout: 5 * time.Second,
		closed:       false,
	}
}

// GetState returns the current state of the transport
func (bt *BaseTransport) GetState() ConnectionState {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return bt.state
}

// setState sets the state of the transport
func (bt *BaseTransport) setState(state ConnectionState) {
	bt.mu.Lock()
	bt.state = state
	bt.mu.Unlock()
}

// SetReadTimeout sets the read timeout for the transport
func (bt *BaseTransport) SetReadTimeout(timeout time.Duration) error {
	bt.mu.Lock()
	bt.readTimeout = timeout
	bt.mu.Unlock()
	return nil
}

// getReadTimeout gets the read timeout for the transport
func (bt *BaseTransport) getReadTimeout() time.Duration {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return bt.readTimeout
}

// SetWriteTimeout sets the write timeout for the transport
func (bt *BaseTransport) SetWriteTimeout(timeout time.Duration) error {
	bt.mu.Lock()
	bt.writeTimeout = timeout
	bt.mu.Unlock()
	return nil
}

// getWriteTimeout gets the write timeout for the transport
func (bt *BaseTransport) getWriteTimeout() time.Duration {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return bt.writeTimeout
}

// GetLocalAddr returns the local address the transport is bound to
func (bt *BaseTransport) GetLocalAddr() net.Addr {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return bt.localAddr
}

// setLocalAddr sets the local address for the transport
func (bt *BaseTransport) setLocalAddr(addr net.Addr) {
	bt.mu.Lock()
	bt.localAddr = addr
	bt.mu.Unlock()
}

// isClosed checks if the transport is closed
func (bt *BaseTransport) isClosed() bool {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return bt.closed
}

// setClosed marks the transport as closed
func (bt *BaseTransport) setClosed() {
	bt.mu.Lock()
	bt.closed = true
	bt.mu.Unlock()
}

// getHandler returns the packet handler for the transport
func (bt *BaseTransport) getHandler() PacketHandler {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return bt.handler
}

// setHandler sets the packet handler for the transport
func (bt *BaseTransport) setHandler(handler PacketHandler) {
	bt.mu.Lock()
	bt.handler = handler
	bt.mu.Unlock()
}

// Init initializes the transport with the given configuration
func (bt *BaseTransport) Init(config map[string]interface{}) error {
	// Default implementation - do nothing
	return nil
}

// Start begins listening for packets on the transport
func (bt *BaseTransport) Start(handler PacketHandler) error {
	if handler == nil {
		return NewTransportError("packet handler cannot be nil", 1001, nil)
	}

	if bt.isClosed() {
		return NewTransportError("transport is closed", 1002, nil)
	}

	bt.setHandler(handler)
	bt.setState(StateConnected)
	return nil
}

// Stop shuts down the transport and releases resources
func (bt *BaseTransport) Stop() error {
	if bt.isClosed() {
		return nil // Already stopped
	}

	bt.setState(StateDisconnecting)
	bt.setHandler(nil)
	bt.setClosed()
	bt.setState(StateDisconnected)
	return nil
}

// Send sends a packet to the specified address
func (bt *BaseTransport) Send(dstAddr net.Addr, data []byte) error {
	return NewTransportError("send not implemented", 1003, nil)
}
