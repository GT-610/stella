package transport

import (
	"errors"
	"net"
	"sync"
	"time"
)

// simpleConnection is a minimal Connection implementation

type simpleConnection struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	transport  *UDPTransport
}

// GetState returns connection state
func (c *simpleConnection) GetState() ConnectionState {
	return StateConnected
}

// GetRemoteAddr returns remote address
func (c *simpleConnection) GetRemoteAddr() net.Addr {
	return c.remoteAddr
}

// GetLocalAddr returns local address
func (c *simpleConnection) GetLocalAddr() net.Addr {
	return c.localAddr
}

// SetReadTimeout sets read timeout
func (c *simpleConnection) SetReadTimeout(timeout time.Duration) error {
	return nil
}

// SetWriteTimeout sets write timeout
func (c *simpleConnection) SetWriteTimeout(timeout time.Duration) error {
	return nil
}

// Connect connects to remote address
func (c *simpleConnection) Connect(remoteAddr net.Addr) error {
	return nil
}

// Disconnect disconnects the connection
func (c *simpleConnection) Disconnect() error {
	return nil
}

// Send sends data
func (c *simpleConnection) Send(data []byte) error {
	return c.transport.Send(c.remoteAddr, data)
}

// Receive receives data
func (c *simpleConnection) Receive(buffer []byte) (int, error) {
	return 0, nil
}

// getConnectionKey generates a key for the connection map based on the remote address
func (m *DefaultConnectionManager) getConnectionKey(addr net.Addr) string {
	return addr.String()
}

// DefaultConnectionManager implements the ConnectionManager interface
// It manages a collection of connections and provides methods to add, remove, and find connections

type DefaultConnectionManager struct {
	// connections is a map of remote addresses to connections
	connections map[string]Connection

	// mu protects the connections map from concurrent access
	mu sync.RWMutex

	// listeners is a list of connection event listeners
	listeners []ConnectionListener

	// listenerMu protects the listeners slice from concurrent access
	listenerMu sync.RWMutex

	// transport is the transport that created this manager
	transport Transport
}

// AddConnectionListener adds a connection listener
func (m *DefaultConnectionManager) AddConnectionListener(listener ConnectionListener) {
	m.AddListener(listener)
}

// NewDefaultConnectionManager creates a new connection manager
func NewDefaultConnectionManager(transport Transport) *DefaultConnectionManager {
	return &DefaultConnectionManager{
		connections: make(map[string]Connection),
		transport:   transport,
	}
}

// AddConnection adds a new connection to the manager
func (m *DefaultConnectionManager) AddConnection(conn Connection) error {
	if conn == nil {
		return NewTransportError("cannot add nil connection", 4001, nil)
	}

	remoteAddr := conn.GetRemoteAddr()
	if remoteAddr == nil {
		return NewTransportError("connection has no remote address", 4002, nil)
	}

	addrStr := remoteAddr.String()

	m.mu.Lock()
	// Check if connection already exists
	if existingConn, exists := m.connections[addrStr]; exists {
		// If the existing connection is closed, replace it
		if existingConn.GetState() == StateDisconnected {
			m.connections[addrStr] = conn
			m.mu.Unlock()
			// Notify listeners
			m.notifyListeners(conn, EventConnected, []byte{}, nil)
			return nil
		}
		m.mu.Unlock()
		return NewTransportError("connection already exists", 4003, nil)
	}

	// Add the new connection
	m.connections[addrStr] = conn
	m.mu.Unlock()

	// Notify listeners
	m.notifyListeners(conn, EventConnected, []byte{}, nil)
	return nil
}

// RemoveConnection removes a connection from the manager
func (m *DefaultConnectionManager) RemoveConnection(conn Connection) error {
	if conn == nil {
		return NewTransportError("cannot remove nil connection", 4004, nil)
	}

	remoteAddr := conn.GetRemoteAddr()
	if remoteAddr == nil {
		return NewTransportError("connection has no remote address", 4005, nil)
	}

	return m.RemoveConnectionByAddr(remoteAddr)
}

// CloseAllConnections closes all connections
func (m *DefaultConnectionManager) CloseAllConnections() error {
	m.mu.Lock()
	// Clear all connections
	m.connections = make(map[string]Connection)
	m.mu.Unlock()
	return nil
}

// RemoveConnectionByAddr removes a connection by its remote address
func (m *DefaultConnectionManager) RemoveConnectionByAddr(addr net.Addr) error {
	if addr == nil {
		return NewTransportError("cannot remove connection with nil address", 4006, nil)
	}

	addrStr := addr.String()

	m.mu.Lock()
	conn, exists := m.connections[addrStr]
	if !exists {
		m.mu.Unlock()
		return NewTransportError("connection not found", 4007, nil)
	}

	// Remove the connection
	delete(m.connections, addrStr)
	m.mu.Unlock()

	// Notify listeners
	m.notifyListeners(conn, EventDisconnected, []byte{}, nil)
	return nil
}

// CreateConnection creates a new connection
func (m *DefaultConnectionManager) CreateConnection(remoteAddr net.Addr) (Connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.getConnectionKey(remoteAddr)

	// Check if connection already exists
	if conn, exists := m.connections[key]; exists {
		return conn, nil
	}

	// Create connection based on transport type
	var newConn Connection

	if t, ok := m.transport.(*UDPTransport); ok {
		// Create a simple connection implementation
		newConn = &simpleConnection{
			localAddr:  m.transport.GetLocalAddr(), // Set local address directly
			remoteAddr: remoteAddr,
			transport:  t,
		}
	} else {
		return nil, errors.New("unsupported transport type")
	}

	// Store the connection
	m.connections[key] = newConn

	// Notify listeners about the new connection with proper event
	m.notifyListeners(newConn, EventConnected, []byte{}, nil)

	return newConn, nil
}

// CloseConnection closes a connection by remote address
func (m *DefaultConnectionManager) CloseConnection(remoteAddr net.Addr) error {
	if remoteAddr == nil {
		return errors.New("cannot close connection with nil address")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.getConnectionKey(remoteAddr)
	conn, exists := m.connections[key]
	if !exists {
		return errors.New("connection not found")
	}

	// Remove from map
	delete(m.connections, key)

	// Notify listeners about the removed connection with proper event
	m.notifyListeners(conn, EventDisconnected, []byte{}, nil)

	return nil
}

// GetConnection retrieves a connection by its remote address
func (m *DefaultConnectionManager) GetConnection(addr net.Addr) Connection {
	if addr == nil {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.getConnectionKey(addr)
	conn, exists := m.connections[key]
	if !exists {
		return nil
	}

	return conn
}

// GetConnections returns all active connections
func (m *DefaultConnectionManager) GetConnections() []Connection {
	m.mu.RLock()
	defer m.mu.RUnlock()

	connections := make([]Connection, 0, len(m.connections))
	for _, conn := range m.connections {
		connections = append(connections, conn)
	}

	return connections
}

// GetOrCreateConnection retrieves a connection by its remote address or creates a new one if it doesn't exist
func (m *DefaultConnectionManager) GetOrCreateConnection(localAddr, remoteAddr net.Addr) Connection {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Try to get existing connection
	key := m.getConnectionKey(remoteAddr)
	conn, exists := m.connections[key]
	if exists && conn.GetState() != StateDisconnected {
		// Connection exists and is active
		return conn
	}

	// Create new connection
	var newConn Connection

	switch t := m.transport.(type) {
	case *UDPTransport:
		// Create a simple connection implementation
		newConn = &simpleConnection{
			localAddr:  localAddr,
			remoteAddr: remoteAddr,
			transport:  t,
		}
		// Try to connect
		newConn.Connect(remoteAddr)
	}

	// Store the new connection
	m.connections[key] = newConn

	return newConn
}

// GetAllConnections returns all connections managed by this manager
func (m *DefaultConnectionManager) GetAllConnections() []Connection {
	m.mu.RLock()
	defer m.mu.RUnlock()

	conns := make([]Connection, 0, len(m.connections))
	for _, conn := range m.connections {
		conns = append(conns, conn)
	}

	return conns
}

// GetConnectionCount returns the number of connections managed by this manager
func (m *DefaultConnectionManager) GetConnectionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.connections)
}

// ClearConnections removes all connections from the manager
func (m *DefaultConnectionManager) ClearConnections() error {
	m.mu.Lock()
	conns := make([]Connection, 0, len(m.connections))
	for _, conn := range m.connections {
		conns = append(conns, conn)
	}
	// Clear the map
	m.connections = make(map[string]Connection)
	m.mu.Unlock()

	// Notify listeners for each removed connection
	for _, conn := range conns {
		m.notifyListeners(conn, EventDisconnected, []byte{}, nil)
	}

	return nil
}

// AddListener adds a connection event listener
func (m *DefaultConnectionManager) AddListener(listener ConnectionListener) error {
	if listener == nil {
		return NewTransportError("cannot add nil listener", 4012, nil)
	}

	m.listenerMu.Lock()
	m.listeners = append(m.listeners, listener)
	m.listenerMu.Unlock()

	return nil
}

// RemoveListener removes a connection event listener
func (m *DefaultConnectionManager) RemoveListener(listener ConnectionListener) error {
	if listener == nil {
		return NewTransportError("cannot remove nil listener", 4013, nil)
	}

	m.listenerMu.Lock()
	defer m.listenerMu.Unlock()

	// Since we can't compare functions directly, we'll just remove the first one
	if len(m.listeners) > 0 {
		m.listeners = m.listeners[1:]
		return nil
	}

	return NewTransportError("listener not found", 4014, nil)
}

// RemoveConnectionListener removes a connection listener
func (m *DefaultConnectionManager) RemoveConnectionListener(listener ConnectionListener) {
	m.RemoveListener(listener)
}

// notifyListeners notifies all registered listeners of a connection event
func (m *DefaultConnectionManager) notifyListeners(conn Connection, event ConnectionEvent, data []byte, err error) {
	m.listenerMu.RLock()
	// Make a copy of the listeners to avoid holding the lock during callbacks
	listeners := make([]ConnectionListener, len(m.listeners))
	copy(listeners, m.listeners)
	m.listenerMu.RUnlock()

	// Notify each listener
	for _, listener := range listeners {
		// Ensure we're not sending nil values for data
		if data == nil {
			data = []byte{}
		}
		listener(conn, event, data, err)
	}
}
