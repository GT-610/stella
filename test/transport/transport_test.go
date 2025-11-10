package transport_test

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stella/virtual-switch/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUDPTransportSendReceive tests the basic send/receive functionality of UDP transport
func TestUDPTransportSendReceive(t *testing.T) {
	// Create two UDP transports on different ports
	serverConfig := map[string]interface{}{"port": 4433}
	serverTransport, err := transport.NewTransport(transport.TransportTypeUDP, serverConfig)
	require.NoError(t, err)

	clientConfig := map[string]interface{}{"port": 4434}
	clientTransport, err := transport.NewTransport(transport.TransportTypeUDP, clientConfig)
	require.NoError(t, err)

	// Test data
	message := []byte("Hello Stella Transport")
	var receivedData []byte
	var receivedAddr net.Addr
	var receiveDone sync.WaitGroup
	receiveDone.Add(1)

	// Start server transport with a handler
	handler := func(addr net.Addr, data []byte) error {
		receivedData = data
		receivedAddr = addr
		receiveDone.Done()
		return nil
	}

	err = serverTransport.Start(handler)
	require.NoError(t, err)
	defer serverTransport.Stop()

	// Start client transport with empty handler
	err = clientTransport.Start(func(addr net.Addr, data []byte) error { return nil })
	require.NoError(t, err)
	defer clientTransport.Stop()

	// Send message from client to server
	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4433}
	err = clientTransport.Send(serverAddr, message)
	require.NoError(t, err)

	// Wait for the message to be received
	done := make(chan struct{})
	go func() {
		receiveDone.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Verify received data
		assert.Equal(t, message, receivedData)
		assert.NotNil(t, receivedAddr)
		assert.Equal(t, "127.0.0.1:4434", receivedAddr.String())

	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for message to be received")
	}
}

// TestConnectionManagerAddRemove tests adding and removing connections
func TestConnectionManagerAddRemove(t *testing.T) {
	// Create a UDP transport
	udpTransport, err := transport.NewTransport(transport.TransportTypeUDP, map[string]interface{}{"port": 4435})
	require.NoError(t, err)
	err = udpTransport.Start(func(addr net.Addr, data []byte) error { return nil })
	require.NoError(t, err)
	defer udpTransport.Stop()

	// Create a connection manager
	manager := transport.NewConnectionManager(udpTransport)
	require.NotNil(t, manager)

	// Create a mock connection
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4436}
	// Use CreateConnection to create a new connection
	conn, err := manager.CreateConnection(remoteAddr)
	require.NoError(t, err)
	assert.NotNil(t, conn)

	// Test getting connection
	retrievedConn := manager.GetConnection(remoteAddr)
	assert.Equal(t, conn, retrievedConn)

	// Test removing connection
	err = manager.CloseConnection(remoteAddr)
	require.NoError(t, err)

	// Test getting non-existent connection
	retrievedConn = manager.GetConnection(remoteAddr)
	assert.Nil(t, retrievedConn)
}

// TestConnectionManagerGetOrCreate tests getting or creating connections
func TestConnectionManagerGetOrCreate(t *testing.T) {
	// Create a UDP transport
	udpTransport, err := transport.NewTransport(transport.TransportTypeUDP, map[string]interface{}{"port": 4437})
	require.NoError(t, err)
	err = udpTransport.Start(func(addr net.Addr, data []byte) error { return nil })
	require.NoError(t, err)
	defer udpTransport.Stop()

	// Create a connection manager
	manager := transport.NewConnectionManager(udpTransport)

	// Test creating a new connection
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4438}
	conn, err := manager.CreateConnection(remoteAddr)
	require.NoError(t, err)
	assert.NotNil(t, conn)

	// Test getting existing connection
	existingConn := manager.GetConnection(remoteAddr)
	assert.Equal(t, conn, existingConn)
}

// TestConnectionManagerListeners tests connection event listeners
func TestConnectionManagerListeners(t *testing.T) {
	// Create a UDP transport
	udpTransport, err := transport.NewTransport(transport.TransportTypeUDP, map[string]interface{}{"port": 4439})
	require.NoError(t, err)
	err = udpTransport.Start(func(addr net.Addr, data []byte) error { return nil })
	require.NoError(t, err)
	defer udpTransport.Stop()

	// Create a connection manager
	manager := transport.NewConnectionManager(udpTransport)

	// Variables to track events
	var added bool
	var removed bool
	var eventMutex sync.Mutex

	// Create a listener
	listener := func(conn transport.Connection, event transport.ConnectionEvent, data []byte, err error) {
		eventMutex.Lock()
		defer eventMutex.Unlock()

		switch event {
		case transport.EventConnected:
			added = true
		case transport.EventDisconnected:
			removed = true
		}
	}

	// Add listener
	manager.AddConnectionListener(listener)

	// Create and add a connection
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4440}
	conn, err := manager.CreateConnection(remoteAddr)
	require.NoError(t, err)
	assert.NotNil(t, conn)

	// Verify add event was triggered
	eventMutex.Lock()
	assert.True(t, added)
	eventMutex.Unlock()

	// Remove connection
	err = manager.CloseConnection(remoteAddr)
	require.NoError(t, err)

	// Verify remove event was triggered
	eventMutex.Lock()
	assert.True(t, removed)
	eventMutex.Unlock()

	// Remove listener
	manager.RemoveConnectionListener(listener)
}

// TestUDPTransportStateManagement tests the state management of UDP transport
func TestUDPTransportStateManagement(t *testing.T) {
	// Create a UDP transport
	udpTransport, err := transport.NewTransport(transport.TransportTypeUDP, map[string]interface{}{"port": 4441})
	require.NoError(t, err)

	// Check initial state
	assert.Equal(t, transport.StateDisconnected, udpTransport.GetState())

	// Start transport
	err = udpTransport.Start(func(addr net.Addr, data []byte) error { return nil })
	require.NoError(t, err)
	assert.Equal(t, transport.StateConnected, udpTransport.GetState())

	// Stop transport
	err = udpTransport.Stop()
	require.NoError(t, err)
	assert.Equal(t, transport.StateDisconnected, udpTransport.GetState())
}

// TestTransportFactory tests the transport factory
func TestTransportFactory(t *testing.T) {
	// Test creating UDP transport
	udpTransport, err := transport.NewTransport(transport.TransportTypeUDP, map[string]interface{}{"port": 4442})
	require.NoError(t, err)
	assert.NotNil(t, udpTransport)
	// Start transport before stopping
	err = udpTransport.Start(func(addr net.Addr, data []byte) error { return nil })
	require.NoError(t, err)
	defer udpTransport.Stop()

	// Test creating unsupported transport
	_, err = transport.NewTransport("unsupported", nil)
	assert.Error(t, err)
}
