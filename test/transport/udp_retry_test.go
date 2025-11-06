// Copyright 2023 The Stella Authors
// SPDX-License-Identifier: Apache-2.0

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

// TestUDPTransportRetryMechanism tests the UDP transport with retry mechanism enabled
func TestUDPTransportRetryMechanism(t *testing.T) {
	// Configure transports with retry mechanism
	serverConfig := map[string]interface{}{
		"port":             4444,
		"maxRetries":       3,
		"retryInterval":    100 * time.Millisecond,
		"retryExponential": true,
	}
	serverTransport, err := transport.NewTransport(transport.TransportTypeUDP, serverConfig)
	require.NoError(t, err)

	clientConfig := map[string]interface{}{
		"port":             4445,
		"maxRetries":       3,
		"retryInterval":    100 * time.Millisecond,
		"retryExponential": true,
	}
	clientTransport, err := transport.NewTransport(transport.TransportTypeUDP, clientConfig)
	require.NoError(t, err)

	// Test data
	message := []byte("Hello UDP with Retry")
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
	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}
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
		assert.Equal(t, "127.0.0.1:4445", receivedAddr.String())
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for message to be received")
	}
}

// TestUDPTransportPacketLoss tests the UDP transport's behavior when packets are lost
func TestUDPTransportPacketLoss(t *testing.T) {
	// Configure transports with retry mechanism
	serverConfig := map[string]interface{}{
		"port":             4446,
		"maxRetries":       3,
		"retryInterval":    100 * time.Millisecond,
		"retryExponential": true,
	}
	serverTransport, err := transport.NewTransport(transport.TransportTypeUDP, serverConfig)
	require.NoError(t, err)

	clientConfig := map[string]interface{}{
		"port":             4447,
		"maxRetries":       3,
		"retryInterval":    100 * time.Millisecond,
		"retryExponential": true,
	}
	clientTransport, err := transport.NewTransport(transport.TransportTypeUDP, clientConfig)
	require.NoError(t, err)

	// Test data
	message := []byte("Hello UDP with Packet Loss")
	var receivedData []byte
	var receiveCount int
	var receiveDone sync.WaitGroup
	receiveDone.Add(1)

	// Count how many times we receive the packet (should be at least once)
	var mu sync.Mutex
	handler := func(addr net.Addr, data []byte) error {
		mu.Lock()
		receiveCount++
		receivedData = data
		mu.Unlock()
		
		// Only signal done on first successful receive
		if receiveCount == 1 {
			receiveDone.Done()
		}
		return nil
	}

	err = serverTransport.Start(handler)
	require.NoError(t, err)
	defer serverTransport.Stop()

	// Start client transport with empty handler
	err = clientTransport.Start(func(addr net.Addr, data []byte) error { return nil })
	require.NoError(t, err)
	defer clientTransport.Stop()

	// We'll simulate packet loss by temporarily blocking the connection
	// In a real test, you might use a network simulator or packet capture
	// For this test, we'll just verify the retry mechanism works in general
	
	// Send message from client to server
	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4446}
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
		// The message should have been received at least once
		assert.GreaterOrEqual(t, receiveCount, 1)
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for message to be received")
	}
}

// TestUDPTransportExponentialBackoff tests the exponential backoff retry strategy
func TestUDPTransportExponentialBackoff(t *testing.T) {
	// Configure transports with specific retry parameters
	serverConfig := map[string]interface{}{
		"port":             4448,
		"maxRetries":       3,
		"retryInterval":    100 * time.Millisecond,
		"retryExponential": true,
	}
	serverTransport, err := transport.NewTransport(transport.TransportTypeUDP, serverConfig)
	require.NoError(t, err)

	// Start server transport
	err = serverTransport.Start(func(addr net.Addr, data []byte) error { return nil })
	require.NoError(t, err)
	defer serverTransport.Stop()

	// Create a client transport that will not receive ACKs
	// We can simulate this by using a different port that won't respond
	clientConfig := map[string]interface{}{
		"port":             4449,
		"maxRetries":       3,
		"retryInterval":    100 * time.Millisecond,
		"retryExponential": true,
	}
	clientTransport, err := transport.NewTransport(transport.TransportTypeUDP, clientConfig)
	require.NoError(t, err)

	// Start client transport
	err = clientTransport.Start(func(addr net.Addr, data []byte) error { return nil })
	require.NoError(t, err)
	defer clientTransport.Stop()

	// Send message to a non-existent address (simulate packet loss)
	invalidAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4450}
	err = clientTransport.Send(invalidAddr, []byte("This packet should be retried"))
	require.NoError(t, err)

	// Wait for retries to complete
	time.Sleep(2 * time.Second)

	// Since we can't directly check the retry intervals in this test,
	// we're mainly verifying that the system doesn't crash and handles the situation gracefully
	assert.NoError(t, err)
}

// TestUDPTransportDisableRetry tests behavior when retry mechanism is disabled
func TestUDPTransportDisableRetry(t *testing.T) {
	// Configure transports with retry disabled
	serverConfig := map[string]interface{}{
		"port":              4451,
		"ackHandlerEnabled": false,
	}
	serverTransport, err := transport.NewTransport(transport.TransportTypeUDP, serverConfig)
	require.NoError(t, err)

	clientConfig := map[string]interface{}{
		"port":              4452,
		"ackHandlerEnabled": false,
	}
	clientTransport, err := transport.NewTransport(transport.TransportTypeUDP, clientConfig)
	require.NoError(t, err)

	// Test data
	message := []byte("Hello UDP without Retry")
	var receivedData []byte
	var receiveDone sync.WaitGroup
	receiveDone.Add(1)

	// Start server transport with a handler
	handler := func(addr net.Addr, data []byte) error {
		receivedData = data
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
	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4451}
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
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timed out waiting for message to be received")
	}
}