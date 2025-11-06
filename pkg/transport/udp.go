// Copyright 2023 The Stella Authors
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"net"
	"sync"
	"time"
)

// UDPTransport implements the Transport interface using UDP

type UDPTransport struct {
	BaseTransport
	conn       *net.UDPConn
	listenAddr *net.UDPAddr
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	bufferSize int
}

// NewUDPTransport creates a new UDP transport instance
func NewUDPTransport() *UDPTransport {
	t := &UDPTransport{
		BaseTransport: *NewBaseTransport(),
		bufferSize:    4096,
	}
	return t
}

// Init initializes the UDP transport
func (t *UDPTransport) Init(config map[string]interface{}) error {
	// Default to port 4433
	t.listenAddr = &net.UDPAddr{
		Port: 4433,
		IP:   net.ParseIP("0.0.0.0"),
	}
	
	// Apply config if provided
	if port, ok := config["port"].(int); ok {
		t.listenAddr.Port = port
	}
	
	if bufferSize, ok := config["bufferSize"].(int); ok && bufferSize > 0 {
		t.bufferSize = bufferSize
	}
	
	return nil
}

// Start begins listening for UDP packets
func (t *UDPTransport) Start(handler PacketHandler) error {
	// Create context
	t.ctx, t.cancel = context.WithCancel(context.Background())
	
	// Bind UDP socket
	conn, err := net.ListenUDP("udp", t.listenAddr)
	if err != nil {
		t.cancel()
		return NewTransportError("failed to bind UDP port", 3001, err)
	}
	
	t.conn = conn
	t.setLocalAddr(conn.LocalAddr())
	
	// Set handler and state
	if err := t.BaseTransport.Start(handler); err != nil {
		t.conn.Close()
		t.cancel()
		return err
	}
	
	// Start receive loop
	t.wg.Add(1)
	go t.receiveLoop()
	
	return nil
}

// Stop shuts down the transport
func (t *UDPTransport) Stop() error {
	if err := t.BaseTransport.Stop(); err != nil {
		return err
	}
	
	t.cancel()
	if t.conn != nil {
		t.conn.Close()
	}
	t.wg.Wait()
	
	return nil
}

// Send sends a UDP packet
func (t *UDPTransport) Send(dstAddr net.Addr, data []byte) error {
	if t.isClosed() {
		return NewTransportError("transport is closed", 3002, nil)
	}
	
	// Resolve UDP address
	udpAddr, ok := dstAddr.(*net.UDPAddr)
	if !ok {
		resolvedAddr, err := net.ResolveUDPAddr("udp", dstAddr.String())
		if err != nil {
			return NewTransportError("invalid destination address", 3003, err)
		}
		udpAddr = resolvedAddr
	}
	
	// Set write deadline
	writeTimeout := t.getWriteTimeout()
	if writeTimeout > 0 {
		t.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	}
	
	// Send data
	_, err := t.conn.WriteToUDP(data, udpAddr)
	if err != nil {
		return NewTransportError("failed to send UDP packet", 3005, err)
	}
	
	return nil
}

// receiveLoop handles incoming packets
func (t *UDPTransport) receiveLoop() {
	defer t.wg.Done()
	buffer := make([]byte, t.bufferSize)
	
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
			// Set read deadline
		readTimeout := t.getReadTimeout()
		if readTimeout > 0 {
			t.conn.SetReadDeadline(time.Now().Add(readTimeout))
		} else {
			t.conn.SetReadDeadline(time.Time{})
		}
			
			// Read packet
			n, addr, err := t.conn.ReadFromUDP(buffer)
			if err != nil {
				// Handle timeouts
				if netErr, ok := err.(net.Error); ok && (netErr.Timeout() || t.ctx.Err() != nil) {
					continue
				}
				// Other errors may indicate a serious problem
				// Just log the error for now as handler only takes addr and data
				continue
			}
			
			if n > 0 {
				// Copy data and call handler
				data := make([]byte, n)
				copy(data, buffer[:n])
				
				handler := t.getHandler()
				if handler != nil {
					handler(addr, data)
				}
			}
		}
	}
}