package transport

import (
	"net"
	"time"
)

// ConnectionState represents the state of a transport connection
type ConnectionState int

const (
	// StateDisconnected represents a connection that is not established
	StateDisconnected ConnectionState = iota
	// StateConnecting represents a connection that is being established
	StateConnecting
	// StateConnected represents a connection that is fully established
	StateConnected
	// StateDisconnecting represents a connection that is being terminated
	StateDisconnecting
)

// String returns the string representation of the connection state
func (s ConnectionState) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateDisconnecting:
		return "disconnecting"
	default:
		return "unknown"
	}
}

// PacketHandler is a function type for handling received packets
// from the transport layer
// srcAddr is the source address of the packet
// data is the raw packet data
// Returns an error if handling the packet failed

type PacketHandler func(srcAddr net.Addr, data []byte) error

// Transport represents the abstract interface for transport protocols
// It provides a common interface for different transport implementations
// (UDP, TCP, etc.) to send and receive packets

type Transport interface {
	// Init initializes the transport with the given configuration
	// config is a map containing implementation-specific configuration
	// Returns an error if initialization failed
	Init(config map[string]interface{}) error

	// Start begins listening for packets on the transport
	// handler is the function to call when a packet is received
	// Returns an error if starting the transport failed
	Start(handler PacketHandler) error

	// Stop shuts down the transport and releases resources
	// Returns an error if stopping the transport failed
	Stop() error

	// Send sends a packet to the specified address
	// dstAddr is the destination address
	// data is the raw packet data to send
	// Returns an error if sending the packet failed
	Send(dstAddr net.Addr, data []byte) error

	// GetState returns the current state of the transport
	GetState() ConnectionState

	// SetReadTimeout sets the read timeout for the transport
	// timeout is the duration to wait for a packet before timing out
	// Returns an error if setting the timeout failed
	SetReadTimeout(timeout time.Duration) error

	// SetWriteTimeout sets the write timeout for the transport
	// timeout is the duration to wait for a send operation to complete
	// Returns an error if setting the timeout failed
	SetWriteTimeout(timeout time.Duration) error

	// GetLocalAddr returns the local address the transport is bound to
	// Returns nil if the transport is not bound to any address
	GetLocalAddr() net.Addr
}

// Connection represents a specific connection between two endpoints
// It provides more fine-grained control over a specific connection

type Connection interface {
	// Connect establishes a connection to the remote address
	// remoteAddr is the address of the remote endpoint
	// Returns an error if the connection failed
	Connect(remoteAddr net.Addr) error

	// Disconnect terminates the connection
	// Returns an error if disconnection failed
	Disconnect() error

	// Send sends data over the connection
	// data is the raw data to send
	// Returns an error if sending failed
	Send(data []byte) error

	// Receive receives data from the connection
	// buffer is the buffer to store the received data
	// Returns the number of bytes received and any error
	Receive(buffer []byte) (int, error)

	// GetState returns the current state of the connection
	GetState() ConnectionState

	// GetRemoteAddr returns the remote address of the connection
	GetRemoteAddr() net.Addr

	// GetLocalAddr returns the local address of the connection
	GetLocalAddr() net.Addr

	// SetReadTimeout sets the read timeout for the connection
	SetReadTimeout(timeout time.Duration) error

	// SetWriteTimeout sets the write timeout for the connection
	SetWriteTimeout(timeout time.Duration) error
}

// ConnectionManager manages multiple connections
// It provides functions to create, get, and close connections

type ConnectionManager interface {
	// CreateConnection creates a new connection to the specified address
	// remoteAddr is the address of the remote endpoint
	// Returns the new connection and any error
	CreateConnection(remoteAddr net.Addr) (Connection, error)

	// GetConnection gets an existing connection to the specified address
	// remoteAddr is the address of the remote endpoint
	// Returns the connection if it exists, nil otherwise
	GetConnection(remoteAddr net.Addr) Connection

	// CloseConnection closes the connection to the specified address
	// remoteAddr is the address of the remote endpoint
	// Returns an error if closing the connection failed
	CloseConnection(remoteAddr net.Addr) error

	// CloseAllConnections closes all active connections
	// Returns an error if any connection failed to close
	CloseAllConnections() error

	// GetConnections returns all active connections
	GetConnections() []Connection

	// AddConnectionListener adds a listener for connection events
	// listener is the function to call when a connection event occurs
	AddConnectionListener(listener ConnectionListener)

	// RemoveConnectionListener removes a connection event listener
	// listener is the function to remove
	RemoveConnectionListener(listener ConnectionListener)
}

// ConnectionEvent represents an event that occurs on a connection

type ConnectionEvent int

const (
	// EventConnected is fired when a connection is established
	EventConnected ConnectionEvent = iota
	// EventDisconnected is fired when a connection is terminated
	EventDisconnected
	// EventDataReceived is fired when data is received on a connection
	EventDataReceived
	// EventError is fired when an error occurs on a connection
	EventError
)

// String returns the string representation of the connection event
func (e ConnectionEvent) String() string {
	switch e {
	case EventConnected:
		return "connected"
	case EventDisconnected:
		return "disconnected"
	case EventDataReceived:
		return "data_received"
	case EventError:
		return "error"
	default:
		return "unknown"
	}
}

// ConnectionListener is a function type for handling connection events
// conn is the connection that the event occurred on
// event is the type of event that occurred
// data is optional data associated with the event (e.g., received data)
// err is an error if the event is an error event

type ConnectionListener func(conn Connection, event ConnectionEvent, data []byte, err error)

// TransportError represents an error that occurs in the transport layer

type TransportError struct {
	// Message is a description of the error
	Message string
	// Code is an error code for the specific error type
	Code int
	// Underlying is the underlying error that caused this error
	Underlying error
}

// Error returns the string representation of the transport error
func (e *TransportError) Error() string {
	return e.Message
}

// Unwrap returns the underlying error
func (e *TransportError) Unwrap() error {
	return e.Underlying
}

// NewTransportError creates a new transport error
func NewTransportError(message string, code int, underlying error) *TransportError {
	return &TransportError{
		Message:    message,
		Code:       code,
		Underlying: underlying,
	}
}
