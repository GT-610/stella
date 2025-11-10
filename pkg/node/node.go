package node

import (
	"errors"
	"fmt"
	"sync"

	"github.com/stella/virtual-switch/pkg/identity"
)

// NodeState represents the current state of a node
type NodeState int

const (
	// NodeStateStopped means the node is not running
	NodeStateStopped NodeState = iota
	// NodeStateStarting means the node is in the process of starting up
	NodeStateStarting
	// NodeStateRunning means the node is fully operational
	NodeStateRunning
	// NodeStateStopping means the node is in the process of shutting down
	NodeStateStopping
	// NodeStateError means the node encountered an error
	NodeStateError
)

// String returns the string representation of the node state
func (s NodeState) String() string {
	switch s {
	case NodeStateStopped:
		return "STOPPED"
	case NodeStateStarting:
		return "STARTING"
	case NodeStateRunning:
		return "RUNNING"
	case NodeStateStopping:
		return "STOPPING"
	case NodeStateError:
		return "ERROR"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// Node represents a Stella virtual switch node
type Node struct {
	// ID is a unique identifier for the node
	ID string

	// Identity contains the node's cryptographic identity
	Identity *identity.Identity

	// State represents the current state of the node
	State NodeState

	// mu protects concurrent access to the node
	mu sync.RWMutex

	// shutdownChan is used to signal shutdown to goroutines
	shutdownChan chan struct{}

	// err holds the last error encountered by the node
	err error
}

// NewNode creates a new Stella node with the given identity
func NewNode(id string, identity *identity.Identity) (*Node, error) {
	if identity == nil {
		return nil, errors.New("identity cannot be nil")
	}

	if id == "" {
		// Generate a default ID based on the node's address
		id = fmt.Sprintf("node-%s", identity.Address.String())
	}

	return &Node{
		ID:           id,
		Identity:     identity,
		State:        NodeStateStopped,
		shutdownChan: make(chan struct{}),
	}, nil
}

// GetState returns the current state of the node
func (n *Node) GetState() NodeState {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.State
}

// SetState sets the state of the node
func (n *Node) SetState(state NodeState) {
	n.mu.Lock()
	n.State = state
	n.mu.Unlock()
}

// GetError returns the last error encountered by the node
func (n *Node) GetError() error {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.err
}

// SetError sets the error state for the node
func (n *Node) SetError(err error) {
	n.mu.Lock()
	n.err = err
	n.State = NodeStateError
	n.mu.Unlock()
}

// IsRunning returns true if the node is in the RUNNING state
func (n *Node) IsRunning() bool {
	return n.GetState() == NodeStateRunning
}

// IsStopped returns true if the node is in the STOPPED state
func (n *Node) IsStopped() bool {
	return n.GetState() == NodeStateStopped
}
