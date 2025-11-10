package node

import (
	"errors"
	"sync"
	"time"
)

// Start begins the node initialization and startup process
func (n *Node) Start(config *Config) error {
	// Check if the node is already running
	if n.IsRunning() {
		return errors.New("node is already running")
	}

	// Check if the node is in the process of stopping
	if n.GetState() == NodeStateStopping {
		return errors.New("node is in the process of stopping")
	}

	// Create a new logger for the node
	logger := NewLogger(n.ID, config.LogLevel)
	logger.Info("Starting node...")

	// Update state to starting
	n.SetState(NodeStateStarting)

	// Reset shutdown channel
	n.mu.Lock()
	if n.shutdownChan != nil {
		close(n.shutdownChan)
	}
	n.shutdownChan = make(chan struct{})
	n.mu.Unlock()

	// Create wait group for all goroutines
	var wg sync.WaitGroup

	// Simulate initialization tasks
	logger.Debug("Initializing node components...")

	// Add a small delay to simulate initialization
	time.Sleep(100 * time.Millisecond)

	// Start main node loop in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		n.runMainLoop(logger)
	}()

	// Update state to running
	n.SetState(NodeStateRunning)
	logger.Info("Node started successfully")

	return nil
}

// Stop begins the node shutdown process
func (n *Node) Stop() error {
	// Check if the node is already stopped
	if n.IsStopped() {
		return errors.New("node is already stopped")
	}

	// Check if the node is already stopping
	if n.GetState() == NodeStateStopping {
		return errors.New("node is already stopping")
	}

	// Create a logger for shutdown messages
	logger := NewLogger(n.ID, "info")
	logger.Info("Stopping node...")

	// Update state to stopping
	n.SetState(NodeStateStopping)

	// Signal shutdown
	n.mu.Lock()
	if n.shutdownChan != nil {
		close(n.shutdownChan)
		n.shutdownChan = nil
	}
	n.mu.Unlock()

	// Simulate cleanup tasks
	logger.Debug("Cleaning up node resources...")

	// Add a small delay to simulate cleanup
	time.Sleep(100 * time.Millisecond)

	// Update state to stopped
	n.SetState(NodeStateStopped)
	logger.Info("Node stopped successfully")

	return nil
}

// runMainLoop runs the main processing loop for the node
func (n *Node) runMainLoop(logger *Logger) {
	logger.Debug("Main loop started")

	// Create a ticker for periodic tasks
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Main loop
	for {
		select {
		case <-ticker.C:
			// Perform periodic tasks
			logger.Debug("Performing periodic maintenance")

		case <-n.shutdownChan:
			// Received shutdown signal
			logger.Debug("Received shutdown signal, exiting main loop")
			return
		}
	}
}

// ShutdownWithTimeout attempts to gracefully shutdown the node within the specified timeout
func (n *Node) ShutdownWithTimeout(timeout time.Duration) error {
	// Start the shutdown process
	err := n.Stop()
	if err != nil {
		return err
	}

	// Wait for the node to reach stopped state or timeout
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			return errors.New("shutdown timed out")
		default:
			if n.IsStopped() {
				return nil
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// ForceStop forces the node to stop immediately without waiting for graceful shutdown
func (n *Node) ForceStop() {
	logger := NewLogger(n.ID, "info")
	logger.Warn("Forcing node to stop immediately")

	// Signal shutdown
	n.mu.Lock()
	if n.shutdownChan != nil {
		close(n.shutdownChan)
		n.shutdownChan = nil
	}
	n.mu.Unlock()

	// Set state to stopped without waiting for cleanup
	n.SetState(NodeStateStopped)
	logger.Info("Node forcefully stopped")
}
