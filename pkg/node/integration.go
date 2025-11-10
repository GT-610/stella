package node

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/stella/virtual-switch/pkg/identity"
)

// IntegratedNode represents a fully integrated node with all components connected
// This module combines identity, configuration, logging, and lifecycle management

// CreateAndInitNode creates a new node, initializes it with a new identity,
// and loads/saves configuration
func CreateAndInitNode(configFile string) (*Node, *Config, error) {
	// Load existing configuration or create a new one
	config, err := LoadConfig(configFile)
	if err != nil {
		// If config file doesn't exist, create a default config
		if os.IsNotExist(err) {
			// Ensure directory exists
			configDir := filepath.Dir(configFile)
			err := os.MkdirAll(configDir, 0755)
			if err != nil {
				return nil, nil, err
			}

			// Create default config
			config = DefaultConfig()
			config.ConfigFile = configFile
			config.DataDir = filepath.Join(configDir, "data")
			config.IdentityFile = filepath.Join(configDir, "identity.json")
		} else {
			return nil, nil, err
		}
	}

	// Ensure data directory exists
	err = os.MkdirAll(config.DataDir, 0755)
	if err != nil {
		return nil, nil, err
	}

	// Load existing identity or create a new one
	var id *identity.Identity

	// Try to load existing identity
	if config.IdentityFile != "" {
		id, err = config.LoadIdentity()
		if err != nil {
			// If identity doesn't exist, create a new one
			if os.IsNotExist(err) {
				id, err = identity.NewIdentity()
				if err != nil {
					return nil, nil, err
				}

				// Save the new identity
				err = config.SaveIdentity(id)
				if err != nil {
					return nil, nil, err
				}
			} else {
				return nil, nil, err
			}
		}
	} else {
		// Create a new identity if no identity file is specified
		id, err = identity.NewIdentity()
		if err != nil {
			return nil, nil, err
		}
	}

	// Create node with the identity
	n, err := NewNode(config.NodeID, id)
	if err != nil {
		return nil, nil, err
	}

	// Save the configuration if it's new
	if !fileExists(configFile) {
		err = config.Save()
		if err != nil {
			return nil, nil, err
		}
	}

	return n, config, nil
}

// RunNodeWithConfig runs a node with the specified configuration
// It handles initialization, starting, and cleanup
func RunNodeWithConfig(configFile string) (*Node, error) {
	// Create and initialize the node
	n, config, err := CreateAndInitNode(configFile)
	if err != nil {
		return nil, err
	}

	// Start the node
	err = n.Start(config)
	if err != nil {
		return nil, err
	}

	return n, nil
}

// ShutdownNode gracefully shuts down the node and saves any necessary state
func ShutdownNode(n *Node, config *Config) error {
	if n == nil {
		return errors.New("node is nil")
	}

	if config == nil {
		return errors.New("config is nil")
	}

	// Save configuration before shutdown
	err := config.Save()
	if err != nil {
		// Log error but continue with shutdown
		logger := NewLogger(n.ID, config.LogLevel)
		logger.Error("Failed to save configuration: " + err.Error())
	}

	// Stop the node
	return n.Stop()
}

// Helper function to check if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetNodeStatus returns a comprehensive status report for the node
func GetNodeStatus(n *Node) map[string]interface{} {
	status := make(map[string]interface{})

	if n == nil {
		status["error"] = "node is nil"
		return status
	}

	status["id"] = n.ID
	status["state"] = n.GetState().String()
	status["isRunning"] = n.IsRunning()
	status["isStopped"] = n.IsStopped()

	err := n.GetError()
	if err != nil {
		status["error"] = err.Error()
	} else {
		status["error"] = nil
	}

	if n.Identity != nil {
		status["identity"] = map[string]interface{}{
			"address":   n.Identity.Address.String(),
			"publicKey": string(n.Identity.PublicKey),
		}
	}

	return status
}
