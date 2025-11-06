// Copyright 2023 The Stella Authors
// SPDX-License-Identifier: Apache-2.0

package node_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stella/virtual-switch/pkg/identity"
	"github.com/stella/virtual-switch/pkg/node"
)

func TestNodeCreation(t *testing.T) {
	// Create a new identity
	id, err := identity.NewIdentity()
	assert.NoError(t, err)
	assert.NotNil(t, id)

	// Test creating a node with a custom ID
	n, err := node.NewNode("test-node", id)
	assert.NoError(t, err)
	assert.NotNil(t, n)
	assert.Equal(t, "test-node", n.ID)
	assert.Equal(t, id, n.Identity)
	assert.Equal(t, node.NodeStateStopped, n.GetState())

	// Test creating a node with an empty ID (should generate from identity)
	n2, err := node.NewNode("", id)
	assert.NoError(t, err)
	assert.NotNil(t, n2)
	assert.Equal(t, "node-"+id.Address.String(), n2.ID)

	// Test creating a node with a nil identity
	n3, err := node.NewNode("test-node", nil)
	assert.Error(t, err)
	assert.Nil(t, n3)
}

func TestNodeStateManagement(t *testing.T) {
	// Create a new node
	id, _ := identity.NewIdentity()
	n, _ := node.NewNode("test-node", id)

	// Test initial state
	assert.Equal(t, node.NodeStateStopped, n.GetState())
	assert.True(t, n.IsStopped())
	assert.False(t, n.IsRunning())

	// Test setting state
	n.SetState(node.NodeStateStarting)
	assert.Equal(t, node.NodeStateStarting, n.GetState())
	assert.False(t, n.IsStopped())
	assert.False(t, n.IsRunning())

	n.SetState(node.NodeStateRunning)
	assert.Equal(t, node.NodeStateRunning, n.GetState())
	assert.False(t, n.IsStopped())
	assert.True(t, n.IsRunning())

	n.SetState(node.NodeStateStopping)
	assert.Equal(t, node.NodeStateStopping, n.GetState())
	assert.False(t, n.IsStopped())
	assert.False(t, n.IsRunning())

	// Test error state
	n.SetError(os.ErrInvalid)
	assert.Equal(t, node.NodeStateError, n.GetState())
	assert.Equal(t, os.ErrInvalid, n.GetError())
}

func TestConfigManagement(t *testing.T) {
	// Test default config
	defaultConfig := node.DefaultConfig()
	assert.NotNil(t, defaultConfig)
	assert.Equal(t, "info", defaultConfig.LogLevel)
	assert.Equal(t, ":9993", defaultConfig.BindAddr)

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "stella-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a test config file
	configFile := filepath.Join(tempDir, "config.json")
	testConfig := &node.Config{
		NodeID:        "test-config-node",
		DataDir:       tempDir,
		ConfigFile:    configFile,
		LogLevel:      "debug",
		BindAddr:      ":12345",
		ControllerURL: "http://localhost:8080",
		AutoStart:     true,
	}

	// Test saving config
	err = testConfig.Save()
	assert.NoError(t, err)

	// Test loading config
	loadedConfig, err := node.LoadConfig(configFile)
	assert.NoError(t, err)
	assert.NotNil(t, loadedConfig)
	assert.Equal(t, testConfig.NodeID, loadedConfig.NodeID)
	assert.Equal(t, testConfig.LogLevel, loadedConfig.LogLevel)
	assert.Equal(t, testConfig.BindAddr, loadedConfig.BindAddr)

	// Test loading non-existent config
	_, err = node.LoadConfig(filepath.Join(tempDir, "non-existent.json"))
	assert.Error(t, err)

	// Test identity saving and loading
	newIdentity, err := identity.NewIdentity()
	assert.NoError(t, err)

	// Set identity file path
	testConfig.IdentityFile = filepath.Join(tempDir, "identity.json")

	// Save identity
	err = testConfig.SaveIdentity(newIdentity)
	assert.NoError(t, err)

	// Load identity
	loadedIdentity, err := testConfig.LoadIdentity()
	assert.NoError(t, err)
	assert.NotNil(t, loadedIdentity)
	assert.NotNil(t, loadedIdentity.Address)
}

func TestLogger(t *testing.T) {
	// Create a logger with debug level
	logger := node.NewLogger("test-logger", "debug")
	assert.NotNil(t, logger)

	// Test log level setting
	logger.SetLevel("info")

	// These won't produce visible output in tests, but we can verify the methods exist
	logger.Debug("This is a debug message")
	logger.Info("This is an info message")
	logger.Warn("This is a warning message")
	logger.Error("This is an error message")

	// We won't actually call Fatal as it would exit the test
}

func TestNodeLifecycle(t *testing.T) {
	// Create a new identity and node
	id, _ := identity.NewIdentity()
	n, _ := node.NewNode("test-lifecycle-node", id)

	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "stella-lifecycle-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a config
	config := node.DefaultConfig()
	config.DataDir = tempDir
	config.ConfigFile = filepath.Join(tempDir, "config.json")
	config.IdentityFile = filepath.Join(tempDir, "identity.json")

	// Test starting the node
	err = n.Start(config)
	assert.NoError(t, err)
	assert.Equal(t, node.NodeStateRunning, n.GetState())

	// Allow some time for the main loop to start
	time.Sleep(150 * time.Millisecond)

	// Test stopping the node
	err = n.Stop()
	assert.NoError(t, err)
	assert.Equal(t, node.NodeStateStopped, n.GetState())

	// Test stopping an already stopped node
	err = n.Stop()
	assert.Error(t, err)

	// Test starting the node again
	err = n.Start(config)
	assert.NoError(t, err)
	assert.Equal(t, node.NodeStateRunning, n.GetState())

	// Test force stop
	n.ForceStop()
	assert.Equal(t, node.NodeStateStopped, n.GetState())
}