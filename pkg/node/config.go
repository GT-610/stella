package node

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/stella/virtual-switch/pkg/identity"
)

// Config represents the configuration for a Stella node
type Config struct {
	// NodeID is the unique identifier for this node
	NodeID string `json:"node_id"`

	// DataDir is the directory where node data is stored
	DataDir string `json:"data_dir"`

	// ConfigFile is the path to the configuration file
	ConfigFile string `json:"config_file"`

	// IdentityFile is the path to the identity file
	IdentityFile string `json:"identity_file"`

	// LogLevel determines the verbosity of logging
	LogLevel string `json:"log_level"`

	// BindAddr is the address the node listens on
	BindAddr string `json:"bind_addr"`

	// ControllerURL is the URL of the controller if using one
	ControllerURL string `json:"controller_url"`

	// AutoStart indicates whether the node should start automatically
	AutoStart bool `json:"auto_start"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	dataDir := filepath.Join(homeDir, ".stella")
	configFile := filepath.Join(dataDir, "config.json")
	identityFile := filepath.Join(dataDir, "identity.json")

	return &Config{
		NodeID:        "", // Will be generated from identity
		DataDir:       dataDir,
		ConfigFile:    configFile,
		IdentityFile:  identityFile,
		LogLevel:      "info",
		BindAddr:      ":9993",
		ControllerURL: "",
		AutoStart:     false,
	}
}

// LoadConfig loads configuration from the specified file
func LoadConfig(filePath string) (*Config, error) {
	// If no file path is specified, use the default
	if filePath == "" {
		return DefaultConfig(), nil
	}

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, errors.New("config file not found")
	}

	// Read the file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Parse the config
	config := &Config{}
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	// Ensure config paths are valid
	if config.DataDir == "" {
		config.DataDir = filepath.Dir(filePath)
	}

	if config.IdentityFile == "" {
		config.IdentityFile = filepath.Join(config.DataDir, "identity.json")
	}

	return config, nil
}

// Save saves the configuration to the specified file
func (c *Config) Save() error {
	// Ensure the directory exists
	dir := filepath.Dir(c.ConfigFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Marshal the config to JSON
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	return ioutil.WriteFile(c.ConfigFile, data, 0600)
}

// LoadIdentity loads the node identity from the configured identity file
func (c *Config) LoadIdentity() (*identity.Identity, error) {
	// Check if the identity file exists
	if _, err := os.Stat(c.IdentityFile); os.IsNotExist(err) {
		// Create a new identity if the file doesn't exist
		identity, err := identity.NewIdentity()
		if err != nil {
			return nil, err
		}

		// Save the new identity
		err = c.SaveIdentity(identity)
		if err != nil {
			return nil, err
		}

		return identity, nil
	}

	// Read the identity file
	data, err := ioutil.ReadFile(c.IdentityFile)
	if err != nil {
		return nil, err
	}

	// Parse the identity
	identity := &identity.Identity{}
	err = json.Unmarshal(data, identity)
	if err != nil {
		return nil, err
	}

	return identity, nil
}

// SaveIdentity saves the node identity to the configured identity file
func (c *Config) SaveIdentity(identity *identity.Identity) error {
	// Ensure the directory exists
	dir := filepath.Dir(c.IdentityFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Marshal the identity to JSON
	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return err
	}

	// Write to file with restrictive permissions
	return ioutil.WriteFile(c.IdentityFile, data, 0600)
}
