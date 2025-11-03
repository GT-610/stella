// Package identity provides identity authentication functionality for Stella network
package identity

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/stella/virtual-switch/pkg/address"
	"github.com/stella/virtual-switch/pkg/crypto"
)

// Identity represents the identity information of a Stella node
type Identity struct {
	Address    *address.Address // Node address
	PublicKey  []byte           // Public key
	PrivateKey []byte           // Private key (optional, used only for local storage)
}

// NewIdentity generates a new identity
func NewIdentity() (*Identity, error) {
	// Generate key pair
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Derive address from public key
	addr := address.NewAddressFromPublicKey(keyPair.Public)

	return &Identity{
		Address:    addr,
		PublicKey:  keyPair.Public,
		PrivateKey: keyPair.Private,
	}, nil
}

// NewIdentityFromPublic creates an identity from a public key (without private key)
func NewIdentityFromPublic(publicKey []byte) (*Identity, error) {
	if len(publicKey) == 0 {
		return nil, errors.New("empty public key")
	}

	// Derive address from public key
	addr := address.NewAddressFromPublicKey(publicKey)

	return &Identity{
		Address:   addr,
		PublicKey: publicKey,
	}, nil
}

// NewIdentityFromString creates an identity from a string representation
// Format: <address>:<base64-encoded-public-key>:<base64-encoded-private-key>
// Private key part is optional
func NewIdentityFromString(s string) (*Identity, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, errors.New("invalid identity string format")
	}

	// Parse address
	addr, err := address.NewAddressFromString(parts[0])
	if err != nil {
		return nil, err
	}

	// Parse public key
	publicKey, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	identity := &Identity{
		Address:   addr,
		PublicKey: publicKey,
	}

	// Parse private key if provided
	if len(parts) == 3 && parts[2] != "" {
		privateKey, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, err
		}
		identity.PrivateKey = privateKey
	}

	return identity, nil
}

// Serialize serializes the identity to a string
func (id *Identity) Serialize() string {
	result := id.Address.String() + ":" + base64.StdEncoding.EncodeToString(id.PublicKey)
	
	// Include private key only if available
	if len(id.PrivateKey) > 0 {
		result += ":" + base64.StdEncoding.EncodeToString(id.PrivateKey)
	}
	
	return result
}

// HasPrivateKey checks if the identity contains a private key
func (id *Identity) HasPrivateKey() bool {
	return len(id.PrivateKey) > 0
}

// Validate validates the identity
// Checks if the address matches the public key
func (id *Identity) Validate() bool {
	// Recalculate address from public key
	computedAddr := address.NewAddressFromPublicKey(id.PublicKey)
	
	// Compare computed address with stored address
	return id.Address.Equals(computedAddr)
}

// GetSharedSecret computes a shared secret with another identity
func (id *Identity) GetSharedSecret(other *Identity) ([]byte, error) {
	if !id.HasPrivateKey() {
		return nil, errors.New("identity has no private key")
	}
	
	return crypto.DeriveSharedSecret(id.PrivateKey, other.PublicKey)
}

// String returns a string representation of the identity
func (id *Identity) String() string {
	// For security, private key is not included by default
	return id.Address.String() + ":" + hex.EncodeToString(id.PublicKey[:8]) + "..."
}