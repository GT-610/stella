// Package address provides address representation functionality for Stella network
package address

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/stella/virtual-switch/pkg/crypto"
)

const (
	// AddressLength ZeroTier address length in bytes
	AddressLength = 5
)

// Address represents a ZeroTier-style 5-byte address
type Address struct {
	bytes [AddressLength]byte
}

// NewAddressFromString creates an address from a hexadecimal string
func NewAddressFromString(s string) (*Address, error) {
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != AddressLength*2 {
		return nil, errors.New("invalid address length")
	}

	bytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	addr := &Address{}
	copy(addr.bytes[:], bytes)
	return addr, nil
}

// NewAddressFromBytes creates an address from a byte array
func NewAddressFromBytes(b []byte) (*Address, error) {
	if len(b) != AddressLength {
		return nil, errors.New("invalid address length")
	}

	addr := &Address{}
	copy(addr.bytes[:], b)
	return addr, nil
}

// NewAddressFromPublicKey derives an address from a public key
// This is a core ZeroTier feature where addresses are directly derived from public keys
func NewAddressFromPublicKey(publicKey []byte) *Address {
	// Hash the key
	hash := crypto.Hash(publicKey)

	// Take the first 5 bytes of the hash as the address
	addr := &Address{}
	copy(addr.bytes[:], hash[:AddressLength])

	return addr
}

// Bytes returns the byte representation of the address
func (a *Address) Bytes() []byte {
	b := make([]byte, AddressLength)
	copy(b, a.bytes[:])
	return b
}

// String returns the hexadecimal string representation of the address
func (a *Address) String() string {
	return fmt.Sprintf("%02x%02x%02x%02x%02x", 
		a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3], a.bytes[4])
}

// Compare compares two addresses and returns -1, 0, or 1 if the receiver is less than, equal to, or greater than the other
func (a *Address) Compare(other *Address) int {
	for i := 0; i < AddressLength; i++ {
		if a.bytes[i] < other.bytes[i] {
			return -1
		}
		if a.bytes[i] > other.bytes[i] {
			return 1
		}
	}
	return 0
}

// Equals compares two addresses for equality
func (a *Address) Equals(other *Address) bool {
	return a.Compare(other) == 0
}