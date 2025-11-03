// Package address provides address system for Stella network
package address

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// MACLength is the byte length of a MAC address
	MACLength = 6
)

// MAC represents an Ethernet MAC address
type MAC struct {
	bytes [MACLength]byte
}

// NewMACFromString creates a MAC address from a string
func NewMACFromString(s string) (*MAC, error) {
	// Supports formats like: 00:11:22:33:44:55 or 001122334455
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != MACLength*2 {
		return nil, errors.New("invalid MAC address length")
	}

	bytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	mac := &MAC{}
	copy(mac.bytes[:], bytes)
	return mac, nil
}

// NewMACFromBytes creates a MAC address from a byte array
func NewMACFromBytes(b []byte) (*MAC, error) {
	if len(b) != MACLength {
		return nil, errors.New("invalid MAC address length")
	}

	mac := &MAC{}
	copy(mac.bytes[:], b)
	return mac, nil
}

// NewRandomMAC generates a random MAC address
func NewRandomMAC() *MAC {
	mac := &MAC{}
	// Generate random bytes, but keep universal/local bit (bit 0) as 0 and local administration bit (bit 1) as 1
	// This ensures generated MAC addresses won't conflict with OUI-assigned ones
	mac.bytes[0] = 0x02 // 设置为本地管理地址
	for i := 1; i < MACLength; i++ {
		// For simple implementation, we temporarily set to fixed values
		mac.bytes[i] = byte(i)
	}
	return mac
}

// NewMACFromZTAddress derives a MAC address from a ZeroTier address
func NewMACFromZTAddress(ztAddr *Address) *MAC {
	mac := &MAC{}
	// 设置为本地管理地址
	mac.bytes[0] = 0x02
	// 复制ZT地址的5个字节到MAC地址的后5个字节
	copy(mac.bytes[1:], ztAddr.bytes[:])
	return mac
}

// Bytes returns the byte representation of the MAC address
func (m *MAC) Bytes() []byte {
	b := make([]byte, MACLength)
	copy(b, m.bytes[:])
	return b
}

// String returns the string representation of the MAC address (xx:xx:xx:xx:xx:xx)
func (m *MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", 
		m.bytes[0], m.bytes[1], m.bytes[2], 
		m.bytes[3], m.bytes[4], m.bytes[5])
}

// IsBroadcast checks if this is a broadcast MAC address
func (m *MAC) IsBroadcast() bool {
	return m.bytes[0] == 0xff && 
		m.bytes[1] == 0xff && 
		m.bytes[2] == 0xff && 
		m.bytes[3] == 0xff && 
		m.bytes[4] == 0xff && 
		m.bytes[5] == 0xff
}

// IsMulticast checks if this is a multicast MAC address
func (m *MAC) IsMulticast() bool {
	return (m.bytes[0] & 0x01) == 0x01
}

// Compare compares two MAC addresses
func (m *MAC) Compare(other *MAC) int {
	for i := 0; i < MACLength; i++ {
		if m.bytes[i] < other.bytes[i] {
			return -1
		}
		if m.bytes[i] > other.bytes[i] {
			return 1
		}
	}
	return 0
}

// Equals checks if two MAC addresses are equal
func (m *MAC) Equals(other *MAC) bool {
	return m.Compare(other) == 0
}