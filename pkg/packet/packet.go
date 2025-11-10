package packet

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/stella/virtual-switch/pkg/address"
)

// Protocol version constants
const (
	// Current ZeroTier protocol version
	ProtocolVersionCurrent = 13
	// Minimum supported protocol version
	ProtocolVersionMinimum = 4
	// Maximum hop count
	ProtocolMaxHops = 7
)

// Cipher suite constants
const (
	// Invalid cipher suite
	CipherInvalid = 0
	// Curve25519 + Poly1305 + Salsa20/12
	CipherC25519_POLY1305_SALSA2012 = 1
	// AES-GMAC + SIV
	CipherAES_GMAC_SIV = 2
)

// Header flag constants
const (
	// Flag bit mask
	FlagMask uint8 = 0xe0
	// Cipher suite mask
	CipherMask uint8 = 0x1c
	// Hop count mask
	HopsMask uint8 = 0x03
	// Extended cipher flag
	FlagExtendedCipher uint8 = 0x80
	// Fragmented flag
	FlagFragmented uint8 = 0x40
	// Trusted path flag
	FlagTrustedPath uint8 = 0x20
)

// Packet structure field index constants
const (
	// 64-bit packet ID/IV/counter
	PacketIdxIV = 0
	// 5-byte destination ZT address
	PacketIdxDest = 8
	// 5-byte source ZT address
	PacketIdxSrc = 13
	// Flags/cipher/hops
	PacketIdxFlags = 18
	// 64-bit MAC
	PacketIdxMAC = 19
	// Packet payload start position
	PacketIdxPayload = 27
	// Encrypted flags and verb position in encrypted payload
	PacketIdxEncryptedFlagsAndVerb = 27
)

// Fragmentation related constants
const (
	// Fragment indicator
	PacketFragmentIndicator = 0xff
	// Fragment packet ID
	PacketFragmentIdxPacketId = 0
	// Fragment destination ZT address
	PacketFragmentIdxDest = 8
	// Fragment indicator position
	PacketFragmentIdxFragmentIndicator = 13
	// Total fragments and fragment number
	PacketFragmentIdxFragmentNo = 14
	// Fragment hop count
	PacketFragmentIdxHops = 15
	// Fragment payload start position
	PacketFragmentIdxPayload = 16
	// Minimum fragment length
	ProtoMinFragmentLength = PacketFragmentIdxPayload
	// Maximum packet length
	ProtoMaxPacketLength = 2048
)

// Protocol verb constants
type Verb uint8

const (
	// No operation
	VerbNOP Verb = 0x00
	// Node existence and basic information announcement
	VerbHELLO Verb = 0x01
	// Error response
	VerbERROR Verb = 0x02
	// Success response
	VerbOK Verb = 0x03
	// Query identity by address
	VerbWHOIS Verb = 0x04
	// Relay-mediated NAT traversal or firewall punching
	VerbRENDEZVOUS Verb = 0x05
	// Ethernet frame transmission
	VerbFRAME Verb = 0x06
	// Extended Ethernet frame
	VerbEXT_FRAME Verb = 0x07
	// Network configuration request
	VerbNETWORK_CONFIG_REQUEST Verb = 0x08
	// Multicast gather
	VerbMULTICAST_GATHER Verb = 0x09
	// Multicast frame
	VerbMULTICAST_FRAME Verb = 0x0a
)

// Packet represents a ZeroTier packet
type Packet struct {
	// Raw packet data
	Data []byte
}

// NewPacket creates a new packet
func NewPacket(dst, src *address.Address) (*Packet, error) {
	if dst == nil || src == nil {
		return nil, fmt.Errorf("destination and source addresses cannot be nil")
	}

	// Create minimum length packet
	data := make([]byte, PacketIdxPayload)

	// Generate random packet ID
	_, err := rand.Read(data[PacketIdxIV:PacketIdxDest])
	if err != nil {
		return nil, fmt.Errorf("failed to generate random packet ID: %v", err)
	}

	// Set destination address
	copy(data[PacketIdxDest:PacketIdxSrc], dst.Bytes())

	// Set source address
	copy(data[PacketIdxSrc:PacketIdxFlags], src.Bytes())

	// Initialize flags, use Curve25519 cipher suite, 0 hops
	// 0b11100000 & 0b00011100 & 0b00000011 = flags/cipher/hops
	data[PacketIdxFlags] = uint8(CipherC25519_POLY1305_SALSA2012 << 2) // Default to Curve25519 cipher suite

	return &Packet{Data: data}, nil
}

// NewPacketFromData creates a packet from raw data
func NewPacketFromData(data []byte) (*Packet, error) {
	if len(data) < PacketIdxPayload {
		return nil, fmt.Errorf("packet too small: minimum length is %d bytes", PacketIdxPayload)
	}

	// Create a copy to avoid modifying original data
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	return &Packet{Data: dataCopy}, nil
}

// PacketID returns the packet's ID
func (p *Packet) PacketID() uint64 {
	return binary.BigEndian.Uint64(p.Data[PacketIdxIV:PacketIdxDest])
}

// SetPacketID sets the packet's ID
func (p *Packet) SetPacketID(id uint64) {
	binary.BigEndian.PutUint64(p.Data[PacketIdxIV:PacketIdxDest], id)
}

// Destination returns the packet's destination address
func (p *Packet) Destination() *address.Address {
	dst, _ := address.NewAddressFromBytes(p.Data[PacketIdxDest:PacketIdxSrc])
	return dst
}

// Source returns the packet's source address
func (p *Packet) Source() *address.Address {
	src, _ := address.NewAddressFromBytes(p.Data[PacketIdxSrc:PacketIdxFlags])
	return src
}

// Flags returns the packet's flags
func (p *Packet) Flags() uint8 {
	return p.Data[PacketIdxFlags] & FlagMask
}

// Cipher returns the packet's cipher suite
func (p *Packet) Cipher() uint8 {
	return (p.Data[PacketIdxFlags] & CipherMask) >> 2
}

// Hops returns the packet's hop count
func (p *Packet) Hops() uint8 {
	return p.Data[PacketIdxFlags] & HopsMask
}

// SetFlags sets the packet's flags
func (p *Packet) SetFlags(flags uint8) {
	// Preserve cipher suite and hop count, only modify flags
	p.Data[PacketIdxFlags] = (p.Data[PacketIdxFlags] & ^FlagMask) | (flags & FlagMask)
}

// SetCipher sets the packet's cipher suite
func (p *Packet) SetCipher(cipher uint8) {
	// Preserve flags and hop count, only modify cipher suite
	p.Data[PacketIdxFlags] = (p.Data[PacketIdxFlags] & ^CipherMask) | ((cipher << 2) & CipherMask)
}

// SetHops sets the packet's hop count
func (p *Packet) SetHops(hops uint8) {
	// Preserve flags and cipher suite, only modify hop count
	p.Data[PacketIdxFlags] = (p.Data[PacketIdxFlags] & ^HopsMask) | (hops & HopsMask)
}

// IncrementHops increments the packet's hop count
func (p *Packet) IncrementHops() {
	newHops := p.Hops() + 1
	if newHops > ProtocolMaxHops {
		// Exceeded maximum hop count, set to maximum
		newHops = ProtocolMaxHops
	}
	p.SetHops(newHops)
}

// MAC returns the packet's MAC value
func (p *Packet) MAC() uint64 {
	return binary.BigEndian.Uint64(p.Data[PacketIdxMAC:PacketIdxPayload])
}

// SetMAC sets the packet's MAC value
func (p *Packet) SetMAC(mac uint64) {
	binary.BigEndian.PutUint64(p.Data[PacketIdxMAC:PacketIdxPayload], mac)
}

// Verb returns the packet's verb
func (p *Packet) Verb() Verb {
	// Verb is located in the lower 5 bits of the first payload byte
	if len(p.Data) > PacketIdxEncryptedFlagsAndVerb {
		return Verb(p.Data[PacketIdxEncryptedFlagsAndVerb] & 0x1f)
	}
	return VerbNOP
}

// SetVerb sets the packet's verb
func (p *Packet) SetVerb(verb Verb) {
	// Ensure packet has enough space
	if len(p.Data) <= PacketIdxEncryptedFlagsAndVerb {
		p.Data = append(p.Data, make([]byte, PacketIdxEncryptedFlagsAndVerb-len(p.Data)+1)...)
	}

	// Preserve high 3 bits, set low 5 bits
	p.Data[PacketIdxEncryptedFlagsAndVerb] = (p.Data[PacketIdxEncryptedFlagsAndVerb] & 0xe0) | (uint8(verb) & 0x1f)
}

// Payload returns the packet's payload
func (p *Packet) Payload() []byte {
	if len(p.Data) <= PacketIdxPayload {
		return []byte{}
	}
	return p.Data[PacketIdxPayload:]
}

// SetPayload sets the packet's payload
func (p *Packet) SetPayload(payload []byte) {
	// Ensure packet has minimum length
	if len(p.Data) < PacketIdxPayload {
		data := make([]byte, PacketIdxPayload)
		copy(data, p.Data)
		p.Data = data
	} else {
		// Preserve header, only modify payload
		p.Data = p.Data[:PacketIdxPayload]
	}

	// Add new payload
	p.Data = append(p.Data, payload...)
}

// Length returns the packet's total length
func (p *Packet) Length() int {
	return len(p.Data)
}

// IsValid checks if the packet is valid
func (p *Packet) IsValid() bool {
	// Check minimum length
	if len(p.Data) < PacketIdxPayload {
		return false
	}

	// Check if destination and source addresses are valid (by attempting to create address objects)
	dst, err := address.NewAddressFromBytes(p.Data[PacketIdxDest:PacketIdxSrc])
	if err != nil || dst == nil {
		return false
	}

	src, err := address.NewAddressFromBytes(p.Data[PacketIdxSrc:PacketIdxFlags])
	if err != nil || src == nil {
		return false
	}

	// Check if hop count is valid
	if p.Hops() > ProtocolMaxHops {
		return false
	}

	// Check if cipher suite is supported
	cipher := p.Cipher()
	if cipher != CipherC25519_POLY1305_SALSA2012 && cipher != CipherAES_GMAC_SIV {
		return false
	}

	return true
}

// Fragment represents a packet fragment
type Fragment struct {
	// Raw fragment data
	Data []byte
}

// NewFragment creates a new packet fragment
func NewFragment(packet *Packet, fragStart, fragLen, fragNo, fragTotal int) (*Fragment, error) {
	// Validate fragment parameters
	if fragNo >= fragTotal || fragNo < 0 || fragTotal <= 0 || fragTotal > 16 {
		return nil, fmt.Errorf("invalid fragment parameters: fragNo=%d, fragTotal=%d", fragNo, fragTotal)
	}

	if fragStart < 0 || fragStart >= len(packet.Data) || (fragStart+fragLen) > len(packet.Data) {
		return nil, fmt.Errorf("fragment out of bounds: start=%d, len=%d, packetLen=%d", fragStart, fragLen, len(packet.Data))
	}

	// Create fragment data
	data := make([]byte, ProtoMinFragmentLength+fragLen)

	// Copy packet ID and destination address
	copy(data[PacketFragmentIdxPacketId:PacketFragmentIdxDest+5], packet.Data[PacketIdxIV:PacketIdxSrc])

	// Set fragment indicator
	data[PacketFragmentIdxFragmentIndicator] = PacketFragmentIndicator

	// Set total fragments and fragment number
	data[PacketFragmentIdxFragmentNo] = uint8(((fragTotal & 0xf) << 4) | (fragNo & 0xf))

	// Set hop count to 0
	data[PacketFragmentIdxHops] = 0

	// Copy fragment data
	copy(data[PacketFragmentIdxPayload:], packet.Data[fragStart:fragStart+fragLen])

	return &Fragment{Data: data}, nil
}

// NewFragmentFromData creates a fragment from raw data
func NewFragmentFromData(data []byte) (*Fragment, error) {
	if len(data) < ProtoMinFragmentLength {
		return nil, fmt.Errorf("fragment too small: minimum length is %d bytes", ProtoMinFragmentLength)
	}

	// Check if it's a valid fragment
	if data[PacketFragmentIdxFragmentIndicator] != PacketFragmentIndicator {
		return nil, fmt.Errorf("not a valid fragment: missing fragment indicator")
	}

	// 创建一个副本，避免修改原始数据
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	return &Fragment{Data: dataCopy}, nil
}

// PacketID returns the ID of the packet this fragment belongs to
func (f *Fragment) PacketID() uint64 {
	return binary.BigEndian.Uint64(f.Data[PacketFragmentIdxPacketId:])
}

// Destination returns the fragment's destination address
func (f *Fragment) Destination() *address.Address {
	dst, _ := address.NewAddressFromBytes(f.Data[PacketFragmentIdxDest : PacketFragmentIdxDest+address.AddressLength])
	return dst
}

// TotalFragments returns the total number of fragments in the packet
func (f *Fragment) TotalFragments() int {
	return int((f.Data[PacketFragmentIdxFragmentNo] >> 4) & 0xf)
}

// FragmentNumber returns the fragment's number
func (f *Fragment) FragmentNumber() int {
	return int(f.Data[PacketFragmentIdxFragmentNo] & 0xf)
}

// Hops returns the fragment's hop count
func (f *Fragment) Hops() uint8 {
	return f.Data[PacketFragmentIdxHops]
}

// IncrementHops increments the fragment's hop count
func (f *Fragment) IncrementHops() {
	newHops := f.Data[PacketFragmentIdxHops] + 1
	if newHops > ProtocolMaxHops {
		newHops = ProtocolMaxHops
	}
	f.Data[PacketFragmentIdxHops] = newHops
}

// Payload returns the fragment's payload
func (f *Fragment) Payload() []byte {
	if len(f.Data) <= PacketFragmentIdxPayload {
		return []byte{}
	}
	return f.Data[PacketFragmentIdxPayload:]
}

// Length returns the fragment's total length
func (f *Fragment) Length() int {
	return len(f.Data)
}

// IsValid checks if the fragment is valid
func (f *Fragment) IsValid() bool {
	// 检查最小长度
	if len(f.Data) < ProtoMinFragmentLength {
		return false
	}

	// Check fragment indicator
	if f.Data[PacketFragmentIdxFragmentIndicator] != PacketFragmentIndicator {
		return false
	}

	// Check fragment number and total count
	fragNo := f.FragmentNumber()
	fragTotal := f.TotalFragments()
	if fragNo < 0 || fragTotal <= 0 || fragNo >= fragTotal || fragTotal > 16 {
		return false
	}

	// Check if destination address is valid (by attempting to create address object)
	dst, err := address.NewAddressFromBytes(f.Data[PacketFragmentIdxDest : PacketFragmentIdxDest+address.AddressLength])
	if err != nil || dst == nil {
		return false
	}

	return true
}
