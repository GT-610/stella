package packet_test

import (
	"testing"
	"github.com/stella/virtual-switch/pkg/address"
	"github.com/stella/virtual-switch/pkg/packet"
)

func TestPacketBasics(t *testing.T) {
	dst, _ := address.NewAddressFromString("deadbeef00")
	src, _ := address.NewAddressFromString("deadbeef01")
	p, err := packet.NewPacket(dst, src)
	if err != nil {
		t.Fatalf("failed to create packet: %v", err)
	}
	if !p.IsValid() {
		t.Error("packet should be valid")
	}
}

func TestFragmentBasics(t *testing.T) {
	dst, _ := address.NewAddressFromString("deadbeef00")
	src, _ := address.NewAddressFromString("deadbeef01")
	p, _ := packet.NewPacket(dst, src)
	p.SetPayload([]byte{1, 2, 3, 4})
	frag, err := packet.NewFragment(p, packet.PacketIdxPayload, 2, 1, 2)
	if err != nil {
		t.Fatalf("failed to create fragment: %v", err)
	}
	if !frag.IsValid() {
		t.Error("fragment should be valid")
	}
}