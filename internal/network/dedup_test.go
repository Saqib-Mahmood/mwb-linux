// internal/network/dedup_test.go
package network

import (
	"sync"
	"testing"
	"time"

	"github.com/lucky-verma/mwb-linux/internal/protocol"
)

func pkt(t protocol.PackageType, id int32) *protocol.Packet {
	return &protocol.Packet{Type: t, ID: id}
}

func TestDedupDropsRepeatedID(t *testing.T) {
	var d packetDedup

	if d.seen(pkt(protocol.Mouse, 100)) {
		t.Fatal("first sighting must not be a duplicate")
	}
	if !d.seen(pkt(protocol.Mouse, 100)) {
		t.Fatal("second sighting of the same id must be dropped")
	}
	// The type is irrelevant — PowerToys keys purely on the id.
	if !d.seen(pkt(protocol.Keyboard, 100)) {
		t.Fatal("id match must drop regardless of packet type")
	}
	if d.seen(pkt(protocol.Mouse, 101)) {
		t.Fatal("a fresh id must pass")
	}
}

func TestDedupExemptTypesAlwaysPass(t *testing.T) {
	var d packetDedup

	// The handshake is deliberately sent ten times with the same random id.
	// Deduplicating it would break connection setup outright.
	for i := 0; i < 10; i++ {
		if d.seen(pkt(protocol.Handshake, 7)) {
			t.Fatalf("Handshake must never be deduplicated (attempt %d)", i+1)
		}
	}
	for _, ty := range []protocol.PackageType{
		protocol.HandshakeAck, protocol.ClipboardText, protocol.ClipboardImage,
	} {
		if d.seen(pkt(ty, 9)) || d.seen(pkt(ty, 9)) {
			t.Errorf("type %d must be exempt from dedup", ty)
		}
	}
	// Exempt packets must not consume ring slots either, so a later
	// non-exempt packet reusing id 7 is still seen as new.
	if d.seen(pkt(protocol.Mouse, 7)) {
		t.Error("exempt packets must not populate the dedup ring")
	}
}

func TestDedupWindowEvicts(t *testing.T) {
	var d packetDedup

	for i := int32(1); i <= dedupWindow; i++ {
		if d.seen(pkt(protocol.Mouse, i)) {
			t.Fatalf("id %d should be new", i)
		}
	}
	// The whole window is still remembered.
	if !d.seen(pkt(protocol.Mouse, dedupWindow)) {
		t.Error("most recent id should still be remembered")
	}
	// Pushing one more id past the window evicts the oldest.
	if d.seen(pkt(protocol.Mouse, dedupWindow+1)) {
		t.Fatal("new id should pass")
	}
	if d.seen(pkt(protocol.Mouse, 1)) {
		t.Error("the oldest id should have been evicted from the window")
	}
}

// TestDedupZeroIDIsProcessed documents a deliberate divergence from the C#
// ring, which is zero-initialised and therefore silently swallows any packet
// whose id is genuinely 0. Losing real input is worse than replaying one
// duplicate, so a zero id passes the first time.
func TestDedupZeroIDIsProcessed(t *testing.T) {
	var d packetDedup
	if d.seen(pkt(protocol.Mouse, 0)) {
		t.Fatal("a zero id must be processed, not swallowed as a phantom duplicate")
	}
	if !d.seen(pkt(protocol.Mouse, 0)) {
		t.Fatal("a repeated zero id is still a duplicate")
	}
}

func TestDedupNilPacket(t *testing.T) {
	var d packetDedup
	if d.seen(nil) {
		t.Error("nil packet must not be reported as a duplicate")
	}
}

func TestDedupConcurrent(t *testing.T) {
	var d packetDedup
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(base int32) {
			defer wg.Done()
			for j := int32(0); j < 200; j++ {
				d.seen(pkt(protocol.Mouse, base*1000+j))
			}
		}(int32(i))
	}
	wg.Wait()
}

func TestHeartbeatIntervalClamp(t *testing.T) {
	original := HeartbeatInterval()
	t.Cleanup(func() { SetHeartbeatInterval(original) })

	cases := []struct {
		in, want time.Duration
	}{
		{0, DefaultHeartbeatInterval},
		{-time.Second, DefaultHeartbeatInterval},
		{time.Second, 60 * time.Second},          // below PowerToys' clamp
		{90 * time.Second, 90 * time.Second},     // in range
		{2 * time.Hour, 3600 * time.Second},      // above PowerToys' clamp
		{3600 * time.Second, 3600 * time.Second}, // exactly at the ceiling
	}
	for _, tc := range cases {
		SetHeartbeatInterval(tc.in)
		if got := HeartbeatInterval(); got != tc.want {
			t.Errorf("SetHeartbeatInterval(%v): got %v, want %v", tc.in, got, tc.want)
		}
	}
}
