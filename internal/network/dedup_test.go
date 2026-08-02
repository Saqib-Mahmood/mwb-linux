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

// An id of 0 means the sender never assigned one, so it is not a sequence
// number and must never be deduplicated.
//
// PowerToys emits these routinely: anything sent via TcpSend rather than SkSend
// skips the id counter, which includes the Hi liveness probe
// (Core/Common.cs:822-836). Windows sends Hi in bursts, so treating 0 as a real
// id let the first through and dropped all the rest — observed live as a flood
// of "duplicate packet dropped type=2 id=0".
func TestDedupNeverDropsZeroID(t *testing.T) {
	var d packetDedup
	for i := 0; i < 20; i++ {
		if d.seen(pkt(protocol.Hi, 0)) {
			t.Fatalf("id 0 must never be treated as a duplicate (attempt %d)", i+1)
		}
	}
	// Nor may they consume ring slots and evict real ids.
	if d.seen(pkt(protocol.Mouse, 42)) {
		t.Fatal("id 42 should be new")
	}
	for i := 0; i < 60; i++ {
		d.seen(pkt(protocol.Hi, 0))
	}
	if !d.seen(pkt(protocol.Mouse, 42)) {
		t.Error("id-0 packets must not evict remembered ids from the ring")
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
