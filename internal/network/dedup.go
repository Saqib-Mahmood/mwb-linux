// internal/network/dedup.go
package network

import (
	"sync"

	"github.com/lucky-verma/mwb-linux/internal/protocol"
)

// dedupWindow is the number of recently-seen packet IDs remembered, matching
// PowerToys Core/Receiver.cs `QUEUE_SIZE = 50`.
const dedupWindow = 50

// packetDedup drops packets whose ID has been seen recently.
//
// PowerToys needs this because Common.SkSend assigns ONE id per logical send
// and then fans the identical frame out to every matching socket
// (Core/Common.cs:916), so a peer reachable over two sockets sees each packet
// twice. Our capture path also sends deliberate duplicates on an edge crossing.
// Without dedup those replay as real input.
//
// Mirrors Core/Receiver.cs:38-79, including the exempt type set: those four
// types are sent outside the SkSend id counter, so their ids are random or
// repeated and must never be deduplicated.
type packetDedup struct {
	mu    sync.Mutex
	ring  [dedupWindow]int32
	valid [dedupWindow]bool
	next  int
}

// dedupExempt reports whether a packet type bypasses the duplicate filter.
//
// ClipboardText and ClipboardImage stream many frames that legitimately reuse
// ids; Handshake and HandshakeAck are emitted by the C# TcpSend path, which
// bypasses the id counter entirely and fills the field with random bytes
// (Class/SocketStuff.cs:1342-1343). Deduplicating either would break the
// connection: the handshake is sent ten times on purpose.
func dedupExempt(pt protocol.PackageType) bool {
	switch pt {
	case protocol.ClipboardText, protocol.ClipboardImage,
		protocol.Handshake, protocol.HandshakeAck:
		return true
	}
	return false
}

// seen records the packet and reports whether it is a duplicate that should be
// dropped. Exempt types are always allowed through and are not recorded.
//
// Unlike the C# ring, which is zero-initialised and therefore silently drops
// any packet whose id is genuinely 0, this tracks slot validity separately. A
// stray id of 0 is processed rather than swallowed; erring toward one extra
// duplicate is safer than losing real input. Our own outbound ids start at 1
// (SendPacket), so this asymmetry is not observable to the peer.
func (d *packetDedup) seen(pkt *protocol.Packet) bool {
	if pkt == nil || dedupExempt(pkt.Type) {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for i := 0; i < dedupWindow; i++ {
		if d.valid[i] && d.ring[i] == pkt.ID {
			return true
		}
	}

	d.next = (d.next + 1) % dedupWindow
	d.ring[d.next] = pkt.ID
	d.valid[d.next] = true
	return false
}
