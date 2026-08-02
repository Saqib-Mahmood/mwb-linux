// internal/network/receiver.go
package network

import (
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/lucky-verma/mwb-linux/internal/protocol"
)

// DefaultHeartbeatInterval is how often we announce ourselves to the peer.
//
// PowerToys itself beats every HeartbeatIntervalSeconds — default 300, clamped
// to 60..3600 (Class/Setting.cs, Form/frmScreen.cs) — and only considers a
// machine dead after MachineStuff.HEARTBEAT_TIMEOUT, which is 1,500,000 ms.
// The previous 5-second cadence here was based on a mistaken belief that
// Windows drops silent clients within ~10s; it does not. 60s is comfortably
// inside every timeout while still refreshing the peer's machine pool
// promptly after a reconnect.
//
// Liveness is really handled by TCP keepalive, which newSecureStream enables.
const DefaultHeartbeatInterval = 60 * time.Second

// heartbeatInterval is a process-wide knob so config can override the cadence.
var heartbeatInterval atomic.Int64

// SetHeartbeatInterval overrides the heartbeat cadence for new connections.
// Values outside PowerToys' own 60..3600 second clamp are pulled into range.
func SetHeartbeatInterval(d time.Duration) {
	switch {
	case d <= 0:
		d = DefaultHeartbeatInterval
	case d < 60*time.Second:
		d = 60 * time.Second
	case d > 3600*time.Second:
		d = 3600 * time.Second
	}
	heartbeatInterval.Store(int64(d))
}

// HeartbeatInterval reports the cadence new connections will use.
func HeartbeatInterval() time.Duration {
	if d := heartbeatInterval.Load(); d > 0 {
		return time.Duration(d)
	}
	return DefaultHeartbeatInterval
}

// startHeartbeat sends periodic heartbeats so the peer keeps us in its machine
// pool and its matrix tile stays live.
func startHeartbeat(conn *Conn, stop chan struct{}) {
	ticker := time.NewTicker(HeartbeatInterval())
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			hb := &protocol.Packet{
				Type: protocol.HeartbeatEx,
				Src:  conn.MachineID,
				Des:  protocol.IDAll,
			}
			hb.SetMachineName(conn.LocalName)
			if err := conn.SendPacket(hb); err != nil {
				// Do not just stop beating. Nothing else on the send side can
				// end the connection, so returning quietly here leaves the
				// client wedged: still "connected", no longer announcing
				// itself, and never reconnecting. Dropping the socket makes
				// ReceiveLoop return, which is what reaches the reconnect path.
				conn.abort("heartbeat send failed", err)
				return
			}
		}
	}
}

// ReceiveLoop reads packets from the connection and dispatches them.
func ReceiveLoop(conn *Conn, handler *Handler) error {
	stop := make(chan struct{})
	go startHeartbeat(conn, stop)
	defer close(stop)

	var dedup packetDedup

	for {
		pkt, err := conn.RecvPacket()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				slog.Info("connection closed by remote")
				return nil
			}
			return err
		}

		// Every inbound packet, before any filtering. Without this it is
		// impossible to tell "the peer never sent it" from "we dropped it",
		// which are very different problems with very different fixes.
		slog.Debug("rx", "type", pkt.Type, "id", pkt.ID, "src", pkt.Src, "des", pkt.Des)

		if dedup.seen(pkt) {
			slog.Warn("duplicate packet dropped", "type", pkt.Type, "id", pkt.ID)
			continue
		}

		switch pkt.Type {
		case protocol.Hi:
			slog.Debug("Hi received, responding with Hello", "localName", conn.LocalName, "machineID", conn.MachineID)
			resp := &protocol.Packet{
				Type: protocol.Hello,
				Src:  conn.MachineID,
				Des:  pkt.Src,
			}
			resp.SetMachineName(conn.LocalName)
			if err := conn.SendPacket(resp); err != nil {
				slog.Error("send Hello response", "err", err)
			}
		case protocol.Heartbeat, protocol.HeartbeatEx, protocol.HeartbeatExL2, protocol.HeartbeatExL3:
			slog.Debug("heartbeat received", "type", pkt.Type, "from", pkt.MachineName())
			resp := &protocol.Packet{
				Type: pkt.Type,
				Src:  conn.MachineID,
				Des:  pkt.Src,
			}
			resp.SetMachineName(conn.LocalName)
			if err := conn.SendPacket(resp); err != nil {
				slog.Error("send heartbeat response", "err", err)
			}
		case protocol.ByeBye:
			slog.Info("remote disconnected (ByeBye)")
			return nil
		case protocol.Invalid:
			slog.Warn("invalid packet received")
		case protocol.Handshake:
			slog.Debug("late handshake packet, ignoring")
		default:
			// Handle Matrix packets (bit 128 set) — server sends these for machine layout
			if pkt.Type&protocol.Matrix == protocol.Matrix {
				subType := pkt.Type &^ protocol.Matrix
				slog.Debug("matrix packet received", "fullType", pkt.Type, "subType", subType, "src", pkt.Src)
				if subType == protocol.Hi {
					resp := &protocol.Packet{
						Type: protocol.Hello,
						Src:  conn.MachineID,
						Des:  pkt.Src,
					}
					resp.SetMachineName(conn.LocalName)
					if err := conn.SendPacket(resp); err != nil {
						slog.Error("send matrix Hello response", "err", err)
					}
				}
			} else {
				handler.HandlePacket(pkt)
			}
		}
	}
}
