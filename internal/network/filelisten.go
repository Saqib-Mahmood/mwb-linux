// internal/network/filelisten.go
package network

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/lucky-verma/mwb-linux/internal/protocol"
)

const (
	// fileReadIdleTimeout bounds how long an inbound bulk transfer may stall
	// without any progress. It mirrors the C# clipboard channel's 30s
	// ReceiveTimeout (Core/Clipboard.cs:794-795), with headroom for a slow disk
	// on the sending side.
	fileReadIdleTimeout = 60 * time.Second

	// fileDrainTimeout bounds the post-transfer drain of the sender's padding.
	// It only ever has to absorb a few dozen bytes already in flight.
	fileDrainTimeout = 2 * time.Second

	// fileDrainLimit caps how much a peer can make us read after the body, so a
	// peer that keeps writing cannot hold the connection open.
	fileDrainLimit = 64 * 1024
)

// ListenFileChannel serves inbound file transfers on the clipboard port.
//
// MWB opens these against skClipboardServer, which listens on the base port,
// so they never arrive at the control listener on base+1 and a client that has
// only the control port open is never offered a file at all. Nothing else
// arrives here: the control handshake has its own port and its own server.
//
// allowedHost restricts connections to the configured peer, resolved once at
// startup, exactly as the control listener does.
func ListenFileChannel(port int, securityKey, machineName, allowedHost string, activeMachineID func() uint32, onFile InboundFile, stop chan struct{}) error {
	if onFile == nil {
		return fmt.Errorf("file channel listener needs a handler")
	}
	if activeMachineID == nil {
		return fmt.Errorf("file channel listener needs the active control machine ID")
	}

	allowedIPs, resolveErr := resolveAllowedPeer(allowedHost)
	if resolveErr != nil {
		slog.Warn("could not resolve configured peer; inbound file transfers disabled",
			"host", allowedHost, "err", resolveErr)
	}

	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	go func() {
		defer func() { _ = ln.Close() }()
		var transfers sync.WaitGroup
		defer transfers.Wait()
		pending := make(chan struct{}, maxPendingHandshakes)

		slog.Info("listening for inbound file transfers",
			"port", port, "allowedHost", allowedHost, "allowedIPs", allowedIPs)

		for {
			select {
			case <-stop:
				return
			default:
			}

			if tl, ok := ln.(*net.TCPListener); ok {
				_ = tl.SetDeadline(time.Now().Add(1 * time.Second))
			}

			raw, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				slog.Debug("file listener accept error", "err", err)
				continue
			}

			if !isAllowedPeer(raw.RemoteAddr(), allowedIPs) {
				slog.Warn("rejected inbound file connection from unexpected source",
					"remote", raw.RemoteAddr(), "allowedHost", allowedHost)
				_ = raw.Close()
				continue
			}

			// Share the control listener's budget shape: a peer must not be
			// able to occupy unbounded goroutines by opening file channels.
			select {
			case pending <- struct{}{}:
			default:
				slog.Warn("rejected inbound file connection: too many in flight",
					"remote", raw.RemoteAddr())
				_ = raw.Close()
				continue
			}

			transfers.Add(1)
			go func(raw net.Conn) {
				defer transfers.Done()
				defer func() { <-pending }()
				defer func() { _ = raw.Close() }()
				serveFileChannel(raw, securityKey, machineName, activeMachineID, onFile)
			}(raw)
		}
	}()

	return nil
}

// serveFileChannel completes the handshake on one inbound file connection and
// hands the positioned stream to the caller's handler.
func serveFileChannel(raw net.Conn, securityKey, machineName string, activeMachineID func() uint32, onFile InboundFile) {
	conn, err := newSecureStream(raw, securityKey, machineName, handshakeTimeout)
	if err != nil {
		slog.Error("file channel stream setup failed", "remote", raw.RemoteAddr(), "err", err)
		return
	}

	first, err := conn.recvChannelHeader()
	if err != nil {
		slog.Error("file channel header failed", "remote", raw.RemoteAddr(), "err", err)
		return
	}
	if first.Type != protocol.Clipboard && first.Type != protocol.ClipboardPush {
		slog.Warn("unexpected packet type opening a file channel",
			"remote", raw.RemoteAddr(), "type", first.Type)
		return
	}

	// MWB's ShakeHand reads a header back before it sends anything, in both
	// roles. Without this the peer sits in ReadEx until its receive timeout and
	// then reports the channel as rejected.
	// PowerToys requires ResolveID(name) == Src and IsConnectedTo(Src)
	// (Core/Clipboard.cs:840), so the header must carry the same identity our
	// control heartbeats put in its machine pool.
	//
	// That is now simply our persisted machine ID, which every connection
	// shares. The activeMachineID callback is kept as an override for tests and
	// for the case where a control connection negotiated something different;
	// when it reports nothing, fall back rather than refusing the channel — an
	// inbound push is still serviceable without a control socket of our own.
	controlID := activeMachineID()
	if controlID == 0 {
		controlID = MachineID()
		slog.Debug("file channel: no active control connection, using the persisted machine id",
			"remote", raw.RemoteAddr(), "machineID", controlID)
	}
	conn.MachineID = controlID
	ack := &protocol.Packet{Type: protocol.ClipboardPush, Src: controlID}
	ack.SetMachineName(machineName)
	if err := conn.sendChannelHeader(ack); err != nil {
		slog.Warn("file channel: could not acknowledge peer",
			"remote", raw.RemoteAddr(), "err", err)
		return
	}

	slog.Info("inbound file channel accepted",
		"remote", first.MachineName(), "type", first.Type)

	// Drop the fixed handshake deadline, but do NOT go deadline-free: swap in a
	// per-read idle timeout so a peer that stops sending mid-body cannot pin
	// this goroutine (and with it, listener shutdown) forever. Matches the 30s
	// ReceiveTimeout the C# side keeps in force for the whole transfer
	// (Core/Clipboard.cs:795).
	if err := raw.SetDeadline(time.Time{}); err != nil {
		slog.Warn("clear file transfer deadline", "err", err)
	}
	conn.SetReadIdleTimeout(fileReadIdleTimeout)
	onFile(conn, first.Type == protocol.ClipboardPush)

	// Drain whatever the sender still has queued before the deferred Close.
	//
	// MWB pads a body up to a 32-byte multiple (Class/SocketStuff.cs:1920) while
	// our reader only consumes whole AES blocks, so 16 or 32 trailing zero bytes
	// are routinely left unread. Closing a socket with unread data makes the
	// kernel send RST instead of FIN, which can surface on the sender as a
	// write error for a transfer that in fact completed. The C# receiver has no
	// such problem because it reads to EOF (Core/Clipboard.cs:618-650).
	drainToEOF(raw)
}

// drainToEOF reads and discards anything left on the socket, bounded so a peer
// that never closes cannot hold the connection open.
func drainToEOF(raw net.Conn) {
	if err := raw.SetReadDeadline(time.Now().Add(fileDrainTimeout)); err != nil {
		return
	}
	// The tail is tens of bytes; the cap is only there to bound a misbehaving
	// or malicious peer that keeps writing.
	_, _ = io.Copy(io.Discard, io.LimitReader(raw, fileDrainLimit))
}
