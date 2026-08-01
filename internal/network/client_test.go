// internal/network/client_test.go
package network

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucky-verma/mwb-linux/internal/protocol"
)

// fakePeerStream performs the peer half of the MWB stream opening from raw
// socket bytes, exactly as PowerToys does, and hands back the cipher streams.
//
// Per direction: 32 cleartext bytes salt(16)||IV(16) on the raw socket, then one
// 16-byte primer block through the cipher. It writes its own prologue before
// reading the peer's, matching newSecureStream, so the two cannot deadlock.
//
// Deliberately implemented from the protocol description rather than by calling
// newSecureStream, so that a regression in newSecureStream cannot be masked by
// both sides making the same mistake.
func fakePeerStream(t *testing.T, conn net.Conn, securityKey string) (*protocol.EncryptWriter, *protocol.DecryptReader, error) {
	t.Helper()

	txSalt, txIV, err := protocol.NewPrologue()
	if err != nil {
		return nil, nil, err
	}
	if _, err := conn.Write(append(append([]byte{}, txSalt...), txIV...)); err != nil {
		return nil, nil, fmt.Errorf("peer write prologue: %w", err)
	}
	rxPrologue := make([]byte, protocol.PrologueSize)
	if _, err := io.ReadFull(conn, rxPrologue); err != nil {
		return nil, nil, fmt.Errorf("peer read prologue: %w", err)
	}
	iters := PBKDF2Iterations()

	enc, err := protocol.NewEncryptWriter(conn, protocol.DeriveKey(securityKey, txSalt, iters), txIV)
	if err != nil {
		return nil, nil, err
	}
	dec, err := protocol.NewDecryptReader(conn,
		protocol.DeriveKey(securityKey, rxPrologue[:protocol.SaltSize], iters),
		rxPrologue[protocol.SaltSize:])
	if err != nil {
		return nil, nil, err
	}

	primer := make([]byte, protocol.IVSize)
	if _, err := rand.Read(primer); err != nil {
		return nil, nil, err
	}
	if _, err := enc.Write(primer); err != nil {
		return nil, nil, fmt.Errorf("peer write primer: %w", err)
	}
	peerPrimer := make([]byte, protocol.IVSize)
	if _, err := io.ReadFull(dec, peerPrimer); err != nil {
		return nil, nil, fmt.Errorf("peer read primer: %w", err)
	}
	return enc, dec, nil
}

func TestConnectionHandshake(t *testing.T) {
	securityKey := "TestSecurityKey!!"
	magic := protocol.Get24BitHash(securityKey)

	// Start a fake MWB server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()

		// Server: exchange the cleartext prologue and the encrypted primer.
		enc, dec, err := fakePeerStream(t, conn, securityKey)
		if err != nil {
			serverDone <- err
			return
		}

		// Server: read handshake packets from client (may receive up to 10)
		// Read at least one handshake packet (64 bytes for big packet)
		pktBuf := make([]byte, protocol.PacketSizeEx)
		if _, err := io.ReadFull(dec, pktBuf); err != nil {
			serverDone <- err
			return
		}

		if err := protocol.ValidatePacket(pktBuf, magic); err != nil {
			serverDone <- err
			return
		}
		protocol.ClearStamp(pktBuf)

		pkt, err := protocol.UnmarshalPacket(pktBuf)
		if err != nil {
			serverDone <- err
			return
		}

		if pkt.Type != protocol.Handshake {
			serverDone <- fmt.Errorf("expected Handshake, got %d", pkt.Type)
			return
		}

		// Drain remaining handshake packets (client sends 10)
		for i := 0; i < 9; i++ {
			drain := make([]byte, protocol.PacketSizeEx)
			_, _ = io.ReadFull(dec, drain)
		}

		// Server: send HandshakeAck with inverted machine fields
		ack := &protocol.Packet{
			Type: protocol.HandshakeAck,
			Src:  0,
			Des:  pkt.Src,
		}
		ack.Handshake.Machine1 = ^pkt.Handshake.Machine1
		ack.Handshake.Machine2 = ^pkt.Handshake.Machine2
		ack.Handshake.Machine3 = ^pkt.Handshake.Machine3
		ack.Handshake.Machine4 = ^pkt.Handshake.Machine4
		ack.SetMachineName("WINHOST")

		ackBuf := ack.Marshal()
		protocol.StampPacket(ackBuf, magic)
		if _, err := enc.Write(ackBuf); err != nil {
			serverDone <- err
			return
		}

		serverDone <- nil
	}()

	// Client: connect and handshake
	addr := ln.Addr().String()
	conn, err := Connect(addr, securityKey, "linux-test", 5*time.Second)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if conn.RemoteName != "WINHOST" {
		t.Errorf("remote name = %q, want %q", conn.RemoteName, "WINHOST")
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for server")
	}
}

// TestStreamWireOrder inspects the raw socket bytes, with no help from our own
// crypto code, and asserts the exact opening sequence PowerToys expects:
//
//	offset  bytes  content
//	     0     16  salt      (cleartext)
//	    16     16  IV        (cleartext)
//	    32     16  primer    (encrypted, discarded)
//	    48     64  Handshake (encrypted, stamped)
//
// This is the regression test for the interop fix. Any byte-count error here
// puts the CBC stream permanently out of phase, and every later frame decrypts
// to noise — which looks exactly like a wrong security key.
func TestStreamWireOrder(t *testing.T) {
	const securityKey = "TestSecurityKey!!"
	magic := protocol.Get24BitHash(securityKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	type result struct {
		err error
	}
	done := make(chan result, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- result{err}
			return
		}
		defer func() { _ = conn.Close() }()

		// Read the client's prologue as opaque bytes.
		prologue := make([]byte, protocol.PrologueSize)
		if _, err := io.ReadFull(conn, prologue); err != nil {
			done <- result{fmt.Errorf("read prologue: %w", err)}
			return
		}
		clientSalt, clientIV := prologue[:protocol.SaltSize], prologue[protocol.SaltSize:]

		// Send our own prologue so the client can build its decryptor.
		ourSalt, ourIV, err := protocol.NewPrologue()
		if err != nil {
			done <- result{err}
			return
		}
		if _, err := conn.Write(append(append([]byte{}, ourSalt...), ourIV...)); err != nil {
			done <- result{err}
			return
		}

		iters := PBKDF2Iterations()
		dec, err := protocol.NewDecryptReader(conn, protocol.DeriveKey(securityKey, clientSalt, iters), clientIV)
		if err != nil {
			done <- result{err}
			return
		}
		enc, err := protocol.NewEncryptWriter(conn, protocol.DeriveKey(securityKey, ourSalt, iters), ourIV)
		if err != nil {
			done <- result{err}
			return
		}
		// Our own primer, so the client's newSecureStream can complete.
		ourPrimer := make([]byte, protocol.IVSize)
		if _, err := rand.Read(ourPrimer); err != nil {
			done <- result{err}
			return
		}
		if _, err := enc.Write(ourPrimer); err != nil {
			done <- result{err}
			return
		}

		// Exactly one 16-byte primer block must precede the first frame.
		primer := make([]byte, protocol.IVSize)
		if _, err := io.ReadFull(dec, primer); err != nil {
			done <- result{fmt.Errorf("read primer: %w", err)}
			return
		}

		// The next 64 bytes must be a valid, stamped Handshake frame. If the
		// primer had been skipped or double-counted this would be garbage.
		frame := make([]byte, protocol.PacketSizeEx)
		if _, err := io.ReadFull(dec, frame); err != nil {
			done <- result{fmt.Errorf("read frame: %w", err)}
			return
		}
		if err := protocol.ValidatePacket(frame, magic); err != nil {
			done <- result{fmt.Errorf("first frame did not validate — stream is out of "+
				"phase or the key is wrong: %w", err)}
			return
		}
		protocol.ClearStamp(frame)
		pkt, err := protocol.UnmarshalPacket(frame)
		if err != nil {
			done <- result{err}
			return
		}
		if pkt.Type != protocol.Handshake {
			done <- result{fmt.Errorf("first frame type = %d, want Handshake(%d)", pkt.Type, protocol.Handshake)}
			return
		}
		if got := pkt.MachineName(); got != "linux-test" {
			done <- result{fmt.Errorf("machine name = %q, want %q", got, "linux-test")}
			return
		}
		done <- result{nil}
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()

	conn, err := newSecureStream(raw, securityKey, "linux-test", 5*time.Second)
	if err != nil {
		t.Fatalf("newSecureStream: %v", err)
	}

	hs := &protocol.Packet{Type: protocol.Handshake, Src: conn.MachineID, Des: protocol.IDAll}
	hs.SetMachineName("linux-test")
	if err := conn.SendPacket(hs); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("wire inspection failed: %v", r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

// TestStreamDirectionsUseDistinctKeys guards the single most seductive bug in
// this protocol: reusing one salt/IV for both directions. It works perfectly
// against another implementation that shares the mistake, and fails only
// against real PowerToys.
func TestStreamDirectionsUseDistinctKeys(t *testing.T) {
	const securityKey = "TestSecurityKey!!"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	peerPrologue := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			peerPrologue <- nil
			return
		}
		defer func() { _ = conn.Close() }()

		ourSalt, ourIV, err := protocol.NewPrologue()
		if err != nil {
			peerPrologue <- nil
			return
		}
		if _, err := conn.Write(append(append([]byte{}, ourSalt...), ourIV...)); err != nil {
			peerPrologue <- nil
			return
		}
		clientPrologue := make([]byte, protocol.PrologueSize)
		if _, err := io.ReadFull(conn, clientPrologue); err != nil {
			peerPrologue <- nil
			return
		}
		// Give the client time to finish its primer write before we close.
		time.Sleep(200 * time.Millisecond)
		peerPrologue <- append(append([]byte{}, ourSalt...), clientPrologue...)
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()

	// newSecureStream will block reading the peer primer, which never arrives;
	// that is fine, we only care about the prologues actually exchanged.
	go func() { _, _ = newSecureStream(raw, securityKey, "linux-test", 2*time.Second) }()

	select {
	case got := <-peerPrologue:
		if got == nil {
			t.Fatal("peer failed")
		}
		serverSalt := got[:protocol.SaltSize]
		clientSalt := got[protocol.PrologueSize : protocol.PrologueSize+protocol.SaltSize]
		if bytes.Equal(serverSalt, clientSalt) {
			t.Fatal("the two directions must use independently random salts")
		}
		iters := PBKDF2Iterations()
		if bytes.Equal(
			protocol.DeriveKey(securityKey, serverSalt, iters),
			protocol.DeriveKey(securityKey, clientSalt, iters),
		) {
			t.Fatal("the two directions must derive different AES keys")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

// TestMachineIDIsStableAcrossConnections is the regression test for the
// identity bug: the machine ID used to be derived from each connection's random
// primer block, so it changed on every reconnect.
//
// PowerToys treats the id as an identity. A per-connection id breaks the bulk
// clipboard channel (Core/Clipboard.cs:840 gates on ResolveID(name) == Src),
// splits the two sockets MWB keeps per peer across two ids so directed input
// can be routed into the wrong one (Core/Common.cs:926), and leaves the peer's
// persisted "name:id" stale so the first switch after a restart fails.
func TestMachineIDIsStableAcrossConnections(t *testing.T) {
	const securityKey = "TestSecurityKey!!"

	restore := MachineID()
	t.Cleanup(func() { machineID.Store(restore) })
	if err := SetMachineID(0x1234ABCD); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	peers := make(chan struct{}, 2)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if _, _, err := fakePeerStream(t, c, securityKey); err != nil {
					return
				}
				peers <- struct{}{}
				time.Sleep(300 * time.Millisecond)
			}(conn)
		}
	}()

	var ids []uint32
	for i := 0; i < 2; i++ {
		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = raw.Close() }()

		c, err := newSecureStream(raw, securityKey, "linux-test", 5*time.Second)
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		ids = append(ids, c.MachineID)
		<-peers
	}

	if ids[0] != ids[1] {
		t.Errorf("machine id changed between connections: %d then %d", ids[0], ids[1])
	}
	if ids[0] != 0x1234ABCD {
		t.Errorf("machine id = %#x, want the configured %#x", ids[0], 0x1234ABCD)
	}
}

func TestSetMachineIDRejectsReserved(t *testing.T) {
	restore := MachineID()
	t.Cleanup(func() { machineID.Store(restore) })

	// 0 is ID.NONE and 255 is ID.ALL (Core/ID.cs). Neither survives the Windows
	// machine-pool round trip, and both are dropped from the matrix auto-fill.
	for _, bad := range []uint32{0, 255} {
		if err := SetMachineID(bad); err == nil {
			t.Errorf("SetMachineID(%d) must be rejected as reserved", bad)
		}
	}
	if err := SetMachineID(42); err != nil {
		t.Errorf("SetMachineID(42): %v", err)
	}
	if got := MachineID(); got != 42 {
		t.Errorf("MachineID() = %d, want 42", got)
	}
}

// TestMachineIDFallbackIsStable checks that even with nothing configured the id
// is minted once and then reused, rather than re-rolled per call.
func TestMachineIDFallbackIsStable(t *testing.T) {
	restore := MachineID()
	t.Cleanup(func() { machineID.Store(restore) })

	machineID.Store(0)
	first := MachineID()
	if first == 0 || first == 255 {
		t.Fatalf("fallback id %d is reserved", first)
	}
	for i := 0; i < 5; i++ {
		if got := MachineID(); got != first {
			t.Fatalf("fallback id changed: %d then %d", first, got)
		}
	}
}

func TestListenAndAcceptReturnsBindError(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	port := ln.Addr().(*net.TCPAddr).Port
	stop := make(chan struct{})
	connCh, err := ListenAndAccept(port, "TestSecurityKey!!", "linux-test", "192.168.1.100", nil, stop)
	if err == nil {
		close(stop)
		t.Fatal("expected bind error, got nil")
	}
	if connCh != nil {
		t.Fatalf("expected nil connection channel on bind error, got %v", connCh)
	}
}

func TestConnectWithRetryRetriesUntilSuccess(t *testing.T) {
	stop := make(chan struct{})
	want := &Conn{}
	var attempts atomic.Int32

	connCh := connectWithRetry(stop, time.Millisecond, func() (*Conn, error) {
		if attempts.Add(1) < 3 {
			return nil, errors.New("server unavailable")
		}
		return want, nil
	})

	select {
	case got := <-connCh:
		if got != want {
			t.Fatalf("connection = %p, want %p", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for retried connection")
	}

	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

func TestConnectWithRetryStopsDuringDelay(t *testing.T) {
	stop := make(chan struct{})
	attempted := make(chan struct{}, 1)

	connCh := connectWithRetry(stop, time.Hour, func() (*Conn, error) {
		attempted <- struct{}{}
		return nil, errors.New("server unavailable")
	})

	select {
	case <-attempted:
	case <-time.After(time.Second):
		t.Fatal("initial connection attempt did not run")
	}

	close(stop)
	select {
	case conn, ok := <-connCh:
		if ok {
			t.Fatalf("unexpected connection after stop: %v", conn)
		}
	case <-time.After(time.Second):
		t.Fatal("retry loop did not stop")
	}
}
