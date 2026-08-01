// internal/network/interop_test.go
package network

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucky-verma/mwb-linux/internal/protocol"
)

// The loopback tests in this package prove we are self-consistent, which is
// exactly what they cannot prove about the protocol: two ends sharing one
// misreading of the C# spec agree perfectly.
//
// tools/reference_peer.py is a second implementation, transcribed from
// src/modules/MouseWithoutBorders/App/ and sharing no code with the Go client.
// It uses CPython's PBKDF2 and libcrypto's AES rather than x/crypto. When the
// two interoperate, the crypto, the framing and the handshake are corroborated
// by something other than themselves.
//
// The real Windows peer is still the final word; this is the closest available
// substitute, since .NET cannot be run here.

type peerEvent struct {
	Event          string `json:"event"`
	Port           int    `json:"port"`
	Magic          string `json:"magic"`
	Error          string `json:"error"`
	RemoteName     string `json:"remote_name"`
	RemoteID       uint32 `json:"remote_id"`
	Trusted        bool   `json:"trusted"`
	HandshakesRecv int    `json:"handshakes_received"`
	KeysDiffer     bool   `json:"keys_differ"`
	TxSalt         string `json:"tx_salt"`
	RxSalt         string `json:"rx_salt"`
	Types          []int  `json:"types"`
	Type           int    `json:"type"`
	Reason         string `json:"reason"`
	X              int    `json:"x"`
	Y              int    `json:"y"`
	VK             int    `json:"vk"`
	Flags          int    `json:"flags"`
}

// referencePeer starts tools/reference_peer.py and streams its JSON events.
type referencePeer struct {
	cmd    *exec.Cmd
	events chan peerEvent
	mu     sync.Mutex
	all    []peerEvent
}

func startReferencePeer(t *testing.T, args ...string) *referencePeer {
	t.Helper()

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available; skipping cross-implementation interop test")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "tools", "reference_peer.py")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("reference peer not found at %s", script)
	}

	cmd := exec.Command(python, append([]string{script}, args...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start reference peer: %v", err)
	}

	rp := &referencePeer{cmd: cmd, events: make(chan peerEvent, 64)}

	go func() {
		defer close(rp.events)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			var ev peerEvent
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				t.Logf("reference peer: unparseable line %q", sc.Text())
				continue
			}
			rp.mu.Lock()
			rp.all = append(rp.all, ev)
			rp.mu.Unlock()
			rp.events <- ev
		}
	}()
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			t.Logf("reference peer stderr: %s", sc.Text())
		}
	}()

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return rp
}

// await blocks until an event of the given name arrives, or the test times out.
func (rp *referencePeer) await(t *testing.T, name string, timeout time.Duration) peerEvent {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev, ok := <-rp.events:
			if !ok {
				rp.dump(t)
				t.Fatalf("reference peer exited before %q", name)
			}
			if ev.Event == "invalid_frame" {
				rp.dump(t)
				t.Fatalf("the reference peer rejected one of our frames: %s", ev.Error)
			}
			if ev.Event == name {
				return ev
			}
		case <-deadline:
			rp.dump(t)
			t.Fatalf("timed out waiting for %q from the reference peer", name)
		}
	}
}

func (rp *referencePeer) dump(t *testing.T) {
	t.Helper()
	rp.mu.Lock()
	defer rp.mu.Unlock()
	var b strings.Builder
	for _, ev := range rp.all {
		j, _ := json.Marshal(ev)
		b.WriteString("\n  ")
		b.Write(j)
	}
	t.Logf("reference peer events:%s", b.String())
}

// TestInteropHandshakeWithReferencePeer runs the real client against the
// independent implementation and checks the whole opening sequence.
func TestInteropHandshakeWithReferencePeer(t *testing.T) {
	const securityKey = "TestSecurityKey!!"

	restore := MachineID()
	t.Cleanup(func() { machineID.Store(restore) })
	if err := SetMachineID(0x00C0FFEE); err != nil {
		t.Fatal(err)
	}

	rp := startReferencePeer(t,
		"--key", securityKey,
		"--name", "WINHOST",
		"--machine-id", "195936478", // 0x0BADC0DE
		"--exit-after-trust",
	)

	listening := rp.await(t, "listening", 20*time.Second)
	if listening.Port == 0 {
		t.Fatal("reference peer reported no port")
	}
	// The magic number is derived from the key by two independent
	// implementations; if these disagree nothing else can work.
	wantMagic := protocol.Get24BitHash(securityKey)
	if got := listening.Magic; got != magicHex(wantMagic) {
		t.Fatalf("magic number disagrees: reference peer %s, Go 0x%08X", got, wantMagic)
	}

	addr := "127.0.0.1:" + itoa(listening.Port)
	conn, err := Connect(addr, securityKey, "linux-test", 20*time.Second)
	if err != nil {
		rp.dump(t)
		t.Fatalf("Connect against the reference peer: %v", err)
	}
	defer func() { _ = conn.Close() }()

	streams := rp.await(t, "streams_open", 20*time.Second)
	if !streams.KeysDiffer {
		t.Error("the two directions derived the same AES key; salts must be independent")
	}
	if streams.TxSalt == streams.RxSalt {
		t.Error("the two directions used the same salt")
	}

	hs := rp.await(t, "handshake_seen", 20*time.Second)
	if hs.RemoteName != "linux-test" {
		t.Errorf("peer saw our name as %q, want %q", hs.RemoteName, "linux-test")
	}

	trust := rp.await(t, "trusted", 20*time.Second)
	if trust.RemoteID != 0x00C0FFEE {
		t.Errorf("peer learned our machine id as %#x, want %#x", trust.RemoteID, 0x00C0FFEE)
	}
	if trust.HandshakesRecv != 10 {
		t.Errorf("peer received %d Handshake frames, want 10 (Class/SocketStuff.cs:1379-1382)",
			trust.HandshakesRecv)
	}

	if conn.RemoteName != "WINHOST" {
		t.Errorf("we learned the peer's name as %q, want %q", conn.RemoteName, "WINHOST")
	}

	summary := rp.await(t, "summary", 20*time.Second)
	if !summary.Trusted {
		rp.dump(t)
		t.Fatal("the reference peer never reached the trusted state")
	}
}

// TestInteropWrongKeyIsRejected proves the magic-number check actually bites:
// with mismatched keys the peer must reject our frames rather than silently
// accepting garbage.
func TestInteropWrongKeyIsRejected(t *testing.T) {
	rp := startReferencePeer(t,
		"--key", "DifferentKey12345",
		"--name", "WINHOST",
		"--timeout", "15",
	)
	listening := rp.await(t, "listening", 20*time.Second)

	addr := "127.0.0.1:" + itoa(listening.Port)
	conn, err := Connect(addr, "TestSecurityKey!!", "linux-test", 8*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatal("a handshake with the wrong security key must not succeed")
	}
	t.Logf("rejected as expected: %v", err)
}

func magicHex(m uint32) string {
	const digits = "0123456789ABCDEF"
	out := []byte("0x00000000")
	for i := 0; i < 8; i++ {
		out[9-i] = digits[(m>>(4*i))&0xF]
	}
	return string(out)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// recordingDevice captures injected input so the test can assert on what the
// receive path actually produced.
type recordingDevice struct {
	mu        sync.Mutex
	moves     [][2]int32
	keysDown  []uint16
	keysUp    []uint16
	buttonsDn []uint16
	wheels    []int32
}

func (d *recordingDevice) MoveTo(x, y int32) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.moves = append(d.moves, [2]int32{x, y})
	return nil
}

func (d *recordingDevice) ButtonDown(b uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.buttonsDn = append(d.buttonsDn, b)
	return nil
}
func (d *recordingDevice) ButtonUp(uint16) error { return nil }
func (d *recordingDevice) Wheel(v int32) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.wheels = append(d.wheels, v)
	return nil
}
func (d *recordingDevice) HWheel(int32) error { return nil }

func (d *recordingDevice) KeyDown(c uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.keysDown = append(d.keysDown, c)
	return nil
}

func (d *recordingDevice) KeyUp(c uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.keysUp = append(d.keysUp, c)
	return nil
}

func (d *recordingDevice) snapshot() ([][2]int32, []uint16) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([][2]int32(nil), d.moves...), append([]uint16(nil), d.keysDown...)
}

// TestInteropInboundInput drives a mouse move and an extended-flag keystroke
// from the independent peer all the way through decryption, framing, dedup,
// dispatch and keymap resolution.
//
// The keystroke is VK_RETURN (0x0D) with LLKHF_EXTENDED set, which is numpad
// Enter. It must resolve to KEY_KPENTER and not to KEY_ENTER — that distinction
// is the whole point of the extended-flag table, and it is invisible to any
// test that only checks the base map.
func TestInteropInboundInput(t *testing.T) {
	const securityKey = "TestSecurityKey!!"

	restore := MachineID()
	t.Cleanup(func() { machineID.Store(restore) })
	if err := SetMachineID(0x00C0FFEE); err != nil {
		t.Fatal(err)
	}

	rp := startReferencePeer(t,
		"--key", securityKey,
		"--name", "WINHOST",
		"--send-mouse", "--mouse-x", "32767", "--mouse-y", "16383",
		"--send-key", "13", // VK_RETURN
		"--key-flags", "1", // LLKHF_EXTENDED
	)
	listening := rp.await(t, "listening", 20*time.Second)

	conn, err := Connect("127.0.0.1:"+itoa(listening.Port), securityKey, "linux-test", 20*time.Second)
	if err != nil {
		rp.dump(t)
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	dev := &recordingDevice{}
	handler := &Handler{Mouse: dev, Keyboard: dev, KeyboardLayout: "us"}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ReceiveLoop(conn, handler)
	}()

	rp.await(t, "sent_mouse", 20*time.Second)
	rp.await(t, "sent_key", 20*time.Second)

	deadline := time.Now().Add(10 * time.Second)
	var moves [][2]int32
	var keys []uint16
	for time.Now().Before(deadline) {
		moves, keys = dev.snapshot()
		if len(moves) > 0 && len(keys) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if len(moves) == 0 {
		rp.dump(t)
		t.Fatal("no mouse movement was injected")
	}
	// Md.X/Y arrive normalised to 0..65535 (Core/Event.cs:112-113) and the
	// handler passes them through in that space.
	if moves[0][0] != 32767 || moves[0][1] != 16383 {
		t.Errorf("injected move = %v, want [32767 16383]", moves[0])
	}

	if len(keys) == 0 {
		rp.dump(t)
		t.Fatal("no key was injected")
	}
	const keyKPEnter = 96 // KEY_KPENTER, verified against this machine's X keymap
	const keyEnter = 28   // KEY_ENTER
	if keys[0] == keyEnter {
		t.Errorf("VK_RETURN with LLKHF_EXTENDED resolved to KEY_ENTER (%d); "+
			"numpad Enter must resolve to KEY_KPENTER (%d)", keyEnter, keyKPEnter)
	}
	if keys[0] != keyKPEnter {
		t.Errorf("injected key = %d, want KEY_KPENTER (%d)", keys[0], keyKPEnter)
	}

	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Log("receive loop did not exit promptly")
	}
}
