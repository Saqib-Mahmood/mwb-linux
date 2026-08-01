package filetransfer

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- header framing ---

func TestHeaderRoundTrip(t *testing.T) {
	for _, name := range []string{
		"report.pdf",
		"file with spaces.txt",
		"ünïcödé-名前.png",
		"star*in*name.txt", // legal on Linux; only the first separator counts
	} {
		buf, err := EncodeHeader(Header{Size: 4096, Name: name})
		if err != nil {
			t.Fatalf("encode %q: %v", name, err)
		}
		if len(buf) != HeaderSize {
			t.Fatalf("header is %d bytes, want %d", len(buf), HeaderSize)
		}
		got, err := ParseHeader(buf, DefaultMaxSize)
		if err != nil {
			t.Fatalf("parse %q: %v", name, err)
		}
		if got.Size != 4096 || got.Name != name {
			t.Errorf("round trip = %+v, want size=4096 name=%q", got, name)
		}
	}
}

func TestParseHeader_Rejects(t *testing.T) {
	hdr := func(text string) []byte {
		buf := make([]byte, HeaderSize)
		for i, r := range []rune(text) {
			buf[i*2] = byte(r)
			buf[i*2+1] = byte(r >> 8)
		}
		return buf
	}

	for _, tc := range []struct {
		name string
		buf  []byte
		want error
	}{
		{"truncated", make([]byte, 512), ErrHeaderTooShort},
		{"no separator", hdr("1234"), ErrHeaderMalformed},
		{"non-numeric size", hdr("abc*file.txt"), ErrHeaderMalformed},
		{"empty name", hdr("100*"), ErrHeaderMalformed},
		{"negative size", hdr("-1*file.txt"), ErrSizeRejected},
		{"over cap", hdr("999999999999*file.txt"), ErrSizeRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseHeader(tc.buf, DefaultMaxSize); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// A peer must not be able to declare a size that overflows into acceptance.
func TestParseHeader_HonoursCap(t *testing.T) {
	buf, err := EncodeHeader(Header{Size: 2048, Name: "x.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHeader(buf, 1024); !errors.Is(err, ErrSizeRejected) {
		t.Errorf("a 2048 byte file under a 1024 byte cap must be refused, got %v", err)
	}
	if _, err := ParseHeader(buf, 4096); err != nil {
		t.Errorf("a 2048 byte file under a 4096 byte cap must be accepted, got %v", err)
	}
}

func TestIsInlinePayload(t *testing.T) {
	for name, want := range map[string]bool{
		"text":            true,
		"textDATA":        true,
		"image.png":       true,
		"IMAGE_clip":      true,
		"report.pdf":      false,
		"my-text-file.md": false, // only a prefix counts
	} {
		if got := IsInlinePayload(name); got != want {
			t.Errorf("IsInlinePayload(%q) = %v, want %v", name, got, want)
		}
	}
}

// --- filename safety ---

// The name comes from a remote machine. Every one of these is a real escape
// attempt, and the Windows-style ones matter most: filepath on Linux does not
// treat "\" as a separator, so an unnormalised basename call would create a
// file literally named "..\..\etc\passwd" instead of rejecting it.
func TestSafeName_ContainsEscapes(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{"report.pdf", "report.pdf"},
		{"/etc/passwd", "passwd"},
		{"../../etc/passwd", "passwd"},
		{`..\..\Windows\System32\evil.dll`, "evil.dll"},
		{`C:\Users\me\Desktop\notes.txt`, "notes.txt"},
		{"subdir/file.txt", "file.txt"},
		{"....//....//escape.sh", "escape.sh"},
		{".bashrc", "_.bashrc"}, // must not silently land as a dotfile
	} {
		got, err := SafeName(tc.raw)
		if err != nil {
			t.Errorf("SafeName(%q) errored: %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("SafeName(%q) = %q, want %q", tc.raw, got, tc.want)
		}
		if strings.ContainsAny(got, `/\`) {
			t.Errorf("SafeName(%q) = %q still contains a separator", tc.raw, got)
		}
	}
}

func TestSafeName_RejectsUnusable(t *testing.T) {
	for _, raw := range []string{"", ".", "..", "/", "///", "../..", "\x00"} {
		if got, err := SafeName(raw); err == nil {
			t.Errorf("SafeName(%q) = %q, want an error", raw, got)
		}
	}
}

// --- destination selection ---

func TestDestPath_NeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := DestPath(dir, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "a (1).txt" {
		t.Errorf("collision produced %q, want %q", filepath.Base(got), "a (1).txt")
	}

	// The original must be untouched.
	body, err := os.ReadFile(filepath.Join(dir, "a.txt"))
	if err != nil || string(body) != "original" {
		t.Errorf("original file was modified: %q %v", body, err)
	}
}

// A symlink planted in the destination must not redirect the write. Lstat, not
// Stat, is what makes a dangling link count as occupied.
func TestDestPath_TreatsSymlinkAsOccupied(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.Symlink(target, filepath.Join(dir, "payload.bin")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	got, err := DestPath(dir, "payload.bin")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) == "payload.bin" {
		t.Error("a dangling symlink was treated as free; the write would follow it to its target")
	}
	if _, err := os.Lstat(target); err == nil {
		t.Error("symlink target was created")
	}
}

func TestDestPath_StaysInsideDir(t *testing.T) {
	dir := t.TempDir()
	got, err := DestPath(dir, "ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(got) != real {
		t.Errorf("destination %q is not inside %q", got, real)
	}
}

// --- streaming ---

// wire builds what a real sender puts on the stream: the fixed header followed
// by a body padded the way MWB pads it, so the receive-side tests are driven by
// bytes a C# peer would actually produce.
func wire(t *testing.T, h Header, body []byte) []byte {
	t.Helper()
	hdr, err := EncodeHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	var padded bytes.Buffer
	if _, err := writeAligned(&padded, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	return append(hdr, padded.Bytes()...)
}

func TestReceive_WritesFile(t *testing.T) {
	dir := t.TempDir()
	body := []byte("hello from the other machine")
	in := bytes.NewReader(wire(t, Header{Size: int64(len(body)), Name: "note.txt"}, body))

	res, err := Receive(in, dir, DefaultMaxSize)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("content = %q, want %q", got, body)
	}

	// Never executable: the sender is remote.
	info, err := os.Stat(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 != 0 {
		t.Errorf("mode = %v, must not be executable", info.Mode().Perm())
	}
}

// A peer that declares one size and sends more must not write past the cap.
func TestReceive_UnderDeclaredSizeCannotOverrun(t *testing.T) {
	dir := t.TempDir()
	body := bytes.Repeat([]byte("A"), 4096)
	in := bytes.NewReader(wire(t, Header{Size: 10, Name: "lie.bin"}, body))

	res, err := Receive(in, dir, DefaultMaxSize)
	if err != nil {
		t.Fatal(err)
	}
	if res.Size != 10 {
		t.Errorf("wrote %d bytes, want exactly the declared 10", res.Size)
	}
}

// A truncated transfer must leave nothing that looks complete.
func TestReceive_ShortBodyLeavesNoFile(t *testing.T) {
	dir := t.TempDir()
	in := bytes.NewReader(wire(t, Header{Size: 1000, Name: "cut.bin"}, []byte("only a few")))

	if _, err := Receive(in, dir, DefaultMaxSize); !errors.Is(err, ErrShortBody) {
		t.Fatalf("err = %v, want ErrShortBody", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("left behind %q; an aborted transfer must clean up", e.Name())
	}
}

func TestReceive_RejectsPathEscape(t *testing.T) {
	dir := t.TempDir()
	body := []byte("pwned")
	in := bytes.NewReader(wire(t, Header{Size: int64(len(body)), Name: `..\..\..\etc\cron.d\evil`}, body))

	res, err := Receive(in, dir, DefaultMaxSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err) // basename reduction should make it safe
	}
	if filepath.Dir(res.Path) != mustEval(t, dir) {
		t.Errorf("wrote to %q, outside %q", res.Path, dir)
	}
	if filepath.Base(res.Path) != "evil" {
		t.Errorf("name = %q, want the basename only", filepath.Base(res.Path))
	}
}

func TestReceive_InlinePayloadStaysInMemory(t *testing.T) {
	dir := t.TempDir()
	body := []byte("clipboard text content")
	in := bytes.NewReader(wire(t, Header{Size: int64(len(body)), Name: "text"}, body))

	res, err := Receive(in, dir, DefaultMaxSize)
	if err != nil {
		t.Fatal(err)
	}
	if res.Path != "" {
		t.Errorf("inline payload was written to %q; it belongs in memory", res.Path)
	}
	if !bytes.Equal(res.Inline, body) {
		t.Errorf("inline = %q, want %q", res.Inline, body)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("inline payload created %d files on disk", len(entries))
	}
}

func TestSend_RoundTripsThroughReceive(t *testing.T) {
	src := filepath.Join(t.TempDir(), "payload.bin")
	body := bytes.Repeat([]byte("xyz"), 5000)
	if err := os.WriteFile(src, body, 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Send(&buf, src, DefaultMaxSize); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	res, err := Receive(&buf, dir, DefaultMaxSize)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("round trip corrupted %d bytes", len(body))
	}
	if filepath.Base(res.Path) != "payload.bin" {
		t.Errorf("name = %q, want payload.bin", filepath.Base(res.Path))
	}
}

func TestSend_RefusesDirectoriesAndOversize(t *testing.T) {
	dir := t.TempDir()
	if err := Send(&bytes.Buffer{}, dir, DefaultMaxSize); !errors.Is(err, ErrUnsafeName) {
		t.Errorf("sending a directory: err = %v, want ErrUnsafeName", err)
	}

	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(big, bytes.Repeat([]byte("z"), 2048), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Send(&bytes.Buffer{}, big, 1024); !errors.Is(err, ErrSizeRejected) {
		t.Errorf("sending over the cap: err = %v, want ErrSizeRejected", err)
	}
}

// Sendable is the gate a caller runs before opening a connection, so its
// verdict has to match what Send would decide on its own.
func TestSendable_MatchesWhatSendAccepts(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "ok.bin")
	if err := os.WriteFile(file, bytes.Repeat([]byte("k"), 300), 0o644); err != nil {
		t.Fatal(err)
	}

	// An unset cap must resolve to MWB's own limit rather than rejecting
	// everything as "over a zero-byte cap".
	size, err := Sendable(file, 0)
	if err != nil {
		t.Fatalf("Sendable with an unset cap: %v", err)
	}
	if size != 300 {
		t.Errorf("size = %d, want 300", size)
	}

	if _, err := Sendable(dir, DefaultMaxSize); !errors.Is(err, ErrUnsafeName) {
		t.Errorf("directory: err = %v, want ErrUnsafeName", err)
	}
	if _, err := Sendable(file, 16); !errors.Is(err, ErrSizeRejected) {
		t.Errorf("over the cap: err = %v, want ErrSizeRejected", err)
	}
	if _, err := Sendable(filepath.Join(dir, "absent.bin"), DefaultMaxSize); err == nil {
		t.Error("a missing path was accepted")
	}
}

func mustEval(t *testing.T, dir string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

// Allocation must follow the bytes that actually arrive, not the header. Sizing
// the inline buffer from the declared size let one connection reserve the whole
// cap, multiplied by however many connections the accept path allows.
func TestReceive_InlineAllocationFollowsRealData(t *testing.T) {
	dir := t.TempDir()
	body := []byte("tiny")
	in := bytes.NewReader(wire(t, Header{Size: int64(len(body)), Name: "text"}, body))

	res, err := Receive(in, dir, 64<<20) // a generous cap must not be pre-reserved
	if err != nil {
		t.Fatal(err)
	}
	if got := cap(res.Inline); int64(got) >= 64<<20 {
		t.Errorf("allocated %d bytes of capacity for a %d byte payload", got, len(body))
	}
	if !bytes.Equal(res.Inline, body) {
		t.Errorf("payload = %q, want %q", res.Inline, body)
	}
}

// A peer that declares a large size and then stops must be refused, not
// buffered while we wait for bytes that never come.
func TestReceive_TruncatedInlineIsShortBody(t *testing.T) {
	dir := t.TempDir()
	hdr, err := EncodeHeader(Header{Size: 64 << 20, Name: "text"})
	if err != nil {
		t.Fatal(err)
	}
	in := bytes.NewReader(append(hdr, make([]byte, readAlignBlock)...))

	if _, err := Receive(in, dir, DefaultMaxSize); !errors.Is(err, ErrShortBody) {
		t.Errorf("err = %v, want ErrShortBody", err)
	}
}

// An inline payload larger than the cap must be refused rather than buffered.
func TestReceive_InlineHonoursCap(t *testing.T) {
	dir := t.TempDir()
	body := bytes.Repeat([]byte("x"), 4096)
	in := bytes.NewReader(wire(t, Header{Size: int64(len(body)), Name: "text"}, body))

	if _, err := Receive(in, dir, 1024); err == nil {
		t.Error("a 4096 byte inline payload under a 1024 byte cap must be refused")
	}
}

// The destination must exist before free space is measured, or statfs fails on
// a missing path and the check passes by default on first use.
func TestReceive_CreatesDestinationDirectory(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "does", "not", "exist", "yet")
	body := []byte("content")
	in := bytes.NewReader(wire(t, Header{Size: int64(len(body)), Name: "f.txt"}, body))

	res, err := Receive(in, dir, DefaultMaxSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Errorf("file not written: %v", err)
	}
}

// --- alignment ---

// recordingWriter keeps the length of every individual write so a test can hold
// the sender to the transport's rule rather than only to the total.
type recordingWriter struct {
	bytes.Buffer
	writes []int
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.writes = append(r.writes, len(p))
	return r.Buffer.Write(p)
}

// The wire length is dictated by MWB, not by the cipher: the C# file sender pads
// with PACKAGE_SIZE - (sentCount % PACKAGE_SIZE) (Class/SocketStuff.cs:1920),
// which is 1..32 by construction, so an already 32-aligned body still gets a
// full extra 32 zero bytes. Anything else is not byte-for-byte.
func TestWriteAligned_WireLengthIsMWBExact(t *testing.T) {
	for _, size := range []int64{0, 1, 15, 16, 17, 31, 32, 33, 64, 1000} {
		body := bytes.Repeat([]byte{0xAB}, int(size))
		want := size + 32 - (size % 32)

		var wire bytes.Buffer
		sent, err := writeAligned(&wire, bytes.NewReader(body), size)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if sent != size {
			t.Errorf("size %d: reported %d bytes of payload", size, sent)
		}
		if int64(wire.Len()) != want {
			t.Errorf("size %d: wire = %d bytes, want %d", size, wire.Len(), want)
		}
		if !bytes.Equal(wire.Bytes()[:size], body) {
			t.Errorf("size %d: payload was altered", size)
		}
		if !bytes.Equal(wire.Bytes()[size:], make([]byte, want-size)) {
			t.Errorf("size %d: padding = %v, want zeros", size, wire.Bytes()[size:])
		}
	}
}

// EncryptWriter rejects any write that is not a whole number of AES blocks, and
// a 32-boundary pad is usually not one (28 bytes, say), so the padding has to be
// merged into the final write instead of issued on its own.
func TestWriteAligned_EveryWriteIsWholeAESBlocks(t *testing.T) {
	for _, size := range []int64{0, 1, 15, 16, 17, 31, 32, 33, 64, 1000, copyBufSize, copyBufSize + 7, copyBufSize*2 + 31} {
		w := &recordingWriter{}
		if _, err := writeAligned(w, bytes.NewReader(bytes.Repeat([]byte{0x5A}, int(size))), size); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(w.writes) == 0 {
			t.Errorf("size %d: nothing was written; MWB always emits at least the trailing package", size)
		}
		for i, n := range w.writes {
			if n%16 != 0 {
				t.Errorf("size %d: write %d is %d bytes, which EncryptWriter would refuse", size, i, n)
			}
		}
	}
}

// The receive side rounds to 16 and the send side pads to 32 on purpose. Every
// size that is not a multiple of either exercises the padding path, and getting
// it wrong truncates the tail of the file.
func TestAlignedRoundTrip_AllTailLengths(t *testing.T) {
	for size := 0; size <= 96; size++ {
		body := bytes.Repeat([]byte{0xAB}, size)

		var wire bytes.Buffer
		if _, err := writeAligned(&wire, bytes.NewReader(body), int64(size)); err != nil {
			t.Fatalf("size %d: writeAligned: %v", size, err)
		}

		var out bytes.Buffer
		got, err := readAligned(&out, &wire, int64(size))
		if err != nil {
			t.Fatalf("size %d: readAligned: %v", size, err)
		}
		if got != int64(size) || !bytes.Equal(out.Bytes(), body) {
			t.Errorf("size %d: round trip gave %d bytes %q", size, got, out.Bytes())
		}
	}
}

// Sizes spanning multiple buffer fills must stay aligned throughout.
func TestAlignedRoundTrip_LargeUnaligned(t *testing.T) {
	const size = copyBufSize*2 + 7
	body := bytes.Repeat([]byte("Q"), size)

	var wire bytes.Buffer
	if _, err := writeAligned(&wire, bytes.NewReader(body), size); err != nil {
		t.Fatal(err)
	}
	if int64(wire.Len()) != sendAlignedLen(size) {
		t.Fatalf("wire is %d bytes, want %d", wire.Len(), sendAlignedLen(size))
	}

	var out bytes.Buffer
	if _, err := readAligned(&out, &wire, size); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), body) {
		t.Errorf("round trip corrupted %d bytes", size)
	}
}

// csInlineWire is what MWB's inline clipboard sender actually puts on the wire.
// SendData appends (sentCount % PACKAGE_SIZE) bytes (Class/SocketStuff.cs:1991),
// an inverted expression that aligns nothing; the CryptoStream then zero-pads
// the tail to the AES block (PaddingMode.Zeros, Core/Encryption.cs:95). We must
// not copy the bug on send, but we do have to read what it produces.
func csInlineWire(body []byte) []byte {
	out := append([]byte(nil), body...)
	out = append(out, make([]byte, len(body)%32)...)
	if rem := len(out) % 16; rem != 0 {
		out = append(out, make([]byte, 16-rem)...)
	}
	return out
}

// Rounding reads up to 32 would break real C# inline images: for L % 32 in 1..8
// the inline sender emits fewer than 32*ceil(L/32) bytes, so a 32-boundary
// reader would wait for bytes that never arrive and then fail with
// ErrShortBody. (At L % 32 == 0 the wire is already 32-aligned, so that case is
// safe either way — the hazard is specifically the 1..8 remainders.)
func TestReadAligned_AcceptsSixteenAlignedInlineBody(t *testing.T) {
	sharper := 0

	for size := 1; size <= 200; size++ {
		body := bytes.Repeat([]byte{0xC3}, size)
		wire := csInlineWire(body)

		if len(wire)%16 != 0 {
			t.Fatalf("size %d: emulated C# wire is %d bytes, not a whole AES block", size, len(wire))
		}
		if readAlignedLen(int64(size)) > int64(len(wire)) {
			t.Fatalf("size %d: reader wants %d bytes but C# only sends %d", size, readAlignedLen(int64(size)), len(wire))
		}
		// Count the sizes where a 32-rounding READER would overrun the wire.
		// Comparing sendAlignedLen here instead would be vacuous: the send pad
		// always adds a whole extra package, so it exceeds the inline wire for
		// every 32-aligned size regardless of the read boundary.
		if (int64(size)+31)/32*32 > int64(len(wire)) {
			sharper++
		}

		var out bytes.Buffer
		got, err := readAligned(&out, bytes.NewReader(wire), int64(size))
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if got != int64(size) || !bytes.Equal(out.Bytes(), body) {
			t.Errorf("size %d: recovered %d bytes %q", size, got, out.Bytes())
		}
	}

	// Guard the reason the two boundaries differ: if this ever hits zero the
	// comment above is stale and the read side could be simplified.
	if sharper == 0 {
		t.Error("no size where a 32-boundary read would overrun the C# inline sender; the split boundaries need re-justifying")
	}
}

func TestAlignedLenHelpers(t *testing.T) {
	for in, want := range map[int64]int64{0: 0, 1: 16, 15: 16, 16: 16, 17: 32, 1024: 1024, 1025: 1040} {
		if got := readAlignedLen(in); got != want {
			t.Errorf("readAlignedLen(%d) = %d, want %d", in, got, want)
		}
	}
	for in, want := range map[int64]int64{0: 32, 1: 32, 31: 32, 32: 64, 33: 64, 64: 96, 1000: 1024} {
		if got := sendAlignedLen(in); got != want {
			t.Errorf("sendAlignedLen(%d) = %d, want %d", in, got, want)
		}
	}
}
