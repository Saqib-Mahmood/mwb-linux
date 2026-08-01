// internal/protocol/stream_test.go
package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

// testKeyIV derives deterministic key material for stream tests. Real streams
// use a random per-connection salt and IV from NewPrologue; tests pin them so
// failures are reproducible.
func testKeyIV(securityKey string) (key, iv []byte) {
	salt := bytes.Repeat([]byte{0x5A}, SaltSize)
	return DeriveKey(securityKey, salt, DefaultPBKDF2Iterations), bytes.Repeat([]byte{0xC3}, IVSize)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, iv := testKeyIV("TestSecurityKey!!")

	plaintext := []byte("Hello, Mouse Without Borders!!!!") // exactly 32 bytes
	if len(plaintext) != 32 {
		t.Fatalf("plaintext len = %d, want 32", len(plaintext))
	}

	// Encrypt
	var cipherBuf bytes.Buffer
	enc, err := NewEncryptWriter(&cipherBuf, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(plaintext); err != nil {
		t.Fatal(err)
	}

	// Ciphertext should not equal plaintext
	cipher := cipherBuf.Bytes()
	if bytes.Equal(cipher, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	// Decrypt
	dec, err := NewDecryptReader(bytes.NewReader(cipher), key, iv)
	if err != nil {
		t.Fatal(err)
	}
	result := make([]byte, len(plaintext))
	if _, err := io.ReadFull(dec, result); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Errorf("decrypted = %q, want %q", result, plaintext)
	}
}

func TestEncryptedStreamMultipleBlocks(t *testing.T) {
	key, iv := testKeyIV("AnotherTestKey123")

	// Write two 32-byte packets
	pkt1 := bytes.Repeat([]byte{0xAA}, 32)
	pkt2 := bytes.Repeat([]byte{0xBB}, 32)

	var cipherBuf bytes.Buffer
	enc, err := NewEncryptWriter(&cipherBuf, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = enc.Write(pkt1); err != nil {
		t.Fatal(err)
	}
	if _, err = enc.Write(pkt2); err != nil {
		t.Fatal(err)
	}

	dec, err := NewDecryptReader(bytes.NewReader(cipherBuf.Bytes()), key, iv)
	if err != nil {
		t.Fatal(err)
	}

	got1 := make([]byte, 32)
	if _, err = io.ReadFull(dec, got1); err != nil {
		t.Fatal(err)
	}
	got2 := make([]byte, 32)
	if _, err = io.ReadFull(dec, got2); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got1, pkt1) {
		t.Error("packet 1 mismatch")
	}
	if !bytes.Equal(got2, pkt2) {
		t.Error("packet 2 mismatch")
	}
}

// --- DecryptReader framing ---
//
// The stream is CBC with PaddingMode.Zeros (Core/Encryption.cs:95): there is no
// depadding holdback, so plaintext byte count must always equal ciphertext byte
// count. A Read that consumed a block but delivered only part of it and dropped
// the rest would advance the CBC chain past plaintext nobody saw, and every
// later frame would fail the peer's magic/checksum checks
// (Class/SocketStuff.cs:543,554). These tests pin that no byte is ever lost,
// whatever buffer sizes the caller picks — Conn.Reader() hands this reader to
// arbitrary code, so the sizes are not ours to choose.

// countingReader records how many times the reader below the cipher was
// consulted, which is how the tests assert the frame path did not grow an extra
// read per frame.
type countingReader struct {
	r     io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.r.Read(p)
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// streamFixture encrypts plaintext and returns a decrypting reader over the
// ciphertext plus the ciphertext length, so tests can compare byte counts.
func streamFixture(t *testing.T, plaintext []byte) (*DecryptReader, *countingReader, int) {
	t.Helper()
	key, iv := testKeyIV("StreamFramingKey!")

	var cipherBuf bytes.Buffer
	enc, err := NewEncryptWriter(&cipherBuf, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(plaintext); err != nil {
		t.Fatal(err)
	}

	src := &countingReader{r: bytes.NewReader(cipherBuf.Bytes())}
	dec, err := NewDecryptReader(src, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	return dec, src, cipherBuf.Len()
}

// drain reads to EOF one io.Reader call at a time using bufSize buffers and
// returns everything delivered.
func drain(t *testing.T, r io.Reader, bufSize int) []byte {
	t.Helper()
	var out []byte
	buf := make([]byte, bufSize)
	for {
		n, err := r.Read(buf)
		if n > bufSize {
			t.Fatalf("Read returned %d for a %d-byte buffer", n, bufSize)
		}
		out = append(out, buf[:n]...)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out
			}
			t.Fatalf("Read: %v", err)
		}
		if n == 0 {
			t.Fatal("Read returned 0, nil: no progress")
		}
	}
}

// The frame path: two 32-byte reads, one underlying read each. Frames are
// always whole blocks, so this must stay allocation- and syscall-free.
func TestDecryptReaderExactBlockReads(t *testing.T) {
	pkt1 := bytes.Repeat([]byte{0xAA}, 32)
	pkt2 := bytes.Repeat([]byte{0xBB}, 32)
	dec, src, ctLen := streamFixture(t, append(append([]byte{}, pkt1...), pkt2...))

	got1 := make([]byte, 32)
	n1, err := dec.Read(got1)
	if err != nil || n1 != 32 {
		t.Fatalf("first Read = (%d, %v), want (32, nil)", n1, err)
	}
	got2 := make([]byte, 32)
	n2, err := dec.Read(got2)
	if err != nil || n2 != 32 {
		t.Fatalf("second Read = (%d, %v), want (32, nil)", n2, err)
	}
	if !bytes.Equal(got1, pkt1) || !bytes.Equal(got2, pkt2) {
		t.Errorf("frames mismatch: %x / %x", got1, got2)
	}
	if n1+n2 != ctLen {
		t.Errorf("delivered %d plaintext bytes for %d ciphertext bytes", n1+n2, ctLen)
	}
	if src.reads != 2 {
		t.Errorf("underlying reads = %d, want 2 (one per frame)", src.reads)
	}
}

// Sixteen 1-byte reads must reassemble the block the first of them decrypted,
// from the residual, without touching the socket again.
func TestDecryptReaderByteAtATime(t *testing.T) {
	plaintext := []byte("sixteen bytes!!!")
	dec, src, ctLen := streamFixture(t, plaintext)

	var got []byte
	one := make([]byte, 1)
	for i := 0; i < len(plaintext); i++ {
		n, err := dec.Read(one)
		if err != nil || n != 1 {
			t.Fatalf("read %d = (%d, %v), want (1, nil)", i, n, err)
		}
		got = append(got, one[0])
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("reassembled %q, want %q", got, plaintext)
	}
	if len(got) != ctLen {
		t.Errorf("delivered %d plaintext bytes for %d ciphertext bytes", len(got), ctLen)
	}
	if src.reads != 1 {
		t.Errorf("underlying reads = %d, want 1: the block is decrypted once and buffered", src.reads)
	}
	if n, err := dec.Read(one); !errors.Is(err, io.EOF) || n != 0 {
		t.Errorf("read past end = (%d, %v), want (0, EOF)", n, err)
	}
}

// An 8-byte read followed by 24 more bytes must yield exactly what a single
// 32-byte read yields: the misaligned split may not perturb the CBC chain.
func TestDecryptReaderSplitReadMatchesWholeRead(t *testing.T) {
	plaintext := []byte("Hello, Mouse Without Borders!!!!")

	whole, _, wholeCT := streamFixture(t, plaintext)
	want := make([]byte, 32)
	if _, err := io.ReadFull(whole, want); err != nil {
		t.Fatal(err)
	}

	split, _, splitCT := streamFixture(t, plaintext)
	head := make([]byte, 8)
	nh, err := split.Read(head)
	if err != nil || nh != 8 {
		t.Fatalf("8-byte Read = (%d, %v), want (8, nil)", nh, err)
	}
	tail := make([]byte, 24)
	nt, err := io.ReadFull(split, tail)
	if err != nil {
		t.Fatalf("24-byte ReadFull: %v", err)
	}

	got := append(append([]byte{}, head...), tail[:nt]...)
	if !bytes.Equal(got, want) {
		t.Errorf("split read gave %x, whole read gave %x", got, want)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("split read gave %q, want %q", got, plaintext)
	}
	if nh+nt != splitCT || splitCT != wholeCT {
		t.Errorf("delivered %d plaintext bytes for %d ciphertext bytes", nh+nt, splitCT)
	}
}

// A 40-byte buffer over 64 bytes of ciphertext: 40 is not a multiple of 16, so
// the reader has to carry 8 plaintext bytes across the io.ReadFull boundary.
func TestDecryptReaderOversizedUnalignedBuffer(t *testing.T) {
	plaintext := bytes.Repeat([]byte("0123456789abcdef"), 4) // 64 bytes
	dec, _, ctLen := streamFixture(t, plaintext)

	first := make([]byte, 40)
	if _, err := io.ReadFull(dec, first); err != nil {
		t.Fatalf("40-byte ReadFull: %v", err)
	}
	second := make([]byte, 24)
	if _, err := io.ReadFull(dec, second); err != nil {
		t.Fatalf("24-byte ReadFull: %v", err)
	}

	got := append(append([]byte{}, first...), second...)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("got %q, want %q", got, plaintext)
	}
	if len(got) != ctLen {
		t.Errorf("delivered %d plaintext bytes for %d ciphertext bytes", len(got), ctLen)
	}
	if n, err := dec.Read(make([]byte, 16)); !errors.Is(err, io.EOF) || n != 0 {
		t.Errorf("read past end = (%d, %v), want (0, EOF)", n, err)
	}
}

// The same NIST SP 800-38A F.2.6 (CBC-AES256.Decrypt) vector crypto_test.go
// pins, but read one byte at a time: standard vectors are the only
// cross-implementation ground truth available here, and the buffering must not
// change a single output byte.
func TestDecryptReaderNISTVectorByteAtATime(t *testing.T) {
	key := hexBytes(t, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	iv := hexBytes(t, "000102030405060708090a0b0c0d0e0f")
	ciphertext := hexBytes(t, ""+
		"f58c4c04d6e5f1ba779eabfb5f7bfbd6"+
		"9cfc4e967edb808d679f777bc6702c7d"+
		"39f23369a9d9bacfa530e26304231461"+
		"b2eb05e2c39be9fcda6c19078c6a9d1b")
	want := hexBytes(t, ""+
		"6bc1bee22e409f96e93d7e117393172a"+
		"ae2d8a571e03ac9c9eb76fac45af8e51"+
		"30c81c46a35ce411e5fbc1191a0a52ef"+
		"f69f2445df4f9b17ad2b417be66c3710")

	for _, bufSize := range []int{1, 3, 7, 16, 17, 31, 40, 64, 100} {
		dec, err := NewDecryptReader(bytes.NewReader(ciphertext), key, iv)
		if err != nil {
			t.Fatal(err)
		}
		got := drain(t, dec, bufSize)
		if !bytes.Equal(got, want) {
			t.Errorf("bufSize %d:\n got %x\nwant %x", bufSize, got, want)
		}
		if len(got) != len(ciphertext) {
			t.Errorf("bufSize %d: delivered %d plaintext bytes for %d ciphertext bytes",
				bufSize, len(got), len(ciphertext))
		}
	}
}

// EOF: clean at a block boundary, and a truncated tail must still hand over the
// blocks that did arrive before reporting the error. PaddingMode.Zeros means a
// partial trailing block is not padding to strip, it is a broken stream.
func TestDecryptReaderEOF(t *testing.T) {
	t.Run("clean", func(t *testing.T) {
		dec, _, _ := streamFixture(t, bytes.Repeat([]byte{0x11}, 16))
		if _, err := io.ReadFull(dec, make([]byte, 16)); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if n, err := dec.Read(make([]byte, 16)); !errors.Is(err, io.EOF) || n != 0 {
				t.Errorf("Read %d after EOF = (%d, %v), want (0, EOF)", i, n, err)
			}
		}
	})

	t.Run("empty buffer", func(t *testing.T) {
		dec, src, _ := streamFixture(t, bytes.Repeat([]byte{0x22}, 16))
		if n, err := dec.Read(nil); n != 0 || err != nil {
			t.Errorf("Read(nil) = (%d, %v), want (0, nil)", n, err)
		}
		if src.reads != 0 {
			t.Errorf("Read(nil) consumed %d underlying reads, want 0", src.reads)
		}
	})

	t.Run("truncated after whole block", func(t *testing.T) {
		key, iv := testKeyIV("StreamFramingKey!")
		var cipherBuf bytes.Buffer
		enc, err := NewEncryptWriter(&cipherBuf, key, iv)
		if err != nil {
			t.Fatal(err)
		}
		plaintext := bytes.Repeat([]byte{0x33}, 32)
		if _, err := enc.Write(plaintext); err != nil {
			t.Fatal(err)
		}
		truncated := cipherBuf.Bytes()[:16+5] // one block, then a partial one
		dec, err := NewDecryptReader(bytes.NewReader(truncated), key, iv)
		if err != nil {
			t.Fatal(err)
		}

		buf := make([]byte, 32)
		n, err := dec.Read(buf)
		if err != nil || n != 16 {
			t.Fatalf("Read = (%d, %v), want (16, nil): the complete block must be delivered", n, err)
		}
		if !bytes.Equal(buf[:16], plaintext[:16]) {
			t.Errorf("block = %x, want %x", buf[:16], plaintext[:16])
		}
		if _, err := dec.Read(buf); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("Read after truncation = %v, want ErrUnexpectedEOF", err)
		}
	})

	t.Run("truncated partial block only", func(t *testing.T) {
		key, iv := testKeyIV("StreamFramingKey!")
		dec, err := NewDecryptReader(bytes.NewReader(make([]byte, 5)), key, iv)
		if err != nil {
			t.Fatal(err)
		}
		// Both buffer sizes must refuse: CBC cannot decrypt 5 bytes, and no
		// plaintext may be invented for them.
		if n, err := dec.Read(make([]byte, 4)); n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("sub-block Read = (%d, %v), want (0, ErrUnexpectedEOF)", n, err)
		}
	})
}

// endlessReader hands back as much (meaningless) ciphertext as asked for,
// forever, without allocating. It exists so the allocation test can measure
// Read in isolation.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) { return len(p), nil }

// The frame path decrypts in place in the caller's buffer, so a 32-byte frame
// read must not allocate. Frames arrive at mouse-move rate; an allocation here
// is per-event garbage.
func TestDecryptReaderFramePathDoesNotAllocate(t *testing.T) {
	key, iv := testKeyIV("StreamFramingKey!")
	dec, err := NewDecryptReader(endlessReader{}, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, PacketSize)
	var readErr error
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := dec.Read(buf); err != nil {
			readErr = err
		}
	})
	if readErr != nil {
		t.Fatalf("Read: %v", readErr)
	}
	if allocs != 0 {
		t.Errorf("frame read allocates %.1f times per call, want 0", allocs)
	}
}

// The bug this reader had, end to end: a consumer handed the stream through
// Conn.Reader() reads a few bytes, and the frame after it must still pass the
// magic/checksum validation the C# peer performs (Class/SocketStuff.cs:543,554).
// Dropping the tail of the consumed block used to desynchronise the CBC chain
// and every later frame failed both checks.
func TestDecryptReaderShortReadKeepsLaterFramesValid(t *testing.T) {
	magic := Get24BitHash("StreamFramingKey!")

	frame1 := bytes.Repeat([]byte{0x10}, PacketSize)
	frame2 := bytes.Repeat([]byte{0x20}, PacketSize)
	StampPacket(frame1, magic)
	StampPacket(frame2, magic)

	dec, _, ctLen := streamFixture(t, append(append([]byte{}, frame1...), frame2...))

	// A consumer that reads a sub-block amount: io.LimitReader, a text scanner,
	// anything not written against our 16-byte assumption.
	head := make([]byte, 5)
	if _, err := io.ReadFull(dec, head); err != nil {
		t.Fatal(err)
	}
	rest := make([]byte, 2*PacketSize-len(head))
	if _, err := io.ReadFull(dec, rest); err != nil {
		t.Fatal(err)
	}

	got := append(append([]byte{}, head...), rest...)
	if len(got) != ctLen {
		t.Fatalf("delivered %d plaintext bytes for %d ciphertext bytes", len(got), ctLen)
	}
	if err := ValidatePacket(got[PacketSize:], magic); err != nil {
		t.Errorf("frame after a 5-byte read failed peer validation: %v", err)
	}
	if !bytes.Equal(got[:PacketSize], frame1) || !bytes.Equal(got[PacketSize:], frame2) {
		t.Errorf("frames corrupted:\n got %x\nwant %x%x", got, frame1, frame2)
	}
}

// --- recoverable short reads and writes ---

// deadlineReader delivers n bytes, then one recoverable error, then the rest —
// modelling a socket whose read deadline fires mid-block. network.idleReader
// refreshes the deadline before every Read precisely so this is retryable.
type deadlineReader struct {
	data  []byte
	pos   int
	stall int // byte offset at which to inject the error
	fired bool
}

var errDeadline = errors.New("i/o timeout")

func (r *deadlineReader) Read(p []byte) (int, error) {
	if !r.fired && r.pos >= r.stall {
		r.fired = true
		return 0, errDeadline
	}
	limit := len(r.data)
	if !r.fired && limit > r.stall {
		limit = r.stall
	}
	if r.pos >= limit {
		if r.pos >= len(r.data) {
			return 0, io.EOF
		}
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:limit])
	r.pos += n
	return n, nil
}

// TestDecryptReaderRecoversFromMidBlockStall is the regression test for silent
// ciphertext loss. A deadline that fires after a partial block must not consume
// those bytes: retrying has to resume exactly where the stream left off, or
// every later block decrypts to garbage.
func TestDecryptReaderRecoversFromMidBlockStall(t *testing.T) {
	key, iv := testKeyIV("StreamFramingKey!")
	plaintext := bytes.Repeat([]byte("0123456789abcdef"), 3) // 48 bytes

	var cipherBuf bytes.Buffer
	enc, err := NewEncryptWriter(&cipherBuf, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(plaintext); err != nil {
		t.Fatal(err)
	}

	// Stall 20 bytes in: one whole block plus 4 bytes of the next.
	src := &deadlineReader{data: cipherBuf.Bytes(), stall: 20}
	dec, err := NewDecryptReader(src, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	var got []byte
	buf := make([]byte, 48)
	for len(got) < len(plaintext) {
		n, err := dec.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			if errors.Is(err, errDeadline) {
				continue // the deadline was refreshed; retry, as idleReader does
			}
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("Read: %v", err)
		}
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("stream desynchronised after a recoverable stall\n got %x\nwant %x", got, plaintext)
	}
}

// shortWriter truncates the FIRST write only, then behaves perfectly.
//
// That matters: if it kept failing, the second Write would return an error
// whether or not EncryptWriter poisons itself, and the test could not tell the
// two apart. Because the underlying writer is healthy again, any error from the
// second Write can only come from the poison.
type shortWriter struct {
	buf     bytes.Buffer
	limit   int
	written int
	tripped bool
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if !w.tripped {
		w.tripped = true
		n := w.limit
		if n > len(p) {
			n = len(p)
		}
		w.buf.Write(p[:n])
		w.written += n
		return n, errDeadline
	}
	w.buf.Write(p)
	w.written += len(p)
	return len(p), nil
}

// TestEncryptWriterPoisonsOnShortWrite: once the CBC chain has advanced over
// ciphertext that never reached the wire, the stream can never be trusted
// again. Subsequent writes must fail rather than quietly emit frames the peer
// will decode as noise.
func TestEncryptWriterPoisonsOnShortWrite(t *testing.T) {
	key, iv := testKeyIV("StreamFramingKey!")
	w := &shortWriter{limit: 20}
	enc, err := NewEncryptWriter(w, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	n, err := enc.Write(bytes.Repeat([]byte{0x11}, 32))
	if err == nil {
		t.Fatal("a short write must report an error")
	}
	if n != 20 {
		t.Errorf("wrote %d bytes, want 20", n)
	}

	// The underlying writer is healthy from here on, so an error can only come
	// from the poison. Without poisoning this write would succeed.
	if _, err := enc.Write(bytes.Repeat([]byte{0x22}, 32)); err == nil {
		t.Fatal("the writer must stay poisoned: the peer's CBC chain is already offset, " +
			"and the underlying writer recovering does not resynchronise it")
	}
	if !errors.Is(err, ErrStreamDesynced) {
		t.Errorf("the error must wrap ErrStreamDesynced so callers can tear the "+
			"connection down; got %v", err)
	}
	if w.written != 20 {
		t.Errorf("poisoned writer emitted %d bytes total, want 20 (nothing after the "+
			"short write)", w.written)
	}
}

// TestDecryptReaderSubBlockStallRecovers covers the OTHER carry path: a
// sub-block request (len(p) < 16) that finds only a partial block on the wire.
// Those consumed bytes must be held too, or a retry resumes mid-block.
func TestDecryptReaderSubBlockStallRecovers(t *testing.T) {
	key, iv := testKeyIV("StreamFramingKey!")
	plaintext := []byte("sixteen bytes!!!") // exactly one block

	var cipherBuf bytes.Buffer
	enc, err := NewEncryptWriter(&cipherBuf, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(plaintext); err != nil {
		t.Fatal(err)
	}

	// Stall 7 bytes into the single block, so the sub-block path takes a short
	// read with a recoverable error.
	src := &deadlineReader{data: cipherBuf.Bytes(), stall: 7}
	dec, err := NewDecryptReader(src, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	var got []byte
	one := make([]byte, 1)
	for len(got) < len(plaintext) {
		n, err := dec.Read(one)
		got = append(got, one[:n]...)
		if err != nil {
			if errors.Is(err, errDeadline) {
				continue // deadline refreshed, retry
			}
			t.Fatalf("Read: %v", err)
		}
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("sub-block path lost or duplicated bytes across a stall\n got %q\nwant %q",
			got, plaintext)
	}
}

// TestDecryptReaderNeverReturnsZeroNil pins the io.Reader contract across the
// whole three-piece state machine. A (0, nil) return spins io.ReadFull forever.
func TestDecryptReaderNeverReturnsZeroNil(t *testing.T) {
	key, iv := testKeyIV("StreamFramingKey!")
	plaintext := bytes.Repeat([]byte("0123456789abcdef"), 4) // 64 bytes

	// Exercise a spread of buffer sizes, including non-multiples of 16 and
	// sizes larger than the whole stream.
	for _, bufSize := range []int{1, 3, 8, 15, 16, 17, 31, 32, 40, 64, 100} {
		var cipherBuf bytes.Buffer
		enc, err := NewEncryptWriter(&cipherBuf, key, iv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := enc.Write(plaintext); err != nil {
			t.Fatal(err)
		}
		dec, err := NewDecryptReader(bytes.NewReader(cipherBuf.Bytes()), key, iv)
		if err != nil {
			t.Fatal(err)
		}

		var got []byte
		buf := make([]byte, bufSize)
		for i := 0; i < 1000; i++ {
			n, err := dec.Read(buf)
			if n == 0 && err == nil {
				t.Fatalf("bufSize %d: Read returned (0, nil), which spins callers forever", bufSize)
			}
			if n > bufSize {
				t.Fatalf("bufSize %d: Read returned %d, more than the buffer", bufSize, n)
			}
			got = append(got, buf[:n]...)
			if err != nil {
				break
			}
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("bufSize %d: recovered %d bytes, want %d", bufSize, len(got), len(plaintext))
		}
	}
}
