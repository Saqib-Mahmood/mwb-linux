// internal/protocol/stream.go
package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
)

// EncryptWriter wraps an io.Writer with AES-256-CBC encryption.
type EncryptWriter struct {
	w    io.Writer
	mode cipher.BlockMode

	// poisoned records a write that advanced the CBC chain without putting all
	// of the resulting ciphertext on the wire. See Write.
	poisoned error
}

// NewEncryptWriter creates an AES-256-CBC encrypting writer.
func NewEncryptWriter(w io.Writer, key, iv []byte) (*EncryptWriter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	return &EncryptWriter{w: w, mode: mode}, nil
}

// Write encrypts data and writes to the underlying writer.
// Data length must be a multiple of 16 (AES block size).
//
// A short write is unrecoverable and poisons the writer. Encryption has already
// advanced the CBC chain over the whole buffer, so if only part of the
// ciphertext reached the socket the peer's decryptor is now permanently offset
// from ours and every later frame fails its magic/checksum test
// (Class/SocketStuff.cs:543,554). That is easy to hit in practice: SendPacket
// puts a 500ms write deadline on every packet, and a congested socket returns
// (n < len, os.ErrDeadlineExceeded).
//
// Failing loudly from then on is the point. Several callers discard the error
// from an individual send — a dropped mouse packet is not worth tearing a
// connection down for — so without this the connection would look healthy while
// emitting nothing the peer can read. Poisoning turns silent corruption into a
// visible failure that the reconnect loop acts on.
func (e *EncryptWriter) Write(p []byte) (int, error) {
	if e.poisoned != nil {
		return 0, e.poisoned
	}
	if len(p)%aesBlockSize != 0 {
		return 0, fmt.Errorf("data length %d not multiple of %d", len(p), aesBlockSize)
	}
	ct := make([]byte, len(p))
	e.mode.CryptBlocks(ct, p)
	n, err := e.w.Write(ct)
	if n != len(ct) {
		if err == nil {
			// io.Writer forbids this, but be explicit rather than trusting it.
			err = io.ErrShortWrite
		}
		e.poisoned = fmt.Errorf("%w after a short write (%d of %d bytes): %w",
			ErrStreamDesynced, n, len(ct), err)
		return n, e.poisoned
	}
	return n, err
}

// ErrStreamDesynced marks an encrypted stream that can no longer be used. The
// connection must be torn down and re-established; there is no way to resync a
// CBC chain whose ciphertext was only partly delivered. Callers test for it with
// errors.Is so the failure becomes a reconnect rather than silent muteness.
var ErrStreamDesynced = errors.New("encrypted stream desynchronised")

// DecryptReader wraps an io.Reader with AES-256-CBC decryption.
type DecryptReader struct {
	r    io.Reader
	mode cipher.BlockMode

	// block is scratch for a read smaller than one AES block, and res is the
	// part of it the caller had no room for. CBC cannot decrypt less than a
	// whole block, so a short read must consume one and carry the remainder
	// over: dropping it would advance the CBC chain past plaintext nobody ever
	// saw, misaligning every later frame and making the C# peer log "Magic
	// number invalid!" / "Checksum invalid!" forever
	// (Class/SocketStuff.cs:543,554). The C# side never hits this because .NET's
	// CryptoStream keeps the undelivered tail of a decrypted block internally —
	// a runtime property of CryptoStream rather than anything visible in the
	// PowerToys source, which only chooses the mode
	// (Core/Encryption.cs:95 PaddingMode.Zeros, :143 CryptoStreamMode.Read).
	// This buffer is what gives us the same behaviour.
	//
	// Not safe for concurrent use: like the write side (see Conn.sendMu), one
	// reader at a time. The cipher state alone would make concurrent reads
	// garble a block; with a plaintext residual they could also hand one
	// caller bytes destined for another.
	block [aesBlockSize]byte
	res   []byte

	// ctCarry holds ciphertext that was consumed from the underlying reader but
	// did not complete a block, and so could not be decrypted yet.
	//
	// This matters because a short read is not always the end of the stream.
	// The bulk file channel wraps this reader in network.idleReader, which
	// refreshes the socket read deadline before every call precisely so that a
	// timeout is a recoverable per-read event. Discarding the partial block
	// would silently consume ciphertext the caller then retries past, leaving
	// the CBC chain permanently offset — the same class of failure this whole
	// type exists to prevent. At most aesBlockSize-1 bytes are ever held.
	ctCarry [aesBlockSize]byte
	ctN     int

	// err is a read error that arrived together with usable plaintext. The
	// bytes go out first and the error surfaces on the next call. It is not
	// sticky: after a recoverable error such as a deadline the caller may retry,
	// and the carry above is what makes that retry correct.
	err error
}

// fillCipher fills buf with ciphertext, drawing on any carried partial block
// first. Callers only ever pass a buffer of at least aesBlockSize, and the
// carry is at most aesBlockSize-1, so the carry always drains in one go.
func (d *DecryptReader) fillCipher(buf []byte) (int, error) {
	n := copy(buf, d.ctCarry[:d.ctN])
	d.ctN = 0
	if n == len(buf) {
		return n, nil
	}
	got, err := io.ReadFull(d.r, buf[n:])
	return n + got, err
}

// carry stores ciphertext that did not complete a block, for the next read.
func (d *DecryptReader) carry(b []byte) {
	d.ctN = copy(d.ctCarry[:], b)
}

// NewDecryptReader creates an AES-256-CBC decrypting reader.
func NewDecryptReader(r io.Reader, key, iv []byte) (*DecryptReader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	return &DecryptReader{r: r, mode: mode}, nil
}

// Read decrypts from the underlying reader and returns plaintext.
//
// One plaintext byte per ciphertext byte, always: the stream is CBC with
// PaddingMode.Zeros (Core/Encryption.cs:95), so there is no depadding holdback
// in either direction and no byte is ever consumed without being delivered.
//
// Like any io.Reader it may return fewer bytes than asked for — a request that
// straddles the tail of a buffered block stops at that boundary. That is the
// same contract the C# side codes against: Class/Extensions.cs:18-30 ReadEx
// loops on Stream.Read until the request is satisfied, so callers here must use
// io.ReadFull rather than assume one call fills the buffer.
func (d *DecryptReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Leftovers from an earlier short read outrank everything, including a
	// pending error: they are plaintext the caller has already paid for.
	if len(d.res) > 0 {
		n := copy(p, d.res)
		d.res = d.res[n:]
		return n, nil
	}
	if d.err != nil {
		err := d.err
		d.err = nil
		return 0, err
	}

	// Sub-block request: decrypt one block into our own buffer and keep the
	// tail. Uses the fixed-size scratch, so no allocation here either.
	if len(p) < aesBlockSize {
		got, err := d.fillCipher(d.block[:])
		if got < aesBlockSize {
			// Not enough for a block. Hold what arrived so a retry resumes in
			// the right place instead of skipping it.
			d.carry(d.block[:got])
			return 0, err
		}
		d.mode.CryptBlocks(d.block[:], d.block[:])
		n := copy(p, d.block[:])
		d.res = d.block[n:]
		return n, nil
	}

	// Whole blocks fit in p, so decrypt in place: one read, no allocation, the
	// path every 32/64-byte frame takes.
	n := (len(p) / aesBlockSize) * aesBlockSize
	got, err := d.fillCipher(p[:n])
	whole := (got / aesBlockSize) * aesBlockSize
	if got > whole {
		// A partial block's worth of ciphertext arrived. Keep it: on a
		// recoverable error the caller retries, and these bytes are still owed
		// to the stream.
		d.carry(p[whole:got])
	}
	if whole == 0 {
		// io.ReadFull never returns short with a nil error, so err is set here.
		return 0, err
	}
	if got == whole && errors.Is(err, io.ErrUnexpectedEOF) {
		// The stream ended on a block boundary, which is a clean end of stream.
		// io.ReadFull only calls it unexpected because we asked for more than
		// was left, and asking for more than a frame is legitimate here.
		err = io.EOF
	}
	d.mode.CryptBlocks(p[:whole], p[:whole])
	// A truncated stream can still have delivered complete blocks. Hand them
	// over and report the error next time, the way CryptoStream surfaces the
	// blocks it decrypted before it hits the incomplete final one.
	d.err = err
	return whole, nil
}
