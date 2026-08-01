package filetransfer

import (
	"errors"
	"fmt"
	"io"
)

// readAlignBlock is the boundary the RECEIVE side rounds a declared size up to.
//
// It is the AES-CBC block, not Package.PACKAGE_SIZE, and it deliberately differs
// from sendAlignBoundary below. The stream is raw CBC with no padding scheme:
// DecryptReader always consumes a whole block, so a body must be drained in
// whole blocks or the connection is left mid-block.
//
// It must not be raised to 32 to match the send side. MWB's inline clipboard
// sender pads with (L % 32) bytes rather than (32 - L % 32)
// (Class/SocketStuff.cs:1991), so for L = 32q+r it puts ceil((32q+2r)/16)*16
// bytes on the wire, which for r in 1..8 is less than the 32*ceil(L/32) a 32-boundary
// reader would demand: that reader would block on bytes a real C# peer never
// sends and then fail with ErrShortBody. Rounding to 16 is never more than
// either MWB sender emits, for any r.
const readAlignBlock = 16

// sendAlignBoundary is Package.PACKAGE_SIZE
// (Core/Package.cs:17), the boundary MWB's file sender pads the body to.
const sendAlignBoundary = 32

// copyBufSize is a multiple of both alignment boundaries so every intermediate
// write is already whole blocks and whole packages.
const copyBufSize = 64 * 1024

// readAlignedLen rounds n up to a whole number of AES blocks.
func readAlignedLen(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return (n + readAlignBlock - 1) / readAlignBlock * readAlignBlock
}

// sendPadLen is how many zero bytes follow a body of size bytes on the wire.
//
// MWB computes PACKAGE_SIZE - (sentCount % PACKAGE_SIZE)
// (Class/SocketStuff.cs:1920), which is 1..32 by construction: a body is always
// followed by zeros, and one whose length is already a multiple of 32 gets a
// full extra 32 bytes. Emitting nothing there would be one package short of
// byte-for-byte.
func sendPadLen(size int64) int64 {
	if size < 0 {
		size = 0
	}
	return sendAlignBoundary - size%sendAlignBoundary
}

// sendAlignedLen is the wire length of a body of size bytes: L + 32 - (L % 32).
func sendAlignedLen(size int64) int64 {
	if size < 0 {
		size = 0
	}
	return size + sendPadLen(size)
}

// writeAligned copies size bytes from r to w, followed by MWB's trailing zero
// package.
func writeAligned(w io.Writer, r io.Reader, size int64) (int64, error) {
	pad := sendPadLen(size)
	// One spare boundary so the padding always fits behind the final chunk.
	// EncryptWriter rejects a write that is not a whole AES block, and a pad of
	// 28 bytes is not one, so it cannot be handed over as a write of its own; it
	// has to ride along with the body bytes that precede it.
	buf := make([]byte, copyBufSize+sendAlignBoundary)
	var sent int64

	for sent < size {
		want := size - sent
		if want > copyBufSize {
			want = copyBufSize
		}
		if _, err := io.ReadFull(r, buf[:want]); err != nil {
			return sent, fmt.Errorf("read source: %w", err)
		}

		out := want
		if sent+want == size {
			out += pad
			// Zero explicitly rather than leaking whatever the buffer held from
			// the previous chunk.
			clear(buf[want:out])
		}
		if _, err := w.Write(buf[:out]); err != nil {
			return sent, err
		}
		sent += want
	}

	if size <= 0 {
		// No body chunk to carry the padding. It is a full boundary here, which
		// is a whole number of AES blocks, so a standalone write is legal.
		clear(buf[:pad])
		if _, err := w.Write(buf[:pad]); err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// readAligned reads readAlignedLen(size) bytes from r and writes the first size
// of them to w, discarding the sender's zero padding.
//
// Any padding past that is left in the stream on purpose: MWB sends one header
// per connection and closes, and its own receiver just reads to EOF and
// truncates at the declared size (Core/Clipboard.cs:618-660).
func readAligned(w io.Writer, r io.Reader, size int64) (int64, error) {
	buf := make([]byte, copyBufSize)
	var consumed, written int64
	total := readAlignedLen(size)

	for consumed < total {
		want := total - consumed
		if want > int64(len(buf)) {
			want = int64(len(buf))
		}
		if _, err := io.ReadFull(r, buf[:want]); err != nil {
			// A peer that closes early is short, not broken. Name it so callers
			// can distinguish truncation from a genuine transport failure.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return written, fmt.Errorf("%w: got %d of %d bytes", ErrShortBody, written, size)
			}
			return written, err
		}

		// Keep only the bytes that are inside the declared size; the rest is
		// padding the sender added to reach a block boundary.
		keep := want
		if consumed+keep > size {
			keep = size - consumed
		}
		if keep > 0 {
			if _, err := w.Write(buf[:keep]); err != nil {
				return written, err
			}
			written += keep
		}
		consumed += want
	}
	return written, nil
}
