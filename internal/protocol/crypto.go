// internal/protocol/crypto.go
package protocol

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"unicode/utf16"

	"golang.org/x/crypto/pbkdf2"
)

const (
	aesKeySize   = 32
	aesBlockSize = 16

	// SaltSize is the per-connection PBKDF2 salt length.
	// PowerToys Core/Encryption.cs: `private const int SaltSize = 16`.
	SaltSize = 16

	// IVSize is the AES-CBC IV length, equal to the block size.
	// PowerToys Core/Encryption.cs: `internal const int SymAlBlockSize = 16`.
	IVSize = aesBlockSize

	// PrologueSize is the length of the cleartext header that opens every
	// encrypted stream: salt(16) || IV(16). PowerToys writes it on the raw
	// socket *before* wrapping it in a CryptoStream, independently in each
	// direction (Core/Encryption.cs GetEncryptedStream/GetDecryptedStream).
	PrologueSize = SaltSize + IVSize

	// DefaultPBKDF2Iterations matches Core/Encryption.cs KeyDerivationIterations
	// in the reference PowerToys build (commit 3bf6820, 2026-06-29).
	DefaultPBKDF2Iterations = 50000

	// UpstreamPBKDF2Iterations is the value current PowerToys main uses after
	// the follow-up hardening PR. A mismatch is indistinguishable from a wrong
	// security key, so callers probe both.
	UpstreamPBKDF2Iterations = 100000
)

// DeriveKey derives the 32-byte AES-256 key from the shared security key and
// the per-connection salt received in the stream prologue.
//
// Mirrors PowerToys Core/Encryption.cs GenLegalKey:
//
//	Rfc2898DeriveBytes.Pbkdf2(MyKey, salt, KeyDerivationIterations, SHA512, 32)
//
// .NET's string overload encodes the password as UTF-8, hence []byte(securityKey).
// Note that Get24BitHash instead uses the low byte of each UTF-16 code unit, so the
// two disagree for non-ASCII keys — config validation rejects those.
func DeriveKey(securityKey string, salt []byte, iterations int) []byte {
	if iterations <= 0 {
		iterations = DefaultPBKDF2Iterations
	}
	return pbkdf2.Key([]byte(securityKey), salt, iterations, aesKeySize, sha512.New)
}

// NewPrologue generates the random salt and IV a peer sends in the clear at the
// start of a stream it encrypts. Both values are public; the shared security key
// is what keeps the derived key secret. The random salt defeats precomputed
// brute-force tables and the random IV avoids cross-session IV reuse.
func NewPrologue() (salt, iv []byte, err error) {
	buf := make([]byte, PrologueSize)
	if _, err := rand.Read(buf); err != nil {
		return nil, nil, fmt.Errorf("generate stream prologue: %w", err)
	}
	return buf[:SaltSize], buf[SaltSize:], nil
}

// magicDigest reproduces the hash chain in PowerToys Core/Encryption.cs
// Get24BitHash: a 32-byte buffer holding the low byte of each of the first 32
// key characters, one SHA-512, then 50,000 further SHA-512 rounds.
//
// The buffer is filled per UTF-16 code unit, not per UTF-8 byte, because C#
// does `bytes[i] = (byte)st[i]` over a UTF-16 string (Encryption.cs:182-186).
// For an ASCII key — everything the Windows key generator produces
// (Encryption.cs:211) — the two are identical; for anything else they diverge,
// and since PowerToys' own key validation only checks length (Encryption.cs:236)
// a non-ASCII key is possible. Note this is a *different* encoding from the one
// PBKDF2 uses: .NET's Rfc2898DeriveBytes.Pbkdf2 string overload is UTF-8. The
// two genuinely disagree upstream, and we have to reproduce both.
//
// The iteration count here is fixed at 50,000 and is unrelated to the PBKDF2
// count — upstream raised the latter but left this alone.
func magicDigest(key string) []byte {
	buf := make([]byte, PacketSize)
	for i, u := range utf16.Encode([]rune(key)) {
		if i >= PacketSize {
			break
		}
		buf[i] = byte(u)
	}
	h := sha512.New()
	h.Write(buf)
	hash := h.Sum(nil)
	for i := 0; i < 50000; i++ {
		h.Reset()
		h.Write(hash)
		hash = h.Sum(nil)
	}
	return hash
}

// packMagic applies the final arithmetic from Encryption.cs:198.
//
// The shift is 23, not 24 — so the h[0] and h[1] terms overlap at bit 23. That
// is upstream's arithmetic and therefore the protocol. C# computes it in an
// unchecked int and casts back to uint, which is the same value modulo 2^32.
func packMagic(hash []byte) uint32 {
	return uint32((int(hash[0]) << 23) + (int(hash[1]) << 16) + (int(hash[len(hash)-1]) << 8) + int(hash[2]))
}

// Get24BitHash computes the MWB magic number from the security key.
func Get24BitHash(key string) uint32 {
	if key == "" {
		return 0
	}
	return packMagic(magicDigest(key))
}

// MagicDetail returns the magic number together with the three digest bytes
// PowerToys prints at startup:
//
//	Core/Encryption.cs:196 — Logger.LogDebug("magic: {0},{1},{2}", h[0], h[1], h[^1])
//
// Comparing these against the Windows log is the only cross-implementation
// check of the key derivation available without running .NET, so `mwb hash`
// surfaces them. A mismatch means the security keys differ.
func MagicDetail(key string) (magic uint32, h0, h1, hLast byte) {
	if key == "" {
		return 0, 0, 0, 0
	}
	hash := magicDigest(key)
	return packMagic(hash), hash[0], hash[1], hash[len(hash)-1]
}

// KeyIsWindowsCompatible reports whether a security key can work with MWB at
// all. Roughly one key in 512 cannot, through no fault of ours.
//
// PowerToys validates the magic number like this (Class/SocketStuff.cs:536-540):
//
//	int magic = (buf[3] << 24) + (buf[2] << 16);
//	if (magic != (Encryption.MagicNumber & 0xFFFF0000)) { ...Invalid... }
//
// `magic` is a signed int, so when buf[3] >= 0x80 the shift overflows to a
// negative value, while the right-hand side is an unsigned uint. C# widens both
// to long, and a negative number never equals a positive one — so every frame
// is rejected, in both directions, even between two Windows machines.
//
// Bit 31 is set exactly when h[0] == 255 and h[1] >= 128, hence 1 in 512. There
// is nothing to fix on our side; the key has to be regenerated on Windows.
func KeyIsWindowsCompatible(key string) bool {
	return Get24BitHash(key)&0x80000000 == 0
}

// StampPacket sets the magic number and checksum in a marshaled packet buffer.
//
// The checksum deliberately covers bytes 2..31 ONLY, even for 64-byte frames.
// That is not an oversight: PowerToys Class/SocketStuff.cs:511-517 loops
// `for (int i = 2; i < Package.PACKAGE_SIZE; i++)` with PACKAGE_SIZE == 32, so
// bytes 32..63 (the machine name / clipboard extension) are genuinely
// unauthenticated on the wire. Widening this bound breaks interoperability.
// See TestChecksumIgnoresExtendedBytes.
//
// Order matters too: the magic bytes are written into buf[2] and buf[3] first
// and are therefore *included* in the sum.
func StampPacket(buf []byte, magic uint32) {
	buf[3] = byte((magic >> 24) & 0xFF)
	buf[2] = byte((magic >> 16) & 0xFF)
	buf[1] = 0
	for i := 2; i < PacketSize; i++ {
		buf[1] = buf[1] + buf[i]
	}
}

// ValidatePacket checks the magic number and checksum.
// The bytes 2..31 bound mirrors StampPacket — see the note there.
func ValidatePacket(buf []byte, magic uint32) error {
	wireMagic := uint32(buf[3])<<24 + uint32(buf[2])<<16
	expectedMagic := magic & 0xFFFF0000
	if wireMagic != expectedMagic {
		return fmt.Errorf("magic mismatch: wire=0x%08X expected=0x%08X", wireMagic, expectedMagic)
	}
	var checksum byte
	for i := 2; i < PacketSize; i++ {
		checksum += buf[i]
	}
	if buf[1] != checksum {
		return fmt.Errorf("checksum mismatch: wire=0x%02X computed=0x%02X", buf[1], checksum)
	}
	return nil
}

// ClearStamp zeroes bytes 1-3 after validation.
func ClearStamp(buf []byte) {
	buf[1] = 0
	buf[2] = 0
	buf[3] = 0
}
