// internal/protocol/crypto_test.go
package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex vector %q: %v", s, err)
	}
	return b
}

// TestAESCBCNISTVectors pins our AES-256-CBC usage to NIST SP 800-38A appendix
// F.2.5/F.2.6 (CBC-AES256.Encrypt / .Decrypt). These are published standard
// vectors and were independently reproduced with `openssl enc -aes-256-cbc
// -nopad` on this machine, so they are true cross-implementation ground truth —
// the .NET peer cannot be executed here, but both it and we must satisfy these.
func TestAESCBCNISTVectors(t *testing.T) {
	key := mustHex(t, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	iv := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	plaintext := mustHex(t, ""+
		"6bc1bee22e409f96e93d7e117393172a"+
		"ae2d8a571e03ac9c9eb76fac45af8e51"+
		"30c81c46a35ce411e5fbc1191a0a52ef"+
		"f69f2445df4f9b17ad2b417be66c3710")
	want := mustHex(t, ""+
		"f58c4c04d6e5f1ba779eabfb5f7bfbd6"+
		"9cfc4e967edb808d679f777bc6702c7d"+
		"39f23369a9d9bacfa530e26304231461"+
		"b2eb05e2c39be9fcda6c19078c6a9d1b")

	var enc bytes.Buffer
	w, err := NewEncryptWriter(&enc, key, iv)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(enc.Bytes(), want) {
		t.Errorf("ciphertext mismatch\n got %x\nwant %x", enc.Bytes(), want)
	}

	r, err := NewDecryptReader(bytes.NewReader(want), key, iv)
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	got := make([]byte, len(plaintext))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch\n got %x\nwant %x", got, plaintext)
	}
}

// TestPBKDF2CrossImplementation pins DeriveKey to values produced by CPython's
// hashlib.pbkdf2_hmac (OpenSSL-backed), an implementation entirely independent
// of golang.org/x/crypto. A mismatch here means the password encoding, the hash
// choice or the iteration count has drifted from what .NET's
// Rfc2898DeriveBytes.Pbkdf2 computes.
func TestPBKDF2CrossImplementation(t *testing.T) {
	salt := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	const securityKey = "TestSecurityKey!!"

	cases := []struct {
		iterations int
		want       string
	}{
		{DefaultPBKDF2Iterations, "20e933f5ef7c2a6ef68458cf03f4522e57eb31bc2ad80379147640c56d7e70ab"},
		{UpstreamPBKDF2Iterations, "5fca849920ece2fda0ff99537f580508fae95b9466c9bb4e52984093623984bc"},
	}
	for _, tc := range cases {
		got := DeriveKey(securityKey, salt, tc.iterations)
		if len(got) != aesKeySize {
			t.Fatalf("iterations=%d: key length = %d, want %d", tc.iterations, len(got), aesKeySize)
		}
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("iterations=%d:\n got %x\nwant %s", tc.iterations, got, tc.want)
		}
	}
}

// TestDeriveKeyPasswordEncodingIsUTF8 guards the password encoding.
// .NET's Rfc2898DeriveBytes.Pbkdf2(string, ...) encodes the password as UTF-8.
// Config validation rejects non-ASCII keys (because Get24BitHash uses a
// different encoding), but if that guard is ever relaxed this test documents
// which encoding the KDF must use.
func TestDeriveKeyPasswordEncodingIsUTF8(t *testing.T) {
	salt := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	const key = "pä§§word-1234567"
	want := pbkdf2.Key([]byte(key), salt, DefaultPBKDF2Iterations, aesKeySize, sha512.New)
	if got := DeriveKey(key, salt, DefaultPBKDF2Iterations); !bytes.Equal(got, want) {
		t.Errorf("password must be UTF-8 encoded\n got %x\nwant %x", got, want)
	}
}

func TestDeriveKeyVariesWithSalt(t *testing.T) {
	const securityKey = "TestSecurityKey!!"
	saltA := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	saltB := mustHex(t, "0f0e0d0c0b0a09080706050403020100")

	a := DeriveKey(securityKey, saltA, DefaultPBKDF2Iterations)
	b := DeriveKey(securityKey, saltB, DefaultPBKDF2Iterations)
	if bytes.Equal(a, b) {
		t.Fatal("different salts must produce different keys — a shared salt would " +
			"silently reuse key material across connections and directions")
	}
	if again := DeriveKey(securityKey, saltA, DefaultPBKDF2Iterations); !bytes.Equal(a, again) {
		t.Fatal("derivation must be deterministic for a given salt")
	}
	other := DeriveKey("DifferentKey12345", saltA, DefaultPBKDF2Iterations)
	if bytes.Equal(a, other) {
		t.Fatal("different security keys must produce different keys")
	}
}

func TestDeriveKeyDefaultsIterations(t *testing.T) {
	salt := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	want := DeriveKey("TestSecurityKey!!", salt, DefaultPBKDF2Iterations)
	for _, n := range []int{0, -1} {
		if got := DeriveKey("TestSecurityKey!!", salt, n); !bytes.Equal(got, want) {
			t.Errorf("iterations=%d should fall back to the default", n)
		}
	}
}

func TestNewPrologue(t *testing.T) {
	salt, iv, err := NewPrologue()
	if err != nil {
		t.Fatalf("NewPrologue: %v", err)
	}
	if len(salt) != SaltSize {
		t.Errorf("salt length = %d, want %d", len(salt), SaltSize)
	}
	if len(iv) != IVSize {
		t.Errorf("iv length = %d, want %d", len(iv), IVSize)
	}
	if SaltSize+IVSize != PrologueSize {
		t.Errorf("PrologueSize = %d, want %d", PrologueSize, SaltSize+IVSize)
	}
	salt2, iv2, err := NewPrologue()
	if err != nil {
		t.Fatalf("NewPrologue: %v", err)
	}
	if bytes.Equal(salt, salt2) {
		t.Error("salt must be random per call")
	}
	if bytes.Equal(iv, iv2) {
		t.Error("iv must be random per call")
	}
}

// TestGet24BitHashCrossImplementation pins the magic number to values produced
// by an independent Python transcription of PowerToys Core/Encryption.cs
// Get24BitHash (SHA-512 over a 32-byte key buffer, then 50,000 further SHA-512
// rounds, then (h[0]<<23)+(h[1]<<16)+(h[63]<<8)+h[2]).
//
// The individual bytes matter operationally: PowerToys logs "magic: h0,h1,h63"
// at startup, which is the only cross-implementation check available without
// running .NET. The `mwb hash` subcommand prints the same three numbers.
func TestGet24BitHashCrossImplementation(t *testing.T) {
	cases := []struct {
		key                 string
		want                uint32
		h0, h1, hLast, hTwo byte
	}{
		{"TestSecurityKey!!", 0x2F4024E0, 94, 64, 36, 224},
		{"DifferentKey12345", 0x1EDA4686, 61, 90, 70, 134},
	}
	for _, tc := range cases {
		if got := Get24BitHash(tc.key); got != tc.want {
			t.Errorf("Get24BitHash(%q) = 0x%08X, want 0x%08X", tc.key, got, tc.want)
		}
		// Reconstruct the logged bytes from the packed value to prove the
		// arithmetic, including that h[0] is shifted by 23 and not 24.
		wantPacked := (uint32(tc.h0) << 23) + (uint32(tc.h1) << 16) + (uint32(tc.hLast) << 8) + uint32(tc.hTwo)
		if wantPacked != tc.want {
			t.Errorf("vector self-inconsistent for %q: packed 0x%08X != 0x%08X", tc.key, wantPacked, tc.want)
		}
	}
	if Get24BitHash("") != 0 {
		t.Error("empty key must return 0")
	}
}

// TestGet24BitHashOnlyFirst32Chars documents that the magic number is computed
// over a 32-byte buffer, so characters past the 32nd are invisible to it.
// Core/Encryption.cs:179-186.
func TestGet24BitHashOnlyFirst32Chars(t *testing.T) {
	base := "0123456789abcdef0123456789abcdef" // exactly 32
	if Get24BitHash(base) != Get24BitHash(base+"ignored-tail") {
		t.Error("characters beyond the 32nd must not affect the magic number")
	}
}

// TestGet24BitHashUsesUTF16CodeUnits pins the non-ASCII behaviour.
//
// C# fills the buffer with `(byte)st[i]` — the low byte of each UTF-16 code
// unit (Core/Encryption.cs:184) — NOT the UTF-8 bytes. PowerToys' own key
// validation checks only length (Encryption.cs:236), so a non-ASCII key is
// reachable, and using UTF-8 here would produce a different magic number while
// the AES key (PBKDF2, UTF-8 on both sides) still matched — a link that
// decrypts perfectly and then rejects every frame.
//
// Expected values come from an independent Python transcription of the C#.
func TestGet24BitHashUsesUTF16CodeUnits(t *testing.T) {
	cases := []struct {
		key  string
		want uint32
	}{
		{"pä§§word-1234567", 0x5084DCB6},
		{"日本語キー1234567890", 0x1E955018},
	}
	for _, tc := range cases {
		if got := Get24BitHash(tc.key); got != tc.want {
			t.Errorf("Get24BitHash(%q) = 0x%08X, want 0x%08X "+
				"(UTF-8 bytes were probably used instead of UTF-16 code units)",
				tc.key, got, tc.want)
		}
	}
}

// TestKeyIsWindowsCompatible covers the upstream signed/unsigned comparison bug
// that makes roughly one key in 512 unusable — see KeyIsWindowsCompatible.
//
// "MwbTestKey000173" is a real 16-character key whose magic is 0x804BAB8F, i.e.
// bit 31 set (h[0] == 255, h[1] == 203). It was found by search and confirmed
// with an independent Python transcription of Get24BitHash.
func TestKeyIsWindowsCompatible(t *testing.T) {
	const incompatible = "MwbTestKey000173"

	if got := Get24BitHash(incompatible); got != 0x804BAB8F {
		t.Fatalf("vector drifted: Get24BitHash(%q) = 0x%08X, want 0x804BAB8F", incompatible, got)
	}
	if KeyIsWindowsCompatible(incompatible) {
		t.Errorf("a key whose magic is 0x%08X cannot work with MWB and must be reported "+
			"incompatible: PowerToys computes the wire magic into a signed int, so a "+
			"negative value never equals its unsigned expectation "+
			"(Class/SocketStuff.cs:536-540)", Get24BitHash(incompatible))
	}

	for _, ok := range []string{"TestSecurityKey!!", "DifferentKey12345", "AAAABBBBCCCCDDDD"} {
		if Get24BitHash(ok)&0x80000000 != 0 {
			t.Fatalf("vector drifted: %q unexpectedly has bit 31 set", ok)
		}
		if !KeyIsWindowsCompatible(ok) {
			t.Errorf("%q has bit 31 clear and must be reported compatible", ok)
		}
	}
}

// TestGet24BitHashAstralPlane pins surrogate-pair handling. C# iterates UTF-16
// code units (Core/Encryption.cs:182-186 over st.Length), so an astral-plane
// character contributes TWO buffer bytes — the low bytes of its high and low
// surrogates — not one byte per rune and not its UTF-8 bytes. Expected value
// from an independent Python transcription.
func TestGet24BitHashAstralPlane(t *testing.T) {
	const key = "\U0001F600key1234567890ab" // U+1F600 GRINNING FACE, then ASCII
	const astralMagic = 0x4A03B114          // UTF-16 code units (what C# does)
	const runeMagic = 0x6CDD9CD5            // one byte per rune (what C# does NOT do)
	got := Get24BitHash(key)
	if got != astralMagic {
		t.Errorf("Get24BitHash(%q) = 0x%08X, want 0x%08X — surrogate pairs must "+
			"contribute two code units, as they do in C#", key, got, astralMagic)
	}
	// A rune-based implementation would treat the emoji as one unit, which is a
	// different buffer and so a different digest.
	if got == runeMagic {
		t.Error("the digest matches a rune-based buffer; UTF-16 code units are required")
	}
}

func TestChecksumAndMagic(t *testing.T) {
	magic := Get24BitHash("TestSecurityKey!!")

	p := &Packet{Type: Mouse, ID: 1, Src: 1, Des: 2}
	p.Mouse.X = 100
	p.Mouse.Y = 200
	buf := p.Marshal()

	StampPacket(buf, magic)

	expectedHi := byte((magic >> 24) & 0xFF)
	expectedLo := byte((magic >> 16) & 0xFF)
	if buf[3] != expectedHi || buf[2] != expectedLo {
		t.Errorf("magic bytes = [%x, %x], want [%x, %x]", buf[2], buf[3], expectedLo, expectedHi)
	}

	if err := ValidatePacket(buf, magic); err != nil {
		t.Errorf("validation failed: %v", err)
	}

	buf[15] ^= 0xFF
	if err := ValidatePacket(buf, magic); err == nil {
		t.Error("validation should fail after corruption")
	}
}

// TestChecksumIgnoresExtendedBytes locks in a deliberate protocol quirk.
//
// PowerToys computes the checksum over bytes 2..31 ONLY, even for 64-byte
// frames (Class/SocketStuff.cs:511-517 and :548-552, both bounded by
// PACKAGE_SIZE == 32). Bytes 32..63 — the machine name and the clipboard
// payload extension — are therefore NOT covered. This looks like a bug and is
// a tempting "cleanup"; widening the bound would break interoperability with
// every real MWB peer. If this test ever fails, the change is wrong.
func TestChecksumIgnoresExtendedBytes(t *testing.T) {
	magic := Get24BitHash("TestSecurityKey!!")

	p := &Packet{Type: Heartbeat, ID: 7, Src: 3, Des: IDAll}
	p.SetMachineName("linuxbox")
	buf := p.Marshal()
	if len(buf) != PacketSizeEx {
		t.Fatalf("Heartbeat must be a %d-byte frame, got %d", PacketSizeEx, len(buf))
	}
	StampPacket(buf, magic)
	if err := ValidatePacket(buf, magic); err != nil {
		t.Fatalf("baseline validation failed: %v", err)
	}

	// Corrupting the extended region must NOT invalidate the frame.
	buf[40] ^= 0xFF
	if err := ValidatePacket(buf, magic); err != nil {
		t.Errorf("bytes 32..63 are outside the MWB checksum; validation must still "+
			"pass, got: %v", err)
	}

	// Corrupting the covered region must invalidate it.
	buf[31] ^= 0xFF
	if err := ValidatePacket(buf, magic); err == nil {
		t.Error("byte 31 is inside the checksum; validation must fail")
	}
}

// TestBigPacketTypeSetMatchesPowerToys locks in the exact set of 64-byte frame
// types from Core/DATA.cs:124-133. IsBigPacket is the sole arbiter of frame
// length on the read side, so any disagreement with the C# peer is an
// unrecoverable CBC desync rather than a dropped packet.
//
// In particular HeartbeatExL2/L3, MachineSwitched and NextMachine are 32-byte
// frames in PowerToys, and Invalid/Error are 64-byte frames because they have
// bit 0x80 set.
func TestBigPacketTypeSetMatchesPowerToys(t *testing.T) {
	big := map[PackageType]bool{
		Hello: true, Awake: true, Heartbeat: true, HeartbeatEx: true,
		Handshake: true, HandshakeAck: true, ClipboardPush: true, Clipboard: true,
		ClipboardAsk: true, ClipboardImage: true, ClipboardText: true, ClipboardDataEnd: true,
		// Matrix family and Invalid/Error, via the 0x80 bit.
		Matrix: true, Invalid: true, Error: true,
	}
	small := []PackageType{
		Hi, ByeBye, HideMouse, HeartbeatExL2, HeartbeatExL3,
		ClipboardDragDrop, ClipboardDragDropEnd, ExplorerDragDrop, ClipboardCapture,
		CaptureScreenCommand, ClipboardDragDropOp, MachineSwitched, NextMachine,
		Keyboard, Mouse,
	}
	for pt := range big {
		if !IsBigPacket(pt) {
			t.Errorf("type %d must be a %d-byte frame", pt, PacketSizeEx)
		}
	}
	for _, pt := range small {
		if IsBigPacket(pt) {
			t.Errorf("type %d must be a %d-byte frame", pt, PacketSize)
		}
	}
	// The Matrix flag combinations PowerToys actually emits
	// (Core/MachineStuff.cs:965-967: Matrix | MatrixSwapFlag | MatrixTwoRowFlag).
	for _, pt := range []PackageType{Matrix, Matrix | 2, Matrix | 4, Matrix | 2 | 4} {
		if !IsBigPacket(pt) {
			t.Errorf("Matrix variant %d must be a %d-byte frame", pt, PacketSizeEx)
		}
	}
}
