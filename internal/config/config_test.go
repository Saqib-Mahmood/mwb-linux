// internal/config/config_test.go
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(`
host = "192.168.1.50"
key = "MySecurityKey1234"
name = "testbox"
port = 15100
`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "192.168.1.50" {
		t.Errorf("host = %q, want %q", cfg.Host, "192.168.1.50")
	}
	if cfg.Key != "MySecurityKey1234" {
		t.Errorf("key = %q", cfg.Key)
	}
	if cfg.Name != "testbox" {
		t.Errorf("name = %q", cfg.Name)
	}
	if cfg.Port != 15100 {
		t.Errorf("port = %d, want 15100", cfg.Port)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(`
host = "10.0.0.1"
key = "SomeKeyHere!1234"
`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 15100 {
		t.Errorf("default port = %d, want 15100", cfg.Port)
	}
	if cfg.Name == "" {
		t.Error("name should default to hostname")
	}
	if cfg.AccelMultiplier != 2.0 {
		t.Errorf("default accel_multiplier = %v, want 2.0", cfg.AccelMultiplier)
	}
	if cfg.InboundMultiplier != 1.0 {
		t.Errorf("default inbound_multiplier = %v, want 1.0", cfg.InboundMultiplier)
	}
	if cfg.KeyboardLayout != "auto" {
		t.Errorf("default keyboard_layout = %q, want auto", cfg.KeyboardLayout)
	}
}

func TestAccelMultiplierExplicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(`
host = "10.0.0.1"
key = "SomeKeyHere!1234"
accel_multiplier = 0.5
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AccelMultiplier != 0.5 {
		t.Errorf("accel_multiplier = %v, want 0.5", cfg.AccelMultiplier)
	}
}

func TestKeyboardLayoutExplicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(`
host = "10.0.0.1"
key = "SomeKeyHere!1234"
keyboard_layout = "de"
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KeyboardLayout != "de" {
		t.Errorf("keyboard_layout = %q, want de", cfg.KeyboardLayout)
	}
}

func TestClipboardEnabledDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(`
host = "10.0.0.1"
key = "SomeKeyHere!1234"
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ClipboardEnabled() {
		t.Error("clipboard should default to enabled when the key is absent")
	}
}

func TestClipboardDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(`
host = "10.0.0.1"
key = "SomeKeyHere!1234"
clipboard = false
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClipboardEnabled() {
		t.Error("clipboard = false should disable clipboard sharing")
	}
}

func TestClipboardEnabledExplicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(`
host = "10.0.0.1"
key = "SomeKeyHere!1234"
clipboard = true
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ClipboardEnabled() {
		t.Error("clipboard = true should enable clipboard sharing")
	}
}

func TestLoadConfigValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	// Missing host
	if err := os.WriteFile(path, []byte(`key = "SomeKeyHere!1234"`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("should fail without host")
	}

	// Missing key
	if err := os.WriteFile(path, []byte(`host = "10.0.0.1"`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("should fail without key")
	}
}

func TestLoadTightensConfigPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(`
host = "10.0.0.1"
key = "SomeKeyHere!1234"
`), 0664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("config permissions = %04o, want 0600", got)
	}
}

// writeConfig is a small helper so the whitespace/name cases below stay short.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// PowerToys stores the security key verbatim: the shipping settings UI assigns
// it straight through (Settings.UI/ViewModels/MouseWithoutBordersViewModel.cs:716-718)
// and renders it in a read-only TextBox unchanged
// (SettingsXAML/Views/MouseWithoutBordersPage.xaml:66).
//
// Only the legacy WinForms page stripped whitespace
// (Form/Settings/SetupPage2a.cs:92), and KeyDisplayedText — the grouped
// rendering that would justify stripping — has no callers anywhere in the tree.
// So interior whitespace MUST be preserved: stripping it would derive a
// different AES key from the peer's, failing in a way that is indistinguishable
// from a wrong key.
func TestKeyInteriorWhitespacePreserved(t *testing.T) {
	spaced, err := Load(writeConfig(t, "host = \"10.0.0.1\"\nkey = \"AAAA BBBB CCCC DDDD\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if spaced.Key != "AAAA BBBB CCCC DDDD" {
		t.Fatalf("key = %q, want it preserved verbatim", spaced.Key)
	}

	plain, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
`))
	if err != nil {
		t.Fatal(err)
	}
	if plain.Key == spaced.Key {
		t.Error("a spaced key and an unspaced key are different keys and must stay different")
	}
}

// Edge whitespace is a copy-paste artifact and cannot be part of a key shown in
// a TextBox, so trimming it is safe and helpful.
func TestKeyEdgeWhitespaceTrimmed(t *testing.T) {
	cfg, err := Load(writeConfig(t, "host = \"10.0.0.1\"\nkey = \"  AAAABBBBCCCCDDDD\t \"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Key != "AAAABBBBCCCCDDDD" {
		t.Errorf("key = %q, want edge whitespace trimmed", cfg.Key)
	}
}

// A short key is warned about, not rejected. Encryption.IsKeyValid's 16-char
// rule has exactly one caller — the legacy WinForms dialog at
// Form/frmMatrix.cs:508 — and nothing enforces it at runtime, so a shorter key
// written straight into settings.json really does work between two Windows
// machines. Refusing it here would break a working pair.
func TestShortKeyIsAcceptedWithAWarning(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDD"
`))
	if err != nil {
		t.Fatalf("a 15-character key must still be usable: %v", err)
	}
	if cfg.Key != "AAAABBBBCCCCDDD" {
		t.Errorf("key = %q, want it passed through unchanged", cfg.Key)
	}
}

func TestKeyExactlyMinLength(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
`))
	if err != nil {
		t.Fatalf("a %d-character key must be accepted: %v", MinKeyLen, err)
	}
	if len(cfg.Key) != MinKeyLen {
		t.Errorf("key length = %d, want %d", len(cfg.Key), MinKeyLen)
	}
}

// The wire field is 32 bytes (Core/DATA.cs:64-92) and Common.GetMachineName
// truncates at 32 (Core/Common.cs:1407-1410), not at the NetBIOS 15.
func TestMachineNameCap(t *testing.T) {
	long := strings.Repeat("a", 40)
	cfg, err := Load(writeConfig(t, "host = \"10.0.0.1\"\nkey = \"AAAABBBBCCCCDDDD\"\nname = \""+long+"\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Repeat("a", MaxMachineNameLen); cfg.Name != want {
		t.Errorf("name = %q (len %d), want %d chars", cfg.Name, len(cfg.Name), MaxMachineNameLen)
	}
}

func TestMachineNameShorterThanNetBIOSLimitIsUntouched(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
name = "linux-workstation-01"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Name != "linux-workstation-01" {
		t.Errorf("name = %q, want the full 20-character name", cfg.Name)
	}
}

func TestSanitizeMachineName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"  box  ", "box"},
		{"box.example.com", "box"}, // Dns.GetHostEntry needs the short label
		{".hidden", "hidden"},      // leading dot is not a label
		{"a:b,c", "abc"},           // pool/matrix separators
		{"héllo", "h??llo"},        // ASCIIEncoding folds to '?' (2 UTF-8 bytes)
		{strings.Repeat("é", 20), strings.Repeat("?", MaxMachineNameLen)},
		{"...", ""},
		{" , : . ", ""},
		{"MiXeD-Case_1", "MiXeD-Case_1"},
	}
	for _, c := range cases {
		got := sanitizeMachineName(c.in)
		if got != c.want {
			t.Errorf("sanitizeMachineName(%q) = %q, want %q", c.in, got, c.want)
		}
		if len(got) > MaxMachineNameLen {
			t.Errorf("sanitizeMachineName(%q) returned %d bytes, over the 32-byte wire field", c.in, len(got))
		}
		for i := 0; i < len(got); i++ {
			if got[i] >= 0x80 {
				t.Errorf("sanitizeMachineName(%q) = %q kept a non-ASCII byte", c.in, got)
				break
			}
		}
	}
}

func TestMachineNameSanitisedByLoad(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
name = "box.lan"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Name != "box" {
		t.Errorf("name = %q, want %q — a dotted name is overwritten with an IP by Windows", cfg.Name, "box")
	}
}

func TestEmptyMachineNameRejected(t *testing.T) {
	_, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
name = "..."
`))
	if err == nil {
		t.Fatal("a name that sanitises to empty should be rejected: LearnMachine throws on it")
	}
}

func TestKeyDerivationIterations(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.KeyDerivationIterations(); got != 50000 {
		t.Errorf("default iterations = %d, want 50000 (Core/Encryption.cs:41)", got)
	}

	cfg, err = Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
pbkdf2_iterations = 100000
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.KeyDerivationIterations(); got != 100000 {
		t.Errorf("iterations = %d, want 100000", got)
	}
}

func TestHeartbeatInterval(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.HeartbeatInterval(); got != 60*time.Second {
		t.Errorf("default heartbeat = %v, want 60s", got)
	}

	cfg, err = Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
heartbeat_seconds = 300
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.HeartbeatInterval(); got != 300*time.Second {
		t.Errorf("heartbeat = %v, want 300s", got)
	}
}

func TestMachineIDOverrideValidation(t *testing.T) {
	if _, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
machine_id = 255
`)); err == nil {
		t.Error("machine_id 255 is ID.ALL and must be rejected")
	}

	if _, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
machine_id = 2147483647
`)); err == nil {
		t.Error("machine_id above int32-1 must be rejected")
	}

	cfg, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
machine_id = 12345
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MachineID != 12345 {
		t.Errorf("machine_id = %d, want 12345", cfg.MachineID)
	}
}

// About 1 security key in 512 produces a magic number with bit 31 set, which
// PowerToys compares as a negative signed int and therefore always rejects —
// Class/SocketStuff.cs:536-540. Such a key cannot work at all, not even
// Windows-to-Windows, so Load refuses it with an explanation rather than
// letting the user debug a dead link.
func TestKeyWithIncompatibleMagicRejected(t *testing.T) {
	// A real 16-character key whose magic is 0x804BAB8F — bit 31 set.
	const incompatible = "MwbTestKey000173"

	_, err := Load(writeConfig(t, "host = \"10.0.0.1\"\nkey = \""+incompatible+"\"\n"))
	if err == nil {
		t.Fatal("a key whose magic has bit 31 set cannot work with MWB and must be rejected")
	}
	if !strings.Contains(err.Error(), "804BAB8F") {
		t.Errorf("the error should name the magic number so the cause is obvious, got: %v", err)
	}

	// And an ordinary key is still accepted.
	if _, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
`)); err != nil {
		t.Fatalf("an ordinary key must be accepted: %v", err)
	}
}

// The switch-feel knobs exist because the inherited defaults made a switch look
// and feel unlike a Windows-to-Windows one: a 200px entry offset is a visible
// jump (MWB uses 2px, Core/MachineStuff.cs:34) and 100ms of input suppression is
// a perceptible dead zone (MWB suppresses nothing).
func TestSwitchFeelDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.SwitchEntry(); got != 8 {
		t.Errorf("default entry offset = %d, want 8", got)
	}
	if got := cfg.SwitchGrace(); got != 15*time.Millisecond {
		t.Errorf("default grace = %v, want 15ms", got)
	}
}

func TestSwitchFeelOverrides(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
host = "10.0.0.1"
key = "AAAABBBBCCCCDDDD"
switch_entry_px = 2
switch_grace_ms = 40
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.SwitchEntry(); got != 2 {
		t.Errorf("entry offset = %d, want 2", got)
	}
	if got := cfg.SwitchGrace(); got != 40*time.Millisecond {
		t.Errorf("grace = %v, want 40ms", got)
	}
}

// 0 or 1 would put the cursor inside the peer's own 1px edge trigger
// (SKIP_PIXELS, Core/MachineStuff.cs:33) and bounce it straight back, so those
// fall back to the default rather than being honoured.
func TestSwitchEntryRejectsBounceProneValues(t *testing.T) {
	for _, v := range []int{0, 1, -5} {
		cfg := &Config{SwitchEntryPx: v}
		if got := cfg.SwitchEntry(); got != 8 {
			t.Errorf("switch_entry_px = %d resolved to %d, want the 8px default", v, got)
		}
	}
}

// A negative grace means "suppress nothing", which is closest to MWB.
func TestSwitchGraceCanBeDisabled(t *testing.T) {
	cfg := &Config{SwitchGraceMs: -1}
	if got := cfg.SwitchGrace(); got != 0 {
		t.Errorf("switch_grace_ms = -1 resolved to %v, want 0", got)
	}
}
