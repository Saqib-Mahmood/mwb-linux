// internal/config/config.go
package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/BurntSushi/toml"

	"github.com/lucky-verma/mwb-linux/internal/protocol"
)

const (
	// MaxMachineNameLen is the MWB wire limit for a machine name, not the
	// Windows NetBIOS limit: the DATA struct carries the name in four int64s
	// (Core/DATA.cs:64-92, space-padded to 32 by the setter) and
	// Common.GetMachineName truncates its own hostname at exactly 32
	// (Core/Common.cs:1407-1410).
	MaxMachineNameLen = 32

	// MinKeyLen mirrors Encryption.IsKeyValid, the only key validation Windows
	// performs (Core/Encryption.cs:234-240).
	MinKeyLen = 16

	// defaultPBKDF2Iterations is Encryption.KeyDerivationIterations
	// (Core/Encryption.cs:41).
	defaultPBKDF2Iterations = 50000

	// defaultHeartbeatSeconds is the low end of PowerToys' own clamp. Windows
	// defaults HeartbeatIntervalSeconds to 300 but clamps reads to 60..3600
	// (Class/Setting.cs:1018-1033), and only expires a peer after
	// HEARTBEAT_TIMEOUT (30 min, Core/MachineStuff.cs:32). Beating at the 60s
	// floor keeps a restarted Windows peer's machine pool fresh quickly.
	defaultHeartbeatSeconds = 60
)

type Config struct {
	Host string `toml:"host"`

	// Key is the shared security key, used verbatim apart from edge trimming.
	// It must match the Windows side character for character; see Load for why
	// interior whitespace is deliberately preserved rather than stripped.
	Key string `toml:"key"`

	// Name is this machine's MWB identity on the wire. It is sanitised and
	// capped at MaxMachineNameLen on load; see sanitizeMachineName for why
	// '.', ':' and ',' cannot be sent to a Windows peer.
	Name         string `toml:"name"`
	Port         int    `toml:"port"`
	RemoteWidth  int    `toml:"remote_width"`
	RemoteHeight int    `toml:"remote_height"`
	Edge         string `toml:"edge"`
	Clipboard    *bool  `toml:"clipboard"` // nil = unset, treated as enabled

	// FileTransfer controls the MWB file copy channel. nil = enabled.
	FileTransfer *bool `toml:"file_transfer"`

	// FileDir is retained only so older configs continue to decode. Clipboard
	// files now use private cache staging and appear in a chosen folder on paste;
	// writing every copied file into a visible directory was incorrect MWB UX.
	// Deprecated: ignored.
	FileDir string `toml:"file_dir"`

	// MaxFileSize caps a single transfer in bytes. 0 = MWB's own 100 MB limit,
	// which a stock Windows peer neither exceeds nor accepts.
	MaxFileSize int64 `toml:"max_file_size"`

	// KeyboardLayout controls inbound Windows->Linux keyboard mapping. "auto"
	// detects the local Linux layout when possible; unsupported layouts fall back
	// to the US-compatible mapping.
	KeyboardLayout string `toml:"keyboard_layout"`

	// AccelMultiplier scales raw evdev deltas before they move the remote cursor
	// (outbound, Linux->Windows). The Windows side adds no acceleration of its
	// own, so this is the only outbound speed knob. <= 0 means unset.
	AccelMultiplier float64 `toml:"accel_multiplier"`

	// InboundMultiplier scales Windows->Linux cursor movement (the inbound,
	// absolute-mirror direction). 1.0 mirrors Windows 1:1; raise it for a faster
	// local cursor when Windows is in control. <= 0 means unset (defaults to 1).
	InboundMultiplier float64 `toml:"inbound_multiplier"`

	// PBKDF2Iterations is the round count used to derive the AES key from the
	// security key. It has to match the Windows peer exactly — a mismatch is
	// indistinguishable from a wrong key, since both just produce garbage
	// plaintext. 0 = the reference build's 50,000
	// (Core/Encryption.cs:41); current PowerToys main uses 100,000.
	PBKDF2Iterations int `toml:"pbkdf2_iterations"`

	// HeartbeatSeconds is how often we announce ourselves so the peer keeps us
	// in its machine pool. 0 = 60. Windows clamps its own interval to
	// 60..3600 (Class/Setting.cs:1018-1033), so values outside that range are
	// pulled into it by the network layer.
	HeartbeatSeconds int `toml:"heartbeat_seconds"`

	// SwitchEntryPx is how far inside the remote screen the cursor lands after a
	// switch, in remote pixels. MWB itself uses 2 (JUMP_PIXELS,
	// Core/MachineStuff.cs:34); a large value is what makes a switch look like a
	// jump rather than a continuous crossing. Must exceed 1 to clear the peer's
	// own edge trigger. 0 = default (8).
	SwitchEntryPx int `toml:"switch_entry_px"`

	// SwitchGraceMs is how long local input is dropped immediately after a
	// switch, to swallow physical momentum that was already in flight. MWB has
	// no equivalent and forwards input straight away, so anything large here is
	// felt as a dead zone. 0 = default (15). Set to -1 for no suppression.
	SwitchGraceMs int `toml:"switch_grace_ms"`

	// Bidirectional enables sending local input to the remote, i.e. driving
	// Windows from this machine's keyboard and mouse. Off by default because it
	// takes an exclusive grab (EVIOCGRAB) of the real input devices whenever
	// control is remote, which makes this machine deaf to local input until
	// control returns. nil = disabled.
	Bidirectional *bool `toml:"bidirectional"`

	// MachineID pins this installation's MWB identity instead of using the
	// persisted state file. Mostly for tests and for matching an existing
	// Windows-side pool entry. 0 = use LoadOrCreateMachineID.
	MachineID uint32 `toml:"machine_id"`
}

func Load(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if cfg.Host == "" {
		return nil, fmt.Errorf("config: host is required")
	}
	if cfg.Key == "" {
		return nil, fmt.Errorf("config: key is required")
	}

	// Trim only the edges. Do NOT strip interior whitespace: the settings UI
	// PowerToys actually ships stores the key verbatim
	// (Settings.UI/ViewModels/MouseWithoutBordersViewModel.cs:716-718) and
	// displays it verbatim in a read-only TextBox
	// (SettingsXAML/Views/MouseWithoutBordersPage.xaml:66). The legacy WinForms
	// page did strip whitespace (Form/Settings/SetupPage2a.cs:92), and
	// Core/Encryption.cs:64-78 KeyDisplayedText does render a key in groups of
	// four — but that method has no callers anywhere in the tree, so nothing
	// shows a grouped key today.
	//
	// Stripping interior spaces would therefore silently derive a *different*
	// AES key from the peer's whenever a key legitimately contains one, and the
	// resulting failure is indistinguishable from a wrong key. Warn instead.
	if trimmed := strings.TrimSpace(cfg.Key); trimmed != cfg.Key {
		slog.Warn("security key had leading or trailing whitespace; trimmed",
			"trimmedLen", len(trimmed))
		cfg.Key = trimmed
	}
	if strings.ContainsFunc(cfg.Key, unicode.IsSpace) {
		slog.Warn("security key contains whitespace, which is kept verbatim — " +
			"PowerToys stores the key exactly as entered, so it must match character for character")
	}
	if !isASCII(cfg.Key) {
		// PBKDF2 hashes the key as UTF-8 but the magic number uses the low byte
		// of each UTF-16 code unit (Core/Encryption.cs:184 vs :108-113), so a
		// non-ASCII key is handled but is a foot-gun worth naming.
		slog.Warn("security key contains non-ASCII characters; PowerToys' own key " +
			"generator only emits ASCII, so double-check it matches the Windows side exactly")
	}
	// Warn, do not reject. Core/Encryption.cs:234-240 IsKeyValid enforces 16
	// characters, but its only caller is the legacy WinForms dialog
	// (Form/frmMatrix.cs:508) — nothing checks the length at runtime, and the
	// shipping settings UI does not call it at all. So a shorter key set
	// directly in settings.json genuinely works between two Windows machines,
	// and refusing it here would break a pair that is otherwise fine.
	if len(cfg.Key) < MinKeyLen {
		slog.Warn("security key is shorter than PowerToys' own 16-character minimum; "+
			"it will still be used, but double-check it matches the Windows side",
			"length", len(cfg.Key), "minimum", MinKeyLen)
	}
	if !protocol.KeyIsWindowsCompatible(cfg.Key) {
		// Roughly 1 key in 512. Nothing we can do about it — see
		// protocol.KeyIsWindowsCompatible for the upstream signed/unsigned bug.
		return nil, fmt.Errorf("config: this security key cannot work with Mouse Without Borders "+
			"at all (magic number 0x%08X has bit 31 set, which PowerToys compares as a negative "+
			"signed int and always rejects — see Class/SocketStuff.cs:536-540). This affects about "+
			"1 key in 512 and breaks Windows-to-Windows too. Generate a new key on the Windows side",
			protocol.Get24BitHash(cfg.Key))
	}
	if cfg.Port == 0 {
		cfg.Port = 15100
	}
	if cfg.Name == "" {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "linux"
		}
		cfg.Name = hostname
	}
	if name := sanitizeMachineName(cfg.Name); name != cfg.Name {
		// Worth a line in the log: the peer's machine pool, matrix and DNS
		// lookups all key off this exact string, so an operator debugging a
		// "Windows can't see me" report needs to know what we actually sent.
		slog.Warn("machine name adjusted for MWB wire compatibility", "configured", cfg.Name, "used", name)
		cfg.Name = name
	}
	if cfg.Name == "" {
		return nil, fmt.Errorf("config: name is empty after removing '.', ':' and ',' — set an explicit name; " +
			"an empty name makes the Windows peer's MachinePool.LearnMachine throw and tear down the control socket")
	}
	if cfg.MachineID == 255 || cfg.MachineID > maxMachineID {
		return nil, fmt.Errorf("config: machine_id %d is invalid (0 = auto, 255 is ID.ALL, max %d)", cfg.MachineID, maxMachineID)
	}
	if cfg.RemoteWidth == 0 {
		cfg.RemoteWidth = 1920
	}
	if cfg.RemoteHeight == 0 {
		cfg.RemoteHeight = 1080
	}
	if cfg.AccelMultiplier <= 0 {
		cfg.AccelMultiplier = 2.0
	}
	if cfg.InboundMultiplier <= 0 {
		cfg.InboundMultiplier = 1.0
	}
	if cfg.KeyboardLayout == "" {
		cfg.KeyboardLayout = "auto"
	}
	if cfg.Edge == "" {
		cfg.Edge = "left"
	}

	// The config holds the plaintext security key — the only secret protecting
	// input injection. Tighten permissions to owner-only (0600) so other local
	// accounts can't read it. This self-heals older installs whose file was
	// created world-readable (0644) without requiring a manual chmod.
	if err := secureConfigPermissions(path); err != nil {
		slog.Warn("could not tighten config file permissions", "path", path, "err", err)
	}

	return &cfg, nil
}

// sanitizeMachineName makes a name safe to put on the wire and to hand to a
// Windows peer, in the order the Windows code itself would see it.
//
// Non-ASCII bytes are folded to '?' because the wire encoding is
// ASCIIEncoding (Core/Common.cs:397-400 GetBytes/GetString), which substitutes
// '?' for anything above 0x7F. Folding before truncating also keeps one
// character equal to one byte, so the 32-byte cap can never split a UTF-8 rune
// and leave mojibake in the DATA struct.
//
// Three characters have to go, because each one corrupts Windows state:
//
//   - '.' — UpdateTcpSockets replaces any dotted socket name with
//     NameFromID or the raw IP (Class/SocketStuff.cs:2154-2161). After that
//     InMachineMatrix(t.MachineName) is false, and the Des==ALL fan-out in
//     Core/Common.cs:926 skips the socket entirely: no broadcast reaches us.
//     Only the first label is kept rather than the dots being deleted, because
//     Windows dials us by name — Dns.GetHostEntry(machineName),
//     Class/SocketStuff.cs:1023 — and the short label is what a Windows box
//     reports for itself (Dns.GetHostName, Core/Common.cs:1394) and the only
//     variant with a chance of resolving.
//   - ':' — separates name from id in MachinePoolString
//     (Class/MachinePoolHelpers.cs:33-39). An extra colon makes the split
//     yield three fields, the entry is dropped, and a malformed pool string
//     sends the whole reload into the catch that calls MachinePool.Clear()
//     (Core/InitAndCleanup.cs:59-63).
//   - ',' — separates entries in both pool and matrix strings; a matrix that
//     does not split into exactly MAX_MACHINE parts is reset to all-empty
//     (Core/MachineStuff.cs:895-899), silently dropping every peer.
//
// isASCII reports whether every byte is < 0x80.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func sanitizeMachineName(name string) string {
	// First non-empty label: ".hidden" keeps "hidden", "box.example.com" keeps
	// "box".
	name = strings.TrimLeft(strings.TrimSpace(name), ".")
	if i := strings.IndexByte(name, '.'); i >= 0 {
		name = name[:i]
	}

	var b strings.Builder
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 0x80:
			b.WriteByte('?')
		case c == ':' || c == ',':
			// Dropped, see above.
		default:
			b.WriteByte(c)
		}
	}

	out := b.String()
	if len(out) > MaxMachineNameLen {
		out = out[:MaxMachineNameLen]
	}
	// The wire field is space-padded and read back with Trim
	// (Core/DATA.cs:83, 88), so edge whitespace never survives anyway;
	// dropping it here keeps our own copy equal to what the peer stores.
	return strings.TrimSpace(out)
}

// secureConfigPermissions restricts the config file to 0600 (owner read/write)
// if it is currently group- or world-accessible.
func secureConfigPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 == 0 {
		return nil // already 0600 or tighter
	}
	return os.Chmod(path, 0o600)
}

func (c *Config) MessagePort() int {
	return c.Port + 1
}

// ClipboardPort is where file and clipboard channels are opened. MWB runs two
// listeners and they are not the same one:
//
//	skMessageServer   = new TcpServer(TcpPort + 1, TCPServerThread);
//	skClipboardServer = new TcpServer(TcpPort,     AcceptConnectionAndSendClipboardData);
//
// Control is TcpPort+1, which MessagePort returns. Clipboard is the base port,
// and ConnectToRemoteClipboardSocket dials it. Sending a file channel to the
// control port instead reaches TCPServerThread, which answers with a control
// Handshake and never routes the connection to the file receiver.
func (c *Config) ClipboardPort() int {
	return c.Port
}

// ClipboardEnabled reports whether clipboard sharing should run. An absent
// clipboard key keeps it enabled, preserving the prior default behavior.
// SwitchEntry reports how far inside the remote screen to land after a switch.
func (c *Config) SwitchEntry() int {
	if c.SwitchEntryPx > 1 {
		return c.SwitchEntryPx
	}
	return 8
}

// SwitchGrace reports how long to drop local input after a switch. A negative
// configured value means no suppression at all.
func (c *Config) SwitchGrace() time.Duration {
	switch {
	case c.SwitchGraceMs < 0:
		return 0
	case c.SwitchGraceMs == 0:
		return 15 * time.Millisecond
	default:
		return time.Duration(c.SwitchGraceMs) * time.Millisecond
	}
}

// BidirectionalEnabled reports whether local input should be forwarded to the
// remote. Unset means disabled — the safe default, since enabling it grabs the
// real input devices.
func (c *Config) BidirectionalEnabled() bool {
	return c.Bidirectional != nil && *c.Bidirectional
}

func (c *Config) ClipboardEnabled() bool {
	return c.Clipboard == nil || *c.Clipboard
}

// FileTransferEnabled reports whether the file copy channel should run.
// An absent setting is treated as enabled, matching clipboard.
func (c *Config) FileTransferEnabled() bool {
	return c.FileTransfer == nil || *c.FileTransfer
}

// KeyDerivationIterations reports the PBKDF2 round count to use. An unset or
// non-positive value means the reference build's Encryption.KeyDerivationIterations
// (Core/Encryption.cs:41).
func (c *Config) KeyDerivationIterations() int {
	if c.PBKDF2Iterations <= 0 {
		return defaultPBKDF2Iterations
	}
	return c.PBKDF2Iterations
}

// HeartbeatInterval reports the presence-heartbeat cadence. An unset or
// non-positive value means defaultHeartbeatSeconds; out-of-range values are
// left alone here and clamped by the network layer, which owns PowerToys'
// 60..3600 rule (Class/Setting.cs:1018-1033).
func (c *Config) HeartbeatInterval() time.Duration {
	if c.HeartbeatSeconds <= 0 {
		return defaultHeartbeatSeconds * time.Second
	}
	return time.Duration(c.HeartbeatSeconds) * time.Second
}

// FileDirectory resolves the legacy direct-download directory.
// Deprecated: clipboard file transfers no longer use this path.
func (c *Config) FileDirectory() string {
	if c.FileDir != "" {
		return os.ExpandEnv(c.FileDir)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "mwb")
	}
	return filepath.Join(home, "Downloads", "mwb")
}
