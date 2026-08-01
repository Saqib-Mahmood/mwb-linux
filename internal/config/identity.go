// internal/config/identity.go
package config

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// maxMachineID is the largest value Encryption.Ran.Next() can return
	// (Random.Next() is [0, int.MaxValue), so its maximum is int.MaxValue-1).
	// Windows stores its own id in an int (Class/Setting.cs:1089-1106), so
	// staying inside the positive int32 range keeps our id to something a
	// Windows peer could have generated for itself and avoids any signed
	// round-trip surprise in the "name:id" pool string.
	maxMachineID = 0x7FFFFFFE

	// idNone and idAll are reserved (Core/ID.cs). The matrix auto-fill skips
	// both (Core/MachineStuff.cs:764), so a machine holding either id is never
	// entered into MachineMatrix and therefore never receives Des==ALL traffic
	// (Core/Common.cs:926). ID.NONE additionally means "unknown machine" in the
	// pool string round-trip (Class/MachinePoolHelpers.cs:36).
	idNone = 0
	idAll  = 255

	machineIDFile = "machine_id"
)

// LoadOrCreateMachineID returns this installation's stable MWB identity,
// creating and persisting one on first use.
//
// PowerToys treats the machine id as an identity, not a nonce: it draws one
// random int with Encryption.Ran.Next() the first time it is asked and saves it
// (Class/Setting.cs:1089-1106). Deriving it per connection instead makes the
// peer relearn us under a new id on every reconnect, which breaks id-based
// routing (Core/Common.cs:926) and leaves stale "name:id" entries in the
// Windows pool that survive a restart (Core/InitAndCleanup.cs:47-58).
//
// stateDir may be empty, in which case DefaultStateDir is used. A returned id
// is usable even when err is non-nil: in that case the id is valid but could
// not be persisted, so the caller may log the error and carry on with an
// identity that lasts only until the next restart.
func LoadOrCreateMachineID(stateDir string) (uint32, error) {
	if stateDir == "" {
		dir, err := DefaultStateDir()
		if err != nil {
			id, genErr := newMachineID()
			if genErr != nil {
				return 0, genErr
			}
			return id, fmt.Errorf("resolve state dir: %w", err)
		}
		stateDir = dir
	}
	path := filepath.Join(stateDir, machineIDFile)

	if id, ok := readMachineID(path); ok {
		return id, nil
	}

	id, err := newMachineID()
	if err != nil {
		return 0, err
	}
	if err := writeMachineID(path, id); err != nil {
		return id, fmt.Errorf("persist machine id: %w", err)
	}
	slog.Info("generated persistent machine id", "id", id, "path", path)
	return id, nil
}

// ResolveMachineID honours an explicit machine_id from the config file and
// falls back to the persisted identity. Provided so callers do not have to
// special-case the override.
func (c *Config) ResolveMachineID(stateDir string) (uint32, error) {
	if c.MachineID != idNone {
		return c.MachineID, nil
	}
	return LoadOrCreateMachineID(stateDir)
}

// DefaultStateDir is $XDG_STATE_HOME/mwb, falling back to ~/.local/state/mwb
// as the XDG base directory spec prescribes.
func DefaultStateDir() (string, error) {
	if base := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(base) {
		return filepath.Join(base, "mwb"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "mwb"), nil
}

// readMachineID reports a usable persisted id. A missing, unreadable,
// unparseable or reserved value is treated as "not set" so the next call simply
// mints a fresh id instead of failing startup.
func readMachineID(path string) (uint32, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		slog.Warn("machine id file is not a number, generating a new id", "path", path)
		return 0, false
	}
	id := uint32(n)
	if id == idNone || id == idAll || id > maxMachineID {
		slog.Warn("persisted machine id is reserved or out of range, generating a new id", "path", path, "id", id)
		return 0, false
	}
	return id, true
}

// writeMachineID persists the id at 0600 under a 0700 directory. The id is not
// a secret, but it is part of this host's identity to the peer and there is no
// reason for other local accounts to see or change it.
func writeMachineID(path string, id uint32) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strconv.FormatUint(uint64(id), 10)+"\n"), 0o600)
}

// newMachineID draws a uniform id in [1, maxMachineID] excluding ID.ALL.
// Rejection sampling rather than masking, so the distribution stays flat.
func newMachineID() (uint32, error) {
	for attempt := 0; attempt < 16; attempt++ {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("read random machine id: %w", err)
		}
		id := binary.BigEndian.Uint32(b[:]) & 0x7FFFFFFF
		if id == idNone || id == idAll || id > maxMachineID {
			continue
		}
		return id, nil
	}
	return 0, fmt.Errorf("could not draw a valid machine id")
}
