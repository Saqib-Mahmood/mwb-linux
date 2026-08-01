// internal/config/identity_test.go
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The whole point of the state file: the id must survive a "restart", because
// the Windows peer keys its machine pool and its socket routing off it
// (Core/Common.cs:926, Core/InitAndCleanup.cs:47-58).
func TestLoadOrCreateMachineIDIsStable(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateMachineID(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first == idNone || first == idAll || first > maxMachineID {
		t.Fatalf("generated id %d is not usable", first)
	}

	second, err := LoadOrCreateMachineID(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Errorf("id changed across calls: %d then %d", first, second)
	}
}

func TestLoadOrCreateMachineIDFilePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "mwb")

	id, err := LoadOrCreateMachineID(dir)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, machineIDFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("machine_id permissions = %04o, want 0600", got)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("state dir permissions = %04o, want 0700", got)
	}

	raw, err := os.ReadFile(filepath.Join(dir, machineIDFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(raw)); got != strconv.FormatUint(uint64(id), 10) {
		t.Errorf("file holds %q, want %d", got, id)
	}
}

// A file holding ID.NONE, ID.ALL, junk or an out-of-range value must be
// replaced rather than used: both reserved ids are skipped by the matrix
// auto-fill (Core/MachineStuff.cs:764), so such a machine never receives
// Des==ALL traffic.
func TestLoadOrCreateMachineIDRejectsUnusableFile(t *testing.T) {
	for _, content := range []string{"", "0", "255", "not-a-number", "4294967295", "2147483647", "-7"} {
		dir := t.TempDir()
		path := filepath.Join(dir, machineIDFile)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		id, err := LoadOrCreateMachineID(dir)
		if err != nil {
			t.Fatalf("content %q: %v", content, err)
		}
		if id == idNone || id == idAll || id > maxMachineID {
			t.Errorf("content %q produced unusable id %d", content, id)
		}

		persisted, ok := readMachineID(path)
		if !ok || persisted != id {
			t.Errorf("content %q: replacement id %d was not persisted (got %d, ok=%v)", content, id, persisted, ok)
		}
	}
}

func TestLoadOrCreateMachineIDTolerantOfWhitespace(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, machineIDFile), []byte(" 4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := LoadOrCreateMachineID(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id != 4242 {
		t.Errorf("id = %d, want 4242", id)
	}
}

func TestNewMachineIDNeverReserved(t *testing.T) {
	seen := make(map[uint32]int)
	for i := 0; i < 2000; i++ {
		id, err := newMachineID()
		if err != nil {
			t.Fatal(err)
		}
		if id == idNone || id == idAll {
			t.Fatalf("drew reserved id %d", id)
		}
		if id > maxMachineID {
			t.Fatalf("drew id %d above Encryption.Ran.Next()'s range", id)
		}
		seen[id]++
	}
	// A repeat inside 2000 draws over a 2^31 space means the draw is not random.
	if len(seen) != 2000 {
		t.Errorf("only %d distinct ids in 2000 draws", len(seen))
	}
}

func TestDefaultStateDir(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/tmp/xdg-state")
	dir, err := DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("/tmp/xdg-state", "mwb"); dir != want {
		t.Errorf("state dir = %q, want %q", dir, want)
	}

	// A relative XDG_STATE_HOME is invalid per the spec and must be ignored.
	t.Setenv("XDG_STATE_HOME", "relative/path")
	t.Setenv("HOME", "/tmp/fakehome")
	dir, err = DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("/tmp/fakehome", ".local", "state", "mwb"); dir != want {
		t.Errorf("state dir = %q, want %q", dir, want)
	}
}

func TestResolveMachineIDHonoursOverride(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{MachineID: 777}

	id, err := cfg.ResolveMachineID(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id != 777 {
		t.Errorf("id = %d, want the configured 777", id)
	}
	if _, err := os.Stat(filepath.Join(dir, machineIDFile)); !os.IsNotExist(err) {
		t.Error("an explicit machine_id must not create the state file")
	}

	fallback, err := (&Config{}).ResolveMachineID(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fallback == idNone || fallback == 777 {
		t.Errorf("id = %d, want a freshly persisted id", fallback)
	}
}

// An unwritable state dir still has to yield a usable id: an unstable identity
// is bad, but refusing to hand one back would leave the caller with nothing.
func TestLoadOrCreateMachineIDUnwritableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	id, err := LoadOrCreateMachineID(filepath.Join(parent, "mwb"))
	if err == nil {
		t.Fatal("expected an error when the id cannot be persisted")
	}
	if id == idNone || id == idAll || id > maxMachineID {
		t.Errorf("id %d should still be usable alongside the error", id)
	}
}
