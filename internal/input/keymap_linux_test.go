//go:build linux

// internal/input/keymap_linux_test.go
package input

import (
	"testing"

	"github.com/lucky-verma/mwb-linux/internal/protocol"
)

func TestVKToKeyCode(t *testing.T) {
	tests := []struct {
		name string
		vk   int32
		want uint16
	}{
		{"VK_A", 0x41, KEY_A},
		{"VK_Z", 0x5A, KEY_Z},
		{"VK_0", 0x30, KEY_0},
		{"VK_9", 0x39, KEY_9},
		{"VK_RETURN", 0x0D, KEY_ENTER},
		{"VK_ESCAPE", 0x1B, KEY_ESC},
		{"VK_SPACE", 0x20, KEY_SPACE},
		{"VK_TAB", 0x09, KEY_TAB},
		{"VK_BACK", 0x08, KEY_BACKSPACE},
		{"VK_LSHIFT", 0xA0, KEY_LEFTSHIFT},
		{"VK_RSHIFT", 0xA1, KEY_RIGHTSHIFT},
		{"VK_LCONTROL", 0xA2, KEY_LEFTCTRL},
		{"VK_RCONTROL", 0xA3, KEY_RIGHTCTRL},
		{"VK_LMENU", 0xA4, KEY_LEFTALT},
		{"VK_RMENU", 0xA5, KEY_RIGHTALT},
		{"VK_LWIN", 0x5B, KEY_LEFTMETA},
		{"VK_F1", 0x70, KEY_F1},
		{"VK_F12", 0x7B, KEY_F12},
		{"VK_LEFT", 0x25, KEY_LEFT},
		{"VK_UP", 0x26, KEY_UP},
		{"VK_RIGHT", 0x27, KEY_RIGHT},
		{"VK_DOWN", 0x28, KEY_DOWN},
		{"VK_DELETE", 0x2E, KEY_DELETE},
		{"VK_INSERT", 0x2D, KEY_INSERT},
		{"VK_HOME", 0x24, KEY_HOME},
		{"VK_END", 0x23, KEY_END},
		{"VK_PRIOR", 0x21, KEY_PAGEUP},
		{"VK_NEXT", 0x22, KEY_PAGEDOWN},
		{"unknown", 0xFFF, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := VKToKeyCode(tt.vk)
			if tt.want == 0 {
				if ok {
					t.Errorf("expected unknown for VK 0x%X", tt.vk)
				}
				return
			}
			if !ok || got != tt.want {
				t.Errorf("VKToKeyCode(0x%X) = %d, %v; want %d, true", tt.vk, got, ok, tt.want)
			}
		})
	}
}

func TestVKToKeyCodeForGermanLayout(t *testing.T) {
	tests := []struct {
		name string
		vk   int32
		want uint16
	}{
		{"VK_Z", 0x5A, KEY_Y},
		{"VK_Y", 0x59, KEY_Z},
		{"VK_OEM_4_ssharp", 0xDB, KEY_MINUS},
		{"VK_OEM_1_udiaeresis", 0xBA, KEY_LEFTBRACE},
		{"VK_OEM_3_odiaeresis", 0xC0, KEY_SEMICOLON},
		{"VK_OEM_7_adiaeresis", 0xDE, KEY_APOSTROPHE},
		{"VK_OEM_PLUS", 0xBB, KEY_RIGHTBRACE},
		{"VK_OEM_6_dead_acute", 0xDD, KEY_EQUAL},
		{"VK_OEM_5_dead_circumflex", 0xDC, KEY_GRAVE},
		{"VK_OEM_2_numbersign", 0xBF, KEY_BACKSLASH},
		{"VK_OEM_MINUS", 0xBD, KEY_SLASH},
		{"VK_OEM_102", 0xE2, KEY_102ND},
		{"VK_2_stays_physical", 0x32, KEY_2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := VKToKeyCodeForLayout(tt.vk, "de")
			if !ok || got != tt.want {
				t.Errorf("VKToKeyCodeForLayout(0x%X, de) = %d, %v; want %d, true", tt.vk, got, ok, tt.want)
			}
		})
	}
}

func TestVKToKeyCodeForUnknownLayoutFallsBack(t *testing.T) {
	got, ok := VKToKeyCodeForLayout(0x5A, "unsupported")
	if !ok || got != KEY_Z {
		t.Errorf("VKToKeyCodeForLayout(0x5A, unsupported) = %d, %v; want %d, true", got, ok, KEY_Z)
	}
}

func TestVKToKeyCodeForCommonLayoutProfiles(t *testing.T) {
	tests := []struct {
		layout string
		vk     int32
		want   uint16
	}{
		{"fr", vkA, KEY_Q},
		{"fr", vkQ, KEY_A},
		{"fr", vkM, KEY_SEMICOLON},
		{"fr", vkOEMComma, KEY_M},
		{"be", vkOEMPlus, KEY_SLASH},
		{"es", vkOEM1, KEY_LEFTBRACE},
		{"es", vkOEMPlus, KEY_RIGHTBRACE},
		{"it", vkOEM4, KEY_MINUS},
		{"gb", vkOEM7, KEY_BACKSLASH},
		{"gb", vkOEM5, KEY_102ND},
		{"pt", vkOEMPlus, KEY_LEFTBRACE},
		{"nordic", vkOEMPlus, KEY_MINUS},
		{"nordic", vkOEM4, KEY_EQUAL},
		{"ch", vkZ, KEY_Y},
		{"ch", vkOEM8, KEY_BACKSLASH},
		{"nl", vkOEMPlus, KEY_SEMICOLON},
	}
	for _, tt := range tests {
		t.Run(tt.layout, func(t *testing.T) {
			got, ok := VKToKeyCodeForLayout(tt.vk, tt.layout)
			if !ok || got != tt.want {
				t.Errorf("VKToKeyCodeForLayout(0x%X, %s) = %d, %v; want %d, true", tt.vk, tt.layout, got, ok, tt.want)
			}
		})
	}
}

func TestVKToKeyCodeExtended(t *testing.T) {
	tests := []struct {
		name     string
		vk       int32
		extended bool
		want     uint16
	}{
		// The plain form of an arrow VK stays on the nav cluster on purpose; see the
		// vkMap doc comment. Both rows lock that choice in.
		{"VK_LEFT extended", 0x25, true, KEY_LEFT},
		{"VK_LEFT plain", 0x25, false, KEY_LEFT},
		{"VK_RETURN plain", 0x0D, false, KEY_ENTER},
		{"VK_RETURN extended", 0x0D, true, KEY_KPENTER},
		{"VK_DELETE extended", 0x2E, true, KEY_DELETE},
		{"VK_CONTROL extended", 0x11, true, KEY_RIGHTCTRL},
		{"VK_MENU extended", 0x12, true, KEY_RIGHTALT},
		// VK_SHIFT is not in extendedVKMap: neither Shift is E0-prefixed.
		{"VK_SHIFT extended falls through", 0x10, true, KEY_LEFTSHIFT},
		// Generic modifiers arrive from MWB's hotkey replay / ReleaseAllKeys.
		{"VK_SHIFT plain", 0x10, false, KEY_LEFTSHIFT},
		{"VK_CONTROL plain", 0x11, false, KEY_LEFTCTRL},
		{"VK_MENU plain", 0x12, false, KEY_LEFTALT},
		{"VK_PAUSE extended falls through", 0x13, true, KEY_PAUSE},
		{"VK_NUMPAD4 extended falls through", 0x64, true, KEY_KP4},
		{"VK_MEDIA_NEXT_TRACK", 0xB0, false, KEY_NEXTSONG},
		{"VK_MEDIA_PREV_TRACK", 0xB1, false, KEY_PREVIOUSSONG},
		{"VK_MEDIA_STOP", 0xB2, false, KEY_STOPCD},
		{"VK_MEDIA_PLAY_PAUSE", 0xB3, false, KEY_PLAYPAUSE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := VKToKeyCodeExtended(tt.vk, tt.extended, "us")
			if !ok || got != tt.want {
				t.Errorf("VKToKeyCodeExtended(0x%X, %v) = %d, %v; want %d, true",
					tt.vk, tt.extended, got, ok, tt.want)
			}
		})
	}
}

func TestVKToKeyCodeExtendedUnknownVK(t *testing.T) {
	if _, ok := VKToKeyCodeExtended(0xFFF, true, "us"); ok {
		t.Error("VKToKeyCodeExtended(0xFFF, true) = ok; want miss")
	}
}

func TestVKToKeyCodeExtendedKeepsLayoutFallback(t *testing.T) {
	// Extended lookups miss for letters, so the layout override must still apply.
	got, ok := VKToKeyCodeExtended(0x5A, true, "de")
	if !ok || got != KEY_Y {
		t.Errorf("VKToKeyCodeExtended(0x5A, true, de) = %d, %v; want %d, true", got, ok, KEY_Y)
	}
}

// Unregistered evdev codes are silently dropped by the kernel, so every extended
// target must be passed to UI_SET_KEYBIT.
func TestUsedKeyCodesCoversExtendedMap(t *testing.T) {
	registered := make(map[uint16]struct{})
	for _, code := range usedKeyCodes() {
		registered[code] = struct{}{}
	}
	for vk, code := range extendedVKMap {
		if _, ok := registered[code]; !ok {
			t.Errorf("extended VK 0x%X target %d missing from usedKeyCodes()", vk, code)
		}
	}
	for _, code := range []uint16{KEY_KPENTER, KEY_NEXTSONG, KEY_PLAYPAUSE, KEY_PREVIOUSSONG, KEY_STOPCD} {
		if _, ok := registered[code]; !ok {
			t.Errorf("key code %d missing from usedKeyCodes()", code)
		}
	}
}

func TestUsedKeyCodesSortedAndDeduplicated(t *testing.T) {
	codes := usedKeyCodes()
	for i := 1; i < len(codes); i++ {
		if codes[i] <= codes[i-1] {
			t.Fatalf("usedKeyCodes() not strictly increasing at %d: %v", i, codes[i-1:i+1])
		}
	}
}

func TestKeyCodeToVKFlags(t *testing.T) {
	tests := []struct {
		name      string
		code      uint16
		wantVK    int32
		wantFlags int32
	}{
		{"numpad enter", KEY_KPENTER, 0x0D, protocol.LLKHF_EXTENDED},
		{"main enter", KEY_ENTER, 0x0D, 0},
		{"right ctrl", KEY_RIGHTCTRL, 0xA3, protocol.LLKHF_EXTENDED},
		{"left ctrl", KEY_LEFTCTRL, 0xA2, 0},
		{"right alt", KEY_RIGHTALT, 0xA5, protocol.LLKHF_EXTENDED},
		// Two VKs reach these codes; the inversion must report the side-specific one
		// a real low-level hook would, not the generic 0x10/0x12.
		{"left shift", KEY_LEFTSHIFT, 0xA0, 0},
		{"left alt", KEY_LEFTALT, 0xA4, 0},
		{"arrow left", KEY_LEFT, 0x25, protocol.LLKHF_EXTENDED},
		{"delete", KEY_DELETE, 0x2E, protocol.LLKHF_EXTENDED},
		{"numpad slash", KEY_KPSLASH, 0x6F, protocol.LLKHF_EXTENDED},
		{"numlock", KEY_NUMLOCK, 0x90, protocol.LLKHF_EXTENDED},
		{"left meta", KEY_LEFTMETA, 0x5B, protocol.LLKHF_EXTENDED},
		{"volume up", KEY_VOLUMEUP, 0xAF, protocol.LLKHF_EXTENDED},
		{"next song", KEY_NEXTSONG, 0xB0, protocol.LLKHF_EXTENDED},
		{"numpad 4", KEY_KP4, 0x64, 0},
		{"numpad 5 prefers VK_NUMPAD5", KEY_KP5, 0x65, 0},
		{"letter a", KEY_A, 0x41, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vk, flags, ok := KeyCodeToVKFlags(tt.code)
			if !ok || vk != tt.wantVK || flags != tt.wantFlags {
				t.Errorf("KeyCodeToVKFlags(%d) = 0x%X, 0x%X, %v; want 0x%X, 0x%X, true",
					tt.code, vk, flags, ok, tt.wantVK, tt.wantFlags)
			}
		})
	}
}

func TestKeyCodeToVKFlagsUnknownCode(t *testing.T) {
	if _, _, ok := KeyCodeToVKFlags(KEY_MAX); ok {
		t.Error("KeyCodeToVKFlags(KEY_MAX) = ok; want miss")
	}
}

// Every extended-class evdev code must survive the Linux -> Windows -> Linux trip.
func TestKeyCodeToVKFlagsRoundTripsExtendedKeys(t *testing.T) {
	for _, code := range usedKeyCodes() {
		vk, flags, ok := KeyCodeToVKFlags(code)
		if !ok {
			t.Errorf("KeyCodeToVKFlags(%d) missing", code)
			continue
		}
		extended := flags&protocol.LLKHF_EXTENDED != 0
		got, ok := VKToKeyCodeExtended(vk, extended, "us")
		if !ok || got != code {
			t.Errorf("round trip of %d via VK 0x%X (extended=%v) = %d, %v", code, vk, extended, got, ok)
		}
	}
}

func TestKeyCodeToVKStillResolvesNumpadEnter(t *testing.T) {
	// The two-return form cannot carry the E0 bit, so it degrades to main Enter
	// rather than dropping the event; internal/capture still calls it.
	vk, ok := KeyCodeToVK(KEY_KPENTER)
	if !ok || vk != 0x0D {
		t.Errorf("KeyCodeToVK(KEY_KPENTER) = 0x%X, %v; want 0xD, true", vk, ok)
	}
}

func TestCanonicalKeyboardLayout(t *testing.T) {
	tests := map[string]string{
		"":               "",
		"auto":           "auto",
		"de":             "de",
		"de_DE":          "de",
		"de,us":          "de",
		"German":         "de",
		"fr-FR":          "fr",
		"Belgian":        "be",
		"Spanish":        "es",
		"Latin-American": "es",
		"it-IT":          "it",
		"en-GB":          "gb",
		"Portuguese":     "pt",
		"Norwegian":      "nordic",
		"Danish":         "nordic",
		"Swedish":        "nordic",
		"Finnish":        "nordic",
		"Swiss-German":   "ch",
		"Dutch":          "nl",
		"en-US":          "us",
		"us":             "us",
	}
	for input, want := range tests {
		if got := CanonicalKeyboardLayout(input); got != want {
			t.Errorf("CanonicalKeyboardLayout(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestVKClearIsDeliberatelyUnmapped guards a decision that looks like an
// omission.
//
// VK_CLEAR (0x0C) is what Windows sends for numpad 5 with NumLock off. Mapping
// it to KEY_KP5 would type "5" whenever the *Linux* seat has NumLock on,
// because we inject an evdev keycode and XKB applies the local NumLock state.
// Windows-to-Windows types nothing there: SendKey injects the virtual key
// without KEYEVENTF_SCANCODE (Class/InputSimulation.cs:137-140). Core/VK.cs
// does not declare VK_CLEAR at all. Dropping the key is the faithful behaviour.
func TestVKClearIsDeliberatelyUnmapped(t *testing.T) {
	for _, extended := range []bool{false, true} {
		if code, ok := VKToKeyCodeExtended(0x0C, extended, "us"); ok {
			t.Errorf("VK_CLEAR(extended=%v) resolved to %d; it must stay unmapped so it "+
				"is dropped rather than typing a digit under local NumLock", extended, code)
		}
	}
}
