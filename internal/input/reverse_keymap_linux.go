//go:build linux

package input

import "github.com/lucky-verma/mwb-linux/internal/protocol"

// reverseVKMap maps Linux evdev KEY_ codes back to Windows VK codes.
var reverseVKMap map[uint16]int32

// reverseExtendedVKMap maps evdev codes back to the VK the Windows low-level hook
// would report for the E0 (extended) form of that key. Its key set doubles as the
// "this code needs LLKHF_EXTENDED set" predicate, so it is derived from
// extendedVKMap rather than listed twice.
var reverseExtendedVKMap map[uint16]int32

func init() {
	// Force vkMap to be populated first (it has its own init)
	reverseVKMap = make(map[uint16]int32, len(vkMap))
	for vk, evdev := range vkMap {
		// Several evdev codes are reachable from two VKs, so pick the highest and
		// keep the inversion independent of Go's randomized map order. Highest is
		// also the right answer in every such case: the side-specific 0xA0-0xA5 that
		// a real hook reports beats the generic 0x10-0x12 that only MWB's own hotkey
		// replay produces (Class/InputHook.cs:348-349), and VK_NUMPAD5 (0x65) beats
		// VK_CLEAR (0x0C) because a bare KEY_KP5 press means the digit whenever the
		// local seat has NumLock on.
		if existing, ok := reverseVKMap[evdev]; ok && existing > vk {
			continue
		}
		reverseVKMap[evdev] = vk
	}

	reverseExtendedVKMap = make(map[uint16]int32, len(extendedVKMap))
	for vk, evdev := range extendedVKMap {
		// Highest VK wins: KEY_RIGHTCTRL/KEY_RIGHTALT are reachable from both the
		// generic 0x11/0x12 and the side-specific 0xA3/0xA5, and the real hook
		// forwards the side-specific ones (Class/InputHook.cs:348-349).
		if existing, ok := reverseExtendedVKMap[evdev]; ok && existing > vk {
			continue
		}
		reverseExtendedVKMap[evdev] = vk
	}
}

// KeyCodeToVK maps a Linux evdev keycode to a Windows Virtual Key code. It cannot
// express the E0 bit, so KEY_KPENTER degrades to a plain VK_RETURN (main Enter) —
// still better than the silent drop callers got before extendedVKMap existed.
// New callers should use KeyCodeToVKFlags.
func KeyCodeToVK(code uint16) (int32, bool) {
	vk, ok := reverseVKMap[code]
	if !ok {
		vk, ok = reverseExtendedVKMap[code]
	}
	return vk, ok
}

// KeyCodeToVKFlags maps a Linux evdev keycode to the Windows VK plus the
// KEYBDDATA.dwFlags bits that must accompany it. Keys whose Windows scancode is
// E0-prefixed need LLKHF_EXTENDED, otherwise the receiver resolves them to their
// numpad twin (Class/InputSimulation.cs:115-123) — numpad Enter would arrive as
// main Enter, right Ctrl as left Ctrl, and so on. Callers OR LLKHF_UP in
// themselves for key releases.
func KeyCodeToVKFlags(code uint16) (int32, int32, bool) {
	extVK, extended := reverseExtendedVKMap[code]
	var flags int32
	if extended {
		flags = protocol.LLKHF_EXTENDED
	}
	// Prefer the plain inversion: for keys present in both it carries the
	// side-specific VK (0xA3 rather than 0x11), which is what the hook sends.
	if vk, ok := reverseVKMap[code]; ok {
		return vk, flags, true
	}
	if extended {
		return extVK, flags, true
	}
	return 0, 0, false
}
