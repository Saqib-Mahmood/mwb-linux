// internal/network/handler.go
package network

import (
	"log/slog"
	"time"

	"github.com/lucky-verma/mwb-linux/internal/input"
	"github.com/lucky-verma/mwb-linux/internal/protocol"
)

// MouseDevice is the interface for mouse injection.
type MouseDevice interface {
	MoveTo(x, y int32) error
	ButtonDown(button uint16) error
	ButtonUp(button uint16) error
	Wheel(delta int32) error
	HWheel(delta int32) error
}

// KeyboardDevice is the interface for keyboard injection.
type KeyboardDevice interface {
	KeyDown(code uint16) error
	KeyUp(code uint16) error
}

// ClipboardHandler handles clipboard packets.
type ClipboardHandler interface {
	HandlePacket(pkt *protocol.Packet)
}

// Handler processes incoming MWB packets and injects input events.
type Handler struct {
	Mouse     MouseDevice
	Keyboard  KeyboardDevice
	Clipboard ClipboardHandler // optional clipboard handler
	// OnBecameActive is called for either accepted activation packet. MWB can
	// return the cursor with MachineSwitched or NextMachine depending on screen
	// topology and connection direction; clipboard activation needs both.
	OnBecameActive func()
	OnActivated    func() // called when remote sends MachineSwitched
	// ShouldActivate optionally rejects MachineSwitched packets from the wrong edge.
	ShouldActivate func() bool
	OnReclaimed    func() // called when server sends NextMachine from the shared edge
	// ShouldReclaim optionally rejects NextMachine packets from the wrong edge.
	ShouldReclaim func(requestX, requestY, targetID int32) bool
	ActivatedAt   *time.Time // when cursor last arrived — skip mouse injection briefly

	// InboundMultiplier scales Windows->Linux cursor movement. 1.0 = mirror
	// Windows 1:1 (the default). Inbound is absolute, so this applies a constant
	// gain to per-packet deltas rather than a true acceleration curve.
	InboundMultiplier float64
	// KeyboardLayout selects the inbound Windows VK -> Linux evdev mapping.
	KeyboardLayout  string
	pendingCtrl     bool
	pendingCtrlCode uint16
	suppressCtrlUp  bool
	// inbound cursor tracking (single-goroutine receive loop, no lock needed)
	inX, inY         int32 // current injected absolute position (0-65535)
	lastInX, lastInY int32 // last absolute position reported by the remote
	inSeeded         bool  // false until the first inbound move seeds the tracker

	// keysDown tracks every keycode we have injected a press for and not yet a
	// release, so control leaving us can let go of them. Same goroutine as the
	// rest of the receive path, so no lock.
	keysDown map[uint16]bool
}

// HandlePacket dispatches a packet to the appropriate handler.
func (h *Handler) HandlePacket(pkt *protocol.Packet) {
	if pkt.Type != protocol.Keyboard {
		if err := h.flushPendingCtrl(); err != nil {
			slog.Error("keyboard input error", "err", err)
		}
	}
	switch pkt.Type {
	case protocol.Mouse:
		h.handleMouse(pkt)
	case protocol.Keyboard:
		h.handleKeyboard(pkt)
	case protocol.MachineSwitched:
		if h.ShouldActivate != nil && !h.ShouldActivate() {
			slog.Debug("MachineSwitched ignored — remote cursor is not on our shared edge", "src", pkt.Src)
			return
		}
		slog.Info("MachineSwitched: cursor switched to us", "src", pkt.Src)
		now := time.Now()
		h.ActivatedAt = &now
		h.inSeeded = false // reseed inbound tracker so the entry move snaps, not scales
		if h.OnBecameActive != nil {
			h.OnBecameActive()
		}
		if h.OnActivated != nil {
			h.OnActivated()
		}
	case protocol.HideMouse:
		// Control is leaving us, so we will never be sent the key-ups for
		// anything currently held. Release them now, exactly as the C# receiver
		// does (Core/Receiver.cs:383-388 -> InitAndCleanup.ReleaseAllKeys).
		slog.Debug("HideMouse received — cursor leaving us", "src", pkt.Src)
		h.releaseHeldKeys()
	case protocol.NextMachine:
		if h.ShouldReclaim != nil && !h.ShouldReclaim(pkt.Mouse.X, pkt.Mouse.Y, pkt.Mouse.WheelDelta) {
			slog.Debug("NextMachine ignored — requested landing point is not on our shared edge",
				"targetID", pkt.Mouse.WheelDelta, "requestX", pkt.Mouse.X, "requestY", pkt.Mouse.Y)
			return
		}
		slog.Info("NextMachine accepted — server wants us to take cursor back",
			"src", pkt.Src, "des", pkt.Des, "targetID", pkt.Mouse.WheelDelta,
			"requestX", pkt.Mouse.X, "requestY", pkt.Mouse.Y)
		// Server's cursor hit the edge shared with us — reclaim local control.
		if h.OnBecameActive != nil {
			h.OnBecameActive()
		}
		if h.OnReclaimed != nil {
			h.OnReclaimed()
		}
	case protocol.ClipboardText, protocol.ClipboardImage, protocol.ClipboardDataEnd,
		protocol.Clipboard, protocol.ClipboardAsk, protocol.ClipboardPush:
		if h.Clipboard != nil {
			h.Clipboard.HandlePacket(pkt)
		}
	case protocol.Hello, protocol.Awake, protocol.HandshakeAck:
		// expected control packets — ignore silently
	default:
		slog.Debug("unhandled packet type", "type", pkt.Type)
	}
}

func (h *Handler) handleMouse(pkt *protocol.Packet) {
	md := pkt.Mouse
	var err error
	switch int(md.DwFlags) {
	case protocol.WM_MOUSEMOVE:
		err = h.moveInbound(md.X, md.Y)
	case protocol.WM_LBUTTONDOWN:
		if err = h.moveInbound(md.X, md.Y); err == nil {
			err = h.Mouse.ButtonDown(input.BTN_LEFT)
		}
	case protocol.WM_LBUTTONUP:
		if err = h.moveInbound(md.X, md.Y); err == nil {
			err = h.Mouse.ButtonUp(input.BTN_LEFT)
		}
	case protocol.WM_RBUTTONDOWN:
		if err = h.moveInbound(md.X, md.Y); err == nil {
			err = h.Mouse.ButtonDown(input.BTN_RIGHT)
		}
	case protocol.WM_RBUTTONUP:
		if err = h.moveInbound(md.X, md.Y); err == nil {
			err = h.Mouse.ButtonUp(input.BTN_RIGHT)
		}
	case protocol.WM_MBUTTONDOWN:
		if err = h.moveInbound(md.X, md.Y); err == nil {
			err = h.Mouse.ButtonDown(input.BTN_MIDDLE)
		}
	case protocol.WM_MBUTTONUP:
		if err = h.moveInbound(md.X, md.Y); err == nil {
			err = h.Mouse.ButtonUp(input.BTN_MIDDLE)
		}
	case protocol.WM_XBUTTONDOWN:
		if err = h.moveInbound(md.X, md.Y); err == nil {
			// WheelDelta holds which X-button: 1=XBUTTON1 (BTN_SIDE), 2=XBUTTON2 (BTN_EXTRA)
			btn := uint16(input.BTN_SIDE)
			if md.WheelDelta == 2 {
				btn = input.BTN_EXTRA
			}
			err = h.Mouse.ButtonDown(btn)
		}
	case protocol.WM_XBUTTONUP:
		if err = h.moveInbound(md.X, md.Y); err == nil {
			btn := uint16(input.BTN_SIDE)
			if md.WheelDelta == 2 {
				btn = input.BTN_EXTRA
			}
			err = h.Mouse.ButtonUp(btn)
		}
	case protocol.WM_MOUSEWHEEL:
		delta := md.WheelDelta / 120
		if delta == 0 && md.WheelDelta > 0 {
			delta = 1
		} else if delta == 0 && md.WheelDelta < 0 {
			delta = -1
		}
		err = h.Mouse.Wheel(delta)
	case protocol.WM_MOUSEHWHEEL:
		delta := md.WheelDelta / 120
		if delta == 0 && md.WheelDelta > 0 {
			delta = 1
		} else if delta == 0 && md.WheelDelta < 0 {
			delta = -1
		}
		err = h.Mouse.HWheel(delta)
	default:
		slog.Debug("unhandled mouse event", "flags", md.DwFlags)
		return
	}
	if err != nil {
		slog.Error("mouse input error", "err", err)
	}
}

// inboundJumpThreshold (in 0-65535 space) separates ordinary per-packet motion
// from a teleport (e.g. the cursor entering from a screen edge). A jump is
// snapped to the reported position rather than scaled, so switch-in never sends
// the cursor flying.
const inboundJumpThreshold = 4096

// moveInbound injects an inbound (Windows->Linux) absolute cursor update,
// applying InboundMultiplier as a constant gain. With multiplier 1.0 it tracks
// the remote position exactly (identical to a 1:1 mirror).
func (h *Handler) moveInbound(mdX, mdY int32) error {
	mult := h.InboundMultiplier
	if mult <= 0 {
		mult = 1.0
	}
	jump := !h.inSeeded ||
		abs32(mdX-h.lastInX) > inboundJumpThreshold ||
		abs32(mdY-h.lastInY) > inboundJumpThreshold
	if jump || mult == 1.0 {
		// Snap to the reported position: on a teleport, or when no gain is asked
		// for (keeps absolute mirroring exact and drift-free at multiplier 1.0).
		h.inX, h.inY = mdX, mdY
	} else {
		h.inX = clamp65535(h.inX + int32(float64(mdX-h.lastInX)*mult))
		h.inY = clamp65535(h.inY + int32(float64(mdY-h.lastInY)*mult))
	}
	h.lastInX, h.lastInY = mdX, mdY
	h.inSeeded = true
	return h.Mouse.MoveTo(h.inX, h.inY)
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

func clamp65535(v int32) int32 {
	if v < 0 {
		return 0
	}
	if v > 65535 {
		return 65535
	}
	return v
}

func (h *Handler) handleKeyboard(pkt *protocol.Packet) {
	kd := pkt.Keyboard
	keyCode, ok := h.keyCodeForPacket(kd)
	if !ok {
		slog.Debug("unknown VK code", "vk", kd.WVk, "keyboardLayout", h.KeyboardLayout)
		return
	}
	isUp := (kd.DwFlags & protocol.LLKHF_UP) != 0
	if h.handlePendingCtrl(kd.WVk, kd.DwFlags, keyCode, isUp) {
		return
	}
	if err := h.flushPendingCtrl(); err != nil {
		slog.Error("keyboard input error", "err", err)
		return
	}
	var err error
	if isUp {
		err = h.Keyboard.KeyUp(keyCode)
		delete(h.keysDown, keyCode)
	} else {
		err = h.Keyboard.KeyDown(keyCode)
		if h.keysDown == nil {
			h.keysDown = make(map[uint16]bool, 8)
		}
		h.keysDown[keyCode] = true
	}
	if err != nil {
		slog.Error("keyboard input error", "err", err)
	}
}

// releaseHeldKeys lets go of everything we injected and never released.
//
// PowerToys does the same on its side (Core/InitAndCleanup.cs:213-244
// ReleaseAllKeys, called from the HideMouse handler at Core/Receiver.cs:383-388)
// because the machine losing control never sees the key-up: the user releases
// the key while the other machine owns the keyboard. Without this, a Shift or
// Ctrl held during a switch stays logically down on the Linux desktop and
// everything typed afterwards is modified — the classic "my keyboard has gone
// weird" symptom, which survives until the key is pressed and released again.
//
// The C# version checks GetAsyncKeyState for what is *physically* down; we
// release what we *injected*, which is the right analogue for a virtual device.
func (h *Handler) releaseHeldKeys() {
	if len(h.keysDown) == 0 {
		return
	}
	slog.Debug("releasing keys held at switch-away", "count", len(h.keysDown))
	for code := range h.keysDown {
		if err := h.Keyboard.KeyUp(code); err != nil {
			slog.Error("releasing held key", "code", code, "err", err)
		}
		delete(h.keysDown, code)
	}
}

// ReleaseHeldKeys is the exported form, for teardown paths outside the receive
// loop (connection loss, shutdown).
func (h *Handler) ReleaseHeldKeys() { h.releaseHeldKeys() }

func (h *Handler) flushPendingCtrl() error {
	if !h.pendingCtrl {
		return nil
	}
	h.pendingCtrl = false
	return h.Keyboard.KeyDown(h.pendingCtrlCode)
}

// keyCodeForPacket resolves a Windows virtual key to a Linux evdev keycode.
//
// The E0/extended rule lives entirely in input.VKToKeyCodeExtended, so this is
// a single lookup. It used to special-case 0x10/0x11/0x12 here, which shadowed
// the map and left numpad Enter and the nav/numpad split unhandled.
//
// Only two bits of Kd.dwFlags carry meaning — 0x80 = UP (handled by the caller)
// and 0x01 = EXTENDED (Class/InputSimulation.cs:115-123). dwFlags is a full
// int32 on the wire, so mask rather than compare.
func (h *Handler) keyCodeForPacket(kd protocol.KeyboardData) (uint16, bool) {
	extended := kd.DwFlags&protocol.LLKHF_EXTENDED != 0
	return input.VKToKeyCodeExtended(kd.WVk, extended, h.KeyboardLayout)
}

func (h *Handler) handlePendingCtrl(vk, flags int32, keyCode uint16, isUp bool) bool {
	if isCtrlVK(vk) {
		if isUp {
			if h.pendingCtrl {
				h.pendingCtrl = false
				if err := h.Keyboard.KeyDown(keyCode); err != nil {
					slog.Error("keyboard input error", "err", err)
					return true
				}
				if err := h.Keyboard.KeyUp(keyCode); err != nil {
					slog.Error("keyboard input error", "err", err)
				}
				return true
			}
			if h.suppressCtrlUp {
				h.suppressCtrlUp = false
				return true
			}
			return false
		}
		h.pendingCtrl = true
		h.pendingCtrlCode = keyCode
		return true
	}
	if !isUp && isRightAltVK(vk, flags) && h.pendingCtrl {
		h.pendingCtrl = false
		h.suppressCtrlUp = true
	}
	return false
}

func isCtrlVK(vk int32) bool {
	return vk == 0x11 || vk == 0xA2 || vk == 0xA3
}

func isRightAltVK(vk, flags int32) bool {
	return vk == 0xA5 || (vk == 0x12 && flags&protocol.LLKHF_EXTENDED != 0)
}
