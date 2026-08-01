#!/usr/bin/env python3
"""A minimal Mouse Without Borders peer, transcribed from the PowerToys C# source.

This exists to test the Go client against an implementation that shares none of
its code. Every constant and every step below was written from
src/modules/MouseWithoutBorders/App/ directly, so if the two agree on the wire,
the agreement is evidence rather than a shared bug.

It is not a usable MWB client: it does the control-channel handshake, answers
heartbeats, and can send a mouse or keyboard packet. That is enough to prove the
crypto, the framing and the handshake.

AES comes from libcrypto via ctypes because CPython has no stdlib block cipher.

Usage:
    reference_peer.py --key KEY [--port N] [--name NAME] [--send-mouse] ...

Prints one JSON object per line to stdout describing what it observed, so a test
can assert on it. Diagnostics go to stderr.
"""

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
import socket
import struct
import sys
import threading

# ---------------------------------------------------------------------------
# Protocol constants -- Core/PackageType.cs, Core/Package.cs, Core/ID.cs
# ---------------------------------------------------------------------------

PACKET_SIZE = 32       # Core/Package.cs:17  PACKAGE_SIZE
PACKET_SIZE_EX = 64    # Core/Package.cs:18  PACKAGE_SIZE_EX

HI, HELLO, BYEBYE = 2, 3, 4
HEARTBEAT, AWAKE = 20, 21
HIDE_MOUSE, HEARTBEAT_EX = 50, 51
CLIPBOARD, CLIPBOARD_DATA_END = 69, 76
MACHINE_SWITCHED, CLIPBOARD_ASK, CLIPBOARD_PUSH = 77, 78, 79
NEXT_MACHINE, KEYBOARD, MOUSE = 121, 122, 123
CLIPBOARD_TEXT, CLIPBOARD_IMAGE = 124, 125
HANDSHAKE, HANDSHAKE_ACK = 126, 127
MATRIX = 128
INVALID, ERROR = 0xFF, 0xFE

ID_ALL = 255

# Core/DATA.cs:124-133 IsBigPackage -- these plus anything with bit 0x80.
BIG_TYPES = {
    HELLO, AWAKE, HEARTBEAT, HEARTBEAT_EX, HANDSHAKE, HANDSHAKE_ACK,
    CLIPBOARD_PUSH, CLIPBOARD, CLIPBOARD_ASK, CLIPBOARD_IMAGE,
    CLIPBOARD_TEXT, CLIPBOARD_DATA_END,
}

# Core/Encryption.cs
SALT_SIZE = 16
IV_SIZE = 16
PBKDF2_ITERATIONS = 50000
DERIVED_KEY_LEN = 32

WM_MOUSEMOVE = 0x0200
LLKHF_EXTENDED = 0x01
LLKHF_UP = 0x80


def is_big(pkt_type: int) -> bool:
    return pkt_type in BIG_TYPES or bool(pkt_type & MATRIX)


# ---------------------------------------------------------------------------
# AES-256-CBC through libcrypto, padding disabled (PaddingMode.Zeros means the
# .NET transform never holds a block back -- Core/Encryption.cs:95).
# ---------------------------------------------------------------------------

def _load_libcrypto():
    for name in ("crypto", "crypto.so.3"):
        path = ctypes.util.find_library(name)
        if path:
            try:
                return ctypes.CDLL(path)
            except OSError:
                continue
    for path in ("libcrypto.so.3", "libcrypto.so"):
        try:
            return ctypes.CDLL(path)
        except OSError:
            continue
    raise RuntimeError("libcrypto not found; cannot do AES")


_lib = _load_libcrypto()
_lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
_lib.EVP_aes_256_cbc.restype = ctypes.c_void_p
_lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
_lib.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]


class AesCbc:
    """Stateful AES-256-CBC; chaining lives in the EVP context."""

    def __init__(self, key: bytes, iv: bytes, encrypt: bool):
        assert len(key) == 32 and len(iv) == 16
        self.ctx = ctypes.c_void_p(_lib.EVP_CIPHER_CTX_new())
        if not self.ctx:
            raise RuntimeError("EVP_CIPHER_CTX_new failed")
        init = _lib.EVP_EncryptInit_ex if encrypt else _lib.EVP_DecryptInit_ex
        init.argtypes = [ctypes.c_void_p] * 3 + [ctypes.c_char_p, ctypes.c_char_p]
        if init(self.ctx, ctypes.c_void_p(_lib.EVP_aes_256_cbc()), None, key, iv) != 1:
            raise RuntimeError("EVP init failed")
        if _lib.EVP_CIPHER_CTX_set_padding(self.ctx, 0) != 1:
            raise RuntimeError("could not disable padding")
        self._update = _lib.EVP_EncryptUpdate if encrypt else _lib.EVP_DecryptUpdate
        self._update.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                 ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]

    def update(self, data: bytes) -> bytes:
        if not data:
            return b""
        out = ctypes.create_string_buffer(len(data) + 16)
        outl = ctypes.c_int(0)
        if self._update(self.ctx, out, ctypes.byref(outl), data, len(data)) != 1:
            raise RuntimeError("EVP update failed")
        # Padding is off and inputs are block multiples, so this always holds.
        assert outl.value == len(data), f"{outl.value} != {len(data)}"
        return out.raw[:outl.value]

    def __del__(self):
        try:
            if getattr(self, "ctx", None):
                _lib.EVP_CIPHER_CTX_free(self.ctx)
        except Exception:
            pass


def derive_key(security_key: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Core/Encryption.cs:106-114 GenLegalKey.

    .NET's Rfc2898DeriveBytes.Pbkdf2(string, ...) encodes the password as UTF-8.
    """
    return hashlib.pbkdf2_hmac("sha512", security_key.encode("utf-8"), salt,
                               iterations, DERIVED_KEY_LEN)


def magic_number(key: str) -> int:
    """Core/Encryption.cs:172-199 Get24BitHash.

    The buffer takes the low byte of each UTF-16 code unit -- `(byte)st[i]` --
    which is NOT the same as the UTF-8 bytes for non-ASCII keys.
    """
    if not key:
        return 0
    units = key.encode("utf-16-le")
    buf = bytearray(PACKET_SIZE)
    for i in range(min(len(units) // 2, PACKET_SIZE)):
        buf[i] = units[i * 2]
    h = hashlib.sha512(bytes(buf)).digest()
    for _ in range(50000):
        h = hashlib.sha512(h).digest()
    return ((h[0] << 23) + (h[1] << 16) + (h[63] << 8) + h[2]) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Framing -- Class/SocketStuff.cs:499-560
# ---------------------------------------------------------------------------

class Packet:
    __slots__ = ("buf",)

    def __init__(self, raw: bytes = None):
        self.buf = bytearray(PACKET_SIZE_EX)
        if raw:
            self.buf[:len(raw)] = raw

    # Offsets from Core/DATA.cs
    @property
    def type(self): return self.buf[0]

    @type.setter
    def type(self, v): self.buf[0] = v

    def _i32(self, off): return struct.unpack_from("<i", self.buf, off)[0]
    def _u32(self, off): return struct.unpack_from("<I", self.buf, off)[0]
    def _set_i32(self, off, v): struct.pack_into("<i", self.buf, off, v)
    def _set_u32(self, off, v): struct.pack_into("<I", self.buf, off, v & 0xFFFFFFFF)

    @property
    def id(self): return self._i32(4)

    @id.setter
    def id(self, v): self._set_i32(4, v)

    @property
    def src(self): return self._u32(8)

    @src.setter
    def src(self, v): self._set_u32(8, v)

    @property
    def des(self): return self._u32(12)

    @des.setter
    def des(self, v): self._set_u32(12, v)

    def machine(self, n): return self._u32(12 + 4 * n)          # Machine1..4 at 16,20,24,28

    def set_machine(self, n, v): self._set_u32(12 + 4 * n, v)

    @property
    def md(self):
        return struct.unpack_from("<iiii", self.buf, 16)         # X, Y, WheelDelta, dwFlags

    def set_md(self, x, y, wheel, flags):
        struct.pack_into("<iiii", self.buf, 16, x, y, wheel, flags)

    @property
    def kd(self):
        return struct.unpack_from("<ii", self.buf, 24)           # wVk, dwFlags

    def set_kd(self, vk, flags):
        struct.pack_into("<ii", self.buf, 24, vk, flags)

    @property
    def name(self):
        # Core/DATA.cs:78-84 -- ASCII, space padded to 32, Trim() on read.
        return self.buf[32:64].decode("ascii", "replace").strip()

    @name.setter
    def name(self, v):
        raw = v.encode("ascii", "replace")[:32].ljust(32, b" ")
        self.buf[32:64] = raw

    def marshal(self, magic: int) -> bytes:
        n = PACKET_SIZE_EX if is_big(self.type) else PACKET_SIZE
        out = bytearray(self.buf[:n])
        # Order matters: magic first, then the sum -- it covers bytes 2..31 ONLY,
        # even for 64-byte frames (Class/SocketStuff.cs:511-517).
        out[3] = (magic >> 24) & 0xFF
        out[2] = (magic >> 16) & 0xFF
        out[1] = 0
        out[1] = sum(out[2:PACKET_SIZE]) & 0xFF
        return bytes(out)


def validate(buf: bytearray, magic: int) -> str:
    """Class/SocketStuff.cs:534-559 ProcessReceivedDataEx. Returns '' if ok."""
    wire_magic = (buf[3] << 24) + (buf[2] << 16)
    if wire_magic != (magic & 0xFFFF0000):
        return f"magic mismatch: wire=0x{wire_magic:08X} want=0x{magic & 0xFFFF0000:08X}"
    checksum = sum(buf[2:PACKET_SIZE]) & 0xFF
    if buf[1] != checksum:
        return f"checksum mismatch: wire=0x{buf[1]:02X} computed=0x{checksum:02X}"
    return ""


# ---------------------------------------------------------------------------

def emit(**kw):
    print(json.dumps(kw), flush=True)


def log(*a):
    print(*a, file=sys.stderr, flush=True)


class Peer:
    def __init__(self, sock, key, name, iterations):
        self.sock = sock
        self.key = key
        self.name = name
        self.iterations = iterations
        self.magic = magic_number(key)
        self.enc = None
        self.dec = None
        self.next_id = 1000
        self.send_lock = threading.Lock()

    def recv_exact_raw(self, n):
        out = b""
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise EOFError("peer closed")
            out += chunk
        return out

    def open_streams(self):
        """Core/Encryption.cs GetEncryptedStream / GetDecryptedStream, then
        Core/Common.cs:1555 SendOrReceiveARandomDataBlockPerInitialIV."""
        tx_salt = os.urandom(SALT_SIZE)
        tx_iv = os.urandom(IV_SIZE)
        self.sock.sendall(tx_salt + tx_iv)              # cleartext, on the raw socket

        prologue = self.recv_exact_raw(SALT_SIZE + IV_SIZE)
        rx_salt, rx_iv = prologue[:SALT_SIZE], prologue[SALT_SIZE:]

        self.enc = AesCbc(derive_key(self.key, tx_salt, self.iterations), tx_iv, True)
        self.dec = AesCbc(derive_key(self.key, rx_salt, self.iterations), rx_iv, False)

        self.sock.sendall(self.enc.update(os.urandom(16)))   # primer, through the cipher
        self.dec.update(self.recv_exact_raw(16))             # theirs, discarded

        emit(event="streams_open",
             tx_salt=tx_salt.hex(), rx_salt=rx_salt.hex(),
             keys_differ=derive_key(self.key, tx_salt, self.iterations)
             != derive_key(self.key, rx_salt, self.iterations))

    def recv_packet(self):
        first = self.dec.update(self.recv_exact_raw(PACKET_SIZE))
        buf = bytearray(PACKET_SIZE_EX)
        buf[:PACKET_SIZE] = first
        err = validate(buf, self.magic)
        buf[1] = buf[2] = buf[3] = 0
        pkt_type = buf[0]
        if err:
            emit(event="invalid_frame", error=err, type=pkt_type)
            return None
        if is_big(pkt_type):
            buf[PACKET_SIZE:PACKET_SIZE_EX] = self.dec.update(self.recv_exact_raw(PACKET_SIZE))
        p = Packet()
        p.buf = buf
        return p

    def send_packet(self, p, assign_id=True):
        if assign_id:
            self.next_id += 1
            p.id = self.next_id
        with self.send_lock:
            self.sock.sendall(self.enc.update(p.marshal(self.magic)))


def run(args):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(1)
    port = srv.getsockname()[1]
    emit(event="listening", port=port, magic=f"0x{magic_number(args.key):08X}")

    srv.settimeout(args.timeout)
    conn, addr = srv.accept()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn.settimeout(args.timeout)
    emit(event="accepted", remote=f"{addr[0]}:{addr[1]}")

    peer = Peer(conn, args.key, args.name, args.iterations)
    peer.open_streams()

    handshakes = 0
    trusted = False
    remote_name = None
    remote_id = None
    seen = []

    while True:
        try:
            p = peer.recv_packet()
        except (EOFError, socket.timeout, OSError) as e:
            emit(event="closed", reason=str(e))
            break
        if p is None:
            break

        seen.append(p.type)

        if p.type == HANDSHAKE:
            handshakes += 1
            if handshakes == 1:
                # Class/SocketStuff.cs:1459-1471 -- reply with the bitwise NOT
                # of the challenge and our own name and id.
                ack = Packet()
                ack.type = HANDSHAKE_ACK
                for n in range(1, 5):
                    ack.set_machine(n, ~p.machine(n) & 0xFFFFFFFF)
                ack.name = peer.name
                ack.src = args.machine_id
                ack.des = p.src
                peer.send_packet(ack)
                remote_name = p.name
                emit(event="handshake_seen", remote_name=remote_name,
                     challenge=[p.machine(n) for n in range(1, 5)])
            continue

        if p.type in (HEARTBEAT, HEARTBEAT_EX, 52, 53):
            if not trusted:
                trusted = True
                remote_id = p.src
                emit(event="trusted", remote_name=p.name, remote_id=remote_id,
                     handshakes_received=handshakes)
                if args.send_mouse:
                    m = Packet()
                    m.type = MOUSE
                    m.src = args.machine_id
                    m.des = remote_id
                    # Absolute, normalised 0..65535 (Core/Event.cs:112-113).
                    m.set_md(args.mouse_x, args.mouse_y, 0, WM_MOUSEMOVE)
                    peer.send_packet(m)
                    emit(event="sent_mouse", x=args.mouse_x, y=args.mouse_y)
                if args.send_key:
                    k = Packet()
                    k.type = KEYBOARD
                    k.src = args.machine_id
                    k.des = remote_id
                    k.set_kd(args.send_key, args.key_flags)
                    peer.send_packet(k)
                    emit(event="sent_key", vk=args.send_key, flags=args.key_flags)
            else:
                emit(event="heartbeat", remote_name=p.name, src=p.src)
            if args.exit_after_trust and trusted:
                break
            continue

        if p.type == HELLO:
            emit(event="hello", remote_name=p.name)
            continue
        if p.type == BYEBYE:
            emit(event="byebye")
            break

        emit(event="packet", type=p.type, src=p.src, des=p.des, id=p.id)

        if args.exit_after_trust and trusted:
            break

    emit(event="summary", trusted=trusted, remote_name=remote_name,
         remote_id=remote_id, handshakes=handshakes, types=sorted(set(seen)))
    conn.close()
    srv.close()
    return 0 if trusted else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--key", required=True, help="shared security key")
    ap.add_argument("--port", type=int, default=0, help="listen port (0 = ephemeral)")
    ap.add_argument("--name", default="WINHOST", help="our machine name")
    ap.add_argument("--machine-id", type=int, default=0x0BADC0DE)
    ap.add_argument("--iterations", type=int, default=PBKDF2_ITERATIONS)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--send-mouse", action="store_true")
    ap.add_argument("--mouse-x", type=int, default=32767)
    ap.add_argument("--mouse-y", type=int, default=32767)
    ap.add_argument("--send-key", type=int, default=0, help="VK code to send, 0 = none")
    ap.add_argument("--key-flags", type=int, default=0)
    ap.add_argument("--exit-after-trust", action="store_true")
    args = ap.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
