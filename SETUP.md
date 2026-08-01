# Setting up this fork against your PowerToys build

This fork exists for one reason: **upstream `mwb-linux` cannot talk to a current
PowerToys build.** Both it and its ancestor `bketelsen/mwb` implement the
pre-June-2026 Mouse Without Borders crypto — a fixed PBKDF2 salt
(`UTF16LE("18446744073709551615")`) and a fixed IV (`ASCII "1844674407370955"`).

PowerToys changed that: every encrypted stream now begins with **32 cleartext
bytes — `salt(16) || IV(16)` — exchanged independently in each direction**, and
the AES key is derived per connection from the salt received. A client built for
the old scheme desynchronises on the first block, which looks exactly like a
wrong security key.

Reference commit for the C# spec: `3bf6820` (2026-06-29), at
`../power-toys/src/modules/MouseWithoutBorders/App/`.

> If you update PowerToys on the Windows side, re-check `Core/Encryption.cs`
> before assuming a broken link is this client's fault. Upstream `main` has
> already raised `KeyDerivationIterations` from 50,000 to 100,000 — see
> `pbkdf2_iterations` below.

---

## 1. One-time root setup for `/dev/uinput`

Injection needs a virtual input device. Without this, `mwb` exits at startup with
`error creating virtual mouse`.

```sh
echo uinput | sudo tee /etc/modules-load.d/uinput.conf
sudo tee /etc/udev/rules.d/99-mwb-uinput.rules >/dev/null <<'EOF'
KERNEL=="uinput", SUBSYSTEM=="misc", GROUP="input", MODE="0660", OPTIONS+="static_node=uinput"
EOF
sudo modprobe uinput
sudo udevadm control --reload-rules && sudo udevadm trigger --subsystem-match=misc
sudo usermod -aG input "$USER"
```

Then **log out and back in** (or `newgrp input`) — group changes do not apply to
a running session. Verify:

```sh
ls -l /dev/uinput      # want: crw-rw---- root input
id -nG | tr ' ' '\n' | grep -x input
```

`OPTIONS+="static_node=uinput"` is the part that makes the permissions apply even
before the module is loaded on demand. Without it the rule appears to do nothing.

Also install the accel rule, which stops the absolute-mode pointer from being
run through libinput's acceleration curve:

```sh
sudo cp packaging/99-mwb-libinput.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

**Security tradeoff, stated plainly.** Group `input` grants read access to every
`/dev/input/event*`, so any process running as you can log every keystroke on the
machine, including passwords. This is unavoidable for the Linux→Windows direction,
which needs `EVIOCGRAB` on the real devices. If you only ever want
Windows→Linux, a narrower rule granting a dedicated group access to `/dev/uinput`
alone is enough, and leaves `/dev/input/*` root-only.

---

## 2. Build

```sh
go build -o mwb ./cmd/mwb        # Go 1.25+
```

There is no `mwb update` in this fork: upstream release binaries carry the old
crypto, so self-updating would silently break the link. Rebuild from source.

---

## 3. Check the security key before anything else

This is the single most useful diagnostic and it takes five seconds.

PowerToys prints a line at startup containing three bytes of the key's hash:

```
magic: 94,64,36
```

Find it in `%LOCALAPPDATA%\Microsoft\PowerToys\MouseWithoutBorders\Logs`. Then:

```sh
./mwb hash --key 'YourSecurityKeyHere'
```

The three numbers must match exactly. If they do not, the two machines have
different keys and nothing else will work. Copy the key **verbatim** from
PowerToys → Mouse Without Borders — it is stored exactly as displayed, so
whitespace and case matter.

`mwb hash` will also refuse a key whose magic number has bit 31 set. About one
key in 512 is affected: PowerToys compares the wire magic as a *signed* int
against an unsigned one (`Class/SocketStuff.cs:536-540`), so such a key is
rejected by MWB itself — even Windows-to-Windows. Generate a new one on Windows.

---

## 4. Configuration

`~/.config/mwb/config.toml`, mode `0600`:

```toml
host = "192.168.1.50"          # the Windows machine
key  = "YourSecurityKeyHere"   # must match PowerToys exactly
name = "kali"                  # must match the matrix entry on Windows

# Optional
# port              = 15100    # control is port+1 = 15101, bulk is port = 15100
# edge              = "right"  # which Linux screen edge hands control to Windows
# keyboard_layout   = "auto"
# clipboard         = true
# file_transfer     = true
# heartbeat_seconds = 60       # clamped to 60..3600, as Windows clamps its own
# pbkdf2_iterations = 50000    # 100000 if your PowerToys is newer than commit 3bf6820
# machine_id        = 0        # 0 = persist one in ~/.local/state/mwb/machine_id
```

Your machine identity is written to `$XDG_STATE_HOME/mwb/machine_id` (falling back
to `~/.local/state/mwb/machine_id`) and reused forever. That matters: PowerToys
treats the machine id as an identity, not a nonce. It keys the clipboard channel's
accept check, routes directed packets, and is saved in the peer's `name:id` pool.

---

## 5. Windows-side configuration

1. **Security key** — must match, character for character.

2. **Add the Linux hostname to the machine matrix**, in a slot adjacent to the
   Windows box. This is not cosmetic: `Common.SkSend` only delivers `Des=ALL`
   frames — heartbeats, matrix updates, clipboard — to sockets whose machine name
   passes `InMachineMatrix` (`Core/Common.cs:926`). Get this wrong and the
   handshake succeeds and then *nothing else arrives*, which is a very confusing
   failure. `MatrixOneRow` defaults to true, so only left/right switching works
   until you enable two-row mode.

   Use the name exactly as `mwb` reports it at startup (`name=` in the log). Names
   are capped at 32 ASCII bytes and compared case-insensitively.

3. **Pin the Linux IP** if your LAN has no working DNS for this box. Your fork
   already has the Name2IP feature — Settings → IP address mapping, one
   `<machine-name> <ip>` per line. Policies:
   - **Additive (0)** — mapped IPs *and* DNS are both tried. Safe default.
   - **Preferred (1)** — mapped IPs get a 5 s head start.
   - **Exclusive (2)** — mapped IPs only, DNS skipped. Most deterministic.

4. **Two settings that silently kill connections:**
   - *Validate remote machine IP* (`ReverseLookup`) — turn it **off** unless your
     PTR records are correct.
   - `SameSubNetOnly` compares only the **first two IPv4 octets**
     (`Class/SocketStuff.cs:1170`), so `192.168.1.x` ↔ `192.168.99.x` passes but
     `10.x` ↔ `192.168.x` is rejected.

5. **Firewall** — allow inbound TCP **15101** (control) and **15100** (clipboard
   and file transfer) for the PowerToys executable. Check from Linux before
   debugging anything else:

   ```sh
   nc -vz <windows-ip> 15101
   nc -vz <windows-ip> 15100
   ```

6. **For first light**, turn *Move mouse relatively* **off** (the absolute path is
   simpler) and *Easy Mouse* **on** (edge switching without a modifier).

---

## 6. Run

```sh
./mwb --debug
```

On the Windows side the log should show `Machine got trusted: <linuxname>` and
the tray tile for the Linux box should turn green.

As a user service:

```sh
make install                                  # builds and installs the unit
systemctl --user enable --now mwb
journalctl --user -u mwb -f
```

---

## Troubleshooting, in the order worth trying

| Symptom | Cause |
|---|---|
| `magic: a,b,c` differs from `mwb hash` | Different security keys. Nothing else matters until this matches. |
| Windows logs **"Magic number invalid!"** | Wrong key, or a PBKDF2 iteration-count mismatch — try `pbkdf2_iterations = 100000`. |
| Windows logs **"Checksum invalid!"** | Framing arithmetic, not the key. |
| Handshake succeeds, then no traffic at all | The Linux hostname is not in the Windows machine matrix. |
| Connects but never becomes trusted | Probably talking to port 15100 instead of 15101; the bulk channel waits for a different header. |
| Nothing happens, `error creating virtual mouse` | The `/dev/uinput` setup in §1, or you have not logged out since `usermod`. |
| Numpad arrows type digits | Extended-flag mapping. Check `xev` for the keycode that actually arrived. |
| Cursor lands slightly off at screen edges | Coordinate normalisation; check all four corners — 0 and 65535 are the classic off-by-one. |

`sudo tcpdump -i any -X -s0 'tcp port 15101'` should show **exactly 32
random-looking cleartext bytes** as the first payload in each direction, then
ciphertext only. If you can read anything after that, the prologue is wrong.

---

## What is verified, and what is not

Verified here, without a Windows machine:

- AES-256-CBC against **NIST SP 800-38A** F.2.5/F.2.6, cross-checked with `openssl`.
- PBKDF2-HMAC-SHA512 against **CPython/OpenSSL**, at both 50,000 and 100,000 rounds.
- The magic number against an independent Python transcription of `Get24BitHash`.
- The full handshake, framing and inbound input path against
  `tools/reference_peer.py` — a second implementation written from the C# source
  that shares no code with the Go client (`internal/network/interop_test.go`).

Not verified: anything requiring a real PowerToys peer. The reference peer
implements what the C# source *says*; only your Windows box can confirm what it
*does*.
