# Setup guide

Everything needed to get this client running on a Linux machine and keep it
running, including each trap that is easy to hit.

- [Quick start](#quick-start)
- [Why this fork exists](#why-this-fork-exists)
- [What gets installed, and where](#what-gets-installed-and-where)
- [Step 1 — /dev/uinput permissions](#step-1--devuinput-permissions)
- [Step 2 — build and install](#step-2--build-and-install)
- [Step 3 — check the security key first](#step-3--check-the-security-key-first)
- [Step 4 — configuration](#step-4--configuration)
- [Step 5 — the Windows side](#step-5--the-windows-side)
- [Step 6 — run it](#step-6--run-it)
- [Auto-start and auto-restart](#auto-start-and-auto-restart)
- [Direct Ethernet between two laptops](#direct-ethernet-between-two-laptops)
- [Troubleshooting](#troubleshooting)
- [Config reference](#config-reference)
- [What is verified, and what is not](#what-is-verified-and-what-is-not)

---

## Quick start

On a fresh Linux machine:

```sh
git clone <this-fork> mwb-linux && cd mwb-linux
./scripts/install.sh          # builds, installs, sets permissions, enables the service
$EDITOR ~/.config/mwb/config.toml     # set host, key, name
mwb hash                              # compare against the Windows log
sudo reboot                           # only needed the first time — see below
```

Then on Windows, add this machine's name to the Mouse Without Borders machine
matrix and map its IP. Details in [step 5](#step-5--the-windows-side).

`install.sh` is idempotent — re-run it after a `git pull` to upgrade in place.

---

## Why this fork exists

Upstream `mwb-linux`, and its ancestor `bketelsen/mwb`, **cannot handshake against
a current PowerToys build.** They implement the pre-June-2026 crypto: a fixed
PBKDF2 salt (`UTF16LE("18446744073709551615")`) and a fixed IV
(`ASCII "1844674407370955"`).

PowerToys PR #48742 replaced that. Every encrypted stream now opens with
**32 cleartext bytes — `salt(16) || IV(16)` — exchanged independently in each
direction**, and the AES key is derived per connection from the salt received.
A client built for the old scheme desynchronises on the very first block, and the
symptom is indistinguishable from a wrong security key.

Reference for every C# citation in this repo: commit `3bf6820` (2026-06-29) of
`src/modules/MouseWithoutBorders/App/`.

> **If you update PowerToys on Windows**, re-read `Core/Encryption.cs` before
> assuming a broken link is this client's fault. Upstream `main` has already
> raised `KeyDerivationIterations` from 50,000 to 100,000 — set
> `pbkdf2_iterations = 100000` if you are on a newer build.

There is no self-update in this fork: upstream release binaries carry the old
crypto, so updating from them would silently break the link. Rebuild from source.

---

## What gets installed, and where

| Path | What | Persists |
|---|---|---|
| `~/.local/bin/mwb` | the binary | ✅ |
| `~/.config/mwb/config.toml` | all settings incl. the shared key (mode `0600`) | ✅ |
| `~/.local/state/mwb/machine_id` | this install's MWB identity | ✅ |
| `~/.config/systemd/user/mwb.service` | auto-start + auto-restart | ✅ |
| `/etc/modules-load.d/uinput.conf` | loads `uinput` at boot | ✅ |
| `/etc/udev/rules.d/99-mwb.rules` | `/dev/uinput` group + mode | ✅ |
| `/etc/udev/rules.d/99-mwb-libinput.rules` | flat pointer accel for the virtual mouse | ✅ |
| `input` group membership | access to `/dev/uinput` and `/dev/input/*` | ✅ |

Static IP for a direct Ethernet link is stored in NetworkManager — see
[that section](#direct-ethernet-between-two-laptops).

---

## Step 1 — `/dev/uinput` permissions

Injection needs a virtual input device. Without it `mwb` exits immediately with
`error creating virtual mouse`.

`./scripts/install.sh` does this for you. Manually, or via
`sudo ./scripts/setup-uinput.sh`:

```sh
echo uinput | sudo tee /etc/modules-load.d/uinput.conf
sudo tee /etc/udev/rules.d/99-mwb.rules >/dev/null <<'EOF'
KERNEL=="uinput", SUBSYSTEM=="misc", GROUP="input", MODE="0660", OPTIONS+="static_node=uinput"
EOF
sudo modprobe uinput
sudo udevadm control --reload-rules && sudo udevadm trigger --subsystem-match=misc
sudo usermod -aG input "$USER"
```

Verify:

```sh
ls -l /dev/uinput                          # want: crw-rw---- root input
id -nG | tr ' ' '\n' | grep -x input
```

**`OPTIONS+="static_node=uinput"` is load-bearing.** Without it the mode is only
applied once the module is loaded, and a non-root open fails on permissions
*before* on-demand autoload can trigger. That is the classic "my udev rule does
nothing" symptom.

**Then reboot** (a full re-login also works). See
[the systemd group trap](#the-service-cannot-open-devuinput-but-running-mwb-by-hand-works).

### Security tradeoff

Group `input` also grants **read access to every `/dev/input/event*`** — so any
process running as you can log every keystroke on the machine, passwords
included. That is unavoidable for the Linux→Windows direction, which needs
`EVIOCGRAB` on the real devices.

If you only ever want Windows→Linux, use a narrower rule granting a dedicated
group access to `/dev/uinput` alone and leave `/dev/input/*` root-only. The tail
of `scripts/setup-uinput.sh` shows how.

---

## Step 2 — build and install

```sh
./scripts/install.sh
```

Or by hand (Go 1.25+):

```sh
go build -o mwb ./cmd/mwb
install -Dm755 mwb ~/.local/bin/mwb
```

Runtime helpers: `xdotool` (edge detection) and `xclip` (clipboard).

```sh
sudo apt install xdotool xclip
```

> If you edit the source later, rebuild **and reinstall** — the service runs
> `~/.local/bin/mwb`, not the copy in your source tree:
> ```sh
> go build -o mwb ./cmd/mwb && install -m755 mwb ~/.local/bin/mwb \
>   && systemctl --user restart mwb
> ```

---

## Step 3 — check the security key first

This is the single most useful diagnostic and takes five seconds. Do it before
anything else.

PowerToys logs three bytes of the key's hash at startup:

```
magic: 94,64,36
```

Find it in `%LOCALAPPDATA%\Microsoft\PowerToys\MouseWithoutBorders\Logs`. Then:

```sh
mwb hash                      # reads the key from config
mwb hash --key 'YourKey'      # or pass one directly
```

The three numbers must match **exactly**. If they don't, the two machines have
different keys and nothing else can work.

> **Quote the key in your shell.** MWB keys routinely contain `<`, `>`, `|`, `&`,
> `$` and `!`. Unquoted, your shell will mangle or redirect them. Single quotes
> are safest — or just use `mwb hash` with no argument and let it read the config,
> which also keeps the key out of your shell history and out of `ps`.

`mwb` also **refuses to start** on a key whose magic number has bit 31 set.
That is not our limitation: PowerToys computes the wire magic into a *signed*
int and compares it against an unsigned expectation
(`Class/SocketStuff.cs:536-540`), so such a key is rejected by MWB itself — even
Windows-to-Windows. It affects roughly **1 key in 512**. Generate a new one on
Windows if you hit it.

---

## Step 4 — configuration

`~/.config/mwb/config.toml`, mode `0600`. Start from
`packaging/config.example.toml`. Minimum:

```toml
host = "192.168.0.107"        # the Windows machine
key  = "YourSecurityKey"      # must match PowerToys exactly
name = "kali"                 # must also be in the Windows machine matrix
```

To drive Windows *from* this machine as well, add:

```toml
bidirectional = true
edge = "right"                # which edge of THIS screen hands over control
```

Full list in the [config reference](#config-reference).

`host` accepts a **comma-separated list** — the first is dialled, all are
allowlisted for inbound. Useful when the same peer is reachable two ways:

```toml
host = "10.10.10.2, 192.168.0.107"
```

---

## Step 5 — the Windows side

### 5.1 Add this machine to the machine matrix

**Not optional.** `Common.SkSend` only delivers `Des=ALL` frames — heartbeats,
matrix updates, clipboard — to sockets whose machine name passes
`InMachineMatrix` (`Core/Common.cs:926`). Miss this and you get a **successful
handshake followed by total silence**, which is a baffling failure mode.

Use the name exactly as `mwb` reports it at startup (`name=` in the log). Names
are capped at 32 ASCII bytes and compared case-insensitively, so `KALI` matches
`kali`.

> ### ⚠️ Do not use the "Connect" button for this
>
> It looks like the obvious way to add a machine. It is not — it **wipes your
> entire matrix and overwrites your key** (`Class/Program.cs:302-322`):
>
> ```csharp
> MachineStuff.ClearComputerMatrix();                  // the whole matrix
> Setting.Values.MyKey = securityKey;                  // your key, replaced
> MachineStuff.MachineMatrix = new string[4] {
>     pcName.Trim().ToUpper(), Common.MachineName, "", "" };
> ```
>
> Your other Windows PCs would be dropped. Instead either enable
> **"Use original user interface"** and edit the matrix in the legacy window, or
> edit `settings.json` directly (below).

### 5.2 Edit `settings.json` directly (the safe route)

Close PowerToys, then edit
`%LOCALAPPDATA%\Microsoft\PowerToys\MouseWithoutBorders\settings.json`:

```json
"MachineMatrixString": ["WINDOWSPC", "OTHERPC", "kali", ""],
"Name2IP":             { "value": "kali 192.168.0.106" },
"Name2IpPolicy":       { "value": 2 },
"ValidateRemoteIp":    { "value": false }
```

- **The list must have exactly 4 entries** — pad with `""`. Any other length and
  MWB silently resets the matrix to all-empty (`Core/MachineStuff.cs:897-900`),
  dropping every peer.
- **`Name2IpPolicy: 2`** is *Exclusive* — mapped IP only, DNS skipped. The right
  choice when your LAN can't resolve the Linux hostname. `0` = Additive (both),
  `1` = Preferred (mapped IPs get a 5s head start).
- **`ValidateRemoteIp: false`** — with it on, Windows does a reverse-DNS check
  and drops candidates whose PTR doesn't match. A Linux box usually has no PTR.
- `Name2IP` accepts **multiple lines for the same name**, and MWB dials them all
  in parallel (`Class/SocketStuff.cs:944-957`). So you can list both a Wi-Fi and
  an Ethernet address and whichever link is up wins:
  ```
  kali 192.168.0.106
  kali 169.254.40.230
  ```

Then restart PowerToys.

### 5.3 Firewall — the one that wastes the most time

Allow inbound TCP **15101** (control) and **15100** (clipboard/files):

```powershell
New-NetFirewallRule -DisplayName "Mouse Without Borders (MWB)" `
    -Direction Inbound -Protocol TCP -LocalPort 15100,15101 `
    -Action Allow -Profile Any
```

**Then check the network profile.** Windows Firewall rules are per-profile, and a
network classified **Public** blocks nearly all inbound traffic. This is why MWB
can work perfectly between two Windows PCs on one network yet be unreachable from
Linux on another:

```powershell
Get-NetConnectionProfile
Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private
```

If PowerToys ever showed a firewall prompt that got dismissed, Windows wrote a
persistent **Block** rule. **Block rules beat allow rules**, so adding an allow
does nothing until the block is gone:

```powershell
Get-NetFirewallRule | Where-Object DisplayName -match 'PowerToys|Mouse' |
    Format-Table DisplayName, Direction, Action, Enabled, Profile -AutoSize

Get-NetFirewallRule |
    Where-Object { $_.DisplayName -match 'PowerToys|Mouse Without Borders' -and
                   $_.Action -eq 'Block' } |
    Remove-NetFirewallRule
```

### 5.4 For a first connection

Set *Move mouse relatively* **off** (the absolute path is simpler and better
tested) and *Easy Mouse* **on** (edge switching without holding a modifier).

---

## Step 6 — run it

```sh
mwb --debug
```

Look for `incoming connection established` / `handshake complete`. On Windows the
tray tile for this machine turns green.

**You don't need to reach Windows.** MWB is symmetric — either peer may dial, and
one working direction is enough. Windows' *outbound* is normally open even when
its inbound is firewalled, so it can dial us and control then flows both ways over
that single socket. Outbound connect failures in our log are expected noise in
that case.

Diagnose connectivity at any point:

```sh
./scripts/check-peer.sh
```

---

## Auto-start and auto-restart

`install.sh` installs and enables a **user** unit — user, not system, because
`mwb` needs your X display and your `/dev/uinput` access, and a system unit would
run the network code as root.

```sh
systemctl --user status mwb          # is it running?
systemctl --user restart mwb         # after editing config
systemctl --user stop mwb            # before running by hand
journalctl --user -u mwb -f          # live log
systemctl --user disable mwb         # stop auto-starting
```

Restart policy (`packaging/mwb.service`):

```ini
[Unit]
StartLimitIntervalSec=0      # retry forever

[Service]
Restart=always
RestartSec=5
```

Two non-obvious details, both of which silently break auto-restart:

- **`StartLimitIntervalSec` must be in `[Unit]`, not `[Service]`.** In
  `[Service]` systemd ignores it and keeps the default 5-starts-in-10s limiter;
  once that trips, the unit gives up permanently. Verify with:
  ```sh
  systemctl --user show mwb -p StartLimitIntervalUSec    # want 0
  ```
- **The unit hangs off `default.target`, not `graphical-session.target`.** Some
  desktops — XFCE among them — never activate `graphical-session.target`, so a
  unit wanted by it simply never starts. Check yours with
  `systemctl --user is-active graphical-session.target`. The cost of using
  `default.target` is that the service may start before X is ready; the restart
  loop absorbs that.

---

## Direct Ethernet between two laptops

A cable straight between the two machines, no router. Modern NICs auto-MDIX, so a
normal patch cable works. There is no DHCP, so both ends need addresses.

Link-local (`169.254.0.0/16`) is fine. Two things make it work:

- `CheckForSameSubNet` compares only the **first two octets**
  (`Class/SocketStuff.cs:1169`) across *all* your interfaces, so `169.254.x.x` on
  both ends passes.
- The `169.254` string test at `Class/SocketStuff.cs:1291` sits inside a
  `catch (SocketException)` block. It runs only *after* a connect has already
  failed and merely picks a friendlier tooltip. **It does not block link-local.**

### Linux

```sh
nmcli con mod "Wired connection 1" \
    ipv4.method manual \
    ipv4.addresses 169.254.40.230/16 \
    ipv4.gateway "" \
    ipv4.never-default yes \
    ipv6.method disabled
nmcli con up "Wired connection 1"
```

`ipv4.never-default yes` matters — without it the cable can become your default
route and take your internet down with it. Verify:

```sh
ip -4 addr show eth0        # 169.254.40.230/16
ip route show default       # still via your Wi-Fi
```

This is stored in the connection profile, so it survives reboots.

### Windows

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 169.254.40.231 -PrefixLength 16
```

No gateway, no DNS. APIPA will also self-assign a `169.254.x.x` address if you
leave it on automatic.

**Then set that network Private.** A link-local Ethernet almost always appears as
"Unidentified network" and gets classified **Public**, which drops 15101 — the
same trap as [5.3](#53-firewall--the-one-that-wastes-the-most-time):

```powershell
Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private
```

If that fails because the network is unidentified, set `Category` to `1` under
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{…}`.

Finally add the Ethernet line to `Name2IP` (keeping the Wi-Fi one).

**You do not need the Windows link-local address in your config.** Inbound peers
on any private or link-local address are accepted (`isAllowedPeer` →
`isLocalNetwork` → `IsLinkLocalUnicast`), so whatever APIPA picks is allowed,
even if it changes.

---

## Troubleshooting

Work top-down; each row is cheaper to check than the one below.

| Symptom | Cause |
|---|---|
| `mwb hash` disagrees with the Windows `magic:` line | Different security keys. Nothing else matters until this matches. |
| `zsh: no such file or directory` when passing `--key` | Your shell ate a metacharacter. Single-quote the key, or use `mwb hash` with no argument. |
| `error creating virtual mouse` | `/dev/uinput` setup (step 1), or you haven't re-logged-in since `usermod`. |
| Windows log: **"Magic number invalid!"** | Wrong key, or a PBKDF2 iteration mismatch — try `pbkdf2_iterations = 100000`. |
| Windows log: **"Checksum invalid!"** | Framing arithmetic, not the key. |
| Handshake succeeds, then nothing at all | This machine's name is missing from the Windows machine matrix. |
| Connects but never becomes trusted | Talking to 15100 instead of 15101; the bulk channel waits for a different header. |
| Nothing at all, port scan shows **dropped** | Firewall. Dropped ≠ refused — see below. |
| Nothing at all, port scan shows **refused** | Reachable, nothing listening: MWB isn't running on Windows. |
| Cursor won't cross the edge | Wrong `edge` value, or `bidirectional` not set. |
| Cursor **jumps** rather than crossing smoothly | `switch_entry_px` too large. MWB lands 2px inside the edge; the inherited default here was 200px. Try `2`. |
| Noticeable **pause** just after a switch | `switch_grace_ms`. MWB suppresses no input at all; try `-1`. Remaining latency is the 10ms edge-detection poll, which is inherent to the xdotool-based detection. |
| Cursor **bounces back** immediately after crossing | `switch_entry_px` too small — it must clear the peer's 1px trigger (`SKIP_PIXELS`). Raise it. |
| Numpad arrows type digits | Extended-flag mapping; check the arriving keycode with `xev`. |
| Modifier stuck down after a switch | Report it — the release paths are implemented but lightly tested on real hardware. |

### refused vs dropped — the most useful distinction

```sh
./scripts/check-peer.sh
```

- **refused** — a TCP RST came back. The host is up and the firewall let the
  packet reach the stack; nothing is listening. → MWB isn't running.
- **dropped** — no reply at all. → a firewall is swallowing it.

If port 22 is *refused* while 15101 is *dropped* on the same host, that proves the
host is reachable and the MWB ports specifically are being filtered.

Watch the wire directly:

```sh
sudo tcpdump -i any -n 'tcp port 15101 and tcp[tcpflags] & tcp-syn != 0'
```

- Nothing → Windows isn't dialing: matrix entry or `Name2IP` is wrong.
- SYNs arrive but no handshake → connectivity is fine; it's a key or protocol
  issue.

The first payload in each direction must be **exactly 32 random-looking cleartext
bytes**, then ciphertext only. Readable data after that means the prologue is
wrong.

### The service cannot open `/dev/uinput` but running `mwb` by hand works

The `systemd --user` manager fixes its supplementary groups when your session
starts. Add yourself to `input` afterwards and the manager never learns about it,
so every service it spawns lacks the group — while your shell, started later, has
it. `systemctl --user daemon-reexec` does **not** help: a process cannot gain
supplementary groups after the fact.

Confirm:

```sh
UMPID=$(pgrep -u "$USER" -f "systemd --user" | head -1)
grep ^Groups /proc/$UMPID/status         # is the 'input' gid there?
getent group input                       # what gid is that?
```

Fix: **reboot**, or `loginctl terminate-user "$USER"` (logs you out).

---

## Config reference

`~/.config/mwb/config.toml`

| Key | Default | Meaning |
|---|---|---|
| `host` | *required* | Peer address(es), comma-separated. First is dialled, all are allowlisted. |
| `key` | *required* | Shared security key. Used verbatim apart from edge trimming. |
| `name` | hostname | This machine's wire name. ≤32 ASCII; `.`/`:`/`,` stripped. Must be in the Windows matrix. |
| `bidirectional` | `false` | Forward local input to the remote. Grabs the real input devices while control is remote. |
| `edge` | `"left"` | Which edge of this screen hands over control: `left` or `right`. |
| `port` | `15100` | Base port. Control is `port+1`; clipboard/files use `port`. |
| `clipboard` | `true` | Clipboard sync. |
| `file_transfer` | `true` | Bulk file channel. |
| `max_file_size` | 100 MB | Per-transfer cap; MWB's own limit. |
| `keyboard_layout` | `"auto"` | Inbound VK→evdev mapping. `us`, `de`, `fr`, `be`, `es`, `it`, `gb`, `pt`, nordic, `ch`, `nl`. |
| `accel_multiplier` | `2.0` | Scales Linux→Windows motion. `1.0` is the faithful value. |
| `inbound_multiplier` | `1.0` | Scales Windows→Linux motion. |
| `switch_entry_px` | `8` | How far inside the remote screen the cursor lands after a switch. MWB uses 2. Larger = visible jump. Must be > 1. |
| `switch_grace_ms` | `15` | Local input dropped right after a switch. MWB drops none; large values feel like a dead zone. `-1` disables. |
| `heartbeat_seconds` | `60` | Presence beat. Clamped 60–3600, as PowerToys clamps its own. |
| `pbkdf2_iterations` | `50000` | **Must match the Windows build.** 50000 up to `3bf6820`; 100000 on newer `main`. |
| `machine_id` | `0` | `0` = persist one in `$XDG_STATE_HOME/mwb/machine_id`. `0` and `255` are reserved. |

Flags override config where both exist: `--debug`, `-bidi`, `-edge`,
`-no-clipboard`, `-config`.

Subcommands: `mwb version`, `mwb hash`.

---

## What is verified, and what is not

Verified here, without a Windows machine:

- **AES-256-CBC** against NIST SP 800-38A F.2.5/F.2.6, cross-checked with `openssl`.
- **PBKDF2-HMAC-SHA512** against CPython/OpenSSL, at both 50,000 and 100,000 rounds.
- **The magic number** against an independent Python transcription of `Get24BitHash`.
- **Handshake, framing and the inbound input path** against
  `tools/reference_peer.py` — a second implementation written from the C# source
  that shares no code with this client (`internal/network/interop_test.go`).
- **Every evdev keycode** against a real X keymap (`xmodmap -pke`, keycode = evdev + 8).

Not verified: anything that needs a real PowerToys peer. The reference peer
implements what the C# source *says*; only a Windows build confirms what it
*does*. Phases beyond input — clipboard flavours, bulk text, screenshot pull,
drag-and-drop — are largely inherited from upstream and lightly exercised.
