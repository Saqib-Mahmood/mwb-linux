#!/usr/bin/env bash
#
# Install this MWB client on a Linux machine, from source.
#
#     ./scripts/install.sh
#
# Idempotent — safe to re-run after a git pull to upgrade in place.
#
# It deliberately BUILDS rather than downloading a release. Upstream release
# binaries implement the pre-June-2026 MWB crypto (a fixed PBKDF2 salt and a
# fixed IV) and cannot handshake against a current PowerToys build, so fetching
# one would silently break the link. See SETUP.md.
#
# What it does, and which parts need root:
#
#   as you        build the binary                 -> ~/.local/bin/mwb
#   as you        write a config template          -> ~/.config/mwb/config.toml
#   as you        install and enable a user unit   -> ~/.config/systemd/user/
#   root (sudo)   load the uinput module, persist it
#   root (sudo)   udev rules for /dev/uinput
#   root (sudo)   add you to the 'input' group
#
# The root steps are skipped with a clear message when sudo is unavailable, so
# the unprivileged parts still complete.

set -euo pipefail

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$*"; }
die()  { printf '\033[31merror\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "Run as your normal user, not root — it calls sudo where needed."

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO_ROOT"

BIN_DIR="$HOME/.local/bin"
CFG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/mwb"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

# ── 1. Toolchain ──────────────────────────────────────────────────────────────
say "Looking for Go"
GO=""
if command -v go >/dev/null 2>&1; then
    GO=$(command -v go)
else
    for cand in "$HOME/.local/go/bin/go" /usr/local/go/bin/go /usr/lib/go/bin/go; do
        [ -x "$cand" ] && { GO="$cand"; break; }
    done
fi
[ -n "$GO" ] || die "Go not found. Either:
    sudo apt install golang-go
or install it without root:
    V=\$(curl -sS 'https://go.dev/VERSION?m=text' | head -1)
    curl -sSL -o /tmp/go.tgz \"https://dl.google.com/go/\${V}.linux-amd64.tar.gz\"
    mkdir -p ~/.local && tar -C ~/.local -xzf /tmp/go.tgz
then re-run this script."
ok "$("$GO" version)"

# ── 2. Build ──────────────────────────────────────────────────────────────────
say "Building"
"$GO" build -o mwb ./cmd/mwb
install -Dm755 mwb "$BIN_DIR/mwb"
ok "installed $BIN_DIR/mwb"
case ":$PATH:" in
    *":$BIN_DIR:"*) : ;;
    *) warn "$BIN_DIR is not on your PATH. Add to ~/.profile or ~/.zshrc:
           export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

# ── 3. Runtime helpers ────────────────────────────────────────────────────────
say "Runtime dependencies"
missing=""
for tool in xdotool xclip; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
    warn "missing:$missing — needed for edge detection (xdotool) and clipboard (xclip)"
    warn "install with:  sudo apt install$missing"
else
    ok "xdotool, xclip present"
fi

# ── 4. Config ─────────────────────────────────────────────────────────────────
say "Config"
mkdir -p "$CFG_DIR"
chmod 700 "$CFG_DIR"
if [ -f "$CFG_DIR/config.toml" ]; then
    ok "keeping existing $CFG_DIR/config.toml"
else
    install -m600 packaging/config.example.toml "$CFG_DIR/config.toml"
    ok "template written to $CFG_DIR/config.toml"
    warn "EDIT IT: set host, key and name before starting the service."
fi
# The file holds the plaintext shared key; keep it owner-only.
chmod 600 "$CFG_DIR/config.toml"

# ── 5. Privileged bits ────────────────────────────────────────────────────────
say "Input device permissions (needs root)"
if ! sudo -v 2>/dev/null; then
    warn "sudo unavailable — skipped. Run scripts/setup-uinput.sh as root later,"
    warn "or mwb will fail at startup with 'error creating virtual mouse'."
else
    sudo sh -c 'printf "uinput\n" > /etc/modules-load.d/uinput.conf'
    sudo modprobe uinput 2>/dev/null || warn "modprobe uinput failed (built into the kernel?)"
    sudo install -m644 packaging/99-mwb.rules          /etc/udev/rules.d/99-mwb.rules
    sudo install -m644 packaging/99-mwb-libinput.rules /etc/udev/rules.d/99-mwb-libinput.rules
    sudo udevadm control --reload-rules
    sudo udevadm trigger --subsystem-match=misc
    sudo udevadm trigger --subsystem-match=input
    ok "uinput module + udev rules installed"

    if id -nG "$USER" | tr ' ' '\n' | grep -qx input; then
        ok "already in the 'input' group"
    else
        sudo usermod -aG input "$USER"
        ok "added $USER to the 'input' group"
        warn "REBOOT REQUIRED — see the note below."
    fi
fi

# ── 6. Service ────────────────────────────────────────────────────────────────
say "Auto-start service"
mkdir -p "$UNIT_DIR"
install -m644 packaging/mwb.service "$UNIT_DIR/mwb.service"
systemctl --user daemon-reload
systemctl --user enable mwb.service >/dev/null
ok "enabled — Restart=always, RestartSec=5, start-rate limiter disabled"

# ── 7. Report ─────────────────────────────────────────────────────────────────
echo
say "Installed"
printf '  %-24s %s\n' "binary"         "$BIN_DIR/mwb"
printf '  %-24s %s\n' "config"         "$CFG_DIR/config.toml"
printf '  %-24s %s\n' "service"        "$(systemctl --user is-enabled mwb.service 2>/dev/null)"
printf '  %-24s %s\n' "/dev/uinput"    "$(ls -l /dev/uinput 2>/dev/null || echo missing)"
printf '  %-24s %s\n' "in input group" "$(id -nG | tr ' ' '\n' | grep -qx input && echo yes || echo 'NO — reboot needed')"

cat <<'EOF'

Next
  1. Edit the config: host, key, name. Then check the key matches Windows:
         mwb hash
     Its "magic: a,b,c" line must equal the one PowerToys logs at startup, in
     %LOCALAPPDATA%\Microsoft\PowerToys\MouseWithoutBorders\Logs

  2. On Windows: add this machine's name to the MWB machine matrix, and map its
     IP under "IP address mapping" (Name2IP). Make sure the network holding that
     IP is classified Private — a Public profile silently drops 15100/15101.

  3. REBOOT if you were just added to the 'input' group, or if the service
     cannot open /dev/uinput. The systemd --user manager fixes its supplementary
     groups at login and cannot pick up a new one afterwards, so a re-login or
     reboot is the only way. Everything else applies immediately.

  4. Then:
         systemctl --user status mwb
         journalctl --user -u mwb -f
         ./scripts/check-peer.sh        # diagnose connectivity

Full guide, with every pitfall we hit: SETUP.md
EOF
