#!/bin/sh
# Check, in order, everything that has to be true before mwb can connect.
# Re-run this after each change on the Windows side.
#
#     ./scripts/check-peer.sh [windows-ip]
#
# With no argument it reads host from ~/.config/mwb/config.toml.

set -u

CFG="${MWB_CONFIG:-$HOME/.config/mwb/config.toml}"
PEER="${1:-}"
if [ -z "$PEER" ]; then
    PEER=$(sed -n 's/^[[:space:]]*host[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$CFG" 2>/dev/null | head -1)
fi
if [ -z "$PEER" ] || [ "$PEER" = "CHANGE_ME" ]; then
    echo "No peer address. Pass one, or set host in $CFG" >&2
    exit 1
fi

PORT=$(sed -n 's/^[[:space:]]*port[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$CFG" 2>/dev/null | head -1)
[ -n "$PORT" ] || PORT=15100
CTRL=$((PORT + 1))

pass() { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m??\033[0m   %s\n' "$1"; }

echo "Peer: $PEER   control port: $CTRL   bulk port: $PORT"
echo

echo "1. Is the host on the network at all?"
if ping -c1 -W2 "$PEER" >/dev/null 2>&1; then
    pass "responds to ping"
elif ip neigh show "$PEER" 2>/dev/null | grep -qE 'REACHABLE|STALE|DELAY'; then
    warn "no ping reply, but it IS in the ARP table — so it is on the LAN."
    echo "       Windows Firewall blocks ICMP by default, so this is normal for Windows."
else
    fail "not reachable and not in the ARP table."
    echo "       Wrong IP, machine powered off, or on a different network."
    echo "       Run 'ipconfig' on Windows and compare the IPv4 address."
    exit 1
fi
echo

echo "2. Are the MWB ports open?"
echo "   'refused' and 'dropped' mean different things and point at different fixes:"
echo "     refused = packet reached the TCP stack, nothing listening  -> MWB is not running"
echo "     dropped = no reply at all                                  -> a firewall is blocking"
echo

# probe_port PORT -> prints a verdict, returns 0 only when the port is open.
probe_port() {
    _p="$1"
    _label="$2"
    _out=$(python3 - "$PEER" "$_p" <<'PY' 2>/dev/null
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(); s.settimeout(3)
try:
    s.connect((host, port)); print("open")
except socket.timeout:
    print("dropped")
except ConnectionRefusedError:
    print("refused")
except Exception as e:
    print(type(e).__name__)
finally:
    s.close()
PY
)
    case "$_out" in
        open)    pass "port $_p ($_label) is accepting connections"; return 0 ;;
        refused) fail "port $_p ($_label) REFUSED — reachable, but nothing is listening" ; return 1 ;;
        dropped) fail "port $_p ($_label) DROPPED — a firewall is silently blocking it"  ; return 2 ;;
        *)       fail "port $_p ($_label): $_out"; return 1 ;;
    esac
}

probe_port "$CTRL" "MWB control"
CTRL_STATE=$?
probe_port "$PORT" "clipboard + file transfer"
echo

if [ "$CTRL_STATE" = "0" ]; then
    echo "Ready. Start the client:"
    echo "    ./mwb --debug"
    echo
    echo "Still to confirm on Windows:"
    echo "  - the machine name from your config is in the MWB machine matrix"
    echo "  - the security key matches (run ./mwb hash and compare the magic: line"
    echo "    against %LOCALAPPDATA%\\Microsoft\\PowerToys\\MouseWithoutBorders\\Logs)"
    exit 0
fi

if [ "$CTRL_STATE" = "2" ]; then
    cat <<'EOF'
The port is DROPPED, not refused, so a firewall rule is blocking it.

The usual cause: when PowerToys first ran, Windows showed a firewall prompt and
it was dismissed or answered "Cancel". Windows then creates a persistent BLOCK
rule. Block rules WIN over allow rules in Windows Firewall, so simply adding an
allow rule does not help — the block has to be removed first.

In an Administrator PowerShell on Windows:

  # 1. What rules exist for PowerToys / these ports?
  Get-NetFirewallRule | Where-Object DisplayName -match 'PowerToys|Mouse' |
      Format-Table DisplayName, Direction, Action, Enabled, Profile -AutoSize

  # 2. Delete any BLOCK rules for it
  Get-NetFirewallRule |
      Where-Object { $_.DisplayName -match 'PowerToys|Mouse Without Borders' -and
                     $_.Action -eq 'Block' } |
      Remove-NetFirewallRule

  # 3. Add an explicit allow for both ports, on every profile
  New-NetFirewallRule -DisplayName "Mouse Without Borders (MWB)" `
      -Direction Inbound -Protocol TCP -LocalPort 15100,15101 `
      -Action Allow -Profile Any

  # 4. Is the network classified Private? Public blocks nearly all inbound.
  Get-NetConnectionProfile
  # If it says Public:
  #   Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private

  # 5. Confirm MWB is actually listening
  netstat -ano | findstr "1510"
EOF
else
    cat <<'EOF'
The port is REFUSED, not dropped: the firewall is letting us through, but
nothing is listening. So MWB is not running.

On Windows:
  1. Open PowerToys and confirm Mouse Without Borders is ENABLED (toggle on).
     The ports only exist while the module is active.
  2. Confirm it bound them, in PowerShell:
         netstat -ano | findstr "1510"
     Expect two LISTENING lines.
  3. If there are none, toggle the module off and on, or restart PowerToys.
EOF
fi
echo
echo "Then re-run this script."
exit 1
