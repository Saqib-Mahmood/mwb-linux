#!/bin/sh
# Grant this user access to /dev/uinput so mwb can create its virtual devices.
#
# Run once, with sudo. Everything here is idempotent.
#
#     sudo ./scripts/setup-uinput.sh
#
# Then LOG OUT AND BACK IN — a new group does not apply to a running session.
#
# Security note: group "input" also grants read access to every
# /dev/input/event*, so any process running as this user can read all keyboard
# input on the machine. That access is unavoidable for the Linux->Windows
# direction, which needs EVIOCGRAB on the real devices. If you only want
# Windows->Linux, see the end of this script for a narrower alternative.

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "This needs root. Re-run with: sudo $0" >&2
    exit 1
fi

# The user to grant access to: SUDO_USER when invoked via sudo, else $1.
TARGET_USER="${SUDO_USER:-${1:-}}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
    echo "Could not work out which user to grant access to." >&2
    echo "Pass it explicitly:  sudo $0 <username>" >&2
    exit 1
fi

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

echo "==> Loading the uinput module and making that persistent"
modprobe uinput
printf 'uinput\n' > /etc/modules-load.d/uinput.conf

echo "==> Installing udev rules"
install -m 0644 "$here/packaging/99-mwb.rules"          /etc/udev/rules.d/99-mwb.rules
install -m 0644 "$here/packaging/99-mwb-libinput.rules" /etc/udev/rules.d/99-mwb-libinput.rules

echo "==> Reloading udev"
udevadm control --reload-rules
udevadm trigger --subsystem-match=misc
udevadm trigger --subsystem-match=input

echo "==> Adding $TARGET_USER to the input group"
if id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx input; then
    echo "    already a member"
else
    usermod -aG input "$TARGET_USER"
fi

echo
echo "==> Result"
ls -l /dev/uinput || echo "    /dev/uinput is missing — is the uinput module available?"

echo
if ls -l /dev/uinput 2>/dev/null | grep -q '^crw-rw----.*input'; then
    echo "/dev/uinput permissions look right."
else
    echo "WARNING: /dev/uinput does not look group-writable by 'input'."
    echo "Check: ls -l /dev/uinput"
fi

cat <<EOF

Now LOG OUT AND BACK IN so the new group applies, then check:

    id -nG | tr ' ' '\\n' | grep -x input
    ls -l /dev/uinput

If you only ever want Windows->Linux control and would rather not grant
keylogging-capable access to /dev/input/*, use a dedicated group instead:

    groupadd -f mwb && usermod -aG mwb $TARGET_USER
    sed -i 's/GROUP="input"/GROUP="mwb"/' /etc/udev/rules.d/99-mwb.rules
    gpasswd -d $TARGET_USER input
    udevadm control --reload-rules && udevadm trigger --subsystem-match=misc

That keeps /dev/input/* root-only, which also means the Linux->Windows
direction (evdev capture) will not work.
EOF
