#!/bin/sh
# Watch for inbound clipboard traffic from the peer.
#
#     ./scripts/watch-clipboard.sh [seconds]
#
# Run it, then copy some text ON WINDOWS. It reports whether the clipboard
# packets ever reach us, which splits the problem cleanly in two:
#
#   packets arrive  -> the peer is sending; any failure is on this side
#   nothing arrives -> the peer never sent; the problem is on Windows
#
# Needs the service running with --debug (ExecStart in
# ~/.config/systemd/user/mwb.service), otherwise the per-packet lines are
# filtered out before they reach the journal.

SECS="${1:-45}"

if ! systemctl --user is-active --quiet mwb; then
    echo "mwb is not running: systemctl --user start mwb" >&2
    exit 1
fi
case "$(systemctl --user show mwb -p ExecStart --value)" in
    *--debug*) : ;;
    *) echo "WARNING: the service is not running with --debug, so per-packet" >&2
       echo "         lines are suppressed and this will show nothing." >&2
       echo "         Add --debug to ExecStart in" >&2
       echo "         ~/.config/systemd/user/mwb.service, then:" >&2
       echo "           systemctl --user daemon-reload && systemctl --user restart mwb" >&2
       echo >&2 ;;
esac

echo "Watching ${SECS}s.  >>> COPY SOME TEXT ON WINDOWS NOW <<<"
echo "-------------------------------------------------------------"

out=$(timeout "$SECS" journalctl --user -u mwb -f -n 0 --no-pager 2>/dev/null \
      | grep -aE 'type=(69|76|124|125)|clipboard')

if [ -z "$out" ]; then
    cat <<'EOF'
NOTHING ARRIVED.

No clipboard packet reached us — no ClipboardText (124), ClipboardImage (125),
ClipboardDataEnd (76) or Clipboard beat (69).

That puts the fault on the Windows side: it never sent. Things to check there,
in order:

  1. PowerToys > Mouse Without Borders > "Share clipboard" is ON.

  2. The MWB *helper* process is running. Clipboard changes are detected by
     WM_CLIPBOARDUPDATE in a separate helper (Helper/FormHelper.cs:240), not by
     the main process, so input can work perfectly while clipboard does nothing.
     Look for PowerToys.MouseWithoutBordersHelper.exe in Task Manager.

  3. %LOCALAPPDATA%\Microsoft\PowerToys\MouseWithoutBorders\Logs — copy
     something and look for:
         CheckClipboardEx: ShareClipboard = ...
     No line at all  -> the change was never detected (helper problem).
     ShareClipboard = False -> the setting is off.
     "Same string data"     -> content matched the previous copy; try new text.

  4. Toggling Mouse Without Borders off and on restarts the helper.
EOF
    exit 1
fi

echo "$out"
echo "-------------------------------------------------------------"
cat <<'EOF'
PACKETS ARRIVED — the peer is sending and we are receiving them.

So the fault is on this side, in decoding or in setting the X selection.
Useful follow-ups:

    journalctl --user -u mwb -n 200 | grep -i clipboard
    xclip -selection clipboard -o        # what actually landed

Look for "clipboard text received from remote" (we decoded it and set the
selection) versus "clipboard decompress failed" (the payload did not decode).
EOF
