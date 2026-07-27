#!/usr/bin/env bash
# karst-gui.sh — open a client GUI window with the relay address and relay-id of a
# running relay (scripts/karst-up.sh) filled in. One command instead of copying
# the relay-id by hand.
#
#   scripts/karst-up.sh                 # bring up the relay first
#   scripts/karst-gui.sh                # ONE window, default profile (~/.config/karst)
#   scripts/karst-gui.sh alice          # a named profile (for two windows on one machine)
#   scripts/karst-gui.sh bob            # a second window (in another terminal)
#
# The profile name is OPTIONAL. Without it, this is an ordinary single client (the
# default $KARST_HOME). A name is needed ONLY to run several identities side by
# side (the Alice↔Bob test): each <name> = a separate /tmp/karst-<name> with its
# own secrets.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

NAME="${1:-}"

RUN="${KARST_RUN_DIR:-$KARST_IMPL/.run}"
RID_FILE="$RUN/relay-id"
ADDR_FILE="$RUN/relay-addr"

if [ ! -f "$RID_FILE" ]; then
  echo "relay is not running (no $RID_FILE). First: scripts/karst-up.sh"
  exit 1
fi
RID="$(cat "$RID_FILE")"
ADDR="$(cat "$ADDR_FILE" 2>/dev/null || echo 127.0.0.1:9000)"

# Display check — a clear error instead of a silent "nothing opened".
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
  echo "no display (DISPLAY/WAYLAND_DISPLAY are empty) — the GUI needs a graphical session."
  echo "Run it in a desktop session, not over bare SSH without X-forwarding."
  exit 1
fi

# Profile directory: with a name — /tmp/karst-<name> (a test profile); without a
# name — the default (we don't set $KARST_HOME, the binary uses ~/.config/karst).
if [ -n "$NAME" ]; then
  HOME_DIR="/tmp/karst-$NAME"
  LABEL="'$NAME'"
else
  HOME_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/karst"
  LABEL="(default profile)"
fi

# Old profile format (before the phrase-root): identity.key/account.key with no
# seed.key. The new login cannot read them — warn instead of silently creating a
# different identity.
if [ -f "$HOME_DIR/identity.key" ] && [ ! -f "$HOME_DIR/seed.key" ]; then
  echo "WARNING: profile $LABEL is in the OLD format (no recovery phrase)."
  echo "The new login won't open it. Clear it and create it again:  rm -rf $HOME_DIR"
  exit 1
fi

karst_build >/dev/null

echo "GUI $LABEL → relay $ADDR (relay-id filled in). First run: \"Create account\" (write down the phrase); then — passphrase → \"Log in\"."
KARST_HOME="$HOME_DIR" \
KARST_RELAY="$ADDR" \
KARST_RELAY_ID="$RID" \
  exec "$(karst_bin karst-gui)"
