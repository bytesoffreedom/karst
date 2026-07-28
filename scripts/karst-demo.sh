#!/usr/bin/env bash
# karst-demo.sh — bring up the WHOLE system locally and prove it with an
# end-to-end exchange: a relay + two clients (Alice, Bob), a message in BOTH
# directions, then clean up. One command answering "does it all work together?"
# NOT for production (SKELETON relay).
#
#   scripts/karst-demo.sh [ADDR]        (default 127.0.0.1:9000)

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ADDR="${1:-127.0.0.1:9000}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/karst-demo.XXXXXX")"
RELAY_LOG="$WORK/relay.log"
RELAY_PID=""

cleanup() {
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== building binaries =="
karst_build

echo "== starting relay on $ADDR =="
KARST_RELAY_HOME="$WORK/relay" "$(karst_bin karst-relay)" "$ADDR" >"$RELAY_LOG" 2>&1 &
RELAY_PID=$!
karst_wait_port "$ADDR" || { echo "relay did not come up; log:"; cat "$RELAY_LOG"; exit 1; }
RID="$(karst_relay_id_from_log "$RELAY_LOG")"
[ -n "$RID" ] || { echo "could not read relay-id; log:"; cat "$RELAY_LOG"; exit 1; }
echo "relay-id: $RID"

CLI="$(karst_bin karst)"
ALICE="$WORK/alice"; BOB="$WORK/bob"
a() { KARST_HOME="$ALICE" KARST_PASSPHRASE=alice-pw "$CLI" "$@"; }
b() { KARST_HOME="$BOB"   KARST_PASSPHRASE=bob-pw   "$CLI" "$@"; }

echo "== init both =="
a init >/dev/null; b init >/dev/null
ALICE_IK="$(a account)"; BOB_IK="$(b account)"
echo "Alice IK: $ALICE_IK"
echo "Bob   IK: $BOB_IK"

echo "== both publish their bundle (§12 discovery) =="
# A capability belongs to ONE relay now, so name it (CRYPTO-24).
a dev-cap --relay "$ADDR" --relay-id "$RID" >/dev/null
b dev-cap --relay "$ADDR" --relay-id "$RID" >/dev/null
a publish --relay "$ADDR" --relay-id "$RID"
b publish --relay "$ADDR" --relay-id "$RID"

echo "== Alice -> Bob =="
a send --relay "$ADDR" --relay-id "$RID" --to "$BOB_IK" "hi Bob — this is Alice"
echo "-- Bob fetches:"
b recv --relay "$ADDR" --relay-id "$RID"

echo "== Bob -> Alice (reverse direction, ratchet turnaround) =="
b send --relay "$ADDR" --relay-id "$RID" --to "$ALICE_IK" "hi Alice — got it"
echo "-- Alice fetches:"
a recv --relay "$ADDR" --relay-id "$RID"

echo "== FILE transfer: Alice -> Bob (chunking + reassembly + SHA) =="
SRC="$WORK/payload.bin"
head -c 8000 /dev/urandom >"$SRC"
SRC_SHA="$(sha256sum "$SRC" | cut -d' ' -f1)"
a send-file --relay "$ADDR" --relay-id "$RID" --to "$BOB_IK" --file "$SRC"
echo "-- Bob fetches (the file is saved in his received/):"
b recv --relay "$ADDR" --relay-id "$RID"
GOT="$BOB/received/payload.bin"
GOT_SHA="$(sha256sum "$GOT" 2>/dev/null | cut -d' ' -f1)"
if [ "$SRC_SHA" = "$GOT_SHA" ] && [ -n "$GOT_SHA" ]; then
  echo "   file intact: SHA matched ($SRC_SHA)"
else
  echo "   ERROR: SHA mismatch (src=$SRC_SHA got=$GOT_SHA)"; exit 1
fi

echo "== DONE: end-to-end text exchange in both directions + file transfer =="
