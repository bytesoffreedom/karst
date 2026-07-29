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
KARST_RELAY_MODE=public KARST_RELAY_POW_BITS=8 \
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
# The relay's DEFAULT role is `private`: it only honours capabilities it issued as invites, so
# `karst dev-cap` (a globally-known test credential) is rejected with `UnknownCapability` — that
# refusal is deliberate (#202: no silent fallback to a public dev credential). A demo therefore
# has to earn admission the way a real client does. Public mode with a low proof-of-work is the
# cheapest honest option and exercises the actual door.
a join --relay "$ADDR" --relay-id "$RID" >/dev/null
b join --relay "$ADDR" --relay-id "$RID" >/dev/null
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
# A received file is stored SEALED under an id, not as a plaintext name on disk — that is the
# point of the encrypted vault. So the demo asks the client to decrypt it out, exactly as a user
# would, instead of reaching into the vault directory and hoping for a filename.
FID="$(b files | awk 'NR==1{print $1}')"
[ -n "$FID" ] || { echo "   ERROR: nothing in Bob's received files"; b files; exit 1; }
GOT="$WORK/got-payload.bin"
b export-file "$FID" --out "$GOT" >/dev/null
# `|| true`: on a missing file sha256sum exits non-zero, and under `set -e -o pipefail` that
# would kill the script BEFORE the comparison below could say what went wrong.
GOT_SHA="$(sha256sum "$GOT" 2>/dev/null | cut -d' ' -f1 || true)"
if [ -n "$GOT_SHA" ] && [ "$SRC_SHA" = "$GOT_SHA" ]; then
  echo "   file intact: SHA matched ($SRC_SHA)"
else
  echo "   ERROR: SHA mismatch (src=$SRC_SHA got=${GOT_SHA:-<no file>})"
  b files
  exit 1
fi

echo "== DONE: end-to-end text exchange in both directions + file transfer =="
