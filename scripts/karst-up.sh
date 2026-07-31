#!/usr/bin/env bash
# karst-up.sh — bring up a local relay and leave it running, printing ready-to-use
# commands for the clients (CLI and GUI). For the manual/GUI scenario.
# Stop with: scripts/karst-down.sh. NOT for production (REFERENCE relay).
#
#   scripts/karst-up.sh [ADDR]          (default 127.0.0.1:9000)

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ADDR="${1:-127.0.0.1:9000}"
RUN="${KARST_RUN_DIR:-$KARST_IMPL/.run}"
mkdir -p "$RUN"
RELAY_LOG="$RUN/relay.log"

if [ -f "$RUN/relay.pid" ] && kill -0 "$(cat "$RUN/relay.pid")" 2>/dev/null; then
  echo "relay is already running (pid $(cat "$RUN/relay.pid")). Stop it: scripts/karst-down.sh"
  exit 1
fi

echo "== building =="
karst_build

echo "== starting relay on $ADDR =="
# Public door with a cheap PoW: a DEFAULT (private) relay only honours capabilities it
# issued as invites, so the hints below would fail against it (#202 removed the silent
# fallback to a public dev credential). This script exists for local manual testing.
KARST_RELAY_MODE=public KARST_RELAY_POW_BITS=8 \
  KARST_RELAY_HOME="$RUN/relay" "$(karst_bin karst-relay)" "$ADDR" >"$RELAY_LOG" 2>&1 &
echo $! >"$RUN/relay.pid"
karst_wait_port "$ADDR" || { echo "relay did not come up; log:"; cat "$RELAY_LOG"; exit 1; }
RID="$(karst_wait_relay_id "$RELAY_LOG")" || { echo "could not read relay-id; log:"; cat "$RELAY_LOG"; exit 1; }
echo "$RID" >"$RUN/relay-id"
echo "$ADDR" >"$RUN/relay-addr"

CLI="$(karst_bin karst)"

cat <<EOF

relay running (pid $(cat "$RUN/relay.pid")), address $ADDR
relay-id: $RID
  (saved in $RUN/relay-id; log $RELAY_LOG)

── Option A: the desktop app (the product) ───────────────────────────────────
  cd impl && cargo run -p desktop            # the Tauri client
  First run: "Create account" → write down the 24 words (recovery phrase) →
  confirm the words → set a passphrase → "Create account". Point it at the relay
  address and relay-id above. Copy your IK, paste it as a contact in the other
  instance (out-of-band trust), and confirm the safety number.

── Option B: two clients in the terminal (CLI) ──────────────────────────────
  export R="--relay $ADDR --relay-id $RID"
  # Alice:
  KARST_HOME=/tmp/karst-alice KARST_PASSPHRASE=pw $CLI init
  KARST_HOME=/tmp/karst-alice KARST_PASSPHRASE=pw $CLI join \$R    # earn admission (PoW)
  KARST_HOME=/tmp/karst-alice KARST_PASSPHRASE=pw $CLI publish \$R
  # Bob (in another window) — same, then find each other's IK:
  KARST_HOME=/tmp/karst-alice KARST_PASSPHRASE=pw $CLI account   # → Alice's IK
  # send/receive:
  KARST_HOME=/tmp/karst-alice KARST_PASSPHRASE=pw $CLI send \$R --to <BOB_IK> "hi"
  KARST_HOME=/tmp/karst-bob   KARST_PASSPHRASE=pw $CLI recv \$R

Stop the relay: scripts/karst-down.sh
EOF
