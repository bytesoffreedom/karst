#!/usr/bin/env bash
# karst-wss-demo.sh — end-to-end demo of the WebSocket-over-TLS carrier on one
# machine: a relay terminating `wss`, and two clients whose whole session rides
# inside an ordinary-looking HTTPS/WebSocket connection. Proves the carrier works
# and shows how to wire it (KARST_WSS + KARST_WSS_ROOT_CA).
#
#   scripts/karst-wss-demo.sh
#
# TEST-ONLY CERT: this generates a throwaway SELF-SIGNED cert for "localhost" and
# tells the clients to trust it via KARST_WSS_ROOT_CA. That is fine for a local
# demo. A real WebSocket-over-TLS deployment needs a REAL cert for a REAL hostname
# (certbot / Let's Encrypt) that validates against the public webpki roots — a
# self-signed cert to an odd endpoint is an observable feature, not a private one.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

command -v openssl >/dev/null 2>&1 || { echo "error: openssl not found (needed to make the test cert)." >&2; exit 1; }

WORK="$(mktemp -d)"
RELAY_PID=""
cleanup() { [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

karst_build

ADDR="127.0.0.1:9443"
CA="$WORK/ca.pem"          # the trust root the clients trust (KARST_WSS_ROOT_CA)
CERT="$WORK/cert.pem"      # the relay's chain (leaf + CA), presented on the wire
KEY="$WORK/key.pem"        # the leaf key

echo "== generating a throwaway test CA + localhost leaf cert (TEST ONLY) =="
# A proper CA → leaf chain: webpki rejects a CA cert used directly as the leaf
# (CaUsedAsEndEntity), so the CA (trust anchor) and the serverAuth leaf are separate.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/ca-key.pem" -out "$CA" -days 2 -subj "/CN=KARST demo CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$KEY" -out "$WORK/leaf.csr" -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in "$WORK/leaf.csr" -CA "$CA" -CAkey "$WORK/ca-key.pem" \
  -CAcreateserial -out "$WORK/leaf.pem" -days 2 \
  -extfile <(printf 'subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature') 2>/dev/null
cat "$WORK/leaf.pem" "$CA" >"$CERT"   # relay presents leaf then CA

echo "== starting relay with the wss carrier on $ADDR =="
KARST_RELAY_HOME="$WORK/relay" KARST_RELAY_TLS_CERT="$CERT" KARST_RELAY_TLS_KEY="$KEY" \
  KARST_RELAY_MODE=public KARST_RELAY_POW_BITS=8 \
  "$(karst_bin karst-relay)" "$ADDR" >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!
karst_wait_port "$ADDR" || { echo "relay did not come up; log:"; cat "$WORK/relay.log"; exit 1; }
RID="$(karst_relay_id_from_log "$WORK/relay.log")"
grep -q "WebSocket-over-TLS" "$WORK/relay.log" || { echo "relay did not enable wss; log:"; cat "$WORK/relay.log"; exit 1; }
echo "   relay-id ${RID:0:24}…  carrier: wss"

CLI="$(karst_bin karst)"
ALICE="$WORK/alice"; BOB="$WORK/bob"
# Every client call goes through the wss carrier (SNI localhost, trusting the test CA).
a() { KARST_HOME="$ALICE" KARST_PASSPHRASE=pw KARST_WSS=localhost KARST_WSS_ROOT_CA="$CA" "$CLI" "$@"; }
b() { KARST_HOME="$BOB"   KARST_PASSPHRASE=pw KARST_WSS=localhost KARST_WSS_ROOT_CA="$CA" "$CLI" "$@"; }

echo "== both accounts init + publish (through wss) =="
a init >/dev/null; b init >/dev/null
ALICE_IK="$(a account)"; BOB_IK="$(b account)"
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

echo "== Alice -> Bob, over the HTTPS-looking carrier =="
a send --relay "$ADDR" --relay-id "$RID" --to "$BOB_IK" "hi Bob — this rode inside wss"
OUT="$(b recv --relay "$ADDR" --relay-id "$RID")"
echo "$OUT"
echo "$OUT" | grep -q "rode inside wss" || { echo "FAILED: message did not round-trip over wss"; exit 1; }

echo
echo "OK — a full KARST session round-tripped through the WebSocket-over-TLS carrier."
echo "To use it for real: give clients KARST_WSS=<your-relay-hostname> and run the"
echo "relay with a REAL cert for that hostname (no KARST_WSS_ROOT_CA needed then)."
