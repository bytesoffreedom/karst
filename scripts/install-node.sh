#!/usr/bin/env bash
# install-node.sh — build, install and CONFIGURE a KARST relay node through an
# interactive prompt. Re-run any time after a `git pull` to update the binary and
# re-review the configuration; your relay identity (relay-id) is preserved.
#
#   scripts/install-node.sh
#
# Answers can be piped for an unattended install (each prompt takes its default on
# empty input):  printf '\n\n\nn\nn\n' | scripts/install-node.sh
#
# ─────────────────────────────────────────────────────────────────────────────
#  WHAT A RELAY IS, HONESTLY (read this):
#  • A relay is a DUMB, UNTRUSTED MAILBOX. It never sees message plaintext (E2E-
#    sealed; it holds no key) and has no signup/account database — your identity is
#    a key, not an account. It DOES hold the public prekey-bundles clients publish
#    (keyed by IK), so a compromised relay learns which IKs published there. Running one
#    is safe and useful, clients can use several, and anyone can run one.
#  • This is a REFERENCE build, NOT a hardened production relay. A PRIVATE relay
#    enforces admission for real (a random per-relay secret; peers get in only with
#    the invite file). A PUBLIC relay is PoW-gated: peers EARN a capability by
#    proof-of-work (`karst join`), bounded by the per-capability quota — a spam
#    BOUND, not Sybil resistance. You can start a public relay with PoW OFF (open,
#    quota-only) when there is no spam yet and turn it on live (`karst-relay pow`).
#    `dev` mode issues a known public cap for local testing only. The cryptography
#    is an unaudited reference implementation. See docs/STATUS.md. Do not rely on it
#    to protect real people from a real adversary.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BINDIR="${KARST_BIN_DIR:-$HOME/.local/bin}"

# --- tiny prompt helpers (EOF-safe: empty / piped-out input → default) ----------
ask() { # ask VAR "prompt" "default"
  local __var="$1" __prompt="$2" __def="$3" __ans=""
  read -r -p "$__prompt [$__def]: " __ans || true
  [ -z "$__ans" ] && __ans="$__def"
  printf -v "$__var" '%s' "$__ans"
}
ask_yn() { # ask_yn "prompt" default(y|n) → 0 = yes
  local __prompt="$1" __def="$2" __ans="" __hint
  [ "$__def" = y ] && __hint="Y/n" || __hint="y/N"
  read -r -p "$__prompt [$__hint]: " __ans || true
  [ -z "$__ans" ] && __ans="$__def"
  case "$__ans" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

echo "== KARST relay node installer =="
sed -n '11,21p' "$0" | sed 's/^#  \{0,1\}//'
echo
karst_require_toolchain

echo "Building the relay (release; this can take several minutes the first time)…"
karst_build_release -p node --bin karst-relay
mkdir -p "$BINDIR"
# Atomic replace so re-installing over a RUNNING relay (the update path) works.
karst_install_bin "$(karst_bin_release karst-relay)" "$BINDIR/karst-relay"
RELAY_BIN="$BINDIR/karst-relay"
echo "installed: $RELAY_BIN"
echo

# --- interactive configuration --------------------------------------------------
echo "Configuration (press Enter to accept each default):"
ask ADDR "  Listen address:port (use 0.0.0.0:9000 for public internet reach)" "127.0.0.1:9000"
ask RHOME "  Relay state dir (holds the node key; relay-id is derived from it)" "$HOME/.config/karst-relay"

# Node role (the admission door). Private is the safe default: invite-only, nobody in
# without the invite file. Public is a PoW-gated open door — peers earn a capability.
# Dev is for LOCAL TESTING ONLY (a known public capability, no real admission).
echo "  Role — who may use this relay:"
echo "    private = invite-only (default). You hand each peer an invite file."
echo "    public  = anyone may join by earning a capability (proof-of-work + quota)."
echo "    dev     = LOCAL TESTING ONLY — a known, public capability; no real admission."
POW_BITS="" ; ADVERTISE="" ; PEERS=""
if ask_yn "  Make this relay PUBLIC (anyone can join)? (No = ask private/dev next)" n; then
  MODE="public"
  # Install-time PoW toggle. Early on there may be no spam to gate, so OPEN (PoW off,
  # quota-only) is offered; the operator can turn PoW on live later with `karst-relay pow on`.
  echo "    Proof-of-work anti-spam makes joiners spend CPU to earn a capability."
  echo "    You can leave it OFF now (open door, quota-only) and turn it on live if spam appears."
  if ask_yn "    Require proof-of-work now? (No = open door for early stages)" n; then
    ask POW_BITS "      PoW difficulty (leading zero bits; higher = more work)" "20"
  else
    POW_BITS="0" # 0 = open: issue without PoW, still quota-bounded
  fi
  # Node-list discovery (public infrastructure — "which relays exist", never users). A
  # routable advertise address lists THIS relay so clients discover it; peers seed the list
  # with other relays. Blank = don't advertise / no peers.
  echo "    Node-list: a routable host:port lets clients discover this relay (blank = 0.0.0.0/"
  echo "    loopback listen addrs are NOT advertised — set a reachable name/IP to be listed)."
  ask ADVERTISE "      Advertise this relay as (host:port, blank = skip)" ""
  ask PEERS "      Seed known relays (addr@relay-id,addr@relay-id; blank = none)" ""
elif ask_yn "  Use DEV mode (LOCAL TESTING ONLY — not for real use)?" n; then
  MODE="dev"
else
  MODE="private"
fi

CERT="" ; KEY=""
if ask_yn "  Enable the WebSocket-over-TLS carrier (look like ordinary HTTPS)?" n; then
  echo "  For a realistic wss deployment this must be a REAL cert for THIS relay's hostname"
  echo "  (e.g. from certbot / Let's Encrypt). A self-signed cert is itself a"
  echo "  fingerprint and defeats the point."
  ask CERT "    TLS certificate (PEM, full chain) path" ""
  ask KEY  "    TLS private key (PEM) path" ""
  if [ -z "$CERT" ] || [ -z "$KEY" ]; then
    echo "  ! both cert and key are required for wss — disabling it." ; CERT="" ; KEY=""
  elif [ ! -r "$CERT" ]; then
    echo "  ! cert not readable: $CERT — disabling wss." ; CERT="" ; KEY=""
  elif [ ! -r "$KEY" ]; then
    echo "  ! key not readable: $KEY — disabling wss." ; CERT="" ; KEY=""
  fi
fi

# --- anonymous reachability: optionally publish over Tor and/or i2p -------------
# The relay binds to $ADDR; Tor/i2p forward an anonymous address to that port, so the
# relay's clearnet IP is never exposed. Keep the listen address on loopback for a
# Tor/i2p-ONLY relay (nothing reaches it except the local router's forward).
ONION="" ; I2P_ADDR="" ; TOR_TORRC="" ; I2P_TUNNEL_CONF=""
RELAY_PORT="${ADDR##*:}"
RELAY_LOCAL="$ADDR" ; case "$ADDR" in 0.0.0.0:*) RELAY_LOCAL="127.0.0.1:$RELAY_PORT" ;; esac
echo "  Anonymous reachability (optional) — let peers reach you without your IP:"
if ask_yn "    Publish this relay as a Tor .onion service?" n; then
  if command -v tor >/dev/null 2>&1; then
    TORDIR="$RHOME/tor" ; HSDIR="$TORDIR/hs"
    mkdir -p "$TORDIR/data" "$HSDIR" ; chmod 700 "$TORDIR" "$TORDIR/data" "$HSDIR"
    TOR_TORRC="$TORDIR/torrc"
    cat >"$TOR_TORRC" <<TORRC
# KARST relay Tor hidden service — run:  tor -f $TOR_TORRC
DataDirectory $TORDIR/data
SocksPort 0
HiddenServiceDir $HSDIR
HiddenServicePort $RELAY_PORT $RELAY_LOCAL
TORRC
    echo "    generating the onion (starting tor briefly)…"
    tor -f "$TOR_TORRC" >"$TORDIR/tor.log" 2>&1 &
    TORPID=$!
    for _ in $(seq 1 30); do [ -f "$HSDIR/hostname" ] && break; sleep 1; done
    kill "$TORPID" 2>/dev/null || true ; wait "$TORPID" 2>/dev/null || true
    if [ -f "$HSDIR/hostname" ]; then
      ONION="$(cat "$HSDIR/hostname"):$RELAY_PORT"
      echo "    onion: $ONION  (stable across restarts — key kept in $HSDIR)"
    else
      echo "    ! tor produced no hostname — see $TORDIR/tor.log"
    fi
  else
    echo "    ! 'tor' is not installed. Install it, add this to your torrc:"
    echo "        HiddenServiceDir /var/lib/tor/karst"
    echo "        HiddenServicePort $RELAY_PORT $RELAY_LOCAL"
    echo "      reload tor, then read /var/lib/tor/karst/hostname for your .onion."
  fi
fi
if ask_yn "    Publish this relay as an i2p (.b32.i2p) service?" n; then
  I2P_TUNNEL_CONF="$RHOME/karst-i2p-tunnel.conf"
  cat >"$I2P_TUNNEL_CONF" <<I2PCONF
# KARST relay i2p server tunnel. Include it from i2pd's tunnels.conf, e.g. copy to
#   /etc/i2pd/tunnels.conf.d/karst.conf   (or ~/.i2pd/tunnels.conf.d/), then restart i2pd.
[karst-relay]
type = server
host = ${RELAY_LOCAL%:*}
port = $RELAY_PORT
keys = karst-relay.dat
I2PCONF
  # Try to read the address i2pd derives for the tunnel key, if i2pd is present + running.
  for kd in "$HOME/.i2pd" /var/lib/i2pd; do
    if [ -f "$kd/karst-relay.dat" ] && command -v i2pd-tools >/dev/null 2>&1; then
      I2P_ADDR="$(i2pd-tools keyinfo "$kd/karst-relay.dat" 2>/dev/null | grep -oE '[a-z2-7]{52}\.b32\.i2p' | head -1)"
      [ -n "$I2P_ADDR" ] && I2P_ADDR="$I2P_ADDR:$RELAY_PORT"
    fi
  done
  echo "    wrote i2p server-tunnel config: $I2P_TUNNEL_CONF"
  if [ -n "$I2P_ADDR" ]; then
    echo "    i2p: $I2P_ADDR"
  else
    echo "      → copy it into i2pd's tunnels.conf.d/, restart i2pd; the .b32.i2p appears in"
    echo "        i2pd's web console (127.0.0.1:7070) under I2P tunnels → karst-relay."
  fi
fi
# Mixnet (Nym) reachability. Unlike Tor/i2p there is no per-relay address: clients route to this
# relay's normal endpoint THROUGH the Nym mixnet (their nym-socks5-client), so all we do here is
# help stand up a network-requester that allows this relay's host:port.
MIXNET=0
if ask_yn "    Make this relay reachable over a mixnet (Nym)?" n; then
  MIXNET=1
  ALLOWED="$RHOME/nym-allowed.list"
  echo "${RELAY_LOCAL%:*}:$RELAY_PORT" >"$ALLOWED"
  echo "    peers reach this relay by pointing their client's SOCKS5 at nym-socks5-client and"
  echo "    ticking 'mixnet' (or CLI --mixnet). They still need a network-requester that permits"
  echo "    this relay — run one and allow $RELAY_LOCAL :"
  if command -v nym-network-requester >/dev/null 2>&1; then
    echo "      nym-network-requester run --open-proxy false \\"
    echo "        --allowed-addresses-file $ALLOWED"
    echo "    (wrote the allow-list: $ALLOWED)"
  else
    echo "      1) install nym-network-requester (https://nymtech.net)"
    echo "      2) add this relay to its allowed.list:  $RELAY_LOCAL"
    echo "      3) share the requester's Nym address with peers for their nym-socks5-client."
  fi
fi
# The address peers should actually dial (anonymous first): onion, else i2p, else clearnet.
PEER_ADDR="$ADDR"
[ -n "$I2P_ADDR" ] && PEER_ADDR="$I2P_ADDR"
[ -n "$ONION" ] && PEER_ADDR="$ONION"
# A public relay advertises the anonymous address (never the raw IP) when one is set.
if [ "$MODE" = public ] && [ -z "$ADVERTISE" ]; then
  [ -n "$I2P_ADDR" ] && ADVERTISE="$I2P_ADDR"
  [ -n "$ONION" ] && ADVERTISE="$ONION"
fi

# --- write the config as an EnvironmentFile (systemd reads it; edits apply on ---
# --- restart; keeping config OUT of the unit means "keep updated" is one edit) --
mkdir -p "$RHOME"
ENVFILE="$RHOME/relay.env"
{
  echo "# KARST relay configuration — edit and restart to apply."
  echo "# Env surface is documented in the project README / docs/STATUS.md."
  echo "KARST_RELAY_ADDR=$ADDR"
  echo "KARST_RELAY_HOME=$RHOME"
  echo "KARST_RELAY_MODE=$MODE"
  # PoW difficulty for a public door (0 = open / no PoW). Toggle live: `karst-relay pow`.
  [ "$MODE" = public ] && echo "KARST_RELAY_POW_BITS=${POW_BITS:-20}"
  # Node-list discovery (public — which relays exist). Advertise self + seed peers.
  if [ "$MODE" = public ]; then
    [ -n "$ADVERTISE" ] && echo "KARST_RELAY_ADVERTISE=$ADVERTISE" || echo "# KARST_RELAY_ADVERTISE=your-host:port"
    [ -n "$PEERS" ] && echo "KARST_RELAY_PEERS=$PEERS" || echo "# KARST_RELAY_PEERS=addr@relay-id,addr@relay-id"
  fi
  # Large-file blobs across a restart: durable (default — a parked upload survives) |
  # ephemeral (wiped on start — the lower-residue posture). Either way: only E2E ciphertext.
  echo "# KARST_RELAY_BLOB_PERSIST=durable"
  # Per-capability spend CEILING (unset = off/no ceiling). A named preset or REQ,BYTES,WINDOW:
  #   chat-only | media-friendly | bytes-only (meter by volume) | unlimited. Change it live at any
  #   time with `karst-relay quota …` — no restart, no re-install.
  echo "# KARST_RELAY_QUOTA=media-friendly"
  if [ -n "$CERT" ]; then
    echo "KARST_RELAY_TLS_CERT=$CERT"
    echo "KARST_RELAY_TLS_KEY=$KEY"
  else
    echo "# KARST_RELAY_TLS_CERT=/path/fullchain.pem"
    echo "# KARST_RELAY_TLS_KEY=/path/privkey.pem"
  fi
} >"$ENVFILE"
chmod 0600 "$ENVFILE"
echo
echo "wrote config: $ENVFILE"

# --- prime once: create the node key on first run (create_new — never clobbered) -
# --- and capture the relay-id from the binary's own output (never hardcoded) -----
KEY_EXISTED=0 ; [ -f "$RHOME/relay.key" ] && KEY_EXISTED=1
PROBE="$ADDR" ; case "$ADDR" in 0.0.0.0:*) PROBE="127.0.0.1:${ADDR##*:}" ;; esac
PLOG="$(mktemp)"
POW="" ; [ "$MODE" = public ] && POW="KARST_RELAY_POW_BITS=${POW_BITS:-20}"
KARST_RELAY_HOME="$RHOME" KARST_RELAY_MODE="$MODE" $POW ${CERT:+KARST_RELAY_TLS_CERT="$CERT" KARST_RELAY_TLS_KEY="$KEY"} \
  "$RELAY_BIN" "$ADDR" >"$PLOG" 2>&1 &
PRIME_PID=$!
RELAY_ID=""
if karst_wait_port "$PROBE"; then
  RELAY_ID="$(karst_relay_id_from_log "$PLOG")"
fi
kill "$PRIME_PID" 2>/dev/null || true
wait "$PRIME_PID" 2>/dev/null || true
if [ -z "$RELAY_ID" ]; then
  echo "! could not determine relay-id — relay output was:" ; cat "$PLOG" ; rm -f "$PLOG" ; exit 1
fi
rm -f "$PLOG"
if [ "$KEY_EXISTED" = 1 ]; then
  echo "existing relay identity preserved."
else
  echo "generated a new node key (0600) at $RHOME/relay.key."
fi

# --- optional: a systemd --user service so the relay survives logout/reboot -----
INSTALLED_SERVICE=0
if command -v systemctl >/dev/null 2>&1 && ask_yn "  Install a systemd --user service to keep the relay running?" n; then
  UNITDIR="$HOME/.config/systemd/user"
  mkdir -p "$UNITDIR"
  cat >"$UNITDIR/karst-relay.service" <<UNIT
[Unit]
Description=KARST relay (reference build, unaudited)

[Service]
EnvironmentFile=$ENVFILE
ExecStart=$RELAY_BIN
Restart=on-failure
# A cold boot can lose a bind race; back off so systemd doesn't rapid-restart into
# its StartLimitBurst and give up. (A clean exit — the `stop` verb — is NOT a failure.)
RestartSec=2

[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload
  # `enable` + `restart` (not `enable --now`) so a RE-RUN over an already-running
  # service actually picks up the freshly-installed binary/config.
  systemctl --user enable karst-relay.service
  systemctl --user restart karst-relay.service
  INSTALLED_SERVICE=1
  echo "  service enabled: systemctl --user status karst-relay"
  # A companion tor service keeps the onion's forward alive alongside the relay.
  if [ -n "$TOR_TORRC" ]; then
    cat >"$UNITDIR/karst-relay-tor.service" <<UNIT
[Unit]
Description=Tor hidden service for the KARST relay
Before=karst-relay.service

[Service]
ExecStart=$(command -v tor) -f $TOR_TORRC
Restart=on-failure

[Install]
WantedBy=default.target
UNIT
    systemctl --user daemon-reload
    systemctl --user enable karst-relay-tor.service
    systemctl --user restart karst-relay-tor.service
    echo "  tor service enabled: systemctl --user status karst-relay-tor"
  fi
  # A --user service starts at LOGIN, not at boot. Linger is what makes "auto-start"
  # actually mean auto-start: with it the relay comes back on reboot (and stays up
  # after logout); without it the unit only runs while you're logged in.
  if loginctl show-user "$USER" 2>/dev/null | grep -q '^Linger=yes'; then
    echo "  linger already on — the relay auto-starts on boot."
  elif ask_yn "  Enable linger so the relay auto-starts on boot (needs sudo)?" y; then
    if sudo loginctl enable-linger "$USER" 2>/dev/null; then
      echo "  linger enabled — the relay comes back automatically after a reboot."
    else
      echo "  ! couldn't enable linger (sudo declined/absent). Run it yourself to survive reboot:"
      echo "      sudo loginctl enable-linger $USER"
    fi
  else
    echo "  (no linger: the relay runs only while you're logged in. Auto-start on boot later with:"
    echo "      sudo loginctl enable-linger $USER )"
  fi
fi

karst_warn_if_not_on_path "$BINDIR"

# --- summary --------------------------------------------------------------------
echo
echo "Relay ready."
echo "  listen:    $ADDR"
[ -n "$ONION" ]    && echo "  onion:     $ONION"
[ -n "$I2P_ADDR" ] && echo "  i2p:       $I2P_ADDR"
echo "  peers use: $PEER_ADDR"
echo "  relay-id:  $RELAY_ID"
echo "  role:      $MODE"
CARRIER="raw TCP"
[ -n "$CERT" ] && CARRIER="WebSocket-over-TLS (wss)"
[ -n "$I2P_ADDR" ] && CARRIER="i2p"
[ -n "$ONION" ] && CARRIER="Tor onion"
echo "  carrier:   $CARRIER"
[ "$MIXNET" = 1 ] && echo "  mixnet:    reachable via Nym (peers use nym-socks5-client + 'mixnet')"
echo "  config:    $ENVFILE"
# `karst-relay pow` finds the running relay's admin socket via KARST_RELAY_HOME; a fresh
# shell only has the default, so prefix the hint when this relay uses a custom home.
POWPFX="" ; [ "$RHOME" != "$HOME/.config/karst-relay" ] && POWPFX="KARST_RELAY_HOME=$RHOME "
if [ "$MODE" = private ]; then
  echo "  invite:    $RHOME/invite.json  (a peer joins with: karst import-cap <that file>)"
elif [ "$MODE" = public ]; then
  if [ "${POW_BITS:-20}" = 0 ]; then
    echo "  door:      OPEN (no PoW) — peers join with: karst join --relay $PEER_ADDR --relay-id $RELAY_ID"
    echo "             turn PoW on later:  ${POWPFX}karst-relay pow on"
  else
    echo "  door:      PoW-gated (${POW_BITS} bits) — peers join with: karst join --relay $PEER_ADDR --relay-id $RELAY_ID"
    echo "             change it live:  ${POWPFX}karst-relay pow open|on N|off"
  fi
fi
if [ "$INSTALLED_SERVICE" = 0 ]; then
  echo
  echo "Start it manually (reads the config above, incl. KARST_RELAY_ADDR):"
  echo "  set -a; . \"$ENVFILE\"; set +a; \"$RELAY_BIN\""
fi
echo
echo "Give peers your  address + relay-id  so their clients can reach you"
echo "(clients: KARST_RELAY=$PEER_ADDR  KARST_RELAY_ID=$RELAY_ID)."
if [ -n "$ONION" ]; then
  echo "  → .onion peers ALSO route through Tor: in the app set the SOCKS5 field to"
  echo "    127.0.0.1:9050 (Tor), or CLI: karst … --relay $PEER_ADDR --socks5 127.0.0.1:9050"
fi
if [ -n "$I2P_ADDR" ]; then
  echo "  → .i2p peers ALSO route through their i2p router: SOCKS5 field 127.0.0.1:4447 (i2pd),"
  echo "    or CLI: karst … --relay $PEER_ADDR --socks5 127.0.0.1:4447"
fi
if [ "$MIXNET" = 1 ]; then
  echo "  → mixnet peers: SOCKS5 field 127.0.0.1:1080 (nym-socks5-client) + tick 'mixnet',"
  echo "    or CLI: karst … --relay $PEER_ADDR --socks5 127.0.0.1:1080 --mixnet"
fi
[ -n "$CERT" ] && echo "wss clients also set: KARST_WSS=<the-hostname-on-your-cert>"
[ -n "$CERT" ] && echo "  to co-host behind a real website, append a secret path the site's"
[ -n "$CERT" ] && echo "  reverse proxy routes here: KARST_WSS=<host>/<random-unguessable-path>"
