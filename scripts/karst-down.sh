#!/usr/bin/env bash
# karst-down.sh — stop the relay brought up by scripts/karst-up.sh.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

RUN="${KARST_RUN_DIR:-$KARST_IMPL/.run}"
PIDFILE="$RUN/relay.pid"

if [ ! -f "$PIDFILE" ]; then
  echo "pid file not found ($PIDFILE) — was the relay started via karst-up.sh?"
  exit 0
fi

PID="$(cat "$PIDFILE")"
if kill "$PID" 2>/dev/null; then
  echo "relay stopped (pid $PID)"
else
  echo "process $PID is no longer alive"
fi
rm -f "$PIDFILE"
