#!/usr/bin/env bash
# Interoperability check against the reference JavaScript SDK
# (@walletconnect/sign-client, pinned in interop/js/package.json).
#
# Starts this crate's relay server, then runs a full session (pair, propose,
# approve, settle, event, request/response, rejection, ping, delete) for every
# dapp/wallet combination of {JavaScript SDK, this crate}.
#
#   interop/run.sh            # needs cargo, node and npm
set -euo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-18089}"
RELAY="ws://127.0.0.1:${PORT}"
LOGS="$(mktemp -d)"
export RELAY_URL="$RELAY" TIMEOUT_MS=60000

cargo build --quiet --examples
(cd interop/js && npm install --no-audit --no-fund --silent)

./target/debug/examples/relay_server "127.0.0.1:${PORT}" >"$LOGS/relay.log" 2>&1 &
RELAY_PID=$!
trap 'kill "$RELAY_PID" 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  grep -q "listening" "$LOGS/relay.log" 2>/dev/null && break
  sleep 0.1
done

dapp_cmd() {
  case "$1" in
    js) echo "node interop/js/dapp.mjs" ;;
    rust) echo "./target/debug/examples/dapp --relay $RELAY" ;;
  esac
}

wallet_cmd() {
  case "$1" in
    js) echo "node interop/js/wallet.mjs" ;;
    rust) echo "./target/debug/examples/wallet --relay $RELAY" ;;
  esac
}

failures=0
for dapp in js rust; do
  for wallet in js rust; do
    name="${dapp}-dapp_${wallet}-wallet"
    dlog="$LOGS/$name.dapp.log"
    wlog="$LOGS/$name.wallet.log"
    $(dapp_cmd "$dapp") >"$dlog" 2>&1 &
    dapp_pid=$!
    uri=""
    for _ in $(seq 1 150); do
      uri="$(grep -o 'wc:[^ ]*' "$dlog" 2>/dev/null | head -1 || true)"
      [ -n "$uri" ] && break
      sleep 0.2
    done
    if [ -z "$uri" ]; then
      echo "FAIL $name: dapp printed no pairing URI"
      cat "$dlog"
      kill "$dapp_pid" 2>/dev/null || true
      failures=$((failures + 1))
      continue
    fi
    wallet_status=0
    timeout 90 $(wallet_cmd "$wallet") "$uri" >"$wlog" 2>&1 || wallet_status=$?
    dapp_status=0
    wait "$dapp_pid" || dapp_status=$?
    if [ "$wallet_status" -eq 0 ] && [ "$dapp_status" -eq 0 ]; then
      echo "ok   $name"
    else
      echo "FAIL $name (dapp exit $dapp_status, wallet exit $wallet_status)"
      echo "--- dapp"; cat "$dlog"
      echo "--- wallet"; cat "$wlog"
      failures=$((failures + 1))
    fi
  done
done

echo "logs: $LOGS"
exit "$failures"
