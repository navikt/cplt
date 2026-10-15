#!/usr/bin/env bash
# Give a local dev build network access on a Mac where Little Snitch only
# allows the Homebrew cplt. The Homebrew cplt runs a proxy on a fixed
# localhost port; the dev build forwards its CONNECT tunnels through it with
# --proxy-upstream, after doing its own domain filtering.
#
#   hack/dev-proxy.sh            # leave running, Ctrl-C to stop
#   target/debug/cplt --with-proxy --proxy-upstream http://127.0.0.1:18443 exec -- curl -sSI https://github.com
#
# Exposure: while this runs, 127.0.0.1:$PORT is an unauthenticated CONNECT
# proxy to any domain, so every process on this machine (not just the dev
# build) can reach the network through the Homebrew cplt's Little Snitch
# allowance. Sandboxed cplt sessions cannot reach it unless they opt in with
# --allow-localhost. Stop it when you are done developing.
set -euo pipefail

PORT="${DEV_PROXY_PORT:-18443}"
CPLT="${DEV_PROXY_CPLT:-}"
if [ -z "$CPLT" ]; then
  for c in /opt/homebrew/bin/cplt /usr/local/bin/cplt; do
    [ -x "$c" ] && CPLT="$c" && break
  done
fi
if [ -z "$CPLT" ] || [ ! -x "$CPLT" ]; then
  echo "dev-proxy: no Homebrew cplt found; install it or set DEV_PROXY_CPLT" >&2
  exit 1
fi

echo "Starting the dev proxy on 127.0.0.1:$PORT. Pass to the dev build:"
echo "  --with-proxy --proxy-upstream http://127.0.0.1:$PORT"
# exec keeps cplt in the foreground: a bind failure is its own non-zero exit,
# and Ctrl-C reaches it directly, so there is nothing to trap or clean up.
exec "$CPLT" --with-proxy --proxy-port "$PORT" --allow-all-domains exec -- sleep 2147483647
