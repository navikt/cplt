#!/usr/bin/env bash
# Give a local dev build network access on a Mac where Little Snitch only
# allows the Homebrew cplt. The Homebrew cplt runs a proxy on a fixed
# localhost port; the dev build forwards its CONNECT tunnels through it with
# --proxy-upstream, after doing its own domain filtering.
#
#   hack/dev-proxy.sh            # leave running, Ctrl-C to stop
#   target/debug/cplt --with-proxy --proxy-upstream http://127.0.0.1:18443 exec -- curl -sSI https://github.com
set -euo pipefail

PORT="${DEV_PROXY_PORT:-18443}"
CPLT="${DEV_PROXY_CPLT:-/opt/homebrew/bin/cplt}"

"$CPLT" --with-proxy --proxy-port "$PORT" --allow-all-domains exec -- sleep 2147483647 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT INT TERM

echo "dev proxy on 127.0.0.1:$PORT (pid $pid). Pass to the dev build:"
echo "  --with-proxy --proxy-upstream http://127.0.0.1:$PORT"
wait "$pid"
