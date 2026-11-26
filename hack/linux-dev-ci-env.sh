#!/bin/sh
# Runs inside the hack/linux-dev.sh container: sets up what the CI
# linux-integration-tests job has (.github/workflows/ci.yaml), then runs "$@".
set -eu

# The 127.0.0.1:443 listener for the proxy-forced test. Docker sets
# ip_unprivileged_port_start=0 in the container, so a non-root user can bind it.
python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 443)); s.listen(128)
print("ready", flush=True); sys.stdout.close()
while True:
    c, _ = s.accept(); c.sendall(b"HELLO443\n"); c.close()
' > "$CARGO_TARGET_DIR/listen443.ready" &
listener=$!
# Wait for the bind; fail loudly if the listener died instead.
while ! grep -q ready "$CARGO_TARGET_DIR/listen443.ready" 2>/dev/null; do
  kill -0 "$listener" 2>/dev/null || { echo "linux-dev: 127.0.0.1:443 listener failed to bind" >&2; exit 1; }
  sleep 0.1
done
export CPLT_TEST_PRIV_443=1

# The session bus as CI sets it up: socket at `bus` in a 0700 XDG_RUNTIME_DIR.
# Not under /tmp, which tests expect to hold only what cplt puts there.
export XDG_RUNTIME_DIR="$CARGO_TARGET_DIR/xdg-runtime"
mkdir -m 700 -p "$XDG_RUNTIME_DIR"
sed "s|<listen>.*</listen>|<listen>unix:path=$XDG_RUNTIME_DIR/bus</listen>|" \
  /usr/share/dbus-1/session.conf > "$CARGO_TARGET_DIR/session.conf"
exec dbus-run-session --config-file="$CARGO_TARGET_DIR/session.conf" -- "$@"
