#!/bin/sh
# Build and test the Linux sandbox (Landlock, seccomp, bubblewrap) in a Debian
# container, from a Mac or any host with docker or podman.
#
#   hack/linux-dev.sh shell            interactive shell in the container
#   hack/linux-dev.sh check            cargo build + clippy for Linux
#   hack/linux-dev.sh test-integration tests/integration_linux.rs
#   hack/linux-dev.sh run CMD...       any command, e.g. run cargo test --lib
#
# The checkout is mounted read-write at /work/cplt (not under /tmp: the sandbox
# denies exec there). target/ and the cargo registry live in named volumes so
# they persist between runs and never mix with the host's macOS build.
set -eu

# Debian bookworm with the toolchain CI uses (1.94), pinned by digest.
BASE=rust:1.94-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2
# The container user takes the host uid: files the tests create in the
# bind-mounted checkout then belong to the same uid inside and out, which the
# ownership checks on cplt's scratch and config dirs require.
uid=$(id -u)
IMAGE=cplt-linux-dev:2-uid$uid

if [ -n "${CPLT_CONTAINER_ENGINE:-}" ]; then engine=$CPLT_CONTAINER_ENGINE
elif command -v docker >/dev/null 2>&1; then engine=docker
elif command -v podman >/dev/null 2>&1; then engine=podman
else echo "linux-dev: need docker or podman (colima works)" >&2; exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)

if ! "$engine" image inspect "$IMAGE" >/dev/null 2>&1; then
  # Same packages as the CI Linux jobs: bubblewrap, git, python3, node, curl.
  # dbus for the session-bus tests. A non-root user, because CI runs tests unprivileged and Landlock/bwrap
  # behave differently as root.
  "$engine" build -t "$IMAGE" - <<DOCKERFILE
FROM $BASE
RUN apt-get update && apt-get install -y --no-install-recommends \
      bubblewrap dbus git python3 nodejs curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add clippy rustfmt \
    && useradd -m -o -u $uid dev \
    && mkdir -p /work/target /home/dev/.cargo \
    && chown dev:dev /work /work/target /home/dev/.cargo
USER dev
ENV CARGO_HOME=/home/dev/.cargo CARGO_TARGET_DIR=/work/target PATH=/usr/local/cargo/bin:\$PATH
WORKDIR /work/cplt
DOCKERFILE
fi

tty=
[ -t 0 ] && [ -t 1 ] && tty=-t

# Why each option:
#   seccomp=unconfined     the default container seccomp profile blocks the
#                          unshare/clone(CLONE_NEWUSER) and mount calls bwrap
#                          makes, and stacking cplt's own filter needs it too.
#   apparmor=unconfined    the default docker AppArmor profile denies mount.
#   systempaths=unconfined the masked /proc entries make bwrap's --proc fail.
# No --privileged and no added capabilities: tests run as a non-root uid and get
# their namespaces the way an unprivileged CI user does.
# dbus-run-session gives the tests a session bus, as a desktop login has.
run() {
  # shellcheck disable=SC2086
  exec "$engine" run --rm -i $tty \
    --security-opt seccomp=unconfined \
    --security-opt apparmor=unconfined \
    --security-opt systempaths=unconfined \
    -v "$root:/work/cplt" \
    -v cplt-linuxdev-target:/work/target \
    -v cplt-linuxdev-cargo:/home/dev/.cargo \
    -e CPLT_TEST_REQUIRE_SANDBOX=1 \
    "$IMAGE" "$@"
}

case "${1:-}" in
  shell) run bash ;;
  check) run sh -c 'cargo build --all-targets && cargo clippy --all-targets -- -D warnings' ;;
  # The 127.0.0.1:443 listener the CI job starts, for the proxy-forced test.
  # Docker sets ip_unprivileged_port_start=0, so the non-root user can bind it.
  test-integration) shift; run sh -c 'python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((\"127.0.0.1\", 443)); s.listen(128)
while True:
    c, _ = s.accept(); c.sendall(b\"HELLO443\\n\"); c.close()
" & sleep 1; CPLT_TEST_PRIV_443=1 dbus-run-session -- cargo test --test integration_linux "$@"' sh ;;
  run) shift; run "$@" ;;
  *) sed -n '2,10p' "$0" >&2; exit 2 ;;
esac
