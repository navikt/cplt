#!/bin/sh
# Build and test the Linux sandbox (Landlock, seccomp, bubblewrap) in a Debian
# container, from a Mac with docker (colima works). Podman is untested.
#
#   hack/linux-dev.sh shell            interactive shell in the container
#   hack/linux-dev.sh check            cargo build + clippy for Linux
#   hack/linux-dev.sh test-integration tests/integration_linux.rs, CI env
#   hack/linux-dev.sh test-all         cargo test --no-fail-fast, as the CI Linux job
#   hack/linux-dev.sh run CMD...       any command, e.g. run cargo test --lib
#
# The checkout is mounted read-write at /work/cplt (not under /tmp: the sandbox
# denies exec there). target/ is a named volume over the checkout's target/,
# so tests that make temp dirs there get a native Linux filesystem, and the
# Linux build never mixes with the host's macOS one. The cargo home is a volume too.
set -eu

# Debian bookworm with the toolchain CI uses (1.94), pinned by digest.
BASE=rust:1.94-slim-bookworm@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2
# The container user takes the host uid: files the tests create in the
# bind-mounted checkout then belong to the same uid inside and out, which the
# ownership checks on cplt's scratch and config dirs require.
uid=$(id -u)
IMAGE=cplt-linux-dev:3-uid$uid

command -v docker >/dev/null 2>&1 || { echo "linux-dev: need docker (colima works)" >&2; exit 1; }
engine=docker

root=$(cd "$(dirname "$0")/.." && pwd)

if ! "$engine" image inspect "$IMAGE" >/dev/null 2>&1; then
  # Same packages as the CI Linux jobs: bubblewrap, git, python3, node, curl.
  # dbus for the session-bus tests. A non-root user, because CI runs tests unprivileged and Landlock/bwrap
  # behave differently as root.
  "$engine" build -t "$IMAGE" - <<DOCKERFILE
FROM $BASE
RUN apt-get update && apt-get install -y --no-install-recommends \
      bubblewrap dbus sqlite3 git python3 nodejs curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add clippy rustfmt \
    && useradd -m -o -u $uid dev \
    && mkdir -p /work/cplt/target /home/dev/.cargo \
    && chown -R dev:dev /work /home/dev/.cargo
USER dev
ENV CARGO_HOME=/home/dev/.cargo CARGO_TARGET_DIR=/work/cplt/target PATH=/usr/local/cargo/bin:\$PATH
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
#   nofile=65536           colima defaults to 1024; the full suite needs more, like a CI runner.
# No --privileged and no added capabilities: tests run as a non-root uid and get
# their namespaces the way an unprivileged CI user does.
run() {
  # shellcheck disable=SC2086
  exec "$engine" run --rm -i $tty \
    --security-opt seccomp=unconfined \
    --ulimit nofile=65536:65536 \
    --security-opt apparmor=unconfined \
    --security-opt systempaths=unconfined \
    -v "$root:/work/cplt" \
    -v cplt-linuxdev-target:/work/cplt/target \
    -v cplt-linuxdev-cargo:/home/dev/.cargo \
    -e CPLT_TEST_REQUIRE_SANDBOX=1 \
    "$IMAGE" "$@"
}

case "${1:-}" in
  shell) run bash ;;
  check) run sh -c 'cargo build --all-targets && cargo clippy --all-targets -- -D warnings' ;;
  test-integration) shift; run sh hack/linux-dev-ci-env.sh cargo test --test integration_linux "$@" ;;
  test-all) shift; run sh hack/linux-dev-ci-env.sh cargo test --no-fail-fast --verbose "$@" ;;
  run) shift; run "$@" ;;
  *) sed -n '2,11p' "$0" >&2; exit 2 ;;
esac
