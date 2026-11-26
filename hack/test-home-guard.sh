#!/bin/sh
# Self-test for hack/home-guard.sh against a throwaway HOME.
set -eu
guard="$(cd "$(dirname "$0")" && pwd)/home-guard.sh"
h=$(mktemp -d)
trap 'rm -rf "$h"' EXIT
mkdir -p "$h/.config/cplt"
fail() { echo "test-home-guard: $1" >&2; exit 1; }

HOME=$h sh "$guard" true || fail "clean run should pass"
HOME=$h sh "$guard" mkdir -p "$h/.cplt-test-home-123/x" "$h/.cargo/registry" \
  || fail "scratch prefix and allowlist should pass"

set +e
out=$(HOME=$h sh "$guard" touch "$h/.config/cplt/guard-canary" 2>&1); rc=$?
set -e
[ "$rc" -eq 3 ] || fail "canary should exit 3, got $rc"
echo "$out" | grep -q "$h/.config/cplt/guard-canary" || fail "canary path not reported: $out"

set +e
HOME=$h sh "$guard" sh -c 'mkdir "$HOME/.leak"; exit 7' 2>/dev/null; rc=$?
set -e
[ "$rc" -eq 7 ] || fail "command failure status should win, got $rc"
echo "test-home-guard: ok"
