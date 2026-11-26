#!/bin/sh
# Run a command and fail if it created anything under the real HOME.
#
# Tests must write only to their scratch HOME (`~/.cplt-test-home-<pid>`, see
# tests/common/mod.rs `scratch_home`). A suite that reaches the real HOME
# once left 37 directories in ~/.config/cplt/sessions; this catches that class.
#
# Snapshot: top-level entries of HOME, three levels under config and state
# dirs, one level under cache dirs. Only new paths count: a run never fails for
# what the developer already had.
#
# shortcut: the check sees every process, so another tool writing to HOME
# during a local run is reported too. Rerun; CI runners are quiet.
#
# Usage: hack/home-guard.sh <command> [args...]
# Exit: the command's status if it failed, else 3 if HOME gained paths.
set -u
home=${HOME:?HOME must be set}

snapshot() {
  find "$home" -mindepth 1 -maxdepth 1 2>/dev/null
  # Config and state: deep enough to see ~/.config/cplt/sessions/<id>.
  for d in .config .local "Library/Application Support" Library/Preferences; do
    [ -d "$home/$d" ] && find "$home/$d" -mindepth 1 -maxdepth 3 2>/dev/null
  done
  # Caches: new tool dirs only; their contents churn with every build.
  for d in .cache Library/Caches; do
    [ -d "$home/$d" ] && find "$home/$d" -mindepth 1 -maxdepth 1 2>/dev/null
  done
}

# Paths a normal toolchain run may create. Each line: one ERE, anchored at HOME.
allowed() {
  grep -Ev "^$home/(\
\.cplt-test-home-[0-9]+|\
\.cargo|\
\.rustup|\
\.cache/(sccache|pip|node|uv)|\
Library/Caches/(sccache|pip|node|uv|ms-playwright)\
)(/|\$)"
}
# .cplt-test-home-<pid>: the documented scratch prefix.
# .cargo, .rustup: cargo and rustup state (registry, toolchains).
# sccache, pip, node, uv, ms-playwright: build/probe tool caches CI may fill.

before=$(mktemp) && after=$(mktemp) || exit 1
trap 'rm -f "$before" "$after"' EXIT
snapshot | LC_ALL=C sort >"$before"
"$@"
status=$?
snapshot | LC_ALL=C sort >"$after"
new=$(LC_ALL=C comm -13 "$before" "$after" | allowed)
[ "$status" -ne 0 ] && exit "$status"
if [ -n "$new" ]; then
  echo "home-guard: the run created paths under the real HOME ($home):" >&2
  echo "$new" | sed 's/^/  /' >&2
  echo "home-guard: tests must use common::scratch_home(); see tests/common/mod.rs" >&2
  exit 3
fi
