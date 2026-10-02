#!/bin/sh
# Keep successful test runs small; show test failures and build diagnostics.
log=$(mktemp) || exit 1
trap 'rm -f "$log"' EXIT
if CARGO_TERM_COLOR=never cargo test --quiet "$@" >"$log" 2>&1; then
  awk '/^warning(\[[^]]+\])?:/ { show = 1 } show || /^test result:/ { print } show && /^$/ { show = 0 }' "$log"
else
  status=$?
  if grep -q '^failures:$' "$log"; then
    awk '/^warning(\[[^]]+\])?:/ { show = 1 } show { print } show && /^$/ { show = 0 }' "$log"
    sed -n '/^failures:$/,$p' "$log"
  else
    cat "$log"
  fi
  exit "$status"
fi
