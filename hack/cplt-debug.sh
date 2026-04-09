#!/usr/bin/env bash
# Debug script for cplt — handles cleanup, build, and test runs
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PROXY_PORT=18080

cleanup() {
    # Kill any orphaned proxy processes
    lsof -ti :"$PROXY_PORT" 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 0.5
}

build() {
    cargo build 2>&1
}

usage() {
    cat <<EOF
Usage: $0 <command> [args...]

Commands:
  version           Quick sandbox test (copilot --version)
  prompt <text>     Run with a prompt (uses native auth discovery)
  denials <args>    Run with --show-denials and custom copilot args
  profile           Print the generated sandbox profile (SBPL)
  cleanup           Kill orphaned proxy/sandbox processes

Examples:
  $0 version
  $0 prompt "say hello"
  $0 denials -p "say hello"
  $0 denials --version
  $0 profile
EOF
}

case "${1:-help}" in
    version)
        cleanup
        build
        echo "--- Running: copilot --version inside sandbox ---"
        ./target/debug/cplt -- --version
        ;;
    prompt)
        cleanup
        build
        echo "--- Running: copilot -p '${2:-say hello}' inside sandbox ---"
        ./target/debug/cplt --show-denials -- -p "${2:-say hello}"
        ;;
    denials)
        cleanup
        build
        shift
        echo "--- Running with --show-denials: copilot $* ---"
        ./target/debug/cplt --show-denials -- "$@"
        ;;
    profile)
        build
        ./target/debug/cplt --print-profile
        ;;
    cleanup)
        echo "Killing orphaned processes on port $PROXY_PORT..."
        cleanup
        echo "Done."
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        echo "Unknown command: $1"
        usage
        exit 1
        ;;
esac
