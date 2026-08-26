#!/bin/bash
set -euo pipefail

# cplt installer — installs the cplt sandbox wrapper.
#
# On macOS: uses Homebrew (brew install navikt/tap/cplt) when available.
# On Linux / CI: downloads the latest release binary from GitHub.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/navikt/cplt/main/install.sh | bash
#   curl -fsSL ... | bash -s -- --version 2026.05.05-174753-75bae5b
#   curl -fsSL ... | bash -s -- --dir /usr/local/bin
#   curl -fsSL ... | bash -s -- --no-brew

REPO="navikt/cplt"
BINARY="cplt"
VERSION=""
INSTALL_DIR=""
NO_BREW=false

# ─── Parse arguments ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version|-v)
      if [[ $# -lt 2 ]]; then echo "Error: --version requires a value"; exit 1; fi
      VERSION="$2"; shift 2 ;;
    --dir|-d)
      if [[ $# -lt 2 ]]; then echo "Error: --dir requires a value"; exit 1; fi
      INSTALL_DIR="$2"; shift 2 ;;
    --no-brew)
      NO_BREW=true; shift ;;
    --help|-h)
      echo "Usage: install.sh [--version <tag>] [--dir <path>] [--no-brew]"
      echo ""
      echo "  --version  Install a specific version (default: latest release)"
      echo "  --dir      Install directory (default: auto-detect from PATH)"
      echo "  --no-brew  Skip Homebrew even if available (use direct download)"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ─── Homebrew install (macOS) ────────────────────────────────────────────────

if [[ "$NO_BREW" == false && -z "$VERSION" && -z "$INSTALL_DIR" ]] && command -v brew &>/dev/null; then
  echo "→ Installing via Homebrew..."
  brew install navikt/tap/cplt
  echo ""
  INSTALLED_VERSION=$(cplt --version 2>/dev/null || echo "unknown")
  echo "✓ cplt is ready! (${INSTALLED_VERSION})"
  echo ""
  echo "Get started:"
  echo "  cplt --doctor             # Check your environment"
  echo "  cplt --shell-install      # Make 'copilot' use the sandboxed version"
  echo "  cplt -- -p \"fix the tests\"  # Run Copilot in sandbox"
  echo ""
  echo "Upgrade later with: brew upgrade cplt"
  exit 0
fi

# ─── Detect platform ─────────────────────────────────────────────────────────

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  darwin) ;;
  linux)  ;;
  *)      echo "Error: Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  arm64|aarch64) ARCH="aarch64" ;;
  x86_64)        ARCH="x86_64" ;;
  *)             echo "Error: Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Map to Rust target triple
case "$OS" in
  darwin) TARGET="${ARCH}-apple-darwin" ;;
  linux)  TARGET="${ARCH}-unknown-linux-gnu" ;;
esac

ASSET="${BINARY}-${TARGET}.tar.gz"

# ─── Resolve version ─────────────────────────────────────────────────────────

if [[ -z "$VERSION" ]]; then
  echo "→ Fetching latest cplt release..."
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  if [[ -z "$VERSION" ]]; then
    echo "Error: Could not determine latest version. Use --version to specify."
    exit 1
  fi
fi

echo "→ Installing cplt ${VERSION} (${OS}/${ARCH})"

# ─── Find install directory ──────────────────────────────────────────────────

find_install_dir() {
  if [[ -n "$INSTALL_DIR" ]]; then
    return
  fi

  # Prefer directories already on PATH, in order of preference
  for dir in "$HOME/.local/bin" "$HOME/bin" "/usr/local/bin"; do
    if echo "$PATH" | tr ':' '\n' | grep -qx "$dir"; then
      if [[ -w "$dir" ]] || [[ ! -d "$dir" && -w "$(dirname "$dir")" ]]; then
        INSTALL_DIR="$dir"
        return
      fi
    fi
  done

  # Default to ~/.local/bin
  INSTALL_DIR="$HOME/.local/bin"
}

find_install_dir
mkdir -p "$INSTALL_DIR"

# ─── Download and extract ────────────────────────────────────────────────────

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "→ Downloading ${ASSET}..."
if ! curl -fsSL -o "${TMP_DIR}/${ASSET}" "$DOWNLOAD_URL"; then
  echo "Error: Failed to download ${DOWNLOAD_URL}"
  echo "Check that version ${VERSION} exists: https://github.com/${REPO}/releases"
  exit 1
fi

# ─── Verify checksum ─────────────────────────────────────────────────────────

echo "→ Verifying checksum..."
if curl -fsSL -o "${TMP_DIR}/SHA256SUMS" "$CHECKSUM_URL" 2>/dev/null; then
  # `|| true`: under `set -euo pipefail` a non-matching grep exits 1, pipefail
  # propagates it, and the assignment trips `set -e` — killing the script with a
  # bare `exit 1` and making the empty-EXPECTED branch below unreachable.
  EXPECTED=$(grep -F "${ASSET}" "${TMP_DIR}/SHA256SUMS" | awk '{print $1}' || true)
  if [[ -z "$EXPECTED" ]]; then
    echo "  ⚠ No checksum entry found for ${ASSET} (skipping verification)"
  else
    if command -v sha256sum &>/dev/null; then
      ACTUAL=$(sha256sum "${TMP_DIR}/${ASSET}" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
      ACTUAL=$(shasum -a 256 "${TMP_DIR}/${ASSET}" | awk '{print $1}')
    else
      echo "  ⚠ Neither sha256sum nor shasum found (skipping verification)"
      ACTUAL=""
    fi
    if [[ -n "$ACTUAL" && "$EXPECTED" != "$ACTUAL" ]]; then
      echo "Error: Checksum mismatch!"
      echo "  Expected: ${EXPECTED}"
      echo "  Got:      ${ACTUAL}"
      exit 1
    fi
    if [[ -n "$ACTUAL" ]]; then
      echo "  ✓ Checksum verified"
    fi
  fi
else
  echo "  ⚠ Could not download checksums (skipping verification)"
fi

# ─── Extract and install ─────────────────────────────────────────────────────

tar -xzf "${TMP_DIR}/${ASSET}" -C "${TMP_DIR}"
chmod +x "${TMP_DIR}/${BINARY}"
mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"

echo "  ✓ Installed to ${INSTALL_DIR}/${BINARY}"

# ─── Verify ──────────────────────────────────────────────────────────────────

if ! command -v "$BINARY" &>/dev/null; then
  echo ""
  echo "⚠ ${INSTALL_DIR} is not in your PATH."
  echo ""
  SHELL_NAME=$(basename "$SHELL")
  case "$SHELL_NAME" in
    zsh)  RC_FILE="$HOME/.zshrc" ;;
    bash) RC_FILE="$HOME/.bashrc" ;;
    fish) RC_FILE="$HOME/.config/fish/config.fish" ;;
    *)    RC_FILE="your shell config" ;;
  esac
  echo "Add it with:"
  if [[ "$SHELL_NAME" == "fish" ]]; then
    echo "  fish_add_path ${INSTALL_DIR}"
  else
    echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ${RC_FILE}"
  fi
  echo ""
  echo "Then restart your terminal or run:"
  echo "  source ${RC_FILE}"
else
  INSTALLED_VERSION=$("${INSTALL_DIR}/${BINARY}" --version 2>/dev/null || echo "unknown")
  echo ""
  echo "✓ cplt is ready! (${INSTALLED_VERSION})"
fi

echo ""
echo "Get started:"
echo "  cplt --doctor             # Check your environment"
echo "  cplt --shell-install      # Make 'copilot' use the sandboxed version"
echo "  cplt -- -p \"fix the tests\"  # Run Copilot in sandbox"
