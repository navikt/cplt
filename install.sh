#!/bin/bash
set -euo pipefail

# cplt installer — installs the cplt sandbox wrapper.
#
# On macOS: uses Homebrew (brew install navikt/tap/cplt) when available.
# On Debian / Ubuntu: adds the Nav apt archive and installs from it.
# Elsewhere, or with --no-apt: downloads the latest release binary from GitHub.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/navikt/cplt/main/install.sh | bash
#   curl -fsSL ... | bash -s -- --version 2026.05.05-174753-75bae5b
#   curl -fsSL ... | bash -s -- --dir /usr/local/bin
#   curl -fsSL ... | bash -s -- --no-brew
#   curl -fsSL ... | bash -s -- --no-apt

REPO="navikt/cplt"
BINARY="cplt"
VERSION=""
INSTALL_DIR=""
NO_BREW=false
NO_APT=false

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
    --no-apt)
      NO_APT=true; shift ;;
    --help|-h)
      echo "Usage: install.sh [--version <tag>] [--dir <path>] [--no-brew] [--no-apt]"
      echo ""
      echo "  --version  Install a specific version (default: latest release)"
      echo "  --dir      Install directory (default: auto-detect from PATH)"
      echo "  --no-brew  Skip Homebrew even if available (use direct download)"
      echo "  --no-apt   Skip the apt archive on Debian/Ubuntu (use direct download)"
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
  echo "  cplt doctor                 # Check your environment"
  echo "  cplt --shell-install        # Make 'copilot' use the sandboxed version"
  echo "  cplt -- -p \"fix the tests\"  # Run Copilot in sandbox"
  echo ""
  echo "Upgrade later with: brew upgrade navikt/tap/cplt"
  exit 0
fi

# ─── apt archive (Debian / Ubuntu) ───────────────────────────────────────────
# A bare binary gets no upgrades from apt, so on apt systems add the archive and
# install from it. An existing script install outside /usr/bin keeps the direct
# download: switching it to apt would leave two copies on PATH.

# The archive key is pinned: a key with any other fingerprint is refused, so a
# hijacked page or TLS connection cannot take over later `apt upgrade` runs.
# Cross-checked against keyring/ in github.com/navikt/apt and the InRelease
# signature. Rotating the key means updating both values.
NAV_APT_KEY_FPR=B92E9C7EDBF0BD72F026B189FFB2724BF4A12D28
# Without gpg the keyring file itself is pinned instead. Any re-export of the
# key (new subkey, signature or expiry) changes this hash, so update it then.
NAV_APT_KEY_SHA256=b4f473cfb22ddbdc5d05d2d9174e4385f9cfa299b8bb2540842e79ad8520417c

sha256_of() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Checks the downloaded key: exactly one primary key, and its fingerprint is the
# pin (subkey fpr lines are ignored). Falls back to the file hash without gpg.
check_apt_key() {
  if command -v gpg &>/dev/null; then
    gpg --show-keys --with-colons "$1" 2>/dev/null | awk -F: -v pin="$NAV_APT_KEY_FPR" '
      $1 == "pub" { pubs++; want = 1; next }
      $1 == "sub" { want = 0; next }
      $1 == "fpr" && want { if ($10 == pin) ok++; want = 0 }
      END { exit !(pubs == 1 && ok == 1) }'
  else
    [[ "$(sha256_of "$1")" == "$NAV_APT_KEY_SHA256" ]]
  fi
}

# Any failure here removes the key and list this run created and falls through
# to the direct download, so a broken step never leaves a dead apt source
# behind. An existing apt install keeps its files, and gets no direct download
# that would shadow /usr/bin/cplt.
apt_install() {
  local keyring=/usr/share/keyrings/navikt-archive-keyring.gpg
  local list=/etc/apt/sources.list.d/navikt.list
  local key_tmp reason="" created=()
  [[ -e "$keyring" ]] || created+=("$keyring")
  [[ -e "$list" ]] || created+=("$list")
  key_tmp="$(mktemp)"
  if ! curl -fsSL -o "$key_tmp" https://navikt.github.io/apt/keyring/navikt-archive-keyring.gpg \
    || ! test -s "$key_tmp"; then
    reason="could not download the archive key"
  elif ! check_apt_key "$key_tmp"; then
    reason="archive key does not match the pinned key ${NAV_APT_KEY_FPR}"
  elif ! sudo install -m 644 "$key_tmp" "$keyring"; then
    reason="could not install the archive key"
  elif ! echo "deb [signed-by=${keyring}] https://navikt.github.io/apt stable main" \
    | sudo tee "$list" >/dev/null; then
    reason="could not write ${list}"
  elif ! sudo apt-get update -qq -o Dir::Etc::sourcelist="$list" \
    -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 </dev/null; then
    reason="apt-get update failed"
  elif ! sudo apt-get install -y cplt </dev/null; then
    reason="apt-get install cplt failed"
  fi
  rm -f "$key_tmp"
  [[ -z "$reason" ]] && return 0
  if [[ ${#created[@]} -gt 0 ]]; then
    sudo rm -f "${created[@]}" 2>/dev/null || true
  fi
  echo "! apt install failed: ${reason}"
  if [[ "$EXISTING" == /usr/bin/cplt ]]; then
    echo "  cplt is already installed from apt, so no direct download is made."
    echo "  Retry with: sudo apt update && sudo apt install --only-upgrade cplt"
    exit 1
  fi
  echo "  Falling back to direct download (--no-apt skips apt)"
  return 1
}

EXISTING="$(command -v "$BINARY" 2>/dev/null || true)"
DEB_ARCH="$(dpkg --print-architecture 2>/dev/null || true)"
# sudo must work without asking, or have a terminal to ask on: under curl | bash
# stdin is the script, not the user.
if [[ "$NO_APT" == false && -z "$VERSION" && -z "$INSTALL_DIR" && "$(uname -s)" == Linux ]] \
  && [[ "$DEB_ARCH" == amd64 || "$DEB_ARCH" == arm64 ]] \
  && command -v apt-get &>/dev/null && command -v sudo &>/dev/null \
  && { sudo -n true 2>/dev/null || [[ -r /dev/tty ]]; } \
  && [[ -z "$EXISTING" || "$EXISTING" == /usr/bin/cplt ]] \
  && echo "→ Adding the Nav apt archive (https://navikt.github.io/apt)..." \
  && apt_install; then
  echo ""
  echo "✓ cplt is ready! ($(cplt --version 2>/dev/null || echo unknown))"
  echo ""
  echo "Get started:"
  echo "  cplt doctor                 # Check your environment"
  echo "  cplt --shell-install        # Make 'copilot' use the sandboxed version"
  echo "  cplt -- -p \"fix the tests\"  # Run Copilot in sandbox"
  echo ""
  echo "Upgrade later with: sudo apt update && sudo apt install --only-upgrade cplt"
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
if ! curl -fsSL -o "${TMP_DIR}/SHA256SUMS" "$CHECKSUM_URL"; then
  echo "Error: Could not download ${CHECKSUM_URL}"
  exit 1
fi
EXPECTED=$(awk -v a="${ASSET}" '$2 == a || $2 == "*" a {print $1}' "${TMP_DIR}/SHA256SUMS")
if [[ -z "$EXPECTED" ]]; then
  echo "Error: No checksum entry for ${ASSET} in SHA256SUMS"
  exit 1
fi
if command -v sha256sum &>/dev/null; then
  ACTUAL=$(sha256sum "${TMP_DIR}/${ASSET}" | awk '{print $1}')
elif command -v shasum &>/dev/null; then
  ACTUAL=$(shasum -a 256 "${TMP_DIR}/${ASSET}" | awk '{print $1}')
else
  echo "Error: Neither sha256sum nor shasum found; cannot verify the download"
  exit 1
fi
if [[ "$EXPECTED" != "$ACTUAL" ]]; then
  echo "Error: Checksum mismatch!"
  echo "  Expected: ${EXPECTED}"
  echo "  Got:      ${ACTUAL}"
  exit 1
fi
echo "  ✓ Checksum verified"

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

# ─── Starter config ──────────────────────────────────────────────────────────
# New users get the defaults `cplt config init` writes. An existing config
# (file, symlink or dangling symlink) is never touched; init refuses it too.
# Skipped as root or under sudo: HOME may be another user's and the file
# would get the wrong owner. Skipped next to an xdg-pinned marker too: the
# user's config may then live under XDG_CONFIG_HOME.

if [[ "$(id -u)" != 0 && -z "${SUDO_USER:-}" ]]; then
  if CONFIG_PATH=$("${INSTALL_DIR}/${BINARY}" config path 2>/dev/null) && [[ -n "$CONFIG_PATH" ]]; then
    if [[ ! -e "$CONFIG_PATH" && ! -L "$CONFIG_PATH" && ! -e "$(dirname "$CONFIG_PATH")/xdg-pinned" ]]; then
      if "${INSTALL_DIR}/${BINARY}" config init </dev/null >/dev/null 2>&1; then
        echo "  ✓ Created starter config: ${CONFIG_PATH}"
      else
        echo "⚠ Could not create a starter config. Run 'cplt config init' later."
      fi
    fi
  else
    echo "⚠ Could not resolve the config path. Run 'cplt config init' later."
  fi
fi

echo ""
echo "Get started:"
echo "  cplt doctor                 # Check your environment"
echo "  cplt --shell-install        # Make 'copilot' use the sandboxed version"
echo "  cplt -- -p \"fix the tests\"  # Run Copilot in sandbox"
echo ""
echo "Upgrade later with: cplt update"
