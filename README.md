# cplt

[![CI](https://github.com/navikt/cplt/actions/workflows/ci.yml/badge.svg)](https://github.com/navikt/cplt/actions/workflows/ci.yml)
[![Release](https://github.com/navikt/cplt/actions/workflows/release.yml/badge.svg)](https://github.com/navikt/cplt/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![macOS](https://img.shields.io/badge/platform-macOS-lightgrey)
![Linux](https://img.shields.io/badge/platform-Linux-lightgrey)

Sandbox wrapper for GitHub Copilot CLI. Runs Copilot inside a kernel-level sandbox so the agent can work on your project but cannot access your secrets.

- **macOS**: Apple Seatbelt/SBPL via `sandbox-exec`
- **Linux**: Landlock LSM + seccomp-BPF (kernel 5.13+)

![cplt banner](./assets/cplt.png)

## Table of contents

- [Quick start](#quick-start)
- [Install](#install)
  - [Shell setup](#shell-setup-recommended)
- [What it does](#what-it-does)
- [Usage](#usage)
- [Configuration file](#configuration-file)
- [Architecture](#architecture)
- [Security](#security)
- [Domain filtering](#domain-filtering)
- [Known impacts](#known-impacts)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [References](#references)

## Quick start

```bash
# Install
brew install navikt/tap/cplt

# Make 'copilot' run the sandboxed version (persistent)
cplt --shell-install

# Check your environment
cplt --doctor

# Run Copilot in sandbox
cplt -- -p "fix the tests"
```

**Primary control: filesystem isolation.** The sandbox blocks access to credentials and secrets at the kernel level. All restrictions apply to Copilot and every process it spawns.

| Resource                                                                         | Status                                   | Notes                                                                                   |
| -------------------------------------------------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------- |
| Read/write project directory                                                     | ✅ Allowed                                |                                                                                         |
| Read `.env*`, `.pem`, `.key` in project                                          | 🔒 Kernel-blocked                         | Prevents secret exfiltration; `--allow-env-files` to override                           |
| Write `.git/hooks`, `.git/config`, `.gitmodules`                                 | 🔒 Kernel-blocked                         | Prevents persistence via git hooks, hooksPath redirect, submodule hijacking             |
| Execute from `/tmp`, `/var/folders`                                              | 🔒 Kernel-blocked                         | Prevents write-then-exec; scratch dir redirects TMPDIR to safe location (on by default) |
| Execute from `~/Library/Caches`                                                  | 🔒 Kernel-blocked                         | Prevents binary-drop staging; Copilot native modules exempted via carve-out             |
| Modify `.vscode/tasks.json`, `launch.json`                                       | ⚠️ Allowed — known risk                   | IDE trust boundary; see SECURITY.md for mitigations                                     |
| Read/write `~/.copilot` (auth, settings)                                         | ✅ Allowed                                | Includes `file-map-executable` for `keytar.node`, `pty.node`, `computer.node`           |
| Write `~/.copilot/pkg` (native modules)                                          | 🔒 Kernel-blocked                         | Prevents persistence via native module replacement                                      |
| Environment variables                                                            | 🔒 Sanitized + hardened                   | Only safe allowlist passes through; lifecycle scripts blocked; `--pass-env VAR` to add  |
| Read `~/.config/gh/hosts.yml` + `config.yml`                                     | ✅ Allowed (read-only)                    | Only these two files — rest of `.config/gh` is blocked                                  |
| Read `~/.config/mise`                                                            | ✅ Allowed (read-only)                    | Tool versions and PATH — no secrets                                                     |
| Read `~/.gitconfig`, `~/.config/git/config`                                      | ✅ Allowed (read-only)                    |                                                                                         |
| Read global git hooks (`core.hooksPath`)                                         | ✅ Allowed (read-only, write-denied)      | Auto-detected; must be under `$HOME` with depth ≥3; writes explicitly blocked           |
| Commit/tag signing (`commit.gpgsign`, `tag.gpgsign`)                             | 🔒 Disabled                               | Private keys (`~/.ssh`, `~/.gnupg`) are blocked; signing disabled via env var override  |
| Read `~/Library/Application Support/Microsoft`                                   | ✅ Allowed (read-only)                    | Device ID for telemetry                                                                 |
| Access macOS Keychain                                                            | ✅ Allowed (read+write)                   | Security framework locks db during access; Copilot uses `keytar.node` for token storage |
| Outbound network (port 443)                                                      | ✅ Allowed                                | All other ports blocked — use `--allow-port` to add extras                              |
| Localhost outbound                                                               | 🔒 Kernel-blocked                         | Prevents local service access; inbound still works for proxy                            |
| SSH agent (unix socket)                                                          | 🔒 Kernel-blocked                         | Prevents signing git operations or SSH to hosts                                         |
| Developer tools (`~/.cargo`, `~/.mise`, `~/.gradle`, `~/.m2`, `~/.sdkman`, `~/.pyenv`, `~/.konan`, etc.) | ✅ Allowed (read+write for caches)        | Only dirs that exist on disk; tightened at runtime via `--doctor`                       |
| Go source code (`~/go/src`)                                                      | 🔒 Kernel-blocked                         | Only `~/go/bin` and `~/go/pkg` are readable                                             |
| Read `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`                                  | 🔒 Kernel-blocked                         |                                                                                         |
| Read `~/.kube`, `~/.docker`, `~/.nais`                                           | 🔒 Kernel-blocked                         |                                                                                         |
| Read `~/.password-store`, `~/.terraform.d`                                       | 🔒 Kernel-blocked                         |                                                                                         |
| Read `~/.config/gcloud`, `~/.config/op`                                          | 🔒 Kernel-blocked                         |                                                                                         |
| Read `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.vault-token`                       | 🔒 Kernel-blocked                         |                                                                                         |
| Read `~/.gem/credentials`                                                        | 🔒 Kernel-blocked                         |                                                                                         |
| Child process inheritance                                                        | ✅ All restrictions apply to subprocesses |                                                                                         |

This table is a summary. The sandbox also allows access to system files (SSL certs, `/etc/hosts`), temp directories (read/write but no exec), and system tool paths (`/usr/bin`, `/opt/homebrew`). Run `cplt --print-profile` to see the complete SBPL rules.

For the full security model, threat analysis, and test strategy, see **[SECURITY.md](SECURITY.md)**.

## Install

### Homebrew (recommended)

```bash
brew install navikt/tap/cplt
```

### Pre-compiled binary

Download the latest release for your platform:

```bash
# macOS — Apple Silicon (M1/M2/M3/M4)
curl -fsSL https://github.com/navikt/cplt/releases/latest/download/cplt-aarch64-apple-darwin.tar.gz | tar xz
sudo mv cplt /usr/local/bin/

# macOS — Intel
curl -fsSL https://github.com/navikt/cplt/releases/latest/download/cplt-x86_64-apple-darwin.tar.gz | tar xz
sudo mv cplt /usr/local/bin/

# Linux — x86_64
curl -fsSL https://github.com/navikt/cplt/releases/latest/download/cplt-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv cplt /usr/local/bin/

# Linux — ARM64
curl -fsSL https://github.com/navikt/cplt/releases/latest/download/cplt-aarch64-unknown-linux-gnu.tar.gz | tar xz
sudo mv cplt /usr/local/bin/
```

Every release binary has [build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) — verify it with:

```bash
gh attestation verify cplt -o navikt
```

### Build from source

```bash
git clone https://github.com/navikt/cplt.git && cd cplt
cargo build --release
sudo cp target/release/cplt /usr/local/bin/
```

Or with [mise](https://mise.jdx.dev):

```bash
mise run install
```

### Shell setup (recommended)

By default, you run the sandboxed version with `cplt`. To make `copilot` run the sandboxed version too, use the one-command installer:

```bash
cplt --shell-install
```

This detects your shell, appends the alias to your rc file, and prints what it did. Safe to run multiple times — it won't add duplicates.

| Shell | File modified | What's added |
|-------|--------------|--------------|
| **zsh** (macOS default) | `~/.zshrc` | `eval "$(cplt --shell-setup)"` |
| **bash** | `~/.bashrc` | `eval "$(cplt --shell-setup)"` |
| **fish** | `~/.config/fish/conf.d/cplt.fish` | `alias copilot cplt` |

After installing, restart your shell or `source` the file to activate.

<details>
<summary>Manual setup (alternative)</summary>

If you prefer not to use `--shell-install`, add the appropriate line to your shell rc file manually:

```bash
# zsh / bash
eval "$(cplt --shell-setup)"

# fish
alias copilot cplt
```

This is the same pattern used by tools like mise, direnv, and starship.
</details>

**Why an alias instead of a symlink?** Both cplt and Copilot CLI install into the same Homebrew bin directory (`/opt/homebrew/bin/`). A symlink would conflict — only one file named `copilot` can exist there. A shell alias avoids this entirely: the real `copilot` binary stays in PATH (so cplt can find and wrap it), and the alias transparently redirects your command.

> **Note:** cplt has recursion prevention built in. If it detects it's already running inside a sandbox (via the `__CPLT_WRAPPED` environment variable), it will refuse to launch again. Read-only subcommands like `--print-profile` and `--doctor` still work inside an existing sandbox.

## What it does

## Usage

```
cplt [OPTIONS] [-- <COPILOT_ARGS>...]
```

Everything after `--` is passed directly to the `copilot` command.

### File access

The project directory is the primary writable workspace, plus a narrow allowlist required for auth, runtime, and tooling (see capability table above). Everything else (SSH keys, cloud credentials, etc.) is blocked by the kernel.

| Flag                       | What it does                                                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-d, --project-dir <DIR>`  | Which directory Copilot can work in. Defaults to the current git repo root.                                                                       |
| `--allow-read <PATH>`      | Let Copilot read (read-only) files outside the project (e.g. shared libraries, docs). Can be repeated.                                            |
| `--allow-write <PATH>`     | Let Copilot read AND write outside the project. Use carefully. Can be repeated.                                                                   |
| `--deny-path <PATH>`       | Block a path that would otherwise be allowed. Deny always wins. Can be repeated.                                                                  |
| `--allow-port <PORT>`      | Allow outbound TCP on an extra port (default: only 443). Can be repeated.                                                                         |
| `--allow-localhost <PORT>` | Allow outbound to `localhost` on a specific port (localhost is blocked by default). Use for MCP servers or dev servers. Can be repeated.          |
| `--allow-localhost-any`    | Allow outbound to `localhost` on **all** ports. Needed for build tools like Turbopack (Next.js) and Vite that use random ephemeral ports for IPC. |

### Environment variables

By default, `cplt` sanitizes the child environment — only safe variables pass through. Cloud credentials, database URLs, and package tokens are stripped. Additionally, security hardening variables are injected to block npm/yarn/pnpm lifecycle scripts (postinstall hooks) — the #1 supply chain attack vector — and disable git commit/tag signing (since `~/.ssh` and `~/.gnupg` are inaccessible inside the sandbox).

**What passes through:**

| Category | Examples | How |
|---|---|---|
| Core system | `HOME`, `USER`, `PATH`, `SHELL`, `TMPDIR`, `LANG` | Explicit allowlist |
| Terminal | `TERM`, `COLORTERM`, `TERM_PROGRAM` | Explicit allowlist |
| Editor | `EDITOR`, `VISUAL`, `PAGER` | Explicit allowlist |
| Auth tokens | `GH_TOKEN`, `GITHUB_TOKEN`, `COPILOT_GITHUB_TOKEN` | Explicit allowlist (needed for Copilot) |
| Copilot config | `COPILOT_DEBUG`, `COPILOT_*` | Prefix allowlist |
| Language runtimes | `NODE_*`, `GOPATH`, `CARGO_HOME`, `JAVA_HOME`, `VIRTUAL_ENV`, `PYTHONPATH` | Explicit allowlist |
| Tool managers | `NVM_*`, `PYENV_*`, `MISE_*`, `SDKMAN_*`, `COREPACK_*`, `YARN_*` | Prefix allowlist |
| XDG dirs | `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME` | Explicit allowlist |

**Prefix allowlist with secret-suffix protection:** Variables matching allowed prefixes (e.g. `COPILOT_*`, `YARN_*`) are passed through *unless* they end with a secret-bearing suffix: `_TOKEN`, `_AUTH`, `_SECRET`, `_SECRET_KEY`, `_KEY`, `_PASSWORD`, or `_CREDENTIALS`. For example, `COPILOT_DEBUG` passes through but `COPILOT_API_KEY` is blocked.

**Always blocked:** `AWS_*`, `AZURE_*`, `NPM_TOKEN`, `DATABASE_URL`, `VAULT_TOKEN`, `SSH_AUTH_SOCK`, Docker vars, CI tokens, and anything not in the allowlist.

| Flag               | What it does                                                                                                                                            |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--pass-env <VAR>` | Explicitly pass an environment variable through to Copilot. Can be repeated.                                                                            |
| `--inherit-env`    | ⚠️ **Dangerous.** Inherit the full parent environment (only strips `NO_COLOR`, `FORCE_COLOR`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`). Use only for debugging. |
| `--allow-lifecycle-scripts` | Allow npm/yarn/pnpm lifecycle scripts (postinstall hooks) to run. Blocked by default. Use when `npm install` needs postinstall hooks.         |
| `--allow-gpg-signing`       | Allow GPG commit/tag signing inside the sandbox. Grants read-only access to public keyring and GPG agent socket (private keys stay denied). See [GPG signing](#gpg-commit-signing). |
| `--no-scratch-dir`          | Disable the per-session scratch directory (on by default). TMPDIR will not be redirected.                                                    |
| `--scratch-dir`             | Explicitly enable per-session scratch directory (already the default). Useful to override `scratch_dir = false` in config.                   |
| `--allow-tmp-exec`          | ⚠️ **Dangerous.** Allow exec from system temp dirs (`/private/tmp`, `/private/var/folders`). Prefer scratch dir.                             |

### Supported runtimes

cplt auto-discovers installed tools and configures sandbox rules accordingly. Only directories that exist on disk get rules (no phantom paths).

| Runtime | Home dirs | Env vars / prefixes | Discovery |
|---|---|---|---|
| **Node.js** | `.nvm`, `.local` | `NODE_*`, `NPM_*`, `NVM_*` | `node` |
| **Rust** | `.cargo`, `.rustup` | `CARGO_HOME`, `RUSTUP_HOME` | `cargo` |
| **Go** | `go/bin`, `go/pkg` | `GOPATH`, `GOROOT`, `GOCACHE`, etc. | `go` |
| **Java/Kotlin (JVM)** | `.sdkman`, `.gradle`, `.m2` | `JAVA_HOME`, `GRADLE_*`, `MAVEN_*`, `SDKMAN_*` | `java`, `gradle` |
| **Kotlin Native** | `.konan` | — | — |
| **Python** | `.pyenv` | `VIRTUAL_ENV`, `PYTHONPATH`, `PYENV_ROOT`, `PYENV_*` | `python3` |
| **Yarn Berry** | `.yarn` | `YARN_*` (hardening overrides `YARN_ENABLE_SCRIPTS`) | `yarn` |
| **pnpm** | `Library/pnpm` | `PNPM_HOME` | `pnpm` |
| **Corepack** | — | `COREPACK_*` | — |
| **mise** | `.mise` | `MISE_*` | `mise` |

To see which tools cplt detected, run `cplt --doctor`.

### Proxy (optional)

The proxy is **disabled by default**. When enabled, all outbound traffic — including Copilot CLI, `gh`, and `curl` — is routed through a localhost CONNECT proxy via `HTTP_PROXY`/`HTTPS_PROXY` env vars and `NODE_USE_ENV_PROXY=1`.

**What the proxy gives you:**

- **Connection logging** — see every domain Copilot connects to in real time
- **Domain blocking** — block known exfiltration infrastructure (paste sites, webhook services, etc.)
- **Domain allowlisting** — restrict connections to only known-safe domains
- **Audit log** — persistent file log of all connections for post-session review
- **Port enforcement** — the proxy enforces the same port restrictions as the sandbox (443 + `--allow-port`)

**One-time use:**

```bash
cplt --with-proxy -- -p "fix the tests"
```

**Enable permanently** (recommended):

```bash
cplt --init-config
```

Then edit `~/.config/cplt/config.toml`:

```toml
[proxy]
enabled = true
# blocked_domains = "~/.config/cplt/blocked-domains.txt"  # block known-bad domains
# allowed_domains = "~/.config/cplt/allowed-domains.txt"  # restrict to known-safe domains
# log_file = "~/.config/cplt/proxy.log"                   # persistent audit log
```

After this, every `cplt` invocation starts the proxy automatically. Use `--no-proxy` to skip it for a single run.

| Flag                        | What it does                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------ |
| `--with-proxy`              | Start a localhost CONNECT proxy that logs connections.                                           |
| `--no-proxy`                | Disable the proxy, even if your config file enables it.                                          |
| `--proxy-port <PORT>`       | Which port the proxy listens on (default: 18080).                                                |
| `--blocked-domains <FILE>`  | Domains to block, one per line. Re-read on every request (edit live).                            |
| `--allowed-domains <FILE>`  | Domains to allow — only listed domains can connect. Parsed at startup (fail-closed).             |
| `--proxy-log <FILE>`        | Append a line per connection to this file for post-session audit.                                |

> **Domain matching:** both blocklist and allowlist use the same rules — `example.com` matches the exact domain and all subdomains (`sub.example.com`, `deep.sub.example.com`). Matching is case-insensitive. Trailing dots are stripped.
>
> **Localhost traffic** (MCP servers, dev servers) bypasses the proxy via `NO_PROXY` and will not appear in the audit log.

### Debugging

| Flag              | What it does                                                                                                                                           |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--doctor`        | Run environment diagnostics: checks auth, Copilot install, tools, and sandbox paths. Exits 0 if all critical checks pass.                              |
| `--print-profile` | Print the generated sandbox profile (SBPL) and exit.                                                                                                   |
| `--show-denials`  | Stream macOS sandbox denial logs in real time.                                                                                                         |
| `--no-validate`   | Skip the startup check that verifies sandbox restrictions are active.                                                                                  |
| `-y, --yes`       | Skip the interactive confirmation prompt. The configuration summary is still printed for auditability. Required when stdin is not a TTY (CI, scripts). |
| `--init-config`   | Create a starter config file at `~/.config/cplt/config.toml` and exit.                                                                                 |

### Examples

```bash
# Most common: run Copilot in sandbox
cplt -- -p "fix the tests"

# Check environment before first run
cplt --doctor

# With connection logging
cplt --with-proxy -- -p "fix the tests"

# Let Copilot read a shared library directory
cplt --allow-read ~/shared-libs -- -p "use shared-libs"

# Allow outbound on extra ports (e.g., external API)
cplt --allow-port 8443 -- -p "test the API"

# Allow localhost for MCP servers or dev servers
cplt --allow-localhost 3000 --allow-localhost 8080 -- -p "use the MCP server"

# Allow all localhost (needed for Next.js/Turbopack, Vite builds)
cplt --allow-localhost-any -- -p "fix the build"

# Non-interactive / CI usage (skip confirmation prompt)
cplt --yes -- -p "fix the tests"

# Block a path you don't want Copilot to see
cplt --deny-path ~/.config/gh -- -p "refactor auth"

# Pass a specific env var through (e.g. custom tool config)
cplt --pass-env MY_CUSTOM_VAR --pass-env ANOTHER_VAR -- -p "run with custom config"

# Inherit full environment (dangerous — only for debugging)
cplt --inherit-env -- -p "debug the build"

# Block paste sites (with proxy enabled)
cplt --with-proxy --blocked-domains ./blocked-domains.txt -- -p "refactor"

# Inspect the generated sandbox profile
cplt --print-profile

# Debug: see what the sandbox blocks in real time
cplt --show-denials -- -p "fix the tests"
```

## Configuration file

Save your preferred defaults to `~/.config/cplt/config.toml` so you don't need to pass flags every time.

**Create the default config:**

```bash
cplt --init-config
```

This creates a commented template at `~/.config/cplt/config.toml`:

```toml
[proxy]
# enabled = true             # Recommended — logs all connections
# port = 18080
# blocked_domains = "~/.config/cplt/blocked-domains.txt"
# allowed_domains = "~/.config/cplt/allowed-domains.txt"
# log_file = "~/.config/cplt/proxy.log"

[sandbox]
# validate = true
# allow_env_files = false
# allow_lifecycle_scripts = false
# allow_gpg_signing = false    # Allow GPG commit signing (see SECURITY.md)
# allow_localhost_any = false
# scratch_dir = true           # On by default; set false to disable
# allow_tmp_exec = false       # Dangerous — prefer scratch_dir
# inherit_env = false          # Dangerous — exposes all env vars
# pass_env = ["MY_CUSTOM_VAR"]

[allow]
# read = ["~/some/path"]
# write = ["~/another/path"]
# ports = [8080]
# localhost = [3000, 8080]

[deny]
# paths = ["~/extra/secret"]
```

**Precedence** (highest to lowest):

1. CLI flags (`--with-proxy`, `--proxy-port`, etc.)
2. Config file (`~/.config/cplt/config.toml`)
3. Built-in defaults

CLI flags always override the config file. Use `--no-proxy` to disable a proxy that's enabled in config.

**Environment variable override:**

Set `CPLT_CONFIG` to use a config file at a custom location:

```bash
CPLT_CONFIG=/path/to/custom.toml cplt -- --version
```

**Path expansion:** Paths in `[allow]` and `[deny]` support `~/` expansion and are resolved relative to the config file directory. `proxy.blocked_domains` supports `~/` expansion only.

### Managing config from the CLI

Instead of editing TOML by hand, use `cplt config`:

```bash
cplt config show                          # show effective config (file + defaults)
cplt config get sandbox.quiet             # get a single value
cplt config explain                       # list all keys with descriptions
cplt config explain sandbox.pass_env      # explain a specific key
cplt config validate                      # check for syntax errors and unknown keys
```

**Setting values:**

```bash
# Scalar keys — set replaces the value
cplt config set sandbox.quiet true
cplt config set proxy.port 18080

# Array keys — set appends (idempotent, no duplicates)
cplt config set allow.read ~/Desktop
cplt config set allow.read ~/Documents    # adds a second entry
cplt config set allow.read ~/Desktop      # no-op, already present
cplt config set allow.ports 8080
```

**Removing values:**

```bash
# Remove a single element from an array
cplt config set allow.read ~/Desktop --unset

# Remove an entire key (reverts to default)
cplt config set allow.read --unset
cplt config set sandbox.quiet --unset
```

## Architecture

```
┌──────────────────────────────────┐
│  cplt (Rust binary)              │
│  ┌───────────┐  ┌─────────────┐  │
│  │ Policy    │  │ CONNECT     │  │
│  │ Generator │  │ Proxy       │  │
│  └─────┬─────┘  │ (optional)  │  │
│        │        └─────────────┘  │
│        ▼                         │
│  ┌─────────────┬────────────┐    │
│  │   macOS     │   Linux    │    │
│  │  Seatbelt   │  Landlock  │    │
│  │  sandbox-   │  + seccomp │    │
│  │  exec       │  pre_exec  │    │
│  └─────────────┴────────────┘    │
│        │                         │
│        ▼                         │
│  copilot (sandboxed)             │
│  ├── All child processes         │
│  ├── Cannot read ~/.ssh          │
│  ├── Network port-restricted     │
│  ├── SSH agent blocked           │
│  └── Filesystem = primary ctrl   │
└──────────────────────────────────┘
```

**Security model**: deny-by-default filesystem with kernel enforcement. Network is restricted to port 443 (HTTPS) by default (use `--allow-port` for extras). SSH agent access and localhost outbound are blocked at the kernel level. The profile generator auto-discovers your environment (`--doctor`) and only includes tool directories that actually exist on disk — fewer rules means a tighter sandbox.

Platform-specific details:
- **macOS**: Seatbelt/SBPL profile generated and passed to `sandbox-exec`
- **Linux**: Landlock LSM rules + seccomp-BPF filter applied via `pre_exec` (kernel 5.13+, TCP port filtering on 6.7+)

See [SECURITY.md](SECURITY.md) for the full threat model, defense layers, and honest gaps.

## Security

~2500 lines of Rust. Four dependencies (clap, libc, serde, toml). No runtime services, no telemetry. Every security boundary is kernel-enforced and tested. Every design decision is documented with the threat it mitigates and the prior art it builds on.

**Our priorities, in order:**

1. **Correct** — every claim is tested, every edge case has a CVE or research reference
2. **Transparent** — read [SECURITY.md](SECURITY.md), it hides nothing
3. **Simple** — single static binary, zero config required, sane defaults
4. **Useful** — get out of the way and let Copilot do its job, safely

For the full security model, threat analysis, and test strategy, see **[SECURITY.md](SECURITY.md)**.

### `~/.config/gh/hosts.yml` is readable

Copilot spawns `gh auth token` to authenticate. This reads `~/.config/gh/hosts.yml` which contains a GitHub OAuth token. We allow reading only `hosts.yml` and `config.yml` (not the entire `.config/gh` directory) because:

- **Required for auth**: Without `gh` auth, Copilot falls back to Keychain only. Many users rely on `gh` CLI for auth.
- **Read-only**: The sandbox cannot modify the token file.
- **Minimal access**: Only the two files `gh` actually reads — extensions, state, and other gh data are blocked.
- **Same-destination token**: The token is a GitHub token that Copilot already sends to GitHub's API. An attacker would need to exfiltrate it to a *different* server.
- **Risk**: A compromised Copilot could exfiltrate this token via port 443. Use `--deny-path ~/.config/gh` if this concerns you (Copilot will use Keychain auth instead).

### Outbound network is port-restricted

SBPL (Seatbelt Profile Language) does not support wildcard port filtering by IP range. Copilot connects to multiple CDN-backed endpoints with changing IPs (`api.business.githubcopilot.com`, `api.githubcopilot.com`, `proxy.business.githubcopilot.com`). We cannot enumerate these IPs. Therefore:

- **Only port 443 (HTTPS) is allowed** — all other outbound TCP ports are blocked at the kernel level
- **Localhost outbound is blocked** — prevents access to local services (databases, dev servers, etc.)
- **SSH agent is blocked** — unix socket access is denied, preventing use of loaded SSH keys
- **Filesystem isolation is the primary control** — credentials are kernel-blocked regardless of network
- **Use `--with-proxy`** to log and filter all outbound connections (including Copilot traffic)
- **Use `--allow-port`** to add extra ports when needed (e.g., `--allow-port 8080` for a dev server)

See [SECURITY.md](SECURITY.md) for the full threat model and honest gaps.

## Domain filtering

When the proxy is enabled, it supports both **blocking** (deny known-bad domains) and **allowlisting** (permit only known-good domains).

### Blocklist

Block domains commonly used for data exfiltration. A default blocklist is included based on real attack infrastructure observed in 2025–2026 supply chain incidents:

```bash
cplt --with-proxy --blocked-domains blocked-domains.txt -- -p "fix tests"
```

The blocklist covers webhook capture services, paste sites, file sharing, tunneling services, and IP recon endpoints. See [`blocked-domains.txt`](blocked-domains.txt) for the full list with sources.

### Allowlist

Restrict connections to only specific domains. When set, the proxy blocks everything not in the list:

```bash
cplt --with-proxy --allowed-domains allowed-domains.txt -- -p "fix tests"
```

Example `allowed-domains.txt` for Copilot-only access:

```
api.github.com
api.githubcopilot.com
api.business.githubcopilot.com
proxy.business.githubcopilot.com
telemetry.business.githubcopilot.com
```

Both blocklist and allowlist can be used together — allowlist is checked first, then blocklist.

Set either permanently in `~/.config/cplt/config.toml`:

```toml
[proxy]
enabled = true
blocked_domains = "~/.config/cplt/blocked-domains.txt"
# allowed_domains = "~/.config/cplt/allowed-domains.txt"
```

> **Note:** The allowlist is parsed at startup and fails closed — if the file is missing or unreadable, cplt exits with an error. The blocklist is re-read on every request so you can edit it live.

## Copilot CLI network endpoints

Copilot CLI 1.0.21 connects directly to these endpoints (empirically verified):

| Endpoint                           | Purpose                                  |
| ---------------------------------- | ---------------------------------------- |
| `api.github.com`                   | GitHub API (user info, token validation) |
| `api.githubcopilot.com`            | Copilot API                              |
| `api.business.githubcopilot.com`   | Copilot Business API (enterprise users)  |
| `proxy.business.githubcopilot.com` | Copilot Business proxy                   |

## Known impacts

The sandbox is kernel-enforced — **all restrictions apply to every process spawned inside it**, including dev servers, test runners, build tools, and package managers. This is by design (a sandboxed agent could otherwise escape by spawning a child process), but it affects some workflows:

### `.env` file blocking

`.env*`, `.pem`, `.key`, `.p12`, `.pfx`, `.jks` files in the project directory are **blocked from reading** by default. This prevents a rogue agent from exfiltrating secrets, but has side effects:

| Operation                      | Impact     | Why                                                                   |
| ------------------------------ | ---------- | --------------------------------------------------------------------- |
| `npm install`                  | ✅ Works    | Does not read `.env` files                                            |
| `cargo build`, `go build`      | ✅ Works    | Does not read `.env` files                                            |
| `next build` / `next dev`      | ⚠️ May fail | Next.js auto-loads `.env`, `.env.local`, `.env.production` at startup |
| `npm run dev` (Node.js)        | ⚠️ May fail | Apps using `dotenv` to load config will get `undefined` env vars      |
| `npm test` / `vitest`          | ⚠️ May fail | Tests that depend on `.env` for config won't find the values          |
| TLS dev servers (`.pem` certs) | ⚠️ Blocked  | Local HTTPS certs in `.pem`/`.key` files can't be read                |
| `.env.example`                 | ⚠️ Blocked  | Matches `.env.*` pattern — use `--allow-env-files` if needed          |
| Writing `.env` files           | ✅ Works    | Only read is denied; Copilot can create `.env` from templates         |

**Fix:** Use `--allow-env-files` when working on projects that need env file loading:

```bash
cplt --allow-env-files -- -p "start the dev server and fix the failing test"
```

Or set it permanently in config:

```toml
[sandbox]
allow_env_files = true
```

### Lifecycle scripts (postinstall hooks)

npm/yarn/pnpm lifecycle scripts are **blocked by default** via `npm_config_ignore_scripts=true` and `YARN_ENABLE_SCRIPTS=false`. This prevents supply chain attacks through postinstall hooks, but may break packages that require post-install steps:

| Operation                        | Impact      | Why                                                            |
| -------------------------------- | ----------- | -------------------------------------------------------------- |
| `npm install` (download only)    | ✅ Works     | Packages are downloaded and extracted normally                 |
| `npm install` (with native deps) | ⚠️ May fail  | Packages like `node-gyp`, `sharp`, `bcrypt` need postinstall  |
| `npm run build` / `npm test`     | ✅ Works     | Explicit scripts are not blocked, only lifecycle hooks         |
| `yarn install` (Yarn Berry)      | ⚠️ May fail  | If packages have install scripts                               |

**Fix:** Use `--allow-lifecycle-scripts` when the project needs postinstall hooks:

```bash
cplt --allow-lifecycle-scripts -- -p "install dependencies and build the project"
```

Or set it permanently in config:

```toml
[sandbox]
allow_lifecycle_scripts = true
```

### Temp dir execution (go test, mise, node-gyp)

Tools that compile-then-execute from `$TMPDIR` are **blocked by default** because the sandbox denies `process-exec` and `file-map-executable` from `/private/tmp` and `/private/var/folders`. This affects:

| Tool                      | Impact      | Why                                                                   |
| ------------------------- | ----------- | --------------------------------------------------------------------- |
| `go test`                 | ❌ Blocked   | Compiles test binaries to `$TMPDIR`, then executes them               |
| `go run`                  | ❌ Blocked   | Compiles to `$TMPDIR` then executes — same as `go test`               |
| `go generate`             | ❌ Blocked   | If the generator is a Go binary compiled to `$TMPDIR`                 |
| `mise run` (inline tasks) | ❌ Blocked   | Writes script to temp file, then executes it                          |
| `node-gyp` (native addons)| ❌ Blocked  | Compiles C/C++ to temp, then loads via dlopen                         |
| `go build`                | ✅ Works     | Output binary goes to project dir or `$GOBIN`, not `$TMPDIR`         |
| `cargo test`              | ✅ Works     | Rust builds in `target/`, not `$TMPDIR`                               |
| `npm test` / `vitest`     | ✅ Works     | JavaScript runs via interpreter, not compiled to temp                 |

**Fix:** The scratch dir is now **on by default** — cplt creates `~/Library/Caches/cplt/tmp/{session-id}/` with `rwx` permissions, redirects `TMPDIR`, `TMP`, `TEMP`, and `GOTMPDIR` there, and cleans up on exit. Stale directories older than 24 hours are garbage-collected on startup.

If you're still seeing this error, check that you haven't set `scratch_dir = false` in your config:

```bash
cplt config explain sandbox.scratch_dir
```

### Localhost blocking

Localhost outbound is blocked by default, which prevents sandboxed processes from connecting to local services:

| Operation                      | Impact            | Why                                                  |
| ------------------------------ | ----------------- | ---------------------------------------------------- |
| `npm install` (registry)       | ✅ Works           | Uses HTTPS to `registry.npmjs.org:443`               |
| `gradle build` (Maven Central) | ✅ Works           | Uses HTTPS to `repo1.maven.org:443`                  |
| Local PostgreSQL (`:5432`)     | ❌ Blocked         | Use `--allow-localhost 5432`                         |
| Local Redis (`:6379`)          | ❌ Blocked         | Use `--allow-localhost 6379`                         |
| Local Kafka (`:9092`)          | ❌ Blocked         | Use `--allow-localhost 9092`                         |
| MCP servers                    | ❌ Blocked         | Use `--allow-localhost 3000`                         |
| Local API/dev server           | ❌ Blocked         | Use `--allow-localhost 8080`                         |
| Spring Boot (`:8080`)          | ❌ Blocked         | Use `--allow-localhost 8080`                         |
| Next.js/Turbopack build        | ❌ Workers blocked | Use `--allow-localhost-any` (random ephemeral ports) |

**Fix:** Use `--allow-localhost <PORT>` for specific services, or `--allow-localhost-any` for build tools that use random ports (Next.js, Vite, esbuild).

### Docker and Testcontainers

Docker is **intentionally blocked** — `~/.docker` is denied and the Docker socket is not accessible. This is by design: Docker gives near-root access to the host system, which defeats the purpose of sandboxing.

- Docker commands, `docker compose`, and Testcontainers will fail
- Local databases via Docker Compose need `--allow-localhost <PORT>` for the exposed port (the database container runs outside the sandbox)
- Consider running database/Kafka containers before starting cplt, then use `--allow-localhost` for the ports

### SSH agent blocking

SSH agent access is blocked (unix socket denied), which means:

- `git clone` over SSH will fail — use HTTPS clones instead
- `ssh` commands spawned by the agent will fail
- `gh` CLI uses HTTPS by default and is unaffected

### macOS protected folders (Desktop, Documents)

macOS TCC (Transparency, Consent, and Control) protects certain folders at the kernel level. Without Full Disk Access, Copilot CLI cannot access `~/Desktop` or `~/Documents` **with or without cplt** — this is a macOS restriction, not a sandbox limitation. The cplt sandbox remains fully active regardless of FDA status.

| Path | Without FDA | With FDA | Notes |
| ---- | :---: | :---: | --- |
| `~/Desktop` | ❌ | ✅ | TCC-protected |
| `~/Documents` | ❌ | ✅ | TCC-protected |
| `~/Downloads` | ✅ | ✅ | Less restrictive TCC policy |
| Dragged screenshots | ❌ | ✅ | `TemporaryItems/NSIRD_*` are per-process isolated |

**Fix: Grant Full Disk Access to your terminal** (recommended):

1. Open **System Settings → Privacy & Security → Full Disk Access**
2. Enable your terminal app (Terminal.app, iTerm2, Ghostty, etc.)
3. **Restart the terminal** — TCC grants only take effect for new processes

This lifts TCC restrictions for all child processes while the cplt sandbox continues to enforce its own deny-by-default rules (write protection, network filtering, dotfile access, etc.).

**Alternatives** (if you prefer not to grant FDA):

1. **Copy files into your project**:
   ```bash
   cp ~/Desktop/screenshot.png .
   ```

2. **Use a non-protected folder** for screenshots:
   ```bash
   defaults write com.apple.screencapture location ~/Screenshots
   mkdir -p ~/Screenshots
   ```
   Then add to config:
   ```toml
   [sandbox]
   allow_read = ["~/Screenshots"]
   ```

### Git restrictions

Certain git operations are blocked to prevent persistence attacks that survive the sandbox session:

| Operation                          | Impact      | Why                                                               |
| ---------------------------------- | ----------- | ----------------------------------------------------------------- |
| `git add/commit/status/diff/log`   | ✅ Works     | Local operations, no writes to protected paths                    |
| `git checkout/merge/rebase/branch` | ✅ Works     | Branch operations work normally                                   |
| `git fetch/pull/push` (HTTPS)      | ✅ Works     | Port 443 allowed, `gh auth token` provides credentials            |
| `git fetch/pull/push` (SSH)        | ❌ Blocked   | SSH agent socket denied — use HTTPS                               |
| `git config` (local)               | ❌ Blocked   | `.git/config` is write-protected (prevents `url.*.insteadOf` hijacking) |
| `git config --global`              | ❌ Blocked   | `~/.gitconfig` is read-only                                      |
| `git remote set-url`               | ❌ Blocked   | Writes to `.git/config`                                           |
| `git submodule add`                | ❌ Blocked   | `.gitmodules` is write-protected (supply chain vector)            |
| Creating git hooks                 | ❌ Blocked   | `.git/hooks/` is write-protected (hooks run unsandboxed)          |
| Signed commits/tags                | ❌ Disabled  | `commit.gpgsign` and `tag.gpgsign` overridden to `false` via env; use `--allow-gpg-signing` to enable |

**Global git hooks**: If `core.hooksPath` is set in `~/.gitconfig`, cplt auto-detects the hooks directory and allows reading it so git operations succeed. Write access is explicitly denied to prevent persistence attacks. The hooks path must be under `$HOME` with at least 3 path components (e.g. `~/.config/git/hooks`) to prevent overly broad read access.

**Commit signing**: `~/.ssh` and `~/.gnupg` are blocked, so GPG/SSH signing would fail. Instead of opening private key directories, cplt injects `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_N`/`GIT_CONFIG_VALUE_N` env vars to disable `commit.gpgsign` and `tag.gpgsign` inside the sandbox. Commits made by Copilot are unsigned — this is expected since users typically re-sign on merge/squash. Use `--allow-gpg-signing` to override this (see [GPG signing](#gpg-commit-signing)).

### GPG commit signing

GPG commit/tag signing is **disabled by default** because `~/.gnupg` is blocked. Copilot commits are unsigned — you re-sign on merge/squash.

If you want Copilot commits to be signed (e.g. branch protection requires signatures), use `--allow-gpg-signing`:

```bash
cplt --allow-gpg-signing -- -p "commit your changes"
```

Or set it permanently in config:

```toml
[sandbox]
allow_gpg_signing = true
```

**Setup checklist:**

Before using this flag, verify GPG signing works outside the sandbox:

```bash
# 1. Check your signing key is configured
git config --get user.signingkey          # should show your key ID

# 2. Check gpg-agent is running
gpg-connect-agent 'GETINFO version' /bye  # should print version + OK

# 3. Cache your passphrase (so signing doesn't hang)
echo "test" | gpg --clearsign > /dev/null  # triggers passphrase prompt

# 4. Verify git signing works
git commit --allow-empty -S -m "test signed commit"
git log --show-signature -1               # should show "Good signature"
git reset HEAD~1                          # undo the test commit
```

If all of that works, `cplt --allow-gpg-signing` will work too. The `gpg-agent` runs **outside** the sandbox, so pinentry prompts appear normally — the sandbox only needs to reach the agent socket.

> **Note:** Signature *verification* (`git log --show-signature`) won't work inside the sandbox because GPG opens `trustdb.gpg` for writing during verification. This is harmless — signing works correctly, and signatures can be verified outside the sandbox or in CI.

**Troubleshooting:**

| Symptom | Cause | Fix |
|---|---|---|
| `error: gpg failed to sign the data` | Agent not running or passphrase not cached | Run `gpg-connect-agent 'GETINFO version' /bye` and `echo test \| gpg --clearsign` outside cplt |
| `signing failed: No secret key` | Wrong `user.signingkey` in git config | Run `gpg --list-secret-keys` and set `git config --global user.signingkey <KEY_ID>` |
| `signing failed: Operation not permitted` | Flag not set, or `--deny-path` overriding | Check `cplt --doctor` output for GPG signing status |
| Commits unsigned despite flag | `gpg.format=ssh` in git config | This flag is GPG-only; SSH signing is not supported |
| `GNUPGHOME` set to non-default path | SBPL rules only cover `~/.gnupg` | Unset `GNUPGHOME` or symlink to `~/.gnupg` |
| `git log --show-signature` shows `Fatal: can't open trustdb.gpg` | GPG opens `trustdb.gpg` for writing during *verification*, which the sandbox denies | This is expected — **signing works**, only verification is affected. Verify signatures outside the sandbox or in CI |

**What this does:**

| Resource | Access | Why |
|---|---|---|
| `~/.gnupg/pubring.kbx`, `pubring.gpg` | Read-only | Public key lookup |
| `~/.gnupg/trustdb.gpg` | Read-only | Trust validation |
| `~/.gnupg/gpg.conf`, `common.conf` | Read-only | GPG config |
| `~/.gnupg/S.gpg-agent` | Read + socket connect | IPC to agent daemon |
| `~/.gnupg/S.keyboxd` | Read + socket connect | IPC to keyboxd (GnuPG 2.4+ public key daemon) |
| `~/.gnupg/private-keys-v1.d/` | **DENIED** | Private keys stay locked |
| `~/.gnupg/secring.gpg` | **DENIED** | Legacy private keyring stays locked |
| `~/.gnupg/*` (writes) | **DENIED** | No modifications |

**Security notes:**

- **Private keys are NOT exposed.** GPG agent holds keys in memory — the Assuan IPC protocol has no command to export private key material. The `private-keys-v1.d/` directory remains denied even with this flag.
- **Risk: signature impersonation and decryption.** A compromised process with agent socket access can request signatures on arbitrary data (adding a "Verified" badge) and, if an encryption subkey exists, decrypt arbitrary ciphertext. This is the same level of impersonation Copilot already has for unsigned commits — signing just adds the badge.
- **GPG-only.** This flag does not enable SSH signing (`gpg.format=ssh`). SSH keys and `SSH_AUTH_SOCK` remain blocked.
- **`--deny-path` wins.** If you specify `--deny-path ~/.gnupg` alongside `--allow-gpg-signing`, the deny takes precedence — all GPG allows are suppressed.
- **`GNUPGHOME`** is not supported yet — only the default `~/.gnupg` location is allowed.

### Port restriction

Only port 443 is allowed by default. Services on other ports need `--allow-port`:

- `npm install` from private registries on non-standard ports
- API calls to services not on 443
- FTP, SMTP, or other protocol connections

## Limitations

### macOS

- **`sandbox-exec` is deprecated** — Apple has not removed it but may in future macOS versions
- **SBPL has no domain-based filtering** — the optional CONNECT proxy provides domain blocking
- **Keychain access required** — Copilot stores auth tokens in macOS Keychain

### Linux

- **Kernel 5.13+ required** — Landlock LSM must be enabled (`cat /sys/kernel/security/lsm`)
- **TCP port filtering requires kernel 6.7+** — older kernels get filesystem-only enforcement; network security via proxy only
- **Landlock cannot deny subpaths within allowed paths** — different granularity than Seatbelt
- **No audit logs** — `--show-denials` is macOS-only; use `strace -f -e trace=file,network` for debugging
- **Auth scoped to env + gh CLI** — no D-Bus/Secret Service integration for v1

### Both platforms

- **No TLS inspection** — the proxy sees domain names (via CONNECT) but not request bodies

For known attack vectors, out-of-scope threats, and prior art, see [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome! To get started:

```bash
git clone https://github.com/navikt/cplt.git && cd cplt
git config core.hooksPath hack    # enables pre-commit fmt + clippy checks
mise run check                    # runs fmt, clippy, and tests
```

Please open an issue before starting large changes. All PRs must pass CI (fmt, clippy, tests).

## References

- [SECURITY.md](SECURITY.md) — Full security model, threat analysis, test strategy, and prior art
- [Apple sandbox-exec(1)](https://keith.github.io/xcode-man-pages/sandbox-exec.1.html)
- [Chromium Seatbelt V2 Design](https://chromium.googlesource.com/chromium/src/sandbox/+show/refs/heads/main/mac/seatbelt_sandbox_design.md)
- [Landlock LSM documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [seccomp-BPF documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [michaelneale/agent-seatbelt-sandbox](https://github.com/michaelneale/agent-seatbelt-sandbox)

## License

[MIT](LICENSE)
