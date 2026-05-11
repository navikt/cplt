# cplt

[![CI](https://github.com/navikt/cplt/actions/workflows/ci.yaml/badge.svg)](https://github.com/navikt/cplt/actions/workflows/ci.yaml)
[![Release](https://github.com/navikt/cplt/actions/workflows/release.yaml/badge.svg)](https://github.com/navikt/cplt/actions/workflows/release.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![macOS](https://img.shields.io/badge/platform-macOS-lightgrey)
![Linux](https://img.shields.io/badge/platform-Linux-lightgrey)

Sandbox wrapper for AI coding agents. Runs GitHub Copilot CLI, OpenCode, Google Gemini CLI, Pi, or a plain shell inside a kernel-level sandbox so the agent can work on your project but cannot access your secrets.

- **macOS**: Apple Seatbelt/SBPL via `sandbox-exec`
- **Linux**: Landlock LSM + seccomp-BPF (kernel 5.13+; full network filtering on 6.7+)

![cplt banner](./assets/cplt.png)

## Table of contents

- [Quick start](#quick-start)
- [Install](#install)
- [What it does](#what-it-does)
- [Usage](#usage)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Security](#security)
- [Contributing](#contributing)
- [References](#references)

**Detailed docs:**
[Configuration](docs/configuration.md) · [Proxy & domain filtering](docs/proxy.md) · [Known impacts](docs/known-impacts.md) · [Security details](docs/security.md)

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

# Or run OpenCode in sandbox (with Copilot subscription — no API key needed)
cplt --agent opencode

# Or with a third-party provider
cplt --agent opencode --pass-env ANTHROPIC_API_KEY

# Or just a sandboxed shell (no AI agent, same security restrictions)
cplt --agent shell
```

**Primary control: filesystem isolation.** The sandbox blocks access to credentials and secrets at the kernel level. All restrictions apply to the agent and every process it spawns.

| Resource                                                                         | Status                                   | Notes                                                                                   |
| -------------------------------------------------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------- |
| Read/write project directory                                                     | ✅ Allowed                                |                                                                                         |
| Read `.env*`, `.pem`, `.key` in project                                          | 🔒 Kernel-blocked                         | Prevents secret exfiltration; `--allow-env-files` to override                           |
| Write `.git/hooks`, `.git/config`, `.gitmodules`                                 | 🔒 Kernel-blocked                         | Prevents persistence via git hooks, hooksPath redirect, submodule hijacking             |
| Execute from `/tmp`, `/var/folders`                                              | 🔒 Kernel-blocked                         | Prevents write-then-exec; scratch dir redirects TMPDIR to safe location (on by default) |
| Execute from `~/Library/Caches`                                                  | 🔒 Kernel-blocked by default              | Prevents binary-drop staging; Copilot native modules exempted via carve-out; `--allow-cache-exec <SUBDIR>` to add targeted exemptions (e.g. `ms-playwright`) |
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
| Developer tools (`~/.cargo`, `~/.mise`, `~/.gradle`, `~/.m2`, `~/.sdkman`, `~/.jenv`, `~/.pyenv`, `~/.konan`, etc.) | ✅ Allowed (read+write for caches)        | Only dirs that exist on disk; tightened at runtime via `--doctor`                       |
| Registry credential files (`~/.m2/settings.xml`, `~/.gradle/gradle.properties`, `~/.cargo/credentials`) | 🔒 Kernel-blocked (macOS)                 | Override with `--allow-read`; see [Private registries](docs/known-impacts.md#private-registries) |
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

### curl | bash

```bash
curl -fsSL https://raw.githubusercontent.com/navikt/cplt/main/install.sh | bash
```

Options:

```bash
# Install a specific version
curl -fsSL ... | bash -s -- --version 2026.05.05-174753-75bae5b

# Install to a custom directory
curl -fsSL ... | bash -s -- --dir ~/.local/bin

# Skip Homebrew (force direct download)
curl -fsSL ... | bash -s -- --no-brew
```

### Download from releases

Download the latest release for your platform from [GitHub Releases](https://github.com/navikt/cplt/releases/latest):

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
cplt [OPTIONS] [-- <AGENT_ARGS>...]
```

Everything after `--` is passed directly to the agent process (copilot, opencode, or shell).

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
| `--allow-localhost-any`    | Allow outbound to `localhost` on **all** ports. Needed for build tools like Turbopack (Next.js) and Vite that use random ephemeral ports for IPC. When combined with `--allow-jvm-attach`, also covers Java's IPv4-mapped addresses (see [SECURITY.md](SECURITY.md)). |

### Environment variables

By default, `cplt` sanitizes the child environment — only safe variables pass through. Cloud credentials, database URLs, and package tokens are stripped. Additionally, security hardening variables are injected to block npm/yarn/pnpm lifecycle scripts (postinstall hooks) — the #1 supply chain attack vector — and disable git commit/tag signing (since `~/.ssh` and `~/.gnupg` are inaccessible inside the sandbox).

**What passes through:**

| Category          | Examples                                                                   | How                                     |
|-------------------|----------------------------------------------------------------------------|-----------------------------------------|
| Core system       | `HOME`, `USER`, `PATH`, `SHELL`, `TMPDIR`, `LANG`                          | Explicit allowlist                      |
| Terminal          | `TERM`, `COLORTERM`, `TERM_PROGRAM`                                        | Explicit allowlist                      |
| Editor            | `EDITOR`, `VISUAL`, `PAGER`                                                | Explicit allowlist                      |
| Auth tokens       | `GH_TOKEN`, `GITHUB_TOKEN`, `COPILOT_GITHUB_TOKEN`                         | Explicit allowlist (needed for Copilot) |
| Copilot config    | `COPILOT_DEBUG`, `COPILOT_*`                                               | Prefix allowlist                        |
| Language runtimes | `NODE_*`, `GOPATH`, `CARGO_HOME`, `JAVA_HOME`, `VIRTUAL_ENV`, `PYTHONPATH` | Explicit allowlist                      |
| Tool managers     | `NVM_*`, `PYENV_*`, `MISE_*`, `SDKMAN_*`, `COREPACK_*`, `YARN_*`           | Prefix allowlist                        |
| XDG dirs          | `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME`     | Explicit allowlist                      |

**Prefix allowlist with secret-suffix protection:** Variables matching allowed prefixes (e.g. `COPILOT_*`, `YARN_*`) are passed through *unless* they end with a secret-bearing suffix: `_TOKEN`, `_AUTH`, `_SECRET`, `_SECRET_KEY`, `_KEY`, `_PASSWORD`, or `_CREDENTIALS`. For example, `COPILOT_DEBUG` passes through but `COPILOT_API_KEY` is blocked.

**Always blocked:** `AWS_*`, `AZURE_*`, `NPM_TOKEN`, `DATABASE_URL`, `VAULT_TOKEN`, `SSH_AUTH_SOCK`, Docker vars, CI tokens, and anything not in the allowlist.

| Flag               | What it does                                                                                                                                            |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--pass-env <VAR>` | Explicitly pass an environment variable through to Copilot. Can be repeated.                                                                            |
| `--inherit-env`    | ⚠️ **Dangerous.** Inherit the full parent environment (only strips `NO_COLOR`, `FORCE_COLOR`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`). Use only for debugging. |
| `--allow-lifecycle-scripts` | Allow npm/yarn/pnpm lifecycle scripts (postinstall hooks) to run. Blocked by default. Use when `npm install` needs postinstall hooks.         |
| `--allow-gpg-signing`       | Allow GPG commit/tag signing inside the sandbox. Grants read-only access to public keyring and GPG agent socket (private keys stay denied). See [GPG signing](docs/known-impacts.md#gpg-commit-signing). |
| `--allow-jvm-attach`        | Allow JVM Attach API unix sockets in `/tmp`. Needed for MockK inline mocking, Mockito inline agents, ByteBuddy. See [JVM Attach API](docs/known-impacts.md#jvm-attach-api). |
| `--no-scratch-dir`          | Disable the per-session scratch directory (on by default). TMPDIR will not be redirected.                                                    |
| `--scratch-dir`             | Explicitly enable per-session scratch directory (already the default). Useful to override `scratch_dir = false` in config.                   |
| `--allow-tmp-exec`          | ⚠️ **Dangerous.** Allow exec from system temp dirs (`/private/tmp`, `/private/var/folders`). Prefer scratch dir.                             |
| `--allow-cache-exec <SUBDIR>` | Allow exec from a specific `~/Library/Caches/<SUBDIR>`. Can be repeated. Use for tools that cache compiled binaries there (e.g. Playwright, pnpm dlx). |
| `--allow-cache-exec-any`    | ⚠️ **Dangerous.** Allow exec from all of `~/Library/Caches`. Prefer `--allow-cache-exec <SUBDIR>` for targeted exemptions. |
| `--allow-browser`           | Allow the agent to open URLs in your default browser. Needed for OAuth code flows (MCP servers, Gemini CLI). Disabled by default. |

### Supported runtimes

cplt auto-discovers installed tools and configures sandbox rules accordingly. Only directories that exist on disk get rules (no phantom paths).

| Runtime | Home dirs | Env vars / prefixes | Discovery |
|---|---|---|---|
| **Node.js** | `.nvm`, `.local` | `NODE_*`, `NPM_*`, `NVM_*` | `node` |
| **Rust** | `.cargo`, `.rustup` | `CARGO_HOME`, `RUSTUP_HOME` | `cargo` |
| **Go** | `go/bin`, `go/pkg` | `GOPATH`, `GOROOT`, `GOCACHE`, etc. | `go` |
| **Java/Kotlin (JVM)** | `.sdkman`, `.jenv`, `.gradle`, `.m2` | `JAVA_HOME`, `JAVA_TOOL_OPTIONS`, `GRADLE_*`, `MAVEN_*`, `SDKMAN_*`, `JENV_*` | `java`, `gradle` |
| **Kotlin Native** | `.konan` | — | — |
| **Python** | `.pyenv` | `VIRTUAL_ENV`, `PYTHONPATH`, `PYENV_ROOT`, `PYENV_*` | `python3` |
| **Yarn Berry** | `.yarn` | `YARN_*` (hardening overrides `YARN_ENABLE_SCRIPTS`) | `yarn` |
| **pnpm** | `Library/pnpm` | `PNPM_HOME` | `pnpm` |
| **Corepack** | — | `COREPACK_*` | — |
| **mise** | `.mise` | `MISE_*` | `mise` |

To see which tools cplt detected, run `cplt --doctor`.

### Proxy

The proxy is **enabled by default** — all outbound traffic (Copilot CLI, `gh`, `curl`) is routed through a localhost CONNECT proxy via `HTTP_PROXY`/`HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1`. The proxy listens on an OS-assigned ephemeral port, so there are no port conflicts.

**What the proxy gives you:**

- **Connection logging** — see every domain Copilot connects to in real time
- **Domain blocking** — block known exfiltration infrastructure (paste sites, webhook services, etc.)
- **Domain allowlisting** — restrict connections to only known-safe domains
- **Audit log** — persistent file log of all connections for post-session review
- **Port enforcement** — the proxy enforces the same port restrictions as the sandbox (443 + `--allow-port`)

**Disable for a single run:**

```bash
cplt --no-proxy -- -p "fix the tests"
```

**Disable permanently** (in `~/.config/cplt/config.toml`):

```toml
[proxy]
enabled = false
```

**Add connection filtering** (recommended):

```bash
cplt --init-config
```

Then edit `~/.config/cplt/config.toml`:

```toml
[proxy]
# blocked_domains = "~/.config/cplt/blocked-domains.txt"  # block known-bad domains
# allowed_domains = "~/.config/cplt/allowed-domains.txt"  # restrict to known-safe domains
# log_file = "~/.config/cplt/proxy.log"                   # persistent audit log
# log_level = "none"                                      # stderr: none|error|blocked|all
```

| Flag                        | What it does                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------ |
| `--with-proxy`              | Explicitly enable the proxy (no-op when proxy is already on by default).                         |
| `--no-proxy`                | Disable the proxy for this run.                                                                  |
| `--proxy-port <PORT>`       | Which port the proxy listens on (default: 0, OS-assigned ephemeral).                             |
| `--blocked-domains <FILE>`  | Domains to block, one per line. Re-read every ~5s (edit live, changes take effect within seconds). |
| `--allowed-domains <FILE>`  | Domains to allow — only listed domains can connect. Validated at startup (fail-closed); re-read every 5s.  |
| `--proxy-log <FILE>`        | Append a line per connection to this file for post-session audit.                                |
| `--proxy-log-level <LEVEL>` | Stderr verbosity: `none` (default/silent), `error`, `blocked`, or `all`. The audit log file always records everything. |
| `--allow-private-domain <DOMAIN>` | Allow connections to this domain even if it resolves to a private/internal IP. Use for corporate intranet services (e.g. internal MCP servers). Suffix matching: `intern.nav.no` covers all subdomains. Can be repeated. |

> **Domain matching:** both blocklist and allowlist use the same rules — `example.com` matches the exact domain and all subdomains (`sub.example.com`, `deep.sub.example.com`). Matching is case-insensitive. Trailing dots are stripped.
>
> **Localhost traffic** (MCP servers, dev servers) bypasses the proxy via `NO_PROXY` and will not appear in the audit log.
>
> **Quiet mode** (`-q` / `sandbox.quiet = true`) suppresses the startup banner. Proxy stderr output is controlled separately by `--proxy-log-level` (default: `none` — silent). Use `--proxy-log` to capture all connections to a file.

### Debugging

| Flag              | What it does                                                                                                                                           |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--doctor`        | Run environment diagnostics: checks auth, Copilot install, tools, and sandbox paths. Exits 0 if all critical checks pass.                              |
| `--print-profile` | Print the generated sandbox profile (SBPL) and exit.                                                                                                   |
| `--show-denials`  | Stream macOS sandbox denial logs in real time.                                                                                                         |
| `--no-validate`   | Skip the startup check that verifies sandbox restrictions are active.                                                                                  |
| `-y, --yes`       | Skip the interactive confirmation prompt. The configuration summary is still printed for auditability. Required when stdin is not a TTY (CI, scripts). |
| `-q, --quiet`     | Suppress the startup banner and non-essential messages. Errors/warnings still print. Also: `sandbox.quiet = true` in config.                           |
| `--no-quiet`      | Override `sandbox.quiet = true` — show the startup summary even when quiet is configured.                                                              |
| `--init-config`   | Create a starter config file at `~/.config/cplt/config.toml` and exit.                                                                                 |

### Copilot session flags

These flags are forwarded directly to the copilot process for convenience — no `--` separator needed.

| Flag                 | What it does                                                                                      |
| -------------------- | ------------------------------------------------------------------------------------------------- |
| `--resume[=SESSION]` | Resume a previous session. Use `--resume` to pick interactively, or `--resume=NAME` by name/ID.  |
| `--continue`         | Resume the most recent session in the current directory.                                          |
| `--remote`           | Enable remote control — monitor and steer the session from GitHub.com or mobile.                  |
| `--name SESSION`     | Name the session for later resumption with `--resume=NAME`.                                       |

You can combine these with cplt sandbox flags and `--` pass-through args:

```bash
cplt --resume=my-task                          # resume by name
cplt --remote --name my-task -- -p "fix tests" # remote + named + prompt
```

### OpenCode support

cplt can sandbox [OpenCode](https://opencode.ai/) in addition to GitHub Copilot CLI. OpenCode is [officially supported](https://github.blog/changelog/2026-01-16-github-copilot-now-supports-opencode/) as a GitHub Copilot client — use your existing Copilot subscription with `/connect` inside OpenCode.

```bash
# Run OpenCode with Copilot subscription (no API key needed)
cplt --agent opencode

# Auto-detect: if only opencode is in PATH, cplt uses it automatically
cplt

# Or use a third-party provider
cplt --agent opencode --pass-env ANTHROPIC_API_KEY
```

**Security notes for OpenCode:**
- **Copilot provider**: auth is handled via `/connect` device flow, stored in `~/.local/share/opencode/auth.json` — no env vars needed
- **Third-party providers**: API keys (ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.) are **not** passed through by default — use `--pass-env`:

```bash
cplt --agent opencode --pass-env ANTHROPIC_API_KEY
cplt --agent opencode --pass-env OPENAI_API_KEY --pass-env OPENAI_ORG_ID
```

- OpenCode config (`~/.config/opencode/`) is read-only in the sandbox
- OpenCode data (`~/.local/share/opencode/`) is writable but execution is denied (write+exec prevention)
- Keychain access is disabled (OpenCode uses its own auth file, not macOS Keychain)
- `--resume`, `--continue`, `--remote`, `--name` flags are Copilot-specific and ignored for OpenCode

### Gemini CLI support

cplt can sandbox [Google Gemini CLI](https://github.com/google-gemini/gemini-cli). Gemini uses Google OAuth (browser flow) by default, or an API key.

```bash
# Run Gemini CLI
cplt --agent gemini

# With API key instead of OAuth
cplt --agent gemini --pass-env GEMINI_API_KEY
```

**Security notes for Gemini:**
- Gemini config/auth (`~/.gemini/`) is writable in the sandbox
- Keychain access is enabled (used for extension integrity verification)
- OAuth browser flow requires `--allow-browser` for first-time login
- `--resume`, `--continue`, `--remote`, `--name` flags are Copilot-specific and ignored for Gemini

### Pi agent support

cplt can sandbox [Pi](https://github.com/earendil-works/pi) (`@earendil-works/pi-coding-agent`). Pi supports multiple LLM providers via API keys.

```bash
# Run Pi (must be explicit — not auto-detected due to binary name collision risk)
cplt --agent pi

# Pass your provider API key
cplt --agent pi --pass-env ANTHROPIC_API_KEY

# Set Pi as your default agent
cplt config set sandbox.agent pi
```

**Security notes for Pi:**
- **Not auto-detected**: the `pi` binary name is too generic and may collide with other tools. Use `--agent pi` or set `sandbox.agent = "pi"` in config
- **API keys are opt-in**: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY` must be explicitly passed via `--pass-env`
- Pi config/auth (`~/.pi/`) is writable in the sandbox
- Pi managed binaries (`~/.pi/agent/bin/`) have process-exec permission (for bundled `fd`, `rg`)
- Keychain access is disabled

### Shell mode

Run a plain sandboxed shell — no AI agent, same security restrictions. Useful for testing build tools, debugging sandbox issues, or working in a secure environment manually.

```bash
# Interactive sandboxed shell (uses $SHELL — fish, zsh, bash)
cplt --agent shell

# Run a single command inside the sandbox
cplt --agent shell -- -c 'go test ./...'

# Inspect what's allowed without entering the shell
cplt --agent shell --print-profile
```

The sandbox applies the same deny-by-default rules — filesystem isolation, network restrictions, env sanitization. Shell config directories (fish variables/history, zsh history) are writable.

### Examples

```bash
# Most common: run Copilot in sandbox
cplt -- -p "fix the tests"

# Resume a previous session
cplt --resume

# Resume a named session
cplt --resume=my-refactor

# Resume the most recent session in this directory
cplt --continue

# Start a named remote session
cplt --remote --name my-task -- -p "fix the tests"

# Check environment before first run
cplt --doctor

# Disable proxy for a single run (proxy is on by default)
cplt --no-proxy -- -p "fix the tests"

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

# Block paste sites
cplt --blocked-domains ./blocked-domains.txt -- -p "refactor"

# Use an internal MCP server on the corporate network
cplt --allow-private-domain intern.nav.no -- -p "use mcp-onboarding"

# Inspect the generated sandbox profile
cplt --print-profile

# Debug: see what the sandbox blocks in real time
cplt --show-denials -- -p "fix the tests"

# Run OpenCode with Copilot subscription (no API key needed)
cplt --agent opencode

# Run OpenCode with a third-party provider
cplt --agent opencode --pass-env ANTHROPIC_API_KEY

# Run OpenCode with auto-detection (if copilot not in PATH)
cplt --pass-env ANTHROPIC_API_KEY

# Run a sandboxed shell (no AI agent)
cplt --agent shell

# Run a one-off command in the sandbox
cplt --agent shell -- -c 'npm test'
```

## Configuration

Save your preferred defaults to `~/.config/cplt/config.toml` so you don't need to pass flags every time.

```bash
cplt --init-config    # create a starter config file
cplt config show      # show effective config (file + defaults)
cplt config explain   # list all keys with descriptions
```

**Precedence** (highest to lowest):

1. CLI flags
2. Config file (`~/.config/cplt/config.toml`)
3. Built-in defaults

Per-repo config (`.cplt.toml`) operates as a separate layer: `[deny]` tightens unconditionally, and approved permissions are **additive only** — they can enable features but cannot disable anything set by CLI or global config.

### Per-repo configuration (`.cplt.toml`)

Commit a `.cplt.toml` to your repository for project-specific settings:

```toml
[deny]
paths = ["~/secrets"]
env = ["VAULT_TOKEN"]

[propose]
allow_jvm_attach = true
allow_docker = true

[propose.allow]
read = ["~/.gradle/gradle.properties"]
```

- **`[deny]`** — applied automatically (can only tighten)
- **`[propose]`** — requested permissions, requires approval: `cplt trust accept --all`
- Read from `git HEAD` — tamper-proof; content-pinned approvals

Use `cplt config set --repo` to manage without editing TOML by hand:

```bash
cplt config set --repo sandbox.allow_jvm_attach true
cplt config set --repo deny.paths "~/secrets"
```

📖 **Full details:** [docs/configuration.md](docs/configuration.md)

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

**Security model**: deny-by-default filesystem with kernel enforcement. On macOS and Linux with kernel 6.7+ (Landlock ABI v4), network is restricted to port 443 (HTTPS) by default (use `--allow-port` for extras). On older Linux kernels, network restriction is provided by the CONNECT proxy (enabled by default). SSH agent access and localhost outbound are blocked at the kernel level (macOS) or via the proxy (Linux). The profile generator auto-discovers your environment (`--doctor`) and only includes tool directories that actually exist on disk — fewer rules means a tighter sandbox.

Platform-specific details:
- **macOS**: Seatbelt/SBPL profile generated and passed to `sandbox-exec`
- **Linux**: Landlock LSM rules + seccomp-BPF filter applied via `pre_exec` (kernel 5.13+, TCP port filtering on 6.7+)

See [SECURITY.md](SECURITY.md) for the full threat model, defense layers, and honest gaps.

## Security

~2500 lines of Rust. Four dependencies (clap, libc, serde, toml). No runtime services, no telemetry. Every security boundary is kernel-enforced and tested.

**Our priorities, in order:**

1. **Correct** — every claim is tested, every edge case has a CVE or research reference
2. **Transparent** — read [SECURITY.md](SECURITY.md), it hides nothing
3. **Simple** — single static binary, zero config required, sane defaults
4. **Useful** — get out of the way and let Copilot do its job, safely

📖 **Full details:** [docs/security.md](docs/security.md) · [SECURITY.md](SECURITY.md)

## Known impacts

The sandbox blocks some workflows by design. Common issues and fixes:

| Impact | Fix |
|---|---|
| `.env` files blocked | `--allow-env-files` |
| npm postinstall hooks blocked | `--allow-lifecycle-scripts` |
| `go test` / `mise run` blocked (temp exec) | Scratch dir is on by default; use `--allow-tmp-exec` if needed |
| Localhost connections blocked | `--allow-localhost <PORT>` or `--allow-localhost-any` |
| Docker blocked | `--allow-docker` ⚠️ |
| SSH blocked | Use HTTPS remotes instead |
| GPG signing disabled | `--allow-gpg-signing` |
| JVM MockK/Mockito fails | `--allow-jvm-attach` |
| Private registry creds blocked | `--allow-read ~/.m2/settings.xml` |

📖 **Full details with tables and troubleshooting:** [docs/known-impacts.md](docs/known-impacts.md)

## Proxy

The proxy is **on by default** — logs and filters all outbound connections. Features:

- **Connection logging** — see every domain the agent connects to
- **Domain blocking** — block exfiltration infrastructure (paste sites, webhooks)
- **Domain allowlisting** — restrict to known-safe domains only
- **Audit log** — persistent file log for post-session review

```bash
cplt --no-proxy -- -p "fix tests"                    # disable for one run
cplt --blocked-domains blocked-domains.txt -- -p "x"  # block known-bad domains
cplt --allowed-domains allowed-domains.txt -- -p "x"  # allowlist mode
```

📖 **Full details:** [docs/proxy.md](docs/proxy.md)

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

**JVM note:** On macOS, the JVM ignores `TMPDIR` — it reads `java.io.tmpdir` from `confstr(_CS_DARWIN_USER_TEMP_DIR)` which always returns `/var/folders/...`. cplt automatically injects `-Djava.io.tmpdir=<scratch> -Djansi.tmpdir=<scratch> -Djava.rmi.server.hostname=localhost` via `JAVA_TOOL_OPTIONS` so that Maven Surefire forks, the Kotlin compiler daemon, and Jansi native lib extraction all use the scratch dir. The RMI hostname flag ensures the Kotlin daemon's Java RMI communication stays on `localhost` (without it, `InetAddress.getLocalHost()` may resolve to a non-loopback IP via mDNS, which the sandbox blocks). Override with `--pass-env JAVA_TOOL_OPTIONS` if you need custom JVM flags. For inline mocking (MockK, Mockito, ByteBuddy), also add `--allow-jvm-attach` — see [JVM Attach API](#jvm-attach-api).

**Gradle 9+ nested sandbox:** Starting with Gradle 8.8, the Gradle daemon runs inside its own macOS sandbox via `sandbox-exec` (controlled by `GRADLE_MACOS_SANDBOX` env var, previously `org.gradle.daemon.sandbox` property). This conflicts with cplt's sandbox because **macOS does not support nested `sandbox-exec` calls** — the inner sandbox fails with "Operation not permitted" on socket operations. cplt automatically injects `GRADLE_MACOS_SANDBOX=off` to disable Gradle's redundant sandbox (cplt already provides kernel-level sandboxing). This is a [known upstream issue](https://github.com/gradle/gradle/issues/29476) affecting any tool that wraps Gradle in an outer sandbox. Override with `--pass-env GRADLE_MACOS_SANDBOX` if you need Gradle's own sandbox for some reason.

**Gradle/JVM still failing?** Some JVM native libraries (e.g. `libjli.dylib`, JNI libs) use `dlopen` from the system temp dir *before* `JAVA_TOOL_OPTIONS` takes effect. If you see "Operation not permitted" during JVM startup itself (not Gradle build), add `--allow-tmp-exec`:

```bash
# Recommended for Gradle projects (localhost + tmp exec + JVM attach):
cplt --allow-localhost-any --allow-tmp-exec --allow-jvm-attach -- -p "run tests"

# Or set permanently:
cplt config set sandbox.allow_localhost_any true
cplt config set sandbox.allow_tmp_exec true
cplt config set sandbox.allow_jvm_attach true
```

**Kotlin daemon on Linux:** The Kotlin compiler daemon writes marker files to `~/.local/share/kotlin/daemon/` and communicates via localhost. If you see `AccessDeniedException: .../kotlin-daemon-client-tsmarker*.tmp`, cplt grants write access to `~/.local/share/kotlin/` automatically. If the daemon still can't connect (falls back to non-daemon compilation with garbled Unicode paths), ensure `--allow-localhost-any` is set — the daemon uses ephemeral ports:

```bash
# Recommended for Kotlin/Gradle on Linux:
cplt config set sandbox.allow_localhost_any true
cplt config set sandbox.allow_jvm_attach true

# If you need additional write paths (e.g. custom Kotlin data dir):
cplt config set sandbox.allow_write '["~/.local/share/kotlin"]'
```

If you're still seeing this error, check that you haven't set `scratch_dir = false` in your config:

```bash
cplt config explain sandbox.scratch_dir
```

### Cache exec (Playwright, pnpm dlx, etc.)

Some tools unpack and execute binaries directly from `~/Library/Caches`, which is exec-blocked by default:

| Tool | Cache path | Fix |
|---|---|---|
| Playwright (browsers) | `~/Library/Caches/ms-playwright/` | `--allow-cache-exec ms-playwright` |
| pnpm dlx | `~/Library/Caches/pnpm/dlx/` | `--allow-cache-exec pnpm/dlx` |

```bash
# Allow Playwright browser binaries
cplt --allow-cache-exec ms-playwright -- -p "run the e2e tests"

# Allow pnpm dlx-cached binaries
cplt --allow-cache-exec pnpm/dlx -- -p "run the scripts"

# Both at once
cplt --allow-cache-exec ms-playwright --allow-cache-exec pnpm/dlx -- -p "run tests"
```

Or set permanently in config:

```toml
[sandbox]
allow_cache_exec = ["ms-playwright", "pnpm/dlx"]
```

`--allow-cache-exec-any` opens exec for all of `~/Library/Caches` — use only as a last resort.

### Localhost blocking

Localhost outbound is blocked by default, which prevents sandboxed processes from connecting to local services:

| Operation                      | Impact            | Why                                                  |
| ------------------------------ | ----------------- | ---------------------------------------------------- |
| `npm install` (registry)       | ✅ Works           | Uses HTTPS to `registry.npmjs.org:443`               |
| `gradle build` (Maven Central) | ✅ Works           | Uses HTTPS to `repo1.maven.org:443`                  |
| Gradle daemon (ephemeral port) | ❌ Blocked         | Use `--allow-localhost-any` (daemon uses random ports) |
| Gradle/JVM startup (native libs)| ❌ Blocked        | Use scratch dir (default) or `--allow-tmp-exec` — see [JVM note](#temp-dir-exec) |
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

**Opting in (⚠️ dangerous):** If you understand the risks (container mounts bypass the sandbox entirely), you can allow Docker access:

```bash
cplt config set sandbox.allow_docker true
# or per-session:
cplt --allow-docker
```

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

### Git workflow (commit & push)

Git commit and push **work out of the box** over HTTPS — no extra flags needed.

**Prerequisites:**

1. **Use HTTPS remotes** (not SSH). Check with `git remote -v`:
   ```bash
   # If you see git@github.com:org/repo.git, switch to HTTPS:
   git remote set-url origin https://github.com/org/repo.git
   ```
   Or rewrite globally for all repos (no remote changes needed):
   ```bash
   git config --global url."https://github.com/".insteadOf "git@github.com:"
   ```
   This makes git transparently use HTTPS even when remotes are configured as SSH. The rewrite is read from `~/.gitconfig` which is readable inside the sandbox.
2. **Authenticate with `gh`** — cplt allows the agent to read `gh auth token`:
   ```bash
   gh auth login   # one-time setup outside the sandbox
   ```
3. **Configure git credential helper** (if not already set by `gh auth setup-git`):
   ```bash
   gh auth setup-git   # sets credential.helper to use gh
   ```

That's it. The agent can now `git add`, `git commit`, `git push`, create branches, and fetch — all inside the sandbox.

**Optional: signed commits** — add `--allow-gpg-signing` (see [GPG signing](#gpg-commit-signing)).

> **Why is SSH blocked?** The SSH agent socket gives access to *all* loaded keys, which could authenticate to any host. HTTPS with `gh auth token` is scoped to GitHub only. See [SSH agent blocking](#ssh-agent-blocking).

> **Tip:** Protect your `main` branch with [branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-a-branch-protection-rule/about-branch-protection-rules) to prevent the agent from pushing directly to main or force-pushing. This is good practice regardless of cplt.

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

### JVM Attach API

JVM testing frameworks like **MockK** (inline mocking), **Mockito** (inline agents), and **ByteBuddy** use the JVM Attach API for runtime class instrumentation. This API creates a Unix domain socket at `/tmp/.java_pid<PID>` — which the sandbox blocks by default.

Enable it with `--allow-jvm-attach`:

```bash
cplt --allow-jvm-attach -- -p "run the tests"
```

Or permanently in config:

```bash
cplt config set sandbox.allow_jvm_attach true
```

**When to enable:**

- Kotlin/Java projects using **MockK** with `mockk()` or `mockkStatic()` inline mocking
- Projects using **Mockito** with `Mockito.mock()` on final classes (requires ByteBuddy agent)
- Any test suite that gets `"Could not self-attach to current VM using external process"` errors
- JMX monitoring tools that attach to running JVMs

**How it works:** The JVM creates a socket at `/tmp/.java_pid<PID>` (hardcoded path, not affected by `java.io.tmpdir`). A helper JVM process connects to this socket to load an instrumentation agent. The sandbox rule uses a regex pattern that only allows sockets matching `.java_pid<PID>` — all other Unix sockets in `/tmp` (including SSH agent, tmux, PostgreSQL) remain blocked.

**Security note:** This opens a narrow IPC channel for `.java_pid*`-named sockets only. SSH agent access (`SSH_AUTH_SOCK`) is NOT exposed — on macOS it lives at `/private/tmp/com.apple.launchd.*/Listeners` which does not match the pattern.

### Port restriction

Only port 443 is allowed by default. Services on other ports need `--allow-port`:

- `npm install` from private registries on non-standard ports
- API calls to services not on 443
- FTP, SMTP, or other protocol connections

### Private registries

Registry credential files are **blocked by default** because they typically contain passwords or tokens that a rogue agent could exfiltrate:

| File | Purpose |
|------|---------|
| `~/.npmrc` | npm registry auth (hard deny — not overridable) |
| `~/.m2/settings.xml` | Maven repository credentials |
| `~/.m2/settings-security.xml` | Maven master password |
| `~/.gradle/gradle.properties` | Gradle/Nexus/Artifactory credentials |
| `~/.cargo/credentials` | Cargo crate registry tokens |
| `~/.cargo/credentials.toml` | Cargo crate registry tokens (TOML format) |

For Maven, Gradle, and Cargo files, you can override this with `--allow-read`:

```bash
# Per session — Maven
cplt --allow-read ~/.m2/settings.xml -- -p "build with Maven"

# Per session — Gradle
cplt --allow-read ~/.gradle/gradle.properties -- -p "build with Gradle"

# Multiple files
cplt --allow-read ~/.m2/settings.xml --allow-read ~/.gradle/gradle.properties -- -p "build"
```

To allow permanently, add to `~/.config/cplt/config.toml`:

```toml
[allow]
read = ["~/.m2/settings.xml", "~/.gradle/gradle.properties"]
```

> **Note:** `.npmrc` cannot be overridden — it is in the hard-deny list alongside `.netrc` and `.pypirc`. If you need npm private registry access, consider using project-level `.npmrc` (which is readable as part of the project directory) with a token injected via environment variable.

> **Linux limitation:** These file-level denials are only enforced on macOS (via SBPL literal deny rules). On Linux, Landlock cannot deny individual files within an allowed directory — the parent dirs (`.m2`, `.gradle`, `.cargo`) remain fully readable for dependency resolution.
||||||| parent of 5cee74e (docs: split README into docs/ for maintainability)
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

**JVM note:** On macOS, the JVM ignores `TMPDIR` — it reads `java.io.tmpdir` from `confstr(_CS_DARWIN_USER_TEMP_DIR)` which always returns `/var/folders/...`. cplt automatically injects `-Djava.io.tmpdir=<scratch> -Djansi.tmpdir=<scratch> -Djava.rmi.server.hostname=localhost` via `JAVA_TOOL_OPTIONS` so that Maven Surefire forks, the Kotlin compiler daemon, and Jansi native lib extraction all use the scratch dir. The RMI hostname flag ensures the Kotlin daemon's Java RMI communication stays on `localhost` (without it, `InetAddress.getLocalHost()` may resolve to a non-loopback IP via mDNS, which the sandbox blocks). Override with `--pass-env JAVA_TOOL_OPTIONS` if you need custom JVM flags. For inline mocking (MockK, Mockito, ByteBuddy), also add `--allow-jvm-attach` — see [JVM Attach API](#jvm-attach-api).

**Gradle/JVM still failing?** Some JVM native libraries (e.g. `libjli.dylib`, JNI libs) use `dlopen` from the system temp dir *before* `JAVA_TOOL_OPTIONS` takes effect. If you see "Operation not permitted" during JVM startup itself (not Gradle build), add `--allow-tmp-exec`:

```bash
# Recommended for Gradle projects (localhost + tmp exec + JVM attach):
cplt --allow-localhost-any --allow-tmp-exec --allow-jvm-attach -- -p "run tests"

# Or set permanently:
cplt config set sandbox.allow_localhost_any true
cplt config set sandbox.allow_tmp_exec true
cplt config set sandbox.allow_jvm_attach true
```

**Kotlin daemon on Linux:** The Kotlin compiler daemon writes marker files to `~/.local/share/kotlin/daemon/` and communicates via localhost. If you see `AccessDeniedException: .../kotlin-daemon-client-tsmarker*.tmp`, cplt grants write access to `~/.local/share/kotlin/` automatically. If the daemon still can't connect (falls back to non-daemon compilation with garbled Unicode paths), ensure `--allow-localhost-any` is set — the daemon uses ephemeral ports:

```bash
# Recommended for Kotlin/Gradle on Linux:
cplt config set sandbox.allow_localhost_any true
cplt config set sandbox.allow_jvm_attach true

# If you need additional write paths (e.g. custom Kotlin data dir):
cplt config set sandbox.allow_write '["~/.local/share/kotlin"]'
```

If you're still seeing this error, check that you haven't set `scratch_dir = false` in your config:

```bash
cplt config explain sandbox.scratch_dir
```

### Cache exec (Playwright, pnpm dlx, etc.)

Some tools unpack and execute binaries directly from `~/Library/Caches`, which is exec-blocked by default:

| Tool | Cache path | Fix |
|---|---|---|
| Playwright (browsers) | `~/Library/Caches/ms-playwright/` | `--allow-cache-exec ms-playwright` |
| pnpm dlx | `~/Library/Caches/pnpm/dlx/` | `--allow-cache-exec pnpm/dlx` |

```bash
# Allow Playwright browser binaries
cplt --allow-cache-exec ms-playwright -- -p "run the e2e tests"

# Allow pnpm dlx-cached binaries
cplt --allow-cache-exec pnpm/dlx -- -p "run the scripts"

# Both at once
cplt --allow-cache-exec ms-playwright --allow-cache-exec pnpm/dlx -- -p "run tests"
```

Or set permanently in config:

```toml
[sandbox]
allow_cache_exec = ["ms-playwright", "pnpm/dlx"]
```

`--allow-cache-exec-any` opens exec for all of `~/Library/Caches` — use only as a last resort.

### Localhost blocking

Localhost outbound is blocked by default, which prevents sandboxed processes from connecting to local services:

| Operation                      | Impact            | Why                                                  |
| ------------------------------ | ----------------- | ---------------------------------------------------- |
| `npm install` (registry)       | ✅ Works           | Uses HTTPS to `registry.npmjs.org:443`               |
| `gradle build` (Maven Central) | ✅ Works           | Uses HTTPS to `repo1.maven.org:443`                  |
| Gradle daemon (ephemeral port) | ❌ Blocked         | Use `--allow-localhost-any` (daemon uses random ports) |
| Gradle/JVM startup (native libs)| ❌ Blocked        | Use scratch dir (default) or `--allow-tmp-exec` — see [JVM note](#temp-dir-exec) |
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

**Opting in (⚠️ dangerous):** If you understand the risks (container mounts bypass the sandbox entirely), you can allow Docker access:

```bash
cplt config set sandbox.allow_docker true
# or per-session:
cplt --allow-docker
```

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

### Git workflow (commit & push)

Git commit and push **work out of the box** over HTTPS — no extra flags needed.

**Prerequisites:**

1. **Use HTTPS remotes** (not SSH). Check with `git remote -v`:
   ```bash
   # If you see git@github.com:org/repo.git, switch to HTTPS:
   git remote set-url origin https://github.com/org/repo.git
   ```
   Or rewrite globally for all repos (no remote changes needed):
   ```bash
   git config --global url."https://github.com/".insteadOf "git@github.com:"
   ```
   This makes git transparently use HTTPS even when remotes are configured as SSH. The rewrite is read from `~/.gitconfig` which is readable inside the sandbox.
2. **Authenticate with `gh`** — cplt allows the agent to read `gh auth token`:
   ```bash
   gh auth login   # one-time setup outside the sandbox
   ```
3. **Configure git credential helper** (if not already set by `gh auth setup-git`):
   ```bash
   gh auth setup-git   # sets credential.helper to use gh
   ```

That's it. The agent can now `git add`, `git commit`, `git push`, create branches, and fetch — all inside the sandbox.

**Optional: signed commits** — add `--allow-gpg-signing` (see [GPG signing](#gpg-commit-signing)).

> **Why is SSH blocked?** The SSH agent socket gives access to *all* loaded keys, which could authenticate to any host. HTTPS with `gh auth token` is scoped to GitHub only. See [SSH agent blocking](#ssh-agent-blocking).

> **Tip:** Protect your `main` branch with [branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-a-branch-protection-rule/about-branch-protection-rules) to prevent the agent from pushing directly to main or force-pushing. This is good practice regardless of cplt.

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

### JVM Attach API

JVM testing frameworks like **MockK** (inline mocking), **Mockito** (inline agents), and **ByteBuddy** use the JVM Attach API for runtime class instrumentation. This API creates a Unix domain socket at `/tmp/.java_pid<PID>` — which the sandbox blocks by default.

Enable it with `--allow-jvm-attach`:

```bash
cplt --allow-jvm-attach -- -p "run the tests"
```

Or permanently in config:

```bash
cplt config set sandbox.allow_jvm_attach true
```

**When to enable:**

- Kotlin/Java projects using **MockK** with `mockk()` or `mockkStatic()` inline mocking
- Projects using **Mockito** with `Mockito.mock()` on final classes (requires ByteBuddy agent)
- Any test suite that gets `"Could not self-attach to current VM using external process"` errors
- JMX monitoring tools that attach to running JVMs

**How it works:** The JVM creates a socket at `/tmp/.java_pid<PID>` (hardcoded path, not affected by `java.io.tmpdir`). A helper JVM process connects to this socket to load an instrumentation agent. The sandbox rule uses a regex pattern that only allows sockets matching `.java_pid<PID>` — all other Unix sockets in `/tmp` (including SSH agent, tmux, PostgreSQL) remain blocked.

**Security note:** This opens a narrow IPC channel for `.java_pid*`-named sockets only. SSH agent access (`SSH_AUTH_SOCK`) is NOT exposed — on macOS it lives at `/private/tmp/com.apple.launchd.*/Listeners` which does not match the pattern.

### Port restriction

Only port 443 is allowed by default. Services on other ports need `--allow-port`:

- `npm install` from private registries on non-standard ports
- API calls to services not on 443
- FTP, SMTP, or other protocol connections

### Private registries

Registry credential files are **blocked by default** because they typically contain passwords or tokens that a rogue agent could exfiltrate:

| File | Purpose |
|------|---------|
| `~/.npmrc` | npm registry auth (hard deny — not overridable) |
| `~/.m2/settings.xml` | Maven repository credentials |
| `~/.m2/settings-security.xml` | Maven master password |
| `~/.gradle/gradle.properties` | Gradle/Nexus/Artifactory credentials |
| `~/.cargo/credentials` | Cargo crate registry tokens |
| `~/.cargo/credentials.toml` | Cargo crate registry tokens (TOML format) |

For Maven, Gradle, and Cargo files, you can override this with `--allow-read`:

```bash
# Per session — Maven
cplt --allow-read ~/.m2/settings.xml -- -p "build with Maven"

# Per session — Gradle
cplt --allow-read ~/.gradle/gradle.properties -- -p "build with Gradle"

# Multiple files
cplt --allow-read ~/.m2/settings.xml --allow-read ~/.gradle/gradle.properties -- -p "build"
```

To allow permanently, add to `~/.config/cplt/config.toml`:

```toml
[allow]
read = ["~/.m2/settings.xml", "~/.gradle/gradle.properties"]
```

> **Note:** `.npmrc` cannot be overridden — it is in the hard-deny list alongside `.netrc` and `.pypirc`. If you need npm private registry access, consider using project-level `.npmrc` (which is readable as part of the project directory) with a token injected via environment variable.

> **Linux limitation:** These file-level denials are only enforced on macOS (via SBPL literal deny rules). On Linux, Landlock cannot deny individual files within an allowed directory — the parent dirs (`.m2`, `.gradle`, `.cargo`) remain fully readable for dependency resolution.

## Limitations

### macOS

- **`sandbox-exec` is deprecated** — Apple has not removed it but may in future macOS versions
- **SBPL has no domain-based filtering** — the optional CONNECT proxy provides domain blocking

### Linux

- **Kernel 5.13+ required** — Landlock LSM must be enabled
- **TCP port filtering requires kernel 6.7+** — older kernels get filesystem-only enforcement
- **Landlock cannot deny subpaths within allowed paths** — `.env` reads and `.git/hooks` writes inside the project dir are not kernel-enforced
- **`--deny-path` has no effect** — Landlock is allowlist-only

📖 **Full details:** [docs/security.md](docs/security.md#limitations)

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
