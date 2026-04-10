# cplt

[![CI](https://github.com/navikt/cplt/actions/workflows/ci.yml/badge.svg)](https://github.com/navikt/cplt/actions/workflows/ci.yml)
[![Release](https://github.com/navikt/cplt/actions/workflows/release.yml/badge.svg)](https://github.com/navikt/cplt/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![macOS](https://img.shields.io/badge/platform-macOS-lightgrey)

macOS Seatbelt sandbox wrapper for GitHub Copilot CLI. Runs Copilot inside Apple's kernel-level sandbox (`sandbox-exec`) so the agent can work on your project but cannot access your secrets.

![cplt banner](./assets/cplt.png)

> **macOS only** — uses Apple's Seatbelt framework (the same mechanism App Store apps run under).

## Table of contents

- [Quick start](#quick-start)
- [Install](#install)
- [What it does](#what-it-does)
- [Usage](#usage)
- [Configuration file](#configuration-file)
- [Architecture](#architecture)
- [Security](#security)
- [Known impacts](#known-impacts)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [References](#references)

## Quick start

```bash
# Install
brew install navikt/tap/cplt

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
| Execute from `/tmp`, `/var/folders`                                              | 🔒 Kernel-blocked                         | Prevents write-then-exec; interpreter-based exec not blocked (see SECURITY.md)          |
| Execute from `~/Library/Caches`                                                  | 🔒 Kernel-blocked                         | Prevents binary-drop staging; write still allowed for build caches                      |
| Modify `.vscode/tasks.json`, `launch.json`                                       | ⚠️ Allowed — known risk                   | IDE trust boundary; see SECURITY.md for mitigations                                     |
| Read/write `~/.copilot` (auth, settings)                                         | ✅ Allowed                                | Includes `file-map-executable` for `keytar.node`, `pty.node`, `computer.node`           |
| Write `~/.copilot/pkg` (native modules)                                          | 🔒 Kernel-blocked                         | Prevents persistence via native module replacement                                      |
| Environment variables                                                            | 🔒 Sanitized + hardened                   | Only safe allowlist passes through; lifecycle scripts blocked; `--pass-env VAR` to add  |
| Read `~/.config/gh/hosts.yml` + `config.yml`                                     | ✅ Allowed (read-only)                    | Only these two files — rest of `.config/gh` is blocked                                  |
| Read `~/.config/mise`                                                            | ✅ Allowed (read-only)                    | Tool versions and PATH — no secrets                                                     |
| Read `~/.gitconfig`, `~/.config/git/config`                                      | ✅ Allowed (read-only)                    |                                                                                         |
| Read `~/Library/Application Support/Microsoft`                                   | ✅ Allowed (read-only)                    | Device ID for telemetry                                                                 |
| Access macOS Keychain                                                            | ✅ Allowed (read+write)                   | Security framework locks db during access; Copilot uses `keytar.node` for token storage |
| Outbound network (port 443)                                                      | ✅ Allowed                                | All other ports blocked — use `--allow-port` to add extras                              |
| Localhost outbound                                                               | 🔒 Kernel-blocked                         | Prevents local service access; inbound still works for proxy                            |
| SSH agent (unix socket)                                                          | 🔒 Kernel-blocked                         | Prevents signing git operations or SSH to hosts                                         |
| Developer tools (`~/.cargo`, `~/.mise`, `~/.gradle`, `~/.m2`, `~/.sdkman`, etc.) | ✅ Allowed (read+write for caches)        | Only dirs that exist on disk; tightened at runtime via `--doctor`                       |
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

Download the latest release for your Mac:

```bash
# Apple Silicon (M1/M2/M3/M4)
curl -fsSL https://github.com/navikt/cplt/releases/latest/download/cplt-aarch64-apple-darwin.tar.gz | tar xz
sudo mv cplt /usr/local/bin/

# Intel Mac
curl -fsSL https://github.com/navikt/cplt/releases/latest/download/cplt-x86_64-apple-darwin.tar.gz | tar xz
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

By default, `cplt` sanitizes the child environment — only safe variables pass through (see `ENV_ALLOWLIST` in `sandbox.rs`). Cloud credentials, database URLs, and package tokens are stripped. Additionally, security hardening variables are injected to block npm/yarn/pnpm lifecycle scripts (postinstall hooks) — the #1 supply chain attack vector.

| Flag               | What it does                                                                                                                                            |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--pass-env <VAR>` | Explicitly pass an environment variable through to Copilot. Can be repeated.                                                                            |
| `--inherit-env`    | ⚠️ **Dangerous.** Inherit the full parent environment (only strips `NO_COLOR`, `FORCE_COLOR`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`). Use only for debugging. |
| `--allow-lifecycle-scripts` | Allow npm/yarn/pnpm lifecycle scripts (postinstall hooks) to run. Blocked by default. Use when `npm install` needs postinstall hooks.         |

### Proxy (optional)

The proxy is **disabled by default**. Copilot CLI connects directly to its APIs (Node.js does not natively respect `http_proxy`/`https_proxy` env vars). The proxy is useful for:

- **Connection logging** — see what domains tools like `gh` and `curl` connect to
- **Domain blocking** — block known exfiltration infrastructure (paste sites, webhook services, etc.)

| Flag                       | What it does                                                                                     |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| `--with-proxy`             | Start a localhost CONNECT proxy that logs connections.                                           |
| `--no-proxy`               | Disable the proxy, even if your config file enables it.                                          |
| `--proxy-port <PORT>`      | Which port the proxy listens on (default: 18080).                                                |
| `--blocked-domains <FILE>` | A text file with domains to block, one per line (e.g. `pastebin.com`). Re-read on every request. |

> **Why doesn't the proxy intercept Copilot traffic?** Copilot CLI is a Node.js application. Node.js does not natively use `http_proxy`/`https_proxy` env vars. Setting these vars actually *breaks* Copilot's auth flow with `api.business.githubcopilot.com`. Go-based tools like `gh` do respect proxy env vars and will be logged.

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
# enabled = false           # Set to true for connection logging
# port = 18080
# blocked_domains = "~/.config/cplt/blocked-domains.txt"

[sandbox]
# validate = true

[allow]
# read = ["~/some/path"]
# write = ["~/another/path"]

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

## Architecture

```
┌──────────────────────────────────┐
│  cplt (Rust binary)   │
│  ┌───────────┐  ┌─────────────┐ │
│  │ Profile    │  │ CONNECT     │ │
│  │ Generator  │  │ Proxy       │ │
│  │ (SBPL)     │  │ (optional)  │ │
│  └─────┬─────┘  └─────────────┘ │
│        │                         │
│        ▼                         │
│  sandbox-exec (Apple kernel)     │
│        │                         │
│        ▼                         │
│  copilot (sandboxed)             │
│  ├── All child processes         │
│  ├── Cannot read ~/.ssh          │
│  ├── Network port-restricted     │
│  ├── SSH agent blocked            │
│  └── Filesystem = primary ctrl   │
└──────────────────────────────────┘
```

**Security model**: deny-by-default filesystem with kernel enforcement. Network is restricted to port 443 (HTTPS) by default (use `--allow-port` for extras). SSH agent access and localhost outbound are blocked at the kernel level. The profile generator auto-discovers your environment (`--doctor`) and only includes tool directories that actually exist on disk — fewer rules means a tighter sandbox. See [SECURITY.md](SECURITY.md) for the full threat model, defense layers, and honest gaps.

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
- **The proxy cannot intercept Copilot traffic** — Node.js ignores `http_proxy` env vars, and setting them breaks auth
- **Use `--allow-port`** to add extra ports when needed (e.g., `--allow-port 8080` for a dev server)

See [SECURITY.md](SECURITY.md) for the full threat model and honest gaps.

## Domain blocking

When the proxy is enabled (`--with-proxy`), it can block domains commonly used for data exfiltration. A default blocklist is included based on real attack infrastructure observed in 2025–2026 supply chain incidents:

```bash
# Enable proxy with domain blocking
cplt --with-proxy --blocked-domains blocked-domains.txt -- -p "fix tests"

# Or set it permanently in config
cplt --init-config
# Then edit ~/.config/cplt/config.toml:
#   [proxy]
#   enabled = true
#   blocked_domains = "~/.config/cplt/blocked-domains.txt"
```

The blocklist covers webhook capture services, paste sites, file sharing, tunneling services, and IP recon endpoints. See [`blocked-domains.txt`](blocked-domains.txt) for the full list with sources.

> **Note:** The proxy only captures traffic from tools that respect `http_proxy` (like `gh`, `curl`). Copilot CLI's own API traffic bypasses the proxy. Domain blocking is a defense-in-depth measure, not a primary control.

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

### Port restriction

Only port 443 is allowed by default. Services on other ports need `--allow-port`:

- `npm install` from private registries on non-standard ports
- API calls to services not on 443
- FTP, SMTP, or other protocol connections

## Limitations

- **macOS only** — uses `sandbox-exec` (deprecated but functional, used by Chromium and VS Code)
- **No TLS inspection** — the proxy sees domain names (via CONNECT) but not request bodies
- **No network filtering** — SBPL doesn't support domain-based or port-based filtering for outbound TCP
- **Keychain access required** — Copilot stores auth tokens in macOS Keychain
- **Proxy doesn't intercept Copilot** — Node.js ignores `http_proxy`; the proxy is for tools like `gh`
- **`sandbox-exec` is deprecated** — Apple has not removed it but may in future macOS versions

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
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [michaelneale/agent-seatbelt-sandbox](https://github.com/michaelneale/agent-seatbelt-sandbox)

## License

[MIT](LICENSE)
