# cplt

[![CI](https://github.com/navikt/cplt/actions/workflows/ci.yaml/badge.svg)](https://github.com/navikt/cplt/actions/workflows/ci.yaml)
[![Release](https://github.com/navikt/cplt/actions/workflows/release.yaml/badge.svg)](https://github.com/navikt/cplt/actions/workflows/release.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![macOS](https://img.shields.io/badge/platform-macOS-lightgrey)
![Linux](https://img.shields.io/badge/platform-Linux-lightgrey)

**Kernel-enforced sandbox for AI coding agents.** cplt wraps GitHub Copilot CLI, OpenCode, Gemini CLI, Antigravity CLI, Pi, Claude Code, or any shell, so the agent can write code but cannot steal credentials, push to main, merge PRs, or exfiltrate secrets.

- **macOS**: Apple Seatbelt/SBPL via `sandbox-exec`
- **Linux**: Landlock LSM + seccomp-BPF + optional Bubblewrap namespace isolation (kernel 5.13+, full network filtering on 6.7+)
- **Windows**: no native support. There is no Windows sandbox backend. Run cplt inside WSL2, where it is an ordinary Linux install and the Microsoft kernel ships Landlock. See [Windows (WSL2) setup](#windows-wsl2).

![cplt banner](./assets/cplt.png)

## Why cplt?

AI agents execute arbitrary code. A compromised agent, whether through prompt injection, a supply chain attack, or a malicious MCP server, can read `~/.ssh`, push to main, merge PRs, or exfiltrate your code, unless the OS itself says no.

cplt gives you kernel-level enforcement with team-configurable policy:

- Per-repo policy in `.cplt.toml`, committed to version control, so it is tamper-proof and auditable
- Deny by default for credentials, secrets, and sensitive files
- Command-level git and gh interception that blocks pushes, merges, and releases
- Outbound network filtering with an audit log
- No Docker, no VMs. One static binary that runs on a locked-down laptop
- Zero-config start for developers, with escape hatches when a build genuinely needs one

## Table of contents

- [Quick start](#quick-start)
- [What it blocks](#what-it-blocks)
- [How cplt compares](#how-cplt-compares)
- [Install](#install)
- [Usage](#usage)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Security](#security)
- [Network and proxy](#network-and-proxy)
- [Command guards](#command-guards)
- [Known impacts](#known-impacts)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [References](#references)

**Detailed docs:**
[Configuration](docs/configuration.md) · [Proxy & domain filtering](docs/proxy.md) · [gh command guard](docs/gh-guard.md) · [git command guard](docs/git-guard.md) · [Known impacts](docs/known-impacts.md) · [Security details](docs/security.md) · [Security model](SECURITY.md)

## Quick start

```bash
brew install navikt/tap/cplt
cplt --shell-install        # make 'copilot' run sandboxed (persistent)
cplt doctor                 # check your environment
cplt -- -p "fix the tests"  # run Copilot in sandbox
```

Other agents and sandbox commands:

```bash
cplt --agent opencode                       # OpenCode (Copilot subscription)
cplt --agent opencode --pass-env ANTHROPIC_API_KEY  # third-party provider
cplt --agent shell                          # interactive sandboxed shell (no AI)
cplt exec -- npm install                    # sandbox any command directly
cplt exec -c "npm install && npm test"      # compound commands in sandbox
alias npm="cplt exec -- npm"               # sandboxed npm for every invocation
```

### Team rollout

```bash
# 1. Generate per-repo policy
cplt init --write

# 2. Developers approve on first run
cplt trust accept --all

# 3. Enable command guards
cplt config set gh_guard.enabled true
cplt config set git_guard.enabled true
cplt config set git_guard.protect_default_branch_only true
```

## What it blocks

The sandbox blocks access to credentials and secrets in the kernel. Command guards block destructive operations. Every restriction applies to the agent and to every process it spawns.

| Resource | Status | Notes |
| --- | --- | --- |
| Read/write project directory | ✅ Allowed | |
| Read/write/delete `.env*`, `.pem`, `.key` in project | 🔒 Kernel-blocked | Prevents secret exfiltration and destruction. `--allow-env-files` overrides |
| Write `.git/hooks`, `.git/config`, `.gitmodules` | 🔒 Kernel-blocked (macOS), ⚠️ partial on Linux | Prevents persistence via git hooks, hooksPath redirect, submodule hijacking. **Linux:** Landlock cannot deny a subpath inside an allowed tree, so these stay writable on the Landlock-only path. `bwrap` re-binds `.git/hooks` read-only but deliberately leaves `.git/config` and `.gitmodules` writable, so `core.hooksPath` remains a persistence route, see [Linux limitations](docs/security.md#linux). Applies to **every** writable root, the project and each `allow.write` grant, including a granted worktree or bare repo whose real hooks live outside `<root>/.git` |
| Execute from `/tmp`, `/var/folders` | 🔒 Kernel-blocked | Prevents write-then-exec. The scratch dir redirects TMPDIR to a safe location, on by default |
| Execute from `~/Library/Caches` | 🔒 Kernel-blocked by default | Prevents binary-drop staging. Copilot native modules are exempted via a carve-out. Add targeted exemptions with `--allow-cache-exec <SUBDIR>`, e.g. `ms-playwright` |
| Modify `.vscode/tasks.json`, `launch.json` | ⚠️ Allowed, known risk | IDE trust boundary. See [SECURITY.md](SECURITY.md) for mitigations |
| Read/write `~/.copilot` (auth, settings) | ✅ Allowed | Includes `file-map-executable` for `keytar.node`, `pty.node`, `computer.node` |
| Write `~/.copilot/pkg` (native modules) | 🔒 Kernel-blocked | Prevents persistence via native module replacement |
| Environment variables | 🔒 Sanitized + hardened | Only a safe allowlist passes through. Lifecycle scripts blocked. `--pass-env VAR` adds one back |
| Read `~/.config/gh/hosts.yml` + `config.yml` | ✅ Allowed (read-only) | Only these two files. The rest of `.config/gh` is blocked |
| Read `~/.config/mise` | ✅ Allowed (read-only) | Tool versions and PATH, no secrets |
| Read `~/.gitconfig`, `~/.config/git/config` | ✅ Allowed (read-only) | |
| Read global git hooks (`core.hooksPath`) | ✅ Allowed (read-only, write-denied) | Auto-detected. Must be under `$HOME` with depth ≥3. Writes are explicitly blocked |
| Commit/tag signing (`commit.gpgsign`, `tag.gpgsign`) | 🔒 Disabled | Private keys in `~/.ssh` and `~/.gnupg` are blocked, so signing is disabled via an env var override |
| Read `~/Library/Application Support/Microsoft` | ✅ Allowed (read-only) | Device ID for telemetry |
| Access macOS Keychain | ✅ Allowed (read+write) | The Security framework locks the db during access. Copilot uses `keytar.node` for token storage |
| Outbound network (port 443) | ✅ Allowed | Every other port is blocked. Add extras with `--allow-port` |
| Localhost outbound | 🔒 Kernel-blocked (macOS), ⚠️ port-based on Linux | Prevents local service access. Inbound still works for the proxy. **Linux:** Landlock rules are port numbers only and cannot tell `localhost:443` from `remote:443`, so a local service on an allowed port is reachable and there is no localhost-specific deny. Use `--with-proxy` for SSRF protection, see [Linux limitations](docs/security.md#linux) |
| SSH agent (unix socket) | 🔒 Kernel-blocked (macOS), ⚠️ env-only on Linux | Prevents signing git operations or SSH to hosts. **Linux:** unix socket `connect()` is not gated, so the withheld `SSH_AUTH_SOCK` is the only barrier and an agent that sets it itself can use the loaded keys. `bwrap` hides the stock OpenSSH socket under `/tmp`, but not a gnome-keyring/gcr or systemd agent under `$XDG_RUNTIME_DIR`. See [Linux limitations](docs/security.md#linux) |
| Developer tools (`~/.cargo`, `~/.gradle`, `~/.m2`, `~/.sdkman`, `~/.jenv`, `~/.pyenv`, `~/.konan`, etc.) | ✅ Allowed (read+write for caches) | Only dirs that exist on disk. Tightened at runtime by what `cplt doctor` detects |
| Registry credential files (`~/.m2/settings.xml`, `~/.gradle/gradle.properties`, `~/.cargo/credentials`) | 🔒 Kernel-blocked on macOS. On Linux the parent tool dir stays readable | Override with `--allow-read`. See [Private registries](docs/known-impacts.md#private-registries) |
| Read `~/.npmrc` | 🔒 Kernel-blocked (both platforms) | Override with `--allow-read`. Breaks yarn 1, see [yarn 1](docs/known-impacts.md#yarn-1-and-unreadable-home-rc-files) |
| Go source code (`~/go/src`) | 🔒 Kernel-blocked | Only `~/go/bin` and `~/go/pkg` are readable |
| Read `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure` | 🔒 Kernel-blocked | |
| Read `~/.kube`, `~/.docker`, `~/.nais` | 🔒 Kernel-blocked | |
| Read `~/.password-store`, `~/.terraform.d` | 🔒 Kernel-blocked | |
| Read `~/.config/gcloud`, `~/.config/op` | 🔒 Kernel-blocked | Individual files are overridable with `--allow-read`. See [Cloud credentials](docs/known-impacts.md#cloud-credential-directories) |
| Read `~/.netrc`, `~/.pypirc`, `~/.vault-token` | 🔒 Kernel-blocked | Un-overridable on macOS. On Linux `allow.read` currently still grants these |
| Read `~/.gem/credentials` | 🔒 Kernel-blocked | Un-overridable on macOS. On Linux `allow.read` currently still grants these |
| `gh` CLI destructive operations (merge, delete, release) | 🔒 Command-gated (opt-in) | `--gh-guard`, see [gh guard](docs/gh-guard.md) |
| `git push` to remote | 🔒 Command-gated (opt-in) | `--git-guard`. Protects the default branch or blocks all pushes |
| Child process inheritance | ✅ All restrictions apply to subprocesses | |

That table is a summary. The sandbox also allows access to system files (SSL certs, `/etc/hosts`), temp directories (read and write, no exec), and system tool paths (`/usr/bin`, `/opt/homebrew`). Run `cplt --print-profile` for the complete SBPL rules.

For the full security model, threat analysis, and test strategy, read [SECURITY.md](SECURITY.md).

## How cplt compares

### Codex CLI's sandbox

| Area | cplt | Codex CLI sandbox |
| --- | --- | --- |
| Outbound network control | CONNECT proxy with domain allow/block lists | No domain-level filtering |
| Environment handling | Allowlist plus hardening env injection | More basic pass-through model |
| Secret file protection | Deny patterns such as `.env*`, `.pem`, `.key` inside the repo | Primarily directory-scoped access |
| Repo policy | [`.cplt.toml`](docs/configuration.md#per-repo-configuration-cplttoml) with an explicit trust/approval flow | No repo-level policy file |
| Agent support | Copilot, OpenCode, Gemini CLI, Antigravity CLI, Pi, Claude Code, or shell | Codex only |

cplt is not stronger everywhere. Codex CLI has Linux namespace isolation today, and it already exposes explicit sandbox modes such as read-only and workspace-write. cplt does not yet have that mode matrix.

### Docker-based sandboxes

| Area | cplt | Docker-based sandbox |
| --- | --- | --- |
| Startup time | Roughly instant for normal CLI use | Usually slower container startup |
| Network control | Per-request outbound filtering via proxy | Usually all-or-nothing network access |
| File controls | Per-path and per-pattern rules | Per-mount controls |
| Host requirements | Single binary | Docker daemon required |
| Corporate laptop fit | Works where Docker is unavailable or restricted | Often blocked by local policy |

Docker still gives you stronger isolation in some environments, especially if you want a fully separate filesystem and process namespace. cplt trades that for lighter setup and tighter integration with the machine you already develop on.

### VS Code agent mode permissions

Tools such as VS Code agent mode rely mainly on UI permissions. cplt enforces its restrictions in the kernel, so the agent cannot talk its way around them with a prompt or a modified instruction. That matters most for CLI agents and credential exposure:

- cplt works outside the IDE
- env vars are filtered before the agent starts
- sensitive files can be blocked even when they live inside the repo
- the same restrictions apply to child processes

### Claude Code's sandbox (Anthropic Sandbox Runtime)

[Anthropic Sandbox Runtime](https://github.com/anthropic-experimental/sandbox-runtime) (`srt`) is the sandboxing layer used by Claude Code. Same high-level approach as cplt, macOS Seatbelt plus kernel-level Linux enforcement plus an HTTP proxy, different implementation.

| Area | cplt | Anthropic srt |
| --- | --- | --- |
| Language / delivery | Single Rust binary | Node.js + npm package + external deps |
| Linux backend | Landlock LSM (no deps, no namespaces) | bubblewrap (container via user namespaces) |
| Environment filtering | Strict allowlist + suffix-deny (`_TOKEN`, `_SECRET`) | Inherits full parent env (secrets pass through) |
| Credential dir protection | 15+ dirs denied by default | User must configure manually |
| DNS rebinding protection | ✅ Post-DNS IP checked against private ranges | ❌ Not implemented |
| Network proxy | HTTP CONNECT + domain allow/block | HTTP + SOCKS5 + experimental TLS MITM |
| SSH git | Blocked at kernel on macOS (agent socket denied); on Linux only `SSH_AUTH_SOCK` is withheld | Proxied via SOCKS5 |
| Package manager scripts | Blocked by default (`npm_config_ignore_scripts`) | Not blocked |
| Agent support | Copilot, OpenCode, Gemini, Antigravity, Pi, Claude Code, Shell | Claude Code |
| Config | TOML (global + per-repo) | JSON (global only) + `--control-fd` live updates |
| Library API | ❌ Binary only | ✅ Embeddable TypeScript library |

cplt is more secure out of the box: env filtering, credential protection, DNS rebinding checks, lifecycle script blocking. srt is more flexible: SOCKS5, TLS inspection, per-request callbacks, library embedding. The Linux backend choice matters. bwrap needs workarounds on Ubuntu 24.04+ because of AppArmor userns restrictions, while Landlock requires kernel 5.13 or newer but has zero external dependencies.

### Honest gaps

- macOS has the strongest file-level enforcement today. Linux coverage is improving but not identical.
- cplt does not yet offer simple read-only / workspace-write / full-access policy presets.
- If you want full container isolation, cplt is not trying to replace Docker.

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

Grab the latest build for your platform from [GitHub Releases](https://github.com/navikt/cplt/releases/latest):

```bash
# macOS, Apple Silicon (M1/M2/M3/M4)
curl -fsSL https://github.com/navikt/cplt/releases/latest/download/cplt-aarch64-apple-darwin.tar.gz | tar xz
sudo mv cplt /usr/local/bin/

# macOS, Intel
curl -fsSL https://github.com/navikt/cplt/releases/latest/download/cplt-x86_64-apple-darwin.tar.gz | tar xz
sudo mv cplt /usr/local/bin/

# Linux, x86_64
curl -fsSL https://github.com/navikt/cplt/releases/latest/download/cplt-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv cplt /usr/local/bin/

# Linux, ARM64
curl -fsSL https://github.com/navikt/cplt/releases/latest/download/cplt-aarch64-unknown-linux-gnu.tar.gz | tar xz
sudo mv cplt /usr/local/bin/
```

Every release binary carries a [build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds). Verify it:

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

`mise run install` and manual builds put cplt in `/usr/local/bin/cplt`. If you also have the Homebrew build at `/opt/homebrew/bin/cplt`, put `/usr/local/bin` first in `PATH` so your development build wins:

```bash
# Check which cplt is active
which cplt

# If it shows /opt/homebrew/bin/cplt, reorder your PATH:
export PATH="/usr/local/bin:$PATH"
```

Or just run `/usr/local/bin/cplt` explicitly and skip PATH resolution entirely.

### Windows (WSL2)

cplt has no Windows sandbox backend. Enforcement is Apple Seatbelt on macOS and Landlock LSM on Linux, so there is nothing to run natively on Windows. The supported route is [WSL2](https://learn.microsoft.com/windows/wsl/install), where cplt is an ordinary Linux install and the sandbox is kernel-enforced. Every Microsoft kernel branch builds `CONFIG_SECURITY_LANDLOCK=y` and lists `landlock` first in `CONFIG_LSM` ([`config-wsl`](https://github.com/microsoft/WSL2-Linux-Kernel/blob/master/arch/x86/configs/config-wsl)), shipped since kernel 5.15.57.1, and WSL's default kernel command line sets no `lsm=` override.

In PowerShell, once:

```powershell
wsl --install                    # WSL2 + the default distro (now Ubuntu 26.04 LTS), then reboot
wsl --install -d Ubuntu-24.04    # ...or pin an older release
wsl --update                     # keep the Microsoft kernel current, see the ABI note below
```

Everything below runs **inside the distro** (`wsl`, or the Ubuntu profile in Windows Terminal), not in PowerShell:

```bash
# 1. Node. Copilot CLI requires Node 22+
#    Ubuntu 26.04 ships 22.x, so apt is enough:
sudo apt update && sudo apt install -y nodejs npm
#    Ubuntu 24.04 ships Node 18, too old. Use nvm, fnm, or NodeSource there instead.

# 2. GitHub CLI, and log in. Ubuntu's universe package works but lags
#    (2.45 on 24.04); add GitHub's apt repo if you want a current gh:
#    https://github.com/cli/cli/blob/trunk/docs/install_linux.md
sudo apt install -y gh
gh auth login

# 3. The agent, installed in the distro, never on the Windows side
npm install -g @github/copilot

# 4. cplt
curl -fsSL https://raw.githubusercontent.com/navikt/cplt/main/install.sh | bash
# (or: brew install navikt/tap/cplt, if you use Homebrew on Linux)

# 5. Check the result
cplt doctor
```

**Do not install Copilot CLI on the Windows side.** With interop on (the default), the Windows `PATH` is appended to the distro's, so a Windows-side `npm install -g @github/copilot` turns up inside the distro as `/mnt/c/Users/<user>/AppData/Roaming/npm/copilot`. That is a Windows install reached through interop. It cannot run in the Linux sandbox, and the npm shim execs a `node` that the distro will not have unless you installed one there too. The symptom used to be an unrelated runtime-extraction error. cplt now names the cause when it resolves an agent under `/mnt/<drive>/` *and* it is running under WSL, and `cplt doctor` reports it as a failing check instead of passing ([#188](https://github.com/navikt/cplt/issues/188)). WSL is detected from kernel-owned state, either `/run/WSL` or the kernel name in `/proc/sys/kernel/osrelease` and `/proc/version`, not from `WSL_DISTRO_NAME`, which is absent under `sudo` and in systemd units and which any process can set. On a plain Linux box `/mnt/c` is left alone. It is an ordinary mount point there.

That check has two limits, both deliberate. It keys on the *default* automount root, so if you have relocated it (`[automount] root` in `/etc/wsl.conf`) the Windows-side install is not recognised and you get the old, less helpful failure with the path in it. And turning interop off stops the Windows `PATH` from leaking in but does **not** unmount `/mnt/c`.

**Kernel and Landlock ABI.** Current WSL (2.7.x and later) ships Linux 6.18, which gives Landlock ABI 7 — everything cplt uses except the unix-socket `connect()` right, which needs ABI 9 (kernel 7.1). An install still on the 6.6 kernel line gets ABI 3: filesystem rules are enforced, but TCP port rules (ABI 4), ioctl restriction (ABI 5) and signal/abstract-socket scoping (ABI 6) are not available, and network filtering falls back to the CONNECT proxy. `wsl --update` moves you forward. `cplt doctor` prints the kernel version and the ABI it found, which is the check that matters on your machine.

> **Do not disable Landlock in `.wslconfig`.** A `[wsl2] kernelCommandLine` with an `lsm=` list that omits `landlock`, or a custom `[wsl2] kernel=` built without `CONFIG_SECURITY_LANDLOCK`, removes the kernel enforcement cplt depends on, and `cplt doctor` will report Landlock as unavailable.

**Keep the project in the Linux filesystem.** Work in `~/src/...` inside the distro rather than `/mnt/c/Users/...`. Microsoft's own guidance is that cross-OS file access is markedly slower, and `/mnt/c` is served over 9p by default as of WSL 2.9.x (virtiofs is opt-in via `[wsl2] virtiofs=true`). More to the point, we have not verified how Landlock enforces rules on that mount. The kernel documents no exclusion for network- or FUSE-backed filesystems, only pipes, sockets and nsfs, and Landlock's own test suite exercises 9p and FUSE, so we expect it to work. Nobody here has confirmed it. Treat a project under `/mnt/c` as unproven rather than supported.

**Bubblewrap.** Ubuntu 23.10+ blocks unprivileged user namespaces through `kernel.apparmor_restrict_unprivileged_userns`, which breaks `bwrap`. That sysctl comes from an Ubuntu kernel patch that is absent from the Microsoft kernel, so the optional Bubblewrap layer is expected to work on Ubuntu-under-WSL2. That is inference from the kernel source, not something we have run. If `bwrap` fails there, please say so in [#189](https://github.com/navikt/cplt/issues/189). cplt's own seccomp filter is a plain `PR_SET_SECCOMP` BPF program, which stacks on top of the filter WSL installs in every process.

> **Not yet verified on a real WSL2 install.** Verified from source: Landlock is compiled in and first in `CONFIG_LSM` on the Microsoft kernel; the `/mnt/<drive>/` detection, the WSL signals it uses, and their error text; that `cplt doctor` fails on such an agent and prints kernel + Landlock ABI; the 5.13+/6.7+ requirements; and that `install.sh` installs the Linux release binary. Still unverified by anyone here: how Landlock behaves on `/mnt/c`, whether Bubblewrap works under WSL2, the exact package versions your distro release ships, and the sequence above end to end. If you run it, please report what actually happened in [#189](https://github.com/navikt/cplt/issues/189).

### Shell setup (recommended)

By default you get the sandbox by typing `cplt`. To make plain `copilot` run sandboxed too:

```bash
cplt --shell-install
```

That detects your shell, appends the alias to your rc file, and prints what it did. Run it as many times as you like, it will not add duplicates.

| Shell | File modified | What's added |
|-------|--------------|--------------|
| zsh (macOS default) | `~/.zshrc` | `eval "$(cplt --shell-setup)"` |
| bash | `~/.bashrc` | `eval "$(cplt --shell-setup)"` |
| fish | `~/.config/fish/conf.d/cplt.fish` | `alias copilot cplt` |

Restart your shell or `source` the file to activate.

<details>
<summary>Manual setup (alternative)</summary>

If you would rather not use `--shell-install`, add the line yourself:

```bash
# zsh / bash
eval "$(cplt --shell-setup)"

# fish
alias copilot cplt
```

Same pattern mise, direnv, and starship use.
</details>

**Why an alias instead of a symlink?** cplt and Copilot CLI install into the same Homebrew bin directory (`/opt/homebrew/bin/`), and only one file named `copilot` can live there, so a symlink would conflict. An alias sidesteps that. The real `copilot` binary stays in PATH where cplt can find and wrap it, and the alias redirects your command.

> **Note:** cplt refuses to nest. If it detects that it is already running inside a sandbox (via the `__CPLT_WRAPPED` environment variable), it will not launch again. Read-only subcommands such as `--print-profile` and `cplt doctor` still work inside an existing sandbox.

## Usage

```
cplt [OPTIONS] [-- <AGENT_ARGS>...]
```

Everything after `--` goes straight to the agent process (copilot, opencode, gemini, antigravity, pi, claude, or shell).

### Policy presets

A preset sets a baseline for the five main sandbox toggles with one flag instead of a list of them. Individual flags still win over the preset, so `--preset permissive --no-allow-tmp-exec` does what it says. Also settable as `[sandbox] preset = "..."` in config.

| Flag | What it does |
| --- | --- |
| `--preset strict` | Full network lockdown. All five toggles off, plus `gh_guard`, `git_guard`, `proxy.forced` (forced-proxy egress) and `proxy.default_allowlist` (fail-closed domain allowlist) on. Escape hatch: `--allow-all-domains` disables just the allowlist |
| `--preset standard` | The current defaults. All five off, scratch dir stays on. Same as passing no preset |
| `--preset permissive` | Turns on `allow_localhost_any`, `allow_tmp_exec`, and `allow_lifecycle_scripts` |
| `--preset full-trust` | ⚠️ Dangerous. Turns on all five, adding `allow_env_files` and `allow_docker` |

Full preset matrix and resolution order: [docs/configuration.md](docs/configuration.md#policy-presets).

### File access

The project directory is the writable workspace, plus a narrow allowlist needed for auth, runtime, and tooling (see the table above). The kernel blocks everything else, SSH keys and cloud credentials included.

| Flag | What it does |
| --- | --- |
| `-d, --project-dir <DIR>` | Which directory Copilot can work in. Defaults to the current git repo root |
| `--allow-read <PATH>` | Let Copilot read files outside the project, read-only. Repeatable |
| `--allow-write <PATH>` | Let Copilot read and write outside the project. Use carefully. Repeatable |
| `--allow-socket <PATH>` | ⚠️ Dangerous. Allow a Unix domain socket path, for example a custom LSP daemon or a database socket. Repeatable. Whatever is on the other end runs outside the sandbox, so pointing this at `docker.sock` or an agent socket is equivalent to `--allow-docker`, and the only guard is that `--deny-path` overlaps are rejected. On Linux it does nothing below kernel 7.1, since unix socket connects are not gated by Landlock before ABI v9 (see [Linux limitations](docs/security.md#linux)) |
| `--deny-path <PATH>` | Block a path that would otherwise be allowed. Deny always wins. Repeatable |
| `--allow-port <PORT>` | Allow outbound TCP on an extra port. Only 443 by default. Repeatable |
| `--allow-localhost <PORT>` | Allow outbound to `localhost` on one port. Localhost is blocked by default. Use for MCP servers or dev servers. Repeatable |
| `--allow-localhost-any` | Allow outbound to `localhost` on **all** ports. Needed by build tools like Turbopack (Next.js) and Vite that use random ephemeral ports for IPC |

### Environment variables

cplt sanitizes the child environment by default. Only safe variables pass through, and cloud credentials, database URLs, and package tokens are stripped. It also injects hardening variables that block npm/yarn/pnpm lifecycle scripts (postinstall hooks, the number one supply chain attack vector), disable git commit and tag signing (since `~/.ssh` and `~/.gnupg` are unreachable inside the sandbox), and opt out of developer tooling telemetry (`DO_NOT_TRACK=1`, `NEXT_TELEMETRY_DISABLED=1`, `TURBO_TELEMETRY_DISABLED=1`, `CHECKPOINT_DISABLE=1`, and others).

What passes through:

| Category | Examples | How |
|---|---|---|
| Core system | `HOME`, `USER`, `PATH`, `SHELL`, `TMPDIR`, `LANG` | Explicit allowlist |
| Terminal | `TERM`, `COLORTERM`, `TERM_PROGRAM` | Explicit allowlist |
| Editor | `EDITOR`, `VISUAL`, `PAGER` | Explicit allowlist |
| Auth tokens | `GH_TOKEN`, `GITHUB_TOKEN`, `COPILOT_GITHUB_TOKEN` | Passed only if you already set them. The gh guard uses a one-time file instead |
| Copilot config | `COPILOT_DEBUG`, `COPILOT_*` | Prefix allowlist |
| Language runtimes | `NODE_*`, `GOPATH`, `CARGO_HOME`, `JAVA_HOME`, `VIRTUAL_ENV`, `PYTHONPATH` | Explicit allowlist |
| Tool managers | `NVM_*`, `FNM_*`, `PYENV_*`, `MISE_*`, `SDKMAN_*`, `COREPACK_*`, `YARN_*` | Prefix allowlist |
| OpenTelemetry | `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_*` | Prefix allowlist (`OTEL_EXPORTER_OTLP_HEADERS` may carry opt-in auth) |
| XDG dirs | `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME` | Explicit allowlist |

**Prefix allowlist with secret-suffix protection.** A variable matching an allowed prefix such as `COPILOT_*` or `YARN_*` still gets dropped if it ends in a secret-bearing suffix: `_TOKEN`, `_AUTH`, `_SECRET`, `_SECRET_KEY`, `_KEY`, `_PASSWORD`, or `_CREDENTIALS`. So `COPILOT_DEBUG` passes and `COPILOT_API_KEY` does not.

**Always blocked:** `AWS_*`, `AZURE_*`, `NPM_TOKEN`, `DATABASE_URL`, `VAULT_TOKEN`, `SSH_AUTH_SOCK`, Docker vars, CI tokens, and anything not in the allowlist.

| Flag | What it does |
| --- | --- |
| `--pass-env <VAR>` | Pass one environment variable through to the agent. Repeatable |
| `--inherit-env` | ⚠️ Dangerous. Inherit the full parent environment. Strips only `NO_COLOR`, `FORCE_COLOR`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`. Debugging only |

### Sandbox toggles

| Flag | What it does |
| --- | --- |
| `--allow-lifecycle-scripts` | Allow npm/yarn/pnpm lifecycle scripts (postinstall hooks) to run. Blocked by default. Use when `npm install` needs them |
| `--allow-gpg-signing` | Allow GPG commit and tag signing inside the sandbox. Grants read-only access to the public keyring and the GPG agent socket. Private keys stay denied. See [GPG signing](docs/known-impacts.md#gpg-commit-signing) |
| `--allow-jvm-attach` | Allow JVM Attach API unix sockets in `/tmp`. Needed for MockK inline mocking, Mockito inline agents, ByteBuddy. See [JVM Attach API](docs/known-impacts.md#jvm-attach-api) |
| `--allow-msbuild` | Allow MSBuild worker-node unix sockets in `/tmp`. Needed for `dotnet build`. Does not enable the persistent MSBuild Server. See [MSBuild worker-node IPC](docs/known-impacts.md#msbuild-worker-node-ipc) |
| `--no-scratch-dir` | Disable the per-session scratch directory, which is on by default. TMPDIR will not be redirected |
| `--scratch-dir` | Explicitly enable the per-session scratch directory. Already the default, so this is for overriding `scratch_dir = false` in config |
| `--allow-tmp-exec` | ⚠️ Dangerous. Allow exec from system temp dirs (`/private/tmp`, `/private/var/folders`). Prefer the scratch dir |
| `--allow-cache-exec <SUBDIR>` | Allow exec from one `~/Library/Caches/<SUBDIR>`. Repeatable. For tools that cache compiled binaries there, such as Playwright and pnpm dlx |
| `--allow-cache-exec-any` | ⚠️ Dangerous. Allow exec from all of `~/Library/Caches`. Prefer `--allow-cache-exec <SUBDIR>` |
| `--allow-browser` | ⚠️ Dangerous. Emits an unscoped `(allow lsopen)`, which lets the agent hand any file or URL to Launch Services. launchd starts the target **outside** the Seatbelt profile, so `open -a Terminal /tmp/x.sh` is an immediate sandbox escape, not just browser-session access. Only turn it on when a sign-in prompt actually appears (MCP server OAuth, re-auth), then turn it back off. Not for a Gemini *first* login — the file it records the auth method in is write-denied, so that login fails in here (cplt warns about it up front); sign in once outside cplt instead. Off by default |
| `--deny-clipboard` | Block the agent from reading or writing the macOS clipboard (`pbpaste`/`pbcopy`) by denying the `com.apple.pasteboard` Mach service. Every other Mach service (Keychain, DNS, Security framework) is unaffected |
| `--use-bubblewrap` | Linux only. Require the bubblewrap namespace layer (PID, mount, IPC, UTS, cgroup, user namespaces plus a private `/tmp`) on top of Landlock and seccomp. Errors out if `bwrap` is missing. Auto-detected when neither flag is given |
| `--no-bubblewrap` | Linux only. Never use bubblewrap, even when installed. Falls back to Landlock and seccomp. Use it when bwrap breaks a specific tool |

### Supported runtimes

cplt auto-discovers installed tools and writes sandbox rules to match. Generally only directories that exist on disk get rules, so there are no phantom paths. On macOS, writable app directories are included when discovered even if they do not exist yet, so they can be created on first use. Linux cannot allow a write to a non-existent path, so creation has to happen outside the sandbox there.

| Runtime | Home dirs | Env vars / prefixes | Discovery |
|---|---|---|---|
| Node.js | `.nvm`, `.local/share/fnm`, `.local/bin` | `NODE_*`, `NPM_*`, `NVM_*`, `FNM_*` | `node` |
| Rust | `.cargo`, `.rustup` | `CARGO_HOME`, `RUSTUP_HOME` | `cargo` |
| Go | `go/bin`, `go/pkg` | `GOPATH`, `GOROOT`, `GOCACHE`, etc. | `go` |
| Java/Kotlin (JVM) | `.sdkman`, `.jenv`, `.gradle`, `.m2` | `JAVA_HOME`, `JAVA_TOOL_OPTIONS`, `GRADLE_*`, `MAVEN_*`, `SDKMAN_*`, `JENV_*` | `java`, `gradle` |
| Kotlin Native | `.konan` | none | none |
| Python | `.pyenv` | `VIRTUAL_ENV`, `PYTHONPATH`, `PYENV_ROOT`, `PYENV_*` | `python3` |
| Yarn Berry | `.yarn` | `YARN_*` (hardening overrides `YARN_ENABLE_SCRIPTS`) | `yarn` |
| pnpm | `Library/pnpm`, `.local/share/pnpm` | `PNPM_HOME` | `pnpm` |
| Corepack | none | `COREPACK_*` | none |
| mise | `.local/share/mise`, `.mise` | `MISE_*` | `mise` |

Run `cplt doctor` to see what cplt detected on your machine.

### Debugging

| Flag | What it does |
| --- | --- |
| `--doctor` | **Deprecated.** Use the `cplt doctor` subcommand instead |
| `--print-profile` | Print the generated sandbox profile (SBPL) and exit |
| `--show-denials` | Stream macOS sandbox denial logs in real time |
| `--no-validate` | Skip the startup check that verifies sandbox restrictions are active |
| `-y, --yes` | Skip the interactive confirmation prompt. The configuration summary still prints, for auditability. Required when stdin is not a TTY, so CI and scripts need it |
| `-q, --quiet` | Suppress the startup banner and non-essential messages. Errors and warnings still print. Also `sandbox.quiet = true` in config |
| `--no-quiet` | Override `sandbox.quiet = true` and show the startup summary anyway |
| `--no-audit` | Skip the post-session change report. cplt normally diffs the working tree against a baseline commit pinned before the run and lists what the session touched, flagging sensitive paths. `-q` suppresses it too |
| `--init-config` | Create a starter config file at `~/.config/cplt/config.toml` and exit |

### Session flags

These translate into the agent's own session flags, so you do not need a `--` separator.

| Flag | What it does |
| --- | --- |
| `--resume[=SESSION]` | Resume a previous session. Bare `--resume` picks interactively, `--resume=NAME` picks by name or ID |
| `--continue` | Resume the most recent session in the current directory |
| `--remote` | Enable remote control, so you can monitor and steer the session from GitHub.com or mobile |
| `--name SESSION` | Name the session so `--resume=NAME` can find it later |

`--continue` and `--resume` are mapped for OpenCode, Antigravity, and Claude Code too:

| cplt flag | Copilot | OpenCode | Antigravity (`agy`) | Claude Code |
| --- | --- | --- | --- | --- |
| `--continue` | `--continue` | `--continue` | `--continue` | `--continue` |
| `--resume` | `--resume` | `--continue`¹ | `--continue`¹ | `--resume` |
| `--resume=ID` | `--resume=ID` | `--session ID` | `--conversation ID` | `--resume ID` |
| `--remote` | `--remote` | ignored | ignored | ignored |
| `--name NAME` | `--name NAME` | ignored | ignored | ignored |

¹ Neither OpenCode nor Antigravity has an interactive session picker, so a bare `--resume` means "continue last session". Claude Code has one, so it maps straight across.

`--remote` and `--name` are Copilot-only. Gemini, Pi, and shell mode get no translation at all, so all four flags are dropped for them. Auto-resume is a separate mechanism: when you invoke cplt with no pass-through args and no session flags, it appends `--resume` for you, and that applies to Copilot and Gemini only.

Combine them with sandbox flags and `--` pass-through args:

```bash
cplt --resume=my-task                          # resume by name
cplt --remote --name my-task -- -p "fix tests" # remote + named + prompt
```

### Agents

Pick one with `--agent <name>`, or make it the default with `cplt config set sandbox.agent <name>`. Copilot, OpenCode, Gemini, and Antigravity are auto-detected from `PATH` in that order when you do not name one.

| Agent | `--agent` value | Auto-detected | Auth |
| --- | --- | --- | --- |
| GitHub Copilot CLI | `copilot` | yes, priority 1 | GitHub token, from the Keychain or `gh` |
| [OpenCode](https://opencode.ai/) | `opencode` | yes, priority 2 | Copilot subscription via `/connect`, or `--pass-env ANTHROPIC_API_KEY` |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | `gemini` | yes, priority 3 | Google OAuth in the browser, or `--pass-env GEMINI_API_KEY` |
| [Antigravity CLI](https://github.com/google-antigravity/antigravity-cli) | `antigravity`, aliases `agy` and `agi` | yes, priority 4 | Google OAuth in the browser |
| [Pi](https://github.com/earendil-works/pi) | `pi` | no | `--pass-env ANTHROPIC_API_KEY` and friends |
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `claude`, aliases `cc` and `claude-code` | no | Subscription OAuth in `~/.claude` or the Keychain, or `--pass-env ANTHROPIC_API_KEY` |
| Your shell | `shell` | no | none |

- **Pi and Claude Code are never auto-detected.** `pi` is a generic binary name that could collide with something else on your machine, and Claude Code has to be chosen on purpose.
- **Third-party API keys are opt-in.** `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN` and the Bedrock/Vertex routing vars (`CLAUDE_CODE_USE_BEDROCK`, `AWS_BEARER_TOKEN_BEDROCK`, `CLAUDE_CODE_USE_VERTEX`, `ANTHROPIC_VERTEX_PROJECT_ID`, `GOOGLE_CLOUD_PROJECT`) never pass through unless you name them with `--pass-env`.
- **Subscription auth needs no env var.** OpenCode's `/connect` device flow stores its token in `~/.local/share/opencode/auth.json`, and Claude Code's OAuth token lives in `~/.claude` (`.credentials.json` on Linux) or the macOS Keychain. Both are reachable inside the sandbox, so cplt does not nag about a missing API key for either.
- **OAuth browser flows need `--allow-browser`** when a sign-in prompt appears. That covers Gemini CLI and Antigravity.
- **Gemini's *first* login has to happen outside cplt.** It records the auth method it picked in `~/.gemini/settings.json`, which cplt write-denies because the same file carries auto-firing `SessionStart` hooks. cplt detects this before launching and says so rather than letting the write fail inside the agent. Run `gemini` once normally, then use cplt as usual — see [Known impacts](docs/known-impacts.md#agent-config-dir-host-persistence-denies).
- **Claude Code auto-update is disabled** with `DISABLE_AUTOUPDATER=1`. Claude Code has no `--no-auto-update` flag, self-updating inside the sandbox is a persistence vector, and it would fail against read-only install paths anyway.
- **`CLAUDE_CONFIG_DIR` is honored.** When it is set, cplt grants that directory instead of `~/.claude` and passes the variable through, so a relocated config root keeps working.
- OpenCode is [an officially supported Copilot client](https://github.blog/changelog/2026-01-16-github-copilot-now-supports-opencode/), so your existing Copilot subscription works with `/connect` inside OpenCode.

Per-agent config dirs, Keychain use, exec permissions, and env isolation are in [SECURITY.md](SECURITY.md#supported-agents).

### Shell mode

Run a plain sandboxed shell with no AI agent and the same restrictions. Handy for testing build tools, debugging sandbox issues, or just working carefully by hand.

```bash
# Interactive sandboxed shell (uses $SHELL: fish, zsh, bash)
cplt --agent shell

# Inspect what's allowed without entering the shell
cplt --agent shell --print-profile
```

The same deny-by-default rules apply: filesystem isolation, network restrictions, env sanitization. Shell config directories (fish variables and history, zsh history) stay writable.

For a single command, [`cplt exec`](#exec-mode) is cleaner than `cplt --agent shell -- -c 'cmd'`.

### Exec mode

<a id="exec-mode"></a>

Run any command inside the sandbox without starting an agent. No startup banner, no confirmation prompt, so it suits scripts, pipes, and shell aliases.

```bash
# Sandbox a single command
cplt exec -- npm install
cplt exec -- make build
cplt exec -- go test ./...

# Compound commands via $SHELL -c
cplt exec -c "npm install && npm test"

# Pass sandbox flags as usual
cplt exec --allow-lifecycle-scripts -- npm install
cplt exec --project-dir /path/to/repo -- make build
cplt exec --with-proxy -- curl https://example.com

# Shell aliases for sandboxed tools
alias npm="cplt exec -- npm"
alias node="cplt exec -- node"
alias python="cplt exec -- python"
```

Every top-level `cplt` flag applies: `--project-dir`, `--allow-read`, `--deny-path`, `--with-proxy`, `--pass-env`, and the rest. Add `--no-quiet` to see the full sandbox configuration summary before the command runs.

### Examples

```bash
# The common case: Copilot in the sandbox
cplt -- -p "fix the tests"

# Sessions
cplt --resume                                   # pick one interactively
cplt --resume=my-refactor                       # by name
cplt --continue                                 # most recent in this directory
cplt --remote --name my-task -- -p "fix tests"  # named remote session

# Check the environment before the first run
cplt doctor

# Let Copilot read a shared library directory
cplt --allow-read ~/shared-libs -- -p "use shared-libs"

# Block a path you don't want Copilot to see
cplt --deny-path ~/.config/gh -- -p "refactor auth"

# Extra outbound port, e.g. an external API
cplt --allow-port 8443 -- -p "test the API"

# Localhost for MCP servers or dev servers
cplt --allow-localhost 3000 --allow-localhost 8080 -- -p "use the MCP server"

# All of localhost, needed by Next.js/Turbopack and Vite builds
cplt --allow-localhost-any -- -p "fix the build"

# Pass specific env vars through
cplt --pass-env MY_CUSTOM_VAR --pass-env ANOTHER_VAR -- -p "run with custom config"

# Inherit the full environment (dangerous, debugging only)
cplt --inherit-env -- -p "debug the build"

# Network
cplt --no-proxy -- -p "fix the tests"                    # proxy is on by default
cplt --blocked-domains ./blocked-domains.txt -- -p "refactor"
cplt --allow-private-domain intern.nav.no -- -p "use mcp-onboarding"

# Non-interactive / CI (skip the confirmation prompt)
cplt --yes -- -p "fix the tests"

# Inspect and debug the sandbox itself
cplt --print-profile
cplt --show-denials -- -p "fix the tests"
```

## Configuration

Configuration happens at two levels: global, for developer preferences, and per-repo, for team policy.

```bash
# Browse and change settings interactively
cplt settings

# Set global preferences
cplt config set sandbox.quiet true
cplt config set proxy.blocked_domains "~/.config/cplt/blocked-domains.txt"
cplt config set gh_guard.enabled true
cplt config set git_guard.enabled true

# Set per-repo policy (committed to .cplt.toml)
cplt config set --repo sandbox.allow_jvm_attach true
cplt config set --repo deny.paths "~/secrets"

# Inspect
cplt config show      # effective config (file + defaults)
cplt config explain   # every key with its description
```

`cplt settings` is the interactive editor, with Effective, Global, and Repository views, search, staged changes, and an explicit confirmation before it saves anything security-sensitive. `cplt config` stays the stable non-interactive interface for scripts and CI. Repository proposals are still committed and approved separately with `cplt trust`. The editor never commits or auto-approves them.

Precedence runs CLI flags, then the global config file at `~/.config/cplt/config.toml`, then built-in defaults. Per-repo config in `.cplt.toml` is a separate layer rather than a rung on that ladder: `[deny]` tightens unconditionally, and approved permissions are additive only, so a repo can enable a feature but can never switch off something set by a CLI flag or global config.

A `.cplt.toml` in the repository root carries team policy:

```toml
[deny]                    # Applied automatically, no opt-in needed
paths = ["~/secrets", "~/.vault-token"]
env = ["VAULT_TOKEN", "DATABASE_URL"]

[propose]                 # Requires developer approval (cplt trust accept)
gh_guard = true
git_push_prevention = true
allow_jvm_attach = true
allow_docker = true

[propose.allow]
ports = [5432]
localhost = [3000]
socket = ["/var/run/docker.sock"]
```

cplt reads it from `git HEAD`, so the agent cannot tamper with its own policy mid-session, and trust approvals are pinned to the file's content. In CI and scripts, where nobody can answer a prompt, `--accept-repo-config` approves the file's proposals for that one run without persisting any trust. `cplt init` writes one for you by detecting the project's tooling:

```bash
cplt init             # preview detected permissions
cplt init --write     # write .cplt.toml to disk
cplt init --quiet     # output only TOML (pipe-friendly)
cplt init --global    # generate a personal ~/.config/cplt/config.toml
```

It knows JVM (Gradle/Maven), Node.js, Docker, Python, Rust, Go, Playwright, Spring Boot, Ktor, TestContainers, Next.js, Vite, Flyway, Cypress, and environment secrets from `.env.example`. Dangerous permissions come out of the generator with a risk warning attached. `--global` looks at machine-level things instead: Playwright browsers, GPG signing, registry credentials, alternative agents.

Some keys are global-only and rejected from `.cplt.toml` because they are machine-specific or a local preference: `sandbox.agent`, `sandbox.quiet`, `sandbox.yes`, `sandbox.validate`, `sandbox.scratch_dir`, `sandbox.pass_env`, `sandbox.inherit_env`, `sandbox.allow_cache_exec`, `sandbox.allow_cache_exec_any`, `proxy.enabled`, `proxy.port`, `proxy.log_file`, `proxy.log_level`, `proxy.blocked_domains`, `proxy.allowed_domains`, and every `[gh_guard]`, `[git_guard]`, and `[audit]` key.

Full details, including the trust model, path expansion rules, and the complete config file reference: [docs/configuration.md](docs/configuration.md).

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

The security model is a deny-by-default filesystem with kernel enforcement. On macOS, and on Linux with kernel 6.7+ (Landlock ABI v4), the network is restricted to port 443 by default, with `--allow-port` for extras. On older Linux kernels the CONNECT proxy provides that restriction instead, which is why it is enabled by default. SSH agent access and localhost outbound are blocked in the kernel on macOS. On Linux neither is: port-based Landlock rules cannot tell localhost from a remote host, and unix socket `connect()` is not gated by Landlock below kernel 7.1, so apart from the sockets bubblewrap masks the withheld `SSH_AUTH_SOCK` is the only thing standing between the agent and your loaded keys. The profile generator discovers your environment (`cplt doctor` shows the same probe results) and emits rules only for tool directories that actually exist on disk. Fewer rules, tighter sandbox.

- **macOS**: a Seatbelt/SBPL profile is generated and handed to `sandbox-exec`
- **Linux**: Landlock LSM rules plus a seccomp-BPF filter, applied via `pre_exec` (kernel 5.13+, TCP port filtering on 6.7+)

Internals and module layout: [docs/architecture.md](docs/architecture.md). Threat model, defense layers, and honest gaps: [SECURITY.md](SECURITY.md).

## Security

One static binary, minimal dependencies, no runtime services, no telemetry. Three defense layers, with clear boundaries between them:

| Layer | Enforcement | Bypassable? | What it protects |
|---|---|---|---|
| 1. Kernel sandbox | macOS Seatbelt / Linux Landlock+seccomp | ❌ No | File access, exec, network ports |
| 2. Network proxy | CONNECT proxy, domain filtering | ❌ No (within the sandbox) | Outbound connections, exfiltration |
| 3. Command guard | PATH-based wrapper scripts | ⚠️ Soft barrier | Pushes, merges, releases, API writes |

What cplt protects against:

- Secret exfiltration (SSH keys, cloud credentials, `.env` files): kernel-blocked
- Unauthorized code execution from temp dirs: kernel-blocked
- Persistence via cache-dir binaries: kernel-blocked, since those dirs are denied exec
- Persistence via git hooks in the project: `.git/hooks` is write-denied at the kernel on macOS. On Linux, with Landlock and no Bubblewrap, it stays writable, and cplt's own parent-side `git` then runs with `core.hooksPath=/dev/null` so it never executes a planted hook, though a `git` you run yourself still will
- Persistence via package-manager tool dirs that are both writable and executable (mise shims, `PNPM_HOME`, `~/.deno/bin`, `~/.bun/bin`): write is granted there so `pnpm add -g` and friends work in-sandbox, so an agent can leave a binary behind that a *later* shell picks up off your `PATH`
- A planted binary hijacking the **agent** cplt launches: at launch and audit, cplt resolves the helpers it runs itself (`git`, `bwrap`, `sandbox-exec`, `mise`, and the `gh` it reads a token from) from fixed system directories rather than `PATH`, but the agent binary itself runs from wherever it was discovered, which for an npm-global install is commonly under a writable mise or node tree
- `cplt doctor`: its version probes (`gh`, `copilot`, `uname`, and each agent it finds) are plain `PATH` lookups run in the parent, so a planted binary executes there. The launch and audit paths do not use them
- Data exfiltration to unauthorized domains: proxy-blocked
- Accidental pushes to main and PR merges without review: guard-blocked

What cplt does not protect against:

- Malicious code already inside the project directory. The agent has full read/write there
- Logic bugs the agent introduces. You still review the code
- A sophisticated adversary bypassing the command guard. Use server-side branch protection
- Network attacks on allowed domains. If github.com is allowed, the agent can read and write there
- macOS Keychain access, which Copilot auth needs. Contents are password-protected

Our priorities, in order: **correct** (every claim is tested, every edge case has a CVE or research reference), **transparent** ([SECURITY.md](SECURITY.md) hides nothing), **simple** (one static binary, zero config required, sane defaults), and **useful** (get out of the way and let the agent work, safely).

More: [docs/security.md](docs/security.md) · [SECURITY.md](SECURITY.md)

## Network and proxy

The proxy is **on by default**. All outbound traffic from Copilot CLI, `gh`, and `curl` goes through a localhost CONNECT proxy via `HTTP_PROXY`/`HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1`. It listens on an OS-assigned ephemeral port, so nothing collides. You get connection logging in real time, domain blocking, domain allowlisting, a persistent audit log, and the same port policy the sandbox enforces (443 plus anything in `allow.ports`).

```bash
cplt --proxy-forced -- -p "fix tests"                 # force all egress through the proxy
cplt --no-proxy -- -p "fix tests"                     # disable for one run
cplt --blocked-domains blocked-domains.txt -- -p "x"  # block known-bad domains
cplt --allowed-domains allowed-domains.txt -- -p "x"  # allowlist mode
cplt --default-allowlist -- -p "x"                    # fail-closed: only the agent's own domains
cplt --observe-domains -- -p "x"                      # record what the agent contacts, block nothing
cplt --proxy-upstream http://proxy.corp:8080 -- -p "x" # chain through a corporate proxy
```

`--observe-domains-out <FILE>` writes the observed set one domain per line, and
`--proxy-upstream-no-proxy <HOST>` lists hosts to reach directly instead of through
the upstream.

```bash
cplt config set proxy.enabled false
cplt config set proxy.blocked_domains "~/.config/cplt/blocked-domains.txt"
cplt config set proxy.allowed_domains "~/.config/cplt/allowed-domains.txt"
cplt config set proxy.log_file "~/.config/cplt/proxy.log"
```

Proxy-forced mode is opt-in. It restricts kernel TCP egress to the proxy port so a raw socket or an `env -u HTTPS_PROXY` cannot slip past. Enforcement is full on macOS, which pins to `localhost:<proxy_port>`. Linux blocks direct TCP `:443` but keeps a port-based residual, and leaves UDP unrestricted because Landlock gates only TCP connect, until [#114](https://github.com/navikt/cplt/issues/114).

Both lists match the same way: `example.com` covers the exact domain and every subdomain, matching is case-insensitive, and trailing dots are stripped. Blocklist and allowlist files are re-read every five seconds, so you can edit them live. Localhost traffic bypasses the proxy via `NO_PROXY` and never appears in the audit log. `--proxy-timeout <SECONDS>` bounds request and header reads (default 60) and does not tear down established CONNECT tunnels, which may idle for up to an hour.

Every proxy flag, domain-filtering detail, upstream corporate-proxy chaining, and the connection log format: [docs/proxy.md](docs/proxy.md).

## Command guards

Enable them and cplt intercepts `gh` and `git` through wrapper scripts in `$PATH`:

| Command | Action |
|---|---|
| `gh pr merge`, `gh repo delete`, `gh release create` | 🔒 Blocked |
| `git push origin main`, `git push --force` | 🔒 Blocked |
| `gh api` (write to other repos) | 🔒 Scope-checked |
| `gh pr list`, `gh issue list`, `git commit` | ✅ Allowed |
| `git push origin feature-branch` | ✅ Allowed with `protect_default_branch_only` |

This is Layer 3, a soft barrier. It stops a compliant agent from doing something destructive by accident. For a hard boundary, lean on the kernel sandbox and server-side branch protection.

With the gh guard on, cplt also caches the GitHub token at launch and serves it once through the `gh auth token` callback, then deletes the cache. That cuts accidental and environment-based leakage. It is not a boundary against a hostile agent, because the cache lives in the agent's own `TMPDIR` and an agent that reads it before the legitimate consumer still gets the token. [SECURITY.md](SECURITY.md) has the full statement on `block_auth_token`.

Full behavior: [docs/gh-guard.md](docs/gh-guard.md) · [docs/git-guard.md](docs/git-guard.md)

## Known impacts

The sandbox blocks some workflows on purpose. The common ones and their fixes:

| Impact | Fix |
|---|---|
| `.env` files blocked | `cplt config set sandbox.allow_env_files true` |
| npm postinstall hooks blocked | `cplt config set sandbox.allow_lifecycle_scripts true` |
| `go test` / `mise run` blocked (temp exec) | The scratch dir is on by default. If you still need it, `cplt config set sandbox.allow_tmp_exec true` |
| Localhost connections blocked | `cplt config set allow.localhost 3000`, or `cplt config set sandbox.allow_localhost_any true` |
| Docker blocked | `cplt config set sandbox.allow_docker true` ⚠️ |
| SSH blocked | Use HTTPS remotes instead |
| GPG signing disabled | `cplt config set sandbox.allow_gpg_signing true` |
| JVM MockK/Mockito fails | `cplt config set sandbox.allow_jvm_attach true` |
| `dotnet build` MSBuild worker nodes blocked | `cplt config set sandbox.allow_msbuild true` |
| Private registry creds blocked | `cplt config set allow.read "~/.m2/settings.xml"` |
| Playwright browsers won't launch | `cplt config set sandbox.allow_cache_exec ms-playwright` |

**Git commit and push work out of the box** over HTTPS, no extra flags. Three prerequisites: use HTTPS remotes rather than SSH (`git remote set-url origin https://github.com/org/repo.git`, or rewrite globally with `git config --global url."https://github.com/".insteadOf "git@github.com:"`), run `gh auth login` once outside the sandbox, and run `gh auth setup-git` if the credential helper is not configured yet. SSH is blocked because the agent socket unlocks *every* loaded key and can authenticate to any host, while the `gh` credential helper is scoped to GitHub.

**Gradle 9+ runs its own nested sandbox, and cplt turns it off.** Since Gradle 8.8 the daemon wraps itself in `sandbox-exec` (controlled by `GRADLE_MACOS_SANDBOX`, previously the `org.gradle.daemon.sandbox` property). macOS does not support nested `sandbox-exec` calls, so the inner sandbox fails with "Operation not permitted" on socket operations. cplt injects `GRADLE_MACOS_SANDBOX=off`, since it already provides kernel-level sandboxing. This is a [known upstream issue](https://github.com/gradle/gradle/issues/29476) that hits any tool wrapping Gradle in an outer sandbox. Override with `--pass-env GRADLE_MACOS_SANDBOX` if you really want Gradle's own sandbox.

Every impact, with the per-tool tables, JVM and Kotlin daemon notes, GPG troubleshooting, and the private-registry platform differences: [docs/known-impacts.md](docs/known-impacts.md).

## Limitations

### macOS

- `sandbox-exec` is deprecated. Apple has not removed it, but may in a future macOS version.
- SBPL has no domain-based filtering. The optional CONNECT proxy provides domain blocking instead.

### Linux

- Kernel 5.13+ required, with Landlock LSM enabled.
- TCP port filtering needs kernel 6.7+. Older kernels get filesystem-only enforcement.
- Landlock cannot deny subpaths within allowed paths, so `.env` read/write/delete inside the project dir is not kernel-enforced. `.git/hooks` writes are blocked when Bubblewrap is active.
- `--deny-path` requires Bubblewrap. It is enforced through mount masks when bwrap is active. Without it, Landlock is allowlist-only and cplt warns about the deny instead of applying it.

More: [docs/security.md](docs/security.md#limitations)

## Contributing

Contributions are welcome.

```bash
git clone https://github.com/navikt/cplt.git && cd cplt
git config core.hooksPath hack    # enables pre-commit fmt + clippy checks
mise run check                    # runs fmt, clippy, and tests
```

Open an issue before starting a large change. Every PR has to pass CI (fmt, clippy, tests).

## References

- [SECURITY.md](SECURITY.md), the full security model, threat analysis, test strategy, and prior art
- [Apple sandbox-exec(1)](https://keith.github.io/xcode-man-pages/sandbox-exec.1.html)
- [Chromium Seatbelt V2 Design](https://chromium.googlesource.com/chromium/src/sandbox/+show/refs/heads/main/mac/seatbelt_sandbox_design.md)
- [Landlock LSM documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [seccomp-BPF documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [michaelneale/agent-seatbelt-sandbox](https://github.com/michaelneale/agent-seatbelt-sandbox)

## License

[MIT](LICENSE)
