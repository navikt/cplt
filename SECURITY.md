# Security Model

This document describes the security architecture of cplt, the threat model it addresses, the defense layers it implements, and how they are validated through automated testing.

## Supported Agents

cplt sandboxes AI coding agents — currently **GitHub Copilot CLI**, **[OpenCode](https://opencode.ai/)**, **Google Gemini CLI**, **[Antigravity CLI](https://github.com/google-antigravity/antigravity-cli)**, **[Pi](https://github.com/earendil-works/pi)**, and **[Claude Code](https://docs.anthropic.com/en/docs/claude-code)**. All share the same core sandbox infrastructure (deny-default Seatbelt/Landlock profile, env sanitization, scratch dir), with agent-specific adaptations:

| Property        | Copilot                             | OpenCode                                                            | Gemini                                    | Antigravity                                 | Pi                                          | Claude Code                                  |
|-----------------|-------------------------------------|---------------------------------------------------------------------|-------------------------------------------|----------------------------------------------|---------------------------------------------|----------------------------------------------|
| Auth mechanism  | GitHub token (Keychain, `GH_TOKEN`) | `/connect` device flow → `auth.json`, or API keys                   | Google OAuth (browser) or API key         | Google OAuth (browser / keyring session)     | API keys (Anthropic, OpenAI, Gemini, etc.)  | OAuth token (Keychain / `~/.claude`) or API key |
| Auth in sandbox | Token served via one-time file read (gh guard) or Keychain | Copilot auth stored in data dir; third-party keys need `--pass-env` | OAuth stored in `~/.gemini/`; key needs `--pass-env` | OAuth/session data stored in `~/.gemini/*` | Keys need `--pass-env`             | OAuth stored in `~/.claude`/Keychain; keys need `--pass-env` |
| Config dir      | `~/.copilot` (read/write)           | `~/.config/opencode` (read-only)                                    | `~/.gemini` (read/write)                  | `~/.gemini/config` (read/write)              | `~/.pi` (read/write)                       | `~/.claude` + `~/.claude.json` (read/write)  |
| Data dir        | `~/Library/Caches/copilot`          | `~/.local/share/opencode` (write, no exec)                          | N/A (in config dir)                       | `~/.gemini/antigravity-cli` (read/write)     | `~/.pi/agent/bin` (read + exec)             | N/A (in config dir)                          |
| State data dir  | N/A                                 | `~/.local/state/opencode` (write, no exec)                          | N/A                                       | N/A                                          | N/A                                          | N/A                                          |
| Keychain access | Yes (required for token storage)    | No                                                                  | Yes (extension integrity)                 | Yes (OAuth/keyring flow)                     | No                                          | Yes (macOS OAuth token storage)              |
| SEA extraction  | Yes (pre-sandbox)                   | No                                                                  | No                                        | No                                           | No                                          | No                                           |
| Env isolation   | `GH_TOKEN` not injected (one-time file); `COPILOT_*` passed | `GH_TOKEN`, `COPILOT_*` suppressed                                  | `GH_TOKEN`, `COPILOT_*` suppressed        | `GH_TOKEN`, `COPILOT_*` suppressed           | `GH_TOKEN`, `COPILOT_*` suppressed          | `GH_TOKEN`, `COPILOT_*` suppressed; `DISABLE_AUTOUPDATER=1` injected |
| Auto-detected   | Yes (priority 1)                    | Yes (priority 2)                                                    | Yes (priority 3)                          | Yes (priority 4)                             | No (explicit only — name collision risk)    | No (explicit only)                           |

### OpenCode-specific security notes

- **Copilot provider support**: OpenCode can authenticate with your GitHub Copilot subscription via `/connect` device flow. The token is stored in `~/.local/share/opencode/auth.json` — no environment variables needed. This works out of the box in the sandbox.
- **Third-party API keys are opt-in**: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and other provider keys are never passed through by default. Users must explicitly use `--pass-env` for each key. This prevents accidental exposure of credentials to a sandboxed process.
- **Data dir is write+no-exec**: `~/.local/share/opencode/` (sessions, auth, SQLite DB) is writable but has both `(deny process-exec)` and `(deny file-map-executable)` to prevent write+exec persistence attacks.
- **State data dir is write+no-exec**: `~/.local/state/opencode/` (locks, history, statistics) is writable but has both `(deny process-exec)` and `(deny file-map-executable)` to prevent write+exec persistence attacks.
- **Config dir is read-only**: `~/.config/opencode/opencode.json` and related config are readable but not writable, preventing config tampering across unsandboxed runs.
- **Copilot env vars isolated**: `GH_TOKEN`, `GITHUB_TOKEN`, `COPILOT_GITHUB_TOKEN`, and all `COPILOT_*` env vars are suppressed for non-Copilot agents. OpenCode's Copilot provider uses its own auth file instead.

### Gemini-specific security notes

- **OAuth browser flow**: Gemini uses Google OAuth by default, requiring `--allow-browser` for first-time login. Auth tokens are stored in `~/.gemini/`.
- **API key alternative**: `GEMINI_API_KEY` or `GOOGLE_CLOUD_PROJECT` can be used instead of OAuth — must be passed via `--pass-env`.
- **Keychain access enabled**: Gemini uses macOS Keychain for extension integrity verification.
- **Config dir is read/write**: `~/.gemini/` stores auth, settings, sessions, and agents.

### Antigravity-specific security notes

- **OAuth browser flow**: Antigravity uses Google OAuth for login.
- **Keychain access enabled**: Antigravity relies on macOS keyring/Keychain integration as an authentication trade-off, similar to other OAuth-based agents.
- **Config/data dirs are read/write**: `~/.gemini/config/` and `~/.gemini/antigravity-cli/`.

### Pi-specific security notes

- **Not auto-detected**: the `pi` binary name is generic and may collide with other tools. Pi must be explicitly selected via `--agent pi` or `sandbox.agent = "pi"` in config.
- **API keys are opt-in**: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY` are never passed through by default. Users must explicitly use `--pass-env` for each key.
- **Config dir is read/write**: `~/.pi/` stores settings, auth, sessions, and themes.
- **Managed binaries have exec**: `~/.pi/agent/bin/` (bundled `fd`, `rg`) has process-exec permission with an explicit write deny (prevents write+exec persistence even though the parent `~/.pi/` is writable).
- **Copilot env vars isolated**: `GH_TOKEN`, `GITHUB_TOKEN`, and `COPILOT_*` are suppressed for Pi.

### Claude Code-specific security notes

- **Not auto-detected**: select explicitly via `--agent claude` (aliases `cc`, `claude-code`) or `sandbox.agent = "claude"` in config.
- **Subscription auth works out of the box**: the OAuth token lives in `~/.claude/.credentials.json` (Linux) or the macOS login Keychain ("Claude Code-credentials"). Both are exposed to the sandbox, so the subscription flow needs no env var. This grants the sandboxed agent its own credentials — an inherent trade-off, same as Copilot's Keychain access.
- **API keys are opt-in**: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`), and Bedrock/Vertex routing vars (`CLAUDE_CODE_USE_BEDROCK`, `AWS_BEARER_TOKEN_BEDROCK`, `CLAUDE_CODE_USE_VERTEX`, `ANTHROPIC_VERTEX_PROJECT_ID`, `GOOGLE_CLOUD_PROJECT`) are never passed by default — use `--pass-env`. Because subscription OAuth works without any env var, cplt does **not** emit the "needs auth" warning for Claude Code.
- **Config dirs are read/write**: `~/.claude/` (sessions, projects, history, settings, credentials) and the top-level `~/.claude.json`.
- **Host-persistence guard**: within the writable config dir, `statusline.sh` and `plugins/` are explicitly write-denied. These auto-execute the next time `claude` runs *outside* the sandbox, so a compromised agent could otherwise plant code that escapes the sandbox via the next launch. `settings.json`, `commands/`, `agents/`, and `skills/` stay writable — Claude legitimately authors them and they require explicit user invocation rather than auto-firing. **macOS-only**: like `DENIED_HOME_SUBPATHS`, Landlock cannot deny a subpath inside an allowed directory, so on Linux these remain writable (the residual `mcpServers` risk in `~/.claude.json` is also unenforceable there). Treat write access to a relocated `CLAUDE_CONFIG_DIR` the same way.
- **`CLAUDE_CONFIG_DIR` is supported**: it is on the env allowlist and, when set, `Agent::Claude.config_dirs()` grants that directory in place of `~/.claude`. Both halves are required — granting the path without passing the variable (or vice versa) would break auth/config inside the sandbox.
- **Auto-update disabled**: `DISABLE_AUTOUPDATER=1` is injected. Claude Code has no `--no-auto-update` flag, and a self-update inside the sandbox is a persistence vector that would also fail against read-only install paths.
- **Copilot env vars isolated**: `GH_TOKEN`, `GITHUB_TOKEN`, and `COPILOT_*` are suppressed for Claude Code.

## Threat Model

cplt assumes the sandboxed agent is **untrusted** — executing arbitrary code suggestions on your machine. The threat model covers:

| Threat | Example | Defense layer |
|---|---|---|
| **Credential theft** | Read `~/.ssh/id_ed25519`, `~/.aws/credentials` | Seatbelt deny rules (macOS) / Landlock deny (Linux) |
| **Data exfiltration** | POST secrets to `https://evil.com/collect` | Filesystem isolation (credentials unreadable) |
| **Secret file access** | Read `~/.netrc`, `~/.npmrc`, `~/.vault-token` | Seatbelt deny rules (macOS) / Landlock deny (Linux) |
| **Destructive GitHub ops** | `gh repo delete`, `gh pr merge`, `gh release create` | gh guard command interception (opt-in) |
| **Unreviewed code push** | `git push origin main` | git guard command interception (opt-in) |
| **Git alias push bypass** | `git -c alias.p=push p origin main` | git guard blocks `-c alias.*` + denies unknown subcommands |
| **Git subtree push bypass** | `git subtree push --prefix=lib origin main` | `subtree` in explicit block list + deny-unknown policy |
| **Multi-refspec bypass** | `git push origin feature main` | git guard checks ALL refspecs, not just first |
| **Token exfiltration via CLI** | `gh auth token` prints raw token | gh guard serves cached token once at startup, deletes file — subprocesses get nothing |
| **Cross-repo operations** | `gh pr close -R other-org/other-repo` | gh guard scope checking against current repo |
| **Org/user data enumeration** | `gh api /orgs/.../audit-log` leaks PII | gh guard restricts API to `/repos/{current-repo}/...` endpoints only |
| **DNS rebinding SSRF** | Domain resolves to `127.0.0.1` after check | Post-DNS-resolution IP validation; `--allow-private-domain` opt-in bypass for explicitly trusted internal domains |
| **Sandbox profile injection** | Path with `\n(allow file-read* (subpath "/"))` | SBPL path character validation (macOS) |
| **Temp file symlink attack** | Symlink at predictable `/tmp/cplt.sb` | Unique filename + `O_CREAT\|O_EXCL` |
| **Write-then-exec in /tmp** | Drop binary in `/tmp`, execute it | Seatbelt deny (macOS) / Landlock deny (Linux); `--scratch-dir` provides safe alternative |
| **Cloud metadata access** | Fetch `169.254.169.254` or CGNAT range | Comprehensive private IP blocklist |
| **Cross-project access** | Read files outside project directory | Seatbelt subpath (macOS) / Landlock ruleset (Linux) |
| **Process-group escape** | Kill parent, children continue unsandboxed | Signal forwarding (SIGTERM, SIGHUP) |
| **Env var credential theft** | Read `AWS_SECRET_ACCESS_KEY` from env | `env_clear()` + safe allowlist |
| **Persistence via native modules** | Replace `keytar.node` with malware | Deny writes to `~/.copilot/pkg` |
| **Git hook injection** | Write post-checkout hook that runs outside sandbox | Seatbelt write-deny (macOS); **Landlock leaves project `.git/hooks` writable** — env hardening does NOT stop a planted hook running unsandboxed on the next `git` run; the *direct* file-planting vector is mitigated when Bubblewrap re-binds `.git/hooks` read-only (Linux). **Residual:** `.git/config` stays writable, so `core.hooksPath` can still redirect hooks to a writable dir — a partial, not complete, mitigation |
| **Git config hijacking** | Set `core.hooksPath=/tmp/evil` or URL redirect | Seatbelt write-deny (macOS); **Linux leaves `.git/config` writable** — Bubblewrap deliberately does NOT re-bind it read-only (that would break legit `git config user.email/name`, `git remote add`, `git push -u`, and risk a stale `.git/config.lock` blocking the user's next out-of-sandbox git). The injected `GIT_CONFIG_*` overrides constrain config resolution for in-sandbox git runs, and the proxy blocks redirected fetches (Linux) |
| **Submodule supply chain** | Modify `.gitmodules` to point to malicious repo | Seatbelt write-deny (macOS); **Linux leaves `.gitmodules` writable** — Bubblewrap deliberately does NOT re-bind it read-only (`git submodule add` writes it); proxy domain filtering limits reachable clone targets (Linux) |
| **Syscall abuse** | `ptrace`, `mount`, `kexec_load` | seccomp-BPF filter (Linux) |

### Platform enforcement comparison

| Protection | macOS (Seatbelt) | Linux (Landlock + seccomp) | Linux (+ Bubblewrap) |
|---|---|---|---|
| Credential files (~/.ssh, ~/.aws) | ✅ Kernel deny | ✅ Not in ruleset (deny-by-default) | ✅ Landlock (deny-by-default) |
| Project .env file read/write/delete | ✅ Kernel deny | ⚠️ Proxy blocks exfiltration | ⚠️ Proxy blocks exfiltration |
| .git/hooks write in project | ✅ Kernel deny | ❌ Writable (Landlock can't sub-deny; env hardening does NOT block hook planting) | ⚠️ Re-bound read-only (blocks direct file planting; `core.hooksPath` via writable `.git/config` is a residual) |
| .git/config write in project | ✅ Kernel deny | ❌ Writable (env hardening constrains in-sandbox config resolution only) | ❌ Deliberately writable (read-only would break git config/remote ops + risk stale `.git/config.lock`) |
| .gitmodules write in project | ✅ Kernel deny | ❌ Writable (Landlock can't sub-deny) | ❌ Deliberately writable (`git submodule add` writes it) |
| .cplt.toml write in project | ✅ Kernel deny | ❌ Writable (Landlock can't sub-deny) | ✅ Re-bound read-only if present |
| Network: outbound port filtering | ✅ Kernel (all versions) | ✅ Kernel (6.7+) / ⚠️ Proxy only (<6.7) | ✅ Same as Landlock (no net namespace) |
| Network: localhost isolation | ✅ Kernel deny | ⚠️ Proxy domain filtering | ⚠️ Proxy domain filtering (no net namespace) |
| Network: force all egress through proxy (`proxy.forced`, opt-in) | ✅ Kernel pins to `localhost:<proxy_port>` (full) | ⚠️ Kernel blocks direct `:443`; port-based residual `evil.com:<proxy_port>` until [#114](https://github.com/navikt/cplt/issues/114) | ⚠️ Same as Landlock (no net namespace) |
| Exec from /tmp | ✅ Kernel deny | ✅ Landlock deny | ✅ Landlock deny |
| Dangerous syscalls | N/A (Seatbelt covers) | ✅ seccomp-BPF | ✅ seccomp-BPF |
| PID namespace isolation | N/A (not applicable) | ❌ Not available | ✅ Kernel namespace |
| Mount namespace isolation | N/A (not applicable) | ❌ Not available | ✅ Kernel namespace |
| User namespace (unprivileged) | N/A (not applicable) | ❌ Not available | ✅ Kernel namespace |
| --deny-path / deny.paths | ✅ Kernel deny | ❌ No effect (warned) | ✅ Mount-masked (files read as EACCES, dirs appear empty; the real content is unreachable) |

Legend: ✅ = kernel-enforced, ⚠️ = defense-in-depth (proxy/env), ❌ = not available

### Linux namespace isolation (Bubblewrap)

On Linux, cplt can optionally layer **Bubblewrap** (`bwrap`) on top of Landlock + seccomp-BPF. Bubblewrap is used by Flatpak and provides battle-tested, unprivileged namespace setup. It is **defense-in-depth for the Landlock/seccomp layer, not a replacement for it** — Landlock (filesystem/network access control) and seccomp (syscall filtering) remain the enforcing boundary; bwrap adds process, IPC, and hostname isolation plus a private `/tmp` around them.

**What bwrap adds:**

1. **PID namespace** — the agent cannot see or signal host processes. `ps` shows only the agent's own process tree, preventing process enumeration attacks.
2. **IPC / UTS / cgroup namespaces** — no shared SysV IPC, an isolated hostname, and an isolated cgroup view.
3. **Mount namespace** — the whole host filesystem is bind-mounted **read-only** (`--ro-bind / /`); write access is granted only at the specific paths carrying a writable Landlock rule (re-bound writable at their real locations). The host root is therefore *enumerable* inside the namespace — the mount namespace only changes the mount topology, it does **not** hide arbitrary files. Confidentiality is Landlock's job (deny-by-default): a path with no read rule is denied by Landlock even though it appears in the mount table.
4. **Private `/tmp`** — `/tmp` is a fresh, empty `tmpfs` that carries no exec-bearing Landlock rule, so the "no exec from `/tmp`" guarantee holds. The scratch dir (write+exec) is kept at its real path and is never overlaid on `/tmp`; a writable path that legitimately lives under `/tmp` (e.g. a `--project-dir` in `/tmp`) is re-bound *after* the tmpfs so it stays usable.
5. **User namespace** — unprivileged operation, no root required. The agent maps to the **invoking host UID** (there is no UID-0 mapping) and holds no real capabilities on the host.
6. **Git-persistence read-only re-bind** — the project's `.git/hooks` and `.cplt.toml` live *inside* the writable project tree, which Landlock cannot carve a sub-deny out of, so on the Landlock-only path they stay writable (a persistence-escape gap vs macOS). When bwrap is active these two pre-existing paths are re-bound **read-only** (`--ro-bind`, emitted after the writable project bind so it shadows it): an agent can no longer plant a `.git/hooks/post-commit` that runs unsandboxed on the next `git` run, nor drop a `.cplt.toml` that relaxes the next session's sandbox. In a git **worktree** the project's `.git` is a gitdir *pointer file* (so `<project>/.git/hooks` does not exist) and the real hooks live under the shared common dir that the sandbox grants write access to, so `<git_common_dir>/hooks` is re-bound **read-only** too — otherwise the worktree persistence vector would be missed. The set is **deliberately narrow**. `.git/config` and `.gitmodules` are **left writable on purpose** — read-only binding them would break common, legitimate in-sandbox git operations (`git config user.email/user.name` identity setup, without which the next `git commit` fails "Please tell me who you are"; plus `git remote add`, `git push -u` upstream tracking, and `git submodule add`, which writes `.gitmodules`) and, because git rewrites config via a `.git/config.lock` + rename, a denied write could leave a **stale `.git/config.lock`** that blocks the user's next out-of-sandbox git. This also matches the git command guard, which explicitly allows `git config user.name`. **Residuals:** (a) because `.git/config` stays writable, an agent can still set `core.hooksPath` to redirect hooks into a writable directory — the `.git/hooks` read-only bind mitigates the *direct* file-planting vector only, not all git-hook persistence; (b) a read-only bind only protects paths that *already exist* at launch (bwrap cannot bind a nonexistent source), so a not-yet-created `.cplt.toml` can still be created; (c) submodule hooks (`.git/modules/<name>/hooks`) are not covered; and (d) this mitigation requires bwrap — the Landlock-only path remains exposed.

Bubblewrap **deliberately does not** create a network namespace (see limitations below), so it is **not a network or confidentiality boundary**.

**Layering — how Landlock + seccomp stay enforced (fail-closed):**

`bwrap` needs `unshare`/`mount`/`pivot_root` to build the namespaces — exactly the syscalls our seccomp filter `EPERM`s, and the bind-mount sources are what a restrictive Landlock domain would block. So Landlock and seccomp are **not** applied to the `bwrap` process; they are applied to the **agent**, inside the namespaces, after bwrap finishes setup:

```text
cplt ──exec──▶ bwrap (creates namespaces, unrestricted)
                 └─exec──▶ cplt re-entry helper (in-namespace)
                             │  applies Landlock + seccomp bound to the
                             │  inodes visible *inside* the namespaces
                             └─execve──▶ agent (Landlock + seccomp enforced)
```

The re-entry helper is this same cplt binary, dispatched by an `.init_array` constructor keyed on the `__CPLT_BWRAP_POLICY_FD` environment variable; the Landlock policy and agent argv arrive over an **inherited pipe** (nothing is written to disk, so the fresh `--tmpfs /tmp` cannot hide it). Because the helper opens its Landlock rule paths *inside* the namespaces, the effective policy is identical to the non-bwrap path. If any step of the helper fails it `_exit(126)`s **before** the agent runs — the agent is never executed unsandboxed. A one-byte confirm pipe lets the parent detect that the inner sandbox was applied; on auto-detect a missing confirmation degrades gracefully to the direct Landlock+seccomp path, while explicit `--use-bubblewrap` treats it as a hard error.

**Activation:**

- **Auto-detect (default):** if `bwrap` is in PATH and can actually create the namespaces (probed by running the real `build_bwrap_args` output against `/bin/true`), it is used automatically. Falls back to Landlock+seccomp otherwise.
- **Explicit enable:** `--use-bubblewrap` or `sandbox.use_bubblewrap = true` — hard-fails if bwrap is unavailable rather than silently falling back.
- **Explicit disable:** `--no-bubblewrap` or `sandbox.use_bubblewrap = false` — uses Landlock+seccomp only. If both are given, off wins.

**Graceful degradation:** Bubblewrap requires a kernel with unprivileged user namespaces enabled. On systems without bwrap or namespace support, cplt falls back to Landlock + seccomp-BPF (still providing the full filesystem and syscall isolation — bwrap changes the process/mount topology, not the access-control policy).

**What bwrap does NOT provide:**

- **No network isolation.** There is no network namespace: the host network is shared **by design** so the sandboxed agent can reach cplt's CONNECT proxy on `127.0.0.1`. Outbound control stays with Landlock TCP port rules (ABI v4+) and the proxy — exactly as on the non-bwrap path. Kernel-level network isolation (a private netns with the proxy bridged in) is future work tracked in [issue #114](https://github.com/navikt/cplt/issues/114).
- **No filesystem confidentiality from the mount namespace.** The full host filesystem is enumerable read-only; Landlock, not the mount namespace, is what denies reads.
- **No UID remapping.** The host UID is visible inside the user namespace (asserted by an integration test); there is no root/UID-0 illusion.

**Security model summary:** the layers, honestly attributed —
- Filesystem: **Landlock** (deny-by-default) is the access control; the mount namespace only makes the host root read-only and provides a private `/tmp`.
- Network: **proxy** (domain filtering) + **Landlock** port filtering (6.7+). Bubblewrap adds nothing here.
- Syscalls: **seccomp-BPF** (ptrace, mount, kexec_load, unshare, … blocked), applied to the agent inside the namespaces.
- Processes: **PID namespace** (host process tree invisible), plus IPC/UTS/cgroup isolation.

**Installation:**
```bash
# Debian/Ubuntu
sudo apt install bubblewrap

# Fedora/RHEL
sudo dnf install bubblewrap

# Arch
sudo pacman -S bubblewrap
```

### Out of scope

- **TLS interception** — the proxy sees CONNECT targets (hostname:port) but not request bodies or responses
- **Kernel exploits** — we rely on Apple's Seatbelt (macOS) and Landlock/seccomp (Linux) enforcement being correct
- **Keychain isolation** (macOS) — Copilot requires Keychain access for auth; this is an accepted trade-off. `mach-lookup` is blanket because Node.js needs it for DNS, Security framework, and system services. The **clipboard** (`com.apple.pasteboard`) is reachable via the same blanket allow; use `--deny-clipboard` to add a targeted deny that blocks only the pasteboard service while leaving all others intact.
- **sandbox-exec deprecation** (macOS) — Apple marks it deprecated but has not removed it; Chromium and VS Code still use it
- **Landlock subpath limitations** (Linux) — Landlock cannot deny access to subpaths within allowed directories. If a parent directory is allowed, all children are allowed. This means certain fine-grained macOS rules (e.g., deny `.config/gh/extensions` while allowing `.config/gh/hosts.yml`) cannot be replicated on Linux. When Bubblewrap is active, user deny paths (`--deny-path` / `deny.paths`) ARE enforced despite this, via mount masks (see the platform comparison table); the built-in fine-grained rules remain macOS-only.
- **Code quality** — the sandbox cannot judge whether code written by Copilot contains backdoors; that's a code review problem
- **`~/.config/gh/hosts.yml` token** — contains the user's GitHub OAuth token. Copilot needs *a* GitHub token to function (via env var or this file). The token is readable inside the sandbox. If this is a concern, set `GH_TOKEN` env var (passes through allowlist) and add `--deny-path ~/.config/gh` to block the file.
- **Interpreter-based temp execution** — the sandbox blocks *direct* exec from `/tmp` (Mach-O/ELF binaries, dlopen), but cannot block `bash /tmp/evil.sh` or `node /tmp/evil.js` because the exec target is the interpreter (`/bin/bash`, `/usr/bin/node`), not the script file. Sandboxing interpreters would break Copilot.
- **`.vscode/` project configs** — the agent can write `.vscode/tasks.json`, `launch.json`, and `settings.json` which VS Code may auto-execute outside the sandbox. This is an IDE trust boundary issue, not a sandbox scope issue. Mitigation: review `.vscode/` changes in `git diff` before committing; set `"task.autoRunTasks": "off"` in VS Code.
- **Write+exec in home cache dirs** — `~/.gradle`, `~/.m2`, `~/Library/pnpm` (macOS) / `~/.local/share/pnpm` (Linux) have both write and exec permissions. Build tools need write for dependency downloads and exec for build plugins. A rogue agent could write a malicious JAR to `~/.m2` or a Gradle plugin to `~/.gradle`, but the executed code would still be sandboxed. `~/Library/Caches` (macOS) is broadly allowed for dev tool caches (go-build, Homebrew, pip, etc.), but browser and app caches (Chrome, Firefox, Discord, etc.) are denied via regex prefix rules — no allowlist maintenance needed for new dev tools. `--allow-cache-exec <SUBDIR>` opts into the same write+exec trade-off for the named subdir (e.g. `ms-playwright`, `pnpm/dlx`) under `~/Library/Caches` (macOS) or `~/.cache` (Linux): a rogue agent could write a binary there and execute it, but execution remains sandboxed. On Linux the subdir is validated to be a traversal-free relative path before a Landlock execute rule is granted, so a crafted value like `../../bin` cannot escape the cache dir. Prefer `--allow-cache-exec <SUBDIR>` over `--allow-cache-exec-any`, which opens the entire cache tree.
- **Playwright Chromium runtime** (macOS, `allow_cache_exec = ["ms-playwright"]`) — when browser testing is enabled, the sandbox grants elevated system permissions beyond the normal `process-exec` and `file-map-executable` rules: `(allow syscall*)` (all syscalls including Mach traps — Chromium uses undocumented traps that vary by macOS version and cannot be individually enumerated in a stable allowlist), `(allow system-socket (socket-domain AF_UNIX))` (Unix domain sockets for IPC between browser, renderer, and GPU processes), `(allow iokit-open-user-client)` (GPU capability probing — unscoped because IOKit class names are hardware-dependent), and `(allow mach-register)` scoped to `^org\.chromium\..+$` (Crashpad and inter-process IPC — anchored with `$` and requires at least one character after the prefix). Unix socket operations for Chrome's `SingletonSocket` use `[^/]+/[^/]+` for the `var/folders` path segments to prevent matching across directory boundaries. All filesystem, network, and credential denies remain enforced independently. These rules activate when `allow_cache_exec` contains `"ms-playwright"` or any subpath like `"ms-playwright/chromium-1217"` (first path component match) — `allow_cache_exec_any` does not trigger them. Without these rules, `chrome-headless-shell` segfaults (`SEGV_ACCERR`) during browser initialization. **Linux:** `--allow-cache-exec ms-playwright` now grants Landlock execute on `~/.cache/ms-playwright` (the XDG equivalent), so the browser binary can run. The macOS Seatbelt/Mach permissions above have no Linux analogue. The remaining difference is Chromium's *own* sandbox: on Linux it builds a setuid-less sandbox using user namespaces (`unshare`/`setns`/`clone` with `CLONE_NEW*`), but cplt's seccomp-bpf filter denies `unshare`/`setns` with `EPERM` (user-namespace creation is a sandbox-escape primitive — see "Defense layers"). cplt deliberately does **not** relax the seccomp filter for browser testing. Instead, run Chromium with its own sandbox disabled (`--no-sandbox`, or Playwright `chromiumSandbox: false`): cplt's Landlock + seccomp is the enforcing boundary, so Chromium's nested sandbox is redundant inside it. `/dev/shm` is already allowed, so `--disable-dev-shm-usage` is not required.
- **Project build scripts** — the agent can modify `Makefile`, `package.json` scripts, `build.gradle`, `.github/workflows/`, etc. These are legitimate Copilot targets and cannot be blocked. The risk is mitigated by code review (git diff) before running builds or committing.
- **POSIX shared memory** (macOS) — `ipc-posix-shm-*` is allowed because Node.js needs it for DNS and system queries. An agent could theoretically use SHM as an IPC channel to processes outside the sandbox, but this requires a cooperating process already running on the machine.
- **DNS tunneling** — DNS queries are unrestricted on both platforms. Bandwidth is ~15 KB/s max, requires attacker-controlled authoritative DNS, and is detectable with network monitoring.

## Real-World Attack Landscape (2025–2026)

This section documents the attack vectors and infrastructure observed in real supply chain attacks. cplt is designed to mitigate these specific threats.

### Attack kill chain

Supply chain attacks through AI coding agents follow a consistent pattern:

```
1. INFECTION          2. RECONNAISSANCE       3. CREDENTIAL HARVEST    4. EXFILTRATION
postinstall hook   →  hostname, IP, user,  →  ~/.ssh/*, ~/.aws/*,  →  HTTP POST to C2
or patched file       env vars, OS info        .env, npm tokens        or DNS tunnel
```

### Observed incidents

| Incident | Year | Vector | Impact |
|---|---|---|---|
| **Shai-Hulud** | 2025 | Compromised npm maintainer accounts | Self-replicating worm hit 700+ packages, stole npm tokens + AWS keys |
| **CamoLeak** | 2025 | Prompt injection in PR comments | Copilot Chat exfiltrated private code via GitHub image proxy (CVE-2025-59145, CVSS 9.6) |
| **RoguePilot** | 2026 | Prompt injection in GitHub issues | GITHUB_TOKEN leaked from Codespaces, enabling full repo takeover |
| **YOLO Mode** | 2025 | Agent writes to .vscode/settings.json | Auto-approved all commands → RCE (CVE-2025-53773) |
| **MCP Poisoning** | 2026 | Hidden instructions in npm metadata | AI agents extracted SSH keys from dev machines, invisible to user |
| **axios RAT** | 2026 | Trojanized npm package by STARDUST CHOLLIMA | Hidden RAT deployed to any system where AI agent ran `npm install` |

### Exfiltration infrastructure (observed in the wild)

| Category | Domains/services | Why attackers use them |
|---|---|---|
| **Discord webhooks** | `discord.com/api/webhooks/*` | Write-only, no authentication needed, blends with legitimate traffic |
| **Webhook capture** | `webhook.site`, `pipedream.com`, `requestbin.com` | Disposable endpoints, no signup required |
| **Tunneling** | `ngrok.io`, `localtunnel.me`, `serveo.net` | Reverse shells through NAT/firewall boundaries |
| **Paste sites** | `pastebin.com`, `paste.ee`, `hastebin.com` | Credential dump staging for later retrieval |
| **File sharing** | `transfer.sh`, `file.io`, `0x0.st`, `catbox.moe` | Exfiltration of SSH keys and .env files |
| **Telegram** | `api.telegram.org` | Bot API as write-only C2 channel |
| **IP recon** | `ipinfo.io`, `ifconfig.me`, `checkip.amazonaws.com` | Victim network fingerprinting |
| **Cloudflare Workers** | `*.workers.dev` | Free hosting for C2 relays, resistant to takedown |
| **Ethereum dead-drop** | Smart contract → Cloudflare-fronted domains | C2 URL rotation without code changes, impossible to take down |

A curated blocklist of these domains is included in [`blocked-domains.txt`](blocked-domains.txt).

### What gets stolen (in order of attacker priority)

1. **npm/pip tokens** — enables worm propagation (Shai-Hulud: 700+ packages from stolen tokens)
2. **CI/CD tokens** — GITHUB_TOKEN, AWS keys from environment variables
3. **SSH keys** — `~/.ssh/id_*`
4. **Cloud credentials** — `~/.aws/credentials`, `~/.config/gcloud`
5. **Environment files** — `.env`, `.env.local` (API keys, database URLs)
6. **Network topology** — internal IPs, DNS servers, hostnames (recon for lateral movement)

### How cplt defends against each step

| Kill chain step | Attack technique | Sandbox defense | Verdict |
|---|---|---|---|
| **1. Infection** | `postinstall` hook runs code | **Blocked by default.** Hardening injects `npm_config_ignore_scripts=true` and `YARN_ENABLE_SCRIPTS=false` | ✅ **Stopped** |
| **2. Recon** | Read hostname, IP, env vars | Can read process env vars (needed for Copilot), hostname | ⚠️ Partial leak possible |
| **3. Credential harvest** | Read ~/.ssh, ~/.aws, .env | **Kernel-blocked.** macOS Seatbelt denies the read syscall. | ✅ **Stopped** |
| **4a. HTTP exfil** | POST to discord/webhook/C2 | **Partially mitigated.** Only port 443 allowed (HTTPS); localhost blocked; SSH agent blocked. Credentials are unreadable, limiting blast radius. Proxy blocklist helps if enabled. | ⚠️ **Partially mitigated** |
| **4b. DNS tunneling** | Encode data in DNS queries | Not inspected — DNS bypasses the proxy | ❌ **Not stopped** |
| **4c. Reverse shell** | Connect back via ngrok | Non-standard ports blocked; `ngrok.io` blocked when proxy enabled; localhost blocked | ⚠️ **Partially mitigated** |
| **5. Binary staging** | Drop RAT into cache dir and execute | **Kernel-blocked by default.** `~/Library/Caches` has no `process-exec` or `file-map-executable`; `/tmp` exec also denied. `--allow-cache-exec <SUBDIR>` grants exec to a specific subdir (e.g. `ms-playwright`) — write+exec risk applies to that subdir. | ✅ **Stopped** (⚠️ opt-in exemption available) |
| **Worm propagation** | Republish infected packages | Can't read npm tokens (in ~/.npmrc, kernel-blocked) | ✅ **Stopped** |

### Honest gaps

**Network is port-restricted, with optional domain filtering.** SBPL (Seatbelt Profile Language) does not support domain-based filtering at the kernel level. Copilot CLI connects to CDN-backed endpoints (`api.business.githubcopilot.com`) with changing IPs that cannot be enumerated. We allow outbound TCP on port 443 only (use `--allow-port` for extras, e.g. `--allow-port 80` for HTTP). SSH agent access and localhost outbound are blocked at the kernel level. This means:

- A compromised agent CAN make HTTPS requests to attacker-controlled servers on port 443
- A compromised agent CANNOT exfiltrate cloud credentials from env vars (env is sanitized; only safe allowlist passes through)
- A compromised agent CAN exfiltrate project source code and Copilot auth tokens
- A compromised agent CANNOT connect to local services (localhost is blocked on macOS; on Linux, use `--with-proxy` — see [Linux-specific limitations](#linux-specific-limitations))
- A compromised agent CANNOT use loaded SSH keys (unix socket is blocked)
- A compromised agent CANNOT connect on non-standard ports (e.g., 8080, 3000) unless `--allow-port` is used
- A compromised agent CANNOT exfiltrate SSH keys, cloud credentials, or npm tokens (kernel-blocked from reading them)
- A compromised agent CAN request GPG signatures (if `--allow-gpg-signing` is enabled) but CANNOT exfiltrate private keys
- The proxy logs and filters all outbound connections by default, including Copilot CLI traffic (via `NODE_USE_ENV_PROXY=1`). The proxy also enforces port restrictions matching the sandbox policy. Use `--no-proxy` to disable.

**JVM IPv4 stack forcing.** macOS SBPL `"localhost"` filters do not match Java NIO's IPv4-mapped addresses (`::ffff:127.0.0.1`) because SBPL only accepts `*` or `localhost` as the host part (literal IPs are rejected). cplt solves this by injecting `-Djava.net.preferIPv4Stack=true` via `JAVA_TOOL_OPTIONS`, which forces the JVM to use pure AF_INET4 sockets. This means connections to `127.0.0.1` stay as IPv4 and `"localhost:PORT"` rules match correctly. As a result, `--allow-localhost <PORT>` now works for Java — the old `"*:*"` nuclear option is no longer needed. If a user overrides JAVA_TOOL_OPTIONS via `--pass-env`, they lose this protection and should use `--allow-localhost-any` as fallback. On Linux (Landlock), this flag is not injected as the kernel handles addresses differently.

*Mitigation:* Use `--allowed-domains allowed-domains.txt` to restrict traffic to known Copilot endpoints only. Use `--blocked-domains blocked-domains.txt` to block known exfiltration infrastructure. Use `--proxy-log proxy.log` for post-session audit. All traffic, including Copilot's own Node.js connections, routes through the proxy.

**`--allow-private-domain` weakens DNS rebinding protection for named domains.** When a domain is listed in `proxy.allow_private_domains` (or `--allow-private-domain`), the proxy skips the post-DNS private IP check for that domain. This is intentional for corporate intranet services (e.g. `intern.nav.no`) that legitimately resolve to RFC 1918 addresses. The accepted risk: if DNS for a listed domain is poisoned or hijacked, a compromised agent could reach arbitrary private hosts on your internal network — not just the intended service. All other proxy checks (port, allowlist, blocklist) still apply. Only list domains you control and whose DNS you trust.

**`~/.config/gh/hosts.yml` is readable.** When gh guard is enabled, Copilot gets its token via a one-time cached file (deleted after first read). When gh guard is disabled, `gh auth token` is available inside the sandbox. This file contains a GitHub OAuth token. Only `hosts.yml` and `config.yml` are readable (not the entire `.config/gh` directory). With outbound port 443 allowed, a compromised agent could theoretically exfiltrate this token. However, the token grants access to GitHub — which Copilot is already connected to. Users who want to mitigate this can use `--deny-path ~/.config/gh` (Copilot will fall back to Keychain auth).

**`block_auth_token` is best-effort, not a same-UID boundary.** When gh guard is enabled with `block_auth_token` (opt-in), cplt withholds `GH_TOKEN` from the environment and instead caches the token to `$SCRATCH/.gh-token` (mode `0600`), serving it once via the `gh` wrapper's `gh auth token` callback and deleting the file after the first read. This genuinely prevents the token from appearing as an inherited env var in every child's `/proc/*/environ`, and the one-time deletion narrows the file's exposure window. It does **not** make the token confidential against an adversarial agent: the scratch dir *is* the agent's `TMPDIR`, and the `gh` wrapper runs as the agent's own UID inside the sandbox, so anything the wrapper can read the agent can read at the same UID. A same-UID `deny` rule is therefore illusory (and would break the legitimate wrapper read, which happens inside the sandbox), so cplt does not add one. A determined agent that `cat`s `$TMPDIR/.gh-token` before the legitimate consumer still obtains the token. Treat `block_auth_token` as reducing accidental/env-based leakage, not as a boundary against a hostile agent — the token grants access to GitHub, which Copilot is connected to anyway.

*Possible mitigation:* A repo-scoped MCP proxy or fine-grained PAT that limits token scope to the current repository only. See issue #4 for investigation.

**The gh/git guards are a best-effort command filter, not a kernel boundary.** The "gh guard" and "git guard" rows in the threat-model table above describe command-level interception, and three properties bound what they can promise:

- **Opt-in.** Both guards default to `enabled = false` (soft rollout). Out of the box cplt performs **no** gh/git command filtering — the fail-closed posture (block mode, default-deny unknown subcommands, scope check, `block_auth_token`, `allow_api_write=false`) only takes effect once an operator sets `gh_guard.enabled = true` / `git_guard.enabled = true` (or passes the equivalent flags). A user who assumes "cplt guards git" without opting in gets nothing.
- **PATH-shim enforcement.** The guards work by writing `gh`/`git` shims into a scratch `bin/` dir and prepending it to `PATH`; the shim calls back into cplt for a policy decision before `exec`ing the real binary. The real `/usr/bin/git` and `/usr/bin/gh` are untouched, so any agent that invokes the binary by **absolute path** (`/usr/bin/git push`), **escapes the alias** (`\git`, `env git`), **resets `PATH`**, or **shells out from another runtime** (`subprocess.run(["/usr/bin/git", "push"])`) bypasses the guard entirely. Command classification (force-push detection, scope checks, `gh auth token` blocking, DELETE blocking) therefore only constrains a *cooperative* agent that goes through the shim — it is not a boundary against an adversarial one.
- **Repository scope is pinned at sandbox startup.** Before the agent starts, cplt
  invokes the pre-resolved Git binary and reads only the project root's local
  `remote.origin.url`, with config includes and inherited `GIT_*` variables disabled.
  The verified scope is baked into the shim. Successful checks set a host-qualified
  `GH_REPO`, clear `GH_HOST`, and reject conflicting hostname flags before executing
  `gh`; failure to determine startup scope blocks the command. Runtime working
  directories, nested repositories, mutable Git configuration, and environment
  overrides therefore cannot retarget the check.

The guards raise the bar against accidental and prompt-injected-but-cooperative misuse; they are not a substitute for the kernel-enforced filesystem/exec isolation that does hold against an adversarial agent. On the *network* side, proxy-forced mode (issues #53 / #117) is the kernel-backed complement: it forces all egress through the cplt proxy at the packet level rather than via tamperable `HTTPS_PROXY` env vars, so a bypassed `git push` / `gh api` write still has to traverse the proxy. Command-level intent (e.g. `GET` vs `DELETE` to `api.github.com`) remains invisible to a CONNECT proxy, so the guards and the proxy cover different layers.

**DNS tunneling** is the one channel we cannot inspect. However:
- Bandwidth is ~15 KB/s at best (encoding overhead in subdomain labels)
- Requires attacker-controlled authoritative DNS server
- The most valuable targets (credentials, tokens, keys) are kernel-blocked from being read
- Detectable with DNS monitoring (high-entropy subdomain queries to unusual domains)

*Possible mitigation:* Route DNS through a local resolver that logs and rate-limits queries, or block DNS entirely and use a pre-configured resolver for known domains. Practical impact is low given that credentials are already inaccessible.

**Reconnaissance leaks basic host info.** Hostname, IP address, OS version, and the sanitized subset of env vars are readable by any code running inside the sandbox. This is unavoidable — Copilot itself needs this information to function.

*Possible mitigation:* A future hardening category could mask hostname and inject synthetic env values, but this risks breaking tools that depend on accurate system info. Low priority given that recon without credential access has minimal value.

**Project source code is readable and writable.** The agent needs read/write access to the project directory — that's its job. A compromised agent could exfiltrate source code via HTTPS on port 443.

*Possible mitigation:* A read-only project mode (`--read-only-project`) for review-only workflows where the agent should not modify files. Outbound bandwidth tracking could detect bulk exfiltration (large POSTs relative to Copilot's normal API pattern), but would require deep packet inspection.

**`~/.copilot/` session history is broadly accessible.** The sandbox grants read/write to all of `~/.copilot/`, which includes the session store database (`session-store.db`) containing all past conversation history, and `session-state/` with per-session artifacts. Copilot's runtime manages these files from inside the sandbox and requires access to function. A compromised agent could read all past conversations to extract business logic, architecture decisions, or referenced credentials.

*Possible mitigation:* Users concerned about session history exposure can use `--deny-path ~/.copilot/session-state` to block access to other sessions' artifacts (accepting loss of cross-session features). Scoping session store access to the current session only would require changes to Copilot's runtime (the session store database is a single SQLite file).

Since credentials are inaccessible inside the sandbox (both at filesystem and environment level), network-based exfiltration can only leak project source code and `~/.config/gh` tokens — a much smaller blast radius than full credential theft.

## Defense Layers

### Layer 0: Environment Variable Sanitization

By default, `cplt` clears the child process environment and re-adds only safe variables from an allowlist. This prevents credential leakage through inherited env vars.

**How it works:**
1. `cmd.env_clear()` removes all environment variables
2. Variables matching `ENV_ALLOWLIST` (49 safe vars) are re-added from the parent process
3. Variables matching `ENV_PREFIX_ALLOWLIST` (9 prefixes: `LC_*`, `COPILOT_*`, `COREPACK_*`, `MISE_*`, `NVM_*`, `PYENV_*`, `SDKMAN_*`, `YARN_*`, `OTEL_*`) are re-added
4. `--pass-env VAR` adds explicit vars (repeatable)
5. `ENV_ALWAYS_DENY` vars (`NO_COLOR`, `FORCE_COLOR`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`) are always stripped

**Deliberately allowed:** `GH_TOKEN`, `GITHUB_TOKEN`, `COPILOT_GITHUB_TOKEN` — Copilot needs a GitHub token to function. This is an accepted trade-off.

**OpenTelemetry (`OTEL_*`):** OTel configuration vars (e.g. `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`) are allowed via the `OTEL_` prefix. `OTEL_EXPORTER_OTLP_HEADERS` may carry opt-in auth headers (e.g. `Authorization=Bearer <token>`) — this is an accepted trade-off in the same class as `GH_TOKEN`, only present when the user has configured an exporter. The `is_secret_suffix` deny-list still strips any `OTEL_*_TOKEN` / `_AUTH` / `_SECRET` / `_KEY` / `_PASSWORD` / `_CREDENTIALS` vars.

**Deliberately blocked:** `AWS_*`, `AZURE_*`, `NPM_TOKEN`, `DATABASE_URL`, `VAULT_TOKEN`, `SSH_AUTH_SOCK`, Docker vars, CI tokens.

**Git configuration:** `~/.gitconfig`, `~/.gitconfig.local`, and
`~/.gitignore_global` are exact read-only exceptions so normal Git and `gh`
workflows can load conventional user configuration. The standard XDG Git config
is also read-only (the `~/.config/git` directory on Linux because Landlock rules
are recursive). Other include files remain blocked unless explicitly allowed.
These files should not contain plaintext credentials; credential directories and
SSH/GPG private keys remain denied.

**Escape hatch:** `--inherit-env` disables sanitization and inherits all env vars (still strips `ENV_ALWAYS_DENY`). This is dangerous and should only be used for debugging.

### Layer 0.25: Security Environment Hardening

Beyond sanitization, `cplt` injects hardening environment variables that disable dangerous tool behaviors inside the sandbox. This is a declarative, category-based system designed for extensibility.

**How it works:**
1. `HARDENING_ENV_VARS` is a compile-time list of `(name, value, category)` tuples
2. Each variable belongs to a `HardeningCategory` (e.g., `LifecycleScripts`, `GitHardening`)
3. Variables are injected unless their category has been opted out via CLI flag
4. If a user explicitly passes a variable via `--pass-env`, their value is preserved

**Currently injected variables:**

| Variable | Value | Category | Purpose |
|---|---|---|---|
| `npm_config_ignore_scripts` | `true` | LifecycleScripts | Block npm/pnpm postinstall hooks |
| `YARN_ENABLE_SCRIPTS` | `false` | LifecycleScripts | Block Yarn Berry lifecycle scripts |
| `GIT_TERMINAL_PROMPT` | `0` | GitHardening | Prevent git credential prompts |
| `GIT_CONFIG_COUNT` | `2` | GitSigning | Number of git config overrides |
| `GIT_CONFIG_KEY_0` | `commit.gpgsign` | GitSigning | Override commit signing config |
| `GIT_CONFIG_VALUE_0` | `false` | GitSigning | Disable commit signing (private keys inaccessible) |
| `GIT_CONFIG_KEY_1` | `tag.gpgsign` | GitSigning | Override tag signing config |
| `GIT_CONFIG_VALUE_1` | `false` | GitSigning | Disable tag signing (private keys inaccessible) |

**Why this matters:** Supply chain attacks (e.g., axios March 2026) use `postinstall` hooks to execute malicious payloads. Blocking lifecycle scripts eliminates this attack class — `npm install` still downloads packages, but no arbitrary code runs. Explicit commands like `npm run build` still work normally. Git signing is disabled because `~/.ssh` and `~/.gnupg` are denied by the sandbox — attempting to sign would fail with EPERM. Disabling via env var gives a clean error-free experience.

**Escape hatches:**
- `--allow-lifecycle-scripts` disables the `LifecycleScripts` category. Use when `npm install` requires postinstall hooks (e.g., native module compilation).
- `--allow-gpg-signing` disables the `GitSigning` category and adds targeted SBPL rules for GPG access. See GPG signing risk analysis below.

### Layer 0.5: Native Module Write Protection

The sandbox denies writes to `~/.copilot/pkg/` (where Copilot's native modules like `keytar.node` live). This prevents a persistence attack where a rogue agent replaces a native module with malware that executes *unsandboxed* next time Copilot runs outside `cplt`.

### Layer 0.6: Copilot Install Directory Auto-Detection

When Copilot CLI is installed via a non-standard Node version manager (e.g. `n` at `~/n/`, Volta at `~/.volta/`, custom npm prefix), its package directory falls outside the static `TOOL_READ_DIRS`. At startup, cplt resolves the copilot binary path, walks up at most 4 ancestors looking for a `package.json` with `"name": "@github/copilot"`, and adds the directory to the sandbox read allowlist. Safety checks:
- **Package identity**: parsed via `serde_json` — only the real Copilot package is accepted
- **Unsafe root rejection**: `/`, `$HOME`, `/tmp`, etc. are rejected
- **SBPL injection validation**: path characters validated before profile interpolation

### Layer 0.7: Global Git Hooks Protection

Git's `core.hooksPath` points to a directory of user-configured hooks that run on commit, push, etc. If not allowed, the sandbox causes git to fail with EPERM (instead of ENOENT for missing hooks). cplt auto-detects the hooks path and allows reading it. Safety checks:
- **Write denied**: `(deny file-write*)` explicitly blocks writes to the hooks directory, preventing persistence attacks even if the path overlaps a writable sandbox directory
- **Under `$HOME`**: paths outside the home directory are rejected (prevents arbitrary filesystem reads)
- **Depth ≥ 3**: the path must have at least 3 components under `$HOME` (e.g. `~/.config/git/hooks` is OK, `~/hooks` is too broad)
- **Unsafe root rejection**: `/`, `$HOME`, `/tmp`, etc. are rejected

### Layer 1: Seatbelt Kernel Sandbox (sandbox-exec)

The primary defense is Apple's mandatory access control framework, enforced in the XNU kernel. All restrictions apply to the sandboxed process **and all its children** — there is no way to shed the sandbox after `sandbox_init()`.

#### Profile structure

```
(deny default)                          ← Block everything by default
(import "bsd.sb")                       ← Allow basic system library access
(allow process-exec/fork)               ← Allow running programs
(allow file-read/write project_dir)     ← Project access
(allow file-read ~/.copilot)            ← Auth token access + native modules
(allow file-read ~/.config/gh/hosts.yml)← GitHub CLI auth (2 files only)
(allow file-read ~/.config/git/config)  ← Git config (read-only)
(allow file-read core.hooksPath dir)    ← Global git hooks (auto-detected, if set)
(deny  file-write core.hooksPath dir)   ← Prevent persistence via hook modification
(allow file-read copilot_install_dir)   ← Copilot CLI package dir (auto-detected)
(allow file-read/write /private/tmp)    ← Temp file access
(deny process-exec /private/tmp)        ← But no executing from tmp!
(allow unix-socket .java_pid*)          ← JVM Attach API only (--allow-jvm-attach, regex-restricted)
(deny  unix-socket /tmp/*)              ← All other unix sockets blocked (SSH agent, etc.)
(deny file-* ~/.ssh, ~/.aws, ...)       ← Sensitive dirs blocked
(deny network-outbound (remote tcp))    ← Block all outbound TCP by default
(allow network-outbound *:443)           ← Then allow HTTPS port only (use --allow-port for extras)
(deny network-outbound localhost:*)     ← Block localhost SSRF (default)
(allow network-outbound localhost:PORT) ← Carve-out for proxy (ephemeral port, assigned at runtime)
;; With --allow-localhost-any: replace deny with (allow ... localhost:*)
;; Java IPv4-mapped issue solved by -Djava.net.preferIPv4Stack=true in JAVA_TOOL_OPTIONS
```

> **Network note:** Outbound TCP is restricted to port 443 by default. SSH agent access (unix sockets) is blocked. JVM Attach API sockets (`/tmp/.java_pid*`) are available via `--allow-jvm-attach` (opt-in, regex-restricted to `.java_pid<PID>` only) — all other unix sockets in `/tmp` remain blocked. Localhost outbound is blocked to prevent SSRF. Use `--allow-port` for additional ports. SBPL does not support domain-based rules — filesystem isolation is the primary security control.

**Key design decision**: Deny rules are placed AFTER allow rules. In Seatbelt's evaluation model with `(deny default)`, more-specific rules override broader ones, and later rules take precedence for equal specificity. This means our deny rules for `~/.ssh` correctly override the broader temp/system allows.

#### Protected paths

Directories always denied (read + write):

- `~/.ssh`, `~/.gnupg` — cryptographic keys
- `~/.aws`, `~/.azure` — cloud credentials
- `~/.kube`, `~/.docker` — infrastructure access
- `~/.nais` — Nav platform credentials
- `~/.password-store` — pass password manager
- `~/.config/gcloud` — Google Cloud credentials
- `~/.config/op` — 1Password CLI
- `~/.terraform.d` — Terraform credentials

Directories explicitly allowed (read-only):

- `~/.config/gh` — GitHub CLI credentials (Copilot spawns `gh auth token`; see [Honest gaps](#honest-gaps))

Files always denied (hard blocks):

- `~/.netrc` — HTTP credentials
- `~/.pypirc` — PyPI credentials
- `~/.gem/credentials` — RubyGems credentials
- `~/.vault-token` — HashiCorp Vault

Files denied by default (overridable via `--allow-read` for private registries):

- `~/.npmrc` — npm registry configuration

#### Symlink attack protection
SBPL (macOS Seatbelt) resolves symlink targets at the kernel VFS layer during path evaluation. To verify this behavior, cplt includes integration tests demonstrating that attempts to read a denied file (such as `.env`) via a symlink with an innocuous name are successfully blocked by the kernel.

#### Tool directory permissions

Home tool directories (`~/.cargo`, `~/.nvm`, etc.) use a per-directory permission model (`HomeToolDir`) with granular `process_exec`, `map_exec`, and `write` flags:

| Directory                                                                                     | process-exec | file-map-executable | file-write | Rationale |
|-----------------------------------------------------------------------------------------------|---|---|---|---|
| `.local/bin`, `.mise`, `.nvm`, `.pyenv`, `.cargo`, `.rustup`, `.sdkman`, `go/bin`, `Library/pnpm` | ✅ | ✅ | varies | Contain executable binaries and shims |
| `.gradle`, `.m2`, `.konan`, `go/pkg`                                                          | ❌ | ✅ | varies | JNI/cgo/Kotlin native libs loaded via dlopen, no direct executables |
| `.yarn`                                                                                       | ❌ | ❌ | ✅ | Yarn Berry global cache — JavaScript packages only, no native binaries |
| `Library/Caches`                                                                              | ❌ | ❌* | ✅ | Broad allow for dev tool caches; browser/app caches denied via regex prefix rules (com.apple.*, com.google.*, org.mozilla.*, etc.) — Xcode dev tools (com.apple.dt.*) re-allowed |

\* Exception: `~/Library/Caches/copilot/pkg/` has `file-map-executable` and `process-exec` for Copilot's native modules and helper binaries (`pty.node`, `spawn-helper`, `rg`). A `file-write*` deny prevents write-then-exec attacks. These carve-outs are placed after the broader deny rules (SBPL last-match-wins).

**Security principle:** Every writable+executable directory is a potential binary-drop staging path. By denying both `process-exec` and `file-map-executable` on `~/Library/Caches`, this vector is eliminated at the kernel level. Non-dev caches (browsers, system apps, communication tools) are denied via `DENIED_CACHE_PREFIXES` regex rules in the SBPL profile — new dev tools auto-work without code changes because their cache dirs don't use these prefixes.

#### Scratch directory

When `--scratch-dir` is enabled, cplt creates a per-session directory at `~/Library/Caches/cplt/tmp/{session-id}/` with full `read/write/exec/map-exec` permissions. This is a controlled exception to the TMPDIR exec deny:

- **Why it exists:** `go test`, `mise` inline tasks, and `node-gyp` compile to `$TMPDIR` then execute. The sandbox blocks this, breaking these tools. On macOS, JVM processes also need this because `java.io.tmpdir` defaults to `/var/folders/...` (ignoring `TMPDIR` env var); cplt injects `-Djava.io.tmpdir`, `-Djansi.tmpdir`, and `-Djava.rmi.server.hostname=localhost` via `JAVA_TOOL_OPTIONS` to redirect JVM temp usage to the scratch dir and keep RMI communication on localhost.
- **Security model:** The scratch dir has both write+exec — this is the accepted trade-off. Mitigations:
  - **Scoped path:** Only the specific session subpath has exec, not all of `~/Library/Caches/cplt/`
  - **0700 permissions:** Owner-only access, verified at creation
  - **Symlink rejection:** Base path is validated as a real directory, not a symlink
  - **Owner check:** `stat()` verifies the directory owner matches the current uid
  - **SBPL injection guard:** Path validated against metacharacters before interpolation
  - **Ephemeral:** Cleaned up on exit via RAII Drop; stale dirs GC'd after 24h on startup
- **On by default:** Enabled by default. Disable with `--no-scratch-dir` or `sandbox.scratch_dir = false` in config.

### Layer 2: CONNECT Proxy (Logging and Domain Filtering)

A localhost CONNECT proxy intercepts all outbound traffic by default. `HTTP_PROXY`/`HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1` are injected into the sandbox environment, routing traffic from Copilot CLI (Node.js), `gh` (Go), `curl`, and any other tool through the proxy. Use `--no-proxy` to disable.

#### Proxy implementation safety

The proxy handles CONNECT tunnels only (non-CONNECT returns 405). Each TCP connection processes exactly one request — no HTTP keep-alive or request pipelining. This eliminates HTTP request smuggling by design.

- **Buffer:** Fixed 8192 bytes, single read — no allocation amplification
- **Connection limit:** 64 concurrent connections max (excess dropped)
- **Binding:** `127.0.0.1` only — not reachable from the network
- **Invalid UTF-8:** Replaced with U+FFFD via `from_utf8_lossy`, which won't match any domain — fail-safe
- **Relay timeout:** 60-second read timeout on both directions prevents idle connection resource exhaustion

#### Proxy-forced mode (#53)

By default the proxy is **advisory at the kernel level**: the sandbox allows outbound TCP to `*:443`, and traffic reaches the proxy only because cplt injects `HTTP_PROXY`/`HTTPS_PROXY`/`NODE_USE_ENV_PROXY=1`. A raw socket, or an agent that runs `env -u HTTPS_PROXY -u HTTP_PROXY …`, can still reach any host on `:443` **without** traversing the proxy — bypassing all domain filtering.

Proxy-forced mode restricts **kernel-level egress to the proxy port only**, so the proxy becomes the sole sanctioned path off the machine. It is **opt-in and off by default** (flipping it to the default is tracked in [#71](https://github.com/navikt/cplt/issues/71)). When enabled:

- **The proxy is mandatory.** It is forced on. If it was explicitly disabled (`--no-proxy` / `proxy.enabled = false`) the launch is a conflict and cplt **errors out** rather than silently choosing a side.
- **Fail-closed:** if the mandatory proxy cannot bind/start, cplt **refuses to launch the agent** — it never falls back to open networking.
- **Domain filtering is unchanged.** Proxy-forced only changes which port the kernel permits; the proxy still enforces `allowed_domains` / `blocked_domains` on everything it carries. Pairing proxy-forced with an allowlist gives "only these domains, with no way around the proxy" (a default per-agent allowlist is tracked in [#52](https://github.com/navikt/cplt/issues/52)).

**Platform asymmetry — enforcement is not equal:**

- **macOS (Seatbelt):** the SBPL profile replaces the `*:443` allow with `localhost:<proxy_port>` only. Seatbelt *can* pin to localhost, so there is **no residual** — no direct-network path exists and the `env -u HTTPS_PROXY` / raw-socket bypass is fully closed.
- **Linux (Landlock):** Landlock drops the `:443` rule and allows only the proxy port. This blocks direct `:443` to any host and forces HTTPS through the proxy — but Landlock is **port-based and cannot pin to localhost**, so a narrow `evil.com:<proxy_port>` channel remains reachable if a remote host answers on that exact port. This is "no direct `:443` bypass," **not** "no egress except the proxy." Closing the residual requires a network namespace and is tracked in [#114](https://github.com/navikt/cplt/issues/114).

> **Escape-hatch caveat:** `--allow-port <PORT>` still opens a **direct** kernel egress channel on that port that does not pass through the proxy (on both platforms). Using it under proxy-forced reopens exactly the kind of unfiltered bypass this mode exists to close.

### Layer 1L: Landlock + seccomp Kernel Sandbox (Linux)

On Linux, kernel-level enforcement uses two complementary mechanisms:

#### Landlock LSM (filesystem + network)

[Landlock](https://docs.kernel.org/userspace-api/landlock.html) is a stacking LSM that provides unprivileged, process-level access control. Rules are additive within a ruleset — access not explicitly granted is denied.

**ABI version support:**

| ABI | Kernel | Capabilities |
|-----|--------|-------------|
| v1  | 5.13+  | Filesystem access control |
| v2  | 5.19+  | + file refer (cross-directory rename) |
| v3  | 6.2+   | + file truncate |
| v4  | 6.7+   | + TCP port filtering (bind + connect) |
| v5  | 6.10+  | + ioctl on character devices |

cplt requires ABI v1 minimum. On ABI < v4, network security relies on the CONNECT proxy only (Landlock cannot filter TCP ports). On ABI v4+, Landlock denies all TCP connections except to explicitly allowed ports.

**Key differences from Seatbelt:**

| Property | Seatbelt (macOS) | Landlock (Linux) |
|----------|-----------------|------------------|
| Granularity | Path regex, file-level deny | Path-based, directory-level allow |
| Default | deny-by-default | deny-by-default |
| Subpath deny | ✅ Can deny subpaths within allowed dirs | ❌ Cannot deny within allowed paths |
| Network | Port-based (all ABIs) | Port-based (ABI v4+ only) |
| Audit logs | Full Seatbelt violation log | None (no audit mode) |
| Privilege | Requires `sandbox-exec` (deprecated) | Unprivileged (any user) |

**Pre-exec safety:** The proxy thread makes the process multi-threaded before `fork`. Landlock rules are pre-computed in the parent process (`PrecomputedSandbox`), and the seccomp filter is installed via raw syscall. The Landlock crate performs small heap allocations in `pre_exec` which is technically not async-signal-safe, but works reliably in practice (the proxy thread is blocked in I/O syscalls during fork, minimizing allocator contention).

#### seccomp-BPF (syscall filtering)

A BPF filter blocks dangerous syscalls that could be used to escape the sandbox or escalate privileges:

| Blocked syscall | Reason |
|----------------|--------|
| `ptrace` | Prevents debugging/injecting into other processes |
| `process_vm_readv`, `process_vm_writev` | Prevents cross-process memory access |
| `mount`, `umount2` | Prevents filesystem namespace manipulation |
| `pivot_root`, `chroot` | Prevents root filesystem escape |
| `unshare` | Prevents creating new namespaces |
| `setns` | Prevents entering other namespaces |
| `reboot` | Prevents system disruption |
| `kexec_load` | Prevents kernel replacement |
| `init_module`, `finit_module`, `delete_module` | Prevents kernel module manipulation |
| `swapon`, `swapoff` | Prevents swap manipulation |
| `personality` | Prevents ABI personality changes |
| `add_key`, `keyctl`, `request_key` | Prevents kernel keyring manipulation |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | Prevents io_uring (bypass of seccomp/Landlock) |
| `userfaultfd` | Prevents userfaultfd exploitation |
| `perf_event_open` | Prevents perf-based side channels |
| `bpf` | Prevents BPF program loading |
| `iopl`, `ioperm` | Prevents I/O port access (x86_64 only) |
| `modify_ldt` | Prevents LDT modification (x86_64 only) |

The filter uses `SECCOMP_RET_ERRNO` (returns EPERM) rather than `SECCOMP_RET_KILL` to avoid crashing on legitimate probes.

#### Protected paths (Linux)

The same credential directories are denied as on macOS:

- `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.nais`
- `~/.password-store`, `~/.config/gcloud`, `~/.config/op`, `~/.terraform.d`
- `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.gem/credentials`, `~/.vault-token`

Linux-specific tool directories use XDG-style paths:

| Directory | Permissions | Rationale |
|-----------|------------|-----------|
| `~/.cache` | read+write | XDG cache dir (pip, go-build, etc.) |
| `~/.local/share/pnpm` | read+write+exec | pnpm global store |
| `~/.local/bin` | read+exec | User-installed binaries |
| `~/.local/share/mise` | read+write+exec | mise tool installations |

#### Linux-specific limitations

1. **No `--show-denials`**: Landlock has no audit logging. Use `strace` for debugging.
2. **No subpath deny**: Cannot deny `~/.config/gh/extensions` while allowing `~/.config/gh/hosts.yml` — the entire directory must be allowed or denied.
3. **No auth integration**: Linux v1 supports env token + `gh auth` only (no D-Bus/Secret Service).
4. **Copilot extraction**: The macOS SEA extraction path is unknown on Linux — `ensure_copilot_extracted()` is skipped.
5. **No localhost isolation at kernel level**: Landlock network rules are port-based only — they cannot distinguish `localhost:443` from `remote:443`. On macOS, Seatbelt blocks localhost outbound separately. On Linux, use `--with-proxy` for localhost SSRF protection (the proxy resolves DNS and blocks private IPs).
6. **`--allow-localhost-any` disables ALL kernel network restriction on Linux**: because Landlock is port-based and cannot express "any localhost port but no remote host", opening all localhost ports requires dropping *every* Landlock TCP-connect rule. The result is unrestricted outbound TCP at the kernel level — an agent can raw-socket to any remote `host:port` and exfiltrate directly, not just reach localhost. macOS (Seatbelt) still pins `localhost:*` and is unaffected. cplt emits a prominent warning when this flag is set on Linux. **Prefer `--proxy-forced`** (which supersedes `allow_localhost_any` — see [Proxy-forced mode](#proxy-forced-mode-53)) or scope to specific ports with `--allow-localhost <PORT>`, which keeps kernel connect-restriction on.

The proxy provides:

1. **Connection logging** — every CONNECT target is logged with timestamp and status
2. **Domain blocklist** — configurable file-based blocklist with subdomain matching
3. **Port enforcement** — only port 443 (and `--allow-port` values) are permitted, matching the sandbox policy
4. **DNS rebinding protection** — resolves DNS first, validates the *resolved IP*, then connects using the pinned address
5. **Comprehensive private IP blocking** — covers all reserved ranges

#### DNS Rebinding Defense

A naïve proxy checks the hostname string (e.g., "api.github.com") against a blocklist before connecting. An attacker can register a domain that resolves to `127.0.0.1` — the hostname check passes but the connection reaches localhost.

Our defense (following [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) guidance):

```
1. Check hostname against blocklist           → block known-bad domains
2. Check hostname patterns (localhost, .local) → fast-path reject
3. DNS resolve hostname → IP address           → get actual target
4. Check RESOLVED IP against private ranges    → catch rebinding
5. Connect to the resolved IP (not hostname)   → pin the address, prevent TOCTOU
```

Step 5 is critical: we connect to the `SocketAddr` from step 3, not re-resolving. This prevents time-of-check-to-time-of-use (TOCTOU) attacks where the DNS response changes between validation and connection.

#### IP Ranges Blocked

| Range | RFC | Purpose |
|---|---|---|
| `127.0.0.0/8` | RFC 1122 | Loopback |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 | Private networks |
| `169.254.0.0/16` | RFC 3927 | Link-local |
| `100.64.0.0/10` | RFC 6598 | CGNAT (Tailscale, WireGuard) |
| `198.18.0.0/15` | RFC 2544 | Benchmarking |
| `240.0.0.0/4` | RFC 1112 | Reserved/future |
| `192.0.0.0/24` | RFC 6890 | IETF protocol assignments |
| `0.0.0.0` | — | Unspecified |
| `255.255.255.255` | — | Broadcast |
| `::1` | RFC 4291 | IPv6 loopback |
| `fc00::/7` | RFC 4193 | IPv6 ULA (private) |
| `fe80::/10` | RFC 4291 | IPv6 link-local |
| `::ffff:A.B.C.D` (private v4) | RFC 4291 | IPv4-mapped IPv6 |

### Layer 3: Input Validation

#### SBPL Injection Prevention

All paths interpolated into sandbox profiles are validated against unsafe characters:

```
Blocked: " ) ( ; \ \n \r \0
```

The newline character is the most dangerous — a path containing `\n(allow file-read* (subpath "/"))` would inject a rule granting read access to the entire filesystem. We validate:

- Project directory path
- Home directory path
- All user-specified allow/deny paths (from CLI and config file)

Config file paths are additionally canonicalized (resolved to absolute paths) at load time.

#### Temp File Safety

The sandbox profile is written to a temp file with:

- **Unique filename**: `cplt-{PID}-{nanosecond_timestamp}.sb`
- **Atomic creation**: `OpenOptions::create_new(true)` — fails if file exists (prevents symlink following)
- **Restricted permissions**: mode `0o600` (owner read/write only)
- **Cleanup on exit**: file is removed after sandbox-exec completes

#### Unsafe Root Rejection

cplt refuses to sandbox overly broad directories that would grant the agent access to sensitive areas:

- `/` — entire filesystem
- `/Users` — all user home directories
- `$HOME` — user's entire home directory
- `/tmp`, `/private/tmp` — shared temp directories
- `/var`, `/private/var` — system variable data
- `/Applications` — installed applications
- `/System` — macOS system files

#### CLI Path Handling

- **Allow paths** (`--allow-read`, `--allow-write`): canonicalized; unresolvable paths are warned and skipped
- **Deny paths** (`--deny-path`): canonicalized; unresolvable paths cause a **hard error** (silently dropping a deny rule is a security risk)

### Layer 4: Per-Repo Config Trust Model (`.cplt.toml`)

Repository maintainers can commit a `.cplt.toml` to configure sandbox settings for all contributors. This creates an attack surface: a compromised or malicious maintainer could weaken the sandbox for everyone who clones the repo. The trust model addresses this with defense-in-depth.

#### Security design principles

1. **Deny-default for permissions.** The `[propose]` section requests sandbox relaxations, but they have **no effect** until the local user explicitly approves them with `cplt trust accept`. Unapproved permissions are silently ignored — the agent runs safely with the tighter default sandbox.

2. **Deny section is tighten-only.** The `[deny]` section can only add restrictions (block paths, block env vars). It is applied automatically without approval because it cannot weaken the sandbox.

3. **No interactive approval during launch.** cplt deliberately does *not* prompt "approve these? [y/N]" when unapproved permissions exist. This prevents approval fatigue — users reflexively hitting `y` to proceed. Instead, approval requires a separate deliberate command (`cplt trust accept`), matching the security model of Deno workspace trust and VS Code Restricted Mode.

4. **Tamper-proof source.** `.cplt.toml` is read from `git HEAD` (committed state) via `git cat-file`, not from the working tree. The sandboxed agent cannot modify its own config mid-session. Write access to `.cplt.toml` is kernel-denied inside the sandbox.

5. **Content-pinned approvals.** Trust entries store a SHA-256 hash of the approved `[propose]` values. If the maintainer changes any proposed values (even reordering array elements is hash-stable due to pre-sort), previous approvals are automatically invalidated and the user must re-approve.

6. **Additive-only semantics.** Repo config can enable features (`allow_docker = true`) but cannot disable anything set by the user's CLI flags or global config. Precedence: CLI > global config > approved repo permissions > defaults.

7. **Path traversal rejection.** Paths in `.cplt.toml` containing `..` components are rejected at parse time, preventing escape attempts like `../../.ssh`.

#### Trust store integrity

- Trust entries are stored in `~/.config/cplt/trust/` — protected from the sandbox (the agent cannot self-approve).
- Each entry's **filename** is a SHA-256 fingerprint of the normalized git remote URL (or the canonicalized project path when there is no remote). Remote URLs are normalized (SSH/HTTPS variants, credentials stripped, ports removed) so the same repo accessed via different URLs shares one trust entry.
- **The remote URL is not an authenticity signal.** It is attacker-controllable: a malicious repo can `git remote set-url origin <victim>` and copy the victim's approved `[propose]` block verbatim (so the content hash also matches) to look up the victim's trust entry and inherit its approved permissions — a confused-deputy escalation. To defeat this, every approval is **also bound to the absolute local checkout path** it was granted at (`repo.path`). Before applying a trust entry, cplt requires the current project directory to match that recorded path (canonicalized); a matching fingerprint presented from a *different* path is **not** auto-trusted and triggers a re-approval prompt. An attacker cannot satisfy this without already controlling the victim's exact on-disk location. Legacy entries with no recorded path are treated as unmatched (one-time re-approval).
- Trust writes are atomic (temp file + rename) to prevent corruption from interrupted writes.

#### Threat scenarios

| Scenario | Mitigation |
|---|---|
| Maintainer adds `allow_docker = true` | No effect until each user explicitly approves |
| Agent modifies `.cplt.toml` at runtime | Read from `git HEAD`, not working tree; writes kernel-denied |
| Maintainer changes proposed values after approval | Content hash mismatch invalidates approval |
| `.cplt.toml` blocks critical env vars via `[deny].env` | `[deny]` can only tighten — removing env vars reduces attack surface |
| Path traversal in deny/allow paths | `..` components rejected at parse time |
| Agent self-approves via trust store | Trust dir (`~/.config/cplt/trust/`) is outside the sandbox |
| Origin-URL spoof to inherit a victim's approval (`git remote set-url origin <victim>` + copy `[propose]`) | Approvals are bound to the local checkout path; a match from a different path is not auto-trusted (re-approval required) |

### GPG Signing Risk Analysis (`--allow-gpg-signing`)

When `--allow-gpg-signing` is enabled, cplt grants targeted access to the GPG subsystem:

**What is exposed:**
- Read-only access to `~/.gnupg/pubring.kbx`, `pubring.gpg`, `trustdb.gpg`, `gpg.conf`, `common.conf` (public data only)
- Unix socket connect to `~/.gnupg/S.gpg-agent` (IPC to the GPG agent daemon running outside the sandbox)

**What stays denied:**
- `~/.gnupg/private-keys-v1.d/` — private key files remain kernel-blocked
- `~/.gnupg/secring.gpg` — legacy private keyring explicitly denied
- All writes to `~/.gnupg/` — no modifications possible
- `~/.ssh/` and `SSH_AUTH_SOCK` — SSH signing is not enabled by this flag

**Key exfiltration is impossible.** The GPG agent uses the Assuan IPC protocol, which exposes `PKSIGN` (sign), `PKDECRYPT` (decrypt), `READKEY` (public key), and `KEYINFO` (metadata) — but has **no command to export private key material**. The agent is a privilege-separation boundary by design. Even if the on-disk key files weren't denied, they are encrypted with the user's passphrase.

**The actual risk is signature impersonation AND decryption.** A compromised process with agent socket access can:
1. Request signatures via `PKSIGN` — signing arbitrary data, including malicious commits
2. Request decryptions via `PKDECRYPT` — if the user has an encryption subkey, the compromised process can decrypt arbitrary ciphertext

This is **not key theft** — the attacker cannot take the key with them. Operations can only be performed while the sandbox is running and the agent connection is active.

**Risk context:** Copilot already has `git commit` ability and can make commits as the user. GPG signing only adds the "Verified" badge. The incremental risk is specifically: a compromised agent can make commits that appear cryptographically verified by the user, and can decrypt data if an encryption subkey exists. Mitigating factors:
- Agent passphrase cache has a TTL (default: 10 min idle, 2 hr max)
- The network proxy (when enabled) can audit/block pushes to unexpected remotes
- Branch protection rules may still require PR review regardless of signature status

**Deny-path override:** If `--deny-path ~/.gnupg` is specified alongside `--allow-gpg-signing`, the deny wins — all GPG allows are suppressed. This is consistent with the project-wide principle that explicit denies always take precedence.

**Known limitations:**
- `GNUPGHOME` is not in `ENV_ALLOWLIST` but could be injected via `--pass-env` or `--inherit-env`, redirecting GPG to a different directory outside the SBPL policy. The SBPL rules only cover `~/.gnupg/`.
- If `~/.gnupg` is a symlink, SBPL path resolution may cause rules to not match as expected. Signing will fail closed (no access) rather than open.

### Network Limitations

#### Proxy support for Copilot traffic

Copilot CLI bundles Node.js v24.11.1, which supports `NODE_USE_ENV_PROXY=1` (added in Node.js v24.5.0). When this env var is set, Node.js natively honors `HTTP_PROXY`/`HTTPS_PROXY` — routing all outbound connections through the specified proxy.

cplt injects `NODE_USE_ENV_PROXY=1`, `HTTP_PROXY`, and `HTTPS_PROXY` into the sandbox environment. All traffic — Copilot CLI, `gh`, `curl`, and any other tool — routes through the localhost CONNECT proxy.

**Historical context:** Earlier versions of Copilot CLI used a Node.js runtime that did not support proxy env vars, and injecting them broke the auth flow. This is no longer the case as of Copilot CLI 1.0.24+ with bundled Node.js v24.11.1.

**Design decision:** The proxy is enabled by default. It listens on an OS-assigned ephemeral port (port 0), so there are no fixed-port conflicts. Use `--no-proxy` to disable for a single run, or set `proxy.enabled = false` in config to disable permanently.

| Component | Language | Routes through proxy? |
|---|---|---|
| Copilot CLI | Node.js | ✅ Yes (via `NODE_USE_ENV_PROXY=1`) |
| `gh` CLI | Go | ✅ Yes (via `net/http.ProxyFromEnvironment()`) |
| `curl` | C | ✅ Yes |

#### SBPL network filtering limitations

SBPL has fundamental limitations for network filtering:

- **No domain-based rules** — SBPL operates at the syscall level, not the application level. It cannot match on hostnames.
- **No wildcard port filtering** — there is no syntax for "allow any host on port 443 only"
- **IP-based rules require known IPs** — Copilot's API endpoints use CDN-backed IPs that change regularly
- **No loopback-only bind** — SBPL only accepts `*` or `localhost` as the host part of IP filters. Literal IPs like `127.0.0.1` cause `"host must be * or localhost"` errors. The `localhost` host matches `INADDR_ANY` (`0.0.0.0`), meaning `(allow network-bind (local ip "localhost:*"))` also permits binding on all interfaces. This is a macOS Seatbelt limitation — processes inside the sandbox can start listeners accessible on the network. Mitigations: outbound is locked to port 443 (no exfiltration via inbound connections), dev machines are typically behind NAT/firewall, and the proxy intercepts all outbound traffic.

The only viable options are `(allow network-outbound (remote tcp))` (allow all) or `(deny network*)` (deny all). We allow outbound TCP because Copilot cannot function without network access, and use port restrictions as a secondary control.

#### Current state

- **Outbound TCP is allowed** in the sandbox profile, restricted to port 443 (+ `--allow-port`)
- **Filesystem isolation is the primary security control** — credentials are kernel-blocked regardless of network policy
- **The proxy** (when enabled) provides connection logging, domain blocking, port enforcement, and DNS rebinding protection for all traffic including Copilot
- **By default the proxy is not mandatory** — because `*:443` is kernel-allowed, a raw socket or `env -u HTTPS_PROXY` can reach the network without traversing the proxy. Opt into **proxy-forced mode** (`--proxy-forced` / `proxy.forced = true`, #53) to restrict kernel egress to the proxy port and close that bypass. Enforcement is asymmetric: macOS pins to `localhost:<proxy_port>` (full, no residual); Linux blocks direct `:443` but is port-based, so a narrow `evil.com:<proxy_port>` residual remains until [#114](https://github.com/navikt/cplt/issues/114). See [Layer 2 → Proxy-forced mode](#proxy-forced-mode-53)

### Self-Update Security (`cplt update`)

The update mechanism downloads releases from GitHub, verifies SHA256 checksums, and atomically replaces the binary.

**Verified:**
- SHA256 checksum is mandatory — update aborts on mismatch
- `--proto-redir =https` prevents HTTP downgrade on redirects
- Archive validation: must contain exactly one regular file named `cplt` (no symlinks, no directories)
- Extracted binary verified via `symlink_metadata` (rejects symlinks)
- Uses absolute paths for system tools on macOS (`/usr/bin/curl`, `/usr/bin/shasum`, `/usr/bin/tar`) and Linux (`/usr/bin/sha256sum`, standard paths only — no bare PATH lookup)
- Atomic replacement: stage to `.new`, set permissions, rename

**Not verified:**
- No cryptographic signature (GPG or Sigstore). `SHA256SUMS` and binary come from the same GitHub release — a compromised release controls both. This is consistent with most Go/Rust CLI tools but weaker than signed package managers.
- Temp directory uses `/tmp/cplt-update-{PID}` — predictable by local attackers, but extracted binary is checked for symlinks before installation.

The Homebrew install path (`brew install navikt/tap/cplt`) uses Homebrew's own verification and is preferred on macOS.

### Install Script Security (`install.sh`)

The install script downloads from GitHub Releases and verifies SHA256 checksums.

**Caveat:** If the `SHA256SUMS` file cannot be downloaded, or no hash utility is available, the script prints a warning and **continues without verification**. This is a deliberate trade-off for usability in minimal CI environments.

For high-security environments, verify the binary manually:
```bash
curl -fsSL -o cplt.tar.gz "https://github.com/navikt/cplt/releases/latest/..."
curl -fsSL -o SHA256SUMS "https://github.com/navikt/cplt/releases/latest/.../SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
```

### Discovery and `--doctor`

`cplt --doctor` probes the environment by running `--version` on all known agent binaries found in PATH (copilot, opencode, gemini, claude). These commands run **outside the sandbox** with full user privileges.

Trust model: cplt trusts that binaries in your PATH are legitimate. This is the same trust model as typing `copilot --version` yourself. If you don't trust a binary in your PATH, remove it before running `--doctor`.

### Config File Trust Model

`~/.config/cplt/config.toml` and `~/.config/cplt/trust/*.toml` are trusted inputs read before sandboxing. They are not permission-checked — the trust model assumes `$HOME` is protected by OS-level permissions (0700 or 0755).

On shared systems, ensure `~/.config/cplt/` has restrictive permissions (0700). A user who can write to this directory can weaken the sandbox configuration.

### Scratch Directory Session IDs

Session IDs for per-session scratch directories are generated from `/dev/urandom` (16 random bytes, hex-encoded). Fallback to PID + nanosecond timestamp if `/dev/urandom` is unavailable (not expected on standard macOS/Linux). The fallback is predictable but the failure mode is denial-of-service (directory creation fails if it already exists), not compromise.

## Test Strategy

### Unit Tests (cross-platform, run on Linux CI)

These test core logic without invoking `sandbox-exec`, using the real library functions (not duplicated copies):

| Category | Tests | What's verified |
|---|---|---|
| Unsafe root detection | 11 | Rejects `/`, `/Users`, `/tmp`, `/var`, `/Applications`, `/System`, `$HOME`; allows project subdirs |
| SBPL injection | 5 | Rejects `\n`, `\0`, `"`, `(`; allows normal paths |
| Domain blocking | 7 | Exact match, subdomain match, no partial match, comments, case-insensitive, empty blocklist |
| Private IP detection | 11 | Loopback, RFC 1918, link-local, unspecified, CGNAT, benchmarking, reserved, ULA, link-local v6 |
| Hostname detection | 3 | localhost, .localhost, .local patterns; allows normal hostnames |
| Profile generation | 35 | Uses real `generate_profile()`; verifies deny-default, project access, sensitive dir/file blocks, network rules, deny-after-allow ordering, exec-from-tmp denied, env file deny/allow, copilot caches carve-outs, tool dir permissions, scratch dir rules |
| Home tool dirs | 1 | All runtime entries present in `HOME_TOOL_DIRS` |
| Env allowlist | 3 | Essential vars included, dangerous vars excluded, runtime vars present |
| Env behavior | 17 | Sanitization, hardening injection, pass-env overrides, LANG prefix leak prevention, YARN hardening bypass prevention, scratch dir TMPDIR redirect, JAVA_TOOL_OPTIONS injection/append/override |
| Config parsing | 24 | TOML parsing, CLI/config merge precedence, tilde expansion, SBPL validation, scratch dir, allow-tmp-exec |

### Integration Tests (macOS only, 39 tests)

These invoke `sandbox-exec` with real Seatbelt profiles and verify **kernel-level enforcement**:

| Category | Tests | What's verified |
|---|---|---|
| File access | 5 | Project read/write, copilot config, temp write, process execution |
| Sensitive dir blocks | 4 | `~/.ssh`, `~/.aws`, `~/.docker`, `~/.kube` blocked |
| Network | 6 | Outbound blocked, JVM Attach socket allowed, SSH agent blocked, `/tmp` sockets blocked, localhost TCP bind on all interfaces (SBPL "localhost" doesn't match Java mapped addresses), `--allow-localhost-any` + `--allow-jvm-attach` opens all outbound TCP |
| Binary CLI | 4 | Version, help, root/home dir rejection |
| Tool dir permissions | 15 | Each HOME_TOOL_DIR has correct exec/map-exec/write at kernel level |
| GPG signing | 4 | Default blocks `~/.gnupg`, flag allows pubring read, private keys stay denied, writes stay denied |

### E2E Project Tests (macOS only, 38 tests)

End-to-end tests using realistic project scaffolding (Node, Go, Python, Rust, Java/Maven, Kotlin) with fake copilot scripts:

| Category | Tests | What's verified |
|---|---|---|
| Per-language file ops | 7 | Read/write files in Node, Go, Python, Rust, Maven, Kotlin/Maven, multi-module Maven project structures |
| Git workflows | 2 | git init/commit/status/diff/log, multi-step edit cycles |
| Security matrix | 2 | Secret files blocked (.env, .pem, .key), home secrets (~/.ssh, ~/.aws) |
| Mode combinations | 7 | allow-env-files, scratch-dir exec, deny-path, config file, deny-path + scratch-dir, allow-lifecycle-scripts, JAVA_TOOL_OPTIONS injection |
| Git persistence | 1 | Cannot write .git/hooks or .git/config |
| Lifecycle scripts | 3 | npm/yarn/pnpm lifecycle script hardening |

### Smoke Tests (macOS only, 6 tests, `#[ignore]`)

Real Copilot CLI integration tests requiring authentication and network access:

| Test | What's verified |
|---|---|
| `smoke_copilot_version` | Copilot outputs version string inside sandbox |
| `smoke_copilot_list_models` | API call returns model list (JSON) |
| `smoke_copilot_simple_prompt` | Chat completion returns response containing UUID canary |
| `smoke_copilot_file_context` | Copilot reads project file and references its content |
| `smoke_copilot_write_file` | Copilot creates a new file on disk (side-effect assertion) |
| `smoke_env_vars_denied` | `SUPER_SECRET_TOKEN` not visible inside sandbox |

### CI Pipeline

The GitHub Actions workflow runs in two stages:

1. **Linux (ubuntu-latest)**: formatting check (`cargo fmt`), linting (`cargo clippy -D warnings`), unit tests
2. **macOS (macos-latest)**: full test suite including integration tests, release binary build and verification

## Prior Art and References

### macOS Seatbelt / sandbox-exec

- [Apple sandbox-exec(1) man page](https://keith.github.io/xcode-man-pages/sandbox-exec.1.html) — Official documentation for the command-line sandbox tool
- [Chromium Seatbelt V2 Design](https://chromium.googlesource.com/chromium/src/sandbox/+show/refs/heads/main/mac/seatbelt_sandbox_design.md) — How Chromium designs and maintains Seatbelt profiles for browser process sandboxing; influenced our deny-default + bsd.sb import approach
- [HackTricks: macOS Sandbox](https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox/index.html) — Comprehensive security research on Seatbelt internals, bypass techniques, and rule evaluation
- [A New Era of macOS Sandbox Escapes (POC2024)](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) — Recent CVE research on sandbox escape via XPC/Mach services; informed our understanding of Seatbelt's limitations
- [michaelneale/agent-seatbelt-sandbox](https://github.com/michaelneale/agent-seatbelt-sandbox) — Early proof-of-concept for sandboxing AI coding agents with Seatbelt; validated the basic approach

### DNS Rebinding and SSRF Prevention

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — Authoritative guidance on validating resolved IPs (not hostnames) and pinning addresses to prevent TOCTOU attacks
- [RFC 1918](https://datatracker.ietf.org/doc/html/rfc1918) — Private IPv4 address ranges (10/8, 172.16/12, 192.168/16)
- [RFC 4193](https://datatracker.ietf.org/doc/html/rfc4193) — IPv6 Unique Local Addresses (fc00::/7)
- [RFC 6598](https://datatracker.ietf.org/doc/html/rfc6598) — CGNAT shared address space (100.64.0.0/10); important for Tailscale/WireGuard environments
- [RFC 4291](https://datatracker.ietf.org/doc/html/rfc4291) — IPv6 addressing architecture (loopback, link-local, IPv4-mapped addresses)

### Secure Temporary Files

- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html) — Motivation for unique filenames and `O_CREAT|O_EXCL`
- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html) — Symlink attacks on predictable temp paths

### AI Agent Sandboxing (broader context)

- [GitHub Copilot Workspace sandbox settings](https://docs.github.com/en/copilot/customizing-copilot/customizing-copilot-in-your-ide) — VS Code's built-in sandbox options for Copilot (terminal command restrictions)
- [Copilot cloud agent firewall](https://docs.github.com/en/enterprise-cloud@latest/copilot/customizing-copilot/customizing-or-disabling-the-firewall-for-copilot-coding-agent) — GitHub's server-side network firewall for the cloud coding agent
- [Copilot allowlist reference](https://docs.github.com/en/copilot/reference/copilot-allowlist-reference) — Default allowed domains for Copilot cloud agent
- [OpenAI Codex sandbox](https://platform.openai.com/docs/guides/codex) — OpenAI's approach to sandboxing code execution with network and filesystem restrictions
- [Anthropic Claude Code permissions](https://docs.anthropic.com/en/docs/claude-code/security) — Permission-based tool approval model for local agent execution

### Supply Chain Attack Research

- [Mend.io: Shai-Hulud npm worm analysis (2025)](https://www.mend.io/blog/npm-supply-chain-attack-packages-compromised-by-self-spreading-malware) — Self-replicating worm that compromised 700+ npm packages
- [Wiz: Shai-Hulud 2.0 — 25K+ repos exposed](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack) — Second wave and blast radius analysis
- [Socket: 60 malicious npm packages](https://socket.dev/blog/60-malicious-npm-packages-leak-network-and-host-data) — Network recon exfiltration to Discord webhooks
- [Oligo: npm supply chain risks with AI agents](https://www.oligo.security/blog/the-hidden-risks-of-the-npm-supply-chain-attacks-ai-agents) — How AI coding agents amplify supply chain attacks
- [ReversingLabs: npm reverse shell malware](https://www.reversinglabs.com/blog/malicious-npm-patch-delivers-reverse-shell) — Patched legitimate packages delivering reverse shells
- [Rafter: AI Agent Security Incident Timeline (2025–2026)](https://rafter.so/blog/incidents/ai-agent-security-timeline-2025-2026) — Comprehensive timeline of agent security incidents
- [CamoLeak: Copilot Chat exfiltration (CVE-2025-59145)](https://rafter.so/blog/incidents/camoleak-invisible-exfiltration-channel) — Invisible data exfiltration via GitHub image proxy
- [LOTS Project — Living Off Trusted Sites](https://lots-project.com/) — Catalog of legitimate domains abused for C2 and exfiltration
- [Veracode: npm C2 via Ethereum smart contracts](https://www.veracode.com/blog/54-new-npm-packages-found-beaconing-to-c2-server-in-ethereum-smart-contract/) — Dead-drop C2 rotation technique

## Reporting Security Issues

If you discover a vulnerability in cplt, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Contact the team via Nav's internal security channels
3. Include a description of the vulnerability, steps to reproduce, and potential impact

We aim to acknowledge reports within 48 hours and provide a fix within one week for critical issues.
