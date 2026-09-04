# Security model

This is the security architecture of cplt: the threat model it addresses, the defense layers it implements, and how automated tests validate them.

## Supported agents

cplt sandboxes AI coding agents. Currently that means **GitHub Copilot CLI**, **[OpenCode](https://opencode.ai/)**, **Google Gemini CLI**, **[Antigravity CLI](https://github.com/google-antigravity/antigravity-cli)**, **[Pi](https://github.com/earendil-works/pi)**, **[Claude Code](https://docs.anthropic.com/en/docs/claude-code)**, and **[goose](https://github.com/aaif-goose/goose)**. All share the same core sandbox (deny-default Seatbelt/Landlock profile, env sanitization, scratch dir), with per-agent adaptations:

| Property        | Copilot                             | OpenCode                                                            | Antigravity                                 | Pi                                          | Claude Code                                  |
|-----------------|-------------------------------------|---------------------------------------------------------------------|----------------------------------------------|---------------------------------------------|----------------------------------------------|
| Auth mechanism  | GitHub token (Keychain, `GH_TOKEN`) | `/connect` device flow to `auth.json`, or API keys                  | Google OAuth (browser / keyring session)     | API keys (Anthropic, OpenAI, Gemini, etc.)  | OAuth token (Keychain / `~/.claude`) or API key |
| Auth in sandbox | Token served via one-time file read (gh guard) or Keychain | Copilot auth stored in data dir; third-party keys need `--pass-env` | OAuth/session data stored in `~/.gemini/*` | Keys need `--pass-env`             | OAuth stored in `~/.claude`/Keychain; keys need `--pass-env` |
| Config dir      | `~/.copilot` (read/write)           | `~/.config/opencode` (read-only)                                    | `~/.gemini/config` (read/write)              | `~/.pi` (read/write)                       | `~/.claude` + `~/.claude.json` (read/write)  |
| Data dir        | `~/Library/Caches/copilot`          | `~/.local/share/opencode` (write, no exec)                          | `~/.gemini/antigravity-cli` (read/write)     | `~/.pi/agent/bin` (read + exec)             | N/A (in config dir)                          |
| State data dir  | N/A                                 | `~/.local/state/opencode` (write, no exec)                          | N/A                                          | N/A                                          | N/A                                          |
| Keychain access | Yes                                 | No                                                                  | Yes (OAuth/keyring flow)                     | No                                          | Yes (macOS OAuth token storage)              |
| SEA extraction  | Yes (pre-sandbox)                   | No                                                                  | No                                           | No                                          | No                                           |
| Env isolation   | `GH_TOKEN` not injected (one-time file); `COPILOT_*` passed | suppressed (see below)                          | suppressed (see below)           | suppressed (see below)          | suppressed (see below); `DISABLE_AUTOUPDATER=1` injected |
| Auto-detected   | Yes (priority 1)                    | Yes (priority 2)                                                    | Yes (priority 3)                             | No (explicit only, name collision risk)     | No (explicit only)                           |

¹ Unless the experimental `sandbox.keychain_substitute` is on *and* the agent has a credential it can reach without the Keychain — see [Keychain access is all-or-nothing](#keychain-access-is-all-or-nothing).


### Rules that apply to every non-Copilot agent

- **Copilot env vars are suppressed.** `GH_TOKEN`, `GITHUB_TOKEN`, `COPILOT_GITHUB_TOKEN`, and every `COPILOT_*` variable are stripped for OpenCode, Gemini, Antigravity, Pi, Claude Code, and goose. OpenCode's Copilot provider uses its own auth file instead.
- **Third-party API keys are opt-in.** `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`), and the Bedrock/Vertex routing vars (`CLAUDE_CODE_USE_BEDROCK`, `AWS_BEARER_TOKEN_BEDROCK`, `CLAUDE_CODE_USE_VERTEX`, `ANTHROPIC_VERTEX_PROJECT_ID`, `GOOGLE_CLOUD_PROJECT`) are never passed through by default. You have to name each one with `--pass-env`. That keeps credentials from reaching a sandboxed process by accident.

- **Host-persistence guard on the agent's own config dir.** Most agents get their global config dir mounted read/write, and some files in there auto-execute the next time the agent runs *outside* the sandbox. goose is the exception: its config dir is read-only, because it rewrites `config.yaml` by rename, which needs directory write and would hand back the whole vector. Those paths are write-denied (`Agent::host_persistence_denies`):

  | Agent | Denied inside the granted config dir |
  | --- | --- |
  | Claude Code | `settings.json`, `statusline.sh`, `plugins/` |
  | Pi | `settings.json`, `extensions/`, `npm/`, `git/` |
  | Antigravity | `config/hooks.json`, `config/mcp_config.json`, `antigravity-cli/bin/` |
  | goose | — (its whole config dir is read-only; see below) |
  | Copilot, OpenCode | — |

  Two of these go beyond "the file that names the code". Pi's `npm/` and `git/` hold the code of packages `pi install` already fetched: denying only the settings file stops a *new* entry being added while leaving the code an existing entry already points at editable in place, which loads on the next host run. Antigravity's `bin/` holds `agentapi` and `webm_encoder`, which it executes on the host.
- **No `allow.write` reopens them.** On **macOS** the denies are emitted at the tail of the profile, after `emit_user_allows`, so SBPL last-match-wins keeps them on top. That placement is load-bearing: while they sat beside the dir-wide allow, `allow.write = ["~/.claude"]` — an ordinary grant, since `is_unsafe_root` only rejects `~` itself — silently reopened every one of them, including Claude's `statusline.sh` and `plugins/`. This is the same fix #212 applied to the git-persistence denies. The consequence is that there is deliberately **no in-cplt escape hatch**: a step that needs to write a denied file happens outside cplt.
- **Linux is weaker.** Landlock cannot deny a subpath inside an allowed directory, so the deny is carried by the same bubblewrap read-only overlay used for `.git/hooks`: it holds only when `bwrap` is present, and only for paths that **already exist on disk** — bubblewrap cannot bind a missing source. That caveat bites harder here than it does for git, because `git init` creates `.git/hooks` while `extensions/` does not exist until the first extension is installed, so on Linux that particular deny is nominal in the common case. Without bubblewrap, the guard is unenforced on Linux entirely.
- **Cost: do the affected step outside cplt.** Denying `settings.json` breaks whatever writes it. For **Pi** it is `pi install` plus every in-session setting that persists there — `/model` (Ctrl+S), `/thinking`, `/settings` — but not auth, which comes from provider API keys via `--pass-env`. For **Claude Code** and **Antigravity** auth is unaffected; the cost is editing hooks, MCP config or a statusline from inside a session.


### Agent notes beyond the table

**OpenCode.** The data dir (`~/.local/share/opencode/`: sessions, auth, SQLite DB) and the state dir (`~/.local/state/opencode/`: locks, history, statistics) both carry `(deny process-exec)` and `(deny file-map-executable)` alongside their write permission, so neither can be used for write-then-exec persistence. The config dir (`~/.config/opencode/opencode.json` and friends) is read-only, so the agent cannot tamper with settings that apply to unsandboxed runs.


**Antigravity.** Keeps the Keychain grant unless `~/.gemini/antigravity-cli/antigravity-oauth-token` already exists — that file is `agy`'s *keyring fallback*, not a mirror, so its presence is the only safe signal that the agent can authenticate without the grant (#242). See [Keychain access is all-or-nothing](#keychain-access-is-all-or-nothing). Its two grants carry their own auto-executing config, so the host-persistence guard applies: `~/.gemini/config/hooks.json` names host commands, `~/.gemini/config/mcp_config.json` holds `mcpServers` that auto-start, and `~/.gemini/antigravity-cli/bin/` holds binaries (`agentapi`, `webm_encoder`) Antigravity runs on the host. All three are write-denied. Note that Antigravity is granted `~/.gemini/config` and `~/.gemini/antigravity-cli`, not `~/.gemini` itself, so Gemini's own user-level `settings.json` is not writable through an Antigravity session.

**Pi.** Not auto-detected: the `pi` binary name is generic and may collide with other tools, so select it explicitly with `--agent pi` or `sandbox.agent = "pi"`. `~/.pi/agent/` holds settings, auth, sessions, and themes. The managed binary dir `~/.pi/agent/bin/` (bundled `fd`, `rg`) has process-exec, and on **macOS only** an explicit `(deny file-write*)` is emitted for it at the tail of the profile — alongside the host-persistence denies, and for the same reason: emitted next to the parent allow it was reopenable by a later user `allow.write`. Linux has no equivalent: Landlock rules are additive, so the parent's read+write unions with the child's read+exec and `~/.pi/agent/bin/` ends up **writable and executable**. `~/.pi/agent/extensions/`, `settings.json`, `npm/` and `git/` are write-denied by the host-persistence guard (macOS Seatbelt; on Linux only via the bubblewrap overlay, and only for paths that already exist). Pi auto-discovers `~/.pi/agent/extensions/*.ts` and `*/index.ts` and loads them at startup without confirmation, since the project-trust gate covers only project-local `.pi/extensions`, and Pi's own documentation states that extensions run with the user's full system permissions and can execute arbitrary code. `settings.json` in the same directory is denied for the same reason: its `extensions` key loads code from arbitrary file paths and its `packages` key from npm or git, so denying the `extensions/` directory alone would not close the vector. `npm/` and `git/` are denied because that is where `pi install` puts the code: without them, denying `settings.json` would stop a *new* `packages` entry being added while leaving an already-installed package editable in place, and it loads on the next host run. A file written to any of these would execute unsandboxed the next time `pi` runs on the host. The cost is in-sandbox package management plus every setting that persists to `settings.json` — `/model` (Ctrl+S), `/thinking`, `/settings`. Do those outside cplt. Auth is unaffected: Pi has no interactive login and reads provider API keys from the environment.

**Claude Code.** Not auto-detected either; select it with `--agent claude` (aliases `cc`, `claude-code`) or `sandbox.agent = "claude"`.

- **Subscription auth works out of the box.** The OAuth token lives in `~/.claude/.credentials.json` (Linux) or the macOS login Keychain ("Claude Code-credentials"). Both are exposed to the sandbox, so the subscription flow needs no env var. That hands the sandboxed agent its own credentials, an inherent trade-off, the same one Copilot's Keychain access makes. Because subscription OAuth needs no env var, cplt does not emit the "needs auth" warning for Claude Code.
- **Config dirs are read/write.** `~/.claude/` (sessions, projects, history, settings, credentials) and the top-level `~/.claude.json`.
- **Host-persistence guard.** Inside that writable config dir, `statusline.sh`, `plugins/` and `settings.json` are explicitly write-denied. All three auto-execute the next time `claude` runs *outside* the sandbox, so a compromised agent could otherwise plant code that escapes via the next launch. `settings.json` was previously left writable on the grounds that it needs explicit user invocation; that was wrong — its `hooks` key auto-fires on `SessionStart`, `UserPromptSubmit` and other events, so it is now denied. `commands/`, `agents/`, and `skills/` stay writable, because Claude legitimately authors them and they really do run only when the user invokes them. Enforcement follows the platform limits above: full on macOS, bubblewrap-only on Linux. These denies also moved to the tail of the profile, which fixed a pre-existing hole — `allow.write = ["~/.claude"]` used to reopen `statusline.sh` and `plugins/`. The residual `mcpServers` risk in `~/.claude.json` stays unenforceable on Linux. Treat write access to a relocated `CLAUDE_CONFIG_DIR` the same way.
- **`CLAUDE_CONFIG_DIR` is supported.** It sits on the env allowlist, and when set, `Agent::Claude.config_dirs()` grants that directory in place of `~/.claude`. Both halves are required. Granting the path without passing the variable, or the reverse, breaks auth and config inside the sandbox.
- **Auto-update disabled.** cplt injects `DISABLE_AUTOUPDATER=1`. Claude Code has no `--no-auto-update` flag, and a self-update inside the sandbox is a persistence vector that would also fail against read-only install paths.

**goose.** Not auto-detected; select it with `--agent goose` or `sandbox.agent = "goose"`. Verified against goose 1.48.0.

- **Provider-agnostic, so no domain defaults.** goose routes model traffic to whichever provider you configure, and an `--observe-domains` capture (1.48.0, 2026-09-03) showed it contacting no goose-owned host of its own. Its built-in allowlist is therefore the shared package-registry base and nothing else; add your provider's domain via `allowed_domains`. See [docs/proxy.md](docs/proxy.md#default-allowlist-fail-closed-networking) for the two hosts that were seen and deliberately excluded.
- **XDG dirs on macOS too.** goose uses `~/.config/goose`, `~/.local/share/goose` and `~/.local/state/goose` on both platforms — not `~/Library/Application Support` — and honours the `XDG_*` overrides on macOS. It creates no cache dir, so none is granted.
- **Config dir is read-only, on purpose.** `config.yaml` declares `extensions:` entries carrying a `cmd` and `args` that goose spawns as subprocesses on every session start. A writable config dir would let a sandboxed agent append an extension that runs **unsandboxed** the next time the user launches goose, the same class as `.git/hooks` and Claude Code's `plugins/`. There is no `write_files` carve-out either: goose rewrites `config.yaml`, `permission.yaml` and `permissions/tool_permissions.json` by creating a temp file in the directory and renaming over the target, which needs directory write and would hand the vector straight back. The cost is that `/mode` and theme changes, the first-run telemetry prompt, and persisted "always allow" tool permissions do not survive a sandboxed session. That last one is a feature: a sandboxed agent should not be able to grant itself standing tool approval for the user's future unsandboxed runs. A full `goose run` against an existing `config.yaml` left it byte-identical, so ordinary use is unaffected.
- **Keychain access is granted, and it is avoidable.** goose stores provider secrets in the OS keyring by default (macOS login Keychain; D-Bus Secret Service on Linux, so the grant is macOS-only in effect) under service `goose`, account `secrets` — a single entry holding every secret. cplt grants the whole of `~/Library/Keychains`, which is broader than that one entry, so a sandboxed goose can reach other Keychain items too (issue #242). Unlike Copilot or Claude Code, goose does not need it: run with `GOOSE_DISABLE_KEYRING=1` and goose falls back to a `secrets.yaml` in its config dir, or pass the provider key with `--pass-env` and skip stored secrets entirely. Prefer either over the Keychain grant.
- **Plugin manifests are covered.** goose auto-spawns MCP servers declared in plugin manifests under `~/.agents/plugins/` and `<project>/.agents/plugins/`. The first is outside every granted directory and unreachable in the sandbox. The second sits in the writable project tree and is the same in-repo persistence class as `.git/hooks`, so it is denied for every writable root, after the user allows so no `allow.write` reopens it. The rest of `.agents/` stays writable: nothing there auto-executes.

## Threat model

cplt assumes the sandboxed agent is **untrusted**, because it executes arbitrary code suggestions on your machine. The threat model covers:

| Threat | Example | Defense layer |
|---|---|---|
| **Credential theft** | Read `~/.ssh/id_ed25519`, `~/.aws/credentials` | Seatbelt deny rules (macOS) / Landlock deny (Linux) |
| **Data exfiltration** | POST secrets to `https://evil.com/collect` | Filesystem isolation (credentials unreadable) |
| **Secret file access** | Read `~/.netrc`, `~/.npmrc`, `~/.vault-token` | Seatbelt deny rules (macOS) / Landlock deny (Linux) |
| **Destructive GitHub ops** | `gh repo delete`, `gh pr merge`, `gh release create` | gh guard command interception (opt-in) |
| **Unreviewed code push** | `git push origin main` | git guard command interception (opt-in) |
| **Git alias push bypass** | `git -c alias.p=push p origin main` | git guard blocks `-c alias.*` and denies unknown subcommands |
| **Git subtree push bypass** | `git subtree push --prefix=lib origin main` | `subtree` in explicit block list, plus deny-unknown policy |
| **Multi-refspec bypass** | `git push origin feature main` | git guard checks ALL refspecs, not just the first |
| **Token exfiltration via CLI** | `gh auth token` prints raw token | gh guard serves the cached token once at startup and deletes the file, so subprocesses get nothing |
| **Cross-repo operations** | `gh pr close -R other-org/other-repo` | gh guard scope checking against current repo |
| **Org/user data enumeration** | `gh api /orgs/.../audit-log` leaks PII | gh guard restricts API to `/repos/{current-repo}/...` endpoints only |
| **DNS rebinding SSRF** | Domain resolves to `127.0.0.1` after check | Post-DNS-resolution IP validation; `--allow-private-domain` opt-in bypass for explicitly trusted internal domains |
| **Sandbox profile injection** | Path with `\n(allow file-read* (subpath "/"))` | SBPL path character validation (macOS) |
| **Cross-session profile replacement** | Overwrite another session's SBPL profile in the shared temp dir before the kernel reads it | The profile is passed to `sandbox-exec -p` as an argument; it is never written to disk, so there is no file to swap |
| **Write-then-exec in /tmp** | Drop binary in `/tmp`, execute it | Seatbelt deny (macOS) / Landlock deny (Linux); `--scratch-dir` provides a safe alternative |
| **Cloud metadata access** | Fetch `169.254.169.254` or CGNAT range | Private IP blocklist covering all reserved ranges |
| **Cross-project access** | Read files outside project directory | Seatbelt subpath (macOS) / Landlock ruleset (Linux) |
| **Process-group escape** | Kill parent, children continue unsandboxed | Signal forwarding (SIGTERM, SIGHUP) |
| **Env var credential theft** | Read `AWS_SECRET_ACCESS_KEY` from env | `env_clear()` plus safe allowlist |
| **Persistence via native modules** | Replace `keytar.node` with malware | Deny writes to `~/.copilot/pkg` |
| **Git hook injection** | Write post-checkout hook that runs outside sandbox | Seatbelt write-deny (macOS). **Landlock leaves project `.git/hooks` writable**, and env hardening does NOT stop a planted hook running unsandboxed on the next `git` run. Bubblewrap re-binds `.git/hooks` read-only, which mitigates the *direct* file-planting vector on Linux. **Residual:** `.git/config` stays writable, so `core.hooksPath` can still redirect hooks to a writable dir. See [Linux namespace isolation](#linux-namespace-isolation-bubblewrap) |
| **Git config hijacking** | Set `core.hooksPath=/tmp/evil` or URL redirect | Seatbelt write-deny (macOS). **Linux leaves `.git/config` writable** and Bubblewrap deliberately keeps it that way, for the reasons in [Linux namespace isolation](#linux-namespace-isolation-bubblewrap). The injected `GIT_CONFIG_*` overrides constrain config resolution for in-sandbox git runs, and the proxy blocks redirected fetches (Linux) |
| **Submodule supply chain** | Modify `.gitmodules` to point to malicious repo | Seatbelt write-deny (macOS). **Linux leaves `.gitmodules` writable**, deliberately, because `git submodule add` writes it; proxy domain filtering limits reachable clone targets (Linux) |
| **Syscall abuse** | `ptrace`, `mount`, `kexec_load` | seccomp-BPF filter (Linux) |

### Platform enforcement comparison

| Protection | macOS (Seatbelt) | Linux (Landlock + seccomp) | Linux (+ Bubblewrap) |
|---|---|---|---|
| Credential files (~/.ssh, ~/.aws) | ✅ Kernel deny | ✅ Not in ruleset (deny-by-default) | ✅ Landlock (deny-by-default) |
| Project .env file read/write/delete | ✅ Kernel deny | ⚠️ Proxy blocks exfiltration | ⚠️ Proxy blocks exfiltration |
| .git/hooks write in project | ✅ Kernel deny | ❌ Writable (Landlock can't sub-deny; env hardening does NOT block hook planting) | ⚠️ Re-bound read-only (blocks direct file planting; `core.hooksPath` via writable `.git/config` is a residual) |
| .git/config write in project | ✅ Kernel deny | ❌ Writable (env hardening constrains in-sandbox config resolution only) | ❌ Deliberately writable (read-only would break git config/remote ops and risk a stale `.git/config.lock`) |
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

On Linux, cplt can optionally layer **Bubblewrap** (`bwrap`) on top of Landlock + seccomp-BPF. Bubblewrap is what Flatpak uses, and it gives us battle-tested unprivileged namespace setup. It is defense-in-depth for the Landlock/seccomp layer, not a replacement for it. Landlock (filesystem and network access control) and seccomp (syscall filtering) remain the enforcing boundary; bwrap adds process, IPC, and hostname isolation plus a private `/tmp` around them.

**What bwrap adds:**

1. **PID namespace.** The agent cannot see or signal host processes. `ps` shows only the agent's own process tree, which stops process enumeration.
2. **IPC / UTS / cgroup namespaces.** No shared SysV IPC, an isolated hostname, an isolated cgroup view.
3. **Mount namespace.** The whole host filesystem is bind-mounted **read-only** (`--ro-bind / /`); write access is granted only at the specific paths carrying a writable Landlock rule, re-bound writable at their real locations. The host root is therefore still *enumerable* inside the namespace. The mount namespace only changes the mount topology, it does not hide arbitrary files. Confidentiality is Landlock's job (deny-by-default): a path with no read rule is denied by Landlock even though it appears in the mount table.
4. **Private `/tmp`.** `/tmp` is a fresh, empty `tmpfs` that carries no exec-bearing Landlock rule, so the "no exec from `/tmp`" guarantee holds. The scratch dir (write+exec) stays at its real path and is never overlaid on `/tmp`. A writable path that legitimately lives under `/tmp` (say a `--project-dir` in `/tmp`) is re-bound *after* the tmpfs so it stays usable.
5. **User namespace.** Unprivileged operation, no root required. The agent maps to the **invoking host UID**, there is no UID-0 mapping, and it holds no real capabilities on the host.
6. **Git-persistence read-only re-bind.** See below.

#### The git-persistence re-bind

The set of paths that must stay unwritable inside a writable tree is defined once, in `sandbox_policy.rs` (`PROTECTED_IN_ROOT` and `PROTECTED_IN_GITDIR`). Each entry states its own Linux coverage: `Bwrap` if the read-only overlay carries it, or `Gap(reason)` if Linux does not enforce it at all. Seatbelt turns the whole set into deny rules, bubblewrap re-binds the `Bwrap` subset read-only, and **Landlock enforces none of it** — it is additive, so a sub-path cannot be subtracted from an allowed writable tree. The backends choose the mechanism; they no longer each decide the list.

The project's `.git/hooks` and `.cplt.toml` live *inside* the writable project tree, and Landlock cannot carve a sub-deny out of it, so on the Landlock-only path they stay writable. That is a persistence-escape gap against macOS. When bwrap is active, those two pre-existing paths are re-bound **read-only** (`--ro-bind`, emitted after the writable project bind so it shadows it), so an agent can no longer plant a `.git/hooks/post-commit` that runs unsandboxed on the next `git` run, nor drop a `.cplt.toml` that relaxes the next session's sandbox. In a git **worktree** the project's `.git` is a gitdir *pointer file*, so `<project>/.git/hooks` does not exist and the real hooks live under the shared common dir that the sandbox grants write access to; `<git_common_dir>/hooks` is therefore re-bound read-only too, otherwise the worktree persistence vector would be missed.

The set is deliberately narrow. `.git/config` and `.gitmodules` are left writable on purpose, because read-only binding them would break legitimate in-sandbox git operations: `git config user.email` / `user.name` identity setup, without which the next `git commit` fails with "Please tell me who you are", plus `git remote add`, `git push -u` upstream tracking, and `git submodule add`, which writes `.gitmodules`. There is a second reason. Git rewrites config via a `.git/config.lock` plus rename, so a denied write could leave a **stale `.git/config.lock`** that blocks the user's next out-of-sandbox git. This matches the git command guard, which explicitly allows `git config user.name`.

Four residuals come with this. Because `.git/config` stays writable, an agent can still set `core.hooksPath` to redirect hooks into a writable directory, so the `.git/hooks` bind mitigates the *direct* file-planting vector only, not all git-hook persistence. A read-only bind protects only paths that *already exist* at launch, since bwrap cannot bind a nonexistent source, so a not-yet-created `.cplt.toml` can still be created. Submodule hooks (`.git/modules/<name>/hooks`) are not covered. And the whole mitigation requires bwrap; the Landlock-only path stays exposed.

Bubblewrap deliberately does not create a network namespace (see the limitations below), so it is not a network or confidentiality boundary.

**How Landlock and seccomp stay enforced (fail-closed):**

`bwrap` needs `unshare`/`mount`/`pivot_root` to build the namespaces, exactly the syscalls our seccomp filter `EPERM`s, and the bind-mount sources are what a restrictive Landlock domain would block. So Landlock and seccomp are **not** applied to the `bwrap` process. They are applied to the **agent**, inside the namespaces, after bwrap finishes setup:

```text
cplt ──exec──▶ bwrap (creates namespaces, unrestricted)
                 └─exec──▶ cplt re-entry helper (in-namespace)
                             │  applies Landlock + seccomp bound to the
                             │  inodes visible *inside* the namespaces
                             └─execve──▶ agent (Landlock + seccomp enforced)
```

The re-entry helper is this same cplt binary, dispatched by an `.init_array` constructor keyed on the `__CPLT_BWRAP_POLICY_FD` environment variable. The Landlock policy and agent argv arrive over an **inherited pipe**, so nothing is written to disk and the fresh `--tmpfs /tmp` cannot hide it. Because the helper opens its Landlock rule paths *inside* the namespaces, the effective policy is identical to the non-bwrap path. If any step of the helper fails it `_exit(126)`s **before** the agent runs, so the agent is never executed unsandboxed. A one-byte confirm pipe lets the parent detect that the inner sandbox was applied. On auto-detect, a missing confirmation degrades gracefully to the direct Landlock+seccomp path; explicit `--use-bubblewrap` treats it as a hard error.

**Activation:**

- **Auto-detect (default):** if `bwrap` is in PATH and can actually create the namespaces (probed by running the real `build_bwrap_args` output against `/bin/true`), cplt uses it. Otherwise it falls back to Landlock+seccomp.
- **Explicit enable:** `--use-bubblewrap` or `sandbox.use_bubblewrap = true`, which hard-fails if bwrap is unavailable rather than silently falling back.
- **Explicit disable:** `--no-bubblewrap` or `sandbox.use_bubblewrap = false`, which uses Landlock+seccomp only. If both are given, off wins.

**Graceful degradation:** Bubblewrap requires a kernel with unprivileged user namespaces enabled. Without bwrap or namespace support, cplt falls back to Landlock + seccomp-BPF, which still provides the full filesystem and syscall isolation. bwrap changes the process and mount topology, not the access-control policy.

**What bwrap does NOT provide:**

- **No network isolation.** There is no network namespace. The host network is shared **by design**, so the sandboxed agent can reach cplt's CONNECT proxy on `127.0.0.1`. Outbound control stays with Landlock TCP port rules (ABI v4+) and the proxy, exactly as on the non-bwrap path. Kernel-level network isolation (a private netns with the proxy bridged in) is future work tracked in [issue #114](https://github.com/navikt/cplt/issues/114).
- **No filesystem confidentiality from the mount namespace.** The full host filesystem is enumerable read-only. Landlock, not the mount namespace, is what denies reads.
- **No UID remapping.** The host UID is visible inside the user namespace (an integration test asserts this). There is no root/UID-0 illusion.

**The layers, honestly attributed:**

- Filesystem: **Landlock** (deny-by-default) is the access control. The mount namespace only makes the host root read-only and provides a private `/tmp`.
- Network: **proxy** (domain filtering) plus **Landlock** port filtering (6.7+). Bubblewrap adds nothing here.
- Syscalls: **seccomp-BPF** (ptrace, mount, kexec_load, unshare, and more), applied to the agent inside the namespaces.
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

- **TLS interception.** The proxy sees CONNECT targets (hostname:port), not request bodies or responses.
- **Kernel exploits.** We rely on Apple's Seatbelt (macOS) and Landlock/seccomp (Linux) enforcement being correct.
- **Keychain isolation** (macOS). See [Keychain access is all-or-nothing](#keychain-access-is-all-or-nothing) below for what the grant actually reaches and when cplt drops it. `mach-lookup` is blanket because Node.js needs it for DNS, the Security framework, and system services. The **clipboard** (`com.apple.pasteboard`) is reachable through that same blanket allow; `--deny-clipboard` adds a targeted deny that blocks only the pasteboard service and leaves all others intact.
- **sandbox-exec deprecation** (macOS). Apple marks it deprecated but has not removed it, and Chromium and VS Code still use it.
- **Landlock subpath limitations** (Linux). Landlock cannot deny access to subpaths within allowed directories. If a parent directory is allowed, all children are allowed. Certain fine-grained macOS rules therefore cannot be replicated on Linux, for example denying `.config/gh/extensions` while allowing `.config/gh/hosts.yml`. When Bubblewrap is active, user deny paths (`--deny-path` / `deny.paths`) ARE enforced despite this, via mount masks (see the platform comparison table). The built-in fine-grained rules stay macOS-only.
- **Code quality.** The sandbox cannot judge whether code written by Copilot contains backdoors. That is a code review problem.
- **`~/.config/gh/hosts.yml` token.** It contains the user's GitHub OAuth token and stays readable inside the sandbox. Copilot needs *a* GitHub token to function, via env var or this file. If that concerns you, set the `GH_TOKEN` env var (it passes the allowlist) and add `--deny-path ~/.config/gh` to block the file. See [Honest gaps](#honest-gaps) for the full analysis.
- **Interpreter-based temp execution.** The sandbox blocks *direct* exec from `/tmp` (Mach-O/ELF binaries, dlopen), but it cannot block `bash /tmp/evil.sh` or `node /tmp/evil.js`, because the exec target is the interpreter (`/bin/bash`, `/usr/bin/node`), not the script file. Sandboxing interpreters would break Copilot.
- **`.vscode/` project configs.** The agent can write `.vscode/tasks.json`, `launch.json`, and `settings.json`, which VS Code may auto-execute outside the sandbox. This is an IDE trust boundary issue, not a sandbox scope issue. Mitigation: review `.vscode/` changes in `git diff` before committing, and set `"task.autoRunTasks": "off"` in VS Code.
- **Write+exec in home cache dirs.** The dependency stores (`~/.cargo/registry`, `~/.cargo/git`, `~/.gradle`, `~/.m2`, `~/.nuget`, `~/go/pkg`, the pnpm stores) are writable and can have shared libraries **mapped** executable from them, because build tools need write for dependency downloads and `dlopen` for proc-macro dylibs, JNI and cgo native libs. None of them can `execve()` a binary: macOS emits a compensating `(deny process-exec)` for every `write && !process_exec` tool dir, and since [#243](https://github.com/navikt/cplt/issues/243) Landlock's `EXECUTE` right follows `process_exec` alone — see [Landlock cannot express `map_exec`](#landlock-cannot-express-map_exec) for what that changed and what is left. A rogue agent could still write a malicious JAR to `~/.m2` or a Gradle plugin to `~/.gradle` and have the build load it, but the executed code stays sandboxed. `~/Library/Caches` (macOS) is broadly allowed for dev tool caches (go-build, Homebrew, pip), while browser and app caches (Chrome, Firefox, Discord) are denied via regex prefix rules, so new dev tools need no allowlist maintenance. `--allow-cache-exec <SUBDIR>` opts into the same write+exec trade-off for one named subdir such as `ms-playwright` or `pnpm/dlx`, under `~/Library/Caches` (macOS) or `~/.cache` (Linux). A rogue agent could write a binary there and execute it, but execution stays sandboxed. On Linux the subdir is validated as a traversal-free relative path before a Landlock execute rule is granted, so `../../bin` cannot escape the cache dir. Prefer it over `--allow-cache-exec-any`, which opens the entire cache tree.
- **User-granted exec trees** (`allow.exec` / `--allow-exec`). A tool prefix outside the default tool directories — a relocated Homebrew or toolchain root — gets read and execute, never write. Two grants are refused outright rather than granted narrowly: an unsafe root — `/`, `/tmp`, `$HOME` and any ancestor of it, or a platform system directory such as `/usr` or `/etc` — and any tree overlapping a writable one — the project directory, an `allow.write` grant, a writable tool directory such as `~/.cache` (use `--allow-cache-exec` there), a **writable agent data directory** (`~/.claude`, `~/.local/share/opencode`, `~/.pi/agent`, `~/.config/fish` — granted by the backends from the agent's own layout, not by config, which is why they were missing from the check), the **git common dir** of a worktree or bare repo, or a tree the backends make writable with no `allow.write` at all: `/tmp` and `/dev/shm` on Linux, `/private/tmp` and `/private/var/folders` on macOS ([#299](https://github.com/navikt/cplt/issues/299); use the scratch dir, or `--allow-tmp-exec` if you really mean all of temp — it does not cover `/dev/shm`, which has no grant to withdraw). The overlap is refused because writable plus executable is a binary-drop staging path, and neither backend can subtract the write from the exec: Landlock unions a write rule on an ancestor with an exec rule on a child with no way to remove it, and the only Linux alternative — a bubblewrap `ro_protect` mount — is absent on any host without user namespaces. Refusing is also the one answer both backends give alike. On macOS the write-deny for the granted tree is emitted last in the profile, after every allow, because SBPL is last-match-wins. Code executed from the tree still runs inside the sandbox.
- **User-granted write trees** (`allow.write` / `--allow-write`). Since [#243](https://github.com/navikt/cplt/issues/243) a granted tree is writable but **not executable**: `process-exec` is granted profile-wide on macOS, so before that fix any `allow.write` grant was silently also an exec grant — the same binary-drop pair `allow.exec` grants are refused for. On Linux a write rule never carried execute in the first place, so the two backends now agree. Three execute rights are re-issued after the deny, and only where they fall inside the granted tree: the project directory and the scratch dir, both write+exec by design, and the `EXEC_IN_WRITABLE` table in `sandbox_policy.rs` — `~/.gradle/jdks` and `~/.bun/install`, which were already write+exec before any grant. Everything else loses execute, including tool directories: `allow.write = ["~/.cargo"]` makes `~/.cargo/bin` writable, and a writable `~/.cargo/bin` is a trojan that outlives the session, so it does not also stay executable. If you need both, they belong in two grants on two trees — and `allow.exec` refuses the overlap if they are not.
- **Landlock cannot express `map_exec`.** <a id="landlock-cannot-express-map_exec"></a>macOS separates `file-map-executable` (mapping a dylib's pages executable) from `process-exec` (running a binary). Landlock has no such split: its `EXECUTE` right is checked on `execve()` — `file_open` with `FMODE_EXEC` — and there is no hook for `mmap(PROT_EXEC)`, which a dynamic loader reaches with `READ_FILE` alone. cplt used to compute the Landlock execute bit as `process_exec || map_exec`, so every dependency store that carries `map_exec` for dylib loading was **write+execute on Linux and nowhere else** ([#243](https://github.com/navikt/cplt/issues/243)). The bit now follows `process_exec` alone. Three trees keep `EXECUTE` on Linux anyway, each recorded in `EXEC_IN_WRITABLE` with its reason and a `LinuxCoverage::Gap`, because Landlock cannot subtract the parent's write grant and the bubblewrap read-only bind that could is absent on hosts without user namespaces:
  - `~/.gradle/jdks` — Gradle provisions toolchain JDKs here and execs them. macOS grants the same exec and takes the write back at the tail of the profile; Linux cannot do the second half, so the tree stays write+execute there.
  - `~/.dotnet` — `DOTNET_ROOT` for SDKs installed by `dotnet-install.sh`. macOS re-grants exec through the configured `dotnet_root`; Landlock has no counterpart rule.
  - `~/.konan` — Kotlin/Native execs the LLVM toolchain it downloads into `~/.konan/dependencies`.
  The last two are **stated gaps, not decisions**: the fix was written and verified on macOS, and neither a real .NET nor a Kotlin/Native build could be run on a Linux host to show whether dropping `EXECUTE` breaks them. A wrong carve-out either reopens the hole or breaks every user of the tool, so the pre-existing right is kept until a Linux host can settle it.
- **Playwright Chromium runtime** (macOS, `allow_cache_exec = ["ms-playwright"]`). Enabling browser testing grants system permissions well beyond the normal `process-exec` and `file-map-executable` rules:
  - `(allow syscall*)`, meaning all syscalls including Mach traps. Chromium uses undocumented traps that vary by macOS version and cannot be enumerated in a stable allowlist.
  - `(allow system-socket (socket-domain AF_UNIX))` for IPC between the browser, renderer, and GPU processes.
  - `(allow iokit-open-user-client)` for GPU capability probing, unscoped because IOKit class names are hardware-dependent.
  - `(allow mach-register)` scoped to three narrow namespaces: `^org\.chromium\..+$` for Crashpad and inter-process IPC, anchored with `$` and requiring at least one character after the prefix; `^com\.google\.chrome\.for\.testing\.MachPortRendezvousServer\.[0-9]+$` for Playwright's Chrome for Testing rendezvous service, fully anchored with a numeric PID suffix; and the `com.google.chrome.for.testing.apps.` app-shim namespace with a suffix of exactly 64 uppercase hexadecimal characters. The emitted SBPL spells that suffix as 64 adjacent `[0-9A-F]` atoms because counted repetition did not match in Seatbelt. Lowercase, non-hexadecimal, shorter, longer, and other product or bundle-ID variants remain denied. Denying either Chrome for Testing registration causes `EPERM (1100)` and prevents the browser from completing startup and CDP navigation.

  Unix socket operations for Chrome's `SingletonSocket` use `[^/]+/[^/]+` for the `var/folders` path segments, so a match cannot cross directory boundaries. All filesystem, network, and credential denies stay enforced independently. These rules activate only when `allow_cache_exec` contains `"ms-playwright"` or any subpath such as a versioned Chromium directory (first path component match); `allow_cache_exec_any` and unrelated entries do not trigger them. Without them, `chrome-headless-shell` segfaults (`SEGV_ACCERR`) during browser initialization, while Chrome for Testing fails its Mach registrations.

  With the same explicit Playwright opt-in, cplt creates one short socket base named `/private/tmp/cplt-pw-<32 lowercase hex>` and sets `PWTEST_SOCKETS_DIR` to that exact path. Creation is atomic from a cryptographically random session ID; the directory is a current-user-owned, non-symlink directory with mode `0700`. A guard owns it for the full child lifetime and removes only that exact directory on exit. A hard termination such as `SIGKILL` skips that guard and leaves the empty directory behind; it carries no capability once the process is gone, and reclaiming it automatically would need a descriptor-relative deletion primitive cplt does not have today. The fixed 53-byte shape is independent of `HOME` and scratch, and leaves conservative headroom below Playwright's 103-byte Unix-socket limit after its observed longest domain and fallback socket suffix are appended.

  The macOS profile grants only `network-bind` and `network-inbound` for local Unix sockets and `network-outbound` for remote Unix sockets beneath that concrete validated directory. It does not grant socket operations on `/private/tmp` itself, siblings, project or scratch paths, and adds no file or temp-execution permission; the existing `/private/tmp` file rules and execution denies remain unchanged. Ambient and inherited values cannot move the automatic capability elsewhere. An explicit `--pass-env PWTEST_SOCKETS_DIR`, from the flag or from `sandbox.pass_env` in config, preserves the caller's value and suppresses both automatic directory creation and its SBPL socket rules; repo `deny.env` still applies last. Passing the key through without exporting a value leaves the child with no socket directory at all, so cplt warns that Playwright will fall back to a `TMPDIR` path that is usually too long.

  **macOS nested sandbox:** Chrome helpers inherit cplt's Seatbelt profile, so Chromium's own Seatbelt initialization fails with `forbidden-sandbox-reinit`. Chromium must therefore launch with `--no-sandbox`. Playwright used as a library already does that by default, and for Playwright MCP, which turns it back on, the same `ms-playwright` opt-in sets `PLAYWRIGHT_MCP_SANDBOX=false` for the child. This is the treatment cplt already gives Gradle's nested `sandbox-exec`, and it keeps a cplt-only workaround out of the MCP server configuration that editors and CLIs share with machines that have no cplt around them. An explicit `--pass-env PLAYWRIGHT_MCP_SANDBOX` hands the choice back to the caller. Any other Chromium launcher still needs its own flag. Chrome and all helpers remain inside the outer cplt profile.

  Launching Chromium this way removes its OS-enforced child privilege separation. A compromised renderer receives the complete cplt Playwright profile, including project read/write access, `syscall*`, AF_UNIX sockets, and IOKit user clients. cplt remains the enforcing boundary, and its filesystem, network, environment, and credential restrictions still apply. This is an explicit trade-off of the `ms-playwright` opt-in, which is the only thing that disables Chromium's sandbox: without it cplt sets nothing, and no browser process is launched outside cplt.

  **Linux:** `--allow-cache-exec ms-playwright` grants Landlock execute on `~/.cache/ms-playwright` (the XDG equivalent), so the browser binary runs. The macOS Seatbelt/Mach permissions above have no Linux analogue. The remaining difference is Chromium's *own* sandbox: on Linux it builds a setuid-less sandbox from user namespaces (`unshare`/`setns`/`clone` with `CLONE_NEW*`), and cplt's seccomp-bpf filter denies `unshare`/`setns` with `EPERM`, because user-namespace creation is a sandbox-escape tool (see "Defense layers"). cplt deliberately does **not** relax the filter for browser testing. Run Chromium with its own sandbox disabled instead (`--no-sandbox`, or Playwright `chromiumSandbox: false`). cplt's Landlock + seccomp is the enforcing boundary, so Chromium's nested sandbox is redundant inside it. `/dev/shm` is already allowed, so `--disable-dev-shm-usage` is not required.
- **Project build scripts.** The agent can modify `Makefile`, `package.json` scripts, `build.gradle`, `.github/workflows/`, and the like. These are legitimate Copilot targets and cannot be blocked. Code review (git diff) before running builds or committing is the mitigation.
- **POSIX shared memory** (macOS). `ipc-posix-shm-*` is allowed because Node.js needs it for DNS and system queries. An agent could in theory use SHM as an IPC channel to processes outside the sandbox, but that requires a cooperating process already running on the machine.
- **DNS tunneling.** DNS queries are unrestricted on both platforms. See [Honest gaps](#honest-gaps) for why we accept this.

## Real-world attack landscape (2025-2026)

These are the attack vectors and infrastructure seen in real supply chain attacks. cplt is designed to mitigate them.

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
| **Shai-Hulud** | 2025 | Compromised npm maintainer accounts | Self-replicating worm hit 700+ packages, stole npm tokens and AWS keys |
| **CamoLeak** | 2025 | Prompt injection in PR comments | Copilot Chat exfiltrated private code via GitHub image proxy (CVE-2025-59145, CVSS 9.6) |
| **RoguePilot** | 2026 | Prompt injection in GitHub issues | GITHUB_TOKEN leaked from Codespaces, enabling full repo takeover |
| **YOLO Mode** | 2025 | Agent writes to .vscode/settings.json | Auto-approved all commands, giving RCE (CVE-2025-53773) |
| **MCP Poisoning** | 2026 | Hidden instructions in npm metadata | AI agents extracted SSH keys from dev machines, invisible to user |
| **axios RAT** | 2026 | Trojanized npm package by STARDUST CHOLLIMA | Hidden RAT deployed to any system where an AI agent ran `npm install` |

### Exfiltration infrastructure (observed in the wild)

| Category | Domains/services | Why attackers use them |
|---|---|---|
| **Discord webhooks** | `discord.com/api/webhooks/*` | Write-only, no authentication needed, blends with legitimate traffic |
| **Webhook capture** | `webhook.site`, `pipedream.com`, `requestbin.com` | Disposable endpoints, no signup required |
| **Tunneling** | `ngrok.io`, `localtunnel.me`, `serveo.net` | Reverse shells through NAT/firewall boundaries |
| **Paste sites** | `pastebin.com`, `paste.ee`, `hastebin.com` | Credential dump staging for later retrieval |
| **File sharing** | `transfer.sh`, `file.io`, `0x0.st`, `catbox.moe` | Exfiltration of SSH keys and .env files |
| **Telegram** | `api.telegram.org` | Bot API as a write-only C2 channel |
| **IP recon** | `ipinfo.io`, `ifconfig.me`, `checkip.amazonaws.com` | Victim network fingerprinting |
| **Cloudflare Workers** | `*.workers.dev` | Free hosting for C2 relays, resistant to takedown |
| **Ethereum dead-drop** | Smart contract to Cloudflare-fronted domains | C2 URL rotation without code changes, impossible to take down |

A curated blocklist of these domains ships in [`blocked-domains.txt`](blocked-domains.txt).

### What gets stolen (in order of attacker priority)

1. **npm/pip tokens.** Enables worm propagation (Shai-Hulud took 700+ packages using stolen tokens).
2. **CI/CD tokens.** GITHUB_TOKEN, AWS keys from environment variables.
3. **SSH keys.** `~/.ssh/id_*`
4. **Cloud credentials.** `~/.aws/credentials`, `~/.config/gcloud`
5. **Environment files.** `.env`, `.env.local` (API keys, database URLs).
6. **Network topology.** Internal IPs, DNS servers, hostnames, all recon for lateral movement.

### How cplt defends against each step

| Kill chain step | Attack technique | Sandbox defense | Verdict |
|---|---|---|---|
| **1. Infection** | `postinstall` hook runs code | **Blocked by default.** Hardening injects `npm_config_ignore_scripts=true` and `YARN_ENABLE_SCRIPTS=false` | ✅ **Stopped** |
| **2. Recon** | Read hostname, IP, env vars | Can read process env vars (needed for Copilot), hostname | ⚠️ Partial leak possible |
| **3. Credential harvest** | Read ~/.ssh, ~/.aws, .env | **Kernel-blocked.** macOS Seatbelt denies the read syscall. | ✅ **Stopped** |
| **4a. HTTP exfil** | POST to discord/webhook/C2 | Only port 443 allowed. On macOS localhost and the SSH agent socket are blocked too; on Linux neither is, and UDP is unrestricted unless `proxy.forced` is on (see [Linux-specific limitations](#linux-specific-limitations)). Credentials are unreadable, so the blast radius is small. The proxy blocklist helps if enabled. | ⚠️ **Partially mitigated** |
| **4b. DNS tunneling** | Encode data in DNS queries | Not inspected; DNS bypasses the proxy | ❌ **Not stopped** |
| **4c. Reverse shell** | Connect back via ngrok | Non-standard ports blocked; `ngrok.io` blocked when proxy enabled; localhost blocked | ⚠️ **Partially mitigated** |
| **5. Binary staging** | Drop RAT into cache dir and execute | **Kernel-blocked by default.** `~/Library/Caches` has no `process-exec` or `file-map-executable`, and `/tmp` exec is denied. `--allow-cache-exec <SUBDIR>` grants exec to one named subdir, and the write+exec risk applies there. `--allow-exec <PATH>` grants exec on a named tool prefix, but never write: a grant overlapping the project dir or an `allow.write` grant is refused at startup on both backends. | ✅ **Stopped** (⚠️ opt-in exemption available) |
| **Worm propagation** | Republish infected packages | Can't read npm tokens (in ~/.npmrc, kernel-blocked) | ✅ **Stopped** |

### Honest gaps

**Network is port-restricted, with optional domain filtering.** SBPL (Seatbelt Profile Language) has no domain-based filtering at the kernel level, and Copilot CLI connects to CDN-backed endpoints (`api.business.githubcopilot.com`) whose IPs change and cannot be enumerated. So we allow outbound TCP on port 443 only, with `--allow-port` for extras such as `--allow-port 80`. On macOS, SSH agent access and localhost outbound are blocked at the kernel level; on Linux neither is, see [Linux-specific limitations](#linux-specific-limitations). That leaves:

- A compromised agent CAN make HTTPS requests to attacker-controlled servers on port 443
- A compromised agent CANNOT exfiltrate cloud credentials from env vars (env is sanitized; only the safe allowlist passes through)
- A compromised agent CAN exfiltrate project source code and Copilot auth tokens
- A compromised agent CANNOT connect to local services (localhost is blocked on macOS; on Linux use `--with-proxy`, see [Linux-specific limitations](#linux-specific-limitations))
- A compromised agent CANNOT use loaded SSH keys **on macOS**, where `(deny default)` plus the per-path `network-outbound … unix-socket` allows leave the agent socket unreachable at the kernel level. **On Linux it CAN below kernel 7.1**: Landlock gains the unix-socket `connect()` right only at ABI v9, and the agent socket is not in the set bubblewrap masks, so the withheld `SSH_AUTH_SOCK` is the only barrier and an agent that sets it itself can use the loaded keys. bwrap's private `/tmp` hides the stock OpenSSH socket but not a desktop agent under `$XDG_RUNTIME_DIR`, see [Linux-specific limitations](#linux-specific-limitations)
- A compromised agent CANNOT connect on non-standard ports such as 8080 or 3000 unless `--allow-port` is used
- A compromised agent CANNOT exfiltrate SSH keys, cloud credentials, or npm tokens (kernel-blocked from reading them)
- A compromised agent CAN request GPG signatures but CANNOT exfiltrate private keys. On macOS this needs `--allow-gpg-signing`; on Linux the agent socket is reachable whether or not the flag is set, so the capability is there by default (see [Linux-specific limitations](#linux-specific-limitations))
- The proxy logs and filters all outbound connections by default, including Copilot CLI traffic (via `NODE_USE_ENV_PROXY=1`), and enforces port restrictions matching the sandbox policy. Use `--no-proxy` to disable.

*Mitigation:* `--allowed-domains allowed-domains.txt` restricts traffic to known Copilot endpoints, `--blocked-domains blocked-domains.txt` blocks known exfiltration infrastructure, and `--proxy-log proxy.log` gives a post-session audit trail. All traffic, Copilot's own Node.js connections included, routes through the proxy.

**JVM IPv4 stack forcing.** macOS SBPL `"localhost"` filters do not match Java NIO's IPv4-mapped addresses (`::ffff:127.0.0.1`), because SBPL accepts only `*` or `localhost` as the host part and rejects literal IPs. cplt injects `-Djava.net.preferIPv4Stack=true` via `JAVA_TOOL_OPTIONS`, forcing the JVM onto pure AF_INET4 sockets, so connections to `127.0.0.1` stay IPv4 and `"localhost:PORT"` rules match. `--allow-localhost <PORT>` therefore works for Java, and the old `"*:*"` nuclear option is gone. Overriding `JAVA_TOOL_OPTIONS` via `--pass-env` loses this protection; fall back to `--allow-localhost-any`. On Linux (Landlock) the flag is not injected, as the kernel handles addresses differently.

**`--allow-private-domain` weakens DNS rebinding protection for named domains.** For a domain listed in `proxy.allow_private_domains` (or `--allow-private-domain`), the proxy skips the post-DNS private IP check. That is intentional for corporate intranet services such as `intern.nav.no` that legitimately resolve to RFC 1918 addresses. The accepted risk: if DNS for a listed domain is poisoned or hijacked, a compromised agent could reach arbitrary private hosts on your internal network, not just the intended service. All other proxy checks (port, allowlist, blocklist) still apply. Only list domains you control and whose DNS you trust.

**`~/.config/gh/hosts.yml` is readable.** With gh guard enabled, Copilot gets its token through a one-time cached file that is deleted after the first read; with gh guard disabled, `gh auth token` works inside the sandbox. The file holds a GitHub OAuth token. Only `hosts.yml` and `config.yml` are readable, not the whole `.config/gh` directory. With outbound port 443 open, a compromised agent could exfiltrate this token, though the token grants access to GitHub, which Copilot is already connected to. To mitigate, use `--deny-path ~/.config/gh`; Copilot falls back to Keychain auth.

**`block_auth_token` is best-effort, not a same-UID boundary.** With gh guard enabled and `block_auth_token` set (opt-in), cplt withholds `GH_TOKEN` from the environment, caches the token to `$SCRATCH/.gh-token` (mode `0600`), serves it once via the `gh` wrapper's `gh auth token` callback, and deletes the file after the first read. That keeps the token out of every child's `/proc/*/environ`, and the deletion narrows the exposure window. It does **not** make the token confidential against an adversarial agent. The scratch dir *is* the agent's `TMPDIR`, and the `gh` wrapper runs as the agent's own UID inside the sandbox, so anything the wrapper can read, the agent can read. A same-UID `deny` rule would be illusory and would break the legitimate wrapper read, so cplt does not add one. An agent that `cat`s `$TMPDIR/.gh-token` before the legitimate consumer still gets the token. Treat `block_auth_token` as reducing accidental and env-based leakage, not as a boundary against a hostile agent.

A repo `deny.env` on any of `GH_TOKEN`, `GITHUB_TOKEN` or `COPILOT_GITHUB_TOKEN` suppresses this cache as well as the environment variable, so `gh auth token` inside such a sandbox returns nothing and no `.gh-token` is written. Denying the token vars means the agent gets no GitHub credential by any channel; serving one through the wrapper would honour the letter of the deny and not its intent.

*Possible mitigation:* a repo-scoped MCP proxy or a fine-grained PAT that limits token scope to the current repository. See issue #4.

**`--allow-browser` grants a sandbox escape, and it cannot be scoped.** The flag (`sandbox.allow_browser`, off by default) emits `(allow lsopen)` so an agent can hand an https URL to your browser during OAuth sign-in. Launch Services starts the target through **launchd, outside the Seatbelt profile**, so what the flag actually grants is "launch any application on this machine, unsandboxed". `open -a Terminal script.sh` is the whole exploit. Wrapping `open` to accept only `http://` and `https://` was investigated for [#251](https://github.com/navikt/cplt/issues/251) and rejected on two measured facts.

- **`lsopen` has no filter in SBPL** — no URL, no bundle id, no path. Every profile under `/System/Library/Sandbox/Profiles` that uses the operation emits it bare, exactly as cplt does. There is no narrower form to write.
- **The grant is reachable without the `open` binary.** A PATH shim only shadows a name; `LSOpenCFURLRef()` calls Launch Services directly. Measured on macOS 15 with a ten-line C program linking CoreServices, compiled outside the sandbox and run inside a real cplt session against `file:///System/Applications/Calculator.app`: **without** `--allow-browser` the call returned `-54` and launched nothing; **with** it, the call returned `0` and Calculator was running outside the sandbox. No `open` process existed in either run. Separately, the blanket `(allow process-exec)` leaves `/usr/bin/open` executable by absolute path, which a PATH shim never sees.

So a shim would constrain only an agent that types `open` politely, which is not the threat model, and shipping one would misrepresent the flag as bounded. cplt does not ship one. The control is the default: leave the flag off, turn it on only while a sign-in prompt is on screen, and turn it back off. Of the supported agents only Antigravity needs it; Copilot, OpenCode and Claude Code use device flows. `cplt config set` treats the key as dangerous and asks for confirmation, and `detect` never proposes it.

**The gh/git guards are a best-effort command filter, not a kernel boundary.** The "gh guard" and "git guard" rows in the threat-model table describe command-level interception. Three properties bound what they can promise.

- **Opt-in.** Both guards default to `enabled = false` (soft rollout), so out of the box cplt performs **no** gh/git command filtering. The fail-closed posture (block mode, default-deny unknown subcommands, scope check, `block_auth_token`, `allow_api_write=false`) takes effect only once an operator sets `gh_guard.enabled = true` / `git_guard.enabled = true` or passes the equivalent flags. A user who assumes "cplt guards git" without opting in gets nothing.
- **PATH-shim enforcement.** The guards write `gh`/`git` shims into a scratch `bin/` dir and prepend it to `PATH`; the shim calls back into cplt for a policy decision before `exec`ing the real binary. The real `/usr/bin/git` and `/usr/bin/gh` are untouched, so any agent that invokes the binary by **absolute path** (`/usr/bin/git push`), **escapes the alias** (`\git`, `env git`), **resets `PATH`**, or **shells out from another runtime** (`subprocess.run(["/usr/bin/git", "push"])`) bypasses the guard entirely. Command classification (force-push detection, scope checks, `gh auth token` blocking, DELETE blocking) therefore only constrains a *cooperative* agent, not an adversarial one.
- **Repository scope is pinned at sandbox startup.** Before the agent starts, cplt invokes the pre-resolved Git binary and reads only the project root's local `remote.origin.url`, with config includes and inherited `GIT_*` variables disabled. That verified scope is baked into the shim. A successful check sets a host-qualified `GH_REPO`, clears `GH_HOST`, and rejects conflicting hostname flags before executing `gh`; failing to determine startup scope blocks the command. Runtime working directories, nested repositories, mutable Git configuration, and environment overrides cannot retarget the check.

The guards raise the bar against accidental and prompt-injected-but-cooperative misuse. They do not substitute for the kernel-enforced filesystem and exec isolation that holds against an adversarial agent. On the *network* side, proxy-forced mode (issues #53 and #117) is the kernel-backed complement: it forces all egress through the cplt proxy at the packet level rather than via tamperable `HTTPS_PROXY` env vars, so a bypassed `git push` or `gh api` write still has to traverse the proxy. Command-level intent (`GET` vs `DELETE` to `api.github.com`) stays invisible to a CONNECT proxy, so the guards and the proxy cover different layers.

**DNS tunneling is the one channel we cannot inspect.** DNS queries are unrestricted on both platforms. What limits the damage: bandwidth is ~15 KB/s at best given the encoding overhead in subdomain labels, it needs an attacker-controlled authoritative DNS server, the most valuable targets (credentials, tokens, keys) are kernel-blocked from being read, and DNS monitoring detects it by the high-entropy subdomain queries to unusual domains.

*Possible mitigation:* route DNS through a local resolver that logs and rate-limits queries, or block DNS entirely and use a pre-configured resolver for known domains. Practical impact is low, since credentials are already inaccessible.

**Reconnaissance leaks basic host info.** Hostname, IP address, OS version, and the sanitized subset of env vars are readable by any code inside the sandbox. This is unavoidable, because Copilot itself needs the information.

*Possible mitigation:* a future hardening category could mask the hostname and inject synthetic env values, at the risk of breaking tools that depend on accurate system info. Low priority, since recon without credential access has little value.

**Project source code is readable and writable.** The agent needs read/write access to the project directory. That is its job. A compromised agent could exfiltrate source over HTTPS on port 443.

*Possible mitigation:* a read-only project mode (`--read-only-project`) for review-only workflows. Outbound bandwidth tracking could flag bulk exfiltration, meaning large POSTs relative to Copilot's normal API pattern, but that needs deep packet inspection.

**`~/.copilot/` session history is broadly accessible.** The sandbox grants read/write to all of `~/.copilot/`, including the session store database (`session-store.db`) holding every past conversation and `session-state/` with per-session artifacts. Copilot's runtime manages these from inside the sandbox and needs the access. A compromised agent could read past conversations to extract business logic, architecture decisions, or referenced credentials.

*Possible mitigation:* `--deny-path ~/.copilot/session-state` blocks access to other sessions' artifacts, at the cost of cross-session features. Scoping the session store to the current session would require changes to Copilot's runtime, since it is a single SQLite file.

Because credentials are inaccessible at both the filesystem and environment level, network-based exfiltration can only leak project source code and `~/.config/gh` tokens. That is a much smaller blast radius than full credential theft.


#### Keychain access is all-or-nothing

The macOS Keychain grant is two SBPL file rules on `~/Library/Keychains` plus the
blanket `(allow mach-lookup)` that reaches securityd. **SBPL cannot narrow it to
one keychain item.** There is no `keychain` operation in the Seatbelt profile
language — `sandbox-exec` rejects `keychain`, `keychain-access`,
`keychain-access-group` and `security-item-read` as unbound variables — and
per-item arbitration happens inside securityd, past the sandbox boundary. So the
choice is the whole login keychain or none of it.

What the grant reaches is bounded by each item's own ACL, not by cplt: an item
whose ACL allows all applications, trusts `/usr/bin/security`, or was set to
"Always Allow" comes out silently. On a developer machine that is a lot more than
the agent's own token — measured on one, the readable set included `gh:github.com`,
`Bitwarden`, `bw_session`, `GnuPG`, and several `* Safe Storage` items. Items
gated on Touch ID or a password are not silently extractable.

Verified by execution: denying only the two file rules is enough. Under a profile
that is otherwise `(allow default)`, `security find-generic-password -s
"Claude Code-credentials" -w` returns the 510-byte credential (exit 0); add
`(deny file-read* file-write* (subpath "$HOME/Library/Keychains"))` and the same
command fails with `SecKeychainSearchCopyNext: The specified item could not be
found in the keychain` (exit 44). Blocking securityd's Mach service instead is
neither necessary nor sufficient on its own.

**The trade is off by default.** It is gated on one experimental config key,
`sandbox.keychain_substitute` (default `false`), covering every agent at once:

```toml
[sandbox]
keychain_substitute = true   # EXPERIMENTAL
```

With it unset, the Keychain grant is exactly what `needs_keychain()` says, for
every agent, as in every release before the key existed. It is off because of the
shape of the failure: if the trade misjudges an agent, the user can neither
authenticate nor recover *from inside the sandbox*, since the recovery path is the
credential store the trade just removed. That is what PR #173 hit, and what the
first Antigravity verification for this change turned out to be — it passed only
because a stale fallback file happened to exist on the test host. Nobody's
authentication should change until they ask for it.

**If your agent cannot authenticate with the key on:** unset
`sandbox.keychain_substitute` (or unset the substitute variable, e.g.
`CLAUDE_CODE_OAUTH_TOKEN`) and the grant comes back on the next run. If the agent
has lost its login entirely, run it once outside cplt to sign in — the browser
flow needs access cplt does not grant by default.

**What the key does when it is on.** Per agent:

| Agent | Grant dropped when (`keychain_substitute = true`) | What the agent holds instead | Refresh |
|---|---|---|---|
| Copilot | never (unverified) | — | — |
| Claude Code | `CLAUDE_CODE_OAUTH_TOKEN` is set | that OAuth token | none — see below |
| Antigravity | `~/.gemini/antigravity-cli/antigravity-oauth-token` exists and is non-empty | that file | refreshes into that file |
| goose | never (provider-dependent) | — | some providers refresh through the keyring mid-session |

The trade is not free. Whole-Keychain read+write is exchanged for a full OAuth
token sitting in the agent's environment, readable by every process it spawns and
exfiltratable over the permitted HTTPS egress. That token is narrower than the
keychain but it is not narrow: `CLAUDE_CODE_OAUTH_TOKEN` is a working Anthropic
credential for the account. What changes is blast radius — one credential the
agent was going to use anyway, instead of every credential the user owns.

That variable is **not** in `ENV_ALLOWLIST` and does not match any allowlisted
prefix, so it is not something the sandbox passes through: it is forwarded by
`apply_deny_env_and_credential` only on runs where the trade actually applied.
With `sandbox.keychain_substitute` off, a `CLAUDE_CODE_OAUTH_TOKEN` exported in
your shell still needs `--pass-env` to reach the agent, exactly as before this
change. `keychain_substitute_vars_are_never_allowlisted` asserts it.

**Why cplt does not pre-extract the Keychain item itself.** The items are refresh
blobs, not static tokens. `Claude Code-credentials` holds an access token with a
few hours of life and a refresh token, and Claude Code rewrites the item in place
(observed: created 26 Aug, modified 2 Sep, `expiresAt` 3h40m out). Handing the
agent that access token and then taking the Keychain away produces a session that
dies mid-work and cannot re-authenticate — the exact failure PR #173 hit for
Copilot. Only credentials that are durable for a whole session qualify.

**Why each agent lands where it does.**

- **Claude Code** — `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`) is built
  straight into the credential without reading secure storage, with
  `refreshToken: null, expiresAt: null`, so no refresh path runs. Verified against
  claude 2.1.258: with `~/Library/Keychains` denied, `claude auth status` reports
  `loggedIn: true, authMethod: oauth_token`. The residual risk is that there is no
  recovery when a long-lived token finally expires — on a 401 Claude Code
  deliberately keeps the env token rather than adopting the stored credential, and
  tells the user to mint a fresh one. `ANTHROPIC_API_KEY` is deliberately *not*
  accepted as a substitute: with a claude.ai login present, Claude Code reports
  `authMethod: claude.ai` and treats the key as merely available, so dropping the
  grant on its account would silently move a subscription user onto per-token API
  billing. Pass it explicitly with `--pass-env ANTHROPIC_API_KEY` if that is what
  you want.
- **Antigravity** — no broker; the grant is dropped only when `agy`'s fallback
  token file is already there. `agy` prefers its keyring and writes the file only
  when the keyring fails: its own strings are "Failed to save token to keyring,
  falling back to file", "Failed to load token from keyring, falling back to
  file" and "Keyring SaveToken timed out ... falling back to file storage". So a
  user whose keyring works has **no** such file, and deleting the grant outright
  strands them — verified by execution: with the file moved aside, `agy models`
  under cplt's real profile returns exit 0, and under the same profile minus the
  two Keychain rules it exits 1 with "Please sign in to view available models".
  Recovering from that needs a browser re-login, and `--allow-browser` is off by
  default. When the file *is* present the trade is safe, also verified: `agy
  models` authenticated, refreshed an already-expired access token, and persisted
  the new one there, with `~/Library/Keychains` denied. Note the honest cost —
  that file holds a refresh token in plaintext at mode 0600 — but `agy` put it
  there itself, with or without cplt. One case fails silently rather than loudly:
  `agy logout` outside cplt clears the keyring but can leave the fallback file
  behind, so a cplt session keeps authenticating with a credential the user
  believes is revoked. Every other way the file goes bad — missing, empty,
  unreadable, corrupt, expired past its refresh token — surfaces as a plain sign-in
  error.

- **goose** — not eligible, and unlike Copilot that is a finding rather than a
  gap. goose's `Config::get_secret` does read the uppercased environment
  variable before its keyring, so precedence is not the problem; the session
  lifetime is. Its GitHub Copilot provider re-reads `GITHUB_COPILOT_TOKEN`
  through that path whenever its cached API info expires, and its OAuth
  persistence layer writes *refreshed* credentials back into the keyring with
  `set_secret` — both mid-session, not at startup. Which of those applies
  depends on the provider goose is configured for, out of the several hundred it
  embeds, so a substitute would have to match the configured provider's key
  rather than any variable from goose's env hints: a developer with
  `OPENAI_API_KEY` exported and goose pointed at Anthropic would otherwise lose
  the keyring and the login with it. `GOOSE_DISABLE_KEYRING` does not rescue it
  either — it sends the same writes to `secrets.yaml` in goose's config dir
  (`$XDG_CONFIG_HOME/goose`, `~/.config/goose` by default), which cplt grants
  read-only. Determined by reading goose's source
  (`aaif-goose/goose`), not by inspecting the credential's shape.

**Copilot is deliberately not eligible.** Claude Code's substitute was
confirmed by running the agent under a profile with the grant dropped; Copilot's
never was. PR #173 asserts an injected `GH_TOKEN` suffices and Copilot's docs
point at these vars, but asserting is not probing — and Copilot is the default,
priority-1 agent, while `GITHUB_TOKEN` is the most commonly exported token on a
developer machine. A fine-grained PAT exported for something unrelated would have
dropped the grant, and if Copilot rejected it the session would have neither. That
is the same precedence question this trade declines to assume, so
Copilot gets the same answer until someone probes it. Re-enabling it is one line
in `Agent::keychain_substitute_env_vars`.

The fallback is deliberate in both directions: when no substitute credential
resolves, the grant stays and the session summary says so, rather than launching
an agent that cannot authenticate and — with the Keychain gone — cannot recover.
A repo `.cplt.toml` `deny.env` entry naming a substitute variable counts as "not
resolved": that list is stripped from the child environment, so honouring it as a
substitute would leave the run with neither Keychain nor token from a checked-in
file.

## Defense layers

### A property that holds across all of them: no silent grants

A grant or setting that cannot be honoured fails loudly at the point it is
written. It is never accepted and then quietly dropped.

This is a security property, not a usability one. A restriction that silently
does nothing leaves an operator believing a path is closed when it is open, and
nothing in the tool contradicts that belief. The failure is invisible by
construction: the config still lists the setting, `cplt config show` still prints
it, and the sandbox still starts.

The property has been broken in both directions and fixed each time: `allow.read`
on a hard-denied file worked on Linux while being silently overridden on macOS
(#207); `--allow-socket` emitted file rules that `connect()` never consults, so
it granted and denied nothing on Linux (#240); `allow.write` inside a credential
directory was inert on macOS while working on Linux (#291); read-only grants
under `/tmp` disappeared inside bubblewrap's private tmpfs (#299); the `[audit]`
section was settable and displayed while no code consumed it (#309).

Where a control genuinely cannot be enforced on a platform, that is documented as
a stated gap with the kernel reason for it, not left as an absence. The Linux
sections below say where those gaps are.

### Layer 0: Environment variable sanitization

By default `cplt` clears the child process environment and re-adds only safe variables from an allowlist, so credentials cannot leak through inherited env vars.

**How it works:**
1. `cmd.env_clear()` removes all environment variables
2. Variables matching `ENV_ALLOWLIST` (49 safe vars) are re-added from the parent process
3. Variables matching `ENV_PREFIX_ALLOWLIST` (9 prefixes: `LC_*`, `COPILOT_*`, `COREPACK_*`, `MISE_*`, `NVM_*`, `PYENV_*`, `SDKMAN_*`, `YARN_*`, `OTEL_*`) are re-added
4. `--pass-env VAR` adds explicit vars (repeatable)
5. `ENV_ALWAYS_DENY` vars (`NO_COLOR`, `FORCE_COLOR`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`) are always stripped

**Deliberately allowed:** `GH_TOKEN`, `GITHUB_TOKEN`, `COPILOT_GITHUB_TOKEN`. Copilot needs a GitHub token to function, and this is an accepted trade-off.

**OpenTelemetry (`OTEL_*`):** OTel configuration vars such as `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, and `OTEL_RESOURCE_ATTRIBUTES` pass through via the `OTEL_` prefix. `OTEL_EXPORTER_OTLP_HEADERS` may carry opt-in auth headers such as `Authorization=Bearer <token>`, an accepted trade-off in the same class as `GH_TOKEN`, and only present when the user has configured an exporter. The `is_secret_suffix` deny-list still strips any `OTEL_*_TOKEN`, `_AUTH`, `_SECRET`, `_KEY`, `_PASSWORD`, or `_CREDENTIALS` var.

**Deliberately blocked:** `AWS_*`, `AZURE_*`, `NPM_TOKEN`, `DATABASE_URL`, `VAULT_TOKEN`, `SSH_AUTH_SOCK`, Docker vars, CI tokens.

**Git configuration:** `~/.gitconfig`, `~/.gitconfig.local`, and `~/.gitignore_global` are exact read-only exceptions, so normal Git and `gh` workflows can load conventional user configuration. The standard XDG Git config is read-only too (the whole `~/.config/git` directory on Linux, because Landlock rules are recursive). Other include files stay blocked unless explicitly allowed. These files should not contain plaintext credentials; credential directories and SSH/GPG private keys remain denied.

**Escape hatch:** `--inherit-env` disables sanitization and inherits all env vars, still stripping `ENV_ALWAYS_DENY`. This is dangerous. Use it only for debugging.

### Layer 0.25: Security environment hardening

Beyond sanitization, `cplt` injects hardening environment variables that disable dangerous tool behaviors inside the sandbox. The system is declarative and category-based so new categories are easy to add.

**How it works:**
1. `HARDENING_ENV_VARS` is a compile-time list of `(name, value, category)` tuples
2. Each variable belongs to a `HardeningCategory`, for example `LifecycleScripts` or `GitHardening`
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

**Why this matters:** Supply chain attacks such as axios in March 2026 use `postinstall` hooks to execute malicious payloads. Blocking lifecycle scripts eliminates that whole attack class. `npm install` still downloads packages, no arbitrary code runs, and explicit commands like `npm run build` still work normally. Git signing is disabled because `~/.ssh` and `~/.gnupg` are denied by the sandbox, so attempting to sign would fail with EPERM. Disabling it via env var gives a clean, error-free experience.

**Escape hatches:**
- `--allow-lifecycle-scripts` disables the `LifecycleScripts` category. Use it when `npm install` requires postinstall hooks, for example native module compilation.
- `--allow-gpg-signing` disables the `GitSigning` category and adds targeted SBPL rules for GPG access. See the GPG signing risk analysis below.

### Layer 0.5: Native module write protection

The sandbox denies writes to `~/.copilot/pkg/`, where Copilot's native modules such as `keytar.node` live. This blocks a persistence attack where a rogue agent replaces a native module with malware that executes *unsandboxed* the next time Copilot runs outside `cplt`.

### Layer 0.6: Copilot install directory auto-detection

When Copilot CLI is installed via a non-standard Node version manager (`n` at `~/n/`, Volta at `~/.volta/`, a custom npm prefix), its package directory falls outside the static `TOOL_READ_DIRS`. At startup, cplt resolves the copilot binary path, walks up at most 4 ancestors looking for a `package.json` with `"name": "@github/copilot"`, and adds that directory to the sandbox read allowlist. Safety checks:
- **Package identity:** parsed via `serde_json`, so only the real Copilot package is accepted
- **Unsafe root rejection:** `/`, `$HOME`, `/tmp`, and similar are rejected
- **SBPL injection validation:** path characters are validated before profile interpolation

### Layer 0.7: Global git hooks protection

Git's `core.hooksPath` points to a directory of user-configured hooks that run on commit, push, and so on. If it is not allowed, the sandbox makes git fail with EPERM instead of the ENOENT it gives for missing hooks. cplt auto-detects the hooks path and allows reading it. Safety checks:
- **Write denied:** `(deny file-write*)` explicitly blocks writes to the hooks directory, preventing persistence attacks even if the path overlaps a writable sandbox directory
- **Under `$HOME`:** paths outside the home directory are rejected, which prevents arbitrary filesystem reads
- **Depth >= 3:** the path must have at least 3 components under `$HOME`, so `~/.config/git/hooks` is fine and `~/hooks` is too broad
- **Unsafe root rejection:** `/`, `$HOME`, `/tmp`, and similar are rejected

### Layer 1: Seatbelt kernel sandbox (sandbox-exec)

The primary defense is Apple's mandatory access control framework, enforced in the XNU kernel. All restrictions apply to the sandboxed process **and all its children**, and there is no way to shed the sandbox after `sandbox_init()`.

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
(allow unix-socket MSBuild<pid>)        ← MSBuild worker-node IPC only (--allow-msbuild, regex-restricted)
(deny  unix-socket /tmp/*)              ← All other unix sockets blocked (SSH agent, MSBuild Server, etc.)
(deny file-* ~/.ssh, ~/.aws, ...)       ← Sensitive dirs blocked
(deny network-outbound (remote tcp))    ← Block all outbound TCP by default
(allow network-outbound *:443)           ← Then allow HTTPS port only (use --allow-port for extras)
(deny network-outbound localhost:*)     ← Block localhost SSRF (default)
(allow network-outbound localhost:PORT) ← Carve-out for proxy (ephemeral port, assigned at runtime)
;; With --allow-localhost-any: replace deny with (allow ... localhost:*)
;; Java IPv4-mapped issue solved by -Djava.net.preferIPv4Stack=true in JAVA_TOOL_OPTIONS
```

> **Network and socket note (macOS profile).** Every socket statement here describes the Seatbelt profile; on Linux unix socket `connect()` is not gated by Landlock below kernel 7.1, and only the sockets bubblewrap masks are removed there, see [Linux-specific limitations](#linux-specific-limitations). Outbound TCP is restricted to port 443 by default, with `--allow-port` for more. Localhost outbound is blocked, which stops the agent reaching a service bound on your machine. SSH agent access (unix sockets) is blocked. JVM Attach API sockets (`/tmp/.java_pid*`) are available via `--allow-jvm-attach`, opt-in and regex-restricted to `.java_pid<PID>` only; all other unix sockets in `/tmp` stay blocked. MSBuild worker-node IPC sockets (`/tmp/MSBuild<PID>`) are available via `--allow-msbuild`, opt-in and regex-restricted to `MSBuild<PID>` only. That does NOT allow the persistent MSBuild Server, whose socket is named `MSBuildServer-<hash>` and never matches the regex; cplt also unconditionally sets `DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER=1`, so that server is never started or reused, including one started outside the sandbox. SBPL supports no domain-based rules, so filesystem isolation is the primary security control.

**Key design decision:** Deny rules are placed AFTER allow rules. In Seatbelt's evaluation model with `(deny default)`, more-specific rules override broader ones, and later rules take precedence at equal specificity. Our deny rules for `~/.ssh` therefore correctly override the broader temp and system allows.

#### Protected paths

Directories always denied (read and write):

- `~/.ssh`, `~/.gnupg` (cryptographic keys)
- `~/.aws`, `~/.azure` (cloud credentials)
- `~/.kube`, `~/.docker` (infrastructure access)
- `~/.nais` (Nav platform credentials)
- `~/.password-store` (pass password manager)
- `~/.config/gcloud` (Google Cloud credentials)
- `~/.config/op` (1Password CLI)
- `~/.terraform.d` (Terraform credentials)

Directories explicitly allowed (read-only):

- `~/.config/gh` (GitHub CLI credentials; Copilot spawns `gh auth token`, see [Honest gaps](#honest-gaps))

Files always denied (hard blocks):

- `~/.netrc` (HTTP credentials)
- `~/.pypirc` (PyPI credentials)
- `~/.gem/credentials` (RubyGems credentials)
- `~/.vault-token` (HashiCorp Vault)

Files denied by default, overridable via `--allow-read` for private registries:

- `~/.npmrc` (npm registry configuration)

#### Symlink attack protection

SBPL resolves symlink targets at the kernel VFS layer during path evaluation. cplt includes integration tests that demonstrate this: reading a denied file such as `.env` through a symlink with an innocuous name is blocked by the kernel.

#### Tool directory permissions

Home tool directories (`~/.cargo`, `~/.nvm`, and friends) use a per-directory permission model (`HomeToolDir`) with granular `process_exec`, `map_exec`, and `write` flags:

| Directory                                                                                     | process-exec | file-map-executable | file-write | Rationale |
|-----------------------------------------------------------------------------------------------|---|---|---|---|
| `.local/bin`, `.mise`, `.nvm`, `.pyenv`, `.cargo`, `.rustup`, `.sdkman`, `go/bin`, `Library/pnpm` | ✅ | ✅ | varies | Contain executable binaries and shims |
| `.gradle`, `.m2`, `.konan`, `go/pkg`                                                          | ❌ | ✅ | varies | JNI/cgo/Kotlin native libs loaded via dlopen, no direct executables |
| `.yarn`                                                                                       | ❌ | ❌ | ✅ | Yarn Berry global cache, JavaScript packages only, no native binaries |
| `Library/Caches`                                                                              | ❌ | ❌* | ✅ | Broad allow for dev tool caches; browser/app caches denied via regex prefix rules (com.apple.*, com.google.*, org.mozilla.*, etc.), with Xcode dev tools (com.apple.dt.*) re-allowed |

\* Exception: `~/Library/Caches/copilot/pkg/` has `file-map-executable` and `process-exec` for Copilot's native modules and helper binaries (`pty.node`, `spawn-helper`, `rg`). A `file-write*` deny prevents write-then-exec attacks. These carve-outs sit after the broader deny rules, since SBPL is last-match-wins.

**Security principle:** every writable and executable directory is a potential binary-drop staging path. Denying both `process-exec` and `file-map-executable` on `~/Library/Caches` eliminates that at the kernel level. Non-dev caches (browsers, system apps, communication tools) are denied via `DENIED_CACHE_PREFIXES` regex rules in the SBPL profile, so new dev tools work without code changes, because their cache dirs do not use these prefixes.

#### Scratch directory

When `--scratch-dir` is enabled, cplt creates a per-session directory at `~/Library/Caches/cplt/tmp/{session-id}/` with full `read/write/exec/map-exec` permissions. This is a controlled exception to the TMPDIR exec deny.

- **Why it exists:** `go test`, `mise` inline tasks, and `node-gyp` compile to `$TMPDIR` and then execute. The sandbox blocks that, which breaks those tools. On macOS, JVM processes need it too, because `java.io.tmpdir` defaults to `/var/folders/...` and ignores the `TMPDIR` env var; cplt injects `-Djava.io.tmpdir`, `-Djansi.tmpdir`, and `-Djava.rmi.server.hostname=localhost` via `JAVA_TOOL_OPTIONS` to redirect JVM temp usage to the scratch dir and keep RMI communication on localhost.
- **Security model:** the scratch dir has both write and exec, which is the accepted trade-off. Mitigations:
  - **Scoped path:** only the specific session subpath has exec, not all of `~/Library/Caches/cplt/`
  - **0700 permissions:** owner-only access, verified at creation
  - **Symlink rejection:** the base path is validated as a real directory, not a symlink
  - **Owner check:** `stat()` verifies the directory owner matches the current uid
  - **SBPL injection guard:** the path is validated against metacharacters before interpolation
  - **Ephemeral:** cleaned up on exit via RAII Drop, and stale dirs are GC'd after 24h on startup
- **On by default:** disable with `--no-scratch-dir` or `sandbox.scratch_dir = false` in config.

### Layer 2: CONNECT proxy (logging and domain filtering)

A localhost CONNECT proxy intercepts all outbound traffic by default. cplt injects `HTTP_PROXY`, `HTTPS_PROXY`, and `NODE_USE_ENV_PROXY=1` into the sandbox environment, which routes traffic from Copilot CLI (Node.js), `gh` (Go), `curl`, and any other tool through the proxy. Use `--no-proxy` to disable.

Copilot CLI bundles Node.js v24.11.1, which supports `NODE_USE_ENV_PROXY=1` (added in Node.js v24.5.0). With that variable set, Node.js natively honors `HTTP_PROXY`/`HTTPS_PROXY`.

| Component | Language | Routes through proxy? |
|---|---|---|
| Copilot CLI | Node.js | ✅ Yes (via `NODE_USE_ENV_PROXY=1`) |
| `gh` CLI | Go | ✅ Yes (via `net/http.ProxyFromEnvironment()`) |
| `curl` | C | ✅ Yes |

**Historical context:** earlier versions of Copilot CLI used a Node.js runtime that did not support proxy env vars, and injecting them broke the auth flow. That stopped being true as of Copilot CLI 1.0.24+ with bundled Node.js v24.11.1.

**Design decision:** the proxy is enabled by default and listens on an OS-assigned ephemeral port (port 0), so there are no fixed-port conflicts. Use `--no-proxy` to disable for a single run, or set `proxy.enabled = false` in config to disable permanently.

The proxy provides:

1. **Connection logging.** Every CONNECT target is logged with timestamp and status.
2. **Domain blocklist.** A configurable file-based blocklist with subdomain matching.
3. **Port enforcement.** Only port 443 and `--allow-port` values are permitted, matching the sandbox policy.
4. **DNS rebinding protection** and **private IP blocking**, both covered below.

#### Proxy implementation safety

The proxy handles CONNECT tunnels only, and returns 405 for anything else. Each TCP connection processes exactly one request, with no HTTP keep-alive and no request pipelining, which eliminates HTTP request smuggling by design.

- **Buffer:** fixed 8192 bytes, single read, no allocation amplification
- **Connection limit:** 64 concurrent connections max, excess dropped
- **Binding:** `127.0.0.1` only, not reachable from the network
- **Invalid UTF-8:** replaced with U+FFFD via `from_utf8_lossy`, which matches no domain, so it fails safe
- **Relay timeout:** 60-second read timeout on both directions, preventing idle connection resource exhaustion

#### DNS rebinding defense

A naive proxy checks the hostname string ("api.github.com") against a blocklist before connecting. An attacker can register a domain that resolves to `127.0.0.1`, so the hostname check passes but the connection reaches localhost.

Our defense follows [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) guidance:

```
1. Check hostname against blocklist           → block known-bad domains
2. Check hostname patterns (localhost, .local) → fast-path reject
3. DNS resolve hostname → IP address           → get actual target
4. Check RESOLVED IP against private ranges    → catch rebinding
5. Connect to the resolved IP (not hostname)   → pin the address, prevent TOCTOU
```

Step 5 is the critical one. We connect to the `SocketAddr` from step 3 rather than re-resolving, which prevents time-of-check-to-time-of-use attacks where the DNS response changes between validation and connection.

#### IP ranges blocked

| Range | RFC | Purpose |
|---|---|---|
| `127.0.0.0/8` | RFC 1122 | Loopback |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 | Private networks |
| `169.254.0.0/16` | RFC 3927 | Link-local |
| `100.64.0.0/10` | RFC 6598 | CGNAT (Tailscale, WireGuard) |
| `198.18.0.0/15` | RFC 2544 | Benchmarking |
| `240.0.0.0/4` | RFC 1112 | Reserved/future |
| `192.0.0.0/24` | RFC 6890 | IETF protocol assignments |
| `0.0.0.0` | N/A | Unspecified |
| `255.255.255.255` | N/A | Broadcast |
| `::1` | RFC 4291 | IPv6 loopback |
| `fc00::/7` | RFC 4193 | IPv6 ULA (private) |
| `fe80::/10` | RFC 4291 | IPv6 link-local |
| `::ffff:A.B.C.D` (private v4) | RFC 4291 | IPv4-mapped IPv6 |

#### Proxy-forced mode (#53)

By default the proxy is **advisory at the kernel level**. The sandbox allows outbound TCP to `*:443`, and traffic reaches the proxy only because cplt injects `HTTP_PROXY`/`HTTPS_PROXY`/`NODE_USE_ENV_PROXY=1`. A raw socket, or an agent that runs `env -u HTTPS_PROXY -u HTTP_PROXY …`, can still reach any host on `:443` **without** traversing the proxy, bypassing all domain filtering.

Proxy-forced mode restricts **kernel-level TCP egress to the proxy port only**, making the proxy the sole sanctioned path off the machine on macOS, and the sole sanctioned TCP path on Linux (see the platform asymmetry below). It is opt-in and off by default; flipping it to the default is tracked in [#71](https://github.com/navikt/cplt/issues/71). When enabled:

- **The proxy is mandatory.** It is forced on. If it was explicitly disabled (`--no-proxy` / `proxy.enabled = false`), the launch is a conflict and cplt **errors out** rather than silently choosing a side.
- **Fail-closed.** If the mandatory proxy cannot bind or start, cplt **refuses to launch the agent**. It never falls back to open networking.
- **Domain filtering is unchanged.** Proxy-forced only changes which port the kernel permits; the proxy still enforces `allowed_domains` / `blocked_domains` on everything it carries. Pairing proxy-forced with an allowlist gives "only these domains, with no way around the proxy". A default per-agent allowlist is tracked in [#52](https://github.com/navikt/cplt/issues/52).

**Enforcement is not equal across platforms:**

- **macOS (Seatbelt):** the SBPL profile replaces the `*:443` allow with `localhost:<proxy_port>` only. Seatbelt *can* pin to localhost, so there is **no residual**. No direct-network path exists and the `env -u HTTPS_PROXY` and raw-socket bypasses are fully closed.
- **Linux (Landlock):** Landlock drops the `:443` rule and allows only the proxy port. This blocks direct **TCP** `:443` to any host and forces HTTPS through the proxy, but two things stay open. Landlock is **port-based and cannot pin to localhost**, so a narrow `evil.com:<proxy_port>` channel stays reachable if a remote host answers on that exact port. Landlock's own restriction is **TCP-only** — it gates UDP at ABI v10 and cplt handles `AccessNet::ConnectTcp` alone — but in this mode a seccomp rule permits only `SOCK_STREAM` with protocol 0 or `IPPROTO_TCP` for `AF_INET`/`AF_INET6`, so UDP, raw, SCTP and DCCP are closed here on any kernel. DNS tunnelling and QUIC/HTTP-3 leave without touching the proxy in every *other* Linux mode. So this is "no direct TCP `:443` bypass and no non-TCP egress", **not** "no egress except the proxy": the proxy-port channel remains. Closing that residual requires a network namespace, tracked in [#114](https://github.com/navikt/cplt/issues/114).

> **Escape-hatch caveat:** `--allow-port <PORT>` opens a **direct** kernel egress channel on that port, to any remote host, that does not pass through the proxy. Under proxy-forced that channel is not opened ([#297](https://github.com/navikt/cplt/issues/297)): the port is dropped from the SBPL profile and from the Landlock ruleset, and cplt warns that it did so. The port stays in the *proxy's* allowed-port policy, so a proxy-aware tool still reaches `remote:<PORT>` by CONNECT, logged and domain-filtered. A tool that opens a raw socket does not, which is the whole point of the mode; run it without proxy-forced.

### Layer 1L: Landlock + seccomp kernel sandbox (Linux)

On Linux, kernel-level enforcement uses two complementary mechanisms.

#### Landlock LSM (filesystem + network)

[Landlock](https://docs.kernel.org/userspace-api/landlock.html) is a stacking LSM that provides unprivileged, process-level access control. Rules are additive within a ruleset, so access that is not explicitly granted is denied.

**ABI version support:**

| ABI | Kernel | Capabilities |
|-----|--------|-------------|
| v1  | 5.13+  | Filesystem access control |
| v2  | 5.19+  | + file refer (cross-directory rename) |
| v3  | 6.2+   | + file truncate |
| v4  | 6.7+   | + TCP port filtering (bind + connect) |
| v5  | 6.10+  | + ioctl on character devices |
| v6  | 6.12+  | + scoping (cplt requests abstract unix sockets; not signals) |
| v9  | 7.1+   | + `connect()` to pathname unix sockets (`ResolveUnix`) |

cplt requires ABI v1 minimum and requests up to v9. On ABI < v4, network security relies on the CONNECT proxy alone, because Landlock cannot filter TCP ports. On ABI v4+, Landlock denies all TCP connections except to explicitly allowed ports. From v6 abstract unix sockets created outside the sandbox are scoped out of the domain, and from v9 `connect()` to a pathname unix socket is restricted to granted paths. Everything above v1 is best-effort, so on an older kernel the right is silently dropped rather than failing the launch.

**UDP is still not restricted by Landlock**, since its UDP support lands at ABI v10 and cplt handles `AccessNet::ConnectTcp` only. Under `proxy.forced` the seccomp filter closes it instead, by permitting only `SOCK_STREAM` with protocol 0 or `IPPROTO_TCP` for `AF_INET`/`AF_INET6` — an allow-list, so SCTP and DCCP go with it. In every other Linux mode UDP remains unrestricted, deliberately: denying `SOCK_DGRAM` there would break `getaddrinfo(3)` for every non-proxied tool.

Kernel 7.1 is not deployed anywhere yet (Ubuntu 24.04 is 6.8, Debian 13 is 6.12, Fedora 42 is ~6.15), so in practice the v9 unix-socket right is inert and the bubblewrap mount masks below are the whole of that protection.


**Key differences from Seatbelt:**

| Property | Seatbelt (macOS) | Landlock (Linux) |
|----------|-----------------|------------------|
| Granularity | Path regex, file-level deny | Path-based, directory-level allow |
| Default | deny-by-default | deny-by-default |
| Subpath deny | ✅ Can deny subpaths within allowed dirs | ❌ Cannot deny within allowed paths |
| Network | Port-based (all ABIs) | Port-based (ABI v4+ only) |
| Audit logs | Full Seatbelt violation log | None (no audit mode) |
| Privilege | Requires `sandbox-exec` (deprecated) | Unprivileged (any user) |

**Pre-exec safety:** the proxy thread makes the process multi-threaded before `fork`. Landlock rules are pre-computed in the parent process (`PrecomputedSandbox`), and the seccomp filter is installed via raw syscall. The Landlock crate performs small heap allocations in `pre_exec`, which is technically not async-signal-safe but works reliably in practice, because the proxy thread is blocked in I/O syscalls during fork, which minimizes allocator contention.

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

The filter uses `SECCOMP_RET_ERRNO` (returns EPERM) rather than `SECCOMP_RET_KILL`, so legitimate probes do not crash.

#### Protected paths (Linux)

The same credential directories and files are denied as on macOS: see [Protected paths](#protected-paths).

Linux-specific tool directories use XDG-style paths:

| Directory | Permissions | Rationale |
|-----------|------------|-----------|
| `~/.cache` | read+write | XDG cache dir (pip, go-build, etc.) |
| `~/.local/share/pnpm` | read+write+exec | pnpm global store |
| `~/.local/bin` | read+exec | User-installed binaries |
| `~/.local/share/mise` | read+write+exec | mise tool installations |

#### Linux-specific limitations

1. **No `--show-denials`.** Landlock has no audit logging. Use `strace` for debugging.
2. **No subpath deny.** The entire directory must be allowed or denied. See [Out of scope](#out-of-scope). This is why `--allow-docker` on Linux exposes all of `~/.docker` read-only, including `trust/private`, which the macOS profile denies.
3. **No auth integration.** Linux v1 supports env token and `gh auth` only, with no D-Bus/Secret Service.
4. **No localhost isolation at kernel level.** Landlock network rules are port-based only and cannot distinguish `localhost:443` from `remote:443`. On macOS, Seatbelt blocks localhost outbound separately. On Linux, use `--with-proxy` for localhost SSRF protection, since the proxy resolves DNS and blocks private IPs.
5. **Unix-socket protection depends on the kernel and on bubblewrap.** Landlock cannot restrict `connect()` to a pathname unix socket before ABI v9 (kernel 7.1); the seccomp filter cannot help, since the path arrives behind a pointer BPF cannot dereference; and a read-only bubblewrap bind does not stop a `connect()` either (the `MS_RDONLY` check lives in `mnt_want_write()`, which unix-socket connect never reaches). Three regimes result, and cplt prints which one a run is in:

   | Kernel | bubblewrap | Outcome |
   |---|---|---|
   | ≥ 7.1 (ABI v9) | either | `connect()` is kernel-mediated; only granted paths are reachable |
   | < 7.1 | active | the known escape sockets are mount-masked; any other pathname socket stays reachable |
   | < 7.1 | absent | no restriction at all |

   The masked set is `$XDG_RUNTIME_DIR/bus`, `$XDG_RUNTIME_DIR/systemd`, `/run/dbus/system_bus_socket`, and — unless `--allow-docker` — the Docker and Podman daemon sockets. The runtime-dir entries are emitted for `/run/user/<uid>` **and** for `$XDG_RUNTIME_DIR` when that variable points elsewhere, because cplt passes it through to the agent: keying the list on the systemd default alone would mask a path nobody uses on such a host while the banner still counted the escape sockets as masked. Additive, so a wrong or hostile value can only add a mask. The third row is the common case today, and bubblewrap is absent whenever it is not installed, `--no-bubblewrap` is passed, or auto-detect falls back at spawn time. Sockets outside the masked set (the SSH agent, an arbitrary application socket) remain reachable below 7.1 regardless.

   For the SSH agent the withheld `SSH_AUTH_SOCK` is the only barrier, and how much bubblewrap helps depends on which agent is running. bwrap's private `/tmp` does hide the stock OpenSSH socket (`/tmp/ssh-XXXXXX/agent.<pid>`), which an agent would otherwise have to enumerate. It does nothing for the desktop agents: gnome-keyring/gcr (`$XDG_RUNTIME_DIR/gcr/ssh`), GNOME keyring (`$XDG_RUNTIME_DIR/keyring/ssh`) and systemd's `ssh-agent` (`$XDG_RUNTIME_DIR/openssh_agent`) all sit at a fixed, guessable path under `/run/user/<uid>` that `--ro-bind / /` leaves visible. On a GNOME or KDE desktop, bwrap adds nothing here.

   So below kernel 7.1 `--allow-socket`'s Landlock rules and the `--allow-gpg-signing` socket rules grant filesystem access that `connect()` never consults — they take effect only from ABI v9, where they become what keeps those sockets reachable while everything ungranted is denied.
6. **D-Bus reaches the session manager.** `XDG_RUNTIME_DIR` is on the env allowlist and `$XDG_RUNTIME_DIR/bus` is connectable (see above), so `systemd-run --user <cmd>` hands the command to the user's systemd instance, which starts it as a fresh unit **outside** Landlock, seccomp and the bubblewrap namespaces. Below kernel 7.1 the path is open **unless bubblewrap is active**, which mount-masks both `$XDG_RUNTIME_DIR/bus` and `$XDG_RUNTIME_DIR/systemd`; from ABI v9 up Landlock denies the `connect()` outright. With neither, it is open. The **mediation gap** underneath it is no longer only a code-reading conclusion: `connect_to_an_ungranted_pathname_socket_follows_the_abi` in `tests/integration_linux.rs` binds a UNIX socket at a path the policy grants nothing on, then connects to it from inside the sandbox, and the Linux CI job observes that connect succeeding below ABI v9. The **escape itself** — handing a command to the session manager over that socket and watching it run outside every layer — has still not been run end to end on a Linux host, and the rest of the reasoning (the env allowlist, the absence of a network namespace, `--ro-bind / /` exposing the runtime dir, no seccomp socket filtering) is code reading. Treat the escape as reachable rather than demonstrated. If it matters for your threat model, install bubblewrap — or run cplt inside a container or a VM, which closes it on any kernel.
7. **UDP is unrestricted except under `proxy.forced`.** Landlock gates UDP only at ABI v10, and cplt handles `AccessNet::ConnectTcp` only, so outbound UDP to any host and port, and inbound UDP bind, are unrestricted at the kernel in every Linux mode but one. Under `proxy.forced` a seccomp rule permits only `SOCK_STREAM` with protocol 0 or `IPPROTO_TCP` for `AF_INET`/`AF_INET6`, which removes UDP, raw, SCTP and DCCP on every kernel — at the cost of anything that opens such a socket, since seccomp cannot see the destination address at `socket(2)` and no loopback exemption is expressible. That is wider than "a UDP tool reached through `--allow-localhost`": the JDK opens `socket(AF_INET, SOCK_DGRAM, 0)` for `SIOCGIFCONF` to enumerate interfaces and throws `SocketException` on `EPERM`, which Gradle propagates. Gradle is already unusable under `proxy.forced` on Linux because of the port lock, so the practical impact is marginal, but the failure is not confined to code that sends UDP. The CONNECT proxy carries TCP only, so UDP never touches it, and outside `proxy.forced` DNS tunnelling, QUIC/HTTP-3 and plain UDP exfiltration are covered by no cplt layer on Linux. macOS restricts UDP, since SBPL's `remote ip` covers UDP as well as TCP and `(deny default)` closes everything the profile does not name, but does not route it through the proxy: in default mode `*:443` admits QUIC/HTTP-3, so the proxy log is a complete record only under `proxy.forced`, where that allow is dropped.
8. **`--allow-localhost-any` disables ALL kernel network restriction on Linux.** Landlock is port-based and cannot express "any localhost port but no remote host", so opening all localhost ports means dropping *every* Landlock TCP-connect rule. The result is unrestricted outbound TCP at the kernel level, so an agent can raw-socket to any remote `host:port` and exfiltrate directly, not just reach localhost. macOS behaves differently. There, `--allow-localhost-any` swaps one SBPL line, replacing `(deny network-outbound (remote ip "localhost:*"))` with the matching allow. The blanket `(deny network-outbound (remote tcp))` and the `*:443` allow are untouched, so remote egress stays scoped to 443 plus any `--allow-port`. Only loopback opens up. cplt emits a prominent warning when this flag is set on Linux. **Prefer `--proxy-forced`**, which supersedes `allow_localhost_any` (see [Proxy-forced mode](#proxy-forced-mode-53)), or scope to specific ports with `--allow-localhost <PORT>`, which keeps kernel connect-restriction on.

### Layer 3: Input validation

#### SBPL injection prevention

All paths interpolated into sandbox profiles are validated against unsafe characters:

```
Blocked: " ) ( ; \ \n \r \0
```

The newline character is the dangerous one. A path containing `\n(allow file-read* (subpath "/"))` would inject a rule granting read access to the entire filesystem. We validate:

- Project directory path
- Home directory path
- All user-specified allow/deny paths, from CLI and config file

Config file paths are additionally canonicalized (resolved to absolute paths) at load time.

#### The profile never becomes a file

The SBPL profile is passed to `sandbox-exec -p` as an argument. It is never written
to disk and never handed over as a pathname.

The profile grants every sandbox write throughout `/private/tmp` and
`/private/var/folders`. While cplt wrote the profile to `$TMPDIR/cplt-*.sb` and
passed `-f <path>`, one sandboxed session could overwrite another session's
profile between the write and the kernel's read — a complete policy replacement,
not merely corruption, since the attacker chooses the replacement text. Measured
at 14 of 15 launches (`profile_cannot_be_swapped_by_another_session` in
`tests/e2e.rs`, which still reproduces the attack against the old code).

An oversized profile fails loudly with `E2BIG` — the argument list must fit in
`kern.argmax` (1 MiB) alongside the environment. The kernel never sees a
truncated profile: `sandbox-exec` either applies the whole thing or refuses to
start. A default profile is about 25 KB and each allow/deny grant adds roughly
2.5 KB, so the ceiling is in the low hundreds of grants.

#### Unsafe root rejection

cplt refuses to sandbox overly broad directories that would hand the agent access to sensitive areas:

- `/` (entire filesystem)
- `/Users` (all user home directories)
- `$HOME` (user's entire home directory)
- `/tmp`, `/private/tmp` (shared temp directories)
- `/var`, `/private/var` (system variable data)
- `/Applications` (installed applications)
- `/System` (macOS system files)

#### CLI path handling

- **Allow paths** (`--allow-read`, `--allow-write`) are canonicalized, and unresolvable paths are warned about and skipped
- **Deny paths** (`--deny-path`) are canonicalized, and unresolvable paths cause a **hard error**, because silently dropping a deny rule is a security risk

### Layer 4: Per-repo config trust model (`.cplt.toml`)

Repository maintainers can commit a `.cplt.toml` to configure sandbox settings for all contributors. That creates an attack surface, since a compromised or malicious maintainer could weaken the sandbox for everyone who clones the repo. The trust model addresses this with defense-in-depth.

#### Security design principles

1. **Deny-default for permissions.** The `[propose]` section requests sandbox relaxations, but they have **no effect** until the local user explicitly approves them with `cplt trust accept`. Unapproved permissions are silently ignored and the agent runs with the tighter default sandbox.

2. **Deny section is tighten-only.** The `[deny]` section can only add restrictions, blocking paths and env vars. It is applied automatically without approval, because it cannot weaken the sandbox.

3. **No interactive approval during launch.** cplt deliberately does *not* prompt "approve these? [y/N]" when unapproved permissions exist. That prevents approval fatigue, where users reflexively hit `y` to proceed. Approval requires a separate deliberate command (`cplt trust accept`), matching the security model of Deno workspace trust and VS Code Restricted Mode.

4. **Tamper-proof source.** `.cplt.toml` is read from `git HEAD` (committed state) via `git cat-file`, not from the working tree, so the sandboxed agent cannot modify its own config mid-session. Write access to `.cplt.toml` is kernel-denied inside the sandbox.

5. **Content-pinned approvals.** Trust entries store a SHA-256 hash of the approved `[propose]` values. If the maintainer changes any proposed value, previous approvals are automatically invalidated and the user must re-approve. Reordering array elements is hash-stable, thanks to a pre-sort.

6. **Additive-only semantics.** Repo config can enable features (`allow_docker = true`) but cannot disable anything set by the user's CLI flags or global config. Precedence: CLI > global config > approved repo permissions > defaults.

7. **Path traversal rejection.** Paths in `.cplt.toml` containing `..` components are rejected at parse time, which prevents escape attempts like `../../.ssh`.

#### Trust store integrity

- Trust entries live in `~/.config/cplt/trust/`, protected from the sandbox, so the agent cannot self-approve.
- Each entry's **filename** is a SHA-256 fingerprint of the normalized git remote URL, or the canonicalized project path when there is no remote. Remote URLs are normalized (SSH/HTTPS variants, credentials stripped, ports removed) so the same repo accessed via different URLs shares one trust entry.
- **The remote URL is not an authenticity signal.** It is attacker-controllable. A malicious repo can `git remote set-url origin <victim>` and copy the victim's approved `[propose]` block verbatim, so the content hash also matches, then look up the victim's trust entry and inherit its approved permissions. That is a confused-deputy escalation. To defeat it, every approval is **also bound to the absolute local checkout path** it was granted at (`repo.path`). Before applying a trust entry, cplt requires the current project directory to match that recorded path, canonicalized. A matching fingerprint presented from a *different* path is **not** auto-trusted and triggers a re-approval prompt. An attacker cannot satisfy this without already controlling the victim's exact on-disk location. Legacy entries with no recorded path are treated as unmatched, giving a one-time re-approval.
- Trust writes are atomic (temp file plus rename) so an interrupted write cannot corrupt the store.

#### Threat scenarios

| Scenario | Mitigation |
|---|---|
| Maintainer adds `allow_docker = true` | No effect until each user explicitly approves |
| Agent modifies `.cplt.toml` at runtime | Read from `git HEAD`, not working tree; writes kernel-denied |
| Maintainer changes proposed values after approval | Content hash mismatch invalidates approval |
| `.cplt.toml` blocks critical env vars via `[deny].env` | `[deny]` can only tighten, and removing env vars reduces attack surface |
| Path traversal in deny/allow paths | `..` components rejected at parse time |
| Agent self-approves via trust store | Trust dir (`~/.config/cplt/trust/`) is outside the sandbox |
| Origin-URL spoof to inherit a victim's approval (`git remote set-url origin <victim>` + copy `[propose]`) | Approvals are bound to the local checkout path; a match from a different path is not auto-trusted, and re-approval is required |

### GPG signing risk analysis (`--allow-gpg-signing`)

When `--allow-gpg-signing` is enabled, cplt grants targeted access to the GPG subsystem.

**What is exposed:**
- Read-only access to public data only: `~/.gnupg/pubring.kbx`, `pubring.gpg`, `trustdb.gpg`, `gpg.conf`, `common.conf`
- Unix socket connect to `~/.gnupg/S.gpg-agent`, which is IPC to the GPG agent daemon running outside the sandbox

**Platform note:** on macOS this grant is what makes the socket reachable — without `--allow-gpg-signing` the profile's `(deny default)` blocks the `connect()`. On Linux below kernel 7.1 the grant changes nothing, since Landlock cannot restrict `connect()` to a pathname unix socket before ABI v9, so the gpg-agent socket is reachable whether or not the flag is set. From v9 up the grant is what keeps it reachable, and it covers `/run/user/<uid>/gnupg` as well as `~/.gnupg`, since modern GnuPG keeps the real sockets in the runtime dir. The read denies on `~/.gnupg/private-keys-v1.d/` still hold on both platforms — but on Linux the "signature impersonation and decryption" risk described below is present by default, not opted into.

**What stays denied:**
- `~/.gnupg/private-keys-v1.d/` stays kernel-blocked. That is where the private keys live.
- `~/.gnupg/secring.gpg`, the legacy private keyring, is explicitly denied
- All writes to `~/.gnupg/`, so no modifications are possible
- `~/.ssh/` and `SSH_AUTH_SOCK`, since SSH signing is not enabled by this flag

**Key exfiltration is impossible.** The GPG agent uses the Assuan IPC protocol, which exposes `PKSIGN` (sign), `PKDECRYPT` (decrypt), `READKEY` (public key), and `KEYINFO` (metadata), but has **no command to export private key material**. The agent is a privilege-separation boundary by design. Even if the on-disk key files were not denied, they are encrypted with the user's passphrase.

**The actual risk is signature impersonation and decryption.** A compromised process with agent socket access can:
1. Request signatures via `PKSIGN`, signing arbitrary data including malicious commits
2. Request decryptions via `PKDECRYPT`, so if the user has an encryption subkey, the compromised process can decrypt arbitrary ciphertext

This is **not key theft**. The attacker cannot take the key with them, and operations only work while the sandbox is running and the agent connection is active.

**Risk context:** Copilot already has `git commit` ability and can make commits as the user. GPG signing only adds the "Verified" badge. The incremental risk is that a compromised agent can make commits that appear cryptographically verified by the user, and can decrypt data if an encryption subkey exists. Mitigating factors:
- The agent passphrase cache has a TTL, by default 10 min idle and 2 hr max
- The network proxy, when enabled, can audit or block pushes to unexpected remotes
- Branch protection rules may still require PR review regardless of signature status

**Deny-path override:** if `--deny-path ~/.gnupg` is specified alongside `--allow-gpg-signing`, the deny wins and all GPG allows are suppressed. This matches the project-wide principle that explicit denies always take precedence.

**Known limitations:**
- `GNUPGHOME` is not in `ENV_ALLOWLIST`, but it could be injected via `--pass-env` or `--inherit-env`, redirecting GPG to a directory outside the SBPL policy. The SBPL rules only cover `~/.gnupg/`.
- If `~/.gnupg` is a symlink, SBPL path resolution may cause rules not to match as expected. Signing then fails closed, with no access, rather than open.

### Network limitations

#### SBPL network filtering limitations

Port filtering works. The host part is what SBPL cannot express.

**Ports are filterable, and cplt relies on it.** `src/sandbox_profile.rs` emits a blanket `(deny network-outbound (remote tcp))`, then `*:443` unless proxy-forced mode drops it, then one `*:PORT` per `--allow-port` — dropped by proxy-forced mode too, for the same reason ([#297](https://github.com/navikt/cplt/issues/297)) — then the localhost deny or allow, then a `localhost:PORT` carve-out per proxy port and per `--allow-localhost` port. SBPL is last-match-wins, so the ordering is the policy.

`real_profile_port_filtering_is_enforced_by_the_kernel` in `tests/integration.rs` runs a generated profile under `sandbox-exec` against two loopback listeners on ephemeral ports, one named in the profile and one not, and asserts the named one connects while the other does not. It is the only test here that proves the filtering filters rather than that the rule parses.

**The host part accepts only `*` or `localhost`.** A literal address such as `127.0.0.1` or `140.82.121.4` is a parse error, `"host must be * or localhost"`. So a rule can say "any host on this port" or "loopback on this port", and nothing narrower.

What follows from that:

- **No domain-based rules.** SBPL operates at the syscall level, not the application level, so it cannot match on hostnames. Domain filtering is the CONNECT proxy's job, see [Layer 2](#layer-2-connect-proxy-logging-and-domain-filtering).
- **No IP allowlisting.** Even if Copilot's API endpoints had stable IPs, which they do not, being CDN-backed, SBPL could not name them.
- **No loopback-only bind.** The `localhost` host matches `INADDR_ANY` (`0.0.0.0`), so `(allow network-bind (local ip "localhost:*"))` also permits binding on all interfaces. Processes inside the sandbox can therefore start listeners reachable on the network. Mitigations: outbound is locked to port 443 so there is no exfiltration via inbound connections, dev machines are typically behind NAT or a firewall, and the proxy intercepts all outbound traffic.

Port scoping is the kernel-level control; domain and host scoping happens one layer up, in the proxy.

#### Current state

Outbound TCP is allowed in the sandbox profile, restricted to port 443 plus `--allow-port`, and filesystem isolation stays the primary security control. See [Layer 2](#layer-2-connect-proxy-logging-and-domain-filtering) for what the proxy enforces, and [Proxy-forced mode](#proxy-forced-mode-53) for why the proxy is advisory by default and how to make it mandatory.

### Self-update security (`cplt update`)

The update mechanism downloads releases from GitHub, verifies SHA256 checksums, and atomically replaces the binary.

**Verified:**
- The SHA256 checksum is mandatory, and the update aborts on mismatch
- `--proto-redir =https` prevents an HTTP downgrade on redirects
- Archive validation requires exactly one regular file named `cplt`, no symlinks and no directories
- The extracted binary is verified via `symlink_metadata`, which rejects symlinks
- Absolute paths are used for system tools on macOS (`/usr/bin/curl`, `/usr/bin/shasum`, `/usr/bin/tar`) and Linux (`/usr/bin/sha256sum`, standard paths only, no bare PATH lookup)
- Replacement is atomic: stage to `.new`, set permissions, rename

**Not verified:**
- There is no cryptographic signature, neither GPG nor Sigstore. `SHA256SUMS` and the binary come from the same GitHub release, so a compromised release controls both. This matches most Go/Rust CLI tools but is weaker than signed package managers.
- The temp directory is `/tmp/cplt-update-{PID}`, predictable by local attackers, though the extracted binary is checked for symlinks before installation.

The Homebrew install path (`brew install navikt/tap/cplt`) uses Homebrew's own verification and is preferred on macOS.

### Install script security (`install.sh`)

The install script downloads from GitHub Releases and verifies SHA256 checksums.

**Caveat:** if the `SHA256SUMS` file cannot be downloaded, or no hash utility is available, the script prints a warning and **continues without verification**. This is a deliberate trade-off for usability in minimal CI environments.

For high-security environments, verify the binary manually:
```bash
curl -fsSL -o cplt.tar.gz "https://github.com/navikt/cplt/releases/latest/..."
curl -fsSL -o SHA256SUMS "https://github.com/navikt/cplt/releases/latest/.../SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
```

### Discovery and `cplt doctor`

`cplt doctor` probes the environment by running `--version` on all known agent binaries found in PATH (copilot, opencode, antigravity, claude). These commands run **outside the sandbox** with full user privileges.

Trust model: cplt trusts that binaries in your PATH are legitimate, the same trust model as typing `copilot --version` yourself. If you don't trust a binary in your PATH, remove it before running `cplt doctor`.

### Config file trust model

`~/.config/cplt/config.toml` and `~/.config/cplt/trust/*.toml` are trusted inputs read before sandboxing. They are not permission-checked. The trust model assumes `$HOME` is protected by OS-level permissions (0700 or 0755).

On shared systems, give `~/.config/cplt/` restrictive permissions (0700). A user who can write to this directory can weaken the sandbox configuration.

`CPLT_CONFIG` moves that trusted input somewhere else, replacing the whole file — every `[sandbox]` key included. It is read from the ambient environment, so a shell that auto-loads repository-provided environment (direnv's `.envrc`, mise) can set it just by you entering a directory, and the repo-config trust model below (which only ever lets a repository *tighten* the sandbox) never sees it.

Two guards keep that visible rather than silent:

- A `CPLT_CONFIG` outside `~/.config/cplt/` prints a warning naming the resolved file. It is deliberately not suppressed by `--quiet` — a quiet run is when a silent substitution costs the most.
- A `CPLT_CONFIG` that resolves **inside the project directory** is refused and cplt exits non-zero. Falling back to the real user config would be another invisible substitution, so this fails loudly instead. Symlinks and `..` are resolved before the comparison, so a path outside the repo that links back into it is refused too.

Neither guard covers a repository that writes a config *outside* the project and points `CPLT_CONFIG` at that. The warning is what makes that case visible.

### Scratch directory session IDs

Session IDs for per-session scratch directories come from `/dev/urandom` (16 random bytes, hex-encoded), falling back to PID plus nanosecond timestamp if `/dev/urandom` is unavailable, which is not expected on standard macOS or Linux. The fallback is predictable, but the failure mode is denial-of-service (directory creation fails if it already exists), not compromise.

## Test strategy

### Unit tests (cross-platform, run on Linux CI)

These test core logic without invoking `sandbox-exec`, using the real library functions rather than duplicated copies:

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

### Integration tests (macOS only, 55 tests)

Most of these invoke `sandbox-exec` with real Seatbelt profiles and verify **kernel-level enforcement**. Three do not, and are marked below: they generate profile text and assert on it, which proves a rule is emitted, not that the kernel honours it.

| Category | Tests | What's verified |
|---|---|---|
| File access | 7 | Project read/write, copilot config, temp write, process execution, `git` execution, Copilot package dir write blocked |
| Sensitive dir and file blocks | 8 | `~/.ssh`, `~/.aws`, `~/.docker`, `~/.kube`, `.netrc`, `.npmrc`, credentials planted in a temp `HOME`, and `--deny-path` overriding `--allow-read` |
| Git repository protection | 5 | Writes to `.git/hooks`, `.git/config`, `.gitmodules`, and `.cplt.toml` blocked; local git config and the global ignore file stay readable |
| Temp and scratch exec | 3 | Exec from `/tmp` blocked by default, allowed with `--allow-tmp-exec`, allowed inside the scratch dir |
| Env files | 4 | `.env` read, symlink read, and delete blocked; allowed with `--allow-env-files` |
| GPG signing | 4 | Default blocks `~/.gnupg`, flag allows pubring read, private keys stay denied, writes stay denied |
| Network | 10 | Outbound blocked by default, a port named in the profile reachable while an unnamed one is not, localhost blocked by default and allowed with `--allow-localhost-any`, Java localhost with and without `preferIPv4Stack`, localhost TCP bind, and the wildcard-bind SBPL limitation. Two are text-only: that the default profile emits `*:443`, and that proxy-forced emits the `localhost:<port>` pin and drops `*:443` |
| Unix sockets | 6 | JVM Attach sockets in `/tmp` and `/var/folders` allowed, MSBuild worker-node socket allowed and blocked without the flag, SSH agent blocked, arbitrary `/tmp` sockets blocked |
| Clipboard | 3 | `--deny-clipboard` blocks `pbpaste` and `pbcopy`, `pbpaste` works by default |
| Binary CLI | 5 | Version, help, root/home dir rejection. The `--print-profile` proxy-forced check is text-only, since `--print-profile` never invokes `sandbox-exec` |

### E2E project tests (macOS only, 49 tests)

End-to-end tests using realistic project scaffolding (Node, Go, Python, Rust, Java/Maven, Kotlin/Ktor, .NET) with fake agent scripts:

| Category | Tests | What's verified |
|---|---|---|
| Per-language file ops | 9 | Read/write files in Node, Go, Python, Rust, Ktor, Maven, Kotlin/Maven, and multi-module Maven layouts |
| Git workflows and persistence | 8 | init/commit/status/diff/log, multi-step edit cycles, `.git/hooks` writes blocked including via a nested or renamed git dir, a granted sibling repo, and a bare repo |
| Post-session audit | 1 | The audit report names the writable roots it did not audit |
| Security matrix | 4 | Secret files blocked (`.env`, `.pem`, `.key`), all `.env` spellings blocked, home secrets (`~/.ssh`, `~/.aws`), env var sanitization |
| Mode combinations | 7 | allow-env-files, scratch-dir exec, deny-path, config file, external allow-read, proxy mode, spawning common tools |
| Proxy behavior | 5 | Proxy env vars injected and absent without the flag, port filtering, allowlist blocking an unlisted domain, audit log written |
| Go toolchain | 4 | `go build`, `go test` with the scratch dir, `GOCACHE` redirect, `go test` blocked without a scratch dir |
| .NET and MSBuild | 3 | `dotnet build` with `--allow-msbuild`, the MSBuild Server env opt-out, the socket blocked without the flag |
| Gradle | 3 | Build over the Gradle daemon unix socket, the daemon socket itself, macOS Gradle sandbox opt-out |
| JVM env and exec | 5 | Maven env passthrough, `JAVA_TOOL_OPTIONS` injection and append, native lib exec from the JVM tmpdir, JVM cache dir permissions |

### Smoke tests (macOS only, 6 tests, `#[ignore]`)

Real Copilot CLI integration tests requiring authentication and network access:

| Test | What's verified |
|---|---|
| `smoke_copilot_version` | Copilot outputs version string inside sandbox |
| `smoke_copilot_list_models` | API call returns model list (JSON) |
| `smoke_copilot_simple_prompt` | Chat completion returns response containing UUID canary |
| `smoke_copilot_file_context` | Copilot reads project file and references its content |
| `smoke_copilot_write_file` | Copilot creates a new file on disk (side-effect assertion) |
| `smoke_env_vars_denied` | `SUPER_SECRET_TOKEN` not visible inside sandbox |

### CI pipeline

The GitHub Actions workflow runs in two stages:

1. **Linux (ubuntu-latest):** formatting check (`cargo fmt`), linting (`cargo clippy -D warnings`), unit tests
2. **macOS (macos-latest):** full test suite including integration tests, release binary build and verification

## Prior art and references

### macOS Seatbelt / sandbox-exec

- [Apple sandbox-exec(1) man page](https://keith.github.io/xcode-man-pages/sandbox-exec.1.html). Official documentation for the command-line sandbox tool.
- [Chromium Seatbelt V2 Design](https://chromium.googlesource.com/chromium/src/sandbox/+show/refs/heads/main/mac/seatbelt_sandbox_design.md). How Chromium designs and maintains Seatbelt profiles for browser process sandboxing; influenced our deny-default plus bsd.sb import approach.
- [HackTricks: macOS Sandbox](https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox/index.html). Security research on Seatbelt internals, bypass techniques, and rule evaluation.
- [A New Era of macOS Sandbox Escapes (POC2024)](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Recent CVE research on sandbox escape via XPC/Mach services; informed our understanding of Seatbelt's limitations.
- [michaelneale/agent-seatbelt-sandbox](https://github.com/michaelneale/agent-seatbelt-sandbox). Early proof-of-concept for sandboxing AI coding agents with Seatbelt; validated the basic approach.

### DNS rebinding and SSRF prevention

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html). Authoritative guidance on validating resolved IPs rather than hostnames, and pinning addresses to prevent TOCTOU attacks.
- [RFC 1918](https://datatracker.ietf.org/doc/html/rfc1918). Private IPv4 address ranges (10/8, 172.16/12, 192.168/16).
- [RFC 4193](https://datatracker.ietf.org/doc/html/rfc4193). IPv6 Unique Local Addresses (fc00::/7).
- [RFC 6598](https://datatracker.ietf.org/doc/html/rfc6598). CGNAT shared address space (100.64.0.0/10), important for Tailscale and WireGuard environments.
- [RFC 4291](https://datatracker.ietf.org/doc/html/rfc4291). IPv6 addressing architecture (loopback, link-local, IPv4-mapped addresses).

### Secure temporary files

- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html). Why the SBPL profile is never written to a temp file at all, and why the files that do live in the scratch dir use `O_CREAT|O_EXCL` with mode `0600`.
- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html). Symlink attacks on predictable temp paths.

### AI agent sandboxing (broader context)

- [GitHub Copilot Workspace sandbox settings](https://docs.github.com/en/copilot/customizing-copilot/customizing-copilot-in-your-ide). VS Code's built-in sandbox options for Copilot (terminal command restrictions).
- [Copilot cloud agent firewall](https://docs.github.com/en/enterprise-cloud@latest/copilot/customizing-copilot/customizing-or-disabling-the-firewall-for-copilot-coding-agent). GitHub's server-side network firewall for the cloud coding agent.
- [Copilot allowlist reference](https://docs.github.com/en/copilot/reference/copilot-allowlist-reference). Default allowed domains for the Copilot cloud agent.
- [OpenAI Codex sandbox](https://platform.openai.com/docs/guides/codex). OpenAI's approach to sandboxing code execution with network and filesystem restrictions.
- [Anthropic Claude Code permissions](https://docs.anthropic.com/en/docs/claude-code/security). Permission-based tool approval model for local agent execution.

### Supply chain attack research

- [Mend.io: Shai-Hulud npm worm analysis (2025)](https://www.mend.io/blog/npm-supply-chain-attack-packages-compromised-by-self-spreading-malware). Self-replicating worm that compromised 700+ npm packages.
- [Wiz: Shai-Hulud 2.0, 25K+ repos exposed](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack). Second wave and blast radius analysis.
- [Socket: 60 malicious npm packages](https://socket.dev/blog/60-malicious-npm-packages-leak-network-and-host-data). Network recon exfiltration to Discord webhooks.
- [Oligo: npm supply chain risks with AI agents](https://www.oligo.security/blog/the-hidden-risks-of-the-npm-supply-chain-attacks-ai-agents). How AI coding agents amplify supply chain attacks.
- [ReversingLabs: npm reverse shell malware](https://www.reversinglabs.com/blog/malicious-npm-patch-delivers-reverse-shell). Patched legitimate packages delivering reverse shells.
- [Rafter: AI Agent Security Incident Timeline (2025-2026)](https://rafter.so/blog/incidents/ai-agent-security-timeline-2025-2026). Timeline of agent security incidents.
- [CamoLeak: Copilot Chat exfiltration (CVE-2025-59145)](https://rafter.so/blog/incidents/camoleak-invisible-exfiltration-channel). Invisible data exfiltration via GitHub image proxy.
- [LOTS Project, Living Off Trusted Sites](https://lots-project.com/). Catalog of legitimate domains abused for C2 and exfiltration.
- [Veracode: npm C2 via Ethereum smart contracts](https://www.veracode.com/blog/54-new-npm-packages-found-beaconing-to-c2-server-in-ethereum-smart-contract/). Dead-drop C2 rotation technique.

## Reporting security issues

If you discover a vulnerability in cplt, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Contact the team via Nav's internal security channels
3. Include a description of the vulnerability, steps to reproduce, and potential impact

We aim to acknowledge reports within 48 hours and provide a fix within one week for critical issues.
