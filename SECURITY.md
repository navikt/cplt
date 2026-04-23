# Security Model

This document describes the security architecture of cplt, the threat model it addresses, the defense layers it implements, and how they are validated through automated testing.

## Threat Model

cplt assumes Copilot CLI is an **untrusted agent** executing arbitrary code suggestions on your machine. The threat model covers:

| Threat | Example | Defense layer |
|---|---|---|
| **Credential theft** | Read `~/.ssh/id_ed25519`, `~/.aws/credentials` | Seatbelt file deny rules |
| **Data exfiltration** | POST secrets to `https://evil.com/collect` | Filesystem isolation (credentials unreadable) |
| **Secret file access** | Read `~/.netrc`, `~/.npmrc`, `~/.vault-token` | Seatbelt file deny rules |
| **DNS rebinding SSRF** | Domain resolves to `127.0.0.1` after check | Post-DNS-resolution IP validation |
| **Sandbox profile injection** | Path with `\n(allow file-read* (subpath "/"))` | SBPL path character validation |
| **Temp file symlink attack** | Symlink at predictable `/tmp/cplt.sb` | Unique filename + `O_CREAT\|O_EXCL` |
| **Write-then-exec in /tmp** | Drop binary in `/tmp`, execute it | `deny process-exec` + `deny file-map-executable` on `/tmp` and `/var/folders`; `--scratch-dir` provides a safe alternative |
| **Cloud metadata access** | Fetch `169.254.169.254` or CGNAT range | Comprehensive private IP blocklist |
| **Cross-project access** | Read files outside project directory | Seatbelt subpath restrictions |
| **Process-group escape** | Kill parent, children continue unsandboxed | `setpgid` + signal forwarding |
| **Env var credential theft** | Read `AWS_SECRET_ACCESS_KEY` from env | `env_clear()` + safe allowlist |
| **Persistence via native modules** | Replace `keytar.node` with malware | Deny writes to `~/.copilot/pkg` |
| **Git hook injection** | Write post-checkout hook that runs outside sandbox | Deny writes to `.git/hooks/` and global `core.hooksPath` dir |
| **Git config hijacking** | Set `core.hooksPath=/tmp/evil` or URL redirect | Deny writes to `.git/config`; global hooks path validated (under `$HOME`, depth ≥3) |
| **Submodule supply chain** | Modify `.gitmodules` to point to malicious repo | Deny writes to `.gitmodules` |

### Out of scope

- **TLS interception** — the proxy sees CONNECT targets (hostname:port) but not request bodies or responses
- **macOS kernel exploits** — we rely on Apple's Seatbelt enforcement being correct
- **Keychain isolation** — Copilot requires Keychain access for auth; this is an accepted trade-off. `mach-lookup` is blanket because Node.js needs it for DNS, Security framework, and system services. Scoping to individual service names is impractical (undocumented, version-dependent).
- **sandbox-exec deprecation** — Apple marks it deprecated but has not removed it; Chromium and VS Code still use it
- **Code quality** — the sandbox cannot judge whether code written by Copilot contains backdoors; that's a code review problem
- **`~/.config/gh/hosts.yml` token** — contains the user's GitHub OAuth token. Copilot needs *a* GitHub token to function (via env var or this file). The token is readable inside the sandbox. If this is a concern, set `GH_TOKEN` env var (passes through allowlist) and add `--deny-path ~/.config/gh` to block the file.
- **Interpreter-based temp execution** — the sandbox blocks *direct* exec from `/tmp` (Mach-O binaries, dlopen), but cannot block `bash /tmp/evil.sh` or `node /tmp/evil.js` because the exec target is the interpreter (`/bin/bash`, `/usr/bin/node`), not the script file. Sandboxing interpreters would break Copilot.
- **`.vscode/` project configs** — the agent can write `.vscode/tasks.json`, `launch.json`, and `settings.json` which VS Code may auto-execute outside the sandbox. This is an IDE trust boundary issue, not a sandbox scope issue. Mitigation: review `.vscode/` changes in `git diff` before committing; set `"task.autoRunTasks": "off"` in VS Code.
- **Write+exec in home cache dirs** — `~/.gradle`, `~/.m2`, `~/Library/pnpm` have both write and exec permissions. Build tools need write for dependency downloads and exec for build plugins. A rogue agent could write a malicious JAR to `~/.m2` or a Gradle plugin to `~/.gradle`, but the executed code would still be sandboxed. `~/Library/Caches` is broadly allowed for dev tool caches (go-build, Homebrew, pip, etc.), but browser and app caches (Chrome, Firefox, Discord, etc.) are denied via regex prefix rules — no allowlist maintenance needed for new dev tools.
- **Project build scripts** — the agent can modify `Makefile`, `package.json` scripts, `build.gradle`, `.github/workflows/`, etc. These are legitimate Copilot targets and cannot be blocked. The risk is mitigated by code review (git diff) before running builds or committing.
- **POSIX shared memory** — `ipc-posix-shm-*` is allowed because Node.js needs it for DNS and system queries. An agent could theoretically use SHM as an IPC channel to processes outside the sandbox, but this requires a cooperating process already running on the machine.
- **DNS tunneling** — DNS queries go through macOS mDNSResponder Unix socket. Seatbelt offers no per-query filtering; it's all-or-nothing. Blocking DNS breaks everything. Bandwidth is ~15 KB/s max, requires attacker-controlled authoritative DNS, and is detectable with network monitoring.

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
| **5. Binary staging** | Drop RAT into cache dir and execute | **Kernel-blocked.** `~/Library/Caches` has no `process-exec` or `file-map-executable`; `/tmp` exec also denied | ✅ **Stopped** |
| **Worm propagation** | Republish infected packages | Can't read npm tokens (in ~/.npmrc, kernel-blocked) | ✅ **Stopped** |

### Honest gaps

**Network is port-restricted, with optional domain filtering.** SBPL (Seatbelt Profile Language) does not support domain-based filtering at the kernel level. Copilot CLI connects to CDN-backed endpoints (`api.business.githubcopilot.com`) with changing IPs that cannot be enumerated. We allow outbound TCP on port 443 only (use `--allow-port` for extras, e.g. `--allow-port 80` for HTTP). SSH agent access and localhost outbound are blocked at the kernel level. This means:

- A compromised agent CAN make HTTPS requests to attacker-controlled servers on port 443
- A compromised agent CANNOT exfiltrate cloud credentials from env vars (env is sanitized; only safe allowlist passes through)
- A compromised agent CAN exfiltrate project source code and Copilot auth tokens
- A compromised agent CANNOT connect to local services (localhost is blocked)
- A compromised agent CANNOT use loaded SSH keys (unix socket is blocked)
- A compromised agent CANNOT connect on non-standard ports (e.g., 8080, 3000) unless `--allow-port` is used
- A compromised agent CANNOT exfiltrate SSH keys, cloud credentials, or npm tokens (kernel-blocked from reading them)
- A compromised agent CAN request GPG signatures (if `--allow-gpg-signing` is enabled) but CANNOT exfiltrate private keys
- The proxy (when enabled with `--with-proxy`) logs and filters all outbound connections, including Copilot CLI traffic (via `NODE_USE_ENV_PROXY=1`). The proxy also enforces port restrictions matching the sandbox policy.

*Mitigation:* Use `--with-proxy --allowed-domains allowed-domains.txt` to restrict traffic to known Copilot endpoints only. Use `--blocked-domains blocked-domains.txt` to block known exfiltration infrastructure. Use `--proxy-log proxy.log` for post-session audit. All traffic, including Copilot's own Node.js connections, routes through the proxy when enabled.

**`~/.config/gh/hosts.yml` is readable.** Copilot spawns `gh auth token` inside the sandbox. This file contains a GitHub OAuth token. Only `hosts.yml` and `config.yml` are readable (not the entire `.config/gh` directory). With outbound port 443 allowed, a compromised agent could theoretically exfiltrate this token. However, the token grants access to GitHub — which Copilot is already connected to. Users who want to mitigate this can use `--deny-path ~/.config/gh` (Copilot will fall back to Keychain auth).

*Possible mitigation:* A repo-scoped MCP proxy or fine-grained PAT that limits token scope to the current repository only. See issue #4 for investigation.

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
3. Variables matching `ENV_PREFIX_ALLOWLIST` (8 prefixes: `LC_*`, `COPILOT_*`, `COREPACK_*`, `MISE_*`, `NVM_*`, `PYENV_*`, `SDKMAN_*`, `YARN_*`) are re-added
4. `--pass-env VAR` adds explicit vars (repeatable)
5. `ENV_ALWAYS_DENY` vars (`NO_COLOR`, `FORCE_COLOR`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`) are always stripped

**Deliberately allowed:** `GH_TOKEN`, `GITHUB_TOKEN`, `COPILOT_GITHUB_TOKEN` — Copilot needs a GitHub token to function. This is an accepted trade-off.

**Deliberately blocked:** `AWS_*`, `AZURE_*`, `NPM_TOKEN`, `DATABASE_URL`, `VAULT_TOKEN`, `SSH_AUTH_SOCK`, Docker vars, CI tokens.

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
(deny file-* ~/.ssh, ~/.aws, ...)       ← Sensitive dirs blocked
(deny network-outbound (remote tcp))    ← Block all outbound TCP by default
(allow network-outbound *:443)           ← Then allow HTTPS port only (use --allow-port for extras)
(deny network-outbound localhost:*)     ← Block localhost SSRF
(allow network-outbound localhost:PORT) ← Carve-out for proxy (if --with-proxy)
```

> **Network note:** Outbound TCP is restricted to port 443 by default. SSH agent access (unix sockets) is blocked. Localhost outbound is blocked to prevent SSRF. Use `--allow-port` for additional ports. SBPL does not support domain-based rules — filesystem isolation is the primary security control.

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

Files always denied:

- `~/.netrc` — HTTP credentials
- `~/.npmrc` — npm registry tokens
- `~/.pypirc` — PyPI credentials
- `~/.gem/credentials` — RubyGems credentials
- `~/.vault-token` — HashiCorp Vault

#### Tool directory permissions

Home tool directories (`~/.cargo`, `~/.nvm`, etc.) use a per-directory permission model (`HomeToolDir`) with granular `process_exec`, `map_exec`, and `write` flags:

| Directory | process-exec | file-map-executable | file-write | Rationale |
|---|---|---|---|---|
| `.local`, `.mise`, `.nvm`, `.pyenv`, `.cargo`, `.rustup`, `.sdkman`, `go/bin`, `Library/pnpm` | ✅ | ✅ | varies | Contain executable binaries and shims |
| `.gradle`, `.m2`, `.konan`, `go/pkg` | ❌ | ✅ | varies | JNI/cgo/Kotlin native libs loaded via dlopen, no direct executables |
| `.yarn` | ❌ | ❌ | ✅ | Yarn Berry global cache — JavaScript packages only, no native binaries |
| `Library/Caches` | ❌ | ❌* | ✅ | Broad allow for dev tool caches; browser/app caches denied via regex prefix rules (com.apple.*, com.google.*, org.mozilla.*, etc.) — Xcode dev tools (com.apple.dt.*) re-allowed |

\* Exception: `~/Library/Caches/copilot/pkg/` has `file-map-executable` and `process-exec` for Copilot's native modules and helper binaries (`pty.node`, `spawn-helper`, `rg`). A `file-write*` deny prevents write-then-exec attacks. These carve-outs are placed after the broader deny rules (SBPL last-match-wins).

**Security principle:** Every writable+executable directory is a potential binary-drop staging path. By denying both `process-exec` and `file-map-executable` on `~/Library/Caches`, this vector is eliminated at the kernel level. Non-dev caches (browsers, system apps, communication tools) are denied via `DENIED_CACHE_PREFIXES` regex rules in the SBPL profile — new dev tools auto-work without code changes because their cache dirs don't use these prefixes.

#### Scratch directory

When `--scratch-dir` is enabled, cplt creates a per-session directory at `~/Library/Caches/cplt/tmp/{session-id}/` with full `read/write/exec/map-exec` permissions. This is a controlled exception to the TMPDIR exec deny:

- **Why it exists:** `go test`, `mise` inline tasks, and `node-gyp` compile to `$TMPDIR` then execute. The sandbox blocks this, breaking these tools. On macOS, JVM processes also need this because `java.io.tmpdir` defaults to `/var/folders/...` (ignoring `TMPDIR` env var); cplt injects `-Djava.io.tmpdir` via `JAVA_TOOL_OPTIONS` to redirect JVM temp usage to the scratch dir.
- **Security model:** The scratch dir has both write+exec — this is the accepted trade-off. Mitigations:
  - **Scoped path:** Only the specific session subpath has exec, not all of `~/Library/Caches/cplt/`
  - **0700 permissions:** Owner-only access, verified at creation
  - **Symlink rejection:** Base path is validated as a real directory, not a symlink
  - **Owner check:** `stat()` verifies the directory owner matches the current uid
  - **SBPL injection guard:** Path validated against metacharacters before interpolation
  - **Ephemeral:** Cleaned up on exit via RAII Drop; stale dirs GC'd after 24h on startup
- **On by default:** Enabled by default. Disable with `--no-scratch-dir` or `sandbox.scratch_dir = false` in config.

### Layer 2: CONNECT Proxy (Optional Logging and Domain Filtering)

When `--with-proxy` is enabled, a localhost CONNECT proxy intercepts all outbound traffic. `HTTP_PROXY`/`HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1` are injected into the sandbox environment, routing traffic from Copilot CLI (Node.js), `gh` (Go), `curl`, and any other tool through the proxy.

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

When `--with-proxy` is enabled, cplt injects `NODE_USE_ENV_PROXY=1`, `HTTP_PROXY`, and `HTTPS_PROXY` into the sandbox environment. All traffic — Copilot CLI, `gh`, `curl`, and any other tool — routes through the localhost CONNECT proxy.

**Historical context:** Earlier versions of Copilot CLI used a Node.js runtime that did not support proxy env vars, and injecting them broke the auth flow. This is no longer the case as of Copilot CLI 1.0.24+ with bundled Node.js v24.11.1.

**Design decision:** The proxy remains opt-in (`--with-proxy`) rather than default-on because:
- It adds latency to every connection (localhost roundtrip + proxy processing)
- The sandbox's filesystem isolation is the primary security control
- Port restrictions are enforced at both the kernel level (SBPL) and the proxy level

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

The only viable options are `(allow network-outbound (remote tcp))` (allow all) or `(deny network*)` (deny all). We allow outbound TCP because Copilot cannot function without network access, and use port restrictions as a secondary control.

#### Current state

- **Outbound TCP is allowed** in the sandbox profile, restricted to port 443 (+ `--allow-port`)
- **Filesystem isolation is the primary security control** — credentials are kernel-blocked regardless of network policy
- **The proxy** (when enabled) provides connection logging, domain blocking, port enforcement, and DNS rebinding protection for all traffic including Copilot

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

### Integration Tests (macOS only, 33 tests)

These invoke `sandbox-exec` with real Seatbelt profiles and verify **kernel-level enforcement**:

| Category | Tests | What's verified |
|---|---|---|
| File access | 5 | Project read/write, copilot config, temp write, process execution |
| Sensitive dir blocks | 4 | `~/.ssh`, `~/.aws`, `~/.docker`, `~/.kube` blocked |
| Network | 1 | Outbound connections blocked |
| Binary CLI | 4 | Version, help, root/home dir rejection |
| Tool dir permissions | 15 | Each HOME_TOOL_DIR has correct exec/map-exec/write at kernel level |
| GPG signing | 4 | Default blocks `~/.gnupg`, flag allows pubring read, private keys stay denied, writes stay denied |

### E2E Project Tests (macOS only, 35 tests)

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
