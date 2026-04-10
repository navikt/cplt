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
| **Write-then-exec in /tmp** | Drop binary in `/tmp`, execute it | `deny process-exec` + `deny file-map-executable` on `/tmp` and `/var/folders` |
| **Cloud metadata access** | Fetch `169.254.169.254` or CGNAT range | Comprehensive private IP blocklist |
| **Cross-project access** | Read files outside project directory | Seatbelt subpath restrictions |
| **Process-group escape** | Kill parent, children continue unsandboxed | `setpgid` + signal forwarding |
| **Env var credential theft** | Read `AWS_SECRET_ACCESS_KEY` from env | `env_clear()` + safe allowlist |
| **Persistence via native modules** | Replace `keytar.node` with malware | Deny writes to `~/.copilot/pkg` |
| **Git hook injection** | Write post-checkout hook that runs outside sandbox | Deny writes to `.git/hooks/` |
| **Git config hijacking** | Set `core.hooksPath=/tmp/evil` or URL redirect | Deny writes to `.git/config` |
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
- **Write+exec in home cache dirs** — `~/Library/Caches`, `~/.gradle`, `~/.m2`, `~/Library/pnpm` have both write and exec permissions. Build tools need write for dependency downloads and exec for build plugins. A rogue agent could write a malicious JAR to `~/.m2` or a Gradle plugin to `~/.gradle`, but the executed code would still be sandboxed.
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

**Network is port-restricted, not domain-filtered.** SBPL (Seatbelt Profile Language) does not support domain-based filtering. Copilot CLI connects to CDN-backed endpoints (`api.business.githubcopilot.com`) with changing IPs that cannot be enumerated. We allow outbound TCP on port 443 only (use `--allow-port` for extras, e.g. `--allow-port 80` for HTTP). SSH agent access and localhost outbound are blocked at the kernel level. This means:

- A compromised agent CAN make HTTPS requests to attacker-controlled servers on port 443
- A compromised agent CANNOT exfiltrate cloud credentials from env vars (env is sanitized; only safe allowlist passes through)
- A compromised agent CAN exfiltrate project source code and Copilot auth tokens
- A compromised agent CANNOT connect to local services (localhost is blocked)
- A compromised agent CANNOT use loaded SSH keys (unix socket is blocked)
- A compromised agent CANNOT connect on non-standard ports (e.g., 8080, 3000) unless `--allow-port` is used
- A compromised agent CANNOT exfiltrate SSH keys, cloud credentials, or npm tokens (kernel-blocked from reading them)
- The proxy (when enabled with `--with-proxy`) provides logging and domain blocking for tools that respect `http_proxy`, but Copilot's own Node.js traffic bypasses it

*Possible mitigation:* A domain-allowlist proxy that intercepts all TLS connections (not just `http_proxy`-aware tools) could restrict traffic to known Copilot endpoints. This requires transparent proxy + iptables-style routing, which conflicts with macOS code signing. Alternatively, a Network Extension (NExt) could filter at the system level — but requires an Apple-signed profile. See issue #4 for MCP proxy exploration.

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

Since credentials are inaccessible inside the sandbox (both at filesystem and environment level), network-based exfiltration can only leak project source code and `~/.config/gh` tokens — a much smaller blast radius than full credential theft.

## Defense Layers

### Layer 0: Environment Variable Sanitization

By default, `cplt` clears the child process environment and re-adds only safe variables from an allowlist. This prevents credential leakage through inherited env vars.

**How it works:**
1. `cmd.env_clear()` removes all environment variables
2. Variables matching `ENV_ALLOWLIST` (38 safe vars) are re-added from the parent process
3. Variables matching `ENV_PREFIX_ALLOWLIST` (6 prefixes like `LC_*`, `COPILOT_*`, `MISE_*`) are re-added
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

**Why this matters:** Supply chain attacks (e.g., axios March 2026) use `postinstall` hooks to execute malicious payloads. Blocking lifecycle scripts eliminates this attack class — `npm install` still downloads packages, but no arbitrary code runs. Explicit commands like `npm run build` still work normally.

**Escape hatch:** `--allow-lifecycle-scripts` disables the `LifecycleScripts` category. Use when `npm install` requires postinstall hooks (e.g., native module compilation).

### Layer 0.5: Native Module Write Protection

The sandbox denies writes to `~/.copilot/pkg/` (where Copilot's native modules like `keytar.node` live). This prevents a persistence attack where a rogue agent replaces a native module with malware that executes *unsandboxed* next time Copilot runs outside `cplt`.

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
(allow file-read/write /private/tmp)    ← Temp file access
(deny process-exec /private/tmp)        ← But no executing from tmp!
(deny file-* ~/.ssh, ~/.aws, ...)       ← Sensitive dirs blocked
(deny network-outbound (remote tcp))    ← Block all outbound TCP by default
(allow network-outbound *:443, *:80)    ← Then allow HTTPS/HTTP ports only
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
| `.local`, `.mise`, `.nvm`, `.cargo`, `.rustup`, `.sdkman`, `go/bin`, `Library/pnpm` | ✅ | ✅ | varies | Contain executable binaries and shims |
| `.gradle`, `.m2`, `go/pkg` | ❌ | ✅ | varies | JNI/cgo native libs loaded via dlopen, no direct executables |
| `Library/Caches` | ❌ | ❌ | ✅ | Build caches only — no exec of any kind (RAT staging risk; see axios case study) |

**Security principle:** Every writable+executable directory is a potential binary-drop staging path. By denying both `process-exec` and `file-map-executable` on `~/Library/Caches`, this vector is eliminated at the kernel level.

### Layer 2: CONNECT Proxy (Optional Logging and Domain Blocking)

When `--with-proxy` is enabled, a localhost CONNECT proxy provides **passive logging and domain blocking** for tools that respect `http_proxy` env vars (like `gh`, `curl`). It does NOT intercept Copilot CLI traffic — Node.js does not natively use `http_proxy`/`https_proxy`, and setting these vars breaks Copilot's auth flow.

The proxy provides:

1. **Connection logging** — every CONNECT target is logged with timestamp and status
2. **Domain blocklist** — configurable file-based blocklist with subdomain matching
3. **DNS rebinding protection** — resolves DNS first, validates the *resolved IP*, then connects using the pinned address
4. **Comprehensive private IP blocking** — covers all reserved ranges

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

### Network Limitations

#### Why we cannot filter Copilot's network traffic

The original design routed all sandbox traffic through a localhost CONNECT proxy, giving us full visibility and control over outbound connections. This was the ideal architecture: block outbound at the kernel level (`(deny network*)`), allow only localhost on the proxy port (`(allow network-outbound (local ip "localhost:18080"))`), and let the proxy log, filter, and enforce a domain allowlist.

**It did not work.** Here is what we discovered through systematic debugging:

**Phase 1: Proxy env vars break Copilot's auth flow.** The sandbox injected `http_proxy=http://localhost:18080` and `https_proxy=http://localhost:18080` into the child process environment. Copilot CLI is a Node.js application, and **Node.js does not natively respect `http_proxy`/`https_proxy` env vars**. The standard `https` module (and most HTTP client libraries in Node) connect directly — they do not read proxy settings from the environment the way Go's `net/http` or curl do.

Setting these env vars did not route Copilot traffic through the proxy. Instead, it interfered with Copilot's HTTP client internals. The auth flow — which contacts `api.github.com` to validate tokens, then `api.business.githubcopilot.com` for the Copilot API — failed with "No authentication information found" even though the token was valid.

**Phase 2: Removing proxy env vars fixes auth.** When we stopped injecting proxy env vars and allowed outbound TCP directly (`(allow network-outbound (remote tcp))`), Copilot authenticated successfully and worked correctly. This confirmed the env vars were the cause — not the sandbox itself.

**Phase 3: Go tools DO respect proxy env vars.** We observed that `gh` (the GitHub CLI, a Go binary that Copilot spawns for `gh auth token`) did route through the proxy. Go's `net/http.ProxyFromEnvironment()` reads `https_proxy` by default. This means the proxy saw CONNECT requests to `api.github.com` from `gh`, but never saw Copilot's own traffic to `api.business.githubcopilot.com`, `api.githubcopilot.com`, or `proxy.business.githubcopilot.com`.

**Root cause summary:**

| Component | Language | Respects `http_proxy`? | Through proxy? |
|---|---|---|---|
| Copilot CLI | Node.js | ❌ No (breaks auth when set) | ❌ Never |
| `gh` CLI | Go | ✅ Yes (`net/http`) | ✅ Yes |
| `curl` | C | ✅ Yes | ✅ Yes |

**Why not force Node.js to use the proxy?** Node.js requires explicit proxy support in the HTTP client code (e.g., the `global-agent` npm package or `--proxy-server` flag for Electron). Copilot CLI is a pre-built binary — we cannot modify its source code to add proxy support. Even if we could, CONNECT proxies for HTTPS only see the target hostname:port (SNI), not the request body, so the security value is limited to domain filtering.

**Design decision:** The proxy is kept as an opt-in tool (`--with-proxy`) for logging connections from tools that DO respect proxy env vars (`gh`, `curl`, other Go/Python tools). It is disabled by default because it provides no value for Copilot's primary traffic and was misleading when presented as a security control.

#### SBPL network filtering limitations

Even without the proxy, we explored filtering at the Seatbelt level. SBPL has fundamental limitations:

- **No domain-based rules** — SBPL operates at the syscall level, not the application level. It cannot match on hostnames.
- **No wildcard port filtering** — there is no syntax for "allow any host on port 443 only"
- **IP-based rules require known IPs** — Copilot's API endpoints (`api.business.githubcopilot.com`) use CDN-backed IPs that change regularly and cannot be enumerated

The only viable options are `(allow network-outbound (remote tcp))` (allow all) or `(deny network*)` (deny all). We chose to allow all outbound TCP because Copilot cannot function without network access.

#### Current state

- **All outbound TCP is allowed** in the sandbox profile
- **Filesystem isolation is the primary security control** — credentials are kernel-blocked regardless of network policy
- **The proxy remains useful** for logging traffic from Go-based tools (`gh`) and for domain blocking as a defense-in-depth measure
- **Future improvement:** If Copilot CLI ever adds native proxy support (e.g., via `global-agent` or `NODE_EXTRA_CA_CERTS` + MITM proxy), the full proxy architecture could be re-enabled

## Test Strategy

### Unit Tests (cross-platform, run on Linux CI)

These test core logic without invoking `sandbox-exec`, using the real library functions (not duplicated copies):

| Category | Tests | What's verified |
|---|---|---|
| Unsafe root detection | 11 | Rejects `/`, `/Users`, `/tmp`, `/var`, `/Applications`, `/System`, `$HOME`; allows project subdirs |
| Domain blocking | 7 | Exact match, subdomain match, no partial match, comments, case-insensitive, empty blocklist |
| Private IP detection | 9 | Loopback, RFC 1918, link-local, unspecified, CGNAT, benchmarking, reserved, ULA, link-local v6 |
| Hostname detection | 3 | localhost, .localhost, .local patterns; allows normal hostnames |
| SBPL injection | 5 | Rejects `\n`, `\0`, `"`, `(`; allows normal paths |
| Profile generation | 8 | Uses real `generate_profile()`; verifies deny-default, project access, sensitive dir blocks, network rules, deny-after-allow ordering, exec-from-tmp denied, sensitive files denied |
| Config parsing | 20 | TOML parsing, CLI/config merge precedence, tilde expansion, SBPL validation, path canonicalization |

### Integration Tests (macOS only)

These invoke `sandbox-exec` with real Seatbelt profiles and verify **kernel-level enforcement**:

| Test | Verifies |
|---|---|
| `sandbox_allows_project_file_read` | Can read files in project directory |
| `sandbox_allows_project_file_write` | Can write files in project directory |
| `sandbox_allows_copilot_config` | Can access `~/.copilot` |
| `sandbox_allows_temp_write` | Can write to `/tmp` |
| `sandbox_allows_process_execution` | Can run child processes |
| `sandbox_blocks_ssh_read` | **Cannot** read `~/.ssh` |
| `sandbox_blocks_aws_read` | **Cannot** read `~/.aws` |
| `sandbox_blocks_docker_read` | **Cannot** read `~/.docker` |
| `sandbox_blocks_kube_read` | **Cannot** read `~/.kube` |
| `sandbox_blocks_outbound_network` | **Cannot** make outbound connections |
| `binary_shows_version` | Binary runs and shows version |
| `binary_shows_help` | Binary shows help text |
| `binary_rejects_root_project_dir` | Refuses `/` as project dir |
| `binary_rejects_home_project_dir` | Refuses `$HOME` as project dir |

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
