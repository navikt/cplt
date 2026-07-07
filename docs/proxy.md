# Proxy and Domain Filtering

## Proxy

The proxy is **enabled by default** — all outbound traffic (Copilot CLI, `gh`, `curl`) is routed through a localhost CONNECT proxy via `HTTP_PROXY`/`HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1`. The proxy listens on an OS-assigned ephemeral port, so there are no port conflicts.

**What the proxy gives you:**

- **Connection logging** — see every domain Copilot connects to in real time
- **Domain blocking** — block known exfiltration infrastructure (paste sites, webhook services, etc.)
- **Domain allowlisting** — restrict connections to only known-safe domains
- **Audit log** — persistent file log of all connections for post-session review
- **Port enforcement** — the proxy enforces the same port restrictions as the sandbox (443 + `--allow-port`)

**Disable for a single run** (override):

```bash
cplt --no-proxy -- -p "fix the tests"
```

**Disable the proxy:**

```bash
cplt config set proxy.enabled false
```

**Add connection filtering** (recommended):

```bash
cplt config set proxy.blocked_domains "~/.config/cplt/blocked-domains.txt"
# or restrict to known-safe domains only:
cplt config set proxy.allowed_domains "~/.config/cplt/allowed-domains.txt"
# optional audit log:
cplt config set proxy.log_file "~/.config/cplt/proxy.log"
```

<details>
<summary>CLI flags reference (override for a single run)</summary>

| Flag                        | What it does                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------ |
| `--with-proxy`              | Explicitly enable the proxy (no-op when proxy is already on by default).                         |
| `--no-proxy`                | Disable the proxy for this run.                                                                  |
| `--proxy-forced` / `--no-proxy-forced` | Force **all** egress through the proxy (opt-in, default off): make the proxy mandatory and restrict kernel egress to the proxy port. Fails closed; conflicts with `--no-proxy`. See [Proxy-forced mode](#proxy-forced-mode). |
| `--proxy-port <PORT>`       | Which port the proxy listens on (default: 0, OS-assigned ephemeral).                             |
| `--blocked-domains <FILE>`  | Domains to block, one per line. Re-read every ~5s (edit live, changes take effect within seconds). |
| `--allowed-domains <FILE>`  | Domains to allow — only listed domains can connect. Validated at startup (fail-closed); re-read every 5s.  |
| `--default-allowlist`       | Enable the agent's built-in default allowlist for this run (opt-in, default off): restrict egress to the agent's fail-closed domain set merged with `--allowed-domains`. See [Default allowlist](#default-allowlist-fail-closed-networking). |
| `--allow-all-domains`       | Escape hatch: disable the default allowlist for this run and allow all domains (blocklist still applies). Also ignores any `--allowed-domains` file. |
| `--proxy-log <FILE>`        | Append a line per connection to this file for post-session audit.                                |
| `--proxy-log-level <LEVEL>` | Stderr verbosity: `none` (default/silent), `error`, `blocked`, or `all`. The audit log file always records everything. |
| `--allow-private-domain <DOMAIN>` | Allow connections to this domain even if it resolves to a private/internal IP. Use for corporate intranet services (e.g. internal MCP servers). Suffix matching: `intern.nav.no` covers all subdomains. Can be repeated. |

</details>

> **Domain matching:** both blocklist and allowlist use the same rules — `example.com` matches the exact domain and all subdomains (`sub.example.com`, `deep.sub.example.com`). Matching is case-insensitive. Trailing dots are stripped.
>
> **Localhost traffic** (MCP servers, dev servers) bypasses the proxy via `NO_PROXY` and will not appear in the audit log.
>
> **Quiet mode** (`-q` / `sandbox.quiet = true`) suppresses the startup banner. Proxy stderr output is controlled separately by `--proxy-log-level` (default: `none` — silent). Use `--proxy-log` to capture all connections to a file.

## Proxy-forced mode

By default the proxy is **advisory at the kernel level**: outbound TCP to `*:443` is allowed by the sandbox, and traffic is routed through the proxy only because cplt sets `HTTP_PROXY`/`HTTPS_PROXY`/`NODE_USE_ENV_PROXY=1`. A tool that opens a raw socket, or an agent that runs `env -u HTTPS_PROXY -u HTTP_PROXY …`, can reach the internet on `:443` **without** passing through the proxy — bypassing all domain filtering.

**Proxy-forced mode (`#53`) closes that bypass.** It is **opt-in and off by default** (making it the default is tracked in [#71](https://github.com/navikt/cplt/issues/71)). Enable it per run or in config:

```bash
cplt --proxy-forced -- -p "fix the tests"
```

```bash
cplt config set proxy.forced true
```

```toml
[proxy]
forced = true
```

**What it changes:**

- **The proxy becomes mandatory.** It is forced on regardless of other proxy defaults.
- **Kernel egress is restricted to the proxy port.** Instead of allowing outbound `*:443`, the sandbox allows outbound only to the proxy's listening port (plus any configured localhost ports). Direct `:443` connections that skip the proxy are blocked at the kernel level, so raw sockets and `env`-unset attempts can no longer reach the network over a direct `:443` connection. Traffic that does reach the network goes through the proxy, which then applies domain allow/block filtering as usual. (How *complete* this is depends on the platform — see the asymmetry note below; on Linux a narrow residual on the proxy port remains.)

**Platform asymmetry (important — enforcement is not equal):**

- **macOS (Seatbelt):** the profile pins egress to `localhost:<proxy_port>`. There is no direct-network path at all — full enforcement, no residual.
- **Linux (Landlock):** Landlock is **port-based and cannot pin to localhost**. Proxy-forced drops the `:443` rule and allows only the proxy port, which blocks direct `:443` to any host — but a narrow `evil.com:<proxy_port>` channel remains reachable if a remote host happens to answer on that exact port. Closing this residual requires a network namespace and is tracked in [#114](https://github.com/navikt/cplt/issues/114). Until then, treat Linux proxy-forced as "no direct `:443` bypass" rather than "no egress except the proxy."

**Fail-closed behavior:**

- If the mandatory proxy cannot bind/start, cplt **refuses to launch the agent** — it never falls back to open networking.
- `--proxy-forced` **conflicts with `--no-proxy`** (and with `proxy.enabled = false`). cplt errors out with a clear message rather than silently picking a side.

**Interaction with allowed-domains:** proxy-forced only changes *kernel* egress (which port the sandbox permits). It does **not** replace domain filtering — the proxy still enforces `allowed_domains` / `blocked_domains` on the traffic it carries. Use proxy-forced together with an allowlist to get "only these domains, and no way around the proxy." A default per-agent allowlist that would pair naturally with this mode is tracked in [#52](https://github.com/navikt/cplt/issues/52).

**Raw-TCP tradeoff (by design):** tools that are not proxy-aware (they ignore `HTTP_PROXY`, or need a non-CONNECT/non-HTTPS protocol) lose direct network access under proxy-forced. That is the point of the mode — the only sanctioned path off the machine is the CONNECT proxy. If you genuinely need such a tool you can add its port with `--allow-port`, but be aware that an extra allowed port opens a **direct** kernel egress channel on that port that does **not** pass through the proxy (and is therefore not domain-filtered) — it reopens exactly the kind of bypass proxy-forced exists to close. Prefer leaving proxy-forced off for those workloads rather than punching a hole through it.

## Domain filtering

When the proxy is enabled, it supports both **blocking** (deny known-bad domains) and **allowlisting** (permit only known-good domains).

### Blocklist

Block domains commonly used for data exfiltration. A default blocklist is included based on real attack infrastructure observed in 2025–2026 supply chain incidents:

```bash
cplt config set proxy.blocked_domains "~/.config/cplt/blocked-domains.txt"
```

The blocklist covers webhook capture services, paste sites, file sharing, tunneling services, and IP recon endpoints. See [`blocked-domains.txt`](../blocked-domains.txt) for the full list with sources.

### Allowlist

Restrict connections to only specific domains. When set, the proxy blocks everything not in the list:

```bash
cplt config set proxy.allowed_domains "~/.config/cplt/allowed-domains.txt"
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

Set either permanently:

```bash
cplt config set proxy.blocked_domains "~/.config/cplt/blocked-domains.txt"
cplt config set proxy.allowed_domains "~/.config/cplt/allowed-domains.txt"
```

> **Note:** Both the allowlist and blocklist are re-read from disk every ~5 seconds (TTL-cached), so you can edit them live mid-session. Changes take effect within seconds without restarting cplt. If a file becomes unreadable at runtime, the last-known-good list is kept (fail-safe). At startup, an unreadable allowlist causes cplt to exit with an error (fail-closed).
>
> The `allow_private_domains` list in `config.toml` is also re-read every ~5 seconds. Domains added via `--allow-private-domain` CLI flags are always preserved regardless of config changes.

### Default allowlist (fail-closed networking)

By default the proxy is **allow-all**: it logs and blocks known-bad domains, but any HTTPS endpoint on the internet is reachable. Because port 443 is open at the kernel level, a compromised agent or a malicious dependency could exfiltrate source code to an arbitrary host. Network control is the only defense-in-depth layer that stops exfiltration *after* an agent is compromised (issue #52).

Each agent ships with a built-in **default allowlist** — the set of domains it legitimately needs, on top of a shared package-registry base. For **Copilot** this is the GitHub Copilot infrastructure plus common package registries:

```
# GitHub Copilot infrastructure
githubcopilot.com          # covers *.githubcopilot.com
api.github.com
github.com
copilot-proxy.githubusercontent.com
actions.githubusercontent.com   # covers *.actions.githubusercontent.com
default.exp2.cds.s9ch.io
# Package registries (shared by all agents)
registry.npmjs.org  registry.yarnpkg.com  repo.maven.apache.org
plugins.gradle.org  crates.io  static.crates.io  pypi.org  files.pythonhosted.org
```

**Per-agent infrastructure defaults.** Each agent adds its own endpoints on top of the shared registry base:

- **Copilot** — GitHub Copilot infrastructure (above).
- **Gemini** — Google Gemini API, Code Assist backend, and Google OAuth.
- **Antigravity** — the same Google AI infrastructure as Gemini, plus `antigravity.google`.
- **Claude** — the Anthropic API, console/login, and feature-flag telemetry.
- **OpenCode** — only OpenCode's own infra (`opencode.ai`, `models.dev`). OpenCode is provider-agnostic, so **you must add your chosen model provider's domain** (e.g. `api.anthropic.com`, `api.openai.com`, or `generativelanguage.googleapis.com`) via `allowed_domains` for the model traffic to be permitted.
- **Pi** — no infrastructure defaults yet; add its endpoints via `allowed_domains` when enabling the allowlist (contributions welcome).
- **Shell** — registry base only (not an AI agent).

These infra lists are best-effort defaults for this opt-in feature; anything missing shows up as `BLOCKED-ALLOWLIST` (see below) so you can add it.

Turn it on to make the proxy **fail-closed** — only these domains (and your own additions) are allowed, everything else is blocked:

```bash
cplt --default-allowlist -- -p "fix the tests"      # for one run
cplt config set proxy.default_allowlist true         # permanently
```

- **Opt-in and off by default.** Enabling it does **not** change any other behaviour, and the global default remains allow-all (see issue #71 for making it the default).
- **Effective allowlist = agent defaults ⊕ your `allowed_domains`.** When on, the agent's built-in list is **merged** with any file/config `allowed_domains`, so you add project registries or internal hosts without re-listing the base set. On startup cplt prints e.g. `Domain policy: 15 domains allowed (agent defaults + 1 configured)`.
- **Blocked attempts are visible.** Denied connections are logged as `BLOCKED-ALLOWLIST` (see `--proxy-log` / `--proxy-log-level blocked`) so you can quickly see what to add.
- **Escape hatch.** `--allow-all-domains` disables the allowlist for a single run (and ignores any `--allowed-domains` file) — allow-all again, for debugging. It overrides both `--default-allowlist` and `proxy.default_allowlist`.
- **Composes with the other proxy features.** The domain allowlist is enforced by the proxy regardless of `proxy.forced` (kernel egress restriction) or `proxy.upstream` (corporate-proxy forwarding): a no-proxy/upstream target still passes through the same allowlist check — the allowlist governs **which** domains, orthogonal to **how** they are routed.

### Verifying / generating an agent's domain allowlist

The per-agent default allowlists (see above) should be **empirically observed**, not guessed. `--observe-domains` runs the session with the proxy in **allow-all mode** and records every domain the agent contacts, then prints the set as a ready-to-paste allowlist. This is how you make a default allowlist *verifiable and exhaustive*.

```bash
# Capture what the agent contacts while doing a representative task.
cplt --agent copilot --observe-domains -- -p "add tests for the parser and run them"
```

`--observe-domains`:

- **Forces the proxy on and in allow-all mode for this run.** It overrides `--preset strict`, `--default-allowlist`, `proxy.default_allowlist`, and any configured `allowed_domains` — nothing is blocked, so you observe the *full* set the agent would contact. cplt prints a one-line notice and a warning that **this run does not enforce domain filtering** (do not treat an observe run as a protected session).
- **Records every CONNECT** regardless of `--proxy-log` / `--proxy-log-level`, then emits the sorted, deduplicated host list to stderr (always, even under `--quiet`):

```
[cplt] observe-domains: 14 domains contacted by Copilot this session
# add to allowed_domains (or src/agent.rs default_allowed_domains):
# bare hosts, exact-or-subdomain match; collapse subdomains to a parent by hand
# e.g. api.githubcopilot.com + proxy.githubcopilot.com -> githubcopilot.com
api.github.com
api.githubcopilot.com
github.com
registry.npmjs.org
...
```

- **`--observe-domains-out <FILE>`** also writes the bare domain list (one per line) to `FILE` for scripting.
- **Works for `cplt exec` too:** `cplt --agent claude --observe-domains exec -- npm test`.

To make it representative, exercise the workflows you care about in one session: resume a chat, build, run tests, install a dependency, etc. The emitted hosts are the *raw* observed set; subdomains are **not** auto-collapsed (that needs a public-suffix heuristic that risks over-broadening). Because the allowlist matcher is **exact-or-subdomain**, you can fold related subdomains to a parent by hand — e.g. `api.githubcopilot.com` + `proxy.githubcopilot.com` → `githubcopilot.com`.

**Updating the allowlist.** Paste the observed hosts into either:

- your own `allowed_domains` file / `proxy.allowed_domains` config (per-project), or
- an agent's built-in defaults in [`src/agent.rs`](../src/agent.rs) (`default_allowed_domains` and the `*_DOMAINS` consts) for a change shipped to everyone.

When editing `src/agent.rs`, record **provenance** in a comment on the const — which agent + version and the date you captured the domains — so reviewers can tell whether the list is current (see the convention note above those consts). Do not fabricate provenance for lists you did not actually observe.

## Proxy operations

### Connection log

Every connection attempt is printed to stderr in real time:

```
[proxy] 14:23:01 CONNECT api.githubcopilot.com:443 → CONNECTED
[proxy] 14:23:04 CONNECT pastebin.com:443 → BLOCKED
[proxy] 14:23:07 CONNECT mcp-onboarding.intern.nav.no:443 → BLOCKED-PRIVATE-RESOLVED
```

To write a persistent audit log:

```bash
cplt config set proxy.log_file "~/.config/cplt/proxy.log"
```

Log file format (one line per connection):

```
2025-01-15T14:23:01Z CONNECT api.githubcopilot.com:443 CONNECTED
2025-01-15T14:23:04Z CONNECT pastebin.com:443 BLOCKED
```

### Status codes

| Status | Meaning | Action |
|---|---|---|
| `CONNECTED` | Connection succeeded | — |
| `BLOCKED` | Domain matched blocklist | Check `--blocked-domains` file |
| `BLOCKED-ALLOWLIST` | Domain not in allowlist | Add domain to `--allowed-domains` file |
| `BLOCKED-PORT` | Port not in allowed list | Add with `--allow-port <PORT>` |
| `BLOCKED-PRIVATE` | Pre-DNS private IP (`.local`, `127.*`, IP literals) | Use `--allow-localhost` for local ports |
| `BLOCKED-PRIVATE-RESOLVED` | DNS resolved to a private IP | Use `--allow-private-domain <DOMAIN>` |
| `DNS-FAIL` | DNS resolution failed | Check domain spelling or network |
| `CONNECT-FAIL:...` | TCP connection to target failed | Target may be down |
| `UNSUPPORTED` | Non-CONNECT HTTP method | Only CONNECT tunnels are supported |
| `LIMIT` | 64 concurrent connections reached | Reduce parallelism |

### Troubleshooting

**Tool blocked with `BLOCKED-PRIVATE-RESOLVED`** — a domain (typically corporate intranet) resolved to a private IP:

```bash
cplt config set proxy.allow_private_domains intern.nav.no
```

Or for a single run: `cplt --allow-private-domain intern.nav.no`

**MCP server on localhost blocked** — use `allow.localhost` (not `allow_private_domains`):

```bash
cplt config set allow.localhost 3000
```

**Tool needs a non-443 port** — add it explicitly:

```bash
cplt config set allow.ports 8443
```

**Nothing connects — check if proxy is running:**

```bash
cplt --print-profile | grep localhost   # shows the proxy port rule in the Seatbelt profile
```

**Disable the proxy entirely for debugging:**

```bash
cplt --no-proxy -- -p "fix tests"
```

### Corporate proxy environments

cplt injects its own `HTTP_PROXY`/`HTTPS_PROXY` into the sandbox environment, replacing any corporate proxy you may have set. The sandbox environment is cleared by default (sensitive env vars stripped), so your external `HTTP_PROXY` does not flow in.

If you need to chain through a corporate proxy instead of using cplt's built-in proxy:

```bash
cplt config set proxy.enabled false
cplt config set sandbox.pass_env HTTP_PROXY
cplt config set sandbox.pass_env HTTPS_PROXY
```

> **Note:** Disabling the proxy removes cplt's built-in domain filtering, connection logging, and port enforcement. The `blocked_domains` and `allowed_domains` settings are features of the built-in proxy — they have no effect when the proxy is disabled. If your corporate proxy has its own domain filtering, rely on that instead. The sandbox still enforces filesystem and process isolation regardless of proxy settings.

### Chaining through an upstream (corporate) proxy

Instead of disabling cplt's proxy, you can keep it **and** forward its approved CONNECT tunnels through your corporate proxy. cplt still enforces **all** of its own filtering (allowlist, blocklist, port policy, resolved-IP SSRF guard) *before* forwarding — the upstream only ever receives targets cplt's policy already permits.

```bash
cplt config set proxy.upstream "http://corporate-proxy.example.com:8080"
# or for a single run:
cplt --proxy-upstream http://corporate-proxy.example.com:8080 -- -p "fix the tests"
```

Optional basic-auth userinfo is supported (`http://user:pass@host:8080`); only the `http` scheme is supported. The credentials are redacted in `config show` and startup output.

#### Bypassing the upstream for some hosts (`NO_PROXY`)

Corporate setups almost always list internal hosts that must **not** go through the corporate proxy. Add them to `proxy.upstream_no_proxy` — a matching CONNECT target is connected to **directly by cplt** instead of being forwarded upstream, exactly like a `NO_PROXY` entry:

```bash
cplt config set proxy.upstream_no_proxy "internal.example.com"
# repeatable CLI flag for a single run:
cplt --proxy-upstream-no-proxy internal.example.com -- -p "..."
```

```toml
[proxy]
upstream = "http://corporate-proxy.example.com:8080"
upstream_no_proxy = ["internal.example.com", "corp.example"]
```

> [!IMPORTANT]
> **Internal hosts also need `allow_private_domains`.** A no-proxy host takes cplt's **direct** path, which applies the resolved-IP SSRF guard — so an internal host that resolves to a private IP (the usual `NO_PROXY` target) is **blocked** (`403 Resolved to private IP`) unless you *also* allow it to resolve private:
> ```toml
> [proxy]
> upstream = "http://corporate-proxy.example.com:8080"
> upstream_no_proxy   = ["internal.example.com"]  # bypass the upstream
> allow_private_domains = ["internal.example.com"]  # AND permit its private IP
> ```

- **Matching** uses the same rules as the other domain lists: `example.com` matches the exact host and all subdomains (`internal.example.com`). Case-insensitive; leading/trailing dots (`.example.com.`) are stripped automatically. **CIDR/IP ranges are not honored** — only hostnames (exact + subdomain) and exact IPs match; a `10.0.0.0/8`-style entry is silently ignored (it could only divert to the already-filtered direct path anyway).
- **`NO_PROXY` env is merged in, additively.** cplt reads the ambient `NO_PROXY`/`no_proxy` environment variable (comma- or whitespace-separated) and merges those hosts on top of the config/CLI list; there is no CLI way to *subtract* an ambient entry. Empty entries and a bare `*` wildcard are ignored (cplt does not honor "bypass everything").
- **No-op without an upstream.** The list is only consulted when `proxy.upstream` is set.
- **Security is preserved.** A no-proxy host is **not** exempt from any filtering. Every gate (allow/block/port/SSRF resolved-IP check) runs *before* the upstream-vs-direct decision, and the direct path re-applies the resolved-IP guard. The host is simply connected directly by cplt — which runs **outside** the sandbox — rather than forwarded to the corporate proxy. Because cplt (not the agent) makes that connection, this also works under `proxy.forced`.

## Copilot CLI network endpoints

Copilot CLI 1.0.21 connects directly to these endpoints (empirically verified):

| Endpoint                           | Purpose                                  |
| ---------------------------------- | ---------------------------------------- |
| `api.github.com`                   | GitHub API (user info, token validation) |
| `api.githubcopilot.com`            | Copilot API                              |
| `api.business.githubcopilot.com`   | Copilot Business API (enterprise users)  |
| `proxy.business.githubcopilot.com` | Copilot Business proxy                   |
