# Design: a generic MCP host broker

Status: proposal, 2026-10-23. Design only, nothing here is implemented.
Refs [#821](https://github.com/navikt/cplt/issues/821), [#807](https://github.com/navikt/cplt/pull/807), [#797](https://github.com/navikt/cplt/issues/797).

Code citations are against `origin/main` at the time of writing. Claims marked
**(unverified)** were not checked against source or by running them.

## 1. Problem and goals

cplt's sandbox keeps credentials out of the agent. MCP servers need
credentials. Today the two meet in three ways, all bad:

- **The server cannot log in.** GitHub's remote MCP needs OAuth without
  dynamic client registration, so OpenCode cannot get a token
  ([#797](https://github.com/navikt/cplt/issues/797)).
- **The server needs a grant cplt will not give.** `nais alpha mcp serve` runs
  as a child of the agent, inside the sandbox, and needs the macOS login
  keychain plus `~/Library/Application Support/nais/nais-credentials.json.enc`.
  Granting `~/Library/Keychains` exposes every silently readable keychain item
  (SECURITY.md:924-945, "Keychain access is all-or-nothing").
- **The token is handed to the agent.** `--pass-env GH_TOKEN` and similar work,
  and are what cplt is trying to stop.

[#807](https://github.com/navikt/cplt/pull/807) fixed GitHub with a one-off
module, `src/github_mcp.rs`. #821 needs the same for Nais, and the owner
expects more. This document asks what the second, third and tenth server
should look like.

Goals:

| # | Goal | Test |
|---|------|------|
| G1 | Credentials never enter the sandbox | No token, keychain or credential-file grant; the agent sees an MCP endpoint, not a secret |
| G2 | Just works | A user who ran `nav-pilot mcp enable` and logged in on the host (`gh auth login`, `nais login -n`) needs no cplt config |
| G3 | Scales to N servers | Adding a server is a declaration plus review, not a new Rust module |
| G4 | No break for existing users | `sandbox.github_mcp_proxy` and `--no-github-mcp-proxy` keep working |
| G5 | Policy is enforced outside the agent | Read-only and tool limits hold even against a hostile agent |

Non-goals: a general MCP gateway for other machines, multi-user serving, and
replacing the agent's own MCP permission prompts.

## 2. User experience

The broker is plumbing. What users see is whether `nav-pilot mcp enable
<name>` gives them working tools. This section sets the target first; the
rest of the document serves it.

Clients in scope: Copilot CLI and OpenCode, the two `nav-pilot mcp enable
--client` targets (navikt/copilot `cli/nav-pilot/internal/cli/mcp_cmd.go:135-137`).
Claude Code and VS Code matter as comparisons and for users who configure
them by hand. pi has no built-in MCP client **(unverified)**, so it is out
of scope until it has one.

### 2.1 Today's journeys

| Server | Client | What the user does | Where it breaks | What they see |
|--------|--------|--------------------|-----------------|---------------|
| GitHub | OpenCode, no cplt | `nav-pilot mcp enable io.github.navikt/github-mcp --client opencode` | OpenCode tries OAuth; GitHub has no DCR | `Incompatible auth server: does not support dynamic client registration` (#797) |
| GitHub | OpenCode, cplt before #807 | Same | Same, and `GH_TOKEN` is stripped, so the bearer-header workaround fails too | `needs authentication` in `opencode mcp list` (#807 e2e) |
| GitHub | OpenCode, cplt with #807 | Same | Works if `gh auth login` was done on the host | Without it: "GitHub MCP in OpenCode needs your gh login: run `gh auth login`." (`src/opencode_v2.rs:330`) |
| GitHub | Copilot CLI | Nothing: built in | Works; Copilot holds the token | Nothing |
| Figma | OpenCode | `nav-pilot mcp enable com.figma/figma-mcp`, then `opencode mcp auth` | Under cplt strict mode, OAuth needs `api.figma.com`; the browser hand-off needs `--allow-browser` or a copied URL | Host consent prompt from nav-pilot (navikt/copilot#1272), then the client's OAuth errors. No summary of the Slack threads was found in the issues, so no Figma error text is quoted |
| Nais | any | `nais login -n` on the host, then a hand-written stdio entry (registry `setupInstructions`; `nav-pilot mcp enable` does not support it) | Under cplt the server runs in the sandbox and cannot read the keychain | Connects, then every call fails: `unauthenticated: please log in with nais login -n` (#821), though the user is logged in |
| Stdio, no secrets (Playwright, next-devtools) | any | `nav-pilot mcp enable <name>` | Missing runtime or a cplt cache rule | `mcp list` shows the problem and the fix (`mcp_cmd.go:489-498`) |

Nais is the worst case: the error names a fix the user has already run.

### 2.2 Target journey

One command, the same everywhere:

```text
$ nav-pilot mcp enable io.github.nais/nais-mcp
  Nais MCP: 12 read-only tools. Login: nais (not logged in).
  Run `nais login -n` now? [Y/n]
  ...browser opens on the host...
  Enabled for opencode and copilot. Under cplt it runs on the host, outside the sandbox, read-only.
```

Rules:

1. **Login happens on the host, once, prompted by nav-pilot**, with the
   tool's own command (`gh auth login`, `nais login -n`) or, for OAuth
   servers, a browser flow run outside the sandbox. The agent is never
   asked to log in.
2. **Same config with or without cplt.** nav-pilot writes the client's
   normal entry (remote URL or stdio command). cplt overlays it at launch,
   as #807 does; outside cplt the entry works as written. The user's file
   never holds a cplt URL or a token.
3. **Same behaviour in every client.** The tool set, read-only state and
   error texts depend on the server and policy, not the client. Where a
   client cannot do something (2.6), nav-pilot says so at enable time, not
   at the first call.
4. **No cplt config for the common case.** Opt-outs exist; nothing has to
   be turned on.

### 2.3 Who owns what

| Owner | Owns | Does not own |
|-------|------|--------------|
| Registry (`allowlist.json`) | Identity, transport, upstream URL, tools and risk classes (`toolRisk`), host needs (`sandboxHosts`), setup steps. **New:** `auth.kind` (none, host-cli, oauth, ambient-stdio), `auth.loginCommand`, `auth.statusCommand`, `minCplt` | Enforcement; anything that runs |
| nav-pilot | Writing each client's config, consent, preflight (binary present, logged in, cplt version), `mcp list` and doctor, running the login command on the host | Holding tokens; runtime policy |
| cplt | The reviewed broker table, spawning and proxying, policy (tool filter, read-only, GraphQL check), the config overlay, one-line launch warnings | Writing user config; consent UI |
| Client | Connecting, showing tools, its own per-call permission prompts | Credentials, for brokered servers |

The registry declares, nav-pilot asks, cplt enforces. navikt/copilot#1272
chose the same chain for egress ("registry changes ... must never grant
egress by themselves"); the broker reuses it.

### 2.4 Status and diagnostics

Extend `nav-pilot mcp list`. It already prints a problem and a `Fix:` line
per server (`mcp_cmd.go:139-145`, `:249`). Target:

```text
SERVER        CLIENTS            LOGIN               PATH          TOOLS
github-mcp    opencode, copilot  gh: ok              cplt broker   10 read
nais-mcp      opencode           nais: expired       cplt broker   12 read
figma-mcp     opencode           oauth: in client    direct        4 read, 10 off (external)
playwright    copilot            none needed         sandbox       13 read/write, 3 off

  nais-mcp: login expired.  Fix: nais login -n
```

LOGIN comes from the registry's `auth.statusCommand` (`gh auth status`;
the nais equivalent is **(unverified)**). PATH comes from a new
`cplt mcp status --json`, which runs launch detection without starting
anything. `cplt doctor` shows the same rows.

Every error, whether from cplt at launch, a broker JSON-RPC error or
nav-pilot, follows one pattern: **what is wrong, then the exact command that
fixes it.** The broker turns a child's auth failure into
`nais-mcp: not logged in on the host. Fix: nais login -n (outside the agent)`,
so the agent can relay it.

### 2.5 Consent and visibility

- **At enable, once per server:** show the risk classes and what is on.
  Read tools are on. `write` is on by default in nav-pilot today
  (navikt/copilot `cli/nav-pilot/internal/provider/mcp_tools.go:46-55`), but should be **off for brokered servers**,
  because the broker runs them outside the sandbox. `external` asks.
  `host-exec` asks with a warning and is never brokered.
- **At launch:** silent, except one line per brokered server on the first
  launch after enable, and a line when a server is skipped (no login,
  proxy off).
- **In session:** the client's own per-call prompts. The broker adds no
  prompts; it refuses with a clear error the agent sees.
- **Changes need new consent:** a registry update that adds a tool or
  raises its class leaves it off until the user re-runs enable. nav-pilot
  already narrows approvals (`cli/nav-pilot/internal/provider/mcp_servers.go:130`).

All prompting happens at enable time. cplt never prompts per session or per
call.

### 2.6 Client differences

| Difference | Copilot CLI | OpenCode | Hidden by | Leaks when |
|------------|-------------|----------|-----------|------------|
| OAuth without DCR (GitHub) | Built-in GitHub login | Fails | Broker (kind A) | OpenCode outside cplt: nav-pilot must warn |
| OAuth with DCR (Figma) | Supported; tokens in `~/.copilot/mcp-oauth-config/` (SECURITY.md:75) | Supported; `opencode mcp auth` | Not hidden; the client does it | Browser hand-off from inside cplt |
| stdio vs HTTP | Both | Both | Under cplt, the broker turns a stdio server into an HTTP entry | Outside cplt the client spawns stdio itself |
| Tool filtering | `tools` list in the entry | Permission rules | Broker filters `tools/list` for brokered servers | Other servers rely on the client's filter |
| Config overlay | No env overlay known **(unverified)** | `OPENCODE_CONFIG_CONTENT` | cplt overlay | Copilot needs another mechanism before it can use the broker (Q2) |
| Fixed headers (`X-MCP-Readonly`) | Entry `headers` | Entry `headers` | Broker forces them | Outside cplt they are only as fixed as the config file |

What cannot be hidden: outside cplt there is no broker, so read-only and
tool limits are only as strong as the client config. `mcp list` should say
so (PATH `direct`).

### 2.7 Failure modes and recovery

| Failure | Detected by | User sees | Recovery |
|---------|-------------|-----------|----------|
| Login missing or expired | nav-pilot preflight; cplt at launch (kind A); broker on the first auth error (kind C) | `<server>: not logged in on the host. Fix: <loginCommand>` | Run it on the host. Kind A re-fetches the token on 401; whether a kind C child picks up a new login without restart is **(unverified)**, so the broker restarts it on an auth error |
| CLI missing | nav-pilot preflight; cplt (not in trusted dirs) | `nais is not installed. Fix: <install command from the registry>` | Install; restart the session |
| Old cplt (no broker, or no row) | nav-pilot compares `cplt --version` with `minCplt` | `cplt <v> cannot broker nais-mcp. Fix: brew upgrade cplt` | Upgrade. Until then the entry runs as configured and fails as today |
| Server down, upstream 5xx | Broker | JSON-RPC error with the upstream status; a proxy log line | Retry; nothing to fix locally |
| Child crashes in a loop | Broker restart budget | `nais-mcp stopped after 3 restarts; see the proxy log` | `--proxy-log-level all`; report upstream |
| Proxy off (`--no-proxy`) | cplt at launch | "goes through cplt's proxy, which is off: left as configured" (`src/opencode_v2.rs:324-326`) | Turn the proxy back on |

### 2.8 How others present MCP auth

| Product | How the user logs in | Where tokens live | Notes |
|---------|----------------------|-------------------|-------|
| Copilot CLI | Built-in GitHub MCP uses the CLI's login; other remote servers through OAuth | `~/.copilot/mcp-oauth-config/` (SECURITY.md:75) | Enterprise registry and allowlist control which servers ([docs](https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-mcp-usage/configure-mcp-registry)) |
| VS Code | Prompts when a server needs auth; uses its GitHub and Microsoft auth providers where they match, else DCR **(unverified)** | VS Code secret storage **(unverified)** | Closest to "just works" for GitHub |
| Claude Code | `/mcp`, pick the server, authenticate in the browser | macOS Keychain (SECURITY.md:1052-1058) | Local servers run unsandboxed ([docs](https://code.claude.com/docs/en/sandboxing)) |
| Docker MCP Toolkit | Desktop UI or `docker mcp oauth authorize <server>`; API keys via `docker mcp secret set` **(unverified)** | Docker's secret store | Gateway injects credentials into server containers ([docs](https://docs.docker.com/ai/mcp-gateway/)) |

The common pattern: log in once, outside the conversation, through a
command or UI the vendor owns, and keep tokens out of the model's reach.
Docker's gateway is closest to this design: credentials live with the
gateway, not the client.

## 3. Taxonomy of servers

Registry entries from navikt/copilot `apps/mcp-registry/allowlist.json`.

| Kind | Example | Where it runs today under cplt | Credential | Broker role |
|------|---------|-------------------------------|------------|-------------|
| A. Remote HTTP, host CLI token | GitHub (`api.githubcopilot.com/mcp`) | Agent connects out through the CONNECT proxy | `gh auth token` on the host | Reverse proxy that adds the token (what #807 does) |
| B. Remote HTTP, OAuth with DCR or CIMD | Figma (`mcp.figma.com/mcp`, `sandboxHosts: ["api.figma.com"]`) | Agent does OAuth itself; tokens land in OpenCode's data dir, inside the sandbox | OAuth tokens held by the client | Optional: broker as the OAuth client, see section 7 |
| C. Local stdio, host credentials | Nais (`nais alpha mcp serve`) | Child of the agent, inside the sandbox; fails without a keychain grant | Keychain item + encrypted file | Spawn on the host, bridge stdio to HTTP |
| D. Local stdio, no secrets | next-devtools, svelte, playwright, chrome-devtools | Child of the agent, inside the sandbox | None | **None.** Keep them in the sandbox |
| E. IDE localhost server | IntelliJ (`http://127.0.0.1:64342/sse`), Aksel Arcade (`127.0.0.1:3846`) | Agent connects to loopback, which needs the localhost opt-in | IDE-side, often none | Out of scope; see open question Q6 |
| F. Remote HTTP, no auth | Aksel, Astro docs, mcp-onboarding | Agent connects out through the CONNECT proxy | None | None |

The broker is for A, C, and maybe B. D and F gain nothing and would lose the
sandbox (D) or add a hop (F). E is a different problem: the IDE already runs
outside the sandbox and its tools are classed `host-exec` in the registry.

## 4. Prior art

| Project | What it does | What to take | Notes |
|---------|--------------|--------------|-------|
| [Docker MCP Gateway](https://docs.docker.com/ai/mcp-gateway/) ([source](https://github.com/docker/mcp-gateway)) | One gateway process; each server in its own container with restricted privileges, network and resources; starts servers on demand; injects secrets centrally; profiles choose which servers a client sees | Lazy start, one gateway for N servers, secrets injected at the gateway, per-server isolation | Per-tool filtering and interceptors not described on the overview page **(unverified)** |
| [Stacklok ToolHive](https://docs.stacklok.com/toolhive/) | Runs servers in containers behind a proxy that exposes HTTP; secrets manager; network filtering; tool name/description filtering in its gateway; authz policies ([reference](https://docs.stacklok.com/toolhive/reference/authz-policy-reference)) | Stdio servers fronted by HTTP, tool filtering at the proxy, a declarative policy file | Cedar as the policy language **(unverified)** |
| [mcp-proxy](https://github.com/sparfenyuk/mcp-proxy), [supergateway](https://github.com/supercorp-ai/supergateway) | Bridges stdio to SSE/streamable HTTP and back | The bridge is small: one child, JSON-RPC lines on stdin/stdout, sessions mapped to the child | Both bind a port with no auth by default **(unverified)**; cplt must not copy that |
| [Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing) | Sandbox covers shell commands only; "local MCP servers ... run with your full access" | Confirms the gap: a mainstream agent leaves MCP servers unsandboxed | |
| [GitHub Copilot MCP registry and allowlist](https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-mcp-usage/configure-mcp-registry) | Enterprise registry (v0.1 API) lists allowed servers; GitHub calls it "not the recommended method for restricting access" and points to `managed-settings.json` | The registry as the source of which servers exist, not as an enforcement point | Which clients enforce it is not stated on that page |
| [Copilot CLI](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/use-copilot-cli) | Built-in `github-mcp-server` remote; user servers in `~/.copilot/mcp-config.json` | cplt already grants its MCP commands (SECURITY.md:64) | Copilot keeps `GH_TOKEN` (SECURITY.md:25-28), so kind A matters less there |
| [MCP authorization spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | OAuth 2.1, protected resource metadata, DCR, and Client ID Metadata Documents (CIMD) | The broker can be the OAuth client for B | |
| [MCP security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices) | Token passthrough: servers "MUST NOT accept any tokens that were not explicitly issued for the MCP server". Confused deputy: proxies with a static client ID "MUST implement per-client consent". Local servers: "Execute MCP server commands in a sandboxed environment"; stdio proxies "SHOULD implement sandboxing ... for spawned processes" and must not expose spawn to a stolen proxy token | See sections 6-8 | |
| [OpenCode MCP config](https://opencode.ai/docs/mcp-servers/) | `type: local` (`command`, `environment`) or `type: remote` (`url`, `headers`, `oauth`, `oauth: false`), `enabled`, `timeout` | The overlay target: a broker entry is `type: remote`, `oauth: false`, URL on the proxy port | |

Is the broker "token passthrough"? No. The agent never holds the upstream
token; the broker accepts no client token and drops any `Authorization` the
client sends (`src/github_mcp.rs:225-244`). The broker is a local client of the
upstream acting with the user's identity, which is the pattern the spec
describes for MCP proxies. The confused-deputy rule bites only if the broker
runs an OAuth flow for many clients; here it has exactly one client per
session, behind a secret path (section 7).

## 5. Architecture options

### 5.1 The options

| | O1. Per-server modules (status quo) | O2. Generic declarative broker in cplt | O3. Separate daemon |
|---|---|---|---|
| Shape | One Rust module per server, like `github_mcp.rs` | One module, servers declared as data; kind A and C handlers | Long-lived host process (cplt-mcpd or ToolHive/Docker) shared across sessions |
| Adding server N | New module, tests, review | New declaration, review | New declaration, daemon config |
| Lifetime | cplt session | cplt session | Independent; outlives sessions |
| Secret path / port | Proxy port, one static endpoint (`src/github_mcp.rs:182-184`) | Proxy port, one path per server | Its own port or socket; needs a grant per session |
| Trust | Hard-coded | cplt-reviewed table, gated by user config | Daemon config |
| Cost | Grows linearly; each module re-solves header rules, logging, limits | One-time | New install, upgrade and crash story; Linux Landlock cannot pin a new port to loopback (`src/github_mcp.rs:7-9`) |
| Fit with G2 | Good | Good | Poor: users must install and run it |

O3 fails G2 and adds a port the sandbox must reach. Docker/ToolHive would
also need Docker or Podman on every laptop. O1 is fine for two servers and
wrong for ten. **O2 is the recommendation**, keeping O1's proven pieces.

### 5.2 Where trust comes from

Three inputs can name a server. They differ in who can write them.

| Source | Writable by agent? | May it enable a broker? |
|--------|-------------------|-------------------------|
| cplt's built-in server table (compiled in) | No | Defines what *can* be brokered: command, credential source, upstream, policy |
| User's OpenCode config dir, `OPENCODE_CONFIG_CONTENT` when it reaches the sandbox (`src/opencode_v2.rs:297-322`) | No (config dir is read-only in the sandbox, SECURITY.md:82) | Yes: an entry that matches a table row turns it on (G2) |
| User cplt config (`~/.config/cplt/config.toml`) | No | Yes: opt-out per server, and later opt-in to extra servers |
| Repo config (`opencode.json`, `.cplt.toml`, `.mcp.json`) | Yes | **Never.** Same rule as today (`src/github_mcp.rs:107-111`) |
| nav-pilot registry (`allowlist.json`) | No, but remote and mutable | Not at launch. Used at build or review time to generate or check the table |

Rule: **the command, credential source and upstream come only from cplt's
table.** User config only selects rows. That keeps a malicious or
prompt-injected config from making cplt spawn an arbitrary host command with
the user's credentials, which is the spec's "stdio proxy" escalation.

Why not read the registry at launch? It would make a network fetch part of
the trust chain and let a registry edit change what runs unsandboxed on every
laptop, with no cplt release. The registry stays the catalogue and approval
record; cplt's table is the enforcement copy. A CI check in navikt/copilot can
flag registry entries of kind A or C that cplt's table lacks.

A user-declared server (`[[mcp_broker.servers]]` in cplt config) is a
possible later phase. It would be "user runs this command on the host
anyway", so no worse than running the server outside cplt, but it moves an
unsandboxed process under cplt's name. Defer it (Q3).

### 5.3 How a server is declared

A table row (Rust data, not a config file in phase 1):

```text
id:          nais
match:       local entry whose command is [nais, alpha, mcp, serve, ...]
             (or registry name io.github.nais/nais-mcp as the entry key)
kind:        stdio
command:     nais alpha mcp serve        # resolved from trusted dirs only
args_policy: fixed; user args --team/--environment passed if on an allowlist
env:         cleared, then HOME, PATH(trusted), LANG, XDG_*; nothing from the agent
credential:  ambient (the binary reads its own keychain item on the host)
policy:      tools allow = registry read tools; execute_graphql gated (6.2)
limits:      body 4 MiB, 1 child, idle timeout, restart budget
opt_out:     sandbox.mcp_broker.nais = false / --no-mcp-broker nais
```

```text
id:          github
match:       remote url api.githubcopilot.com/mcp or /mcp/readonly (src/github_mcp.rs:39-48)
kind:        http
upstream:    https://api.githubcopilot.com/mcp/readonly   # pinned (src/github_mcp.rs:34)
credential:  gh auth token (src/discover.rs:155)
headers:     force X-MCP-Readonly: true, X-MCP-Lockdown: true; pass X-MCP-Toolsets
opt_out:     sandbox.github_mcp_proxy = false / --no-github-mcp-proxy  (kept)
```

### 5.4 Transport and endpoint

Keep #807's choice: streamable HTTP on the existing CONNECT proxy port, at
`http://127.0.0.1:<port>/<128-bit secret>`, one secret per server per
session. Reasons, all already measured in #807:

- No new sandbox rule. On Linux a Landlock port rule cannot be limited to
  loopback (`src/github_mcp.rs:7-9`, SECURITY.md:40).
- The proxy's head size cap, head deadline and 64-connection limit apply
  (`src/proxy.rs:87`, `src/proxy.rs:1163-1187`, `src/proxy.rs:1226`).
- OpenCode remote entries take a plain URL (`oauth: false`).

Change needed: `endpoint_for` (`src/github_mcp.rs:210-220`) becomes a lookup
over a small map of `secret -> server`, still constant time per comparison.
Dispatch stays at `src/proxy.rs:1205`.

The worktree broker's per-session Unix socket (`src/worktree_broker.rs:1-20`)
is the other precedent. It is better isolation, but OpenCode cannot point a
remote MCP entry at a Unix socket **(unverified)**, so it does not fit here.

### 5.5 The stdio bridge

Streamable HTTP to one stdio child:

1. `POST` with a JSON-RPC message or batch: write it to the child's stdin as
   one line. For requests, read stdout until the matching `id`(s) answer and
   return `application/json` (or `text/event-stream` if the child sends
   progress or server requests first).
2. Notifications and responses from the client: write, return `202`.
3. `GET` (standalone SSE stream): return `405`, as GitHub does and the spec
   allows; server-initiated messages that arrive outside a request are
   buffered to the next response or dropped with a log line. Revisit if a
   server needs sampling or elicitation.
4. `DELETE`: end the MCP session; the child stays for the next one.
5. `Mcp-Session-Id`: the broker issues its own random ID on `initialize`; one
   live session per child. A second `initialize` restarts the child (OpenCode
   reconnects this way **(unverified)**).

A demultiplexer thread owns stdout and routes by `id`. Child stderr goes to
the proxy log, bounded and redacted, like curl's (`src/github_mcp.rs:403-411`).

Alternative for Nais: `nais alpha mcp serve --transport http --listen
127.0.0.1:<port>` (checked with `nais alpha mcp serve --help`, Nais CLI
7.0.1). The broker would reverse-proxy to it like kind A. It saves the bridge
but adds an unauthenticated loopback listener that any local process can
call, and the default `--listen :8080` binds all interfaces. Use stdio.

### 5.6 Lifecycle

| Aspect | Proposal |
|--------|----------|
| Detection | At launch, as today (`src/main.rs:4749-4761`): scan user config, match table rows, check preconditions (proxy on, binary in trusted dirs, credential present). Missing login: one warning line naming the fix, entry left alone (`src/opencode_v2.rs:323-331`) |
| Spawn | Lazy, on the first request to that server's path. Keeps launch fast and costs nothing for unused servers |
| Concurrency | One child per server per session. Requests serialised per JSON-RPC id, not per HTTP connection; several in flight |
| Timeouts | Per-request deadline (default 120 s, per-row override); idle child killed after 10 min and respawned lazily |
| Restart | On child exit, the next request respawns; at most 3 restarts per minute, then 503 with a log line |
| Shutdown | Children are in cplt's process group and are killed on session exit, like the curl children (`src/github_mcp.rs:420-421`) |
| Kind A | One curl per request, as today. A persistent upstream connection is a later optimisation |

## 6. Policy at the broker

The broker is outside the sandbox, so its policy is the only boundary left
for the server's actions. Policy in the agent (OpenCode permission rules
written by nav-pilot) is advisory: the agent controls the client.

### 6.1 Tool allow and deny

The registry classes each tool: unlisted is `read`, else `write`,
`external` or `host-exec` (navikt/copilot
`cli/nav-pilot/internal/provider/mcp_tools.go:21-28`). `nav-pilot mcp enable`
turns on read and write and asks for the rest
(`cli/nav-pilot/internal/cli/mcp_tools.go:17-18`).

At the broker:

- **`tools/list`**: filter the response to allowed tools, so the agent never
  sees the rest.
- **`tools/call`**: refuse a tool not on the list with a JSON-RPC error. Do
  not rely on the filtered list; the agent can call any name.
- Default allow set for a brokered server: `read` only. `write` and
  `external` need a per-server user opt-in in cplt config. `host-exec` is
  never brokered.
- Unknown tools (a server update adds one) are denied until the table
  classifies them. This fails closed and costs a cplt release per new tool;
  see Q4.

GitHub today filters nothing at the broker and relies on upstream
`/readonly` + `X-MCP-Readonly`, which is stronger than any filter cplt could
write. Keep that and add the filter only where no upstream mode exists.

### 6.2 Read-only mode and the GraphQL mutation problem

Nais exposes `execute_graphql`. It is the one tool that matters. Options:

| Option | Strength | Cost |
|--------|----------|------|
| a. Rely on nais's own check | nais parses the query against the schema and refuses a first operation that is not a query, plus secret-related fields and over-deep queries ([graphql.go](https://github.com/nais/cli/blob/44c28bca52f3d9e21e1174b1ae0d6727620d2832/internal/mcp/tools/graphql.go#L296-L330), [L499-L506](https://github.com/nais/cli/blob/44c28bca52f3d9e21e1174b1ae0d6727620d2832/internal/mcp/tools/graphql.go#L499-L506)). MCP.md says "All operations are read-only" | Only the **first** operation is checked. The request sent has no `operationName` ([L335-L338](https://github.com/nais/cli/blob/44c28bca52f3d9e21e1174b1ae0d6727620d2832/internal/mcp/tools/graphql.go#L335-L338)), so a spec-compliant server should reject a multi-operation document; whether the Nais API does is **(unverified)** |
| b. Broker parses the operation | Defence in depth: refuse any document that contains `mutation` or `subscription` operations, or more than one operation | Needs a GraphQL lexer in cplt (no crate today); a lexer-level check for operation keywords outside strings and comments is about 100 lines |
| c. Upstream read-only credential | Strongest: a token or role that cannot mutate | Not offered by Nais today **(unverified)**; would need nais/cli or Nais API work |
| d. Deny `execute_graphql` | Trivially safe | Removes most of the server's value |

Recommendation: a + b now, ask Nais for c. b closes the multi-operation gap
regardless of server behaviour. There is no `--read-only` flag in
`nais alpha mcp serve --help` (7.0.1).

General rule for the table: a row may mark a tool `arg_check = graphql_query`
(or a future kind). Argument checks are named, reviewed functions, not a
pattern language.

### 6.3 Limits of argument inspection

Argument inspection only works where the argument has a grammar the broker
fully understands (GraphQL operation type, a fixed enum). It does not work
for free text, URLs fetched by the server, file paths on the host, or
anything the server interprets later. Do not promise more. When a tool's
safety depends on unparseable input, the answer is deny or an upstream mode.

### 6.4 Audit logging

One line per JSON-RPC call in the proxy log and `--proxy-log`, extending the
`[github-mcp]` format (`src/github_mcp.rs:148-171`):
`[mcp:<id>] <time> tools/call <tool> → ALLOWED|DENIED <reason>|FAIL <code>`.
Log method and tool name, never arguments or results (they can carry data
and secrets). Escape every agent-supplied string (`escape_debug`, as now).
Redact the token from child stderr and curl stderr (`src/github_mcp.rs:434-437`).

### 6.5 Rate and size limits

- Body cap 4 MiB, chunked requests refused, only GET, POST and DELETE
  (`src/github_mcp.rs:329-363`); keep for all servers.
- Response cap per call (default 16 MiB) to protect the agent's context and
  memory.
- Calls per minute per server; nais already has `--rate-limit` (default 25),
  so pass it and add a broker cap for servers without one.

### 6.6 Prompt-injection exposure

The broker does not reduce prompt injection: tool results (issue bodies,
Nais resource descriptions) reach the model unchanged. It limits the blast
radius: a hijacked agent gets read-only tools, not the token. Adding a
brokered server widens what an injected agent can read, and with the user's
identity. Read-only defaults matter for that reason. No content filtering is
proposed.

## 7. Credentials

| Source | Kind | How the broker gets it | Stays on host? |
|--------|------|------------------------|----------------|
| `gh auth token` | A | Existing trusted lookup, 5 s timeout, token in `SecretToken` (SECURITY.md:36, `src/discover.rs:155`) | Yes on this channel. But the agent can already get the gh token through the exec token and `OPENCODE_AUTH_CONTENT` (SECURITY.md:32-38); #731 tracks a narrower token |
| Keychain + file (nais) | C | Ambient: the child runs on the host and reads its own item; cplt never reads it | Yes |
| Linux Secret Service | C | Same, ambient, via the host's D-Bus session. Where nais stores it on Linux is **(unverified)** | Yes |
| Env-var API keys | A or C | Read from the host env at launch, passed to the child or header, never to the sandbox | Yes |
| OAuth tokens (Figma) | B | See below | Yes, if the broker is the client |

Refresh: kind C refreshes itself (the child owns its login). Kind A gets
the token once per session today; a long session can outlive it. Proposal:
on an upstream `401`, re-run the lookup once and retry.

**OAuth for kind B.** Today OpenCode does Figma's OAuth inside the sandbox
and stores the tokens where the agent can read them. The broker could be the
OAuth client instead: discover protected resource metadata, register with
DCR or present a CIMD client ID, open the browser on the host (cplt is
outside the sandbox and needs no `--allow-browser`), receive the code on a
loopback redirect, and keep the tokens in the host keychain. The agent then
sees only the secret-path endpoint.

That is a real OAuth client in cplt: PKCE, state, loopback listener, token
store, refresh. The confused-deputy MUSTs apply only to proxies that accept
dynamic registration from many clients; the broker has one client and no
registration endpoint, so it does not apply. It is worth doing only if
OAuth tokens in OpenCode's data dir are judged a problem. Defer (Q5).

## 8. Threat model

Attacker: the sandboxed agent, or content that steers it. Assets: host
credentials, host code execution, the user's identity at upstream services.

| Threat | Today (#807) | With the broker | Mitigation |
|--------|--------------|-----------------|------------|
| Agent reads the secret path | It can: the URL is in `OPENCODE_CONFIG_CONTENT`, in its env | Same | Accepted. The secret only stops *other* local processes and non-sandbox users from using the endpoint. The agent is the intended client |
| Secret leaks out (logs, transcript, a commit) | Valid only for the session and only on loopback | Same | Per-session secret, loopback bind; never logged (logs show the server id, not the path) |
| Guessing the path | 128 bits, constant-time compare (`src/github_mcp.rs:208-220`) | Same, per server | |
| SSRF via the broker | Upstream pinned; redirects off; https only (`src/github_mcp.rs:34`, `:377-391`) | Same for kind A. Kind C children make their own requests; the broker cannot see them | No client-controlled URL ever. A child's own egress is bounded only by its sandbox (next row) |
| Malicious repo config enabling a server | Repo config ignored | Same | Section 5.2: only user config selects, only cplt's table defines |
| Host-exec through the server process | n/a (curl only) | **New.** The stdio child runs on the host, unsandboxed. A bug in it, or a tool that reads files or runs commands, is a host escape | Spawn the child in its own narrow sandbox profile (below) |
| Header injection | Control bytes refused, auth and `X-MCP-*` stripped (`src/github_mcp.rs:225-250`) | Same code for kind A; kind C has no upstream headers | Reuse the functions |
| JSON-RPC smuggling (batch with a denied call, duplicate ids) | n/a | New | Parse every message; deny the whole batch if any member is denied; broker owns id mapping |
| DoS | 64 connections, head cap, 4 MiB body (`src/proxy.rs:87`) | Plus child restarts and slow calls | Restart budget, per-call deadline, response cap, rate limit. A DoS only hurts the agent's own session |
| Credential theft by reading the child | n/a | The child runs as the same UID outside the sandbox; the agent cannot reach its memory or files because the sandbox blocks them | Child sandbox must deny the agent's writable roots as *exec* sources: the child never runs a binary the agent could have written |

**A narrower sandbox for the child.** Moving nais out of the agent's sandbox
trades "keychain readable by the agent" for "nais unsandboxed". The second
is much better, since the agent controls only tool arguments, not code, but
still more than needed. The broker should spawn the child under a dedicated
profile from the existing profile generators (`src/sandbox_profile.rs:55`
and the Landlock/bwrap backends):

- read: its binary, its config dir (`~/Library/Application Support/nais`),
  system libraries; on macOS the keychain file rules and securityd lookup
  (needed for the credential), which is acceptable because the child is
  trusted code, not the agent;
- write: its own log or cache dir only; no project, no home;
- network: through cplt's CONNECT proxy, allowlisted to the row's hosts;
- no exec of anything outside trusted dirs.

Whether `nais` runs under such a profile (Go binary, keychain via
Security.framework) is **(unverified)**; phase 2 must measure it. If it does
not, ship unsandboxed with the residual documented in SECURITY.md, as the
status of every other host-side helper.

## 9. Migration of `github_mcp.rs`

`github_mcp.rs` becomes the first kind-A row. Nothing user-visible changes.

1. Move the static single endpoint (`src/github_mcp.rs:182-206`) to a
   registry of endpoints keyed by secret; `endpoint_for` looks up all.
2. Split the module: transport pieces (head parsing, header rules, curl
   config, relay, log) into `mcp_broker/http.rs`; GitHub-specific constants
   (`UPSTREAM`, URL match, forced headers) into the row.
3. Generalise `opencode_v2::github_mcp` (`src/opencode_v2.rs:297-350`) to
   loop over rows. It already merges one `OPENCODE_CONFIG_CONTENT` overlay;
   rows share it.
4. Config: keep `sandbox.github_mcp_proxy` and `--[no-]github-mcp-proxy`
   (`src/config/registry.rs:242-246`, `:978-982`) as the GitHub row's toggle,
   forever. New rows use `sandbox.mcp_broker.<id>` and
   `--no-mcp-broker <id>`. A global `sandbox.mcp_broker = false` turns all
   off. Explicit `sandbox.github_mcp_proxy` wins over the global key for
   GitHub, so nobody's setting changes meaning.
5. Log prefix stays `[github-mcp]` for GitHub; new rows use `[mcp:<id>]`.
6. The existing seam test (`src/proxy.rs:4193`) and off-path test
   (`src/opencode_v2.rs:1068`) must pass unchanged; that is the refactor's
   acceptance test.

## 10. Recommendation

Build O2: a declarative broker inside cplt, servers defined by a compiled-in
table, enabled by the user's own client config, served on the proxy port
behind a secret path per server.

| Phase | Scope | Exit |
|-------|-------|------|
| 1 | Refactor `github_mcp.rs` into the broker with one kind-A row; multi-endpoint lookup; no behaviour change | #807's tests pass unchanged; e2e on macOS |
| 2 | Kind C stdio bridge; Nais row (#821) with read-only tool allow list, GraphQL operation check, lazy spawn, restart budget; measure the child sandbox | Nais works under cplt with no keychain grant, mutation and multi-op documents refused at the broker, macOS and Linux e2e |
| 2b (navikt/copilot, alongside 2) | Registry `auth` fields; `nav-pilot mcp enable` supports Nais, runs login preflight; `mcp list` LOGIN and PATH columns via `cplt mcp status --json` | Section 2.2 journey works end to end for Nais in OpenCode |
| 3 | Tool filtering for all rows from registry classes; audit lines; response cap and rate limit | |
| 4 | Child sandbox profile on by default, if phase 2's measurement allows | |
| 5 (optional) | Broker as OAuth client for kind B (Figma); user-declared rows | Owner decision |

Copilot CLI and other agents: same broker, new overlay writers. Not in
scope until an agent needs it (Q2).

### Open questions for the owner

- **Q1.** Is unsandboxed `nais` on the host acceptable for phase 2, with the
  child sandbox in phase 4? Or must the child sandbox ship with Nais?
- **Q2.** Should Copilot CLI and other agents use the broker too (for
  example, the read-only GitHub guarantee for Copilot, #797's third
  question), or stay OpenCode-only for now?
- **Q3.** Should users be able to declare their own brokered servers in cplt
  config, or only cplt's reviewed table?
- **Q4.** Unknown tools after a server update: deny until cplt is released
  (safe, slower), or allow `read` by default (convenient)?
- **Q5.** Is Figma's OAuth token sitting in OpenCode's data dir a problem
  worth a broker OAuth client?
- **Q6.** IDE localhost servers (IntelliJ, Aksel Arcade): out of scope for
  the broker, agreed?
- **Q7.** May `write`-class tools be opted in per server in cplt config, or
  is the broker read-only by policy?
- **Q8.** Should the table be generated from the registry in CI, or kept by
  hand with a registry consistency check?
- **Q9.** May `nav-pilot mcp enable` run the login command (`nais login -n`,
  `gh auth login`) itself after a yes, or only print it?
- **Q10.** Should brokered servers turn `write` tools off by default, even
  though `nav-pilot mcp enable` turns them on for other servers?

### Issues to file

- navikt/cplt: phase 1 refactor (github_mcp into broker, no behaviour change).
- navikt/cplt: phase 2 stdio bridge and Nais row, superseding the plan in #821.
- navikt/cplt: child sandbox profile for brokered servers (measure nais first).
- navikt/cplt: re-fetch the gh token on upstream 401.
- nais/cli: check every operation, not only the first, in `execute_graphql`; ask for a read-only credential or `--read-only` mode.
- navikt/copilot: `nav-pilot mcp list` LOGIN and PATH columns, login preflight at enable, `cplt mcp status --json` consumer.
- navikt/cplt: `cplt mcp status --json` for nav-pilot and doctor.
- navikt/copilot: registry metadata (`auth.kind`, `auth.loginCommand`, `auth.statusCommand`, `minCplt`) for broker kinds (credential source) and a CI check against cplt's table; update the nais `setupInstructions` once phase 2 ships.
