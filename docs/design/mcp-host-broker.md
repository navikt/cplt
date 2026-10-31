# Design: a generic MCP host broker

Status: phases 1 and 1b shipped, plus the child sandbox on macOS (#862) and
Linux (#873). Section 11 lists what shipped.
Roadmap: [#912](https://github.com/navikt/cplt/issues/912). Revised
2026-10-23 with the owner's decisions (section 0), updated 2026-10-28. Where this text and the code differ, the code
and [SECURITY.md](../../SECURITY.md) describe what ships.
Refs [#821](https://github.com/navikt/cplt/issues/821), [#807](https://github.com/navikt/cplt/pull/807), [#797](https://github.com/navikt/cplt/issues/797), [#820](https://github.com/navikt/cplt/issues/820).

Code citations are against `origin/main` at the time of writing. Claims
marked **(unverified)** were not checked against source or by running them.

## 0. Decisions (owner, 2026-10-23)

| # | Topic | Decision |
|---|-------|----------|
| D1 | Boundary | cplt stays generic and knows nothing about Nav's registry. It owns a broker spec schema, hard invariants, credential resolution, enforcement, the runtime and `cplt mcp status --json`. nav-pilot, the trusted launcher outside the sandbox, owns the registry, consent, per-client config and the host login UX. It turns registry entries into specs and hands them to cplt through a stable interface (section 5) |
| D2 | Invariants | Credential never enters the sandbox; pinned upstream or command; read-only by default; `host-exec` never brokered. cplt rejects a spec that breaks one |
| D3 | Compiled-in knowledge | cplt keeps a hand-kept table of **credential mechanisms** only (gh token; nais keychain via `nais alpha mcp serve`). Tool policy is never compiled in |
| D4 | Spec format | Built from standard MCP `server.json` fields; only what the spec lacks goes in a namespaced `_meta` extension (section 5.2). Any spec-compliant registry could feed cplt |
| D5 | Clients | All, from phase 1: Copilot CLI (`--disable-mcp-server` + `--additional-mcp-config`), OpenCode (`OPENCODE_CONFIG_CONTENT`). pi is out of scope (owner, 2026-10-28) |
| D6 | Local transport | stdio over a per-session Unix socket. Client entry: `command: cplt mcp-stdio <id>`, piped to the host child, after `src/worktree_broker.rs`. macOS first; Linux needs a bwrap bind (later). Remote kind (GitHub) keeps the HTTP proxy path |
| D7 | Host child | Sandboxed since #849: on macOS by Seatbelt, on Linux by bwrap with its own network namespace (TCP only to its egress proxy, writes only to its temp and config dirs). Phase 1 was unsandboxed, env cleared, egress pinned with `HTTPS_PROXY` to cplt's CONNECT proxy, allowed to the spec's hosts only. Both grant writes to nais's config dir (refresh rewrites it); macOS the login keychain file, Linux the D-Bus session socket (go-keyring) |
| D8 | Tools | Read-only by default. Writes opted in per server with `nav-pilot mcp enable --tools`, written to the user's cplt config. New or unclassified tools refused until re-consent. Write tools off by default for brokered servers. Enforced at spec load: a tool in `tools.allow` that `tools.classes` marks `write` or `external` is refused unless the spec sets `writeConsent` (`src/mcp_broker/spec.rs`) |
| D9 | GraphQL | Broker refuses a `mutation` or `subscription` keyword, or more than one operation, with a simple check. File the nais/cli fix first (it checks only `Operations[0]`) |
| D10 | Login | nav-pilot runs `nais login -n` / `gh auth login` on the host after a yes; with `--json` or no tty it only prints the command. Nais status: `nais auth print-access-token` |
| D11 | Without cplt | `mcp list` PATH `direct` says "no read-only guarantee"; nav-pilot warns or refuses on enabling `execute_graphql` outside cplt. A gh login mid-session needs a restart; the error says so. The kind A part may change once #820 lands (section 8) |
| D12 | Errors | Broker DENIED and auth errors are mirrored to cplt's launch output or proxy log, not only to the agent |
| D13 | DoS | Cap in-flight requests per child. `notifications/tools/list_changed` is not delivered; documented |
| D14 | Out of scope | IDE servers. Figma OAuth is a later phase. No user-declared rows |
| D15 | Phasing | Phase 1 = Nais (#821) in all clients, read allowlist, egress pin; extract shared pieces only as needed. GitHub moves to the shared model when a third server arrives. Then the child sandbox, then Figma OAuth |

These replace the earlier open questions Q1-Q10; section 12 keeps only
what is still open.

## 1. Problem and goals

cplt keeps credentials out of the agent. MCP servers need credentials.
Today that fails three ways:

- **The server cannot log in.** GitHub's remote MCP has OAuth without
  dynamic client registration, so OpenCode cannot get a token (#797).
- **The server needs a grant cplt will not give.** `nais alpha mcp serve`
  runs as a child of the agent, inside the sandbox, and needs the macOS
  login keychain plus `~/Library/Application Support/nais/nais-credentials.json.enc`.
  Granting `~/Library/Keychains` exposes every silently readable item
  (SECURITY.md:924-945).
- **The token is handed to the agent** with `--pass-env`, which cplt is
  trying to stop.

#807 fixed GitHub with a one-off module, `src/github_mcp.rs`. #821 needs
Nais, and more servers will follow.

| # | Goal | Test |
|---|------|------|
| G1 | Credentials never enter the sandbox | No token, keychain or credential-file grant; the agent sees an MCP endpoint, not a secret |
| G2 | Just works | After `nav-pilot mcp enable <name>` and a host login, no cplt config is needed |
| G3 | Scales to N servers | A new server is a registry entry plus, at most, a credential mechanism in cplt |
| G4 | No break for existing users | `sandbox.github_mcp_proxy` and `--no-github-mcp-proxy` keep working |
| G5 | Policy holds against a hostile agent | Read-only and tool limits are enforced outside the sandbox |

Non-goals: a gateway for other machines, multi-user serving, replacing
the client's own permission prompts.

## 2. User experience

Clients: Copilot CLI and OpenCode (the `nav-pilot mcp enable --client`
targets, navikt/copilot `cli/nav-pilot/internal/cli/mcp_cmd.go:135-137`),
pi is out of scope (D5). Claude Code and VS Code appear as comparisons.

### 2.1 Today's journeys

| Server | Client | What the user does | Where it breaks | What they see |
|--------|--------|--------------------|-----------------|---------------|
| GitHub | OpenCode, no cplt | `nav-pilot mcp enable io.github.navikt/github-mcp --client opencode` | OpenCode tries OAuth; GitHub has no DCR | `Incompatible auth server: does not support dynamic client registration` (#797) |
| GitHub | OpenCode, cplt before #807 | Same | `GH_TOKEN` is stripped too | `needs authentication` (#807 e2e) |
| GitHub | OpenCode, cplt with #807 | Same | Works after `gh auth login` on the host | Otherwise: "GitHub MCP in OpenCode needs your gh login: run `gh auth login`." (`src/opencode_v2.rs:330`) |
| GitHub | Copilot CLI | Nothing; built in | Works; Copilot holds the token | Nothing |
| Figma | OpenCode | `nav-pilot mcp enable com.figma/figma-mcp`, then `opencode mcp auth` | Strict mode needs `api.figma.com`; the browser hand-off needs `--allow-browser` or a copied URL | nav-pilot host consent (navikt/copilot#1272), then client OAuth errors. No Slack summary was found in the issues, so no Figma error is quoted |
| Nais | any | `nais login -n`, then a hand-written stdio entry (`nav-pilot mcp enable` does not support it) | Under cplt the server is sandboxed and cannot read the keychain | Every call fails: `unauthenticated: please log in with nais login -n` (#821), though the user is logged in |
| Stdio, no secrets | any | `nav-pilot mcp enable <name>` | Missing runtime or a cache rule | `mcp list` problem plus fix (`mcp_cmd.go:489-498`) |

### 2.2 Target journey

```text
$ nav-pilot mcp enable io.github.nais/nais-mcp
  Nais MCP: 12 read-only tools. Login: nais (not logged in).
  Run `nais login -n` now? [Y/n]
  ...browser opens on the host...
  Enabled for opencode and copilot. Under cplt it runs on the host, read-only.
```

1. Login happens on the host, once, run by nav-pilot after a yes (D10).
   The agent is never asked to log in.
2. The user's client config is the same with or without cplt. cplt
   overlays it at launch; the file never holds a cplt path or a token.
3. Tool set, read-only state and error text depend on the spec, not the
   client.
4. No cplt config to write by hand. nav-pilot writes the spec (section 5).

### 2.3 Who owns what

| Owner | Owns | Does not own |
|-------|------|--------------|
| Registry (any spec-compliant MCP Registry) | `server.json` plus the `_meta` extension: identity, transport, upstream, tools, risk classes, hosts, credential mechanism, login and status commands | Anything that runs |
| nav-pilot | Fetching the registry, consent, client config, preflight, host login, writing the broker spec into the user's cplt config, `mcp list` | Tokens; runtime enforcement |
| cplt | Spec schema and validation, invariants, credential mechanisms, broker runtime, policy enforcement, client overlays at launch, `cplt mcp status --json` | Registry knowledge; consent UI |
| Client | Connecting, showing tools, per-call prompts | Credentials for brokered servers |

The registry declares, nav-pilot asks, cplt enforces. navikt/copilot#1272
chose the same chain for egress.

### 2.4 Status and diagnostics

`nav-pilot mcp list` already prints a problem and a `Fix:` line per server
(`mcp_cmd.go:139-145`, `:249`). Target:

```text
SERVER        CLIENTS            LOGIN            PATH                              TOOLS
github-mcp    opencode, copilot  gh: ok           cplt broker                       10 read
nais-mcp      opencode, copilot  nais: expired    cplt broker                       12 read
figma-mcp     opencode           oauth: client    direct (no read-only guarantee)   4 read, 10 off
playwright    copilot            none             sandbox                           13 read/write, 3 off

  nais-mcp: login expired.  Fix: nais login -n
```

LOGIN runs the spec's status command (`gh auth status`, `nais auth
print-access-token`, output discarded). PATH comes from `cplt mcp status
--json` (section 5.5). `cplt doctor` shows the same rows.

Every error is "what is wrong. Fix: exact command", in nav-pilot, at cplt
launch, in the proxy log and in the broker's JSON-RPC errors (D12).

### 2.5 Consent and visibility

- **At enable, once per server:** risk classes and what is on. Brokered
  servers get read tools only (D8); writes need `--tools`. `external` asks;
  `host-exec` is never brokered.
- **At launch:** one line per brokered server on the first launch after a
  change, and a line when one is skipped (no login, proxy off).
- **In session:** only the client's prompts. The broker refuses with an
  error the agent sees and cplt logs.
- **Changes:** a registry update that adds a tool or raises its class
  leaves it refused until the user re-runs `enable` (D8; nav-pilot already
  narrows approvals, `cli/nav-pilot/internal/provider/mcp_servers.go:130`).

### 2.6 Client differences

| Difference | Copilot CLI | OpenCode | pi | Hidden by |
|------------|-------------|----------|----|-----------|
| Launch overlay | `--disable-mcp-server <name>` (removes the user's entry for the session) plus `--additional-mcp-config <json\|@file>` (adds the brokered one); both in `copilot --help` (1.0.x) | `OPENCODE_CONFIG_CONTENT`, deep-merged (`src/github_mcp.rs:75-99`) | **(unverified)** | cplt |
| OAuth without DCR (GitHub) | Built-in GitHub login | Fails | n/a | Broker, remote kind |
| OAuth with DCR (Figma) | Client does it; tokens in `~/.copilot/mcp-oauth-config/` (SECURITY.md:75) | `opencode mcp auth` | n/a | Not hidden until the Figma phase |
| Local server | `command` + `args` | `command` array | **(unverified)** | Both get `cplt mcp-stdio <id>` |
| Tool filtering | `tools` list | Permission rules | | Broker filters `tools/list` |

What cannot be hidden: without cplt there is no broker, so limits are only
as strong as the client config (D11).

### 2.7 Failure modes and recovery

| Failure | Detected by | User sees | Recovery |
|---------|-------------|-----------|----------|
| Login missing or expired | nav-pilot preflight; cplt at launch; broker on an auth error | `<server>: not logged in on the host. Fix: <login command>` | Run it on the host. Kind C: broker restarts the child on the next call. GitHub: the token is read at launch, so "restart the session" is part of the message (D11) |
| CLI missing | nav-pilot preflight; cplt (binary not in trusted dirs) | `nais is not installed. Fix: <install hint from the spec>` | Install, restart |
| Old cplt | nav-pilot compares `cplt mcp status --json`'s `schema` with what it writes | `cplt <v> cannot read broker spec v<n>. Fix: brew upgrade cplt` | Upgrade; until then nav-pilot does not write the spec |
| Server down | Broker | JSON-RPC error with the upstream status; proxy log line | Retry |
| Child crash loop | Restart budget | `nais-mcp stopped after 3 restarts; see the proxy log` | `--proxy-log-level all` |
| Proxy off | cplt at launch | "goes through cplt's proxy, which is off: left as configured" (`src/opencode_v2.rs:324-326`) | Turn the proxy on |

### 2.8 How others present MCP auth

| Product | How the user logs in | Where tokens live | Notes |
|---------|----------------------|-------------------|-------|
| Copilot CLI | Built-in GitHub MCP uses the CLI login; other remotes via OAuth | `~/.copilot/mcp-oauth-config/` (SECURITY.md:75) | Enterprise registry allowlist ([docs](https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-mcp-usage/configure-mcp-registry)) |
| VS Code | Prompt on auth; its GitHub and Microsoft providers where they match, else DCR **(unverified)** | Secret storage **(unverified)** | Closest to "just works" for GitHub |
| Claude Code | `/mcp`, authenticate in the browser | macOS Keychain (SECURITY.md:1052-1058) | Local servers run unsandboxed ([docs](https://code.claude.com/docs/en/sandboxing)) |
| Docker MCP Toolkit | Desktop UI or `docker mcp oauth authorize`; `docker mcp secret set` **(unverified)** | Docker's secret store | Gateway injects credentials ([docs](https://docs.docker.com/ai/mcp-gateway/)) |

Common pattern: log in once, outside the conversation, through the
vendor's command or UI; keep tokens out of the model's reach.

## 3. Taxonomy of servers

| Kind | Example | Today under cplt | Credential | Broker role |
|------|---------|------------------|------------|-------------|
| A. Remote HTTP, host CLI token | GitHub | Through the CONNECT proxy | `gh auth token` | HTTP reverse proxy that adds the token (#807) |
| B. Remote HTTP, OAuth (DCR/CIMD) | Figma | Client does OAuth inside the sandbox | Client-held tokens | Later phase (D14) |
| C. Local stdio, host credentials | Nais | Child of the agent, sandboxed; fails | Keychain + file | Host child behind `cplt mcp-stdio` (D6) |
| D. Local stdio, no secrets | Playwright, next-devtools | Child of the agent, sandboxed | None | None; stays sandboxed |
| E. IDE localhost | IntelliJ, Aksel Arcade | Loopback opt-in | IDE-side | Out of scope (D14) |
| F. Remote, no auth | Aksel, Astro docs | Through the CONNECT proxy | None | None |

## 4. Prior art

| Project | What it does | What to take |
|---------|--------------|--------------|
| [Docker MCP Gateway](https://docs.docker.com/ai/mcp-gateway/) ([source](https://github.com/docker/mcp-gateway)) | One gateway; each server in a restricted container; started on demand; secrets injected centrally | Lazy start, credentials at the gateway, per-server isolation |
| [Stacklok ToolHive](https://docs.stacklok.com/toolhive/) | Servers in containers behind an HTTP proxy; secrets; network filtering; tool filtering; [authz policies](https://docs.stacklok.com/toolhive/reference/authz-policy-reference) | Tool filtering at the proxy; declarative policy |
| [mcp-proxy](https://github.com/sparfenyuk/mcp-proxy), [supergateway](https://github.com/supercorp-ai/supergateway) | stdio to HTTP bridges | Confirms the bridge is small. Their unauthenticated ports **(unverified)** are what the Unix socket avoids |
| [Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing) | Sandbox covers shell only; local MCP servers "run with your full access" | The gap is common |
| [GitHub Copilot MCP registry](https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-mcp-usage/configure-mcp-registry) | v0.1 registry lists allowed servers; GitHub says it is not the recommended restriction | Registry as catalogue, not enforcement |
| [MCP server.json schema](https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json) | Standard server description: `packages[]`, `remotes[]`, `_meta` | Base of the broker spec (D4) |
| [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | OAuth 2.1, DCR, CIMD | For the Figma phase |
| [MCP security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices) | No token passthrough ("MUST NOT accept any tokens that were not explicitly issued for the MCP server"); per-client consent for OAuth proxies; sandbox spawned stdio servers; stdio proxies must not let a stolen proxy token spawn commands | Sections 6-8 |
| [OpenCode MCP config](https://opencode.ai/docs/mcp-servers/) | `local` (`command`, `environment`) or `remote` (`url`, `headers`, `oauth`) | Overlay target |

The broker is not token passthrough: the agent never holds the upstream
token and any client `Authorization` is dropped (`src/github_mcp.rs:225-244`).
The spec's "proxy spawns arbitrary commands" risk does not apply: the
command comes from a spec the agent cannot write, and the socket only
selects an already declared id.

## 5. Architecture

### 5.1 Options considered

| | O1. Per-server modules (status quo) | O2. Generic broker in cplt, specs from nav-pilot | O3. Separate daemon |
|---|---|---|---|
| New server | New Rust module | Registry entry; a credential mechanism only if new | Daemon config |
| Trust | Hard-coded | Spec in the user's cplt config, validated against invariants | Daemon config |
| Fit with G2 | Good | Good | Poor: users install and run it |

O2, per D1.

### 5.2 The broker spec: server.json plus `_meta`

The registry is a spec-compliant MCP Registry; `apps/mcp-registry` entries
declare `"$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"`.
The spec nav-pilot hands cplt is one `server.json` per server, using
standard fields wherever they exist:

| Need | server.json field | Notes |
|------|-------------------|-------|
| Identity | `name`, `version` | Reverse-DNS name; also the broker id |
| Remote upstream | `remotes[].type`, `.url`, `.headers` | Fixed headers (`X-MCP-Readonly`) already live here for GitHub |
| Packaged local server | `packages[]` with `registryType`, `identifier`, `runtimeHint`, `transport.type: stdio`, `packageArguments`, `environmentVariables` | Covers npm, pypi, oci, nuget, mcpb |
| Host binary (`nais`) | **none** | server.json has no registryType for "a CLI already on the host". Goes in `_meta` (`command`) |
| Credential mechanism | **none** | `_meta` |
| Tools and risk classes | **none** | `_meta` |
| Read-only policy, argument checks | **none** | `_meta` |
| Egress hosts | **none** (only implied by `remotes[].url`) | `_meta` |
| Login / status commands | **none** | `_meta` |

Proposed extension key: `_meta["io.github.navikt/broker"]` on the
server.json, version 1:

```json
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name": "io.github.nais/nais-mcp",
  "version": "7.0.1",
  "_meta": {
    "io.github.navikt/broker": {
      "v": 1,
      "credential": "nais-keychain",
      "command": ["nais", "alpha", "mcp", "serve"],
      "egressHosts": ["console.nav.cloud.nais.io"],
      "tools": {
        "allow": ["get_nais_context", "execute_graphql", "validate_graphql", "schema_list_types"],
        "classes": {}
      },
      "argChecks": {"execute_graphql": "graphql-read-only"},
      "login": {"run": "nais login -n", "status": "nais auth print-access-token"}
    }
  }
}
```

(The Nais egress host above is a placeholder **(unverified)**; phase 1
measures what nais calls.)

| Field | Type | Meaning | cplt check |
|-------|------|---------|-----------|
| `v` | int | Extension version | Unknown major: spec rejected |
| `credential` | string | Name in cplt's mechanism table (D3): `gh-token`, `nais-keychain`, `none` | Must exist in the table; the mechanism fixes what the command or upstream may be |
| `command` | string[] | Host binary and args (kind C, when no `packages[]` fits) | First element resolved in trusted dirs only; must match the mechanism's allowed command |
| `egressHosts` | string[] | Hosts the child may reach via the CONNECT proxy | Bare public hostnames; same validation as #1272 profiles; a host on cplt's built-in blocked-domains list is refused (only the built-in list, not a user blocklist) |
| `tools.allow` | string[] | Tools the user consented to | Any tool not listed is refused; `host-exec` class in `classes` is refused at load |
| `tools.classes` | map | Risk class per tool (`write`, `external`, `host-exec`; absent = read) | A `write`/`external` tool in `allow` needs `writeConsent: true` |
| `writeConsent` | bool | Set by `enable --tools` | Default false |
| `argChecks` | map | Named, cplt-implemented checks per tool | Unknown check name: spec rejected |
| `login` | object | Commands nav-pilot runs and cplt quotes in errors | Not executed by cplt |

Where today's custom fields live, and where they should:

| Field | In `allowlist.json` (source) | As served by the registry | Should be |
|-------|------------------------------|---------------------------|-----------|
| `tools` | Top level of each server object | `_meta["io.github.navikt/registry"].tools` on the list response (`apps/mcp-registry/types.go:119-122`) | Response `_meta` (curation by the registry). Copied into the broker extension by nav-pilot |
| `toolRisk` | Top level | Same `_meta` key | Same |
| `sandboxHosts` | Top level | Same `_meta` key (`apps/mcp-registry/README.md:142`) | Same; becomes `egressHosts` in the broker extension |
| `setupInstructions` | Top level | Same `_meta` key | Same (UI text, never reaches cplt) |
| Nais launch command | Only as prose in `setupInstructions`; no `packages[]` | Not machine-readable | New `_meta` field (`command`), since server.json cannot express a host CLI |
| Credential, login/status | Absent | Absent | New `_meta` fields |

`allowlist.json` mixes non-standard keys into the server object; the
registry moves them into the response `_meta`, which keeps the served
`server.json` valid. nav-pilot already reads them from there
(navikt/copilot `cli/nav-pilot/internal/provider/opencode_mcp.go:185-213`).
cplt reads only `server.json` plus `io.github.navikt/broker`, not the
registry's response shape, so any compliant registry plus that extension
can feed it.

### 5.3 The interface between nav-pilot and cplt

| Aspect | Specification |
|--------|---------------|
| Location | `$XDG_CONFIG_HOME/cplt/mcp/<name-with-slashes-as-__>.json`, one file per server. User config dir, outside every sandbox grant, so the agent cannot write it. The per-server toggle stays in `config.toml`: `sandbox.mcp_broker.<id> = false` |
| Writer | nav-pilot only, atomically (temp file + rename), mode 0600 |
| Reader | cplt at launch, with `untrusted::read_untrusted` and a size cap, like `src/github_mcp.rs:112-139`. Symlinks and files in a writable tree are refused, as for OpenCode config (SECURITY.md:82) |
| Versioning | `v` in the extension. cplt reports the versions it reads in `cplt mcp status --json` (`"schema": [1]`); nav-pilot writes the highest common one, or refuses with "upgrade cplt" |
| Rejection | A spec that fails validation or an invariant is not loaded. cplt prints one line at launch (`nais-mcp: broker spec rejected: tools.allow has host-exec tool X. Fix: nav-pilot mcp enable io.github.nais/nais-mcp`), and lists it under `rejected` in `cplt mcp status --json`. The client entry is left as configured. Never a launch failure |
| Per-run override | `--no-mcp-broker <id>` (repeatable), like `--deny-env` |
| Repo config | Never read for specs |

Invariants enforced at load (D2):

1. `credential` names a mechanism in cplt's table, and the command or
   upstream matches what that mechanism allows (for `gh-token`, upstream
   `https://api.githubcopilot.com/mcp/readonly` only).
2. No secret value anywhere in the spec (no header value matching a token
   pattern; `environmentVariables` with `isSecret: true` refused unless the
   mechanism supplies them).
3. Write or external tools only with `writeConsent: true`; `host-exec`
   never.
4. Upstream `https` only; command from trusted dirs only.
5. Tool policy comes only from the spec. A tool not in `tools.allow` is
   refused, whatever cplt's own tables say; cplt has no compiled-in tool
   classes, so a cplt release can never make a tool callable without
   nav-pilot re-consent.
6. No credential placeholders in a spec. The credential's form (prefix,
   auth style) comes from the source in cplt's table, never from the spec.

### 5.4 Transports

**Local (kind C): stdio over a Unix socket (D6).** At launch cplt creates a
per-session socket directory outside every granted root, as the worktree
broker does (`src/worktree_broker.rs:1-20`), and grants the sandbox
connect on that one socket. The client entry becomes
`command: ["cplt", "mcp-stdio", "<id>"]`. That shim, running inside the
sandbox, connects to the socket, sends the id, and copies stdin/stdout.
The host side spawns or reuses the child and pipes bytes; it parses
JSON-RPC lines only to apply policy. Supported MCP protocol versions:
2025-06-18 and 2025-11-25, which carry one JSON-RPC message per line on
stdio; the broker checks `protocolVersion` in `initialize` and refuses
others. JSON-RPC batch arrays are rejected with an error; there is no
legacy (2025-03-26) batch handling. No secret path is needed: as in the
worktree broker, the client is the sandboxed agent, which already holds
that authority. On Linux (#834) the socket sits in a 0700
`/tmp/cplt-mcp-<id>/`, and Bubblewrap binds the
socket file itself past its private `/tmp`; the Landlock rule is read+write
on that one path, which is what `connect(2)` needs from ABI v9.

**Remote (kind A): HTTP on the proxy port behind a secret path**, as #807.
Kept until a third server makes the shared model worth it (D15).

### 5.5 `cplt mcp status --json`

```json
{"schema": [1],
 "servers": [
  {"id": "io.github.nais/nais-mcp", "state": "brokered", "transport": "unix",
   "credential": "nais-keychain", "credential_ok": true,
   "tools_allowed": 12, "clients": ["opencode", "copilot"]},
  {"id": "io.github.navikt/github-mcp", "state": "brokered", "transport": "http",
   "credential": "gh-token", "credential_ok": true}
 ],
 "rejected": [{"file": "…/mcp/x.json", "reason": "…", "fix": "…"}]}
```

Runs launch detection without starting the server. `credential_ok` uses the
mechanism's status probe; no secret is printed. The probe runs in the
server's own sandbox, through a broker serving that one spec: on Linux
bwrap, filtered bus and egress proxy; on macOS `mcp_child_profile` and
egress proxy (#930). The server can write its config dir
(`~/.config/nais`, `~/Library/Application Support/nais`), and nais reads
`config.yaml` there on every run, whose values set any flag (a planted
`nais: false` turns the probe into a gcloud call).

### 5.6 Lifecycle

| Aspect | Proposal |
|--------|----------|
| Detection | At launch: load specs, check credential presence; on failure one line with the fix, entry left alone |
| Spawn | Lazy, on the first socket connection for that id |
| Concurrency | One child per server per session; in-flight requests capped per child (default 8), excess gets a JSON-RPC error (D13) |
| Timeouts | Per-call deadline (120 s): the client gets a JSON-RPC timeout error (-32603), the server a `notifications/cancelled`, and a late response is dropped. A client cancel frees the slot the same way. Idle child stopped after 10 min (not yet implemented) |
| Sessions and restart | The MCP session is tied to the child's lifetime. When the child exits or is replaced (crash, idle stop, auth restart), the broker closes every client socket bound to it. cplt cannot replay `initialize` over stdio, so the shim exits, the client sees the server process end, and it reconnects and re-initializes against a fresh child. Respawn at most 3 per minute, then refuse with a log line. (An HTTP 404 for an unknown `Mcp-Session-Id` applies only to the remote path) |
| Notifications | Server-initiated messages outside a request (including `notifications/tools/list_changed`) are not delivered (D13) |
| Shutdown | The broker owns each child explicitly: it keeps the `Child` handle, and on session exit (and on idle stop) sends SIGTERM, waits a short grace, sends SIGKILL, then `wait()`s to reap, as the curl path does (`src/github_mcp.rs:420-421`). It does not rely on the process group: cplt does not kill the session's group (`src/audit.rs:1137-1148`) |

### 5.7 The host child (D7)

- **Env:** cleared, then `HOME`, `PATH` (trusted dirs), `LANG`, `TMPDIR`
  (host), and `HTTPS_PROXY`/`HTTP_PROXY` pointing at cplt's CONNECT proxy.
- **Egress:** the proxy allows the child only `egressHosts`. Phase 1 uses
  a listener of its own per server (`egress_port` in `src/mcp_broker/runtime.rs`),
  apart from the agent's proxy. A host outside `egressHosts` gets 403; a
  failed dial gets 502, or 504 on a timeout, not DENIED (#876).
  On macOS this is **enforced** (#849): the child runs under
  `sandbox-exec` with `mcp_child_profile` (`src/sandbox_profile.rs`),
  built from the agent profile's header and process rules plus a network
  block of its own: mDNSResponder and `localhost:<egress port>`, nothing
  else (no listener, no unix sockets such as a Gradle daemon's). A direct
  connect to any other host or local port fails with `EPERM`, UDP is
  denied, and with no `egressHosts` there is no TCP at all. Name lookups
  stay open, as for the agent. `mach-lookup` allows only `com.apple.SecurityServer`
  beyond `bsd.sb` (#911), so XPC services that act for the caller, such as
  `nsurlsessiond`, are out of reach. The list was measured 2026-10-28 with
  nais 7.0.3: the allow replaced by `(allow mach-lookup (with report))`,
  `log stream --predicate 'sender == "Sandbox"'` running, then startup,
  `tools/list`, `get_nais_context`, `nais auth print-access-token -n` and
  go-keyring's `security add-generic-password -U` on a temp keychain. Only
  the `security` helper looked up anything, and only securityd. securityd
  and the `bsd.sb` services still act for the child, so this contains the
  nais workload; it is not a full jail for an arbitrary hostile binary. On Linux this is **enforced** too (#849):
  the broker runs `bwrap` (from the trusted dirs, never `PATH`) with
  `--unshare-user/pid/ipc/uts/cgroup/net`, `--die-with-parent` and
  `--new-session` (`child_bwrap_args` in `src/mcp_broker/runtime.rs`).
  The fresh network namespace has only its own loopback, so a direct
  connect fails with `ENETUNREACH`. A namespace cannot reach the proxy on
  the host's loopback, so the broker also serves each egress proxy as a
  0600 unix socket in its socket dir and bwrap binds that socket alone
  into the namespace at `/tmp/cplt-egress.sock`. Inside, bwrap starts
  cplt again with `__CPLT_MCP_EGRESS_RELAY` set, which an `.init_array`
  constructor dispatches before `main` (as bwrap's re-entry helper is).
  That relay listens on `127.0.0.1:<egress port>`
  (the port `HTTPS_PROXY` names), relays each connection to that socket,
  and then runs the server. On the host each unix connection goes on to
  the TCP egress proxy, which makes the decision. With no `egressHosts`
  there is no listener and no socket, so no TCP at all. Name lookups do
  not work in the namespace either; the proxy resolves names. Fails
  closed: without bwrap the child is not spawned, and if bwrap cannot
  build the namespaces, or the relay cannot listen, it exits before the
  server starts.
- **Files (macOS):** reads are open (the child holds the host login anyway,
  and its egress is pinned). Writes go only to its temp dir and the
  mechanism's `write_dirs` under `HOME`: for `nais-keychain`,
  `~/Library/Application Support/nais` (refresh rewrites
  `nais-credentials.json.enc`). The keychain is reached through securityd
  (`com.apple.SecurityServer`, the one allowed Mach service); go-keyring's `security`
  helper also needs `ipc-posix-shm` on `com.apple.AppleDatabaseChanged` to
  post a keychain change. A refresh also rewrites the login keychain file
  from the caller's process (a `login.keychain-db.sb-*` temp file, then a
  rename), so a `keychain` mechanism may write exactly
  `~/Library/Keychains/login.keychain-db` and its `.sb-*` siblings; without
  it `security` exits 161 and the refresh is lost (measured 2026-10-25). Measured 2026-10-25: `nais auth
  print-access-token -n` exits 0 under the profile (network opened for the
  check) with no file or keychain denials.
- **Files (Linux):** `--ro-bind / /`, so reads are open as on macOS and
  every write outside the grants fails with `EROFS`. Granted: a private
  tmpfs `/tmp` (`TMPDIR=/tmp`), the mechanism's `linux_write_dirs` under
  `XDG_CONFIG_HOME` (default `~/.config`; for `nais-keychain`,
  `~/.config/nais`, created 0700 if missing) bound writable, with
  `XDG_CONFIG_HOME` set to that resolved dir, and fresh `/proc` and
  `/dev`. `HOME` is an empty tmpfs, remounted read-only, with only the
  mechanism's grants bound back: its `linux_write_dirs` and its
  `linux_read_paths` (for `nais-keychain`, none: found by reading nais/cli
  for `alpha mcp serve` and `auth print-access-token -n`, see
  `src/mcp_broker/credential.rs`). That hides sockets in `HOME`, such as
  Docker Desktop's `~/.docker/desktop/docker.sock`. A `HOME` under `/tmp`
  or `/run` is private already; `HOME=/` refuses the child. cplt itself
  (the relay) is bound in at `/run/cplt-relay`, since it may live in
  `HOME`. `/run`, and `XDG_RUNTIME_DIR` if it lives elsewhere, are private
  tmpfs, which hides the system bus, a docker socket and the rest of the
  host's runtime sockets, and so are `/nix/var/nix/daemon-socket` and
  `/nix/var/nix/gc-socket` where they exist: the Nix daemon builds as a
  trusted user (root) and fetches through fixed-output derivations, past
  the egress proxy. bwrap 0.8 and later also gets `--disable-userns`; on
  older bwrap (Ubuntu 22.04 ships 0.6) the child starts without it and
  `cplt doctor` warns, as it adds kernel surface, not host privilege. On NixOS `/run/current-system` is restored as a
  symlink to its store path, so `/run/current-system/sw/bin` still
  resolves. Unix sockets elsewhere under the read-only root (under
  `/var`, say) stay connectable, and copies of `HOME` elsewhere in the
  root (btrfs snapshots, a second bind mount) stay readable: hiding
  `HOME`, and the XDG config and data dirs outside it, is a denylist.
- **Session bus (Linux):** never the host bus itself. The unfiltered user
  bus reaches `systemd --user` (`StartTransientUnit`) and D-Bus
  activation, which is host exec. For a `keychain` mechanism the broker
  runs `xdg-dbus-proxy` (trusted dirs only, never `PATH`) on a socket in
  its 0700 session dir, as Flatpak does: `--filter
  --talk=org.freedesktop.secrets`, nothing else. go-keyring makes every
  call to the Secret Service (open session, search, unlock, the prompt
  objects and their signals, get secret); the proxy itself passes the bus
  driver's `Hello`, `AddMatch` and similar. bwrap binds that socket alone
  at `/run/cplt-bus`, and the child gets
  `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/cplt-bus`. A call to any other
  name, `org.freedesktop.systemd1` included, or `StartServiceByName` for
  one, is refused by the proxy (`tests: keychain_child_reaches_only_the_secret_service`).
  The proxy's `--fd` pipe is bwrap's `--sync-fd`, so it exits with the
  child. The host bus is the first `unix:path=` socket in
  `DBUS_SESSION_BUS_ADDRESS` (or `$XDG_RUNTIME_DIR/bus` when that is
  unset); an abstract or TCP address is out of reach. With no host bus,
  or without xdg-dbus-proxy (one `FAIL` line in the broker log; `cplt
  doctor` warns and `--fix` installs it), the child gets no bus and no
  `DBUS_SESSION_BUS_ADDRESS`, and nais reports it is not logged in. Other
  mechanisms never get a bus. Residual: anything the Secret Service
  serves the user is reachable through that one name. With gnome-keyring
  that is every unlocked item in the login collection (other apps'
  passwords and tokens), plus gnome-keyring's internal interface on the
  same name; with KeePassXC, every entry in the groups its Secret Service
  integration exposes.
- The child is trusted code acting on attacker-chosen arguments.
- **Stderr:** to the broker log (`--proxy-log`, and the terminal at
  `--proxy-log-level all`), at most 64 lines of 512 bytes per child, every
  run of 20 or more token characters replaced by `[redacted]`. The child's
  environment is never logged.

## 6. Policy at the broker

### 6.1 Tools

- Filter `tools/list` to `tools.allow`.
- Refuse any other `tools/call` with a JSON-RPC error; log it (D12).
- A tool the server reports that is not in the spec's `tools.allow` is
  refused until `enable` is re-run (D8, invariant 5). The allow list is
  the only source of tool policy; cplt never classifies tools itself.
- JSON-RPC batch arrays are rejected (5.4).

GitHub keeps its upstream `/readonly` endpoint and forced headers, which
are stronger than a filter.

### 6.2 GraphQL (`execute_graphql`)

nais refuses non-query operations, but checks only the first operation
([graphql.go L499-L506](https://github.com/nais/cli/blob/44c28bca52f3d9e21e1174b1ae0d6727620d2832/internal/mcp/tools/graphql.go#L499-L506)),
and sends no `operationName` ([L335-L338](https://github.com/nais/cli/blob/44c28bca52f3d9e21e1174b1ae0d6727620d2832/internal/mcp/tools/graphql.go#L335-L338)).
Whether the Nais API rejects a multi-operation document is **(unverified)**.

nais's other checks also miss fragments: `checkForSecrets` does not
traverse named fragment definitions, and `calculateQueryDepth` counts a
spread as one level, so a query can hide a forbidden selection in a
fragment.

The broker's `graphql-read-only` check (D9) looks at the whole document,
every definition including fragments: strip strings and comments, then
refuse if any operation definition has a type other than `query` (the
`mutation` or `subscription` keyword anywhere at a definition position),
or if there is more than one operation definition. Anything the check
cannot parse is refused. False positives (a field literally named
`mutation`) are acceptable: they fail closed.

Limit: the check is about operation type only. It does not judge what a
query selects, so selections hidden in fragments (secret fields, depth)
remain nais's job. Upstream fix, filed first: check every operation, and
traverse fragments in the secret and depth checks.

### 6.3 Limits of argument inspection

Checks work only on arguments with a grammar the broker understands. Free
text, URLs the server fetches, and host paths cannot be checked; such
tools are denied or need an upstream mode.

### 6.4 Audit, size, rate

- One line per call: `[mcp:<id>] <time> tools/call <tool> → ALLOWED|DENIED <reason>|FAIL <code>`.
  No arguments or results. Agent strings escaped (`src/github_mcp.rs:148-171`).
- Child stderr to the proxy log, bounded and redacted (5.7).
- Message cap 4 MiB each way; nais `--rate-limit` passed through.

### 6.5 Prompt injection

Not reduced: tool results reach the model unchanged. The broker limits the
blast radius to read-only tools with the user's identity.

## 7. Credentials

cplt's mechanism table (D3), hand-kept, split into where the credential
comes from (source) and how it reaches the upstream (delivery), to match
#820's rule shape:

| Mechanism | Source | Delivery | Status probe | Kind |
|-----------|--------|----------|--------------|------|
| `gh-token` | Trusted `gh auth token` lookup (`src/discover.rs:155`), held as `SecretToken`; later #820's credential source (section 8) | `Authorization: Bearer` added by the broker's HTTP path | Lookup succeeds | A |
| `nais-keychain` | Ambient: nais reads its own keychain item (macOS) or Secret Service (Linux, go-keyring); cplt never touches it | None by cplt: cplt spawns the fixed `nais alpha mcp serve`, which uses it | `nais auth print-access-token` exits 0 | C |
| `none` | Nothing | Nothing | n/a | C without secrets |

Linux residual for `nais-keychain`: without active bubblewrap (or below
Landlock ABI v9), the agent can read Secret Service directly over D-Bus,
including nais's item, whatever the broker does (SECURITY.md:1589-1606).
The broker keeps the credential out of the sandbox's config and env; it
does not close that D-Bus path. Phase 1b (#834) therefore refuses the
broker unless Bubblewrap wraps the run and masks every bus and systemd socket
that exists (`sandbox::mcp_broker_refusal`), and makes that run's Bubblewrap
strict, so a spawn-time failure stops the run rather than falling back to
Landlock alone. The sandbox gets no D-Bus; the host child keeps it.

A new mechanism is a cplt change; a new server using an existing one is
not. GitHub token refresh: read at launch; a login mid-session needs a
restart, and the error says so (D11). This may change for kind A once
#820 lands, if injection resolves the token per request.

Note: the gh token is still reachable in the sandbox through the exec token
and `OPENCODE_AUTH_CONTENT` (SECURITY.md:32-38). The broker removes one
channel; #731 and #820 address the rest.

## 8. Relation to #820 (proxy-side token injection)

#820 (spike in session token-flow-spike-820) asks whether the CONNECT
proxy can terminate TLS for `api.github.com` and `github.com` and inject
the token there, so the agent gets a placeholder.

Input from the spike: #820 plans a generic injection layer. Each per-host
rule has a host pattern, a credential source on the host, an auth style
(Bearer, token, or Basic in base64) and a prefix-preserving placeholder.
It is not built and touches nothing in `src/` yet; if approved it touches
`src/proxy.rs` and `src/agent.rs:1124-1177`. #822 (forced-proxy default)
is on hold.

| Topic | Relation | Status |
|-------|----------|--------|
| Credential resolution | The broker consumes #820's credential-source interface instead of owning token plumbing. Section 7's `gh-token` row becomes a reference to #820's credential source once that exists; until then the broker uses today's lookup (`src/discover.rs:155`) behind the same shape. Design against it, do not block on it | Agreed direction |
| Remote MCP upstreams | With TLS termination, kind A (GitHub) could use injection on the normal CONNECT path, with no secret path. The broker would keep only policy (forced headers, tool filter) | **Open.** TLS termination (rustls/rcgen plus per-runtime CA env) is not owner-approved; #807's secret path stays until it is |
| Stdio and keychain servers | Injection cannot help: the credential is used by a host process, not sent by the agent. Nais needs the broker either way | Settled |
| Host list | Copilot sends its long-lived token straight to `*.githubcopilot.com`, so any injection host list must include it | Input for #820 |
| Path scope | `api.githubcopilot.com` is also the GitHub MCP host. Injecting there for every path would give the agent the full `/mcp` endpoint with the user's token, bypassing the read-only kind A. So a read-only kind A depends on #820 rules having a path scope that excludes `/mcp` (or pins it to `/mcp/readonly` with forced headers) | **Open**, input for #820 |
| Policy | Injection alone does not filter tools or force read-only; the broker owns that | Settled |
| Order | Phase 1 (Nais) does not depend on #820 | Settled |

## 9. Threat model

Attacker: the sandboxed agent or content steering it.

| Threat | Mitigation |
|--------|------------|
| Agent writes or changes a spec | Specs live in the user's cplt config, outside every grant; repo config never read |
| Spec asks for something dangerous (arbitrary command, secret in a header, host-exec tool) | Invariants at load (5.3); command must match the credential mechanism |
| Agent connects to the socket | Intended; it can only pick a declared id |
| Secret path leaks (remote kind) | Per-session, loopback, never logged; 128-bit, constant-time compare (`src/github_mcp.rs:208-220`) |
| SSRF | Remote: pinned upstream, no redirects, https only (`src/github_mcp.rs:34`, `:377-391`). Child: egress pinned to `egressHosts` via the proxy, enforced by Seatbelt on macOS and by a bwrap network namespace on Linux (5.7) |
| Host-exec through the child | Env cleared, egress pinned, read-only tools. macOS: child profile limits network to the proxy and writes to its own dirs. Linux: bwrap child with no network but the proxy, a read-only root, and a session bus filtered to `org.freedesktop.secrets` |
| Agent reads the credential directly (Linux) | Without active bubblewrap, Secret Service is reachable over D-Bus (SECURITY.md:1589-1606); see section 7 |
| Header injection | Control bytes refused, auth and `X-MCP-*` stripped (`src/github_mcp.rs:225-250`) |
| JSON-RPC smuggling | Every message parsed; batch arrays rejected; protocol version checked |
| DoS | In-flight cap per child, restart budget, deadlines, message cap. Hurts only the agent's own session |

## 10. Migration of `github_mcp.rs`

Not in phase 1 (D15). When a third server arrives:

1. GitHub gets a spec (`credential: gh-token`, `remotes[]` with the
   read-only URL and forced headers) written by nav-pilot.
2. `sandbox.github_mcp_proxy` and `--no-github-mcp-proxy` stay, as aliases
   for the GitHub id's toggle. Without a spec file cplt keeps today's
   built-in detection, so users without a newer nav-pilot see no change.
3. Shared pieces move out of `github_mcp.rs` (head parsing, header rules,
   log). The seam test (`src/proxy.rs:4193`) and off-path test
   (`src/opencode_v2.rs:1068`) must pass unchanged.

## 11. Phases

| Phase | Scope | Exit | Status |
|-------|-------|------|--------|
| 1 | Nais (#821) in OpenCode and Copilot CLI: spec schema v1 and loader, `nais-keychain` mechanism, `cplt mcp-stdio` over a Unix socket (macOS), host child with cleared env and egress pin, read allowlist, GraphQL check, `cplt mcp status --json`, mirrored errors. nav-pilot: `_meta` fields in the registry, spec writing, login after a yes, `mcp list` LOGIN and PATH | Nais works under cplt on macOS in both clients with no keychain grant; mutations and multi-op documents refused | Shipped (#825, fixes up to #846, #863) |
| 1b | Linux: bwrap bind for the socket; Secret Service; require bubblewrap's bus masks or warn about the D-Bus exposure | Linux e2e | Shipped (#838) |
| 2 | GitHub on the shared model, when a third server arrives | #807 tests unchanged | Deferred (#909) |
| 3 | Child sandbox: network and file profile | nais measured under it | Shipped: macOS (#862), Linux (#873) |
| 4 | Figma OAuth in the broker | — | Planned (#910) |

## 12. Still open

Decided:

- The child's egress has its own listener per server (5.7).
- Nais egress hosts are measured; they live in the spec's `egressHosts`.
- pi is out of scope (D5).
- GitHub moves to the shared model only with a third server (#909).
- D8 is enforced through `tools.allow` and `writeConsent` (6.1).

Open:

- Exact extension key name (`io.github.navikt/broker`), and whether the
  registry should serve it directly in `server.json` `_meta` or nav-pilot
  should build it from the response `_meta`.
- How kind A relates to #820 once the spike reports (section 8).

## 13. Issues to file

All filed or done. Open work is tracked in
[#912](https://github.com/navikt/cplt/issues/912).

## 14. Remote servers with OAuth (#910)

Status: proposal, 2026-10-31. Phase 4 in section 11. Consumers: Figma's
remote MCP and the Nav MCP gateway (navikt/copilot#2083, phase 1 #2085).
The gateway is an MCP-spec OAuth 2.1 authorization server: protected-resource
metadata (RFC 9728) per route, the route URL as the RFC 8707 `resource`,
PKCE S256, CIMD preferred with DCR as the fallback, and rotating refresh
tokens. Claims about the MCP spec (2026-07-28 authorization and
client-registration pages) and about Figma are marked **(unverified)**
where this document has not checked them against the source.

### 14.1 What the broker does today

- The loader refuses any non-empty `remotes[]`
  (`src/mcp_broker/spec.rs:174-181`), and every spec needs a `command`
  (`spec.rs:216-218`). Mechanisms are `nais-keychain` and `none`
  (`src/mcp_broker/credential.rs:41-75`); `gh-token` is refused there and
  served by the built-in GitHub MCP proxy (`credential.rs:78-84`).
- Policy (`tools.allow`, `classes`, `writeConsent`, `argChecks`) is checked
  at load (`spec.rs:239-275`) and on every message
  (`src/mcp_broker/policy.rs:60`, `:148`, `:239`). It does not care what
  the upstream is.
- The broker speaks stdio JSON-RPC lines, protocol versions 2025-06-18 and
  2025-11-25 only (`src/mcp_broker/mod.rs:31`). 2026-07-28 is not accepted
  yet; a remote kind that negotiates it needs that list extended.
- cplt stores no credential of its own. `nais-keychain` is ambient: nais
  reads its own keychain item (`credential.rs:42-44`). There is no keychain
  or Secret Service write path in cplt today.
- The GitHub proxy runs the upstream leg through the system `curl` from the
  trusted dirs, with token and request on stdin (`src/github_mcp.rs:16-19`,
  `:206-212`). Its comment "cplt has no TLS stack" is stale: `rustls` is a
  dependency since #820 (`Cargo.toml:17`), used by the proxy's TLS
  termination.
- Auth errors are mirrored as `FAIL not logged in on the host. Fix: <login>`
  (`src/mcp_broker/runtime.rs:1135-1143`, detection in `policy.rs:292-317`).

### 14.2 Spec schema

A `remote` kind is a spec with one `remotes[]` entry of type
`streamable-http` and `credential: "oauth"`, and no `command`:

```json
{
  "name": "com.figma/figma-mcp",
  "remotes": [{"type": "streamable-http", "url": "https://mcp.figma.com/mcp"}],
  "_meta": {"io.github.navikt/broker": {
    "v": 2,
    "credential": "oauth",
    "oauth": {"issuer": "https://api.figma.com", "scopes": ["mcp:read"]},
    "egressHosts": ["mcp.figma.com", "api.figma.com"],
    "tools": {"allow": ["get_design_context"], "classes": {}}
  }}
}
```

(Figma's URL, issuer and scope names are placeholders **(unverified)**.)

New invariants, enforced at load:

1. `credential: oauth` requires exactly one remote, `https`, port 443, and
   no `command`; every other mechanism still refuses `remotes[]`.
2. The remote's host and `oauth.issuer`'s host are both in `egressHosts`,
   and `oauth.issuer` is chosen by the user (specs come only from the user
   config dir). Discovery that leads anywhere else fails (14.7).
3. No `headers` with values, no `clientSecret`, no token in the spec
   (invariants 2 and 6 unchanged). The client identity is not a spec field;
   it comes from cplt (14.3).
4. `tools.allow`, `classes`, `writeConsent` and `argChecks` are unchanged.

`v` goes to 2. A cplt that reads only `[1]` rejects the spec with "upgrade
cplt", which `cplt mcp status --json` already lets nav-pilot predict
(`mod.rs:21-23`).

### 14.3 Client identity

| Option | For | Against |
|--------|-----|---------|
| CIMD: `client_id` is an HTTPS URL to a JSON document Nav hosts | One identity for every server, no registration state, the gateway already prefers it. The authorization server shows the domain at consent | Needs a stable Nav domain; servers that lack CIMD support need a fallback |
| Pre-registered client id per server | Works with any server that registers clients by hand | One registration per server and per vendor; a public client id is no secret anyway |
| DCR | Works with Figma today **(unverified)** | A fresh client per user and machine, state to keep, no stable identity to allowlist |

Recommendation: **CIMD, with DCR as the fallback**, in that order, and a
pre-registered id only if a server supports neither. The document is
`https://ki-utvikling.nav.no/cplt/oauth-client.json` (owner decision
2026-10-31), served as a static file by navikt/copilot's my-copilot app, with
`redirect_uris` `http://127.0.0.1/callback` (loopback, any port per
RFC 8252 7.3), `token_endpoint_auth_method: none`,
`grant_types` `authorization_code` and `refresh_token`. The document is
public; it holds no secret. Document integrity: `CODEOWNERS` + required review
on that path; the gateway refuses any non-loopback `redirect_uri` for this
`client_id` regardless of document contents; alert on document change. cplt
compiles the URL in (D3: a mechanism is a cplt row), so a spec cannot pick a
different client. The DCR registration result (a `client_id`) is stored with
the tokens and reused.

### 14.4 Login on the host

`nav-pilot mcp enable <id>` asks first (D10), writes the spec, then runs
`cplt mcp login <id>` on the host. With `--json` or no tty it only prints
that command. Login never runs inside a session: `cplt mcp login` refuses
when detected in a sandbox by something the agent cannot forge, not env
(`CPLT_MCP_SOCKET`, `src/mcp_broker/mod.rs:29`, is no security boundary).

1. Fetch the remote URL without a token; read `WWW-Authenticate`
   `resource_metadata`, else the well-known PRM path (RFC 9728).
2. Fetch PRM. Its `resource` may be an origin per RFC 9728; accept equal or
   a same-origin prefix of the spec URL. Its `authorization_servers` must
   contain `oauth.issuer`. Fetch that issuer's metadata (RFC 8414, then
   OpenID discovery); its `issuer` must equal `oauth.issuer` byte for byte.
3. Pick CIMD if the metadata says `client_id_metadata_document_supported`,
   else DCR at `registration_endpoint`, else fail with one line naming the
   server.
4. Bind a listener on `127.0.0.1:0`. Because macOS `ps` exposes the `open` URL
   (`(allow sysctl-read)`, `src/sandbox_profile.rs:1144`), use a random path
   segment in the callback URL (`http://127.0.0.1:<port>/callback/<random>`).
   Build the request with PKCE S256, `state`, `resource=<spec URL>` (RFC 8707)
   and the spec's scopes, and open the browser (`open` on macOS, `xdg-open` on
   Linux) or print the URL.
5. The listener accepts only the first `GET /callback/<random>` request
   matching path and `state` (and `iss` per RFC 9207 when the metadata
   advertises it), ignores other requests, and closes immediately after match
   or timeout (5 minutes). PKCE keeps process snooping of the auth URL down to
   login DoS.
6. Exchange the code with the verifier and `resource`. Store the result.

Every request in 1-6 goes only to `egressHosts`, https, no redirects
followed. Because `curl` re-resolves, the private-address claim would be false
without pinning (`egress.rs` `dial_public` filters then dials,
`src/mcp_broker/egress.rs:64-75`). Fix: cplt resolves, filters with
`is_private_ip`, and passes `curl --resolve host:443:ip --proto =https --max-redirs 0`.

### 14.5 Token storage and refresh

Tokens live in a file under cplt's state dir (`cplt_state_dir`,
`~/.config/cplt`, which the agent sandbox denies: `DENIED_DOTFILES`), mode
0600, on both systems; the keyring dependency is no longer needed. Token and
lock file names (`oauth-<mapped_id>.json`, `oauth-<mapped_id>.lock`) use the
same `__` id mapping as spec files (`src/mcp_broker/spec.rs:134`) and reject
`..` segments. Storing tokens in the OS keychain or Secret Service, or
encrypting with a key kept there, is not acceptable: the macOS agent sandbox
profile grants read/write on `~/Library/Keychains` when the agent needs the
keychain (`src/sandbox_profile.rs:934-944`), so a token in the login keychain is
readable by the agent. Residual risk: any process running as the user outside
the sandbox can read the file, same as other CLI token files. nav-pilot
never reads them.

Several cplt sessions share one token file. Refresh runs under an `flock`
on `<state dir>/oauth-<mapped_id>.lock`. The broker re-reads the file under the
lock before refreshing (before expiry, and on a 401 capped to once per 30 s
per id), and writes the rotated refresh token via temp file + atomic rename
under the lock before using the new access token. On `invalid_grant`, it
re-reads the file under the lock and deletes it only if the stored refresh
token equals the rejected one; every call then fails with the re-login line
(14.6). Nothing retries in a loop.

### 14.6 The proxy leg, audit and errors

The client entry stays `cplt mcp-stdio <id>` (D6). The broker reads each
line, applies the same `on_client` and `on_server` checks
(`policy.rs:60`, `:239`), and instead of writing to a child's stdin sends
it as a streamable-HTTP POST to the pinned URL with `Authorization: Bearer`
and `MCP-Protocol-Version`, and turns JSON or SSE responses back into lines.
Before sending a token, the broker only sends it to the spec's remote URL.
A JWT access token whose `aud` does not match the remote URL is not sent
(opaque tokens: rely on RFC 8707 at the AS, residual risk noted). The
`Mcp-Session-Id` header is kept per connection. The HTTPS leg uses the
GitHub proxy's pattern: system `curl` from the trusted dirs, token and
request on stdin, `-q`, no redirects (`src/github_mcp.rs:16-19`). A
long-lived SSE GET stream for server-initiated messages is not opened,
since the broker drops those anyway (SECURITY.md, "Brokered local MCP
servers").

Compared with the GitHub proxy (SECURITY.md, "GitHub MCP for OpenCode
v2"): both hold the credential on the host and pin one upstream. The
GitHub proxy is an HTTP endpoint on the proxy port and forwards whole
requests; this is the stdio broker, so the JSON-RPC policy (tool allowlist,
filtered `tools/list`, argument checks, in-flight cap) applies, which the
GitHub proxy does not have.

Audit: unchanged from #907, one line per `tools/call` with id, tool,
outcome and duration, no arguments or results. One extra line per refresh
(`oauth refresh ok` or `FAIL oauth refresh: <error code>`), never a token.

Errors: a 401 after one refresh, or `invalid_grant`, gives the agent a
JSON-RPC error and the terminal one line, once per session (output
policy: act now):
`figma-mcp: login expired. Fix: nav-pilot mcp enable com.figma/figma-mcp`.

### 14.7 Threats

| Threat | Mitigation |
|--------|------------|
| PRM points at another authorization server | `issuer` must equal the spec's `oauth.issuer`, whose host is in `egressHosts`. The spec is written by nav-pilot from the registry, outside the sandbox |
| Malicious authorization server or redirect | No redirects followed in discovery or exchange; https only; private addresses refused; `state`, PKCE and `iss` checked; the callback listener takes one request and closes |
| Token theft from the sandbox | Tokens never enter the sandbox: not in env, config, the socket's messages or logs. The agent can only make calls through the broker's policy, which is the same exposure as nais today |
| Token theft on the host | Same as any keychain item the user owns. Tokens are bound by `resource` to one route (gateway); a stolen gateway token reaches one server |
| Consent phishing with CIMD and a loopback redirect | Anyone can send a user an authorization link naming Nav's `client_id` with a loopback redirect, and the consent screen shows Nav's domain. The code only reaches a listener on the victim's machine, but a local process could race for the port. The MCP spec names this risk **(unverified wording)**. The gateway should show the client domain and requested route at consent; Figma's screen is outside Nav's control |
| Upstream used to exfiltrate | The broker reaches only the spec's URL; `egressHosts` pins discovery. The agent's own allowlist is not changed |
| Agent triggers a login | The agent can run the OAuth flow itself (sandbox allows loopback bind/inbound, `src/sandbox_profile.rs:3975-3976`; Linux shares host netns), using Nav's public CIMD `client_id` and its own loopback redirect, then ask the user to click a link. Env-based refusal (`CPLT_MCP_SOCKET`, `src/mcp_broker/mod.rs:29`) is no boundary. Owner decision 2026-10-31: (a) the gateway shows consent for this `client_id` only after the user enters a short code that cplt prints in the terminal; (b) while an oauth spec is loaded, cplt adds the AS host and token endpoint to the agent's proxy blocklist; (c) detect sandbox by something the agent cannot forge, not env; residual: macOS without forced proxy can still reach the AS directly, mitigated by (a). nav-pilot tells users cplt opens the browser itself and never asks them to click an agent-shown link |

### 14.8 Phases and open questions

| Option | For | Against |
|--------|-----|---------|
| Figma first | A real user need (#910's acceptance); works on DCR alone | Figma's DCR, scopes and redirect rules are unverified; a vendor we cannot change; a session id and SSE quirks to learn on a third party |
| Gateway first | Nav controls both ends: CIMD, `resource`, rotation and audit can be tested end to end; one client serves every team route | Waits for #2085; no user value until a route exists |

Recommendation: **gateway first**, against #2085's dev deployment, with
CIMD only. Figma follows as a second step that adds DCR. Both share
14.2-14.6; only client registration differs.

Open:

- Whether scopes come from the spec or from PRM `scopes_supported`.
- Whether 2026-07-28 is needed for these servers or 2025-11-25 suffices.
- Whether Figma supports CIMD or only DCR **(unverified)**.
