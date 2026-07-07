# Configuration

## How cplt config works

cplt reads config in this order:

1. CLI flags for the current run
2. `~/.config/cplt/config.toml` (or `CPLT_CONFIG`)
3. built-in defaults

List values are merged, so repeated `cplt config set` commands accumulate for
`allow.read`, `allow.write`, `allow.ports`, `allow.localhost`, and `deny.paths`.

## Quick setup

Use `cplt config set` to configure cplt without editing files:

```bash
cplt config set sandbox.quiet true
cplt config set proxy.port 9090
cplt config set allow.read ~/Desktop
cplt config set allow.ports 8080
cplt config set gh_guard.enabled true
cplt config set git_guard.enabled true
```

If your startup command is getting long, move repeated flags into config.
For your personal machine setup, use global config (no `--repo`):

```bash
cplt config set sandbox.allow_localhost_any true
cplt config set sandbox.allow_docker true
cplt config set sandbox.allow_jvm_attach true
cplt config set allow.read ~/.gitconfig
cplt config set allow.read ~/code/work/.gitconfig-nav
```

That translates a one-off command like:

```bash
cplt --allow-localhost-any --allow-docker --allow-jvm-attach \
  --allow-read ~/.gitconfig --allow-read ~/code/work/.gitconfig-nav
```

into saved config:

- `sandbox.allow_localhost_any` for tools that spin up random localhost ports
- `sandbox.allow_docker` for Gradle/Testcontainers/Docker access
- `sandbox.allow_jvm_attach` for Gradle daemon, MockK, and Mockito inline mocking
- `allow.read` for host files the agent should always be able to inspect

Use `cplt config explain` to see what a key does and how to set it.

## Policy presets

Instead of toggling individual flags, pick a named **preset** — a security
*posture* that sets a baseline for the five sandbox toggles **and** the safety
features (`gh_guard`, `git_guard`, forced-proxy egress, fail-closed domain
allowlist) with one flag or key:

```bash
cplt --preset strict       # full lockdown: toggles off + guards + forced proxy + domain allowlist on
cplt --preset standard     # the current defaults (no-op baseline)
cplt --preset permissive   # localhost + tmp exec + lifecycle scripts on
cplt --preset full-trust   # everything on (docker, env files, tmp exec, localhost, lifecycle)
```

Or in config:

```toml
[sandbox]
preset = "standard"
```

| Preset | localhost (`allow_localhost_any`) | env files (`allow_env_files`) | tmp exec (`allow_tmp_exec`) | docker (`allow_docker`) | lifecycle (`allow_lifecycle_scripts`) | `gh_guard` | `git_guard` | `proxy.forced` | `proxy.default_allowlist` |
|--------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `strict` | off | off | off | off | off | **on** | **on** | **on** | **on** |
| `standard` | off | off | off¹ | off | off | off | off | off | off |
| `permissive` | **on** | off | **on** | off | **on** | off | off | off | off |
| `full-trust` | **on** | **on** | **on** | **on** | **on** | off | off | off | off |

¹ `standard` leaves the per-session scratch directory on (the default), which is
what most tools need — `allow_tmp_exec` (raw `/tmp` exec) stays off. `standard`
is identical to cplt's hardcoded defaults, so omitting `--preset` behaves exactly
like `--preset standard`.

**Only `strict` enables the safety features — a full network lockdown.** It hardens
the dimensions that matter most: `gh_guard` (gate GitHub traffic), `git_guard`
(block push/force-push), `proxy.forced` (mandatory proxy, kernel egress locked to
it), and `proxy.default_allowlist` (fail-closed domain filtering — only the agent's
built-in allowlist plus any `allowed_domains` resolve, everything else is blocked).
Forced egress and the domain allowlist are orthogonal and compose: the kernel pins
egress to the proxy, and the proxy then filters domains. `standard`, `permissive`,
and `full-trust` all leave those four at their default (off), so selecting them
changes nothing about guards, forced egress, or the allowlist. `strict` enables
only *safety* features, so `config set sandbox.preset strict` needs no `--force`
(unlike `permissive`/`full-trust`, which weaken the sandbox). Opt into strict but
keep the network open with `--allow-all-domains` (or `proxy.default_allowlist =
false`), which overrides just the allowlist — explicit off wins over the baseline.

**Precedence — the preset is only a baseline.** An explicit individual flag or
config value always overrides the preset, whichever source the preset came from:

```bash
# permissive baseline, but keep tmp exec blocked:
cplt --preset permissive --no-allow-tmp-exec

# strict baseline, but allow docker just for this run:
cplt --preset strict --allow-docker
```

The resolution order for each toggle is: **explicit CLI flag → explicit config
value → preset baseline → hardcoded default (off)**. The preset itself resolves
CLI (`--preset`) over config (`[sandbox] preset`). Each preset-controlled flag has
a matching `--no-…` form (`--no-allow-localhost-any`, `--no-allow-env-files`,
`--no-allow-tmp-exec`, `--no-allow-docker`, `--no-allow-lifecycle-scripts`) so you
can opt a single toggle out of a permissive/full-trust baseline.

Presets are **global-only** — they cannot be requested from a repo `.cplt.toml`,
because a single preset would silently pull in several dangerous permissions and
defeat per-key trust review. A repo must propose individual keys instead.

Use **repo config + trust** for project-specific sandbox permissions that
belong to the repository, and **global config** for machine-specific paths:

- `.cplt.toml` + `cplt trust` for `sandbox.allow_jvm_attach`,
  `sandbox.allow_docker`, `sandbox.allow_localhost_any`, `allow.ports`
- `~/.config/cplt/config.toml` for `allow.read ~/.gitconfig` and other
  host-specific file paths

### Global-only settings

These settings are **not supported in `.cplt.toml`** because they are machine-
specific or local CLI preferences. `cplt config set --repo <key>` rejects them
with an explanation — set them in `~/.config/cplt/config.toml` instead:

| Key | Why |
|---|---|
| `sandbox.preset` | composes several dangerous permissions into one baseline — a repo must request individual keys so each is reviewed and trusted separately |
| `sandbox.agent` | preferred agent depends on what's installed locally |
| `sandbox.quiet` | local output preference |
| `sandbox.yes` | local prompt-skip preference |
| `sandbox.validate` | local launch behavior |
| `sandbox.scratch_dir` | local temp handling |
| `sandbox.use_bubblewrap` | depends on bwrap being installed on the machine |
| `sandbox.pass_env` | machine-specific env passthrough |
| `sandbox.inherit_env` | local debug-only behavior |
| `sandbox.allow_cache_exec` | cache paths differ per machine |
| `sandbox.allow_cache_exec_any` | too broad for repo policy |
| `proxy.enabled` | local proxy preference |
| `proxy.forced` | forcing all egress through the proxy is a local security preference, not project policy |
| `proxy.port` | port conflicts are machine-specific |
| `proxy.log_file` | local log path |
| `proxy.log_level` | local verbosity preference |
| `proxy.timeout` | local network condition preference |
| `proxy.blocked_domains` | local path to a blocklist file |
| `proxy.allowed_domains` | local path to an allowlist file |
| all `[gh_guard]` keys | guard policy is configured globally, not per-repo |
| all `[git_guard]` keys | guard policy is configured globally, not per-repo |
| all `[audit]` keys | audit destination/level is a local concern |

For project-specific settings (committed to `.cplt.toml`):

```bash
cplt config set --repo sandbox.allow_jvm_attach true
cplt config set --repo allow.ports 8080
cplt config set --repo deny.paths "~/secrets"
```

**Removing values:**

```bash
cplt config set allow.read ~/Desktop --unset     # remove one element
cplt config set allow.read --unset               # remove entire key
cplt config set sandbox.quiet --unset            # revert to default
```

**Inspecting config:**

```bash
cplt config show                          # show effective config (file + defaults)
cplt config get sandbox.quiet             # get a single value
cplt config explain                       # list all keys with descriptions
cplt config explain sandbox.pass_env      # explain a specific key
cplt config validate                      # check for syntax errors and unknown keys
```

## Configuration file

The config file lives at `~/.config/cplt/config.toml`. You can create a starter template with:

```bash
cplt config init
```

This creates a commented template at `~/.config/cplt/config.toml`:

```toml
[proxy]
# enabled = true             # Default: true — disable with --no-proxy or set false
# forced = false             # Default: false (opt-in). Force ALL egress through the proxy:
#                            # restrict kernel egress to the proxy port (no direct *:443),
#                            # closing the raw-socket / env-unset bypass. Fails closed if the
#                            # proxy can't start; conflicts with proxy.enabled = false. See docs/proxy.md
# port = 0                   # Default: 0 (OS-assigned ephemeral port)
# blocked_domains = "~/.config/cplt/blocked-domains.txt"
# allowed_domains = "~/.config/cplt/allowed-domains.txt"
# log_file = "~/.config/cplt/proxy.log"
# log_level = "none"             # Stderr verbosity: none, error, blocked, all
# timeout = 60                   # Proxy read/write timeout in seconds
# allow_private_domains = ["intern.nav.no"]  # Allow internal/intranet domains to resolve to private IPs

[sandbox]
# agent = "copilot"          # Preferred agent: copilot, opencode, gemini, pi, shell (auto-detected if not set)
# validate = true
# allow_env_files = false
# allow_lifecycle_scripts = false
# allow_gpg_signing = false    # Allow GPG commit signing (see SECURITY.md)
# allow_jvm_attach = false     # Allow JVM Attach API unix sockets (MockK, Mockito)
# allow_localhost_any = false
# scratch_dir = true           # On by default; set false to disable
# allow_tmp_exec = false       # Dangerous — prefer scratch_dir
# allow_cache_exec = []        # Allow exec from specific ~/Library/Caches subdirs, e.g. ["ms-playwright", "pnpm/dlx"]
# allow_cache_exec_any = false # Dangerous — allow exec from all of ~/Library/Caches
# inherit_env = false          # Dangerous — exposes all env vars
# pass_env = ["MY_CUSTOM_VAR"]

[allow]
# read = ["~/some/path"]
# write = ["~/another/path"]
# ports = [8080]
# localhost = [3000, 8080]

[deny]
# paths = ["~/extra/secret"]
```

**Precedence** (highest to lowest):

1. CLI flags (`--with-proxy`, `--no-proxy`, `--proxy-port`, etc.)
2. Config file (`~/.config/cplt/config.toml`)
3. Built-in defaults

Per-repo config (`.cplt.toml`) operates independently: the `[deny]` section tightens the sandbox unconditionally (no approval needed), and approved `[propose]` permissions are **additive** — they can enable features (e.g., `allow_docker = true`) but cannot disable anything set by CLI or global config.

**Environment variable override:**

Set `CPLT_CONFIG` to use a config file at a custom location:

```bash
CPLT_CONFIG=/path/to/custom.toml cplt -- --version
```

**Path expansion:** Paths in `[allow]` and `[deny]` support `~/` expansion and are resolved relative to the config file directory. `proxy.blocked_domains` supports `~/` expansion only.

### Advanced: editing TOML directly

For complex configuration (arrays of objects, multi-line values), you can edit `~/.config/cplt/config.toml` directly. Use `cplt config validate` to check for errors after editing.

**Repo-local config (`--repo`):**

Use `--repo` to write project-specific settings to `.cplt.toml` instead of global config:

```bash
# Request sandbox permissions (requires approval via `cplt trust accept`)
cplt config set --repo sandbox.allow_jvm_attach true
cplt config set --repo sandbox.allow_localhost_any true
cplt config set --repo allow.read "~/.gradle/gradle.properties"
cplt config set --repo allow.ports 8080

# Deny section — tightens security, applied immediately without approval
cplt config set --repo deny.paths "~/secrets"
cplt config set --repo deny.env "VAULT_TOKEN"

# Remove a permission request
cplt config set --repo sandbox.allow_jvm_attach --unset
```

Settings are mapped automatically: permission requests go under `[propose]`, restrictions under `[deny]`. Keys that are machine-specific (like `sandbox.quiet`, `proxy.port`) are rejected with a clear explanation.

> **Note:** Global config remains the default. Use `--repo` explicitly for project settings.

## Per-repo configuration (`.cplt.toml`)

Commit a `.cplt.toml` file to your repository for project-specific sandbox settings. This eliminates the need for every developer to configure the same CLI flags or global config.

### Security model

- **`[deny]`** — applied automatically (can only tighten the sandbox, no approval needed)
- **`[propose]`** — requested permissions, requires explicit user approval via `cplt trust accept`
- Read from `git HEAD` (committed state) — the agent cannot tamper with its own config mid-session
- Write to `.cplt.toml` is kernel-denied inside the sandbox
- Trust approvals are content-pinned — if requested values change, approvals are invalidated

### Example `.cplt.toml`

```toml
# Deny section — applied automatically, no approval needed
[deny]
paths = ["~/secrets", "~/.vault"]
env = ["VAULT_TOKEN", "MY_SECRET"]

# Requested permissions — requires approval via `cplt trust accept`
[propose]
allow_jvm_attach = true          # For MockK/Mockito tests
allow_docker = true              # Container access
allow_localhost_any = true       # Dev servers on any port

[propose.allow]
read = ["~/.gradle/gradle.properties"]
ports = [8080, 5432]
localhost = [5432]

[propose.proxy]
allow_private_domains = ["intern.nav.no"]
```

### Trust management

```bash
cplt trust                                # Show permissions and approval status
cplt trust accept allow_jvm_attach        # Approve specific keys
cplt trust accept --all                   # Approve everything
cplt trust revoke allow_docker            # Revoke a specific key
cplt trust revoke --all                   # Revoke all trust for this repo
```

Trust decisions are stored in `~/.config/cplt/trust/` (protected from the sandbox).

**For CI/scripts** where interactive approval isn't possible:

```bash
cplt --accept-repo-config -- -p "run tests"
```

### Auto-generate with `cplt init`

Instead of writing `.cplt.toml` by hand, detect your project's ecosystem:

```bash
cplt init                   # Preview detected permissions
cplt init --write           # Write .cplt.toml to disk
cplt init --write --force   # Overwrite existing file
cplt init --quiet           # Output only TOML (pipe-friendly)
```

#### Personal config with `cplt init --global`

Scan your machine for installed tools and generate `~/.config/cplt/config.toml`:

```bash
cplt init --global          # Preview personal config suggestions
cplt init --global --write  # Write to ~/.config/cplt/config.toml
```

Detects:
| Tool | Probes | Suggests |
|------|--------|----------|
| Gradle wrapper | `~/.gradle/wrapper/dists/` | `allow_cache_exec = ["gradle"]` |
| Playwright browsers | `~/Library/Caches/ms-playwright/` | `allow_cache_exec = ["ms-playwright"]` |
| GPG signing | `~/.gnupg/` + git config | `allow_gpg_signing = true` |
| Gradle registry | `~/.gradle/gradle.properties` | `allow.read` for credentials file |
| Alternative agents | `opencode`/`aider` in PATH | `agent = "..."` |

**Supported ecosystems:**

| Ecosystem | Detected via | Suggests |
|-----------|-------------|----------|
| JVM (Gradle/Maven) | `build.gradle*`, `pom.xml` | `allow_jvm_attach`, read gradle properties |
| Node.js | `package.json` | localhost ports, `allow_localhost_any` (for Next.js/Vite) |
| Docker | `Dockerfile`, `compose.yml` | `allow_docker` ⚠️, exposed ports |
| Python | `pyproject.toml`, `requirements.txt` | localhost ports (for Django/FastAPI) |
| Rust | `Cargo.toml` | (works with defaults) |
| Go | `go.mod` | (works with defaults) |
| Playwright | `@playwright/test` in package.json | `allow_cache_exec` (personal config hint) |
| Environment secrets | `.env.example` | `deny.env` for sensitive variables |
| Spring Boot | `application.yml` + Spring in Gradle | localhost 8080, PostgreSQL port |
| Ktor | `application.conf` + Ktor in Gradle | localhost 8080 |
| TestContainers | `testcontainers` in Gradle deps | `allow_docker` ⚠️, `allow_localhost_any` |
| Next.js | `next.config.ts/js` | localhost 3000, `allow_localhost_any` |
| Vite | `vite.config.ts/js` | localhost 5173, `allow_localhost_any` |
| Flyway | `db/migration(s)` directories | PostgreSQL port 5432 |
| Cypress | `cypress.config.ts` + `cypress/` dir | `allow_browser`, `allow_localhost_any` |

**Machine-specific suggestions** (like `allow_cache_exec` or home-relative read paths) are emitted as comments pointing you to add them to your personal `~/.config/cplt/config.toml`.

**Dangerous permissions** (⚠️ in the table) include risk warnings in the generated TOML. `allow_lifecycle_scripts` is never auto-suggested — it's only shown as a diagnostic if lifecycle scripts are detected, since it allows arbitrary code execution on `npm install`.

### Precedence

1. CLI flags (highest)
2. Global config (`~/.config/cplt/config.toml`)
3. Built-in defaults

Repo config is **not in this hierarchy** — it operates as a separate layer:
- `[deny]` always tightens the sandbox (no approval needed)
- Approved `[propose]` permissions are additive (can enable, never disable)
