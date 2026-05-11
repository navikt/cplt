# Configuration

## Configuration file

Save your preferred defaults to `~/.config/cplt/config.toml` so you don't need to pass flags every time.

**Create the default config:**

```bash
cplt --init-config
```

This creates a commented template at `~/.config/cplt/config.toml`:

```toml
[proxy]
# enabled = true             # Default: true — disable with --no-proxy or set false
# port = 0                   # Default: 0 (OS-assigned ephemeral port)
# blocked_domains = "~/.config/cplt/blocked-domains.txt"
# allowed_domains = "~/.config/cplt/allowed-domains.txt"
# log_file = "~/.config/cplt/proxy.log"
# log_level = "none"             # Stderr verbosity: none, error, blocked, all
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

### Managing config from the CLI

Instead of editing TOML by hand, use `cplt config`:

```bash
cplt config show                          # show effective config (file + defaults)
cplt config get sandbox.quiet             # get a single value
cplt config explain                       # list all keys with descriptions
cplt config explain sandbox.pass_env      # explain a specific key
cplt config validate                      # check for syntax errors and unknown keys
```

**Setting values:**

```bash
# Scalar keys — set replaces the value
cplt config set sandbox.quiet true
cplt config set proxy.port 9090

# Array keys — set appends (idempotent, no duplicates)
cplt config set allow.read ~/Desktop
cplt config set allow.read ~/Documents    # adds a second entry
cplt config set allow.read ~/Desktop      # no-op, already present
cplt config set allow.ports 8080
```

**Removing values:**

```bash
# Remove a single element from an array
cplt config set allow.read ~/Desktop --unset

# Remove an entire key (reverts to default)
cplt config set allow.read --unset
cplt config set sandbox.quiet --unset
```

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
