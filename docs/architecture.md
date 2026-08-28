# cplt architecture guide

> Guiding principles for code quality, structure, and evolution.
> Read this before contributing. Update it when conventions change.

## Core tenets

1. **Security is the product.** Every design decision must consider whether it
   weakens the sandbox. When in doubt, deny.

2. **Types over conventions.** Use the type system to make invalid states
   unrepresentable. A compile error beats a runtime check.

3. **Small functions, clear names.** If you cannot describe what a function does
   in one sentence without "and", split it.

4. **Errors are UX.** Error messages answer "what happened", "why", and "what
   to do next". Never show raw internal errors to the user.

5. **One source of truth.** Define constants, color codes, and format strings
   once, then reference them everywhere.

6. **Honest about gaps.** Never overstate protection. Name what is
   kernel-enforced and what is best-effort. Document known limitations in
   SECURITY.md.

## Module responsibilities

The significant modules, not an exhaustive listing. `src/lib.rs` has the full set.

```
src/
  main.rs              CLI entry point, orchestration.
    main()             → parse CLI, call run(), format errors
    run()              → orchestrate: early exits → resolve → proxy → sandbox → execute
    resolve_context()  → config loading, path resolution, agent detection
    start_proxy_if_enabled() → proxy startup, domain file resolution/validation
    run_doctor()       → `cplt doctor` subflow
    run_config_command()  → config subcommand dispatch
    run_trust_command()   → trust subcommand dispatch
    run_update()          → update subcommand dispatch
  lib.rs               Module declarations + is_unsafe_root(). The crate's public API.
  ui.rs                All terminal output: colors, prefixed helpers, NO_COLOR/TTY.
  config/              Config module
    mod.rs             Re-exports only
    types.rs           Config, Resolved, CliFlags, FeatureToggle, LoadedConfig structs
    error.rs           ConfigError enum (thiserror)
    loading.rs         load_file(), parse(), merge(), print_summary()
    path.rs            config_path(), expand_tilde(), resolve helpers, `config init` template
    validation.rs      Unknown key detection, diagnostics, Levenshtein suggestions
    registry.rs        ConfigKeyInfo, CONFIG_KEYS metadata, lookup_key()
    editing.rs         TOML document manipulation (set/append/remove/unset)
    display.rs         explain_key(), display_config(), get_config_value()
    repo.rs            Per-repo config set support, RepoKeyTarget
  agent.rs             Agent abstraction: binary discovery, config dirs, session flag
                       translation, default domain allowlists, auth hints.
  sandbox.rs           Module root: re-exports + SandboxConfig, prepare(), exec_sandboxed().
  sandbox_policy.rs    Constants, deny lists, env allowlists, validation.
  sandbox_profile.rs   SBPL profile generation (macOS Seatbelt).
  sandbox_env.rs       Sandbox environment variable construction.
  sandbox_exec.rs      Process execution, signal forwarding.
  sandbox_landlock.rs  Landlock LSM + seccomp-BPF (Linux).
  sandbox_bubblewrap.rs Optional Bubblewrap namespace layer + in-namespace re-entry helper (Linux).
  discover.rs          Runtime probing (`cplt doctor`), tool/auth discovery.
  detect.rs            Project and machine ecosystem detectors behind `cplt init`.
  proxy.rs             CONNECT proxy, domain blocking, audit log.
  gh_proxy.rs          gh and git command guards: policy tables, gates, wrapper scripts.
  scratch.rs           Per-session scratch directory, TMPDIR redirect.
  trust.rs             Trust store: accept/revoke repo config proposals.
  repo_config.rs       Per-repo .cplt.toml parsing and application.
  git.rs               Hardened parent-side git invocation (single choke point).
  audit.rs             Post-session project-change report.
  check.rs             Startup sandbox self-check.
  init.rs              `cplt init` output generation.
  gradle_init.rs       cplt-managed Gradle init script.
  settings.rs          Interactive settings TUI.
  subscriptions.rs     Blocklist subscription fetch, cache, and verification.
  update.rs            Self-update check and download.
```

**Rule:** each file has one clear responsibility. If a file exceeds ~1000 lines,
look for a natural seam to split. If two files always change together, consider
merging them.

## Error handling

### Application boundary (main.rs)

Use `anyhow` for error propagation in `run()` and other orchestration code.
Handle `BrokenPipe` silently, per Unix convention:

```rust
fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            // Broken pipe (e.g. `cplt config show | head`): exit silently.
            for cause in e.chain() {
                if let Some(io) = cause.downcast_ref::<std::io::Error>()
                    && io.kind() == std::io::ErrorKind::BrokenPipe
                {
                    return ExitCode::SUCCESS;
                }
            }
            ui::error(&format!("{e:#}"));
            ExitCode::FAILURE
        }
    }
}
```

### Library modules

Use `thiserror` error enums with `#[non_exhaustive]`:

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("Cannot read config file {path}: {source}")]
    FileRead { path: PathBuf, source: std::io::Error },
    #[error("Invalid TOML in {path}: {source}")]
    TomlParse { path: String, source: toml::de::Error },
    #[error("{0}")]
    Validation(String),  // rich contextual messages
}
```

`UpdateError` (update.rs) and `ConfigError` (config/) are migrated already.
`Result<T, String>` still remains in sandbox_policy.rs, proxy.rs, trust.rs, and
agent.rs; migrate those as you touch the modules.

Never use `Result<T, String>` in new code. For quick prototyping, use
`anyhow::Result<T>` and refine later.

### Unwrap and expect

- `unwrap()` is acceptable only when the operation is provably infallible, such
  as `writeln!` to a `String`. Use `expect("reason")` to document the invariant.
- In application and orchestration code, use `?` or `bail!()`.
- In security-critical paths, prefer explicit error handling over `?`.
- SBPL profile generation uses the `sbpl!` macro, which wraps `writeln!` with
  `.expect("write to String")` to cut noise while preserving the invariant.

## Output and color

All terminal styling goes through `src/ui.rs`, which defines the ANSI constants
(`GREEN`, `RED`, `YELLOW`, `BLUE`, `DIM`, `BOLD`, `RESET`), `use_color()`
(checks the `NO_COLOR` env var and stderr TTY detection), `color(code)` (returns
the escape code, or `""` when color is disabled, so it is safe to embed in any
format string), and the prefixed helpers `info()`, `warn()`, `error()`, `ok()`.

```rust
use crate::ui;

// Prefixed messages (always stderr)
ui::info("Loading config...");
ui::warn("Path not found, skipping");
ui::error("Cannot resolve $HOME");
ui::ok("Sandbox ready");

// Inline color in format strings (respects NO_COLOR + TTY)
eprintln!("  {}✓{} passed", ui::color(ui::GREEN), ui::color(ui::RESET));
```

**Rules:**
- Never write raw `\x1b[` escape sequences. Use `ui::color()`.
- Data goes to stdout (`println!`). Diagnostics go to stderr (`eprintln!`).

## Lints

Clippy pedantic lints are enabled in `Cargo.toml`. Targeted allows suppress
false positives without losing real value:

```toml
[lints.clippy]
pedantic = { level = "warn", priority = -1 }
missing_errors_doc = "allow"
# ... see Cargo.toml for full list with rationale
```

**Rules:**
- All new code must pass `cargo clippy -- -D warnings` with zero warnings.
- When adding an allow, document _why_ in the comment.
- Prefer fixing the lint over allowing it unless it is genuinely noise.
- Use `let...else` for early-return destructuring, not `match` with one arm.

## Module documentation

Every module has a `//!` doc comment explaining its purpose. Keep these brief,
one to three lines:

```rust
//! HTTP CONNECT proxy with domain filtering.
//!
//! Intercepts outbound HTTPS connections from the sandboxed agent,
//! enforcing blocked/allowed domain lists and private IP restrictions.
```

## Public enums: `#[non_exhaustive]`

All public enums use `#[non_exhaustive]`, so variants can be added without
breaking downstream code. Match expressions must include a wildcard arm `_`.

```rust
#[non_exhaustive]
pub enum VersionStatus {
    UpToDate,
    UpdateAvailable { ... },
    // Future variants won't break callers
}
```

## Visibility

Use the narrowest visibility that works. Everything starts private and widens
only when something outside its module needs it: `pub(crate)` when sibling
modules use it, `pub` when tests or external consumers do.

| Visibility | When to use |
|------------|-------------|
| `pub` | Intentional public API (used by integration tests or external consumers) |
| `pub(crate)` | Shared between modules but not part of the public API |
| `pub(super)` | Shared within a module tree, for example the sandbox submodules |
| private | The default |

## Type design

### Prefer enums over boolean pairs

CLI flag pairs like `--with-proxy` / `--no-proxy` use `FeatureToggle`:

```rust
pub enum FeatureToggle {
    ForceOn,     // --with-proxy
    ForceOff,    // --no-proxy
    #[default]
    UseDefault,  // neither flag → use config/default
}
```

Clap keeps two boolean flags. `FeatureToggle::from_pair(on, off)` converts them
at the merge boundary, and `resolve(config_default)` produces the final `bool`.

### Use newtypes for domain concepts

When a `String` or `PathBuf` carries semantic meaning, consider a newtype:

```rust
pub struct ProjectDir(PathBuf);  // A validated project root, not just any path
pub struct TrustHash(String);    // A content hash, not just any string
```

### Structs with many fields

For structs with more than 8 fields, like `ProfileOptions`, document field
groups with comments. If the struct is constructed in many places, consider a
builder. Keep fields private and expose them through methods when validation
matters.

## Security patterns

### Deny by default

Every sandbox rule starts as denied. Code that adds an allow must justify it in
a comment:

```rust
// Allow read access to Git hooks so `git commit` works inside the sandbox.
// Risk: hooks can execute arbitrary code, but the user opted in with --allow-gpg-signing.
emit_git_hooks(&mut sb, opts.git_hooks_path);
```

### Fail closed

If a security check cannot run, the result is "deny":

```rust
// ✗ Fail open: silent security degradation
let paths = canonicalize_paths(&deny_paths).unwrap_or_default();

// ✓ Fail closed: abort on unresolvable deny paths
let paths = canonicalize_deny_paths(&deny_paths)?;
```

### DANGEROUS flag convention

Flags that significantly weaken the sandbox must:

1. Be marked `dangerous: true` in the config key definition
2. Include `[DANGEROUS]` in their `--help` text
3. Require `--force` when set via `cplt config set`

## Testing

### Which tier to use

| Change | Test tier |
|--------|-----------|
| Sandbox rule (SBPL/Landlock policy string) | Unit test |
| Kernel enforcement (does the OS actually block it?) | Integration test |
| Config parsing/merge | Unit test |
| CLI flag wiring → sandbox invocation → exit code | E2E test |
| Real-world developer workflow (git, npm, python) | E2E projects test |
| Environment variable filtering | Unit test |

### Test naming

```rust
#[test]
fn deny_path_blocks_read_access() { ... }      // verb + subject + expected behavior
#[test]
fn config_merge_cli_overrides_file() { ... }    // module + scenario
```

### Test helpers

Shared test utilities go in `tests/` helper modules rather than being
duplicated across test files. Use `tempfile::TempDir` for filesystem tests.

## Naming conventions

| Pattern | Convention | Example |
|---------|-----------|---------|
| Constructors | `new()`, `with_*()` | `ScratchDir::create()` |
| Getters | No `get_` prefix | `fn path(&self) -> &Path` |
| Conversions | `as_*/to_*/into_*` | `agent.as_str()`, `into_inner()` |
| Boolean queries | `is_*/has_*` | `is_unsafe_root()`, `has_api_key()` |
| Fallible ops | Return `Result` | `fn load_file() -> Result<...>` |

## Git conventions

- Do not add `Co-authored-by` trailers
- GPG signing may be unavailable in the sandbox; use `git -c commit.gpgSign=false commit`
- Run `mise run check` before pushing (fmt + clippy + unit + lib tests)

## What not to do

- **Don't add dependencies lightly.** Each dependency is attack surface. Justify
  new crates in the PR description.
- **Don't scatter constants.** Colors live in `ui.rs`, policy constants in
  `sandbox_policy.rs`, config keys in `config/registry.rs`.
- **Don't comment what, comment why.** `// Create a new vector` is noise.
  `// SBPL uses last-match-wins, so denies must come after allows` is valuable.
- **Don't weaken deny rules** without updating SECURITY.md and getting review.
