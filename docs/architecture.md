# cplt Architecture Guide

> Guiding principles for code quality, structure, and evolution.
> Read this before contributing. Update it when conventions change.

---

## Core Tenets

1. **Security is the product.** Every design decision must consider whether it
   weakens the sandbox. When in doubt, deny.

2. **Types over conventions.** Use the type system to make invalid states
   unrepresentable. A compile error is better than a runtime check.

3. **Small functions, clear names.** If you can't describe what a function does
   in one sentence without "and", split it.

4. **Errors are UX.** Error messages answer "what happened", "why", and "what
   to do next". Never show raw internal errors to the user.

5. **One source of truth.** Constants, color codes, format strings — define
   once, reference everywhere.

6. **Honest about gaps.** Never overstate protection. Name what's kernel-enforced
   vs. best-effort. Document known limitations in SECURITY.md.

---

## Module Responsibilities

```
src/
  main.rs              CLI entry point. Parses args, calls run(), formats errors.
                        Should NOT contain business logic.
  lib.rs               Module declarations + is_unsafe_root(). Public API surface.
  ui.rs                All terminal output: colors, prefixed helpers, NO_COLOR/TTY.
  config.rs            Config file parsing, CLI/config merge, validation, explain.
  agent.rs             Agent abstraction: binary discovery, config dirs, auth hints.
  sandbox.rs           Module root: re-exports + SandboxConfig, prepare(), exec_sandboxed().
  sandbox_policy.rs    Constants, deny lists, env allowlists, validation.
  sandbox_profile.rs   SBPL profile generation (macOS Seatbelt).
  sandbox_env.rs       Sandbox environment variable construction.
  sandbox_exec.rs      Process execution, signal forwarding.
  sandbox_landlock.rs  Landlock LSM + seccomp-BPF (Linux).
  discover.rs          Runtime probing (--doctor), tool/auth discovery.
  proxy.rs             CONNECT proxy, domain blocking, audit log.
  scratch.rs           Per-session scratch directory, TMPDIR redirect.
  trust.rs             Trust store: accept/revoke repo config proposals.
  repo_config.rs       Per-repo .cplt.toml parsing and application.
  update.rs            Self-update check and download.
```

**Rule:** Each file has one clear responsibility. If a file exceeds ~1000 lines,
look for a natural seam to split. If two files are always changed together,
consider merging them.

---

## Error Handling

### Application boundary (main.rs)

Use `anyhow` for error propagation in `run()` and other orchestration code:

```rust
fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let config = load_config(&cli).context("loading config")?;
    // ...
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => { ui::error(&format!("{e:#}")); ExitCode::FAILURE }
    }
}
```

### Library modules (config.rs, trust.rs, etc.)

Currently use `Result<T, String>` (60 instances across 12 files). This is
legacy debt — migrate to `thiserror` error enums as modules are touched:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}")]
    ReadFailed { path: PathBuf, #[source] source: std::io::Error },
    #[error("invalid TOML in {path}")]
    InvalidToml { path: PathBuf, #[source] source: toml::de::Error },
}
```

**Never** use `Result<T, String>` in new code. For quick prototyping, use
`anyhow::Result<T>` and refine later.

### Unwrap and expect

- `unwrap()` is acceptable only when the operation is provably infallible
  (e.g., `writeln!` to a `String`). Use `expect("reason")` to document the
  invariant.
- In application/orchestration code, use `?` or `bail!()`.
- In security-critical paths, prefer explicit error handling over `?`.
- SBPL profile generation uses the `sbpl!` macro (wraps `writeln!` with
  `.expect("write to String")`) to reduce noise while preserving the invariant.

---

## Output & Color

All terminal styling goes through `src/ui.rs`. This module:
- Defines ANSI constants (`GREEN`, `RED`, `YELLOW`, `BLUE`, `DIM`, `BOLD`, `RESET`)
- Provides `use_color()` — checks `NO_COLOR` env + stderr TTY detection
- Provides `color(code)` — returns the escape code or `""` when color is disabled
- Provides prefixed helpers: `info()`, `warn()`, `error()`, `ok()`

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
- `ui::color()` returns `""` when color is disabled — safe to embed in format strings.

---

## Visibility

Use the narrowest visibility that works:

| Visibility | When to use |
|------------|-------------|
| `pub` | Intentional public API (used by integration tests or external consumers) |
| `pub(crate)` | Shared between modules but not part of the public API |
| `pub(super)` | Shared within a module tree (e.g., sandbox submodules) |
| private | Default. Everything starts private. |

**Rule of thumb:** If it's not used outside its module, it's private. If it's used
by sibling modules but not tests, it's `pub(crate)`. If tests need it, it's `pub`.

---

## Type Design

### Prefer enums over boolean pairs

```rust
// ✗ Two bools can be contradictory
pub scratch_dir: bool,
pub no_scratch_dir: bool,

// ✓ One enum, impossible to conflict
pub enum ScratchMode { Default, Enabled, Disabled }
```

### Use newtypes for domain concepts

When a `String` or `PathBuf` has semantic meaning, consider a newtype:

```rust
pub struct ProjectDir(PathBuf);  // Not just any path — a validated project root
pub struct TrustHash(String);    // Not just any string — a content hash
```

### Structs with many fields

For structs with >8 fields (like `ProfileOptions`), document field groups with
comments. If the struct is constructed in many places, consider a builder.
Keep fields private and expose through methods when validation matters.

---

## Security Patterns

### Deny by default

Every sandbox rule starts as denied. Code that adds allows must justify the
allow in a comment:

```rust
// Allow read access to Git hooks so `git commit` works inside the sandbox.
// Risk: hooks can execute arbitrary code, but the user opted in with --allow-gpg-signing.
emit_git_hooks(&mut sb, opts.git_hooks_path);
```

### Fail closed

If a security check cannot run, the result is "deny":

```rust
// ✗ Fail open — silent security degradation
let paths = canonicalize_paths(&deny_paths).unwrap_or_default();

// ✓ Fail closed — abort on unresolvable deny paths
let paths = canonicalize_deny_paths(&deny_paths)?;
```

### DANGEROUS flag convention

Flags that significantly weaken the sandbox must:
1. Be marked `dangerous: true` in the config key definition
2. Include `[DANGEROUS]` in their `--help` text
3. Require `--force` when set via `cplt config set`

---

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

Shared test utilities go in `tests/` helper modules, not duplicated across test
files. Use `tempfile::TempDir` for filesystem tests.

---

## Function Design

### main.rs structure

```
main()              → parse CLI, call run(), format errors (10 lines)
run()               → orchestrate: config → sandbox → execute (returns anyhow::Result<ExitCode>)
run_doctor()        → --doctor subflow
run_config_command()→ config subcommand dispatch
run_trust_command() → trust subcommand dispatch
run_update()        → update subcommand dispatch
```

### Naming conventions

| Pattern | Convention | Example |
|---------|-----------|---------|
| Constructors | `new()`, `with_*()` | `ScratchDir::create()` |
| Getters | No `get_` prefix | `fn path(&self) -> &Path` |
| Conversions | `as_*/to_*/into_*` | `agent.as_str()`, `into_inner()` |
| Boolean queries | `is_*/has_*` | `is_unsafe_root()`, `has_api_key()` |
| Fallible ops | Return `Result` | `fn load_file() -> Result<...>` |

---

## Git Conventions

- Do **not** add `Co-authored-by` trailers
- GPG signing may be unavailable in sandbox; use `git -c commit.gpgSign=false commit`
- Run `mise run check` before pushing (fmt + clippy + unit + lib tests)

---

## What Not To Do

- **Don't add dependencies lightly.** Each dependency is attack surface. Justify
  new crates in the PR description.
- **Don't `pub` by default.** Start private, widen when needed.
- **Don't use `Result<T, String>` in new code.** Use `anyhow` or `thiserror`.
- **Don't scatter constants.** Colors in `ui.rs`, policy constants in
  `sandbox_policy.rs`, config keys in `config.rs`.
- **Don't comment what, comment why.** `// Create a new vector` is noise.
  `// SBPL uses last-match-wins, so denies must come after allows` is valuable.
- **Don't weaken deny rules** without updating SECURITY.md and getting review.

---

## Known Technical Debt

Tracked in [#38](https://github.com/navikt/cplt/issues/38). Priority order:

### P0 — Do first

1. **`thiserror` error types** for `update.rs` (17 instances) and `config.rs`
   (14 instances) — eliminates 69% of remaining `Result<T, String>`.
2. **Fix risky unwraps** — `std::env::var("HOME").unwrap()` in `discover.rs`,
   `as_table_mut().unwrap()` in `config.rs` (5-7 critical sites).

### P1 — Next

3. **Split `run()`** (576 lines) into phases: `resolve_config()`,
   `start_proxy()`, `run_sandbox()`.
4. **Split `config.rs`** (3488 lines) into submodules: parse, merge, validate,
   edit.
5. **Replace boolean flag pairs** with enums: `with_proxy`/`no_proxy` →
   `ProxyMode`, `scratch_dir`/`no_scratch_dir` → `ScratchMode`, etc.

### P2 — Backlog

6. **Visibility cleanup** — ~25-30 items unnecessarily `pub`, should be
   `pub(crate)`.
7. **Reduce cloning** — ~80 `.clone()` calls, many avoidable with references
   or builders.
