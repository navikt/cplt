# AGENTS.md

Rust project — macOS Seatbelt sandbox wrapper for GitHub Copilot CLI.

## Build & test

```bash
mise run check          # fmt + clippy + unit/lib tests (works inside sandbox)
mise run test:all       # all suites except live smoke tests (macOS only)
mise run test           # all tests via cargo test (macOS only)
mise run test:unit      # unit tests only (cross-platform)
mise run test:lib       # library crate module tests
mise run clippy         # linter
mise run fmt            # auto-format
```

Always run `mise run check` at the end of a coding session.

## Code style

- Rust 2024 edition, stable toolchain
- Standard rustfmt formatting (no overrides)
- Clippy must pass clean (warnings are errors in CI)
- Prefer `&str`/`&[T]` over owned types in function signatures
- Security-critical code: add doc comments explaining the *why*
- Only comment code that needs clarification

## Project layout

- `src/sandbox.rs` — module root with re-exports (submodules use `#[path]`)
- `src/sandbox_policy.rs` — constants, types, deny lists, env allowlists, validation
- `src/sandbox_profile.rs` — SBPL profile generation (`generate_profile`, `ProfileOptions`)
- `src/sandbox_env.rs` — environment variable construction (`build_sandbox_env`)
- `src/sandbox_exec.rs` — sandbox execution, validation, signal forwarding
- `src/scratch.rs` — per-session scratch directory with TMPDIR redirect
- `src/config.rs` — config file parsing, CLI/config merging, `Resolved` struct
- `src/discover.rs` — runtime environment probing (`--doctor`)
- `src/main.rs` — CLI entry point, orchestration
- `src/lib.rs` — library crate root (re-exports modules for test access)
- `src/proxy.rs` + `src/proxy/` — CONNECT proxy, domain blocking
- `tests/unit_tests.rs` — cross-platform unit tests (128 tests)
- `tests/integration.rs` — macOS sandbox-exec kernel-level tests (33 tests)
- `tests/e2e.rs` — end-to-end with compiled binary + smoke tests
- `tests/e2e_projects.rs` — e2e tests with realistic project scaffolding (28 tests)
- `SECURITY.md` — threat model, defense layers, honest gaps

## Testing

Test suites and where they can run:

| Task                    | Suite          | In sandbox | Linux CI | macOS CI | Requirements                  |
|-------------------------|----------------|:----------:|:--------:|:--------:|-------------------------------|
| `mise run test:unit`    | unit_tests     | ✅         | ✅       | ✅       | None                          |
| `mise run test:lib`     | lib (modules)  | ✅         | ✅       | ✅       | None                          |
| `mise run test:integration` | integration | ✅         | ❌       | ✅       | macOS `sandbox-exec`          |
| `mise run test:e2e`     | e2e            | ✅         | ❌       | ✅       | macOS + `copilot` in PATH     |
| `mise run test:e2e-projects` | e2e_projects | ✅      | ❌       | ✅       | macOS `sandbox-exec`          |
| `mise run test:e2e-live`| e2e (ignored)  | ❌         | ❌       | ⚠️       | macOS + Copilot auth + network|
| `mise run check`        | fmt+clippy+unit+lib | ✅    | ✅       | ✅       | None (safe everywhere)        |
| `mise run test:all`     | all above      | ✅         | ❌       | ✅       | macOS + `copilot` in PATH     |

- **check** runs fmt, clippy, unit_tests, and lib tests — safe inside sandbox, CI, anywhere
- **unit_tests** + **lib** are cross-platform — use `check` on Linux CI or inside sandbox
- **integration**, **e2e**, **e2e_projects** all require macOS with `sandbox-exec`
- **e2e-live** (6 smoke tests) need real Copilot auth and network — not for regular CI
- All suites except **e2e-live** run fine inside the cplt sandbox

### Test strategy

The four tiers validate different properties — all are needed:

1. **Unit tests** verify SBPL profile string generation: the profile text contains the
   correct allow/deny rules, env vars are filtered properly, config merging works.
   Fast and cross-platform, but do not prove the kernel actually enforces anything.
2. **Integration tests** verify kernel enforcement: run a real command inside
   `sandbox-exec` and assert it is denied or allowed. This is the ground truth for
   security properties — if a unit test says "deny" but integration passes, the rule
   is broken.
3. **E2E tests** verify the full binary pipeline: CLI arg parsing → profile generation →
   sandbox-exec invocation → exit code. Catches wiring bugs between modules.
4. **E2E project tests** verify realistic developer workflows (git, node, python, rust
   file ops, config files) work correctly inside the sandbox. Catches real-world
   breakage that synthetic tests miss.

**Which tier to use:**
- Adding/changing a sandbox rule → unit test for the SBPL string + integration test for kernel enforcement
- Adding a config option → unit test for merge logic in `config.rs`
- Adding env var filtering → unit test in `unit_tests.rs`
- Fixing a real-world breakage → e2e_projects test reproducing the scenario

## Security constraints

This is a security tool. Changes to sandbox rules, env handling, or network policy must:
- Have a clear security rationale documented in the commit or code comment
- Not weaken existing deny rules without discussion
- Update SECURITY.md if the threat model or defense layers change

Do not modify `blocked-domains.txt` without reviewing the domain's purpose.

## Key patterns

- `(deny default)` + specific allows — deny-by-default sandbox
- `ENV_ALLOWLIST` — only safe env vars pass through
- `HARDENING_ENV_VARS` — declarative security env injection (add new entries here)
- `HomeToolDir` — per-directory exec/map/write permissions
- Config precedence: CLI flag > config file > default (secure default)

## Git conventions

- Do **not** add `Co-authored-by` trailers to commits
- GPG signing may be unavailable in sandbox; use `git -c commit.gpgSign=false commit` when needed

## Docs

- [README.md](README.md) — usage, flags, troubleshooting
- [SECURITY.md](SECURITY.md) — threat model, attack analysis, defense layers
