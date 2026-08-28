# AGENTS.md

Rust project, a macOS Seatbelt sandbox wrapper for GitHub Copilot CLI.

## Build and test

Always run `mise run check` at the end of a coding session.

| Task | Suite | In sandbox | Linux CI | macOS CI | Requirements |
|-------------------------|----------------|:----------:|:--------:|:--------:|-------------------------------|
| `mise run check` | fmt + clippy + unit + lib | ✅ | ✅ | ✅ | None (safe everywhere) |
| `mise run test:unit` | unit_tests | ✅ | ✅ | ✅ | None |
| `mise run test:lib` | lib (modules) | ✅ | ✅ | ✅ | None |
| `mise run test:integration` | integration | ✅ | ❌ | ✅ | macOS `sandbox-exec` |
| `mise run test:integration-linux` | integration_linux | ❌ | ✅ | ❌ | Linux with Landlock (5.13+) |
| `mise run test:e2e` | e2e | ✅ | ❌ | ✅ | macOS + `copilot` in PATH |
| `mise run test:e2e-projects` | e2e_projects | ✅ | ❌ | ✅ | macOS `sandbox-exec` |
| `mise run test:e2e-live` | e2e (ignored), 6 smoke tests | ❌ | ❌ | ⚠️ | macOS + Copilot auth + network |
| `mise run test:all` | all of the above except live | ✅ | ❌ | ✅ | macOS + `copilot` in PATH |
| `mise run test:everything` | all + live | ❌ | ❌ | ⚠️ | macOS + Copilot auth + network |
| `mise run test` | everything via `cargo test` | ❌ | ❌ | ✅ | macOS |

Non-test tasks:

```bash
mise run clippy            # linter
mise run fmt               # auto-format
mise run check:all-targets # cargo check every release target, to catch breakage on
                           # non-native targets (requires user setup)
```

## Code style

- Rust 2024 edition, stable toolchain
- Standard rustfmt formatting (no overrides)
- Clippy must pass clean (warnings are errors in CI)
- Prefer `&str`/`&[T]` over owned types in function signatures
- Security-critical code gets doc comments explaining the *why*
- Only comment code that needs clarification

## Project layout

- `src/sandbox.rs` module root with re-exports (submodules use `#[path]`)
- `src/sandbox_policy.rs` constants, types, deny lists, env allowlists, validation
- `src/sandbox_profile.rs` SBPL profile generation (`generate_profile`, `ProfileOptions`)
- `src/sandbox_env.rs` environment variable construction (`build_sandbox_env`)
- `src/sandbox_exec.rs` sandbox execution, validation, signal forwarding
- `src/sandbox_landlock.rs` Landlock LSM + seccomp-BPF (cross-platform policy, Linux-only enforcement)
- `src/scratch.rs` per-session scratch directory with TMPDIR redirect
- `src/config.rs` config file parsing, CLI/config merging, `Resolved` struct
- `src/discover.rs` runtime environment probing (`--doctor`)
- `src/agent.rs` agent abstraction (Copilot, OpenCode, Shell): binary discovery, config dirs, auth hints. Also holds 10 agent unit tests, which run as lib tests
- `src/main.rs` CLI entry point, orchestration
- `src/lib.rs` library crate root (re-exports modules for test access)
- `src/proxy.rs` + `src/proxy/` CONNECT proxy, domain blocking
- `tests/unit_tests.rs` cross-platform unit tests (161 tests)
- `tests/integration.rs` macOS sandbox-exec kernel-level tests (39 tests)
- `tests/integration_linux.rs` Linux Landlock+seccomp kernel-level tests (24 tests)
- `tests/e2e.rs` end-to-end with compiled binary + smoke tests (67 tests)
- `tests/e2e_projects.rs` e2e tests with realistic project scaffolding (38 tests)
- `SECURITY.md` threat model, defense layers, honest gaps

## Test strategy

The four tiers each prove something the others cannot, so all four are needed.

1. **Unit tests** verify profile and policy generation: the SBPL profile text and
   Landlock policy contain the correct allow/deny rules, env vars are filtered
   properly, config merging works. Fast and cross-platform, but they do not prove
   the kernel actually enforces anything.
2. **Integration tests** verify kernel enforcement by running a real command
   inside the sandbox (macOS `sandbox-exec`, Linux Landlock+seccomp) and asserting
   it is denied or allowed. This is the ground truth for security properties.
3. **E2E tests** verify the full binary pipeline: CLI arg parsing → profile
   generation → sandbox invocation → exit code. Catches wiring bugs between modules.
4. **E2E project tests** verify that realistic developer workflows (git, node,
   python, rust file ops, config files) work inside the sandbox. Catches
   real-world breakage that synthetic tests miss.

Which tier to use:

- Adding or changing a sandbox rule → unit test for the policy string, plus an integration test for kernel enforcement
- Adding a config option → unit test for merge logic in `config.rs`
- Adding env var filtering → unit test in `unit_tests.rs`
- Fixing a real-world breakage → e2e_projects test reproducing the scenario
- Adding a Landlock rule → unit test in `sandbox_landlock.rs`, plus a test in `integration_linux.rs`

## Security constraints

This is a security tool. Changes to sandbox rules, env handling, or network policy must:

- Have a clear security rationale documented in the commit or a code comment
- Not weaken existing deny rules without discussion
- Update SECURITY.md if the threat model or defense layers change

Do not modify `blocked-domains.txt` without reviewing the domain's purpose.

## Key patterns

- `(deny default)` plus specific allows, so the sandbox is deny-by-default
- `ENV_ALLOWLIST`, the only env vars that pass through
- `HARDENING_ENV_VARS`, declarative security env injection. Add new entries here
- `HOME_TOOL_DIRS` is a **single unified list** for both macOS and Linux. Put both
  `Library/*` (macOS) and `.cache`/`.local/share/*` (XDG/Linux) paths in this one
  list. Do NOT create platform-specific duplicates. Non-existent paths are skipped
  at runtime.
- `HomeToolDir`, per-directory exec/map/write permissions
- Network outbound scoping: `--allow-localhost-any` uses `"localhost:*"` for all
  cases. Java's IPv4-mapped address issue is solved by injecting
  `-Djava.net.preferIPv4Stack=true` via `JAVA_TOOL_OPTIONS` (macOS only), so
  `"*:*"` is no longer needed.
- Config precedence: CLI flag > config file > default (secure default)

## Git conventions

- Do not add `Co-authored-by` trailers to commits
- GPG signing may be unavailable in the sandbox; use `git -c commit.gpgSign=false commit` when needed

## Docs

- [README.md](README.md) usage, flags, troubleshooting
- [SECURITY.md](SECURITY.md) threat model, attack analysis, defense layers
