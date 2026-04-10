# AGENTS.md

Rust project — macOS Seatbelt sandbox wrapper for GitHub Copilot CLI.

## Build & test

```bash
mise run check          # fmt + clippy + test (run before every commit)
mise run test           # all tests
mise run test:unit      # unit tests only (cross-platform)
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
- `src/config.rs` — config file parsing, CLI/config merging, `Resolved` struct
- `src/discover.rs` — runtime environment probing (`--doctor`)
- `src/main.rs` — CLI entry point, orchestration
- `src/proxy.rs` + `src/proxy/` — CONNECT proxy, domain blocking
- `tests/unit_tests.rs` — cross-platform unit tests
- `tests/integration.rs` — macOS sandbox-exec tests
- `tests/e2e.rs` — end-to-end with compiled binary
- `SECURITY.md` — threat model, defense layers, honest gaps

## Testing

Tests are split by platform requirement:
- **unit_tests** run on any OS (Linux CI, macOS)
- **integration** + **e2e** require macOS with `sandbox-exec`
- 2 e2e tests are `#[ignore]` (need Copilot auth + network)

When adding sandbox rules, add a unit test verifying the SBPL string.
When adding config options, add a merge test in `config.rs`.

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

## Docs

- [README.md](README.md) — usage, flags, troubleshooting
- [SECURITY.md](SECURITY.md) — threat model, attack analysis, defense layers
