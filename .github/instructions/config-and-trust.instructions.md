---
applyTo: "src/config/**/*.rs,src/repo_config.rs,src/trust.rs,src/settings.rs"
---

# Configuration, repo config, and trust store review instructions

## Untrusted `.cplt.toml` and trust store

- **Single-read hashing and parsing.** `.cplt.toml` lives in the untrusted project worktree. Read it once via `untrusted::read_untrusted`, hash those exact bytes for `src/trust.rs`, and parse the same buffer. Never re-read `.cplt.toml` from disk after checking or recording trust.
- **Validation parity across entry points.** Every key or path accepted in `.cplt.toml`, `src/settings.rs`, or `cplt config set` must run through the same path and policy validation in `src/config/validation.rs`. Do not allow `.cplt.toml` or the TUI to bypass `--force` requirements or protected-path checks enforced by `cplt config set`.
- **Terminal output sanitization.** Strip control characters and terminal escape sequences when rendering untrusted strings from `.cplt.toml` in trust prompts, `cplt status`, or error messages.

## Config registry and resolution

- **Validate at write time.** Refuse invalid grants, relative paths where absolute or home-relative paths are required, and contradictory settings at `cplt config set` time before they reach disk.
- **Every registered key needs a consumer.** Do not add a key to `src/config/registry.rs` unless `Resolved` consumes it and a test verifies its runtime effect.
- **Precedence invariant.** CLI flags override user config, which overrides presets, which override secure defaults. Explicit grants such as `--pass-env` must never be silently cancelled by broader flags such as `--inherit-env`.
