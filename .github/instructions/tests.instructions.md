---
applyTo: "tests/**/*.rs,src/**/*.rs"
---

# Test isolation and coverage review instructions

## Subprocess and environment isolation

- **Use `tests/common/mod.rs` helpers.** Never spawn `cplt` or `git` in `tests/` with raw `Command::new`. Use `cplt_cmd()` so `CPLT_CONFIG` is isolated from the developer's machine, `git_cmd(dir)` so host git config and GPG signing cannot break fixtures, and `temp_repo(remote)` whenever a test depends on the repository's `origin` remote.
- **No executable fixtures in `/tmp` or `/var/folders`.** The sandbox blocks execution under `/tmp` and `/var/folders` by design. Tests that execute temporary binaries or scripts inside the sandbox must create their temporary directory under the project tree via `project_temp_dir()`.
- **Clean working tree.** Tests must write all artifacts into `TempDir`-scoped directories that clean up on drop so `git status --porcelain` stays empty after the suite finishes.

## Required test tiers for security changes

- **Sandbox policy changes.** Require both a unit test asserting the SBPL or Landlock policy output and a kernel integration test in `tests/integration.rs` or `tests/integration_linux.rs` proving the kernel enforces the rule.
- **Untrusted file reads.** Any parent-side code reading from an agent-writable directory must have a test that plants a symlink and a FIFO (`mkfifo`) at the target path and verifies both are rejected without blocking or following the link.
- **Config and grant changes.** Every new config key or CLI flag needs a test that fails if the setting stops taking effect at runtime.
