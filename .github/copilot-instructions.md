# Copilot instructions for cplt

`cplt` is a kernel-enforced sandbox for AI coding agents using macOS Seatbelt (SBPL) and Linux Landlock, seccomp-BPF, and optional bubblewrap, paired with a local HTTP CONNECT proxy and `gh`/`git` command guards.

## Core security invariants

- **Hostile filesystem boundary.** `cplt` runs outside the sandbox. Treat every path the sandboxed agent can write as hostile, including the project directory, `.git`, the per-session scratch directory, agent config/state/data directories, and `cplt`'s cache.
- **Untrusted file reads.** Never read agent-writable paths on the parent side with `std::fs::read_to_string`, `std::fs::read`, or `File::open`. Use `untrusted::read_untrusted(path, limit)` or `untrusted::open_untrusted(path)` with a bounded read so symlinks and FIFOs are rejected. Before passing an agent-writable path to a subprocess, check `symlink_metadata(path)` and `.file_type().is_file()`, because `Path::is_file()` follows symlinks.
- **Hardened subprocess spawning.** `std::process::Command::new` is a disallowed method in `clippy.toml`. Parent-side code must invoke git through `git::trusted_git()` and other host binaries through `git::trusted_binary()`. Only add `#[allow(clippy::disallowed_methods)]` with a comment when the binary path is already resolved or the command deliberately resolves `PATH` inside the sandbox.
- **No silent grants.** A grant, restriction, config key, or CLI flag that cannot be honored must fail loudly at the earliest point, preferring `config set` over config resolution over launch. Never accept a setting and silently drop it on one backend. Platform enforcement differences must be declared via `LinuxCoverage::Gap(reason)` in the policy tables.
- **Staged rollout.** Changes that can break existing setups need an automatic fallback, a documented one-step recovery, or a default-off config key tracked in issue `#264`. When gated behind a default-off key, generated profiles with the key unset must remain byte-identical.

## Code style and review priorities

- Prioritize security bypasses, macOS vs Linux enforcement drift, symlink or TOCTOU races, parser discrepancies, and missing tests over minor style preferences.
- Prefer `&str` and `&[T]` over owned types in function signatures.
- Security-critical changes must include doc comments explaining the security rationale and update `SECURITY.md` when the threat model or defense layers change.
