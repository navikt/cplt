---
applyTo: "src/sandbox*.rs,src/proxy*.rs"
---

# Sandbox, environment, and proxy review instructions

## macOS Seatbelt (SBPL) rules

- **Operation specificity beats rule order.** In Seatbelt, a narrower operation such as `file-read-data` overrides a broader `(deny file-read*)` regardless of position in the profile. Emit automatic file grants before the deny block using `file-read*`, not `file-read-data`. Only explicit user-approved overrides belong after the deny block.
- **SBPL string escaping.** Every path or string interpolated into SBPL expressions must pass through `escape_sbpl_path` and path validation so quotes, backslashes, and control characters cannot inject SBPL directives.
- **Localhost outbound rules.** `--allow-localhost-any` must scope outbound rules to `"localhost:*"`, never `"*:*"`.

## Linux Landlock, seccomp, and bubblewrap parity

- **Unified tool directory table.** `HOME_TOOL_DIRS` in `src/sandbox_policy.rs` is a single list covering both macOS `Library/*` paths and Linux XDG paths. Do not create platform-specific duplicates.
- **Subdirectory deny limitations.** Landlock is purely additive and cannot carve out a denied child path inside a granted parent directory without a bubblewrap mount mask. When adding a deny rule in `src/sandbox_policy.rs` or `src/sandbox_profile.rs`, verify how `src/sandbox_landlock.rs` and `src/sandbox_bubblewrap.rs` enforce it, or document the limitation with `LinuxCoverage::Gap(reason)`.

## Environment variable hardening

- **Allowlist discipline.** `ENV_ALLOWLIST` is the only set of ambient variables copied into the sandbox by default. Do not add tokens, cloud credentials, or runtime code-injection variables.
- **Interpreter and linker injection.** Any pass-through or merge logic for variables like `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`, `PYTHONSTARTUP`, `RUBYOPT`, `PERL5OPT`, `DOTNET_STARTUP_HOOKS`, `LD_*`, or `DYLD_*` must strip execution primitives before entering the sandbox.

## HTTP CONNECT proxy

- **DNS rebinding prevention.** When dialing a target host without an upstream proxy, resolve DNS once, validate every resolved IP against private, loopback, link-local, and metadata ranges after normalizing with `to_canonical()`, and connect directly to the verified `SocketAddr` list. Never pass the unverified hostname back to `TcpStream::connect`.
