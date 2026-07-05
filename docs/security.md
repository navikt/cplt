# Security

~2500 lines of Rust. Four dependencies (clap, libc, serde, toml). No runtime services, no telemetry. Every security boundary is kernel-enforced and tested. Every design decision is documented with the threat it mitigates and the prior art it builds on.

**Our priorities, in order:**

1. **Correct** — every claim is tested, every edge case has a CVE or research reference
2. **Transparent** — read [SECURITY.md](../SECURITY.md), it hides nothing
3. **Simple** — single static binary, zero config required, sane defaults
4. **Useful** — get out of the way and let Copilot do its job, safely

For the full security model, threat analysis, and test strategy, see **[SECURITY.md](../SECURITY.md)**.

## `~/.config/gh/hosts.yml` is readable

Copilot spawns `gh auth token` to authenticate. This reads `~/.config/gh/hosts.yml` which contains a GitHub OAuth token. We allow reading only `hosts.yml` and `config.yml` (not the entire `.config/gh` directory) because:

- **Required for auth**: Without `gh` auth, Copilot falls back to Keychain only. Many users rely on `gh` CLI for auth.
- **Read-only**: The sandbox cannot modify the token file.
- **Minimal access**: Only the two files `gh` actually reads — extensions, state, and other gh data are blocked.
- **Same-destination token**: The token is a GitHub token that Copilot already sends to GitHub's API. An attacker would need to exfiltrate it to a *different* server.
- **Risk**: A compromised Copilot could exfiltrate this token via port 443. Use `--deny-path ~/.config/gh` if this concerns you (Copilot will use Keychain auth instead).

## Outbound network is port-restricted

SBPL (Seatbelt Profile Language) does not support wildcard port filtering by IP range. Copilot connects to multiple CDN-backed endpoints with changing IPs (`api.business.githubcopilot.com`, `api.githubcopilot.com`, `proxy.business.githubcopilot.com`). We cannot enumerate these IPs. Therefore:

- **Only port 443 (HTTPS) is allowed** — all other outbound TCP ports are blocked at the kernel level
- **Localhost outbound is blocked** — prevents access to local services (databases, dev servers, etc.)
- **SSH agent is blocked** — unix socket access is denied, preventing use of loaded SSH keys
- **Filesystem isolation is the primary control** — credentials are kernel-blocked regardless of network
- **The proxy is on by default** — logs and filters all outbound connections (Copilot, gh, curl)
- **Use `cplt config set allow.ports 8080`** to add extra ports when needed (e.g., for a dev server)

See [SECURITY.md](../SECURITY.md) for the full threat model and honest gaps.

## Limitations

### macOS

- **`sandbox-exec` is deprecated** — Apple has not removed it but may in future macOS versions
- **SBPL has no domain-based filtering** — the optional CONNECT proxy provides domain blocking
- **Keychain access required** — Copilot stores auth tokens in macOS Keychain

### Linux

- **Kernel 5.13+ required** — Landlock LSM must be enabled (`cat /sys/kernel/security/lsm`)
- **TCP port filtering requires kernel 6.7+** — older kernels get filesystem-only enforcement; network security via proxy only
- **Landlock network rules are port-based only** — cannot distinguish localhost from remote. When `--allow-localhost-any` is set, kernel TCP connect filtering is disabled entirely (the proxy still enforces domain filtering and port restrictions for remote connections)
- **Gradle/JVM on Linux** — Gradle daemon uses ephemeral localhost ports. Use `--allow-localhost-any` or `cplt config set sandbox.allow_localhost_any true` to allow Gradle client↔daemon communication. If JVM startup itself fails, also add `--allow-tmp-exec` (native lib loading from temp)
- **Landlock cannot deny subpaths within allowed paths** — unlike macOS Seatbelt, Landlock cannot deny `.env` reads or `.git/hooks` writes *inside* the project directory at the kernel level. Defense-in-depth comes from the proxy (blocks exfiltration) and env hardening (`GIT_CONFIG_NOSYSTEM`, etc.)
- **`--deny-path` has no effect** — Landlock is allowlist-only; a runtime warning is emitted
- **Some macOS flags are not applicable** — `--allow-docker`, `--allow-jvm-attach`, `--allow-cache-exec` emit warnings and are ignored on Linux
- **No audit logs** — `--show-denials` is macOS-only; use `strace -f -e trace=file,network` for debugging
- **Auth scoped to env + gh CLI** — no D-Bus/Secret Service integration for v1
- **Bubblewrap layer is optional defense-in-depth** — when `bwrap` is installed (or `--use-bubblewrap`/`sandbox.use_bubblewrap` is set), the sandbox additionally gets PID/IPC/UTS/cgroup/user namespaces and a private `/tmp`; Landlock + seccomp are applied inside the namespaces by a fail-closed re-entry helper (the agent can never run unsandboxed). It does **not** add a network namespace (host network is shared so the filtering proxy keeps working — kernel-level network isolation is tracked in [#114](https://github.com/navikt/cplt/issues/114)) and does not hide the host filesystem (visible read-only; Landlock controls access). Auto-detect falls back to Landlock-only with a warning if bwrap is missing or non-functional

### Both platforms

- **No TLS inspection** — the proxy sees domain names (via CONNECT) but not request bodies

For known attack vectors, out-of-scope threats, and prior art, see [SECURITY.md](../SECURITY.md).
