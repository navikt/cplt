# Security

One Rust binary, and a dependency list short enough to read in a sitting (see `Cargo.toml`). No runtime services, no telemetry. Every security boundary is kernel-enforced and tested. Every design decision is documented with the threat it mitigates and the prior art it builds on.

**Our priorities, in order:**

1. **Correct.** Every claim is tested, and every edge case has a CVE or research reference.
2. **Transparent.** Read [SECURITY.md](../SECURITY.md). It hides nothing.
3. **Simple.** One static binary, zero config required, sane defaults.
4. **Useful.** Get out of the way and let the agent do its job, safely.

For the full security model, threat analysis, and test strategy, see **[SECURITY.md](../SECURITY.md)**.

## `~/.config/gh/hosts.yml` is readable

Copilot spawns `gh auth token` to authenticate, which reads `~/.config/gh/hosts.yml`. That file holds a GitHub OAuth token. cplt allows reading `hosts.yml` and `config.yml` only, not the rest of `.config/gh`, for these reasons.

- Auth needs it. Without `gh` auth, Copilot falls back to Keychain only, and many people rely on the `gh` CLI instead.
- The access is read-only. The sandbox cannot modify the token file.
- It is minimal. Only the two files `gh` actually reads are granted. Extensions, state, and everything else under `.config/gh` stay blocked.
- The token goes where it already goes. It is a GitHub token Copilot already sends to GitHub's API, so an attacker would have to exfiltrate it to a *different* server.
- The residual risk is real. A compromised Copilot could exfiltrate the token over port 443. Use `--deny-path ~/.config/gh` if that bothers you, and Copilot will use Keychain auth instead.

## Outbound network is port-restricted

This section describes the macOS Seatbelt profile; the Linux equivalents, and where they fall short, are in [Limitations](#linux) below. SBPL accepts only `*` or `localhost` as the host in a `remote ip` rule. There is no way to name an address or a range, and Copilot connects to CDN-backed endpoints whose IPs change (`api.business.githubcopilot.com`, `api.githubcopilot.com`, `proxy.business.githubcopilot.com`), so enumerating them was never an option either. What is left is the port.

- Only port 443 is allowed. Every other outbound TCP port is blocked at the kernel level.
- Localhost outbound is blocked on macOS, which keeps the agent away from local services such as databases and dev servers. Landlock has no localhost pinning, so this does not hold on Linux.
- The SSH agent is blocked on macOS. Unix socket access is denied, so loaded SSH keys cannot be used. On Linux it is not gated by Landlock below kernel 7.1; bubblewrap's private `/tmp` hides the stock OpenSSH socket, but a desktop agent under `$XDG_RUNTIME_DIR` stays reachable.
- Filesystem isolation is the primary control. Credentials are kernel-blocked whatever the network allows.
- The proxy is on by default, and logs and filters every outbound connection from Copilot, `gh`, and `curl` alike.
- `cplt config set allow.ports 8080` adds a port when you need one, for a dev server for example.

See [SECURITY.md](../SECURITY.md) for the full threat model and honest gaps.

## Limitations

### macOS

- **`sandbox-exec` is deprecated.** Apple has not removed it, but may in a future macOS version.
- **SBPL has no domain-based filtering.** The optional CONNECT proxy provides domain blocking.
- **Keychain access is required.** Copilot stores auth tokens in the macOS Keychain.
- **Proxy-forced mode gets full enforcement.** With `--proxy-forced` or `proxy.forced = true` ([#53](https://github.com/navikt/cplt/issues/53), opt-in, off by default), SBPL pins outbound egress to `localhost:<proxy_port>`. Seatbelt can pin to localhost, so there is **no residual** on macOS: no direct `:443` path exists, and neither raw sockets nor `env -u HTTPS_PROXY` can get around the proxy. It fails closed if the proxy cannot start, and conflicts with `--no-proxy`.

### Linux

- **Kernel 5.13+ is required.** Landlock LSM must be enabled (`cat /sys/kernel/security/lsm`).
- **TCP port filtering needs kernel 6.7+.** Older kernels get filesystem-only enforcement, and network security comes from the proxy alone.
- **Landlock network rules are TCP-only.** cplt handles `AccessNet::ConnectTcp` and nothing else, and Landlock's UDP support lands at ABI v10, above the v9 cplt requests. Outbound UDP to any host and port, and inbound UDP bind, are unrestricted at the kernel in every Linux mode **except `proxy.forced`**, where a seccomp rule permits only `SOCK_STREAM` with protocol 0 or `IPPROTO_TCP` for `AF_INET`/`AF_INET6` and so removes UDP, raw, SCTP and DCCP on any kernel. The CONNECT proxy carries TCP only, so UDP never reaches it: outside `proxy.forced`, DNS tunnelling, QUIC/HTTP-3 and plain UDP exfiltration have no cplt layer in front of them. macOS restricts UDP but does not route it either: `remote ip "*:443"` covers UDP as well as TCP, so in default mode QUIC/HTTP-3 on 443 leaves without touching the proxy there too. Only under `proxy.forced`, where the `*:443` allow is dropped and `(deny default)` closes the rest, is the macOS proxy log a complete record.
- **Unix socket connects are restricted only by bubblewrap below kernel 7.1.** Landlock gains that right at ABI v9 (kernel 7.1), which cplt now requests best-effort; seccomp cannot filter a path behind a pointer, and a read-only bubblewrap bind does not stop a `connect()`. Below 7.1 the bubblewrap mount masks over `$XDG_RUNTIME_DIR/bus`, `$XDG_RUNTIME_DIR/systemd`, `/run/dbus/system_bus_socket` and the container-daemon sockets are the whole of the protection, and they apply only when bubblewrap actually wraps the run. Any other socket whose path the agent can name is reachable: the SSH agent socket (only the withheld `SSH_AUTH_SOCK` stands in the way, and while bwrap's private `/tmp` hides the stock OpenSSH socket, a gnome-keyring/gcr or systemd agent sits at a fixed `$XDG_RUNTIME_DIR` path that stays visible), `/var/run/docker.sock`, the gpg-agent socket, `$XDG_RUNTIME_DIR/bus`. `--allow-socket` and `--allow-gpg-signing`'s socket rules therefore do nothing below 7.1, and become load-bearing from v9 up. Full detail in [Linux limitations](../SECURITY.md#linux-specific-limitations).
- **D-Bus reaches the session manager unless something masks it.** `XDG_RUNTIME_DIR` is on the env allowlist, so if `$XDG_RUNTIME_DIR/bus` is connectable (previous bullet) `systemd-run --user <cmd>` starts a unit **outside** Landlock, seccomp and the bwrap namespaces. From kernel 7.1 Landlock denies the `connect()`; below that, bubblewrap mount-masks `$XDG_RUNTIME_DIR/bus` and `$XDG_RUNTIME_DIR/systemd`, and with neither the path is open. Established by code reading rather than by running it on a host. Install bubblewrap, or run inside a container or VM, if this matters.
- **Landlock network rules are port-based only** and cannot tell localhost from a remote host. When `--allow-localhost-any` is set, kernel TCP connect filtering is **disabled entirely on Linux**: Landlock cannot express "any localhost port but no remote host", so *every* TCP-connect rule is dropped and an agent can raw-socket to any remote `host:port` and exfiltrate directly, not merely reach localhost. macOS still pins `localhost:*`. cplt emits a prominent warning. Prefer `--proxy-forced`, which supersedes this flag, or scope to specific ports with `--allow-localhost <PORT>` to keep kernel connect-restriction on.
- **Proxy-forced mode is only partial on Linux.** With `--proxy-forced` or `proxy.forced = true` ([#53](https://github.com/navikt/cplt/issues/53), opt-in, off by default), Landlock drops the `:443` rule and allows only the proxy port, which blocks direct TCP `:443` to any host and forces HTTPS through the CONNECT proxy. But Landlock is **port-based and cannot pin to localhost**, so a narrow `evil.com:<proxy_port>` channel stays reachable if a remote host answers on that exact port. Landlock itself gates **TCP only**, but the seccomp rule above closes UDP, raw, SCTP and DCCP in this mode, so the residual is the proxy-port channel rather than open UDP. Read it as "no direct TCP `:443` bypass", not "no egress except the proxy". Closing the residual needs a network namespace, tracked in [#114](https://github.com/navikt/cplt/issues/114). macOS has no such residual, because SBPL pins to `localhost:<proxy_port>`. It fails closed if the proxy cannot start, and conflicts with `--no-proxy`.
- **Gradle and the JVM on Linux.** The Gradle daemon uses ephemeral localhost ports. Use `--allow-localhost-any` or `cplt config set sandbox.allow_localhost_any true` to let the Gradle client and daemon talk. If JVM startup itself fails, add `--allow-tmp-exec` as well, for native library loading from the temp dir.
- **Landlock cannot deny subpaths within allowed paths.** Unlike macOS Seatbelt, it cannot deny `.env` reads or `.git/hooks` writes *inside* the project directory at the kernel level. For `.env`, the proxy blocks exfiltration as defense-in-depth. For `.git/hooks` and `.cplt.toml`, in the project directory and in every `allow.write` grant alike, **these stay writable on the Landlock-only path**. Env hardening (`GIT_CONFIG_NOSYSTEM`, injected `GIT_CONFIG_*`) only constrains git's config resolution for commands run *inside* the sandbox. It does **not** stop an agent planting a `.git/hooks/post-commit` that runs unsandboxed on the next `git` invocation. That direct file-planting vector is mitigated only when the Bubblewrap layer re-binds `.git/hooks` and `.cplt.toml` read-only. `.git/config` and `.gitmodules` stay writable even under bwrap, deliberately, since read-only binding them breaks legitimate `git config`, `remote`, and `submodule` operations and risks a stale `.git/config.lock`. So `core.hooksPath` remains a residual persistence path.
- **`--deny-path` has no effect.** Landlock is allowlist-only, and a runtime warning is emitted.
- **Some macOS flags do not apply.** `--allow-jvm-attach` and `--allow-cache-exec` emit warnings and are ignored on Linux. `--allow-docker` does apply now: it exempts the Docker and Podman daemon sockets from the bubblewrap mount masks and grants them in Landlock. `~/.docker` stays denied on Linux, so CLI contexts and registry auth are still unavailable.
- **No audit logs.** `--show-denials` is macOS-only. Use `strace -f -e trace=file,network` for debugging.
- **Auth is scoped to env plus the `gh` CLI.** No D-Bus or Secret Service integration for v1.
- **The Bubblewrap layer is optional defense-in-depth.** When `bwrap` is installed, or `--use-bubblewrap` / `sandbox.use_bubblewrap` is set, the sandbox also gets PID, IPC, UTS, cgroup, and user namespaces plus a private `/tmp`. Landlock and seccomp are applied inside the namespaces by a fail-closed re-entry helper, so the agent can never run unsandboxed. It also re-binds a **narrow** set of pre-existing git-persistence paths **read-only**: `.git/hooks` and `.cplt.toml` under **every writable root**, meaning the project and each `allow.write` grant, plus the resolved shared `.git`'s `hooks` for a worktree, where `<root>/.git` is a gitdir pointer file and the real hooks live in the common dir, or a bare repo, where hooks sit at `<root>/hooks`. That mitigates the direct `.git/hooks` file-planting vector the Landlock-only path leaves open. `.git/config` and `.gitmodules` are deliberately left writable, since read-only would break legitimate git config, remote, and submodule operations and risk a stale `.git/config.lock`.

  Three residuals. `core.hooksPath` set through the writable `.git/config` can still redirect hooks. Only paths that already exist at launch can be protected, so a `.cplt.toml` that does not exist yet can still be created. And submodule hooks (`.git/modules/<name>/hooks`) are covered only when the submodule itself is granted via `allow.write`, because its `.git` gitlink then resolves into the parent's `modules/<name>`, which gets the same protection. A submodule merely nested inside a granted parent is not covered, since only the grant root is resolved and never the subdirectories under it.

  Bubblewrap does **not** add a network namespace. The host network is shared so the filtering proxy keeps working, and kernel-level network isolation is tracked in [#114](https://github.com/navikt/cplt/issues/114). It does not hide the host filesystem either, which stays visible read-only with Landlock controlling access. Auto-detect falls back to Landlock-only with a warning when bwrap is missing or non-functional.

### Both platforms

- **No TLS inspection.** The proxy sees domain names through CONNECT, but not request bodies.
- **Parent-side git is hardened against repository-controlled program execution** ([#210](https://github.com/navikt/cplt/issues/210)). cplt runs `git` in the parent, *outside* the sandbox, with the working directory set to the project. The post-session audit, the `.cplt.toml` trust decision, trust identity, and sandbox path discovery all do this. Since `.git/config` stays writable to the agent on both platforms, see the Linux note above, a repository could otherwise choose a program that parent `git` executes unsandboxed.

  Every parent-side invocation now goes through `src/git.rs`, which clears inherited `GIT_*`, sets `GIT_CONFIG_NOSYSTEM`, `GIT_ATTR_NOSYSTEM`, `GIT_TERMINAL_PROMPT=0`, and `GIT_OPTIONAL_LOCKS=0`, and forces every executable config key it does not need to a safe value with `-c`: `core.fsmonitor`, `core.hooksPath`, `core.pager`, `core.editor`, `sequence.editor`, `core.sshCommand`, `core.gitProxy`, `core.alternateRefsCommand`, `credential.helper`, `uploadpack.packObjectsHook`, and `gpg.program`. `git diff` additionally gets `--no-textconv --no-ext-diff`.

  **Residual:** `filter.<name>.clean` and `.process` are named by an arbitrary subsection, so no fixed override can neutralize them. When the repository's own `local` or `worktree` scope config defines one, cplt **refuses** the working-tree queries instead, and the audit reports `incomplete` rather than a clean session it never verified. A committed `.cplt.toml` **still applies**, because it is read from the object store with `git cat-file`, which cannot reach a filter and is never refused. But its drift state reads as `Drifted` without the working tree having been compared, which also blocks the one-time `cplt trust accept`, since that approves only `Committed`. An agent can therefore force the audit to `incomplete` by writing `.git/config`. That is inherent to failing closed, since the only way to answer instead is to execute the filter. Filters in the user's `--global` config, `git lfs install` by default, are the user's own choice and do not trigger this. User-facing guidance is in [known-impacts.md](known-impacts.md#repo-local-git-content-filters-lfs-git-crypt). Global config is deliberately **not** blanked, because `cplt doctor` path discovery reads `core.hooksPath` and `commit.gpgsign` from it.

For known attack vectors, out-of-scope threats, and prior art, see [SECURITY.md](../SECURITY.md).
