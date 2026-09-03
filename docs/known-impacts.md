# Known impacts

The sandbox is kernel-enforced, so **all restrictions apply to every process spawned inside it**: dev servers, test runners, build tools, package managers. That is deliberate, since a sandboxed agent could otherwise escape by spawning a child process. It does affect some workflows.

## `.env` file blocking

`.env*`, `.pem`, `.key`, `.p12`, `.pfx`, `.jks` files in the project directory are **blocked from reading** by default. This stops a rogue agent exfiltrating secrets, but it has side effects:

| Operation                      | Impact     | Why                                                                   |
| ------------------------------ | ---------- | --------------------------------------------------------------------- |
| `npm install`                  | ✅ Works    | Does not read `.env` files                                            |
| `cargo build`, `go build`      | ✅ Works    | Does not read `.env` files                                            |
| `next build` / `next dev`      | ⚠️ May fail | Next.js auto-loads `.env`, `.env.local`, `.env.production` at startup |
| `npm run dev` (Node.js)        | ⚠️ May fail | Apps using `dotenv` to load config will get `undefined` env vars      |
| `npm test` / `vitest`          | ⚠️ May fail | Tests that depend on `.env` for config won't find the values          |
| TLS dev servers (`.pem` certs) | ⚠️ Blocked  | Local HTTPS certs in `.pem`/`.key` files can't be read                |
| `.env.example`                 | ⚠️ Blocked  | Matches the `.env.*` pattern; use `--allow-env-files` if needed       |
| Writing `.env` files           | ✅ Works    | Only read is denied; Copilot can create `.env` from templates         |

**Fix:**

```bash
cplt config set sandbox.allow_env_files true
```

Or for a single run: `cplt --allow-env-files -- -p "start the dev server"`

## Relative paths in `.cplt.toml` now bite (behaviour change)

A relative path in a repo `.cplt.toml`, say `deny.paths = ["target"]` or `propose.allow.read = ["vendor"]`, used to be **silently unenforced**. macOS compiled it into the profile as a rule that matched nothing, and Linux dropped it. It is now resolved against the repository root and enforced for real.

If your repo already ships one, it starts working on upgrade, and a deny entry that was previously inert will now block a directory that actually exists:

| Entry that was inert                | What it does now                       |
| ----------------------------------- | -------------------------------------- |
| `deny.paths = ["target"]`           | blocks the Rust build dir, so builds fail |
| `deny.paths = [".git"]`             | blocks git entirely                     |
| `deny.paths = ["node_modules"]`     | blocks installs and `node` resolution   |

**Check before upgrading:**

```bash
cplt --print-profile | grep 'deny file-read'
```

**Fix:** remove the entry from `.cplt.toml`, or narrow it to the path you actually meant. Paths that do not exist yet are kept (macOS enforces them once created), so an entry naming a future directory is not an error.

## Lifecycle scripts (postinstall hooks)

npm/yarn/pnpm lifecycle scripts are **blocked by default** via `npm_config_ignore_scripts=true` and `YARN_ENABLE_SCRIPTS=false`. This stops supply chain attacks through postinstall hooks, but it may break packages that need a post-install step:

| Operation                        | Impact      | Why                                                            |
| -------------------------------- | ----------- | -------------------------------------------------------------- |
| `npm install` (download only)    | ✅ Works     | Packages are downloaded and extracted normally                 |
| `npm install` (with native deps) | ⚠️ May fail  | Packages like `node-gyp`, `sharp`, `bcrypt` need postinstall  |
| `npm run build` / `npm test`     | ✅ Works     | Explicit scripts are not blocked, only lifecycle hooks         |
| `yarn install` (Yarn Berry)      | ⚠️ May fail  | If packages have install scripts                               |

**Fix:**

```bash
cplt config set sandbox.allow_lifecycle_scripts true
```

Or for a single run: `cplt --allow-lifecycle-scripts -- -p "install dependencies"`

<a id="temp-dir-exec"></a>

## Temp dir execution (go test, mise, node-gyp)

Tools that compile then execute from `$TMPDIR` are **blocked by default**, because the sandbox denies `process-exec` and `file-map-executable` from `/private/tmp` and `/private/var/folders`. This affects:

| Tool                      | Impact      | Why                                                                   |
| ------------------------- | ----------- | --------------------------------------------------------------------- |
| `go test`                 | ❌ Blocked   | Compiles test binaries to `$TMPDIR`, then executes them               |
| `go run`                  | ❌ Blocked   | Compiles to `$TMPDIR` then executes, same as `go test`                |
| `go generate`             | ❌ Blocked   | If the generator is a Go binary compiled to `$TMPDIR`                 |
| `mise run` (inline tasks) | ❌ Blocked   | Writes script to temp file, then executes it                          |
| `node-gyp` (native addons)| ❌ Blocked  | Compiles C/C++ to temp, then loads via dlopen                         |
| `go build`                | ✅ Works     | Output binary goes to project dir or `$GOBIN`, not `$TMPDIR`         |
| `cargo test`              | ✅ Works     | Rust builds in `target/`, not `$TMPDIR`                               |
| `npm test` / `vitest`     | ✅ Works     | JavaScript runs via interpreter, not compiled to temp                 |

**Fix:** the scratch dir is **on by default**. cplt creates `~/Library/Caches/cplt/tmp/{session-id}/` with `rwx` permissions, redirects `TMPDIR`, `TMP`, `TEMP`, and `GOTMPDIR` there, and cleans up on exit. Stale directories older than 24 hours are garbage-collected on startup.

**JVM note:** on macOS the JVM ignores `TMPDIR`. It reads `java.io.tmpdir` from `confstr(_CS_DARWIN_USER_TEMP_DIR)`, which always returns `/var/folders/...`. So cplt injects `-Djava.io.tmpdir=<scratch> -Djansi.tmpdir=<scratch> -Djava.rmi.server.hostname=localhost -Djava.net.preferIPv4Stack=true` via `JAVA_TOOL_OPTIONS`, which puts Maven Surefire forks, the Kotlin compiler daemon, and Jansi native lib extraction on the scratch dir. The RMI hostname flag keeps the Kotlin daemon's Java RMI traffic on `localhost`. The `preferIPv4Stack` flag forces pure IPv4 sockets, because Java's dual-stack IPv6 sockets produce IPv4-mapped addresses that SBPL cannot match, which breaks the sandbox's localhost filtering. Override with `--pass-env JAVA_TOOL_OPTIONS` if you need custom JVM flags. For inline mocking (MockK, Mockito, ByteBuddy), also add `--allow-jvm-attach`. See [JVM Attach API](#jvm-attach-api).

**Gradle/JVM still failing?** Some JVM native libraries, `libjli.dylib` and JNI libs among them, call `dlopen` on the system temp dir *before* `JAVA_TOOL_OPTIONS` takes effect. If you see "Operation not permitted" during JVM startup itself rather than during the Gradle build, add `--allow-tmp-exec`:

```bash
# Recommended for Gradle projects (localhost + tmp exec + JVM attach):
cplt --allow-localhost-any --allow-tmp-exec --allow-jvm-attach -- -p "run tests"

# Or set permanently:
cplt config set sandbox.allow_localhost_any true
cplt config set sandbox.allow_tmp_exec true
cplt config set sandbox.allow_jvm_attach true
```

**Kotlin daemon on Linux:** the Kotlin compiler daemon writes marker files to `~/.local/share/kotlin/daemon/` and talks over localhost. If you see `AccessDeniedException: .../kotlin-daemon-client-tsmarker*.tmp`, cplt grants write access to `~/.local/share/kotlin/` automatically. If the daemon still cannot connect and falls back to non-daemon compilation with garbled Unicode paths, set `--allow-localhost-any`, because the daemon uses ephemeral ports:

```bash
# Recommended for Kotlin/Gradle on Linux:
cplt config set sandbox.allow_localhost_any true
cplt config set sandbox.allow_jvm_attach true

# If you need additional write paths (e.g. custom Kotlin data dir):
cplt config set allow.write "~/.local/share/kotlin"
```

If you still see this error, check that you have not set `scratch_dir = false` in your config:

```bash
cplt config explain sandbox.scratch_dir
```

## Cache exec (Playwright, pnpm dlx, etc.)

Some tools unpack and execute binaries straight out of `~/Library/Caches` (macOS) or `~/.cache` (Linux), which is exec-blocked by default:

| Tool | Cache path | Fix |
|---|---|---|
| Playwright (browsers) | `~/Library/Caches/ms-playwright/` · `~/.cache/ms-playwright/` | `--allow-cache-exec ms-playwright` |
| pnpm dlx | `~/Library/Caches/pnpm/dlx/` · `~/.cache/pnpm/dlx/` | `--allow-cache-exec pnpm/dlx` |

**Fix:**

```bash
cplt config set sandbox.allow_cache_exec ms-playwright
cplt config set sandbox.allow_cache_exec pnpm/dlx
```

Or for a single run: `cplt --allow-cache-exec ms-playwright --allow-cache-exec pnpm/dlx`

`--allow-cache-exec-any` opens exec for the entire cache tree (`~/Library/Caches` on macOS, `~/.cache` on Linux). Last resort only.

> **Playwright on Linux:** also run Chromium with its own sandbox disabled
> (`chromiumSandbox: false`, or launch with `--no-sandbox`). cplt's seccomp filter
> blocks the `unshare`/`setns` syscalls Chromium's nested namespace sandbox needs,
> and cplt's Landlock + seccomp is the enforcing boundary, so the nested sandbox is
> redundant. The cache-exec subdir is validated to be traversal-free before a
> Landlock execute rule is granted.

## Localhost blocking

Localhost outbound is blocked by default on macOS, so sandboxed processes cannot connect to local services. On Linux, Landlock rules are port numbers only and cannot pin to localhost, so a local service on an allowed port is reachable; use `--with-proxy` for SSRF protection, and see [Linux limitations](../SECURITY.md#linux-specific-limitations).


| Operation                      | Impact            | Why                                                  |
| ------------------------------ | ----------------- | ---------------------------------------------------- |
| `npm install` (registry)       | ✅ Works           | Uses HTTPS to `registry.npmjs.org:443`               |
| `gradle build` (Maven Central) | ✅ Works           | Uses HTTPS to `repo1.maven.org:443`                  |
| Gradle daemon (ephemeral port) | ❌ Blocked         | Use `--allow-localhost-any` (daemon uses random ports) |
| Gradle/JVM startup (native libs)| ❌ Blocked        | Use scratch dir (default) or `--allow-tmp-exec`, see [JVM note](#temp-dir-execution-go-test-mise-node-gyp) |
| Local PostgreSQL (`:5432`)     | ❌ Blocked         | Use `--allow-localhost 5432`                         |
| Local Redis (`:6379`)          | ❌ Blocked         | Use `--allow-localhost 6379`                         |
| Local Kafka (`:9092`)          | ❌ Blocked         | Use `--allow-localhost 9092`                         |
| MCP servers                    | ❌ Blocked         | Use `--allow-localhost 3000`                         |
| Local API/dev server           | ❌ Blocked         | Use `--allow-localhost 8080`                         |
| Spring Boot (`:8080`)          | ❌ Blocked         | Use `--allow-localhost 8080`                         |
| Next.js/Turbopack build        | ❌ Workers blocked | Use `--allow-localhost-any` (random ephemeral ports) |

**Fix:** use `cplt config set allow.localhost <PORT>` for specific services, or `cplt config set sandbox.allow_localhost_any true` for build tools that pick random ports (Next.js, Vite, esbuild).

## App/build can't reach the network under cplt

When the proxy is on (the default), cplt injects the standard `HTTP(S)_PROXY` env vars so agent traffic can be filtered and logged, and **every** process inherits them: your app, your build, your tests, not just the agent. So when something reaches the network fine outside cplt but times out under it, the cause is usually the HTTP client mishandling those vars, or a domain or port that really is blocked, not cplt refusing all traffic. Some client versions have shipped proxy-handling regressions, so check for a newer patch release.

cplt does not restrict outbound *domains* by default, but the proxy still enforces the port policy, the private-IP and localhost safeguards, and any configured allowlist or blocklist. To see what happened, run with the proxy log (`--proxy-log <file>` or `--proxy-log-level all`) and look for `BLOCKED` lines. If nothing was blocked, the request left cplt and the fault is client-side. `BLOCKED-*` lines mean a port or a configured list stopped it, a policy question rather than a client bug.

## Docker and Testcontainers

Docker is **intentionally blocked**. `~/.docker` is denied, and on macOS the Docker socket is not reachable, since `(deny default)` covers `network-outbound` to unix sockets. Docker gives near-root access to the host system, which defeats the purpose of sandboxing.

**On Linux it depends on bubblewrap.** Unix socket `connect()` is not gated by Landlock before ABI v9 (kernel 7.1), and a read-only bwrap bind does not stop a `connect()` either, so the only thing that removes the daemon socket on a current kernel is bubblewrap's mount mask over `/run/docker.sock`, `/var/run/docker.sock`, `/run/user/<uid>/docker.sock`, `/run/user/<uid>/podman` and `/run/podman`. Without bubblewrap an agent that can speak HTTP over the socket has near-root access to the host. `--allow-docker` lifts those masks and grants the sockets in Landlock (it is no longer ignored on Linux); `~/.docker` stays denied either way, so CLI contexts and registry auth remain unavailable. See [Linux limitations](../SECURITY.md#linux-specific-limitations).

- Docker commands, `docker compose`, and Testcontainers will fail
- Local databases via Docker Compose need `--allow-localhost <PORT>` for the exposed port (the database container runs outside the sandbox)
- Consider running database/Kafka containers before starting cplt, then use `--allow-localhost` for the ports

**Opting in (⚠️ dangerous):** if you understand the risks (container mounts bypass the sandbox entirely), you can allow Docker access:

```bash
cplt config set sandbox.allow_docker true
# or per-session:
cplt --allow-docker
```

## SSH agent blocking

SSH agent access is blocked on macOS (the agent socket is not reachable — the profile's `(deny default)` covers `network-outbound` to unix sockets) and `SSH_AUTH_SOCK` is stripped from the environment on both platforms. Which means:

- `git clone` over SSH fails. Use HTTPS clones instead
- `ssh` commands spawned by the agent fail
- `gh` CLI uses HTTPS by default and is unaffected

**Linux caveat — this is not kernel-enforced below kernel 7.1.** Landlock gains the unix-socket `connect()` right only at ABI v9, and the SSH agent socket is not in the set bubblewrap masks (see [Linux limitations](../SECURITY.md#linux-specific-limitations)), so the withheld `SSH_AUTH_SOCK` is the whole barrier: without bubblewrap `/tmp` is readable, so `ls /tmp/ssh-*/agent.*` finds a stock OpenSSH socket and `SSH_AUTH_SOCK=... ssh-add -l` uses the loaded keys. bubblewrap's private `/tmp` hides that one, but not a gnome-keyring or systemd agent at a fixed `$XDG_RUNTIME_DIR` path.

Bubblewrap's private `/tmp` helps only for that stock layout. The desktop agents put their socket under `$XDG_RUNTIME_DIR` — `gcr/ssh` (gnome-keyring), `keyring/ssh`, `openssh_agent` (systemd) — a fixed path under `/run/user/<uid>` that bwrap's read-only bind of `/` leaves visible and that needs no enumeration. On GNOME or KDE, bwrap adds nothing here.

If your keys must be unusable by a compromised agent on Linux, unload them (`ssh-add -D`) before starting the session.

## D-Bus and systemd (Linux) — the session manager is reachable

`XDG_RUNTIME_DIR` is on the environment allowlist, and Landlock cannot restrict `connect()` to a pathname unix socket before ABI v9 (kernel 7.1), so on a current kernel `$XDG_RUNTIME_DIR/bus` is reachable from inside the sandbox unless bubblewrap masks it. This is established by reading the code, not by running it on a host — treat it as reachable rather than demonstrated. `systemd-run --user <cmd>` hands the command to the user's systemd instance, which starts it as a new unit **outside** Landlock, seccomp and the bubblewrap namespaces. The same applies to any other D-Bus service on the session bus that can start a process.

- **With bubblewrap** (the default when `bwrap` is installed) `$XDG_RUNTIME_DIR/bus`, `$XDG_RUNTIME_DIR/systemd` and `/run/dbus/system_bus_socket` are mount-masked, which closes this path
- **Without it** — not installed, `--no-bubblewrap`, or an auto-detect fallback at spawn time — nothing closes it below kernel 7.1
- From kernel 7.1 (Landlock ABI v9) the `connect()` is denied outright, bubblewrap or not
- If your threat model needs it closed today, install bubblewrap, or run cplt inside a container or VM

## UDP is unrestricted outside proxy-forced (Linux)

Landlock gates UDP only at ABI v10 and cplt handles TCP connect alone, so outbound UDP to any host and port — and inbound UDP bind — is unrestricted at the kernel in every Linux mode except `proxy.forced`. The CONNECT proxy carries TCP only, so UDP traffic never reaches it and never appears in the proxy log.

- Under **`proxy.forced`** a seccomp rule permits only `SOCK_STREAM` with protocol 0 or `IPPROTO_TCP` for `AF_INET`/`AF_INET6`, which removes UDP, raw, SCTP and DCCP on any kernel. Anything that opens such a socket gets `EPERM` from `socket()`, not just code that sends UDP: the JDK enumerates interfaces via `socket(AF_INET, SOCK_DGRAM, 0)` + `SIOCGIFCONF` and throws `SocketException`, which Gradle propagates (already moot under `proxy.forced`, where the port lock breaks Gradle anyway). seccomp cannot see the destination address at `socket(2)`, so no loopback exemption is possible
- Outside `proxy.forced` the rule is deliberately not applied — denying `SOCK_DGRAM` would break `getaddrinfo(3)`, and so all DNS, for every non-proxied tool
- DNS tunnelling, QUIC/HTTP-3, and plain UDP exfiltration are not covered by any cplt layer on Linux outside `proxy.forced`
- The proxy log is therefore not a complete record of what left the machine on Linux
- macOS restricts UDP but does not route it through the proxy either: `remote ip "*:443"` covers UDP as well as TCP, so in default mode QUIC/HTTP-3 on 443 leaves without being logged there too. Only under `proxy.forced`, where the `*:443` allow is dropped and `(deny default)` closes the rest, is the macOS proxy log complete

## macOS protected folders (Desktop, Documents)

macOS TCC (Transparency, Consent, and Control) protects certain folders at the kernel level. Without Full Disk Access, Copilot CLI cannot reach `~/Desktop` or `~/Documents` **with or without cplt**. That is a macOS restriction, not a sandbox limitation, and the cplt sandbox stays fully active either way.

| Path | Without FDA | With FDA | Notes |
| ---- | :---: | :---: | --- |
| `~/Desktop` | ❌ | ✅ | TCC-protected |
| `~/Documents` | ❌ | ✅ | TCC-protected |
| `~/Downloads` | ✅ | ✅ | Less restrictive TCC policy |
| Dragged screenshots | ❌ | ✅ | `TemporaryItems/NSIRD_*` are per-process isolated |

**Fix: grant Full Disk Access to your terminal** (recommended):

1. Open **System Settings → Privacy & Security → Full Disk Access**
2. Enable your terminal app (Terminal.app, iTerm2, Ghostty, etc.)
3. **Restart the terminal.** TCC grants only take effect for new processes

This lifts TCC restrictions for all child processes, while the cplt sandbox keeps enforcing its own deny-by-default rules (write protection, network filtering, dotfile access, etc.).

**Alternatives** (if you prefer not to grant FDA):

1. **Copy files into your project**:
   ```bash
   cp ~/Desktop/screenshot.png .
   ```

2. **Use a non-protected folder** for screenshots:
   ```bash
   defaults write com.apple.screencapture location ~/Screenshots
   mkdir -p ~/Screenshots
   ```
   Then add to config:
   ```toml
   [sandbox]
   allow_read = ["~/Screenshots"]
   ```

## Git workflow (commit & push)

Git commit and push **work out of the box** over HTTPS, no extra flags needed.

**Prerequisites:**

1. **Use HTTPS remotes** (not SSH). Check with `git remote -v`:
   ```bash
   # If you see git@github.com:org/repo.git, switch to HTTPS:
   git remote set-url origin https://github.com/org/repo.git
   ```
   Or rewrite globally for all repos (no remote changes needed):
   ```bash
   git config --global url."https://github.com/".insteadOf "git@github.com:"
   ```
   Git then uses HTTPS transparently even when remotes are configured as SSH. The rewrite is read from `~/.gitconfig`, which is readable inside the sandbox.
2. **Authenticate with `gh`.** cplt allows the agent to read `gh auth token`:
   ```bash
   gh auth login   # one-time setup outside the sandbox
   ```
3. **Configure git credential helper** (if not already set by `gh auth setup-git`):
   ```bash
   gh auth setup-git   # sets credential.helper to use gh
   ```

That's it. The agent can now `git add`, `git commit`, `git push`, create branches, and fetch, all inside the sandbox.

**Optional, signed commits:** add `--allow-gpg-signing` (see [GPG signing](#gpg-commit-signing)).

> **Why is SSH blocked?** The SSH agent socket gives access to *all* loaded keys, which could authenticate to any host. HTTPS with `gh auth token` is scoped to GitHub only. See [SSH agent blocking](#ssh-agent-blocking).

> **Tip:** protect your `main` branch with [branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-a-branch-protection-rule/about-branch-protection-rules) so the agent cannot push directly to main or force-push. Good practice regardless of cplt.

## Git restrictions

Some git operations are blocked to prevent persistence attacks that would survive the sandbox session:

| Operation                          | Impact      | Why                                                               |
| ---------------------------------- | ----------- | ----------------------------------------------------------------- |
| `git add/commit/status/diff/log`   | ✅ Works     | Local operations, no writes to protected paths                    |
| `git checkout/merge/rebase/branch` | ✅ Works     | Branch operations work normally                                   |
| `git fetch/pull/push` (HTTPS)      | ✅ Works     | Port 443 allowed, `gh auth token` provides credentials            |
| `git fetch/pull/push` (SSH)        | ❌ Blocked on macOS | SSH agent socket denied, use HTTPS. On Linux only `SSH_AUTH_SOCK` is withheld |
| `git config` (local)               | ❌ Blocked on macOS | `.git/config` is write-protected on macOS, which prevents `url.*.insteadOf` hijacking. Landlock cannot deny a file inside a writable root, so it stays writable on Linux |
| `git config --global`              | ❌ Blocked   | Git config and `~/.gitignore_global` are read-only                 |
| `git remote set-url`               | ❌ Blocked on macOS | Writes to `.git/config`, which stays writable on Linux |
| `git submodule add`                | ❌ Blocked on macOS | `.gitmodules` is write-protected on macOS. Writable on Linux, same Landlock limit (supply chain vector) |
| Creating git hooks                 | ❌ Blocked   | `.git/hooks/` is write-protected in the project and in every `allow.write` grant, hooks run unsandboxed. On Linux this needs the Bubblewrap layer, see [security.md](security.md) |
| Signed commits/tags                | ❌ Disabled  | `commit.gpgsign` and `tag.gpgsign` overridden to `false` via env; use `--allow-gpg-signing` to enable |

**Global git hooks:** if `core.hooksPath` is set in `~/.gitconfig`, cplt auto-detects the hooks directory and allows reading it so git operations succeed. Write access is explicitly denied, to stop persistence attacks. The hooks path must be under `$HOME` with at least 3 path components (`~/.config/git/hooks`, for instance) to keep the read grant from being overly broad.

**Commit signing:** `~/.ssh` and `~/.gnupg` are blocked, so GPG/SSH signing would fail. Rather than open private key directories, cplt injects `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_N`/`GIT_CONFIG_VALUE_N` env vars that disable `commit.gpgsign` and `tag.gpgsign` inside the sandbox. Commits made by Copilot are unsigned, which is expected since users typically re-sign on merge or squash. Use `--allow-gpg-signing` to override this (see [GPG signing](#gpg-commit-signing)).

## GPG commit signing

GPG commit and tag signing is **disabled by default** because `~/.gnupg` is blocked. Copilot commits are unsigned, and you re-sign on merge or squash.

If you want Copilot commits signed, say because branch protection requires signatures:

```bash
cplt config set sandbox.allow_gpg_signing true
```

Or for a single run: `cplt --allow-gpg-signing`

**Setup checklist.** Before using this flag, verify GPG signing works outside the sandbox:

```bash
# 1. Check your signing key is configured
git config --get user.signingkey          # should show your key ID

# 2. Check gpg-agent is running
gpg-connect-agent 'GETINFO version' /bye  # should print version + OK

# 3. Cache your passphrase (so signing doesn't hang)
echo "test" | gpg --clearsign > /dev/null  # triggers passphrase prompt

# 4. Verify git signing works
git commit --allow-empty -S -m "test signed commit"
git log --show-signature -1               # should show "Good signature"
git reset HEAD~1                          # undo the test commit
```

If all of that works, `cplt --allow-gpg-signing` will work too. The `gpg-agent` runs **outside** the sandbox, so pinentry prompts appear normally. The sandbox only needs to reach the agent socket.

> **Note:** signature *verification* (`git log --show-signature`) does not work inside the sandbox, because GPG opens `trustdb.gpg` for writing during verification. This is harmless. Signing works, and signatures can be verified outside the sandbox or in CI.

**Troubleshooting:**

| Symptom | Cause | Fix |
|---|---|---|
| `error: gpg failed to sign the data` | Agent not running or passphrase not cached | Run `gpg-connect-agent 'GETINFO version' /bye` and `echo test \| gpg --clearsign` outside cplt |
| `signing failed: No secret key` | Wrong `user.signingkey` in git config | Run `gpg --list-secret-keys` and set `git config --global user.signingkey <KEY_ID>` |
| `signing failed: Operation not permitted` | Flag not set, or `--deny-path` overriding | Check `cplt doctor` output for GPG signing status |
| Commits unsigned despite flag | `gpg.format=ssh` in git config | This flag is GPG-only; SSH signing is not supported |
| `GNUPGHOME` set to non-default path | SBPL rules only cover `~/.gnupg` | Unset `GNUPGHOME` or symlink to `~/.gnupg` |
| `git log --show-signature` shows `Fatal: can't open trustdb.gpg` | GPG opens `trustdb.gpg` for writing during *verification*, which the sandbox denies | Expected. **Signing works**, only verification is affected. Verify signatures outside the sandbox or in CI |

**What this does:**

| Resource | Access | Why |
|---|---|---|
| `~/.gnupg/pubring.kbx`, `pubring.gpg` | Read-only | Public key lookup |
| `~/.gnupg/trustdb.gpg` | Read-only | Trust validation |
| `~/.gnupg/gpg.conf`, `common.conf` | Read-only | GPG config |
| `~/.gnupg/S.gpg-agent` | Read + socket connect | IPC to agent daemon |
| `~/.gnupg/S.keyboxd` | Read + socket connect | IPC to keyboxd (GnuPG 2.4+ public key daemon) |
| `~/.gnupg/private-keys-v1.d/` | **DENIED** | Private keys stay locked |
| `~/.gnupg/secring.gpg` | **DENIED** | Legacy private keyring stays locked |
| `~/.gnupg/*` (writes) | **DENIED** | No modifications |

**Security notes:**

- **Private keys are NOT exposed.** The GPG agent holds keys in memory, and the Assuan IPC protocol has no command to export private key material. The `private-keys-v1.d/` directory stays denied even with this flag.
- **Risk: signature impersonation and decryption.** A compromised process with agent socket access can request signatures on arbitrary data, which adds a "Verified" badge, and can decrypt arbitrary ciphertext if an encryption subkey exists. This is the same level of impersonation Copilot already has for unsigned commits; signing just adds the badge.
- **GPG-only.** This flag does not enable SSH signing (`gpg.format=ssh`). SSH keys and `SSH_AUTH_SOCK` stay blocked.
- **`--deny-path` wins.** If you pass `--deny-path ~/.gnupg` alongside `--allow-gpg-signing`, the deny takes precedence and every GPG allow is suppressed.
- **`GNUPGHOME`** is not supported yet. Only the default `~/.gnupg` location is allowed.

## Gradle plugin workers and `JAVA_TOOL_OPTIONS`

cplt injects `-Djava.net.preferIPv4Stack=true` via `JAVA_TOOL_OPTIONS` (see the JVM note above) so JVM localhost connections match the sandbox's `localhost:*` rules. Most JVM children read `JAVA_TOOL_OPTIONS` at startup. **Gradle plugin workers** do not. WorkerExecutor process isolation, ktlint-gradle for example, forks JVMs with explicit `forkOptions {}` and does not reliably propagate the environment, so the flag is lost, the worker's dual-stack sockets produce IPv4-mapped `::ffff:127.0.0.1` addresses, and SBPL cannot match those.

Symptom (even with `allow_localhost_any = true`):

```
org.gradle.internal.remote.internal.ConnectException: Could not connect to server [... port:NNNNN, addresses:[/127.0.0.1]]
```

**cplt mitigation (macOS, opt-in):** set `sandbox.gradle_init = true` and cplt installs a guarded init script at `$GRADLE_USER_HOME/init.d/cplt-sandbox.gradle` (or `~/.gradle/init.d/` when unset) on sandbox launch. It activates only inside the sandbox (`__CPLT_WRAPPED` guard) and applies `preferIPv4Stack` to the daemon plus `Test` and `JavaExec` forks. It is opt-in because cplt does not write to tool config dirs by default. `WorkerExecutor` forks have no public configuration hook, so for those the plugin has to propagate the environment itself:

```kotlin
forkOptions {
    environment("JAVA_TOOL_OPTIONS", System.getenv("JAVA_TOOL_OPTIONS") ?: "")
}
```

Known affected: `ktlint-gradle` ([JLLeitschuh/ktlint-gradle#1110](https://github.com/JLLeitschuh/ktlint-gradle/issues/1110)). SBPL itself cannot be fixed, because macOS sandbox profiles have no primitive for IPv4-mapped addresses. That is why cplt reaches for the `preferIPv4Stack` workaround at all.

That last claim is not a guess. SBPL accepts only `*` or `localhost` as the host in a `remote ip` rule; a literal address is a parse error, and the `localhost` token does not match an IPv4-mapped connect:

```
(remote ip "*:*")                  connect succeeds
(remote ip "localhost:*")          PermissionError [Errno 1] Operation not permitted
(remote ip "::ffff:127.0.0.1:*")   sandbox-exec: host must be * or localhost in network address
(remote ip "127.0.0.1:*")          sandbox-exec: host must be * or localhost in network address
```

So the only rule that would match these workers is `*:*`, which allows every outbound address rather than loopback. `--allow-localhost-any` will not be widened to mean that.

**Workaround until the plugin propagates the environment:** run the affected tasks outside cplt, and keep the rest of the build inside.

```bash
./gradlew ktlintFormat
./gradlew ktlintCheck detektMain detektTest build
```

## Gradle toolchain JDKs

`~/.gradle` is a dependency store. The sandbox grants read, write, and `file-map-executable` there (for JNI libs) but **not** `process-exec`, so a rogue agent cannot drop a binary into the dependency cache and run it. Gradle's toolchain support auto-provisions JDKs into `~/.gradle/jdks`, inside that non-executable tree, so forking a toolchain `javac` or test JVM failed with `Operation not permitted` and no config key could grant exec.

cplt now carves `~/.gradle/jdks` back out as executable, and makes it **read-only** to keep the write-then-exec hole closed. Consequence: with `org.gradle.java.installations.auto-download=true`, a toolchain that is not already on disk fails at provisioning time with a write error instead of at exec time. Provision it once outside cplt, or use a JDK outside `~/.gradle`:

```properties
# ~/.gradle/gradle.properties
org.gradle.java.installations.auto-download=false
org.gradle.java.installations.paths=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home
```

The provisioning failure surfaces as `foojay (Unable to download toolchain ..., due to: java.io.IOException: Operation not permitted)`, which reads like a network problem. It is the write being denied, not the download. Check the proxy only after ruling this out.

Two limits are worth knowing. Both rules match the *resolved* path, so if `~/.gradle/jdks` is a symlink to another volume they silently do not apply. The agent cannot create that symlink itself, since the same rules deny writing or `mkdir` at that path, so it takes a pre-existing relocation. A relocated `GRADLE_USER_HOME` misses the rules entirely, though that is pre-existing, because the whole `~/.gradle` grant is keyed to the default location.

**Linux:** unaffected. Landlock has a single `EXECUTE` right covering both `execve` and executable mappings, so the map-exec grant on `~/.gradle` already implies exec there. The carve-out is macOS-only, and the read-only pairing cannot be expressed on Linux for the same reason [`DENIED_HOME_SUBPATHS`](#private-registries) cannot.

## JVM Attach API

JVM testing frameworks like **MockK** (inline mocking), **Mockito** (inline agents), and **ByteBuddy** use the JVM Attach API for runtime class instrumentation. That API creates a Unix domain socket at `/tmp/.java_pid<PID>`, which the sandbox blocks by default.

Enable it:

```bash
cplt config set sandbox.allow_jvm_attach true
```

Or for a single run: `cplt --allow-jvm-attach`

**When to enable:**

- Kotlin/Java projects using **MockK** with `mockk()` or `mockkStatic()` inline mocking
- Projects using **Mockito** with `Mockito.mock()` on final classes (requires the ByteBuddy agent)
- Any test suite that gets `"Could not self-attach to current VM using external process"` errors
- JMX monitoring tools that attach to running JVMs

**How it works:** the JVM creates a socket at `/tmp/.java_pid<PID>`, a hardcoded path that `java.io.tmpdir` does not affect. A helper JVM process connects to that socket to load an instrumentation agent. The sandbox rule uses a regex that only allows sockets matching `.java_pid<PID>`, so on macOS every other Unix socket in `/tmp` (SSH agent, tmux, PostgreSQL) stays blocked. On Linux no unix socket is gated in the first place, so the flag grants nothing that was not already reachable, see [Linux limitations](../SECURITY.md#linux-specific-limitations).

**Security note:** this opens a narrow IPC channel for `.java_pid*`-named sockets only. SSH agent access (`SSH_AUTH_SOCK`) is NOT exposed. On macOS it lives at `/private/tmp/com.apple.launchd.*/Listeners`, which does not match the pattern.

## MSBuild worker-node IPC

`dotnet build` forks out-of-proc **worker nodes** that talk back to the client over a Unix domain socket at `/tmp/MSBuild<PID>`, which the sandbox blocks by default.

Enable it:

```bash
cplt config set sandbox.allow_msbuild true
```

Or for a single run: `cplt --allow-msbuild`

**When to enable:**

- Any `dotnet build`/`dotnet test`/`dotnet run` invocation that fails to spin up MSBuild worker nodes inside the sandbox

**How it works:** MSBuild names its out-of-proc worker-node pipe `MSBuild<PID>` (`NamedPipeUtil.GetPlatformSpecificPipeName`, prefixed with `/tmp/` on Unix). The sandbox rule uses a regex that only allows sockets matching that exact `MSBuild<PID>` form.

This is a **different socket** from the persistent **MSBuild Server**, the opt-in `dotnet build` acceleration feature that keeps a compiler process alive between builds. That one names its pipe `MSBuildServer-<hash>` (see [MSBuild-Server.md](https://github.com/dotnet/msbuild/blob/main/documentation/MSBuild-Server.md#pipe-name-convention--handshake)), a name the `--allow-msbuild` regex does not match, so it stays blocked. To close that off structurally instead of leaning on the socket-path allowlist alone, cplt also sets `DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER=1` unconditionally inside the sandbox, so `dotnet build` never starts or reuses a persistent server, including one a process outside the sandbox already started.

**Security note:** this opens a narrow IPC channel for `MSBuild<PID>`-named sockets only. On macOS, SSH agent access and all other Unix sockets in `/tmp`, the persistent MSBuild Server included, stay blocked. On Linux no unix socket is gated in the first place, so the flag grants nothing that was not already reachable, see [Linux limitations](../SECURITY.md#linux-specific-limitations).

## Port restriction

Only port 443 is allowed by default. Services on other ports need explicit configuration:

```bash
cplt config set allow.ports 8443
```

- `npm install` from private registries on non-standard ports
- API calls to services not on 443
- FTP, SMTP, or other protocol connections

## Private registries

Registry credential files are **blocked by default**, because they typically hold passwords or tokens a rogue agent could exfiltrate:

| File | Purpose |
|------|---------|
| `~/.npmrc` | npm registry auth |
| `~/.m2/settings.xml` | Maven repository credentials |
| `~/.m2/settings-security.xml` | Maven master password |
| `~/.gradle/gradle.properties` | Gradle/Nexus/Artifactory credentials |
| `~/.cargo/credentials` | Cargo crate registry tokens |
| `~/.cargo/credentials.toml` | Cargo crate registry tokens (TOML format) |

**Fix:** all of these can be overridden with `--allow-read`.

```bash
cplt config set allow.read "~/.m2/settings.xml"
cplt config set allow.read "~/.gradle/gradle.properties"
cplt config set allow.read "~/.npmrc"
```

Or for a single run: `cplt --allow-read ~/.m2/settings.xml`

> **Note:** these are the *overridable* credential denials (`DENIED_HOME_SUBPATHS`). A second list, `~/.netrc`, `~/.pypirc`, `~/.gem/credentials` and `~/.vault-token`, is meant to be hard-denied, and **on macOS it is**: the generic `allow.read` grants are emitted before the literal deny rules, and only `DENIED_HOME_SUBPATHS` and `DENIED_DOTFILES` get a post-deny re-allow, so no `allow.read` can reach them. **On Linux that guarantee does not currently hold.** Landlock is grant-only, so those files are withheld by omission rather than by a deny rule, and `allow.read` paths are added to the ruleset without being checked against the list. `cplt config set allow.read "~/.netrc"` therefore produces a working read grant. This is a known gap, tracked in #207. Do not rely on the hard-deny list to stop a deliberate `allow.read` on Linux.

You do not need to allow `~/.npmrc` just to stop yarn 1 crashing on it — cplt redirects `NPM_CONFIG_USERCONFIG` for that, see [yarn 1 and unreadable home rc files](#yarn-1-and-unreadable-home-rc-files) below. If you would rather not hand `~/.npmrc` to the agent at all but do need a private registry, use a project-level `.npmrc`, which is readable as part of the project directory and can take its token from an environment variable.

> **Linux limitation:** the denials for files *inside an allowed tool dir* are only enforced on macOS, via SBPL literal deny rules. On Linux, Landlock cannot deny individual files within an allowed directory, so the parent dirs (`.m2`, `.gradle`, `.cargo`) stay fully readable for dependency resolution. `~/.npmrc` is the exception: it sits at the top of `$HOME`, which is never granted, so it is withheld on both platforms.

## Repo-local git content filters (LFS, git-crypt)

If a repository's **own** `.git/config` defines a content filter, `filter.<name>.clean` or `filter.<name>.process`, cplt refuses the git queries that read working-tree content. Two things change:

```
[cplt] audit: incomplete
[cplt] .cplt.toml differs from the version committed in git HEAD.
```

The audit reports `incomplete` instead of listing changes, and the one-time `cplt trust accept` fails, because it approves only a `Committed` state and the drift check could not run.

**This does not affect most LFS users.** `git lfs install` writes to your `--global` config by default, and a filter there is your choice rather than the repository's, so it does not trigger the refusal. Only a filter defined in the repo's `.git/config` or a worktree config does.

**A committed `.cplt.toml` still applies.** cplt reads it from the object store with `git cat-file`, which cannot reach a filter and is never refused. Permissions you have already approved keep working. It is the one-time accept that is blocked.

**Why it works this way.** Git runs a content filter's program when it reads working-tree files, and cplt runs `git` in the parent process, *outside* the sandbox. `.git/config` stays writable to the agent on both platforms, so a repository could otherwise pick a program that cplt executes unsandboxed ([#210](https://github.com/navikt/cplt/issues/210)). Unlike the other executable config keys, filters are named by an arbitrary subsection, so no fixed `-c` override can neutralise them. That leaves two options. Run the filter, which is the escape. Or refuse, and say so. An `incomplete` audit is a loud "could not verify", not a clean session cplt never checked.

One consequence is worth knowing: an agent can deliberately force the audit to `incomplete` by writing `.git/config`. That is inherent to failing closed.

**Fix:** move the filter to your global config if it belongs there (`git config --global filter.lfs.clean …`), or accept the `incomplete` audit for that repository. If you need `cplt trust accept` to work, remove the repo-local filter for the one invocation.

## yarn 1 and unreadable home rc files

**The `~/.npmrc` half of this is handled automatically since [#180](https://github.com/navikt/cplt/issues/180).** cplt sets `NPM_CONFIG_USERCONFIG` to a path inside the session scratch dir that deliberately does not exist, so the user-level npmrc read fails with `ENOENT`, which yarn 1 tolerates, instead of the denial errno, which it does not. Nothing is granted: `~/.npmrc` stays unreadable either way. `~/.yarnrc` is a separate loader and still needs `allow.read`; see below.

The injection is skipped in three cases, where the failure below can still appear:

- you allowed `~/.npmrc` yourself (`allow.read`), so you asked for the real file and cplt does not redirect around it;
- you set `NPM_CONFIG_USERCONFIG` yourself — in any capitalisation, since npm and yarn lowercase the key — and your value wins;
- the scratch dir is off (`--no-scratch-dir`), so there is no session-scoped writable location to point at.

Without it, `yarn install` fails outright under the default policy when an `~/.npmrc` exists on the host. Nothing is resolved and no `node_modules` is written:

```
yarn install v1.22.22
error Error: EACCES: permission denied, open '/home/you/.npmrc'
```

macOS reports the same failure as `EPERM: operation not permitted`. The errno differs by backend; the outcome does not.

**Fix, in the skipped cases.** If you only install from the public registry, point yarn at a different npmrc. The token stays outside the sandbox:

```bash
: > .npmrc.sandbox
NPM_CONFIG_USERCONFIG="$PWD/.npmrc.sandbox" cplt exec -- yarn install
```

If you do need the registry auth in `~/.npmrc`, allow it instead:

```bash
cplt config set allow.read "~/.npmrc"
```

Or for a single run: `cplt --allow-read ~/.npmrc`. Deleting an `~/.npmrc` you do not use works just as well. Neither fix covers a `~/.yarnrc`. See below.

**Why only yarn 1.** `~/.npmrc` is denied by default because it commonly holds a registry token. Every package manager reads it; only yarn 1 treats an *unreadable* one as fatal. Both of its config loaders, `NpmRegistry.getPossibleConfigLocations` (which is what reaches `~/.npmrc`) and `parseRcPaths` (which reads the `.yarnrc` family), tolerate a *missing* file and rethrow everything else:

```js
} catch (error) {
  if (error.code === 'ENOENT' || error.code === 'EISDIR') {
    return {};
  } else {
    throw error;      // EACCES / EPERM reaches here
  }
}
```

npm, pnpm and bun all carry on past a denied `~/.npmrc` and install normally from the public registry ([navikt/cplt#180](https://github.com/navikt/cplt/issues/180) measured npm 10.9.8, pnpm 11.22.0 and bun 1.4.0). The trigger is therefore the file's *existence*, not its contents. An `~/.npmrc` holding nothing but `save-exact=true` breaks yarn 1 exactly as a token-bearing one does.

**It is not only `~/.npmrc`, and the automatic fix does not cover the rest.** `parseRcPaths` fails the same way on `~/.yarnrc` when it exists. `NPM_CONFIG_USERCONFIG` does not reach that loader, so the redirect above leaves this crash in place, as does allowing `~/.npmrc`:

```
error Error: EPERM: operation not permitted, open '/Users/you/.yarnrc'
```

`~/.yarnrc` is not in any deny list. Like most home dotfiles it is simply never granted, since the sandbox enumerates the specific `$HOME` config files tools need rather than granting `$HOME` wholesale. Allow it the same way (`cplt config set allow.read "~/.yarnrc"`) if you keep one.

**Why `NPM_CONFIG_USERCONFIG` works.** It is on cplt's environment allowlist because it names a path rather than carrying a secret, and yarn 1's npmrc loader honours it: `mergeEnv('npm_config_')` lowercases the variable into `config.userconfig`, which replaces the `~/.npmrc` entry in `getPossibleConfigLocations`. That list is gated on an existence check before the read, so a path that does not exist is skipped rather than read. Because that lowercasing collapses every spelling into one entry, and an *empty* value is falsy enough to fall back to `~/.npmrc`, cplt also removes any other-cased `npm_config_userconfig` from the child environment when it injects — otherwise a stray empty one could win the merge and undo the redirect. This is why cplt injects the variable rather than granting the file. `allow.read` fixes the crash by handing the credential over, the redirect fixes it by removing the need. npm and pnpm honour the same variable and could not read `~/.npmrc` in the sandbox anyway, so nothing changes for them. It redirects only the npmrc loader, so a `~/.yarnrc` still needs the treatment above.

The XDG variables, by contrast, do not help. yarn 1's `.yarnrc` scan builds its own path list with hardcoded `~/.yarnrc` entries and runs before the XDG-aware `getConfigDir()` is consulted, so neither `XDG_CONFIG_HOME` nor `XDG_DATA_HOME` removes those paths from the list. yarn 2+ (berry) uses a different config loader and is unaffected.

One footgun with `allow.read`: the path must **exist** when cplt starts. A missing path is warned about and dropped, so `allow.read "~/.npmrc"` on a machine without one is silently inert. That is fine here, since yarn only fails when the file exists in the first place.

**Why cplt does not make the *denial itself* look like ENOENT.** The redirect above sidesteps the errno for the one file that has an env-var escape hatch. It does not change what a denied `open` reports, so `~/.yarnrc` and every other withheld dotfile still fail with the platform's denial errno. The tempting general accommodation is to report these files as *absent* rather than *denied*, which every package manager tolerates. macOS can express that. SBPL accepts `(deny file-read* (literal …) (with errno 2))`, so the read fails with `No such file or directory`. Linux cannot. Landlock is grant-only with no control over the errno a denied `open` returns, and on Linux `~/.npmrc` is not denied by a rule at all. It is simply never granted. Shipping the macOS half would fix macOS, leave Linux (where this was reported) untouched, and split the two backends' denial semantics for every tool, not just yarn. One line of config is the better trade. Bubblewrap could mask the file with an empty `/dev/null` bind, but it is opt-in, applies only where the wrapper is active, and inverts the existing deny-path masks, which deliberately use an unreadable placeholder so a masked read fails loudly instead of reading as empty.

Adding `~/.npmrc` to the default read grant is not an option either. That hands the npm token to the sandboxed agent, which is the one thing the denial exists to prevent.

## Cloud credential directories

The following directories are **entirely blocked**, with no read, write, or execute:

| Directory | Purpose |
|-----------|---------|
| `~/.config/gcloud` | Google Cloud SDK config, ADC credentials, Python virtualenv |
| `~/.aws` | AWS credentials and config |
| `~/.azure` | Azure CLI credentials |
| `~/.kube` | Kubernetes cluster credentials |
| `~/.config/op` | 1Password CLI sessions |

### Reading individual files (e.g. Application Default Credentials)

You can grant **read-only** access to specific files inside these directories with `allow.read`:

```bash
# Per session
cplt --allow-read ~/.config/gcloud/application_default_credentials.json -- -p "deploy"

# Per repo (.cplt.toml)
cplt config set --repo allow.read ~/.config/gcloud/application_default_credentials.json
```

This lets GCP SDKs authenticate using the ADC JSON file without exposing the entire directory.

### Executing cloud CLIs (gcloud, aws, az) is intentionally blocked

Even with `allow.read`, the agent **cannot execute** binaries inside these directories. `gcloud`, for instance, uses a Python virtualenv at `~/.config/gcloud/virtenv/` that needs execute permission the sandbox does not grant.

**This is intentional.** Cloud CLIs have unrestricted access to your cloud infrastructure. An agent running `gcloud` could create or delete resources, read secrets, or modify IAM policies. The sandbox closes that escalation path.

**Workarounds:**

| Need | Solution |
|------|----------|
| GCP authentication for SDKs | `allow.read ~/.config/gcloud/application_default_credentials.json`, SDKs read the JSON directly |
| AWS authentication for SDKs | `allow.read ~/.aws/credentials`, SDKs read credentials directly |
| Running cloud CLI commands | Run them outside the sandbox in a regular terminal |
| CI/CD with cloud access | Use project-level service account keys or workload identity, not user credentials |

> **Design principle:** `allow.read` grants read access to credential *files* so SDKs can authenticate. It does not grant execute permission, because executing cloud CLIs would bypass the sandbox's network and filesystem restrictions.

## Developer tooling telemetry

Plenty of developer tools phone home with default-on usage analytics: build systems, framework CLIs, language toolchains. cplt stops them with two complementary layers.

**Layer 1, env var opt-outs** (injected unconditionally via `HARDENING_ENV_VARS`):

| Variable | Affects |
|----------|---------|
| `DO_NOT_TRACK=1` | Cross-tool standard signal ([consoledonottrack.com](https://consoledonottrack.com/)) |
| `NEXT_TELEMETRY_DISABLED=1` | Next.js build telemetry |
| `TURBO_TELEMETRY_DISABLED=1` | Turborepo usage telemetry |
| `CHECKPOINT_DISABLE=1` | HashiCorp tools (terraform, vault, packer, nomad) |
| `GATSBY_TELEMETRY_DISABLED=1` | Gatsby build telemetry |

**Layer 2, proxy domain blocks** (in `blocked-domains.txt`):

| Domain | Blocks |
|--------|--------|
| `checkpoint.hashicorp.com` | HashiCorp version/update pings |
| `telemetry.nextjs.org` | Next.js telemetry fallback |
| `mobile.events.data.microsoft.com` | VS Code + all Microsoft extensions (1DS SDK) |
| `dc.services.visualstudio.com` | Older VS Code / App Insights |
| `telemetry.go.dev` | Go toolchain upload endpoint |
| `posthog.com` | AI agent analytics (PostHog, all subdomains) |

Tools keep working normally. These are non-essential telemetry endpoints.

## Agent config-dir host-persistence denies

Each agent's global config dir is mounted read/write, but the files in it that **auto-execute on the host** the next time you run that agent outside cplt are write-denied. A sandboxed agent never needs to write them mid-session, and anything it did write there would run unsandboxed on your next launch.

| Agent | Denied | What breaks |
| --- | --- | --- |
| Gemini | `~/.gemini/settings.json`, `extensions/`, `policies/`, `hooks/` | ❌ **First login.** Gemini records the auth method it picked as `selectedAuthType` in `settings.json`, so signing in from inside cplt fails with `Failed to save settings: …`. cplt warns about this before launching — run `gemini` once outside cplt. Also blocks editing user-level hooks, extensions and policies from inside a session |
| Pi | `~/.pi/agent/settings.json`, `extensions/`, `npm/`, `git/` | ⚠️ `pi install`, and every in-session setting that persists to `settings.json`: `/model` (Ctrl+S), `/thinking`, `/settings`. Do those outside cplt. Auth is unaffected — Pi uses provider API keys via `--pass-env` |
| Claude Code | `~/.claude/settings.json`, `statusline.sh`, `plugins/` | ⚠️ Editing `settings.json` (including `hooks`) from inside a session. `commands/`, `agents/` and `skills/` stay writable. Auth is unaffected — the OAuth token is in the Keychain or `.credentials.json` |
| Antigravity | `~/.gemini/config/hooks.json`, `config/mcp_config.json`, `antigravity-cli/bin/` | ⚠️ Editing hooks or MCP server config from inside a session. Auth is unaffected |
| Copilot, OpenCode | — | Nothing denied |

**There is no flag that reopens these.** The denies are emitted at the very end of the profile, after every user `allow.write`, so even `--allow-write ~/.gemini/settings.json` does not override them. That is deliberate: before this, `allow.write = ["~/.gemini"]` silently reopened the whole set.

**Linux is weaker than macOS here.** Landlock cannot deny a subpath inside an allowed directory, so the denies are carried by the bubblewrap read-only overlay. They hold only when `bwrap` is installed, and only for paths that **already exist** — bubblewrap cannot bind a missing source, so a `extensions/` directory that does not exist yet is unprotected until something creates it. Without bubblewrap the guard does not apply on Linux at all.

**Fix (Gemini first login):**

```bash
gemini          # once, outside cplt — complete the sign-in
cplt --agent gemini
```

## AI agent telemetry

AI agents and their third-party packages often send usage analytics and crash reports to external services such as PostHog and Sentry. cplt blocks these at two layers:

1. **Env var injection.** cplt injects `OMO_DISABLE_POSTHOG=1` and `DO_NOT_TRACK=1` so agents opt out before making any network call.
2. **Proxy blocklist.** `posthog.com` is in `blocked-domains.txt` as a fallback for tools that ignore env vars.

For the `oh-my-openagent` OpenCode plugin specifically, `OMO_DISABLE_POSTHOG=1` stops PostHog being initialised, so no network calls are made and no errors appear.

> **oh-my-openagent transcripts:** the plugin's Claude Code hooks feature writes transcripts to `$CLAUDE_CONFIG_DIR/transcripts` (default `~/.claude`), which the sandbox denies for non-Claude agents. The write fails with `EACCES` and OpenCode aborts the prompt. cplt therefore injects `CLAUDE_CONFIG_DIR=<XDG_STATE_HOME>/opencode/claude-config` for OpenCode sessions, falling back to `~/.local/state/opencode/claude-config` when `XDG_STATE_HOME` is unset, which lands it in the write-allowed OpenCode state dir. If you set `CLAUDE_CONFIG_DIR` yourself, cplt respects it; add that path to `allow.write` if it lives outside the OpenCode dirs.

**If you use `allowed_domains` (allowlist mode):** the proxy blocklist is not consulted in that mode, but the env var injection still suppresses telemetry silently.

**Impact:** none. Telemetry is non-essential and the agent works normally without it.

**Why blocked?** Analytics events may include code context, prompt fragments, or usage patterns that amount to unintended data exfiltration from inside the sandbox.

**If you want to allow telemetry** (not recommended):

```toml
# .cplt.toml
[hardening]
disabled_categories = ["telemetry_opt_out"]

[proxy]
blocked_domains = "none"   # disable the default blocklist entirely
```
