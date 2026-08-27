# Known Impacts

The sandbox is kernel-enforced — **all restrictions apply to every process spawned inside it**, including dev servers, test runners, build tools, and package managers. This is by design (a sandboxed agent could otherwise escape by spawning a child process), but it affects some workflows:

## `.env` file blocking

`.env*`, `.pem`, `.key`, `.p12`, `.pfx`, `.jks` files in the project directory are **blocked from reading** by default. This prevents a rogue agent from exfiltrating secrets, but has side effects:

| Operation                      | Impact     | Why                                                                   |
| ------------------------------ | ---------- | --------------------------------------------------------------------- |
| `npm install`                  | ✅ Works    | Does not read `.env` files                                            |
| `cargo build`, `go build`      | ✅ Works    | Does not read `.env` files                                            |
| `next build` / `next dev`      | ⚠️ May fail | Next.js auto-loads `.env`, `.env.local`, `.env.production` at startup |
| `npm run dev` (Node.js)        | ⚠️ May fail | Apps using `dotenv` to load config will get `undefined` env vars      |
| `npm test` / `vitest`          | ⚠️ May fail | Tests that depend on `.env` for config won't find the values          |
| TLS dev servers (`.pem` certs) | ⚠️ Blocked  | Local HTTPS certs in `.pem`/`.key` files can't be read                |
| `.env.example`                 | ⚠️ Blocked  | Matches `.env.*` pattern — use `--allow-env-files` if needed          |
| Writing `.env` files           | ✅ Works    | Only read is denied; Copilot can create `.env` from templates         |

**Fix:**

```bash
cplt config set sandbox.allow_env_files true
```

Or for a single run: `cplt --allow-env-files -- -p "start the dev server"`

Or set it permanently:

```bash
cplt config set sandbox.allow_env_files true
```

## Lifecycle scripts (postinstall hooks)

npm/yarn/pnpm lifecycle scripts are **blocked by default** via `npm_config_ignore_scripts=true` and `YARN_ENABLE_SCRIPTS=false`. This prevents supply chain attacks through postinstall hooks, but may break packages that require post-install steps:

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

Tools that compile-then-execute from `$TMPDIR` are **blocked by default** because the sandbox denies `process-exec` and `file-map-executable` from `/private/tmp` and `/private/var/folders`. This affects:

| Tool                      | Impact      | Why                                                                   |
| ------------------------- | ----------- | --------------------------------------------------------------------- |
| `go test`                 | ❌ Blocked   | Compiles test binaries to `$TMPDIR`, then executes them               |
| `go run`                  | ❌ Blocked   | Compiles to `$TMPDIR` then executes — same as `go test`               |
| `go generate`             | ❌ Blocked   | If the generator is a Go binary compiled to `$TMPDIR`                 |
| `mise run` (inline tasks) | ❌ Blocked   | Writes script to temp file, then executes it                          |
| `node-gyp` (native addons)| ❌ Blocked  | Compiles C/C++ to temp, then loads via dlopen                         |
| `go build`                | ✅ Works     | Output binary goes to project dir or `$GOBIN`, not `$TMPDIR`         |
| `cargo test`              | ✅ Works     | Rust builds in `target/`, not `$TMPDIR`                               |
| `npm test` / `vitest`     | ✅ Works     | JavaScript runs via interpreter, not compiled to temp                 |

**Fix:** The scratch dir is now **on by default** — cplt creates `~/Library/Caches/cplt/tmp/{session-id}/` with `rwx` permissions, redirects `TMPDIR`, `TMP`, `TEMP`, and `GOTMPDIR` there, and cleans up on exit. Stale directories older than 24 hours are garbage-collected on startup.

**JVM note:** On macOS, the JVM ignores `TMPDIR` — it reads `java.io.tmpdir` from `confstr(_CS_DARWIN_USER_TEMP_DIR)` which always returns `/var/folders/...`. cplt automatically injects `-Djava.io.tmpdir=<scratch> -Djansi.tmpdir=<scratch> -Djava.rmi.server.hostname=localhost -Djava.net.preferIPv4Stack=true` via `JAVA_TOOL_OPTIONS` so that Maven Surefire forks, the Kotlin compiler daemon, and Jansi native lib extraction all use the scratch dir. The RMI hostname flag ensures the Kotlin daemon's Java RMI communication stays on `localhost`. The `preferIPv4Stack` flag forces pure IPv4 sockets so that the sandbox's localhost filtering works correctly for Java (without it, Java's dual-stack IPv6 sockets produce IPv4-mapped addresses that SBPL can't match). Override with `--pass-env JAVA_TOOL_OPTIONS` if you need custom JVM flags. For inline mocking (MockK, Mockito, ByteBuddy), also add `--allow-jvm-attach` — see [JVM Attach API](#jvm-attach-api).

**Gradle/JVM still failing?** Some JVM native libraries (e.g. `libjli.dylib`, JNI libs) use `dlopen` from the system temp dir *before* `JAVA_TOOL_OPTIONS` takes effect. If you see "Operation not permitted" during JVM startup itself (not Gradle build), add `--allow-tmp-exec`:

```bash
# Recommended for Gradle projects (localhost + tmp exec + JVM attach):
cplt --allow-localhost-any --allow-tmp-exec --allow-jvm-attach -- -p "run tests"

# Or set permanently:
cplt config set sandbox.allow_localhost_any true
cplt config set sandbox.allow_tmp_exec true
cplt config set sandbox.allow_jvm_attach true
```

**Kotlin daemon on Linux:** The Kotlin compiler daemon writes marker files to `~/.local/share/kotlin/daemon/` and communicates via localhost. If you see `AccessDeniedException: .../kotlin-daemon-client-tsmarker*.tmp`, cplt grants write access to `~/.local/share/kotlin/` automatically. If the daemon still can't connect (falls back to non-daemon compilation with garbled Unicode paths), ensure `--allow-localhost-any` is set — the daemon uses ephemeral ports:

```bash
# Recommended for Kotlin/Gradle on Linux:
cplt config set sandbox.allow_localhost_any true
cplt config set sandbox.allow_jvm_attach true

# If you need additional write paths (e.g. custom Kotlin data dir):
cplt config set allow.write "~/.local/share/kotlin"
```

If you're still seeing this error, check that you haven't set `scratch_dir = false` in your config:

```bash
cplt config explain sandbox.scratch_dir
```

## Cache exec (Playwright, pnpm dlx, etc.)

Some tools unpack and execute binaries directly from `~/Library/Caches` (macOS) / `~/.cache` (Linux), which is exec-blocked by default:

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

`--allow-cache-exec-any` opens exec for the entire cache tree (`~/Library/Caches` on macOS, `~/.cache` on Linux) — use only as a last resort.

> **Playwright on Linux:** also run Chromium with its own sandbox disabled
> (`chromiumSandbox: false`, or launch with `--no-sandbox`). cplt's seccomp filter
> blocks the `unshare`/`setns` syscalls Chromium's nested namespace sandbox needs;
> cplt's Landlock + seccomp is the enforcing boundary, so the nested sandbox is
> redundant. The cache-exec subdir is validated to be traversal-free before a
> Landlock execute rule is granted.

## Localhost blocking

Localhost outbound is blocked by default, which prevents sandboxed processes from connecting to local services:

| Operation                      | Impact            | Why                                                  |
| ------------------------------ | ----------------- | ---------------------------------------------------- |
| `npm install` (registry)       | ✅ Works           | Uses HTTPS to `registry.npmjs.org:443`               |
| `gradle build` (Maven Central) | ✅ Works           | Uses HTTPS to `repo1.maven.org:443`                  |
| Gradle daemon (ephemeral port) | ❌ Blocked         | Use `--allow-localhost-any` (daemon uses random ports) |
| Gradle/JVM startup (native libs)| ❌ Blocked        | Use scratch dir (default) or `--allow-tmp-exec` — see [JVM note](#temp-dir-exec) |
| Local PostgreSQL (`:5432`)     | ❌ Blocked         | Use `--allow-localhost 5432`                         |
| Local Redis (`:6379`)          | ❌ Blocked         | Use `--allow-localhost 6379`                         |
| Local Kafka (`:9092`)          | ❌ Blocked         | Use `--allow-localhost 9092`                         |
| MCP servers                    | ❌ Blocked         | Use `--allow-localhost 3000`                         |
| Local API/dev server           | ❌ Blocked         | Use `--allow-localhost 8080`                         |
| Spring Boot (`:8080`)          | ❌ Blocked         | Use `--allow-localhost 8080`                         |
| Next.js/Turbopack build        | ❌ Workers blocked | Use `--allow-localhost-any` (random ephemeral ports) |

**Fix:** Use `cplt config set allow.localhost <PORT>` for specific services, or `cplt config set sandbox.allow_localhost_any true` for build tools that use random ports (Next.js, Vite, esbuild).

## App/build can't reach the network under cplt

When the proxy is on (the default), cplt injects the standard `HTTP(S)_PROXY` env vars into the session so agent traffic can be filtered and logged, and **every** process inherits them — your app, build, and tests, not just the agent. So if something reaches the network fine outside cplt but times out under it, the usual cause is the HTTP client mishandling those proxy env vars (some client versions have shipped proxy-handling regressions — check for a newer patch release), or a domain/port that really is blocked — not cplt refusing all traffic.

cplt doesn't restrict outbound *domains* by default, but the proxy still enforces the port policy, private-IP/localhost safeguards, and any configured allowlist/blocklist. To see what actually happened, run with the proxy log (`--proxy-log <file>` or `--proxy-log-level all`) and look for `BLOCKED` lines: if nothing was blocked the request left cplt and the fault is client-side; `BLOCKED-*` lines mean a port or configured list stopped it — a policy question, not a client bug.

## Docker and Testcontainers

Docker is **intentionally blocked** — `~/.docker` is denied and the Docker socket is not accessible. This is by design: Docker gives near-root access to the host system, which defeats the purpose of sandboxing.

- Docker commands, `docker compose`, and Testcontainers will fail
- Local databases via Docker Compose need `--allow-localhost <PORT>` for the exposed port (the database container runs outside the sandbox)
- Consider running database/Kafka containers before starting cplt, then use `--allow-localhost` for the ports

**Opting in (⚠️ dangerous):** If you understand the risks (container mounts bypass the sandbox entirely), you can allow Docker access:

```bash
cplt config set sandbox.allow_docker true
# or per-session:
cplt --allow-docker
```

## SSH agent blocking

SSH agent access is blocked (unix socket denied), which means:

- `git clone` over SSH will fail — use HTTPS clones instead
- `ssh` commands spawned by the agent will fail
- `gh` CLI uses HTTPS by default and is unaffected

## macOS protected folders (Desktop, Documents)

macOS TCC (Transparency, Consent, and Control) protects certain folders at the kernel level. Without Full Disk Access, Copilot CLI cannot access `~/Desktop` or `~/Documents` **with or without cplt** — this is a macOS restriction, not a sandbox limitation. The cplt sandbox remains fully active regardless of FDA status.

| Path | Without FDA | With FDA | Notes |
| ---- | :---: | :---: | --- |
| `~/Desktop` | ❌ | ✅ | TCC-protected |
| `~/Documents` | ❌ | ✅ | TCC-protected |
| `~/Downloads` | ✅ | ✅ | Less restrictive TCC policy |
| Dragged screenshots | ❌ | ✅ | `TemporaryItems/NSIRD_*` are per-process isolated |

**Fix: Grant Full Disk Access to your terminal** (recommended):

1. Open **System Settings → Privacy & Security → Full Disk Access**
2. Enable your terminal app (Terminal.app, iTerm2, Ghostty, etc.)
3. **Restart the terminal** — TCC grants only take effect for new processes

This lifts TCC restrictions for all child processes while the cplt sandbox continues to enforce its own deny-by-default rules (write protection, network filtering, dotfile access, etc.).

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

Git commit and push **work out of the box** over HTTPS — no extra flags needed.

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
   This makes git transparently use HTTPS even when remotes are configured as SSH. The rewrite is read from `~/.gitconfig` which is readable inside the sandbox.
2. **Authenticate with `gh`** — cplt allows the agent to read `gh auth token`:
   ```bash
   gh auth login   # one-time setup outside the sandbox
   ```
3. **Configure git credential helper** (if not already set by `gh auth setup-git`):
   ```bash
   gh auth setup-git   # sets credential.helper to use gh
   ```

That's it. The agent can now `git add`, `git commit`, `git push`, create branches, and fetch — all inside the sandbox.

**Optional: signed commits** — add `--allow-gpg-signing` (see [GPG signing](#gpg-commit-signing)).

> **Why is SSH blocked?** The SSH agent socket gives access to *all* loaded keys, which could authenticate to any host. HTTPS with `gh auth token` is scoped to GitHub only. See [SSH agent blocking](#ssh-agent-blocking).

> **Tip:** Protect your `main` branch with [branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-a-branch-protection-rule/about-branch-protection-rules) to prevent the agent from pushing directly to main or force-pushing. This is good practice regardless of cplt.

## Git restrictions

Certain git operations are blocked to prevent persistence attacks that survive the sandbox session:

| Operation                          | Impact      | Why                                                               |
| ---------------------------------- | ----------- | ----------------------------------------------------------------- |
| `git add/commit/status/diff/log`   | ✅ Works     | Local operations, no writes to protected paths                    |
| `git checkout/merge/rebase/branch` | ✅ Works     | Branch operations work normally                                   |
| `git fetch/pull/push` (HTTPS)      | ✅ Works     | Port 443 allowed, `gh auth token` provides credentials            |
| `git fetch/pull/push` (SSH)        | ❌ Blocked   | SSH agent socket denied — use HTTPS                               |
| `git config` (local)               | ❌ Blocked   | `.git/config` is write-protected (prevents `url.*.insteadOf` hijacking) |
| `git config --global`              | ❌ Blocked   | Git config and `~/.gitignore_global` are read-only                 |
| `git remote set-url`               | ❌ Blocked   | Writes to `.git/config`                                           |
| `git submodule add`                | ❌ Blocked   | `.gitmodules` is write-protected (supply chain vector)            |
| Creating git hooks                 | ❌ Blocked   | `.git/hooks/` is write-protected (hooks run unsandboxed)          |
| Signed commits/tags                | ❌ Disabled  | `commit.gpgsign` and `tag.gpgsign` overridden to `false` via env; use `--allow-gpg-signing` to enable |

**Global git hooks**: If `core.hooksPath` is set in `~/.gitconfig`, cplt auto-detects the hooks directory and allows reading it so git operations succeed. Write access is explicitly denied to prevent persistence attacks. The hooks path must be under `$HOME` with at least 3 path components (e.g. `~/.config/git/hooks`) to prevent overly broad read access.

**Commit signing**: `~/.ssh` and `~/.gnupg` are blocked, so GPG/SSH signing would fail. Instead of opening private key directories, cplt injects `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_N`/`GIT_CONFIG_VALUE_N` env vars to disable `commit.gpgsign` and `tag.gpgsign` inside the sandbox. Commits made by Copilot are unsigned — this is expected since users typically re-sign on merge/squash. Use `--allow-gpg-signing` to override this (see [GPG signing](#gpg-commit-signing)).

## GPG commit signing

GPG commit/tag signing is **disabled by default** because `~/.gnupg` is blocked. Copilot commits are unsigned — you re-sign on merge/squash.

If you want Copilot commits to be signed (e.g. branch protection requires signatures):

```bash
cplt config set sandbox.allow_gpg_signing true
```

Or for a single run: `cplt --allow-gpg-signing`

**Setup checklist:**

Before using this flag, verify GPG signing works outside the sandbox:

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

If all of that works, `cplt --allow-gpg-signing` will work too. The `gpg-agent` runs **outside** the sandbox, so pinentry prompts appear normally — the sandbox only needs to reach the agent socket.

> **Note:** Signature *verification* (`git log --show-signature`) won't work inside the sandbox because GPG opens `trustdb.gpg` for writing during verification. This is harmless — signing works correctly, and signatures can be verified outside the sandbox or in CI.

**Troubleshooting:**

| Symptom | Cause | Fix |
|---|---|---|
| `error: gpg failed to sign the data` | Agent not running or passphrase not cached | Run `gpg-connect-agent 'GETINFO version' /bye` and `echo test \| gpg --clearsign` outside cplt |
| `signing failed: No secret key` | Wrong `user.signingkey` in git config | Run `gpg --list-secret-keys` and set `git config --global user.signingkey <KEY_ID>` |
| `signing failed: Operation not permitted` | Flag not set, or `--deny-path` overriding | Check `cplt --doctor` output for GPG signing status |
| Commits unsigned despite flag | `gpg.format=ssh` in git config | This flag is GPG-only; SSH signing is not supported |
| `GNUPGHOME` set to non-default path | SBPL rules only cover `~/.gnupg` | Unset `GNUPGHOME` or symlink to `~/.gnupg` |
| `git log --show-signature` shows `Fatal: can't open trustdb.gpg` | GPG opens `trustdb.gpg` for writing during *verification*, which the sandbox denies | This is expected — **signing works**, only verification is affected. Verify signatures outside the sandbox or in CI |

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

- **Private keys are NOT exposed.** GPG agent holds keys in memory — the Assuan IPC protocol has no command to export private key material. The `private-keys-v1.d/` directory remains denied even with this flag.
- **Risk: signature impersonation and decryption.** A compromised process with agent socket access can request signatures on arbitrary data (adding a "Verified" badge) and, if an encryption subkey exists, decrypt arbitrary ciphertext. This is the same level of impersonation Copilot already has for unsigned commits — signing just adds the badge.
- **GPG-only.** This flag does not enable SSH signing (`gpg.format=ssh`). SSH keys and `SSH_AUTH_SOCK` remain blocked.
- **`--deny-path` wins.** If you specify `--deny-path ~/.gnupg` alongside `--allow-gpg-signing`, the deny takes precedence — all GPG allows are suppressed.
- **`GNUPGHOME`** is not supported yet — only the default `~/.gnupg` location is allowed.

## Gradle plugin workers and `JAVA_TOOL_OPTIONS`

cplt injects `-Djava.net.preferIPv4Stack=true` via `JAVA_TOOL_OPTIONS` (see the JVM note above) so JVM localhost connections match the sandbox's `localhost:*` rules. Most JVM children read `JAVA_TOOL_OPTIONS` at startup, but **Gradle plugin workers** (WorkerExecutor process isolation, e.g. ktlint-gradle) fork JVMs with explicit `forkOptions {}` and do not reliably propagate the environment — the flag is lost, their dual-stack sockets produce IPv4-mapped `::ffff:127.0.0.1` addresses, and SBPL cannot match them.

Symptom (even with `allow_localhost_any = true`):

```
org.gradle.internal.remote.internal.ConnectException: Could not connect to server [... port:NNNNN, addresses:[/127.0.0.1]]
```

**cplt mitigation (macOS, opt-in):** set `sandbox.gradle_init = true` and cplt installs a guarded init script at `$GRADLE_USER_HOME/init.d/cplt-sandbox.gradle` (or `~/.gradle/init.d/` when unset) on sandbox launch. It activates only inside the sandbox (`__CPLT_WRAPPED` guard) and applies `preferIPv4Stack` to the daemon plus `Test`/`JavaExec` forks. Opt-in because cplt does not write to tool config dirs by default. `WorkerExecutor` forks have no public configuration hook — for those, the plugin must propagate the environment itself:

```kotlin
forkOptions {
    environment("JAVA_TOOL_OPTIONS", System.getenv("JAVA_TOOL_OPTIONS") ?: "")
}
```

Known affected: `ktlint-gradle` ([JLLeitschuh/ktlint-gradle#1110](https://github.com/JLLeitschuh/ktlint-gradle/issues/1110)). SBPL itself cannot be fixed — macOS sandbox profiles have no primitive for IPv4-mapped addresses, which is why cplt uses the `preferIPv4Stack` workaround at all.

## Gradle toolchain JDKs

`~/.gradle` is a dependency store: the sandbox grants read, write, and `file-map-executable` (for JNI libs) but **not** `process-exec`, so a rogue agent cannot drop a binary into the dependency cache and run it. Gradle's toolchain support auto-provisions JDKs into `~/.gradle/jdks`, which lands inside that non-executable tree — forking a toolchain `javac` or test JVM failed with `Operation not permitted`, and no config key could grant exec.

cplt now carves `~/.gradle/jdks` back out as executable, and makes it **read-only** to keep the write-then-exec hole closed. Consequence: with `org.gradle.java.installations.auto-download=true`, a toolchain that is not already on disk fails at provisioning time with a write error instead of at exec time. Provision it once outside cplt, or use a JDK outside `~/.gradle`:

```properties
# ~/.gradle/gradle.properties
org.gradle.java.installations.auto-download=false
org.gradle.java.installations.paths=/Library/Java/JavaVirtualMachines/temurin-25.jdk/Contents/Home
```

Note that the provisioning failure surfaces as `foojay (Unable to download toolchain ..., due to: java.io.IOException: Operation not permitted)`, which reads like a network problem. It is the write being denied, not the download — check the proxy only after ruling this out.

Two limits worth knowing. Both rules match the *resolved* path, so if `~/.gradle/jdks` is a symlink to another volume they silently do not apply; the agent cannot create that symlink itself (the same rules deny writing or `mkdir` at that path), so it takes a pre-existing relocation. And a relocated `GRADLE_USER_HOME` misses the rules entirely — but that is pre-existing, since the whole `~/.gradle` grant is keyed to the default location.

**Linux:** unaffected. Landlock has a single `EXECUTE` right covering both `execve` and executable mappings, so the map-exec grant on `~/.gradle` already implies exec there — the carve-out is macOS-only, and the read-only pairing cannot be expressed on Linux for the same reason [`DENIED_HOME_SUBPATHS`](#private-registries) cannot.

## JVM Attach API

JVM testing frameworks like **MockK** (inline mocking), **Mockito** (inline agents), and **ByteBuddy** use the JVM Attach API for runtime class instrumentation. This API creates a Unix domain socket at `/tmp/.java_pid<PID>` — which the sandbox blocks by default.

Enable it:

```bash
cplt config set sandbox.allow_jvm_attach true
```

Or for a single run: `cplt --allow-jvm-attach`

**When to enable:**

- Kotlin/Java projects using **MockK** with `mockk()` or `mockkStatic()` inline mocking
- Projects using **Mockito** with `Mockito.mock()` on final classes (requires ByteBuddy agent)
- Any test suite that gets `"Could not self-attach to current VM using external process"` errors
- JMX monitoring tools that attach to running JVMs

**How it works:** The JVM creates a socket at `/tmp/.java_pid<PID>` (hardcoded path, not affected by `java.io.tmpdir`). A helper JVM process connects to this socket to load an instrumentation agent. The sandbox rule uses a regex pattern that only allows sockets matching `.java_pid<PID>` — all other Unix sockets in `/tmp` (including SSH agent, tmux, PostgreSQL) remain blocked.

**Security note:** This opens a narrow IPC channel for `.java_pid*`-named sockets only. SSH agent access (`SSH_AUTH_SOCK`) is NOT exposed — on macOS it lives at `/private/tmp/com.apple.launchd.*/Listeners` which does not match the pattern.

## MSBuild worker-node IPC

`dotnet build` forks out-of-proc **worker nodes** that talk back to the client over a Unix domain socket at `/tmp/MSBuild<PID>` — which the sandbox blocks by default.

Enable it:

```bash
cplt config set sandbox.allow_msbuild true
```

Or for a single run: `cplt --allow-msbuild`

**When to enable:**

- Any `dotnet build`/`dotnet test`/`dotnet run` invocation that fails to spin up MSBuild worker nodes inside the sandbox

**How it works:** MSBuild names its out-of-proc worker-node pipe `MSBuild<PID>` (`NamedPipeUtil.GetPlatformSpecificPipeName`, prefixed with `/tmp/` on Unix). The sandbox rule uses a regex pattern that only allows sockets matching this exact `MSBuild<PID>` form.

This is a **different socket** from the persistent **MSBuild Server** (opt-in `dotnet build` acceleration feature that keeps a compiler process alive between builds), which names its pipe `MSBuildServer-<hash>` (see [MSBuild-Server.md](https://github.com/dotnet/msbuild/blob/main/documentation/MSBuild-Server.md#pipe-name-convention--handshake)) — a name the `--allow-msbuild` regex does not match, so it remains blocked. To close this off structurally rather than relying only on the socket-path allowlist, cplt also unconditionally sets `DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER=1` inside the sandbox, so `dotnet build` never attempts to start or reuse a persistent server — including one a process outside the sandbox may have already started.

**Security note:** This opens a narrow IPC channel for `MSBuild<PID>`-named sockets only. SSH agent access and all other Unix sockets in `/tmp` (including the persistent MSBuild Server) remain blocked.

## Port restriction

Only port 443 is allowed by default. Services on other ports need explicit configuration:

```bash
cplt config set allow.ports 8443
```

- `npm install` from private registries on non-standard ports
- API calls to services not on 443
- FTP, SMTP, or other protocol connections

## Private registries

Registry credential files are **blocked by default** because they typically contain passwords or tokens that a rogue agent could exfiltrate:

| File | Purpose |
|------|---------|
| `~/.npmrc` | npm registry auth |
| `~/.m2/settings.xml` | Maven repository credentials |
| `~/.m2/settings-security.xml` | Maven master password |
| `~/.gradle/gradle.properties` | Gradle/Nexus/Artifactory credentials |
| `~/.cargo/credentials` | Cargo crate registry tokens |
| `~/.cargo/credentials.toml` | Cargo crate registry tokens (TOML format) |

All of these can be overridden with `--allow-read`:

**Fix:**

```bash
cplt config set allow.read "~/.m2/settings.xml"
cplt config set allow.read "~/.gradle/gradle.properties"
cplt config set allow.read "~/.npmrc"
```

Or for a single run: `cplt --allow-read ~/.m2/settings.xml`

> **Note:** these are the *overridable* credential denials (`DENIED_HOME_SUBPATHS`). A second list — `~/.netrc`, `~/.pypirc`, `~/.gem/credentials`, `~/.vault-token` — is meant to be hard-denied, and **on macOS it is**: the generic `allow.read` grants are emitted before the literal deny rules, and only `DENIED_HOME_SUBPATHS` and `DENIED_DOTFILES` get a post-deny re-allow, so no `allow.read` can reach them. **On Linux that guarantee does not currently hold.** Landlock is grant-only, so those files are withheld by omission rather than by a deny rule, and `allow.read` paths are added to the ruleset without being checked against the list — `cplt config set allow.read "~/.netrc"` therefore produces a working read grant. This is a known gap, tracked in #207; do not rely on the hard-deny list to stop a deliberate `allow.read` on Linux.

If you would rather not hand `~/.npmrc` to the agent at all, see [`NPM_CONFIG_USERCONFIG`](#yarn-1-and-unreadable-home-rc-files) below, or use a project-level `.npmrc`, which is readable as part of the project directory and can take its token from an environment variable.

> **Linux limitation:** The denials for files *inside an allowed tool dir* are only enforced on macOS (via SBPL literal deny rules). On Linux, Landlock cannot deny individual files within an allowed directory — the parent dirs (`.m2`, `.gradle`, `.cargo`) remain fully readable for dependency resolution. `~/.npmrc` is the exception: it sits at the top of `$HOME`, which is never granted, so it is withheld on both platforms.

## yarn 1 and unreadable home rc files

`yarn install` fails outright under the default policy when an `~/.npmrc` exists on the host — nothing is resolved and no `node_modules` is written:

```
yarn install v1.22.22
error Error: EACCES: permission denied, open '/home/you/.npmrc'
```

macOS reports the same failure as `EPERM: operation not permitted`. The errno differs by backend; the outcome does not.

**Fix.** If you only install from the public registry, point yarn at a different npmrc — the token stays outside the sandbox:

```bash
: > .npmrc.sandbox
NPM_CONFIG_USERCONFIG="$PWD/.npmrc.sandbox" cplt exec -- yarn install
```

If you do need the registry auth in `~/.npmrc`, allow it instead:

```bash
cplt config set allow.read "~/.npmrc"
```

Or for a single run: `cplt --allow-read ~/.npmrc`. Deleting an `~/.npmrc` you do not use works just as well. If you also keep a `~/.yarnrc`, neither fix covers it on its own — see below.

**Why only yarn 1.** `~/.npmrc` is denied by default because it commonly holds a registry token. Every package manager reads it; only yarn 1 treats an *unreadable* one as fatal. Both of its config loaders — `NpmRegistry.getPossibleConfigLocations`, which is what reaches `~/.npmrc`, and `parseRcPaths`, which reads the `.yarnrc` family — tolerate a *missing* file and rethrow everything else:

```js
} catch (error) {
  if (error.code === 'ENOENT' || error.code === 'EISDIR') {
    return {};
  } else {
    throw error;      // EACCES / EPERM reaches here
  }
}
```

npm, pnpm and bun all continue past a denied `~/.npmrc` and install normally from the public registry ([navikt/cplt#180](https://github.com/navikt/cplt/issues/180) measured npm 10.9.8, pnpm 11.22.0 and bun 1.4.0). The trigger is therefore the file's *existence*, not its contents: an `~/.npmrc` holding nothing but `save-exact=true` breaks yarn 1 exactly as a token-bearing one does.

**It is not only `~/.npmrc`.** `parseRcPaths` fails the same way on `~/.yarnrc` when it exists — including when `~/.npmrc` has already been allowed, so allowing `~/.npmrc` alone is not enough if you keep a `~/.yarnrc`:

```
error Error: EPERM: operation not permitted, open '/Users/you/.yarnrc'
```

`~/.yarnrc` is not in any deny list — like most home dotfiles it is simply never granted, since the sandbox enumerates the specific `$HOME` config files tools need rather than granting `$HOME` wholesale. Allow it the same way (`cplt config set allow.read "~/.yarnrc"`) if you keep one.

**Why `NPM_CONFIG_USERCONFIG` works.** It is on cplt's environment allowlist because it names a path rather than carrying a secret, and yarn 1's npmrc loader honours it — `this.config.userconfig || join(home, '.npmrc')` — so pointing it at a readable file makes yarn skip `~/.npmrc` without the sandbox ever granting it. That is why it is the better default: `allow.read` fixes the crash by handing the credential over, this fixes it by removing the need. It redirects only the npmrc loader, so a `~/.yarnrc` still needs the treatment above.

The XDG variables, by contrast, do not help. yarn 1's `.yarnrc` scan builds its own path list with hardcoded `~/.yarnrc` entries and runs before the XDG-aware `getConfigDir()` is consulted, so neither `XDG_CONFIG_HOME` nor `XDG_DATA_HOME` removes those paths from the list. yarn 2+ (berry) uses a different config loader and is unaffected.

One footgun with `allow.read`: the path must **exist** when cplt starts. A missing path is warned about and dropped, so `allow.read "~/.npmrc"` on a machine without one is silently inert — which is fine here, since yarn only fails when the file exists in the first place.

**Why cplt does not make the denial look like ENOENT.** The tempting accommodation is to report these files as *absent* rather than *denied*, which every package manager tolerates. macOS can express that — SBPL accepts `(deny file-read* (literal …) (with errno 2))`, and the read then fails with `No such file or directory`. Linux cannot: Landlock is grant-only with no control over the errno a denied `open` returns, and on Linux `~/.npmrc` is not denied by a rule at all — it is simply never granted. Shipping the macOS half would fix macOS, leave Linux (where this was reported) untouched, and split the two backends' denial semantics for every tool, not just yarn. One line of config is the better trade. Bubblewrap could mask the file with an empty `/dev/null` bind, but it is opt-in, applies only where the wrapper is active, and inverts the convention the existing deny-path masks follow, which deliberately use an unreadable placeholder so a masked read fails loudly rather than silently reading as empty.

Adding `~/.npmrc` to the default read grant is not an option either: that hands the npm token to the sandboxed agent, which is the one thing the denial exists to prevent.

## Cloud credential directories

The following directories are **entirely blocked** (no read, write, or execute):

| Directory | Purpose |
|-----------|---------|
| `~/.config/gcloud` | Google Cloud SDK config, ADC credentials, Python virtualenv |
| `~/.aws` | AWS credentials and config |
| `~/.azure` | Azure CLI credentials |
| `~/.kube` | Kubernetes cluster credentials |
| `~/.config/op` | 1Password CLI sessions |

### Reading individual files (e.g. Application Default Credentials)

You can grant **read-only** access to specific files inside these directories using `allow.read`:

```bash
# Per session
cplt --allow-read ~/.config/gcloud/application_default_credentials.json -- -p "deploy"

# Per repo (.cplt.toml)
cplt config set --repo allow.read ~/.config/gcloud/application_default_credentials.json
```

This lets GCP SDKs authenticate using the ADC JSON file without exposing the entire directory.

### Executing cloud CLIs (gcloud, aws, az) — intentionally blocked

Even with `allow.read`, the agent **cannot execute** binaries inside these directories. For example, `gcloud` uses a Python virtualenv at `~/.config/gcloud/virtenv/` which requires execute permission that the sandbox does not grant.

**This is intentional.** Cloud CLIs have unrestricted access to your cloud infrastructure — an agent running `gcloud` could create/delete resources, read secrets, or modify IAM policies. The sandbox prevents this escalation path.

**Workarounds:**

| Need | Solution |
|------|----------|
| GCP authentication for SDKs | `allow.read ~/.config/gcloud/application_default_credentials.json` — SDKs read the JSON directly |
| AWS authentication for SDKs | `allow.read ~/.aws/credentials` — SDKs read credentials directly |
| Running cloud CLI commands | Run them outside the sandbox in a regular terminal |
| CI/CD with cloud access | Use project-level service account keys or workload identity (not user credentials) |

> **Design principle:** `allow.read` grants read access to credential *files* so SDKs can authenticate. It does not grant execute permission because executing cloud CLIs would bypass the sandbox's network and filesystem restrictions.

## Developer tooling telemetry

Many developer tools — build systems, framework CLIs, language toolchains — send default-on usage analytics to external services. cplt uses two complementary layers to prevent this:

**Layer 1 — env var opt-outs** (injected unconditionally via `HARDENING_ENV_VARS`):

| Variable | Affects |
|----------|---------|
| `DO_NOT_TRACK=1` | Cross-tool standard signal ([consoledonottrack.com](https://consoledonottrack.com/)) |
| `NEXT_TELEMETRY_DISABLED=1` | Next.js build telemetry |
| `TURBO_TELEMETRY_DISABLED=1` | Turborepo usage telemetry |
| `CHECKPOINT_DISABLE=1` | HashiCorp tools (terraform, vault, packer, nomad) |
| `GATSBY_TELEMETRY_DISABLED=1` | Gatsby build telemetry |

**Layer 2 — proxy domain blocks** (in `blocked-domains.txt`):

| Domain | Blocks |
|--------|--------|
| `checkpoint.hashicorp.com` | HashiCorp version/update pings |
| `telemetry.nextjs.org` | Next.js telemetry fallback |
| `mobile.events.data.microsoft.com` | VS Code + all Microsoft extensions (1DS SDK) |
| `dc.services.visualstudio.com` | Older VS Code / App Insights |
| `telemetry.go.dev` | Go toolchain upload endpoint |
| `posthog.com` | AI agent analytics (PostHog — all subdomains) |

Tools continue to work normally — these are non-essential telemetry endpoints.

## AI agent telemetry

AI agents and their third-party packages often send usage analytics and crash reports to external services (PostHog, Sentry, etc.). cplt blocks these at two layers:

1. **Env var injection** — cplt injects `OMO_DISABLE_POSTHOG=1` and `DO_NOT_TRACK=1` so agents opt out before making any network call.
2. **Proxy blocklist** — `posthog.com` is in `blocked-domains.txt` as a fallback for tools that ignore env vars.

For the `oh-my-openagent` OpenCode plugin specifically, `OMO_DISABLE_POSTHOG=1` prevents PostHog from being initialised, so no network calls are made and no errors appear.

> **oh-my-openagent transcripts:** the plugin's Claude Code hooks feature writes transcripts to `$CLAUDE_CONFIG_DIR/transcripts` (default `~/.claude`), which the sandbox denies for non-Claude agents — the write fails with `EACCES` and OpenCode aborts the prompt. cplt therefore injects `CLAUDE_CONFIG_DIR=<XDG_STATE_HOME>/opencode/claude-config` (falling back to `~/.local/state/opencode/claude-config` when `XDG_STATE_HOME` is unset) for OpenCode sessions, into the write-allowed OpenCode state dir. If you set `CLAUDE_CONFIG_DIR` yourself, cplt respects it — add that path to `allow.write` if it lives outside the OpenCode dirs.

**If you use `allowed_domains` (allowlist mode):** The proxy blocklist is not consulted in this mode — the env var injection still suppresses telemetry silently.

**Impact:** None — telemetry is non-essential and the agent functions normally without it.

**Why blocked?** Analytics events may include code context, prompt fragments, or usage patterns that constitute unintended data exfiltration from inside the sandbox.

**If you want to allow telemetry** (not recommended):

```toml
# .cplt.toml
[hardening]
disabled_categories = ["telemetry_opt_out"]

[proxy]
blocked_domains = "none"   # disable the default blocklist entirely
```
