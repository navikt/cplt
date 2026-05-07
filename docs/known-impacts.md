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

**Fix:** Use `--allow-env-files` when working on projects that need env file loading:

```bash
cplt --allow-env-files -- -p "start the dev server and fix the failing test"
```

Or set it permanently in config:

```toml
[sandbox]
allow_env_files = true
```

## Lifecycle scripts (postinstall hooks)

npm/yarn/pnpm lifecycle scripts are **blocked by default** via `npm_config_ignore_scripts=true` and `YARN_ENABLE_SCRIPTS=false`. This prevents supply chain attacks through postinstall hooks, but may break packages that require post-install steps:

| Operation                        | Impact      | Why                                                            |
| -------------------------------- | ----------- | -------------------------------------------------------------- |
| `npm install` (download only)    | ✅ Works     | Packages are downloaded and extracted normally                 |
| `npm install` (with native deps) | ⚠️ May fail  | Packages like `node-gyp`, `sharp`, `bcrypt` need postinstall  |
| `npm run build` / `npm test`     | ✅ Works     | Explicit scripts are not blocked, only lifecycle hooks         |
| `yarn install` (Yarn Berry)      | ⚠️ May fail  | If packages have install scripts                               |

**Fix:** Use `--allow-lifecycle-scripts` when the project needs postinstall hooks:

```bash
cplt --allow-lifecycle-scripts -- -p "install dependencies and build the project"
```

Or set it permanently in config:

```toml
[sandbox]
allow_lifecycle_scripts = true
```

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

**JVM note:** On macOS, the JVM ignores `TMPDIR` — it reads `java.io.tmpdir` from `confstr(_CS_DARWIN_USER_TEMP_DIR)` which always returns `/var/folders/...`. cplt automatically injects `-Djava.io.tmpdir=<scratch> -Djansi.tmpdir=<scratch> -Djava.rmi.server.hostname=localhost` via `JAVA_TOOL_OPTIONS` so that Maven Surefire forks, the Kotlin compiler daemon, and Jansi native lib extraction all use the scratch dir. The RMI hostname flag ensures the Kotlin daemon's Java RMI communication stays on `localhost` (without it, `InetAddress.getLocalHost()` may resolve to a non-loopback IP via mDNS, which the sandbox blocks). Override with `--pass-env JAVA_TOOL_OPTIONS` if you need custom JVM flags. For inline mocking (MockK, Mockito, ByteBuddy), also add `--allow-jvm-attach` — see [JVM Attach API](#jvm-attach-api).

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
cplt config set sandbox.allow_write '["~/.local/share/kotlin"]'
```

If you're still seeing this error, check that you haven't set `scratch_dir = false` in your config:

```bash
cplt config explain sandbox.scratch_dir
```

## Cache exec (Playwright, pnpm dlx, etc.)

Some tools unpack and execute binaries directly from `~/Library/Caches`, which is exec-blocked by default:

| Tool | Cache path | Fix |
|---|---|---|
| Playwright (browsers) | `~/Library/Caches/ms-playwright/` | `--allow-cache-exec ms-playwright` |
| pnpm dlx | `~/Library/Caches/pnpm/dlx/` | `--allow-cache-exec pnpm/dlx` |

```bash
# Allow Playwright browser binaries
cplt --allow-cache-exec ms-playwright -- -p "run the e2e tests"

# Allow pnpm dlx-cached binaries
cplt --allow-cache-exec pnpm/dlx -- -p "run the scripts"

# Both at once
cplt --allow-cache-exec ms-playwright --allow-cache-exec pnpm/dlx -- -p "run tests"
```

Or set permanently in config:

```toml
[sandbox]
allow_cache_exec = ["ms-playwright", "pnpm/dlx"]
```

`--allow-cache-exec-any` opens exec for all of `~/Library/Caches` — use only as a last resort.

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

**Fix:** Use `--allow-localhost <PORT>` for specific services, or `--allow-localhost-any` for build tools that use random ports (Next.js, Vite, esbuild).

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
| `git config --global`              | ❌ Blocked   | `~/.gitconfig` is read-only                                      |
| `git remote set-url`               | ❌ Blocked   | Writes to `.git/config`                                           |
| `git submodule add`                | ❌ Blocked   | `.gitmodules` is write-protected (supply chain vector)            |
| Creating git hooks                 | ❌ Blocked   | `.git/hooks/` is write-protected (hooks run unsandboxed)          |
| Signed commits/tags                | ❌ Disabled  | `commit.gpgsign` and `tag.gpgsign` overridden to `false` via env; use `--allow-gpg-signing` to enable |

**Global git hooks**: If `core.hooksPath` is set in `~/.gitconfig`, cplt auto-detects the hooks directory and allows reading it so git operations succeed. Write access is explicitly denied to prevent persistence attacks. The hooks path must be under `$HOME` with at least 3 path components (e.g. `~/.config/git/hooks`) to prevent overly broad read access.

**Commit signing**: `~/.ssh` and `~/.gnupg` are blocked, so GPG/SSH signing would fail. Instead of opening private key directories, cplt injects `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_N`/`GIT_CONFIG_VALUE_N` env vars to disable `commit.gpgsign` and `tag.gpgsign` inside the sandbox. Commits made by Copilot are unsigned — this is expected since users typically re-sign on merge/squash. Use `--allow-gpg-signing` to override this (see [GPG signing](#gpg-commit-signing)).

## GPG commit signing

GPG commit/tag signing is **disabled by default** because `~/.gnupg` is blocked. Copilot commits are unsigned — you re-sign on merge/squash.

If you want Copilot commits to be signed (e.g. branch protection requires signatures), use `--allow-gpg-signing`:

```bash
cplt --allow-gpg-signing -- -p "commit your changes"
```

Or set it permanently in config:

```toml
[sandbox]
allow_gpg_signing = true
```

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

## JVM Attach API

JVM testing frameworks like **MockK** (inline mocking), **Mockito** (inline agents), and **ByteBuddy** use the JVM Attach API for runtime class instrumentation. This API creates a Unix domain socket at `/tmp/.java_pid<PID>` — which the sandbox blocks by default.

Enable it with `--allow-jvm-attach`:

```bash
cplt --allow-jvm-attach -- -p "run the tests"
```

Or permanently in config:

```bash
cplt config set sandbox.allow_jvm_attach true
```

**When to enable:**

- Kotlin/Java projects using **MockK** with `mockk()` or `mockkStatic()` inline mocking
- Projects using **Mockito** with `Mockito.mock()` on final classes (requires ByteBuddy agent)
- Any test suite that gets `"Could not self-attach to current VM using external process"` errors
- JMX monitoring tools that attach to running JVMs

**How it works:** The JVM creates a socket at `/tmp/.java_pid<PID>` (hardcoded path, not affected by `java.io.tmpdir`). A helper JVM process connects to this socket to load an instrumentation agent. The sandbox rule uses a regex pattern that only allows sockets matching `.java_pid<PID>` — all other Unix sockets in `/tmp` (including SSH agent, tmux, PostgreSQL) remain blocked.

**Security note:** This opens a narrow IPC channel for `.java_pid*`-named sockets only. SSH agent access (`SSH_AUTH_SOCK`) is NOT exposed — on macOS it lives at `/private/tmp/com.apple.launchd.*/Listeners` which does not match the pattern.

## Port restriction

Only port 443 is allowed by default. Services on other ports need `--allow-port`:

- `npm install` from private registries on non-standard ports
- API calls to services not on 443
- FTP, SMTP, or other protocol connections

## Private registries

Registry credential files are **blocked by default** because they typically contain passwords or tokens that a rogue agent could exfiltrate:

| File | Purpose |
|------|---------|
| `~/.npmrc` | npm registry auth (hard deny — not overridable) |
| `~/.m2/settings.xml` | Maven repository credentials |
| `~/.m2/settings-security.xml` | Maven master password |
| `~/.gradle/gradle.properties` | Gradle/Nexus/Artifactory credentials |
| `~/.cargo/credentials` | Cargo crate registry tokens |
| `~/.cargo/credentials.toml` | Cargo crate registry tokens (TOML format) |

For Maven, Gradle, and Cargo files, you can override this with `--allow-read`:

```bash
# Per session — Maven
cplt --allow-read ~/.m2/settings.xml -- -p "build with Maven"

# Per session — Gradle
cplt --allow-read ~/.gradle/gradle.properties -- -p "build with Gradle"

# Multiple files
cplt --allow-read ~/.m2/settings.xml --allow-read ~/.gradle/gradle.properties -- -p "build"
```

To allow permanently, add to `~/.config/cplt/config.toml`:

```toml
[allow]
read = ["~/.m2/settings.xml", "~/.gradle/gradle.properties"]
```

> **Note:** `.npmrc` cannot be overridden — it is in the hard-deny list alongside `.netrc` and `.pypirc`. If you need npm private registry access, consider using project-level `.npmrc` (which is readable as part of the project directory) with a token injected via environment variable.

> **Linux limitation:** These file-level denials are only enforced on macOS (via SBPL literal deny rules). On Linux, Landlock cannot deny individual files within an allowed directory — the parent dirs (`.m2`, `.gradle`, `.cargo`) remain fully readable for dependency resolution.
