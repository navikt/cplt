# cplt CLI Design Guide

> UX principles and conventions for a security-focused sandbox wrapper.
> Based on [clig.dev](https://clig.dev), GNU/POSIX conventions, 12-Factor CLI Apps,
> and patterns from gh, cargo, ripgrep, kubectl, and Deno.

---

## Philosophy

cplt is a **security tool that must feel like a developer tool**. Users won't adopt
a sandbox they fight with. Every UX decision balances two tensions:

1. **Security strictness** — deny-by-default, never silently weaken
2. **Developer flow** — get out of the way, don't make me think

When in doubt: be strict by default, but make relaxation easy and explicit.

The threat model ([SECURITY.md](../SECURITY.md)) assumes the sandboxed agent
is **untrusted** — it may execute arbitrary code from prompt injection, supply
chain attacks, or compromised dependencies. The CLI UX must reflect this:
security is not a feature you toggle, it's the baseline.

### Core principles

| # | Principle | cplt implication |
|---|-----------|------------------|
| 1 | **Human-first** | CLI is a text UI, not a scripting primitive. Invest in formatting. |
| 2 | **Saying just enough** | No silent hangs, no debug dumps. One line per action. |
| 3 | **Secure defaults** | Every flag defaults to the restrictive option. |
| 4 | **Honest about gaps** | Never overstate protection. Name what's kernel-enforced vs. best-effort. |
| 5 | **Ease of discovery** | `--doctor`, `config explain`, progressive help. |
| 6 | **Conversation** | Suggest next steps: "run `cplt --doctor` to diagnose". |
| 7 | **Composability** | Data on stdout, diagnostics on stderr. Scriptable exit codes. |
| 8 | **Empathy** | Error messages answer "what now?", not just "what happened". |
| 9 | **Fail closed** | If a security check can't run, deny — never silently proceed. |

---

## 1. Naming

### 1.1 Subcommands: noun–verb, singular nouns

```
cplt config show        # noun = config, verb = show
cplt config validate
cplt trust accept       # noun = trust, verb = accept (security-meaningful)
cplt trust revoke
```

- **Nouns are singular** for singleton concepts: `config`, `trust`, `update`.
- **Verbs are imperative**: `show`, `set`, `get`, `init`, `explain`.
- Use **domain-specific verbs** for security decisions: `trust accept` / `trust revoke`
  instead of generic `add` / `remove` — the verb should communicate the security meaning.
- The bare noun is the **default action**: `cplt config` → `cplt config show`.
- Never create a `*:list` or `* list` subcommand — the bare noun IS the list.

### 1.2 Flags: `--kebab-case`, consistent prefixes

| Prefix | Meaning | Examples |
|--------|---------|----------|
| `--allow-*` | Grant a permission | `--allow-read`, `--allow-port`, `--allow-localhost` |
| `--deny-*` | Revoke a permission | `--deny-path` |
| `--no-*` | Disable a default-on behavior | `--no-proxy`, `--no-quiet`, `--no-validate` |
| `--with-*` | Enable an optional feature | `--with-proxy` |
| `--pass-*` | Forward something through | `--pass-env` |

**Rules:**

- Boolean flags that default to **on** get a `--no-*` form to disable.
- Boolean flags that default to **off** are bare: `--verbose`, `--yes`.
- Don't mix `--no-*` and `--skip-*` — pick one prefix. cplt uses `--no-*`.
- Never accept secrets via flags (they appear in `ps` and shell history).
  Use env vars, `--token-file`, or stdin.

### 1.3 Short flags: reserve for frequent use

Only assign short flags to options used **interactively in every session**:

```
-d    --project-dir       # every invocation
-q    --quiet             # common preference
-y    --yes               # batch mode
```

Don't assign short flags to security-sensitive options (`--allow-*`, `--deny-*`)
— they should be typed deliberately. Don't assign `-v` — it's ambiguous between
`--verbose` and `--version`.

### 1.4 Arguments: minimize positional args

Positional arguments are allowed only when the meaning is **universally obvious**:

```
cplt -- -p "fix the tests"     # everything after -- is the wrapped command
cplt config set KEY VALUE       # key-value pair is a natural ordered pair
```

For everything else, use named flags. Compare:

```
# Bad: what is each positional?
cplt fork myapp destapp

# Good: self-documenting
cplt fork --from myapp --to destapp
```

### 1.5 Avoid naming traps

- **No catch-all subcommand**: don't make `cplt echo` run `echo` in the sandbox.
  Use `cplt -- echo` with explicit separator.
- **No abbreviation matching**: `cplt con` should NOT resolve to `config`.
  This prevents ever adding a `connect` subcommand.
- **No ambiguous siblings**: don't have both `update` and `upgrade`.

---

## 2. Help text

### 2.1 Structure: progressive disclosure

```
cplt — run AI coding agents in a macOS/Linux sandbox

USAGE
  cplt [flags] -- <agent-args>
  cplt <command> [flags]

CORE COMMANDS
  config      Manage configuration
  trust       Manage project trust
  update      Update cplt

COMMON FLAGS
  -d, --project-dir <path>   Project directory (default: cwd)
  -q, --quiet                Suppress the configuration banner
  -y, --yes                  Auto-approve prompts

SANDBOX FLAGS
  --allow-read <path>        Grant read access beyond the project
  --allow-write <path>       Grant write access beyond the project
  --deny-path <path>         Block access to a path
  --allow-port <port>        Allow outbound network to a port

Run 'cplt --help' for the complete flag reference.
Run 'cplt <command> --help' for command-specific help.

EXAMPLES
  cplt -- -p "fix the tests"
  cplt --allow-port 3000 -- -p "start the dev server"
  cplt --doctor
```

**Principles:**

- **Top-level help shows 5–10 flags**, not 50. Group by frequency.
- **Full help** (`cplt --help`) shows everything, organized by category.
- Each description fits **one line, ≤80 chars**. No trailing period.
- Commands grouped by purpose (Core / Diagnostics / Management), like `gh`.
- End with 2–3 **real-world examples** showing progressive complexity.
- Always show `EXAMPLES` — it's the most-read section.

### 2.2 Description style

```
# Good: what it does + when you'd use it
--allow-localhost-any    Allow all localhost ports (for Vite, Next.js, Turbopack)

# Bad: restating the flag name
--allow-localhost-any    Allow any localhost
```

- Start with a verb: "Allow", "Grant", "Block", "Show", "Print".
- Name specific tools/frameworks when a flag exists for their sake.
- Mark dangerous flags: append `(DANGEROUS)` or `⚠` in the description.

### 2.3 Long descriptions

For flags with nuance, use clap's `long_help` (shown in `--help`, hidden in `-h`):

```rust
#[arg(
    long,
    help = "Allow all localhost ports (for Vite, Next.js, Turbopack)",
    long_help = "Allow all localhost ports. Use this when your dev server \
                 binds to a random port. Equivalent to --allow-localhost '*'. \
                 If combined with --allow-jvm-attach, uses '*:*' because \
                 Java NIO's IPv4-mapped addresses aren't matched by SBPL's \
                 localhost filter."
)]
```

---

## 3. Output formatting

### 3.1 The three output tiers

Every user-facing output should work in three modes:

| Mode | Detection | Behavior |
|------|-----------|----------|
| **Human (TTY)** | `stdout.is_terminal()` | Colors, alignment, symbols (✓ ✗ ⚠) |
| **Pipe** | `!stdout.is_terminal()` | Plain text, no ANSI, grep-friendly |
| **Structured** | `--json` flag | JSON to stdout, diagnostics to stderr |

Currently cplt primarily uses human mode. Future work should add pipe and
JSON support where appropriate (`--doctor --json`, `config show --json`).

### 3.2 Color semantics

| Color | ANSI | Meaning | Used for |
|-------|------|---------|----------|
| Red | `\x1b[0;31m` | Error, blocked, denied | `[cplt] Error: ...`, `✗ denied` |
| Yellow | `\x1b[0;33m` | Warning, caution, dangerous | `⚠ (DANGEROUS)`, `--inherit-env` |
| Green | `\x1b[0;32m` | Success, allowed, passed | `✓ allowed`, `✓ auth found` |
| Blue | `\x1b[0;34m` | Informational, labels | `[cplt]` prefix, headers |
| Bold | `\x1b[1m` | Section headers, emphasis | `── Sandbox Configuration ──` |
| Gray | `\x1b[0;90m` | Secondary, diminished | Timestamps, paths, defaults |

**Rules:**

- Red is **only** for genuine errors and security denials. Never for warnings.
- Use symbols **and** color — don't rely on color alone (accessibility).
- Respect `NO_COLOR` env var, `TERM=dumb`, and `--no-color` flag.
  Check: `NO_COLOR` set → no color. `FORCE_COLOR` set → force color.
- Degrade gracefully: true-color → 256-color → 16-color → plain.

### 3.3 Spacing and alignment

The configuration banner uses **columnar alignment** — maintain this:

```
[cplt]  Filesystem:
[cplt]    Project:       read/write  /path/to/project
[cplt]    Extra read:    allowed     ~/shared-libs
[cplt]    Deny:          blocked     ~/.ssh
```

- **Indent with 2 spaces** per nesting level.
- **Align columns** within a section (pad labels to equal width).
- **One record per line** — keep output grep-friendly.
- **No box-drawing characters** beyond simple `──` dividers.

### 3.4 stdout / stderr contract

Different commands have different output contracts:

| Command type | stdout | stderr |
|---|---|---|
| **Wrapper run mode** | agent stdout (passthrough) | cplt banner, proxy logs, errors |
| **Machine-readable**: `config get`, `config path` | raw value | notes, warnings |
| **Human reports**: `--doctor`, `config show` | formatted report | errors, progress |
| **Profile output**: `--print-profile` | profile text | errors only |

**Rule**: anything a script might pipe or capture goes to stdout.
Everything else — banners, warnings, progress, proxy logs — goes to stderr.

### 3.5 Prefix convention

All cplt output uses a **bracketed prefix** on stderr:

```
[cplt]    — main program messages
[proxy]   — proxy subsystem messages
[doctor]  — diagnostic output
```

This is good. It enables `cplt 2>&1 | grep '\[proxy\]'` filtering.
Maintain this consistently across all output.

### 3.5 Verbosity levels

cplt has two independent verbosity controls — keep them separate:

| Control | Levels | Scope |
|---------|--------|-------|
| `--quiet` / `--no-quiet` | on/off | Configuration banner |
| `--proxy-log-level` | `none`, `error`, `blocked`, `all` | Proxy connection log |

This is the right model. Don't merge them into a single `-v` flag — the
audiences are different (user vs. network auditor).

Future: consider `CPLT_LOG=debug` env var for internal diagnostics (tracing),
following the `CARGO_LOG` / `RUST_LOG` convention.

---

## 4. Error messages

### 4.1 Anatomy of a good error

Every error should contain up to four parts:

```
[cplt] Error: cannot resolve deny.paths entry "~/.nonexistent"        ← WHAT
  --> ~/.config/cplt/config.toml:12                                    ← WHERE
  Caused by: No such file or directory (os error 2)                    ← WHY
  hint: Fix the path or remove it. Silently dropping deny rules        ← HOW
        is a security risk.
```

| Part | When to include |
|------|----------------|
| **What** | Always. Be specific: "cannot resolve path", not "error". |
| **Where** | When a file/line is relevant (config errors, profile errors). |
| **Why** | When the root cause differs from the symptom. |
| **How to fix** | Always for user-caused errors. Skip for internal bugs. |

### 4.2 Error patterns

**Actionable config errors** (cplt does this well — keep it):
```
Unknown section [proxxy]: did you mean [proxy]?
```

**Sandbox execution errors** (room for improvement):
```
# Current:
[cplt] Failed to start sandboxed process: No such file or directory

# Better:
[cplt] Error: sandbox failed to start
  Caused by: copilot binary not found
  hint: Run `cplt --doctor` to check your installation
```

**Security-critical errors** must:
- Never be silenced by `--quiet`
- Explain the security implication
- Fail closed (error out, don't proceed with weaker security)

**Deny-path resolution errors** (this pattern is correct — preserve it):
```
[cplt] Error: deny.paths entry "~/.nonexistent" cannot be resolved
  Caused by: No such file or directory (os error 2)
  Silently dropping deny rules is a security risk.
  Fix the path in your config or remove it.
```

**SBPL injection prevention** (from SECURITY.md Layer 3):
```
[cplt] Error: path contains unsafe characters for sandbox profile
  Path: /tmp/evil\n(allow file-read* (subpath "/"))
  Blocked characters: newline, null, quotes, parentheses, semicolons
  These could inject rules into the sandbox profile.
```

**Unsafe root rejection** (from SECURITY.md Layer 3):
```
[cplt] Error: refusing to sandbox with project directory "/"
  This would grant the agent read/write access to the entire filesystem.
  Use a specific project directory instead.
```

### 4.3 Anti-patterns

- ❌ **Bare error codes**: `Error: ENOENT` — meaningless to most users.
- ❌ **Stack traces for user errors**: reserve for `--debug` or internal bugs.
- ❌ **Double-printing**: cargo's `AlreadyPrintedError` pattern — if a subsystem
  already printed the error, don't print it again at the top level.
- ❌ **Swallowed errors**: never silently ignore a failure. Warn or error.

---

## 5. Exit codes

### 5.1 Current behavior

cplt already passes through the agent's exit code — when the sandbox starts
successfully, `ExitCode::from(child_exit_code)` is returned. However, wrapper
errors (config, sandbox setup) also exit 1, making them indistinguishable from
an agent that exited 1.

### 5.2 Recommended convention

```
0           Success (sandbox ran, agent exited cleanly)
1–124       Agent's exit code (passed through unchanged)
125         cplt wrapper failure (config error, sandbox setup failed)
126         Agent found but not executable / sandbox launch denied
127         Agent binary not found
128 + N     Agent terminated by signal N (e.g., 130 = Ctrl+C)
2           Usage error (clap already does this for bad arguments)
```

The key insight: scripts need to distinguish "cplt itself failed" from
"the agent returned an error". Using 125 for wrapper failures (the git
convention) avoids collision with typical agent exit codes.

### 5.3 Documentation

Exit codes should be documented in:
- `--help` (brief, in the EXAMPLES section or a dedicated EXIT CODES section)
- `README.md` (reference table)
- Man page (if/when generated)

### 5.4 Signal exits

When the child is killed by a signal, return `128 + signal_number` instead
of collapsing to 1. This is the POSIX convention and lets callers detect
SIGKILL, SIGSEGV, etc.

### 5.5 Broken pipe

When stdout is a pipe and the reader closes early, exit 0 — not an error.
This is what ripgrep does and what users expect from `cplt ... | head`.

---

## 6. Configuration UX

### 6.1 Precedence (cplt already follows this — document it)

```
1. CLI flags              (highest priority)
2. Repo-local config      (.cplt.toml, trust-gated)
3. User config            (~/.config/cplt/config.toml, or CPLT_CONFIG path)
4. Built-in defaults      (lowest priority, always secure)
```

Note: `CPLT_CONFIG` controls the config file **location**, not individual
settings. There is no general `CPLT_*` env var mapping for config keys.
If env-based overrides are added in the future, they should follow the
pattern `CPLT_SANDBOX_QUIET=true` (section + key, underscored).

### 6.2 Config discovery commands

cplt has excellent config tooling — maintain the pattern:

| Command | Purpose |
|---------|---------|
| `cplt config init` | Create starter config (never overwrites) |
| `cplt config show` | Display effective config (merged from all sources) |
| `cplt config validate` | Check for errors with suggestions |
| `cplt config explain` | Learn what each key does |
| `cplt config path` | Print config file path |
| `cplt config get KEY` | Print a single value |
| `cplt config set KEY VAL` | Modify a value |

### 6.3 Config validation messages

Follow the "did you mean?" pattern consistently:

```
# Typo in section name
Unknown section [sandboxx]: did you mean [sandbox]?

# Typo in key name
Unknown key 'quite' in [sandbox]: did you mean 'quiet'?

# Type mismatch
Type error in sandbox.quiet: expected boolean, got string "yes"
  hint: Use `true` or `false` (TOML booleans are bare words)

# Security issue
Empty deny.paths list: this removes all path denials.
  hint: Remove the [deny] section entirely to use defaults,
        or list specific paths to deny.
```

---

## 7. Security-specific UX

cplt treats the sandboxed agent as **untrusted** — it may execute arbitrary
code suggestions on your machine. Every UX choice in this section is informed
by the threat model in [SECURITY.md](../SECURITY.md).

### 7.1 The untrusted-agent mental model

Users must understand what cplt protects and what it doesn't. The banner
and help text should reinforce the four defense layers:

| Layer | What it does | UX surface |
|-------|-------------|------------|
| **Env sanitization** | Clears env, re-adds safe allowlist only | `--pass-env`, `--inherit-env (DANGEROUS)` |
| **Env hardening** | Injects `npm_config_ignore_scripts=true`, git signing off | `--allow-lifecycle-scripts`, `--allow-gpg-signing` |
| **Kernel sandbox** | Seatbelt (macOS) / Landlock+seccomp (Linux) | `--allow-read`, `--deny-path`, `--allow-port` |
| **CONNECT proxy** | Domain blocking, port enforcement, DNS rebinding defense | `--no-proxy`, `--proxy-log-level`, `--blocked-domains` |

Help text and error messages should reference these layers by name so users
build an accurate mental model. For example:

```
[cplt] ⚠ --allow-lifecycle-scripts disables env hardening for npm/yarn/pnpm.
         Supply chain attacks (e.g., postinstall hooks) will not be blocked.
```

### 7.2 The `(DANGEROUS)` marker

Flags that weaken the sandbox are marked `(DANGEROUS)` in help text.
This is effective — keep it.

**Which flags qualify as DANGEROUS:**

A flag is `(DANGEROUS)` when it removes a defense layer or creates a new
attack surface. Assess using the kill chain from SECURITY.md:

| Flag | What it weakens | Kill chain impact |
|------|----------------|-------------------|
| `--inherit-env` | Env sanitization (Layer 0) | Credential harvest: `AWS_*`, `NPM_TOKEN` etc. become readable |
| `--allow-lifecycle-scripts` | Env hardening (Layer 0.25) | Infection: `postinstall` hooks can run arbitrary code |
| `--allow-docker` | Kernel sandbox (Layer 1) | Full escape: Docker socket grants host-level access |
| `--allow-tmp-exec` | Kernel sandbox (Layer 1) | Binary staging: write+exec in `/tmp` |
| `--allow-gpg-signing` | Kernel sandbox (Layer 1) | Signature impersonation + decryption via GPG agent socket |
| `--allow-cache-exec-any` | Kernel sandbox (Layer 1) | Binary staging: write+exec in entire `~/Library/Caches` |

**Rules:**

- Apply to any flag that bypasses a security boundary listed above.
- Show a **runtime warning** when a dangerous flag is used, explaining
  which defense layer is weakened and why it matters:
  ```
  [cplt] ⚠ --inherit-env passes ALL environment variables into the sandbox.
         AWS_*, NPM_TOKEN, DATABASE_URL and other secrets become readable.
         The agent is untrusted and may exfiltrate these via HTTPS.
  ```
- Never require `(DANGEROUS)` flags for common workflows.
- Dangerous flags should be **absent from short help** (`-h`) and only
  visible in full help (`--help`), reducing accidental discovery.

### 7.3 Graduated risk communication

Not all `--allow-*` flags are equally dangerous. Use three tiers:

| Tier | Marker | Example | Runtime behavior |
|------|--------|---------|-----------------|
| **Safe** | (none) | `--allow-read ~/shared-libs` | Silent — normal operation |
| **Caution** | `⚠` in banner | `--allow-localhost-any`, `--allow-port 80` | Yellow warning in banner |
| **Dangerous** | `(DANGEROUS)` | `--inherit-env`, `--allow-docker` | Red warning, always shown (not silenced by `--quiet`) |

**Compound risk escalation**: When `--allow-localhost-any` + `--allow-jvm-attach`
are both set, the SBPL rule broadens to `"*:*"` (all outbound TCP). This
compound effect must be communicated:

```
[cplt] ⚠ --allow-localhost-any + --allow-jvm-attach: all outbound TCP allowed.
         SBPL localhost filter cannot match Java's IPv4-mapped addresses.
         The proxy remains as a compensating control for domain filtering.
```

### 7.4 Trust model UX

The repo-local config trust model (`.cplt.toml`) has specific security
properties that the UX must surface. From SECURITY.md:

- `.cplt.toml` is read from **git HEAD** (committed state), not the working
  tree — the agent cannot modify its own config mid-session.
- `[propose]` sections have **no effect** until explicitly approved.
- `[deny]` sections are **applied automatically** (they can only tighten).
- Approvals are **content-pinned** (SHA-256) — changing proposed values
  invalidates previous approvals.
- Trust entries are stored in `~/.config/cplt/trust/` — **outside the sandbox**.

Surface this clearly:

```
[cplt] Repo config (.cplt.toml):
[cplt]   Source:    git HEAD (tamper-proof)
[cplt]   Deny:     applied  deny-path ~/.credentials (tighten-only, auto-applied)
[cplt]   Propose:  pending  allow-port 3000, allow-localhost-any
[cplt]   Run `cplt trust accept` to approve proposed permissions
```

**Design decisions from SECURITY.md to preserve:**

- **No interactive approval during launch.** cplt deliberately does NOT prompt
  "approve these? [y/N]" when unapproved permissions exist. This prevents
  approval fatigue. Approval requires a separate deliberate command.
- **Additive-only semantics.** Repo config can enable features but cannot
  disable anything set by CLI flags or global config.
- **Path traversal rejection.** Paths containing `..` are rejected at parse time.

### 7.5 Deny-path asymmetry

Allow-paths and deny-paths have deliberately different error handling,
because the security implications differ:

| Path type | Unresolvable path | Rationale |
|-----------|-------------------|-----------|
| `--allow-read` | Warn and skip | Missing allow is safe (less access) |
| `--deny-path` | **Hard error, abort** | Silently dropping a deny rule is a security risk |

This asymmetry is correct and must be preserved. Error messages should
explain the security rationale:

```
[cplt] Error: deny.paths entry "~/.nonexistent" cannot be resolved
  Silently dropping deny rules is a security risk.
  Fix the path in your config or remove it.
```

### 7.6 Audit trail

The proxy provides a connection-level audit trail. UX rules:

- Use **one line per event**, structured for grep/jq.
- Include timestamp, method, target (host:port), and decision.
- Never log request bodies — the proxy is a CONNECT tunnel (TLS passthrough),
  and logging body content would require TLS interception (out of scope).
- Log **all** traffic including Copilot's own connections (via `NODE_USE_ENV_PROXY`).

```
2025-01-15T10:32:44.123Z CONNECT api.github.com:443 OK
2025-01-15T10:32:45.234Z CONNECT evil.com:443 BLOCKED (not in allowlist)
2025-01-15T10:32:46.345Z CONNECT 169.254.169.254:80 BLOCKED (private IP)
```

The DNS rebinding defense should be visible in logs when it triggers:

```
2025-01-15T10:32:47.456Z CONNECT legit-looking.com:443 BLOCKED (resolved to 127.0.0.1, private IP)
```

### 7.7 Honest gaps in UX

SECURITY.md documents honest gaps — the design guide should ensure these
are **not hidden** from users. Gaps that affect UX decisions:

| Gap | UX implication |
|-----|---------------|
| Project source code is readable+writable | Don't claim "everything is protected" — be honest about blast radius |
| `~/.config/gh/hosts.yml` token is readable | Document mitigation: `--deny-path ~/.config/gh` |
| DNS tunneling is not blocked | Don't claim "all network is filtered" |
| `.env` protection is macOS-only (Seatbelt) | On Linux, warn: "`.env` exfiltration blocked by proxy, not kernel" |
| Interpreter-based temp exec bypasses sandbox | Don't claim "no execution from /tmp" — clarify: "no *binary* execution" |
| `~/Library/Caches` write+exec dirs exist | `--allow-cache-exec <SUBDIR>` help should state the accepted risk |
| `~/.copilot/` session history is accessible | Document mitigation: `--deny-path ~/.copilot/session-state` |

The `--doctor` output and help text should use precise language:

```
# Good: precise claim
Credential files (SSH, AWS, cloud) are kernel-blocked from reading.

# Bad: overpromise
All sensitive data is fully protected inside the sandbox.
```

---

## 8. Diagnostics (`--doctor`)

### 8.1 Output structure

cplt's `--doctor` output is well-designed. Maintain the pattern:

```
[doctor] Section Name
  ✓ Check passed: detail
  ⚠ Check warning: detail
    Fix: actionable remediation
  ✗ Check failed: detail
    Fix: actionable remediation

Summary: 8 passed, 1 warning, 1 error
```

### 8.2 Rules

- Every `✗` and `⚠` must include a `Fix:` or `hint:` line.
- Exit 0 only if all critical checks pass (warnings are OK).
- Group checks by defense layer (matching SECURITY.md):
  Auth → Agents → Tools → Sandbox Mechanism → Protected Paths → Config.
- Show **full resolved paths** — users need to verify the right binary is found.
- **Security checks are never optional**: sandbox mechanism, protected path
  verification, and auth checks must always run regardless of `--quiet`.

### 8.3 Security-specific doctor checks

These checks validate SECURITY.md's defense layers are operational:

```
[doctor] Sandbox mechanism
  ✓ macOS: Seatbelt (sandbox-exec) available
  ✓ Profile generation: deny-default verified

[doctor] Protected paths
  ✓ ~/.ssh exists and will be denied (5 key files)
  ✓ ~/.aws exists and will be denied
  ⚠ ~/.gnupg not found (GPG signing protection: N/A)
  ✓ ~/.npmrc exists and will be denied (npm token protected)

[doctor] Env sanitization
  ✓ Allowlist: 49 safe vars + 8 prefixes
  ✓ Hardening: npm_config_ignore_scripts=true will be injected
  ⚠ ANTHROPIC_API_KEY in environment (not passed through by default)
    hint: Use --pass-env ANTHROPIC_API_KEY to forward explicitly

[doctor] Proxy
  ✓ Proxy: will bind on ephemeral port
  ✓ Blocked domains: 47 entries loaded from blocked-domains.txt
  ✓ DNS rebinding: private IP validation enabled
```

### 8.4 Doctor trust model

From SECURITY.md: `--doctor` runs agent binaries with `--version` **outside
the sandbox** with full user privileges. This is noted in the security model
as an accepted trust boundary. The doctor output should not suggest that
these version checks are sandboxed:

```
[doctor] Agents (running outside sandbox)
  ✓ Copilot (copilot) v1.0.21: /opt/homebrew/bin/copilot
```

### 8.3 Future: machine-readable doctor

Consider `cplt --doctor --json` for CI integration:

```json
{
  "checks": [
    {"name": "auth.github_token", "status": "pass", "detail": "GITHUB_TOKEN is set"},
    {"name": "agent.copilot", "status": "pass", "detail": "v1.0.21 at /opt/homebrew/bin/copilot"},
    {"name": "sandbox.mechanism", "status": "fail", "detail": "Landlock requires kernel 5.13+"}
  ],
  "summary": {"pass": 8, "warn": 1, "fail": 1}
}
```

---

## 9. Shell completion

### 9.1 Generation

Provide completion scripts for bash, zsh, fish, and PowerShell:

```bash
cplt completions bash  > /usr/local/etc/bash_completion.d/cplt
cplt completions zsh   > ~/.zfunc/_cplt
cplt completions fish  > ~/.config/fish/completions/cplt.fish
```

### 9.2 Smart completions

- Complete `--allow-read` with filesystem paths.
- Complete `--agent` with discovered agent names (`copilot`, `opencode`).
- Complete `--proxy-log-level` with `none`, `error`, `blocked`, `all`.
- Complete `config` subcommands with `show`, `validate`, `init`, etc.

---

## 10. Version output

```
$ cplt --version
cplt 0.8.2 (macOS, Seatbelt)

$ cplt --version --verbose
cplt 0.8.2 (macOS, Seatbelt)
  commit:    a2b3c4d
  built:     2025-01-15
  rust:      1.83.0
  sandbox:   Seatbelt (macOS) / Landlock ABI 3 (Linux)
```

Keep the first line parseable: `cplt <semver>`. Scripts can do:
```bash
cplt --version | awk '{print $2}'
```

---

## 11. Interaction patterns

### 11.1 Non-interactive mode

Every prompt must have a flag equivalent:

| Prompt | Flag override |
|--------|---------------|
| "Approve repo config?" | `-y` / `--yes` |
| "Allow dangerous flag?" | `-y` |
| "Create config file?" | `--init-config` |

When `!stdin.is_terminal()` or `--yes` is set, use the safe default
(deny) for security prompts, and proceed for non-security prompts.

### 11.2 Ctrl+C handling

```
^C                          → forward SIGINT to agent, wait briefly
^C^C (within 1 second)      → kill agent immediately, exit
```

Don't print "Gracefully stopping..." unless cleanup takes >1 second.

### 11.3 Long-running operations

For operations that take >2 seconds (update, doctor network checks):

```
[cplt] Checking for updates...
[cplt] ✓ Updated to 0.8.3 (was 0.8.2)
```

One status line, one result line. No progress bars unless the operation
takes >10 seconds with measurable progress.

---

## 12. Wrapper ergonomics

cplt is both a CLI and a wrapper. This creates unique UX challenges.

### 12.1 Flag ownership

```
cplt [cplt-flags] -- [agent-flags]
```

- Everything before `--` belongs to cplt.
- Everything after `--` is forwarded to the agent unchanged.
- **Never add a cplt flag that collides** with common agent flags unless it's
  explicitly cplt's responsibility (e.g., `--resume` is Copilot-specific).

### 12.2 Pass-through flags

Some cplt flags exist purely to forward to specific agents:
`--resume`, `--continue`, `--remote`, `--name`.

Rules for pass-through flags:
- Document which agent they apply to.
- Warn (don't error) when used with an agent that doesn't support them.
- Prefer strict `--` forwarding over adding more top-level pass-through flags.
- For future agents, use `--agent-arg KEY=VALUE` over new top-level flags.

### 12.3 Proxy default

The proxy is **enabled by default** — `--with-proxy` is a no-op in the
default configuration. The meaningful override is `--no-proxy` to disable it.
Help text should present `--no-proxy` as the primary control, with
`--with-proxy` documented as "force-enable if disabled in config."

---

## 13. Platform capability UX

cplt's security enforcement varies significantly by platform. SECURITY.md
documents the precise enforcement comparison — the UX must make this
transparent, not abstract it away.

### 13.1 Name the active backend

Always tell the user which enforcement mechanism is active:

```
[cplt] Sandbox: Seatbelt (macOS)
[cplt] Sandbox: Landlock ABI 5 + seccomp (Linux)
[cplt] Sandbox: Landlock ABI 1 + seccomp + proxy (Linux, no port filtering)
[cplt] Sandbox: proxy-only (Landlock not available)
```

Include the Landlock ABI version — it determines which features work:

| ABI | Kernel | Capabilities gained |
|-----|--------|---------------------|
| v1  | 5.13+  | Filesystem access control |
| v2  | 5.19+  | + file refer (cross-directory rename) |
| v3  | 6.2+   | + file truncate |
| v4  | 6.7+   | + TCP port filtering |
| v5  | 6.10+  | + ioctl on character devices |

### 13.2 Platform enforcement comparison

The banner and `--doctor` should surface real enforcement differences,
not hide them. From SECURITY.md:

| Protection | macOS (Seatbelt) | Linux (Landlock + seccomp) |
|---|---|---|
| Credential files (~/.ssh, ~/.aws) | ✅ Kernel deny | ✅ Deny-by-default |
| Project .env reads | ✅ Kernel deny | ⚠️ Proxy blocks exfiltration |
| .git/hooks write in project | ✅ Kernel deny | ⚠️ Env hardening only |
| Network: outbound port filtering | ✅ Kernel | ✅ Kernel (ABI v4+) / ⚠️ Proxy (<v4) |
| Network: localhost isolation | ✅ Kernel deny | ⚠️ Proxy domain filtering |
| Exec from /tmp | ✅ Kernel deny | ✅ Landlock deny |
| --deny-path | ✅ Kernel deny | ❌ No effect (warned) |
| Dangerous syscalls | N/A (Seatbelt) | ✅ seccomp-BPF |

Legend: ✅ = kernel-enforced, ⚠️ = defense-in-depth (proxy/env), ❌ = not available

### 13.3 Degradation policy

**Principle: users must know their actual protection level.** Never silently
downgrade enforcement without informing the user.

- **Kernel enforcement unavailable**: warn prominently and name the
  compensating control:
  ```
  [cplt] ⚠ Network port filtering: proxy-only (Landlock ABI < 4)
           Install kernel 6.7+ for kernel-level port enforcement
  ```
- **Feature partially enforced**: show what works and what doesn't:
  ```
  [cplt] ⚠ .env file protection on Linux: proxy blocks exfiltration,
           but files are readable inside the sandbox (kernel deny
           requires Seatbelt/macOS)
  ```
- **Flag has no effect on this platform**: warn at startup. From SECURITY.md,
  `--deny-path` has no effect on Linux — this must produce a visible warning:
  ```
  [cplt] ⚠ --deny-path has no effect on Linux (Landlock cannot deny
           subpaths within allowed directories). Ignored.
  ```
- **Compound degradation**: when multiple features degrade simultaneously,
  summarize the aggregate impact:
  ```
  [cplt] ⚠ Linux sandbox (Landlock ABI 1): filesystem only.
           Network isolation relies entirely on the proxy.
           .env files and .git/hooks are protected by env hardening only.
  ```

### 13.4 Defense-in-depth UX

Some protections on Linux use defense-in-depth (proxy + env hardening)
instead of kernel enforcement. The UX should distinguish these:

| UX indicator | Meaning |
|-------------|---------|
| `✅ kernel-blocked` | OS prevents the action — strongest guarantee |
| `⚠️ proxy-blocked` | CONNECT proxy blocks exfiltration — bypassed by non-HTTP protocols |
| `⚠️ env-hardened` | Hardening env vars disable dangerous behavior — bypassed if tool ignores vars |
| `❌ not enforced` | Feature unavailable on this platform |

The banner should use these indicators when running on Linux to set
accurate expectations.

---

## 14. Deprecation and compatibility

### 14.1 Flag evolution rules

- Never silently change the security meaning of an existing flag.
- Deprecated flags warn for at least one release cycle before removal.
- Dangerous behavior changes require explicit opt-in, not opt-out.
- Compatibility aliases are hidden from primary help (`#[arg(hide = true)]`).

### 14.2 Config stability

Config keys have **stronger** compatibility guarantees than CLI flags:
- Users can't easily update config files across machines.
- Renamed keys should be accepted with a deprecation warning.
- Removed keys should error with a migration hint.

### 14.3 Output stability

- `--json` output is treated as API — fields can be added, never removed.
- Human-readable output format may change between versions.
- Document that scripts should use `--json` for stable parsing.

---

## 15. Security prompt rules

### 15.1 Prompt classes

Not all prompts are equal. `--yes` should not be a universal "weaken security"
switch. This directly implements SECURITY.md's design principle: "no interactive
approval during launch" to prevent approval fatigue.

| Prompt type | Non-interactive default | `--yes` behavior | Rationale (from SECURITY.md) |
|---|---|---|---|
| **Security relaxation** (dangerous flag) | deny / fail closed | accept only if the specific `--allow-*` flag is also present | Approval fatigue prevention |
| **Trust approval** (repo config) | deny — proposals silently ignored | require explicit `cplt trust accept` (separate command) | Content-pinned approvals need deliberate review |
| **Non-security setup** (create config) | proceed or skip | proceed | No security impact |
| **Destructive action** (overwrite) | deny | require `--force` | Prevent accidental data loss |

### 15.2 Non-interactive security

When `!stdin.is_terminal()`:
- Security prompts **always deny** (fail closed).
- Non-security prompts use the safe default.
- Print a clear message: `"Cannot prompt for approval (not a terminal). Use --flag to allow."`

### 15.3 The no-prompt principle

SECURITY.md explicitly states: cplt does *not* prompt "approve these? [y/N]"
when unapproved repo permissions exist. This is deliberate:

- Users reflexively hit `y` to proceed (approval fatigue).
- The repo config may contain dozens of proposals — a prompt doesn't
  give enough context to make an informed decision.
- Approval should happen via `cplt trust accept` where the user can
  review exactly what's being approved.

**Exception**: `config set` with dangerous values already requires `--force`.
This is the correct pattern — a targeted flag for the specific action,
not a generic yes/no prompt.

---

## 16. Patterns summary — cplt scorecard

### What cplt does well ✅

- **Deny-by-default** with explicit `--allow-*` grants (Deno pattern)
- **`(DANGEROUS)` markers** on high-risk flags
- **Columnar banner output** with status colors and alignment
- **`--doctor` diagnostics** with ✓/⚠/✗ and subsystem grouping
- **Config validation** with "did you mean?" suggestions (Levenshtein)
- **Prefix convention** (`[cplt]`, `[proxy]`, `[doctor]`) for filtering
- **Real-world examples** in help text naming specific frameworks
- **Proxy log levels** as independent verbosity control
- **Proxy enabled by default** with ephemeral port to avoid conflicts
- **Config subcommand suite** (init, show, validate, explain, get, set)
- **`config set` safeguards** dangerous settings with `--force`
- **Trust model** for repo-local config with content-hash pinning
- **Signal forwarding** with SIGTTOU/SIGTTIN suppression
- **Environment sanitization** with explicit allowlist and secret-suffix filtering
- **Hardening env vars** for package-manager lifecycle scripts and git signing
- **Recursion prevention** via `__CPLT_WRAPPED`
- **Scratch directory** ergonomics for tools needing executable temp space
- **Auto agent discovery** across Copilot/OpenCode/Gemini/shell
- **Path validation** against SBPL injection and path traversal
- **Agent exit code passthrough** — wrapper forwards the child's exit code

### Areas for improvement ⚠️

| Area | Current state | Recommendation |
|------|---------------|----------------|
| **Exit code disambiguation** | Wrapper errors and agent errors both return 1 | Use 125 for wrapper failures (git convention) |
| **Signal exit codes** | Signal deaths collapse to 1 | Return 128+N per POSIX |
| **Help length** | ~50 flags in flat list | Group into categories, progressive disclosure |
| **`NO_COLOR` / TTY detection** | Manual ANSI constants, no `NO_COLOR` check | Respect `NO_COLOR`, `TERM=dumb`, `is_terminal()` |
| **Color/prefix duplication** | ANSI constants duplicated across modules | Centralize into a `ui` or `output` module |
| **Pipe mode** | No TTY detection for output format | Strip ANSI when `!is_terminal()`; replace symbols with `PASS`/`WARN`/`FAIL` |
| **JSON output** | Not available | Add `--json` to `--doctor`, `config show`, `trust` |
| **Broken pipe** | Not handled | Exit 0 on `BrokenPipe`, like ripgrep |
| **Doctor remediation** | Some warnings lack fix suggestions | Add `Fix:` lines for every ✗ and ⚠ |
| **Shell completions** | Not yet available | Add `cplt completions <shell>` subcommand |
| **`--version` detail** | Basic | Add commit hash, build date, sandbox mechanism |
| **`trust` help text** | References `cplt trust --accept-all` | Update to `cplt trust accept --all` |
| **Platform degradation UX** | Some Linux warnings say "no effect" but continue | Define when partial enforcement requires `--force` |
| **`process::exit(1)`** | Some paths use `exit()` directly | Prefer `ExitCode` return for clean drop behavior |

---

## 17. Migration priorities

### Phase 1 — Correctness

- Fix `trust` help text referencing stale command names.
- Centralize ANSI color constants and prefix helpers into one module.
- Respect `NO_COLOR` env var and `TERM=dumb`.
- Document actual exit code behavior in `--help` and README.
- Replace `std::process::exit(1)` calls with `ExitCode` returns.

### Phase 2 — Scriptability

- Return 125 for wrapper failures, 128+N for signal deaths.
- Handle broken pipe (exit 0).
- Add `--json` to `--doctor`, `config show`, `trust show`.
- Define and enforce the stdout/stderr contract per command type.
- Add TTY detection: strip ANSI in pipe mode.

### Phase 3 — Ergonomics

- Add `cplt completions <shell>` for bash, zsh, fish.
- Group help output by category with progressive disclosure.
- Add `Fix:` lines for every doctor warning and failure.
- Add platform capability summary to banner output.
- Enrich `--version` with commit hash, build date, and sandbox backend.

---

## References

- [Command Line Interface Guidelines](https://clig.dev) — the canonical modern reference
- [Heroku CLI Style Guide](https://devcenter.heroku.com/articles/cli-style-guide)
- [no-color.org](https://no-color.org) — `NO_COLOR` standard
- [12-Factor CLI Apps](https://medium.com/@jdxcode/12-factor-cli-apps-dd3c227a0e46)
- [gh CLI source](https://github.com/cli/cli) — subcommand grouping, JSON output, color system
- [ripgrep source](https://github.com/BurntSushi/ripgrep) — exit codes, config, broken pipe
- [cargo source](https://github.com/rust-lang/cargo) — error hierarchy, plugin discovery
- [kubectl source](https://github.com/kubernetes/kubernetes) — output formats, verbosity levels
- [Deno permissions](https://docs.deno.com/runtime/fundamentals/security/) — sandbox UX model
