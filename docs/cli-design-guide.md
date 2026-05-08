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

### Core principles

| # | Principle | cplt implication |
|---|-----------|------------------|
| 1 | **Human-first** | CLI is a text UI, not a scripting primitive. Invest in formatting. |
| 2 | **Saying just enough** | No silent hangs, no debug dumps. One line per action. |
| 3 | **Secure defaults** | Every flag defaults to the restrictive option. |
| 4 | **Ease of discovery** | `--doctor`, `config explain`, progressive help. |
| 5 | **Conversation** | Suggest next steps: "run `cplt --doctor` to diagnose". |
| 6 | **Composability** | Data on stdout, diagnostics on stderr. Scriptable exit codes. |
| 7 | **Empathy** | Error messages answer "what now?", not just "what happened". |

---

## 1. Naming

### 1.1 Subcommands: noun–verb, plural nouns

```
cplt config show        # noun = config, verb = show
cplt config validate
cplt trust add          # noun = trust, verb = add
```

- **Nouns are singular** when they refer to a single resource (`config`, `trust`).
- **Verbs are imperative**: `show`, `set`, `get`, `init`, `explain` — not `showing`, `setting`.
- The bare noun is the **list/default action**: `cplt config` → `cplt config show`.
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

### 3.4 Prefix convention

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

### 4.3 Anti-patterns

- ❌ **Bare error codes**: `Error: ENOENT` — meaningless to most users.
- ❌ **Stack traces for user errors**: reserve for `--debug` or internal bugs.
- ❌ **Double-printing**: cargo's `AlreadyPrintedError` pattern — if a subsystem
  already printed the error, don't print it again at the top level.
- ❌ **Swallowed errors**: never silently ignore a failure. Warn or error.

---

## 5. Exit codes

### 5.1 Convention

```
0     Success (sandbox ran, agent exited cleanly)
1     General error (sandbox failed, config invalid)
2     Usage error (bad arguments, missing required flags)
N     Agent's exit code (pass through the wrapped command's exit code)
```

**The critical distinction**: cplt is a wrapper. When the sandbox starts
successfully but the agent exits non-zero, cplt should **pass through
the agent's exit code** so scripts can distinguish "cplt failed" from
"agent failed".

### 5.2 Documentation

Exit codes should be documented in:
- `--help` (brief, in the EXAMPLES section or a dedicated EXIT CODES section)
- `README.md` (reference table)
- Man page (if/when generated)

### 5.3 Broken pipe

When stdout is a pipe and the reader closes early, exit 0 — not an error.
This is what ripgrep does and what users expect from `cplt ... | head`.

---

## 6. Configuration UX

### 6.1 Precedence (cplt already follows this — document it)

```
1. CLI flags              (highest priority)
2. Environment variables  (CPLT_CONFIG, CPLT_*)
3. Repo-local config      (.cplt.toml, with trust model)
4. User config            (~/.config/cplt/config.toml)
5. Built-in defaults      (lowest priority, always secure)
```

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

### 7.1 The `(DANGEROUS)` marker

Flags that weaken the sandbox are marked `(DANGEROUS)` in help text.
This is effective — keep it. Rules:

- Apply to any flag that **bypasses a security boundary**: `--inherit-env`,
  `--allow-docker`, `--allow-tmp-exec`, `--allow-gpg-signing`.
- Show a **runtime warning** when a dangerous flag is used:
  ```
  [cplt] ⚠ --inherit-env passes ALL environment variables into the sandbox.
         Secrets in your shell environment will be accessible to the agent.
  ```
- Never require `(DANGEROUS)` flags for common workflows.

### 7.2 Trust model UX

The repo-local config trust model (`.cplt.toml`) should be transparent:

```
[cplt] Repo config (.cplt.toml):
[cplt]   Status:    pending approval
[cplt]   Proposes:  allow-port 3000, allow-localhost-any
[cplt]   Run `cplt trust add` to approve
```

### 7.3 Audit trail

For the proxy log and any future audit features:
- Use **one line per event**, structured for grep/jq.
- Include timestamp, action, target, decision.
- Never log secrets or request bodies.

```
2025-01-15T10:32:44.123Z CONNECT api.github.com:443 OK
2025-01-15T10:32:45.234Z CONNECT evil.com:443 BLOCKED (not in allowlist)
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
- Group checks by subsystem: Auth → Agents → Tools → Sandbox → Config.
- Show **full resolved paths** — users need to verify the right binary is found.

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

## 12. Patterns summary — cplt scorecard

### What cplt does well ✅

- **Deny-by-default** with explicit `--allow-*` grants (Deno pattern)
- **`(DANGEROUS)` markers** on high-risk flags
- **Columnar banner output** with status colors and alignment
- **`--doctor` diagnostics** with ✓/⚠/✗ and actionable remediation
- **Config validation** with "did you mean?" suggestions
- **Prefix convention** (`[cplt]`, `[proxy]`, `[doctor]`) for filtering
- **Real-world examples** in help text naming specific frameworks
- **Proxy log levels** as independent verbosity control
- **Config subcommand suite** (init, show, validate, explain, get, set)
- **Trust model** for repo-local config with approval workflow
- **Signal forwarding** with SIGTTOU/SIGTTIN suppression

### Areas for improvement ⚠️

| Area | Current state | Recommendation |
|------|---------------|----------------|
| **Exit codes** | 0 or 1 only, undocumented | Pass through agent's code; document in help |
| **Help length** | ~50 flags in flat list | Group into categories, progressive disclosure |
| **Pipe mode** | No TTY detection for output | Strip colors and symbols when `!is_terminal()` |
| **`NO_COLOR` support** | Manual ANSI codes | Respect `NO_COLOR` env var ([no-color.org](https://no-color.org)) |
| **JSON output** | Not available | Add `--json` to `--doctor`, `config show` |
| **Broken pipe** | Not handled | Exit 0 on `BrokenPipe`, like ripgrep |
| **Error context** | Some bare errors | Add "hint:" lines to sandbox execution errors |
| **Shell completions** | Not yet available | Add `cplt completions <shell>` subcommand |
| **`--version` detail** | Basic | Add commit hash, build date, sandbox mechanism |
| **Double-print guard** | Not implemented | Prevent errors printing at both subsystem and top level |

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
