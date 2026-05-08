# cplt CLI Audit Report

> Systematic codebase review against [cli-design-guide.md](cli-design-guide.md)
> Audit date: 2025-07-16

---

## Summary

| Category | Compliant | Violations | Severity breakdown |
|----------|:---------:|:----------:|-------------------|
| Output & Color (§3–4) | 4 | 6 | 2 critical, 2 moderate, 2 low |
| Errors & Exit codes (§5–6) | 3 | 4 | 2 critical, 1 moderate, 1 low |
| Flags & Help (§1–2) | 5 | 3 | 1 moderate, 2 low |
| Security UX (§7) | 6 | 2 | 1 moderate, 1 low |
| Doctor & Config (§8–9) | 5 | 2 | 2 moderate |
| Wrapper ergonomics (§10) | 3 | 1 | 1 low |
| **Totals** | **26** | **18** | **4 critical, 8 moderate, 6 low** |

Severity: **critical** = incorrect behavior or security gap, **moderate** = ergonomic gap impacting users, **low** = polish / nice-to-have.

---

## 1. Output & Color (§3–4)

### ✓ Compliant

- **Stream separation**: `println!` for data/reports (stdout), `eprintln!` for diagnostics (stderr). Correct throughout.
- **Prefix tags**: Consistent use of `[cplt]`, `[doctor]`, `[proxy]` — identifies source of messages.
- **Unicode symbols**: Consistent vocabulary: ✓=green, ✗=red, ⚠=red/dim, ○=yellow.
- **Proxy log format**: `[proxy] timestamp METHOD target → status` — structured, readable.

### ✗ Violations

| # | Severity | Finding | Location | Guide §
|---|----------|---------|----------|--------
| O-1 | **critical** | **NO_COLOR not respected.** cplt always emits ANSI. `NO_COLOR` is in `ENV_ALWAYS_DENY` (stripped from agent), but cplt itself never checks it for its own output. Violates [no-color.org](https://no-color.org) and guide §4.1. | `sandbox_policy.rs:250`, all output functions | §4.1 |
| O-2 | **critical** | **No TTY detection for output.** No `is_terminal()` / `isatty()` check. Colors are emitted even when piped to a file or another process. Only TTY check in codebase is for input prompts (`main.rs:595-600` opens `/dev/tty`). | All output functions | §4.1 |
| O-3 | **moderate** | **ANSI constants duplicated in 4 modules.** Each module re-defines `GREEN`, `RED`, `DIM`, `RESET` etc. as local constants. No centralized color module — fragile, risks inconsistency. | `discover.rs:329`, `main.rs:529`, `proxy.rs:78`, `config.rs:554` | §4.2 |
| O-4 | **moderate** | **~11 hardcoded raw escape sequences.** Beyond the 4 constant blocks, raw `\x1b[` escapes scattered in `sandbox.rs`, `scratch.rs`, `sandbox_landlock.rs`, `sandbox_exec.rs`. | Various | §4.2 |
| O-5 | **low** | **FORCE_COLOR never checked.** Listed in `ENV_ALWAYS_DENY` (stripped from agent env) but cplt never interprets it for its own output either. Minor since NO_COLOR is the more important standard. | `sandbox_policy.rs:251` | §4.1 |
| O-6 | **low** | **No pipe/non-interactive mode.** When stdout is not a TTY, output could omit banner, progress hints, and ANSI. Currently no behavioral change. | — | §4.3 |

**Recommended fix priority:**
1. O-1 + O-2: Create a centralized `color.rs` module with `fn colored(color, text) -> String` that checks `NO_COLOR` env + `stdout.is_terminal()`. Replace all 4 constant blocks and raw escapes. This fixes O-1, O-2, O-3, O-4 in one pass.
2. O-6: Use TTY detection to suppress banner/chrome when piped (pairs naturally with O-2).

---

## 2. Errors & Exit Codes (§5–6)

### ✓ Compliant

- **Error quality (deny-path)**: Deny-path errors are excellent — include what, where, why, and suggested fix. (`main.rs:713` area)
- **Security errors never silenced**: `--quiet` does not suppress security-critical messages. ✓
- **Agent exit code passthrough**: `ExitCode::from(child_exit_code)` correctly forwards the agent's exit code. (`sandbox_exec.rs`)

### ✗ Violations

| # | Severity | Finding | Location | Guide §
|---|----------|---------|----------|--------
| E-1 | **critical** | **Signal death → exit 1.** When the child is killed by a signal, `status.code().unwrap_or(1)` collapses to 1. Should be `128 + signal_number` per POSIX convention (and guide §6.1). Breaks `set -e` scripts that distinguish OOM-kill (137) from normal failure (1). | `sandbox_exec.rs:152` | §6.1 |
| E-2 | **critical** | **Broken pipe completely unhandled.** No `BrokenPipe` error handling, no `SIGPIPE` setup. `println!` to a closed pipe will panic or print an error to stderr. Common when `cplt --doctor \| head`. | Not present anywhere | §6.2 |
| E-3 | **moderate** | **Two `process::exit(1)` calls bypass cleanup.** Direct `process::exit` skips destructors, temp file cleanup, and any future graceful shutdown logic. | `main.rs:713` (deny-path), `main.rs:1222` (SEA extraction) | §5.2 |
| E-4 | **low** | **Error messages lack remediation hints in some paths.** `sandbox_exec.rs` errors are "what" only (e.g., "sandbox-exec failed") without "try X" suggestions. Contrast with deny-path errors which are exemplary. | `sandbox_exec.rs` error strings | §5.1 |

**Recommended fix priority:**
1. E-1: Replace `status.code().unwrap_or(1)` with signal-aware exit: `status.code().unwrap_or_else(|| status.signal().map(|s| 128 + s).unwrap_or(1))`.
2. E-2: Add `#[cfg(unix)] unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL); }` early in main, or handle `BrokenPipe` in output helpers.
3. E-3: Refactor to return `ExitCode` instead of calling `process::exit`. At minimum, document why the bypass is necessary.

---

## 3. Flags & Help (§1–2)

### ✓ Compliant

- **Flag prefix convention**: All flags use consistent semantic prefixes: `--allow-*`, `--deny-*`, `--pass-*`, `--no-*`, `--with-*`. Excellent.
- **No short flags on security-sensitive options**: Correct — security flags are long-form only. ✓
- **No prefix/abbreviation matching**: Disabled (secure, prevents typo-activated flags). ✓
- **Subcommand naming**: `trust accept/revoke` (not add/remove) — security-meaningful verbs. ✓
- **Progressive examples**: 13 realistic examples in `after_help` block. ✓

### ✗ Violations

| # | Severity | Finding | Location | Guide §
|---|----------|---------|----------|--------
| F-1 | **moderate** | **`--allow-lifecycle-scripts` not marked DANGEROUS.** Config definition has `dangerous: false` despite its help text explicitly warning about supply chain risks. Other high-risk flags are correctly marked. Inconsistent security signal. | `config.rs` dangerous field (line ~1537-1615) | §7.2 |
| F-2 | **low** | **`--allow-cache-exec-any` marked dangerous in config but not in help text.** The DANGEROUS label appears in `config set` validation but not in `--help` output for the flag itself. Users see the risk warning only when using config, not CLI flags. | `main.rs` flag definition vs `config.rs` | §7.2 |
| F-3 | **low** | **No progressive disclosure (`-h` vs `--help`).** Both produce identical output. Best practice (cargo, gh): `-h` shows compact summary, `--help` shows full detail with `long_help` attributes. Not urgent given cplt's ~50 flags. | `main.rs` clap configuration | §2.2 |

**Recommended fix priority:**
1. F-1: Change `dangerous: true` for `allow-lifecycle-scripts`. This is a security correctness issue.
2. F-2: Add `[DANGEROUS]` prefix to help text for `--allow-cache-exec-any`.
3. F-3: Low priority. Add `long_help` to complex flags over time; Clap supports `-h`/`--help` differentiation via `Command::help_template`.

---

## 4. Security UX (§7)

### ✓ Compliant

- **Compound risk warning**: When `--allow-localhost-any` + `--allow-jvm-attach` both active, summary shows "ALL TCP" with ⚠ warning and explains why. (`config.rs:690-694`)
- **Trust model warnings**: Unapproved repo-config proposals are warned (unless `--quiet`), never silently applied. ✓
- **Non-interactive fail-closed**: Without `--yes`, trust prompts fail closed. `--accept-repo-config` available for CI. ✓
- **Config set --force**: Required for all 5 dangerous config keys. ✓
- **Deny-path asymmetry**: Allow-path on non-existent path warns+skips. Deny-path on non-existent path errors+exits. Correct fail-closed behavior. ✓
- **Linux degradation warnings**: All 5 platform-specific warnings (Landlock ABI, deny-path limited, seccomp status) are shown. ✓

### ✗ Violations

| # | Severity | Finding | Location | Guide §
|---|----------|---------|----------|--------
| S-1 | **moderate** | **DANGEROUS flags warn in banner only, not at invocation time.** When a user passes `--allow-exec-any` on the CLI, the DANGEROUS label only appears in the config summary banner. No immediate warning at parse time like "⚠ --allow-exec-any disables exec sandboxing (DANGEROUS)". | `config.rs` print_summary | §7.2 |
| S-2 | **low** | **`--quiet` suppresses unapproved trust proposals.** While security *errors* survive `--quiet`, the repo-config proposal warning is suppressed. In CI, this means unapproved configs apply silently when `--quiet` is used without `--accept-repo-config`. | `main.rs` quiet logic | §7.5 |

**Note:** S-2 is mitigated by the fact that unapproved proposals are applied as *proposals* (not enforced) and `--accept-repo-config` is the intended CI path. But the silent suppression is still a paper cut.

---

## 5. Doctor & Config (§8–9)

### ✓ Compliant

- **Check categories**: Doctor covers Auth, Agents, Tools, Sandbox Paths, Sandbox Mechanism — comprehensive. ✓
- **Summary line**: "All critical checks passed ✓" or "Critical issues found" at end. ✓
- **Exit code**: 0 on warnings, non-zero on critical failures. ✓
- **Config validation**: Levenshtein distance suggestions for typos, type mismatch errors, SBPL injection detection, path traversal detection. Excellent. ✓
- **Config precedence**: CLI > config > defaults, clearly documented. Repo config for deny rules auto-applied, propose rules require `trust accept`. ✓

### ✗ Violations

| # | Severity | Finding | Location | Guide §
|---|----------|---------|----------|--------
| D-1 | **moderate** | **Doctor lacks Fix:/hint: remediation lines.** Most failures show the problem but not how to fix it. Only Landlock checks include troubleshooting. Compare with `rustup` or `brew doctor` which include actionable next steps for every check. | `discover.rs:338-508` | §8.1 |
| D-2 | **moderate** | **Doctor doesn't note "running outside sandbox".** Agent version checks execute outside the sandbox (as noted in guide §8.2), but doctor output doesn't indicate this. Users may assume doctor validates the sandboxed environment. | `discover.rs` doctor output | §8.2 |

**Recommended fix priority:**
1. D-1: Add `hint:` lines to common failure modes (e.g., auth: "run `gh auth login`", agent not found: "install with `npm i -g @anthropic/copilot`").
2. D-2: Add a note line at start: `[doctor] Note: checks run outside sandbox — results show host state`.

---

## 6. Wrapper Ergonomics (§10)

### ✓ Compliant

- **Transparent passthrough**: cplt args before `--`, agent args after. Clean separation. ✓
- **Signal forwarding**: SIGTERM, SIGHUP forwarded to child; SIGTTOU, SIGTTIN ignored. ✓
- **Version output**: `cplt --version` works. ✓

### ✗ Violations

| # | Severity | Finding | Location | Guide §
|---|----------|---------|----------|--------
| W-1 | **low** | **Version output lacks platform/build info.** Only shows version string. Best practice (rustc, cargo, gh): include OS, arch, commit hash, build date. Helpful for bug reports. | `main.rs` version attribute | §10.3 |

---

## Priority Matrix

### Phase 1: Security & correctness (critical)

| Item | Effort | Impact |
|------|--------|--------|
| E-1: Signal death → 128+signal | Small | Correct POSIX behavior, CI scripts |
| O-1+O-2: NO_COLOR + TTY detection | Medium | no-color.org compliance, pipe safety |
| F-1: Mark --allow-lifecycle-scripts DANGEROUS | Trivial | Consistent security signaling |

### Phase 2: Ergonomic gaps (moderate)

| Item | Effort | Impact |
|------|--------|--------|
| O-3+O-4: Centralize color module | Medium | Maintainability, consistency |
| E-2: Handle broken pipe | Small | No panic on `cplt \| head` |
| D-1: Doctor remediation hints | Medium | Actionable diagnostics |
| D-2: Doctor "outside sandbox" note | Trivial | Security clarity |
| S-1: DANGEROUS warning at parse time | Small | Immediate risk awareness |
| E-3: Replace process::exit with returns | Small | Clean shutdown |
| F-2: DANGEROUS in help text for cache-exec | Trivial | Consistency |

### Phase 3: Polish (low)

| Item | Effort | Impact |
|------|--------|--------|
| F-3: Progressive -h vs --help | Medium | Discoverability |
| O-6: Pipe/non-interactive mode | Medium | Script-friendliness |
| W-1: Rich version output | Small | Bug report quality |
| S-2: --quiet trust proposal behavior | Small | CI edge case |
| O-5: FORCE_COLOR support | Trivial | Completeness |

---

## Scorecard Update

Based on verified audit findings, updating the design guide scorecard:

| Area | Rating | Notes |
|------|--------|-------|
| Flag naming & prefixes | ★★★★★ | Exemplary. Consistent prefixes, no short security flags. |
| Help text & examples | ★★★★☆ | Good examples, but no progressive disclosure. |
| Error messages | ★★★★☆ | Deny-path errors are best-in-class; sandbox_exec errors lack hints. |
| Exit codes | ★★★☆☆ | Agent passthrough correct, but signal→1 bug and process::exit bypasses. |
| Color & formatting | ★★☆☆☆ | Consistent symbols, but no NO_COLOR, no TTY check, duplicated constants. |
| Security UX | ★★★★☆ | Strong trust model, fail-closed, but DANGEROUS marking inconsistencies. |
| Doctor | ★★★☆☆ | Good coverage, but no remediation hints, no sandbox context note. |
| Config UX | ★★★★★ | Validation, Levenshtein suggestions, SBPL injection protection. Excellent. |
| Platform adaptation | ★★★★☆ | All Linux warnings shown, but could surface defense-in-depth status. |

**Overall: 33/45 (73%)** — Strong security architecture, solid flag design, needs output layer and error handling work.
