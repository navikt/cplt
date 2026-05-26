# gh Guard & Git Guard

## Overview

The gh guard prevents sandboxed agents from executing destructive GitHub
operations through the `gh` CLI. It intercepts all `gh` invocations inside
the sandbox and enforces a command-level policy before passing through to
the real binary.

The git guard prevents agents from pushing code by blocking `git push` and
`git request-pull`.

## Configuration

Both features are **opt-in** (disabled by default) for a safe rollout:

```toml
# ~/.config/cplt/config.toml

[gh_guard]
enabled = true              # blocks destructive gh operations
scope_check = true          # enforce repo-scoping on write commands
block_auth_token = true     # deny "gh auth token" exfiltration
inject_token = false        # inject GH_TOKEN into sandbox (opt-in)
unknown_command = "block"   # block|allow unrecognized gh commands

[git_guard]
enabled = true              # blocks git push
prevent_push = true         # block git push/request-pull
```

CLI flags (override config for a single run):

```bash
cplt --gh-guard          # enable gh guard
cplt --no-gh-guard       # disable gh guard
cplt --git-guard         # enable git push prevention
cplt --no-git-guard      # disable git push prevention
```

Per-repo via `.cplt.toml`:
```toml
[propose]
gh_guard = true
git_push_prevention = true
```

### Backward compatibility

The old flat config still works:
```toml
[sandbox]
gh_proxy = true              # maps to [gh_guard] enabled=true with defaults
git_push_prevention = true   # maps to [git_guard] enabled=true with defaults
```

### Security: Policy baked at launch

Policy flags are baked into the wrapper script at sandbox launch time.
The `gh-gate` subcommand receives `--scope-check`, `--block-auth-token`,
`--unknown-command=block` as CLI flags, preventing the agent from
influencing policy by editing config files inside the sandbox.

## How it works

```
Agent calls gh → wrapper script (in PATH) → cplt gh-gate → policy check
                                                ├─ Allow → exec real gh
                                                ├─ ScopeCheck → verify repo → exec or block
                                                └─ Block → print error, exit 1
```

1. At sandbox launch (when scratch directory is enabled), cplt writes a small wrapper to `{scratch}/bin/gh`
2. `{scratch}/bin` is prepended to PATH, shadowing the real `gh`
3. The wrapper calls `cplt gh-gate --real-gh /path/to/gh -- <args>`
4. cplt evaluates the command against the policy table
5. If allowed, `exec()` replaces the process with the real `gh` (zero overhead)
6. If blocked, prints an error explaining why and exits non-zero

## Policy tiers

| Tier | Behavior | Examples |
|------|----------|----------|
| **Allow** | Always permitted | `pr list`, `issue view`, `run list`, `search` |
| **ScopeCheck** | Permitted only for current repo | `pr create`, `issue comment`, `pr close` |
| **Block** | Never permitted | `repo delete`, `pr merge`, `release create`, `workflow run` |

### Design principles

- **Default-deny**: Unknown commands are blocked (fail-closed)
- **Reads are safe**: All read operations (`list`, `view`, `status`, `diff`) are allowed
- **Writes are scoped**: Operations that modify state are checked against the current repo
- **Destructive ops need humans**: Merging, deleting, releasing — these require human judgment
- **`gh api` is special**: GET requests are scope-checked; all other methods are blocked

## Scope checking

When a command is classified as `ScopeCheck`, cplt verifies that the command
targets the current repository:

1. Detects the current repo from `git remote get-url origin`
2. If the command has `-R`/`--repo` flag, compares it to current repo
3. If `-R` matches (case-insensitive, `.git` suffix stripped) → allowed
4. If `-R` targets a different repo → blocked
5. If no `-R` flag → allowed (implicitly targets current repo)

## Command classifications

### Always allowed (reads)

```
gh pr list/view/status/diff/checks
gh issue list/view/status
gh repo view/list/set-default/gitignore/license
gh run list/view/download/watch
gh workflow list/view
gh release list/view/download/verify
gh search *
gh auth status
gh config list/get/clear-cache
gh secret list
gh variable list/get
gh label list
gh cache list
gh ssh-key list
gh gpg-key list
gh org list
gh copilot *
gh ruleset *
gh attestation *
```

### Scope-checked (current-repo writes)

```
gh pr create/comment/edit/review/ready/close/reopen/checkout/update-branch
gh issue create/comment/edit/close/reopen/develop
gh label create/edit
```

### Blocked (destructive/out-of-scope)

```
gh repo create/delete/archive/fork/rename/edit/sync/deploy-key
gh pr merge/revert/lock/unlock
gh issue delete/transfer/lock/unlock/pin/unpin
gh release create/edit/delete/upload
gh secret set/delete
gh variable set/delete
gh workflow run/enable/disable
gh run rerun/cancel/delete
gh auth login/logout/refresh/setup-git/switch/token
gh config set
gh extension install/remove/upgrade/exec
gh gist create/edit/delete
gh ssh-key add/delete
gh gpg-key add/delete
gh label delete/clone
gh cache delete
gh codespace *
gh project * (except list/view/field-list/item-list)
```

## `gh auth token` and token injection

`gh auth token` is **blocked** to prevent token exfiltration. Instead, cplt
pre-extracts the token before the sandbox starts:

1. Before launching the sandbox, cplt runs `gh auth token` (outside the sandbox)
2. Injects the token as `GH_TOKEN` into the sandboxed environment
3. Blocks `gh auth token` inside the sandbox (no way to exfiltrate the value)

This means the agent has API access via `GH_TOKEN` (needed for operations),
but cannot extract the raw token string to send to external services.

**When this applies:**
- Only for Copilot agent (other agents have their own auth mechanisms)
- Only when `GH_TOKEN`/`GITHUB_TOKEN` is not already set in the environment
- Falls back gracefully if `gh` is not installed or not authenticated

## `gh api` handling

The `gh api` command provides raw API access and requires special treatment:

| Condition | Decision | Reason |
|-----------|----------|--------|
| No method flag (implicit GET) | ScopeCheck | Read operations |
| `-X GET` | ScopeCheck | Explicit read |
| `-X POST/PUT/PATCH/DELETE` | Block | Write operations |
| `-f`, `-F`, or `--input` present | Block | Input implies write |

## Error messages

When a command is blocked, the agent sees a clear message:

```
blocked by cplt: 'gh repo delete' is not allowed in sandbox (deletes entire repository)
blocked by cplt: 'gh pr create' targets 'other/repo' but current repo is 'navikt/cplt' (normal agent workflow)
```

## Git Push Prevention

In addition to the gh proxy, cplt installs a git wrapper that blocks `git push`
while allowing all other git operations. This prevents agents from pushing code
without human review.

### How it works

```
Agent calls git push → wrapper → cplt git-gate → BLOCKED
Agent calls git commit → wrapper → cplt git-gate → exec real git ✓
```

### Blocked git commands

| Command | Reason |
|---------|--------|
| `git push` | Remote writes — human should review and push |
| `git request-pull` | Initiates upstream merge requests |
| `git send-pack` | Plumbing equivalent of push — remote writes |

### Allowed git commands

Everything else is allowed: `commit`, `add`, `branch`, `checkout`, `merge`,
`rebase`, `fetch`, `pull`, `log`, `diff`, `status`, `stash`, `tag`, etc.

**Design choice — default-allow for unknown git commands:**
Unlike the gh proxy (default-deny), the git wrapper uses default-allow for
unrecognized commands. Git has hundreds of plumbing commands, aliases, and
extensions. The push operation is the only remote-write git command that needs
blocking — the explicit block list is sufficient.

### Defense in depth

The git push prevention complements existing sandbox layers:

| Layer | What it does | Strength |
|-------|-------------|----------|
| AGENTS.md | Instructs agent not to push | Soft (compliance-based) |
| `GIT_TERMINAL_PROMPT=0` | Blocks interactive credential prompts | Medium |
| **git wrapper** | Blocks `git push` at command level | Strong (kernel PATH) |
| Sandbox network policy | Can block git protocol ports | Strongest (kernel) |

The recommended approach is to use the git wrapper as the primary enforcement
and AGENTS.md as the UX layer (agent doesn't even attempt push → clean experience).

## Maintenance

The policy table lives in `src/gh_proxy.rs`. When GitHub adds new commands
to the `gh` CLI, they are **automatically blocked** (default-deny) until
explicitly classified. This is the safe default but requires periodic updates.

### Adding new commands

1. Check `gh help <new-command>` to understand what it does
2. Add entries to the `POLICY` table in `src/gh_proxy.rs`
3. Add tests to the `#[cfg(test)]` module
4. Run `cargo test --lib gh_proxy`

### Detecting new commands

To find commands that exist in `gh` but aren't in the policy table:

```bash
gh help --all 2>&1 | grep "^  " | awk '{print $1}' | sort -u
```

Compare against the commands in `POLICY`.

## Limitations

- **Not a security boundary for data exfiltration**: The proxy prevents
  accidental destructive actions, not deliberate data theft. An agent
  could still exfiltrate code via `gh api` GET to read repo contents.
  Use the network proxy's domain filtering for exfiltration prevention.

- **Shell escape**: If an agent uses `curl` with `GH_TOKEN` directly
  (bypassing `gh`), this proxy has no effect. The GH_TOKEN is already
  filtered from non-Copilot agents via env sanitization, and the network
  proxy handles domain-level control.

- **Subcommand parsing is heuristic**: Complex flag combinations may
  confuse the parser. In doubt, commands are blocked (fail-closed).

## Rollout plan

### Phase 1: Current (this PR)
- Core policy engine with 35 unit tests
- Opt-in via config: `sandbox.gh_proxy = true` / `sandbox.git_push_prevention = true`
- CLI flags: `--gh-guard` / `--no-gh-guard`, `--git-guard` / `--no-git-guard`
- Default-deny for all unknown gh commands
- GH_TOKEN pre-injection (blocks `gh auth token` exfiltration)
- **Default: off** — users opt-in to test

### Phase 2: Flip default to on
- Once stable, change default from `false` to `true`
- Users can still opt-out via `--no-gh-guard` / config
- Audit logging (append to proxy log file)
- `cplt doctor` check for gh proxy status

### Phase 3: Refinement
- Custom allow/block lists in config: `gh-proxy.allow = ["pr merge"]`
- Per-repo overrides via `.cplt.toml`: `[propose] gh_proxy_allow = ["workflow run"]`
- Warning mode (log but don't block) for gradual rollout
- Helper script to detect new `gh` commands from upstream releases

## Testing

The command wrappers have 35 unit tests covering:
- Command parsing (simple, with flags, with `-R`, API commands)
- Policy evaluation (all three tiers, wildcard groups, default-deny)
- Scope checking (matching, non-matching, case-insensitive, .git suffix)
- URL parsing (HTTPS, SSH shorthand, SSH URL, non-GitHub)
- Wrapper script generation (gh and git)
- Git push blocking (with flags like `-c key=value`)
- Git read/local-write operations allowed

Integration testing (Phase 2):
- E2E test: compile cplt, set up wrapper, verify blocked commands fail
- E2E test: verify allowed commands pass through to real gh/git
- E2E test: verify scope-check blocks cross-repo operations

Run tests:
```bash
cargo test --lib gh_proxy    # 35 policy/parser/git tests
mise run check               # full suite including gh_proxy
```
