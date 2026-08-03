# gh Guard & Git Guard

## Overview

The gh guard prevents sandboxed agents from executing destructive GitHub
operations through the `gh` CLI. It intercepts all `gh` invocations inside
the sandbox and enforces a command-level policy before passing through to
the real binary.

The git guard prevents agents from pushing code by blocking `git push`,
`git request-pull`, and `git send-pack`.

## Configuration

Both features are **opt-in** (disabled by default) for a safe rollout:

```bash
# Enable gh guard (blocks destructive gh operations)
cplt config set gh_guard.enabled true
cplt config set gh_guard.scope_check true          # enforce repo-scoping on write commands
cplt config set gh_guard.block_auth_token true     # deny "gh auth token" exfiltration
cplt config set gh_guard.unknown_command block      # block unrecognized gh commands

# Enable git guard (blocks git push)
cplt config set git_guard.enabled true
cplt config set git_guard.prevent_push true         # block git push/request-pull
```

For per-repo enforcement (committed to version control):

```bash
cplt config set --repo sandbox.gh_proxy true
cplt config set --repo sandbox.git_push_prevention true
```

<details>
<summary>CLI flags (override for a single run)</summary>

```bash
cplt --gh-guard          # enable gh guard
cplt --no-gh-guard       # disable gh guard
cplt --git-guard         # enable git push prevention
cplt --no-git-guard      # disable git push prevention
cplt --allow-api-write   # allow gh api write operations to current repo (overrides config)
cplt --no-allow-api-write # deny gh api write operations (overrides config)
```
</details>

<details>
<summary>Advanced: full TOML reference</summary>

```toml
# ~/.config/cplt/config.toml

[gh_guard]
enabled = true              # blocks destructive gh operations
scope_check = true          # enforce repo-scoping on write commands
block_auth_token = true     # deny "gh auth token" exfiltration
inject_token = false        # inject GH_TOKEN into sandbox (opt-in)
unknown_command = "block"   # block|allow unrecognized gh commands
allow_api_write = false     # allow gh api write (POST/PUT/PATCH) to current repo (opt-in)

[git_guard]
enabled = true              # blocks git push
prevent_push = true         # block git push/request-pull
```
</details>

### Backward compatibility

The old flat config still works:
```toml
[sandbox]
gh_proxy = true              # maps to [gh_guard] enabled=true with defaults
git_push_prevention = true   # maps to [git_guard] enabled=true with defaults
```

### Security: Policy baked at launch

The policy flags, absolute path to the real `gh` binary, and verified repository
scope are baked into the wrapper script at sandbox launch time. The `gh-gate`
subcommand receives `--repo-scope`, `--scope-check`, `--block-auth-token`,
`--unknown-command=block`, and `--allow-api-write`/`--no-allow-api-write` as CLI
flags. Runtime working directories, nested repositories, Git configuration, and
`PATH` cannot redefine the approved scope.

## How it works

```
Agent calls gh → wrapper script (in PATH) → cplt gh-gate → policy check
                                                ├─ Allow → exec real gh
                                                ├─ ScopeCheck → verify repo → exec or block
                                                └─ Block → print error, exit 1
```

1. At sandbox launch (when scratch directory is enabled), cplt writes a small wrapper to `{scratch}/bin/gh`
2. `{scratch}/bin` is prepended to PATH, shadowing the real `gh`
3. The wrapper calls `cplt gh-gate --real-gh /path/to/gh --repo-scope owner/repo -- <args>`
4. cplt evaluates the command against the policy table
5. If allowed, `exec()` replaces the process with the real `gh` (zero overhead)
6. If blocked, prints an error explaining why and exits non-zero

> **Note:** Wrappers require the scratch directory. If you run with `--no-scratch-dir`,
> the gh/git guards will be inactive (shown as such in `--doctor` output).

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
- **`gh api` is special**: GET requests are scope-checked; write methods are blocked by default (opt-in with `allow_api_write = true`; GraphQL always blocked)

## Scope checking

When a command is classified as `ScopeCheck`, cplt verifies that the command
targets the current repository:

1. At sandbox startup, reads `remote.origin.url` from the project root using the trusted Git binary
2. Ignores global/system config, config includes, and inherited `GIT_*` variables
3. Bakes the verified `owner/repo` into the wrapper; unavailable scope remains fail-closed
4. If the command has `-R`/`--repo`, compares it to the startup scope
5. Rejects a conflicting `--hostname` or fully qualified non-GitHub API endpoint
6. Sets `GH_REPO=github.com/owner/repo` and clears `GH_HOST` before executing `gh`

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
gh auth login/logout/refresh/setup-git/switch
gh auth token (served from one-time cache — see below)
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

## `gh auth token` and token isolation

`gh auth token` is handled with a **one-time-read** mechanism that gives
Copilot its auth token without exposing it to subprocesses:

1. Before launching the sandbox, cplt runs `gh auth token` (outside the sandbox)
2. Writes the token to a file in the scratch dir (`{scratch}/.gh-token`, mode 0600)
3. On Copilot's first call to `gh auth token`, the wrapper reads and returns the
   cached token, then **immediately deletes the file**
4. Any subsequent call by tools or MCP servers gets "no cached token available"

**Why not inject as `GH_TOKEN` env var?**

Environment variables are inherited by all child processes. If `GH_TOKEN` is set,
every tool, MCP server, and subprocess the agent spawns would have the token.
The file-based approach ensures only the first reader (Copilot at startup) gets it.

**Security properties:**
- Token file exists for <1 second (deleted after Copilot's startup read)
- Token never exposed as an environment variable
- Copilot caches the token in memory after first read — one read is sufficient
- After deletion, subprocesses cannot obtain the token via `gh auth token`

**When this applies:**
- Only for Copilot agent (other agents have their own auth mechanisms)
- Only when `block_auth_token = true` (default)
- Only when `GH_TOKEN`/`GITHUB_TOKEN` is not already set in the environment
- Falls back gracefully if `gh` is not installed or not authenticated

**Opt-in env var injection:**

If you prefer the simpler approach (token in env), set `inject_token = true`:
```toml
[gh_guard]
inject_token = true   # injects GH_TOKEN env var (visible to all subprocesses)
```

## `gh api` handling

The `gh api` command provides raw API access and requires special treatment:

| Condition | Default | With `allow_api_write = true` | Reason |
|-----------|---------|-------------------------------|--------|
| No method flag (implicit GET) | ScopeCheck | ScopeCheck | Read operations — must target current repo |
| `-X GET` | ScopeCheck | ScopeCheck | Explicit read — must target current repo |
| `-X POST/PUT/PATCH` | Block | ScopeCheck | Write operations — opt-in required |
| `-X DELETE` | Block | Block | Destructive — always blocked |
| `-f`, `-F`, or `--input` present | Block | ScopeCheck | Input implies write — opt-in required |
| `graphql` endpoint | Block | Block | Arbitrary mutations possible — always blocked |

When `allow_api_write = true`, write requests are **scope-checked** (not freely allowed):
they must target the current repository. Cross-repo writes are still denied.

**Enable in config:**
```toml
[gh_guard]
enabled = true
allow_api_write = true
```

**Or for a single run:**
```bash
cplt --allow-api-write -- -p "post review comment replies"
```

> **Note:** `gh api graphql` remains unconditionally blocked even with `allow_api_write = true`
> because GraphQL mutations are specified via stdin and cannot be statically scope-checked.

### API scope enforcement

GET requests are **repo-scoped** — only endpoints matching `/repos/{current-owner}/{current-repo}/...`
are allowed. This blocks:

- `/orgs/.../audit-log` — org audit logs (contains employee PII)
- `/orgs/.../members` — org membership enumeration
- `/orgs/.../teams` — team structure
- `/user/repos` — private repos across all orgs
- `/users/.../repos` — other users' repo lists

Agents that need current-repo data (issues, PRs, actions, commits) work normally.
If an agent needs org-level access, the human should run those commands outside the sandbox.

### Why `gh api` is stricter than other commands

Higher-level commands like `gh repo view`, `gh repo list`, `gh issue list` are **allowed
cross-repo** because they:
- Output curated, read-only data (not raw API responses with PII)
- Are commonly needed by agents (checking dependencies, understanding upstream issues)
- Don't expose sensitive org internals (audit logs, SSO identities, member emails)

The raw `gh api` endpoint is restricted because it can access any REST endpoint including
sensitive org/user data that the higher-level commands don't expose.

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

## Security Boundaries

This section is explicit about what the gh/git guard protects against and what it does NOT protect against.

### What it protects against

| Threat | How it's stopped |
|--------|-----------------|
| Agent merges a PR without human review | `gh pr merge` is in the Block tier — always denied |
| Agent deletes a repository | `gh repo delete` is in the Block tier |
| Agent creates releases or uploads artifacts | `gh release create/upload` blocked |
| Agent triggers CI workflows | `gh workflow run` blocked |
| Agent pushes directly to main/master | `git push` blocked (or only default branch blocked with `protect_default_branch_only`) |
| Agent force-pushes and rewrites history | `--force`/`--force-with-lease` detection on push |
| Agent exfiltrates `gh auth token` value | `gh auth token` blocked; token served via one-time-read file (deleted after first use). Env var injection only with `inject_token=true` |
| Agent modifies secrets/variables | `gh secret set/delete`, `gh variable set/delete` blocked |
| Agent installs malicious gh extensions | `gh extension install/remove` blocked |
| Agent operates on other repositories | `-R other/repo` checked via ScopeCheck |
| Agent uses `gh api` POST to mutate state | Presence of `-f`, `-F`, `--input`, or non-GET method → blocked by default; opt-in with `allow_api_write = true` (scope-checked to current repo) |
| Agent uses `gh api graphql` for mutations | `graphql` endpoint unconditionally blocked even with `allow_api_write = true` (mutations via stdin not parseable) |

### What it does NOT protect against

| Gap | Explanation | Mitigation |
|-----|-------------|------------|
| **Data exfiltration via `gh api` GET** | The agent can `gh api /repos/owner/repo/contents/secret.yml` to read and then exfiltrate via network | Use network proxy domain filtering (`--blocked-domains`) |
| **Direct `curl` with `GH_TOKEN`** | Agent can `curl -H "Authorization: token $GH_TOKEN" https://api.github.com/...` bypassing the gh wrapper entirely | GH_TOKEN is only injected for Copilot agent; network proxy logs all outbound connections |
| **Wrapper bypass via real binary path** | Agent can `cat $(which gh)` to discover the real `gh` path in the wrapper script and call it directly | The wrapper uses `exec` so the real path is in the script; defense: Seatbelt blocks writes to scratch bin dir, but the path is readable |
| **Agent edits `.github/workflows/`** | Agent can write CI configs that run on push — destructive actions happen in CI, not locally | Code review (git diff); git push is blocked so workflows can't trigger |
| **Agent creates commits on main locally** | `git commit` on the main branch is allowed (it's a local operation) | The push guard prevents pushing those commits; human reviews before push |
| **`git send-pack` plumbing variants** | Covered — `send-pack` is in the block list | ✅ Already handled |
| **Agent reads project source code** | Project dir is fully readable (agent's core function) | Network domain filtering to prevent exfiltration |
| **Heuristic parser confusion** | Extremely unusual flag combinations might confuse the parser | Fail-closed: unknown states → blocked; 87+ E2E tests cover bypass variants |
| **New `gh` commands added upstream** | Unknown commands get `Decision::Unknown` → blocked by default (safe) | Periodic policy table updates; `unknown_command = "block"` is default |

### Security model summary

```
┌────────────────────────────────────────────────────────────────┐
│                    DEFENSE IN DEPTH                              │
├────────────────────────────────────────────────────────────────┤
│  Layer 1: Kernel sandbox (Seatbelt/Landlock)                    │
│    → Blocks credential file reads, exec from tmp, localhost     │
│    → CANNOT be bypassed by any user-space code                  │
├────────────────────────────────────────────────────────────────┤
│  Layer 2: Environment sanitization                              │
│    → Only safe env vars pass through                            │
│    → Agent never sees AWS_SECRET_KEY, NPM_TOKEN, etc.           │
├────────────────────────────────────────────────────────────────┤
│  Layer 3: gh/git command guard (THIS FEATURE)                   │
│    → Prevents destructive GitHub/git operations                 │
│    → PATH-based interception (wrapper shadows real binary)      │
│    → Soft barrier: bypassable if agent discovers real binary    │
│    → Policy baked at launch (agent can't modify)                │
├────────────────────────────────────────────────────────────────┤
│  Layer 4: Network proxy (domain filtering)                      │
│    → Blocks known exfiltration domains                          │
│    → Logs all outbound CONNECT requests                         │
├────────────────────────────────────────────────────────────────┤
│  Layer 5: AGENTS.md instructions                                │
│    → Tells agent not to push/merge/delete                       │
│    → Compliance-based only (no enforcement)                     │
└────────────────────────────────────────────────────────────────┘
```

**The gh/git guard is Layer 3** — it sits between kernel enforcement (unbypassable) and instructions (unenforceable). It is a **strong deterrent** that stops compliant agents and catches accidental destructive operations. It is NOT a hard security boundary against a determined adversary with code execution.

The hard security boundary is Layer 1 (kernel sandbox): credentials, SSH keys, and secret files are physically inaccessible regardless of what the agent does.

### protect_default_branch_only mode

When `git_guard.protect_default_branch_only = true`:

- Push to `main` or `master` → **BLOCKED**
- Push to `feature/x`, `copilot/fix-123`, any other branch → **ALLOWED**
- `git push` with no explicit branch → **ALLOWED** (current branch, likely a feature branch)
- Push with refspec `HEAD:refs/heads/main` → **BLOCKED** (refspec parsing detects target)
- `git push origin` (no branch) → **ALLOWED**

This mode is designed for workflows where agents should be able to push their work to feature branches for PR review, while preventing direct pushes to the default branch.

**Security note:** This is intentionally permissive. The agent can push to any non-default branch. The human review gate becomes the pull request, not the push prevention. Use full `prevent_push = true` if you want no pushes at all.

## Limitations

- **Not a security boundary for data exfiltration**: The guard prevents
  accidental destructive actions, not deliberate data theft. An agent
  could still exfiltrate code via `gh api` GET to read repo contents.
  Use the network proxy's domain filtering for exfiltration prevention.

- **Shell escape**: If an agent uses `curl` with `GH_TOKEN` directly
  (bypassing `gh`), this guard has no effect. The GH_TOKEN is only
  injected for Copilot agents, and the network proxy handles domain-level control.

- **Wrapper discoverability**: The agent can read the wrapper script
  (`cat $(which gh)`) to discover the real `gh` binary path. This is a
  soft barrier, not a hard one. The kernel sandbox (Layer 1) is the hard barrier.

- **Subcommand parsing is heuristic**: Complex flag combinations may
  confuse the parser. In doubt, commands are blocked (fail-closed).

## Testing

The command guards have 87+ E2E tests and 40+ unit tests covering:
- Command parsing (simple, with flags, with `-R`, API commands)
- Policy evaluation (all three tiers, wildcard groups, default-deny)
- Scope checking (matching, non-matching, case-insensitive, .git suffix)
- API endpoint path extraction (cross-repo detection)
- Input flag bypass prevention (`--field=value`, `-fvalue`, `--input=-`)
- GraphQL endpoint blocking
- Force-push flag detection (including `--force-with-lease=ref` form)
- URL parsing (HTTPS, SSH shorthand, SSH URL, non-GitHub)
- Wrapper script generation (gh and git)
- Git push blocking (with flags like `-c key=value`)
- Git read/local-write operations allowed
- protect_default_branch_only (branch and refspec parsing)
- Full sandbox integration (wrapper → gate → real binary)

Run tests:
```bash
cargo test --lib gh_proxy              # unit tests (parser, policy, helpers)
cargo test --test e2e_guards           # 87 E2E tests (full binary pipeline)
mise run check                         # full suite
```
