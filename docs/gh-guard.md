# gh guard

The gh guard stops a sandboxed agent from running destructive GitHub
operations through the `gh` CLI. It intercepts every `gh` invocation inside
the sandbox and checks it against a command-level policy before handing off
to the real binary.

Its sibling, the git guard, blocks `git push`, `git request-pull`, and
`git send-pack`. That one has its own doc, [git-guard.md](git-guard.md).

## Configuration

Both guards are opt-in and disabled by default, so a rollout can be gradual.

```bash
# Enable gh guard (blocks destructive gh operations)
cplt config set gh_guard.enabled true
cplt config set gh_guard.scope_check true          # enforce repo-scoping on write commands
cplt config set gh_guard.block_auth_token true     # deny "gh auth token" exfiltration
cplt config set gh_guard.unknown_command block      # block unrecognized gh commands
cplt config set gh_guard.mode block                 # block | warn | audit (default block)

# Enable git guard (blocks git push)
cplt config set git_guard.enabled true
cplt config set git_guard.prevent_push true         # block git push/request-pull
cplt config set git_guard.mode block                # block | warn | audit (default block)
```

Both guards take a `mode`. `block` prints the message and exits non-zero.
`warn` prints the same message behind `⚠️  WARNING (would block):` and runs the
command anyway. `audit` prints it behind `[audit] gh-gate: would block:` (or
`git-gate`) and runs it. Use `warn` or `audit` to find out what a rollout would
break before you enforce it.

For per-repo enforcement, committed to version control:

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
mode = "block"              # block | warn | audit
scope_check = true          # enforce repo-scoping on write commands
block_auth_token = true     # deny "gh auth token" exfiltration
inject_token = false        # inject GH_TOKEN into sandbox (opt-in)
unknown_command = "block"   # block|allow unrecognized gh commands
allow_api_write = false     # allow gh api write (POST/PUT/PATCH) to current repo (opt-in)

[git_guard]
enabled = true              # blocks git push
mode = "block"              # block | warn | audit
prevent_push = true         # block git push/request-pull
prevent_force_push = true   # block force push, even where a plain push is allowed
```
</details>

### Backward compatibility

The old flat config still works:
```toml
[sandbox]
gh_proxy = true              # maps to [gh_guard] enabled=true with defaults
git_push_prevention = true   # maps to [git_guard] enabled=true with defaults
```

### Policy is baked at launch

cplt bakes the policy flags, the absolute paths to the real `gh` and trusted
`git` binaries, and the verified repository scope into the wrapper script when
the sandbox starts. The `gh-gate` subcommand receives `--repo-scope`,
`--real-git`, `--scope-check`, `--block-auth-token`, `--unknown-command=block`,
and `--allow-api-write`/`--no-allow-api-write` as CLI flags. Runtime working
directories, nested repositories, Git configuration, and `PATH` cannot redefine
the approved scope; the cwd is only checked as evidence for an implicit target.

## How it works

```
Agent calls gh → wrapper script (in PATH) → cplt gh-gate → policy check
                                                ├─ Allow → exec real gh
                                                ├─ ScopeCheck → verify repo → exec or block
                                                └─ Block → print error, exit 1
```

1. At sandbox launch (when scratch directory is enabled), cplt writes a small wrapper to `{scratch}/bin/gh`
2. `{scratch}/bin` is prepended to PATH, shadowing the real `gh`
3. The wrapper calls `cplt gh-gate --real-gh /path/to/gh --real-git /path/to/git --repo-scope owner/repo -- <args>`
4. cplt evaluates the command against the policy table
5. If allowed, `exec()` replaces the process with the real `gh`, so there is no runtime overhead
6. If blocked, it prints an error explaining why and exits non-zero

> **Note:** Wrappers require the scratch directory. If you run with `--no-scratch-dir`,
> the gh/git guards will be inactive (shown as such in `cplt doctor` output).

## Policy tiers

| Tier | Behavior | Examples |
|------|----------|----------|
| **Allow** | Read-only; repo-scoped reads resolve against the startup repo, and an unverifiable cwd is pinned there rather than refused | `pr list`, `issue view`, `run list`, `search` |
| **ScopeCheck** | Permitted only for the startup repo; implicit targets must resolve there from cwd | `pr create`, `issue comment`, `pr close` |
| **Block** | Never permitted | `repo delete`, `pr merge`, `release create`, `workflow run` |
| **Unknown** | Not in the policy table, blocked by default | anything GitHub adds to `gh` after the table was last updated |

Merging, deleting, and releasing need human judgment, which is why they sit in
the Block tier rather than being scope-checked. `gh api` is the one command with
its own rules, described below.

Two entries surprise people. `gh repo clone` is blocked, because cloning
another repository pulls code into the sandbox from outside the enforced scope.
Plain `git clone` is not affected, since it is on the git guard's allow list.
And `gh auth status` is allowed while `gh auth status --show-token` is blocked.
The policy table classifies `auth status` as a read, so the token flag is
intercepted separately, in every spelling (`--show-token`, `--show-token=true`,
`-t`, and bundled clusters such as `-at`).

"Always permitted" in the Allow tier means permitted for the startup repo. A
repo-scoped read invoked from a *different* repository is blocked rather than
silently answered from the startup repo (#213). The repo-scoped groups are
`pr`, `issue`, `run`, `workflow`, `release`, `label`, `cache`, `secret`,
`variable`, `repo` and `ruleset`; commands that do not resolve a repository from
the cwd (`auth`, `search`, `gist`, `org`, `project`, `config`, `extension`,
`attestation`, `copilot`, ssh/gpg key listings, and the owner-scoped `repo list`
/ `repo gitignore` / `repo license`) stay usable from any directory.

## Scope checking

When a command is classified as `ScopeCheck`, cplt verifies that the command
targets the repository captured at sandbox startup:

1. At sandbox startup, reads `remote.origin.url` from the project root using the trusted Git binary
2. Ignores global/system config, config includes, and inherited `GIT_*` variables
3. Bakes the verified `owner/repo` and trusted Git path into the wrapper; unavailable scope remains fail-closed
4. If the command has `-R`/`--repo`, compares it to the startup scope
5. Otherwise, resolves the invocation cwd with the trusted Git binary and requires that repo to match the startup scope
6. Preserves explicit `/repos/owner/repo/...` API endpoint checks without requiring cwd matching
7. Rejects a conflicting `--hostname` or fully qualified non-GitHub API endpoint
8. Sets `GH_REPO=github.com/owner/repo` and clears `GH_HOST` before executing `gh`

Repo-scoped `Allow` commands get the same cwd check (step 5) when their target is
implicit, so a read from a sibling repository is blocked instead of silently
answered from the startup repo. Unlike `ScopeCheck`, an *unverifiable* cwd is not
fatal for a read: the command stays pinned to the startup repo, which is the safe
target.

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
gh auth status              # but not with --show-token or -t, see below
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
gh repo clone/create/delete/archive/fork/rename/edit/sync/deploy-key
gh pr merge/revert/lock/unlock
gh issue delete/transfer/lock/unlock/pin/unpin
gh release create/edit/delete/upload
gh secret set/delete
gh variable set/delete
gh workflow run/enable/disable
gh run rerun/cancel/delete
gh auth login/logout/refresh/setup-git/switch
gh auth token (served from one-time cache, see below)
gh auth status --show-token / -t (plain gh auth status stays allowed)
gh gist clone, gh label clone
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

`gh auth token` gets a one-time-read mechanism that hands Copilot its auth token
without exposing it to subprocesses:

1. Before launching the sandbox, cplt runs `gh auth token` (outside the sandbox)
2. Writes the token to a file in the scratch dir (`{scratch}/.gh-token`, mode 0600)
3. On Copilot's first call to `gh auth token`, the wrapper reads and returns the
   cached token, then **immediately deletes the file**
4. Any subsequent call by tools or MCP servers gets "no cached token available"

A `GH_TOKEN` environment variable would be inherited by every tool, MCP server,
and subprocess the agent spawns. The file gives it to the first reader only,
which is Copilot at startup. Copilot then caches it in memory, so one read is
enough. The file exists for well under a second, the token never appears as an
environment variable, and after the delete no subprocess can get it back via
`gh auth token`.

This path applies only:
- to the Copilot agent (other agents have their own auth mechanisms)
- when `block_auth_token = true` (default)
- when `GH_TOKEN`/`GITHUB_TOKEN` is not already set in the environment

It falls back gracefully if `gh` is not installed or not authenticated.

If you prefer the token in the environment instead, set `inject_token = true`:
```toml
[gh_guard]
inject_token = true   # injects GH_TOKEN env var (visible to all subprocesses)
```

## `gh api` handling

`gh api` gives raw API access, so it is classified per request rather than per
subcommand.

| Condition | Default | With `allow_api_write = true` | Reason |
|-----------|---------|-------------------------------|--------|
| No method flag (implicit GET) | ScopeCheck | ScopeCheck | Read operation, must target current repo |
| `-X GET` | ScopeCheck | ScopeCheck | Explicit read, must target current repo |
| `-X POST/PUT/PATCH` | Block | ScopeCheck | Write operation, opt-in required |
| `-X DELETE` | Block | Block | Destructive, always blocked |
| `-f`, `-F`, or `--input` present | Block | ScopeCheck | Input implies write, opt-in required |
| `graphql` endpoint | Block | Block | Arbitrary mutations possible, always blocked |

Note that `allow_api_write = true` scope-checks writes rather than freeing them.
Cross-repo writes are still denied.

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

GET requests are repo-scoped. Only endpoints matching
`/repos/{current-owner}/{current-repo}/...` are allowed, which blocks:

- `/orgs/.../audit-log`, org audit logs, which contain employee PII
- `/orgs/.../members`, org membership enumeration
- `/orgs/.../teams`, team structure
- `/user/repos`, private repos across all orgs
- `/users/.../repos`, other users' repo lists

Agents that need current-repo data (issues, PRs, actions, commits) work normally.
If an agent needs org-level access, the human should run those commands outside the sandbox.

### Why `gh api` is stricter than other commands

Higher-level commands like `gh repo view`, `gh repo list`, and `gh issue list` are
allowed cross-repo. They output curated, read-only data rather than raw API
responses with PII, agents commonly need them (checking dependencies,
understanding upstream issues), and they do not expose sensitive org internals
such as audit logs, SSO identities, or member emails.

Raw `gh api` can reach any REST endpoint, including exactly that sensitive
org and user data, so it gets the tighter rule.

## Error messages

Every block starts with `⚠️ BLOCKED by sandbox:`, followed by the reason and a
line asking the agent to note it for the human operator and carry on. The
opening lines:

```
⚠️ BLOCKED by sandbox: 'gh repo delete' is not allowed in this environment.
⚠️ BLOCKED by sandbox: 'gh pr create' targets 'other/repo' which is outside the current repo 'navikt/cplt'.
⚠️ BLOCKED by sandbox: 'gh newthing' is not recognized by the policy table.
⚠️ BLOCKED by sandbox: 'gh pr create' cannot verify target repository scope.
⚠️ BLOCKED by sandbox: 'gh api' targets an endpoint outside 'https://api.github.com'.
⚠️ BLOCKED by sandbox: 'gh issue list' targets GitHub host 'ghe.example.com', outside the approved host 'github.com'.
⚠️ BLOCKED by sandbox: revealing the GitHub token is not allowed in this environment.
```

The full message bodies live in `src/gh_proxy.rs`.

## Git push prevention

cplt installs a git wrapper alongside the gh wrapper. It blocks `git push`,
`git request-pull`, `git send-pack`, and `git subtree push` while letting local
git work through, so an agent can commit but a human has to push. It also blocks
anything that would retarget the `origin` remote, since that is where the gh
guard reads the enforced scope from, and it refuses git subcommands it does not
recognize while push prevention is on. Blocked commands, the
`protect_default_branch_only` mode, branch and refspec parsing, and the git-side
defense-in-depth layers are all covered in [git-guard.md](git-guard.md).

## Maintenance

The policy table lives in `src/gh_proxy.rs`. Commands GitHub adds to the `gh` CLI
are blocked automatically until someone classifies them, which is the safe
default but means the table needs periodic updates.

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

## Security boundaries

What the gh/git guard stops, and what it does not.

### What it protects against

| Threat | How it's stopped |
|--------|-----------------|
| Agent merges a PR without human review | `gh pr merge` is in the Block tier, always denied |
| Agent deletes a repository | `gh repo delete` is in the Block tier |
| Agent creates releases or uploads artifacts | `gh release create/upload` blocked |
| Agent triggers CI workflows | `gh workflow run` blocked |
| Agent pushes directly to main/master | `git push` blocked (or only default branch blocked with `protect_default_branch_only`) |
| Agent force-pushes and rewrites history | `--force`/`--force-with-lease` detection on push |
| Agent exfiltrates `gh auth token` value | `gh auth token` blocked; token served via one-time-read file (deleted after first use). Env var injection only with `inject_token=true` |
| Agent modifies secrets/variables | `gh secret set/delete`, `gh variable set/delete` blocked |
| Agent installs malicious gh extensions | `gh extension install/remove` blocked |
| Agent operates on other repositories | `-R other/repo` checked via ScopeCheck |
| Agent uses `gh api` POST to mutate state | Presence of `-f`, `-F`, `--input`, or non-GET method is blocked by default; opt-in with `allow_api_write = true` (scope-checked to current repo) |
| Agent uses `gh api graphql` for mutations | `graphql` endpoint unconditionally blocked even with `allow_api_write = true` (mutations via stdin not parseable) |

### What it does NOT protect against

| Gap | Explanation | Mitigation |
|-----|-------------|------------|
| **Data exfiltration via `gh api` GET** | The agent can `gh api /repos/owner/repo/contents/secret.yml` to read and then exfiltrate via network | Use network proxy domain filtering (`--blocked-domains`) |
| **Direct `curl` with `GH_TOKEN`** | Agent can `curl -H "Authorization: token $GH_TOKEN" https://api.github.com/...` bypassing the gh wrapper entirely | GH_TOKEN is only injected for Copilot agent; network proxy logs all outbound connections |
| **Wrapper bypass via real binary path** | Agent can `cat $(which gh)` to discover the real `gh` path in the wrapper script and call it directly | The wrapper uses `exec` so the real path is in the script; Seatbelt blocks writes to the scratch bin dir, but the path stays readable |
| **Agent edits `.github/workflows/`** | Agent can write CI configs that run on push, so destructive actions happen in CI, not locally | Code review (git diff); git push is blocked so workflows can't trigger |
| **Agent creates commits on main locally** | `git commit` on the main branch is allowed, being a local operation | The push guard prevents pushing those commits; human reviews before push |
| **`git send-pack` plumbing variants** | Covered, `send-pack` is in the block list | Already handled |
| **Agent reads project source code** | Project dir is fully readable (agent's core function) | Network domain filtering to prevent exfiltration |
| **Heuristic parser confusion** | Extremely unusual flag combinations might confuse the parser | Fail-closed: unknown states are blocked, and the e2e guard suite covers bypass variants |
| **New `gh` commands added upstream** | Unknown commands get `Decision::Unknown` and are blocked by default | Periodic policy table updates; `unknown_command = "block"` is default |

### Where the guard sits

| Layer | What it does | Can it be bypassed? |
|-------|--------------|---------------------|
| 1. Kernel sandbox (Seatbelt/Landlock) | Blocks credential file reads, exec from tmp, localhost | No, not by any user-space code |
| 2. Environment sanitization | Only safe env vars pass through; the agent never sees `AWS_SECRET_KEY`, `NPM_TOKEN`, and friends | No |
| 3. gh/git command guard (this feature) | Prevents destructive GitHub/git operations by shadowing the real binary in `PATH`; policy is baked at launch so the agent can't modify it | Yes, if the agent discovers the real binary |
| 4. Network proxy (domain filtering) | Blocks known exfiltration domains, logs all outbound CONNECT requests | Partly, see the gaps above |
| 5. AGENTS.md instructions | Tells the agent not to push/merge/delete | Yes, compliance only, nothing enforces it |

The gh/git guard is Layer 3. It sits between kernel enforcement, which cannot be
bypassed, and instructions, which cannot be enforced. Treat it as a strong
deterrent that stops compliant agents and catches accidental destructive
operations, not as a hard boundary against a determined adversary who already
has code execution.

The hard boundary is Layer 1. Credentials, SSH keys, and secret files are
physically inaccessible no matter what the agent does.

## Testing

The command guards are covered by `tests/e2e_guards.rs` and the `#[cfg(test)]` module in `src/gh_proxy.rs`, covering:

- Command parsing: plain, with flags, with `-R`, and API commands
- Policy evaluation across all three tiers, wildcard groups, and default-deny
- Scope checking: matching, non-matching, case-insensitive, `.git` suffix
- API endpoint path extraction and cross-repo detection
- Input flag bypass attempts (`--field=value`, `-fvalue`, `--input=-`)
- GraphQL endpoint blocking
- Force-push flag detection, including the `--force-with-lease=ref` form
- URL parsing: HTTPS, SSH shorthand, SSH URL, non-GitHub
- Wrapper script generation for both gh and git
- Git push blocking with flags like `-c key=value`, and git read/local-write operations passing through
- `protect_default_branch_only` branch and refspec parsing
- Full sandbox integration, wrapper through gate to real binary

Run tests:
```bash
cargo test --lib gh_proxy              # unit tests (parser, policy, helpers)
cargo test --test e2e_guards           # E2E tests (full binary pipeline)
mise run check                         # full suite
```
