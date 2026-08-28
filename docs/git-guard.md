# Git guard

The git guard stops a sandboxed agent from pushing code to a remote. It
intercepts every `git` invocation inside the sandbox and blocks the
remote-write commands while local operations pass through. An agent can commit,
branch, merge, and rebase all it wants. A human still reviews and pushes.

## Configuration

The git guard is opt-in and disabled by default.

```bash
cplt config set git_guard.enabled true
cplt config set git_guard.prevent_push true                  # block git push/request-pull/send-pack (default true)
cplt config set git_guard.prevent_force_push true            # block force push (default true)
cplt config set git_guard.protect_default_branch_only false  # block all pushes (default)
cplt config set git_guard.mode block                         # block | warn | audit (default block)
```

`mode` controls what happens on a block. `block` prints the message and exits
non-zero. `warn` prints `⚠️  WARNING (would block): …` and runs the command
anyway. `audit` prints `[audit] git-gate: would block: …` and runs it. Use
`warn` or `audit` during a rollout to find out what would break before you
enforce.

`git_guard.allow_push` is a structured exception list for the cases where a
push has to go through. Each entry may name a `remote`, a list of `branches`
(glob patterns), and whether `force` is permitted. An entry matches only if
every constraint it sets matches, and a force push needs `force = true`. One
exception: under `protect_default_branch_only`, a force push to a feature
branch is rejected by `prevent_force_push` before the allow list is consulted,
so `force = true` does not reach that path. `cplt config set` cannot write this
key at all, because it is an array of tables, so edit the config file directly:

```toml
[[git_guard.allow_push]]
remote = "origin"
branches = ["renovate/*", "dependabot/*"]
force = false
```

<details>
<summary>CLI flag (override for a single run)</summary>

```bash
cplt --git-guard -- -p "fix the tests"
```
</details>

### protect_default_branch_only

With this enabled, only pushes to the default branch are blocked and feature
branch pushes go through:

```bash
cplt config set git_guard.enabled true
cplt config set git_guard.protect_default_branch_only true
```

The guard parses `git push [options...] [remote] [refspec...]` to find the
target branch:

| Command | Target branch | Result |
|---------|---------------|--------|
| `git push origin feature/fix-123` | `feature/fix-123` | Allowed |
| `git push origin main` | `main` | Blocked |
| `git push origin master` | `master` | Blocked |
| `git push origin HEAD:refs/heads/main` | `main` (from refspec) | Blocked |
| `git push origin HEAD:main` | `main` (from refspec) | Blocked |
| `git push` (bare) | resolved from the current branch via the real git | Allowed on a feature branch, blocked on `main`/`master`, blocked if the branch cannot be resolved |
| `git push origin` | same, no branch in the arguments | Allowed on a feature branch, blocked on `main`/`master`, blocked if the branch cannot be resolved |
| `git push --force origin feature/x` | `feature/x` | Blocked while `prevent_force_push` is on, which is the default |
| `git push --force origin main` | `main` | Blocked |

The default branch names are `main` and `master`, recognized with or without an
`origin/` prefix. When several refspecs are given, the guard checks all of them
and blocks if any names a default branch, so `git push origin feature main`
does not slip through.

A push with no branch in the arguments is not waved through. The guard shells
out to the real git to resolve the current branch, and fails closed when it
cannot: an unresolvable branch counts as protected and the push is blocked.

**Security note:** This mode is intentionally permissive about branches. The
agent can push to any non-default branch, and the human review gate becomes the
pull request rather than the push prevention itself. Force push stays blocked
even on a feature branch while `prevent_force_push` is on, which is the
default. Use full `prevent_push = true` with `protect_default_branch_only =
false` if you want no pushes at all.

## How it works

A wrapper script lives in the sandbox's scratch directory, which is prepended to
`PATH`, so it shadows the real `git` binary. It hands every argument to
`cplt git-gate` for evaluation:

```
cplt git-gate --real-git /usr/bin/git --mode=block --prevent-push=true --prevent-force-push=true --protect-default-branch-only=false -- push origin feature/x
```

If the gate allows the command, the wrapper `exec`s the real `git` and the agent
sees no difference. If the gate blocks it, the wrapper prints an error and exits
non-zero.

## Blocked commands

| Command | Reason |
|---------|--------|
| `git push` | Remote write, a human should review and push |
| `git request-pull` | Initiates upstream merge requests |
| `git send-pack` | Plumbing equivalent of push, also a remote write |
| `git subtree push` | A remote write in subtree clothing. The local forms `add`, `pull`, `split`, and `merge` stay allowed |
| `git remote add origin …`, `git remote set-url origin …`, `git remote rename <old> origin` | Retargets the `origin` remote, which is where the gh guard reads the enforced repo scope from |
| `git config remote.origin.url …`, `git config remote.origin.pushurl …` | Same retargeting, through config instead of the `remote` subcommand |
| `git config url.<base>.insteadOf …`, `…pushInsteadOf …` | git's URL-rewrite rules silently redirect transport for any matching URL |
| `git -c alias.<name>=<cmd> …` | An alias defined on the command line expands inside the real git, after the guard has already decided |
| Any unrecognized subcommand | See below |

Remote-URL mutation is blocked whenever the guard is active, not only under
`prevent_push`. Read-only inspection stays allowed: `git remote -v`,
`git remote get-url origin`, `git config --get remote.origin.url`, and the other
read forms. Managing remotes other than `origin`, such as
`git remote add upstream …`, is also allowed.

### Flag detection

The guard also spots the force-push flags on `git push`:

| Flag | Detection |
|------|-----------|
| `--force` / `-f` | Force-push detection |
| `--force-with-lease` | Including the `--force-with-lease=ref` form |
| `--force-if-includes` | Modern force-push variant |

Force push is blocked wherever it lands while `prevent_force_push` is on, which
is the default, including on a feature branch under
`protect_default_branch_only`. Set `git_guard.prevent_force_push = false` if you
want the agent to be able to force-push its own branch. Force push to a default
branch is blocked unless a `git_guard.allow_push` entry names that branch with
`force = true`.

## Allowed commands

The guard holds an explicit allowlist of read-only, local-write, and
remote-read subcommands: `status`, `log`, `show`, `diff`, `blame`, `bisect`,
`branch`, `checkout`, `switch`, `merge`, `rebase`, `cherry-pick`, `revert`,
`reset`, `restore`, `stash`, `tag`, `worktree`, `add`, `rm`, `mv`, `clean`,
`commit`, `am`, `apply`, `fetch`, `pull`, `clone`, `ls-remote`, `remote`,
`config`, `submodule`, `lfs`, `subtree`, and the read and local-packing
plumbing (`cat-file`, `rev-parse`, `ls-files`, `pack-objects`, `gc`, and so on).
`src/gh_proxy.rs` holds the full list.

**Default-deny while push prevention is active.** An unrecognized subcommand is
blocked, not passed through, whenever `prevent_push` is on. An agent can define
an alias that resolves to a blocked subcommand, and git expands aliases inside
the real binary after the guard has approved the command, so anything the guard
cannot classify has to be refused. If only `prevent_force_push` is on, the
guard checks force flags on `push` and lets everything else through.

## Security boundaries

### What it does NOT protect against

| Gap | Explanation | Mitigation |
|-----|-------------|------------|
| **Agent commits on main locally** | Local commit is allowed | Push guard prevents remote effect; human reviews before push |
| **Wrapper bypass via real binary** | Agent can read wrapper script to find real git path | Wrapper is in scratch dir; kernel blocks writes there but path is readable |
| **SSH push (if creds available)** | Agent could use raw SSH if keys were accessible | Kernel sandbox blocks `~/.ssh/` access entirely |
| **Agent modifies `.git/hooks`** | Post-push hooks or other persistence | Kernel sandbox blocks writes to `.git/hooks/` on both platforms, and to `.git/config` on macOS only. On Linux `.git/config` stays writable, so `core.hooksPath` can still redirect hooks. |
| **Git credential helper** | Could theoretically extract tokens | `GIT_TERMINAL_PROMPT=0` disables interactive prompts; credential files blocked |

### Defense in depth

The git guard is a soft barrier at Layer 3. It stops a compliant agent from
pushing by accident. An adversary who finds the real binary path can get around
it. These are the layers around it:

| Layer | Control | Strength |
|-------|---------|----------|
| AGENTS.md | Instructs agent not to push | Soft (compliance-based) |
| `GIT_TERMINAL_PROMPT=0` | Blocks interactive credential prompts | Medium |
| **Git wrapper (this feature)** | Blocks `git push` at command level | Strong (kernel PATH) |
| Kernel sandbox | Blocks `~/.ssh/` and `.git/hooks` writes. `.git/config` only on macOS | Strongest (unbypassable) |
| Server branch protection | Rejects unauthorized pushes server-side | Strongest (server-side) |

Use the git wrapper as the primary enforcement and AGENTS.md as the UX layer, so
the agent does not even attempt a push and the experience stays clean.

## Per-repo configuration

Enable via `.cplt.toml` in the repository:

```toml
[propose]
git_push_prevention = true
```

This requires developer approval (`cplt trust accept`) before taking effect.

## Error messages

Every block starts with `⚠️ BLOCKED by sandbox:`, followed by the reason, what
is still allowed, and a line asking the agent to note it for the human operator
and carry on. The opening lines:

```
⚠️ BLOCKED by sandbox: 'git push' is not allowed in this environment.
⚠️ BLOCKED by sandbox: 'git push --force' is not allowed in this environment.
⚠️ BLOCKED by sandbox: 'git subtree push' is not allowed in this environment.
⚠️ BLOCKED by sandbox: 'git frobnicate' is not a recognized subcommand.
⚠️ BLOCKED by sandbox: 'git remote' would change a remote's URL.
⚠️ BLOCKED by sandbox: 'git -c alias.*' is not allowed.
```

In `warn` mode the same text is prefixed with `⚠️  WARNING (would block):` and
the command runs anyway. In `audit` mode the prefix is
`[audit] git-gate: would block:`. The full message bodies live in
`src/gh_proxy.rs`.

## Testing

```bash
cargo test --lib gh_proxy              # unit tests (push parsing, branch detection)
cargo test --test e2e_guards           # E2E tests (full binary → wrapper → gate)
mise run check                         # full suite
```

Key coverage: `git push` blocked across flag combinations, `git push -c key=value`
with an option before the subcommand, `git commit` and `git add` allowed,
`protect_default_branch_only` against both branch names and refspecs, the
force-push flag variants, and wrapper script generation and execution.
