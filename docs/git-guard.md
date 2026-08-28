# Git guard

The git guard stops a sandboxed agent from pushing code to a remote. It
intercepts every `git` invocation inside the sandbox and blocks the
remote-write commands while local operations pass through. An agent can commit,
branch, merge, and rebase all it wants. A human still reviews and pushes.

## Configuration

The git guard is opt-in and disabled by default.

```bash
cplt config set git_guard.enabled true
cplt config set git_guard.prevent_push true                  # block git push/request-pull/send-pack
cplt config set git_guard.protect_default_branch_only false  # block all pushes (default)
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
| `git push` (bare) | none, no explicit target | Allowed, conservatively assumed to be a feature branch |
| `git push origin` | none, no branch given | Allowed |
| `git push --force origin feature/x` | `feature/x` | Allowed, force-push to a feature branch |
| `git push --force origin main` | `main` | Blocked |

The default branch names are `main` and `master`, recognized with or without an
`origin/` prefix.

**Security note:** This mode is intentionally permissive. The agent can push
to any non-default branch. The human review gate becomes the pull request,
not the push prevention itself. Use full `prevent_push = true` if you want
no pushes at all.

## How it works

A wrapper script lives in the sandbox's scratch directory, which is prepended to
`PATH`, so it shadows the real `git` binary. It hands every argument to
`cplt git-gate` for evaluation:

```
cplt git-gate --real-git /usr/bin/git --mode block --prevent-push true --prevent-force-push true -- push origin feature/x
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

### Flag detection

The guard also spots the force-push flags on `git push`:

| Flag | Detection |
|------|-----------|
| `--force` / `-f` | Force-push detection |
| `--force-with-lease` | Including the `--force-with-lease=ref` form |
| `--force-if-includes` | Modern force-push variant |

When `protect_default_branch_only` is active, force-push to a feature branch is
allowed, since that is the agent's own branch. Force-push to a default branch is
always blocked.

## Allowed commands

Everything else passes through unchanged: `commit`, `add`, `branch`,
`checkout`, `merge`, `rebase`, `fetch`, `pull`, `log`, `diff`, `status`,
`stash`, `tag`, `remote`, `config` (read), etc.

**Default-allow, unlike the gh guard.** The gh guard is default-deny. The git
guard is not, because git has hundreds of plumbing commands, aliases, and
extensions, and push is the only remote-write git command that needs blocking.
The explicit block list is enough.

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

When a push is blocked, the agent sees:

```
[cplt] BLOCKED: git push is not allowed inside the sandbox.
       The human developer should review changes and push manually.
       To allow feature-branch pushes: set git_guard.protect_default_branch_only = true
```

When only default branch is blocked:

```
[cplt] BLOCKED: git push to 'main' is not allowed.
       Push to feature branches instead. The human developer merges to main.
```

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
