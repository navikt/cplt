# Git Guard

## Overview

The git guard prevents sandboxed agents from pushing code to remote
repositories. It intercepts all `git` invocations inside the sandbox
and blocks remote-write commands while allowing all local operations.

This ensures agents can commit, branch, merge, and rebase freely —
but a human must review and push.

## Configuration

The git guard is **opt-in** (disabled by default):

```toml
# ~/.config/cplt/config.toml

[git_guard]
enabled = true                       # activate the git wrapper
prevent_push = true                  # block git push/request-pull/send-pack
protect_default_branch_only = false  # only block pushes to main/master
```

Or via CLI:

```bash
cplt --git-guard -- -p "fix the tests"
```

### protect_default_branch_only

When enabled, only pushes to the default branch (`main` or `master`) are
blocked. Feature branch pushes are allowed:

```toml
[git_guard]
enabled = true
protect_default_branch_only = true
```

| Command | Result |
|---------|--------|
| `git push origin feature/fix-123` | ✅ Allowed |
| `git push origin main` | 🔒 Blocked |
| `git push origin master` | 🔒 Blocked |
| `git push` (bare, no explicit branch) | ✅ Allowed (assumes feature branch) |
| `git push origin HEAD:refs/heads/main` | 🔒 Blocked (refspec parsing detects target) |
| `git push --force origin feature/x` | ✅ Allowed (force-push to feature branch) |
| `git push --force origin main` | 🔒 Blocked |

**Security note:** This mode is intentionally permissive. The agent can push
to any non-default branch. The human review gate becomes the pull request,
not the push prevention itself. Use full `prevent_push = true` if you want
no pushes at all.

## How it works

```
Agent calls:  git push origin feature/x
                  │
                  ▼
Wrapper script (in scratch dir, shadows real git in $PATH)
                  │
                  ▼
cplt git-gate --repo <url> --scratch <dir> [--protect-default-branch-only true] -- push origin feature/x
                  │
         ┌───────┴───────┐
         │ Is it a       │
         │ blocked cmd?  │
         └───────┬───────┘
              no │        yes
                 │         │
                 ▼         ▼
         exec real git   EXIT 1 + error message
```

The wrapper script:
1. Lives in the sandbox's scratch directory (prepended to `PATH`)
2. Shadows the real `git` binary
3. Passes all arguments to `cplt git-gate` for policy evaluation
4. If allowed, `exec`s the real `git` (seamless — agent sees no difference)
5. If blocked, prints an error and exits non-zero

## Blocked commands

| Command | Reason |
|---------|--------|
| `git push` | Remote writes — human should review and push |
| `git request-pull` | Initiates upstream merge requests |
| `git send-pack` | Plumbing equivalent of push (remote writes) |

### Flag detection

The guard also detects dangerous flags on push:

| Flag | Detection |
|------|-----------|
| `--force` / `-f` | Force-push detection |
| `--force-with-lease` | Including `--force-with-lease=ref` form |
| `--force-if-includes` | Modern force-push variant |

When `protect_default_branch_only` is active, force-push to feature branches
is allowed (it's the agent's own branch). Force-push to default branches is
always blocked.

## Allowed commands

Everything else passes through unchanged: `commit`, `add`, `branch`,
`checkout`, `merge`, `rebase`, `fetch`, `pull`, `log`, `diff`, `status`,
`stash`, `tag`, `remote`, `config` (read), etc.

**Design choice — default-allow for git:**
Unlike the gh guard (default-deny), the git guard uses default-allow.
Git has hundreds of plumbing commands, aliases, and extensions. The push
operation is the only remote-write git command that needs blocking — the
explicit block list is sufficient.

## Branch detection logic

When `protect_default_branch_only = true`, the guard parses `git push`
arguments to extract the target branch:

```
git push [options...] [remote] [refspec...]
```

- **`git push origin main`** → target branch: `main` → blocked
- **`git push origin feature/x`** → target branch: `feature/x` → allowed
- **`git push origin HEAD:refs/heads/main`** → refspec target: `main` → blocked
- **`git push origin HEAD:main`** → refspec target: `main` → blocked
- **`git push`** (bare) → no explicit target → allowed (conservative: likely feature branch)
- **`git push origin`** → no branch specified → allowed

Default branches detected: `main`, `master` (with or without `origin/` prefix).

## Security boundaries

### What it protects against

| Threat | How it's stopped |
|--------|-----------------|
| Agent pushes code directly to main | `git push` blocked entirely, or only to default branch |
| Agent force-pushes and rewrites history | `--force`/`--force-with-lease` detected |
| Agent initiates merge requests | `git request-pull` blocked |
| Agent uses plumbing to push | `git send-pack` blocked |

### What it does NOT protect against

| Gap | Explanation | Mitigation |
|-----|-------------|------------|
| **Agent commits on main locally** | Local commit is allowed | Push guard prevents remote effect; human reviews before push |
| **Wrapper bypass via real binary** | Agent can read wrapper script to find real git path | Wrapper is in scratch dir; kernel blocks writes there but path is readable |
| **SSH push (if creds available)** | Agent could use raw SSH if keys were accessible | Kernel sandbox blocks `~/.ssh/` access entirely |
| **Agent modifies `.git/hooks`** | Post-push hooks or other persistence | Kernel sandbox blocks writes to `.git/hooks/` and `.git/config` |
| **Git credential helper** | Could theoretically extract tokens | `GIT_TERMINAL_PROMPT=0` disables interactive prompts; credential files blocked |

### Security level

The git guard is a **soft barrier (Layer 3)**. It prevents compliant agents
from accidental pushes. A determined adversary who discovers the real binary
path could bypass it.

**Hard boundaries that complement it:**
- Kernel sandbox blocks `~/.ssh/` (no SSH push possible)
- Kernel sandbox blocks `.git/hooks/` writes (no hook persistence)
- Server-side branch protection rules (ultimate backstop)

## Defense in depth

| Layer | Control | Strength |
|-------|---------|----------|
| AGENTS.md | Instructs agent not to push | Soft (compliance-based) |
| `GIT_TERMINAL_PROMPT=0` | Blocks interactive credential prompts | Medium |
| **Git wrapper (this feature)** | Blocks `git push` at command level | Strong (kernel PATH) |
| Kernel sandbox | Blocks `~/.ssh/`, `.git/hooks` writes | Strongest (unbypassable) |
| Server branch protection | Rejects unauthorized pushes server-side | Strongest (server-side) |

The recommended approach: use the git wrapper as the primary enforcement
and AGENTS.md as the UX layer (agent doesn't even attempt push → clean
experience).

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

Key test coverage:
- `git push` blocked (with various flag combinations)
- `git push -c key=value` (option before subcommand)
- `git commit`, `git add`, etc. allowed
- `protect_default_branch_only` with branch names and refspecs
- Force-push flag detection variants
- Wrapper script generation and execution
