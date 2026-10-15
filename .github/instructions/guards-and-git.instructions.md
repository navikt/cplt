---
applyTo: "src/gh_proxy.rs,src/gh_graphql.rs,src/git.rs,src/shim.rs,src/agent.rs,src/opencode_v2.rs,src/gradle_init.rs"
---

# Command guards and git hardening review instructions

## Argument parser parity in `src/gh_proxy.rs`

- **Flag clustering and attached values.** `gh` uses Cobra/pflag and `git` uses its own option parser. Both accept clustered short flags such as `-fXDELETE` or `-uorigin` and attached values such as `--method=DELETE` or `--repo=owner/repo`. Any guard inspection loop must handle exact flags, `--flag=value`, and short-flag clusters identically to the underlying binary.
- **Global flags in any position.** `gh` accepts global flags like `-R`/`--repo` both before and after the subcommand. Scan the full argument vector rather than stopping at the subcommand token.
- **Fail closed on ambiguity.** Unknown subcommands, unrecognized flags on security-sensitive verbs, or malformed GraphQL documents must be denied or routed to confirmation, never silently classified as safe.

## Git guard and parent-side `src/git.rs`

- **Sensitive git config keys.** The git guard must block `-c` and `git config` writes to execution and redirection keys including `core.fsmonitor`, `core.hooksPath`, `core.sshCommand`, `core.pager`, `core.editor`, `core.gitProxy`, `diff.external`, `credential.helper`, `filter.*`, `alias.*`, `protocol.*`, and `remote.origin.url`.
- **Single parent-side choke point.** Every parent-side git invocation must go through `git::command(project_dir, args)`, not raw `Command::new(git::trusted_git()?)`. `git::trusted_git()` only resolves the binary path from `TRUSTED_BIN_DIRS`. `git::command()` applies `harden()`, which clears inherited `GIT_*` environment variables, sets `GIT_CONFIG_NOSYSTEM=1` and `GIT_ATTR_NOSYSTEM=1`, prepends `-c` overrides from `CONFIG_OVERRIDES`, inserts `--no-textconv --no-ext-diff` after `diff`, refuses `VALUE_TAKING_GLOBALS` (`-C`, `-c`, `--git-dir`, `--work-tree`, `--namespace`, `--config-env`, `--attr-source`), and refuses worktree-reading subcommands when `repo_defines_content_filter(project_dir)` is true.

## REST and GraphQL inspection in `src/gh_graphql.rs`

- **Endpoint and method checks.** `gh api` read-only classification must decode percent-encoded path segments, reject path traversal, and treat any `-f`, `-F`, `--raw-field`, `--field`, or `--input` flag as a mutation unless explicitly executing a verified read-only GraphQL `query`.
