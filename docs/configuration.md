# Configuration

## Precedence

cplt resolves each setting in this order, highest first:

1. CLI flags for the current run (`--with-proxy`, `--no-proxy`, `--proxy-port`, and so on)
2. This project's per-repo user config, `~/.config/cplt/local/<hash>.toml` (see [Per-repo user config](#per-repo-user-config-config-set---local))
3. The config file, `~/.config/cplt/config.toml`, or whatever `CPLT_CONFIG` points at
4. Built-in defaults

Per-repo config (`.cplt.toml`) sits outside that hierarchy, as a separate layer with its own rules. See [Per-repo configuration](#per-repo-configuration-cplttoml).

Sessions that span several repositories are configured separately again — see [Working across several repositories](#working-across-several-repositories---repo-dir).

List values merge instead of replacing, so repeated `cplt config set` commands accumulate for `allow.read`, `allow.write`, `allow.ports`, `allow.localhost`, `allow.domains`, and `deny.paths`.

Point `CPLT_CONFIG` at another file to use it instead of the default location:

```bash
CPLT_CONFIG=/path/to/custom.toml cplt -- --version
```

`CPLT_CONFIG` replaces the whole config file, `[sandbox]` keys included, so it
can widen the sandbox in ways a repo's `.cplt.toml` never can. Because a shell
that auto-loads repository environment (direnv, mise) can set it just by you
entering a directory, cplt keeps the substitution visible:

- Pointing it anywhere other than `~/.config/cplt/` prints a warning naming the
  file. The warning is not suppressed by `--quiet`.
- Pointing it **inside the project directory** is refused and cplt exits: that
  file is repository content, and it would replace your config with none of the
  review a `.cplt.toml` gets. Symlinks and `..` are resolved first, so a link
  from outside the repo back into it is refused too. Unset `CPLT_CONFIG` (check
  `.envrc` and mise config) to run.

Paths in `[allow]` and `[deny]` support `~/` expansion and resolve relative to the config file's directory. `proxy.blocked_domains` supports `~/` expansion only.

## Per-repo user config (`config set --local`)

Your own settings for one checkout, kept out of the repository:

```bash
cplt config set --local proxy.port 8443
cplt config set --local allow.read ~/scratch/spleis
cplt config path --local       # where this project's file lives
cplt config local list         # every project with one, and the orphans
```

The file lives at `~/.config/cplt/local/<sha256 of the checkout's canonical
path>.toml`, **outside** the repository — which is what lets it widen the
sandbox the way `config.toml` does. Write access to `~/.config/cplt/` is denied
inside the sandbox, so the agent cannot write its own grants there; a file in
the working tree could make no such claim. Dangerous keys still need `--force`,
and `config show` labels every scalar it supplies `(local)`, dangerous ones
included. List keys union with the global layer, so they are shown merged and
unattributed — except `sandbox.repo_dirs`, which only this layer can set.

Two rules are specific to this layer:

- **Absolute paths only.** A relative entry is refused at `config set --local`
  and again at load: there is no sensible directory for it to anchor to.
- **A moved or replaced checkout stops applying.** The file records the `origin`
  it was written for; if a different repository now sits at that path, cplt
  warns (not suppressed by `--quiet`) and applies nothing. Re-adopt it by
  setting any key with `--local` again. A checkout that moved leaves an orphan
  file, which `cplt config local list` marks as "path no longer exists".

## Working across several repositories (`--repo-dir`)

A session often spans more than one repository: a service and the library it
pulls in, an app and its schema, a Gradle build with an included build beside
it. By default only the launch repository has an identity — `gh` write commands
are scoped to it, and a `gh pr create` aimed at the other one is refused.

Name the other repository and it becomes a first-class repository of the
session:

```bash
# For one run
cplt --repo-dir libs/sykepenger-model exec -- ./gradlew build

# Persisted for this checkout, so every later launch picks it up with no flag
cplt config set --local sandbox.repo_dirs ~/src/spleis/libs/sykepenger-model

# Or name the repository and let cplt find and verify the checkout
cplt link navikt/sykepenger-model
```

The startup summary then lists what is in scope, and where each entry came
from:

```
 Repositories:
   navikt/spleis            ~/src/spleis                        launch repository
   navikt/sykepenger-model  ~/src/spleis/libs/sykepenger-model   local config
```

A flag *adds to* the persisted set rather than replacing it, so a one-off
`--repo-dir` on top of a saved list is the union of both.

### What naming a repository does, and what it does not

**For a repository nested inside the project, it declares identity, not
access.** A nested checkout already sits inside the project directory, so the
agent could always read, write and build there — the project directory is
granted as one subtree. What `--repo-dir` adds is that `gh` may target it:
`gh pr create -R navikt/sykepenger-model` is allowed, the gh scope set includes
it, and `GH_REPO` pinning accounts for it.

It also decides what the post-session audit measures. Each named repository is
audited on its own lines, against its own baseline:

```
[cplt] Session ended (exit 0, 41s)
[cplt] Project changes: 2 files (+18 -3)
[cplt]   src/main.rs  +18 -3
[cplt] Changes in ~/src/spleis/libs/sykepenger-model: 1 file (+4 -0)
[cplt]   src/Vedtaksperiode.kt  +4 -0
```

That report is the reason to name a repository even when the agent could
already write to it. A checkout keeps its own git history, so the launch
repository's `git status` sees it as a single entry — or, when it is
gitignored, as nothing at all. Before it had a report of its own, a session
that edited only the nested repository printed `no project file changes`.

**For a repository beside the launch one, it declares access as well.** A
sibling checkout — `~/src/spleis` and `~/src/sykepenger-model` side by side —
is not reachable at all unless you name it, and naming it grants read, write
and execute on that tree:

```bash
cd ~/src/spleis
cplt --repo-dir ~/src/sykepenger-model
```

The startup summary distinguishes the two cases, because they are the same row
otherwise:

```
 Repositories:
   navikt/spleis            ~/src/spleis                 launch repository
   navikt/sykepenger-model  ~/src/sykepenger-model       --repo-dir   new read/write/exec tree
```

Execute is the part that needed a feature. `--allow-write` has always given a
sibling read and write, but a write grant is deliberately **not** executable —
a tree that is both is where an agent drops a binary and runs it. So this works
for editing and fails for building:

```bash
# Edit-only: files yes, build no, gh identity no
cplt --allow-write ~/src/sykepenger-model exec -- $EDITOR
```

Use `--allow-write` when the sibling only needs to be edited, and `--repo-dir`
when its own build, tests or pull requests have to run.

If you have `allow.write` over a directory that holds checkouts, cplt says so at
launch and names the repositories it found. That grant looks like "let the agent
work in these" and is not: a script there fails with `bad interpreter: Operation
not permitted`, which names neither cplt nor the grant, and reads like a problem
with the project. Naming the repositories is the fix. A named root is a
second writable-and-executable tree, with the same protected paths as the
project: `.git/hooks`, `.git/config`, `.cplt.toml` and the rest stay unwritable
in it, so a hook cannot be planted to run outside the sandbox later.

**The git guard follows the set too.** A `git push` inside a named repository is
judged by *that* repository's default branch, captured at launch — so a
repository whose default branch is `trunk` protects `trunk`, not the launch
repository's `main`. An `allow_push` rule naming a remote is pinned to that
remote's URL in every repository in scope, and it authorizes a push only when
the push also runs in one of them: a rule written for this session cannot
authorize a push from a clone the agent made underneath the project, whose
`origin` you were never thinking about
([#424](https://github.com/navikt/cplt/issues/424)).

**A named repository's `[deny]` applies too.** `[deny]` can only tighten, so it
needs no approval, no trust entry and no content hash — there is no grant a
second repository could open with it. Paths anchor to the repository that wrote
them, so each repository's deny applies inside itself. `deny.env` is the
exception and is process-wide: a named repository stripping a variable strips it
for the session, and cplt says so at launch.

`[propose]` is launch-repository only. A named repository that proposes
something gets one line saying it was not consulted; approving proposals per
repository is [#206](https://github.com/navikt/cplt/issues/206)'s decision to
make first. A `.cplt.toml` in a named repository that cannot be parsed **stops
the launch** rather than being skipped: the file exists, so a restriction its
owner wrote is missing, and a missing restriction is not a warning to scroll
past.

Launching from the parent (`--project-dir ~/src`) grants the whole tree and is a
much wider grant than naming two repositories. It also does **not** let you name
the checkouts: `--repo-dir` requires the launch directory to be a git repository
toplevel, and a plain directory holding repositories is not one, so the
combination is refused rather than quietly granting identity to everything under
it.

### Which layer it can be set in

`sandbox.repo_dirs` is settable **only** in the per-repo local config
(`config set --local`), and this is deliberate:

| Layer | Accepted | Why |
| --- | --- | --- |
| `--local` (`~/.config/cplt/local/<hash>.toml`) | **yes** | Outside the repository and unwritable from inside the sandbox, so it can name roots the way `config.toml` can widen the sandbox. Scoped to one checkout. |
| Global (`~/.config/cplt/config.toml`) | no | A repository list in your global config would attach to every session, including repositories where those paths mean something else. |
| `.cplt.toml` (`config set --repo`) | no | It is committed, so it would hand every cloner's agent a new project-grade root. Repo config can tighten, never grant paths. |

Each refusal names the layer that does work, so you do not have to remember the
table.

`config set` takes `-g`, `-l` and `-r` for `--global`, `--local` and `--repo`.
The long forms are used throughout this document because they say which file is
being written.

### Naming a repository instead of a path

`cplt link` takes the repository, finds the checkout, and checks it really is
that repository before writing the path:

```bash
cplt link navikt/sykepenger-model
# [cplt] navikt/sykepenger-model → /Users/you/src/sykepenger-model
#        (beside this repository, origin verified)
```

Where it looks, in order: beside the launch repository; then across the forge
directory, so `nais/unleash` is findable from `navikt/cplt` in a
`<host>/<org>/<repo>` layout; then the origin of each directory beside the
launch repository, capped, which finds a clone in a differently-named
directory. A directory that resolves inside the launch repository is never a
candidate — that tree is agent-writable, so a checkout planted there would be a
repository of the agent's choosing wearing the right name. That check runs on
the resolved path, so a symlinked sibling pointing back into the project does
not get around it. Note the sibling directory itself is only as trustworthy as
your machine: one `--project-dir <parent>` launch makes every directory beside
the repository writable from the sandbox.

Every candidate has its `origin` read by the trusted git **outside** the
sandbox and must match the name you asked for. A directory called
`sykepenger-model` that is some other repository is not linked, and a directory
you name yourself is checked too:

```bash
cplt link navikt/sykepenger-model ~/elsewhere/model    # verified, not assumed
```

If two equally good candidates verify, cplt refuses and names both rather than
picking. A directory named after the repository beats one matched only by its
origin, and the weaker matches are printed so you can link one of those
instead. Linked worktrees of the chosen checkout are counted, not listed — they
share one `.git`, so they all report the same origin.

`cplt link <owner>/<name> --unlink` removes it again, so a root can be dropped
by the name it was added under. It matches on the recorded directory's origin
where it can read one, and falls back to the directory's own name where it
cannot — a deleted directory has no identity to read, and neither does one whose
`.git/config` was rewritten since. Without that fallback the entries most worth
removing would be the ones the command refused to find. If more than one entry
answers, it names them and removes none; `cplt config set --local
sandbox.repo_dirs <DIR> --unset` is always available.

What this writes is an ordinary `sandbox.repo_dirs` entry, so everything below
applies to it unchanged. What it adds is the identity check. And note the
limit: **"origin verified" describes the moment you ran the command.** On Linux
an agent can rewrite `.git/config` in any tree it was granted, and Landlock
cannot carve that file out of a writable root — which is why the link is stored
and re-validated as a path, never re-resolved from the name.

### Relative paths are resolved when you set them

`../sibling` is how people name the repository next door, so `config set` takes
it and stores what it resolves to:

```bash
cd ~/src/spleis
cplt config set --local sandbox.repo_dirs ../sykepenger-model
# [cplt] sandbox.repo_dirs = [/Users/you/src/sykepenger-model]
```

The file holds absolute paths only. A relative entry *in* the file has no
stable anchor — it would mean different directories depending on where cplt was
started — so what gets written is the resolved path, not what you typed. A
`~/` entry is stored as typed: it is already anchor-independent, and expanding
it would bake in one machine's home directory.

The path has to exist when you set it. A relative entry cplt cannot resolve now
is one the next launch would refuse anyway, and the error at write time names
the directory you were standing in.

Removing works the same way, so you can `--unset ../sykepenger-model` without
looking up how it was stored.

### Rules that apply on every launch, not only when written

A persisted entry is re-validated at each launch, because the file may be weeks
old and the tree it names is agent-writable. An entry is refused — the launch
stops, it is not silently dropped — when it:

- is not a git repository toplevel (a subdirectory of one is not a repository),
- contains the launch repository (launch from it and name the inner one),
- has a symlink as its **final** component (a symlink planted there last session
  would redirect the identity this launch pins; a symlinked *ancestor* is fine,
  it is just the path you took to get there),
- contains a `..` component, which hides which directory is actually named,
- is your home directory or another unsafe root.

The launch repository itself is refused too: it is always in scope, and naming
it again is a sign the entry means something else.

Refusals name the source, so a persisted root says which file to fix rather
than blaming a flag nobody passed:

```
[cplt] sandbox.repo_dirs entry ~/src/spleis/libs in
       ~/.config/cplt/local/3291….toml is not a git repository; for a plain
       directory use `--allow-write`.
```

### Everyday recipes

```bash
# What is in scope right now, without launching an agent
cplt config get sandbox.repo_dirs
cplt config show | grep repo_dirs      # shown with its (local) label

# Stop naming one, or clear the list
cplt config set --local sandbox.repo_dirs ~/src/spleis/libs/sykepenger-model --unset
cplt config set --local sandbox.repo_dirs --unset

# Which checkouts have a local config at all
cplt config local list
```

For a monorepo of many small repositories, name only the ones the agent will
open pull requests against. Every named root widens what `gh` may write to, and
the gh guard is the thing standing between an agent and the wrong repository.

## Quick setup

`cplt settings` browses and changes settings interactively. It stages edits, shows their source and security impact, and writes validated TOML atomically. For scripts, CI, or a direct non-interactive edit, use `cplt config set`:

```bash
cplt config set sandbox.quiet true
cplt config set proxy.port 9090
cplt config set allow.read ~/Desktop
cplt config set allow.ports 8080
cplt config set git_guard.mode warn      # the git guard blocks by default
cplt config set gh_guard.enabled false   # opt out of the gh guard
```

When your startup command gets long, move the repeated flags into config. Your personal machine setup belongs in global config, so leave off `--repo`:

```bash
cplt config set sandbox.allow_localhost_any true  # tools that grab random localhost ports
cplt config set sandbox.allow_docker true         # Gradle, Testcontainers, Docker
cplt config set sandbox.allow_jvm_attach true     # Gradle daemon, MockK, Mockito inline mocking
cplt config set allow.read ~/.gitconfig           # host files the agent should always read
cplt config set allow.read ~/code/work/.gitconfig-nav
```

That saves you from typing this every time:

```bash
cplt --allow-localhost-any --allow-docker --allow-jvm-attach \
  --allow-read ~/.gitconfig --allow-read ~/code/work/.gitconfig-nav
```

`cplt config explain` tells you what a key does and how to set it.

## Policy presets

A preset is a named security posture. One flag or key sets a baseline for the five sandbox toggles and for the safety features (`gh_guard`, `git_guard`, forced-proxy egress, fail-closed domain allowlist):

```bash
cplt --preset strict       # full lockdown: toggles off + guards + forced proxy + domain allowlist on
cplt --preset standard     # the current defaults (no-op baseline)
cplt --preset permissive   # localhost + tmp exec + lifecycle scripts on
cplt --preset full-trust   # everything on (docker, env files, tmp exec, localhost, lifecycle)
```

Or in config:

```toml
[sandbox]
preset = "standard"
```

| Preset | localhost (`allow_localhost_any`) | env files (`allow_env_files`) | tmp exec (`allow_tmp_exec`) | docker (`allow_docker`) | lifecycle (`allow_lifecycle_scripts`) | `gh_guard` | `git_guard` | `proxy.forced` | `proxy.default_allowlist` |
|--------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `strict` | off | off | off | off | off | **on** | **on** | **on** | **on** |
| `standard` | off | off | off¹ | off | off | off | off | off | off |
| `permissive` | **on** | off | **on** | off | **on** | off | off | off | off |
| `full-trust` | **on** | **on** | **on** | **on** | **on** | off | off | off | off |

¹ `standard` leaves the per-session scratch directory on, which is the default and what most tools need. `allow_tmp_exec` (raw `/tmp` exec) stays off. `standard` is identical to cplt's hardcoded defaults, so omitting `--preset` behaves exactly like `--preset standard`.

`gh_guard` and `git_guard` are on under `standard` (the default posture), both in `block` mode; the git guard blocks pushes to the default branch only (`protect_default_branch_only`), so feature-branch pushes still work. `strict` additionally drops that relaxation — every push is blocked — and turns on `proxy.forced` (mandatory proxy, kernel egress locked to it) and `proxy.default_allowlist` (fail-closed domain filtering, where only the agent's built-in allowlist plus any `allowed_domains` resolve and everything else is blocked). The last two are orthogonal and compose: the kernel pins egress to the proxy, then the proxy filters domains. `permissive` and `full-trust` turn both guards back off along with weakening the sandbox toggles.

Because `strict` only enables safety features, `config set sandbox.preset strict` needs no `--force`, unlike `permissive` and `full-trust`, which weaken the sandbox. To take the strict baseline but keep the network open, add `--allow-all-domains` (or `proxy.default_allowlist = false`). That overrides just the allowlist, since an explicit off beats the baseline.

### Preset precedence

A preset is only a baseline. An explicit flag or config value always overrides it, whichever source the preset came from:

```bash
# permissive baseline, but keep tmp exec blocked:
cplt --preset permissive --no-allow-tmp-exec

# strict baseline, but allow docker just for this run:
cplt --preset strict --allow-docker
```

Each toggle resolves in this order: explicit CLI flag, then explicit config value, then preset baseline, then the hardcoded default (off). The preset itself resolves CLI (`--preset`) over config (`[sandbox] preset`). Every preset-controlled toggle has a matching `--no-…` form (`--no-allow-localhost-any`, `--no-allow-env-files`, `--no-allow-tmp-exec`, `--no-allow-docker`, `--no-allow-lifecycle-scripts`), so you can opt a single toggle out of a permissive or full-trust baseline.

## Global-only settings

Project-specific sandbox permissions belong in `.cplt.toml`, approved with `cplt trust`. That covers `sandbox.allow_jvm_attach`, `sandbox.allow_msbuild`, `sandbox.allow_docker`, `sandbox.allow_localhost_any`, and `allow.ports`. Machine-specific paths such as `allow.read ~/.gitconfig` go in `~/.config/cplt/config.toml`.

`sandbox.pass_env` is the exception among the environment settings: a project can propose the variables its build needs (`NODE_ENV`, `TZ`, `SPRING_PROFILES_ACTIVE`), because it names them one at a time and a reviewer sees the list in the diff. The value still comes from whoever launches the agent, never from the file, and each developer approves once with `cplt trust`. `sandbox.inherit_env` stays refused — it passes the whole environment, so there is nothing for a reviewer to review.

The settings below are machine-specific or local CLI preferences, so `.cplt.toml` does not support them at all. `cplt config set --repo <key>` rejects each one with an explanation. Set them globally instead.

| Key | Why |
|---|---|
| `sandbox.preset` | composes several dangerous permissions into one baseline, so a repo must request individual keys and get each reviewed and trusted separately |
| `sandbox.agent` | preferred agent depends on what's installed locally |
| `sandbox.quiet` | local output preference |
| `sandbox.yes` | local prompt-skip preference |
| `sandbox.validate` | local launch behavior |
| `sandbox.scratch_dir` | local temp handling |
| `sandbox.brief` | local agent-context preference |
| `sandbox.agents_md` | a repo must not be able to make cplt write into its own `AGENTS.md` |
| `sandbox.use_bubblewrap` | depends on bwrap being installed on the machine |
| `sandbox.audit` | local output preference, not project sandbox policy |
| `sandbox.gradle_init` | writes to the machine's Gradle user home, not project policy |
| `sandbox.inherit_env` | too dangerous for repo config, it would affect every team member |
| `allow.exec` | exec paths differ per machine, and a repo must not be able to make one of its own trees executable |
| `sandbox.allow_cache_exec` | cache paths differ per machine |
| `sandbox.allow_cache_exec_any` | too broad for repo policy |
| `proxy.enabled` | local proxy preference |
| `proxy.forced` | forcing all egress through the proxy is a local security preference, not project policy |
| `proxy.port` | port conflicts are machine-specific |
| `proxy.log_file` | local log path |
| `proxy.log_level` | local verbosity preference |
| `proxy.timeout` | local network condition preference |
| `proxy.blocked_domains` | local path to a blocklist file |
| `proxy.allowed_domains` | local path to an allowlist file |
| `proxy.default_allowlist` | proxy settings are machine-specific, not project policy |
| `proxy.upstream` | the corporate proxy is machine-specific and network-specific |
| `proxy.upstream_no_proxy` | same, and it only means anything alongside `proxy.upstream` |
| all `[proxy.subscriptions]` keys | subscription sources are security-sensitive, and a repo must not be able to add one |
| all `[gh_guard]` keys | guard policy is configured globally, not per-repo |
| all `[git_guard]` keys | guard policy is configured globally, not per-repo |

### Removing values

```bash
cplt config set allow.read ~/Desktop --unset     # remove one element
cplt config set allow.read --unset               # remove entire key
cplt config set sandbox.quiet --unset            # revert to default
```

### Inspecting config

```bash
cplt config show                          # show effective config (file + defaults)
cplt config get sandbox.quiet             # get a single value
cplt config explain                       # list all keys with descriptions
cplt config explain sandbox.pass_env      # explain a specific key
cplt config validate                      # check for syntax errors and unknown keys
```

## Configuration file

The config file lives at `~/.config/cplt/config.toml`. `cplt config init` writes a commented starter template there. It covers `[proxy]`, `[proxy.subscriptions]`, `[allow]`, `[deny]`, `[sandbox]`, `[gh_guard]`, and `[git_guard]`, with every key commented out and documented inline, so a fresh file changes nothing until you uncomment something. Run it and read the result rather than copying a snippet from here, since the template is generated from `src/config/path.rs` and moves with the code:

```bash
cplt config init
cplt config explain            # every key, its type, default, and what it does
cplt config explain proxy.forced
```

For arrays of objects, multi-line values, and other complex configuration, edit the file directly and run `cplt config validate` afterwards.

**Dotted keys:** a dotted key belongs to whatever section header precedes it. `allow.read = [...]` is valid on its own — above every header, or written as `read = [...]` under `[allow]` — but the same line below `[git_guard]` means `git_guard.allow.read`. cplt then sees an unknown key and ignores it, with a warning at launch and an error from `cplt config validate`, so the grant never takes effect.

## Agent sandbox brief (`sandbox.brief`, `sandbox.agents_md`) — EXPERIMENTAL

> **EXPERIMENTAL.** Both keys, and the `--brief` / `--no-brief` /
> `--agents-md` / `--no-agents-md` flags, are
> unstable: their names, defaults and output are not covered by any stability
> guarantee and may change or be removed in a future release. Don't build
> tooling on the brief's wording or on the AGENTS.md block's markers.

An agent inside the sandbox has no way of knowing it is sandboxed: it hits
`EPERM`, assumes a bug, and retries. cplt can hand it the answer up front, in
two layers. Both are off by default — cplt writing files that an agent then
reads is a behaviour change, so you ask for it. Running `cplt check` from
outside the sandbox reports the same policy either way, and is what to reach
for when you have not opted in.

**`sandbox.brief` (default `false`)** — writes two files into the per-session
scratch directory (the one `$TMPDIR` points at inside the sandbox):

| File | For | Named by |
| --- | --- | --- |
| `CPLT_BRIEF.md` | the agent to read | `$CPLT_BRIEF` |
| `CPLT_BRIEF.json` | a tool to parse | `$CPLT_BRIEF_JSON` |

Both are rendered from the resolved policy for *that* launch — the repositories
in scope, network mode, `.env` handling, credential denies — and disappear with
the scratch dir when the session ends. Neither touches your project.

The two environment variables are set only when the files exist, so an agent can
test for `$CPLT_BRIEF` rather than guessing a path, and a variable never names a
file that is not there. That means neither is set with `sandbox.brief = false`,
and neither is set with `--no-scratch-dir` (or `sandbox.scratch_dir = false`)
either: the brief lives in the scratch dir and nowhere else, so cplt warns and
writes nothing.

The JSON carries a little more than the prose: the `allow.read` / `allow.write`
/ `allow.exec` path lists, the port numbers, and every repository in scope even
for a single-repository session, where the prose omits the section because it
would restate what the rest of the brief assumes. Both come from one captured
set of facts, so they cannot describe different sessions.

Turn it on for one run with `--brief`, or for good with
`cplt config set sandbox.brief true`.

There is nothing about the brief that only works for some projects, so if you
want your agents to have it, turn it on in your global config. Turning it on is
also what makes the `## Repositories` section reach the agent: the list of what
a multi-repository session actually spans exists only here.

**`sandbox.agents_md` (default `false`)** — additionally injects a managed
block into `<project>/AGENTS.md`, creating the file if it does not exist. This
writes into your repository, so it is a second opt-in on top of the first:

- The block is delimited by `<!-- cplt:sandbox begin -->` /
  `<!-- cplt:sandbox end -->` markers. Re-runs replace it in place; content
  outside the markers is never touched.
- It contains no policy detail from your machine — the same generic text for
  every repo, safe to commit.
- It is written only on an actual agent launch, after the confirmation prompt.
  `--print-profile`, `cplt check`, `cplt exec` and a declined prompt leave the
  repo untouched.
- Skipped outside a git work tree, and skipped with a warning if the file
  somehow ends up with more than one marker pair.
- It requires `sandbox.brief` as well. With the brief off — the default — the
  AGENTS.md block is never written, whatever `agents_md` says.

Turn both on for one run, or globally:

```bash
cplt --brief --agents-md            # this launch only
cplt config set sandbox.brief true  # every launch
cplt config set sandbox.agents_md true
```

And back off again for a single run, without editing the config:

```bash
cplt --no-brief       # no CPLT_BRIEF.md, and no AGENTS.md block either
cplt --no-agents-md   # keep the brief, leave the repository alone
```

The flag always beats the config key, in both directions. `--no-brief` covers
both layers because the AGENTS.md block is gated on the brief.

Both are global-only keys — a repository cannot ask cplt to write into its own
`AGENTS.md`.

## Per-repo configuration (`.cplt.toml`)

### Keys this cplt does not know

A `.cplt.toml` may use keys a newer cplt understands. They are **ignored and
reported**, not treated as errors, so a repository can adopt a key before every
developer has upgraded:

```
[cplt] .cplt.toml uses a key this version of cplt does not understand
       (propose.allow_future_thing), and it is ignored. That is usually a newer
       cplt writing the file than the one reading it: upgrade, or check the
       spelling if you wrote them by hand.
```

The two sections fail in opposite directions, and the warning says which:

- An unknown key under `[propose]` grants nothing, so ignoring it **fails
  closed**. This is also why a repository cannot smuggle in a key like `preset`
  that a future version might honour: an unknown key does nothing here.
- An unknown key under `[deny]` is a restriction its author expected and this
  version will not apply. The warning calls that out explicitly, because
  nothing else in the session will mention it.

Everything the version *does* understand still applies. Before this, one unknown
key failed the whole parse — the launch repository lost its `[deny]` along with
it, and a named repository stopped the launch.

Malformed TOML is a different thing and still an error: it is not version skew,
and there is nothing to salvage from it.

An unknown key does not invalidate an existing trust approval, because it
proposes nothing. When you upgrade and the key becomes real, it starts counting
towards the approval hash and you are asked to review it — approval tracks what
the file can actually do on your machine.

Commit a `.cplt.toml` to your repository for project-specific sandbox settings, so every developer does not have to configure the same CLI flags or global config. Global config stays the default, so pass `--repo` explicitly for project settings:

```bash
# Request sandbox permissions (requires approval via `cplt trust accept`)
cplt config set --repo sandbox.allow_jvm_attach true
cplt config set --repo sandbox.allow_localhost_any true
cplt config set --repo allow.read "~/.gradle/gradle.properties"
cplt config set --repo allow.ports 8080

# Deny section: tightens security, applied immediately without approval
cplt config set --repo deny.paths "~/secrets"
cplt config set --repo deny.env "VAULT_TOKEN"

# Remove a permission request
cplt config set --repo sandbox.allow_jvm_attach --unset
```

Settings map to sections automatically. Permission requests go under `[propose]`, restrictions under `[deny]`. Machine-specific keys such as `sandbox.quiet` and `proxy.port` are rejected with a clear explanation.

### Security model

- `[deny]` applies automatically and needs no approval, because it can only tighten the sandbox.
- `[propose]` holds requested permissions and requires explicit approval via `cplt trust accept`. Approvals are additive: they can enable a feature such as `allow_docker = true`, never disable something CLI or global config set.
- cplt reads the file from `git HEAD`, the committed state, so the agent cannot tamper with its own config mid-session.
- An **uncommitted** `.cplt.toml` — untracked, gitignored, or edited but not committed — grants nothing, on both platforms, and the launch says so. Its `[deny]` keys still apply, and so does a `[propose]` key that only tightens (`gh_guard = true`, `git_push_prevention = true`), because those are `[deny]`-shaped and need no approval anywhere. A restriction needs no audit trail, and dropping it would remove something its author believed was in force; a relaxation needs one, and the commit is it. `--accept-repo-config` does not change this: it skips the prompt, not the commit.
- Writing `.cplt.toml` is kernel-denied inside the sandbox.
- Trust approvals are content-pinned. If the requested values change, the approvals are invalidated.

Paths in `[deny]` and `[propose.allow]` support `~/` expansion. A relative path resolves against the repository root, the directory the `.cplt.toml` came from, which under `--project-dir <subdir>` is still the git root rather than the subdir. So `paths = ["secrets"]` denies `<repo>/secrets` on every clone.

`./secrets`, `secrets/.`, `secrets/`, and `a//b` all normalize to the same path, and symlinks resolve to their target. The sandbox matches resolved paths, so the un-normalized spellings would compile into the profile and silently match nothing. Resolution walks up to the deepest part of the path that exists, so a symlink still resolves when the leaf below it does not exist yet: `link/secret` with `link -> real` becomes `<repo>/real/secret`.

`..` components are rejected, as are entries naming a whole tree root: `""`, `"."`, `"./"` (the repo root) and `"/"` (the filesystem root). As a deny entry, any of those would block read and write of the entire checkout, so a committed one would brick the repo for everyone who clones it.

Approved `[propose.allow]` paths must stay inside the repo. A trust approval pins a hash of the `.cplt.toml` bytes, so it only vouches for what those bytes name. A relative entry names a location in the repo. If a symlink resolves it somewhere outside, the entry is refused with a warning rather than granted. Otherwise a repo could get `read = ["data"]` approved while `data -> ./safe`, then repoint `data -> /` in a later commit with `.cplt.toml` unchanged, hash unchanged, and the approval still live. Absolute and `~/` entries are exempt, because they are written literally in the file and the pinned hash does cover them. `[deny]` has no such restriction, since it needs no approval and can only tighten.

Unlike global config, a repo path that does not exist yet is kept rather than treated as an error. macOS starts enforcing the deny once the directory appears, and one committed typo cannot brick cplt for everyone who clones the repo. On Linux such a path cannot be masked, and cplt warns.

### Example `.cplt.toml`

```toml
# Deny section: applied automatically, no approval needed
[deny]
paths = ["~/secrets", "~/.vault"]
env = ["VAULT_TOKEN", "MY_SECRET"]

# Requested permissions: requires approval via `cplt trust accept`
[propose]
allow_jvm_attach = true          # For MockK/Mockito tests
allow_docker = true              # Container access
allow_localhost_any = true       # Dev servers on any port

[propose.allow]
read = ["~/.gradle/gradle.properties"]
ports = [8080, 5432]
localhost = [5432]

[propose.proxy]
allow_private_domains = ["intern.nav.no"]
```

### Trust management

```bash
cplt trust                                # Show permissions and approval status
cplt trust accept allow_jvm_attach        # Approve specific keys
cplt trust accept --all                   # Approve everything
cplt trust revoke allow_docker            # Revoke a specific key
cplt trust revoke --all                   # Revoke all trust for this repo
```

Trust decisions live in `~/.config/cplt/trust/`, protected from the sandbox.

In CI and scripts, where interactive approval is not possible:

```bash
cplt --accept-repo-config -- -p "run tests"
```

### Auto-generate with `cplt init`

Instead of writing `.cplt.toml` by hand, let cplt detect your project's ecosystem:

```bash
cplt init                   # Preview detected permissions
cplt init --write           # Write .cplt.toml to disk
cplt init --write --force   # Overwrite existing file
cplt init --quiet           # Output only TOML (pipe-friendly)
```

Supported ecosystems:

| Ecosystem | Detected via | Suggests |
|-----------|-------------|----------|
| JVM (Gradle/Maven) | `build.gradle*`, `pom.xml` | `allow_jvm_attach`, read gradle properties |
| Node.js | `package.json` | localhost ports, `allow_localhost_any` (for Next.js/Vite) |
| Docker | `Dockerfile`, `compose.yml` | `allow_docker` (dangerous), exposed ports |
| Python | `pyproject.toml`, `requirements.txt` | localhost ports (for Django/FastAPI) |
| Rust | `Cargo.toml` | (works with defaults) |
| Go | `go.mod` | (works with defaults) |
| Playwright | `@playwright/test` or `"playwright"` in package.json | `allow_cache_exec` (personal config hint) |
| Environment secrets | `.env.example` | `deny.env` for sensitive variables |
| Spring Boot | `application.yml` + Spring in Gradle | localhost 8080, PostgreSQL port |
| Ktor | `application.conf` + Ktor in Gradle | localhost 8080 |
| TestContainers | `testcontainers` in Gradle deps | `allow_docker` (dangerous), `allow_localhost_any` |
| Next.js | `next.config.ts/js/mjs` | localhost 3000, `allow_localhost_any` |
| Vite | `vite.config.ts/js/mjs` | localhost 5173, `allow_localhost_any` |
| Flyway | `src/main/resources/db/migration` or `.../migrations` | PostgreSQL port 5432 |
| Cypress | `cypress.config.ts/js/mjs` + `cypress/` dir | `allow_localhost_any` |

Machine-specific suggestions such as `allow_cache_exec` or home-relative read paths come out as comments pointing you to add them to your personal `~/.config/cplt/config.toml`.

The Playwright suggestion enables cache execution and, with it, turns off Chromium's nested sandbox, which cannot run inside cplt. Playwright MCP is handled through `PLAYWRIGHT_MCP_SANDBOX`; any other Chromium launcher needs `--no-sandbox` itself. See [Known impacts](known-impacts.md#cache-exec-playwright-pnpm-dlx-etc).

Permissions marked dangerous above get risk warnings in the generated TOML. `allow_lifecycle_scripts` is never auto-suggested. If lifecycle scripts are detected it only shows up as a diagnostic, because it allows arbitrary code execution on `npm install`.

#### Personal config with `cplt init --global`

Scan your machine for installed tools and generate `~/.config/cplt/config.toml`:

```bash
cplt init --global          # Preview personal config suggestions
cplt init --global --write  # Write to ~/.config/cplt/config.toml
```

It detects:

| Tool | Probes | Suggests |
|------|--------|----------|
| Playwright browsers | `~/Library/Caches/ms-playwright/` (macOS) or `~/.cache/ms-playwright/` (Linux) | `allow_cache_exec = ["ms-playwright"]` |
| GPG signing | `~/.gnupg/`, plus `commit.gpgsign` from global git config for the reason text | `allow_gpg_signing = true` |
| Gradle registry credentials | `~/.gradle/gradle.properties` mentioning `repository`, `nexus`, or `artifactory` | `allow.read` for that file |
| npm registry credentials | `~/.npmrc` with a `registry` or `_authToken` line | `allow.read` for that file |
| Maven repository settings | `~/.m2/settings.xml` with a `<server>`, `<mirror>`, or `<repository>` | `allow.read` for that file |
| Default agent | `copilot`, `opencode`, `aider`, `antigravity`, `claude` in PATH | `agent = "..."`, but only when exactly one is found and it is not `copilot` |
