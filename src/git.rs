//! Hardened `git` invocation for the **parent** process (issue #210).
//!
//! # Why this module exists
//!
//! cplt runs `git` in the parent — outside the sandbox — with the working
//! directory set to the project being sandboxed: the post-session audit
//! ([`crate::audit`]), the repo-config trust decision ([`crate::repo_config`]),
//! trust identity ([`crate::trust`]), and sandbox path discovery
//! ([`crate::discover`], [`crate::detect`]) all do it.
//!
//! `git` run inside a repository honours **that repository's** configuration,
//! and several config keys name a program git then executes. `.git/config` is
//! inside the project directory, so a sandboxed agent can write it; a
//! prompt-injected agent that appends
//!
//! ```text
//! [core]
//!     fsmonitor = /path/to/payload
//! ```
//!
//! makes the *next* parent-side `git status` execute `payload` **unsandboxed**.
//! That is a straight sandbox escape, and for [`crate::repo_config`] it is
//! worse still: those invocations are the input to the trust decision.
//!
//! The repository's config is not the only thing an agent can aim at these
//! invocations. The *binary* is the other one: any program looked up by name is
//! resolved from the parent's `PATH` at spawn time, after the agent has
//! finished writing to directories that are on it. [`TRUSTED_BIN_DIRS`] and
//! [`trusted_binary`] are the answer, and are used for every parent-side spawn
//! in cplt, not only git's — this module is where the reasoning lives, so it is
//! where they live. [`TRUSTED_BIN_DIRS`] also spells out what that does not fix.
//!
//! # What is actually reachable
//!
//! Measured against git 2.55 for exactly the subcommands cplt runs
//! (`rev-parse`, `cat-file`, `config`, `remote`, `status --porcelain`,
//! `diff --numstat`, `diff --quiet`):
//!
//! | key | executed by | handled by |
//! |---|---|---|
//! | `core.fsmonitor` | `status`, `diff` | `-c core.fsmonitor=false` |
//! | `diff.<d>.textconv` | `diff --quiet` (via `.gitattributes`) | `--no-textconv` |
//! | `filter.<f>.clean` | `status`, `diff` (via `.gitattributes`) | refuse — see below |
//! | `filter.<f>.process` | `status`, `diff` (via `.gitattributes`) | refuse — see below |
//!
//! Not reachable by any subcommand cplt runs, but overridden anyway because the
//! cost is nil and the next subcommand someone adds must not reopen the hole:
//! `core.hooksPath`, `core.pager`, `core.editor`, `sequence.editor`,
//! `core.sshCommand`, `core.gitProxy`, `core.alternateRefsCommand`,
//! `credential.helper`, `uploadpack.packObjectsHook`, `gpg.program`.
//!
//! Confirmed *not* a vector: `alias.*` (git refuses to let an alias shadow a
//! builtin, and every subcommand cplt runs is a builtin), `filter.<f>.smudge`
//! (checkout only), `merge.<m>.driver` (merge only), `diff.<d>.command`
//! (external diff, ignored by `--numstat` and `--quiet`).
//!
//! # The one thing `-c` cannot fix
//!
//! Content filters are named by an arbitrary subsection (`filter.<anything>`),
//! so no fixed `-c` override neutralizes them. Setting the discovered ones to
//! empty *would* stop the execution, but it would also make git compare raw
//! working-tree bytes against a filtered blob — in an LFS or git-crypt repo
//! every filtered file would then read as modified, and the audit would report
//! changes that never happened. Silently wrong is worse than incomplete, so
//! this module **refuses** any subcommand that reads working-tree content when
//! the repository's own config defines a content filter. Callers already handle
//! that failure as a failed git call.
//!
//! Only `local`- and `worktree`-scope config counts as repository-controlled.
//! A filter installed in the user's `--global` config (what `git lfs install`
//! writes by default) is the *user's* choice, not the repo's, and does not
//! trigger the refusal.
//!
//! # What the refusal actually costs
//!
//! Narrower than it first looks, because the paths that *apply* a repo config
//! are all content-free and are never refused:
//!
//! - **`.cplt.toml` still applies.** [`crate::repo_config::load_repo_config`]
//!   reads it with `git cat-file blob HEAD:.cplt.toml` — the object store, not
//!   the working tree — and resolves the repo root with `rev-parse`. Neither
//!   can reach a filter, so a committed config keeps taking effect and already
//!   accepted permissions keep applying.
//! - **The audit degrades** to [`crate::audit::AuditReport::Incomplete`].
//! - **The drift state degrades.** `repo_config::repo_config_state` answers
//!   `Committed` vs `Drifted` with `git diff --quiet`, which is refused, so a
//!   modified-looking `Drifted` is reported. That is only a message in most
//!   places, but `cplt trust accept` approves nothing but `Committed`, so the
//!   one-time interactive accept is blocked in such a repo — with an error the
//!   user sees, naming drift rather than the real reason.
//!
//! # Accepted, not overlooked
//!
//! An agent inside the sandbox can force the audit to `Incomplete` at will by
//! writing `filter.x.clean` into the writable `.git/config`. That is inherent
//! to failing closed: the only way to answer the query instead is to execute
//! the filter, which is the escape this module exists to prevent. `Incomplete`
//! is a loud "could not verify", never a forged clean session, so denial of the
//! *report* is the correct trade against execution of the *payload*.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// Absolute directories a parent-side binary may be resolved from.
///
/// `Command::new("git")` resolves through `execvp` **at spawn time**, using the
/// *parent's* `PATH`. cplt spawns binaries in the parent both after the agent
/// has exited (`audit::Baseline::finish`) and before the next one starts (the
/// gh-guard scope check, the bwrap probe). The sandbox grants write **and**
/// exec to several directories that are on a developer's `PATH` (mise shims,
/// `PNPM_HOME`, `~/.deno/bin`, `~/.bun/bin` — see
/// `sandbox_policy::HOME_TOOL_DIRS` and `APP_DIRS`), so an agent can drop a file
/// named `git` (or `bwrap`, or `mise`) into one of them and have the parent
/// execute it unsandboxed — at the end of this session, or at the start of the
/// next one.
///
/// Every entry is a directory the sandbox exposes **read-only**
/// (`sandbox_policy::TOOL_READ_DIRS` on macOS,
/// `sandbox_landlock::LINUX_TOOL_DIRS` on Linux), so nothing inside the sandbox
/// can write to it — an invariant `sandbox.rs`'s
/// `every_trusted_dir_is_covered_by_a_tool_read_grant` enforces. `/usr/bin`
/// first: it
/// is the only one that is SIP-protected on macOS and root-owned on Linux.
///
/// # What this does not fix
///
/// This closes the "attacker prepends a directory that wins `PATH` resolution"
/// half of the problem, and nothing more. If the user's own `git` lives in an
/// agent-writable tree that also happens to be one of these directories — a
/// Homebrew prefix owned by the user, say, that a `sandbox.allow.write` grant
/// opened up — then resolving to a fixed absolute path still finds the
/// trojaned file. Nor does it cover the agent binary itself, which cplt spawns
/// from wherever it was discovered (commonly an npm global under a mise node
/// install, i.e. a writable+exec tree). Making the whole class safe means not
/// granting write to directories that also carry exec, which is a separate
/// decision.
pub const TRUSTED_BIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    // NixOS: the activated system profile, root-owned and read-only granted.
    // Without it a NixOS user has no trusted git at all, which costs more than
    // the audit — `repo_config::load_repo_config` reads `.cplt.toml` with
    // `git cat-file` and reports "no repo config" when git cannot run.
    "/run/current-system/sw/bin",
    // Homebrew on Linux; same trust level as /opt/homebrew/bin.
    "/home/linuxbrew/.linuxbrew/bin",
];

/// An existing regular file that **this process** may execute.
///
/// `which` and `execvp` both require `X_OK` for the calling user, so mode bits
/// alone are the wrong question: a root-owned `0700` `git` has an execute bit
/// set, yet every spawn of it fails with `EACCES` — and accepting it here would
/// shadow a genuinely executable `git` later in [`TRUSTED_BIN_DIRS`], which is
/// the failure mode this predicate exists to prevent. `faccessat` with
/// `AT_EACCESS` asks the kernel the same question the spawn will, owner, group,
/// supplementary groups, other and any ACL included.
///
/// This is a shadowing filter, not a security guarantee. The answer describes
/// the file as it was at this instant; it can be replaced, chmod'ed or
/// unmounted before the spawn (TOCTOU), and nothing here proves the file is
/// the binary it claims to be. Trust comes from the directory being read-only
/// to the sandbox — see [`TRUSTED_BIN_DIRS`] — never from this call.
pub(crate) fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    // `X_OK` on its own would also accept a *searchable directory*, so the
    // regular-file check stays. It runs first: it is the cheap rejection.
    if !std::fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return false;
    }
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false; // An interior NUL cannot name a real file.
    };
    // SAFETY: `c_path` is a valid NUL-terminated C string that outlives the call.
    unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            libc::X_OK,
            libc::AT_EACCESS,
        ) == 0
    }
}

/// Read-only prefixes a trusted binary is allowed to **resolve into**.
///
/// [`TRUSTED_BIN_DIRS`] constrains the *path*, which is not the same thing as
/// the file. `/usr/local/bin/git` and `/opt/homebrew/bin/git` are symlinks on
/// every Homebrew install, and on Homebrew-for-Intel `/usr/local` is owned by
/// the invoking user — so the link can point anywhere, including into a
/// directory the sandbox grants **write** to. Checking only the path would call
/// that trusted and hand the agent the unsandboxed exec this module exists to
/// prevent.
///
/// Rejecting symlinks outright is not the answer: the legitimate targets are
/// real (`/opt/homebrew/bin/git` → `/opt/homebrew/Cellar/git/*/bin/git`,
/// `/run/current-system/sw/bin/git` → `/nix/store/*/bin/git`, `/bin` → `/usr/bin`
/// on a usrmerge distro, Debian's `/etc/alternatives` hop landing back in
/// `/usr/bin`), and refusing them would leave most installs with no trusted git
/// at all. So the target is checked against the *containing* read-only prefixes
/// rather than [`TRUSTED_BIN_DIRS`] itself.
///
/// Every entry is a prefix the sandbox never grants write to: the macOS
/// `sandbox_policy::TOOL_READ_DIRS` and Linux `sandbox_landlock::LINUX_TOOL_DIRS`
/// read-only tool grants, plus the Nix store (root-owned and mounted read-only,
/// and never named by any cplt write grant).
///
/// Only the *final* target is checked, not every hop. A chain whose middle link
/// sits in an agent-writable directory would still pass — but arranging that
/// means the user's own `git` already routes through an agent-writable path,
/// which no supported install does.
pub(crate) const TRUSTED_BIN_ROOTS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/local",
    "/opt/homebrew",
    "/run/current-system",
    "/nix/store",
    "/snap",
    "/home/linuxbrew/.linuxbrew",
];

/// Does `path` resolve to a file under one of `roots`?
///
/// Both sides are canonicalized: the roots because several are themselves
/// symlinks (`/run/current-system` into the Nix store, `/var` into `/private/var`
/// on macOS), and a textual prefix test against an unresolved root answers the
/// wrong question.
fn resolves_into(path: &Path, roots: &[&str]) -> bool {
    let Ok(target) = std::fs::canonicalize(path) else {
        return false;
    };
    roots
        .iter()
        .filter_map(|r| std::fs::canonicalize(r).ok())
        .any(|root| target.starts_with(root))
}

/// First executable `name` found in `dirs` that resolves into `roots`. Split out
/// of [`trusted_binary`] so the not-found path is testable without depending on
/// the host's `/usr/bin`.
///
/// `name` must be a single normal path component. `Path::join` drops the base
/// entirely for an absolute `name` and happily walks out of it for `../x`, so
/// without this check `trusted_binary` could return a path outside
/// [`TRUSTED_BIN_DIRS`] — the one guarantee it exists to make.
///
/// A candidate whose target escapes `roots` is skipped like a non-executable
/// shadow, not fatal: the search goes on to the next directory, so a repointed
/// `/usr/local/bin/git` still lets a genuine `/opt/homebrew/bin/git` win.
fn find_in(dirs: &[&str], roots: &[&str], name: &str) -> Option<PathBuf> {
    let mut parts = Path::new(name).components();
    if !matches!(parts.next(), Some(std::path::Component::Normal(_))) || parts.next().is_some() {
        return None;
    }
    dirs.iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|p| is_executable_file(p) && resolves_into(p, roots))
}

/// Resolve `name` from [`TRUSTED_BIN_DIRS`], never from `PATH`, and only when
/// it resolves into [`TRUSTED_BIN_ROOTS`].
///
/// For every parent-side spawn. `None` means "not installed anywhere the agent
/// cannot reach"; callers degrade as they already do when the tool is missing.
/// Deliberately no `PATH` fallback: a fallback would restore the exact lookup
/// this exists to remove, and would do so precisely on the machines where the
/// attacker's directory is the only match.
pub(crate) fn trusted_binary(name: &str) -> Option<PathBuf> {
    find_in(TRUSTED_BIN_DIRS, TRUSTED_BIN_ROOTS, name)
}

/// The `git` binary, resolved once from [`TRUSTED_BIN_DIRS`].
///
/// Resolved once per process so a directory that appears *during* a session
/// cannot change the answer between two calls, and so the warning below is
/// emitted at most once.
///
/// `None` when no trusted `git` exists. Callers then degrade exactly as they do
/// when git is missing: `Baseline::capture` records no baseline and no
/// untracked set, and the report is `AuditReport::Unavailable` ("change audit
/// unavailable"). Never a clean bill of health — but note it is `Unavailable`,
/// not `Incomplete`, because both capture queries fail together.
pub(crate) fn trusted_git() -> Option<&'static Path> {
    static GIT: OnceLock<Option<PathBuf>> = OnceLock::new();
    GIT.get_or_init(|| {
        let found = trusted_binary("git");
        if found.is_none() {
            crate::ui::warn(&format!(
                "no git found in {} — parent-side git queries (audit, repo config \
                 trust, gh guard scope) are skipped rather than resolved through \
                 PATH, which a sandboxed agent can write to. The git-persistence \
                 denies still cover <root>/.git for every writable root; a bare \
                 repository's gitdir cannot be resolved without git and loses them",
                TRUSTED_BIN_DIRS.join(", ")
            ));
        }
        found
    })
    .as_deref()
}

/// `-c key=value` overrides prepended to every parent-side git invocation.
///
/// `-c` beats every config file, so a repository cannot win against this table
/// no matter what it writes into `.git/config`. Each entry names a config key
/// whose value git may **execute**, and which no parent-side cplt invocation
/// legitimately needs.
///
/// The third column is the cost of the override — reviewed per entry, because
/// blanket-applying every hardening flag git offers would break legitimate
/// behaviour (see `GIT_CONFIG_GLOBAL` in [`harden`] for one cplt actually
/// depends on).
pub const CONFIG_OVERRIDES: &[(&str, &str, &str)] = &[
    (
        "core.fsmonitor",
        "false",
        "REACHABLE: run by status/diff. Cost: cplt's own status/diff lose the \
         fsmonitor fast path on a large repo; results are byte-identical.",
    ),
    (
        "core.hooksPath",
        "/dev/null",
        "Hooks are the canonical repo-controlled exec vector and .git/hooks is \
         agent-writable. No subcommand cplt runs triggers a hook. Cost: none \
         today; a future parent-side commit/gc would silently skip hooks.",
    ),
    (
        "core.pager",
        "cat",
        "Every caller pipes stdout, so no pager runs today. Cost: none.",
    ),
    (
        "core.editor",
        "false",
        "No parent-side subcommand is interactive. Cost: none.",
    ),
    (
        "sequence.editor",
        "false",
        "Rebase/sequencer only. Cost: none.",
    ),
    (
        "core.sshCommand",
        "",
        "Empty restores git's default ssh. The parent runs no transport \
         command. Cost: none.",
    ),
    ("core.gitProxy", "", "Transport only. Cost: none."),
    (
        "core.alternateRefsCommand",
        "",
        "Alternates enumeration only. Cost: none.",
    ),
    (
        "credential.helper",
        "",
        "Empty resets the helper list. The parent authenticates nothing. \
         Cost: none.",
    ),
    (
        "uploadpack.packObjectsHook",
        "",
        "Server side only. Cost: none.",
    ),
    (
        "gpg.program",
        "false",
        "The parent verifies no signatures. Cost: none. NOTE detect.rs reads \
         commit.gpgsign, which is a config read, not a gpg invocation.",
    ),
];

/// Global flags that take their value as a **separate** token, and are therefore
/// refused outright.
///
/// [`subcommand`] finds the subcommand as the first argument without a leading
/// `-`. With `-C dir diff` it would return `dir`, and [`insert_diff_flags`]
/// would then add no `--no-textconv` / `--no-ext-diff` — hardening silently
/// absent. The refusal still fails closed (an unrecognised token is treated as
/// content-reading), and no cplt call site passes these, so forbidding them is
/// cheaper and more fail-closed than teaching the parser to consume values.
/// `-c` is refused for the same reason plus a second one: config overrides
/// belong in [`CONFIG_OVERRIDES`], where they are reviewed, not at call sites.
const VALUE_TAKING_GLOBALS: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    // Both take a separate-token value in git 2.55. `--attr-source evil diff`
    // would make `subcommand()` return "evil", silently skipping the diff-flag
    // insertion — the exact mis-parse this refusal exists to prevent. And
    // `--config-env` can override CONFIG_OVERRIDES, since later config
    // parameters win.
    "--config-env",
    "--attr-source",
];

/// Subcommands that provably never read working-tree file **content**, and so
/// can never reach a `.gitattributes` filter or diff driver.
///
/// Everything not on this list is treated as content-reading and gated by
/// [`repo_defines_content_filter`]. The list is an allowlist on purpose: adding
/// a new subcommand fails closed rather than silently inheriting an exemption.
const CONTENT_FREE_SUBCOMMANDS: &[&str] = &["rev-parse", "cat-file", "config", "remote"];

/// Inherited environment variables that would undo [`CONFIG_OVERRIDES`] or
/// retarget the query, cleared from every parent-side invocation.
///
/// `GIT_*` is swept wholesale in [`harden`] as well; this named list exists so
/// the clearing is recorded on the `Command` even when the variable is absent
/// from the current environment, which is what makes it testable.
const GIT_ENV_CLEARED: &[&str] = &[
    // Retarget which repository is queried.
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_CEILING_DIRECTORIES",
    // Re-inject config, and therefore re-inject the executable keys.
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
    // Name a program directly, bypassing the config layer entirely.
    "GIT_EXTERNAL_DIFF",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_PAGER",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "GIT_ASKPASS",
    "GIT_PROXY_COMMAND",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_ATTR_SOURCE",
];

/// Environment applied to every parent-side git invocation.
///
/// Deliberately **not** set here: `GIT_CONFIG_GLOBAL=/dev/null`. cplt reads the
/// user's global config on purpose — `discover::git_hooks_path` reads
/// `core.hooksPath` and `detect` reads `commit.gpgsign`, both to decide what the
/// sandbox must allow. Blanking global config would silently break sandbox path
/// detection for every hooks user, and buys nothing: the threat is the
/// *repository's* config, not the user's.
fn harden(cmd: &mut Command) {
    // Cleared unconditionally, so the removal is recorded on the Command (and
    // therefore assertable) whether or not the variable happens to be set.
    for name in GIT_ENV_CLEARED {
        cmd.env_remove(name);
    }
    // Catch-all sweep for the rest of the GIT_* namespace. Same reasoning as
    // `gh_proxy::detect_current_repo`, which already does this.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(key);
        }
    }
    cmd
        // Skip /etc/gitconfig. Matches the sandboxed child's hardening
        // (`sandbox_policy::HARDENING_ENV_VARS`). Cost: a site-wide
        // /etc/gitconfig is ignored for cplt's own queries.
        .env("GIT_CONFIG_NOSYSTEM", "1")
        // Skip /etc/gitattributes, which can name diff/filter drivers.
        .env("GIT_ATTR_NOSYSTEM", "1")
        // Never block on a credential prompt — the parent has no business
        // prompting, and a hung git would hang cplt.
        .env("GIT_TERMINAL_PROMPT", "0")
        // Generalizes the `--no-optional-locks` that audit.rs passed by hand to
        // every site: read-only queries never take the index lock.
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null());
    for (key, value, _) in CONFIG_OVERRIDES {
        cmd.arg("-c").arg(format!("{key}={value}"));
    }
}

/// The tokens **before** the subcommand — the only position a git global flag
/// can occupy.
///
/// Position matters: `--git-dir` is a global flag *and* a `rev-parse` query
/// (`rev-parse --git-dir`, which cplt runs), and `-C` is a global flag *and* a
/// `diff` copy-detection flag. Scanning the whole argument list would refuse
/// both legitimate uses.
fn leading_globals<'a, 'b>(args: &'a [&'b str]) -> &'a [&'b str] {
    match args.iter().position(|a| !a.starts_with('-')) {
        Some(i) => &args[..i],
        None => args,
    }
}

/// The subcommand in `args` — the first argument that is not a global flag.
fn subcommand<'a>(args: &[&'a str]) -> Option<&'a str> {
    args.iter()
        .find(|a| !a.starts_with('-'))
        .copied()
        // `-c key=value` and `--git-dir=x` take their value in the same token,
        // so a leading `-` is enough to skip them. `-C <dir>` is not used by
        // any cplt call site; if it ever is, the value would be misread as the
        // subcommand and fail closed (treated as content-reading).
        .filter(|s| !s.is_empty())
}

/// True when the subcommand may read working-tree file content, and therefore
/// may run a `.gitattributes`-selected filter or diff driver.
fn reads_worktree_content(args: &[&str]) -> bool {
    match subcommand(args) {
        Some(sub) => !CONTENT_FREE_SUBCOMMANDS.contains(&sub),
        // No subcommand at all (`git --version`): nothing to read. Still
        // treated as content-reading — fail closed, cost is one config read.
        None => true,
    }
}

/// Insert `--no-textconv --no-ext-diff` **immediately after** a `diff`
/// subcommand.
///
/// `git diff` resolves `diff.<driver>.textconv` and `diff.<driver>.command`
/// through `.gitattributes`. Neither has a fixed key name, so these flags are
/// the only handle. Cost of `--no-textconv`: a binary file with a textconv
/// driver is counted as binary (rendered `(binary)` in the audit) rather than
/// as converted text lines — the file is still reported as changed.
///
/// Position is load-bearing: appending them would put them after any `--`
/// pathspec separator, where git reads them as **pathspecs** and silently
/// applies no hardening at all.
fn insert_diff_flags<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::with_capacity(args.len() + 2);
    let mut inserted = false;
    for arg in args {
        out.push(arg);
        if !inserted && *arg == "diff" && subcommand(args) == Some("diff") {
            out.push("--no-textconv");
            out.push("--no-ext-diff");
            inserted = true;
        }
    }
    out
}

/// Build a hardened `git` command for `project_dir`.
///
/// Returns `None` when the repository's own config defines a content filter and
/// `args` names a subcommand that would run it. Every parent-side git call in
/// cplt goes through here; callers treat `None` exactly like a failed git
/// invocation, which is already an honest "could not verify" outcome.
///
/// Pass `Path::new(".")` for the call sites that intentionally query the
/// process working directory rather than a specific project.
#[must_use]
pub fn command(project_dir: &Path, args: &[&str]) -> Option<Command> {
    if leading_globals(args)
        .iter()
        .any(|a| VALUE_TAKING_GLOBALS.contains(a))
    {
        // Never silent: this branch is unreachable for every current call
        // site, so reaching it means someone added one and needs to know the
        // call was refused rather than quietly degraded.
        crate::ui::warn(&format!(
            "refusing git invocation with a value-taking global flag: {args:?}. \
             Put config overrides in git::CONFIG_OVERRIDES instead."
        ));
        return None;
    }
    if reads_worktree_content(args) && repo_defines_content_filter(project_dir) {
        warn_refused_once();
        return None;
    }
    let mut cmd = Command::new(trusted_git()?);
    harden(&mut cmd);
    for arg in insert_diff_flags(args) {
        cmd.arg(arg);
    }
    cmd.current_dir(project_dir);
    Some(cmd)
}

/// True when the repository at `project_dir` defines a content filter in its
/// **own** (`local` or `worktree` scope) config.
///
/// `git config --list` is itself run through the hardened path, and `config` is
/// on [`CONTENT_FREE_SUBCOMMANDS`], so this does not recurse.
///
/// `--includes` is load-bearing: local config may `include.path` a file that
/// defines the filter, and git honours it when running `status` — a listing
/// without `--includes` would miss it and fail *open*.
///
/// Returns `false` when git cannot answer (not a repo, git missing): there is
/// no repo config to fear in that case, and the caller's own git call will fail
/// on its own terms.
#[must_use]
pub fn repo_defines_content_filter(project_dir: &Path) -> bool {
    let Some(git) = trusted_git() else {
        return false;
    };
    let mut cmd = Command::new(git);
    harden(&mut cmd);
    let Ok(out) = cmd
        .args(["config", "--list", "--show-scope", "--includes", "-z"])
        .current_dir(project_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    // `-z` output is a flat NUL-separated stream of alternating fields:
    // scope NUL "key\nvalue" NUL scope NUL "key\nvalue" NUL ...
    // A valueless key has no newline; `split_once` yielding None handles it.
    let text = String::from_utf8_lossy(&out.stdout);
    let mut fields = text.split('\0');
    while let (Some(scope), Some(entry)) = (fields.next(), fields.next()) {
        if scope != "local" && scope != "worktree" {
            continue;
        }
        let key = entry.split_once('\n').map_or(entry, |(k, _)| k);
        if is_content_filter_key(key) {
            return true;
        }
    }
    false
}

/// `filter.<name>.clean` / `filter.<name>.process` — the two filter stages git
/// runs while comparing the working tree. `smudge` is checkout-only and cannot
/// be reached by any read-only query.
fn is_content_filter_key(key: &str) -> bool {
    let Some(rest) = key.strip_prefix("filter.") else {
        return false;
    };
    // Config keys are lowercased by git except for the subsection, which is
    // case-sensitive and may contain dots — so match on the last segment.
    matches!(
        rest.rsplit_once('.').map(|(_, last)| last),
        Some("clean" | "process")
    )
}

/// Explain the refusal once per process. Without this the user sees only an
/// unexplained "audit incomplete".
fn warn_refused_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        crate::ui::warn(
            "repository config defines a git content filter (filter.*.clean/process). \
             cplt is skipping working-tree git queries so the filter never runs outside \
             the sandbox. See cplt issue #210.",
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full expected table, spelled out independently of
    /// [`CONFIG_OVERRIDES`] — a test that only iterates the const cannot notice
    /// the const being emptied. `core.fsmonitor` is the one key measured to
    /// execute for the subcommands cplt runs today; the rest are the
    /// defence-in-depth layer, and defence in depth that can be silently
    /// deleted is not defence in depth.
    #[test]
    fn the_override_table_is_exactly_this() {
        let expected: &[(&str, &str)] = &[
            ("core.fsmonitor", "false"),
            ("core.hooksPath", "/dev/null"),
            ("core.pager", "cat"),
            ("core.editor", "false"),
            ("sequence.editor", "false"),
            ("core.sshCommand", ""),
            ("core.gitProxy", ""),
            ("core.alternateRefsCommand", ""),
            ("credential.helper", ""),
            ("uploadpack.packObjectsHook", ""),
            ("gpg.program", "false"),
        ];
        let actual: Vec<(&str, &str)> = CONFIG_OVERRIDES.iter().map(|(k, v, _)| (*k, *v)).collect();
        assert_eq!(
            actual, expected,
            "CONFIG_OVERRIDES changed. Removing an entry weakens #210 hardening; \
             adding one needs a reviewed cost note. Update this list deliberately."
        );
    }

    /// Fails if [`command`] goes back to `Command::new("git")`. The bare name
    /// is resolved by `execvp` at spawn time from the *parent's* `PATH`, and the
    /// parent spawns git after the agent has exited — so any agent-writable
    /// directory on `PATH` (mise shims, `PNPM_HOME`, `~/.bun/bin`) is an
    /// unsandboxed exec.
    #[test]
    fn git_is_resolved_from_a_trusted_absolute_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let Some(cmd) = command(dir.path(), &["rev-parse", "HEAD"]) else {
            // No trusted git on this machine: the call must be refused, never
            // degraded to the bare name. That is the other half of the contract.
            assert!(trusted_git().is_none(), "refused despite a resolved git");
            return;
        };
        let program = PathBuf::from(cmd.get_program());
        assert_eq!(program.file_name().and_then(|n| n.to_str()), Some("git"));
        assert!(
            program.is_absolute(),
            "git must not be resolved through PATH: {program:?}"
        );
        assert!(
            TRUSTED_BIN_DIRS.iter().any(|d| program.starts_with(d)),
            "{program:?} is outside TRUSTED_BIN_DIRS"
        );
    }

    /// Spelled out independently of the const, like the override table above: a
    /// test that only iterates it cannot notice a writable directory being added
    /// or `/usr/bin` being dropped.
    #[test]
    fn the_trusted_bin_dirs_are_exactly_this() {
        assert_eq!(
            TRUSTED_BIN_DIRS,
            &[
                "/usr/bin",
                "/bin",
                "/usr/local/bin",
                "/opt/homebrew/bin",
                "/run/current-system/sw/bin",
                "/home/linuxbrew/.linuxbrew/bin",
            ],
            "TRUSTED_BIN_DIRS changed. Every entry must be absolute and read-only \
             to the sandbox — see `every_trusted_dir_is_covered_by_a_tool_read_grant` \
             in sandbox.rs."
        );
    }

    /// The not-found path, which the host's real `/usr/bin/git` would otherwise
    /// hide: no `git` in the searched dirs must yield `None`, never a bare name.
    #[test]
    fn find_in_returns_none_when_the_binary_is_absent() {
        let empty = tempfile::tempdir().expect("tempdir");
        let populated = tempfile::tempdir().expect("tempdir");
        let planted = populated.path().join("git");
        plant_executable(&planted);
        let dirs = [empty.path().to_str().expect("utf8")];
        assert_eq!(find_in(&dirs, &dirs, "git"), None);
        let dirs = [
            empty.path().to_str().expect("utf8"),
            populated.path().to_str().expect("utf8"),
        ];
        // First match wins, and the earlier directory is searched first.
        assert_eq!(find_in(&dirs, &dirs, "git"), Some(planted));
    }

    fn plant_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, "#!/bin/sh\n").expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    /// A non-executable file named `git` in an earlier trusted directory must
    /// not shadow the real one: `execvp` needs `X_OK`, so matching it would turn
    /// every parent-side spawn into `EACCES` instead of searching on.
    #[test]
    fn find_in_skips_a_non_executable_shadow() {
        let shadow = tempfile::tempdir().expect("tempdir");
        let real = tempfile::tempdir().expect("tempdir");
        std::fs::write(shadow.path().join("git"), "not executable").expect("write");
        let planted = real.path().join("git");
        plant_executable(&planted);

        let dirs = [shadow.path().to_str().expect("utf8")];
        assert_eq!(find_in(&dirs, &dirs, "git"), None);
        let dirs = [
            shadow.path().to_str().expect("utf8"),
            real.path().to_str().expect("utf8"),
        ];
        assert_eq!(find_in(&dirs, &dirs, "git"), Some(planted));
    }

    /// A file with an execute bit that does **not** apply to us is still a
    /// shadow. Mode `0o011` (exec for group and other, not owner) on a file we
    /// own is the reproducible stand-in for the real case — a root-owned `0700`
    /// `git` — which needs a second uid to create. `mode & 0o111 != 0` accepts
    /// both; `faccessat(X_OK)` rejects both.
    #[test]
    fn find_in_skips_a_binary_we_may_not_execute() {
        use std::os::unix::fs::PermissionsExt;

        // SAFETY: a plain getuid(), no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            // root bypasses the permission check whenever *any* execute bit is
            // set, so there is no shadow to observe. The root-owned-0700 case
            // this stands in for is likewise unreachable while we are root.
            return;
        }
        let shadow = tempfile::tempdir().expect("tempdir");
        let real = tempfile::tempdir().expect("tempdir");
        let denied = shadow.path().join("git");
        std::fs::write(&denied, "#!/bin/sh\n").expect("write");
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o011)).expect("chmod");
        assert!(!is_executable_file(&denied), "execute bit is not our bit");

        let planted = real.path().join("git");
        plant_executable(&planted);
        let dirs = [
            shadow.path().to_str().expect("utf8"),
            real.path().to_str().expect("utf8"),
        ];
        assert_eq!(find_in(&dirs, &dirs, "git"), Some(planted));
    }

    /// The Homebrew shape, which must keep working: `bin/git` is a symlink and
    /// its target lives elsewhere under the same read-only prefix
    /// (`/opt/homebrew/bin/git` → `/opt/homebrew/Cellar/git/*/bin/git`).
    /// Rejecting symlinks outright would leave those installs with no trusted
    /// git at all.
    #[test]
    fn find_in_accepts_a_symlink_that_stays_inside_a_trusted_root() {
        let root = tempfile::tempdir().expect("tempdir");
        let bin = root.path().join("bin");
        let cellar = root.path().join("Cellar/git/2.55/bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        std::fs::create_dir_all(&cellar).expect("mkdir");
        let real = cellar.join("git");
        plant_executable(&real);
        let link = bin.join("git");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let dirs = [bin.to_str().expect("utf8")];
        let roots = [root.path().to_str().expect("utf8")];
        assert_eq!(find_in(&dirs, &roots, "git"), Some(link));
    }

    /// The hole this closes: the *path* is in a trusted directory but the file
    /// is not. `/usr/local/bin` is user-owned on a Homebrew-for-Intel install,
    /// so its `git` symlink can be repointed into an agent-writable tree — and a
    /// path-only check would call that trusted and execute it unsandboxed.
    ///
    /// The escape is skipped like a non-executable shadow, not fatal: a genuine
    /// binary in a later trusted directory still wins.
    #[test]
    fn find_in_rejects_a_symlink_that_escapes_the_trusted_roots() {
        let root = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");
        let bin = root.path().join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        let payload = outside.path().join("git");
        plant_executable(&payload);
        std::os::unix::fs::symlink(&payload, bin.join("git")).expect("symlink");

        let roots = [root.path().to_str().expect("utf8")];
        let dirs = [bin.to_str().expect("utf8")];
        assert_eq!(
            find_in(&dirs, &roots, "git"),
            None,
            "a symlink out of the trusted roots must not resolve"
        );

        let real_dir = root.path().join("sbin");
        std::fs::create_dir_all(&real_dir).expect("mkdir");
        let real = real_dir.join("git");
        plant_executable(&real);
        let dirs = [
            bin.to_str().expect("utf8"),
            real_dir.to_str().expect("utf8"),
        ];
        assert_eq!(
            find_in(&dirs, &roots, "git"),
            Some(real),
            "the search must continue past an escaping symlink"
        );
    }

    /// Spelled out independently of the const, like [`TRUSTED_BIN_DIRS`]: every
    /// root must be a prefix the sandbox never grants write to, and a widened
    /// entry (`/`, `/home`, `$HOME`) would silently re-admit the symlink escape.
    #[test]
    fn the_trusted_bin_roots_are_exactly_this() {
        assert_eq!(
            TRUSTED_BIN_ROOTS,
            &[
                "/usr/bin",
                "/bin",
                "/usr/local",
                "/opt/homebrew",
                "/run/current-system",
                "/nix/store",
                "/snap",
                "/home/linuxbrew/.linuxbrew",
            ],
            "TRUSTED_BIN_ROOTS changed. Every entry must be an absolute prefix the \
             sandbox exposes read-only — see `sandbox_policy::TOOL_READ_DIRS` and \
             `sandbox_landlock::LINUX_TOOL_DIRS`."
        );
        for dir in TRUSTED_BIN_DIRS {
            assert!(
                TRUSTED_BIN_ROOTS
                    .iter()
                    .any(|r| Path::new(dir).starts_with(r)),
                "{dir} has no containing root, so nothing in it can ever resolve"
            );
        }
    }

    /// A directory named `git` is searchable, so `X_OK` alone would accept it.
    #[test]
    fn is_executable_file_rejects_a_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("git");
        std::fs::create_dir(&sub).expect("mkdir");
        assert!(!is_executable_file(&sub));
    }

    /// `Path::join` drops the base for an absolute `name` and walks out of it
    /// for `../x`, either of which would return a path outside
    /// [`TRUSTED_BIN_DIRS`] — the guarantee `trusted_binary` exists to make.
    #[test]
    fn find_in_refuses_anything_but_a_bare_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("git");
        plant_executable(&outside);
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).expect("mkdir");
        let dirs = [sub.to_str().expect("utf8")];

        assert_eq!(find_in(&dirs, &dirs, outside.to_str().expect("utf8")), None);
        assert_eq!(find_in(&dirs, &dirs, "../git"), None);
        assert_eq!(find_in(&dirs, &dirs, "./git"), None);
        assert_eq!(find_in(&dirs, &dirs, ""), None);
        assert_eq!(trusted_binary("/bin/sh"), None);
    }

    #[test]
    fn value_taking_global_flags_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        // `-C dir diff` would make `subcommand()` return `dir`, so the diff
        // driver flags would silently not be inserted.
        assert!(command(dir.path(), &["-C", "/tmp", "diff"]).is_none());
        assert!(command(dir.path(), &["-c", "core.fsmonitor=evil", "status"]).is_none());
        assert!(command(dir.path(), &["--git-dir", "/tmp", "rev-parse"]).is_none());
        // Found by adversarial review: both take a separate-token value in git
        // 2.55, so `--attr-source evil diff` makes `subcommand()` return "evil".
        assert!(command(dir.path(), &["--attr-source", "evil", "diff"]).is_none());
        assert!(command(dir.path(), &["--config-env", "x=Y", "status"]).is_none());
        // The single-token forms parse correctly and stay allowed.
        assert!(command(dir.path(), &["--git-dir=/tmp", "rev-parse"]).is_some());
        // Position-sensitive: `--git-dir` AFTER the subcommand is a rev-parse
        // QUERY, not a global flag — and cplt actually runs it. Refusing it
        // broke two guard tests before this was scoped to leading tokens.
        assert!(command(dir.path(), &["rev-parse", "--git-dir"]).is_some());
        assert!(command(dir.path(), &["rev-parse", "--git-common-dir"]).is_some());
        // Likewise `-C` after `diff` is copy detection, not a global flag.
        assert_eq!(leading_globals(&["diff", "-C", "HEAD"]), &[] as &[&str]);
        // The scan stops at the first non-flag token — here `-C`'s own value.
        // That is enough to spot the flag, and the invocation is refused before
        // the mis-parsed boundary could matter.
        assert_eq!(leading_globals(&["-C", "/tmp", "diff"]), &["-C"]);
    }

    /// Named independently of [`GIT_ENV_CLEARED`] on purpose: a test that only
    /// iterates the const cannot notice the const shrinking. These are the
    /// variables that would hand a repository (or an ambient environment) a
    /// program to run, or point git at a different repository entirely.
    #[test]
    fn the_load_bearing_git_env_vars_stay_cleared() {
        for name in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_CONFIG",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_COUNT",
            "GIT_EXTERNAL_DIFF",
            "GIT_SSH_COMMAND",
            "GIT_PAGER",
            "GIT_EDITOR",
            "GIT_ASKPASS",
            "GIT_PROXY_COMMAND",
            "GIT_ATTR_SOURCE",
        ] {
            assert!(
                GIT_ENV_CLEARED.contains(&name),
                "{name} must stay in GIT_ENV_CLEARED"
            );
        }
    }

    #[test]
    fn every_override_is_documented_and_well_formed() {
        for (key, _, why) in CONFIG_OVERRIDES {
            assert!(key.contains('.'), "not a config key: {key}");
            assert!(!key.contains('='), "key must not embed a value: {key}");
            assert!(why.len() > 20, "undocumented override: {key}");
        }
    }

    #[test]
    fn subcommand_skips_global_flags() {
        assert_eq!(subcommand(&["status", "--porcelain"]), Some("status"));
        assert_eq!(subcommand(&["--no-optional-locks", "diff"]), Some("diff"));
        assert_eq!(subcommand(&["-c", "x=y", "rev-parse"]), Some("x=y"));
        assert_eq!(subcommand(&["--version"]), None);
    }

    #[test]
    fn content_free_subcommands_are_not_gated() {
        assert!(!reads_worktree_content(&["rev-parse", "HEAD"]));
        assert!(!reads_worktree_content(&["cat-file", "blob", "HEAD:x"]));
        assert!(!reads_worktree_content(&["config", "--global", "x"]));
        assert!(!reads_worktree_content(&["remote", "get-url", "origin"]));
    }

    #[test]
    fn worktree_reading_subcommands_are_gated() {
        assert!(reads_worktree_content(&["status", "--porcelain"]));
        assert!(reads_worktree_content(&["diff", "--numstat"]));
        assert!(reads_worktree_content(&["diff", "--quiet", "HEAD"]));
        // Unknown / future subcommands fail closed.
        assert!(reads_worktree_content(&["stash", "list"]));
        assert!(reads_worktree_content(&["commit", "-m", "x"]));
        assert!(reads_worktree_content(&[]));
    }

    #[test]
    fn recognises_content_filter_keys() {
        assert!(is_content_filter_key("filter.lfs.clean"));
        assert!(is_content_filter_key("filter.lfs.process"));
        assert!(is_content_filter_key("filter.my.weird.name.clean"));
        assert!(!is_content_filter_key("filter.lfs.smudge"));
        assert!(!is_content_filter_key("filter.lfs.required"));
        assert!(!is_content_filter_key("diff.lfs.textconv"));
        assert!(!is_content_filter_key("core.fsmonitor"));
        assert!(!is_content_filter_key("filter"));
    }

    #[test]
    fn diff_flags_land_before_any_pathspec_separator() {
        // Appending them instead would put them after `--`, where git reads
        // them as pathspecs and the hardening silently does nothing.
        assert_eq!(
            insert_diff_flags(&["diff", "--quiet", "HEAD", "--", ".cplt.toml"]),
            vec![
                "diff",
                "--no-textconv",
                "--no-ext-diff",
                "--quiet",
                "HEAD",
                "--",
                ".cplt.toml"
            ]
        );
        // Not a diff → untouched.
        assert_eq!(
            insert_diff_flags(&["status", "--porcelain"]),
            vec!["status", "--porcelain"]
        );
        // A later literal "diff" (e.g. a pathspec) must not get a second pair.
        assert_eq!(
            insert_diff_flags(&["diff", "--", "diff"]),
            vec!["diff", "--no-textconv", "--no-ext-diff", "--", "diff"]
        );
    }

    #[test]
    fn diff_gets_the_driver_flags() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cmd = command(dir.path(), &["diff", "--numstat"]).expect("no filter in a bare tempdir");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|a| a == "--no-textconv"), "{args:?}");
        assert!(args.iter().any(|a| a == "--no-ext-diff"), "{args:?}");
        assert!(args.iter().any(|a| a == "core.fsmonitor=false"), "{args:?}");
    }

    #[test]
    fn non_diff_does_not_get_diff_flags() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cmd = command(dir.path(), &["status", "--porcelain"]).expect("no filter");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|a| a == "--no-textconv"), "{args:?}");
    }

    #[test]
    fn hardening_env_is_applied() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cmd = command(dir.path(), &["rev-parse", "HEAD"]).expect("content-free");
        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let get = |name: &str| {
            envs.iter()
                .find(|(k, _)| k == name)
                .and_then(|(_, v)| v.clone())
        };
        // Every named GIT_* is recorded as CLEARED (value None), so an
        // inherited GIT_EXTERNAL_DIFF or GIT_CONFIG_GLOBAL cannot re-open what
        // CONFIG_OVERRIDES closes.
        for name in GIT_ENV_CLEARED {
            let entry = envs.iter().find(|(k, _)| k == name);
            assert!(
                matches!(entry, Some((_, None))),
                "{name} must be cleared, got {entry:?}"
            );
        }
        assert_eq!(get("GIT_CONFIG_NOSYSTEM").as_deref(), Some("1"));
        assert_eq!(get("GIT_ATTR_NOSYSTEM").as_deref(), Some("1"));
        assert_eq!(get("GIT_TERMINAL_PROMPT").as_deref(), Some("0"));
        assert_eq!(get("GIT_OPTIONAL_LOCKS").as_deref(), Some("0"));
        // Every override reaches the command line.
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for (key, value, _) in CONFIG_OVERRIDES {
            assert!(
                args.iter().any(|a| a == &format!("{key}={value}")),
                "override {key} missing from {args:?}"
            );
        }
    }
}
