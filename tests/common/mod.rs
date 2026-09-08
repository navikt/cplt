//! Shared test isolation helpers.
//!
//! Tests must not inherit the machine they run on. Two failures traced to the
//! same root (issue #245): one test asserted a property of one developer's
//! `~/.config/cplt/config.toml` while exercising nothing, and six e2e tests
//! only passed when the checkout's `origin` happened to be `navikt/cplt`.
//!
//! The cure is structural. Every `Command` a test spawns is built here with
//! the ambient state already neutralised, so a test has to opt *out* of
//! isolation (`cplt_cmd_with_ambient_config`) rather than remember to opt in.
//! Do not reach for `Command::new` directly in a test — a convention that
//! depends on memory has already failed twice.

// This turns off the #239 *security* lint only: a test binary is not the
// unsandboxed parent around an agent session, so the PATH-hijack hazard
// `disallowed_methods` guards against does not apply here. It grants no
// licence to spawn ad hoc: the #245 isolation rule stands unchanged, and every
// `Command` a test spawns is still built through the `tests/common` helpers,
// which no lint can enforce and review does.
#![allow(clippy::disallowed_methods)]
#![allow(dead_code)] // not every test binary uses every helper

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// A `CPLT_CONFIG` value that can never name a real file: `/dev/null` is a
/// character device, so nothing can exist beneath it. Config resolution falls
/// through to the built-in defaults instead of the developer's dotfiles.
pub const NO_CONFIG: &str = "/dev/null/nonexistent";

/// Path to the `cplt` binary built for this test run.
#[must_use]
pub fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cplt"))
}

/// A `cplt` `Command` isolated from the developer's config file.
///
/// `gh_guard.enabled`, `sandbox.preset`, `allow_localhost_any` and every other
/// key resolve as CLI flag > config > default. Without this the "default"
/// under test is whatever the machine happens to have configured.
#[must_use]
pub fn cplt_cmd() -> Command {
    let mut cmd = Command::new(binary_path());
    cmd.env("CPLT_CONFIG", NO_CONFIG);
    // Greppable stderr. The summary pads its columns and colours them, so a
    // test that reads it either matches the escape codes or settles for a
    // case-insensitive substring — which is what the one test reading the
    // summary did. NO_COLOR is a documented cplt input (see `ui::no_color`),
    // not a test-only backdoor.
    cmd.env("NO_COLOR", "1");
    // `FORCE_COLOR` outranks `NO_COLOR` in `ui::no_color`, and npm and a good
    // many CI jobs export it — so without this, colour codes land between
    // `gh guard:` and `on` on exactly the machines least likely to be watched.
    cmd.env_remove("FORCE_COLOR");
    cmd
}

/// A `cplt` `Command` that reads the ambient `~/.config/cplt/config.toml`.
///
/// Deliberately verbose: a test using this asserts something about config
/// *discovery*, and its assertions must hold for any config the reader's
/// machine might have. If that is not what you meant, use [`cplt_cmd`].
#[must_use]
pub fn cplt_cmd_with_ambient_config() -> Command {
    Command::new(binary_path())
}

/// Resolve a binary by name, preferring `/usr/bin` so the developer's PATH
/// cannot substitute a different implementation.
///
/// # Panics
/// If the binary is not found in `/usr/bin` or on `PATH`.
#[must_use]
pub fn binary_in_path(name: &str) -> PathBuf {
    let system = PathBuf::from("/usr/bin").join(name);
    if system.is_file() {
        return system;
    }
    std::env::split_paths(&std::env::var_os("PATH").expect("PATH should be set"))
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("{name} should be available in PATH"))
}

/// A `git` `Command` in `dir`, isolated from the developer's global and system
/// git config.
///
/// Global config reaches a fixture repo as `commit.gpgsign` (no signing key on
/// CI, or none on the developer's machine), `core.hooksPath` (arbitrary hooks
/// running inside the fixture), `init.defaultBranch` and aliases. All of it
/// turns fixture setup into a property of the machine.
#[must_use]
pub fn git_cmd(dir: &Path) -> Command {
    let mut cmd = Command::new(binary_in_path("git"));
    cmd.current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    cmd
}

/// Run an isolated `git` command in `dir` and return whether it succeeded.
pub fn git_ok(dir: &Path, args: &[&str]) -> bool {
    git_cmd(dir)
        .args(args)
        .output()
        .expect("git should run")
        .status
        .success()
}

/// A throwaway git repository whose `origin` is `remote` ("owner/name").
///
/// Anything that resolves a repository from the cwd — the gh-guard's scope
/// check above all — must run here rather than in the checkout, whose `origin`
/// is `navikt/cplt` only for people who cloned it directly.
///
/// # Panics
/// If `git init` or `git remote add` fails.
#[must_use]
pub fn temp_repo(remote: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    assert!(git_ok(dir.path(), &["init", "--quiet"]));
    assert!(git_ok(
        dir.path(),
        &[
            "remote",
            "add",
            "origin",
            &format!("https://github.com/{remote}.git"),
        ]
    ));
    // `git clone` records the remote's default branch here, and the git guard
    // reads it to decide what `protect_default_branch_only` protects. A repo
    // built by `git init` has none, which is not what these fixtures stand in
    // for.
    assert!(git_ok(
        dir.path(),
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
        ]
    ));
    dir
}

/// Assert a gate refused a command *for the stated reason*.
///
/// `assert!(!ok, …)` on its own is a vacuous assertion: it passes when the
/// command failed for any reason at all — a renamed flag clap rejects, a
/// fixture that never got built, a panic in the harness. Tests of that shape
/// have shipped green over guards that were never running (issue #126).
/// Pinning the refusal text is what separates "the policy blocked it" from "it
/// fell over on the way to the policy".
///
/// `reason` should be the distinguishing part of the message — the `Reason:`
/// line, not the `BLOCKED by sandbox` banner every refusal carries.
///
/// # Panics
/// If the command succeeded, or failed without emitting the refusal banner and
/// `reason`.
pub fn assert_refused(stderr: &str, ok: bool, reason: &str) {
    assert!(
        !ok,
        "must be refused, but the gate let it through.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("BLOCKED by sandbox"),
        "must fail as a policy refusal, not for some other reason.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains(reason),
        "refusal must name {reason:?}.\nstderr: {stderr}"
    );
}

// ── Golden-path harness (#431) ───────────────────────────────────────
//
// The e2e suite asserted on the agent's view of the sandbox and almost never
// on the operator's view of cplt, because reaching the operator's surfaces
// cost 40–60 lines of boilerplate per test. These helpers make a golden-path
// test a few lines: a scratch HOME, a launch, and the two strings it produced.

static SCRATCH_HOME_COUNTER: AtomicU32 = AtomicU32::new(0);

/// A scratch `HOME` with no cplt config in it.
///
/// Every operator-surface assertion needs one: `config set` writes under
/// `$HOME/.config/cplt`, and the launch reads it back from there, so the two
/// only agree about the same file if both see the same HOME.
///
/// The caller owns the directory; `std::fs::remove_dir_all` it when done.
///
/// # Panics
/// If the directory cannot be created.
#[must_use]
pub fn make_config_home(label: &str) -> PathBuf {
    // The pid is in the name because the counter is not: it is per process, so
    // two concurrent runs of the same test binary — one in a terminal, one in
    // an editor — would otherwise pick the same directory, and the
    // `remove_dir_all` below would delete the other run's HOME mid-launch.
    let home = std::env::temp_dir().join(format!(
        ".cplt-e2e-{label}-{}-{}",
        std::process::id(),
        SCRATCH_HOME_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).expect("scratch HOME should be creatable");
    home
}

/// A `cplt` `Command` that reads `home`'s config from inside `repo`.
///
/// `CPLT_CONFIG` is removed, not repointed: the per-repo local layer lives
/// beside the config file, and the whole point is to exercise the paths
/// `$HOME/.config/cplt/{config.toml,local/}` that a real run uses.
#[must_use]
pub fn cplt_local(home: &Path, repo: &Path) -> Command {
    let mut cmd = cplt_cmd();
    cmd.current_dir(repo)
        .env("HOME", home.to_str().expect("HOME path should be UTF-8"))
        .env_remove("CPLT_CONFIG");
    cmd
}

/// Run `cplt <args>` against `home` from inside `repo`, returning
/// `(stdout, stderr, status)`.
///
/// stderr is where the launch summary, the `(local)` labels and the guard
/// lines live — the surfaces five defects hid on — so it is returned as a
/// `String` ready to grep rather than left in the `Output`.
///
/// # Panics
/// If the binary cannot be spawned.
#[must_use]
pub fn launch(
    home: &Path,
    repo: &Path,
    args: &[&str],
) -> (String, String, std::process::ExitStatus) {
    let output = cplt_local(home, repo)
        .args(args)
        .output()
        .expect("cplt should run");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status,
    )
}

/// A work tree with one commit and an `origin` pointing at a bare repository
/// beside it: `(tempdir, work, origin)`.
///
/// The bare origin is what makes a push observable — a push that reaches it
/// leaves a ref behind, so "the guard refused it" can be told apart from "the
/// push failed on the way to the guard".
///
/// Built inside `dir_in` rather than `/tmp` when the caller passes the
/// checkout: the macOS sandbox denies process-exec under `/private/tmp`, so a
/// git that must run inside the sandbox cannot live there.
///
/// # Panics
/// If any git command fails.
#[must_use]
pub fn bare_origin_repo(dir_in: &Path) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::Builder::new()
        .prefix(".cplt-e2e-origin-")
        .tempdir_in(dir_in)
        .expect("create temp dir");
    let origin = tmp.path().join("origin.git");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).expect("create work dir");

    let run = |dir: &Path, args: &[&str]| {
        let out = git_cmd(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .expect("git should run");
        assert!(
            out.status.success(),
            "git {args:?} should succeed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(
        tmp.path(),
        &["init", "--bare", "-b", "main", origin.to_str().unwrap()],
    );
    run(&work, &["init", "-b", "main"]);
    run(&work, &["commit", "--allow-empty", "-m", "init"]);
    run(
        &work,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    (tmp, work, origin)
}
