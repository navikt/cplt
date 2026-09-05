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

// Test code spawns freely: it is not the unsandboxed parent around an agent
// session, so the PATH-resolution hazard `disallowed_methods` guards against
// (#239) does not apply. The isolation helpers in `tests/common` are the rule
// here, and they are enforced by review, not by this lint.
#![allow(clippy::disallowed_methods)]
#![allow(dead_code)] // not every test binary uses every helper

use std::path::{Path, PathBuf};
use std::process::Command;

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
