//! End-to-end proof that a repository cannot make cplt's **parent-side** git
//! calls execute a program of the repository's choosing (issue #210).
//!
//! Each test plants a payload script in a git config key that the named git
//! subcommand would otherwise run, exercises the real cplt code path that
//! invokes it, and asserts the payload never ran. The payload writes a marker
//! file, so "never ran" is a filesystem fact rather than an inference.
//!
//! Run: cargo test --test e2e_git_hardening

use std::path::{Path, PathBuf};
use std::process::Stdio;

mod common;
use common::git_cmd;

/// A scratch repo plus the marker path its payload would create.
struct Fixture {
    _tmp: tempfile::TempDir,
    repo: PathBuf,
    marker: PathBuf,
    payload: PathBuf,
}

fn git(repo: &Path, args: &[&str]) -> bool {
    // `git_cmd` keeps the developer's (and CI's) own git config out of FIXTURE
    // SETUP: a global `core.hooksPath` pre-commit hook or `commit.gpgsign`
    // would otherwise make `git commit` fail here for reasons unrelated to the
    // property under test. This affects only these setup commands — the cplt
    // code paths under test spawn their own git and see the real environment.
    git_cmd(repo)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Build a committed repo containing `.cplt.toml` and a tracked data file, with
/// a `.gitattributes` that routes everything through the `evil` diff/filter
/// drivers. Returns `None` when git is unavailable (CI without git).
fn fixture() -> Option<Fixture> {
    let tmp = tempfile::tempdir().ok()?;
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).ok()?;
    let marker = tmp.path().join("PAYLOAD_RAN");
    let payload = tmp.path().join("payload.sh");
    std::fs::write(
        &payload,
        format!(
            "#!/bin/sh\n\
             : > '{}'\n\
             # Behave like an identity filter so a *failure* to harden shows up\n\
             # as a marker file rather than as a git error.\n\
             exec cat\n",
            marker.display()
        ),
    )
    .ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).ok()?;
    }

    if !git(&repo, &["init", "-q", "-b", "main", "."]) {
        return None;
    }
    std::fs::write(repo.join(".cplt.toml"), "allow = []\n").ok()?;
    std::fs::write(repo.join("data.txt"), "before\n").ok()?;
    std::fs::write(repo.join(".gitattributes"), "* diff=evil filter=evil\n").ok()?;
    assert!(git(&repo, &["add", "-A"]));
    assert!(git(&repo, &["commit", "-qm", "init"]));

    Some(Fixture {
        _tmp: tmp,
        repo,
        marker,
        payload,
    })
}

/// Simulate the session: change a tracked file and the config, so `git status`
/// and `git diff` must actually compare content (and would run the payload).
fn dirty(f: &Fixture) {
    std::fs::write(f.repo.join("data.txt"), "before\nafter\n").unwrap();
    std::fs::write(f.repo.join(".cplt.toml"), "allow = [\"x\"]\n").unwrap();
}

fn set_key(f: &Fixture, key: &str) {
    assert!(git(
        &f.repo,
        &["config", key, &f.payload.display().to_string()]
    ));
}

/// `core.fsmonitor` is run by `git status` and `git diff`. This is the key the
/// issue names, and the one that is genuinely reachable today.
///
/// The audit must stay **correct** here — neutralizing fsmonitor only costs the
/// fast path, so the report is still `Available` and still names the changed
/// file. Degrading to `Incomplete` would be a silent regression of the feature.
#[test]
fn fsmonitor_is_not_executed_by_the_audit_and_the_audit_stays_correct() {
    let Some(f) = fixture() else {
        eprintln!("skipping: git unavailable");
        return;
    };
    set_key(&f, "core.fsmonitor");

    let baseline = cplt::audit::Baseline::capture(&f.repo);
    dirty(&f);
    let report = baseline.finish(0);

    assert!(
        !f.marker.exists(),
        "core.fsmonitor payload executed in the parent process"
    );
    match report {
        cplt::audit::AuditReport::Available { changes, .. } => {
            assert!(
                changes.iter().any(|c| c.path == "data.txt"),
                "audit lost the change it exists to report: {changes:?}"
            );
        }
        other => panic!("fsmonitor hardening must not cost audit accuracy, got {other:?}"),
    }
}

/// `diff.<driver>.textconv` is reached through `.gitattributes` by
/// `git diff --quiet`, which `repo_config::repo_config_state` runs to decide
/// whether `.cplt.toml` matches HEAD — i.e. it feeds the trust decision.
#[test]
fn textconv_is_not_executed_by_the_repo_config_trust_check() {
    let Some(f) = fixture() else {
        eprintln!("skipping: git unavailable");
        return;
    };
    set_key(&f, "diff.evil.textconv");
    dirty(&f);

    let state = cplt::repo_config::repo_config_state(&f.repo);

    assert!(
        !f.marker.exists(),
        "diff.evil.textconv payload executed in the parent process"
    );
    // The working tree no longer matches HEAD, and hardening does not change
    // that answer — textconv is a rendering concern, not a sameness one.
    assert_eq!(state, cplt::repo_config::RepoConfigState::Drifted);
}

/// `filter.<name>.clean` is reached through `.gitattributes` by both
/// `git status` and `git diff`. No fixed `-c` override can name it, so cplt
/// refuses the query instead — and must then say so rather than report a clean
/// session it never verified.
#[test]
fn content_filter_is_not_executed_and_the_audit_degrades_to_incomplete() {
    let Some(f) = fixture() else {
        eprintln!("skipping: git unavailable");
        return;
    };
    set_key(&f, "filter.evil.clean");

    let baseline = cplt::audit::Baseline::capture(&f.repo);
    dirty(&f);
    let report = baseline.finish(0);

    assert!(
        !f.marker.exists(),
        "filter.evil.clean payload executed in the parent process"
    );
    assert!(
        matches!(report, cplt::audit::AuditReport::Incomplete { .. }),
        "a repo cplt refused to scan must never read as audited, got {report:?}"
    );
}

/// The same for `filter.<name>.process`, git's long-running filter protocol.
#[test]
fn filter_process_is_not_executed() {
    let Some(f) = fixture() else {
        eprintln!("skipping: git unavailable");
        return;
    };
    set_key(&f, "filter.evil.process");
    dirty(&f);

    let _ = cplt::audit::Baseline::capture(&f.repo).finish(0);
    let _ = cplt::repo_config::repo_config_state(&f.repo);

    assert!(
        !f.marker.exists(),
        "filter.evil.process payload executed in the parent process"
    );
}

/// A filter hidden behind `include.path` must still be detected. Listing the
/// config without `--includes` would miss it and fail **open** — git itself
/// honours the include when it runs `status`.
#[test]
fn content_filter_reached_through_include_path_is_detected() {
    let Some(f) = fixture() else {
        eprintln!("skipping: git unavailable");
        return;
    };
    std::fs::write(
        f.repo.join(".git/hidden.cfg"),
        format!(
            "[filter \"evil\"]\n\tclean = {}\n",
            f.payload.display().to_string().replace('\\', "/")
        ),
    )
    .unwrap();
    assert!(git(&f.repo, &["config", "include.path", "hidden.cfg"]));

    assert!(
        cplt::git::repo_defines_content_filter(&f.repo),
        "an include.path'd filter must be treated as repository-controlled"
    );
    assert!(
        cplt::git::command(&f.repo, &["status", "--porcelain"]).is_none(),
        "working-tree queries must be refused when a content filter is defined"
    );
    // Object-store reads cannot reach a filter, so they stay available: the
    // refusal is scoped, not a blanket shutdown of git.
    assert!(cplt::git::command(&f.repo, &["rev-parse", "HEAD"]).is_some());
}

/// An ordinary repo — no repository-controlled exec keys at all — must be
/// completely unaffected. This is the regression guard against over-hardening:
/// it also proves the developer's own global config never trips the refusal.
#[test]
fn an_ordinary_repo_is_fully_audited() {
    let Some(f) = fixture() else {
        eprintln!("skipping: git unavailable");
        return;
    };
    let baseline = cplt::audit::Baseline::capture(&f.repo);
    dirty(&f);
    let report = baseline.finish(0);

    assert!(!f.marker.exists());
    match report {
        cplt::audit::AuditReport::Available { changes, .. } => {
            assert!(changes.iter().any(|c| c.path == "data.txt"), "{changes:?}");
            assert!(
                changes.iter().any(|c| c.path == ".cplt.toml"),
                "{changes:?}"
            );
        }
        other => panic!("expected Available, got {other:?}"),
    }
    assert!(cplt::git::command(&f.repo, &["status", "--porcelain"]).is_some());
}

/// `worktree`-scope config (`extensions.worktreeConfig`) is repository-owned
/// too — a filter parked there must count exactly like one in `.git/config`.
#[test]
fn worktree_scope_content_filter_is_detected() {
    let Some(f) = fixture() else {
        eprintln!("skipping: git unavailable");
        return;
    };
    assert!(git(
        &f.repo,
        &["config", "extensions.worktreeConfig", "true"]
    ));
    assert!(git(
        &f.repo,
        &[
            "config",
            "--worktree",
            "filter.evil.clean",
            &f.payload.display().to_string(),
        ]
    ));
    dirty(&f);

    assert!(
        cplt::git::repo_defines_content_filter(&f.repo),
        "a worktree-scope filter must be treated as repository-controlled"
    );
    let _ = cplt::audit::Baseline::capture(&f.repo).finish(0);
    assert!(
        !f.marker.exists(),
        "worktree-scope filter.evil.clean executed in the parent process"
    );
}

// ── Git guard: a setting that cannot be honoured grants nothing (#215) ──
//
// Both properties below are instances of the "no silent grants" rule in
// AGENTS.md and SECURITY.md: an authorization the guard cannot *prove* must be
// refused, not extended on the strength of a name.

use cplt::config::ResolvedPushRule;
use cplt::gh_proxy::gate_git;

/// A repo whose `origin` is `url`, checked out on `branch`, recording `default`
/// as the remote's default branch (`None`: never recorded, as in a fetch-only
/// clone). `None` when the fixture could not be built.
fn guard_repo(url: &str, branch: &str, default: Option<&str>) -> Option<tempfile::TempDir> {
    let tmp = tempfile::tempdir().ok()?;
    let dir = tmp.path();
    if !common::git_ok(dir, &["init", "--quiet"]) {
        return None;
    }
    assert!(common::git_ok(
        dir,
        &["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")]
    ));
    assert!(common::git_ok(dir, &["remote", "add", "origin", url]));
    if let Some(default) = default {
        assert!(common::git_ok(
            dir,
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                &format!("refs/remotes/origin/{default}"),
            ]
        ));
    }
    Some(tmp)
}

fn git_bin() -> PathBuf {
    common::binary_in_path("git")
}

/// An `allow_push` rule whose remote name could not be pinned to a URL at
/// launch matches nothing — in *any* repository.
///
/// Two repositories, each with a remote called `origin`, pointing at different
/// URLs. Matching such a rule by bare name authorizes a push to whichever repo
/// the command happens to target, which is the cross-repo grant #215 exists to
/// prevent; the single-repo case cannot tell the two behaviours apart.
#[test]
fn an_unpinned_allow_push_rule_authorizes_no_repository() {
    let Some(launch) = guard_repo("https://github.com/navikt/cplt.git", "main", Some("main"))
    else {
        return; // fixture setup failed
    };
    let Some(other) = guard_repo("https://github.com/someone/else.git", "main", Some("main"))
    else {
        return;
    };
    let git = git_bin();

    // Written for the launch repo's `origin`, but pinning failed at launch.
    let unpinned = ResolvedPushRule {
        remote: Some("origin".to_string()),
        branches: vec!["main".to_string()],
        force: false,
        url: None,
    };

    for repo in [launch.path(), other.path()] {
        let dir = repo.to_string_lossy().into_owned();
        let err = gate_git(
            &["-C", &dir, "push", "origin", "main"],
            true,
            true,
            false,
            std::slice::from_ref(&unpinned),
            Some(&git),
        )
        .expect_err("an unpinned rule must authorize nothing");
        assert!(
            err.contains("pinned to a repository URL"),
            "the block must say the rule could not be pinned, got: {err}"
        );
    }

    // Control: pinned to the launch repo, the same rule authorizes the push
    // there and only there.
    let pinned = ResolvedPushRule {
        url: Some(cplt::trust::normalize_remote_url(
            "https://github.com/navikt/cplt.git",
        )),
        ..unpinned
    };
    let launch_dir = launch.path().to_string_lossy().into_owned();
    let other_dir = other.path().to_string_lossy().into_owned();
    assert!(
        gate_git(
            &["-C", &launch_dir, "push", "origin", "main"],
            true,
            true,
            false,
            std::slice::from_ref(&pinned),
            Some(&git),
        )
        .is_ok(),
        "a pinned rule must still authorize its own repository"
    );
    assert!(
        gate_git(
            &["-C", &other_dir, "push", "origin", "main"],
            true,
            true,
            false,
            std::slice::from_ref(&pinned),
            Some(&git),
        )
        .is_err(),
        "a pinned rule must not authorize another repository's origin"
    );
}

/// `protect_default_branch_only` protects the repository's *actual* default
/// branch, not a hardcoded `main`/`master`.
#[test]
fn protect_default_branch_only_protects_a_default_that_is_not_main() {
    let Some(repo) = guard_repo("https://github.com/o/o.git", "develop", Some("develop")) else {
        return; // fixture setup failed
    };
    let git = git_bin();
    let dir = repo.path().to_string_lossy().into_owned();
    let gate = |branch: &str| {
        gate_git(
            &["-C", &dir, "push", "origin", branch],
            true,
            true,
            true,
            &[],
            Some(&git),
        )
    };

    assert!(
        gate("develop").is_err(),
        "the repository's default branch must be protected"
    );
    assert!(
        gate("main").is_err(),
        "main/master stay protected as a floor"
    );
    assert!(
        gate("feature/x").is_ok(),
        "a feature branch is still allowed"
    );

    // A bare `git push` on the default branch is blocked too — the branch is
    // resolved from HEAD, the default from the remote, both in this repo.
    assert!(
        gate_git(&["-C", &dir, "push"], true, true, true, &[], Some(&git)).is_err(),
        "bare push while on the default branch must be blocked"
    );
}

/// Each repository is judged by its own default branch, including through `-C`.
#[test]
fn the_default_branch_is_resolved_in_the_repo_the_command_targets() {
    let Some(develop) = guard_repo("https://github.com/o/dev.git", "develop", Some("develop"))
    else {
        return; // fixture setup failed
    };
    let Some(mainline) = guard_repo("https://github.com/o/main.git", "main", Some("main")) else {
        return;
    };
    let git = git_bin();
    let gate = |repo: &Path| {
        let dir = repo.to_string_lossy().into_owned();
        gate_git(
            &["-C", &dir, "push", "origin", "develop"],
            true,
            true,
            true,
            &[],
            Some(&git),
        )
    };

    assert!(
        gate(develop.path()).is_err(),
        "develop is the default branch there"
    );
    assert!(
        gate(mainline.path()).is_ok(),
        "develop is an ordinary feature branch there"
    );
}

/// When the default branch cannot be resolved the relaxation is refused rather
/// than guessed: `protect_default_branch_only` only permits a push it can prove
/// is *not* to the default branch.
#[test]
fn protect_default_branch_only_grants_nothing_when_the_default_is_unknown() {
    let Some(repo) = guard_repo("https://github.com/o/o.git", "feature/x", None) else {
        return; // fixture setup failed
    };
    let git = git_bin();
    let dir = repo.path().to_string_lossy().into_owned();
    let err = gate_git(
        &["-C", &dir, "push", "origin", "feature/x"],
        true,
        true,
        true,
        &[],
        Some(&git),
    )
    .expect_err("no resolved default branch means no push is proven safe");
    assert!(
        err.contains("git remote set-head"),
        "the block must say how to record the default branch, got: {err}"
    );
}
