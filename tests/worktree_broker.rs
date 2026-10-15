//! Tests for the managed-worktree broker (#531): `cplt worktree add`.
//!
//! macOS only, like the feature. `add` runs the real hardened git against a
//! throwaway repository. `HOME` is pinned to a temp dir for each test, since the
//! broker's git reads the user's global config and a real LFS or filter driver
//! there would change the outcome.
#![cfg(target_os = "macos")]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use cplt::worktree_broker::{Broker, Context, add, validate_name, validate_reference};
use cplt::worktrees::{self, DEFAULT_WALK_MAX_DIRS};

/// `HOME` is process-wide, so the tests that set it run one at a time.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_guard() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct Fixture {
    home: tempfile::TempDir,
    project: tempfile::TempDir,
    root: PathBuf,
    common: PathBuf,
}

impl Fixture {
    /// A repository whose tracked files are `files`, plus a managed root.
    fn new(files: &[(&str, &str)]) -> Self {
        // Under the lock: `home_temp_dir` reads the process-wide HOME, which
        // another test may have pointed at its own temp dir.
        let home = {
            let _g = env_guard();
            common::home_temp_dir("wt-broker-home")
        };
        Self::in_home(home, files)
    }

    fn in_home(home: tempfile::TempDir, files: &[(&str, &str)]) -> Self {
        let project = common::temp_repo("navikt/worktree-broker-fixture");
        std::fs::write(project.path().join(".gitignore"), "target/\n").unwrap();
        write_files(project.path(), files);
        assert!(common::git_ok(project.path(), &["add", "-A"]));
        assert!(common::git_ok(
            project.path(),
            &["commit", "--quiet", "-m", "fixture"]
        ));
        let (root, common) = with_home(home.path(), || {
            let root =
                worktrees::prepare_root(home.path(), project.path(), true, DEFAULT_WALK_MAX_DIRS)
                    .expect("root")
                    .expect("in a repository");
            let common = worktrees::repository_common_dir(project.path())
                .expect("common")
                .expect("common dir");
            (root, common)
        });
        Self {
            home,
            project,
            root,
            common,
        }
    }

    fn ctx(&self) -> Context {
        let ctx = Context::new(self.project.path(), &self.common, &self.root).expect("context");
        // These isolated plumbing tests have no caller deny policy. Real policy
        // enforcement is exercised by the sandbox E2E regression.
        ctx.set_read_policy("(version 1)\n(allow default)\n")
            .unwrap();
        ctx
    }

    fn add(&self, name: &str, reference: &str) -> Result<String, String> {
        with_home(self.home.path(), || add(&self.ctx(), name, reference))
    }

    fn base(&self) -> PathBuf {
        self.root.parent().unwrap().to_path_buf()
    }

    fn admin_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.common.join("worktrees"))
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }
}

fn with_home<R>(home: &Path, f: impl FnOnce() -> R) -> R {
    let _g = env_guard();
    temp_env::with_vars(
        [
            ("HOME", Some(home.as_os_str())),
            ("XDG_CONFIG_HOME", Some(home.join(".config").as_os_str())),
        ],
        f,
    )
}

fn write_files(dir: &Path, files: &[(&str, &str)]) {
    for (rel, body) in files {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }
}

fn commit_all(dir: &Path) {
    assert!(common::git_ok(dir, &["add", "-A"]));
    assert!(common::git_ok(dir, &["commit", "--quiet", "-m", "more"]));
}

fn tracked_files() -> Vec<(&'static str, &'static str)> {
    vec![
        (".cplt.toml", "[propose]\n"),
        (".github/hooks/pre.sh", "echo hook\n"),
        ("src/a.txt", "alpha\n"),
    ]
}

#[test]
fn public_git_names_do_not_collide_with_private_metadata() {
    for name in ["git", "GIT"] {
        let fx = Fixture::new(&tracked_files());
        fx.add(name, "HEAD").unwrap();
        assert!(fx.root.join(name).join("src/a.txt").is_file());
    }
}

#[test]
fn executable_bare_markers_are_refused() {
    let fx = Fixture::new(&[
        ("bare/HEAD", "ref: refs/heads/main\n"),
        ("bare/objects", "x"),
        ("bare/refs", "x"),
    ]);
    for name in ["objects", "refs"] {
        std::fs::set_permissions(
            fx.project.path().join("bare").join(name),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    commit_all(fx.project.path());
    assert!(
        fx.add("bare", "HEAD")
            .unwrap_err()
            .contains("bare git repository")
    );
}

#[test]
fn symlink_dotdot_escape_is_refused() {
    let fx = Fixture::new(&tracked_files());
    symlink(".", fx.project.path().join("s")).unwrap();
    symlink("s/../absent-outside", fx.project.path().join("escape")).unwrap();
    commit_all(fx.project.path());
    assert!(fx.add("escape", "HEAD").unwrap_err().contains("symlink"));
}

#[test]
fn filesystem_protected_aliases_are_refused_but_ordinary_unicode_is_allowed() {
    for path in [
        ".claude/ſettings.json",
        "nested/.github/hoo\u{212a}s/payload",
        "nested/.claude/ſettings.json",
    ] {
        let fx = Fixture::new(&tracked_files());
        let ctx = with_home(fx.home.path(), || fx.ctx());
        write_files(fx.project.path(), &[(path, "payload\n")]);
        commit_all(fx.project.path());
        let err = add(&ctx, "alias", "HEAD").unwrap_err();
        assert!(
            err.contains("protected filesystem name is an alias"),
            "{path}: {err}"
        );
        assert!(!fx.root.join("alias").exists());
        assert!(fx.admin_entries().is_empty());
    }
    let fx = Fixture::new(&tracked_files());
    let ctx = with_home(fx.home.path(), || fx.ctx());
    write_files(fx.project.path(), &[("blåbær/日本語.txt", "allowed\n")]);
    commit_all(fx.project.path());
    add(&ctx, "unicode", "HEAD").unwrap();
    assert_eq!(
        std::fs::read_to_string(fx.root.join("unicode/blåbær/日本語.txt")).unwrap(),
        "allowed\n"
    );
}

#[test]
fn launch_head_cannot_approve_protected_content_not_checked_out() {
    let fx = Fixture::new(&tracked_files());
    write_files(
        fx.project.path(),
        &[(".github/hooks/pre.sh", "echo malicious\n")],
    );
    commit_all(fx.project.path());
    write_files(
        fx.project.path(),
        &[(".github/hooks/pre.sh", "echo hook\n")],
    );
    let err = with_home(fx.home.path(), || {
        Context::new(fx.project.path(), &fx.common, &fx.root)
    })
    .unwrap_err();
    assert!(
        err.contains("protected launch bytes differ from HEAD"),
        "{err}"
    );
    let fx = Fixture::new(&[]);
    write_files(fx.project.path(), &[(".claude/settings.json", "{}\n")]);
    commit_all(fx.project.path());
    std::fs::remove_file(fx.project.path().join(".claude/settings.json")).unwrap();
    assert!(
        Context::new(fx.project.path(), &fx.common, &fx.root)
            .unwrap_err()
            .contains("protected filesystem content differs")
    );
}

#[test]
fn local_protected_config_and_ignored_dependencies_are_not_part_of_the_snapshot() {
    let fx = Fixture::new(&tracked_files());
    write_files(
        fx.project.path(),
        &[
            (".claude/settings.local.json", "{}\n"),
            ("node_modules/dependency/.claude/settings.json", "{}\n"),
        ],
    );
    let ctx = with_home(fx.home.path(), || fx.ctx());
    add(&ctx, "clean", "HEAD").unwrap();
    assert!(!fx.root.join("clean/.claude/settings.local.json").exists());
    assert!(!fx.root.join("clean/node_modules").exists());
}

#[test]
fn launch_protected_aliases_and_mode_mismatch_are_refused() {
    let fx = Fixture::new(&[]);
    write_files(fx.project.path(), &[(".claude/ſettings.json", "{}\n")]);
    commit_all(fx.project.path());
    assert!(
        Context::new(fx.project.path(), &fx.common, &fx.root)
            .unwrap_err()
            .contains("alias")
    );
    let fx = Fixture::new(&tracked_files());
    std::fs::set_permissions(
        fx.project.path().join(".github/hooks/pre.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(
        Context::new(fx.project.path(), &fx.common, &fx.root)
            .unwrap_err()
            .contains("mode differs")
    );
}

#[test]
fn launch_protected_fifo_and_symlink_are_never_read() {
    use std::os::unix::ffi::OsStrExt;
    for fifo in [false, true] {
        let fx = Fixture::new(&tracked_files());
        let hook = fx.project.path().join(".github/hooks/pre.sh");
        std::fs::remove_file(&hook).unwrap();
        if fifo {
            let name = std::ffi::CString::new(hook.as_os_str().as_bytes()).unwrap();
            // SAFETY: name is a live NUL-terminated filename.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        } else {
            symlink("/etc/passwd", hook).unwrap();
        }
        let started = Instant::now();
        assert!(Context::new(fx.project.path(), &fx.common, &fx.root).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}

#[test]
fn protected_content_is_frozen_before_refs_can_move() {
    for (label, path, body) in [
        ("new settings", ".claude/settings.json", "{\"hooks\":{}}\n"),
        ("changed hook", ".github/hooks/pre.sh", "echo attacker\n"),
        ("case alias", ".ClAuDe/SeTtInGs.JsOn", "{}\n"),
        (
            "nested config",
            "sub/.opencode/plugins/evil.ts",
            "throw 1;\n",
        ),
        ("nested cplt", "sub/.cplt.toml", "[propose]\n"),
    ] {
        let fx = Fixture::new(&tracked_files());
        let ctx = with_home(fx.home.path(), || fx.ctx());
        write_files(fx.project.path(), &[(path, body)]);
        commit_all(fx.project.path());
        let err = add(&ctx, "wt1", "HEAD").expect_err(label);
        assert!(
            err.contains("protected config differs from launch HEAD"),
            "{label}: {err}"
        );
        assert!(!fx.root.join("wt1").exists());
        assert!(fx.admin_entries().is_empty());
    }
}

#[test]
fn deleting_or_changing_the_mode_of_protected_content_is_refused() {
    for remove in [true, false] {
        let fx = Fixture::new(&tracked_files());
        let ctx = with_home(fx.home.path(), || fx.ctx());
        let hook = fx.project.path().join(".github/hooks/pre.sh");
        if remove {
            std::fs::remove_file(hook).unwrap();
        } else {
            std::fs::set_permissions(hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        commit_all(fx.project.path());
        assert!(
            add(&ctx, "wt1", "HEAD")
                .unwrap_err()
                .contains("protected config differs")
        );
    }
}

#[test]
fn ordinary_new_files_are_allowed_with_original_protected_content() {
    let fx = Fixture::new(&tracked_files());
    let ctx = with_home(fx.home.path(), || fx.ctx());
    write_files(fx.project.path(), &[("new.txt", "ordinary\n")]);
    commit_all(fx.project.path());
    add(&ctx, "wt1", "HEAD").unwrap();
    for (path, body) in tracked_files()
        .into_iter()
        .chain([("new.txt", "ordinary\n")])
    {
        assert_eq!(
            std::fs::read_to_string(fx.root.join("wt1").join(path)).unwrap(),
            body
        );
    }
}

#[test]
fn baseline_uses_the_linked_launch_head_not_the_common_head() {
    let fx = Fixture::new(&tracked_files());
    let linked = fx.project.path().join("launch");
    assert!(common::git_ok(
        fx.project.path(),
        &[
            "worktree",
            "add",
            "--detach",
            linked.to_str().unwrap(),
            "HEAD"
        ]
    ));
    write_files(&linked, &[(".cplt.toml", "[deny]\npaths = []\n")]);
    commit_all(&linked);
    let ctx = with_home(fx.home.path(), || {
        let ctx = Context::new(&linked, &fx.common, &fx.root).unwrap();
        ctx.set_read_policy("(version 1)\n(allow default)\n")
            .unwrap();
        ctx
    });
    let head = common::git_cmd(&linked)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let sha = String::from_utf8(head.stdout).unwrap();
    add(&ctx, "linked", sha.trim()).unwrap();
    assert_eq!(
        std::fs::read_to_string(fx.root.join("linked/.cplt.toml")).unwrap(),
        "[deny]\npaths = []\n"
    );
    assert!(
        add(&ctx, "common", "HEAD")
            .unwrap_err()
            .contains("protected config differs")
    );
}

#[test]
fn symlink_ancestors_of_protected_paths_fail_closed() {
    for path in [".claude", "sub/.GitHub", "sub/.opencode/plugins"] {
        let fx = Fixture::new(&tracked_files());
        let ctx = with_home(fx.home.path(), || fx.ctx());
        let target = fx.project.path().join(path);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        symlink("safe", target).unwrap();
        commit_all(fx.project.path());
        assert!(
            add(&ctx, "wt1", "HEAD")
                .unwrap_err()
                .contains("protected config must be a regular tracked file")
        );
    }
}

#[test]
fn attributes_cannot_transform_unchanged_protected_blobs() {
    let fx = Fixture::new(&[
        (".cplt.toml", "[propose]\n"),
        (".github/hooks/pre.sh", "echo $Id$\n"),
    ]);
    let ctx = with_home(fx.home.path(), || fx.ctx());
    write_files(
        fx.project.path(),
        &[(".gitattributes", ".github/hooks/pre.sh ident\n")],
    );
    commit_all(fx.project.path());
    let err = add(&ctx, "wt1", "HEAD").unwrap_err();
    assert!(
        err.contains("protected checkout bytes differ from launch HEAD"),
        "{err}"
    );
    assert!(fx.admin_entries().is_empty());
    assert!(!fx.root.join("wt1").exists());
}

/// Socket length is independent of HOME, even with a long checkout path.
#[test]
fn a_long_home_uses_a_short_private_socket_directory() {
    let home = tempfile::Builder::new()
        .prefix(&format!(".cplt-long-{}-", "h".repeat(70)))
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    let fx = Fixture::in_home(home, &tracked_files());
    let broker = with_home(fx.home.path(), || Broker::start(fx.ctx())).expect("short socket");
    assert!(broker.socket().as_os_str().len() <= 103);
    let reply = send(
        broker.socket(),
        b"{\"op\":\"add\",\"name\":\"long-home\",\"ref\":\"HEAD\"}\n",
    );
    assert!(reply.contains("\"ok\":true"), "{reply}");
    assert!(
        fx.add("wt1", "HEAD").is_ok(),
        "the request path itself is not limited by the home length"
    );
}

#[test]
fn adds_a_detached_worktree_with_the_complete_checkout() {
    let fx = Fixture::new(&tracked_files());
    // An in-tree link is allowed: its target stays inside the worktree.
    std::fs::create_dir_all(fx.project.path().join("docs")).unwrap();
    symlink("../src/a.txt", fx.project.path().join("docs/link-ok")).unwrap();
    commit_all(fx.project.path());
    let path = fx.add("wt1", "HEAD").expect("add");
    let wt = PathBuf::from(&path);
    assert_eq!(wt, fx.root.join("wt1"));
    for (rel, body) in tracked_files() {
        assert_eq!(
            std::fs::read_to_string(wt.join(rel)).unwrap(),
            body,
            "{rel}"
        );
    }
    assert_eq!(
        std::fs::read_link(wt.join("docs/link-ok")).unwrap(),
        PathBuf::from("../src/a.txt")
    );
    let status = common::git_cmd(&wt)
        .args(["status", "--porcelain"])
        .output()
        .unwrap();
    assert!(status.stdout.is_empty(), "clean checkout: {status:?}");
    let head = common::git_cmd(&wt)
        .args(["symbolic-ref", "--quiet", "HEAD"])
        .output()
        .unwrap();
    assert!(!head.status.success(), "detached HEAD, no branch created");
    let pointer = std::fs::read_to_string(wt.join(".git")).unwrap();
    let admin = pointer.trim().strip_prefix("gitdir: ").unwrap();
    let back = std::fs::read_to_string(Path::new(admin).join("gitdir")).unwrap();
    assert_eq!(back, format!("{}\n", wt.join(".git").display()));
    assert_eq!(
        std::fs::read_dir(fx.base().join(".staging"))
            .unwrap()
            .count(),
        0,
        "staging is emptied on success"
    );
    assert!(fx.add("wt1", "HEAD").is_err(), "name already taken");
}

#[test]
fn a_post_checkout_hook_never_runs() {
    let fx = Fixture::new(&tracked_files());
    let marker = fx.home.path().join("hook-ran");
    let hook = fx.common.join("hooks/post-checkout");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    fx.add("wt1", "HEAD").expect("add");
    assert!(
        !marker.exists(),
        "core.hooksPath=/dev/null keeps hooks from running"
    );
}

#[test]
fn refuses_a_filter_driver_in_repository_config_and_writes_nothing() {
    let fx = Fixture::new(&tracked_files());
    let marker = fx.home.path().join("filter-ran");
    assert!(common::git_ok(
        fx.project.path(),
        &[
            "config",
            "filter.evil.smudge",
            &format!("touch '{}' && cat", marker.display()),
        ]
    ));
    std::fs::write(fx.project.path().join(".gitattributes"), "* filter=evil\n").unwrap();
    commit_all(fx.project.path());
    let err = fx.add("wt1", "HEAD").expect_err("filter refused");
    assert!(err.contains("content filter"), "{err}");
    assert!(err.contains("filter.evil.smudge"), "names the key: {err}");
    assert!(!marker.exists(), "the smudge driver never ran");
    assert!(!fx.root.join("wt1").exists());
    assert!(fx.admin_entries().is_empty(), "{:?}", fx.admin_entries());
}

#[test]
fn refuses_a_filter_driver_in_the_global_config() {
    let fx = Fixture::new(&tracked_files());
    std::fs::write(
        fx.home.path().join(".gitconfig"),
        "[filter \"evil\"]\n\tsmudge = cat\n",
    )
    .unwrap();
    let err = fx.add("wt1", "HEAD").expect_err("global filter refused");
    assert!(err.contains("content filter"), "{err}");
    assert!(!fx.root.join("wt1").exists());
}

#[test]
fn filters_in_included_config_are_refused() {
    let fx = Fixture::new(&tracked_files());
    let included = fx.home.path().join("included-config");
    std::fs::write(&included, "[filter \"included\"]\nsmudge = cat\n").unwrap();
    assert!(common::git_ok(
        fx.project.path(),
        &["config", "include.path", included.to_str().unwrap()]
    ));
    let err = fx.add("wt1", "HEAD").unwrap_err();
    assert!(err.contains("filter.included.smudge"), "{err}");
    assert!(fx.admin_entries().is_empty());
}

#[test]
fn refuses_links_that_leave_the_tree_and_bare_repositories() {
    for (label, target) in [
        ("absolute symlink", "/etc/passwd"),
        ("escaping relative symlink", "../../../../../../etc"),
    ] {
        let fx = Fixture::new(&tracked_files());
        symlink(target, fx.project.path().join("evil")).unwrap();
        commit_all(fx.project.path());
        let err = fx.add("wt1", "HEAD").expect_err(label);
        assert!(
            err.contains("points outside the worktree"),
            "{label}: {err}"
        );
        assert!(!fx.root.join("wt1").exists(), "{label}");
        assert!(
            fx.admin_entries().is_empty(),
            "{label}: {:?}",
            fx.admin_entries()
        );
    }

    let fx = Fixture::new(&tracked_files());
    write_files(
        fx.project.path(),
        &[
            ("sub/HEAD", "ref: refs/heads/main\n"),
            ("sub/objects/keep", "x"),
            ("sub/refs/keep", "x"),
        ],
    );
    commit_all(fx.project.path());
    let err = fx.add("wt1", "HEAD").expect_err("bare repo refused");
    assert!(err.contains("bare git repository"), "{err}");
    assert!(!fx.root.join("wt1").exists());
}

#[test]
fn rejects_hostile_names_and_refs_before_git_runs() {
    for bad in [
        ".git", "..", "../x", "a/b", "-x", "", "a..b", "x.lock", ".hidden",
    ] {
        assert!(validate_name(bad).is_err(), "name {bad:?}");
    }
    for bad in [
        "-b",
        "--upload-pack=x",
        "../x",
        "a..b",
        "main;rm",
        "",
        "a//b",
        "x.lock",
        "a b",
    ] {
        assert!(validate_reference(bad).is_err(), "ref {bad:?}");
    }
    assert!(validate_name("feature-1.x_2").is_ok());
    assert!(validate_reference("feature/x-1").is_ok());

    let fx = Fixture::new(&tracked_files());
    assert!(fx.add("../escape", "HEAD").is_err());
    assert!(fx.add("ok", "--upload-pack=sh").is_err());
    assert!(fx.admin_entries().is_empty());
    assert!(!fx.root.parent().unwrap().join("escape").exists());
}

#[test]
fn an_unknown_ref_creates_nothing() {
    let fx = Fixture::new(&tracked_files());
    let err = fx.add("wt1", "no-such-ref").expect_err("unknown ref");
    assert!(err.contains("does not name a commit"), "{err}");
    assert!(fx.admin_entries().is_empty());
    assert_eq!(std::fs::read_dir(&fx.root).unwrap().count(), 0);
}

#[test]
fn requests_fail_closed_until_the_session_read_policy_is_installed() {
    let fx = Fixture::new(&tracked_files());
    let ctx = Context::new(fx.project.path(), &fx.common, &fx.root).unwrap();
    let err = add(&ctx, "wt1", "HEAD").unwrap_err();
    assert!(
        err.contains("session read policy is not installed"),
        "{err}"
    );
    assert!(fx.admin_entries().is_empty());
    assert!(!fx.root.join("wt1").exists());
    ctx.set_read_policy("(version 1)\n(allow default)\n")
        .unwrap();
    assert!(
        ctx.set_read_policy("(version 1)\n(allow default)\n")
            .is_err()
    );
}

#[test]
fn an_existing_destination_is_not_replaced_and_the_admin_dir_is_rolled_back() {
    let fx = Fixture::new(&tracked_files());
    let decoy = fx.root.join("wt1");
    std::fs::create_dir_all(&decoy).unwrap();
    std::fs::write(decoy.join("mine.txt"), "keep\n").unwrap();
    let before = fx.admin_entries();
    let err = fx.add("wt1", "HEAD").expect_err("destination exists");
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(
        std::fs::read_to_string(decoy.join("mine.txt")).unwrap(),
        "keep\n"
    );
    assert_eq!(fx.admin_entries(), before, "no admin dir left behind");
    assert_eq!(
        std::fs::read_dir(fx.base().join(".staging"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn replaced_launch_commondir_cannot_select_a_fake_filter_repository() {
    let fx = Fixture::new(&tracked_files());
    let linked = fx.project.path().join("launch");
    assert!(common::git_ok(
        fx.project.path(),
        &[
            "worktree",
            "add",
            "--detach",
            linked.to_str().unwrap(),
            "HEAD"
        ]
    ));
    let ctx = with_home(fx.home.path(), || {
        let ctx = Context::new(&linked, &fx.common, &fx.root).unwrap();
        ctx.set_read_policy("(version 1)\n(allow default)\n")
            .unwrap();
        ctx
    });
    let fake = common::temp_repo("navikt/fake-broker-repo");
    write_files(
        fake.path(),
        &[
            ("src/a.txt", "wrong repository\n"),
            (".gitattributes", "* filter=evil\n"),
        ],
    );
    commit_all(fake.path());
    let marker = fx.home.path().join("fake-filter-ran");
    assert!(common::git_ok(
        fake.path(),
        &[
            "config",
            "filter.evil.smudge",
            &format!("touch '{}' && cat", marker.display())
        ]
    ));
    std::fs::write(
        fx.common.join("worktrees/launch/commondir"),
        format!("{}\n", fake.path().join(".git").display()),
    )
    .unwrap();
    with_home(fx.home.path(), || add(&ctx, "wt1", "HEAD")).expect("pinned common repository");
    assert_eq!(
        std::fs::read_to_string(fx.root.join("wt1/src/a.txt")).unwrap(),
        "alpha\n"
    );
    assert!(!marker.exists(), "fake config was never used by checkout");
}

#[test]
fn common_filter_added_after_preflight_never_executes() {
    let fx = Fixture::new(&[(".gitattributes", "* filter=evil\n"), ("data", "raw\n")]);
    // Enough checkout work to keep the private directory visible to the writer.
    for n in 0..2000 {
        std::fs::write(fx.project.path().join(format!("file-{n}")), "raw\n").unwrap();
    }
    commit_all(fx.project.path());
    let marker = fx.home.path().join("raced-filter-ran");
    let staging = fx.base().join(".staging");
    let config = fx.common.join("config");
    let original = std::fs::read_to_string(&config).unwrap();
    let malicious = format!(
        "{original}\n[filter \"evil\"]\nsmudge = touch '{}' && cat\nprocess = touch '{}'\n",
        marker.display(),
        marker.display()
    );
    let writer = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            // Context construction also uses staging for launch-byte copies.
            // Only the request's private admin proves preflight has finished.
            if std::fs::read_dir(&staging).is_ok_and(|entries| {
                entries
                    .flatten()
                    .any(|entry| entry.path().join(".git-admin/HEAD").is_file())
            }) {
                std::fs::write(&config, malicious).unwrap();
                return;
            }
            assert!(
                Instant::now() < deadline,
                "checkout did not reach private staging"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let result = fx.add("wt1", "HEAD");
    writer.join().unwrap();
    result.expect("config changed only after preflight");
    assert!(
        !marker.exists(),
        "neither smudge nor process runs on the host"
    );
    assert_eq!(
        std::fs::read_to_string(fx.root.join("wt1/data")).unwrap(),
        "raw\n"
    );
}

#[test]
fn a_symlink_or_fifo_worktrees_namespace_is_never_followed() {
    for fifo in [false, true] {
        let fx = Fixture::new(&tracked_files());
        let path = fx.common.join("worktrees");
        let victim = tempfile::tempdir().unwrap();
        std::fs::write(victim.path().join("keep"), "untouched\n").unwrap();
        if fifo {
            use std::os::unix::ffi::OsStrExt;
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: path is a live NUL-terminated filename.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        } else {
            symlink(victim.path(), &path).unwrap();
        }
        let started = Instant::now();
        assert!(fx.add("wt1", "HEAD").is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(std::fs::read_dir(victim.path()).unwrap().count(), 1);
        assert!(!fx.root.join("wt1").exists());
    }
}

#[test]
fn lock_wait_and_partial_request_are_cancelled_on_shutdown() {
    use std::os::unix::io::AsRawFd;
    let fx = Fixture::new(&tracked_files());
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(fx.base().join(".lock"))
        .unwrap();
    // SAFETY: lock owns the descriptor.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let broker = with_home(fx.home.path(), || Broker::start(fx.ctx())).unwrap();
    let mut stream = UnixStream::connect(broker.socket()).unwrap();
    stream
        .write_all(b"{\"op\":\"add\",\"name\":\"blocked\",\"ref\":\"HEAD\"}\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    drop(broker);
    assert!(started.elapsed() < Duration::from_secs(2));
    let broker = with_home(fx.home.path(), || Broker::start(fx.ctx())).unwrap();
    let mut stream = UnixStream::connect(broker.socket()).unwrap();
    stream.write_all(b"{").unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    drop(broker);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn slow_request_bytes_do_not_restart_the_read_deadline() {
    let fx = Fixture::new(&tracked_files());
    let broker = with_home(fx.home.path(), || Broker::start(fx.ctx())).unwrap();
    let mut stream = UnixStream::connect(broker.socket()).unwrap();
    stream.set_nonblocking(true).unwrap();
    let started = Instant::now();
    let mut reply = String::new();
    for _ in 0..11 {
        match stream.write_all(b" ") {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                assert!(
                    started.elapsed() >= Duration::from_secs(10),
                    "broker closed before the read deadline: {e}"
                );
                break;
            }
            Err(e) => panic!("unexpected request write failure: {e}"),
        }
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => {
                assert!(started.elapsed() >= Duration::from_secs(10), "early EOF");
                break;
            }
            Ok(_) => {
                assert!(
                    started.elapsed() >= Duration::from_secs(10),
                    "early response"
                );
                reply.push(char::from(byte[0]));
                break;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => panic!("unexpected request read failure: {e}"),
        }
        std::thread::sleep(Duration::from_millis(950));
    }
    while !reply.ends_with('\n') {
        assert!(
            started.elapsed() < Duration::from_secs(13),
            "deadline restarted"
        );
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => reply.push(char::from(byte[0])),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("unexpected reply read failure: {e}"),
        }
    }
    // EOF without a reply is valid once the deadline closes the peer. Any
    // response must still identify the deadline, not an unrelated refusal.
    assert!(
        reply.is_empty() || reply.contains("request read deadline exceeded"),
        "{reply}"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(10),
        "early deadline: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(13),
        "deadline restarted: {elapsed:?}"
    );
}

#[test]
fn a_missing_blob_never_fetches_from_a_configured_promisor() {
    let fx = Fixture::new(&[("missing", "missing blob\n")]);
    let out = common::git_cmd(fx.project.path())
        .args(["rev-parse", "HEAD:missing"])
        .output()
        .unwrap();
    let blob = String::from_utf8(out.stdout).unwrap();
    let blob = blob.trim();
    std::fs::remove_file(fx.common.join("objects").join(&blob[..2]).join(&blob[2..])).unwrap();
    let marker = fx.home.path().join("fetch-ran");
    let helper = fx.home.path().join("fetch-helper");
    std::fs::write(
        &helper,
        format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    for (key, value) in [
        ("remote.evil.promisor", "true".to_string()),
        ("remote.evil.url", format!("ext::{}", helper.display())),
        ("protocol.ext.allow", "always".to_string()),
    ] {
        assert!(common::git_ok(fx.project.path(), &["config", key, &value]));
    }
    assert!(fx.add("wt1", "HEAD").is_err(), "missing blob fails closed");
    assert!(!marker.exists());
    assert!(fx.admin_entries().is_empty());
    assert!(!fx.root.join("wt1").exists());
}

#[test]
fn the_socket_serves_one_request_and_shuts_down() {
    let fx = Fixture::new(&tracked_files());
    let broker = with_home(fx.home.path(), || Broker::start(fx.ctx())).expect("start");
    let socket = broker.socket().to_path_buf();
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket is private to the user");
    let dir_mode = std::fs::metadata(socket.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);

    let reply = send(
        &socket,
        b"{\"op\":\"add\",\"name\":\"wt2\",\"ref\":\"HEAD\"}\n",
    );
    assert!(reply.contains("\"ok\":true"), "{reply}");
    assert!(reply.contains("wt2"), "{reply}");
    let bad = send(
        &socket,
        b"{\"op\":\"remove\",\"name\":\"wt2\",\"ref\":\"HEAD\"}\n",
    );
    assert!(bad.contains("unknown operation"), "{bad}");
    let extra = send(
        &socket,
        b"{\"op\":\"add\",\"name\":\"x\",\"ref\":\"HEAD\",\"path\":\"/\"}\n",
    );
    assert!(
        extra.contains("\"ok\":false"),
        "unknown fields refused: {extra}"
    );
    let huge = format!("{{\"op\":\"add\",\"name\":\"{}\"}}\n", "a".repeat(5000));
    let big = send(&socket, huge.as_bytes());
    assert!(big.contains("\"ok\":false"), "{big}");

    let started = Instant::now();
    drop(broker);
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "shutdown is bounded"
    );
    assert!(!socket.exists(), "socket removed on shutdown");
}

fn send(socket: &Path, line: &[u8]) -> String {
    let mut stream = UnixStream::connect(socket).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream.write_all(line).unwrap();
    let mut reply = String::new();
    BufReader::new(&stream).read_line(&mut reply).unwrap();
    reply
}
