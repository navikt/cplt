//! Managed Git worktree root for sub-agents (`sandbox.allow_git_worktrees`, #531).
//!
//! The sandbox policy is fixed at launch, so an agent cannot create a worktree
//! outside the checkout unless the destination was granted up front. This
//! module owns that destination: one directory per local repository,
//! `~/.cplt-worktrees/<fingerprint>`, granted read, write and execute exactly
//! like a `--repo-dir` root. The shared parent is never granted, so the roots
//! of other repositories stay out of reach.
//!
//! The path is derived, never configured: a user-chosen parent (`~/src`) would
//! expose every sibling checkout as a write-then-exec area.
//!
//! cplt creates the root and never removes it or anything in it. Worktrees and
//! branches persist across sessions on purpose; deleting them on exit would
//! destroy work a resumed session expects to find.

use std::path::{Path, PathBuf};

/// The environment variable the sandboxed agent reads the root from.
pub const ENV: &str = "CPLT_WORKTREE_ROOT";

/// Home-relative parent of every per-repository root. Never granted itself.
pub const BASE: &str = ".cplt-worktrees";

/// Refuse the key on any OS but macOS.
///
/// macOS denies the protected paths at any depth below a granted root with a
/// regex. Linux has no equivalent: Landlock cannot subtract a path from a
/// granted tree, and bubblewrap re-binds read-only only paths that exist at
/// launch, at fixed depths (`<root>/<rel>`), never `<root>/<worktree>/<rel>`.
/// So nothing inside the root would be kernel-enforced, and the key is
/// macOS-only until that changes. `os` is `std::env::consts::OS`, passed in so
/// the refusal is testable on either host.
pub fn refuse_unsupported_os(os: &str) -> Result<(), String> {
    if os == "macos" {
        return Ok(());
    }
    Err(format!(
        "sandbox.allow_git_worktrees is macOS-only for now. On {os}, nothing inside the \
         worktree root would be kernel-enforced: Landlock cannot subtract paths from a granted \
         tree, so .git pointers, hooks and agent config inside the worktrees would all be \
         writable"
    ))
}

/// The canonical common Git directory of the repository at `project_dir`,
/// checked against steering. `Ok(None)` when `project_dir` is not in a
/// repository at all.
///
/// The fingerprint below decides which root is granted, so this is a grant
/// input, not a deny input like [`crate::discover::git_dir_of`]. git derives
/// `--git-common-dir` from a `commondir` file inside the gitdir, and the gitdir
/// of a linked worktree sits in a tree the agent can write. A planted value
/// would point this launch at another repository's root. So only the two
/// layouts git itself produces are accepted, the same rule
/// [`crate::discover::git_common_dir`] applies: the common dir is the gitdir,
/// or the gitdir is `<common>/worktrees/<name>`.
pub fn repository_common_dir(project_dir: &Path) -> Result<Option<PathBuf>, String> {
    let run = |arg: &str| -> Result<Option<PathBuf>, String> {
        let out = crate::git::command(project_dir, &["rev-parse", arg])
            .ok_or("no trusted git binary to identify the repository")?
            .output()
            .map_err(|e| format!("cannot run git: {e}"))?;
        if !out.status.success() {
            return Ok(None);
        }
        let raw = String::from_utf8_lossy(&out.stdout);
        resolve(project_dir, raw.trim()).map(Some)
    };
    let (Some(common), Some(git_dir)) = (run("--git-common-dir")?, run("--absolute-git-dir")?)
    else {
        return Ok(None);
    };
    let linked = git_dir.parent().filter(|p| p.ends_with("worktrees"));
    if common == git_dir || linked.and_then(Path::parent) == Some(common.as_path()) {
        Ok(Some(common))
    } else {
        Err(format!(
            "the repository's common git directory {} is not where its gitdir {} says it \
             should be (a steered `commondir`?)",
            common.display(),
            git_dir.display()
        ))
    }
}

/// The root's directory name: the first 128 bits of SHA-256 over the canonical
/// common dir.
///
/// A local path, never the remote URL: two clones of the same GitHub
/// repository are different repositories on disk and must not share a root.
/// Every linked worktree of one repository resolves to the same common dir, so
/// they share it, which is the same repository identity trust approval uses
/// since #527.
#[must_use]
pub fn fingerprint(common_dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    Sha256::digest(common_dir.as_os_str().as_bytes())[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Create (or reuse) and validate this repository's root, returning its
/// canonical path.
///
/// Every check runs on every launch, not only on creation: the root is
/// agent-writable, so the agent can remove it and leave a symlink in its
/// place. That is refused here rather than followed.
///
/// - `~/.cplt-worktrees` and the root must be real directories (no symlink),
///   owned by this user; both are set to mode 0700.
/// - The canonical root must equal `<canonical home>/.cplt-worktrees/<fp>`,
///   which rules out a symlinked ancestor below home.
/// - The path must be safe to interpolate into an SBPL profile.
/// - The worktree links must be intact ([`link_problems`]).
///
/// `create` is false for `doctor` and `check`, which report on the root and
/// must not create it. `Ok(None)` means `project_dir` is not in a repository;
/// the caller decides whether that fails the launch.
pub fn prepare_root(
    home_dir: &Path,
    project_dir: &Path,
    create: bool,
) -> Result<Option<PathBuf>, String> {
    let Some(common) = repository_common_dir(project_dir)? else {
        return Ok(None);
    };
    let root = prepare_root_for(home_dir, &common, create)?;
    let problems = link_problems(&common, &root);
    if !problems.is_empty() {
        return Err(format!(
            "the worktree links of this repository do not match what git writes, so git \
             run outside cplt could read agent-written config:\n    {}\n  Inspect them outside \
             cplt and remove the worktrees involved (`git worktree remove --force`, or delete \
             the directories and run `git worktree prune`)",
            problems.join("\n    ")
        ));
    }
    Ok(Some(root))
}

/// [`prepare_root`] once the repository is known. Split out so the path checks
/// can be tested without a repository.
pub fn prepare_root_for(
    home_dir: &Path,
    common_dir: &Path,
    create: bool,
) -> Result<PathBuf, String> {
    let home = std::fs::canonicalize(home_dir)
        .map_err(|e| format!("cannot resolve home {}: {e}", home_dir.display()))?;
    let base = home.join(BASE);
    let root = base.join(fingerprint(common_dir));
    for (dir, label) in [(&base, "worktree base"), (&root, "worktree root")] {
        if !create && dir.symlink_metadata().is_err() {
            // Nothing there yet, and a report must not create it. The launch
            // will, and runs every check then.
            return Ok(root.clone());
        }
        secure_dir(dir, label)?;
    }
    let canonical = std::fs::canonicalize(&root)
        .map_err(|e| format!("cannot resolve {}: {e}", root.display()))?;
    if canonical != root {
        return Err(format!(
            "worktree root resolved to {} but expected {}",
            canonical.display(),
            root.display()
        ));
    }
    crate::sandbox::validate_sbpl_path(&root).map_err(|e| format!("worktree root: {e}"))?;
    Ok(root)
}

/// Create `dir` if absent, then check and fix it through one descriptor.
///
/// Opened `O_NOFOLLOW | O_DIRECTORY`, so a symlink or a file in its place is
/// refused by the kernel rather than by a separate `lstat`, and the owner
/// check and `fchmod` apply to the directory that was opened, not to whatever
/// the name points at by then.
fn secure_dir(dir: &Path, label: &str) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            return Err(format!("cannot create {label} {}: {e}", dir.display()));
        }
        _ => {}
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
        .map_err(|e| {
            // macOS reports a symlink as ENOTDIR here, Linux as ELOOP; the
            // lstat only picks the message, the open already refused it.
            let link = dir
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink());
            match e.raw_os_error() {
                Some(libc::ELOOP | libc::ENOTDIR) if link => format!(
                    "{label} {} is a symlink, cplt refuses to use it",
                    dir.display()
                ),
                Some(libc::ENOTDIR) => format!("{label} {} is not a directory", dir.display()),
                _ => format!("cannot open {label} {}: {e}", dir.display()),
            }
        })?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat {label} {}: {e}", dir.display()))?;
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    if meta.uid() != uid {
        return Err(format!(
            "{label} {} is owned by uid {}, not {uid}. cplt refuses to use it",
            dir.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o777 != 0o700 {
        // `File::set_permissions` is fchmod on this descriptor.
        file.set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot set permissions on {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// `raw` as a canonical path, relative to `base` when not absolute.
fn resolve(base: &Path, raw: &str) -> Result<PathBuf, String> {
    let p = Path::new(raw);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    };
    std::fs::canonicalize(&abs).map_err(|e| format!("cannot resolve {}: {e}", abs.display()))
}

fn entries(dir: &Path) -> Vec<std::fs::DirEntry> {
    std::fs::read_dir(dir)
        .map(|it| it.flatten().collect())
        .unwrap_or_default()
}

/// Every way the agent-writable worktree bookkeeping can differ from what
/// `git worktree add` writes, one line per finding. Empty when intact.
///
/// Two links decide which config and hooks git on the host reads, and the
/// agent can write both:
///
/// - `<common>/worktrees/<name>/commondir` must lead back to `common`. Aimed
///   at `<root>/x/`, git reads `<root>/x/config` (`core.fsmonitor`). Missing,
///   git treats the admin dir itself as the common dir and reads its `config`.
///   The kernel only refuses an in-place rewrite; unlink-and-recreate and new
///   admin dirs are caught here.
/// - `<root>/<name>/.git` must be a pointer file naming an admin dir under
///   `<common>/worktrees` whose `gitdir` names this pointer back. A pointer
///   the agent recreated (`mv wt wt.old && mkdir wt && echo gitdir: ...`) can
///   name a gitdir in the root, where config and hooks are writable.
///
/// Only `<root>/*/.git` is checked, the depth `git worktree add
/// "$CPLT_WORKTREE_ROOT/<name>"` writes.
#[must_use]
pub fn link_problems(common: &Path, root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let admin = common.join("worktrees");
    if admin.symlink_metadata().is_ok_and(|m| !m.is_dir()) {
        out.push(format!("{} is not a directory", admin.display()));
        return out;
    }
    for entry in entries(&admin) {
        let dir = entry.path();
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            out.push(format!("{} is not a directory", dir.display()));
            continue;
        }
        let file = dir.join("commondir");
        match std::fs::read_to_string(&file) {
            Ok(raw) => match resolve(&dir, raw.trim()) {
                Ok(p) if p == common => {}
                Ok(p) => out.push(format!(
                    "{} points at {}, not {}",
                    file.display(),
                    p.display(),
                    common.display()
                )),
                Err(e) => out.push(format!("{}: {e}", file.display())),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => out.push(format!(
                "{} is missing, so git would read {}/config as repository config",
                file.display(),
                dir.display()
            )),
            Err(e) => out.push(format!("cannot read {}: {e}", file.display())),
        }
    }
    for entry in entries(root) {
        let pointer = entry.path().join(".git");
        let Ok(meta) = pointer.symlink_metadata() else {
            continue;
        };
        if !meta.is_file() {
            out.push(format!(
                "{} is not a gitdir pointer file",
                pointer.display()
            ));
            continue;
        }
        if let Err(e) = check_pointer(&pointer, &admin) {
            out.push(format!("{}: {e}", pointer.display()));
        }
    }
    out
}

/// One `<root>/<name>/.git` pointer against its admin dir, both directions.
fn check_pointer(pointer: &Path, admin: &Path) -> Result<(), String> {
    let raw = std::fs::read_to_string(pointer).map_err(|e| e.to_string())?;
    let target = raw
        .trim()
        .strip_prefix("gitdir:")
        .ok_or("not a `gitdir:` pointer")?;
    let wt = pointer.parent().unwrap_or(pointer);
    let gitdir = resolve(wt, target.trim())?;
    if gitdir.parent() != Some(admin) {
        return Err(format!(
            "names {}, which is not under {}",
            gitdir.display(),
            admin.display()
        ));
    }
    let back_file = gitdir.join("gitdir");
    let back = std::fs::read_to_string(&back_file)
        .map_err(|e| format!("cannot read {}: {e}", back_file.display()))?;
    let me = std::fs::canonicalize(pointer).map_err(|e| e.to_string())?;
    if resolve(&gitdir, back.trim()).ok().as_deref() != Some(me.as_path()) {
        return Err(format!(
            "{} does not name this pointer back",
            back_file.display()
        ));
    }
    Ok(())
}

/// [`link_problems`] for the end of a session, re-deriving the common dir.
/// A repository that no longer resolves is itself a finding.
#[must_use]
pub fn session_end_problems(project_dir: &Path, root: &Path) -> Vec<String> {
    match repository_common_dir(project_dir) {
        Ok(Some(common)) => link_problems(&common, root),
        Ok(None) => vec![format!(
            "{} no longer resolves as a git repository",
            project_dir.display()
        )],
        Err(e) => vec![e],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn fingerprint_is_per_common_dir() {
        let a = fingerprint(Path::new("/w/a/.git"));
        assert_eq!(a.len(), 32);
        assert_eq!(a, fingerprint(Path::new("/w/a/.git")));
        assert_ne!(a, fingerprint(Path::new("/w/b/.git")));
    }

    #[test]
    fn creates_a_private_root_and_reuses_it() {
        use std::os::unix::fs::PermissionsExt;
        let h = home();
        let root = prepare_root_for(h.path(), Path::new("/w/a/.git"), true).expect("created");
        let home = std::fs::canonicalize(h.path()).unwrap();
        assert_eq!(
            root,
            home.join(BASE).join(fingerprint(Path::new("/w/a/.git")))
        );
        for dir in [root.as_path(), root.parent().unwrap()] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
        }
        std::fs::write(root.join("keep"), "x").unwrap();
        assert_eq!(
            prepare_root_for(h.path(), Path::new("/w/a/.git"), true),
            Ok(root.clone())
        );
        assert!(
            root.join("keep").exists(),
            "an existing root is reused, never emptied"
        );
    }

    #[test]
    fn refuses_a_symlinked_root() {
        let h = home();
        let fp = fingerprint(Path::new("/w/a/.git"));
        let target = h.path().join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(h.path().join(BASE)).unwrap();
        std::os::unix::fs::symlink(&target, h.path().join(BASE).join(&fp)).unwrap();
        let err = prepare_root_for(h.path(), Path::new("/w/a/.git"), true).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
    }

    #[test]
    fn refuses_a_symlinked_base() {
        let h = home();
        let target = h.path().join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, h.path().join(BASE)).unwrap();
        let err = prepare_root_for(h.path(), Path::new("/w/a/.git"), true).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        assert!(
            std::fs::read_dir(&target).unwrap().next().is_none(),
            "nothing is created through the link"
        );
    }

    #[allow(clippy::disallowed_methods)] // test fixture setup, isolated config
    fn git_in(dir: &Path, args: &[&str]) -> bool {
        std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// A repository and its linked worktrees share one root (the #527
    /// identity); a separate clone does not; a planted `commondir` is refused
    /// rather than followed to another repository's root.
    #[test]
    fn repository_identity_follows_the_common_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let (main, other) = (base.join("main"), base.join("other"));
        for d in [&main, &other] {
            std::fs::create_dir_all(d).unwrap();
            if !git_in(d, &["init", "-q", "-b", "main"]) {
                eprintln!("SKIPPED: git unavailable");
                return;
            }
        }
        std::fs::write(main.join("f"), "x").unwrap();
        assert!(git_in(&main, &["add", "-A"]) && git_in(&main, &["commit", "-qm", "i"]));
        let wt = base.join("wt");
        assert!(git_in(
            &main,
            &["worktree", "add", "-q", "-b", "f", &wt.to_string_lossy()]
        ));

        let common = main.join(".git");
        assert_eq!(repository_common_dir(&main), Ok(Some(common.clone())));
        assert_eq!(repository_common_dir(&wt), Ok(Some(common)));
        assert_ne!(
            repository_common_dir(&other).map(|c| c.map(|c| fingerprint(&c))),
            repository_common_dir(&main).map(|c| c.map(|c| fingerprint(&c))),
        );

        std::fs::write(
            other.join(".git/commondir"),
            main.join(".git").to_string_lossy().as_bytes(),
        )
        .unwrap();
        let err = repository_common_dir(&other).unwrap_err();
        assert!(err.contains("steered"), "{err}");

        let plain = base.join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        assert_eq!(repository_common_dir(&plain), Ok(None));
    }

    #[test]
    fn refuses_a_file_in_place_of_the_root() {
        let h = home();
        std::fs::create_dir_all(h.path().join(BASE)).unwrap();
        let fp = fingerprint(Path::new("/w/a/.git"));
        std::fs::write(h.path().join(BASE).join(fp), "").unwrap();
        let err = prepare_root_for(h.path(), Path::new("/w/a/.git"), true).unwrap_err();
        assert!(err.contains("not a directory"), "{err}");
    }

    /// `doctor` and `check` report the root without creating it.
    #[test]
    fn a_report_does_not_create_the_root() {
        let h = home();
        let root = prepare_root_for(h.path(), Path::new("/w/a/.git"), false).expect("path");
        assert!(root.ends_with(fingerprint(Path::new("/w/a/.git"))));
        assert!(!h.path().join(BASE).exists());
    }

    /// Item 3 of the #574 review: the key is macOS-only.
    #[test]
    fn the_key_is_refused_off_macos() {
        assert_eq!(refuse_unsupported_os("macos"), Ok(()));
        let err = refuse_unsupported_os("linux").unwrap_err();
        assert!(err.contains("macOS-only"), "{err}");
    }

    /// A repository with one managed worktree, as `git worktree add` leaves it.
    /// Returns (common dir, root, worktree), or `None` without git.
    fn repo_with_worktree(base: &Path) -> Option<(PathBuf, PathBuf, PathBuf)> {
        let main = base.join("main");
        std::fs::create_dir_all(&main).unwrap();
        if !git_in(&main, &["init", "-q", "-b", "main"]) {
            return None;
        }
        std::fs::write(main.join("f"), "x").unwrap();
        assert!(git_in(&main, &["add", "-A"]) && git_in(&main, &["commit", "-qm", "i"]));
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let wt = root.join("wt");
        assert!(git_in(
            &main,
            &["worktree", "add", "-q", "-b", "f", &wt.to_string_lossy()]
        ));
        Some((main.join(".git"), root, wt))
    }

    /// Item 1: a per-worktree `commondir` aimed into the root (where the agent
    /// can write `config` with `core.fsmonitor`) is found, and so is one that
    /// was deleted.
    #[test]
    fn a_steered_worktree_commondir_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, _)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        assert_eq!(link_problems(&common, &root), Vec::<String>::new());

        let commondir = common.join("worktrees/wt/commondir");
        std::fs::create_dir_all(root.join("x")).unwrap();
        std::fs::write(&commondir, root.join("x").to_string_lossy().as_bytes()).unwrap();
        let problems = link_problems(&common, &root);
        assert!(
            problems.iter().any(|p| p.contains("commondir points at")),
            "{problems:?}"
        );

        std::fs::remove_file(&commondir).unwrap();
        let problems = link_problems(&common, &root);
        assert!(
            problems.iter().any(|p| p.contains("is missing")),
            "{problems:?}"
        );
    }

    /// Item 2: a `.git` pointer recreated to name a gitdir inside the root is
    /// found, and so is one whose admin dir does not name it back.
    #[test]
    fn a_recreated_worktree_pointer_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        std::fs::rename(&wt, root.join("wt.old")).unwrap();
        std::fs::create_dir_all(&wt).unwrap();
        let evil = root.join("g");
        std::fs::create_dir_all(&evil).unwrap();
        std::fs::write(wt.join(".git"), format!("gitdir: {}\n", evil.display())).unwrap();
        let problems = link_problems(&common, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("wt/.git") && p.contains("not under")),
            "{problems:?}"
        );

        // Pointing at the real admin dir from a second directory: the admin
        // dir names `wt.old/.git`, not this one.
        std::fs::remove_dir_all(&wt).unwrap();
        let copy = root.join("copy");
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(
            copy.join(".git"),
            format!("gitdir: {}\n", common.join("worktrees/wt").display()),
        )
        .unwrap();
        let problems = link_problems(&common, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("copy/.git") && p.contains("name this pointer back")),
            "{problems:?}"
        );
    }
}
