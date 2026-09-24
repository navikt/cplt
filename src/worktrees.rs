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

/// What Linux does not enforce inside the managed root. Printed at every Linux
/// launch with the key on, and restated in SECURITY.md.
///
/// macOS denies the protected paths at any depth below a granted root with a
/// regex. Linux has no equivalent: Landlock cannot subtract a path from a
/// granted tree, and bubblewrap re-binds read-only only paths that exist at
/// launch, at fixed depths (`<root>/<rel>`), never `<root>/<worktree>/<rel>`.
pub const LINUX_GAP: &str = "sandbox.allow_git_worktrees on Linux: the persistence denies \
    inside managed worktrees (.github/hooks, .claude/settings.json, .cplt.toml, .mcp.json, \
    the worktree's .git pointer, and the rest of the per-root list) are NOT enforced. Landlock \
    cannot subtract paths from the granted root, and bubblewrap only protects paths that exist \
    at launch at fixed depths. The shared .git/hooks of this repository keeps whatever \
    protection it already has (read-only under bubblewrap). Review managed worktrees before \
    running tools in them outside cplt.";

/// The canonical common Git directory of the repository at `project_dir`,
/// checked against steering.
///
/// The fingerprint below decides which root is granted, so this is a grant
/// input, not a deny input like [`crate::discover::git_dir_of`]. git derives
/// `--git-common-dir` from a `commondir` file inside the gitdir, and the gitdir
/// of a linked worktree sits in a tree the agent can write. A planted value
/// would point this launch at another repository's root. So only the two
/// layouts git itself produces are accepted, the same rule
/// [`crate::discover::git_common_dir`] applies: the common dir is the gitdir,
/// or the gitdir is `<common>/worktrees/<name>`.
pub fn repository_common_dir(project_dir: &Path) -> Result<PathBuf, String> {
    let run = |arg: &str| -> Result<PathBuf, String> {
        let out = crate::git::command(project_dir, &["rev-parse", arg])
            .ok_or("no trusted git binary to identify the repository")?
            .output()
            .map_err(|e| format!("cannot run git: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{} is not in a git repository",
                project_dir.display()
            ));
        }
        let raw = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        let abs = if raw.is_absolute() {
            raw
        } else {
            project_dir.join(raw)
        };
        std::fs::canonicalize(&abs).map_err(|e| format!("cannot resolve {}: {e}", abs.display()))
    };
    let common = run("--git-common-dir")?;
    let git_dir = run("--absolute-git-dir")?;
    let linked = git_dir.parent().filter(|p| p.ends_with("worktrees"));
    if common == git_dir || linked.and_then(Path::parent) == Some(common.as_path()) {
        Ok(common)
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
pub fn prepare_root(home_dir: &Path, project_dir: &Path) -> Result<PathBuf, String> {
    let common = repository_common_dir(project_dir)?;
    prepare_root_for(home_dir, &common)
}

/// [`prepare_root`] once the repository is known. Split out so the path checks
/// can be tested without a repository.
pub fn prepare_root_for(home_dir: &Path, common_dir: &Path) -> Result<PathBuf, String> {
    let home = std::fs::canonicalize(home_dir)
        .map_err(|e| format!("cannot resolve home {}: {e}", home_dir.display()))?;
    let base = home.join(BASE);
    let root = base.join(fingerprint(common_dir));
    for (dir, label) in [(&base, "worktree base"), (&root, "worktree root")] {
        match crate::scratch::create_secure_dir(dir, label) {
            Ok(()) => {}
            Err(_) if dir.symlink_metadata().is_ok() => {}
            Err(e) => return Err(e),
        }
        crate::scratch::validate_dir_safety(dir, label)?;
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
        let root = prepare_root_for(h.path(), Path::new("/w/a/.git")).expect("created");
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
            prepare_root_for(h.path(), Path::new("/w/a/.git")),
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
        let err = prepare_root_for(h.path(), Path::new("/w/a/.git")).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
    }

    #[test]
    fn refuses_a_symlinked_base() {
        let h = home();
        let target = h.path().join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, h.path().join(BASE)).unwrap();
        let err = prepare_root_for(h.path(), Path::new("/w/a/.git")).unwrap_err();
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
        assert_eq!(repository_common_dir(&main), Ok(common.clone()));
        assert_eq!(repository_common_dir(&wt), Ok(common));
        assert_ne!(
            repository_common_dir(&other).map(|c| fingerprint(&c)),
            repository_common_dir(&main).map(|c| fingerprint(&c)),
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
        assert!(repository_common_dir(&plain).is_err());
    }

    #[test]
    fn refuses_a_file_in_place_of_the_root() {
        let h = home();
        std::fs::create_dir_all(h.path().join(BASE)).unwrap();
        let fp = fingerprint(Path::new("/w/a/.git"));
        std::fs::write(h.path().join(BASE).join(fp), "").unwrap();
        let err = prepare_root_for(h.path(), Path::new("/w/a/.git")).unwrap_err();
        assert!(err.contains("not a directory"), "{err}");
    }
}
