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
    max_dirs: usize,
) -> Result<Option<PathBuf>, String> {
    let Some(common) = repository_common_dir(project_dir)? else {
        return Ok(None);
    };
    let root = prepare_root_for(home_dir, &common, create)?;
    let problems = link_problems(&common, &root, max_dirs);
    if !problems.is_empty() {
        return Err(format!(
            "the worktree links of this repository do not match what git writes, so git \
             run outside cplt could read agent-written config and run it. Do not run git in \
             these directories until this is fixed:\n    {}\n  Found:\n    {}\n  Inspect them \
             without git and remove the worktrees involved (delete the directories, then run \
             `git worktree prune` from this repository)",
            problem_dirs(&problems).join("\n    "),
            problems
                .iter()
                .map(|p| p.detail.as_str())
                .collect::<Vec<_>>()
                .join("\n    ")
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

/// One finding of [`link_problems`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkProblem {
    /// The directory where a plain `git` on the host would follow the bad
    /// link: the worktree the user would `cd` into, or the root itself when
    /// no narrower directory is known.
    pub dir: PathBuf,
    /// What is wrong, naming the file involved.
    pub detail: String,
}

impl std::fmt::Display for LinkProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

/// The distinct [`LinkProblem::dir`]s, in order of first appearance: the
/// directories not to run git in.
#[must_use]
pub fn problem_dirs(problems: &[LinkProblem]) -> Vec<String> {
    let mut dirs: Vec<String> = Vec::new();
    for p in problems {
        let d = p.dir.display().to_string();
        if !dirs.contains(&d) {
            dirs.push(d);
        }
    }
    dirs
}

/// How deep below the root the `.git` walk looks. A tree deeper than this is
/// a finding, not a pass: past it a `.git` would go unseen.
const WALK_MAX_DEPTH: usize = 64;

/// Default for `sandbox.worktree_walk_max_dirs`: how many directories the
/// `.git` walk visits (files are not counted, so build output of many small
/// files does not spend it). Reaching it is a finding, not a pass, for the
/// same reason as the depth.
pub const DEFAULT_WALK_MAX_DIRS: usize = 100_000;

/// Every way the agent-writable worktree bookkeeping can differ from what
/// `git worktree add` writes. Empty when intact. Fails closed: anything that
/// cannot be read is a finding.
///
/// Two links decide which config and hooks git on the host reads, and the
/// agent can write both:
///
/// - `<common>/worktrees/<name>/commondir` must lead back to `common`. Aimed
///   at `<root>/x/`, git reads `<root>/x/config` (`core.fsmonitor`). Missing,
///   git treats the admin dir itself as the common dir and reads its `config`.
///   The kernel only refuses an in-place rewrite; unlink-and-recreate and new
///   admin dirs are caught here.
/// - Each admin dir's `gitdir` must name an existing regular file called
///   `.git`: the pointer of a live worktree.
/// - Every `.git` in the root, in any letter case: on a case-insensitive
///   volume (the APFS default) git opens `.GIT` when it looks up `.git`. The
///   only one allowed is `<root>/<name>/.git`,
///   the depth `git worktree add "$CPLT_WORKTREE_ROOT/<name>"` writes, as a
///   regular file naming an admin dir under `<common>/worktrees` whose
///   `gitdir` names it back. Anything else (a pointer the agent recreated, one
///   in a subdirectory, one at the root, a symlink, a directory) can name a
///   gitdir in the root, where config and hooks are writable, and `git status`
///   in that directory would run its `core.fsmonitor` on the host. On macOS
///   the kernel refuses creating those, but a directory moved in with a `.git`
///   already inside is not a create, so the whole root is walked. Symlinks are
///   not followed.
/// - Every directory holding `HEAD` with `objects/` and `refs/`, or with a
///   `commondir`: git's discovery takes it for a bare repository and obeys the
///   `config` beside them, with no `.git` anywhere.
/// - Every entry directly in the root that is not a directory. A symlink
///   there leads a `cd` (and the git after it) out of the root.
/// - Every symlink deeper down that leads out of the root to a repository
///   ([`symlink_problem`]). It is tested, never walked through.
#[must_use]
pub fn link_problems(common: &Path, root: &Path, max_dirs: usize) -> Vec<LinkProblem> {
    let mut out = Vec::new();
    admin_problems(common, root, &mut out);
    walk_problems(common, root, max_dirs, &mut out);
    out
}

fn admin_problems(common: &Path, root: &Path, out: &mut Vec<LinkProblem>) {
    let admin = &common.join("worktrees");
    let mut push = |dir: &Path, detail: String| {
        out.push(LinkProblem {
            dir: dir.to_path_buf(),
            detail,
        });
    };
    match admin.symlink_metadata() {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return push(root, format!("{} is not a directory", admin.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => return push(root, format!("cannot stat {}: {e}", admin.display())),
    }
    let it = match std::fs::read_dir(admin) {
        Ok(it) => it,
        Err(e) => return push(root, format!("cannot read {}: {e}", admin.display())),
    };
    for entry in it {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                push(root, format!("cannot read {}: {e}", admin.display()));
                continue;
            }
        };
        let dir = entry.path();
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            push(root, format!("{} is not a directory", dir.display()));
            continue;
        }
        // The worktree this admin dir serves, from its `gitdir` back link:
        // where the user would run git. Unknown, the whole root is suspect.
        let back = dir.join("gitdir");
        let target = std::fs::read_to_string(&back).map(|raw| PathBuf::from(raw.trim()));
        let worktree = target
            .as_ref()
            .ok()
            .and_then(|t| t.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| root.to_path_buf());
        match &target {
            Ok(t)
                if t.file_name() == Some(".git".as_ref())
                    && t.symlink_metadata().is_ok_and(|m| m.is_file()) => {}
            Ok(t) => push(
                &worktree,
                format!(
                    "{} names {}, which is not an existing regular .git file",
                    back.display(),
                    t.display()
                ),
            ),
            Err(e) => push(root, format!("cannot read {}: {e}", back.display())),
        }
        let file = dir.join("commondir");
        match std::fs::read_to_string(&file) {
            Ok(raw) => match resolve(&dir, raw.trim()) {
                Ok(p) if p == common => {}
                Ok(p) => push(
                    &worktree,
                    format!(
                        "{} points at {}, not {}",
                        file.display(),
                        p.display(),
                        common.display()
                    ),
                ),
                Err(e) => push(&worktree, format!("{}: {e}", file.display())),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => push(
                &worktree,
                format!(
                    "{} is missing, so git would read {}/config as repository config",
                    file.display(),
                    dir.display()
                ),
            ),
            Err(e) => push(&worktree, format!("cannot read {}: {e}", file.display())),
        }
    }
}

/// Walk the whole root for `.git` entries and bare-repository layouts,
/// bounded by [`WALK_MAX_DEPTH`] and `max_dirs`.
fn walk_problems(common: &Path, root: &Path, max_dirs: usize, out: &mut Vec<LinkProblem>) {
    let admin = &common.join("worktrees");
    let mut push = |dir: &Path, detail: String| {
        out.push(LinkProblem {
            dir: dir.to_path_buf(),
            detail,
        });
    };
    let mut budget = max_dirs;
    // Directories counted under each entry directly in the root, for the
    // message when the budget runs out: which worktree spent it.
    let mut counts: Vec<(PathBuf, usize)> = Vec::new();
    // (directory, its depth below the root, its index in `counts`)
    let mut stack = vec![(root.to_path_buf(), 0usize, 0usize)];
    while let Some((dir, depth, top)) = stack.pop() {
        let it = match std::fs::read_dir(&dir) {
            Ok(it) => it,
            // Gone since it was listed, or no root yet: nothing to follow.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                push(&dir, format!("cannot read {}: {e}", dir.display()));
                continue;
            }
        };
        // What git's bare-repository discovery looks for. Case-blind, like
        // the `.git` match below. Taken from the listing, so a dangling
        // `HEAD -> refs/heads/main` counts, as it does for git.
        let (mut head, mut objects, mut refs, mut commondir) = (false, false, false, false);
        for entry in it {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    push(&dir, format!("cannot read {}: {e}", dir.display()));
                    continue;
                }
            };
            let path = entry.path();
            // `DirEntry::file_type` does not follow symlinks.
            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(e) => {
                    push(&dir, format!("cannot stat {}: {e}", path.display()));
                    continue;
                }
            };
            let name = entry.file_name();
            let is = |n: &str| name.to_string_lossy().eq_ignore_ascii_case(n);
            // git follows a symlink for `objects` and `refs`.
            let dirlike = kind.is_dir() || kind.is_symlink();
            head |= is("HEAD");
            objects |= dirlike && is("objects");
            refs |= dirlike && is("refs");
            commondir |= is("commondir");
            // Case-blind: on a case-insensitive volume git opens `.GIT` when
            // it looks up `.git`.
            if is(".git") {
                if depth == 1 && kind.is_file() && name == ".git" {
                    if let Err(e) = check_pointer(&path, admin) {
                        push(&dir, format!("{}: {e}", path.display()));
                    }
                } else if depth == 1 {
                    push(
                        &dir,
                        format!("{} is not a gitdir pointer file named .git", path.display()),
                    );
                } else {
                    push(
                        &dir,
                        format!(
                            "{} is not where `git worktree add` puts a worktree's .git",
                            path.display()
                        ),
                    );
                }
                continue;
            }
            if kind.is_symlink() && depth > 0 {
                if let Some(detail) = symlink_problem(&path, root, common) {
                    push(&dir, detail);
                }
                continue;
            }
            if !kind.is_dir() {
                if depth == 0 {
                    push(
                        root,
                        format!(
                            "{} is not a directory: only worktree directories belong directly \
                             in the root",
                            path.display()
                        ),
                    );
                }
                continue;
            }
            if depth + 1 > WALK_MAX_DEPTH {
                push(
                    root,
                    format!(
                        "{} is more than {WALK_MAX_DEPTH} levels below the root, so the check \
                         for .git entries could not look inside it",
                        path.display()
                    ),
                );
                continue;
            }
            if budget == 0 {
                counts.sort_by(|a, b| b.1.cmp(&a.1));
                let per: Vec<String> = counts
                    .iter()
                    .map(|(p, n)| format!("{}: {n}", p.display()))
                    .collect();
                push(
                    root,
                    format!(
                        "the root holds more than {max_dirs} directories \
                         (sandbox.worktree_walk_max_dirs), so the check for .git entries \
                         stopped before the end. Directories counted per worktree before it \
                         stopped: {}. Remove worktrees or build output you no longer need, \
                         or raise the limit",
                        per.join(", ")
                    ),
                );
                return;
            }
            budget -= 1;
            let top = if depth == 0 {
                counts.push((path.clone(), 0));
                counts.len() - 1
            } else {
                top
            };
            counts[top].1 += 1;
            stack.push((path, depth + 1, top));
        }
        if head && ((objects && refs) || commondir) {
            push(
                &dir,
                format!(
                    "{} holds HEAD with objects and refs or a commondir, so git run there \
                     takes it for a bare repository and reads its config",
                    dir.display()
                ),
            );
        }
    }
}

/// `dir` passes git's gitdir test as far as a check needs: `HEAD` (a dangling
/// symlink counts) with `objects/` and `refs/`, or with a `commondir` naming
/// where those live.
fn looks_like_gitdir(dir: &Path) -> bool {
    dir.join("HEAD").symlink_metadata().is_ok()
        && (dir.join("commondir").symlink_metadata().is_ok()
            || (dir.join("objects").is_dir() && dir.join("refs").is_dir()))
}

/// A symlink below a worktree, checked without walking through it.
///
/// `cd` through it and git starts discovery at the target, then walks up
/// from there. A target inside the root is covered by the walk itself. One
/// outside it (`/private/tmp/evil`, which the agent can write) is checked the
/// way git would: the first `.git` or gitdir-shaped directory on the way up
/// is a finding, unless it is this repository's own common dir, whose config
/// and hooks are kernel-denied. A target that does not exist is no directory
/// to run git in; one that cannot be resolved for another reason is a
/// finding.
fn symlink_problem(link: &Path, root: &Path, common: &Path) -> Option<String> {
    let target = match std::fs::canonicalize(link) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            return Some(format!(
                "{}: cannot resolve the symlink: {e}",
                link.display()
            ));
        }
    };
    if !target.is_dir() || target.starts_with(root) {
        return None;
    }
    for dir in target.ancestors() {
        if dir == common {
            return None;
        }
        let dotgit = dir.join(".git");
        if dotgit.symlink_metadata().is_ok() {
            return (dotgit != common).then(|| {
                format!(
                    "{} leads to {}, where git would use the repository at {}",
                    link.display(),
                    target.display(),
                    dotgit.display()
                )
            });
        }
        if looks_like_gitdir(dir) {
            return Some(format!(
                "{} leads to {}, where git would use {} as a bare repository",
                link.display(),
                target.display(),
                dir.display()
            ));
        }
    }
    None
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
pub fn session_end_problems(project_dir: &Path, root: &Path, max_dirs: usize) -> Vec<LinkProblem> {
    let detail = match repository_common_dir(project_dir) {
        Ok(Some(common)) => return link_problems(&common, root, max_dirs),
        Ok(None) => format!(
            "{} no longer resolves as a git repository",
            project_dir.display()
        ),
        Err(e) => e,
    };
    vec![LinkProblem {
        dir: project_dir.to_path_buf(),
        detail,
    }]
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
        assert_eq!(
            link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS),
            Vec::<LinkProblem>::new()
        );

        let commondir = common.join("worktrees/wt/commondir");
        std::fs::create_dir_all(root.join("x")).unwrap();
        std::fs::write(&commondir, root.join("x").to_string_lossy().as_bytes()).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            problems
                .iter()
                .any(|p| p.detail.contains("commondir points at")),
            "{problems:?}"
        );

        std::fs::remove_file(&commondir).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            problems.iter().any(|p| p.detail.contains("is missing")),
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
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            problems
                .iter()
                .any(|p| p.detail.contains("wt/.git") && p.detail.contains("not under")),
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
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            problems
                .iter()
                .any(|p| p.detail.contains("copy/.git")
                    && p.detail.contains("name this pointer back")),
            "{problems:?}"
        );
    }

    /// The finding for `path`, if any.
    fn finding<'a>(problems: &'a [LinkProblem], path: &Path) -> Option<&'a LinkProblem> {
        let s = path.display().to_string();
        problems.iter().find(|p| p.detail.starts_with(&s))
    }

    /// #574 re-review blocker: a `.git` at any depth but `<root>/<name>/.git`
    /// is found, whatever its type, and names the directory git would run in.
    #[test]
    fn a_git_entry_anywhere_in_the_root_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        let evil = root.join("g");
        std::fs::create_dir_all(&evil).unwrap();
        let pointer = format!("gitdir: {}\n", evil.display());
        let (sub, sub2, deep) = (wt.join("sub"), wt.join("sub2"), wt.join("d/e/f"));
        for d in [&sub, &sub2, &deep] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(sub.join(".git"), &pointer).unwrap();
        std::fs::write(root.join("p"), &pointer).unwrap();
        std::os::unix::fs::symlink(root.join("p"), sub2.join(".git")).unwrap();
        std::fs::create_dir_all(deep.join(".git")).unwrap();
        std::fs::write(root.join(".git"), &pointer).unwrap();

        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        for (git, dir) in [
            (sub.join(".git"), &sub),
            (sub2.join(".git"), &sub2),
            (deep.join(".git"), &deep),
            (root.join(".git"), &root),
        ] {
            let p = finding(&problems, &git)
                .unwrap_or_else(|| panic!("{} not found: {problems:?}", git.display()));
            assert_eq!(&p.dir, dir, "names the directory git would run in");
        }
        assert!(
            finding(&problems, &wt.join(".git")).is_none(),
            "{problems:?}"
        );
    }

    /// A depth-one `.git` that is a symlink, even to a valid pointer, is not
    /// what `git worktree add` writes.
    #[test]
    fn a_symlinked_worktree_pointer_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        std::fs::rename(wt.join(".git"), root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), wt.join(".git")).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        let p = finding(&problems, &wt.join(".git")).expect("found");
        assert!(p.detail.contains("not a gitdir pointer file"), "{p:?}");
        assert_eq!(p.dir, wt);
    }

    /// `<common>/worktrees` as a symlink, and an admin entry that is not a
    /// directory, are both findings.
    #[test]
    fn admin_dir_shape_is_checked() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, _)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        let admin = common.join("worktrees");
        std::fs::write(admin.join("stray"), "").unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            finding(&problems, &admin.join("stray"))
                .is_some_and(|p| p.detail.contains("not a directory")),
            "{problems:?}"
        );

        std::fs::rename(&admin, base.join("moved")).unwrap();
        std::os::unix::fs::symlink(base.join("moved"), &admin).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            finding(&problems, &admin).is_some_and(|p| p.detail.contains("not a directory")),
            "{problems:?}"
        );
    }

    /// Fail closed: a directory in the root that cannot be read is a finding,
    /// not a skip.
    #[test]
    fn an_unreadable_directory_is_a_finding() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        let locked = wt.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable = std::fs::read_dir(&locked).is_ok(); // root ignores modes
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        if readable {
            eprintln!("SKIPPED: running as root");
            return;
        }
        assert!(
            problems
                .iter()
                .any(|p| p.dir == locked && p.detail.starts_with("cannot read")),
            "{problems:?}"
        );

        let admin = common.join("worktrees");
        std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o000)).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let expected = format!("cannot read {}:", admin.display());
        assert!(
            problems.iter().any(|p| p.detail.starts_with(&expected)),
            "{problems:?}"
        );
    }

    /// A tree deeper than the walk looks is a finding, not a pass.
    #[test]
    fn the_walk_bound_is_a_finding() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let common = root.join("no-common");
        let mut deep = root.clone();
        for _ in 0..WALK_MAX_DEPTH {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        assert_eq!(
            link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS),
            Vec::<LinkProblem>::new()
        );
        std::fs::create_dir(deep.join("d")).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            problems.iter().any(|p| p.detail.contains("levels below")),
            "{problems:?}"
        );
    }

    /// A root that already exists with a looser mode is tightened to 0700 by
    /// the `fchmod` in `secure_dir`, not only created that way.
    #[test]
    fn an_existing_root_is_tightened_to_0700() {
        use std::os::unix::fs::PermissionsExt;
        let h = home();
        let root = std::fs::canonicalize(h.path())
            .unwrap()
            .join(BASE)
            .join(fingerprint(Path::new("/w/a/.git")));
        std::fs::create_dir_all(&root).unwrap();
        for dir in [root.as_path(), root.parent().unwrap()] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        prepare_root_for(h.path(), Path::new("/w/a/.git"), true).expect("reused");
        for dir in [root.as_path(), root.parent().unwrap()] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
        }
    }

    /// #574 review blocker: on a case-insensitive volume git opens `.GIT`
    /// when it looks up `.git`, so a case variant is a `.git` too. At depth
    /// one only the exact name `git worktree add` writes passes.
    #[test]
    fn a_case_variant_git_entry_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        let sub = wt.join("sub");
        std::fs::create_dir_all(sub.join(".GIT")).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        let p = finding(&problems, &sub.join(".GIT")).expect("nested .GIT found");
        assert_eq!(p.dir, sub);

        std::fs::rename(wt.join(".git"), wt.join(".Git")).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        let p = finding(&problems, &wt.join(".Git")).expect("depth-one .Git found");
        assert!(p.detail.contains("named .git"), "{p:?}");
    }

    /// An admin dir whose `gitdir` does not name an existing regular `.git`
    /// file serves no live worktree: a finding, not a pass.
    #[test]
    fn an_admin_dir_without_a_live_pointer_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        let back = common.join("worktrees/wt/gitdir");
        std::fs::write(&back, format!("{}\n", wt.join("f").display())).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            finding(&problems, &back)
                .is_some_and(|p| p.detail.contains("not an existing regular .git file")),
            "{problems:?}"
        );

        std::fs::write(&back, format!("{}\n", wt.join(".git").display())).unwrap();
        std::fs::remove_dir_all(&wt).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            finding(&problems, &back)
                .is_some_and(|p| p.detail.contains("not an existing regular .git file")),
            "{problems:?}"
        );
    }

    /// A symlink or file directly in the root is a finding: a `cd` through it
    /// leaves the root, and git follows.
    #[test]
    fn a_non_directory_directly_in_the_root_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let common = root.join("no-common");
        std::fs::create_dir(root.join("wt")).unwrap();
        assert_eq!(
            link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS),
            Vec::<LinkProblem>::new()
        );
        std::os::unix::fs::symlink("/", root.join("link")).unwrap();
        std::fs::write(root.join("file"), "").unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        for name in ["link", "file"] {
            assert!(
                finding(&problems, &root.join(name))
                    .is_some_and(|p| p.detail.contains("not a directory")),
                "{name}: {problems:?}"
            );
        }
    }

    /// A directory with `HEAD`, `objects/` and `refs/` is a bare repository
    /// to git's discovery, which then reads the `config` beside them.
    #[test]
    fn a_bare_repository_layout_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        let bare = wt.join("b");
        std::fs::create_dir_all(bare.join("objects")).unwrap();
        std::fs::create_dir_all(bare.join("refs")).unwrap();
        assert_eq!(
            link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS),
            Vec::<LinkProblem>::new(),
            "objects and refs alone are not a repository"
        );
        // A dangling `HEAD -> refs/heads/main` is a HEAD to git.
        std::os::unix::fs::symlink("refs/heads/main", bare.join("HEAD")).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        let p = finding(&problems, &bare).expect("bare layout found");
        assert!(p.detail.contains("bare"), "{p:?}");
        assert_eq!(p.dir, bare);

        // HEAD with a `commondir` needs no objects or refs of its own.
        let linked = wt.join("c");
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::write(linked.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(linked.join("commondir"), "/elsewhere\n").unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(finding(&problems, &linked).is_some(), "{problems:?}");
    }

    /// #577 review (a): a symlink below a worktree that leads out of the root
    /// to a repository is where a `cd` and git would pick up that
    /// repository's config. Tested, not walked. One into this repository's
    /// own checkout, or one that dangles, is not a finding.
    #[test]
    fn a_symlink_out_of_the_root_to_a_repository_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        let evil = base.join("evil");
        std::fs::create_dir_all(evil.join(".git")).unwrap();
        std::fs::create_dir_all(evil.join("deep/er")).unwrap();
        let bare = base.join("bare");
        for d in ["objects", "refs", "sub"] {
            std::fs::create_dir_all(bare.join(d)).unwrap();
        }
        std::fs::write(bare.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::create_dir_all(base.join("main/lib")).unwrap();

        std::os::unix::fs::symlink(&evil, wt.join("tools")).unwrap();
        std::os::unix::fs::symlink(evil.join("deep/er"), wt.join("deep")).unwrap();
        std::os::unix::fs::symlink(bare.join("sub"), wt.join("b")).unwrap();
        std::os::unix::fs::symlink(base.join("main/lib"), wt.join("own")).unwrap();
        std::os::unix::fs::symlink(base.join("gone"), wt.join("dangling")).unwrap();
        std::os::unix::fs::symlink(wt.join("f"), wt.join("file")).unwrap();

        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        for name in ["tools", "deep", "b"] {
            let p = finding(&problems, &wt.join(name))
                .unwrap_or_else(|| panic!("{name}: {problems:?}"));
            assert_eq!(p.dir, wt, "{name}");
        }
        for name in ["own", "dangling", "file"] {
            assert!(
                finding(&problems, &wt.join(name)).is_none(),
                "{name}: {problems:?}"
            );
        }
    }

    /// #577 review (c): the create deny sees only the top directory of a
    /// rename, so a tree staged outside the root with a `.git` inside and
    /// moved in whole gets past it. The walk is what finds it.
    #[test]
    fn a_git_moved_in_inside_its_parent_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        let stage = base.join("stage/sub");
        std::fs::create_dir_all(stage.join(".git")).unwrap();
        std::fs::rename(&stage, wt.join("sub")).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            finding(&problems, &wt.join("sub/.git")).is_some(),
            "{problems:?}"
        );
    }

    /// The directory budget is the caller's (`sandbox.worktree_walk_max_dirs`),
    /// and running out of it names how many directories each worktree held.
    #[test]
    fn the_directory_budget_is_configurable_and_reports_counts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let common = root.join("no-common");
        std::fs::create_dir_all(root.join("big/a/b")).unwrap();
        std::fs::create_dir_all(root.join("big/c")).unwrap();
        std::fs::create_dir_all(root.join("small")).unwrap();
        // Five directories: big, big/a, big/a/b, big/c and small.
        assert_eq!(link_problems(&common, &root, 5), Vec::<LinkProblem>::new());
        let problems = link_problems(&common, &root, 3);
        let p = problems
            .iter()
            .find(|p| p.detail.contains("sandbox.worktree_walk_max_dirs"))
            .unwrap_or_else(|| panic!("{problems:?}"));
        assert!(p.detail.contains("more than 3 directories"), "{p:?}");
        let big = format!("{}: ", root.join("big").display());
        let small = format!("{}: 1", root.join("small").display());
        assert!(p.detail.contains(&big), "{p:?}");
        assert!(p.detail.contains(&small), "{p:?}");
    }
}
