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
        secure_dir(dir, label, create)?;
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
///
/// `fix` is false for `doctor`, `check` and `--print-profile`: they check
/// but never create the directory or change its mode.
fn secure_dir(dir: &Path, label: &str, fix: bool) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    if fix {
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
                return Err(format!("cannot create {label} {}: {e}", dir.display()));
            }
            _ => {}
        }
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
    if fix && meta.mode() & 0o777 != 0o700 {
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
/// The rules are strict on purpose. Checking where a link *leads* is a race
/// the agent wins: a value that resolves correctly through a symlink today is
/// re-aimed tomorrow by changing the symlink, which nothing checks. So every
/// link must be the exact text git writes, in a regular file, naming a path
/// with no symlink in it:
///
/// - Each `<common>/worktrees/<id>/commondir` is exactly `../..`. Aimed at
///   `<root>/x/`, git would read `<root>/x/config` (`core.fsmonitor`).
/// - Each `<common>/worktrees/<id>/gitdir` is an absolute path with no
///   symlink, `.` or `..` in it, naming an existing regular file called
///   `.git`. Inside the root it must be `<root>/<name>/.git`.
/// - The only `.git` in the root, in any letter case (on a case-insensitive
///   volume, the APFS default, git opens `.GIT` for `.git`), is
///   `<root>/<name>/.git`: a regular file that reads exactly
///   `gitdir: <common>/worktrees/<id>`, whose admin dir's `gitdir` reads
///   exactly `<root>/<name>/.git`. Anything else (a pointer the agent
///   recreated, one in a subdirectory or at the root, a symlink, a directory)
///   can name a gitdir whose config the agent wrote, and `git status` in that
///   directory would run its `core.fsmonitor` on the host. On macOS the kernel
///   refuses creating those, but a directory moved in with a `.git` already
///   inside is not a create, so the whole root is walked.
/// - No directory holds `HEAD` with `objects` and `refs`, or `HEAD` with a
///   `commondir`, of any file type: git's discovery takes that for a bare
///   repository and obeys the `config` beside it, with no `.git` anywhere.
/// - Nothing directly in the root is anything but a directory.
/// - No symlink anywhere below, dangling or not, unless it stays inside its
///   own worktree, which the walk covers ([`link_stays_inside`]). A link that
///   leads out, even one that comes back in, can be aimed at a repository the
///   agent builds in `/private/tmp`, now or later.
#[must_use]
pub fn link_problems(common: &Path, root: &Path, max_dirs: usize) -> Vec<LinkProblem> {
    let mut out = Vec::new();
    admin_problems(common, root, &mut out);
    walk_problems(common, root, max_dirs, &mut out);
    out
}

/// The text of the regular file `path`, less one trailing newline.
///
/// Opened `O_NOFOLLOW | O_NONBLOCK` and checked through the descriptor: a
/// symlink is refused by the kernel, and a FIFO in its place cannot hang the
/// launch.
fn read_link_file(path: &Path) -> Result<String, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("cannot open {} as a regular file: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let mut raw = String::new();
    file.by_ref()
        .take(64 * 1024)
        .read_to_string(&mut raw)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(raw.strip_suffix('\n').unwrap_or(&raw).to_string())
}

/// `raw` is absolute and has no symlink, `.`, `..` or doubled `/` in it: its
/// canonical form is the same text.
fn is_plain_path(raw: &str) -> bool {
    Path::new(raw).is_absolute()
        && std::fs::canonicalize(raw).is_ok_and(|c| c.as_os_str() == std::ffi::OsStr::new(raw))
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
        let mut worktree = root.to_path_buf();
        match read_link_file(&back) {
            Ok(raw) => {
                let target = Path::new(&raw);
                if let Some(wt) = target.parent() {
                    worktree = wt.to_path_buf();
                }
                let in_root_ok = !target.starts_with(root)
                    || target.parent().and_then(Path::parent) == Some(root);
                let ok = target.file_name() == Some(".git".as_ref())
                    && in_root_ok
                    && is_plain_path(&raw)
                    && target.symlink_metadata().is_ok_and(|m| m.is_file());
                if !ok {
                    push(
                        &worktree,
                        format!(
                            "{} names {raw}, which is not an existing regular .git file on a \
                             path without symlinks{}",
                            back.display(),
                            if in_root_ok {
                                ""
                            } else {
                                ", directly in a worktree of the root"
                            }
                        ),
                    );
                }
            }
            Err(e) => push(root, e),
        }
        let file = dir.join("commondir");
        match read_link_file(&file) {
            Ok(raw) if raw == "../.." => {}
            Ok(raw) => push(
                &worktree,
                format!(
                    "{} reads {raw:?}, not \"../..\" as git writes it",
                    file.display()
                ),
            ),
            Err(e) => push(&worktree, e),
        }
    }
}

/// Walk the whole root for `.git` entries, bare-repository layouts and
/// symlinks, bounded by [`WALK_MAX_DEPTH`] and `max_dirs`.
fn walk_problems(common: &Path, root: &Path, max_dirs: usize, out: &mut Vec<LinkProblem>) {
    let mut push = |dir: &Path, detail: String| {
        out.push(LinkProblem {
            dir: dir.to_path_buf(),
            detail,
        });
    };
    let mut budget = max_dirs;
    // Directories counted under each entry directly in the root: the
    // worktree, and how many directories it spent for the message when the
    // budget runs out.
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
        // What git's bare-repository discovery looks for, taken from the
        // listing by name and any file type: git tests `HEAD` with lstat and
        // `objects` and `refs` with `access(X_OK)`, which an executable
        // regular file passes. Case-blind, like the `.git` match below.
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
            head |= is("HEAD");
            objects |= is("objects");
            refs |= is("refs");
            commondir |= is("commondir");
            if is(".git") {
                if depth == 1 && kind.is_file() && name == ".git" {
                    if let Err(e) = check_pointer(&path, common) {
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
                // Allowed only when it stays inside its own worktree, where
                // the walk sees whatever it leads to. Everything else,
                // dangling included, can be aimed at a repository later.
                let worktree = &counts[top].0;
                if !link_stays_inside(&path, worktree) {
                    push(
                        &dir,
                        format!(
                            "{} is a symlink that does not resolve inside {}",
                            path.display(),
                            worktree.display()
                        ),
                    );
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

/// The symlink `link` leads into `worktree` without passing through anything
/// outside it.
///
/// Where the link resolves today is not enough: `wt/l -> /private/tmp/s/d`
/// with `/private/tmp/s -> wt` resolves inside the worktree, and re-aiming
/// `/private/tmp/s` later (outside the root, so never checked) sends a `cd`
/// into `wt/l` to a planted repository. So the target text, joined to the
/// link's directory and normalised without touching the disk, must lie inside
/// the worktree, and it must resolve inside it today.
///
/// A symlink met on the way is then inside the worktree, and the walk holds
/// it to this same rule, so by induction nothing outside is ever traversed.
/// That keeps chains like npm's `.bin/x -> ../pkg/bin/x` with a workspace
/// `pkg -> ../packages/pkg` working. The normalising is exact only where no
/// symlink precedes a `..`: leading `..` climb the link's own directories,
/// which the walk reached as real directories, and a `..` after a name is
/// refused.
fn link_stays_inside(link: &Path, worktree: &Path) -> bool {
    use std::path::Component;
    let (Ok(target), Some(parent)) = (std::fs::read_link(link), link.parent()) else {
        return false;
    };
    let mut lexical = parent.to_path_buf();
    let mut named = false;
    for part in target.components() {
        match part {
            Component::RootDir => lexical = PathBuf::from("/"),
            Component::CurDir => {}
            Component::ParentDir if !named => {
                lexical.pop();
            }
            Component::Normal(name) => {
                named = true;
                lexical.push(name);
            }
            Component::ParentDir | Component::Prefix(_) => return false,
        }
    }
    lexical.starts_with(worktree)
        && std::fs::canonicalize(link).is_ok_and(|c| c.starts_with(worktree))
}

/// One `<root>/<name>/.git` pointer against its admin dir, both directions,
/// by exact text.
fn check_pointer(pointer: &Path, common: &Path) -> Result<(), String> {
    let raw = read_link_file(pointer)?;
    let admin_root = common.join("worktrees");
    let target = raw
        .strip_prefix("gitdir: ")
        .ok_or("not a `gitdir: ` pointer")?;
    let gitdir = Path::new(target);
    let one_name = gitdir.file_name().is_some_and(|n| n != "." && n != "..");
    if !one_name || gitdir.parent() != Some(admin_root.as_path()) {
        return Err(format!(
            "reads {raw:?}, not `gitdir: {}/<id>`",
            admin_root.display()
        ));
    }
    if !is_plain_path(target) {
        return Err(format!(
            "names {target}, which does not exist or has a symlink in its path"
        ));
    }
    let back_file = gitdir.join("gitdir");
    let back = read_link_file(&back_file)?;
    if std::ffi::OsStr::new(&back) != pointer.as_os_str() {
        return Err(format!(
            "{} reads {back:?}, not this pointer",
            back_file.display()
        ));
    }
    Ok(())
}

/// `~/.cplt-worktrees` when something other than a directory is there (a
/// file, a symlink). With the key on the launch refuses it; with the key off
/// it is worth one line, not an alarm.
#[must_use]
pub fn stray_base(home_dir: &Path) -> Option<PathBuf> {
    let base = home_dir.join(BASE);
    base.symlink_metadata()
        .is_ok_and(|m| !m.is_dir())
        .then_some(base)
}

/// [`link_problems`] for a root an earlier session left, run while the key is
/// off. Turning the key off does not make a planted link harmless: git on the
/// host still follows it.
///
/// Read-only: it creates, fixes and follows nothing, and it runs no git at
/// all unless `~/.cplt-worktrees` exists, so a user who never turned the key
/// on pays one `lstat`. Empty when there is no root for this repository.
#[must_use]
pub fn existing_root_problems(
    home_dir: &Path,
    project_dir: &Path,
    max_dirs: usize,
) -> Vec<LinkProblem> {
    let finding = |dir: &Path, detail: String| {
        vec![LinkProblem {
            dir: dir.to_path_buf(),
            detail,
        }]
    };
    // `None` when absent; a finding when it is there but not a directory we
    // can look at (a symlink, a file, EACCES), since that is not "no root".
    let present = |p: &Path| match p.symlink_metadata() {
        Ok(m) if m.is_dir() => Ok(true),
        Ok(_) => Err(finding(p, format!("{} is not a directory", p.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(finding(p, format!("cannot stat {}: {e}", p.display()))),
    };
    let Ok(home) = std::fs::canonicalize(home_dir) else {
        return Vec::new();
    };
    let base = home.join(BASE);
    // A file or symlink in place of the base holds no root to check: the
    // launch says so in one line ([`stray_base`]), not as a link finding.
    if stray_base(&home).is_some() {
        return Vec::new();
    }
    match present(&base) {
        Ok(true) => {}
        Ok(false) => return Vec::new(),
        Err(f) => return f,
    }
    let common = match repository_common_dir(project_dir) {
        Ok(Some(common)) => common,
        Ok(None) => return Vec::new(),
        Err(e) => {
            return finding(
                project_dir,
                format!("cannot tell which worktree root belongs to this repository: {e}"),
            );
        }
    };
    let root = base.join(fingerprint(&common));
    match present(&root) {
        Ok(true) => link_problems(&common, &root, max_dirs),
        Ok(false) => Vec::new(),
        Err(f) => f,
    }
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
            problems.iter().any(|p| p.detail.contains("not \"../..\"")),
            "{problems:?}"
        );

        std::fs::remove_file(&commondir).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        let expected = format!("cannot open {}", commondir.display());
        assert!(
            problems.iter().any(|p| p.detail.starts_with(&expected)),
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
                .any(|p| p.detail.contains("wt/.git") && p.detail.contains("not `gitdir: ")),
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
                .any(|p| p.detail.contains("copy/.git") && p.detail.contains("not this pointer")),
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
        // A report (`doctor`, `check`, `--print-profile`) changes nothing.
        prepare_root_for(h.path(), Path::new("/w/a/.git"), false).expect("reported");
        for dir in [root.as_path(), root.parent().unwrap()] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "a report chmods {}", dir.display());
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

        // A regular `.git` deeper than `<root>/<name>/.git` is not a worktree
        // `git worktree add "$CPLT_WORKTREE_ROOT/<name>"` makes.
        std::fs::create_dir_all(wt.join("sub")).unwrap();
        std::fs::write(wt.join("sub/.git"), "").unwrap();
        std::fs::write(&back, format!("{}\n", wt.join("sub/.git").display())).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            finding(&problems, &back)
                .is_some_and(|p| p.detail.contains("directly in a worktree of the root")),
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

    /// The bare-repository finding for `dir`, if any.
    fn bare_finding<'a>(problems: &'a [LinkProblem], dir: &Path) -> Option<&'a LinkProblem> {
        problems
            .iter()
            .find(|p| p.dir == dir && p.detail.contains("bare repository"))
    }

    /// A directory with `HEAD`, `objects/` and `refs/` is a bare repository
    /// to git's discovery, which then reads the `config` beside them. So is
    /// `HEAD` with a `commondir`.
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
        std::fs::write(bare.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(bare_finding(&problems, &bare).is_some(), "{problems:?}");

        let linked = wt.join("c");
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::write(linked.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(linked.join("commondir"), "/elsewhere\n").unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(bare_finding(&problems, &linked).is_some(), "{problems:?}");
    }

    /// #574 round 7, bypass 4: git tests `objects` and `refs` with
    /// `access(X_OK)`, so executable regular files pass. Any file type counts.
    #[test]
    fn a_bare_layout_of_plain_files_is_found() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        let bare = wt.join("b");
        std::fs::create_dir_all(&bare).unwrap();
        std::fs::write(bare.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        for f in ["objects", "refs"] {
            std::fs::write(bare.join(f), "").unwrap();
            std::fs::set_permissions(bare.join(f), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(bare_finding(&problems, &bare).is_some(), "{problems:?}");
    }

    /// #574 round 7, bypass 1: every link is exact text in a regular file on
    /// a path with no symlink. A pointer through a symlink to the real admin
    /// dir, a `commondir` that is a symlink to a file naming the common dir,
    /// and an admin `gitdir` through a symlink all resolve correctly today and
    /// can be re-aimed tomorrow, so each is a finding.
    #[test]
    fn links_through_symlinks_are_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        let admin = common.join("worktrees/wt");
        let pointer = wt.join(".git");

        let l = base.join("l");
        std::os::unix::fs::symlink(&admin, &l).unwrap();
        std::fs::write(&pointer, format!("gitdir: {}\n", l.display())).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            finding(&problems, &pointer).is_some_and(|p| p.detail.contains("not `gitdir: ")),
            "{problems:?}"
        );
        std::fs::write(&pointer, format!("gitdir: {}\n", admin.display())).unwrap();
        assert_eq!(
            link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS),
            Vec::<LinkProblem>::new()
        );

        let commondir = admin.join("commondir");
        let c = base.join("c");
        std::fs::write(&c, format!("{}\n", common.display())).unwrap();
        std::fs::remove_file(&commondir).unwrap();
        std::os::unix::fs::symlink(&c, &commondir).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            problems
                .iter()
                .any(|p| p.detail.contains(&commondir.display().to_string())),
            "{problems:?}"
        );
        // Even with the right text, a symlink is refused: its target in
        // `/private/tmp` can be rewritten after the check.
        std::fs::write(&c, "../..\n").unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            problems.iter().any(|p| p
                .detail
                .starts_with(&format!("cannot open {}", commondir.display()))),
            "{problems:?}"
        );
        // A regular file naming a symlink to the common dir resolves right
        // today and is re-aimed by changing the symlink.
        let cl = base.join("cl");
        std::os::unix::fs::symlink(&common, &cl).unwrap();
        std::fs::remove_file(&commondir).unwrap();
        std::fs::write(&commondir, format!("{}\n", cl.display())).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            problems.iter().any(|p| p.detail.contains("not \"../..\"")),
            "{problems:?}"
        );
        std::fs::write(&commondir, "../..\n").unwrap();

        let lw = base.join("lw");
        std::os::unix::fs::symlink(&wt, &lw).unwrap();
        let back = admin.join("gitdir");
        std::fs::write(&back, format!("{}\n", lw.join(".git").display())).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            finding(&problems, &back).is_some_and(|p| p.detail.contains("without symlinks")),
            "{problems:?}"
        );
    }

    /// #574 round 7, bypasses 2 and 3: a symlink anywhere below the root that
    /// does not resolve inside its own worktree is a finding, whatever it
    /// leads to: a repository outside, a directory that looks harmless now, a
    /// dangling target (armed later), or this repository's own gitdir (a
    /// `<common>/.git` plant would make it a repository of its own).
    #[test]
    fn a_symlink_out_of_its_worktree_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        let evil = base.join("evil");
        std::fs::create_dir_all(evil.join(".git")).unwrap();
        std::fs::create_dir_all(base.join("main/lib")).unwrap();
        std::os::unix::fs::symlink(&evil, wt.join("tools")).unwrap();
        std::os::unix::fs::symlink(base.join("main/lib"), wt.join("own")).unwrap();
        std::os::unix::fs::symlink(common.join("refs"), wt.join("refs-link")).unwrap();
        std::os::unix::fs::symlink(base.join("later"), wt.join("dangling")).unwrap();
        std::fs::create_dir_all(wt.join("d")).unwrap();
        std::os::unix::fs::symlink(&evil, wt.join("d/deep")).unwrap();

        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        for name in ["tools", "own", "refs-link", "dangling", "d/deep"] {
            assert!(
                finding(&problems, &wt.join(name)).is_some_and(|p| p.detail.contains("symlink")),
                "{name}: {problems:?}"
            );
        }
    }

    /// The one exemption: a symlink that resolves inside its own worktree
    /// (`node_modules/.bin`, pnpm's store links) is allowed, because the walk
    /// sees what it leads to. Aimed at a repository inside the worktree, the
    /// repository itself is still found.
    #[test]
    fn a_symlink_inside_its_worktree_is_covered_by_the_walk() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        std::fs::create_dir_all(wt.join("node_modules/pkg/bin")).unwrap();
        std::fs::write(wt.join("node_modules/pkg/bin/x"), "").unwrap();
        std::fs::create_dir_all(wt.join("node_modules/.bin")).unwrap();
        std::os::unix::fs::symlink("../pkg/bin/x", wt.join("node_modules/.bin/x")).unwrap();
        std::os::unix::fs::symlink(wt.join("node_modules/pkg"), wt.join("pkg-link")).unwrap();
        assert_eq!(
            link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS),
            Vec::<LinkProblem>::new()
        );

        let repo = wt.join("inner");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::os::unix::fs::symlink(&repo, wt.join("inner-link")).unwrap();
        let bare = wt.join("inner-bare");
        std::fs::create_dir_all(bare.join("objects")).unwrap();
        std::fs::create_dir_all(bare.join("refs")).unwrap();
        std::fs::write(bare.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::os::unix::fs::symlink(&bare, wt.join("bare-link")).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            finding(&problems, &wt.join("inner-link")).is_none(),
            "{problems:?}"
        );
        assert!(
            finding(&problems, &repo.join(".git")).is_some(),
            "{problems:?}"
        );
        assert!(bare_finding(&problems, &bare).is_some(), "{problems:?}");
    }

    /// A symlink into another worktree of the root is not inside its own.
    #[test]
    fn a_symlink_into_another_worktree_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        std::fs::create_dir_all(root.join("other")).unwrap();
        std::os::unix::fs::symlink(root.join("other"), wt.join("o")).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(finding(&problems, &wt.join("o")).is_some(), "{problems:?}");
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

    /// #574 round 8 blocker: `wt/l -> <outside>/s/d` with `<outside>/s -> wt`
    /// resolves inside the worktree today, and re-aiming `s` later (never
    /// checked, it is outside the root) sends git in `wt/l` elsewhere. The
    /// link passes through a path outside the worktree, so it is a finding.
    #[test]
    fn a_symlink_back_in_through_an_outside_symlink_is_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        std::fs::create_dir_all(wt.join("d")).unwrap();
        let s = base.join("s");
        std::os::unix::fs::symlink(&wt, &s).unwrap();
        let l = wt.join("l");
        std::os::unix::fs::symlink(s.join("d"), &l).unwrap();
        assert!(
            std::fs::canonicalize(&l).unwrap().starts_with(&wt),
            "the chain resolves inside the worktree today"
        );
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(
            finding(&problems, &l).is_some_and(|p| p.detail.contains("symlink")),
            "{problems:?}"
        );
    }

    /// The rule still lets a chain of links that stay inside the worktree
    /// through (npm workspaces: `.bin/x -> ../pkg/bin/x`, `pkg ->
    /// ../packages/pkg`), and refuses a `..` after a name, which the kernel
    /// resolves against wherever a symlink before it points.
    #[test]
    fn links_chained_inside_the_worktree_pass() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let Some((common, root, wt)) = repo_with_worktree(&base) else {
            eprintln!("SKIPPED: git unavailable");
            return;
        };
        std::fs::create_dir_all(wt.join("packages/pkg/bin")).unwrap();
        std::fs::write(wt.join("packages/pkg/bin/x"), "").unwrap();
        std::fs::create_dir_all(wt.join("node_modules/.bin")).unwrap();
        std::os::unix::fs::symlink("../packages/pkg", wt.join("node_modules/pkg")).unwrap();
        std::os::unix::fs::symlink("../pkg/bin/x", wt.join("node_modules/.bin/x")).unwrap();
        assert_eq!(
            link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS),
            Vec::<LinkProblem>::new()
        );

        let up = wt.join("up");
        std::os::unix::fs::symlink("packages/../packages/pkg", &up).unwrap();
        let problems = link_problems(&common, &root, DEFAULT_WALK_MAX_DIRS);
        assert!(finding(&problems, &up).is_some(), "{problems:?}");
    }

    /// Key off, a file or symlink at `~/.cplt-worktrees`: one warning line
    /// from the launch ([`stray_base`]), not a link finding at launch and
    /// again at session end.
    #[test]
    fn a_stray_base_is_not_a_link_finding() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let main = base.join("main");
        std::fs::create_dir_all(&main).unwrap();
        if !git_in(&main, &["init", "-q", "-b", "main"]) {
            eprintln!("SKIPPED: git unavailable");
            return;
        }
        let home = base.join("home");
        std::fs::create_dir_all(&home).unwrap();
        assert_eq!(stray_base(&home), None);
        std::os::unix::fs::symlink("/nonexistent", home.join(BASE)).unwrap();
        assert_eq!(stray_base(&home), Some(home.join(BASE)));
        assert_eq!(
            existing_root_problems(&home, &main, DEFAULT_WALK_MAX_DIRS),
            Vec::new()
        );
    }

    /// With the key off, a root an earlier session left is still checked. A
    /// root cplt cannot look at (EACCES) and a repository whose common dir
    /// cannot be told are findings, not "no root".
    #[test]
    fn an_existing_root_is_checked_with_the_key_off() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let main = base.join("main");
        std::fs::create_dir_all(&main).unwrap();
        if !git_in(&main, &["init", "-q", "-b", "main"]) {
            eprintln!("SKIPPED: git unavailable");
            return;
        }
        let home = base.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let max = DEFAULT_WALK_MAX_DIRS;
        assert_eq!(existing_root_problems(&home, &main, max), Vec::new());

        let common = main.join(".git");
        let root = home.join(BASE).join(fingerprint(&common));
        std::fs::create_dir_all(&root).unwrap();
        assert_eq!(existing_root_problems(&home, &main, max), Vec::new());
        std::os::unix::fs::symlink("/", root.join("out")).unwrap();
        let problems = existing_root_problems(&home, &main, max);
        assert!(
            finding(&problems, &root.join("out")).is_some(),
            "{problems:?}"
        );
        std::fs::remove_file(root.join("out")).unwrap();

        let base_dir = home.join(BASE);
        std::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable = std::fs::read_dir(&base_dir).is_ok(); // root ignores modes
        let problems = existing_root_problems(&home, &main, max);
        std::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        if !readable {
            assert!(
                problems.iter().any(|p| p.detail.starts_with("cannot stat")),
                "{problems:?}"
            );
        }

        // A steered `commondir` makes `repository_common_dir` fail.
        let other = base.join("other");
        std::fs::create_dir_all(&other).unwrap();
        assert!(git_in(&other, &["init", "-q", "-b", "main"]));
        std::fs::write(
            common.join("commondir"),
            other.join(".git").to_string_lossy().as_bytes(),
        )
        .unwrap();
        let problems = existing_root_problems(&home, &main, max);
        assert!(
            problems
                .iter()
                .any(|p| p.detail.starts_with("cannot tell which worktree root")),
            "{problems:?}"
        );
    }
}
