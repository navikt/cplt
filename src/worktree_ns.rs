//! Linux: kernel protection for managed worktrees inside the bubblewrap
//! namespace (#965).
//!
//! macOS denies the protected paths at any depth below the managed root with a
//! regex. bubblewrap can only bind paths that exist when it starts, and the
//! broker creates worktrees mid-session. So the parent enters the session's
//! user and mount namespaces (it owns the user namespace bwrap created, which
//! gives it `CAP_SYS_ADMIN` there) and attaches bind mounts itself:
//!
//! - before the agent starts: `<common>/worktrees` read-only, so plain
//!   `git worktree add` cannot create an admin directory, every existing admin
//!   directory writable again on top, and the per-worktree set below for each
//!   existing worktree in the root;
//! - after each broker publish: the per-worktree set for the new worktree.
//!
//! The per-worktree set is the project's own bubblewrap list
//! (`git_persistence_paths` read-only, `rename_pin_paths` self-bound), plus
//! the `.git` pointer and the admin links (`commondir`, `gitdir`,
//! `config.worktree`) read-only and the worktree and admin directories pinned
//! against rename.
//!
//! Mounts are made with `open_tree`/`move_mount` on descriptors opened without
//! following a symlink in any component, so a link the agent swaps in cannot
//! redirect a bind. A failure is never skipped: the launch or the request is
//! refused.
//!
//! The work happens in a re-exec of this binary ([`HELPER_ARG`]), because
//! `setns(CLONE_NEWUSER)` needs a single-threaded process.

use std::io::{BufRead, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::OnceLock;

/// argv[1] of the helper re-exec.
pub const HELPER_ARG: &str = "__cplt-worktree-ns";

/// How a path is bound onto itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Read-only.
    Ro,
    /// Same flags as now: only makes the path a mountpoint, so it cannot be
    /// renamed or removed.
    Pin,
    /// Writable: an admin directory under the read-only `worktrees`.
    Rw,
}

impl Mode {
    fn tag(self) -> &'static str {
        match self {
            Self::Ro => "ro",
            Self::Pin => "pin",
            Self::Rw => "rw",
        }
    }
}

/// The managed root and the common git dir, registered by the broker.
static SCOPE: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
/// The session's user and mount namespaces, opened before the agent starts.
static NS: OnceLock<(OwnedFd, OwnedFd)> = OnceLock::new();

/// The broker is running: the session must apply these protections.
pub fn register(root: &Path, common: &Path) {
    let _ = SCOPE.set((root.to_path_buf(), common.to_path_buf()));
}

/// Whether a broker needs the namespace protections this session.
pub fn required() -> bool {
    SCOPE.get().is_some()
}

/// Open the namespaces of `pid` (the bwrap child, host pid) and apply the
/// launch set. Called before the agent is allowed to start.
pub fn attach_and_protect(pid: i32) -> Result<(), String> {
    let (root, common) = SCOPE.get().ok_or("no managed worktree root registered")?;
    let open = |kind: &str| {
        std::fs::File::open(format!("/proc/{pid}/ns/{kind}"))
            .map(OwnedFd::from)
            .map_err(|e| format!("cannot open the session's {kind} namespace: {e}"))
    };
    let _ = NS.set((open("user")?, open("mnt")?));
    apply(&launch_set(root, common)?)
}

/// After a broker publish: protect the new worktree, or fail.
pub fn protect_new(worktree: &Path, admin: &Path) -> Result<(), String> {
    if NS.get().is_none() {
        return Err(
            "the session namespace is not attached; worktree protections unavailable".into(),
        );
    }
    apply(&worktree_set(worktree, admin))
}

fn exists(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok()
}

/// The protections for one worktree and its admin directory, in mount order:
/// pins first, read-only binds on top.
pub fn worktree_set(worktree: &Path, admin: &Path) -> Vec<(PathBuf, Mode)> {
    use crate::sandbox::bubblewrap_paths as bw;
    let mut set = vec![
        (worktree.to_path_buf(), Mode::Pin),
        (admin.to_path_buf(), Mode::Pin),
    ];
    let pins = bw::rename_pins(worktree);
    set.extend(
        pins.into_iter()
            .filter(|p| exists(p))
            .map(|p| (p, Mode::Pin)),
    );
    let ro = bw::persistence(worktree)
        .into_iter()
        .chain([
            worktree.join(".git"),
            admin.join("commondir"),
            admin.join("gitdir"),
            admin.join("config.worktree"),
        ])
        .filter(|p| exists(p));
    set.extend(ro.map(|p| (p, Mode::Ro)));
    set.dedup();
    set
}

/// `<common>/worktrees` read-only, each admin directory writable on top, and
/// the worktree set for every admin directory whose worktree is in the root.
fn launch_set(root: &Path, common: &Path) -> Result<Vec<(PathBuf, Mode)>, String> {
    let worktrees = common.join("worktrees");
    match std::fs::symlink_metadata(&worktrees) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err(format!("{} is not a directory", worktrees.display())),
        Err(_) => std::fs::create_dir(&worktrees)
            .map_err(|e| format!("cannot create {}: {e}", worktrees.display()))?,
    }
    let mut set = vec![(worktrees.clone(), Mode::Ro)];
    let mut admins: Vec<PathBuf> = std::fs::read_dir(&worktrees)
        .map_err(|e| format!("cannot list {}: {e}", worktrees.display()))?
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    admins.sort();
    for admin in &admins {
        set.push((admin.clone(), Mode::Rw));
    }
    for admin in &admins {
        let Ok(Some(text)) = crate::untrusted::read_untrusted(&admin.join("gitdir"), 4096) else {
            continue;
        };
        let Some(wt) = Path::new(text.trim()).parent() else {
            continue;
        };
        if wt.parent() == Some(root) && exists(wt) {
            set.extend(worktree_set(wt, admin));
        }
    }
    Ok(set)
}

/// Run the helper with the namespace descriptors on fds 3 and 4 and the set
/// on stdin, one `<mode>\t<path>` per line.
#[allow(clippy::disallowed_methods)] // current_exe: this binary, by absolute path
fn apply(set: &[(PathBuf, Mode)]) -> Result<(), String> {
    use std::os::unix::process::CommandExt as _;
    let (user, mnt) = NS.get().ok_or("the session namespace is not attached")?;
    let (user, mnt) = (user.as_raw_fd(), mnt.as_raw_fd());
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate cplt: {e}"))?;
    let mut input = String::new();
    for (path, mode) in set {
        let text = path.to_str().ok_or("worktree paths must be UTF-8")?;
        if text.contains(['\n', '\t']) {
            return Err("worktree paths must not contain tabs or newlines".into());
        }
        input.push_str(&format!("{}\t{text}\n", mode.tag()));
    }
    let mut cmd = Command::new(exe);
    cmd.arg(HELPER_ARG)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: dup2 only, between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(user, 3) < 0 || libc::dup2(mnt, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start the namespace helper: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("namespace helper failed: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "cannot protect the managed worktrees: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// The helper: join the namespaces on fds 3 and 4, then bind every line of
/// stdin onto itself. Exits non-zero at the first failure.
pub fn helper_main() -> ExitCode {
    match helper() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn helper() -> Result<(), String> {
    // SAFETY: setns on descriptors the parent placed at 3 and 4.
    unsafe {
        if libc::setns(3, libc::CLONE_NEWUSER) != 0 {
            return Err(format!("setns(user): {}", std::io::Error::last_os_error()));
        }
        if libc::setns(4, libc::CLONE_NEWNS) != 0 {
            return Err(format!("setns(mnt): {}", std::io::Error::last_os_error()));
        }
    }
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| format!("cannot read the set: {e}"))?;
        let (tag, path) = line.split_once('\t').ok_or("malformed line")?;
        let mode = match tag {
            "ro" => Mode::Ro,
            "pin" => Mode::Pin,
            "rw" => Mode::Rw,
            _ => return Err(format!("unknown mode {tag:?}")),
        };
        bind(Path::new(path), mode).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(())
}

const OPEN_TREE_CLONE: libc::c_uint = 1;
const AT_RECURSIVE: libc::c_uint = 0x8000;
const MOUNT_ATTR_RDONLY: u64 = 1;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;
const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x40;

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Clone the mount tree at `path` (submounts included, so earlier binds below
/// it stay) and attach it on top of `path`, changing only the top mount's
/// read-only flag.
fn bind(path: &Path, mode: Mode) -> std::io::Result<()> {
    let target = crate::sandbox::landlock_mod::open_no_symlinks_walk(path)?;
    // SAFETY: raw mount syscalls on descriptors owned here; empty C strings.
    unsafe {
        let tree = libc::syscall(
            libc::SYS_open_tree,
            target.as_raw_fd(),
            c"".as_ptr(),
            OPEN_TREE_CLONE
                | AT_RECURSIVE
                | libc::AT_EMPTY_PATH as libc::c_uint
                | libc::O_CLOEXEC as libc::c_uint,
        );
        if tree < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let tree = OwnedFd::from_raw_fd(tree as i32);
        let (set, clr) = match mode {
            Mode::Ro => (MOUNT_ATTR_RDONLY, 0),
            Mode::Rw => (0, MOUNT_ATTR_RDONLY),
            Mode::Pin => (0, 0),
        };
        if set != 0 || clr != 0 {
            let attr = MountAttr {
                attr_set: set,
                attr_clr: clr,
                propagation: 0,
                userns_fd: 0,
            };
            if libc::syscall(
                libc::SYS_mount_setattr,
                tree.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH as libc::c_uint,
                &raw const attr,
                std::mem::size_of::<MountAttr>(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        if libc::syscall(
            libc::SYS_move_mount,
            tree.as_raw_fd(),
            c"".as_ptr(),
            target.as_raw_fd(),
            c"".as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
