//! Parent-side broker for `cplt worktree add <name> <ref>` (#531, macOS only).
//!
//! `git worktree add` inside the sandbox writes the checkout, the admin dir and
//! the `.git` pointer under agent control, and the root is checked only after
//! the fact. This module moves checkout into private staging, with Git still
//! constrained by the session read policy. The sandboxed
//! client sends one bounded JSON line over a per-session Unix socket. The parent
//! checks out a fixed commit in private staging, validates the tree, points the
//! admin dir at its final location and publishes the worktree into the root with
//! one atomic no-overwrite rename.
//!
//! Scope is detached HEAD only. A branch is made by the agent afterwards with
//! `git -C <path> switch -c <branch>`, under the same sandbox rules as any
//! worktree. The broker writes no refs, so a failed request never has to delete
//! one.
//!
//! Authority: the socket lives in a directory outside every granted root, and
//! the sandbox may connect to that one path only. There is no secret. The client
//! is the sandboxed agent, the same authority the sandbox already grants, so a
//! token would add nothing.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::git;
use crate::worktrees;

/// The environment variable the sandboxed client reads the socket from.
pub const SOCKET_ENV: &str = "CPLT_WORKTREE_SOCKET";

/// Longest request or response line. A request is a few dozen bytes, so anything
/// past this is not a request this broker serves.
const MAX_LINE: u64 = 4096;
/// Bounds a single read or write, so a client that connects and stalls cannot
/// hold the serial worker.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// One budget shared by lock acquisition, all commands and tree validation.
const GIT_TIMEOUT: Duration = Duration::from_secs(60);
/// Entries (files and directories) the tree check visits. Past this the tree is
/// refused, not partly checked.
const MAX_TREE_ENTRIES: usize = 200_000;
/// `sun_path` on macOS is 104 bytes including the NUL.
#[cfg(target_os = "macos")]
const SOCKET_PATH_MAX: usize = 103;
/// Lock file under the base, held for the duration of one add. Serialises
/// sessions of the same user, which each run their own broker.
const LOCK_NAME: &str = ".lock";
const STAGING_DIR: &str = ".staging";

/// One request from the client. Unknown fields are refused, so a future client
/// cannot silently ask for something this broker ignores.
#[cfg(target_os = "macos")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    op: String,
    name: String,
    #[serde(rename = "ref")]
    reference: String,
}

/// The reply: exactly one of `path` (on success) or `error`.
#[derive(Serialize, Deserialize)]
struct Response {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// The paths one broker serves. All of them are fixed when the session starts.
#[derive(Clone, Debug)]
pub struct Context {
    /// `~/.cplt-worktrees`: outside every granted root, private to cplt.
    base: PathBuf,
    /// The repository's common git directory.
    common: PathBuf,
    common_fd: Arc<File>,
    /// Resolved at launch, never through a linked worktree's commondir.
    objects: PathBuf,
    objects_fd: Arc<File>,
    home: Option<std::ffi::OsString>,
    xdg_config_home: Option<std::ffi::OsString>,
    read_policy: Arc<OnceLock<String>>,
    protected: ProtectedTree,
    /// `<base>/<fingerprint>`, the directory worktrees are published into.
    root: PathBuf,
}

impl Context {
    /// `root` must be `<base>/<fingerprint>`, the layout
    /// [`worktrees::prepare_root`] produces. Anything else is refused, because
    /// the lock, the staging area and the socket are all derived from `base`.
    pub fn new(project: &Path, common: &Path, root: &Path) -> Result<Self, String> {
        let base = root
            .parent()
            .ok_or("worktree root has no parent directory")?
            .to_path_buf();
        if base.file_name() != Some(worktrees::BASE.as_ref()) {
            return Err(format!(
                "worktree root {} is not under {}",
                root.display(),
                worktrees::BASE
            ));
        }
        let common = std::fs::canonicalize(common)
            .map_err(|e| format!("cannot resolve common git directory: {e}"))?;
        let objects = std::fs::canonicalize(common.join("objects"))
            .map_err(|e| format!("cannot resolve git objects: {e}"))?;
        for path in [&common, &objects, root] {
            let text = path.to_str().ok_or("broker paths must be UTF-8")?;
            if text.contains(['\n', '\r']) {
                return Err("broker paths must not contain newlines".into());
            }
        }
        let mut ctx = Self {
            base,
            common_fd: Arc::new(open_dir(&common)?),
            objects_fd: Arc::new(open_dir(&objects)?),
            common,
            objects,
            home: std::env::var_os("HOME"),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            read_policy: Arc::new(OnceLock::new()),
            protected: BTreeMap::new(),
            root: root.to_path_buf(),
        };
        let stop = AtomicBool::new(false);
        let budget = Budget::new(&stop);
        // The launch checkout may be linked and have a different HEAD from the
        // main checkout. Pin its commit before any agent can move either ref.
        let mut head = git::command(project, &["rev-parse", "--verify", "HEAD^{commit}"])
            .ok_or("no trusted git binary to snapshot launch HEAD")?;
        harden_data_query(&ctx, &mut head);
        let out = run_bounded(head, &budget)?;
        let sha =
            commit_id(&out).map_err(|_| "cannot snapshot launch HEAD: it must name a commit")?;
        let cmd = pinned_common_command(&ctx, &["ls-tree", "-r", "-z", "--full-tree", &sha])?;
        ctx.protected = protected_tree(run_bounded(cmd, &budget)?, &budget)?;
        Ok(ctx)
    }

    /// Install the immutable policy before serving requests. Without it every
    /// operation fails closed, including direct library calls to add().
    pub fn set_read_policy(&self, profile: &str) -> Result<(), String> {
        self.read_policy
            .set(profile.to_string())
            .map_err(|_| "worktree broker read policy was already installed".into())
    }
}

/// A running broker. Dropping it stops the worker and removes the socket after
/// request cancellation and cleanup. Filesystem cleanup is outside the budget.
#[derive(Debug)]
pub struct Broker {
    socket: PathBuf,
    #[cfg(target_os = "macos")]
    _socket_dir: crate::scratch::PlaywrightSocketDir,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    #[cfg(target_os = "macos")]
    read_policy: Arc<OnceLock<String>>,
}

impl Broker {
    /// Reuse the short private socket-directory guard. The session profile pins
    /// this directory against writes; no broad temp-directory grant is added.
    #[cfg(target_os = "macos")]
    pub fn start(ctx: Context) -> Result<Self, String> {
        secure_dir(&ctx.base, "worktree base")?;
        let socket_dir = crate::scratch::PlaywrightSocketDir::create()?;
        let socket = socket_dir.path().join("s");
        if socket.as_os_str().len() > SOCKET_PATH_MAX {
            return Err("the worktree broker socket exceeds the Unix socket path limit".into());
        }
        let listener = UnixListener::bind(&socket)
            .map_err(|e| format!("cannot bind {}: {e}", socket.display()))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot restrict {}: {e}", socket.display()))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("cannot poll {}: {e}", socket.display()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let read_policy = Arc::clone(&ctx.read_policy);
        let worker_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("cplt-worktree-broker".into())
            .spawn(move || serve(&listener, &ctx, &worker_stop))
            .map_err(|e| format!("cannot start the worktree broker thread: {e}"))?;
        Ok(Self {
            socket,
            _socket_dir: socket_dir,
            stop,
            thread: Some(thread),
            read_policy,
        })
    }

    /// Off macOS the key is refused before a launch gets here, so this is only
    /// reached by a bug. It fails rather than running without the sandbox rule.
    #[cfg(not(target_os = "macos"))]
    pub fn start(_ctx: Context) -> Result<Self, String> {
        Err("the worktree broker is macOS-only".into())
    }

    /// The socket path. The sandbox profile grants connect to this exact path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Capture the final session policy, after all PreparedSandbox amendments.
    /// Linux never starts this broker and must not treat a policy summary as SBPL.
    #[cfg(target_os = "macos")]
    pub fn set_sandbox(&self, sandbox: &crate::sandbox::PreparedSandbox) -> Result<(), String> {
        self.read_policy
            .set(crate::sandbox::describe(sandbox).to_string())
            .map_err(|_| "worktree broker read policy was already installed".into())
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

#[cfg(target_os = "macos")]
/// The accept loop. Polled rather than blocking, so `stop` is seen within one
/// poll interval even with no client.
fn serve(listener: &UnixListener, ctx: &Context, stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                // macOS hands an accepted socket the listener's O_NONBLOCK.
                let _ = stream.set_nonblocking(false);
                handle(ctx, stream, stop);
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

#[cfg(target_os = "macos")]
/// Serve one connection: read one request, answer once, close.
fn handle(ctx: &Context, stream: UnixStream, stop: &AtomicBool) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let response = match read_request(&stream, stop)
        .and_then(|r| add_with_budget(ctx, &r.name, &r.reference, &Budget::new(stop)))
    {
        Ok(path) => Response {
            ok: true,
            path: Some(path),
            error: None,
        },
        Err(error) => Response {
            ok: false,
            path: None,
            error: Some(truncate(&error, 512)),
        },
    };
    if let Ok(mut line) = serde_json::to_string(&response) {
        line.push('\n');
        let _ = (&stream).write_all(line.as_bytes());
    }
}

#[cfg(target_os = "macos")]
fn read_request(stream: &UnixStream, stop: &AtomicBool) -> Result<Request, String> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut line = Vec::new();
    while line.len() < MAX_LINE as usize {
        if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err("request read deadline exceeded".into());
        }
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| format!("cannot bound request read: {e}"))?;
        let mut byte = [0];
        match (&*stream).read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(format!("cannot read request: {e}")),
        }
    }
    let body = line
        .strip_suffix(b"\n")
        .ok_or("request must be one line of at most 4096 bytes")?;
    let req: Request = serde_json::from_slice(body)
        .map_err(|_| "request is not a valid add request".to_string())?;
    if req.op != "add" {
        return Err(format!("unknown operation {:?}", truncate(&req.op, 32)));
    }
    Ok(req)
}

/// Create the worktree `name` at commit `reference`, detached, in the root.
///
/// Every step runs in order, and the first failure rolls back what this call
/// created. Checkout never reads agent-controlled config or linked admin files.
/// Shared admin writes are exclusive and descriptor-relative, never truncating.
pub fn add(ctx: &Context, name: &str, reference: &str) -> Result<String, String> {
    add_with_budget(ctx, name, reference, &Budget::new(&AtomicBool::new(false)))
}

fn add_with_budget(
    ctx: &Context,
    name: &str,
    reference: &str,
    budget: &Budget<'_>,
) -> Result<String, String> {
    validate_name(name)?;
    validate_reference(reference)?;
    ctx.read_policy
        .get()
        .ok_or("worktree broker session read policy is not installed")?;
    let _lock = acquire_lock(&ctx.base, budget)?;
    check_identity(&ctx.common, &ctx.common_fd)?;
    check_identity(&ctx.objects, &ctx.objects_fd)?;
    refuse_filters(ctx, budget)?;
    let sha = resolve_commit(ctx, reference, budget)?;
    let tree = protected_tree(
        run_bounded(
            common_command(ctx, &["ls-tree", "-r", "-z", "--full-tree", &sha])?,
            budget,
        )?,
        budget,
    )?;
    if tree != ctx.protected {
        return Err(
            "protected config differs from launch HEAD; prepare the worktree outside cplt".into(),
        );
    }

    let staging = new_staging_dir(&ctx.base)?;
    let mut job = Job {
        staging: staging.clone(),
        admin: None,
        worktree: staging.join(name),
        final_git: ctx.root.join(name).join(".git"),
        published: false,
    };
    let private = staging.join("git");
    checkout(ctx, &private, &job.worktree, &sha, budget)?;
    validate_tree(&job.worktree, budget)?;
    verify_protected_checkout(ctx, &private, &job.worktree, budget)?;
    check_identity(&ctx.common, &ctx.common_fd)?;
    budget.check()?;
    job.admin = Some(Admin::create(ctx)?);
    let admin = job.admin.as_ref().unwrap();
    admin.write("HEAD", format!("{sha}\n").as_bytes())?;
    admin.write("commondir", b"../..\n")?;
    admin.write(
        "gitdir",
        format!("{}\n", job.final_git.display()).as_bytes(),
    )?;
    let mut index =
        File::open(private.join("index")).map_err(|e| format!("cannot open private index: {e}"))?;
    let mut target = admin.create_file("index")?;
    let mut buf = [0; 8192];
    loop {
        budget.check()?;
        let n = index
            .read(&mut buf)
            .map_err(|e| format!("cannot read private index: {e}"))?;
        if n == 0 {
            break;
        }
        target
            .write_all(&buf[..n])
            .map_err(|e| format!("cannot copy index: {e}"))?;
    }
    std::fs::write(
        job.worktree.join(".git"),
        format!(
            "gitdir: {}\n",
            ctx.common.join("worktrees").join(&admin.name).display()
        ),
    )
    .map_err(|e| format!("cannot write staged .git pointer: {e}"))?;
    admin.check_identity()?;
    same_directory(
        &open_at(
            &ctx.common_fd,
            "worktrees",
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?,
        &admin.parent,
    )?;
    budget.check()?;
    publish(&staging, name, &ctx.root)?;
    job.published = true;
    Ok(job
        .final_git
        .parent()
        .unwrap_or(&ctx.root)
        .display()
        .to_string())
}

/// What one request has created so far, and the cleanup owed if it fails.
struct Job {
    staging: PathBuf,
    admin: Option<Admin>,
    worktree: PathBuf,
    final_git: PathBuf,
    published: bool,
}

impl Drop for Job {
    fn drop(&mut self) {
        if let Some(admin) = &mut self.admin {
            admin.published = self.published;
        }
        // Only this broker can access staging, including after publication.
        let _ = std::fs::remove_dir_all(&self.staging);
    }
}

/// The request's name: one path component git and the filesystem both accept,
/// with no leading dot, so it can never be `.git`, `..` or a hidden entry.
pub fn validate_name(name: &str) -> Result<(), String> {
    let first_ok = name
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric());
    let ok = first_ok
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !name.contains("..")
        && !name.ends_with('.')
        && !name.to_ascii_lowercase().ends_with(".lock");
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid worktree name {:?}: use letters, digits, '.', '_' or '-', starting with a \
             letter or digit, at most 64 characters",
            truncate(name, 64)
        ))
    }
}

/// The request's ref: a branch, tag or commit name. Only the shapes cplt
/// accepts are passed to git; anything git would read as an option (a leading
/// `-`) is refused by the first-character rule.
pub fn validate_reference(reference: &str) -> Result<(), String> {
    let first_ok = reference
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric());
    let ok = first_ok
        && reference.len() <= 255
        && reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
        && !reference.contains("..")
        && !reference.contains("//")
        && !reference.ends_with('/')
        && !reference.ends_with('.')
        && !reference.ends_with(".lock");
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid ref {:?}: use a branch, tag or commit name",
            truncate(reference, 64)
        ))
    }
}

/// Refuse when any `filter.<name>.*` is set in any config scope, including the
/// user's global config.
///
/// This is a fidelity check, not an execution barrier: private checkout config
/// cannot load these drivers even if they change after this check.
fn refuse_filters(ctx: &Context, budget: &Budget<'_>) -> Result<(), String> {
    let cmd = common_command(
        ctx,
        &[
            "config",
            "--includes",
            "--name-only",
            "--get-regexp",
            r"^filter\.",
        ],
    )?;
    let out = run_bounded(cmd, budget)?;
    match out.status.code() {
        Some(1) => Ok(()),
        Some(0) => {
            let keys: Vec<&str> = std::str::from_utf8(&out.stdout)
                .unwrap_or("")
                .lines()
                .filter_map(|l| l.split_whitespace().next())
                .collect();
            Err(format!(
                "refusing: a git content filter is configured ({}). Private checkout cannot \
                 reproduce its transformations. Remove those filter.* entries from the repository or your global git \
                 config, or use `git worktree add` inside the sandbox instead.",
                truncate(&keys.join(", "), 200)
            ))
        }
        _ => Err("cannot check the repository for content filters".into()),
    }
}

/// The full commit `reference` names, read from local refs only. No fetch.
fn resolve_commit(ctx: &Context, reference: &str, budget: &Budget<'_>) -> Result<String, String> {
    let spec = format!("{reference}^{{commit}}");
    let cmd = common_command(ctx, &["rev-parse", "--verify", "--quiet", &spec])?;
    let out = run_bounded(cmd, budget)?;
    if !out.status.success() {
        return Err(format!(
            "ref {:?} does not name a commit in this repository",
            truncate(reference, 64)
        ));
    }
    commit_id(&out)
}

fn commit_id(out: &Output) -> Result<String, String> {
    if !out.status.success() {
        return Err("git could not resolve a commit".into());
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let hex_ok = matches!(sha.len(), 40 | 64) && sha.bytes().all(|b| b.is_ascii_hexdigit());
    if hex_ok {
        Ok(sha)
    } else {
        Err("git did not return a commit id".into())
    }
}

/// Only data queries use common config; explicitly pin both Git directories so
/// a replaced launch-worktree commondir cannot redirect them. No transport.
fn common_command(ctx: &Context, args: &[&str]) -> Result<Command, String> {
    sandbox_git(ctx, pinned_common_command(ctx, args)?, None)
}

/// Bootstrap use is limited to launch HEAD and its tree before agent startup.
/// Request-time callers must use common_command so session read denies apply.
fn pinned_common_command(ctx: &Context, args: &[&str]) -> Result<Command, String> {
    let dir = format!("--git-dir={}", ctx.common.display());
    let mut all = vec![dir.as_str()];
    all.extend_from_slice(args);
    let mut cmd = git::command(&ctx.common, &all).ok_or("no trusted git binary")?;
    harden_data_query(ctx, &mut cmd);
    Ok(cmd)
}

fn harden_data_query(ctx: &Context, cmd: &mut Command) {
    for (key, value) in [
        ("HOME", &ctx.home),
        ("XDG_CONFIG_HOME", &ctx.xdg_config_home),
    ] {
        if let Some(value) = value {
            cmd.env(key, value);
        } else {
            cmd.env_remove(key);
        }
    }
    cmd.env("GIT_COMMON_DIR", &ctx.common)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "protocol.allow")
        .env("GIT_CONFIG_VALUE_0", "never");
}

type ProtectedTree = BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)>;

/// Keep exact path bytes, mode and blob id. Case folding is only for matching
/// deny-table names, so renames and colliding aliases cannot compare equal.
fn protected_tree(out: Output, budget: &Budget<'_>) -> Result<ProtectedTree, String> {
    if !out.status.success() {
        return Err("cannot inspect protected paths in commit tree".into());
    }
    let mut protected = BTreeMap::new();
    let mut entries = 0;
    for entry in out.stdout.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        budget.check()?;
        entries += 1;
        if entries > MAX_TREE_ENTRIES {
            return Err("commit tree exceeds the broker entry limit".into());
        }
        let tab = entry
            .iter()
            .position(|b| *b == b'\t')
            .ok_or("invalid git tree entry")?;
        let path = &entry[tab + 1..];
        let fields: Vec<_> = entry[..tab].split(|b| *b == b' ').collect();
        if fields.len() != 3 {
            return Err("invalid git tree metadata".into());
        }
        let mode = fields[0];
        if protected_path(path, mode == b"120000" || mode == b"160000") {
            if mode != b"100644" && mode != b"100755" {
                return Err("protected config must be a regular tracked file; prepare the worktree outside cplt".into());
            }
            if protected
                .insert(path.to_vec(), (mode.to_vec(), fields[2].to_vec()))
                .is_some()
            {
                return Err("duplicate protected path in commit tree".into());
            }
        }
    }
    Ok(protected)
}

fn protected_path(path: &[u8], ancestor: bool) -> bool {
    let path = path.to_ascii_lowercase();
    let components: Vec<_> = path.split(|b| *b == b'/').collect();
    crate::sandbox::PROTECTED_IN_ROOT.iter().any(|p| {
        let rel = p.rel.as_bytes().to_ascii_lowercase();
        let wanted: Vec<_> = rel.split(|b| *b == b'/').collect();
        (0..components.len())
            .filter(|start| *start == 0 || p.nested)
            .any(|start| {
                let actual = &components[start..];
                actual == wanted
                    || (p.tree && actual.starts_with(&wanted))
                    || (ancestor && wanted.starts_with(actual))
            })
    })
}

/// Attributes can transform bytes without changing the protected blob id in the
/// tree. Verify raw staged bytes too, before granting the published path.
fn verify_protected_checkout(
    ctx: &Context,
    private: &Path,
    worktree: &Path,
    budget: &Budget<'_>,
) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let entries: Vec<_> = ctx.protected.iter().collect();
    for batch in entries.chunks(128) {
        budget.check()?;
        let mut cmd =
            git::private_data_command(private, worktree).ok_or("no trusted git binary")?;
        cmd.current_dir(worktree)
            .args(["hash-object", "--no-filters", "--"]);
        for (path, _) in batch {
            cmd.arg(std::ffi::OsStr::from_bytes(path));
        }
        let out = run_bounded(sandbox_git(ctx, cmd, private.parent())?, budget)?;
        if !out.status.success() {
            return Err("cannot verify protected checkout content".into());
        }
        let ids: Vec<_> = out
            .stdout
            .split(|b| *b == b'\n')
            .filter(|id| !id.is_empty())
            .collect();
        if ids.len() != batch.len()
            || ids
                .iter()
                .zip(batch)
                .any(|(id, (_, (_, expected)))| *id != expected.as_slice())
        {
            return Err("protected checkout bytes differ from launch HEAD; prepare the worktree outside cplt".into());
        }
    }
    Ok(())
}

/// The kernel enforces reads of refs, config includes and recursive alternates.
/// Path preflight cannot enforce this: every intermediate link is agent mutable.
#[cfg(target_os = "macos")]
#[allow(clippy::disallowed_methods)] // absolute SIP-protected sandbox-exec
fn sandbox_git(ctx: &Context, cmd: Command, staging: Option<&Path>) -> Result<Command, String> {
    use std::fmt::Write as _;
    let mut profile = ctx
        .read_policy
        .get()
        .ok_or("worktree broker session read policy is not installed")?
        .clone();
    if let Some(staging) = staging {
        crate::sandbox::validate_sbpl_path(staging)?;
        // This grant is only on private request data. It grants no source read
        // outside staging, and no execution of materialized repository content.
        write!(profile, "\n(allow file-read* file-write* (subpath \"{}\"))\n(deny process-exec (subpath \"{}\"))\n", staging.display(), staging.display())
            .map_err(|e| format!("cannot build broker checkout profile: {e}"))?;
    }
    let mut wrapped = Command::new("/usr/bin/sandbox-exec");
    wrapped
        .args(["-p", &profile])
        .arg(cmd.get_program())
        .args(cmd.get_args());
    for (key, value) in cmd.get_envs() {
        if let Some(value) = value {
            wrapped.env(key, value);
        } else {
            wrapped.env_remove(key);
        }
    }
    if let Some(dir) = cmd.get_current_dir() {
        wrapped.current_dir(dir);
    }
    wrapped.stdin(Stdio::null());
    Ok(wrapped)
}

#[cfg(not(target_os = "macos"))]
fn sandbox_git(_ctx: &Context, _cmd: Command, _staging: Option<&Path>) -> Result<Command, String> {
    Err("the worktree broker is macOS-only".into())
}

/// Private metadata has no commondir, includes, filters or promisor remotes.
/// Alternates load objects only, never the alternate repository's config.
fn checkout(
    ctx: &Context,
    private: &Path,
    worktree: &Path,
    sha: &str,
    budget: &Budget<'_>,
) -> Result<(), String> {
    for dir in [
        private.to_path_buf(),
        private.join("objects"),
        private.join("objects/info"),
        private.join("refs"),
        worktree.to_path_buf(),
    ] {
        std::fs::create_dir(&dir).map_err(|e| format!("cannot create private checkout: {e}"))?;
    }
    if ctx.objects.as_os_str().as_encoded_bytes().contains(&b'\n') {
        return Err("git objects path contains a newline".into());
    }
    std::fs::write(
        private.join("objects/info/alternates"),
        format!("{}\n", ctx.objects.display()),
    )
    .map_err(|e| format!("cannot write private alternates: {e}"))?;
    // SHA-256 needs an explicit repository format; SHA-1 uses Git's default.
    let config = if sha.len() == 64 {
        "[core]\nrepositoryformatversion = 1\n[extensions]\nobjectFormat = sha256\n"
    } else {
        "[core]\nrepositoryformatversion = 0\n"
    };
    std::fs::write(private.join("config"), config)
        .map_err(|e| format!("cannot write private config: {e}"))?;
    std::fs::write(private.join("HEAD"), format!("{sha}\n"))
        .map_err(|e| format!("cannot write private HEAD: {e}"))?;
    let mut cmd = git::private_checkout_command(private, worktree, sha)
        .ok_or("no trusted git binary to create the worktree")?;
    cmd.current_dir(worktree);
    let out = run_bounded(sandbox_git(ctx, cmd, private.parent())?, budget)?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "private git checkout failed: {}",
            truncate(String::from_utf8_lossy(&out.stderr).trim(), 300)
        ))
    }
}

/// Check the staged tree before it is published. Refuses:
///
/// - any entry named `.git` (any letter case), which would be a nested
///   repository the host's git follows;
/// - a directory holding `HEAD`, `objects` and `refs`, which git reads as a bare
///   repository and whose `config` it then obeys;
/// - a symlink that is absolute or whose resolved target leaves the worktree;
/// - more than [`MAX_TREE_ENTRIES`] entries.
///
/// Symlinks are checked with `read_link`, not followed, and no directory is
/// entered through a link. Staging is private to this process, so nothing
/// changes under the walk.
fn validate_tree(worktree: &Path, budget: &Budget<'_>) -> Result<(), String> {
    let root =
        std::fs::canonicalize(worktree).map_err(|e| format!("cannot resolve worktree: {e}"))?;
    let mut stack = vec![worktree.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let mut has_head = false;
        let mut has_objects = false;
        let mut has_refs = false;
        let mut has_commondir = false;
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for entry in entries {
            budget.check()?;
            let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
            seen += 1;
            if seen > MAX_TREE_ENTRIES {
                return Err(format!(
                    "the checkout has more than {MAX_TREE_ENTRIES} entries; refusing to publish it"
                ));
            }
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.eq_ignore_ascii_case(".git") {
                return Err(format!(
                    "the checkout contains a nested repository at {}",
                    path.strip_prefix(worktree).unwrap_or(&path).display()
                ));
            }
            let ft = entry
                .file_type()
                .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
            // Bare-repo markers are checked by name for every entry type: `refs`
            // and `objects` are directories, `HEAD` a file.
            match name.as_ref() {
                "HEAD" if !ft.is_dir() => has_head = true,
                "refs" if ft.is_dir() => has_refs = true,
                "objects" if ft.is_dir() => has_objects = true,
                "commondir" => has_commondir = true,
                _ => {}
            }
            if ft.is_symlink() {
                check_symlink(&path, &root)?;
            } else if ft.is_dir() {
                stack.push(path);
            }
        }
        if has_head && ((has_objects && has_refs) || has_commondir) {
            return Err(format!(
                "{} looks like a bare git repository; refusing to publish it",
                dir.strip_prefix(worktree).unwrap_or(&dir).display()
            ));
        }
    }
    Ok(())
}

/// A symlink must resolve to something inside `root`. Absolute targets are
/// refused outright. A relative target is resolved through the filesystem when
/// it exists, so a link to a link that leaves the tree is caught, and lexically
/// when it dangles.
fn check_symlink(link: &Path, root: &Path) -> Result<(), String> {
    let target =
        std::fs::read_link(link).map_err(|e| format!("cannot read {}: {e}", link.display()))?;
    let rel = link.strip_prefix(root).unwrap_or(link);
    let escapes = || {
        format!(
            "symlink {} points outside the worktree; refusing to publish it",
            rel.display()
        )
    };
    if target.is_absolute() {
        return Err(escapes());
    }
    if let Ok(resolved) = std::fs::canonicalize(link) {
        return if resolved.starts_with(root) {
            Ok(())
        } else {
            Err(escapes())
        };
    }
    // Dangling: walk the components lexically from the link's directory.
    let mut depth: i64 = link
        .parent()
        .and_then(|p| p.strip_prefix(root).ok())
        .map_or(0, |p| {
            i64::try_from(p.components().count()).unwrap_or(i64::MAX)
        });
    for c in target.components() {
        match c {
            Component::ParentDir => depth -= 1,
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            _ => return Err(escapes()),
        }
        if depth < 0 {
            return Err(escapes());
        }
    }
    Ok(())
}

fn open_dir(path: &Path) -> Result<File, String> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))
}

fn check_identity(path: &Path, saved: &File) -> Result<(), String> {
    same_directory(&open_dir(path)?, saved)
}

fn same_directory(current: &File, saved: &File) -> Result<(), String> {
    let a = current.metadata().map_err(|e| e.to_string())?;
    let b = saved.metadata().map_err(|e| e.to_string())?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err("git administration directory was replaced".into());
    }
    Ok(())
}

fn open_at(dir: &File, name: &str, flags: i32) -> Result<File, String> {
    let name = CString::new(name).map_err(|_| "invalid admin filename")?;
    // SAFETY: dir stays open and name is a live NUL-terminated string.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "cannot open git admin entry: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: openat returned a fresh descriptor, owned by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn mkdir_at(dir: &File, name: &str) -> Result<(), String> {
    let name = CString::new(name).map_err(|_| "invalid admin directory name")?;
    // SAFETY: dir stays open and name is a live NUL-terminated string.
    if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(format!(
            "cannot create git admin directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Hold descriptors across writes and rollback. Agent namespaces are never
/// recursively deleted, and pre-existing files can never be truncated.
struct Admin {
    parent: File,
    dir: File,
    name: String,
    published: bool,
}

impl Admin {
    fn create(ctx: &Context) -> Result<Self, String> {
        // EEXIST is fine only if the subsequent no-follow directory open succeeds.
        let name = CString::new("worktrees").unwrap();
        // SAFETY: common_fd and name outlive the call.
        if unsafe { libc::mkdirat(ctx.common_fd.as_raw_fd(), name.as_ptr(), 0o700) } != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
        {
            return Err("cannot create common worktrees directory".into());
        }
        let parent = open_at(
            &ctx.common_fd,
            "worktrees",
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let name = format!("cplt-{}", random_hex()?);
        mkdir_at(&parent, &name)?;
        let dir = open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        Ok(Self {
            parent,
            dir,
            name,
            published: false,
        })
    }

    fn create_file(&self, name: &str) -> Result<File, String> {
        open_at(
            &self.dir,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
        )
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.create_file(name)?
            .write_all(bytes)
            .map_err(|e| format!("cannot write git admin entry: {e}"))
    }

    fn check_identity(&self) -> Result<(), String> {
        same_directory(
            &open_at(&self.parent, &self.name, libc::O_RDONLY | libc::O_DIRECTORY)?,
            &self.dir,
        )
    }
}

impl Drop for Admin {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        for name in ["HEAD", "commondir", "gitdir", "index"] {
            let name = CString::new(name).unwrap();
            // SAFETY: descriptor and filename are live. unlinkat does not follow links.
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        if self.check_identity().is_ok() {
            let name = CString::new(self.name.as_str()).unwrap();
            // SAFETY: descriptor and name are live; only an empty directory is removed.
            unsafe {
                libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
            }
        }
    }
}

struct Budget<'a> {
    deadline: Instant,
    stop: &'a AtomicBool,
}

impl<'a> Budget<'a> {
    fn new(stop: &'a AtomicBool) -> Self {
        Self {
            deadline: Instant::now() + GIT_TIMEOUT,
            stop,
        }
    }

    fn check(&self) -> Result<(), String> {
        if self.stop.load(Ordering::Acquire) {
            return Err("worktree broker is stopping".into());
        }
        if Instant::now() >= self.deadline {
            return Err("worktree request deadline exceeded (60s)".into());
        }
        Ok(())
    }
}

/// Move the staged worktree into the root. `RENAME_EXCL` makes an existing name
/// an error, so an existing worktree is never replaced, and the descriptors
/// make the two directories the ones opened, not whatever the names point at by
/// then.
#[cfg(target_os = "macos")]
fn publish(staging: &Path, name: &str, root: &Path) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::io::AsRawFd;
    let open_dir = |p: &Path| {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(p)
            .map_err(|e| format!("cannot open {}: {e}", p.display()))
    };
    let src_dir = open_dir(staging)?;
    let dst_dir = open_dir(root)?;
    let c_name = CString::new(name).map_err(|_| "worktree name contains a NUL byte")?;
    // SAFETY: both descriptors are open directories owned by this function for
    // the duration of the call, and both names are NUL-terminated C strings that
    // outlive it. renameatx_np only reads them.
    let rc = unsafe {
        libc::renameatx_np(
            src_dir.as_raw_fd(),
            c_name.as_ptr(),
            dst_dir.as_raw_fd(),
            c_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        return Err(format!(
            "{name} already exists in the managed worktree root; choose another name"
        ));
    }
    Err(format!("cannot publish the worktree: {err}"))
}

#[cfg(not(target_os = "macos"))]
fn publish(_staging: &Path, _name: &str, _root: &Path) -> Result<(), String> {
    Err("the worktree broker is macOS-only".into())
}

/// Poll the base lock within the request budget; shutdown also cancels a wait.
fn acquire_lock(base: &Path, budget: &Budget<'_>) -> Result<File, String> {
    use std::os::unix::io::AsRawFd;
    let path = base.join(LOCK_NAME);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return Err("worktree lock is not a regular file".into());
    }
    loop {
        budget.check()?;
        // SAFETY: file owns the descriptor; flock takes no pointers.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            break;
        }
        let err = std::io::Error::last_os_error();
        if !matches!(err.raw_os_error(), Some(libc::EWOULDBLOCK | libc::EINTR)) {
            return Err(format!("cannot lock {}: {err}", path.display()));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(file)
}

/// A fresh staging directory, `<base>/.staging/<random>`, mode 0700.
fn new_staging_dir(base: &Path) -> Result<PathBuf, String> {
    let parent = base.join(STAGING_DIR);
    secure_dir(&parent, "worktree staging")?;
    let dir = parent.join(random_hex()?);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

/// Create (if absent) and check a directory cplt owns, mode 0700, no symlink.
/// The same checks the root gets, so the two cannot drift apart.
fn secure_dir(dir: &Path, label: &str) -> Result<(), String> {
    worktrees::secure_dir(dir, label, true)
}

/// 8 bytes from the kernel RNG, hex-encoded: 64 bits is enough that one session
/// cannot guess another's socket path, and short enough that the socket path
/// fits `sun_path` under a home directory of ordinary length.
fn random_hex() -> Result<String, String> {
    let mut bytes = [0u8; 8];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Drain nonblocking pipes while polling the shared deadline. Neither a full
/// pipe nor a descendant holding one open may extend the budget.
fn run_bounded(mut cmd: Command, budget: &Budget<'_>) -> Result<Output, String> {
    budget.check()?;
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run git: {e}"))?;
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or("missing git stdout")?;
        let mut stderr = child.stderr.take().ok_or("missing git stderr")?;
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            // SAFETY: these are live pipe descriptors owned above.
            if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                return Err("cannot make git output nonblocking".into());
            }
        }
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut out_done = false;
        let mut err_done = false;
        loop {
            budget.check()?;
            drain(&mut stdout, &mut out, &mut out_done, budget)?;
            drain(&mut stderr, &mut err, &mut err_done, budget)?;
            if let Some(status) = child
                .try_wait()
                .map_err(|e| format!("cannot wait for git: {e}"))?
                && out_done
                && err_done
            {
                return Ok(Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

fn drain(
    reader: &mut impl Read,
    bytes: &mut Vec<u8>,
    done: &mut bool,
    budget: &Budget<'_>,
) -> Result<(), String> {
    let mut buf = [0; 8192];
    loop {
        budget.check()?;
        match reader.read(&mut buf) {
            Ok(0) => {
                *done = true;
                return Ok(());
            }
            Ok(n) => {
                if bytes.len() + n > 1024 * 1024 {
                    return Err("git output exceeds 1 MiB".into());
                }
                bytes.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("cannot read git output: {e}")),
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// The sandboxed side of `cplt worktree add`. Sends one request to the socket
/// the sandbox grants, prints the new path on success.
///
/// The socket comes from [`SOCKET_ENV`], which the launcher sets after
/// filtering the environment, so a value inherited from the parent cannot point
/// the client elsewhere.
pub fn run_client(name: &str, reference: &str) -> ExitCode {
    let Some(socket) = std::env::var_os(SOCKET_ENV).filter(|s| !s.is_empty()) else {
        eprintln!(
            "cplt worktree: not available here. It needs a cplt session with \
             sandbox.allow_git_worktrees on, on macOS."
        );
        return ExitCode::FAILURE;
    };
    let stream = match UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cplt worktree: cannot reach the worktree broker: {e}");
            return ExitCode::FAILURE;
        }
    };
    let wait = GIT_TIMEOUT + IO_TIMEOUT;
    let _ = stream.set_read_timeout(Some(wait));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let Ok(mut line) = serde_json::to_string(&serde_json::json!({
        "op": "add",
        "name": name,
        "ref": reference,
    })) else {
        eprintln!("cplt worktree: cannot encode the request");
        return ExitCode::FAILURE;
    };
    line.push('\n');
    if let Err(e) = (&stream).write_all(line.as_bytes()) {
        eprintln!("cplt worktree: cannot send the request: {e}");
        return ExitCode::FAILURE;
    }
    let mut reply = Vec::new();
    if let Err(e) = (&stream).take(MAX_LINE).read_to_end(&mut reply) {
        eprintln!("cplt worktree: no reply from the broker: {e}");
        return ExitCode::FAILURE;
    }
    match serde_json::from_slice::<Response>(&reply) {
        Ok(Response {
            ok: true,
            path: Some(p),
            ..
        }) => {
            println!("{p}");
            ExitCode::SUCCESS
        }
        Ok(Response { error: Some(e), .. }) => {
            eprintln!("cplt worktree: {e}");
            ExitCode::FAILURE
        }
        _ => {
            eprintln!("cplt worktree: the broker sent an unreadable reply");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_matching_tracks_the_declaration_and_component_boundaries() {
        for p in crate::sandbox::PROTECTED_IN_ROOT {
            assert!(protected_path(p.rel.as_bytes(), false), "{}", p.rel);
            assert!(protected_path(p.rel.to_ascii_uppercase().as_bytes(), false));
            assert_eq!(
                protected_path(format!("nested/{}", p.rel).as_bytes(), false),
                p.nested
            );
            assert_eq!(
                protected_path(format!("{}/child", p.rel).as_bytes(), false),
                p.tree
            );
            assert!(!protected_path(
                format!("{}-ordinary", p.rel).as_bytes(),
                false
            ));
            if let Some((ancestor, _)) = p.rel.rsplit_once('/') {
                assert!(protected_path(ancestor.as_bytes(), true));
            }
        }
    }

    #[test]
    fn admin_writes_never_truncate_and_rollback_never_follows_a_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let parent = open_dir(temp.path()).unwrap();
        mkdir_at(&parent, "ours").unwrap();
        let admin = Admin {
            dir: open_at(&parent, "ours", libc::O_RDONLY | libc::O_DIRECTORY).unwrap(),
            parent,
            name: "ours".into(),
            published: false,
        };
        let victim = temp.path().join("victim");
        std::fs::write(&victim, "keep\n").unwrap();
        std::fs::hard_link(&victim, temp.path().join("ours/HEAD")).unwrap();
        assert!(admin.write("HEAD", b"overwrite\n").is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep\n");
        std::fs::rename(temp.path().join("ours"), temp.path().join("moved")).unwrap();
        std::fs::create_dir(temp.path().join("ours")).unwrap();
        std::fs::write(temp.path().join("ours/HEAD"), "other request\n").unwrap();
        drop(admin);
        assert_eq!(
            std::fs::read_to_string(temp.path().join("ours/HEAD")).unwrap(),
            "other request\n"
        );
        assert!(temp.path().join("moved").is_dir());
        assert_eq!(std::fs::read_to_string(victim).unwrap(), "keep\n");
    }

    #[test]
    fn a_lock_wait_obeys_the_operation_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let stop = AtomicBool::new(false);
        let _held = acquire_lock(temp.path(), &Budget::new(&stop)).unwrap();
        let budget = Budget {
            deadline: Instant::now() + Duration::from_millis(50),
            stop: &stop,
        };
        assert!(
            acquire_lock(temp.path(), &budget)
                .unwrap_err()
                .contains("deadline")
        );
    }

    #[test]
    #[allow(clippy::disallowed_methods)] // absolute trusted system shell, fixed test scripts
    fn commands_share_a_deadline_and_output_is_drained_and_capped() {
        let stop = AtomicBool::new(false);
        let mut budget = Budget {
            deadline: Instant::now() + Duration::from_secs(5),
            stop: &stop,
        };
        let mut first = Command::new("/bin/sh");
        first.args(["-c", "exit 0"]);
        run_bounded(first, &budget).unwrap();
        // Expiring the shared budget is deterministic even under suite load.
        budget.deadline = Instant::now();
        let mut second = Command::new("/bin/sh");
        second.args(["-c", "exit 0"]);
        assert!(
            run_bounded(second, &budget)
                .unwrap_err()
                .contains("deadline")
        );

        let mut output = Command::new("/bin/sh");
        output.args(["-c", "/usr/bin/yes output"]);
        assert!(
            run_bounded(output, &Budget::new(&stop))
                .unwrap_err()
                .contains("1 MiB")
        );
    }
}
