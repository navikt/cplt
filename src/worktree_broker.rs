//! Parent-side broker for `cplt worktree add <name> <ref>` (#531 macOS, #965 Linux).
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
//! Authority on macOS: the socket lives in a directory outside every granted
//! root, and the sandbox may connect to that one path only. On Linux, Landlock
//! below ABI v9 cannot gate `connect(2)` to a pathname socket, so there is no
//! path at all: the sandbox inherits one end of a `SOCK_SEQPACKET` socketpair,
//! and each client passes the broker a fresh stream over it (`SCM_RIGHTS`).
//! Only processes that inherited that descriptor can reach the broker. There is
//! no secret. The client is the sandboxed agent, the same authority the sandbox
//! already grants, so a token would add nothing.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::io::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd};
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
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
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    op: String,
    name: String,
    #[serde(rename = "ref", default)]
    reference: String,
    /// `remove --force`: remove even with local changes (#1015).
    #[serde(default)]
    force: bool,
    /// `-b`: a new branch to create at `ref` (#966).
    #[serde(default)]
    branch: Option<String>,
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

/// Linux: the agent's own precomputed Landlock rules, opened before the agent
/// ran, so no path is reopened per request (an agent-swapped symlink cannot
/// widen them) and nothing leaks per request.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct LaunchRules(crate::sandbox::landlock_mod::PrecomputedSandbox);

#[cfg(target_os = "linux")]
impl std::fmt::Debug for LaunchRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LaunchRules")
    }
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
    /// The final session Landlock rules, the Linux counterpart of `read_policy`.
    #[cfg(target_os = "linux")]
    landlock: Arc<OnceLock<LaunchRules>>,
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
            #[cfg(target_os = "linux")]
            landlock: Arc::new(OnceLock::new()),
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
        let out = run_bounded(cmd, &budget)?;
        let tracked = tracked_paths(&out)?;
        ctx.protected = protected_tree(out, &budget)?;
        verify_protected_names(project, &ctx.protected, Some(&tracked), &budget)?;
        verify_launch_bytes(&ctx, project, &budget)?;
        Ok(ctx)
    }

    /// Install the immutable policy before serving requests. Without it every
    /// operation fails closed, including direct library calls to add().
    pub fn set_read_policy(&self, profile: &str) -> Result<(), String> {
        self.read_policy
            .set(profile.to_string())
            .map_err(|_| "worktree broker read policy was already installed".into())
    }

    /// Linux: install the session Landlock rules the broker's git runs under.
    /// Refused when any rule reaches the private staging area: Landlock cannot
    /// take it back out of a granted tree, so the agent could read or swap a
    /// checkout in flight. The broker is then off, never running unconfined.
    #[cfg(target_os = "linux")]
    pub(crate) fn set_landlock_policy(
        &self,
        policy: &crate::sandbox::LandlockPolicy,
        rules: &crate::sandbox::landlock_mod::PrecomputedSandbox,
        deny_masks: usize,
    ) -> Result<(), String> {
        // The broker's git runs in the host mount namespace, where bubblewrap's
        // deny masks do not exist; through alternates or symlinked object
        // directories it could read what they hide and publish it into the
        // root. So no broker while any mask is in force.
        if deny_masks > 0 {
            return Err(format!(
                "the session masks {deny_masks} deny path(s) inside granted trees, and the \
                 broker's git runs outside the namespace that hides them"
            ));
        }
        let staging = std::fs::canonicalize(&self.base)
            .unwrap_or_else(|_| self.base.clone())
            .join(STAGING_DIR);
        if let Some(rule) = policy.fs_rules.iter().find(|r| {
            (r.access.read || r.access.write || r.access.create_dirs)
                && (staging.starts_with(&r.path)
                    || std::fs::canonicalize(&r.path).is_ok_and(|p| staging.starts_with(p)))
        }) {
            return Err(format!(
                "the session grants {}, which covers the broker's private staging in {}; \
                 narrow that grant to use cplt worktree add",
                rule.path.display(),
                staging.display()
            ));
        }
        self.landlock
            .set(LaunchRules(rules.clone()))
            .map_err(|_| "worktree broker Landlock policy was already installed".into())
    }
}

/// A running broker. Dropping it stops the worker and removes the socket after
/// request cancellation and cleanup. Filesystem cleanup is outside the budget.
#[derive(Debug)]
pub struct Broker {
    /// macOS: the socket path. Linux: `fd:<n>`, the inherited descriptor.
    socket: PathBuf,
    #[cfg(target_os = "macos")]
    _socket_dir: crate::scratch::SessionSocketDir,
    /// Linux: the end the sandbox inherits. Close-on-exec everywhere except
    /// the sandbox spawn, where `seal_inherited_fds` keeps it (see
    /// [`INHERITED_FD`]).
    #[cfg(target_os = "linux")]
    client_end: OwnedFd,
    /// Linux: written on drop to wake the serve loop.
    #[cfg(target_os = "linux")]
    wake: OwnedFd,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    #[cfg(target_os = "macos")]
    read_policy: Arc<OnceLock<String>>,
    #[cfg(target_os = "linux")]
    landlock: Context,
}

/// Linux: the descriptor the sandbox spawn must keep open, or `-1`. Published
/// for the same reason as `audit::SETTLE_PROBE_FD`: the seal is the one choke
/// point every spawn path shares. A missed keep fails closed (no broker).
pub(crate) static INHERITED_FD: std::sync::atomic::AtomicI32 =
    std::sync::atomic::AtomicI32::new(-1);

impl Broker {
    /// Reuse the short private socket-directory guard. The session profile pins
    /// this directory against writes; no broad temp-directory grant is added.
    #[cfg(target_os = "macos")]
    pub fn start(ctx: Context) -> Result<Self, String> {
        secure_dir(&ctx.base, "worktree base")?;
        let socket_dir = crate::scratch::SessionSocketDir::create()?;
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

    /// Linux (#965): no socket path is granted. The sandbox inherits one end
    /// of a `SOCK_SEQPACKET` socketpair; a client sends a fresh stream socket
    /// over it and speaks the same one-line protocol on that stream.
    #[cfg(target_os = "linux")]
    pub fn start(ctx: Context) -> Result<Self, String> {
        secure_dir(&ctx.base, "worktree base")?;
        let mut fds = [-1; 2];
        // SAFETY: socketpair writes two descriptors into the array on success.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(format!(
                "cannot create the broker socketpair: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: both descriptors were just created and are owned here only.
        let (server, client) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let socket = PathBuf::from(format!("fd:{}", client.as_raw_fd()));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let policy_ctx = ctx.clone();
        crate::worktree_ns::register(&ctx.root, &ctx.common);
        let mut pipe = [-1; 2];
        // SAFETY: pipe2 writes two descriptors on success.
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err("cannot create the broker stop pipe".into());
        }
        // SAFETY: both were just created and are owned here only.
        let (wake, wake_w) =
            unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
        let thread = std::thread::Builder::new()
            .name("cplt-worktree-broker".into())
            .spawn(move || serve_fd(&server, &wake, &ctx, &worker_stop))
            .map_err(|e| format!("cannot start the worktree broker thread: {e}"))?;
        INHERITED_FD.store(client.as_raw_fd(), Ordering::Release);
        Ok(Self {
            socket,
            client_end: client,
            wake: wake_w,
            stop,
            thread: Some(thread),
            landlock: policy_ctx,
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub fn start(_ctx: Context) -> Result<Self, String> {
        Err("the worktree broker needs macOS or Linux".into())
    }

    /// The socket path. The sandbox profile grants connect to this exact path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Capture the final session policy, after all PreparedSandbox amendments.
    #[cfg(target_os = "macos")]
    pub fn set_sandbox(&self, sandbox: &mut crate::sandbox::PreparedSandbox) -> Result<(), String> {
        sandbox.protect_worktree_staging();
        self.read_policy
            .set(crate::sandbox::describe(sandbox).to_string())
            .map_err(|_| "worktree broker read policy was already installed".into())
    }

    /// Linux: capture the final session Landlock rules for the broker's git.
    #[cfg(target_os = "linux")]
    pub fn set_sandbox(&self, sandbox: &mut crate::sandbox::PreparedSandbox) -> Result<(), String> {
        self.landlock.set_landlock_policy(
            sandbox.landlock_policy(),
            sandbox.precomputed_rules(),
            sandbox.bwrap_deny_masks(),
        )
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        let _ = INHERITED_FD.compare_exchange(
            self.client_end.as_raw_fd(),
            -1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
        self.stop.store(true, Ordering::Release);
        #[cfg(target_os = "linux")]
        // SAFETY: one byte to an owned pipe.
        unsafe {
            libc::write(self.wake.as_raw_fd(), [1u8].as_ptr().cast(), 1);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        #[cfg(target_os = "macos")]
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

/// Linux accept loop: each datagram on the inherited socketpair must carry
/// exactly one descriptor, an `AF_UNIX` stream socket, which is then served
/// exactly like an accepted macOS connection. Anything else is closed unread.
#[cfg(target_os = "linux")]
fn serve_fd(server: &OwnedFd, wake: &OwnedFd, ctx: &Context, stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        if let Some(stream) = recv_stream(server) {
            handle(ctx, stream, stop);
            continue;
        }
        // Block until a datagram or the stop pipe; no busy poll.
        let mut fds = [
            libc::pollfd {
                fd: server.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: two live pollfds.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if r < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return;
        }
        if fds[0].revents & libc::POLLHUP != 0 && fds[0].revents & libc::POLLIN == 0 {
            // Every sandbox copy is gone; nothing more can arrive.
            return;
        }
    }
}

/// One datagram from the socketpair, non-blocking. `None` when there was
/// nothing, or when it was not exactly one stream socket (any received
/// descriptors are closed on drop).
#[cfg(target_os = "linux")]
fn recv_stream(server: &OwnedFd) -> Option<UnixStream> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // Room for several descriptors, so a datagram carrying more than one is
    // seen whole and refused rather than silently truncated.
    let mut control = [0u64; 16];
    // SAFETY: zeroed msghdr is a valid empty header; the pointers set below
    // outlive the recvmsg call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    // SAFETY: msg points at live buffers; MSG_CMSG_CLOEXEC keeps received
    // descriptors out of every later spawn.
    let n = unsafe {
        libc::recvmsg(
            server.as_raw_fd(),
            &raw mut msg,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n < 0 {
        return None;
    }
    let mut fds = Vec::new();
    // SAFETY: the CMSG macros walk the control buffer recvmsg just filled,
    // bounded by msg_controllen.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&raw const msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c);
                let size = std::mem::size_of::<libc::c_int>();
                let len = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                for i in 0..len / size {
                    let mut raw = [0u8; std::mem::size_of::<libc::c_int>()];
                    std::ptr::copy_nonoverlapping(data.add(i * size), raw.as_mut_ptr(), size);
                    fds.push(OwnedFd::from_raw_fd(libc::c_int::from_ne_bytes(raw)));
                }
            }
            c = libc::CMSG_NXTHDR(&raw const msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 || fds.len() != 1 {
        return None;
    }
    let fd = fds.pop()?;
    let opt = |name| {
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: v and len are live locals of the sizes getsockopt expects.
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                name,
                (&raw mut v).cast(),
                &raw mut len,
            )
        };
        (rc == 0).then_some(v)
    };
    if opt(libc::SO_DOMAIN) != Some(libc::AF_UNIX) || opt(libc::SO_TYPE) != Some(libc::SOCK_STREAM)
    {
        return None;
    }
    Some(UnixStream::from(fd))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
/// Serve one connection: read one request, answer once, close.
fn handle(ctx: &Context, stream: UnixStream, stop: &AtomicBool) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let response = match read_request(&stream, stop).and_then(|r| {
        if r.op == "remove" {
            return remove_with_budget(ctx, &r.name, r.force, &Budget::new(stop));
        }
        add_with_budget(
            ctx,
            &r.name,
            &r.reference,
            r.branch.as_deref(),
            &Budget::new(stop),
        )
    }) {
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
        send_bounded(&stream, line.as_bytes(), stop);
    }
}

/// Wait up to `ms` for `events` on `stream`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn poll_ready(stream: &UnixStream, events: libc::c_short, ms: libc::c_int) -> bool {
    let mut pfd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events,
        revents: 0,
    };
    // SAFETY: one live pollfd.
    unsafe { libc::poll(&raw mut pfd, 1, ms) > 0 }
}

/// Write the reply with non-blocking sends, within [`IO_TIMEOUT`] and while
/// the broker runs. Gives up silently: the client may be gone.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn send_bounded(stream: &UnixStream, mut bytes: &[u8], stop: &AtomicBool) {
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::MSG_DONTWAIT;
    let deadline = Instant::now() + IO_TIMEOUT;
    while !bytes.is_empty() && !stop.load(Ordering::Acquire) && Instant::now() < deadline {
        if !poll_ready(stream, libc::POLLOUT, 100) {
            continue;
        }
        // SAFETY: bytes is a live slice.
        let n = unsafe {
            libc::send(
                stream.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                flags,
            )
        };
        if n > 0 {
            bytes = &bytes[n as usize..];
        } else if n < 0
            && !matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            )
        {
            return;
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn read_request(stream: &UnixStream, stop: &AtomicBool) -> Result<Request, String> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut line = Vec::new();
    while line.len() < MAX_LINE as usize {
        if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err("request read deadline exceeded".into());
        }
        // Per-call non-blocking I/O bounded by poll: a sender holding an alias
        // of this socket can change its timeouts or O_NONBLOCK, but not these.
        if !poll_ready(stream, libc::POLLIN, 100) {
            continue;
        }
        let mut byte = [0];
        // SAFETY: one byte into a live buffer.
        let n = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                1,
                libc::MSG_DONTWAIT,
            )
        };
        let res = if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        };
        match res {
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
    if req.op != "add" && req.op != "remove" {
        return Err(format!("unknown operation {:?}", truncate(&req.op, 32)));
    }
    Ok(req)
}

/// Create the worktree `name` at commit `reference` in the root (#966): on
/// `new_branch` when given (created at `reference`), on `reference` itself when
/// it names a local branch, otherwise detached.
///
/// Every step runs in order, and the first failure rolls back what this call
/// created, a new branch included. Checkout never reads agent-controlled config
/// or linked admin files. Shared admin writes are exclusive and
/// descriptor-relative, never truncating.
pub fn add(
    ctx: &Context,
    name: &str,
    reference: &str,
    new_branch: Option<&str>,
) -> Result<String, String> {
    add_with_budget(
        ctx,
        name,
        reference,
        new_branch,
        &Budget::new(&AtomicBool::new(false)),
    )
}

fn add_with_budget(
    ctx: &Context,
    name: &str,
    reference: &str,
    new_branch: Option<&str>,
    budget: &Budget<'_>,
) -> Result<String, String> {
    validate_name(name)?;
    validate_reference(reference)?;
    if let Some(branch) = new_branch {
        validate_reference(branch)
            .map_err(|_| format!("invalid branch name {:?}", truncate(branch, 64)))?;
    }
    #[cfg(not(target_os = "linux"))]
    ctx.read_policy
        .get()
        .ok_or("worktree broker session read policy is not installed")?;
    #[cfg(target_os = "linux")]
    ctx.landlock
        .get()
        .ok_or("worktree broker session Landlock policy is not installed")?;
    let _lock = acquire_lock(&ctx.base, budget)?;
    check_identity(&ctx.common, &ctx.common_fd)?;
    check_identity(&ctx.objects, &ctx.objects_fd)?;
    refuse_filters(ctx, budget)?;
    let sha = resolve_commit(ctx, reference, budget)?;
    let branch = match new_branch {
        Some(branch) => {
            // Same ambiguity refusal as without -b: never branch from a guess.
            local_branch(ctx, reference, budget)?;
            check_new_branch(ctx, branch, budget)?;
            Some(branch.to_string())
        }
        None => local_branch(ctx, reference, budget)?,
    };
    if let Some(branch) = &branch {
        refuse_busy_branch(ctx, branch, budget)?;
    }
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
    let private = staging.join(".git-admin");
    checkout(ctx, &private, &job.worktree, &sha, budget)?;
    validate_tree(&job.worktree, budget)?;
    verify_protected_names(&job.worktree, &ctx.protected, None, budget)?;
    verify_protected_checkout(ctx, &private, &job.worktree, budget)?;
    check_identity(&ctx.common, &ctx.common_fd)?;
    budget.check()?;
    // Created last before the admin entry, and deleted again on any failure
    // below, so a refused request leaves no ref behind.
    let created = match new_branch {
        Some(branch) => Some(CreatedBranch::create(ctx, branch, &sha, budget)?),
        None => None,
    };
    job.admin = Some(Admin::create(ctx)?);
    let admin = job.admin.as_ref().unwrap();
    let head = match &branch {
        Some(branch) => format!("ref: refs/heads/{branch}\n"),
        None => format!("{sha}\n"),
    };
    admin.write("HEAD", head.as_bytes())?;
    admin.write("commondir", b"../..\n")?;
    admin.write(
        "gitdir",
        format!("{}\n", job.final_git.display()).as_bytes(),
    )?;
    let mut index = open_at(
        &open_dir(&private)?,
        "index",
        libc::O_RDONLY | libc::O_NONBLOCK,
    )?;
    let metadata = index.metadata().map_err(|_| "cannot stat private index")?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err("private index is not a singly linked regular file".into());
    }
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
    // Linux (#965): every protected path exists before publish, so each gets
    // its read-only bind (config.worktree in the admin dir, empty protected
    // subtrees in the tree).
    #[cfg(target_os = "linux")]
    crate::worktree_ns::ensure_placeholders(
        &job.worktree,
        &ctx.common.join("worktrees").join(&admin.name),
    )?;
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
    // Linux (#965): the tree appeared under the session's read-only root, so
    // the agent cannot write it yet; bind its protections and make it writable.
    // On failure it is removed with its admin dir and branch.
    #[cfg(target_os = "linux")]
    {
        let published = ctx.root.join(name);
        let admin_dir = ctx.common.join("worktrees").join(&admin.name);
        if let Err(e) = crate::worktree_ns::protect_new(&published, &admin_dir) {
            let _ = std::fs::remove_dir_all(&published);
            return Err(e);
        }
    }
    job.published = true;
    if let Some(created) = &created {
        created.keep.set(true);
    }
    Ok(job
        .final_git
        .parent()
        .unwrap_or(&ctx.root)
        .display()
        .to_string())
}

/// Remove the managed worktree `name` (#1015). Never the main worktree, never
/// anything outside the root, and never one with local changes or a lock
/// unless `force` (git's single `--force`; a locked worktree is always refused).
pub fn remove(ctx: &Context, name: &str, force: bool) -> Result<String, String> {
    remove_with_budget(ctx, name, force, &Budget::new(&AtomicBool::new(false)))
}

/// Every input is agent-controlled: the name, the tree, any symlink planted in
/// the root, the tree's `.git` pointer. So the target is one validated name
/// under the root, its admin dir is found from git's own records (the admin
/// `gitdir` files `git worktree list` reads, never the tree's pointer), and the
/// tree is moved into private staging with one rename before anything is
/// deleted. The rename moves whatever is at the path, never a symlink target,
/// and the moved inode must be the one checked, so a swap after the check is
/// put back and refused.
fn remove_with_budget(
    ctx: &Context,
    name: &str,
    force: bool,
    budget: &Budget<'_>,
) -> Result<String, String> {
    use std::os::unix::ffi::OsStrExt;
    validate_name(name)?;
    #[cfg(not(target_os = "linux"))]
    ctx.read_policy
        .get()
        .ok_or("worktree broker session read policy is not installed")?;
    #[cfg(target_os = "linux")]
    ctx.landlock
        .get()
        .ok_or("worktree broker session Landlock policy is not installed")?;
    let _lock = acquire_lock(&ctx.base, budget)?;
    check_identity(&ctx.common, &ctx.common_fd)?;
    let target = ctx.root.join(name);
    let not_managed = || {
        format!(
            "{} is not a worktree of this repository under $CPLT_WORKTREE_ROOT",
            target.display()
        )
    };
    let meta = std::fs::symlink_metadata(&target).map_err(|_| not_managed())?;
    if !meta.is_dir() {
        return Err(not_managed());
    }
    let canonical_root = std::fs::canonicalize(&ctx.root).map_err(|_| not_managed())?;
    let names = [target.clone(), canonical_root.join(name)];

    // git's view: the path must be a linked worktree (never the first, main entry).
    let list = run_bounded(
        common_command(ctx, &["worktree", "list", "--porcelain", "-z"])?,
        budget,
    )?;
    if !list.status.success() {
        return Err("git worktree list failed".into());
    }
    let listed = list
        .stdout
        .split(|&b| b == 0)
        .filter_map(|f| f.strip_prefix(b"worktree "))
        .skip(1)
        .any(|p| names.iter().any(|n| n.as_os_str().as_bytes() == p));
    if !listed {
        return Err(not_managed());
    }
    // The admin dir whose gitdir record names this tree: exactly one, a real dir.
    let mut admins = Vec::new();
    for entry in std::fs::read_dir(ctx.common.join("worktrees"))
        .map_err(|_| not_managed())?
        .flatten()
    {
        budget.check()?;
        let admin = entry.path();
        if !std::fs::symlink_metadata(&admin).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        let Some(gitdir) = crate::untrusted::read_untrusted(&admin.join("gitdir"), 4096)
            .ok()
            .flatten()
        else {
            continue;
        };
        let gitdir = Path::new(gitdir.trim_end_matches('\n'));
        if names.iter().any(|n| n.join(".git") == gitdir) {
            admins.push(admin);
        }
    }
    let [admin] = admins.as_slice() else {
        return Err(not_managed());
    };
    if std::fs::symlink_metadata(admin.join("locked")).is_ok() {
        return Err(format!(
            "worktree {name} is locked; unlock it outside cplt first"
        ));
    }
    if !force {
        refuse_filters(ctx, budget)?;
        let git_dir = format!("--git-dir={}", admin.display());
        let work_tree = format!("--work-tree={}", target.display());
        let mut cmd = git::command(
            &ctx.common,
            &[
                &git_dir,
                &work_tree,
                "status",
                "--porcelain",
                "-z",
                "--ignore-submodules=none",
            ],
        )
        .ok_or("no trusted git binary")?;
        harden_data_query(ctx, &mut cmd);
        let out = run_bounded(sandbox_git(ctx, cmd, None)?, budget)?;
        if !out.status.success() {
            return Err("cannot check the worktree for local changes".into());
        }
        if !out.stdout.is_empty() {
            return Err(format!(
                "worktree {name} has modified or untracked files; commit them, or pass --force to discard them"
            ));
        }
    }
    budget.check()?;
    let staging = new_staging_dir(&ctx.base)?;
    let moved = staging.join(name);
    let result = (|| {
        std::fs::rename(&target, &moved).map_err(|e| format!("cannot move {name}: {e}"))?;
        let now = std::fs::symlink_metadata(&moved).map_err(|_| not_managed())?;
        if !now.is_dir() || now.dev() != meta.dev() || now.ino() != meta.ino() {
            // Swapped since the check: put back whatever was moved.
            let _ = std::fs::rename(&moved, &target);
            return Err(format!(
                "{name} changed during removal; nothing was removed"
            ));
        }
        Ok(())
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_dir(&staging);
        return Err(e);
    }
    // Both are now in places only cplt writes: staging, and the protected
    // common dir. remove_dir_all never follows a symlink inside them.
    let admin_result = std::fs::remove_dir_all(admin);
    let _ = std::fs::remove_dir_all(&staging);
    admin_result.map_err(|e| format!("removed the tree but not its git admin dir: {e}"))?;
    Ok(target.display().to_string())
}

/// A branch this request created, deleted again unless the request publishes.
struct CreatedBranch<'a> {
    ctx: &'a Context,
    full: String,
    sha: String,
    keep: std::cell::Cell<bool>,
}

impl<'a> CreatedBranch<'a> {
    /// Create-only: an empty old value makes git refuse if the ref exists, so
    /// a branch made since the earlier check is never moved.
    fn create(
        ctx: &'a Context,
        branch: &str,
        sha: &str,
        budget: &Budget<'_>,
    ) -> Result<Self, String> {
        let full = format!("refs/heads/{branch}");
        // The guard exists before git runs: a deadline or cancellation can
        // end the wait after the ref is already written.
        let guard = Self {
            ctx,
            full: full.clone(),
            sha: sha.to_string(),
            keep: std::cell::Cell::new(false),
        };
        let out = run_bounded(
            common_command(
                ctx,
                &["update-ref", "-m", "cplt worktree add", &full, sha, ""],
            )?,
            budget,
        )?;
        if !out.status.success() {
            // Git refused the create, so the ref, if any, is not ours to delete.
            guard.keep.set(true);
            return Err(format!(
                "cannot create branch {branch:?}: {}",
                truncate(String::from_utf8_lossy(&out.stderr).trim(), 200)
            ));
        }
        Ok(guard)
    }
}

impl Drop for CreatedBranch<'_> {
    fn drop(&mut self) {
        if self.keep.get() {
            return;
        }
        // Deletes only while the ref still points where this request put it.
        let stop = AtomicBool::new(false);
        if let Ok(cmd) = common_command(self.ctx, &["update-ref", "-d", &self.full, &self.sha]) {
            let _ = run_bounded(cmd, &Budget::new(&stop));
        }
    }
}

/// `branch` must be a valid branch name by git's rules and must not exist.
fn check_new_branch(ctx: &Context, branch: &str, budget: &Budget<'_>) -> Result<(), String> {
    let full = format!("refs/heads/{branch}");
    let valid = run_bounded(common_command(ctx, &["check-ref-format", &full])?, budget)?;
    if !valid.status.success() {
        return Err(format!("invalid branch name {:?}", truncate(branch, 64)));
    }
    let exists = run_bounded(
        common_command(ctx, &["show-ref", "--verify", "--quiet", &full])?,
        budget,
    )?;
    match exists.status.code() {
        Some(0) => Err(format!(
            "branch {:?} already exists; pass it as <ref> without -b to check it out",
            truncate(branch, 64)
        )),
        Some(1) => Ok(()),
        _ => Err("cannot check whether the branch exists".into()),
    }
}

/// The local branch `reference` names, or `None` for a tag, commit or remote
/// branch, which are checked out detached. An ambiguous name is refused rather
/// than guessed.
fn local_branch(
    ctx: &Context,
    reference: &str,
    budget: &Budget<'_>,
) -> Result<Option<String>, String> {
    // Ref existence, not git's localized ambiguity warning, decides.
    let exists = |full: &str| -> Result<bool, String> {
        let out = run_bounded(
            common_command(ctx, &["show-ref", "--verify", "--quiet", full])?,
            budget,
        )?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err("cannot check the repository's refs".into()),
        }
    };
    if let Some(branch) = reference.strip_prefix("refs/heads/") {
        return Ok(exists(reference)?.then(|| branch.to_string()));
    }
    let branch = exists(&format!("refs/heads/{reference}"))?;
    let other = exists(&format!("refs/tags/{reference}"))? || exists(&format!("refs/{reference}"))?;
    match (branch, other) {
        (true, true) => Err(format!(
            "ref {:?} is ambiguous; name it in full, such as refs/heads/{0} or refs/tags/{0}",
            truncate(reference, 64)
        )),
        (true, false) => Ok(Some(reference.to_string())),
        _ => Ok(None),
    }
}

/// Git's rule: a branch is busy while any worktree has it as HEAD or is
/// rebasing or bisecting it (git's `find_shared_symref`).
///
/// Reads the admin files directly rather than running `git worktree list`:
/// no subprocess, no content-filter probe, and the rebase and bisect states
/// the porcelain listing does not show. The files are agent-writable, so each
/// is read without following a symlink and with a size cap.
fn refuse_busy_branch(ctx: &Context, branch: &str, budget: &Budget<'_>) -> Result<(), String> {
    let full = format!("refs/heads/{branch}");
    let mut admins = vec![ctx.common.clone()];
    if let Ok(entries) = std::fs::read_dir(ctx.common.join("worktrees")) {
        for entry in entries.flatten() {
            admins.push(entry.path());
        }
    }
    for admin in admins {
        budget.check()?;
        let read = |rel: &str| {
            crate::untrusted::read_untrusted(&admin.join(rel), 4096)
                .ok()
                .flatten()
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        let busy = read("HEAD").strip_prefix("ref: ") == Some(full.as_str())
            || read("rebase-merge/head-name") == full
            || read("rebase-apply/head-name") == full
            || read("BISECT_START") == branch
            || read("BISECT_START") == full;
        if busy {
            return Err(format!(
                "branch {:?} is checked out, or being rebased or bisected, in another \
                 worktree ({}); use -b <new-branch> or another ref",
                truncate(branch, 64),
                truncate(&admin.display().to_string(), 200)
            ));
        }
    }
    Ok(())
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

/// Launch inspection projects HEAD onto disk. Ignored/local files are neither
/// trusted nor published, so they must not disable this tracked-only baseline.
fn tracked_paths(out: &Output) -> Result<std::collections::BTreeSet<Vec<u8>>, String> {
    let mut paths = std::collections::BTreeSet::new();
    for entry in out.stdout.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let tab = entry
            .iter()
            .position(|b| *b == b'\t')
            .ok_or("invalid git tree entry")?;
        let mut path = &entry[tab + 1..];
        loop {
            paths.insert(path.to_vec());
            let Some(slash) = path.iter().rposition(|b| *b == b'/') else {
                break;
            };
            path = &path[..slash];
        }
    }
    Ok(paths)
}

/// Ask the filesystem which entry each protected spelling names. APFS aliases
/// (including long s and Kelvin sign) are not Unicode lowercase mappings.
/// Never follow a symlink while resolving a protected name or its ancestors.
fn verify_protected_names(
    root: &Path,
    expected: &ProtectedTree,
    tracked: Option<&std::collections::BTreeSet<Vec<u8>>>,
    budget: &Budget<'_>,
) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let mut found = std::collections::BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    let mut count = 0;
    let included = |path: &Path| {
        tracked.is_none_or(|paths| {
            path.strip_prefix(root)
                .is_ok_and(|rel| paths.contains(rel.as_os_str().as_bytes()))
        })
    };
    while let Some(dir) = stack.pop() {
        budget.check()?;
        for protected in crate::sandbox::PROTECTED_IN_ROOT {
            if dir != root && !protected.nested {
                continue;
            }
            let mut actual = dir.clone();
            let mut present = true;
            for component in protected.rel.split('/') {
                let lookup = actual.join(component);
                let metadata = match lookup.symlink_metadata() {
                    Ok(metadata) => metadata,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        present = false;
                        break;
                    }
                    Err(_) => return Err("cannot resolve protected filesystem name".into()),
                };
                let mut matching = None;
                for entry in
                    std::fs::read_dir(&actual).map_err(|_| "cannot list protected parent")?
                {
                    budget.check()?;
                    let entry = entry.map_err(|_| "cannot read protected parent entry")?;
                    let m = entry
                        .path()
                        .symlink_metadata()
                        .map_err(|_| "cannot stat protected parent entry")?;
                    if m.dev() == metadata.dev() && m.ino() == metadata.ino() {
                        matching = Some(entry.path());
                        break;
                    }
                }
                let entry = matching.ok_or("cannot identify protected filesystem entry")?;
                if !included(&entry) {
                    present = false;
                    break;
                }
                if metadata.file_type().is_symlink() {
                    return Err("protected filesystem path has a symlink; prepare the worktree outside cplt".into());
                }
                // Exact spelling is required even when an alias was in HEAD.
                if entry.file_name() != Some(std::ffi::OsStr::new(component)) {
                    return Err(
                        "protected filesystem name is an alias; prepare the worktree outside cplt"
                            .into(),
                    );
                }
                actual = entry;
            }
            if !present {
                continue;
            }
            let mut pending = vec![actual];
            let mut protected_entries = 0;
            while let Some(path) = pending.pop() {
                budget.check()?;
                protected_entries += 1;
                if protected_entries > MAX_TREE_ENTRIES {
                    return Err("protected filesystem tree exceeds entry limit".into());
                }
                let meta = path
                    .symlink_metadata()
                    .map_err(|_| "cannot stat protected entry")?;
                if meta.is_dir() && protected.tree {
                    for entry in
                        std::fs::read_dir(path).map_err(|_| "cannot list protected tree")?
                    {
                        let path = entry
                            .map_err(|_| "cannot read protected tree entry")?
                            .path();
                        if included(&path) {
                            pending.push(path);
                        }
                    }
                } else {
                    let rel = path
                        .strip_prefix(root)
                        .map_err(|_| "protected path escaped checkout")?
                        .as_os_str()
                        .as_bytes()
                        .to_vec();
                    if !meta.is_file() || !expected.contains_key(&rel) {
                        return Err("protected filesystem content differs from launch HEAD; prepare the worktree outside cplt".into());
                    }
                    found.insert(rel);
                }
            }
        }
        for entry in std::fs::read_dir(&dir).map_err(|_| "cannot inspect checkout directories")? {
            budget.check()?;
            let entry = entry.map_err(|_| "cannot inspect checkout directory entry")?;
            if !included(&entry.path()) {
                continue;
            }
            count += 1;
            if count > MAX_TREE_ENTRIES {
                return Err("checkout exceeds protected-name scan limit".into());
            }
            if entry.file_name().as_bytes().eq_ignore_ascii_case(b".git") {
                continue;
            }
            if entry
                .file_type()
                .map_err(|_| "cannot stat checkout directory")?
                .is_dir()
            {
                stack.push(entry.path());
            }
        }
    }
    if found.len() != expected.len() {
        return Err("protected filesystem content differs from launch HEAD; prepare the worktree outside cplt".into());
    }
    Ok(())
}

/// HEAD is agent-mutable across sessions. Trust only protected content actually
/// checked out at launch, read through no-follow directory and file descriptors.
fn verify_launch_bytes(ctx: &Context, project: &Path, budget: &Budget<'_>) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let staging = new_staging_dir(&ctx.base)?;
    let _cleanup = Job {
        staging: staging.clone(),
        admin: None,
        worktree: staging.clone(),
        final_git: PathBuf::new(),
        published: false,
    };
    let root = open_dir(project)?;
    for (number, (path, (mode, id))) in ctx.protected.iter().enumerate() {
        budget.check()?;
        let mut parent = root.try_clone().map_err(|_| "cannot pin launch checkout")?;
        let parts: Vec<_> = path.split(|b| *b == b'/').collect();
        for part in &parts[..parts.len() - 1] {
            parent = open_at(
                &parent,
                std::str::from_utf8(part).map_err(|_| "protected launch path is not UTF-8")?,
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
        }
        let name = std::str::from_utf8(parts.last().unwrap())
            .map_err(|_| "protected launch path is not UTF-8")?;
        let source = open_at(&parent, name, libc::O_RDONLY | libc::O_NONBLOCK)?;
        let metadata = source
            .metadata()
            .map_err(|_| "cannot stat launch protected file")?;
        if !metadata.is_file()
            || metadata.len() > 1024 * 1024
            || (metadata.mode() & 0o111 != 0) != (mode == b"100755")
        {
            return Err("protected launch file or mode differs from HEAD".into());
        }
        let copy = staging.join(number.to_string());
        let mut target = File::create(&copy).map_err(|_| "cannot copy launch protected file")?;
        let n = std::io::copy(&mut source.take(1024 * 1024 + 1), &mut target)
            .map_err(|_| "cannot read launch protected file")?;
        if n > 1024 * 1024 {
            return Err("launch protected file exceeds 1 MiB".into());
        }
        let path = std::str::from_utf8(copy.as_os_str().as_bytes())
            .map_err(|_| "private launch path is not UTF-8")?;
        let out = run_bounded(
            pinned_common_command(ctx, &["hash-object", "--no-filters", "--", path])?,
            budget,
        )?;
        if !out.status.success() || out.stdout.strip_suffix(b"\n") != Some(id.as_slice()) {
            return Err("protected launch bytes differ from HEAD; restore the trusted checkout outside cplt".into());
        }
    }
    Ok(())
}

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

/// Linux: the same session rules the agent runs under, plus read and write
/// (never execute) on this request's private staging directory, applied to
/// the broker's git between fork and exec.
#[cfg(target_os = "linux")]
fn sandbox_git(ctx: &Context, mut cmd: Command, staging: Option<&Path>) -> Result<Command, String> {
    use crate::sandbox::FsAccess;
    use std::os::unix::process::CommandExt as _;
    let mut pre = ctx
        .landlock
        .get()
        .ok_or("worktree broker session Landlock policy is not installed")?
        .0
        .clone();
    // The one per-request rule: this request's private staging directory,
    // opened without following a link and owned by the closure, so it closes
    // with the Command whether or not it spawns.
    let staging_fd = match staging {
        Some(staging) => {
            let fd = crate::sandbox::landlock_mod::open_no_symlinks_walk(staging)
                .map_err(|e| format!("cannot open broker staging: {e}"))?;
            pre.pre_opened_fds.push((
                fd.as_raw_fd(),
                FsAccess {
                    read: true,
                    write: true,
                    execute: false,
                    ioctl: false,
                    create_dirs: true,
                },
            ));
            Some(fd)
        }
        None => None,
    };
    cmd.stdin(Stdio::null());
    // SAFETY: apply_precomputed is the same hook the agent spawn uses; it
    // makes raw syscalls on data prepared in the parent.
    unsafe {
        cmd.pre_exec(move || {
            let _keep = &staging_fd;
            crate::sandbox::landlock_mod::apply_precomputed(&pre)
        });
    }
    Ok(cmd)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn sandbox_git(_ctx: &Context, _cmd: Command, _staging: Option<&Path>) -> Result<Command, String> {
    Err("the worktree broker needs macOS or Linux".into())
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
    let mut stack = vec![(worktree.to_path_buf(), 1usize)];
    let mut seen = 0usize;
    while let Some((dir, depth)) = stack.pop() {
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
            has_head |= name.eq_ignore_ascii_case("HEAD");
            has_refs |= name.eq_ignore_ascii_case("refs");
            has_objects |= name.eq_ignore_ascii_case("objects");
            has_commondir |= name.eq_ignore_ascii_case("commondir");
            if ft.is_symlink() {
                check_symlink(&path, &root)?;
            } else if ft.is_dir() {
                if depth + 1 > worktrees::WALK_MAX_DEPTH {
                    return Err(format!(
                        "{} is more than {} levels below the worktree root; refusing to publish it",
                        path.strip_prefix(worktree).unwrap_or(&path).display(),
                        worktrees::WALK_MAX_DEPTH
                    ));
                }
                stack.push((path, depth + 1));
            }
        }
        for (flag, marker) in [
            (&mut has_head, "HEAD"),
            (&mut has_objects, "objects"),
            (&mut has_refs, "refs"),
            (&mut has_commondir, "commondir"),
        ] {
            if !*flag {
                match dir.join(marker).symlink_metadata() {
                    Ok(_) => *flag = true,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(format!("cannot stat {}: {e}", dir.join(marker).display()));
                    }
                }
            }
        }
        if worktrees::bare_layout(has_head, has_objects, has_refs, has_commondir) {
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
/// it exists. Dangling links and a `..` after a named component fail closed,
/// using the same rule as the launch/exit worktree checks.
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
    if target.is_absolute() || !worktrees::link_stays_inside(link, root) {
        return Err(escapes());
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

/// Linux: `renameat2(RENAME_NOREPLACE)`, the counterpart of `RENAME_EXCL`.
/// Called through `syscall(2)` so it does not depend on the libc wrapper
/// (older glibc and musl lack it).
#[cfg(target_os = "linux")]
fn publish(staging: &Path, name: &str, root: &Path) -> Result<(), String> {
    let src_dir = open_dir(staging)?;
    let dst_dir = open_dir(root)?;
    let c_name = CString::new(name).map_err(|_| "worktree name contains a NUL byte")?;
    // SAFETY: both descriptors are open directories owned here for the call;
    // the name is a NUL-terminated C string that outlives it.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            src_dir.as_raw_fd(),
            c_name.as_ptr(),
            dst_dir.as_raw_fd(),
            c_name.as_ptr(),
            libc::RENAME_NOREPLACE,
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

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn publish(_staging: &Path, _name: &str, _root: &Path) -> Result<(), String> {
    Err("the worktree broker needs macOS or Linux".into())
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

fn client_os_error(os: &str) -> Option<String> {
    if os == "macos" || os == "linux" {
        return None;
    }
    Some(format!(
        "cplt worktree: worktrees inside the sandbox are unsupported on {os}: the \
         parent-side worktree broker runs on macOS and Linux only. Prepare worktrees outside cplt."
    ))
}

/// Reach the broker named by [`SOCKET_ENV`]: a socket path on macOS, or
/// `fd:<n>` on Linux, the inherited socketpair end.
fn connect(socket: &std::ffi::OsStr) -> std::io::Result<UnixStream> {
    #[cfg(target_os = "linux")]
    if let Some(n) = socket.to_str().and_then(|s| s.strip_prefix("fd:")) {
        let fd: libc::c_int = n
            .parse()
            .ok()
            .filter(|&fd| fd > 2)
            .ok_or_else(|| std::io::Error::other(format!("bad broker descriptor {n:?}")))?;
        return send_stream(fd);
    }
    UnixStream::connect(socket)
}

/// Make a stream pair, pass one end to the broker over the inherited
/// `SOCK_SEQPACKET` descriptor, keep the other.
#[cfg(target_os = "linux")]
fn send_stream(fd: libc::c_int) -> std::io::Result<UnixStream> {
    let (ours, theirs) = UnixStream::pair()?;
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut control = vec![0u64; space.div_ceil(8)];
    // SAFETY: zeroed msghdr is valid; every pointer set below outlives sendmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: the control buffer holds one SCM_RIGHTS header with one int.
    let rc = unsafe {
        let c = libc::CMSG_FIRSTHDR(&raw const msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        let raw = theirs.as_raw_fd().to_ne_bytes();
        std::ptr::copy_nonoverlapping(raw.as_ptr(), libc::CMSG_DATA(c), raw.len());
        libc::sendmsg(fd, &raw const msg, libc::MSG_NOSIGNAL)
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    drop(theirs);
    Ok(ours)
}

/// The sandboxed side of `cplt worktree add`. Sends one request to the socket
/// the sandbox grants, prints the new path on success.
///
/// The socket comes from [`SOCKET_ENV`], which the launcher sets after
/// filtering the environment, so a value inherited from the parent cannot point
/// the client elsewhere.
pub fn run_client(name: &str, reference: &str, branch: Option<&str>) -> ExitCode {
    request(
        serde_json::json!({"op": "add", "name": name, "ref": reference, "branch": branch}),
        name,
    )
}

/// The sandboxed side of `cplt worktree remove <path> [--force]` (#1015).
/// `path` is a name, or a path whose parent is `$CPLT_WORKTREE_ROOT`; the
/// broker checks the name again and trusts nothing else from here.
pub fn run_remove_client(path: &str, force: bool) -> ExitCode {
    let name = match path.trim_end_matches('/').rsplit_once('/') {
        None => path,
        Some((parent, name)) => {
            let root = std::env::var("CPLT_WORKTREE_ROOT").unwrap_or_default();
            if root.is_empty() || parent != root.trim_end_matches('/') {
                eprintln!(
                    "cplt worktree: only worktrees directly under $CPLT_WORKTREE_ROOT can be removed"
                );
                return ExitCode::FAILURE;
            }
            name
        }
    };
    request(
        serde_json::json!({"op": "remove", "name": name, "force": force}),
        name,
    )
}

fn request(body: serde_json::Value, name: &str) -> ExitCode {
    if let Some(msg) = client_os_error(std::env::consts::OS) {
        eprintln!("{msg}");
        return ExitCode::FAILURE;
    }
    let Some(socket) = std::env::var_os(SOCKET_ENV).filter(|s| !s.is_empty()) else {
        eprintln!(
            "cplt worktree: not available here. It needs a cplt session with \
             sandbox.allow_git_worktrees on."
        );
        return ExitCode::FAILURE;
    };
    let stream = match connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cplt worktree: cannot reach the worktree broker: {e}");
            return ExitCode::FAILURE;
        }
    };
    let wait = GIT_TIMEOUT + IO_TIMEOUT;
    let _ = stream.set_read_timeout(Some(wait));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let Ok(mut line) = serde_json::to_string(&body) else {
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
        eprintln!(
            "cplt worktree: no reply from the broker: {e}. The request may still publish; check $CPLT_WORKTREE_ROOT/{name} before retrying."
        );
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
            eprintln!(
                "cplt worktree: the broker sent an unreadable reply. The request may have published; check $CPLT_WORKTREE_ROOT/{name} before retrying."
            );
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

    #[test]
    fn client_os_error_allows_macos_and_linux_only() {
        assert_eq!(client_os_error("macos"), None);
        assert_eq!(client_os_error("linux"), None);
        let other = client_os_error("freebsd").expect("other systems are refused");
        assert!(other.contains("macOS and Linux only"), "{other}");
        assert!(other.contains("Prepare worktrees outside cplt"), "{other}");
    }
}
