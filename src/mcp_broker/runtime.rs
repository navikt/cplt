//! The host side: socket, connections and the server child.

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::egress::egress_tunnel;
use super::policy::{Action, Pending, auth_error, error_line, on_client, on_server};
use super::spec::Spec;
use super::{CALL_TIMEOUT, DENIED, KILL_GRACE, MAX_MESSAGE, SPAWNS_PER_MINUTE};

/// Where broker lines go: cplt's terminal output and the `--proxy-log` file.
#[derive(Clone)]
pub struct Log {
    pub level: crate::proxy::ProxyLogLevel,
    pub file: Option<PathBuf>,
}

/// DENIED, auth and other failures reach the terminal at every level (D12);
/// the rest only at `--proxy-log-level all`.
fn to_terminal(level: crate::proxy::ProxyLogLevel, text: &str) -> bool {
    text.contains("DENIED")
        || text.starts_with("FAIL")
        || text.starts_with("stopped")
        || level == crate::proxy::ProxyLogLevel::All
}

impl Log {
    /// Every line reaches the log file; see [`to_terminal`] for the terminal.
    pub(crate) fn line(&self, id: &str, text: &str) {
        let id = id.escape_debug().to_string();
        let text = text.escape_debug().to_string();
        if to_terminal(self.level, &text) {
            eprintln!(
                "{}[mcp:{id}]{} {} {text}",
                crate::ui::color(crate::ui::YELLOW),
                crate::ui::color(crate::ui::RESET),
                crate::proxy::chrono_now()
            );
        }
        if let Some(path) = &self.file
            && let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        {
            let _ = writeln!(f, "{} [mcp:{id}] {text}", crate::proxy::iso_now());
        }
    }
}

pub(crate) struct Server {
    spec: Spec,
    /// The live child, if a client is connected. One per server.
    child: Mutex<Option<Arc<Mutex<Child>>>>,
    spawns: Mutex<VecDeque<Instant>>,
    /// This server's own CONNECT proxy, allowing only its `egressHosts`;
    /// `None` when it has none, so there is nothing to listen for.
    egress_port: Option<u16>,
}

pub(crate) struct Shared {
    servers: BTreeMap<String, Server>,
    home: PathBuf,
    log: Log,
    stop: AtomicBool,
    /// Open connections (socket clients and egress tunnels together).
    open: Arc<AtomicUsize>,
}

/// Connections served at once; past this an accepted one is closed at once,
/// before any thread is spawned. Each holds a thread until it ends, and a
/// stalled handshake ends after its 10 s read timeout.
pub(crate) const MAX_CONNECTIONS: usize = 32;

/// A connection slot, released on drop.
pub(crate) struct Permit(Arc<AtomicUsize>);

impl Permit {
    #[allow(deprecated)] // `try_update` is not in the pinned 1.94 toolchain
    pub(crate) fn take(open: &Arc<AtomicUsize>) -> Option<Self> {
        open.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < MAX_CONNECTIONS).then_some(n + 1)
        })
        .ok()
        .map(|_| Self(Arc::clone(open)))
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The running broker. Dropping it stops every child and removes the socket.
pub struct Broker {
    socket: PathBuf,
    #[cfg(target_os = "macos")]
    _dir: crate::scratch::SessionSocketDir,
    #[cfg(not(target_os = "macos"))]
    _dir: SocketDir,
    shared: Arc<Shared>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Broker {
    /// Bind the socket and serve `specs`. The child's egress goes through the
    /// proxy on `proxy_port`, whose allowlist already holds the specs' hosts.
    pub fn start(specs: Vec<Spec>, home: &Path, log: Log) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt;
        #[cfg(target_os = "macos")]
        let dir = crate::scratch::SessionSocketDir::create()?;
        #[cfg(not(target_os = "macos"))]
        let dir = SocketDir::create()?;
        let socket = dir.path().join("m");
        let listener = std::os::unix::net::UnixListener::bind(&socket)
            .map_err(|e| format!("cannot bind {}: {e}", socket.display()))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot restrict {}: {e}", socket.display()))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("cannot poll {}: {e}", socket.display()))?;
        let mut egress = Vec::new();
        let mut servers = BTreeMap::new();
        for spec in specs {
            let egress_port = if spec.egress_hosts.is_empty() {
                None
            } else {
                let l = std::net::TcpListener::bind("127.0.0.1:0")
                    .and_then(|l| l.set_nonblocking(true).map(|()| l))
                    .map_err(|e| format!("cannot start the egress proxy: {e}"))?;
                let port = l.local_addr().map_err(|e| e.to_string())?.port();
                egress.push((spec.id.clone(), l));
                Some(port)
            };
            let server = Server {
                spec,
                child: Mutex::new(None),
                spawns: Mutex::new(VecDeque::new()),
                egress_port,
            };
            servers.insert(server.spec.id.clone(), server);
        }
        let shared = Arc::new(Shared {
            servers,
            home: home.to_path_buf(),
            log,
            stop: AtomicBool::new(false),
            open: Arc::new(AtomicUsize::new(0)),
        });
        for (id, l) in egress {
            let s = Arc::clone(&shared);
            std::thread::spawn(move || {
                let Some(server) = s.servers.get(&id) else {
                    return;
                };
                while !s.stop.load(Ordering::Acquire) {
                    match l.accept() {
                        Ok((stream, _)) => {
                            let Some(permit) = Permit::take(&s.open) else {
                                continue;
                            };
                            let hosts = server.spec.egress_hosts.clone();
                            let (log, id) = (s.log.clone(), id.clone());
                            std::thread::spawn(move || {
                                let _permit = permit;
                                egress_tunnel(stream, &hosts, &log, &id);
                            });
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(50)),
                    }
                }
            });
        }
        let s = Arc::clone(&shared);
        let thread = std::thread::spawn(move || {
            while !s.stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let Some(permit) = Permit::take(&s.open) else {
                            continue;
                        };
                        let s = Arc::clone(&s);
                        std::thread::spawn(move || {
                            let _permit = permit;
                            serve(&s, stream);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        });
        Ok(Self {
            socket,
            _dir: dir,
            shared,
            thread: Some(thread),
        })
    }

    /// The socket path the sandbox profile grants connect to.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub fn specs(&self) -> impl Iterator<Item = &Spec> {
        self.shared.servers.values().map(|s| &s.spec)
    }
}

/// Linux (#834): a private 0700 dir under `/tmp` for the one socket.
/// Bubblewrap binds the socket itself past its private `/tmp`. Not in the
/// runtime dir: with the broker on, bubblewrap hides the runtime dirs whole
/// (the bus lives there), and a user `--deny-path` cannot mask `/tmp`.
/// Removed on drop.
#[cfg(not(target_os = "macos"))]
struct SocketDir {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(not(target_os = "macos"))]
impl SocketDir {
    fn create() -> Result<Self, String> {
        const LABEL: &str = "MCP broker socket dir";
        let path = Path::new("/tmp").join(format!(
            "cplt-mcp-{}",
            crate::scratch::generate_session_id()?
        ));
        crate::scratch::create_secure_dir(&path, LABEL)?;
        let (device, inode) =
            crate::scratch::secure_dir_identity(&path, LABEL).inspect_err(|_| {
                let _ = std::fs::remove_dir(&path);
            })?;
        Ok(Self {
            path,
            device,
            inode,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

/// Removed only if it is still the directory `create` made (device and
/// inode, no symlink), as for the Playwright socket dir.
#[cfg(not(target_os = "macos"))]
impl Drop for SocketDir {
    fn drop(&mut self) {
        crate::scratch::remove_owned_dir(
            &self.path,
            self.device,
            self.inode,
            "MCP broker socket dir",
        );
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        for server in self.shared.servers.values() {
            let child = server.child.lock().ok().and_then(|mut c| c.take());
            if let Some(child) = child {
                kill(&child);
            }
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// SIGTERM, a short grace, SIGKILL, then reap.
pub(crate) fn kill(child: &Mutex<Child>) {
    let Ok(mut child) = child.lock() else { return };
    // Reaped (or unknown): its pid may belong to someone else now.
    if !matches!(child.try_wait(), Ok(None)) {
        return;
    }
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: kill(2) on our own child, which try_wait just saw unreaped
        // and which nothing else reaps (we hold its lock).
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
    let start = Instant::now();
    while start.elapsed() < KILL_GRACE {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // Still unreaped under our lock, so the pid is still ours.
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn read_line(r: &mut impl BufRead, limit: u64) -> Option<String> {
    let mut buf = Vec::new();
    let n = r.take(limit + 1).read_until(b'\n', &mut buf).ok()?;
    if n == 0 || buf.len() as u64 > limit {
        return None;
    }
    String::from_utf8(buf)
        .ok()
        .map(|s| s.trim_end_matches(['\n', '\r']).to_string())
}

pub(crate) fn write_line(w: &Mutex<impl Write>, line: &str) -> bool {
    let Ok(mut w) = w.lock() else { return false };
    w.write_all(line.as_bytes())
        .and_then(|()| w.write_all(b"\n"))
        .and_then(|()| w.flush())
        .is_ok()
}

pub(crate) fn spawn_child(shared: &Shared, server: &Server) -> std::io::Result<Child> {
    let spec = &server.spec;
    // No egress hosts, no listener: port 0 cannot be connected to, so every
    // proxied request fails at once instead of going out direct.
    let proxy = format!("http://127.0.0.1:{}", server.egress_port.unwrap_or(0));
    let mut cmd = child_command(spec, &shared.home, server.egress_port)?;
    host_env(&mut cmd, &shared.home, spec.credential.keychain);
    cmd.env("HTTPS_PROXY", &proxy)
        .env("HTTP_PROXY", &proxy)
        .env("https_proxy", &proxy)
        .env("http_proxy", &proxy)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        // Never the agent-writable project: `python3 -m x` imports from cwd.
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let Some(err) = child.stderr.take() {
        let (log, id) = (shared.log.clone(), spec.id.clone());
        std::thread::spawn(move || log_stderr(BufReader::new(err), &log, &id));
    }
    Ok(child)
}

/// Lines of a child's stderr logged per child, and bytes per line.
const STDERR_CAP: usize = 64;
const STDERR_LINE: u64 = 512;

/// The child's stderr to the broker log, line by line, each line redacted,
/// until [`STDERR_CAP`] lines; the rest is drained unlogged so the child
/// never blocks on a full pipe.
fn log_stderr(mut r: impl BufRead, log: &Log, id: &str) {
    let mut logged = 0;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.by_ref().take(STDERR_LINE).read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if logged >= STDERR_CAP {
            continue;
        }
        logged += 1;
        let line = redact(String::from_utf8_lossy(&buf).trim_end());
        log.line(id, &format!("stderr: {line}"));
        if logged >= STDERR_CAP {
            log.line(id, "stderr: (cap reached, rest not logged)");
        }
    }
}

/// Mask anything token-shaped: a run of 20 or more token characters (JWTs,
/// API keys, hex digests, base64) becomes `[redacted]`.
fn redact(line: &str) -> String {
    let tok = |c: char| c.is_ascii_alphanumeric() || "-_.=+/".contains(c);
    let mut out = String::new();
    let mut run = String::new();
    for c in line.chars().chain(std::iter::once(' ')) {
        if tok(c) {
            run.push(c);
            continue;
        }
        out.push_str(if run.len() >= 20 { "[redacted]" } else { &run });
        run.clear();
        out.push(c);
    }
    out.pop();
    out
}

/// The server's command. On macOS it runs under `sandbox-exec` with
/// [`crate::sandbox::mcp_child_profile`]: TCP only to its egress proxy,
/// writes only to its credential's `write_dirs` and its temp dir (#849).
/// Elsewhere the child is not network-sandboxed (see the design doc).
#[allow(clippy::disallowed_methods)] // resolved in the trusted dirs at load; sandbox-exec is fixed
fn child_command(spec: &Spec, home: &Path, egress: Option<u16>) -> std::io::Result<Command> {
    if !cfg!(target_os = "macos") {
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.command[1..]);
        return Ok(cmd);
    }
    let mut dirs = vec![std::env::temp_dir()];
    dirs.extend(spec.credential.write_dirs.iter().map(|d| home.join(d)));
    // Seatbelt matches resolved paths (/var is /private/var). A dir that does
    // not exist yet keeps its spelling: a fresh login creates it.
    let dirs: Vec<_> = dirs
        .into_iter()
        .map(|d| d.canonicalize().unwrap_or(d))
        .collect();
    let profile =
        crate::sandbox::mcp_child_profile(home, &dirs, egress).map_err(std::io::Error::other)?;
    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-p")
        .arg(profile)
        .arg("--")
        .arg(&spec.program)
        .args(&spec.command[1..]);
    Ok(cmd)
}

/// The host child's environment, also the credential probe's, so the two
/// never disagree. Cleared, then: HOME, the trusted PATH, TMPDIR, LANG, and
/// on Linux, for a `keychain` mechanism only, the session bus
/// (`DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR`), which go-keyring needs
/// to reach the Secret Service on the host, and
/// `XDG_CONFIG_HOME`/`XDG_DATA_HOME`, where nais (`os.UserConfigDir`) keeps
/// its login. The child runs on the host, not in the sandbox.
pub(crate) fn host_env(cmd: &mut Command, home: &Path, keychain: bool) {
    cmd.env_clear();
    for (k, v) in host_env_pairs(home, keychain, &|k| std::env::var_os(k)) {
        cmd.env(k, v);
    }
}

fn host_env_pairs(
    home: &Path,
    keychain: bool,
    get: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Vec<(&'static str, std::ffi::OsString)> {
    let mut env = vec![
        ("HOME", home.as_os_str().to_owned()),
        ("PATH", crate::git::TRUSTED_BIN_DIRS.join(":").into()),
        ("TMPDIR", std::env::temp_dir().into_os_string()),
    ];
    let mut keep = vec!["LANG"];
    if cfg!(target_os = "linux") {
        keep.extend(["XDG_CONFIG_HOME", "XDG_DATA_HOME"]);
        if keychain {
            keep.extend(["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"]);
        }
    }
    env.extend(keep.into_iter().filter_map(|k| get(k).map(|v| (k, v))));
    env
}

/// One client connection: the id line, then JSON-RPC lines both ways until
/// either side ends. The child lives exactly as long as the connection: an
/// MCP stdio session cannot be resumed, so the client reconnects and
/// re-initializes against a fresh child.
pub(crate) fn serve(shared: &Shared, stream: UnixStream) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let client = Arc::new(Mutex::new(stream));
    let refuse = |msg: &str| {
        write_line(
            &client,
            &error_line(&Value::Null, DENIED, &format!("cplt: {msg}")),
        );
    };
    let Some(id) = read_line(&mut reader, 512) else {
        return;
    };
    let Some(server) = shared.servers.get(&id) else {
        refuse("no brokered MCP server with that id");
        return;
    };
    let spec = &server.spec;
    if let Ok(s) = client.lock() {
        let _ = s.set_read_timeout(None);
    }
    let child = {
        let Ok(mut slot) = server.child.lock() else {
            return;
        };
        // Under the slot lock: Drop sets `stop` before scanning the slots,
        // so either it sees this child or no child is started.
        if shared.stop.load(Ordering::Acquire) {
            return;
        }
        if slot.is_some() {
            // ponytail: one client per server; multiplexing needs id rewriting.
            refuse("this MCP server already has a client in this session");
            return;
        }
        let Ok(mut spawns) = server.spawns.lock() else {
            return;
        };
        while spawns
            .front()
            .is_some_and(|t| t.elapsed() > Duration::from_secs(60))
        {
            spawns.pop_front();
        }
        if spawns.len() >= SPAWNS_PER_MINUTE {
            shared.log.line(
                &spec.id,
                &format!(
                    "stopped after {SPAWNS_PER_MINUTE} restarts in a minute; see the proxy log"
                ),
            );
            refuse("server stopped after too many restarts");
            return;
        }
        spawns.push_back(Instant::now());
        match spawn_child(shared, server) {
            Ok(c) => {
                shared.log.line(&spec.id, "started");
                let c = Arc::new(Mutex::new(c));
                *slot = Some(Arc::clone(&c));
                c
            }
            Err(e) => {
                shared
                    .log
                    .line(&spec.id, &format!("FAIL cannot start: {e}"));
                refuse("cannot start the server");
                return;
            }
        }
    };
    let (stdin, stdout) = {
        let Ok(mut c) = child.lock() else { return };
        (c.stdin.take(), c.stdout.take())
    };
    let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
        return;
    };
    let stdin: Arc<Mutex<ChildStdin>> = Arc::new(Mutex::new(stdin));
    let pending = Arc::new(Mutex::new(Pending::default()));

    // Server → client. On child exit, close the client's socket.
    let out = {
        let (client, stdin, pending) = (
            Arc::clone(&client),
            Arc::clone(&stdin),
            Arc::clone(&pending),
        );
        let spec = spec.clone();
        let log = shared.log.clone();
        std::thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            while let Some(line) = read_line(&mut r, MAX_MESSAGE) {
                if auth_error(&line) {
                    let fix = spec
                        .login
                        .as_deref()
                        .map(|l| format!(" Fix: {l}"))
                        .unwrap_or_default();
                    log.line(&spec.id, &format!("FAIL not logged in on the host.{fix}"));
                }
                let action = match pending.lock() {
                    Ok(mut p) => on_server(&line, &spec, &mut p),
                    Err(_) => break,
                };
                match action {
                    Action::Forward(l) => {
                        if !write_line(&client, &l) {
                            break;
                        }
                    }
                    Action::Reply(l, _) => {
                        write_line(&stdin, &l);
                    }
                    Action::Drop => {}
                }
            }
            if let Ok(c) = client.lock() {
                let _ = c.shutdown(std::net::Shutdown::Both);
            }
        })
    };

    // Deadline: about ten times a second, time out requests past
    // CALL_TIMEOUT. Written under the pending lock, so a reused id never
    // gets the stale error.
    let done = Arc::new(AtomicBool::new(false));
    // Cancels go through a bounded channel to a writer thread: a child that
    // stops reading stdin must not stall the ticker (the timeout replies
    // still go out). The writer unblocks when the child is killed.
    let (cancel_tx, cancel_rx) = std::sync::mpsc::sync_channel::<String>(64);
    let canceller = {
        let stdin = Arc::clone(&stdin);
        std::thread::spawn(move || {
            while let Ok(c) = cancel_rx.recv() {
                if !write_line(&stdin, &c) {
                    break;
                }
            }
        })
    };
    let ticker = {
        let (client, pending, done) =
            (Arc::clone(&client), Arc::clone(&pending), Arc::clone(&done));
        let (log, id) = (shared.log.clone(), spec.id.clone());
        std::thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                let Ok(mut p) = pending.lock() else { break };
                for (error, cancel) in p.evict(CALL_TIMEOUT) {
                    log.line(&id, "FAIL request timed out");
                    write_line(&client, &error);
                    // Best effort: a full queue means the child is stuck.
                    let _ = cancel_tx.try_send(cancel);
                }
                drop(p);
                if done.load(Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };

    // Client → server.
    while let Some(line) = read_line(&mut reader, MAX_MESSAGE) {
        let action = match pending.lock() {
            Ok(mut p) => on_client(&line, spec, &mut p),
            Err(_) => break,
        };
        match action {
            Action::Forward(l) => {
                if !write_line(&stdin, &l) {
                    break;
                }
            }
            Action::Reply(l, log) => {
                if let Some(text) = log {
                    shared.log.line(&spec.id, &text);
                }
                if !write_line(&client, &l) {
                    break;
                }
            }
            Action::Drop => {}
        }
    }
    // Client gone (or the socket was closed): end the child.
    done.store(true, Ordering::Release);
    drop(stdin);
    if let Ok(mut slot) = server.child.lock()
        && slot.as_ref().is_some_and(|c| Arc::ptr_eq(c, &child))
    {
        *slot = None;
    }
    kill(&child);
    let _ = out.join();
    let _ = ticker.join();
    let _ = canceller.join();
}

#[cfg(test)]
// Most of these need the macOS-only runtime.
mod tests {
    use super::*;
    use crate::mcp_broker::test_util::*;

    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use serde_json::Value;

    #[test]
    fn redact_masks_token_shaped_runs_only() {
        assert_eq!(
            redact("error: token eyJhbGciOiJIUzI1NiJ9.e30.abc expired"),
            "error: token [redacted] expired"
        );
        assert_eq!(
            redact("dial tcp: connect refused"),
            "dial tcp: connect refused"
        );
    }

    #[test]
    fn stderr_is_capped_and_redacted() {
        let file = std::env::temp_dir().join(format!("cplt-849-stderr-{}.log", std::process::id()));
        let log = Log {
            level: crate::proxy::ProxyLogLevel::default(),
            file: Some(file.clone()),
        };
        let mut input = String::from("secret ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
        input.push_str(&"x \n".repeat(20_000));
        log_stderr(std::io::Cursor::new(input), &log, "t");
        let out = std::fs::read_to_string(&file).unwrap();
        let _ = std::fs::remove_file(&file);
        assert!(!out.contains("ghp_"), "{out}");
        assert!(out.contains("cap reached"));
        assert_eq!(out.lines().count(), STDERR_CAP + 1);
    }

    /// The kernel, not the profile text: inside the child profile a TCP
    /// connect reaches only the egress port, not another local port and not
    /// a remote host.
    #[cfg(target_os = "macos")]
    #[test]
    #[allow(clippy::disallowed_methods)] // fixed /usr/bin paths
    fn child_profile_allows_only_the_egress_port() {
        let allowed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = |l: &std::net::TcpListener| l.local_addr().unwrap().port();
        let home = std::env::temp_dir().canonicalize().unwrap();
        let profile = crate::sandbox::mcp_child_profile(&home, &[], Some(port(&allowed))).unwrap();
        let nc = |host: &str, p: u16| {
            Command::new("/usr/bin/sandbox-exec")
                .args(["-p", &profile, "--", "/usr/bin/nc", "-z", "-G", "2", host])
                .arg(p.to_string())
                .output()
                .unwrap()
                .status
                .success()
        };
        assert!(nc("127.0.0.1", port(&allowed)), "egress port refused");
        assert!(!nc("127.0.0.1", port(&other)), "another local port reached");
        assert!(!nc("1.1.1.1", 443), "a remote host reached");
        // And no writes outside its dirs.
        let st = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile, "--", "/usr/bin/touch"])
            .arg(home.join(format!("cplt-849-w-{}", std::process::id())))
            .status()
            .unwrap();
        assert!(!st.success(), "wrote outside write_dirs");
    }

    #[test]
    fn the_host_child_keeps_the_bus_and_xdg_dirs_on_linux_only() {
        let get = |k: &str| {
            matches!(
                k,
                "DBUS_SESSION_BUS_ADDRESS"
                    | "XDG_RUNTIME_DIR"
                    | "XDG_CONFIG_HOME"
                    | "XDG_DATA_HOME"
                    | "LANG"
                    | "SECRET"
            )
            .then(|| std::ffi::OsString::from(format!("v-{k}")))
        };
        let env = host_env_pairs(Path::new("/home/u"), true, &get);
        let names: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
        assert!(
            names.contains(&"HOME") && names.contains(&"LANG"),
            "{names:?}"
        );
        assert!(
            !names.contains(&"SECRET"),
            "nothing else from cplt's env: {names:?}"
        );
        for k in [
            "DBUS_SESSION_BUS_ADDRESS",
            "XDG_RUNTIME_DIR",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
        ] {
            assert_eq!(
                names.contains(&k),
                cfg!(target_os = "linux"),
                "{k}: {names:?}"
            );
        }
        // The session bus only for a mechanism that reads the keychain.
        let bare = host_env_pairs(Path::new("/home/u"), false, &get);
        assert!(
            !bare
                .iter()
                .any(|(k, _)| matches!(*k, "DBUS_SESSION_BUS_ADDRESS" | "XDG_RUNTIME_DIR")),
            "{bare:?}"
        );
    }

    #[test]
    fn failures_reach_the_terminal_at_every_level() {
        use crate::proxy::ProxyLogLevel::{All, Blocked, None as Silent};
        for level in [Silent, Blocked, All] {
            assert!(to_terminal(level, "tools/call → DENIED tool"));
            assert!(to_terminal(level, "egress → DENIED example.com"));
            assert!(to_terminal(level, "FAIL not logged in on the host."));
            assert!(to_terminal(level, "stopped after 3 restarts in a minute"));
        }
        assert!(!to_terminal(Silent, "started"));
        assert!(!to_terminal(Blocked, "started"));
        assert!(to_terminal(All, "started"));
    }

    #[test]
    fn kill_terminates_and_never_signals_a_reaped_child() {
        #[allow(clippy::disallowed_methods)]
        let c = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let c = Mutex::new(c);
        let start = Instant::now();
        kill(&c);
        assert!(start.elapsed() < KILL_GRACE + Duration::from_secs(1));
        assert!(matches!(c.lock().unwrap().try_wait(), Ok(Some(_))));
        kill(&c); // already reaped: returns at once, no signal
        // SIGTERM ignored: SIGKILL after the grace.
        #[allow(clippy::disallowed_methods)]
        let mut c = Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; echo ready; exec sleep 30"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        // Readiness, not a sleep: the trap is set once "ready" is printed.
        let mut l = String::new();
        BufReader::new(c.stdout.take().unwrap())
            .read_line(&mut l)
            .unwrap();
        assert_eq!(l, "ready\n");
        let c = Mutex::new(c);
        kill(&c);
        assert!(matches!(c.lock().unwrap().try_wait(), Ok(Some(_))));
    }

    fn cat_broker() -> Broker {
        let mut spec = check(base()).unwrap();
        spec.command = vec!["cat".into()];
        spec.program = "/bin/cat".into();
        Broker::start(
            vec![spec],
            Path::new("/tmp"),
            Log {
                level: crate::proxy::ProxyLogLevel::None,
                file: None,
            },
        )
        .unwrap()
    }

    fn connect(b: &Broker) -> (UnixStream, BufReader<UnixStream>) {
        let mut s = UnixStream::connect(b.socket()).unwrap();
        writeln!(s, "io.github.nais/nais-mcp").unwrap();
        // A hang bound, not a latency check: under the full suite a spawn can
        // stall for seconds.
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let r = BufReader::new(s.try_clone().unwrap());
        (s, r)
    }

    fn wait_free(b: &Broker) {
        let server = &b.shared.servers["io.github.nais/nais-mcp"];
        let start = Instant::now();
        while server.child.lock().unwrap().is_some() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "child slot never freed"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_second_client_is_refused() {
        let b = cat_broker();
        let (mut a, mut ra) = connect(&b);
        // A round trip proves the child is up and bound to `a`.
        writeln!(a, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
        let mut l = String::new();
        ra.read_line(&mut l).unwrap();
        let (_b2, mut rb) = connect(&b);
        let mut l = String::new();
        rb.read_line(&mut l).unwrap();
        assert!(l.contains("already has a client"), "{l}");
    }

    #[test]
    fn the_restart_budget_stops_respawns() {
        let b = cat_broker();
        for _ in 0..SPAWNS_PER_MINUTE {
            let (mut a, mut ra) = connect(&b);
            writeln!(a, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
            let mut l = String::new();
            ra.read_line(&mut l).unwrap();
            drop((a, ra));
            wait_free(&b);
        }
        let (_a, mut ra) = connect(&b);
        let mut l = String::new();
        ra.read_line(&mut l).unwrap();
        assert!(l.contains("too many restarts"), "{l}");
    }

    #[test]
    fn connection_permits_are_bounded() {
        let open = Arc::new(AtomicUsize::new(0));
        let held: Vec<Permit> = (0..MAX_CONNECTIONS)
            .map(|_| Permit::take(&open).unwrap())
            .collect();
        assert!(Permit::take(&open).is_none());
        drop(held);
        assert!(Permit::take(&open).is_some());
    }

    fn sh_broker(script: &str) -> Broker {
        sh_broker_with(script, true)
    }

    fn sh_broker_with(script: &str, egress: bool) -> Broker {
        let mut spec = check(base()).unwrap();
        if !egress {
            spec.egress_hosts.clear();
        }
        spec.command = vec!["sh".into(), "-c".into(), script.into()];
        spec.program = "/bin/sh".into();
        Broker::start(
            vec![spec],
            Path::new("/tmp"),
            Log {
                level: crate::proxy::ProxyLogLevel::None,
                file: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn the_child_runs_in_root_with_a_cleared_env() {
        let b = sh_broker(
            r#"read l; printf '{"jsonrpc":"2.0","id":1,"result":{"cwd":"%s","pp":"%s"}}\n' "$PWD" "${PYTHONPATH:-none}"; cat >/dev/null"#,
        );
        let (mut a, mut ra) = connect(&b);
        writeln!(a, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
        let mut l = String::new();
        ra.read_line(&mut l).unwrap();
        let v: Value = serde_json::from_str(&l).unwrap();
        assert_eq!(v["result"]["cwd"], "/", "{l}");
        assert_eq!(v["result"]["pp"], "none", "{l}");
    }

    #[test]
    fn a_child_that_stops_reading_stdin_does_not_stall_timeouts() {
        let b = sh_broker("sleep 60");
        let (mut a, mut ra) = connect(&b);
        let req = |id: u32, pad: usize| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{id},"method":"ping","params":{{"p":"{}"}}}}"#,
                "x".repeat(pad)
            )
        };
        // Two small requests, then one that fills the pipe and blocks the
        // client-to-server thread in write.
        writeln!(a, "{}", req(1, 0)).unwrap();
        writeln!(a, "{}", req(2, 0)).unwrap();
        writeln!(a, "{}", req(3, 3 * 1024 * 1024)).unwrap();
        let mut ids = Vec::new();
        for _ in 0..3 {
            let mut l = String::new();
            ra.read_line(&mut l).unwrap();
            let v: Value = serde_json::from_str(&l).unwrap();
            assert!(
                v["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("timed out"),
                "{l}"
            );
            ids.push(v["id"].as_u64().unwrap());
        }
        ids.sort_unstable();
        assert_eq!(ids, [1, 2, 3]);
    }

    #[test]
    fn no_child_after_stop() {
        let b = cat_broker();
        b.shared.stop.store(true, Ordering::Release);
        // The accept loop may already be gone (connect or write then fails)
        // or may still accept: either way no child may start.
        if let Ok(mut s) = UnixStream::connect(b.socket()) {
            let _ = writeln!(s, "io.github.nais/nais-mcp");
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut l = String::new();
            let _ = BufReader::new(s).read_line(&mut l);
            assert!(l.is_empty(), "closed without serving: {l}");
        }
        assert!(
            b.shared.servers["io.github.nais/nais-mcp"]
                .child
                .lock()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn no_egress_hosts_no_listener() {
        let script = r#"read l; printf '{"jsonrpc":"2.0","id":1,"result":{"p":"%s"}}\n' "$HTTPS_PROXY"; cat >/dev/null"#;
        for (egress, port0) in [(false, true), (true, false)] {
            let b = sh_broker_with(script, egress);
            let server = &b.shared.servers["io.github.nais/nais-mcp"];
            assert_eq!(server.egress_port.is_none(), port0);
            let (mut a, mut ra) = connect(&b);
            writeln!(a, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
            let mut l = String::new();
            ra.read_line(&mut l).unwrap();
            assert_eq!(l.contains("127.0.0.1:0\""), port0, "{l}");
        }
    }
}
