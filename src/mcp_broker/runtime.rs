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
use super::shim::{CHILD_EGRESS_SOCKET, RELAY_ENV};
use super::spec::Spec;
use super::{CALL_TIMEOUT, DENIED, KILL_GRACE, MAX_MESSAGE, SPAWNS_PER_MINUTE};

/// Where broker lines go: cplt's terminal output and the `--proxy-log` file.
#[derive(Clone)]
pub struct Log {
    pub level: crate::proxy::ProxyLogLevel,
    pub file: Option<PathBuf>,
}

/// DENIED, failed egress dials, auth and other failures reach the terminal at every level (D12);
/// the rest only at `--proxy-log-level all`.
fn to_terminal(level: crate::proxy::ProxyLogLevel, text: &str) -> bool {
    text.contains("DENIED")
        || text.contains("connect failed")
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
    /// Linux: the same proxy as a unix socket, bound into the child's
    /// network namespace, where host loopback is out of reach (#849).
    egress_socket: Option<PathBuf>,
    /// Linux, `keychain` mechanisms: where this server's xdg-dbus-proxy
    /// listens, in the broker's 0700 socket dir.
    bus_socket: PathBuf,
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
        let mut egress_unix = Vec::new();
        let mut servers = BTreeMap::new();
        for (n, spec) in specs.into_iter().enumerate() {
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
            let egress_socket = match egress_port {
                Some(port) if cfg!(target_os = "linux") => {
                    let path = dir.path().join(format!("e{n}"));
                    let l = std::os::unix::net::UnixListener::bind(&path)
                        .and_then(|l| l.set_nonblocking(true).map(|()| l))
                        .map_err(|e| format!("cannot bind {}: {e}", path.display()))?;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .map_err(|e| format!("cannot restrict {}: {e}", path.display()))?;
                    egress_unix.push((l, port));
                    Some(path)
                }
                _ => None,
            };
            let server = Server {
                spec,
                child: Mutex::new(None),
                spawns: Mutex::new(VecDeque::new()),
                egress_port,
                egress_socket,
                bus_socket: dir.path().join(format!("b{n}")),
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
        // The host end of the Linux child's egress hop: each connection on
        // the unix socket goes on to the TCP proxy above, which decides.
        // It takes a permit here and another at the TCP proxy, so a Linux
        // child's tunnel counts twice against MAX_CONNECTIONS: at most 16
        // of them at once. Deliberate: the hop's own thread needs a bound
        // before it connects, and sharing one permit across the two
        // listeners would need a handshake between them.
        for (l, port) in egress_unix {
            let s = Arc::clone(&shared);
            std::thread::spawn(move || {
                while !s.stop.load(Ordering::Acquire) {
                    match l.accept() {
                        Ok((stream, _)) => {
                            let Some(permit) = Permit::take(&s.open) else {
                                continue;
                            };
                            std::thread::spawn(move || {
                                let _permit = permit;
                                let _ = stream.set_nonblocking(false);
                                if let Ok(up) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                                    super::shim::pipe(up, stream);
                                }
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

    /// Run `args` with server `id`'s program, in the server's own sandbox
    /// and environment, egress through its proxy: the credential probe.
    /// stdin is closed at once; stdout and stderr are not read.
    pub(crate) fn spawn_probe(&self, id: &str, args: &[&str]) -> std::io::Result<Child> {
        let server = self
            .shared
            .servers
            .get(id)
            .ok_or_else(|| std::io::Error::other("no such server"))?;
        let mut child = spawn_child_with(&self.shared, server, Some(args))?;
        drop(child.stdin.take());
        if let Some(mut out) = child.stdout.take() {
            std::thread::spawn(move || std::io::copy(&mut out, &mut std::io::sink()));
        }
        Ok(child)
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
    spawn_child_with(shared, server, None)
}

/// [`spawn_child`] with `args` in place of the spec's own arguments: the
/// credential probe, run in the same sandbox as the server.
fn spawn_child_with(
    shared: &Shared,
    server: &Server,
    args: Option<&[&str]>,
) -> std::io::Result<Child> {
    let spec = &server.spec;
    // No egress hosts, no listener: port 0 cannot be connected to, so every
    // proxied request fails at once instead of going out direct.
    let proxy = format!("http://127.0.0.1:{}", server.egress_port.unwrap_or(0));
    let (mut cmd, setup) = child_command(shared, server, args)?;
    host_env(&mut cmd, &shared.home, spec.credential.keychain);
    for k in &setup.unset {
        cmd.env_remove(k);
    }
    for (k, v) in &setup.env {
        cmd.env(k, v);
    }
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
    // The bus proxy's sync pipe now lives in bwrap alone.
    drop(setup);
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
        // Longer than the cap: drop the whole line, never log it in pieces
        // (a token cut at the seam would pass redaction as two short runs).
        let overlong = buf.len() as u64 == STDERR_LINE && buf.last() != Some(&b'\n');
        if overlong {
            let mut tail = Vec::new();
            while let Ok(n) = r.by_ref().take(STDERR_LINE).read_until(b'\n', &mut tail) {
                if n == 0 || tail.last() == Some(&b'\n') {
                    break;
                }
                tail.clear();
            }
        }
        if logged >= STDERR_CAP {
            continue;
        }
        logged += 1;
        if overlong {
            log.line(id, "stderr: [line over 512 bytes dropped]");
        } else {
            let line = redact(String::from_utf8_lossy(&buf).trim_end());
            log.line(id, &format!("stderr: {line}"));
        }
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

/// `path` with its nearest existing ancestor canonicalized and the missing
/// tail appended, so a grant on a not-yet-created dir under a symlinked
/// parent still names the path Seatbelt will see.
fn resolve_existing_prefix(path: &Path) -> PathBuf {
    let mut tail = Vec::new();
    let mut cur = path;
    loop {
        if let Ok(real) = cur.canonicalize() {
            return tail.iter().rev().fold(real, |p, c| p.join(c));
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_owned());
                cur = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// The server's command. On macOS it runs under `sandbox-exec` with
/// [`crate::sandbox::mcp_child_profile`]: TCP only to its egress proxy,
/// writes only to its credential's `write_dirs` and its temp dir (#849).
/// On Linux it runs under bwrap with its own network namespace, see
/// [`linux_child_command`]. Nowhere does it run unsandboxed.
#[allow(clippy::disallowed_methods)] // resolved in the trusted dirs at load; sandbox-exec is fixed
fn child_command(
    shared: &Shared,
    server: &Server,
    args: Option<&[&str]>,
) -> std::io::Result<(Command, ChildSetup)> {
    let (spec, home, egress) = (&server.spec, shared.home.as_path(), server.egress_port);
    let args: Vec<String> = match args {
        Some(a) => a.iter().map(|a| (*a).to_string()).collect(),
        None => spec.command[1..].to_vec(),
    };
    if cfg!(target_os = "linux") {
        return linux_child_command(shared, server, &args);
    }
    if !cfg!(target_os = "macos") {
        return Err(std::io::Error::other(
            "no sandbox for the MCP server child on this OS",
        ));
    }
    let mut dirs = vec![std::env::temp_dir()];
    dirs.extend(spec.credential.write_dirs.iter().map(|d| home.join(d)));
    // Seatbelt matches resolved paths (/var is /private/var). A dir that does
    // not exist yet (a fresh login creates it) resolves through its parents.
    let dirs: Vec<_> = dirs
        .into_iter()
        .map(|d| resolve_existing_prefix(&d))
        .collect();
    let profile = crate::sandbox::mcp_child_profile(home, &dirs, spec.credential.keychain, egress)
        .map_err(std::io::Error::other)?;
    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-p")
        .arg(profile)
        .arg("--")
        .arg(&spec.program)
        .args(&args);
    Ok((cmd, ChildSetup::default()))
}

/// What the child's command needs past [`host_env`], and what must live
/// until it is spawned.
#[derive(Default)]
struct ChildSetup {
    env: Vec<(&'static str, std::ffi::OsString)>,
    unset: Vec<&'static str>,
    /// The read end of the bus proxy's `--fd` pipe, handed to bwrap as its
    /// `--sync-fd`: the proxy exits when bwrap, and so the child, is gone.
    sync: Option<std::io::PipeReader>,
}

/// Where the filtered session bus appears inside the Linux child.
const CHILD_BUS_SOCKET: &str = "/run/cplt-bus";

/// The Linux child (#849): `bwrap <`[`child_bwrap_args`]`> -- <this
/// binary>` with [`RELAY_ENV`] naming the port and the server's argv, so
/// it starts as the egress relay, which runs the server. Fails, never
/// falls back, when bwrap is missing; when bwrap cannot build the
/// namespaces it exits before the server starts.
#[allow(clippy::disallowed_methods)] // bwrap from the trusted dirs; cplt is this binary
fn linux_child_command(
    shared: &Shared,
    server: &Server,
    args: &[String],
) -> std::io::Result<(Command, ChildSetup)> {
    let spec = &server.spec;
    #[cfg(target_os = "linux")]
    let bwrap = crate::sandbox::bubblewrap_probe::check_availability();
    #[cfg(not(target_os = "linux"))]
    let bwrap: Option<PathBuf> = None;
    let bwrap = bwrap.ok_or_else(|| {
        std::io::Error::other("bwrap not found; the MCP server child does not run unsandboxed")
    })?;
    let cplt = std::env::current_exe()?;
    let disable_userns = disables_userns(&bwrap);
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| shared.home.join(".config"));
    let write_dirs: Vec<PathBuf> = spec
        .credential
        .linux_write_dirs
        .iter()
        .map(|d| config_home.join(d))
        .collect();
    // bwrap cannot bind a missing source; a first login creates it anyway.
    for d in &write_dirs {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(d)?;
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let mut setup = ChildSetup::default();
    let bus = child_bus(
        shared,
        server,
        runtime.as_deref(),
        crate::git::trusted_binary("xdg-dbus-proxy"),
        &mut setup,
    );
    let mut argv = vec![spec.program.to_string_lossy().into_owned()];
    argv.extend(args.iter().cloned());
    let relay = serde_json::json!([server.egress_port.unwrap_or(0), argv]).to_string();
    setup.env.extend([
        (RELAY_ENV, relay.into()),
        // The private /tmp is the only temp dir it can write.
        ("TMPDIR", "/tmp".into()),
        ("XDG_CONFIG_HOME", config_home.clone().into_os_string()),
    ]);
    let current_system = std::fs::read_link("/run/current-system").ok();
    let mut cmd = Command::new(bwrap);
    // An empty HOME, bar the mechanism's grants. One under the private /tmp
    // or /run is empty already; `/` (or a relative HOME) cannot be hidden.
    let home = shared.home.as_path();
    if !home.is_absolute() || home.parent().is_none() {
        return Err(std::io::Error::other(format!(
            "HOME {} cannot be hidden from the MCP server child",
            home.display()
        )));
    }
    // HOME, then the config and data dirs nais may be pointed at outside it:
    // each hidden unless /tmp, /run or an earlier one covers it already.
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && spec.credential.keychain);
    let hide = hidden_dirs(home, &config_home, data_home.as_deref());
    let read_paths: Vec<PathBuf> = spec
        .credential
        .linux_read_paths
        .iter()
        .map(|p| home.join(p))
        .collect();
    let nix_sockets: Vec<PathBuf> = NIX_SOCKET_DIRS
        .iter()
        .map(PathBuf::from)
        .filter(|d| d.is_dir())
        .collect();
    cmd.args(child_bwrap_args(&ChildMounts {
        hide: &hide,
        write_dirs: &write_dirs,
        read_paths: &read_paths,
        relay_exe: Some(&cplt),
        disable_userns,
        runtime_dir: runtime.as_deref(),
        current_system: current_system.as_deref(),
        nix_sockets: &nix_sockets,
        bus,
        egress_socket: server.egress_socket.as_deref(),
    }));
    if let Some(sync) = &setup.sync {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let fd = sync.as_raw_fd();
        cmd.args(["--sync-fd", "3"]);
        // SAFETY: only dup2/fcntl, async-signal-safe, between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                let r = if fd == 3 {
                    libc::fcntl(3, libc::F_SETFD, 0)
                } else {
                    libc::dup2(fd, 3)
                };
                if r < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    cmd.arg("--").arg(CHILD_RELAY_EXE);
    Ok((cmd, setup))
}

/// The filtered session bus for a `keychain` mechanism: where it listens,
/// with `setup` pointing the child at it; else `None`, with the bus address
/// unset. Never the host bus itself: no `proxy` (xdg-dbus-proxy from the
/// trusted dirs), or one that does not start, is no bus.
fn child_bus<'a>(
    shared: &Shared,
    server: &'a Server,
    runtime: Option<&Path>,
    proxy: Option<PathBuf>,
    setup: &mut ChildSetup,
) -> Option<&'a Path> {
    let spec = &server.spec;
    let mut bus = None;
    if spec.credential.keychain {
        let addr = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
        match pick_session_bus(addr.as_deref(), runtime, is_socket) {
            None => shared.log.line(
                &spec.id,
                "FAIL no session bus on the host, so no keychain login for the server",
            ),
            Some(real) => match start_bus_proxy(proxy, &real, &server.bus_socket) {
                Ok(sync) => {
                    setup.sync = Some(sync);
                    bus = Some(server.bus_socket.as_path());
                }
                Err(e) => shared.log.line(
                    &spec.id,
                    &format!("FAIL no session bus for the server, so no keychain login: {e}"),
                ),
            },
        }
    }
    if bus.is_some() {
        let addr = format!("unix:path={CHILD_BUS_SOCKET}");
        setup.env.push(("DBUS_SESSION_BUS_ADDRESS", addr.into()));
    } else {
        setup.unset.push("DBUS_SESSION_BUS_ADDRESS");
    }
    bus
}

fn is_socket(p: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket())
}

/// The host's session bus socket: the first `unix:path=` in `addr` that is
/// a socket, or with no address set, `$XDG_RUNTIME_DIR/bus`. An abstract
/// or TCP bus lives in the host's network namespace and is out of reach.
fn pick_session_bus(
    addr: Option<&str>,
    runtime_dir: Option<&Path>,
    is_socket: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    match addr {
        Some(a) => crate::sandbox::parse_dbus_address(a)
            .paths
            .into_iter()
            .find(|p| is_socket(p)),
        None => runtime_dir.map(|d| d.join("bus")).filter(|p| is_socket(p)),
    }
}

/// The D-Bus spelling of `unix:path=<path>`: bytes outside the safe set
/// as `%XX`.
fn dbus_path_address(path: &Path) -> String {
    use std::fmt::Write as _;
    use std::os::unix::ffi::OsStrExt;
    let mut out = String::from("unix:path=");
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_/.\\*".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02x}");
        }
    }
    out
}

/// What the filtered bus lets the child talk to: the Secret Service only.
/// go-keyring makes every call there (open session, search, unlock, the
/// prompt objects and their signals, get secret). xdg-dbus-proxy itself
/// always passes the bus driver's `Hello`, `AddMatch` and the like.
const BUS_TALK: &[&str] = &["--talk=org.freedesktop.secrets"];

/// Start xdg-dbus-proxy (from the trusted dirs, never `PATH`) on `socket`,
/// filtering the host bus at `real` to [`BUS_TALK`], as Flatpak does. Its
/// `--fd` is the write end of a pipe: it writes one byte when it listens,
/// and exits once the read end, returned here, is closed.
#[allow(clippy::disallowed_methods)] // from crate::git::trusted_binary
fn start_bus_proxy(
    proxy: Option<PathBuf>,
    real: &Path,
    socket: &Path,
) -> std::io::Result<std::io::PipeReader> {
    let proxy = proxy.ok_or_else(|| {
        std::io::Error::other("xdg-dbus-proxy is not installed in the trusted dirs")
    })?;
    let _ = std::fs::remove_file(socket);
    let (mut ready, w) = std::io::pipe()?;
    let mut child = Command::new(proxy)
        .arg(dbus_path_address(real))
        .arg(socket)
        .arg("--filter")
        .args(BUS_TALK)
        .arg("--fd=1")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(w)
        .stderr(Stdio::null())
        .spawn()?;
    let ok = ready.read_exact(&mut [0u8]);
    // Reaped whenever it exits, with the child or on its own.
    std::thread::spawn(move || child.wait());
    ok.map_err(|_| std::io::Error::other("xdg-dbus-proxy exited before it was ready"))?;
    Ok(ready)
}

/// bwrap's arguments for the Linux child, before `--`: every namespace
/// bwrap has, the network one included, so the only way out is the egress
/// socket. The host root read-only; private `/tmp` and `/run` (hiding the
/// host's sockets there, the system bus and docker's among them) and, if
/// it lives elsewhere, a private runtime dir; then writable `write_dirs`,
/// the session bus socket alone, and the egress socket.
/// What [`child_bwrap_args`] mounts, found on the host by
/// [`linux_child_command`].
#[derive(Default)]
struct ChildMounts<'a> {
    /// Dirs that get an empty tmpfs, remounted read-only once the grants
    /// are bound: `HOME`, and the XDG config and data dirs outside it.
    hide: &'a [PathBuf],
    write_dirs: &'a [PathBuf],
    /// Bound back read-only under the empty `HOME`.
    read_paths: &'a [PathBuf],
    runtime_dir: Option<&'a Path>,
    current_system: Option<&'a Path>,
    /// The Nix daemon's socket dirs that exist on this host.
    nix_sockets: &'a [PathBuf],
    bus: Option<&'a Path>,
    egress_socket: Option<&'a Path>,
    /// This binary, bound in at [`CHILD_RELAY_EXE`]: it may live in `HOME`.
    relay_exe: Option<&'a Path>,
    /// bwrap 0.8+: `--disable-userns`, no nested user namespaces.
    disable_userns: bool,
}

/// Whether this host's bwrap has `--disable-userns` (0.8+), from
/// `bwrap --version`; `None` without a trusted bwrap. Ubuntu 22.04 ships
/// 0.6: there the child runs without it, and `cplt doctor` warns.
pub fn bwrap_disables_userns() -> Option<bool> {
    #[cfg(target_os = "linux")]
    let bwrap = crate::sandbox::bubblewrap_probe::check_availability();
    #[cfg(not(target_os = "linux"))]
    let bwrap: Option<PathBuf> = None;
    bwrap.map(|b| disables_userns(&b))
}

#[allow(clippy::disallowed_methods)] // bwrap from the trusted dirs
fn disables_userns(bwrap: &Path) -> bool {
    static ANSWER: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ANSWER.get_or_init(|| {
        Command::new(bwrap)
            .arg("--version")
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .is_some_and(|o| version_has_disable_userns(&String::from_utf8_lossy(&o.stdout)))
    })
}

/// `bubblewrap 0.9.0` and later than 0.8: true. The version is the first
/// word shaped `N.N`, so a distro suffix after it does not count.
fn version_has_disable_userns(out: &str) -> bool {
    let version = out.split_whitespace().find_map(|w| {
        let mut n = w.split('.');
        let major = n.next()?.parse::<u32>().ok()?;
        let minor: String = n.next()?.chars().take_while(char::is_ascii_digit).collect();
        Some((major, minor.parse::<u32>().ok()?))
    });
    version.is_some_and(|v| v >= (0, 8))
}

/// What gets an empty tmpfs in the Linux child: `home`, `config_home` and
/// `data_home` (the dirs `host_env_pairs` hands over), less those under
/// `/tmp`, `/run` or one already in the list.
fn hidden_dirs(home: &Path, config_home: &Path, data_home: Option<&Path>) -> Vec<PathBuf> {
    let mut hide: Vec<PathBuf> = Vec::new();
    for d in [Some(home), Some(config_home), data_home]
        .into_iter()
        .flatten()
    {
        let covered =
            d.starts_with("/tmp") || d.starts_with("/run") || hide.iter().any(|h| d.starts_with(h));
        if !covered {
            hide.push(d.to_path_buf());
        }
    }
    hide
}

/// Where the relay (this binary) appears inside the Linux child.
const CHILD_RELAY_EXE: &str = "/run/cplt-relay";

/// The Nix daemon's socket dirs. Reaching the daemon builds as a trusted
/// user (root on the host) or fetches through fixed-output derivations,
/// past the egress proxy.
const NIX_SOCKET_DIRS: &[&str] = &["/nix/var/nix/daemon-socket", "/nix/var/nix/gc-socket"];

fn child_bwrap_args(m: &ChildMounts) -> Vec<std::ffi::OsString> {
    let ChildMounts {
        hide,
        write_dirs,
        read_paths,
        runtime_dir,
        current_system,
        nix_sockets,
        bus,
        egress_socket,
        relay_exe,
        disable_userns,
    } = *m;
    let mut a: Vec<std::ffi::OsString> = [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--unshare-net",
        "--die-with-parent",
        "--new-session",
        "--ro-bind",
        "/",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    if disable_userns {
        a.push("--disable-userns".into());
    }
    // NixOS: the system profile (and the trusted /run/current-system/sw/bin)
    // is a link into the read-only store; keep it under the private /run.
    if let Some(target) = current_system {
        a.extend([
            "--symlink".into(),
            target.into(),
            "/run/current-system".into(),
        ]);
    }
    if let Some(rt) = runtime_dir.filter(|d| !d.starts_with("/run") && !d.starts_with("/tmp")) {
        a.extend(["--tmpfs".into(), rt.into()]);
    }
    for d in nix_sockets {
        a.extend(["--tmpfs".into(), d.into()]);
    }
    for h in hide {
        a.extend(["--tmpfs".into(), h.into()]);
    }
    let mut bind = |flag: &str, src: &Path, dst: &Path| {
        a.extend([flag.into(), src.into(), dst.into()]);
    };
    for d in write_dirs {
        bind("--bind", d, d);
    }
    for p in read_paths {
        bind("--ro-bind-try", p, p);
    }
    for h in hide {
        // The empty dir itself read-only, as the rest of the root is.
        a.extend(["--remount-ro".into(), h.into()]);
    }
    let mut bind = |flag: &str, src: &Path, dst: &Path| {
        a.extend([flag.into(), src.into(), dst.into()]);
    };
    if let Some(exe) = relay_exe {
        bind("--ro-bind", exe, Path::new(CHILD_RELAY_EXE));
    }
    if let Some(bus) = bus {
        bind("--ro-bind", bus, Path::new(CHILD_BUS_SOCKET));
    }
    if let Some(sock) = egress_socket {
        bind("--ro-bind", sock, Path::new(CHILD_EGRESS_SOCKET));
    }
    a
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
                    Ok(mut p) => {
                        let a = on_server(&line, &spec, &mut p);
                        if let Some(text) = p.1.take() {
                            log.line(&spec.id, &text);
                        }
                        a
                    }
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
            Ok(mut p) => {
                let a = on_client(&line, spec, &mut p);
                if let Some(text) = p.1.take() {
                    shared.log.line(&spec.id, &text);
                }
                a
            }
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

    /// As `tests/common::sandbox_usable`: false where sandbox-exec cannot
    /// apply a profile (inside cplt's own sandbox), unless CI requires it.
    #[cfg(target_os = "macos")]
    #[allow(clippy::disallowed_methods)] // fixed /usr/bin path
    fn sandbox_usable() -> bool {
        let ok = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .output()
            .is_ok_and(|o| o.status.success());
        assert!(
            ok || std::env::var("CPLT_TEST_REQUIRE_SANDBOX").as_deref() != Ok("1"),
            "sandbox required by CPLT_TEST_REQUIRE_SANDBOX but unavailable"
        );
        ok
    }

    #[test]
    fn resolve_existing_prefix_keeps_the_missing_tail() {
        let tmp = std::env::temp_dir();
        let real = tmp.canonicalize().unwrap();
        let p = tmp.join("cplt-849-missing/a/b");
        assert_eq!(
            resolve_existing_prefix(&p),
            real.join("cplt-849-missing/a/b")
        );
        let link = real.join(format!("cplt-849-link-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let got = resolve_existing_prefix(&link.join("nais"));
        let _ = std::fs::remove_file(&link);
        assert_eq!(got, real.join("nais"));
    }

    fn strings(a: Vec<std::ffi::OsString>) -> Vec<String> {
        a.into_iter().map(|a| a.into_string().unwrap()).collect()
    }

    /// #849: the Linux child's namespace. Every namespace, the network one
    /// included; the host root read-only with private /tmp and /run, and
    /// only then the write dirs, the filtered bus and the egress socket, so
    /// no tmpfs hides them.
    #[test]
    fn child_bwrap_args_isolate_the_network_and_bind_only_the_grants() {
        let args = strings(child_bwrap_args(&ChildMounts {
            hide: &[PathBuf::from("/home/u")],
            write_dirs: &[PathBuf::from("/home/u/.config/nais")],
            read_paths: &[PathBuf::from("/home/u/.netrc")],
            relay_exe: Some(Path::new("/home/u/.local/bin/cplt")),
            runtime_dir: Some(Path::new("/run/user/1000")),
            bus: Some(Path::new("/tmp/cplt-mcp-x/b0")),
            egress_socket: Some(Path::new("/tmp/cplt-mcp-x/e0")),
            ..ChildMounts::default()
        }));
        let s = args.join(" ");
        for ns in ["user", "pid", "ipc", "uts", "cgroup", "net"] {
            assert!(args.contains(&format!("--unshare-{ns}")), "{s}");
        }
        assert!(args.contains(&"--die-with-parent".into()), "{s}");
        let tail = "--ro-bind / / --proc /proc --dev /dev --tmpfs /tmp --tmpfs /run \
                    --tmpfs /home/u \
                    --bind /home/u/.config/nais /home/u/.config/nais \
                    --ro-bind-try /home/u/.netrc /home/u/.netrc \
                    --remount-ro /home/u \
                    --ro-bind /home/u/.local/bin/cplt /run/cplt-relay \
                    --ro-bind /tmp/cplt-mcp-x/b0 /run/cplt-bus \
                    --ro-bind /tmp/cplt-mcp-x/e0 /tmp/cplt-egress.sock";
        assert!(s.ends_with(tail), "{s}");
        let writable: Vec<_> = args
            .windows(2)
            .filter(|w| w[0] == "--bind")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(writable, ["/home/u/.config/nais"], "{s}");

        // No egress, no bus: neither socket is bound. A runtime dir outside
        // /run gets its own tmpfs.
        let bare = strings(child_bwrap_args(&ChildMounts {
            runtime_dir: Some(Path::new("/var/rt")),
            ..ChildMounts::default()
        }));
        assert!(bare.contains(&"--unshare-net".into()));
        assert!(
            bare.ends_with(&["--tmpfs".into(), "/var/rt".into()]),
            "{bare:?}"
        );
        assert!(
            !bare
                .iter()
                .any(|a| a == "--bind" || a == CHILD_EGRESS_SOCKET || a == CHILD_BUS_SOCKET)
        );
    }

    /// #849: a keychain server whose host has a session bus but no
    /// xdg-dbus-proxy gets no bus at all, never the host's own.
    #[test]
    fn no_dbus_proxy_no_bus() {
        let b = cat_broker();
        let server = &b.shared.servers["io.github.nais/nais-mcp"];
        assert!(server.spec.credential.keychain);
        let dir = tempfile::tempdir().unwrap();
        let host_bus = dir.path().join("bus");
        let _l = std::os::unix::net::UnixListener::bind(&host_bus).unwrap();
        let addr = format!("unix:path={}", host_bus.display());
        let mut setup = ChildSetup::default();
        let bus = temp_env::with_var("DBUS_SESSION_BUS_ADDRESS", Some(&addr), || {
            child_bus(&b.shared, server, None, None, &mut setup)
        });
        assert_eq!(bus, None);
        assert_eq!(setup.unset, ["DBUS_SESSION_BUS_ADDRESS"]);
        assert!(setup.env.is_empty() && setup.sync.is_none());
        assert!(!server.bus_socket.exists());
        // bwrap then binds no bus socket.
        let s = strings(child_bwrap_args(&ChildMounts {
            bus,
            ..ChildMounts::default()
        }));
        assert!(!s.iter().any(|a| a == CHILD_BUS_SOCKET), "{s:?}");
    }

    #[test]
    fn disable_userns_from_bwrap_0_8() {
        for (out, want) in [
            ("bubblewrap 0.6.1\n", false),
            ("bubblewrap 0.8.0\n", true),
            ("bubblewrap 0.11.0", true),
            ("bubblewrap 1.0", true),
            ("bubblewrap 0.9.0 (distro)", true),
            ("bubblewrap 0.6.1 (Ubuntu 1.2)", false),
            ("", false),
        ] {
            assert_eq!(version_has_disable_userns(out), want, "{out:?}");
        }
        let on = strings(child_bwrap_args(&ChildMounts {
            disable_userns: true,
            ..ChildMounts::default()
        }));
        let at = |a: &[String], f: &str| a.iter().position(|x| x == f);
        // After --unshare-user, which it needs.
        assert!(
            at(&on, "--disable-userns") > at(&on, "--unshare-user"),
            "{on:?}"
        );
        let off = strings(child_bwrap_args(&ChildMounts::default()));
        assert!(at(&off, "--disable-userns").is_none());
    }

    /// NixOS: the daemon's socket dirs get a tmpfs each, so the child
    /// cannot ask the daemon to build (as root) or fetch (past the proxy).
    #[test]
    fn child_bwrap_args_hide_the_nix_daemon() {
        let dirs: Vec<PathBuf> = NIX_SOCKET_DIRS.iter().map(PathBuf::from).collect();
        let s = strings(child_bwrap_args(&ChildMounts {
            nix_sockets: &dirs,
            ..ChildMounts::default()
        }))
        .join(" ");
        assert!(
            s.contains("--tmpfs /nix/var/nix/daemon-socket --tmpfs /nix/var/nix/gc-socket"),
            "{s}"
        );
        // After the root bind, or the root would cover it again.
        assert!(
            s.find("--ro-bind / /") < s.find("--tmpfs /nix/var/nix/daemon-socket"),
            "{s}"
        );
    }

    /// Config and data dirs outside HOME are hidden like HOME, before the
    /// grant in them is bound, and remounted read-only after it.
    #[test]
    fn xdg_dirs_outside_home_are_hidden_too() {
        let h = |c: &str, d: Option<&str>| {
            hidden_dirs(Path::new("/home/u"), Path::new(c), d.map(Path::new))
        };
        assert_eq!(h("/home/u/.config", None), [PathBuf::from("/home/u")]);
        assert_eq!(
            h("/srv/cfg", Some("/srv/data")),
            ["/home/u", "/srv/cfg", "/srv/data"].map(PathBuf::from)
        );
        assert_eq!(h("/tmp/cfg", Some("/run/d")), [PathBuf::from("/home/u")]);
        let hide = h("/srv/cfg", None);
        let s = strings(child_bwrap_args(&ChildMounts {
            hide: &hide,
            write_dirs: &[PathBuf::from("/srv/cfg/nais")],
            ..ChildMounts::default()
        }))
        .join(" ");
        assert!(
            s.contains(
                "--tmpfs /home/u --tmpfs /srv/cfg --bind /srv/cfg/nais /srv/cfg/nais \
                 --remount-ro /home/u --remount-ro /srv/cfg"
            ),
            "{s}"
        );
    }

    /// NixOS: a program under /run/current-system/sw/bin (a trusted dir)
    /// still resolves after the private /run, through the restored link.
    #[test]
    fn child_bwrap_args_keep_nixos_current_system() {
        let store = Path::new("/nix/store/abc-nixos-system");
        let args = strings(child_bwrap_args(&ChildMounts {
            current_system: Some(store),
            ..ChildMounts::default()
        }));
        let s = args.join(" ");
        assert!(
            s.contains("--tmpfs /run --symlink /nix/store/abc-nixos-system /run/current-system"),
            "{s}"
        );
        let program = Path::new("/run/current-system/sw/bin/nais");
        let rest = program.strip_prefix("/run/current-system").unwrap();
        assert_eq!(
            store.join(rest),
            Path::new("/nix/store/abc-nixos-system/sw/bin/nais")
        );
    }

    #[test]
    fn pick_session_bus_takes_an_existing_socket_only() {
        let sock = |p: &Path| p == Path::new("/run/user/1000/bus") || p == Path::new("/x y/bus");
        let rt = Some(Path::new("/run/user/1000"));
        assert_eq!(
            pick_session_bus(Some("unix:path=/run/user/1000/bus,guid=abc"), None, sock),
            Some(PathBuf::from("/run/user/1000/bus"))
        );
        // Escaped, and a later entry when the first is not a socket.
        assert_eq!(
            pick_session_bus(Some("unix:path=/gone;unix:path=/x%20y/bus"), None, sock),
            Some(PathBuf::from("/x y/bus"))
        );
        assert_eq!(
            pick_session_bus(Some("unix:abstract=/tmp/dbus-x"), rt, sock),
            None
        );
        assert_eq!(
            pick_session_bus(Some("tcp:host=localhost,port=1"), rt, sock),
            None
        );
        // Unset: the runtime dir's bus, if it is there.
        assert_eq!(
            pick_session_bus(None, rt, sock),
            Some(PathBuf::from("/run/user/1000/bus"))
        );
        assert_eq!(
            pick_session_bus(None, Some(Path::new("/var/rt")), sock),
            None
        );
        assert_eq!(pick_session_bus(None, None, sock), None);
    }

    #[test]
    fn dbus_path_address_escapes() {
        assert_eq!(
            dbus_path_address(Path::new("/run/user/1000/bus")),
            "unix:path=/run/user/1000/bus"
        );
        assert_eq!(
            dbus_path_address(Path::new("/x y,z")),
            "unix:path=/x%20y%2cz"
        );
    }

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
        // A token across the 512-byte cut must not leak its tail.
        input.push_str(&"y ".repeat(250));
        input.push_str(" ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n");
        input.push_str(&"x \n".repeat(20_000));
        log_stderr(std::io::Cursor::new(input), &log, "t");
        let out = std::fs::read_to_string(&file).unwrap();
        let _ = std::fs::remove_file(&file);
        assert!(
            !out.contains("ghp_") && !out.contains("bbbb") && !out.contains("y y"),
            "{out}"
        );
        assert!(out.contains("[line over 512 bytes dropped]"), "{out}");
        assert!(out.contains("cap reached"));
        assert_eq!(out.lines().count(), STDERR_CAP + 1);
    }

    /// #849 refresh bug: Security.framework rewrites a file keychain in the
    /// caller (temp sibling, then rename). keychain=true must allow it, and
    /// keychain=false is the control. Only an explicit temp keychain is used.
    #[cfg(target_os = "macos")]
    #[test]
    #[allow(clippy::disallowed_methods)] // fixed /usr/bin paths
    fn child_profile_keychain_write_needs_the_keychain_grant() {
        if !sandbox_usable() {
            return;
        }
        let home = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("cplt-849-kc-{}", std::process::id()));
        let dir = home.join("Library/Keychains");
        std::fs::create_dir_all(&dir).unwrap();
        let kc = dir.join("login.keychain-db");
        let kc = kc.to_str().unwrap();
        let sec = |args: &[&str]| Command::new("/usr/bin/security").args(args).output();
        let Ok(made) = sec(&["create-keychain", "-p", "test", kc]) else {
            let _ = std::fs::remove_dir_all(&home);
            return;
        };
        // create-keychain also adds it to the user's search list: remove it
        // (and the files) whatever happens below. A new keychain is unlocked.
        struct Cleanup<'a>(&'a str, &'a Path);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = Command::new("/usr/bin/security")
                    .args(["delete-keychain", self.0])
                    .output();
                let _ = std::fs::remove_dir_all(self.1);
            }
        }
        let _cleanup = Cleanup(kc, &home);
        assert!(made.status.success(), "create-keychain failed");
        let add = |keychain: bool, acct: &str| {
            let profile = crate::sandbox::mcp_child_profile(&home, &[], keychain, None).unwrap();
            Command::new("/usr/bin/sandbox-exec")
                .args(["-p", &profile, "--", "/usr/bin/security"])
                .args([
                    "add-generic-password",
                    "-U",
                    "-a",
                    acct,
                    "-s",
                    "cplt-test",
                    "-w",
                    "x",
                    kc,
                ])
                .env("HOME", &home)
                .output()
                .unwrap()
                .status
                .success()
        };
        let denied = !add(false, "t0");
        let allowed = add(true, "t1");
        assert!(denied, "control: keychain=false still wrote the keychain");
        assert!(allowed, "keychain=true could not write the keychain");
    }

    /// The kernel, not the profile text: the child cannot look up
    /// nsurlsessiond, which would fetch URLs past the egress rule. The
    /// control is the same profile without the deny.
    #[cfg(target_os = "macos")]
    #[test]
    #[allow(clippy::disallowed_methods)] // fixed /usr/bin paths
    fn child_profile_denies_nsurlsessiond_lookup() {
        if !sandbox_usable() {
            return;
        }
        // The real interpreter, not the /usr/bin stub (see below).
        let out = Command::new("/usr/bin/python3")
            .args(["-c", "import sys; print(sys.executable)"])
            .output()
            .unwrap();
        let py_bin = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let probe = "import ctypes,sys;l=ctypes.CDLL('/usr/lib/libSystem.B.dylib');\
            p=ctypes.c_uint();sys.exit(l.bootstrap_look_up(\
            ctypes.c_uint.in_dll(l,'bootstrap_port'),b'com.apple.nsurlsessiond',ctypes.byref(p)) != 0)";
        let home = std::env::temp_dir().canonicalize().unwrap();
        let profile = crate::sandbox::mcp_child_profile(&home, &[], false, None).unwrap();
        let reach = |profile: &str| {
            Command::new("/usr/bin/sandbox-exec")
                .args(["-p", profile, "--", &py_bin, "-I", "-c", probe])
                .status()
                .unwrap()
                .success()
        };
        let control = profile.replace(
            r#"(deny mach-lookup (global-name "com.apple.nsurlsessiond"))"#,
            "",
        );
        assert!(reach(&control), "control: nsurlsessiond unreachable");
        assert!(!reach(&profile), "child looked up nsurlsessiond");
    }

    /// The kernel, not the profile text: inside the child profile a TCP
    /// connect reaches only the egress port, not another local port and not
    /// a remote host.
    #[cfg(target_os = "macos")]
    #[test]
    #[allow(clippy::disallowed_methods)] // fixed /usr/bin paths
    fn child_profile_allows_only_the_egress_port() {
        if !sandbox_usable() {
            return;
        }
        let allowed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = |l: &std::net::TcpListener| l.local_addr().unwrap().port();
        let home = std::env::temp_dir().canonicalize().unwrap();
        // Written with the /var spelling: child_command canonicalizes, so
        // the test must too, or a /private/var mismatch would pass silently.
        let wdir = home.join(format!("cplt-849-wd-{}", std::process::id()));
        std::fs::create_dir_all(&wdir).unwrap();
        let profile = crate::sandbox::mcp_child_profile(
            &home,
            &[wdir.canonicalize().unwrap()],
            false,
            Some(port(&allowed)),
        )
        .unwrap();
        let run = |args: &[&str]| {
            Command::new("/usr/bin/sandbox-exec")
                .args(["-p", &profile, "--"])
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        };
        let nc = |host: &str, p: u16| run(&["/usr/bin/nc", "-z", "-G", "2", host, &p.to_string()]);
        assert!(nc("127.0.0.1", port(&allowed)), "egress port refused");
        assert!(!nc("127.0.0.1", port(&other)), "another local port reached");
        assert!(!nc("1.1.1.1", 443), "a remote host reached");
        // A unix socket under ~/.gradle (a daemon's) and a listener: denied.
        // `home` is the profile's HOME, so this is the path the agent
        // profile's Gradle rule would have opened.
        let sock_dir = home.join(".gradle");
        std::fs::create_dir_all(&sock_dir).unwrap();
        let sock = sock_dir.join(format!("cplt-849-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        // The real interpreter, not the /usr/bin stub, which runs xcodebuild
        // and fails inside a sandbox on CI runners (as in tests/mcp_broker.rs).
        let out = Command::new("/usr/bin/python3")
            .args(["-c", "import sys; print(sys.executable)"])
            .output()
            .unwrap();
        let py_bin = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let py_bin = py_bin.as_str();
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let s = format!(
            "import socket;socket.socket(socket.AF_UNIX).connect({:?})",
            sock.display().to_string()
        );
        let host = |a: &[&str]| Command::new(a[0]).args(&a[1..]).status().unwrap().success();
        assert!(
            host(&[py_bin, "-c", &s]),
            "control: socket unreachable on the host"
        );
        assert!(!run(&[py_bin, "-c", &s]), "reached a ~/.gradle socket");
        drop(listener);
        let _ = std::fs::remove_file(&sock);
        let py = "import socket;s=socket.socket();s.bind(('127.0.0.1',0));s.listen()";
        assert!(host(&[py_bin, "-c", py]), "control: bind fails on the host");
        assert!(!run(&[py_bin, "-c", py]), "bound a listener");
        // Writes: inside a write_dir yes, elsewhere no.
        let inside = wdir.join("ok");
        assert!(
            run(&["/usr/bin/touch", &inside.display().to_string()]),
            "write_dir not writable"
        );
        let _ = std::fs::remove_dir_all(&wdir);
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
            assert!(to_terminal(
                level,
                "egress → connect failed example.com (timed out)"
            ));
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

    /// #849: a keychain server's bus is xdg-dbus-proxy, filtered to the
    /// Secret Service. Runs where the host has a session bus, dbus-send and
    /// xdg-dbus-proxy (CI: the mcp-broker-e2e job, under dbus-run-session).
    #[test]
    #[cfg(target_os = "linux")]
    #[allow(clippy::disallowed_methods)] // /bin/sh, absolute
    fn keychain_child_reaches_only_the_secret_service() {
        let required = std::env::var("CPLT_TEST_REQUIRE_SESSION_BUS").as_deref() == Ok("1");
        let addr = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
        let rt = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        let ready = pick_session_bus(addr.as_deref(), rt.as_deref(), is_socket).is_some()
            && crate::git::trusted_binary("xdg-dbus-proxy").is_some()
            && crate::git::trusted_binary("dbus-send").is_some();
        assert!(
            ready || !required,
            "no session bus, xdg-dbus-proxy or dbus-send"
        );
        if !ready {
            return;
        }
        let send = "dbus-send --session --print-reply";
        let ping = "/ org.freedesktop.DBus.Peer.Ping";
        let start = "--dest=org.freedesktop.DBus / org.freedesktop.DBus.StartServiceByName \
                     string:org.freedesktop.systemd1 uint32:0";
        // The proxy refuses with a bare error name; the real bus answers
        // for itself (no service file, or a failed activation on a host
        // that can activate systemd). The host's own answer is the control.
        let refused = "ServiceUnknown: org.freedesktop.DBus.Error.ServiceUnknown";
        let host = Command::new("/bin/sh")
            .args([
                "-c",
                &format!("{send} --dest=org.freedesktop.systemd1 {ping} 2>&1"),
            ])
            .output()
            .unwrap();
        let host = String::from_utf8_lossy(&host.stdout);
        assert!(
            host.starts_with("Error ") && !host.contains(refused),
            "control: {host}"
        );
        let q = |cmd: &str| format!(r#"$({cmd} 2>&1 | tr -d '"\\\n')"#);
        let b = sh_broker(&format!(
            r#"read l; printf '{{"jsonrpc":"2.0","id":1,"result":{{"addr":"%s","secrets":"%s","systemd":"%s","start":"%s"}}}}\n' "$DBUS_SESSION_BUS_ADDRESS" "{}" "{}" "{}"; cat >/dev/null"#,
            q(&format!("{send} --dest=org.freedesktop.secrets {ping}")),
            q(&format!("{send} --dest=org.freedesktop.systemd1 {ping}")),
            q(&format!("{send} {start}")),
        ));
        let (mut a, mut ra) = connect(&b);
        writeln!(a, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
        let mut l = String::new();
        ra.read_line(&mut l).unwrap();
        let v: Value = serde_json::from_str(&l).unwrap_or_else(|e| panic!("{e}: {l}"));
        let r = &v["result"];
        assert_eq!(r["addr"], "unix:path=/run/cplt-bus", "{l}");
        // The Secret Service request reaches the real bus.
        let secrets = r["secrets"].as_str().unwrap();
        assert!(!secrets.contains(refused), "{l}");
        // systemd and activation of anything else are refused by the proxy.
        for k in ["systemd", "start"] {
            let got = r[k].as_str().unwrap();
            assert!(got.contains(refused), "{k}: {l}");
        }
        // The proxy lives as long as the child.
        let bus = b.shared.servers["io.github.nais/nais-mcp"]
            .bus_socket
            .clone();
        assert!(UnixStream::connect(&bus).is_ok(), "proxy not up");
        drop((a, ra));
        wait_free(&b);
        let start = Instant::now();
        while UnixStream::connect(&bus).is_ok() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "proxy outlived the child"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
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
