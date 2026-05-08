//! HTTP CONNECT proxy with domain filtering.
//!
//! Intercepts outbound HTTPS connections from the sandboxed agent,
//! enforcing blocked/allowed domain lists and private IP restrictions.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::ui;

/// Controls how much the proxy logs to stderr.
/// The audit log file (if configured) always records everything regardless of this level.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyLogLevel {
    /// No proxy output to stderr (default).
    #[default]
    None,
    /// Only log errors (DNS failures, connect failures, internal errors).
    Error,
    /// Log errors and blocked connections.
    Blocked,
    /// Log everything including successful connections.
    All,
}

impl ProxyLogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Error => "error",
            Self::Blocked => "blocked",
            Self::All => "all",
        }
    }

    /// Whether this status should be logged at the given level.
    fn should_log(self, status: &str) -> bool {
        match self {
            Self::None => false,
            Self::Error => is_error_status(status),
            Self::Blocked => is_error_status(status) || is_blocked_status(status),
            Self::All => true,
        }
    }
}

impl std::str::FromStr for ProxyLogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" | "off" => Ok(Self::None),
            "error" | "errors" => Ok(Self::Error),
            "blocked" => Ok(Self::Blocked),
            "all" | "verbose" => Ok(Self::All),
            _ => Err(format!(
                "invalid proxy log level '{s}': expected none, error, blocked, or all"
            )),
        }
    }
}

fn is_error_status(status: &str) -> bool {
    status.starts_with("DNS-FAIL")
        || status.starts_with("CONNECT-FAIL")
        || status.starts_with("FAIL")
        || status == "LIMIT"
}

fn is_blocked_status(status: &str) -> bool {
    status.starts_with("BLOCKED")
}

const MAX_CONNECTIONS: usize = 64;
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How often file-backed domain lists are re-read from disk.
/// Within the TTL window, cached values are returned without I/O.
const RELOAD_TTL: Duration = Duration::from_secs(5);

/// Cached domain list with TTL-based refresh.
struct DomainCache {
    domains: Vec<String>,
    /// When the last reload attempt was made (success or failure).
    /// Used for TTL backoff on both success and error paths.
    last_attempt: Instant,
}

impl DomainCache {
    fn new(domains: Vec<String>) -> Self {
        Self {
            domains,
            last_attempt: Instant::now(),
        }
    }

    fn is_stale(&self) -> bool {
        self.last_attempt.elapsed() >= RELOAD_TTL
    }
}

/// Shared proxy state holding cached domain lists and config paths.
/// Wrapped in `Arc` and shared across connection threads.
pub struct ProxyState {
    // Blocklist: file of domains to block
    blocked_file: PathBuf,
    blocked_cache: Mutex<DomainCache>,

    // Allowlist: optional file of permitted domains (fail-closed when configured)
    allowed_domains_file: Option<PathBuf>,
    allowlist_cache: Mutex<DomainCache>,

    // Private domains: merged from immutable CLI args + dynamic TOML config
    cli_private_domains: Vec<String>,
    config_file: Option<PathBuf>,
    private_domains_cache: Mutex<DomainCache>,

    // Ports: frozen at startup (kernel Seatbelt profile is immutable)
    allowed_ports: Vec<u16>,

    // Audit log
    log_file: Option<PathBuf>,
    // Verbosity level for stderr output
    log_level: ProxyLogLevel,
}

impl ProxyState {
    /// Get the current blocklist, re-reading from disk if TTL expired.
    /// On read failure, keeps last-good list and resets TTL for retry.
    fn get_blocked_domains(&self) -> Vec<String> {
        get_cached_domains(
            &self.blocked_cache,
            Some(&self.blocked_file),
            parse_lines_file,
        )
    }

    /// Get the allowlist, re-reading from disk if TTL expired.
    /// Returns empty Vec when no allowlist file is configured (allow-all mode).
    fn get_allowed_domains(&self) -> Vec<String> {
        match self.allowed_domains_file.as_deref() {
            Some(path) => get_cached_domains(&self.allowlist_cache, Some(path), parse_lines_file),
            None => Vec::new(),
        }
    }

    /// Get private domains: union of immutable CLI entries + dynamic config entries.
    fn get_private_domains(&self) -> Vec<String> {
        let config_domains = get_cached_domains(
            &self.private_domains_cache,
            self.config_file.as_deref(),
            parse_private_domains_from_toml,
        );

        if self.cli_private_domains.is_empty() {
            return config_domains;
        }
        if config_domains.is_empty() {
            return self.cli_private_domains.clone();
        }

        // Merge CLI + config, deduplicate
        let mut merged = self.cli_private_domains.clone();
        merged.extend(config_domains);
        merged.sort_unstable();
        merged.dedup();
        merged
    }
}

/// Read cached domains, refreshing from disk if TTL has expired.
/// On read failure: keeps the last-good list, resets TTL for backoff retry.
fn get_cached_domains(
    cache: &Mutex<DomainCache>,
    path: Option<&Path>,
    parser: fn(&Path) -> Option<Vec<String>>,
) -> Vec<String> {
    let mut guard = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    if !guard.is_stale() {
        return guard.domains.clone();
    }

    // TTL expired — attempt reload
    if let Some(path) = path
        && let Some(new_domains) = parser(path)
    {
        guard.domains = new_domains;
    }
    // On failure: keep last-good domains (fail-safe)
    guard.last_attempt = Instant::now();
    guard.domains.clone()
}

/// Parse a one-domain-per-line file (blocklist or allowlist format).
/// Returns None on read failure (caller keeps last-good).
fn parse_lines_file(path: &Path) -> Option<Vec<String>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.kind() == std::io::ErrorKind::NotADirectory =>
        {
            // File doesn't exist or path component is not a directory — silent.
            return None;
        }
        Err(e) => {
            eprintln!(
                "{}[proxy]{} Warning: cannot read {}: {e}",
                ui::color(ui::YELLOW),
                ui::color(ui::RESET),
                path.display()
            );
            return None;
        }
    };
    Some(
        contents
            .lines()
            .map(|l| l.trim().to_lowercase().trim_end_matches('.').to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect(),
    )
}

/// Parse `proxy.allow_private_domains` from a TOML config file.
/// Returns None on read/parse failure (caller keeps last-good).
fn parse_private_domains_from_toml(path: &Path) -> Option<Vec<String>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{}[proxy]{} Warning: cannot read config {}: {e}",
                ui::color(ui::YELLOW),
                ui::color(ui::RESET),
                path.display()
            );
            return None;
        }
    };

    // Minimal TOML parsing: find [proxy] section, extract allow_private_domains array.
    // We avoid pulling in the full toml crate dependency here by doing line-based parsing.
    let mut in_proxy_section = false;
    let mut domains: Vec<String> = Vec::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_proxy_section = trimmed == "[proxy]";
            continue;
        }
        if !in_proxy_section {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("allow_private_domains") {
            let value = value.trim_start().strip_prefix('=')?;
            let value = value.trim();
            // Parse simple TOML array: ["foo.com", "bar.com"]
            if let Some(inner) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
                for entry in inner.split(',') {
                    let entry = entry.trim().trim_matches('"').trim_matches('\'');
                    let normalized = entry.to_lowercase().trim_end_matches('.').to_string();
                    if !normalized.is_empty() {
                        domains.push(normalized);
                    }
                }
            }
            break;
        }
    }
    Some(domains)
}

pub struct ProxyHandle {
    shutdown_flag: Arc<std::sync::atomic::AtomicBool>,
    /// Actual port the proxy is listening on. With a configured port of 0,
    /// the OS assigns an ephemeral port; this field reflects the real value.
    pub port: u16,
}

impl ProxyHandle {
    pub fn shutdown(&self) {
        self.shutdown_flag
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Accept loop is non-blocking with 50ms sleep, so it will notice
        // the flag within ~50ms without needing a wake-up connection.
    }
}

/// Bundled proxy startup options.
pub struct ProxyOptions {
    pub port: u16,
    pub blocked_file: PathBuf,
    pub allowed_ports: Vec<u16>,
    /// Path to an allowlist file (one domain per line). When set, only
    /// matching domains pass. The file is re-read every RELOAD_TTL seconds.
    pub allowed_domains_file: Option<PathBuf>,
    /// Initial allowed domains from CLI/config (used for startup validation).
    /// After startup, the file is the source of truth for dynamic reload.
    pub allowed_domains_initial: Vec<String>,
    /// Domains allowed to resolve to private IPs — CLI portion (immutable).
    pub cli_private_domains: Vec<String>,
    /// Domains allowed to resolve to private IPs — config portion (initial).
    pub config_private_domains: Vec<String>,
    /// Path to TOML config file for dynamic reload of private_domains.
    pub config_file: Option<PathBuf>,
    /// Path to append audit log lines. None = no file logging.
    pub log_file: Option<PathBuf>,
    /// Verbosity level for proxy stderr output.
    pub log_level: ProxyLogLevel,
}

/// Start the proxy on a background thread. Returns a handle for shutdown.
///
/// `allowed_ports` controls which remote ports CONNECT tunnels can reach.
/// Port 443 is always allowed. Additional ports come from `--allow-port`.
pub fn start(opts: ProxyOptions) -> Result<ProxyHandle, String> {
    let mut ports: Vec<u16> = vec![443];
    ports.extend_from_slice(&opts.allowed_ports);
    ports.sort_unstable();
    ports.dedup();

    let addr = format!("127.0.0.1:{}", opts.port);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("Cannot bind to {addr}: {e}"))?;
    let actual_port = listener
        .local_addr()
        .map_err(|e| format!("Cannot get proxy listen address: {e}"))?
        .port();

    // Validate blocklist is readable at startup (fail-fast, not fail-open)
    let blocked_initial = if opts.blocked_file.exists() {
        parse_lines_file(&opts.blocked_file).ok_or_else(|| {
            format!(
                "Cannot read blocked domains file {}",
                opts.blocked_file.display()
            )
        })?
    } else {
        Vec::new()
    };

    // Validate allowlist at startup (fail-closed: abort if configured but unreadable)
    let allowlist_initial = if let Some(ref path) = opts.allowed_domains_file {
        if path.exists() {
            parse_lines_file(path)
                .ok_or_else(|| format!("Cannot read allowed domains file {}", path.display()))?
        } else if !opts.allowed_domains_initial.is_empty() {
            // File doesn't exist yet but we have initial domains from config
            opts.allowed_domains_initial.clone()
        } else {
            // No file and no initial domains — this is fine (no allowlist)
            Vec::new()
        }
    } else {
        opts.allowed_domains_initial.clone()
    };

    // Validate log file is writable at startup
    if let Some(ref log_path) = opts.log_file {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .map_err(|e| format!("Cannot open proxy log file {}: {e}", log_path.display()))?;
    }

    // Build shared state with initial caches
    let state = Arc::new(ProxyState {
        blocked_file: opts.blocked_file,
        blocked_cache: Mutex::new(DomainCache::new(blocked_initial)),
        allowed_domains_file: opts.allowed_domains_file,
        allowlist_cache: Mutex::new(DomainCache::new(allowlist_initial)),
        cli_private_domains: opts.cli_private_domains,
        config_file: opts.config_file,
        private_domains_cache: Mutex::new(DomainCache::new(opts.config_private_domains)),
        allowed_ports: ports,
        log_file: opts.log_file,
        log_level: opts.log_level,
    });

    listener
        .set_nonblocking(false)
        .map_err(|e| format!("set_nonblocking: {e}"))?;

    let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = shutdown_flag.clone();
    let active_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    std::thread::Builder::new()
        .name("proxy-accept".into())
        .spawn(move || {
            accept_loop(listener, flag, state, active_count);
        })
        .map_err(|e| format!("spawn proxy thread: {e}"))?;

    std::thread::sleep(Duration::from_millis(50));

    Ok(ProxyHandle {
        shutdown_flag,
        port: actual_port,
    })
}

fn accept_loop(
    listener: TcpListener,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    state: Arc<ProxyState>,
    active_count: Arc<std::sync::atomic::AtomicUsize>,
) {
    // Non-blocking accept with periodic shutdown check
    listener.set_nonblocking(true).ok();

    loop {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }

        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(_) => continue,
        };

        // Ensure accepted socket is blocking (listener is non-blocking for
        // shutdown checks, but connection handlers need blocking I/O).
        stream.set_nonblocking(false).ok();
        stream.set_nodelay(true).ok();

        // Connection limit
        let count = active_count.load(std::sync::atomic::Ordering::SeqCst);
        if count >= MAX_CONNECTIONS {
            log_connection(
                "REJECT",
                "connection limit",
                "LIMIT",
                state.log_file.as_deref(),
                state.log_level,
            );
            drop(stream);
            continue;
        }

        active_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let conn_state = state.clone();
        let counter = active_count.clone();

        if let Err(e) = std::thread::Builder::new()
            .name("proxy-conn".into())
            .spawn(move || {
                handle_connection(stream, &conn_state);
                counter.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            })
        {
            active_count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            log_connection(
                "INTERNAL",
                "thread-spawn",
                &format!("FAIL:{e}"),
                state.log_file.as_deref(),
                state.log_level,
            );
        }
    }
}

fn handle_connection(mut client: TcpStream, state: &ProxyState) {
    client.set_read_timeout(Some(READ_TIMEOUT)).ok();
    client.set_write_timeout(Some(READ_TIMEOUT)).ok();

    // Read the request line
    let mut buf = [0u8; 8192];
    let n = match client.read(&mut buf) {
        Ok(0) => return,
        Ok(n) => n,
        Err(_) => return,
    };

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");

    // Parse method and target
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }

    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(client, target, state);
    } else {
        // For non-CONNECT, send a simple error — the sandbox should force
        // CONNECT via proxy env vars for HTTPS traffic
        log_connection(
            method,
            target,
            "UNSUPPORTED",
            state.log_file.as_deref(),
            state.log_level,
        );
        let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n");
    }
}

fn handle_connect(mut client: TcpStream, target: &str, state: &ProxyState) {
    // Parse host:port
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
        None => (target.to_string(), 443),
    };

    // Normalize hostname: lowercase, strip trailing dot (valid DNS but
    // would bypass exact-match rules otherwise).
    let host = normalize_hostname(&host);
    let log_file = state.log_file.as_deref();
    let log_level = state.log_level;

    // Enforce port policy — only allow ports matching the sandbox network rules.
    // Without this, the proxy would let sandboxed processes tunnel to arbitrary
    // remote ports, bypassing the sandbox's port restrictions.
    if !state.allowed_ports.contains(&port) {
        log_connection("CONNECT", target, "BLOCKED-PORT", log_file, log_level);
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nPort not allowed\r\n");
        return;
    }

    // Enforce domain allowlist — when configured, only listed domains pass.
    // Fail-closed: if the allowlist is non-empty and the domain isn't in it, deny.
    let allowed_domains = state.get_allowed_domains();
    if !allowed_domains.is_empty() && !is_domain_match(&host, &allowed_domains) {
        log_connection("CONNECT", target, "BLOCKED-ALLOWLIST", log_file, log_level);
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nDomain not in allowlist\r\n");
        return;
    }

    // Check blocklist (hostname-level)
    let blocked_domains = state.get_blocked_domains();
    if is_blocked_in_list(&host, &blocked_domains) {
        log_connection("CONNECT", target, "BLOCKED", log_file, log_level);
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by cplt\r\n");
        return;
    }

    // Reject hostname patterns that are known private (fast path before DNS)
    if is_private_hostname(&host) {
        log_connection("CONNECT", target, "BLOCKED-PRIVATE", log_file, log_level);
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nPrivate target blocked\r\n");
        return;
    }

    // Resolve DNS FIRST, then check the resolved IP
    let addr = format!("{host}:{port}");
    let socket_addr = if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(a) = addrs.next() {
            a
        } else {
            log_connection("CONNECT", target, "DNS-FAIL", log_file, log_level);
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return;
        }
    } else {
        log_connection("CONNECT", target, "DNS-FAIL", log_file, log_level);
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        return;
    };

    // Check the RESOLVED IP address (prevents DNS rebinding attacks).
    // Domains in allow_private_domains are explicitly trusted to resolve to private IPs
    // (e.g. corporate internal services). All other checks still apply.
    let private_domains = state.get_private_domains();
    if is_private_ip(&socket_addr.ip()) && !is_domain_match(&host, &private_domains) {
        log_connection(
            "CONNECT",
            target,
            "BLOCKED-PRIVATE-RESOLVED",
            log_file,
            log_level,
        );
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nResolved to private IP\r\n");
        return;
    }

    // Connect to resolved address (not re-resolving)
    let remote = match TcpStream::connect_timeout(&socket_addr, CONNECT_TIMEOUT) {
        Ok(s) => {
            s.set_nodelay(true).ok();
            s
        }
        Err(e) => {
            log_connection(
                "CONNECT",
                target,
                &format!("CONNECT-FAIL:{e}"),
                log_file,
                log_level,
            );
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return;
        }
    };

    // Log after TCP connect succeeds — this is the audit-relevant event.
    log_connection("CONNECT", target, "CONNECTED", log_file, log_level);

    // Send 200 to client
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }

    // Bidirectional relay
    relay(client, remote);
}

fn relay(client: TcpStream, remote: TcpStream) {
    let Ok(mut client_read) = client.try_clone() else {
        return;
    };
    let Ok(mut remote_write) = remote.try_clone() else {
        return;
    };
    let mut remote_read = remote;
    let mut client_write = client;

    // Set timeouts for relay
    client_read.set_read_timeout(Some(READ_TIMEOUT)).ok();
    remote_read.set_read_timeout(Some(READ_TIMEOUT)).ok();

    // Use Write shutdown (TCP half-close) so the other direction can
    // finish delivering in-flight data. shutdown(Both) would kill the
    // read half of the shared socket, breaking the other relay thread.
    let t1 = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match client_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if remote_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        remote_write.shutdown(std::net::Shutdown::Write).ok();
    });

    let t2 = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match remote_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if client_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        client_write.shutdown(std::net::Shutdown::Write).ok();
    });

    t1.join().ok();
    t2.join().ok();
}

/// Check if a hostname matches any entry in a pre-parsed blocklist.
fn is_blocked_in_list(hostname: &str, blocked_domains: &[String]) -> bool {
    let host = normalize_hostname(hostname);
    for pattern in blocked_domains {
        if host == *pattern || host.ends_with(&format!(".{pattern}")) {
            return true;
        }
    }
    false
}

pub fn is_blocked(hostname: &str, blocked_file: &PathBuf) -> bool {
    if !blocked_file.exists() {
        return false;
    }
    let contents = match std::fs::read_to_string(blocked_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{}[proxy]{} Warning: cannot read blocklist {}: {e}",
                ui::color(ui::YELLOW),
                ui::color(ui::RESET),
                blocked_file.display()
            );
            return false;
        }
    };
    is_blocked_in_content(hostname, &contents)
}

pub fn is_blocked_in_content(hostname: &str, contents: &str) -> bool {
    let host = normalize_hostname(hostname);
    for line in contents.lines() {
        let pattern = line.trim().to_lowercase();
        if pattern.is_empty() || pattern.starts_with('#') {
            continue;
        }
        let pattern = pattern.trim_end_matches('.');
        if host == pattern || host.ends_with(&format!(".{pattern}")) {
            return true;
        }
    }
    false
}

/// Normalize a hostname for consistent matching: lowercase, strip trailing dot.
fn normalize_hostname(host: &str) -> String {
    host.to_lowercase().trim_end_matches('.').to_string()
}

/// Check if a hostname matches any entry in a domain list.
/// Matching is exact or subdomain: `example.com` matches `example.com`
/// and `sub.example.com`. Case-insensitive, trailing dots stripped.
pub fn is_domain_match(hostname: &str, domains: &[String]) -> bool {
    let host = normalize_hostname(hostname);
    for pattern in domains {
        if host == *pattern || host.ends_with(&format!(".{pattern}")) {
            return true;
        }
    }
    false
}

/// Parse a domain list file into normalized entries.
/// Returns an error if the file cannot be read (fail-closed for allowlists).
pub fn parse_domain_file(path: &std::path::Path) -> Result<Vec<String>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read domain file {}: {e}", path.display()))?;
    Ok(contents
        .lines()
        .map(|l| l.trim().to_lowercase().trim_end_matches('.').to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

/// Check if a resolved IP address is private/reserved (post-DNS resolution).
/// This is the primary defense against DNS rebinding attacks.
pub fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()                // 127.0.0.0/8
                || v4.is_private()           // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()        // 169.254.0.0/16
                || v4.is_unspecified()       // 0.0.0.0
                || v4.is_broadcast()         // 255.255.255.255
                || is_cgnat(v4)              // 100.64.0.0/10 (Tailscale, VPN)
                || is_benchmarking(v4)       // 198.18.0.0/15
                || is_reserved_v4(v4)        // 240.0.0.0/4
                || is_protocol_assign(v4) // 192.0.0.0/24
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()                 // ::1
                || v6.is_unspecified()       // ::
                || is_ula(v6)                // fc00::/7 (private v6)
                || is_link_local_v6(v6)      // fe80::/10
                || is_v4_mapped_private(v6) // ::ffff:127.0.0.1 etc.
        }
    }
}

/// Check hostname patterns that are known to be private (pre-DNS fast path).
pub fn is_private_hostname(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    // Check if it's an IP literal first
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return is_private_ip(&ip);
    }
    h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local")
}

// CGNAT range (RFC 6598) — used by Tailscale, WireGuard, carrier NAT
fn is_cgnat(ip: &std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64 // 100.64.0.0/10
}

// Benchmarking range (RFC 2544)
fn is_benchmarking(ip: &std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] & 0xFE) == 18 // 198.18.0.0/15
}

// Reserved/future use (RFC 1112)
fn is_reserved_v4(ip: &std::net::Ipv4Addr) -> bool {
    ip.octets()[0] >= 240 // 240.0.0.0/4
}

// IETF protocol assignments (RFC 6890)
fn is_protocol_assign(ip: &std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 192 && o[1] == 0 && o[2] == 0 // 192.0.0.0/24
}

// IPv6 Unique Local Address (RFC 4193)
fn is_ula(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xFE00) == 0xFC00 // fc00::/7
}

// IPv6 link-local (RFC 4291)
fn is_link_local_v6(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xFFC0) == 0xFE80 // fe80::/10
}

// IPv4-mapped IPv6 addresses with private IPv4
fn is_v4_mapped_private(ip: &std::net::Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        v4.is_loopback()
            || v4.is_private()
            || v4.is_link_local()
            || v4.is_unspecified()
            || is_cgnat(&v4)
    } else {
        false
    }
}

fn log_connection(
    method: &str,
    target: &str,
    status: &str,
    log_file: Option<&Path>,
    level: ProxyLogLevel,
) {
    if level.should_log(status) {
        let color = match status {
            "BLOCKED" | "BLOCKED-PRIVATE" | "BLOCKED-PORT" | "BLOCKED-ALLOWLIST" | "LIMIT" => {
                ui::color(ui::RED)
            }
            "CONNECTED" => ui::color(ui::GREEN),
            _ => ui::color(ui::YELLOW),
        };
        let timestamp = chrono_now();
        eprintln!(
            "{color}[proxy]{} {timestamp} {method} {target} → {status}",
            ui::color(ui::RESET)
        );
    }

    // Append to audit log file (reopen per-write for rotation compatibility)
    if let Some(path) = log_file
        && let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        let iso = iso_now();
        let _ = writeln!(f, "{iso} {method} {target} {status}");
    }
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{hours:02}:{mins:02}:{s:02}")
}

fn iso_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let days = secs / 86400;
    let rem = secs % 86400;
    // Approximate date calculation (sufficient for log timestamps)
    let (y, m, d) = days_to_ymd(days);
    let h = rem / 3600;
    let mi = (rem % 3600) / 60;
    let s = rem % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil calendar from day count (algorithm from Howard Hinnant)
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y } as u64;
    (y, m, d)
}

use std::net::ToSocketAddrs;

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a unique temp directory for test isolation.
    fn test_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cplt-test-proxy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn domain_cache_returns_cached_within_ttl() {
        let cache = Mutex::new(DomainCache::new(vec!["example.com".to_string()]));
        let result = get_cached_domains(&cache, None, |_| panic!("should not call parser"));
        assert_eq!(result, vec!["example.com"]);
    }

    #[test]
    fn domain_cache_reloads_after_ttl() {
        let dir = test_dir("reload");
        let path = dir.join("domains.txt");
        std::fs::write(&path, "old.com\n").unwrap();

        let cache = Mutex::new(DomainCache {
            domains: vec!["old.com".to_string()],
            last_attempt: Instant::now()
                .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                .unwrap(),
        });

        let result = get_cached_domains(&cache, Some(&path), parse_lines_file);
        assert_eq!(result, vec!["old.com"]);

        // Modify file and force stale
        std::fs::write(&path, "new.com\n").unwrap();
        cache.lock().unwrap().last_attempt = Instant::now()
            .checked_sub(RELOAD_TTL + Duration::from_millis(100))
            .unwrap();

        let result = get_cached_domains(&cache, Some(&path), parse_lines_file);
        assert_eq!(result, vec!["new.com"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn domain_cache_keeps_last_good_on_failure() {
        let cache = Mutex::new(DomainCache {
            domains: vec!["good.com".to_string()],
            last_attempt: Instant::now()
                .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                .unwrap(),
        });

        let bad_path = Path::new("/tmp/nonexistent-cplt-test-file-xyz.txt");
        let result = get_cached_domains(&cache, Some(bad_path), parse_lines_file);
        assert_eq!(
            result,
            vec!["good.com"],
            "should keep last-good list on failure"
        );
    }

    #[test]
    fn domain_cache_resets_ttl_after_failure() {
        let cache = Mutex::new(DomainCache {
            domains: vec!["good.com".to_string()],
            last_attempt: Instant::now()
                .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                .unwrap(),
        });

        let bad_path = Path::new("/tmp/nonexistent-cplt-test-file-xyz.txt");
        let _ = get_cached_domains(&cache, Some(bad_path), parse_lines_file);

        let guard = cache.lock().unwrap();
        assert!(!guard.is_stale(), "TTL should be reset after failed reload");
    }

    #[test]
    fn parse_lines_file_skips_comments_and_empty() {
        let dir = test_dir("parse-lines");
        let path = dir.join("test.txt");
        std::fs::write(&path, "# comment\n\nexample.com\n  MIXED.Case.  \n").unwrap();

        let result = parse_lines_file(&path).unwrap();
        assert_eq!(result, vec!["example.com", "mixed.case"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_private_domains_from_toml_extracts_correctly() {
        let dir = test_dir("toml-extract");
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "[sandbox]\nquiet = true\n\n[proxy]\nallow_private_domains = [\"intern.nav.no\", \"dev.CORP.example.com\"]\nport = 8080\n\n[allow]\nports = [443]\n",
        )
        .unwrap();

        let result = parse_private_domains_from_toml(&path).unwrap();
        assert_eq!(result, vec!["intern.nav.no", "dev.corp.example.com"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_private_domains_from_toml_empty_section() {
        let dir = test_dir("toml-empty");
        let path = dir.join("config.toml");
        std::fs::write(&path, "[proxy]\nport = 8080\n").unwrap();

        let result = parse_private_domains_from_toml(&path).unwrap();
        assert!(result.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_private_domains_from_toml_no_proxy_section() {
        let dir = test_dir("toml-noproxy");
        let path = dir.join("config.toml");
        std::fs::write(&path, "[sandbox]\nquiet = true\n").unwrap();

        let result = parse_private_domains_from_toml(&path).unwrap();
        assert!(result.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_state_merges_cli_and_config_private_domains() {
        let state = ProxyState {
            blocked_file: PathBuf::from("/dev/null"),
            blocked_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_domains_file: None,
            allowlist_cache: Mutex::new(DomainCache::new(Vec::new())),
            cli_private_domains: vec!["cli.example.com".to_string()],
            config_file: None,
            private_domains_cache: Mutex::new(DomainCache::new(vec![
                "config.example.com".to_string(),
            ])),
            allowed_ports: vec![443],
            log_file: None,
            log_level: ProxyLogLevel::None,
        };

        let domains = state.get_private_domains();
        assert!(domains.contains(&"cli.example.com".to_string()));
        assert!(domains.contains(&"config.example.com".to_string()));
    }

    #[test]
    fn proxy_state_private_domains_deduplicates() {
        let state = ProxyState {
            blocked_file: PathBuf::from("/dev/null"),
            blocked_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_domains_file: None,
            allowlist_cache: Mutex::new(DomainCache::new(Vec::new())),
            cli_private_domains: vec!["shared.com".to_string()],
            config_file: None,
            private_domains_cache: Mutex::new(DomainCache::new(vec!["shared.com".to_string()])),
            allowed_ports: vec![443],
            log_file: None,
            log_level: ProxyLogLevel::None,
        };

        let domains = state.get_private_domains();
        assert_eq!(
            domains.iter().filter(|d| *d == "shared.com").count(),
            1,
            "duplicates should be removed"
        );
    }

    #[test]
    fn proxy_state_allowlist_empty_when_no_file() {
        let state = ProxyState {
            blocked_file: PathBuf::from("/dev/null"),
            blocked_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_domains_file: None,
            allowlist_cache: Mutex::new(DomainCache::new(vec![
                "should-not-appear.com".to_string(),
            ])),
            cli_private_domains: Vec::new(),
            config_file: None,
            private_domains_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_ports: vec![443],
            log_file: None,
            log_level: ProxyLogLevel::None,
        };

        let domains = state.get_allowed_domains();
        assert!(domains.is_empty(), "no file configured = no allowlist");
    }

    #[test]
    fn proxy_state_blocked_domains_from_file() {
        let dir = test_dir("blocked");
        let path = dir.join("blocked.txt");
        std::fs::write(&path, "evil.com\nbad.org\n").unwrap();

        let state = ProxyState {
            blocked_file: path,
            blocked_cache: Mutex::new(DomainCache {
                domains: Vec::new(),
                last_attempt: Instant::now()
                    .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                    .unwrap(),
            }),
            allowed_domains_file: None,
            allowlist_cache: Mutex::new(DomainCache::new(Vec::new())),
            cli_private_domains: Vec::new(),
            config_file: None,
            private_domains_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_ports: vec![443],
            log_file: None,
            log_level: ProxyLogLevel::None,
        };

        let blocked = state.get_blocked_domains();
        assert_eq!(blocked, vec!["evil.com", "bad.org"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_state_dynamic_reload_picks_up_changes() {
        let dir = test_dir("dynamic-reload");
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            "[proxy]\nallow_private_domains = [\"old.nav.no\"]\n",
        )
        .unwrap();

        let state = ProxyState {
            blocked_file: PathBuf::from("/dev/null"),
            blocked_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_domains_file: None,
            allowlist_cache: Mutex::new(DomainCache::new(Vec::new())),
            cli_private_domains: vec!["cli.nav.no".to_string()],
            config_file: Some(config_path.clone()),
            private_domains_cache: Mutex::new(DomainCache {
                domains: vec!["old.nav.no".to_string()],
                last_attempt: Instant::now()
                    .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                    .unwrap(),
            }),
            allowed_ports: vec![443],
            log_file: None,
            log_level: ProxyLogLevel::None,
        };

        // First read: picks up "old.nav.no" from cache reload + "cli.nav.no"
        let domains = state.get_private_domains();
        assert!(domains.contains(&"old.nav.no".to_string()));
        assert!(domains.contains(&"cli.nav.no".to_string()));

        // Simulate config edit mid-session
        std::fs::write(
            &config_path,
            "[proxy]\nallow_private_domains = [\"new.nav.no\"]\n",
        )
        .unwrap();

        // Force TTL expiry
        state.private_domains_cache.lock().unwrap().last_attempt = Instant::now()
            .checked_sub(RELOAD_TTL + Duration::from_millis(100))
            .unwrap();

        let domains = state.get_private_domains();
        assert!(domains.contains(&"new.nav.no".to_string()));
        assert!(domains.contains(&"cli.nav.no".to_string()));
        assert!(
            !domains.contains(&"old.nav.no".to_string()),
            "old config domain should be gone after reload"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_blocked_in_list_matches_exact_and_subdomain() {
        let blocked = vec!["evil.com".to_string(), "bad.org".to_string()];
        assert!(is_blocked_in_list("evil.com", &blocked));
        assert!(is_blocked_in_list("sub.evil.com", &blocked));
        assert!(!is_blocked_in_list("notevil.com", &blocked));
        assert!(!is_blocked_in_list("good.com", &blocked));
    }

    #[test]
    fn proxy_start_validates_blocklist_at_startup() {
        let dir = test_dir("start-valid");
        let blocked = dir.join("blocked.txt");
        std::fs::write(&blocked, "test.com\n").unwrap();

        let result = start(ProxyOptions {
            port: 0,
            blocked_file: blocked,
            allowed_ports: vec![],
            allowed_domains_file: None,
            allowed_domains_initial: Vec::new(),
            cli_private_domains: Vec::new(),
            config_private_domains: Vec::new(),
            config_file: None,
            log_file: None,
            log_level: ProxyLogLevel::None,
        });
        assert!(result.is_ok());
        result.unwrap().shutdown();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_start_fails_on_unreadable_allowlist() {
        let dir = test_dir("start-fail");
        let blocked = dir.join("blocked.txt");
        std::fs::write(&blocked, "").unwrap();

        // Create a directory where a file is expected (unreadable as file)
        let allowlist_path = dir.join("allowlist");
        std::fs::create_dir(&allowlist_path).unwrap();

        let result = start(ProxyOptions {
            port: 0,
            blocked_file: blocked,
            allowed_ports: vec![],
            allowed_domains_file: Some(allowlist_path),
            allowed_domains_initial: Vec::new(),
            cli_private_domains: Vec::new(),
            config_private_domains: Vec::new(),
            config_file: None,
            log_file: None,
            log_level: ProxyLogLevel::None,
        });
        assert!(result.is_err(), "should fail when allowlist is unreadable");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_state_allowlist_reloads_from_file() {
        let dir = test_dir("allowlist-reload");
        let path = dir.join("allowed.txt");
        std::fs::write(&path, "github.com\n").unwrap();

        let state = ProxyState {
            blocked_file: PathBuf::from("/dev/null"),
            blocked_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_domains_file: Some(path.clone()),
            allowlist_cache: Mutex::new(DomainCache {
                domains: vec!["github.com".to_string()],
                last_attempt: Instant::now()
                    .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                    .unwrap(),
            }),
            cli_private_domains: Vec::new(),
            config_file: None,
            private_domains_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_ports: vec![443],
            log_file: None,
            log_level: ProxyLogLevel::None,
        };

        // Initial read picks up github.com from stale cache (triggers reload)
        let domains = state.get_allowed_domains();
        assert_eq!(domains, vec!["github.com"]);

        // Edit file
        std::fs::write(&path, "github.com\nnpm.pkg.github.com\n").unwrap();
        state.allowlist_cache.lock().unwrap().last_attempt = Instant::now()
            .checked_sub(RELOAD_TTL + Duration::from_millis(100))
            .unwrap();

        let domains = state.get_allowed_domains();
        assert!(domains.contains(&"npm.pkg.github.com".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
