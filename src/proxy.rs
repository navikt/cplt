use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const MAX_CONNECTIONS: usize = 64;
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const GREEN: &str = "\x1b[0;32m";
const RED: &str = "\x1b[0;31m";
const YELLOW: &str = "\x1b[0;33m";
const NC: &str = "\x1b[0m";

pub struct ProxyHandle {
    shutdown_flag: Arc<std::sync::atomic::AtomicBool>,
}

impl ProxyHandle {
    pub fn shutdown(&self) {
        self.shutdown_flag
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Accept loop is non-blocking with 50ms sleep, so it will notice
        // the flag within ~50ms without needing a wake-up connection.
    }
}

/// Start the proxy on a background thread. Returns a handle for shutdown.
///
/// `allowed_ports` controls which remote ports CONNECT tunnels can reach.
/// Port 443 is always allowed. Additional ports come from `--allow-port`.
pub fn start(
    port: u16,
    blocked_file: PathBuf,
    allowed_ports: &[u16],
) -> Result<ProxyHandle, String> {
    let mut ports: Vec<u16> = vec![443];
    ports.extend_from_slice(allowed_ports);
    ports.sort_unstable();
    ports.dedup();
    let allowed_ports = Arc::new(ports);
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).map_err(|e| format!("Cannot bind to {addr}: {e}"))?;

    // Validate blocklist is readable at startup (fail-fast, not fail-open)
    if blocked_file.exists() {
        std::fs::read_to_string(&blocked_file).map_err(|e| {
            format!(
                "Cannot read blocked domains file {}: {e}",
                blocked_file.display()
            )
        })?;
    }

    listener
        .set_nonblocking(false)
        .map_err(|e| format!("set_nonblocking: {e}"))?;

    let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = shutdown_flag.clone();
    let active_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    std::thread::Builder::new()
        .name("proxy-accept".into())
        .spawn(move || {
            accept_loop(listener, flag, blocked_file, active_count, allowed_ports);
        })
        .map_err(|e| format!("spawn proxy thread: {e}"))?;

    std::thread::sleep(Duration::from_millis(50));

    Ok(ProxyHandle { shutdown_flag })
}

fn accept_loop(
    listener: TcpListener,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    blocked_file: PathBuf,
    active_count: Arc<std::sync::atomic::AtomicUsize>,
    allowed_ports: Arc<Vec<u16>>,
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

        // Connection limit
        let count = active_count.load(std::sync::atomic::Ordering::SeqCst);
        if count >= MAX_CONNECTIONS {
            log_connection("REJECT", "connection limit", "LIMIT");
            drop(stream);
            continue;
        }

        active_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let blocked = blocked_file.clone();
        let counter = active_count.clone();
        let ports = allowed_ports.clone();

        if let Err(e) = std::thread::Builder::new()
            .name("proxy-conn".into())
            .spawn(move || {
                handle_connection(stream, &blocked, &ports);
                counter.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            })
        {
            active_count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            log_connection("INTERNAL", "thread-spawn", &format!("FAIL:{e}"));
        }
    }
}

fn handle_connection(mut client: TcpStream, blocked_file: &PathBuf, allowed_ports: &[u16]) {
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
        handle_connect(client, target, blocked_file, allowed_ports);
    } else {
        // For non-CONNECT, send a simple error — the sandbox should force
        // CONNECT via proxy env vars for HTTPS traffic
        log_connection(method, target, "UNSUPPORTED");
        let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n");
    }
}

fn handle_connect(
    mut client: TcpStream,
    target: &str,
    blocked_file: &PathBuf,
    allowed_ports: &[u16],
) {
    // Parse host:port
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
        None => (target.to_string(), 443),
    };

    // Enforce port policy — only allow ports matching the sandbox network rules.
    // Without this, the proxy would let sandboxed processes tunnel to arbitrary
    // remote ports, bypassing the sandbox's port restrictions.
    if !allowed_ports.contains(&port) {
        log_connection("CONNECT", target, "BLOCKED-PORT");
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nPort not allowed\r\n");
        return;
    }

    // Check blocklist (hostname-level)
    if is_blocked(&host, blocked_file) {
        log_connection("CONNECT", target, "BLOCKED");
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by cplt\r\n");
        return;
    }

    // Reject hostname patterns that are known private (fast path before DNS)
    if is_private_hostname(&host) {
        log_connection("CONNECT", target, "BLOCKED-PRIVATE");
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nPrivate target blocked\r\n");
        return;
    }

    // Resolve DNS FIRST, then check the resolved IP
    let addr = format!("{host}:{port}");
    let socket_addr = match addr.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => a,
            None => {
                log_connection("CONNECT", target, "DNS-FAIL");
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                return;
            }
        },
        Err(_) => {
            log_connection("CONNECT", target, "DNS-FAIL");
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return;
        }
    };

    // Check the RESOLVED IP address (prevents DNS rebinding attacks)
    if is_private_ip(&socket_addr.ip()) {
        log_connection("CONNECT", target, "BLOCKED-PRIVATE-RESOLVED");
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nResolved to private IP\r\n");
        return;
    }

    log_connection("CONNECT", target, "OK");

    // Connect to resolved address (not re-resolving)
    let remote = match TcpStream::connect_timeout(&socket_addr, CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            log_connection("CONNECT", target, &format!("FAIL:{e}"));
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return;
        }
    };

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
    let mut client_read = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut remote_write = match remote.try_clone() {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut remote_read = remote;
    let mut client_write = client;

    // Set timeouts for relay
    client_read.set_read_timeout(Some(READ_TIMEOUT)).ok();
    remote_read.set_read_timeout(Some(READ_TIMEOUT)).ok();

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
        remote_write.shutdown(std::net::Shutdown::Both).ok();
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
        client_write.shutdown(std::net::Shutdown::Both).ok();
    });

    t1.join().ok();
    t2.join().ok();
}

pub fn is_blocked(hostname: &str, blocked_file: &PathBuf) -> bool {
    if !blocked_file.exists() {
        return false;
    }
    let contents = match std::fs::read_to_string(blocked_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{YELLOW}[proxy]{NC} Warning: cannot read blocklist {}: {e}",
                blocked_file.display()
            );
            return false;
        }
    };
    is_blocked_in_content(hostname, &contents)
}

pub fn is_blocked_in_content(hostname: &str, contents: &str) -> bool {
    let host = hostname.to_lowercase();
    for line in contents.lines() {
        let pattern = line.trim().to_lowercase();
        if pattern.is_empty() || pattern.starts_with('#') {
            continue;
        }
        if host == pattern || host.ends_with(&format!(".{pattern}")) {
            return true;
        }
    }
    false
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

fn log_connection(method: &str, target: &str, status: &str) {
    let color = match status {
        "BLOCKED" | "BLOCKED-PRIVATE" | "LIMIT" => RED,
        "OK" => GREEN,
        _ => YELLOW,
    };
    let timestamp = chrono_now();
    eprintln!("{color}[proxy]{NC} {timestamp} {method} {target} → {status}");
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

use std::net::ToSocketAddrs;
