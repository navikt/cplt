//! `cplt mcp-stdio <id>`, the sandbox side.

use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use super::SOCKET_ENV;

/// `cplt mcp-stdio <id>`, inside the sandbox: copy stdio to the broker.
pub fn run_stdio(id: &str) -> ExitCode {
    let Some(socket) = std::env::var_os(SOCKET_ENV).filter(|s| !s.is_empty()) else {
        eprintln!("cplt mcp-stdio: {SOCKET_ENV} is not set; run inside a cplt session");
        return ExitCode::FAILURE;
    };
    let mut stream = match UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cplt mcp-stdio: cannot reach the broker: {e}");
            return ExitCode::FAILURE;
        }
    };
    if writeln!(stream, "{id}").is_err() {
        return ExitCode::FAILURE;
    }
    let Ok(mut up) = stream.try_clone() else {
        return ExitCode::FAILURE;
    };
    std::thread::spawn(move || {
        pump(&mut std::io::stdin().lock(), &mut up);
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    pump(&mut stream, &mut std::io::stdout().lock());
    ExitCode::SUCCESS
}

/// Copy until EOF, flushing each chunk. Not `io::copy`: on Linux it
/// splices socket to pipe, and the reply never reached the client (#834).
pub(crate) fn pump(from: &mut impl std::io::Read, to: &mut impl Write) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if to.write_all(&buf[..n]).and_then(|()| to.flush()).is_err() {
                    return;
                }
            }
        }
    }
}

/// How long the unix side may stay silent once the TCP side has ended, so a
/// peer that never closes cannot hold a connection slot forever.
const HALF_CLOSED_IDLE: std::time::Duration = std::time::Duration::from_secs(30);

/// Both ways between a TCP and a unix stream until each side ends: the
/// egress hop on either side of the Linux child's network namespace (#849).
pub(crate) fn pipe(tcp: TcpStream, unix: UnixStream) {
    pipe_idle(tcp, unix, HALF_CLOSED_IDLE);
}

fn pipe_idle(tcp: TcpStream, unix: UnixStream, idle: std::time::Duration) {
    let (Ok(mut t), Ok(mut u)) = (tcp.try_clone(), unix.try_clone()) else {
        return;
    };
    let back = std::thread::spawn(move || {
        pump(&mut u, &mut t);
        let _ = t.shutdown(Shutdown::Write);
    });
    let (mut t, mut u) = (tcp, unix);
    pump(&mut t, &mut u);
    let _ = u.shutdown(Shutdown::Write);
    // The TCP side is done (the proxy closed, or its deadline fired): the
    // unix peer still gets to finish a half-closed stream, but an idle read
    // now ends the back pump instead of blocking forever.
    let _ = u.set_read_timeout(Some(idle));
    let _ = back.join();
}

/// Set by the broker on bwrap for the Linux child (#849): JSON
/// `[port, program, args...]`. Its presence makes this process the egress
/// relay, dispatched before `main` as bwrap's own re-entry helper is, so
/// any binary carrying this crate (cplt, its unit tests) can play it.
pub(crate) const RELAY_ENV: &str = "__CPLT_MCP_EGRESS_RELAY";

/// Where the egress socket appears inside the Linux child's namespace.
pub(crate) const CHILD_EGRESS_SOCKET: &str = "/tmp/cplt-egress.sock";

#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array")]
static RELAY_CTOR: extern "C" fn() = relay_entry;

#[cfg(target_os = "linux")]
extern "C" fn relay_entry() {
    let Some(v) = std::env::var_os(RELAY_ENV) else {
        return;
    };
    std::process::exit(relay(v.as_encoded_bytes()));
}

/// [`RELAY_ENV`]'s payload run: the server's exit code, 126 for a payload
/// that does not parse.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn relay(payload: &[u8]) -> i32 {
    match serde_json::from_slice::<(u16, Vec<String>)>(payload) {
        Ok((port, argv)) => run_egress_relay(port, &argv),
        Err(_) => 126,
    }
}

/// The egress relay, run by bwrap inside the Linux child's fresh network
/// namespace (#849): listen on `127.0.0.1:<port>` there (the port
/// `HTTPS_PROXY` names), relay each connection to [`CHILD_EGRESS_SOCKET`],
/// the broker's egress proxy bound in from the host, and run the server
/// with this process's stdio and environment. Returns the server's exit
/// code; the listener is up before the server starts.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn run_egress_relay(port: u16, argv: &[String]) -> i32 {
    let Some((program, args)) = argv.split_first() else {
        return 126;
    };
    // Port 0: no egress hosts, so no listener; every proxied request fails.
    if port != 0 {
        let listener = match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("cplt egress relay: cannot listen on {port}: {e}");
                return 126;
            }
        };
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    if let Ok(up) = UnixStream::connect(CHILD_EGRESS_SOCKET) {
                        pipe(conn, up);
                    }
                });
            }
        });
    }
    #[allow(clippy::disallowed_methods)] // the spec's program, resolved on the host at load
    let status = std::process::Command::new(program)
        .args(args)
        .env_remove(RELAY_ENV)
        .status();
    match status {
        Ok(s) => {
            use std::os::unix::process::ExitStatusExt;
            s.code().or(s.signal().map(|n| 128 + n)).unwrap_or(1)
        }
        Err(e) => {
            eprintln!("cplt egress relay: cannot run the server: {e}");
            127
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unix peer that keeps its write half open after the TCP side has
    /// closed no longer pins the pipe (and its connection permit).
    #[test]
    fn pipe_ends_when_the_unix_peer_idles_after_tcp_closes() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        drop(l.accept().unwrap().0); // the proxy closes at once
        let (ours, _peer) = UnixStream::pair().unwrap(); // _peer stays open
        let t0 = std::time::Instant::now();
        pipe_idle(tcp, ours, std::time::Duration::from_millis(200));
        assert!(t0.elapsed() < std::time::Duration::from_secs(5));
    }

    use super::relay;

    #[test]
    fn relay_refuses_a_malformed_payload_and_runs_the_server_on_port_0() {
        assert_eq!(relay(b"not json"), 126);
        assert_eq!(relay(b"[1, []]"), 126, "no program");
        // Port 0: no listener, the server still runs; its status comes back.
        assert_eq!(relay(br#"[0, ["/bin/sh", "-c", "exit 7"]]"#), 7);
        assert_eq!(relay(br#"[0, ["/nonexistent/server"]]"#), 127);
    }
}
