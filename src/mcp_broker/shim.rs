//! `cplt mcp-stdio <id>`, the sandbox side.

use std::ffi::OsString;
use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
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

/// Both ways between a TCP and a unix stream until each side ends: the
/// egress hop on either side of the Linux child's network namespace (#849).
pub(crate) fn pipe(tcp: TcpStream, unix: UnixStream) {
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
    let _ = back.join();
}

/// `cplt mcp-egress-relay <socket> <port> <program> [args]`, run by bwrap
/// inside the Linux child's fresh network namespace (#849): listen on
/// `127.0.0.1:<port>` there (the port `HTTPS_PROXY` names), relay each
/// connection to `<socket>`, the broker's egress proxy bound in from the
/// host, and run the server with this process's stdio and environment.
/// Exits with the server's status; the listener is up before it starts.
pub fn run_egress_relay(socket: PathBuf, port: u16, argv: &[OsString]) -> ExitCode {
    let Some((program, args)) = argv.split_first() else {
        return ExitCode::FAILURE;
    };
    // Port 0: no egress hosts, so no listener; every proxied request fails.
    if port != 0 {
        let listener = match TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("cplt mcp-egress-relay: cannot listen on {port}: {e}");
                return ExitCode::FAILURE;
            }
        };
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let socket = socket.clone();
                std::thread::spawn(move || {
                    if let Ok(up) = UnixStream::connect(&socket) {
                        pipe(conn, up);
                    }
                });
            }
        });
    }
    #[allow(clippy::disallowed_methods)] // the spec's program, resolved on the host at load
    let status = std::process::Command::new(program).args(args).status();
    match status {
        Ok(s) => {
            use std::os::unix::process::ExitStatusExt;
            let code = s.code().or(s.signal().map(|n| 128 + n)).unwrap_or(1);
            ExitCode::from(u8::try_from(code).unwrap_or(1))
        }
        Err(e) => {
            eprintln!("cplt mcp-egress-relay: cannot run the server: {e}");
            ExitCode::FAILURE
        }
    }
}
