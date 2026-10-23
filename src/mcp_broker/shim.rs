//! `cplt mcp-stdio <id>`, the sandbox side.

use std::io::Write;
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
fn pump(from: &mut impl std::io::Read, to: &mut impl Write) {
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
