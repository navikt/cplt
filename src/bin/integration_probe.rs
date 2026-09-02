use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        eprintln!("usage: integration_probe <cmd> [args]");
        std::process::exit(2);
    };

    let rc = match cmd.as_str() {
        "uds-echo" => {
            let Some(path) = args.next() else {
                eprintln!("uds-echo <socket-path>");
                std::process::exit(2);
            };
            uds_echo(Path::new(&path))
        }
        "unix-bind" => {
            let Some(path) = args.next() else {
                eprintln!("unix-bind <socket-path>");
                std::process::exit(2);
            };
            unix_bind(Path::new(&path))
        }
        "ssh-agent-check" => ssh_agent_check(),
        "tcp-bind" => {
            let Some(host) = args.next() else {
                eprintln!("tcp-bind <host> <port>");
                std::process::exit(2);
            };
            let Some(port_str) = args.next() else {
                eprintln!("tcp-bind <host> <port>");
                std::process::exit(2);
            };
            let Ok(port) = port_str.parse::<u16>() else {
                eprintln!("invalid port: {port_str}");
                std::process::exit(2);
            };
            tcp_bind(&host, port)
        }
        "dir-list" => {
            let Some(path) = args.next() else {
                eprintln!("dir-list <path>");
                std::process::exit(2);
            };
            dir_list(Path::new(&path))
        }
        _ => {
            eprintln!("unknown command: {cmd}");
            2
        }
    };

    std::process::exit(rc);
}

fn uds_echo(path: &Path) -> i32 {
    let _ = fs::remove_file(path);
    let listener = match UnixListener::bind(path) {
        Ok(v) => v,
        Err(e) => {
            println!("ERROR:{e}");
            return 1;
        }
    };
    let handle = std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let _ = conn.write_all(b"OK");
        }
    });

    std::thread::sleep(std::time::Duration::from_millis(200));

    let mut client = match UnixStream::connect(path) {
        Ok(v) => v,
        Err(e) => {
            println!("ERROR:{e}");
            let _ = fs::remove_file(path);
            return 1;
        }
    };
    let mut buf = [0u8; 10];
    let out = match client.read(&mut buf) {
        Ok(n) if n > 0 => String::from_utf8_lossy(&buf[..n]).to_string(),
        Ok(_) => String::new(),
        Err(e) => {
            println!("ERROR:{e}");
            let _ = fs::remove_file(path);
            return 1;
        }
    };
    println!("{out}");
    let _ = fs::remove_file(path);
    let _ = handle.join();
    0
}

fn unix_bind(path: &Path) -> i32 {
    let _ = fs::remove_file(path);
    match UnixListener::bind(path) {
        Ok(listener) => {
            drop(listener);
            let _ = fs::remove_file(path);
            println!("EXPOSED");
            0
        }
        Err(e) => {
            let code = e.raw_os_error().unwrap_or_default();
            if code == libc::EPERM || code == libc::EACCES {
                println!("BLOCKED");
                0
            } else {
                println!("ERROR:{e}");
                1
            }
        }
    }
}

fn ssh_agent_check() -> i32 {
    let sock = std::env::var("SSH_AUTH_SOCK").unwrap_or_default();
    if sock.is_empty() {
        println!("NO_SSH_AGENT");
        return 0;
    }
    match UnixStream::connect(sock) {
        Ok(_) => {
            println!("EXPOSED");
            0
        }
        Err(e) => {
            let code = e.raw_os_error().unwrap_or_default();
            if code == libc::EPERM || code == libc::EACCES {
                println!("BLOCKED");
                0
            } else {
                println!("ERROR:{e}");
                1
            }
        }
    }
}

fn tcp_bind(host: &str, port: u16) -> i32 {
    match std::net::TcpListener::bind((host, port)) {
        Ok(listener) => {
            let local_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
            drop(listener);
            println!("OK:{local_port}");
            0
        }
        Err(e) => {
            println!("DENIED:{e}");
            1
        }
    }
}

fn dir_list(path: &Path) -> i32 {
    match fs::read_dir(path) {
        Ok(_) => {
            println!("ALLOWED");
            0
        }
        Err(e) => {
            let code = e.raw_os_error().unwrap_or_default();
            if code == libc::EPERM || code == libc::EACCES {
                println!("BLOCKED");
                1
            } else {
                println!("ERROR:{e}");
                1
            }
        }
    }
}
