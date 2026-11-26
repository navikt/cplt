//! Run the launcher from a process whose exec-time environment is empty.
//!
//! The kernel exposes a process's argv and exec-time environment to other
//! processes of the same user (`KERN_PROCARGS2` on macOS, `/proc/<pid>/environ`
//! on Linux), and neither Seatbelt nor Landlock can withhold it. Both read the
//! block the kernel copied at `execve`, not the live `environ`, so `setenv`
//! after start changes nothing they report.
//!
//! So `cplt` re-execs itself once, first thing in `main`, with an empty
//! environment and the original one on an inherited pipe (see `send`),
//! read once. The new image loads it back with `set_var` before any thread
//! exists, so every in-process lookup sees what the user exported, while the
//! exec-time block that stays readable for the whole session holds nothing.

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

/// argv[1] of the re-exec'd image; argv[2] is the descriptor number. An argv
/// marker, not an env var: the environment is exactly what is being emptied,
/// and a caller that forges it can only feed its own values back to itself.
pub const MARKER: &str = "--__cplt-env-fd";

/// Upper bound on the environment read back (ARG_MAX on macOS is 1 MiB).
const LIMIT: u64 = 4 << 20;

/// The arguments `main` should parse. In the first image this does not return
/// when the re-exec succeeds; if it cannot happen, cplt runs on as before.
/// In the re-exec'd image it restores the environment and strips the marker.
///
/// # Safety
/// Call before any thread is spawned: it calls `set_var`.
pub unsafe fn launch() -> Vec<OsString> {
    let mut args: Vec<OsString> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == MARKER) {
        let fd = args.get(2).and_then(|s| s.to_str()?.parse::<i32>().ok());
        args.drain(1..3.min(args.len()));
        let Some(Ok(vars)) = fd.map(read_env) else {
            eprintln!("cplt: cannot restore the launch environment");
            std::process::exit(1);
        };
        for (k, v) in vars {
            // SAFETY: single-threaded, per the caller's contract.
            unsafe { std::env::set_var(k, v) };
        }
        return args;
    }
    // Returns only on failure (no temp dir, exe gone). Availability over
    // hardening: say so, then run on as before.
    let Err(e) = reexec(&args);
    crate::ui::warn(&format!(
        "the launcher kept the full environment, so other processes of your user \
         (including the sandboxed agent) can read it: re-exec with a clean \
         environment failed: {e}"
    ));
    args
}

/// What a parent-side helper (git, security, lsof, the worktree broker's
/// git) receives: the variables those tools need to find their config,
/// locale, agent socket and network proxy. Never a token: a helper that needs
/// a secret gets it on stdin or a descriptor.
pub const HELPER_ENV: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "PATH",
    "SHELL",
    "TMPDIR",
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "SSH_AUTH_SOCK",
    "DBUS_SESSION_BUS_ADDRESS",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "GH_CONFIG_DIR",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// Give `cmd` only [`HELPER_ENV`] from the restored environment. Call it right
/// after `Command::new`: `env_clear` also drops variables set before it.
pub fn helper_env(cmd: &mut std::process::Command) {
    #[cfg(test)]
    HELPER_ENV_CALLS.with(|n| n.set(n.get() + 1));
    cmd.env_clear();
    for k in HELPER_ENV {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
}

/// `Command::new(program)` with [`helper_env`] applied. The caller still
/// owes `program` a trusted, absolute path, as for `Command::new`.
#[allow(clippy::disallowed_methods)] // the caller resolves `program`
pub fn helper_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    helper_env(&mut cmd);
    cmd
}

#[cfg(test)]
thread_local! {
    static HELPER_ENV_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How often this thread called [`helper_env`]: lets a test prove a spawn
/// site goes through it.
#[cfg(test)]
pub fn helper_env_calls() -> usize {
    HELPER_ENV_CALLS.with(std::cell::Cell::get)
}

fn reexec(args: &[OsString]) -> std::io::Result<std::convert::Infallible> {
    use std::os::unix::process::CommandExt;
    if cfg!(debug_assertions) && std::env::var_os("CPLT_TEST_FAIL_REEXEC").is_some() {
        return Err(std::io::Error::other(
            "forced by CPLT_TEST_FAIL_REEXEC (debug build)",
        ));
    }
    // The binary that is running now, not a PATH lookup.
    let exe = std::env::current_exe()?.canonicalize()?;
    let block = encode(std::env::vars_os());
    if block.len() as u64 > LIMIT {
        return Err(std::io::Error::other("environment larger than 4 MiB"));
    }
    let fd = send(&block)?;
    #[allow(clippy::disallowed_methods)] // exe is the resolved running binary
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg0(args.first().map_or(exe.as_os_str(), |a| a.as_os_str()))
        .arg(MARKER)
        .arg(fd.to_string())
        .args(args.iter().skip(1))
        .env_clear();
    let err = cmd.exec();
    // SAFETY: our read end; the exec did not happen.
    unsafe { libc::close(fd) };
    Err(err)
}

/// The block on a pipe, so it never has a filesystem name another process
/// could open (a temp file exists under `$TMPDIR` until it is unlinked). A
/// pipe buffer holds only 16-64 KiB and no thread may exist yet, so a
/// double-forked writer feeds it; the reader sees EOF when the writer exits.
/// Returns the read end, inheritable across exec.
fn send(block: &[u8]) -> std::io::Result<i32> {
    let mut fds = [0; 2];
    // SAFETY: plain syscalls on descriptors this function owns.
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let [r, w] = fds;
        libc::fcntl(w, libc::F_SETFD, libc::FD_CLOEXEC);
        let middle = libc::fork();
        if middle < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(r);
            libc::close(w);
            return Err(e);
        }
        if middle == 0 {
            // Single-threaded child: only async-signal-safe calls from here.
            libc::close(r);
            if libc::fork() == 0 {
                let mut rest = block;
                while !rest.is_empty() {
                    let n = libc::write(w, rest.as_ptr().cast(), rest.len());
                    if n <= 0 {
                        libc::_exit(1);
                    }
                    rest = &rest[n as usize..];
                }
                libc::_exit(0);
            }
            libc::_exit(0);
        }
        libc::close(w);
        let mut status = 0;
        libc::waitpid(middle, &raw mut status, 0);
        if libc::fcntl(r, libc::F_SETFD, 0) != 0 {
            let e = std::io::Error::last_os_error();
            libc::close(r);
            return Err(e);
        }
        Ok(r)
    }
}

/// `KEY\0VALUE\0` pairs behind an 8-byte length, so a block cut short (the
/// writer died, the second fork failed) is told apart from an empty
/// environment and refused.
fn encode(vars: impl Iterator<Item = (OsString, OsString)>) -> Vec<u8> {
    let mut body = Vec::new();
    for (k, v) in vars {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    let mut out = (body.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

fn decode(bytes: &[u8]) -> Option<Vec<(OsString, OsString)>> {
    let (len, body) = bytes.split_first_chunk::<8>()?;
    if u64::from_le_bytes(*len) != body.len() as u64 {
        return None;
    }
    if body.is_empty() {
        return Some(Vec::new());
    }
    let body = body.strip_suffix(&[0])?;
    let parts: Vec<&[u8]> = body.split(|b| *b == 0).collect();
    if !parts.len().is_multiple_of(2) {
        return None;
    }
    parts
        .chunks(2)
        .map(|kv| {
            let (k, v) = (kv[0], kv[1]);
            (!k.is_empty() && !k.contains(&b'=')).then(|| {
                (
                    OsString::from_vec(k.to_vec()),
                    OsString::from_vec(v.to_vec()),
                )
            })
        })
        .collect()
}

fn read_env(fd: i32) -> std::io::Result<Vec<(OsString, OsString)>> {
    let bad = || std::io::Error::other("bad environment descriptor");
    // SAFETY: fstat on an arbitrary number is harmless; a closed fd fails.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if fd < 3 || unsafe { libc::fstat(fd, &raw mut st) } != 0 {
        return Err(bad());
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err(bad());
    }
    // SAFETY: open, a pipe, and ours from here on (closed on drop).
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > LIMIT {
        return Err(std::io::Error::other("environment block over the limit"));
    }
    decode(&buf).ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_values_with_equals_and_newlines() {
        let vars = vec![
            (OsString::from("A"), OsString::from("x=y\nz")),
            (OsString::from("EMPTY"), OsString::new()),
        ];
        assert_eq!(decode(&encode(vars.clone().into_iter())), Some(vars));
    }

    #[test]
    fn refuses_malformed_blocks() {
        let framed = |b: &[u8]| {
            let mut v = (b.len() as u64).to_le_bytes().to_vec();
            v.extend_from_slice(b);
            v
        };
        assert_eq!(decode(&framed(b"A\0")), None);
        assert_eq!(decode(&framed(b"A=B\0v\0")), None);
        assert_eq!(decode(&framed(b"\0v\0")), None);
        assert_eq!(decode(&framed(b"A\0v")), None);
        assert_eq!(decode(&framed(b"")), Some(Vec::new()));
    }

    /// A writer that dies early leaves an empty or short pipe: refused.
    #[test]
    fn an_empty_or_truncated_block_is_refused() {
        let full = encode(vec![(OsString::from("A"), OsString::from("b"))].into_iter());
        for cut in [0, 4, full.len() - 1] {
            let (r, mut w) = std::io::pipe().unwrap();
            std::io::Write::write_all(&mut w, &full[..cut]).unwrap();
            drop(w);
            let fd = std::os::fd::IntoRawFd::into_raw_fd(r);
            assert!(read_env(fd).is_err(), "cut at {cut}");
        }
    }

    #[test]
    #[allow(clippy::disallowed_methods)] // never spawned
    fn helper_env_drops_everything_outside_the_list() {
        let mut cmd = std::process::Command::new("/usr/bin/true");
        cmd.env("CPLT_TEST_SECRET", "x");
        helper_env(&mut cmd);
        let keys: Vec<_> = cmd.get_envs().map(|(k, _)| k.to_owned()).collect();
        assert!(
            keys.iter().all(|k| HELPER_ENV.iter().any(|h| k == h)),
            "{keys:?}"
        );
        assert!(!keys.iter().any(|k| k == "CPLT_TEST_SECRET"));
    }

    #[test]
    fn refuses_a_descriptor_that_is_not_a_pipe() {
        let f = tempfile::tempfile().unwrap();
        assert!(read_env(std::os::fd::AsRawFd::as_raw_fd(&f)).is_err());
        assert!(read_env(1).is_err());
    }

    #[test]
    fn a_block_larger_than_a_pipe_buffer_arrives_whole() {
        let vars = vec![(OsString::from("BIG"), OsString::from("x".repeat(300_000)))];
        let fd = send(&encode(vars.clone().into_iter())).unwrap();
        assert_eq!(read_env(fd).unwrap(), vars);
    }
}
