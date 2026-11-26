//! Run the launcher from a process whose exec-time environment is empty.
//!
//! The kernel exposes a process's argv and exec-time environment to other
//! processes of the same user (`KERN_PROCARGS2` on macOS, `/proc/<pid>/environ`
//! on Linux), and neither Seatbelt nor Landlock can withhold it. Both read the
//! block the kernel copied at `execve`, not the live `environ`, so `setenv`
//! after start changes nothing they report.
//!
//! So `cplt` re-execs itself once, first thing in `main`, with an empty
//! environment and the original one in an unlinked temp file passed by
//! descriptor. The new image loads it back with `set_var` before any thread
//! exists, so every in-process lookup sees what the user exported, while the
//! exec-time block that stays readable for the whole session holds nothing.

use std::ffi::OsString;
use std::io::{Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd};
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
    // Returns only on failure (no temp dir, exe gone): availability over
    // hardening, the launch runs on as before.
    let _ = reexec(&args);
    args
}

fn reexec(args: &[OsString]) -> std::io::Result<std::convert::Infallible> {
    use std::os::unix::process::CommandExt;
    // The binary that is running now, not a PATH lookup.
    let exe = std::env::current_exe()?.canonicalize()?;
    let mut file = tempfile::tempfile()?;
    file.write_all(&encode(std::env::vars_os()))?;
    file.rewind()?;
    let fd = file.as_raw_fd();
    // Inherited by the new image only; it closes it after one read.
    // SAFETY: fd is owned by `file` and open.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[allow(clippy::disallowed_methods)] // exe is the resolved running binary
    let err = std::process::Command::new(exe)
        .arg0(&args[0])
        .arg(MARKER)
        .arg(fd.to_string())
        .args(&args[1..])
        .env_clear()
        .exec();
    Err(err)
}

fn encode(vars: impl Iterator<Item = (OsString, OsString)>) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in vars {
        out.extend_from_slice(k.as_bytes());
        out.push(0);
        out.extend_from_slice(v.as_bytes());
        out.push(0);
    }
    out
}

fn decode(bytes: &[u8]) -> Option<Vec<(OsString, OsString)>> {
    let body = bytes.strip_suffix(&[0])?;
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
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(bad());
    }
    // SAFETY: open, a regular file, and ours from here on (closed on drop).
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = Vec::new();
    file.take(LIMIT).read_to_end(&mut buf)?;
    if buf.is_empty() {
        return Ok(Vec::new());
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
        assert_eq!(decode(b"A\0"), None);
        assert_eq!(decode(b"A=B\0v\0"), None);
        assert_eq!(decode(b"\0v\0"), None);
        assert_eq!(decode(b"A\0v"), None);
    }

    #[test]
    fn refuses_a_descriptor_that_is_not_a_regular_file() {
        let (r, _w) = std::io::pipe().unwrap();
        assert!(read_env(r.as_raw_fd()).is_err());
        assert!(read_env(1).is_err());
    }
}
