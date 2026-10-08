//! Reading files the sandboxed agent can write.
//!
//! cplt runs unsandboxed. A plain `read_to_string` on an agent-writable path
//! hangs forever on a planted FIFO, follows a planted symlink to read
//! somewhere else, and loads a planted multi-gigabyte file into memory. The
//! helpers here open with `O_NONBLOCK` (a FIFO opens at once), `O_NOFOLLOW`
//! (a symlink as the last component is refused), `O_CLOEXEC`, then `fstat` the
//! open descriptor and accept only a regular file.

use std::fs::File;
use std::io::{self, Read as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

/// `Ok(None)` when `path` is a symlink or anything but a regular file; `Err`
/// for other open errors (`NotFound` included).
pub fn open_untrusted(path: &Path) -> io::Result<Option<File>> {
    open(path, libc::O_NOFOLLOW)
}

/// Read `path` as UTF-8 if it is a regular file (not a symlink) of at most
/// `limit` bytes. `Ok(None)` for a symlink, FIFO, device, directory or a
/// larger file.
pub fn read_untrusted(path: &Path, limit: u64) -> io::Result<Option<String>> {
    read(open_untrusted(path)?, limit)
}

/// Like [`read_untrusted`] but follows symlinks, for paths whose symlinks are
/// legitimate (a dotfile-managed `settings.json`) or already confined by the
/// caller. A FIFO or device behind the link is still refused.
pub fn read_regular_following(path: &Path, limit: u64) -> io::Result<Option<String>> {
    read(open(path, 0)?, limit)
}

fn open(path: &Path, extra: libc::c_int) -> io::Result<Option<File>> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | extra)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(file.metadata()?.is_file().then_some(file))
}

fn read(file: Option<File>, limit: u64) -> io::Result<Option<String>> {
    let Some(file) = file else { return Ok(None) };
    if file.metadata()?.len() > limit {
        return Ok(None);
    }
    // One byte past the limit: a file that grew after the fstat is refused,
    // not silently truncated.
    let mut s = String::new();
    file.take(limit + 1).read_to_string(&mut s)?;
    Ok((s.len() as u64 <= limit).then_some(s))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// `mkfifo(path)`, for tests that plant a FIFO.
    pub(crate) fn mkfifo(path: &Path) {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
    }

    /// Run `f` on a thread and fail if it takes over 10 s: a FIFO read hangs.
    pub(crate) fn bounded<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(f()));
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("hung on a planted FIFO")
    }

    #[test]
    fn refuses_fifo_symlink_and_oversize() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("fifo");
        mkfifo(&fifo);
        let f = fifo.clone();
        assert!(bounded(move || read_untrusted(&f, 10).unwrap().is_none()));
        assert!(bounded(move || read_regular_following(&fifo, 10)
            .unwrap()
            .is_none()));

        let real = d.path().join("real");
        std::fs::write(&real, "hi").unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_untrusted(&link, 10).unwrap().is_none());
        assert_eq!(
            read_regular_following(&link, 10).unwrap().as_deref(),
            Some("hi")
        );
        assert_eq!(read_untrusted(&real, 10).unwrap().as_deref(), Some("hi"));
        assert!(read_untrusted(&real, 1).unwrap().is_none());
        assert!(read_untrusted(&d.path().join("nope"), 1).is_err());
    }
}
