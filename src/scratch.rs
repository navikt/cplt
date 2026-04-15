//! Per-session scratch directory for TMPDIR redirect.
//!
//! Many tools (Go test, mise inline tasks, node-gyp) compile binaries to
//! `$TMPDIR` then execute them. The sandbox blocks exec from system temp dirs
//! to prevent write-then-exec attacks:
//! - macOS: `/private/tmp`, `/private/var/folders`
//! - Linux: `/tmp`, `/var/tmp`
//!
//! The scratch directory provides a controlled alternative: a per-session
//! directory with write+exec permissions, cleaned up automatically on exit.
//!
//! Location varies by platform:
//! - macOS: `~/Library/Caches/cplt/tmp/{session-id}/`
//! - Linux: `~/.cache/cplt/tmp/{session-id}/`
//!
//! Each session gets a UUID subdirectory for isolation.

use crate::sandbox::validate_sbpl_path;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Base directory for scratch dirs, relative to $HOME.
#[cfg(target_os = "macos")]
const SCRATCH_BASE: &str = "Library/Caches/cplt/tmp";

/// Base directory for scratch dirs, relative to $HOME.
/// Uses `~/.cache` (does not read `$XDG_CACHE_HOME` — sandbox env is filtered).
#[cfg(not(target_os = "macos"))]
const SCRATCH_BASE: &str = ".cache/cplt/tmp";

/// Maximum age for stale scratch dirs before garbage collection.
const STALE_AGE: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

/// A per-session scratch directory with write+exec permissions.
///
/// Implements `Drop` to ensure cleanup on all exit paths (RAII guard).
/// The directory is created under `$HOME/{SCRATCH_BASE}/{uuid}/`.
#[derive(Debug)]
pub struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    /// Create a new per-session scratch directory.
    ///
    /// Steps:
    /// 1. Create base dir (`~/Library/Caches/cplt/tmp/`) if needed
    /// 2. Canonicalize base + home and verify base is under expected prefix
    ///    (catches symlinks at any ancestor level)
    /// 3. Validate base dir ownership and permissions
    /// 4. Create session subdir with random UUID
    /// 5. Set permissions to 0700
    /// 6. Validate path for SBPL injection
    pub fn create(home_dir: &Path) -> Result<Self, String> {
        let base = home_dir.join(SCRATCH_BASE);

        // Create base directory tree
        std::fs::create_dir_all(&base)
            .map_err(|e| format!("Cannot create scratch base {}: {e}", base.display()))?;

        // Canonicalize both home and base to catch symlinks at ANY ancestor level.
        // If ~/Library is a symlink to /somewhere/else, canonicalize will resolve it,
        // and the prefix check below will reject the escape.
        let canonical_home = std::fs::canonicalize(home_dir)
            .map_err(|e| format!("Cannot canonicalize home dir {}: {e}", home_dir.display()))?;
        let canonical_base = std::fs::canonicalize(&base)
            .map_err(|e| format!("Cannot canonicalize scratch base {}: {e}", base.display()))?;

        let expected_prefix = canonical_home.join(SCRATCH_BASE);
        if canonical_base != expected_prefix {
            return Err(format!(
                "Scratch base resolved to {} but expected {} — \
                 an ancestor directory may be a symlink",
                canonical_base.display(),
                expected_prefix.display()
            ));
        }

        // Validate base dir: must be owned by us, 0700, not a symlink
        validate_dir_safety(&canonical_base)?;

        // Generate a unique session directory name
        let session_id = generate_session_id();
        let session_dir = canonical_base.join(&session_id);

        // Create session directory with restricted permissions
        create_secure_dir(&session_dir)?;

        // Validate for SBPL injection before we use it in profile generation
        if let Err(e) = validate_sbpl_path(&session_dir) {
            let _ = std::fs::remove_dir_all(&session_dir);
            return Err(format!("Scratch dir path unsafe: {e}"));
        }

        Ok(ScratchDir { path: session_dir })
    }

    /// Path to the scratch directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Garbage-collect stale scratch directories older than 24 hours.
    ///
    /// Only deletes entries that look like our UUID-named session dirs.
    /// Runs best-effort: errors are logged but don't prevent startup.
    pub fn gc_stale(home_dir: &Path) {
        let base = home_dir.join(SCRATCH_BASE);
        if !base.exists() {
            return;
        }

        let entries = match std::fs::read_dir(&base) {
            Ok(e) => e,
            Err(_) => return,
        };

        let now = SystemTime::now();

        for entry in entries.flatten() {
            let path = entry.path();

            // Only process directories
            if !path.is_dir() {
                continue;
            }

            // Only delete entries that look like our session IDs (hex UUID)
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if !is_session_id(&name) {
                continue;
            }

            // Check age via directory modification time
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let modified = match metadata.modified() {
                Ok(t) => t,
                Err(_) => continue,
            };

            if let Ok(age) = now.duration_since(modified)
                && age > STALE_AGE
            {
                let _ = std::fs::remove_dir_all(&path).map_err(|e| {
                    eprintln!(
                        "\x1b[0;33m[cplt]\x1b[0m Warning: cannot remove stale scratch dir {}: {e}",
                        path.display()
                    );
                });
            }
        }
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = std::fs::remove_dir_all(&self.path).map_err(|e| {
                eprintln!(
                    "\x1b[0;33m[cplt]\x1b[0m Warning: cannot cleanup scratch dir {}: {e}",
                    self.path.display()
                );
            });
        }
    }
}

/// Generate a random session ID using /dev/urandom.
fn generate_session_id() -> String {
    let mut buf = [0u8; 16];
    let got_random = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut buf)
        })
        .is_ok();

    if !got_random {
        // Fallback: use PID + timestamp for uniqueness
        let pid = std::process::id();
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        buf[0..4].copy_from_slice(&pid.to_le_bytes());
        buf[4..].copy_from_slice(&ts.to_le_bytes()[..12]);
    }
    hex_encode(&buf)
}

/// Check if a string looks like one of our session IDs (32-char hex).
fn is_session_id(name: &str) -> bool {
    name.len() == 32 && name.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate that a directory is safe to use as scratch base.
///
/// Checks:
/// - Is a directory (not a symlink to one)
/// - Owned by current user
/// - Permissions are 0700 (set if not)
fn validate_dir_safety(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = path
        .symlink_metadata()
        .map_err(|e| format!("Cannot stat {}: {e}", path.display()))?;

    // Must be a real directory, not a symlink
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "Scratch base {} is a symlink — refusing to use it",
            path.display()
        ));
    }

    if !metadata.is_dir() {
        return Err(format!(
            "Scratch base {} is not a directory",
            path.display()
        ));
    }

    // Must be owned by us
    let my_uid = unsafe { libc::getuid() };
    if metadata.uid() != my_uid {
        return Err(format!(
            "Scratch base {} is owned by uid {}, expected {} — refusing to use it",
            path.display(),
            metadata.uid(),
            my_uid
        ));
    }

    // Ensure permissions are 0700
    let mode = metadata.mode() & 0o777;
    if mode != 0o700 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Cannot set permissions on {}: {e}", path.display()))?;
    }

    Ok(())
}

/// Create a directory with 0700 permissions atomically.
fn create_secure_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("Cannot create scratch dir {}: {e}", path.display()))
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn session_id_is_32_hex_chars() {
        let id = generate_session_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn is_session_id_accepts_valid() {
        assert!(is_session_id("0123456789abcdef0123456789abcdef"));
        assert!(is_session_id("AABBCCDD00112233AABBCCDD00112233"));
    }

    #[test]
    fn is_session_id_rejects_invalid() {
        assert!(!is_session_id("too-short"));
        assert!(!is_session_id("0123456789abcdef0123456789abcde")); // 31 chars
        assert!(!is_session_id("0123456789abcdef0123456789abcdefg")); // 33 chars
        assert!(!is_session_id("0123456789abcdef0123456789abcdeg")); // non-hex
    }

    #[test]
    fn scratch_dir_creates_and_cleans_up() {
        let tmp = std::env::temp_dir().join("cplt-test-scratch");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        {
            let scratch = ScratchDir::create(&tmp).unwrap();
            assert!(scratch.path().exists());
            assert!(scratch.path().is_dir());

            // Verify permissions are 0700
            let meta = scratch.path().metadata().unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        }
        // After drop, the session dir should be gone
        let base = tmp.join(SCRATCH_BASE);
        if base.exists() {
            let entries: Vec<_> = std::fs::read_dir(&base).unwrap().collect();
            assert!(
                entries.is_empty(),
                "scratch dir should be cleaned up on drop"
            );
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn scratch_dir_rejects_symlink_base() {
        let tmp = std::env::temp_dir().join("cplt-test-symlink");
        let _ = std::fs::remove_dir_all(&tmp);
        let real_dir = tmp.join("real");
        std::fs::create_dir_all(&real_dir).unwrap();

        let link_base = tmp.join(SCRATCH_BASE);
        std::fs::create_dir_all(link_base.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&real_dir, &link_base).unwrap();

        let result = ScratchDir::create(&tmp);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symlink"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn scratch_dir_rejects_ancestor_symlink() {
        // If the scratch base ancestor is a symlink, the scratch dir
        // would escape. The canonicalize + prefix check must catch this.
        let tmp = std::env::temp_dir().join("cplt-test-ancestor-symlink");
        let _ = std::fs::remove_dir_all(&tmp);
        let evil_target = tmp.join("evil-target");
        std::fs::create_dir_all(&evil_target).unwrap();

        // Create the ancestor path with a symlink at the parent of SCRATCH_BASE
        let scratch_path = std::path::Path::new(SCRATCH_BASE);
        let parent = scratch_path.parent().unwrap(); // e.g. "Library/Caches/cplt" or ".cache/cplt"
        let grandparent = parent.parent().unwrap(); // e.g. "Library/Caches" or ".cache"
        let basename = parent.file_name().unwrap(); // e.g. "cplt"

        std::fs::create_dir_all(tmp.join(grandparent)).unwrap();
        std::os::unix::fs::symlink(&evil_target, tmp.join(grandparent).join(basename)).unwrap();

        let result = ScratchDir::create(&tmp);
        assert!(result.is_err(), "must reject ancestor symlinks");
        let err = result.unwrap_err();
        assert!(
            err.contains("symlink") || err.contains("ancestor"),
            "error should mention symlink: {err}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gc_removes_stale_dirs() {
        let tmp = std::env::temp_dir().join("cplt-test-gc");
        let _ = std::fs::remove_dir_all(&tmp);
        let base = tmp.join(SCRATCH_BASE);
        std::fs::create_dir_all(&base).unwrap();

        // Create a "stale" session dir with a valid-looking name
        let stale_name = "0123456789abcdef0123456789abcdef";
        let stale_dir = base.join(stale_name);
        std::fs::create_dir(&stale_dir).unwrap();

        // Backdate the modification time to 25 hours ago using libc::utimes
        let old_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 25 * 3600;
        let times = [
            libc::timeval {
                tv_sec: old_secs,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: old_secs,
                tv_usec: 0,
            },
        ];
        let c_path = std::ffi::CString::new(stale_dir.to_str().unwrap()).unwrap();
        unsafe {
            libc::utimes(c_path.as_ptr(), times.as_ptr());
        }

        // Create a "fresh" session dir
        let fresh_name = "fedcba9876543210fedcba9876543210";
        let fresh_dir = base.join(fresh_name);
        std::fs::create_dir(&fresh_dir).unwrap();

        ScratchDir::gc_stale(&tmp);

        assert!(!stale_dir.exists(), "stale dir should be removed");
        assert!(fresh_dir.exists(), "fresh dir should be preserved");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gc_ignores_non_session_entries() {
        let tmp = std::env::temp_dir().join("cplt-test-gc-safe");
        let _ = std::fs::remove_dir_all(&tmp);
        let base = tmp.join(SCRATCH_BASE);
        std::fs::create_dir_all(&base).unwrap();

        // Create dirs that don't look like session IDs
        let safe_dir = base.join("not-a-session-id");
        std::fs::create_dir(&safe_dir).unwrap();
        let file_path = base.join("some-file.txt");
        std::fs::write(&file_path, "test").unwrap();

        ScratchDir::gc_stale(&tmp);

        assert!(safe_dir.exists(), "non-session dirs should be preserved");
        assert!(file_path.exists(), "files should be preserved");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
