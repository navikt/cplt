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
#[cfg(target_os = "macos")]
use crate::sandbox::{
    PLAYWRIGHT_SOCKET_DIR_PREFIX, PLAYWRIGHT_SOCKET_ROOT, validate_playwright_socket_dir,
};
use crate::ui;
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
const STALE_AGE: Duration = Duration::from_hours(24);

/// cplt-owned, per-session copies of pnpm executables whose inode is linked
/// into pnpm's writable content-addressable store.
const PNPM_SHADOW_BASE: &str = ".cplt-pnpm-shadow";

/// A per-session scratch directory with write+exec permissions.
///
/// Implements `Drop` to ensure cleanup on all exit paths (RAII guard).
/// The directory is created under `$HOME/{SCRATCH_BASE}/{uuid}/`.
#[derive(Debug)]
pub struct ScratchDir {
    path: PathBuf,
}

/// A read-only executable copy of pnpm outside its writable store.
///
/// pnpm's standalone executable can be hardlinked into
/// `$PNPM_HOME/store/v*/links/*/pnpm`. The kernel then evaluates execution
/// against that writable store inode even when PATH names the global install.
/// Copying the file breaks the hardlink relationship. The sandbox grants this
/// unique directory read+execute, never write, and prepends it to PATH.
#[derive(Debug)]
pub struct PnpmShadowDir {
    path: PathBuf,
    device: u64,
    inode: u64,
    source_device: u64,
    source_inode: u64,
    _lock: std::fs::File,
}

impl PnpmShadowDir {
    /// Copy `pnpm` when it shares an inode with a pnpm store hardlink.
    pub fn create_if_needed(home_dir: &Path, pnpm: &Path) -> Result<Option<Self>, String> {
        ensure_pnpm_package_manager_stores(home_dir)?;
        if !pnpm_requires_shadow(home_dir, pnpm)? {
            return Ok(None);
        }
        use std::os::unix::fs::MetadataExt;
        let source = std::fs::metadata(pnpm)
            .map_err(|e| format!("Cannot inspect pnpm executable {}: {e}", pnpm.display()))?;

        let base = home_dir.join(PNPM_SHADOW_BASE);
        match base.symlink_metadata() {
            Ok(_) => validate_dir_safety(&base, "pnpm shadow base")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_secure_dir(&base, "pnpm shadow base")?;
            }
            Err(error) => {
                return Err(format!(
                    "Cannot inspect pnpm shadow base {}: {error}",
                    base.display()
                ));
            }
        }
        let canonical_home = std::fs::canonicalize(home_dir)
            .map_err(|e| format!("Cannot canonicalize home dir {}: {e}", home_dir.display()))?;
        let canonical_base = std::fs::canonicalize(&base).map_err(|e| {
            format!(
                "Cannot canonicalize pnpm shadow base {}: {e}",
                base.display()
            )
        })?;
        if canonical_base != canonical_home.join(PNPM_SHADOW_BASE) {
            return Err(format!(
                "pnpm shadow base resolved to {} but expected {}. An ancestor directory may be a symlink",
                canonical_base.display(),
                canonical_home.join(PNPM_SHADOW_BASE).display()
            ));
        }
        let base_identity = secure_dir_identity(&canonical_base, "pnpm shadow base")?;
        let base_file = lock_pnpm_shadow_base(&canonical_base, base_identity)?;
        gc_stale_pnpm_shadows(&canonical_base, &base_file);

        let session_dir = canonical_base.join(generate_session_id()?);
        create_secure_dir(&session_dir, "pnpm shadow dir")?;
        let identity = secure_dir_identity(&session_dir, "pnpm shadow dir")?;
        let shadow = session_dir.join("pnpm");
        if let Err(error) = copy_executable(pnpm, &shadow) {
            let _ = std::fs::remove_dir_all(&session_dir);
            return Err(error);
        }
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) =
            std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o500))
        {
            let _ = std::fs::remove_dir_all(&session_dir);
            return Err(format!("Cannot make pnpm shadow read-only: {error}"));
        }
        let session_lock = match lock_pnpm_shadow_session(&session_dir, identity) {
            Ok(lock) => lock,
            Err(error) => {
                let _ =
                    std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o700));
                let _ = std::fs::remove_dir_all(&session_dir);
                return Err(error);
            }
        };
        drop(base_file);

        Ok(Some(Self {
            path: session_dir,
            device: identity.0,
            inode: identity.1,
            source_device: source.dev(),
            source_inode: source.ino(),
            _lock: session_lock,
        }))
    }

    /// Directory prepended to PATH and granted read+execute by the sandbox.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Copied pnpm executable used for direct `cplt exec -- pnpm` launches.
    pub fn binary(&self) -> PathBuf {
        self.path.join("pnpm")
    }

    /// Whether `path` names the source inode copied into this shadow.
    pub fn shadows(&self, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;

        std::fs::metadata(path).is_ok_and(|metadata| {
            metadata.is_file()
                && metadata.dev() == self.source_device
                && metadata.ino() == self.source_inode
        })
    }
}

impl Drop for PnpmShadowDir {
    fn drop(&mut self) {
        remove_owned_dir(&self.path, self.device, self.inode, "pnpm shadow dir");
    }
}

fn ensure_pnpm_package_manager_stores(home_dir: &Path) -> Result<(), String> {
    let canonical_home = std::fs::canonicalize(home_dir)
        .map_err(|e| format!("Cannot canonicalize home dir {}: {e}", home_dir.display()))?;
    for root in pnpm_home_roots(home_dir) {
        if !root.is_dir() {
            continue;
        }
        let canonical_root = std::fs::canonicalize(&root)
            .map_err(|e| format!("Cannot resolve pnpm home {}: {e}", root.display()))?;
        if let Ok(relative) = root.strip_prefix(home_dir) {
            let expected = canonical_home.join(relative);
            if canonical_root != expected {
                return Err(format!(
                    "pnpm home {} resolves through a symlink to {}",
                    root.display(),
                    canonical_root.display()
                ));
            }
        }
        let store = canonical_root.join("package-manager-store");
        match store.symlink_metadata() {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(format!(
                    "pnpm package-manager-store {} must be a real directory",
                    store.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&store).map_err(|e| {
                    format!(
                        "Cannot create pnpm package-manager-store {}: {e}",
                        store.display()
                    )
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "Cannot inspect pnpm package-manager-store {}: {error}",
                    store.display()
                ));
            }
        }
    }
    Ok(())
}

fn copy_executable(source: &Path, destination: &Path) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut source_file = std::fs::File::open(source)
        .map_err(|e| format!("Cannot open pnpm executable {}: {e}", source.display()))?;
    let mut destination_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(destination)
        .map_err(|e| format!("Cannot create pnpm shadow {}: {e}", destination.display()))?;
    std::io::copy(&mut source_file, &mut destination_file)
        .map_err(|e| format!("Cannot copy pnpm executable into shadow: {e}"))?;
    destination_file
        .sync_all()
        .map_err(|e| format!("Cannot sync pnpm shadow {}: {e}", destination.display()))?;
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o500))
        .map_err(|e| format!("Cannot set pnpm shadow permissions: {e}"))
}

/// Whether pnpm must run from a read-only shadow instead of its source inode.
pub fn pnpm_requires_shadow(home_dir: &Path, pnpm: &Path) -> Result<bool, String> {
    let roots: Vec<PathBuf> = pnpm_home_roots(home_dir)
        .into_iter()
        .filter_map(|root| std::fs::canonicalize(root.join("store")).ok())
        .collect();
    pnpm_has_store_alias_in(pnpm, &roots)
}

fn pnpm_has_store_alias_in(pnpm: &Path, roots: &[PathBuf]) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;

    let pnpm = std::fs::canonicalize(pnpm)
        .map_err(|e| format!("Cannot resolve pnpm executable {}: {e}", pnpm.display()))?;
    let source = std::fs::metadata(&pnpm)
        .map_err(|e| format!("Cannot inspect pnpm executable {}: {e}", pnpm.display()))?;
    if !source.is_file() {
        return Ok(false);
    }

    for root in roots {
        if pnpm.starts_with(root) {
            return Ok(true);
        }
        if source.nlink() < 2 {
            continue;
        }
        let Ok(versions) = std::fs::read_dir(root) else {
            continue;
        };
        for version in versions.flatten() {
            let name = version.file_name();
            if !name.to_string_lossy().starts_with('v') {
                continue;
            }
            let links = version.path().join("links");
            let Ok(packages) = std::fs::read_dir(links) else {
                continue;
            };
            for package in packages.flatten() {
                let candidate = package.path().join("pnpm");
                let Ok(metadata) = candidate.symlink_metadata() else {
                    continue;
                };
                if metadata.file_type().is_file()
                    && metadata.dev() == source.dev()
                    && metadata.ino() == source.ino()
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn lock_pnpm_shadow_base(
    base: &Path,
    expected_identity: (u64, u64),
) -> Result<std::fs::File, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let base_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(base)
        .map_err(|error| format!("Cannot open pnpm shadow base {}: {error}", base.display()))?;
    let metadata = base_file.metadata().map_err(|error| {
        format!(
            "Cannot inspect pnpm shadow base {}: {error}",
            base.display()
        )
    })?;
    if (metadata.dev(), metadata.ino()) != expected_identity {
        return Err(format!(
            "pnpm shadow base {} changed while it was being opened",
            base.display()
        ));
    }
    // SAFETY: `base_file` owns a valid descriptor. The advisory lock is
    // released automatically when the file is dropped.
    if unsafe { libc::flock(base_file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!(
            "Cannot lock pnpm shadow base {}: {}",
            base.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(base_file)
}

fn lock_pnpm_shadow_session(
    path: &Path,
    expected_identity: (u64, u64),
) -> Result<std::fs::File, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let session = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("Cannot open pnpm shadow {}: {error}", path.display()))?;
    let metadata = session
        .metadata()
        .map_err(|error| format!("Cannot inspect pnpm shadow {}: {error}", path.display()))?;
    if (metadata.dev(), metadata.ino()) != expected_identity {
        return Err(format!(
            "pnpm shadow {} changed while it was being opened",
            path.display()
        ));
    }
    // SAFETY: `session` owns a valid descriptor. Keeping this shared lock for
    // the guard's lifetime prevents garbage collection of a live shadow.
    if unsafe { libc::flock(session.as_raw_fd(), libc::LOCK_SH) } != 0 {
        return Err(format!(
            "Cannot lock pnpm shadow {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(session)
}

/// Remove stale pnpm shadows even when the current pnpm does not need one.
pub fn cleanup_stale_pnpm_shadows(home_dir: &Path) -> Result<(), String> {
    let base = home_dir.join(PNPM_SHADOW_BASE);
    match base.symlink_metadata() {
        Ok(_) => validate_dir_safety(&base, "pnpm shadow base")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "Cannot inspect pnpm shadow base {}: {error}",
                base.display()
            ));
        }
    }
    let canonical_home = std::fs::canonicalize(home_dir)
        .map_err(|e| format!("Cannot canonicalize home dir {}: {e}", home_dir.display()))?;
    let canonical_base = std::fs::canonicalize(&base).map_err(|e| {
        format!(
            "Cannot canonicalize pnpm shadow base {}: {e}",
            base.display()
        )
    })?;
    if canonical_base != canonical_home.join(PNPM_SHADOW_BASE) {
        return Err(format!(
            "pnpm shadow base resolved to {} but expected {}. An ancestor directory may be a symlink",
            canonical_base.display(),
            canonical_home.join(PNPM_SHADOW_BASE).display()
        ));
    }
    let identity = secure_dir_identity(&canonical_base, "pnpm shadow base")?;
    let base_file = lock_pnpm_shadow_base(&canonical_base, identity)?;
    gc_stale_pnpm_shadows(&canonical_base, &base_file);
    Ok(())
}

fn gc_stale_pnpm_shadows(base: &Path, base_file: &std::fs::File) {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    let now = SystemTime::now();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !is_session_id(name_str) {
            continue;
        }
        let Ok(c_name) = std::ffi::CString::new(name.as_bytes()) else {
            continue;
        };
        // SAFETY: `base_file` remains open for the call, `c_name` is
        // NUL-terminated, and openat returns a new owned descriptor on success.
        let child_fd = unsafe {
            libc::openat(
                base_file.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if child_fd < 0 {
            continue;
        }
        // SAFETY: `child_fd` was returned by openat and ownership transfers to File.
        let child = unsafe { std::fs::File::from_raw_fd(child_fd) };
        // SAFETY: `child` owns a valid descriptor. A live shadow keeps a
        // shared lock, so cleanup skips it even after the stale-age threshold.
        if unsafe { libc::flock(child.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            continue;
        }
        let Ok(metadata) = child.metadata() else {
            continue;
        };
        if metadata.uid() != unsafe { libc::getuid() } {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let Ok(age) = now.duration_since(modified) else {
            continue;
        };
        if age <= STALE_AGE {
            continue;
        }
        if child
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .is_err()
        {
            continue;
        }

        let pnpm = c"pnpm";
        // SAFETY: both descriptors and C strings are valid for the calls. All
        // operations are anchored to the validated directory descriptors, so
        // replacing the base pathname cannot redirect cleanup elsewhere.
        unsafe {
            libc::unlinkat(child.as_raw_fd(), pnpm.as_ptr(), 0);
        }
        // SAFETY: same as above; AT_REMOVEDIR removes only the opened base's
        // immediate UUID-named child and fails if unexpected entries remain.
        let removed =
            unsafe { libc::unlinkat(base_file.as_raw_fd(), c_name.as_ptr(), libc::AT_REMOVEDIR) };
        if removed != 0 {
            ui::warn("Warning: cannot remove a stale pnpm shadow");
        }
    }
}

/// pnpm data roots that can contain executable shims and writable stores.
pub fn pnpm_home_roots(home_dir: &Path) -> Vec<PathBuf> {
    let mut roots = vec![
        home_dir.join("Library/pnpm"),
        home_dir.join(".local/share/pnpm"),
    ];
    if let Some(xdg_data_home) = std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty())
    {
        let xdg_data_home = PathBuf::from(xdg_data_home);
        roots.push(if xdg_data_home.is_absolute() {
            xdg_data_home.join("pnpm")
        } else {
            home_dir.join(xdg_data_home).join("pnpm")
        });
    }
    if let Some(pnpm_home) = std::env::var_os("PNPM_HOME").filter(|value| !value.is_empty()) {
        let pnpm_home = PathBuf::from(pnpm_home);
        roots.push(if pnpm_home.is_absolute() {
            pnpm_home
        } else {
            home_dir.join(pnpm_home)
        });
    }
    roots.sort();
    roots.dedup();
    roots
}

/// Whether a pnpm executable needs an exact file-level execute grant.
pub fn pnpm_needs_exec_grant(home_dir: &Path, pnpm: &Path) -> bool {
    let roots: Vec<PathBuf> = pnpm_home_roots(home_dir)
        .into_iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect();
    pnpm_exec_grant_allowed(pnpm, &roots)
}

fn pnpm_exec_grant_allowed(pnpm: &Path, roots: &[PathBuf]) -> bool {
    if roots.iter().any(|root| {
        pnpm.starts_with(root.join("store")) || pnpm.starts_with(root.join("package-manager-store"))
    }) {
        return false;
    }
    roots.iter().any(|root| pnpm.starts_with(root))
}

/// Existing PATH executables inside pnpm homes that can be granted exactly.
///
/// Directory-wide execution would also cover the writable content store.
/// Hardlinked files and targets inside either writable store are excluded.
pub fn pnpm_path_executables(home_dir: &Path) -> Vec<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    pnpm_path_executables_in(home_dir, &path)
}

fn pnpm_path_executables_in(home_dir: &Path, path: &std::ffi::OsStr) -> Vec<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let roots: Vec<PathBuf> = pnpm_home_roots(home_dir)
        .into_iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect();
    let mut executables = Vec::new();

    for dir in std::env::split_paths(path) {
        let Ok(dir) = std::fs::canonicalize(dir) else {
            continue;
        };
        if !roots.iter().any(|root| dir.starts_with(root)) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let candidate = entry.path();
            if !crate::git::is_executable_file(&candidate) {
                continue;
            }
            let Ok(candidate) = std::fs::canonicalize(candidate) else {
                continue;
            };
            if !pnpm_exec_grant_allowed(&candidate, &roots) {
                continue;
            }
            let Ok(metadata) = std::fs::metadata(&candidate) else {
                continue;
            };
            if metadata.nlink() == 1 && !executables.contains(&candidate) {
                executables.push(candidate);
            }
        }
    }
    executables
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
                "Scratch base resolved to {} but expected {}. \
                 An ancestor directory may be a symlink",
                canonical_base.display(),
                expected_prefix.display()
            ));
        }

        // Validate base dir: must be owned by us, 0700, not a symlink
        validate_dir_safety(&canonical_base, "Scratch base")?;

        // Generate a unique session directory name
        let session_id = generate_session_id()?;
        let session_dir = canonical_base.join(&session_id);

        // Create session directory with restricted permissions
        create_secure_dir(&session_dir, "scratch dir")?;

        // Validate for SBPL injection before we use it in profile generation
        if let Err(e) = validate_sbpl_path(&session_dir) {
            let _ = std::fs::remove_dir_all(&session_dir);
            return Err(format!("Scratch dir path unsafe: {e}"));
        }

        Ok(ScratchDir { path: session_dir })
    }

    /// The directory every scratch dir is created under, whether or not one
    /// exists yet.
    ///
    /// Callers that must know what the session can write — the proxy list-file
    /// check (#426) — need the tree, not this run's instance.
    #[must_use]
    pub fn base(home_dir: &Path) -> PathBuf {
        home_dir.join(SCRATCH_BASE)
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
        gc_stale_session_dirs(&base);
    }
}

fn gc_stale_session_dirs(base: &Path) {
    if !base.exists() {
        return;
    }

    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };

    let now = SystemTime::now();

    for entry in entries.flatten() {
        let path = entry.path();

        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }

        // Only delete entries that look like our session IDs (hex UUID)
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !is_session_id(&name) {
            continue;
        }

        // Check age via directory modification time
        let Ok(modified) = metadata.modified() else {
            continue;
        };

        if let Ok(age) = now.duration_since(modified)
            && age > STALE_AGE
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.uid() != unsafe { libc::getuid() } {
                continue;
            }
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
            if let Err(e) = std::fs::remove_dir_all(&path) {
                ui::warn(&format!(
                    "Warning: cannot remove stale scratch dir {}: {e}",
                    path.display()
                ));
            }
        }
    }
}

/// A short, random, per-session macOS directory for Playwright control sockets.
///
/// The directory is deliberately independent of [`ScratchDir`]: it remains
/// available when scratch execution is disabled and receives socket-only SBPL
/// rules. The guard must outlive every sandboxed child that uses its path.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct PlaywrightSocketDir {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(target_os = "macos")]
impl PlaywrightSocketDir {
    /// Atomically create a cplt-owned Playwright socket base under `/private/tmp`.
    pub fn create() -> Result<Self, String> {
        let root = Path::new(PLAYWRIGHT_SOCKET_ROOT);
        let canonical_root = std::fs::canonicalize(root)
            .map_err(|e| format!("Cannot canonicalize Playwright socket root: {e}"))?;
        let root_metadata = root
            .symlink_metadata()
            .map_err(|e| format!("Cannot stat Playwright socket root: {e}"))?;
        if canonical_root != root
            || root_metadata.file_type().is_symlink()
            || !root_metadata.is_dir()
        {
            return Err("Playwright socket root is not the expected real directory".to_string());
        }

        let session_id = generate_session_id()?;
        Self::create_for_session_id(&session_id)
    }

    fn create_for_session_id(session_id: &str) -> Result<Self, String> {
        let path = Path::new(PLAYWRIGHT_SOCKET_ROOT)
            .join(format!("{PLAYWRIGHT_SOCKET_DIR_PREFIX}{session_id}"));
        validate_playwright_socket_dir(&path)?;
        create_secure_dir(&path, "Playwright socket dir")?;

        let identity = secure_dir_identity(&path, "Playwright socket dir");
        let (device, inode) = match identity {
            Ok(identity) => identity,
            Err(error) => {
                let _ = std::fs::remove_dir(&path);
                return Err(error);
            }
        };

        Ok(Self {
            path,
            device,
            inode,
        })
    }

    /// Exact validated directory authorized by the generated SBPL profile.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(target_os = "macos")]
impl Drop for PlaywrightSocketDir {
    fn drop(&mut self) {
        remove_owned_dir(&self.path, self.device, self.inode, "Playwright socket dir");
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if self.path.exists()
            && let Err(e) = std::fs::remove_dir_all(&self.path)
        {
            ui::warn(&format!(
                "Warning: cannot cleanup scratch dir {}: {e}",
                self.path.display()
            ));
        }
    }
}

/// Generate a random session ID using /dev/urandom.
pub(crate) fn generate_session_id() -> Result<String, String> {
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut buf)
        })
        .map_err(|_| "Cannot generate a cryptographically random session ID".to_string())?;
    Ok(hex_encode(&buf))
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
pub(crate) fn validate_dir_safety(path: &Path, label: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = path
        .symlink_metadata()
        .map_err(|e| format!("Cannot stat {}: {e}", path.display()))?;

    // Must be a real directory, not a symlink
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} {} is a symlink, cplt refuses to use it",
            path.display()
        ));
    }

    if !metadata.is_dir() {
        return Err(format!("{label} {} is not a directory", path.display()));
    }

    // Must be owned by us
    let my_uid = unsafe { libc::getuid() };
    if metadata.uid() != my_uid {
        return Err(format!(
            "{label} {} is owned by uid {}, expected {}. cplt refuses to use it",
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
pub(crate) fn create_secure_dir(path: &Path, label: &str) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("Cannot create {label} {}: {e}", path.display()))
}

fn secure_dir_identity(path: &Path, label: &str) -> Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt;

    validate_dir_safety(path, label)?;
    let metadata = path
        .symlink_metadata()
        .map_err(|e| format!("Cannot stat {}: {e}", path.display()))?;
    Ok((metadata.dev(), metadata.ino()))
}

fn remove_owned_dir(path: &Path, expected_device: u64, expected_inode: u64, label: &str) {
    use std::os::unix::fs::MetadataExt;

    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            ui::warn(&format!(
                "Warning: cannot inspect {label} {} during cleanup: {error}",
                path.display()
            ));
            return;
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.dev() != expected_device
        || metadata.ino() != expected_inode
    {
        ui::warn(&format!(
            "Warning: refusing to cleanup replaced {label} {}",
            path.display()
        ));
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
        ui::warn(&format!(
            "Warning: cannot make {label} {} removable during cleanup: {error}",
            path.display()
        ));
        return;
    }
    if let Err(error) = std::fs::remove_dir_all(path) {
        ui::warn(&format!(
            "Warning: cannot cleanup {label} {}: {error}",
            path.display()
        ));
    }
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
        let id = generate_session_id().unwrap();
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
    fn creates_missing_pnpm_package_manager_store() {
        let home = tempfile::tempdir().unwrap();
        let pnpm_home = home.path().join(".local/share/pnpm");
        std::fs::create_dir_all(&pnpm_home).unwrap();

        ensure_pnpm_package_manager_stores(home.path()).unwrap();

        assert!(pnpm_home.join("package-manager-store").is_dir());
    }

    #[test]
    fn refuses_symlinked_pnpm_home_before_creating_version_store() {
        let home = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".local/share")).unwrap();
        std::os::unix::fs::symlink(target.path(), home.path().join(".local/share/pnpm")).unwrap();

        let error =
            ensure_pnpm_package_manager_stores(home.path()).expect_err("symlink must be refused");

        assert!(error.contains("resolves through a symlink"));
        assert!(!target.path().join("package-manager-store").exists());
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

        // Create the ancestor path with a symlink at the "cplt" level.
        // Use SCRATCH_BASE to derive the correct platform-specific path
        // (Library/Caches/cplt/tmp on macOS, .cache/cplt/tmp on Linux).
        let scratch_base = Path::new(SCRATCH_BASE);
        // Parent of "tmp" within the base is the "cplt" directory's parent
        let cplt_parent = tmp.join(scratch_base.parent().and_then(|p| p.parent()).unwrap());
        std::fs::create_dir_all(&cplt_parent).unwrap();
        let cplt_dir = tmp.join(scratch_base.parent().unwrap());
        std::os::unix::fs::symlink(&evil_target, &cplt_dir).unwrap();

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
    fn pnpm_shadow_breaks_store_hardlink_and_cleans_up() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let home = tempfile::tempdir().unwrap();
        let global = home.path().join("Library/pnpm/global/v11");
        let links = home
            .path()
            .join("Library/pnpm/store/v10/links/pnpm-package");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::create_dir_all(&links).unwrap();
        let pnpm = global.join("pnpm");
        std::fs::write(&pnpm, b"#!/bin/sh\nprintf shadow\n").unwrap();
        std::fs::set_permissions(&pnpm, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::hard_link(&pnpm, links.join("pnpm")).unwrap();

        let shadow = PnpmShadowDir::create_if_needed(home.path(), &pnpm)
            .unwrap()
            .expect("hardlinked pnpm needs a shadow");
        let shadow_path = shadow.binary();
        let source_meta = std::fs::metadata(&pnpm).unwrap();
        let shadow_meta = std::fs::metadata(&shadow_path).unwrap();

        assert_ne!(source_meta.ino(), shadow_meta.ino());
        assert_eq!(shadow_meta.permissions().mode() & 0o777, 0o500);
        assert_eq!(
            std::fs::metadata(shadow.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o500
        );
        assert!(shadow.shadows(&pnpm));
        assert!(shadow.shadows(&links.join("pnpm")));
        assert!(!shadow.shadows(&shadow_path));
        let session_path = shadow.path().to_path_buf();
        drop(shadow);
        assert!(!session_path.exists());
    }

    #[test]
    fn pnpm_executed_directly_from_store_always_uses_a_shadow() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let store = home.path().join("Library/pnpm/store/v10/links/package");
        std::fs::create_dir_all(&store).unwrap();
        let pnpm = store.join("pnpm");
        std::fs::write(&pnpm, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&pnpm, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            PnpmShadowDir::create_if_needed(home.path(), &pnpm)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn pnpm_without_store_hardlink_needs_no_shadow() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let pnpm = home.path().join("pnpm");
        std::fs::write(&pnpm, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&pnpm, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            PnpmShadowDir::create_if_needed(home.path(), &pnpm)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn pnpm_shadow_rejects_a_symlinked_base_before_cleanup() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let home = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        symlink(target.path(), home.path().join(PNPM_SHADOW_BASE)).unwrap();

        let global = home.path().join("Library/pnpm/global/v11");
        let links = home.path().join("Library/pnpm/store/v10/links/package");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::create_dir_all(&links).unwrap();
        let pnpm = global.join("pnpm");
        std::fs::write(&pnpm, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&pnpm, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::hard_link(&pnpm, links.join("pnpm")).unwrap();

        let err = PnpmShadowDir::create_if_needed(home.path(), &pnpm)
            .expect_err("a symlinked shadow base must be rejected");
        assert!(err.contains("is a symlink"), "{err}");
        assert!(
            target.path().read_dir().unwrap().next().is_none(),
            "the symlink target must not be traversed or modified"
        );
    }

    #[test]
    fn pnpm_shadow_removes_only_stale_owned_sessions() {
        let home = tempfile::tempdir().unwrap();
        let base = home.path().join(PNPM_SHADOW_BASE);
        create_secure_dir(&base, "pnpm shadow base").unwrap();
        let stale = base.join("0123456789abcdef0123456789abcdef");
        let fresh = base.join("fedcba9876543210fedcba9876543210");
        create_secure_dir(&stale, "stale shadow").unwrap();
        create_secure_dir(&fresh, "fresh shadow").unwrap();
        std::fs::write(stale.join("pnpm"), b"stale").unwrap();
        std::fs::write(fresh.join("pnpm"), b"fresh").unwrap();
        let stale_time = SystemTime::now() - STALE_AGE - Duration::from_secs(1);
        std::fs::File::open(&stale)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(stale_time))
            .unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o500)).unwrap();

        cleanup_stale_pnpm_shadows(home.path()).unwrap();

        assert!(!stale.exists());
        assert!(fresh.exists());
    }

    #[test]
    fn pnpm_shadow_keeps_a_locked_live_session_past_stale_age() {
        let home = tempfile::tempdir().unwrap();
        let base = home.path().join(PNPM_SHADOW_BASE);
        create_secure_dir(&base, "pnpm shadow base").unwrap();
        let live = base.join("0123456789abcdef0123456789abcdef");
        create_secure_dir(&live, "live shadow").unwrap();
        std::fs::write(live.join("pnpm"), b"live").unwrap();
        let live_identity = secure_dir_identity(&live, "live shadow").unwrap();
        let _live_lock = lock_pnpm_shadow_session(&live, live_identity).unwrap();
        let stale_time = SystemTime::now() - STALE_AGE - Duration::from_secs(1);
        std::fs::File::open(&live)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(stale_time))
            .unwrap();
        std::fs::set_permissions(&live, std::fs::Permissions::from_mode(0o500)).unwrap();

        cleanup_stale_pnpm_shadows(home.path()).unwrap();

        assert!(live.exists());
    }

    #[test]
    fn pnpm_shadow_follows_custom_pnpm_home() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let pnpm_home = home.path().join("custom-pnpm");
        let global = pnpm_home.join("global/v11");
        let links = pnpm_home.join("store/v10/links/pnpm-package");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::create_dir_all(&links).unwrap();
        let pnpm = global.join("pnpm");
        std::fs::write(&pnpm, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&pnpm, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::hard_link(&pnpm, links.join("pnpm")).unwrap();

        assert!(
            pnpm_has_store_alias_in(&pnpm, &[pnpm_home.join("store")]).unwrap(),
            "a custom PNPM_HOME store alias must be detected"
        );
    }

    #[test]
    fn pnpm_path_grants_only_non_hardlinked_executables() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let pnpm_home = home.path().join("Library/pnpm");
        let bin = pnpm_home.join("global/bin");
        let store = pnpm_home.join("store/v10/links/package");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&store).unwrap();

        let safe = bin.join("safe-tool");
        let linked = bin.join("linked-tool");
        std::fs::write(&safe, b"#!/bin/sh\n").unwrap();
        std::fs::write(&linked, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&linked, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::hard_link(&linked, store.join("linked-tool")).unwrap();
        let path = std::env::join_paths([&bin]).unwrap();

        let grants = pnpm_path_executables_in(home.path(), &path);

        assert_eq!(grants, vec![safe.canonicalize().unwrap()]);
    }

    #[test]
    fn pnpm_exec_grants_reject_nested_stores_and_external_symlink_targets() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let home = tempfile::tempdir().unwrap();
        let outer = home.path().join("Library/pnpm");
        let nested = outer.join("custom");
        let nested_store = nested.join("store/v10");
        let external = home.path().join("external");
        std::fs::create_dir_all(&nested_store).unwrap();
        std::fs::create_dir_all(&external).unwrap();
        let stored = nested_store.join("pnpm");
        let outside = external.join("pnpm");
        std::fs::write(&stored, b"#!/bin/sh\n").unwrap();
        std::fs::write(&outside, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&stored, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&outside, nested.join("external-pnpm")).unwrap();

        let roots = vec![
            outer.canonicalize().unwrap(),
            nested.canonicalize().unwrap(),
        ];
        assert!(!pnpm_exec_grant_allowed(
            &stored.canonicalize().unwrap(),
            &roots
        ));
        assert!(!pnpm_exec_grant_allowed(
            &nested.join("external-pnpm").canonicalize().unwrap(),
            &roots
        ));
    }

    #[test]
    fn package_manager_store_does_not_need_an_extra_exec_grant() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("Library/pnpm");
        let global = root.join("global/v11/pnpm");
        let managed = root.join("package-manager-store/v10/pnpm");
        std::fs::create_dir_all(global.parent().unwrap()).unwrap();
        std::fs::create_dir_all(managed.parent().unwrap()).unwrap();
        std::fs::write(&global, b"pnpm").unwrap();
        std::fs::write(&managed, b"pnpm").unwrap();

        assert!(pnpm_needs_exec_grant(
            home.path(),
            &global.canonicalize().unwrap()
        ));
        assert!(!pnpm_needs_exec_grant(
            home.path(),
            &managed.canonicalize().unwrap()
        ));
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

    #[cfg(target_os = "macos")]
    #[test]
    fn playwright_socket_dir_has_secure_short_shape_and_cleans_up_exactly() {
        use crate::sandbox::{PLAYWRIGHT_SOCKET_PATH_LIMIT, PLAYWRIGHT_SOCKET_WORST_CASE_SUFFIX};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let guard = PlaywrightSocketDir::create().unwrap();
        let path = guard.path().to_path_buf();
        let sibling = tempfile::Builder::new()
            .prefix("cplt-pw-test-sibling-")
            .tempdir_in(PLAYWRIGHT_SOCKET_ROOT)
            .unwrap();
        std::fs::write(path.join("marker"), b"owned").unwrap();

        assert_eq!(path.parent(), Some(Path::new(PLAYWRIGHT_SOCKET_ROOT)));
        validate_playwright_socket_dir(&path).unwrap();
        let suffix = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
            .strip_prefix(PLAYWRIGHT_SOCKET_DIR_PREFIX)
            .unwrap();
        assert_eq!(suffix.len(), 32);
        assert!(
            suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );

        let metadata = path.symlink_metadata().unwrap();
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), unsafe { libc::getuid() });
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert!(
            path.as_os_str().len() + PLAYWRIGHT_SOCKET_WORST_CASE_SUFFIX.len()
                < PLAYWRIGHT_SOCKET_PATH_LIMIT
        );

        drop(guard);
        assert!(!path.exists());
        assert!(
            sibling.path().exists(),
            "cleanup must not touch sibling directories"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn playwright_socket_dir_collision_preserves_existing_directory() {
        let guard = PlaywrightSocketDir::create().unwrap();
        let path = guard.path().to_path_buf();
        let session_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(PLAYWRIGHT_SOCKET_DIR_PREFIX))
            .unwrap();

        let collision = PlaywrightSocketDir::create_for_session_id(session_id);
        assert!(collision.is_err());
        assert!(path.is_dir(), "collision handling must preserve the owner");

        drop(guard);
        assert!(!path.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn playwright_socket_dir_cleanup_refuses_replaced_path() {
        use std::os::unix::fs::MetadataExt;

        let tmp = tempfile::tempdir().unwrap();
        let guarded_path = tmp.path().join("guarded");
        let original_path = tmp.path().join("original");
        let unrelated = tmp.path().join("unrelated");
        std::fs::create_dir(&guarded_path).unwrap();
        let metadata = guarded_path.symlink_metadata().unwrap();
        std::fs::rename(&guarded_path, &original_path).unwrap();
        std::fs::create_dir(&unrelated).unwrap();
        std::os::unix::fs::symlink(&unrelated, &guarded_path).unwrap();

        let guard = PlaywrightSocketDir {
            path: guarded_path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        drop(guard);

        assert!(guarded_path.is_symlink());
        assert!(original_path.is_dir());
        assert!(unrelated.is_dir());
    }
}
