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
    device: u64,
    inode: u64,
    /// Shared `flock` on [`SESSION_MARKER`] while the session runs, so
    /// [`ScratchDir::gc_stale`] can tell a live session from an orphan.
    _lock: Option<std::fs::File>,
}

/// Lock file marking a scratch dir whose session holds a lock while it runs.
/// Dirs without it (older cplt, or a failed lock) are left to the 24h sweep.
const SESSION_MARKER: &str = ".cplt-session";

/// gh token caches cplt writes into the scratch dir (see `sandbox_exec`).
const GH_TOKEN_FILES: [&str; 2] = [".gh-exec-token", ".gh-token"];

/// A read-only executable copy of pnpm outside its writable store.
///
/// pnpm's standalone executable can be hardlinked into
/// `$PNPM_HOME/store/v*/links/**/pnpm` (pnpm 11 nests it 7 levels deep). The kernel then evaluates execution
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
    store_device: u64,
    store_inode: u64,
    _lock: std::fs::File,
}

impl PnpmShadowDir {
    /// Copy `pnpm` when it shares an inode with a pnpm store hardlink, or is
    /// a launcher whose target lies in a pnpm home (#936).
    ///
    /// When `launch_dir` pins another exact pnpm version that is already in
    /// the store, shadow that binary instead (#890). pnpm 11 would otherwise
    /// switch by spawning it straight from the non-executable store.
    pub fn create_if_needed(
        home_dir: &Path,
        pnpm: &Path,
        launch_dir: &Path,
    ) -> Result<Option<Self>, String> {
        ensure_pnpm_package_manager_stores(home_dir)?;
        // pnpm 11 puts a `/bin/sh` launcher on PATH that execs the real
        // binary, a symlink into the store. Shadow the binary; `source`
        // stays the PATH entry so direct launches still map to the shadow.
        let pinned = pinned_pnpm_binary(home_dir, launch_dir)
            .and_then(|binary| pnpm_store_binary_source(home_dir, &binary).ok().flatten());
        let Some(source) =
            pinned.map_or_else(|| pnpm_shadow_source(home_dir, pnpm), |s| Ok(Some(s)))?
        else {
            return Ok(None);
        };
        use std::os::unix::fs::MetadataExt;
        let entry = std::fs::metadata(pnpm)
            .map_err(|e| format!("Cannot inspect pnpm executable {}: {e}", pnpm.display()))?;
        let store = source
            .file
            .metadata()
            .map_err(|e| format!("Cannot inspect pnpm store binary: {e}"))?;

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
        if let Err(error) = copy_executable(&source.file, &shadow) {
            let _ = std::fs::remove_dir_all(&session_dir);
            return Err(error);
        }
        // @pnpm/exe 11 loads `dist/pnpm.mjs` next to its executable. Link it
        // read-only: Seatbelt and Landlock check exec on the resolved store
        // path, so nothing under it becomes executable.
        if let Some(dist) = source
            .path
            .parent()
            .map(|dir| dir.join("dist"))
            .filter(|dist| dist.is_dir())
            && let Err(error) = std::os::unix::fs::symlink(&dist, session_dir.join("dist"))
        {
            let _ = std::fs::remove_dir_all(&session_dir);
            return Err(format!("Cannot link pnpm dist into shadow: {error}"));
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
            source_device: entry.dev(),
            source_inode: entry.ino(),
            store_device: store.dev(),
            store_inode: store.ino(),
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

    /// The shadow to run for `cplt exec -- <requested>` resolved to `path`.
    ///
    /// A command named `pnpm` that resolves to the PATH entry, or any name
    /// (an alias such as `pn`) that resolves to the store binary the shadow
    /// copies. A multicall shim such as mise's serves `node` from the PATH
    /// entry's inode, so other names on that inode keep their own binary.
    pub fn binary_for(&self, requested: &str, path: &Path) -> Option<PathBuf> {
        use std::os::unix::fs::MetadataExt;

        let is_store = std::fs::metadata(path).is_ok_and(|metadata| {
            metadata.is_file()
                && metadata.dev() == self.store_device
                && metadata.ino() == self.store_inode
        });
        (is_store
            || Path::new(requested).file_name() == Some("pnpm".as_ref()) && self.shadows(path))
        .then(|| self.binary())
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

fn copy_executable(mut source: &std::fs::File, destination: &Path) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut destination_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(destination)
        .map_err(|e| format!("Cannot create pnpm shadow {}: {e}", destination.display()))?;
    std::io::copy(&mut source, &mut destination_file)
        .map_err(|e| format!("Cannot copy pnpm executable into shadow: {e}"))?;
    destination_file
        .sync_all()
        .map_err(|e| format!("Cannot sync pnpm shadow {}: {e}", destination.display()))?;
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o500))
        .map_err(|e| format!("Cannot set pnpm shadow permissions: {e}"))
}

/// The store binary pnpm runs from, opened once so the shadow copies exactly
/// what was checked.
pub struct PnpmShadowSource {
    /// Symlink-free path the file was opened at.
    pub path: PathBuf,
    file: std::fs::File,
}

/// The binary pnpm must run from a read-only shadow, or `None` if it runs
/// from its own inode. Follows a pnpm 11 cmd-shim launcher to the binary it
/// execs. The binary can live in the sandbox-writable store, so it is opened
/// without following a symlink in any component, checked on that fd, and
/// refused unless it is a Mach-O or ELF executable.
pub fn pnpm_shadow_source(
    home_dir: &Path,
    pnpm: &Path,
) -> Result<Option<PnpmShadowSource>, String> {
    let Some(binary) = pnpm_cmd_shim_target(home_dir, pnpm) else {
        return pnpm_store_binary_source(home_dir, pnpm);
    };
    // The shim target is already confined to a pnpm home, which the sandbox
    // keeps read-only and non-executable outside `package-manager-store/`.
    // pnpm can install it as a plain file with no store alias, under
    // `global/v11/<hash>/...` (#936), so shadow it like a store binary.
    let roots: Vec<PathBuf> = pnpm_home_roots(home_dir)
        .into_iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect();
    pnpm_shadow_source_in(&binary, &roots, true)
}

/// [`pnpm_shadow_source`] for a path already known to be the binary, so no
/// shim probe runs on it.
fn pnpm_store_binary_source(
    home_dir: &Path,
    binary: &Path,
) -> Result<Option<PnpmShadowSource>, String> {
    let roots: Vec<PathBuf> = pnpm_home_roots(home_dir)
        .into_iter()
        .filter_map(|root| std::fs::canonicalize(root.join("store")).ok())
        .collect();
    pnpm_shadow_source_in(binary, &roots, false)
}

/// With `in_pnpm_home`, `roots` are canonical pnpm homes and the opened path
/// only has to lie inside one, not alias the store (a cmd-shim target).
/// Containment is checked on the path opened with no symlink in any
/// component, so a link swapped into the writable store after the shim
/// check cannot steer the copy outside the roots. Every other check runs.
fn pnpm_shadow_source_in(
    binary: &Path,
    roots: &[PathBuf],
    in_pnpm_home: bool,
) -> Result<Option<PnpmShadowSource>, String> {
    use std::os::unix::fs::FileExt;

    let path = std::fs::canonicalize(binary)
        .map_err(|e| format!("Cannot resolve pnpm executable {}: {e}", binary.display()))?;
    let file = open_no_symlinks(&path)
        .map_err(|e| format!("Cannot open pnpm executable {}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("Cannot inspect pnpm executable {}: {e}", path.display()))?;
    let contained = if in_pnpm_home {
        roots.iter().any(|root| path.starts_with(root))
    } else {
        pnpm_has_store_alias_in(&path, &meta, roots)
    };
    if !meta.is_file() || !contained {
        return Ok(None);
    }
    let mut magic = [0u8; 4];
    let read = file
        .read_at(&mut magic, 0)
        .map_err(|e| format!("Cannot read pnpm executable {}: {e}", path.display()))?;
    const BINARY_MAGIC: [[u8; 4]; 6] = [
        *b"\x7fELF",
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xfe, 0xed, 0xfa, 0xce],
        [0xca, 0xfe, 0xba, 0xbe],
    ];
    // Never copy anything else out of the store: a script such as the
    // `pnpm.mjs` the JS package's launcher hands to node needs no shadow,
    // and a planted link to a secret must not land in one.
    if read < magic.len() || !BINARY_MAGIC.contains(&magic) {
        return Ok(None);
    }
    Ok(Some(PnpmShadowSource { path, file }))
}

/// Open read-only, failing on a symlink in any path component.
/// `O_NONBLOCK` so a FIFO swapped in by the sandbox opens at once and fails
/// the caller's regular-file check instead of hanging.
fn open_no_symlinks(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(target_os = "linux")]
    {
        crate::sandbox::openat2_no_symlinks(
            libc::AT_FDCWD,
            path,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
        .map(std::fs::File::from)
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW_ANY | libc::O_NONBLOCK)
            .open(path)
    }
}

/// The store binary of the exact pnpm version pinned by the nearest
/// `package.json` with a `packageManager` field, if pnpm already put it in
/// the store. pnpm 11 switches to that binary in place, from
/// `store/v*/links/@pnpm/exe/<version>/<hash>/node_modules/@pnpm/exe/pnpm`.
pub fn pinned_pnpm_binary(home_dir: &Path, launch_dir: &Path) -> Option<PathBuf> {
    let pin = launch_dir.ancestors().find_map(|dir| {
        // Read before the sandbox exists: refuse a FIFO or device and cap
        // the size, so a planted `package.json` cannot hang every launch.
        let manifest =
            crate::untrusted::read_regular_following(&dir.join("package.json"), 1 << 20).ok()??;
        let manifest: serde_json::Value = serde_json::from_str(&manifest).ok()?;
        Some(manifest.get("packageManager")?.as_str()?.to_owned())
    })?;
    let version = pin.strip_prefix("pnpm@")?.split('+').next()?;
    // An exact version is one path component, never `..` or a separator.
    if !version.starts_with(|c: char| c.is_ascii_digit())
        || !version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return None;
    }
    for root in pnpm_home_roots(home_dir) {
        let Ok(stores) = std::fs::read_dir(root.join("store")) else {
            continue;
        };
        for store in stores.flatten() {
            let Ok(hashes) = std::fs::read_dir(store.path().join("links/@pnpm/exe").join(version))
            else {
                continue;
            };
            let mut hashes: Vec<PathBuf> = hashes.flatten().map(|hash| hash.path()).collect();
            hashes.sort();
            if let Some(binary) = hashes
                .into_iter()
                .map(|hash| hash.join("node_modules/@pnpm/exe/pnpm"))
                .find(|binary| binary.is_file())
            {
                return Some(binary);
            }
        }
    }
    None
}

/// The binary a pnpm cmd-shim launcher execs, when it lies in a pnpm home.
///
/// pnpm writes `$PNPM_HOME/bin/pnpm` as a small `/bin/sh` script ending in
/// `# cmd-shim-target=<path>`, absolute or relative to the shim. Anything
/// else returns `None`.
pub fn pnpm_cmd_shim_target(home_dir: &Path, pnpm: &Path) -> Option<PathBuf> {
    let roots: Vec<PathBuf> = pnpm_home_roots(home_dir)
        .into_iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect();
    pnpm_cmd_shim_target_in(pnpm, &roots)
}

fn pnpm_cmd_shim_target_in(pnpm: &Path, roots: &[PathBuf]) -> Option<PathBuf> {
    // The agent can swap a FIFO in for the shim; this read is unsandboxed.
    let script = crate::untrusted::read_regular_following(pnpm, 4096).ok()??;
    if !script.starts_with("#!/bin/sh") {
        return None;
    }
    let target = script
        .lines()
        .find_map(|line| line.strip_prefix("# cmd-shim-target="))
        .map(PathBuf::from)?;
    // A shim inside a relocatable root, such as the default PNPM_HOME, names
    // its target relative to the shim's real directory (#936).
    let shim_dir = std::fs::canonicalize(pnpm).ok()?.parent()?.to_path_buf();
    let target = std::fs::canonicalize(shim_dir.join(target)).ok()?;
    (target.is_file() && roots.iter().any(|root| target.starts_with(root))).then_some(target)
}

fn pnpm_has_store_alias_in(pnpm: &Path, source: &std::fs::Metadata, roots: &[PathBuf]) -> bool {
    use std::os::unix::fs::MetadataExt;

    for root in roots {
        if pnpm.starts_with(root) {
            return true;
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
            if store_links_contain_inode(&version.path().join("links"), 0, source) {
                return true;
            }
        }
    }
    false
}

/// Directory levels below `links/` to search. pnpm 11 nests the binary at
/// `links/@pnpm/exe/<version>/<hash>/node_modules/@pnpm/exe/pnpm` (7 levels).
const PNPM_LINKS_MAX_DEPTH: usize = 8;

/// Bounded walk for a regular file named `pnpm` sharing `source`'s inode.
/// Symlinks are never followed: `DirEntry::file_type` does not resolve them.
fn store_links_contain_inode(dir: &Path, depth: usize, source: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    if depth > PNPM_LINKS_MAX_DEPTH {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if store_links_contain_inode(&entry.path(), depth + 1, source) {
                return true;
            }
        } else if file_type.is_file()
            && entry.file_name() == "pnpm"
            && entry
                .metadata()
                .is_ok_and(|m| m.dev() == source.dev() && m.ino() == source.ino())
        {
            return true;
        }
    }
    false
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

        // SAFETY: both descriptors and C strings are valid for the calls. All
        // operations are anchored to the validated directory descriptors, so
        // replacing the base pathname cannot redirect cleanup elsewhere.
        // `dist` is a symlink; unlinkat removes the link, not its target.
        for entry in [c"pnpm", c"dist"] {
            unsafe {
                libc::unlinkat(child.as_raw_fd(), entry.as_ptr(), 0);
            }
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

/// [`pnpm_home_roots`] for `home_dir` and for the literal `env_home`.
///
/// `home_dir` is canonical, but `pnpm setup` writes `PNPM_HOME` with the
/// `$HOME` it saw, and its rc block compares PATH entries as strings. When
/// `$HOME` is a symlink only the literal spelling matches.
pub fn pnpm_path_roots(home_dir: &Path, env_home: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = pnpm_home_roots(home_dir);
    if let Some(home) = env_home.filter(|h| h.is_absolute() && *h != home_dir) {
        roots.extend(pnpm_home_roots(home));
    }
    roots.sort();
    roots.dedup();
    roots
}

/// Whether the launch dir pins a pnpm already in the store, which cplt
/// shadows instead of whatever pnpm is on PATH (#890).
pub fn pinned_pnpm_shadow_applies(home_dir: &Path, launch_dir: &Path) -> bool {
    pinned_pnpm_binary(home_dir, launch_dir)
        .is_some_and(|binary| matches!(pnpm_store_binary_source(home_dir, &binary), Ok(Some(_))))
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

        let (device, inode) = match secure_dir_identity(&session_dir, "scratch dir") {
            Ok(identity) => identity,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&session_dir);
                return Err(error);
            }
        };

        // Validate for SBPL injection before we use it in profile generation
        if let Err(e) = validate_sbpl_path(&session_dir) {
            let _ = std::fs::remove_dir_all(&session_dir);
            return Err(format!("Scratch dir path unsafe: {e}"));
        }

        let lock = lock_session(&session_dir);
        Ok(ScratchDir {
            path: session_dir,
            device,
            inode,
            _lock: lock,
        })
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

        // A session that crashed or was killed never ran `Drop`, so its gh
        // token cache would sit on disk until the 24h sweep. Remove it now
        // when the dir is marked and its lock is free. Unmarked dirs may be
        // live sessions of an older cplt: leave them alone.
        let held = session_lock_held(&path);
        if held == Some(false) {
            for file in GH_TOKEN_FILES {
                let _ = std::fs::remove_file(path.join(file));
            }
        }

        // Check age via directory modification time
        let Ok(modified) = metadata.modified() else {
            continue;
        };

        if let Ok(age) = now.duration_since(modified)
            && age > STALE_AGE
            && held != Some(true)
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.uid() != unsafe { libc::getuid() } {
                continue;
            }
            if let Ok(dir) = open_dir_nofollow(&path) {
                let _ = dir.set_permissions(std::fs::Permissions::from_mode(0o700));
            }
            if let Err(e) = remove_tree(&path) {
                ui::warn(&format!(
                    "Warning: cannot remove stale scratch dir {}: {e}",
                    path.display()
                ));
            }
        }
    }
}

/// Remove directories in `base` whose name passes `name_ok` and whose mtime is
/// older than `max_age`. Same rules as [`gc_stale_session_dirs`]: no symlinks,
/// real directories only, owned by us. Best-effort, one `readdir`.
pub(crate) fn sweep_old_dirs(base: &Path, name_ok: impl Fn(&str) -> bool, max_age: Duration) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != unsafe { libc::getuid() }
            || !entry.file_name().to_str().is_some_and(&name_ok)
        {
            continue;
        }
        let old = metadata
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age > max_age);
        if old {
            if let Ok(dir) = open_dir_nofollow(&path) {
                let _ = dir.set_permissions(std::fs::Permissions::from_mode(0o700));
            }
            let _ = remove_tree(&path);
        }
    }
}

/// Socket dirs left behind by a killed session (Drop never ran).
#[cfg(target_os = "macos")]
const SOCKET_STALE_AGE: Duration = Duration::from_hours(24 * 7);

/// Our socket-dir name, and no running session holds its lock: a live
/// session keeps its dir however old it is.
#[cfg(target_os = "macos")]
fn socket_dir_sweepable(root: &Path, name: &str) -> bool {
    name.strip_prefix(PLAYWRIGHT_SOCKET_DIR_PREFIX)
        .is_some_and(is_session_id)
        && session_lock_held(&root.join(name)) != Some(true)
}

/// Create [`SESSION_MARKER`] in `dir` and hold a shared lock on it. On
/// failure the marker is removed, so launches never treat the dir as orphaned.
fn lock_session(dir: &Path) -> Option<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `f` owns a valid descriptor; the lock lives as long as it.
    lock_session_with(dir, |f| unsafe {
        libc::flock(f.as_raw_fd(), libc::LOCK_SH) == 0
    })
}

fn lock_session_with(dir: &Path, flock: impl Fn(&std::fs::File) -> bool) -> Option<std::fs::File> {
    let marker = dir.join(SESSION_MARKER);
    let locked = std::fs::File::create(&marker).ok().filter(|f| flock(f));
    if locked.is_none() {
        let _ = std::fs::remove_file(&marker);
        ui::warn(
            "Warning: cannot lock the scratch dir; stale gh token caches are left to the 24-hour cleanup.",
        );
    }
    locked
}

/// `None`: the dir has no session marker. `Some(true)`: a running cplt holds
/// it. `Some(false)`: marked and unlocked, so its session is gone.
fn session_lock_held(dir: &Path) -> Option<bool> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    // The agent can write the scratch dir: never follow a symlink, and never
    // block on a FIFO it left in place of the marker.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join(SESSION_MARKER))
        .ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    // SAFETY: `f` owns a valid descriptor; the lock is released when it drops.
    Some(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0)
}

/// A short, random, per-session macOS directory for Playwright control sockets.
///
/// The directory is deliberately independent of [`ScratchDir`]: it remains
/// available when scratch execution is disabled and receives socket-only SBPL
/// rules. The guard must outlive every sandboxed child that uses its path.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct SessionSocketDir {
    path: PathBuf,
    device: u64,
    inode: u64,
    _lock: Option<std::fs::File>,
}

#[cfg(target_os = "macos")]
impl SessionSocketDir {
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
        sweep_old_dirs(root, |n| socket_dir_sweepable(root, n), SOCKET_STALE_AGE);

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

        let lock = lock_session(&path);
        Ok(Self {
            path,
            device,
            inode,
            _lock: lock,
        })
    }

    /// Exact validated directory authorized by the generated SBPL profile.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(target_os = "macos")]
impl Drop for SessionSocketDir {
    fn drop(&mut self) {
        remove_owned_dir(&self.path, self.device, self.inode, "Playwright socket dir");
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        remove_owned_dir(&self.path, self.device, self.inode, "scratch dir");
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
pub(crate) fn is_session_id(name: &str) -> bool {
    name.len() == 32 && name.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate that a directory is safe to use as scratch base.
///
/// Checks:
/// - Is a directory (not a symlink to one)
/// - Owned by current user
/// - Permissions are 0700 (set if not)
fn open_dir_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let open_rdonly = || {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    };
    match open_rdonly() {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            if chmod_700_nofollow(path).is_ok() {
                return open_rdonly();
            }
            Err(e)
        }
        Err(e) => Err(e),
    }
}

/// `chmod 0700` on `path` itself, never on what a link there points to.
fn chmod_700_nofollow(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let rc = unsafe {
            libc::fchmodat(
                libc::AT_FDCWD,
                c_path.as_ptr(),
                0o700,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    // Linux: an O_PATH fd on the entry itself (a link fails O_DIRECTORY),
    // then chmod through /proc, which reaches that inode and nothing else.
    // Portable where fchmodat's AT_SYMLINK_NOFOLLOW is not (glibc < 2.32).
    #[cfg(not(target_os = "macos"))]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        use std::os::unix::io::AsRawFd;
        let fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        std::fs::set_permissions(
            format!("/proc/self/fd/{}", fd.as_raw_fd()),
            std::fs::Permissions::from_mode(0o700),
        )
    }
}

pub(crate) fn validate_dir_safety(path: &Path, label: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;

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

    let dir_file =
        open_dir_nofollow(path).map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
    let fd_meta = dir_file
        .metadata()
        .map_err(|e| format!("Cannot fstat {}: {e}", path.display()))?;
    if fd_meta.dev() != metadata.dev() || fd_meta.ino() != metadata.ino() {
        return Err(format!(
            "{label} {} was replaced during validation",
            path.display()
        ));
    }
    if fd_meta.uid() != my_uid {
        return Err(format!(
            "{label} {} is owned by uid {}, expected {}. cplt refuses to use it",
            path.display(),
            fd_meta.uid(),
            my_uid
        ));
    }

    // Ensure permissions are 0700 on the verified fd to avoid path TOCTOU
    let mode = fd_meta.mode() & 0o777;
    if mode != 0o700 && unsafe { libc::fchmod(dir_file.as_raw_fd(), 0o700) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(format!("Cannot set permissions on {}: {e}", path.display()));
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

pub(crate) fn secure_dir_identity(path: &Path, label: &str) -> Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt;

    validate_dir_safety(path, label)?;
    let metadata = path
        .symlink_metadata()
        .map_err(|e| format!("Cannot stat {}: {e}", path.display()))?;
    Ok((metadata.dev(), metadata.ino()))
}

pub(crate) fn remove_owned_dir(
    path: &Path,
    expected_device: u64,
    expected_inode: u64,
    label: &str,
) {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;

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
    let Ok(dir_file) = open_dir_nofollow(path) else {
        ui::warn(&format!(
            "Warning: cannot open {label} {} during cleanup",
            path.display()
        ));
        return;
    };
    let Ok(fd_meta) = dir_file.metadata() else {
        return;
    };
    if fd_meta.dev() != expected_device || fd_meta.ino() != expected_inode {
        ui::warn(&format!(
            "Warning: refusing to cleanup replaced {label} {}",
            path.display()
        ));
        return;
    }
    if unsafe { libc::fchmod(dir_file.as_raw_fd(), 0o700) } != 0 {
        let error = std::io::Error::last_os_error();
        ui::warn(&format!(
            "Warning: cannot make {label} {} removable during cleanup: {error}",
            path.display()
        ));
        return;
    }
    drop(dir_file);
    if let Err(error) = remove_tree(path) {
        ui::warn(&format!(
            "Warning: cannot cleanup {label} {}: {error}",
            path.display()
        ));
    }
}

/// `remove_dir_all`, retrying once after giving the owner rwx on every real
/// directory below `dir`. Tools run in the sandbox (Go's module cache, for
/// one) leave read-only dirs behind. The walk only runs on EACCES, so a
/// large `node_modules` costs no extra chmods in the common case.
fn remove_tree(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            make_subdirs_removable(dir);
            std::fs::remove_dir_all(dir)
        }
        other => other,
    }
}

/// Never follows symlinks at any depth: the walk is fd-relative. Each child
/// is opened with `openat(parent, name, O_DIRECTORY|O_NOFOLLOW)`, listed
/// through `fdopendir` and chmodded with `fchmod`, so swapping any dir in the
/// tree for a symlink cannot steer the walk outside the scratch dir.
fn make_subdirs_removable(dir: &Path) {
    if let Ok(top) = open_dir_nofollow(dir) {
        chmod_subdirs_at(&top);
    }
}

fn chmod_subdirs_at(dir: &std::fs::File) {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    // fdopendir takes ownership of the fd it gets, so hand it a dup.
    let dup = unsafe { libc::dup(dir.as_raw_fd()) };
    if dup < 0 {
        return;
    }
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        unsafe { libc::close(dup) };
        return;
    }
    let mut names = Vec::new();
    loop {
        let ent = unsafe { libc::readdir(stream) };
        if ent.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_owned());
        }
    }
    unsafe { libc::closedir(stream) };

    for name in names {
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            continue; // not a dir, a symlink, or unreadable
        }
        // SAFETY: `fd` is a fresh descriptor this File now owns.
        let child = unsafe { std::fs::File::from_raw_fd(fd) };
        if let Ok(meta) = child.metadata() {
            let mode = meta.permissions().mode() | 0o700;
            let _ = child.set_permissions(std::fs::Permissions::from_mode(mode));
            chmod_subdirs_at(&child);
        }
    }
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn age(path: &std::path::Path, by: std::time::Duration) {
        let t = std::time::SystemTime::now() - by;
        std::fs::File::open(path).unwrap().set_modified(t).unwrap();
    }

    /// Set the link's own mtime, not its target's.
    fn age_link(path: &std::path::Path, by: std::time::Duration) {
        use std::os::unix::ffi::OsStrExt;
        let secs = (std::time::SystemTime::now() - by)
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let tv = libc::timeval {
            tv_sec: secs as libc::time_t,
            tv_usec: 0,
        };
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::lutimes(c.as_ptr(), [tv, tv].as_ptr()) }, 0);
    }

    fn check_sweep(
        old_name: &str,
        fresh_name: &str,
        held_name: Option<&str>,
        filter: impl Fn(&Path, &str) -> bool,
        max: Duration,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("keep");
        std::fs::create_dir(&target).unwrap();
        let dir = |n: &str| {
            let d = tmp.path().join(n);
            std::fs::create_dir(&d).unwrap();
            d
        };
        let (old, fresh, unmatched) = (dir(old_name), dir(fresh_name), dir("not-ours"));
        std::fs::write(old.join("f"), "x").unwrap();
        let held = held_name.map(dir);
        let _lock = held.as_deref().map(lock_session);
        // A name the filter accepts, so only the no-follow check protects it.
        let link = tmp.path().join(old_name.replace('a', "b"));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        for d in [&old, &unmatched, &target].into_iter().chain(held.as_ref()) {
            age(d, max * 2);
        }
        age_link(&link, max * 2);
        sweep_old_dirs(tmp.path(), |n| filter(tmp.path(), n), max);
        assert!(!old.exists(), "old dir removed");
        assert!(fresh.exists(), "fresh dir kept");
        assert!(unmatched.exists(), "old dir with a foreign name kept");
        assert!(held.is_none_or(|h| h.exists()), "dir with a held lock kept");
        assert!(
            target.exists() && link.symlink_metadata().is_ok(),
            "link target untouched"
        );
    }

    #[test]
    fn sweep_removes_old_update_staging_dirs() {
        let id = |c: char| c.to_string().repeat(32);
        let f = |_: &Path, n: &str| is_session_id(n);
        check_sweep(&id('a'), &id('c'), None, f, Duration::from_hours(24));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sweep_removes_old_socket_dirs() {
        let id = |c: char| format!("cplt-pw-{}", c.to_string().repeat(32));
        check_sweep(
            &id('a'),
            &id('c'),
            Some(&id('d')),
            socket_dir_sweepable,
            SOCKET_STALE_AGE,
        );
    }

    #[test]
    fn the_eacces_chmod_never_follows_a_link() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let _ = super::chmod_700_nofollow(&link);
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        // A plain dir is still fixed.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000)).unwrap();
        super::chmod_700_nofollow(&target).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

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

    /// A crashed session's gh token cache goes at the next start. A live
    /// session's stays, and so does an unmarked dir's (an older cplt that
    /// takes no lock may still be using it). `Drop` takes the rest.
    #[test]
    fn gc_removes_orphaned_gh_token_caches_only() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let live = ScratchDir::create(&home).unwrap();
        let new_dir = || {
            let d = ScratchDir::base(&home).join(generate_session_id().unwrap());
            std::fs::create_dir(&d).unwrap();
            d
        };
        // Crashed session: marked, nobody holds the lock.
        let orphan = new_dir();
        std::fs::write(orphan.join(SESSION_MARKER), "").unwrap();
        // Older cplt (or failed lock): no marker.
        let unmarked = new_dir();
        for dir in [live.path(), orphan.as_path(), unmarked.as_path()] {
            for f in GH_TOKEN_FILES {
                std::fs::write(dir.join(f), "x").unwrap();
            }
        }
        ScratchDir::gc_stale(&home);
        for f in GH_TOKEN_FILES {
            assert!(live.path().join(f).exists(), "live {f} kept");
            assert!(unmarked.join(f).exists(), "unmarked {f} kept");
            assert!(!orphan.join(f).exists(), "orphan {f} removed");
        }
        let live_path = live.path().to_path_buf();
        drop(live);
        assert!(!live_path.exists(), "Drop removes the session dir");
    }

    /// A failed lock leaves no marker, so later launches skip the dir.
    #[test]
    fn failed_session_lock_leaves_no_marker() {
        let dir = tempfile::tempdir().unwrap();
        assert!(lock_session_with(dir.path(), |_| false).is_none());
        assert!(!dir.path().join(SESSION_MARKER).exists());
        assert_eq!(session_lock_held(dir.path()), None);
        let ok = tempfile::tempdir().unwrap();
        let _lock = lock_session(ok.path()).unwrap();
        assert_eq!(session_lock_held(ok.path()), Some(true));
    }

    /// A FIFO or symlink planted as the marker is ignored, without blocking.
    #[test]
    fn planted_marker_is_ignored() {
        let fifo = tempfile::tempdir().unwrap();
        let path = std::ffi::CString::new(
            fifo.path()
                .join(SESSION_MARKER)
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        // SAFETY: valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert_eq!(session_lock_held(fifo.path()), None);

        let link = tempfile::tempdir().unwrap();
        let target = link.path().join("target");
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, link.path().join(SESSION_MARKER)).unwrap();
        assert_eq!(session_lock_held(link.path()), None);
    }

    /// The 24h sweep spares a dir whose session still holds the lock.
    #[test]
    fn gc_sweep_skips_locked_old_dirs() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let live = ScratchDir::create(&home).unwrap();
        let old = std::time::SystemTime::now() - STALE_AGE - Duration::from_secs(60);
        std::fs::File::open(live.path())
            .unwrap()
            .set_modified(old)
            .unwrap();
        ScratchDir::gc_stale(&home);
        assert!(live.path().exists());
    }

    #[test]
    fn scratch_dir_creates_and_cleans_up() {
        let tmp = tempfile::env::temp_dir().join("cplt-test-scratch");
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
        let tmp = tempfile::env::temp_dir().join("cplt-test-symlink");
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
        let tmp = tempfile::env::temp_dir().join("cplt-test-ancestor-symlink");
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
    fn pnpm_11_launcher_shadows_the_store_binary_it_execs() {
        use std::os::unix::fs::PermissionsExt;

        // Layout written by `pnpm add --global @pnpm/exe@11.5.1`.
        let home = tempfile::tempdir().unwrap();
        let pnpm_home = home.path().join("Library/pnpm");
        let exe =
            pnpm_home.join("store/v11/links/@pnpm/exe/11.5.1/6d9e6c9c/node_modules/@pnpm/exe");
        let modules = pnpm_home.join("global/v11/4c2a-1a17dcdd4ea/node_modules/@pnpm");
        let bin = pnpm_home.join("bin");
        for dir in [&exe.join("dist"), &modules, &bin] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(exe.join("pnpm"), b"\xcf\xfa\xed\xfe").unwrap();
        std::fs::write(exe.join("dist/pnpm.mjs"), b"").unwrap();
        std::os::unix::fs::symlink(&exe, modules.join("exe")).unwrap();
        let target = modules.join("exe/pnpm");
        let launcher = bin.join("pnpm");
        std::fs::write(
            &launcher,
            format!(
                "#!/bin/sh\nbasedir=$(dirname \"$(echo \"$0\" | sed -e 's,\\\\,/,g')\")\n\n\
                 exec \"$basedir/../global/v11/4c2a-1a17dcdd4ea/node_modules/@pnpm/exe/pnpm\"   \"$@\"\n\
                 exit $?\n# cmd-shim-target={}\n",
                target.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();

        let shadow = PnpmShadowDir::create_if_needed(home.path(), &launcher, home.path())
            .unwrap()
            .expect("a launcher into the store needs a shadow");
        assert_eq!(std::fs::read(shadow.binary()).unwrap(), b"\xcf\xfa\xed\xfe");
        assert!(shadow.path().join("dist/pnpm.mjs").exists());
        assert!(shadow.shadows(&launcher));
        let session_path = shadow.path().to_path_buf();
        drop(shadow);
        assert!(!session_path.exists());
        assert!(
            exe.join("dist/pnpm.mjs").exists(),
            "cleanup must not follow dist"
        );
    }

    #[test]
    fn pnpm_shadow_uses_the_version_the_project_pins() {
        // #890: pnpm 11 switches to a pinned version by spawning it from the
        // store. Shadow that version so no switch is needed.
        let home = tempfile::tempdir().unwrap();
        let links = home.path().join("Library/pnpm/store/v11/links");
        let global = links.join("@pnpm/exe/11.26.0/aaaa/node_modules/@pnpm/exe");
        let pinned = links.join("@pnpm/exe/11.25.0/bbbb/node_modules/@pnpm/exe");
        for dir in [&global, &pinned.join("dist")] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(global.join("pnpm"), b"\xcf\xfa\xed\xfeglobal").unwrap();
        std::fs::write(pinned.join("pnpm"), b"\xcf\xfa\xed\xfepinned").unwrap();
        let project = home.path().join("project");
        std::fs::create_dir_all(project.join("sub")).unwrap();
        let shadow_bytes = |pin: &str| {
            std::fs::write(
                project.join("package.json"),
                format!(r#"{{"packageManager":"{pin}"}}"#),
            )
            .unwrap();
            let shadow = PnpmShadowDir::create_if_needed(
                home.path(),
                &global.join("pnpm"),
                &project.join("sub"),
            )
            .unwrap()
            .unwrap();
            assert!(shadow.shadows(&global.join("pnpm")));
            std::fs::read(shadow.binary()).unwrap()
        };

        assert_eq!(
            shadow_bytes("pnpm@11.25.0+sha512.abc"),
            b"\xcf\xfa\xed\xfepinned"
        );
        // Not in the store, a range, another tool, or a path: keep PATH pnpm.
        for pin in [
            "pnpm@11.24.0",
            "pnpm@^11",
            "yarn@11.25.0",
            "pnpm@../../../x",
        ] {
            assert_eq!(shadow_bytes(pin), b"\xcf\xfa\xed\xfeglobal", "{pin}");
        }
        // A multicall shim (mise) serves pnpm and node from one inode; an
        // alias such as `pn` names the pinned store binary itself.
        std::fs::write(
            project.join("package.json"),
            r#"{"packageManager":"pnpm@11.25.0"}"#,
        )
        .unwrap();
        let mise = home.path().join("mise");
        std::fs::write(&mise, b"\xcf\xfa\xed\xfemise").unwrap();
        let shadow = PnpmShadowDir::create_if_needed(home.path(), &mise, &project)
            .unwrap()
            .unwrap();
        assert_eq!(
            shadow.binary_for("shims/pnpm", &mise),
            Some(shadow.binary())
        );
        assert_eq!(shadow.binary_for("shims/node", &mise), None);
        assert_eq!(
            shadow.binary_for("pn", &pinned.join("pnpm")),
            Some(shadow.binary())
        );
        drop(shadow);
        // Never copy a pinned file that is not a binary.
        std::fs::write(pinned.join("pnpm"), b"#!/bin/sh\n").unwrap();
        assert_eq!(shadow_bytes("pnpm@11.25.0"), b"\xcf\xfa\xed\xfeglobal");
    }

    #[test]
    fn pinned_pnpm_ignores_a_fifo_or_device_package_json() {
        let home = tempfile::tempdir().unwrap();
        let fifo = home.path().join("fifo");
        std::fs::create_dir_all(&fifo).unwrap();
        let c = std::ffi::CString::new(fifo.join("package.json").as_os_str().as_encoded_bytes())
            .unwrap();
        // SAFETY: `c` is a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let zero = home.path().join("zero");
        std::fs::create_dir_all(&zero).unwrap();
        std::os::unix::fs::symlink("/dev/zero", zero.join("package.json")).unwrap();
        for dir in [&fifo, &zero] {
            assert_eq!(pinned_pnpm_binary(home.path(), dir), None);
        }
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
        std::fs::write(&pnpm, b"\xcf\xfa\xed\xfe").unwrap();
        std::fs::set_permissions(&pnpm, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::hard_link(&pnpm, links.join("pnpm")).unwrap();

        let shadow = PnpmShadowDir::create_if_needed(home.path(), &pnpm, home.path())
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
        // An alias to the store binary still runs the shadow.
        assert_eq!(
            shadow.binary_for("pn", &links.join("pnpm")),
            Some(shadow_path.clone())
        );
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
        std::fs::write(&pnpm, b"\xcf\xfa\xed\xfe").unwrap();
        std::fs::set_permissions(&pnpm, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            PnpmShadowDir::create_if_needed(home.path(), &pnpm, home.path())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn pnpm_shadow_refuses_a_symlinked_store_binary() {
        let home = tempfile::tempdir().unwrap();
        let store = home.path().join("Library/pnpm/store/v10/links/package");
        std::fs::create_dir_all(&store).unwrap();
        let secret = home.path().join("id_ed25519");
        std::fs::write(&secret, b"\xcf\xfa\xed\xfesecret").unwrap();
        let pnpm = store.join("pnpm");
        std::os::unix::fs::symlink(&secret, &pnpm).unwrap();
        let roots = [std::fs::canonicalize(home.path().join("Library/pnpm/store")).unwrap()];

        // The canonical store path, swapped for a link after canonicalize.
        let canonical = std::fs::canonicalize(&store).unwrap().join("pnpm");
        assert!(open_no_symlinks(&canonical).is_err());
        // A parent directory swapped for a link.
        let real = home.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("pnpm"), b"\xcf\xfa\xed\xfe").unwrap();
        let linked = std::fs::canonicalize(home.path()).unwrap().join("linked");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        assert!(open_no_symlinks(&linked.join("pnpm")).is_err());
        // Resolved outside the store, the target is never shadowed.
        assert!(
            pnpm_shadow_source_in(&pnpm, &roots, false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn pnpm_shadow_refuses_a_store_fifo_without_blocking() {
        let home = tempfile::tempdir().unwrap();
        let store = home.path().join("Library/pnpm/store/v10/links/package");
        std::fs::create_dir_all(&store).unwrap();
        let fifo = std::fs::canonicalize(&store).unwrap().join("pnpm");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c` is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let roots = [std::fs::canonicalize(home.path().join("Library/pnpm/store")).unwrap()];
        assert!(
            pnpm_shadow_source_in(&fifo, &roots, false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn pnpm_shadow_refuses_a_non_binary_store_file() {
        let home = tempfile::tempdir().unwrap();
        let store = home.path().join("Library/pnpm/store/v10/links/package");
        std::fs::create_dir_all(&store).unwrap();
        let pnpm = store.join("pnpm");
        std::fs::write(&pnpm, b"-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();

        assert!(
            PnpmShadowDir::create_if_needed(home.path(), &pnpm, home.path())
                .unwrap()
                .is_none(),
            "a non-binary store file must never be copied into a shadow"
        );
    }

    #[test]
    fn pnpm_cmd_shim_relative_target_resolves_against_shim_dir() {
        // The `@pnpm/exe` layout in the default PNPM_HOME gets a relocatable
        // shim: `exec "$basedir/../global/..."` and a relative marker (#936).
        let home = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(home.path())
            .unwrap()
            .join("Library/pnpm");
        let rel = "../global/v11/abc123/node_modules/@pnpm/exe/pnpm";
        let binary = root.join("bin").join(rel);
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(&binary, b"\xcf\xfa\xed\xfe").unwrap();
        let shim = root.join("bin/pnpm");
        std::fs::write(
            &shim,
            format!(
                "#!/bin/sh\nbasedir=$(dirname \"$0\")\nexec \"$basedir/{rel}\" \"$@\"\nexit $?\n# cmd-shim-target={rel}\n"
            ),
        )
        .unwrap();
        let roots = [root.clone()];
        assert_eq!(
            pnpm_cmd_shim_target_in(&shim, &roots),
            Some(std::fs::canonicalize(&binary).unwrap())
        );
        // A relative target that climbs out of every pnpm root stays refused.
        std::fs::write(home.path().join("outside"), b"x").unwrap();
        std::fs::write(&shim, "#!/bin/sh\n# cmd-shim-target=../../../outside\n").unwrap();
        assert!(pnpm_cmd_shim_target_in(&shim, &roots).is_none());
    }

    #[test]
    fn pnpm_cmd_shim_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pnpm");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c` is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(pnpm_cmd_shim_target_in(&fifo, &[dir.path().to_path_buf()]).is_none());
    }

    #[test]
    fn pnpm_global_shadow_links_the_sibling_dist() {
        // #936: @pnpm/exe 12 ships `dist/` without `pnpm.mjs`. The shadow
        // links the global binary's own `dist`, whatever it holds, and a
        // missing `dist` does not fail the shadow.
        use std::os::unix::fs::PermissionsExt;

        for dist_files in [
            Some(&["pnpm.mjs", "node_modules/x"][..]),
            Some(&["node_modules/x", "node-gyp-bin/x"][..]),
            None,
        ] {
            let home = tempfile::tempdir().unwrap();
            let root = home.path().join("Library/pnpm");
            let exe = root.join("global/v11/557a16cc/node_modules/@pnpm/exe");
            std::fs::create_dir_all(&exe).unwrap();
            std::fs::create_dir_all(root.join("bin")).unwrap();
            let binary = exe.join("pnpm");
            std::fs::write(&binary, b"\xcf\xfa\xed\xfe").unwrap();
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
            for file in dist_files.unwrap_or_default() {
                let path = exe.join("dist").join(file);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, b"").unwrap();
            }
            let shim = root.join("bin/pnpm");
            std::fs::write(
                &shim,
                format!("#!/bin/sh\n# cmd-shim-target={}\n", binary.display()),
            )
            .unwrap();

            let shadow = PnpmShadowDir::create_if_needed(home.path(), &shim, home.path())
                .unwrap()
                .expect("a global pnpm behind a shim needs a shadow");
            let link = std::fs::read_link(shadow.path().join("dist")).ok();
            assert_eq!(
                link,
                dist_files.map(|_| std::fs::canonicalize(exe.join("dist")).unwrap())
            );
            for file in dist_files.unwrap_or_default() {
                assert!(shadow.path().join("dist").join(file).exists());
            }
        }
    }

    #[test]
    fn pnpm_cmd_shim_target_in_global_without_store_alias_is_shadowed() {
        // #936: pnpm 12 installs `@pnpm/exe/pnpm` under `global/` as a plain
        // file (nlink 1), no hardlink into the store. The shim still execs it
        // from the non-executable pnpm home, so it needs a shadow.
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("Library/pnpm");
        let binary = root.join("global/v11/557a16cc/node_modules/@pnpm/exe/pnpm");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let shim = root.join("bin/pnpm");
        let write_shim = |target: &Path| {
            std::fs::write(
                &shim,
                format!(
                    "#!/bin/sh\nbasedir=$(dirname \"$0\")\n\
                     exec \"$basedir/../global/v11/557a16cc/node_modules/@pnpm/exe/pnpm\" \"$@\"\n\
                     exit $?\n# cmd-shim-target={}\n",
                    target.display()
                ),
            )
            .unwrap();
        };

        write_shim(&binary);
        let source = pnpm_shadow_source(home.path(), &shim)
            .unwrap()
            .expect("a plain binary under global/ needs a shadow");
        assert_eq!(source.path, std::fs::canonicalize(&binary).unwrap());

        // A target outside every pnpm home gets nothing.
        let outside = home.path().join("outside-pnpm");
        std::fs::copy(&binary, &outside).unwrap();
        write_shim(&outside);
        assert!(pnpm_shadow_source(home.path(), &shim).unwrap().is_none());

        // A target that is not a Mach-O or ELF binary gets nothing.
        let script = root.join("global/v11/557a16cc/node_modules/pnpm.cjs");
        std::fs::write(&script, b"#!/usr/bin/env node\n").unwrap();
        write_shim(&script);
        assert!(pnpm_shadow_source(home.path(), &shim).unwrap().is_none());

        // A pnpm binary on PATH, not reached through a shim, still needs a
        // store alias: the relaxed check is for the shim target only.
        assert!(pnpm_shadow_source(home.path(), &binary).unwrap().is_none());
        assert!(pnpm_shadow_source(home.path(), &outside).unwrap().is_none());

        // A target that passed the shim check but was swapped for a link out
        // of the roots before the open must not be copied.
        let roots = [std::fs::canonicalize(&root).unwrap()];
        let swapped = root.join("store/swapped");
        std::fs::create_dir_all(root.join("store")).unwrap();
        std::os::unix::fs::symlink(&outside, &swapped).unwrap();
        assert!(
            pnpm_shadow_source_in(&swapped, &roots, true)
                .unwrap()
                .is_none()
        );
        assert!(
            pnpm_shadow_source_in(&binary, &roots, true)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn pnpm_js_package_launcher_needs_no_shadow() {
        for script in ["pnpm.mjs", "pnpm.cjs"] {
            js_package_launcher_needs_no_shadow(script);
        }
    }

    fn js_package_launcher_needs_no_shadow(script: &str) {
        // Layout written by `pnpm add --global pnpm@11` (the JS package).
        let home = tempfile::tempdir().unwrap();
        let pnpm_home = home.path().join("Library/pnpm");
        let package = pnpm_home.join("store/v11/links/@/pnpm/11.5.1/abc/node_modules/pnpm");
        let bin = pnpm_home.join("bin");
        std::fs::create_dir_all(package.join("bin")).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let target = package.join("bin").join(script);
        std::fs::write(&target, b"#!/usr/bin/env node\nimport '../dist/pnpm.mjs'\n").unwrap();
        let launcher = bin.join("pnpm");
        std::fs::write(
            &launcher,
            format!(
                "#!/bin/sh\nexec node \"{}\" \"$@\"\n# cmd-shim-target={}\n",
                target.display(),
                target.display()
            ),
        )
        .unwrap();

        assert!(
            PnpmShadowDir::create_if_needed(home.path(), &launcher, home.path())
                .expect("the launch must proceed")
                .is_none()
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
            PnpmShadowDir::create_if_needed(home.path(), &pnpm, home.path())
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
        std::fs::write(&pnpm, b"\xcf\xfa\xed\xfe").unwrap();
        std::fs::set_permissions(&pnpm, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::hard_link(&pnpm, links.join("pnpm")).unwrap();

        let err = PnpmShadowDir::create_if_needed(home.path(), &pnpm, home.path())
            .expect_err("a symlinked shadow base must be rejected");
        assert!(err.contains("is a symlink"));
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
    fn pnpm_11_deep_store_alias_is_detected() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let pnpm_home = home.path().join("Library/pnpm");
        let hash = "f46248bbf917cdf17e3592d9b231e3a131c0bbe510c80cdc381baf092bbd7728";
        let exe = pnpm_home.join(format!(
            "store/v11/links/@pnpm/exe/11.5.1/{hash}/node_modules/@pnpm/exe"
        ));
        let platform = pnpm_home.join(format!(
            "store/v11/links/@pnpm/macos-arm64/11.5.1/{hash}/node_modules/@pnpm/macos-arm64"
        ));
        let global = pnpm_home.join("global/v11/node_modules/@pnpm/exe");
        for dir in [&exe, &platform, &global] {
            std::fs::create_dir_all(dir).unwrap();
        }
        // @pnpm/exe's setup.js hardlinks the platform binary as exe/pnpm,
        // so both store paths and the global install share one inode.
        let binary = platform.join("pnpm");
        std::fs::write(&binary, b"\xcf\xfa\xed\xfe").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::hard_link(&binary, exe.join("pnpm")).unwrap();
        let pnpm = global.join("pnpm");
        std::fs::hard_link(&binary, &pnpm).unwrap();

        assert!(
            pnpm_shadow_source_in(&pnpm, &[pnpm_home.join("store")], false)
                .unwrap()
                .is_some(),
            "a pnpm 11 deep store alias must be detected"
        );

        let unrelated = global.join("other");
        std::fs::write(&unrelated, b"x").unwrap();
        std::fs::hard_link(&unrelated, global.join("other2")).unwrap();
        assert!(
            pnpm_shadow_source_in(&unrelated, &[pnpm_home.join("store")], false)
                .unwrap()
                .is_none()
        );
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
        std::fs::write(&pnpm, b"\xcf\xfa\xed\xfe").unwrap();
        std::fs::set_permissions(&pnpm, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::hard_link(&pnpm, links.join("pnpm")).unwrap();

        assert!(
            pnpm_shadow_source_in(&pnpm, &[pnpm_home.join("store")], false)
                .unwrap()
                .is_some(),
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
        let tmp = tempfile::env::temp_dir().join("cplt-test-gc");
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
    fn gc_removes_stale_dir_with_read_only_subdirs() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(SCRATCH_BASE);
        let stale_dir = base.join("0123456789abcdef0123456789abcdef");
        let ro = stale_dir.join("go/pkg/mod/x@v1");
        std::fs::create_dir_all(&ro).unwrap();
        std::fs::write(ro.join("f.go"), "package x").unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::os::unix::fs::symlink(&outside, ro.join("link")).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(ro.parent().unwrap(), std::fs::Permissions::from_mode(0o555))
            .unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(25 * 3600);
        std::fs::File::open(&stale_dir)
            .unwrap()
            .set_modified(old)
            .unwrap();

        ScratchDir::gc_stale(tmp.path());

        assert!(
            !stale_dir.exists(),
            "stale dir with read-only subdirs should be removed"
        );
        let mode = outside.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o555,
            "symlink target outside scratch must not be chmodded"
        );
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn gc_ignores_non_session_entries() {
        let tmp = tempfile::env::temp_dir().join("cplt-test-gc-safe");
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

        let guard = SessionSocketDir::create().unwrap();
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
        let guard = SessionSocketDir::create().unwrap();
        let path = guard.path().to_path_buf();
        let session_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(PLAYWRIGHT_SOCKET_DIR_PREFIX))
            .unwrap();

        let collision = SessionSocketDir::create_for_session_id(session_id);
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

        let guard = SessionSocketDir {
            path: guarded_path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            _lock: None,
        };
        drop(guard);

        assert!(guarded_path.is_symlink());
        assert!(original_path.is_dir());
        assert!(unrelated.is_dir());
    }

    #[test]
    fn scratch_dir_cleanup_refuses_replaced_path() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let scratch = ScratchDir::create(&home).unwrap();
        let path = scratch.path().to_path_buf();
        let moved = home.join("moved-scratch");
        let victim = home.join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("keep.txt"), "keep").unwrap();

        std::fs::rename(&path, &moved).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        drop(scratch);

        assert!(path.is_symlink());
        assert!(victim.join("keep.txt").exists());
    }

    #[test]
    fn mode_0300_dir_is_repaired_and_cleaned_up() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let dir = home.join("no-read-dir");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o300)).unwrap();

        validate_dir_safety(&dir, "test dir").expect("mode 0300 dir should be repaired to 0700");
        let mode = dir.symlink_metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);

        let scratch = ScratchDir::create(&home).unwrap();
        let scratch_path = scratch.path().to_path_buf();
        std::fs::write(scratch_path.join("file.txt"), "data").unwrap();
        std::fs::set_permissions(&scratch_path, std::fs::Permissions::from_mode(0o300)).unwrap();
        drop(scratch);
        assert!(
            !scratch_path.exists(),
            "mode 0300 scratch dir must still be removed on drop"
        );
    }
}
