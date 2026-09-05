//! Self-update: download and install the latest cplt release from GitHub.
//!
//! Uses absolute paths for all external tools (`/usr/bin/curl`, `/usr/bin/tar`,
//! `/usr/bin/shasum`, `/usr/bin/xattr`, `/usr/bin/codesign`) to avoid PATH
//! manipulation attacks — this code runs outside the sandbox.

use std::path::{Path, PathBuf};
use std::process::Command;

const RELEASES_API: &str = "https://api.github.com/repos/navikt/cplt/releases";
const DOWNLOAD_BASE: &str = "https://github.com/navikt/cplt/releases/download";

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UpdateError {
    #[error("Failed to parse GitHub API response: {0}")]
    ApiParse(#[from] serde_json::Error),

    #[error("No suitable release found on GitHub")]
    NoRelease,

    #[error("GitHub API rate limit reached. Try again later.")]
    RateLimited,

    #[error("Cannot reach GitHub. Check your connection.\n  {0}")]
    NetworkUnreachable(String),

    #[error("Download failed: {0}")]
    DownloadFailed(String),

    #[error("Invalid UTF-8 in response")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error(
        "SHA256 verification failed!\n  Expected: {expected}\n  Got:      {actual}\n  Download may be corrupted or tampered with."
    )]
    ChecksumMismatch { expected: String, actual: String },

    #[error("No SHA256 checksum found for '{0}' in SHA256SUMS")]
    NoChecksum(String),

    #[error("SHA256 computation failed")]
    HashFailed,

    #[error("Cannot parse hash output")]
    HashParse,

    #[error("Archive appears to be corrupt")]
    CorruptArchive,

    #[error("Archive is empty")]
    EmptyArchive,

    #[error(
        "Release archive has unexpected contents ({count} entries).\n  Expected a single 'cplt' entry."
    )]
    UnexpectedArchive { count: usize },

    #[error(
        "Archive entry is not a regular file: {0}\n  Refusing to extract symlinks or directories."
    )]
    NotRegularFile(String),

    #[error("Archive contains unexpected file: '{0}'\n  Expected 'cplt'.")]
    WrongFilename(String),

    #[error("Extracted archive does not contain 'cplt' binary")]
    BinaryNotFound,

    #[error("Extracted 'cplt' is not a regular file (symlink or directory)")]
    BinaryNotRegularFile,

    #[error("Extraction failed: {0}")]
    ExtractionFailed(String),

    #[error("{0}")]
    Io(String),

    #[error("sudo not found. Install the binary manually:\n  sudo cp <binary> /usr/local/bin/cplt")]
    SudoNotFound,

    #[error("sudo cp failed. You can also run manually:\n  sudo cp {src} {dest}")]
    SudoFailed { src: String, dest: String },

    #[error("sha256sum not found in standard paths (/usr/bin, /usr/sbin, /bin)")]
    HashToolNotFound,

    #[error("xattr -cr failed")]
    XattrFailed,

    #[error("codesign failed")]
    CodesignFailed,

    #[error(
        "Version mismatch: binary reports '{got}' but release tag expects '{expected}'.\n  This is a release pipeline bug. The binary was built with a different version than the tag."
    )]
    VersionMismatch { expected: String, got: String },

    #[error(
        "The staged binary at {0} was replaced after cplt validated it.\n  Refusing to run or install it."
    )]
    StagedBinaryReplaced(String),
}

/// A parsed GitHub release.
#[derive(Debug)]
pub struct Release {
    pub tag: String,
    pub version: String,
}

/// Result of comparing current vs latest version.
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum VersionStatus {
    /// Already on the latest version.
    UpToDate,
    /// A newer version is available.
    UpdateAvailable {
        current: String,
        latest: String,
        tag: String,
    },
    /// Same date but different build (SHA differs).
    SameDateDifferentBuild {
        current: String,
        latest: String,
        tag: String,
    },
    /// Running a dev build (version is "0.0.0").
    DevBuild { latest: String, tag: String },
}

/// Fetch the latest release from GitHub.
pub fn fetch_latest_release(current_version: &str) -> Result<Release, UpdateError> {
    let url = format!("{RELEASES_API}?per_page=20");
    let body = curl_get_json(&url, current_version)?;

    let releases: Vec<serde_json::Value> = serde_json::from_str(&body)?;

    for rel in &releases {
        // Skip drafts and prereleases
        if rel
            .get("draft")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        if rel
            .get("prerelease")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }

        if let Some(tag) = rel.get("tag_name").and_then(|v| v.as_str()) {
            // Accept both "cplt/VERSION" and bare "VERSION" tag formats
            let version = tag.strip_prefix("cplt/").unwrap_or(tag);
            // Validate it looks like a version (YYYY.MM.DD-HHMMSS-SHA or legacy formats)
            if looks_like_version(version) {
                return Ok(Release {
                    tag: tag.to_string(),
                    version: version.to_string(),
                });
            }
        }
    }

    Err(UpdateError::NoRelease)
}

/// Compare current version against the latest release.
pub fn check_version(current: &str, latest: &Release) -> VersionStatus {
    if current == "0.0.0" {
        return VersionStatus::DevBuild {
            latest: latest.version.clone(),
            tag: latest.tag.clone(),
        };
    }

    if current == latest.version {
        return VersionStatus::UpToDate;
    }

    let current_date = version_date(current);
    let latest_date = version_date(&latest.version);

    if current_date == latest_date {
        VersionStatus::SameDateDifferentBuild {
            current: current.to_string(),
            latest: latest.version.clone(),
            tag: latest.tag.clone(),
        }
    } else if latest_date > current_date {
        VersionStatus::UpdateAvailable {
            current: current.to_string(),
            latest: latest.version.clone(),
            tag: latest.tag.clone(),
        }
    } else {
        // Current is newer than latest release (local build)
        VersionStatus::UpToDate
    }
}

/// Download, verify, and install the update.
pub fn perform_update(
    tag: &str,
    current_version: &str,
    expected_version: &str,
) -> Result<String, UpdateError> {
    let arch = std::env::consts::ARCH;
    let asset = asset_name(arch);
    let asset_url = format!("{DOWNLOAD_BASE}/{tag}/{asset}");
    let sums_url = format!("{DOWNLOAD_BASE}/{tag}/SHA256SUMS");

    // 1. Download the archive
    eprintln!("  Downloading {asset}...");
    let home = std::env::var("HOME")
        .map_err(|_| UpdateError::Io("HOME is not set, cannot stage the update".to_string()))?;
    let tmp_dir = create_stage_dir(Path::new(&home))?;
    let archive_path = tmp_dir.join(&asset);
    curl_download(&asset_url, &archive_path, current_version)?;

    // 2. Download and verify SHA256
    eprintln!("  Verifying SHA256 checksum...");
    let sums_body = curl_get(&sums_url, current_version)?;
    let expected_hash = parse_sha256sums(&sums_body, &asset)?;
    let actual_hash = compute_sha256(&archive_path)?;
    if actual_hash != expected_hash {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(UpdateError::ChecksumMismatch {
            expected: expected_hash,
            actual: actual_hash,
        });
    }

    // 3. Validate and extract archive
    eprintln!("  Extracting...");
    validate_archive(&archive_path)?;
    let extract_dir = tmp_dir.join("extract");
    std::fs::create_dir_all(&extract_dir)
        .map_err(|e| UpdateError::Io(format!("Cannot create extract dir: {e}")))?;
    extract_archive(&archive_path, &extract_dir)?;

    let new_binary = extract_dir.join("cplt");
    // Use symlink_metadata to NOT follow symlinks — reject if it's a symlink
    let meta = std::fs::symlink_metadata(&new_binary).map_err(|_| {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        UpdateError::BinaryNotFound
    })?;
    if !meta.file_type().is_file() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(UpdateError::BinaryNotRegularFile);
    }

    // 4. Resolve current binary location
    let current_exe = std::env::current_exe()
        .map_err(|e| UpdateError::Io(format!("Cannot determine current binary path: {e}")))?;
    let target_path = std::fs::canonicalize(&current_exe).unwrap_or(current_exe);

    // 5. Stage: set permissions and platform-specific postprocessing.
    // Both rewrite the file, and codesign is free to do so by rename, so the
    // inode identity below is taken afterwards.
    eprintln!("  Preparing binary...");
    set_executable(&new_binary)?;
    postprocess_binary(&new_binary);

    // 5b. Pin the inode. Everything after this point must be the same file:
    // the version probe below executes it *unsandboxed*, so a swap between
    // probe and install would run one binary and ship another.
    let binary = StagedBinary::open(&new_binary).inspect_err(|_| {
        let _ = std::fs::remove_dir_all(&tmp_dir);
    })?;

    // 5c. Verify the binary reports the expected version.
    // Catches release pipeline bugs where the tag and binary version diverge
    // (e.g., version timestamp generated twice → infinite update loop).
    binary.verify_unchanged()?;
    verify_binary_version(&new_binary, expected_version, &tmp_dir)?;

    // 6. Install to target path — use sudo if direct write fails
    binary.verify_unchanged()?;
    let needs_sudo = !is_writable(&target_path);
    if needs_sudo {
        eprintln!(
            "  Elevated permissions required for {}...",
            target_path.display()
        );
        sudo_install(&new_binary, &target_path)?;
    } else {
        let staged = target_path.with_extension("new");
        binary.copy_to(&staged)?;
        set_executable(&staged)?;
        postprocess_binary(&staged);
        std::fs::rename(&staged, &target_path).map_err(|e| {
            let _ = std::fs::remove_file(&staged);
            UpdateError::Io(format!("Cannot replace binary: {e}"))
        })?;
    }

    // 7. Clean up
    let _ = std::fs::remove_dir_all(&tmp_dir);

    Ok(target_path.display().to_string())
}

/// Check if the current binary is managed by Homebrew.
pub fn is_homebrew_managed() -> bool {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok());
    match exe {
        Some(p) => {
            let s = p.to_string_lossy();
            s.contains("/Cellar/") || s.contains("/homebrew/")
        }
        None => false,
    }
}

/// Construct the asset filename for the current platform and architecture.
pub fn asset_name(arch: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        format!("cplt-{arch}-apple-darwin.tar.gz")
    }
    #[cfg(target_os = "linux")]
    {
        format!("cplt-{arch}-unknown-linux-gnu.tar.gz")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        format!("cplt-{arch}-apple-darwin.tar.gz")
    }
}

/// Check if a string looks like a cplt version.
/// Accepts formats:
///   - YYYY.MM.DD-SHA (legacy)
///   - YYYY.MM.DD.HH.MM.SS-SHA (intermediate)
///   - YYYY.MM.DD-HHMMSS-SHA (current)
pub fn looks_like_version(s: &str) -> bool {
    // SHA is always the last dash-separated segment
    let Some((prefix, sha)) = s.rsplit_once('-') else {
        return false;
    };
    if sha.is_empty() {
        return false;
    }

    // Try current format: YYYY.MM.DD-HHMMSS
    if let Some((date_str, time_str)) = prefix.rsplit_once('-') {
        let date_parts: Vec<&str> = date_str.split('.').collect();
        if date_parts.len() == 3
            && date_parts[0].len() == 4
            && date_parts[1..].iter().all(|p| p.len() == 2)
            && date_parts
                .iter()
                .all(|p| p.chars().all(|c| c.is_ascii_digit()))
            && time_str.len() == 6
            && time_str.chars().all(|c| c.is_ascii_digit())
        {
            return true;
        }
    }

    // Try legacy formats: YYYY.MM.DD or YYYY.MM.DD.HH.MM.SS (no time dash)
    let date_parts: Vec<&str> = prefix.split('.').collect();
    if date_parts.len() != 3 && date_parts.len() != 6 {
        return false;
    }
    date_parts[0].len() == 4
        && date_parts[1..].iter().all(|p| p.len() == 2)
        && date_parts
            .iter()
            .all(|p| p.chars().all(|c| c.is_ascii_digit()))
}

/// Extract the sortable date+time portion of a version string.
/// Returns everything before the last `-` (the git SHA).
/// Lexicographic comparison works correctly across all formats:
///   "2026.04.13" < "2026.04.13-173045" < "2026.04.13.17.30.45"
pub fn version_date(version: &str) -> &str {
    version
        .rsplit_once('-')
        .map_or(version, |(prefix, _)| prefix)
}

/// Parse SHA256SUMS content and find the hash for a given asset.
pub fn parse_sha256sums(content: &str, asset_name: &str) -> Result<String, UpdateError> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Format: "HASH  FILENAME" or "HASH FILENAME"
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 && fields.last() == Some(&asset_name) {
            return Ok(fields[0].to_lowercase());
        }
    }
    Err(UpdateError::NoChecksum(asset_name.to_string()))
}

// --- Internal helpers ---

/// HTTP GET returning body as string (for JSON/text).
#[allow(clippy::disallowed_methods)] // /usr/bin/curl, an absolute system path
fn curl_get(url: &str, version: &str) -> Result<String, UpdateError> {
    let output = Command::new("/usr/bin/curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto-redir",
            "=https",
            "--max-time",
            "30",
            "--header",
            &format!("User-Agent: cplt/{version}"),
            url,
        ])
        .output()
        .map_err(|e| UpdateError::Io(format!("Cannot run /usr/bin/curl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("403") || stderr.contains("rate limit") {
            return Err(UpdateError::RateLimited);
        }
        return Err(UpdateError::DownloadFailed(stderr.into_owned()));
    }

    Ok(String::from_utf8(output.stdout)?)
}

/// HTTP GET expecting JSON, with Accept header.
#[allow(clippy::disallowed_methods)] // /usr/bin/curl, an absolute system path
fn curl_get_json(url: &str, version: &str) -> Result<String, UpdateError> {
    let output = Command::new("/usr/bin/curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto-redir",
            "=https",
            "--max-time",
            "30",
            "--header",
            &format!("User-Agent: cplt/{version}"),
            "--header",
            "Accept: application/vnd.github+json",
            url,
        ])
        .output()
        .map_err(|e| UpdateError::Io(format!("Cannot run /usr/bin/curl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("403") || stderr.contains("rate limit") {
            return Err(UpdateError::RateLimited);
        }
        return Err(UpdateError::NetworkUnreachable(stderr.into_owned()));
    }

    Ok(String::from_utf8(output.stdout)?)
}

/// Download a file to disk.
#[allow(clippy::disallowed_methods)] // /usr/bin/curl, an absolute system path
fn curl_download(url: &str, dest: &Path, version: &str) -> Result<(), UpdateError> {
    let output = Command::new("/usr/bin/curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto-redir",
            "=https",
            "--max-time",
            "120",
            "--header",
            &format!("User-Agent: cplt/{version}"),
            "--output",
            &dest.to_string_lossy(),
            url,
        ])
        .output()
        .map_err(|e| UpdateError::Io(format!("Cannot run /usr/bin/curl: {e}")))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(UpdateError::DownloadFailed(stderr.into_owned()))
    }
}

/// Compute SHA256 hash of a file using the platform's hash utility.
///
/// macOS uses `/usr/bin/shasum -a 256`, Linux uses `sha256sum`.
fn compute_sha256(path: &Path) -> Result<String, UpdateError> {
    let output = sha256_command(path)?;

    if !output.status.success() {
        return Err(UpdateError::HashFailed);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .next()
        .map(str::to_lowercase)
        .ok_or(UpdateError::HashParse)
}

#[cfg(target_os = "macos")]
#[allow(clippy::disallowed_methods)] // absolute system path
fn sha256_command(path: &Path) -> Result<std::process::Output, UpdateError> {
    Command::new("/usr/bin/shasum")
        .args(["-a", "256", &path.to_string_lossy()])
        .output()
        .map_err(|e| UpdateError::Io(format!("Cannot run shasum: {e}")))
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::disallowed_methods)] // absolute candidates, existence-checked before use
fn sha256_command(path: &Path) -> Result<std::process::Output, UpdateError> {
    // Use absolute paths only — bare PATH lookup could run a malicious binary.
    let candidates = [
        "/usr/bin/sha256sum",
        "/usr/sbin/sha256sum",
        "/bin/sha256sum",
    ];
    let bin = candidates
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .ok_or(UpdateError::HashToolNotFound)?;
    Command::new(bin)
        .arg(path.to_string_lossy().to_string())
        .output()
        .map_err(|e| UpdateError::Io(format!("Cannot run sha256sum: {e}")))
}

/// Validate archive contents before extraction.
/// Rejects archives with symlinks, directories, or unexpected entries.
/// Uses verbose listing (`-tvf`) to detect file types — plain `-tzf`
/// cannot distinguish symlinks from regular files.
#[allow(clippy::disallowed_methods)] // /usr/bin/tar, an absolute system path
fn validate_archive(path: &Path) -> Result<(), UpdateError> {
    let output = Command::new("/usr/bin/tar")
        .args(["-tvzf", &path.to_string_lossy()])
        .output()
        .map_err(|e| UpdateError::Io(format!("Cannot list archive contents: {e}")))?;

    if !output.status.success() {
        return Err(UpdateError::CorruptArchive);
    }

    let listing = String::from_utf8_lossy(&output.stdout);
    let entries: Vec<&str> = listing.lines().filter(|l| !l.is_empty()).collect();

    if entries.is_empty() {
        return Err(UpdateError::EmptyArchive);
    }

    if entries.len() != 1 {
        return Err(UpdateError::UnexpectedArchive {
            count: entries.len(),
        });
    }

    let entry = entries[0];

    // Verbose tar output starts with permissions: "-rwxr-xr-x" for regular files,
    // "l..." for symlinks, "d..." for directories
    if !entry.starts_with('-') {
        return Err(UpdateError::NotRegularFile(entry.to_string()));
    }

    // Verify the filename (last field) is exactly "cplt"
    let filename = entry.split_whitespace().last().unwrap_or("");
    if filename != "cplt" {
        return Err(UpdateError::WrongFilename(filename.to_string()));
    }

    Ok(())
}

/// Extract archive to a directory.
#[allow(clippy::disallowed_methods)] // /usr/bin/tar, an absolute system path
fn extract_archive(archive: &Path, dest: &Path) -> Result<(), UpdateError> {
    let output = Command::new("/usr/bin/tar")
        .args([
            "-xzf",
            &archive.to_string_lossy(),
            "-C",
            &dest.to_string_lossy(),
        ])
        .output()
        .map_err(|e| UpdateError::Io(format!("Cannot extract archive: {e}")))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(UpdateError::ExtractionFailed(stderr.into_owned()))
    }
}

/// Staging base for downloads, relative to `$HOME`.
///
/// Deliberately *not* the system temp directory. Every cplt sandbox can write
/// throughout `/tmp` and `/var/folders`, so a same-UID process could swap the
/// archive or the extracted binary between validation and use. `~/.config/cplt`
/// is a hard deny for sandboxed agents (see `sandbox_policy::DENIED_DOTFILES`),
/// which takes that reach away.
const STAGE_BASE: &str = ".config/cplt/update";

/// Create a private staging directory for the update process.
///
/// The directory name is 128 bits from `/dev/urandom` rather than the pid, and
/// it is created with `mkdir(2)` at mode 0700, which fails with `EEXIST` rather
/// than adopting a directory someone else planted — the "check then create"
/// version this replaces did adopt it.
fn create_stage_dir(home: &Path) -> Result<PathBuf, UpdateError> {
    let base = home.join(STAGE_BASE);
    std::fs::create_dir_all(&base)
        .map_err(|e| UpdateError::Io(format!("Cannot create staging base: {e}")))?;

    // Canonicalize both sides so a symlink at any ancestor is caught, not
    // followed: `~/.config` swapped for a symlink would otherwise stage the
    // update wherever it points.
    let canonical_home = std::fs::canonicalize(home)
        .map_err(|e| UpdateError::Io(format!("Cannot canonicalize home dir: {e}")))?;
    let canonical_base = std::fs::canonicalize(&base)
        .map_err(|e| UpdateError::Io(format!("Cannot canonicalize staging base: {e}")))?;
    if canonical_base != canonical_home.join(STAGE_BASE) {
        return Err(UpdateError::Io(format!(
            "Staging base resolved to {} but expected {}. An ancestor may be a symlink",
            canonical_base.display(),
            canonical_home.join(STAGE_BASE).display()
        )));
    }
    crate::scratch::validate_dir_safety(&canonical_base, "Update staging base")
        .map_err(UpdateError::Io)?;

    let dir = canonical_base.join(crate::scratch::generate_session_id().map_err(UpdateError::Io)?);
    crate::scratch::create_secure_dir(&dir, "update staging dir").map_err(UpdateError::Io)?;
    Ok(dir)
}

/// The extracted binary, held open so that validation, execution and install
/// all refer to the same inode.
///
/// Re-checking a *path* proves nothing: between two `stat` calls the name can
/// be pointed at a different file. This holds the descriptor from the file it
/// validated, compares `(dev, ino)` before each use of the path, and installs
/// by copying out of the descriptor rather than re-opening the name.
#[derive(Debug)]
struct StagedBinary {
    path: PathBuf,
    file: std::fs::File,
    dev: u64,
    ino: u64,
}

impl StagedBinary {
    /// Open `path` without following symlinks and record the inode identity.
    fn open(path: &Path) -> Result<Self, UpdateError> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => UpdateError::BinaryNotFound,
                // O_NOFOLLOW refusing a symlink surfaces as ELOOP, which is the
                // check doing its job rather than an I/O problem.
                _ if e.raw_os_error() == Some(libc::ELOOP) => UpdateError::BinaryNotRegularFile,
                _ => UpdateError::Io(format!("Cannot open staged binary: {e}")),
            })?;
        let meta = file
            .metadata()
            .map_err(|e| UpdateError::Io(format!("Cannot stat staged binary: {e}")))?;
        if !meta.file_type().is_file() {
            return Err(UpdateError::BinaryNotRegularFile);
        }
        Ok(Self {
            path: path.to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
            file,
        })
    }

    /// Fail if the path no longer names the inode we validated.
    fn verify_unchanged(&self) -> Result<(), UpdateError> {
        use std::os::unix::fs::MetadataExt;

        let meta =
            std::fs::symlink_metadata(&self.path).map_err(|_| UpdateError::BinaryNotFound)?;
        if meta.dev() != self.dev || meta.ino() != self.ino {
            return Err(UpdateError::StagedBinaryReplaced(
                self.path.display().to_string(),
            ));
        }
        Ok(())
    }

    /// Copy the validated bytes to `dest`, reading from the held descriptor.
    ///
    /// Never re-opens `self.path`, so a swap of that name cannot change what
    /// gets installed.
    fn copy_to(&self, dest: &Path) -> Result<(), UpdateError> {
        use std::io::Seek;

        let mut src = self
            .file
            .try_clone()
            .map_err(|e| UpdateError::Io(format!("Cannot re-read staged binary: {e}")))?;
        src.rewind()
            .map_err(|e| UpdateError::Io(format!("Cannot rewind staged binary: {e}")))?;
        let mut out = std::fs::File::create(dest)
            .map_err(|e| UpdateError::Io(format!("Cannot stage binary: {e}")))?;
        std::io::copy(&mut src, &mut out)
            .map_err(|e| UpdateError::Io(format!("Cannot stage binary: {e}")))?;
        Ok(())
    }
}

/// Set executable permissions on a file.
fn set_executable(path: &Path) -> Result<(), UpdateError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| UpdateError::Io(format!("Cannot set permissions: {e}")))
}

/// Verify the extracted binary reports the expected version.
///
/// Runs `<binary> --version` and checks the output contains the expected version
/// string. This is a defense-in-depth check against release pipeline bugs where
/// the tag version and the binary's embedded version diverge (which would cause
/// an infinite update loop).
#[allow(clippy::disallowed_methods)] // runs the freshly extracted binary by path
fn verify_binary_version(
    binary: &Path,
    expected_version: &str,
    tmp_dir: &Path,
) -> Result<(), UpdateError> {
    let output = Command::new(binary)
        .arg("--version")
        .output()
        .map_err(|e| UpdateError::Io(format!("Cannot run extracted binary: {e}")))?;

    let version_output = String::from_utf8_lossy(&output.stdout);
    // --version output is like "cplt 2026.05.29-080706-abc1234"
    let reported = version_output.trim();

    if !reported.contains(expected_version) {
        let _ = std::fs::remove_dir_all(tmp_dir);
        return Err(UpdateError::VersionMismatch {
            expected: expected_version.to_string(),
            got: reported.to_string(),
        });
    }

    Ok(())
}

/// Apply platform-specific binary postprocessing after download.
///
/// On macOS, removes quarantine attributes and ad-hoc code signs the binary
/// (required by Gatekeeper). On Linux, this is a no-op.
fn postprocess_binary(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = run_xattr(path);
        let _ = run_codesign(path);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
    }
}

/// Remove macOS quarantine extended attributes.
/// Remove quarantine attribute (macOS only — required for Gatekeeper).
#[cfg(target_os = "macos")]
#[allow(clippy::disallowed_methods)] // /usr/bin/xattr, an absolute system path
fn run_xattr(path: &Path) -> Result<(), UpdateError> {
    let output = Command::new("/usr/bin/xattr")
        .args(["-cr", &path.to_string_lossy()])
        .output()
        .map_err(|e| UpdateError::Io(format!("xattr failed: {e}")))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(UpdateError::XattrFailed)
    }
}

/// Ad-hoc code sign the binary (macOS only — required for Gatekeeper).
#[cfg(target_os = "macos")]
#[allow(clippy::disallowed_methods)] // /usr/bin/codesign, an absolute system path
fn run_codesign(path: &Path) -> Result<(), UpdateError> {
    let output = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", &path.to_string_lossy()])
        .output()
        .map_err(|e| UpdateError::Io(format!("codesign failed: {e}")))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(UpdateError::CodesignFailed)
    }
}

/// Check if the target path (or its parent directory) is writable by the current user.
fn is_writable(path: &Path) -> bool {
    // Check if the parent directory is writable (can we create/replace a file here?)
    // We probe the directory rather than opening the target file because on Linux,
    // opening a running binary for write returns ETXTBSY ("text file busy"), which
    // would incorrectly trigger the sudo path for user-owned paths like ~/.local/bin/.
    path.parent().is_some_and(|p| {
        let probe = p.join(".cplt_write_probe");
        let ok = std::fs::File::create(&probe).is_ok();
        let _ = std::fs::remove_file(&probe);
        ok
    })
}

/// Install binary using sudo for the final copy + permission step.
/// Downloads and verification happen as the current user; only the
/// file placement requires elevated privileges.
#[allow(clippy::disallowed_methods)] // sudo resolved from absolute candidates by find_sudo()
fn sudo_install(src: &Path, dest: &Path) -> Result<(), UpdateError> {
    let sudo = find_sudo()?;

    let output = Command::new(&sudo)
        .args(["cp", "-f", &src.to_string_lossy(), &dest.to_string_lossy()])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| UpdateError::Io(format!("Cannot run sudo: {e}")))?;

    if !output.success() {
        return Err(UpdateError::SudoFailed {
            src: src.display().to_string(),
            dest: dest.display().to_string(),
        });
    }

    // Set correct permissions
    let _ = Command::new(&sudo)
        .args(["chmod", "755", &dest.to_string_lossy()])
        .status();

    Ok(())
}

/// Find sudo binary on the system.
fn find_sudo() -> Result<PathBuf, UpdateError> {
    for p in ["/usr/bin/sudo", "/bin/sudo"] {
        let path = Path::new(p);
        if path.exists() {
            return Ok(path.to_path_buf());
        }
    }
    Err(UpdateError::SudoNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// Write `bytes` to a fresh file at `path`.
    fn write_file(path: &Path, bytes: &[u8]) {
        let mut f = std::fs::File::create(path).expect("create");
        f.write_all(bytes).expect("write");
    }

    #[test]
    fn stage_dir_is_private_unpredictable_and_exclusive() {
        let home = tempfile::tempdir().expect("tempdir");
        let a = create_stage_dir(home.path()).expect("first stage dir");
        let b = create_stage_dir(home.path()).expect("second stage dir");

        // Under cplt's own config dir, never the system temp dir: every cplt
        // sandbox can write throughout /tmp and /var/folders, and `.config/cplt`
        // is a hard deny (see `profile_denies_write_to_cplt_config_dir`).
        // Asserted against the caller's home rather than `env::temp_dir()`,
        // because the fake home in this test is itself a temp directory.
        assert_eq!(STAGE_BASE, ".config/cplt/update");
        let base = std::fs::canonicalize(home.path()).unwrap().join(STAGE_BASE);
        assert!(
            a.starts_with(&base),
            "stage dir {} is not under {}",
            a.display(),
            base.display()
        );

        // Unpredictable: two runs must not collide, and the name must not be
        // derivable from the pid.
        assert_ne!(a, b, "two staging dirs collided");
        let name = a.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name.len(), 32, "expected 128 bits of hex, got {name:?}");
        assert!(
            !name.contains(&std::process::id().to_string()),
            "staging dir name {name:?} leaks the pid"
        );

        // Owner-only from the moment it exists (mkdir with mode, not chmod after).
        let mode = std::fs::symlink_metadata(&a).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "staging dir is not 0700");

        // Exclusive creation: an existing directory is refused, not adopted.
        let planted = base.join("00000000000000000000000000000000");
        crate::scratch::create_secure_dir(&planted, "planted").expect("plant");
        assert!(
            crate::scratch::create_secure_dir(&planted, "planted").is_err(),
            "creating over an existing staging dir must fail"
        );
    }

    #[test]
    fn staged_binary_refuses_a_swapped_inode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cplt");
        write_file(&path, b"good");

        let staged = StagedBinary::open(&path).expect("open");
        staged
            .verify_unchanged()
            .expect("untouched file must verify");

        // Same path, different inode — exactly the swap the version probe and
        // the install would otherwise walk into.
        let evil = dir.path().join("evil");
        write_file(&evil, b"evil");
        std::fs::rename(&evil, &path).expect("swap");

        let err = staged
            .verify_unchanged()
            .expect_err("swap must be detected");
        assert!(
            matches!(err, UpdateError::StagedBinaryReplaced(_)),
            "{err:?}"
        );
    }

    #[test]
    fn staged_binary_installs_the_bytes_it_validated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cplt");
        write_file(&path, b"good");

        let staged = StagedBinary::open(&path).expect("open");

        let evil = dir.path().join("evil");
        write_file(&evil, b"evil");
        std::fs::rename(&evil, &path).expect("swap");

        // Copying re-reads the held descriptor, not the name, so the swap
        // cannot change what lands on disk.
        let dest = dir.path().join("installed");
        staged.copy_to(&dest).expect("copy");
        assert_eq!(std::fs::read(&dest).unwrap(), b"good");
    }

    #[test]
    fn staged_binary_rejects_a_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        write_file(&real, b"good");
        let link = dir.path().join("cplt");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let err = StagedBinary::open(&link).expect_err("a symlinked staged binary must be refused");
        assert!(matches!(err, UpdateError::BinaryNotRegularFile), "{err:?}");
    }

    #[test]
    fn staged_binary_accepts_in_place_edits_of_the_same_inode() {
        // Sanity check that the guard keys on the inode and not on content or
        // mtime: postprocess_binary rewrites the file in place.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cplt");
        write_file(&path, b"good");
        let staged = StagedBinary::open(&path).expect("open");
        let ino = std::fs::symlink_metadata(&path).unwrap().ino();

        let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.write_all(b"gooo").unwrap();
        drop(f);

        assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), ino);
        staged
            .verify_unchanged()
            .expect("in-place edit is not a swap");
    }

    #[test]
    fn version_looks_valid() {
        // Legacy format (YYYY.MM.DD-SHA)
        assert!(looks_like_version("2026.04.13-a1b2c3d"));
        assert!(looks_like_version("2024.12.01-abc1234"));
        // Intermediate format (YYYY.MM.DD.HH.MM.SS-SHA)
        assert!(looks_like_version("2026.04.13.17.30.45-a1b2c3d"));
        // Current format (YYYY.MM.DD-HHMMSS-SHA)
        assert!(looks_like_version("2026.04.13-173045-a1b2c3d"));
        assert!(looks_like_version("2024.12.01-000000-abc1234"));
    }

    #[test]
    fn version_rejects_invalid() {
        assert!(!looks_like_version("0.0.0"));
        assert!(!looks_like_version("2026.04.13"));
        assert!(!looks_like_version("not-a-version"));
        assert!(!looks_like_version(""));
        assert!(!looks_like_version("2026.4.13-abc")); // month not 2 digits
        assert!(!looks_like_version("2026.04.13.17.30-abc")); // 5 dot-parts (invalid)
        assert!(!looks_like_version("2026.04.13-1730-abc")); // time not 6 digits
    }

    #[test]
    fn version_date_extraction() {
        // Legacy: everything before the single dash
        assert_eq!(version_date("2026.04.13-a1b2c3d"), "2026.04.13");
        // Current: everything before the last dash (date-time portion)
        assert_eq!(
            version_date("2026.04.13-173045-a1b2c3d"),
            "2026.04.13-173045"
        );
        // Intermediate
        assert_eq!(
            version_date("2026.04.13.17.30.45-a1b2c3d"),
            "2026.04.13.17.30.45"
        );
        assert_eq!(version_date("0.0.0"), "0.0.0");
    }

    #[test]
    fn version_comparison_newer() {
        let latest = Release {
            tag: "cplt/2026.04.15-100000-abc1234".to_string(),
            version: "2026.04.15-100000-abc1234".to_string(),
        };
        let status = check_version("2026.04.13-080000-def5678", &latest);
        assert!(matches!(status, VersionStatus::UpdateAvailable { .. }));
    }

    #[test]
    fn version_comparison_up_to_date() {
        let latest = Release {
            tag: "cplt/2026.04.13-173045-abc1234".to_string(),
            version: "2026.04.13-173045-abc1234".to_string(),
        };
        let status = check_version("2026.04.13-173045-abc1234", &latest);
        assert_eq!(status, VersionStatus::UpToDate);
    }

    #[test]
    fn version_comparison_local_newer() {
        let latest = Release {
            tag: "cplt/2026.04.10-120000-abc1234".to_string(),
            version: "2026.04.10-120000-abc1234".to_string(),
        };
        let status = check_version("2026.04.13-080000-def5678", &latest);
        assert_eq!(status, VersionStatus::UpToDate);
    }

    #[test]
    fn version_comparison_same_date_different_sha() {
        let latest = Release {
            tag: "cplt/2026.04.13-173045-abc1234".to_string(),
            version: "2026.04.13-173045-abc1234".to_string(),
        };
        let status = check_version("2026.04.13-173045-def5678", &latest);
        assert!(matches!(
            status,
            VersionStatus::SameDateDifferentBuild { .. }
        ));
    }

    #[test]
    fn version_comparison_dev_build() {
        let latest = Release {
            tag: "cplt/2026.04.13-173045-abc1234".to_string(),
            version: "2026.04.13-173045-abc1234".to_string(),
        };
        let status = check_version("0.0.0", &latest);
        assert!(matches!(status, VersionStatus::DevBuild { .. }));
    }

    #[test]
    fn version_comparison_cross_format() {
        // Current format release vs legacy local version
        let latest = Release {
            tag: "cplt/2026.04.15-100000-abc1234".to_string(),
            version: "2026.04.15-100000-abc1234".to_string(),
        };
        let status = check_version("2026.04.13-def5678", &latest);
        assert!(matches!(status, VersionStatus::UpdateAvailable { .. }));
    }

    #[test]
    fn version_same_day_different_time() {
        // Same day but different time → later time is newer
        let latest = Release {
            tag: "cplt/2026.04.13-180000-abc1234".to_string(),
            version: "2026.04.13-180000-abc1234".to_string(),
        };
        let status = check_version("2026.04.13-120000-def5678", &latest);
        assert!(matches!(status, VersionStatus::UpdateAvailable { .. }));
    }

    #[test]
    fn sha256sums_parsing() {
        let sums = "abc123def456  cplt-aarch64-apple-darwin.tar.gz\nxyz789uvw012  cplt-x86_64-apple-darwin.tar.gz\n";
        assert_eq!(
            parse_sha256sums(sums, "cplt-aarch64-apple-darwin.tar.gz").unwrap(),
            "abc123def456"
        );
        assert_eq!(
            parse_sha256sums(sums, "cplt-x86_64-apple-darwin.tar.gz").unwrap(),
            "xyz789uvw012"
        );
    }

    #[test]
    fn sha256sums_missing_asset() {
        let sums = "abc123  cplt-aarch64-apple-darwin.tar.gz\n";
        assert!(parse_sha256sums(sums, "cplt-x86_64-apple-darwin.tar.gz").is_err());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn asset_name_aarch64() {
        assert_eq!(asset_name("aarch64"), "cplt-aarch64-apple-darwin.tar.gz");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn asset_name_x86_64() {
        assert_eq!(asset_name("x86_64"), "cplt-x86_64-apple-darwin.tar.gz");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn asset_name_aarch64_linux() {
        assert_eq!(
            asset_name("aarch64"),
            "cplt-aarch64-unknown-linux-gnu.tar.gz"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn asset_name_x86_64_linux() {
        assert_eq!(asset_name("x86_64"), "cplt-x86_64-unknown-linux-gnu.tar.gz");
    }

    #[test]
    fn homebrew_detection_cellar_path() {
        // Can't easily test is_homebrew_managed() since it reads current_exe,
        // but we can verify the logic conceptually via path patterns
        let cellar_path = "/opt/homebrew/Cellar/cplt/2026.04.13/bin/cplt";
        assert!(cellar_path.contains("/Cellar/") || cellar_path.contains("/homebrew/"));

        let direct_path = "/usr/local/bin/cplt";
        assert!(!direct_path.contains("/Cellar/"));
    }

    #[test]
    fn tag_prefix_stripping() {
        let tag = "cplt/2026.04.13-abc1234";
        let version = tag.strip_prefix("cplt/").unwrap_or(tag);
        assert_eq!(version, "2026.04.13-abc1234");

        let bare_tag = "2026.04.13-abc1234";
        let version2 = bare_tag.strip_prefix("cplt/").unwrap_or(bare_tag);
        assert_eq!(version2, "2026.04.13-abc1234");
    }
}
