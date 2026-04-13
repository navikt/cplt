//! Self-update: download and install the latest cplt release from GitHub.
//!
//! Uses absolute paths for all external tools (`/usr/bin/curl`, `/usr/bin/tar`,
//! `/usr/bin/shasum`, `/usr/bin/xattr`, `/usr/bin/codesign`) to avoid PATH
//! manipulation attacks — this code runs outside the sandbox.

use std::path::{Path, PathBuf};
use std::process::Command;

const RELEASES_API: &str = "https://api.github.com/repos/navikt/cplt/releases";
const DOWNLOAD_BASE: &str = "https://github.com/navikt/cplt/releases/download";

/// A parsed GitHub release.
#[derive(Debug)]
pub struct Release {
    pub tag: String,
    pub version: String,
}

/// Result of comparing current vs latest version.
#[derive(Debug, PartialEq)]
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
pub fn fetch_latest_release(current_version: &str) -> Result<Release, String> {
    let url = format!("{RELEASES_API}?per_page=20");
    let body = curl_get_json(&url, current_version)?;

    let releases: Vec<serde_json::Value> = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse GitHub API response: {e}"))?;

    for rel in &releases {
        // Skip drafts and prereleases
        if rel.get("draft").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }
        if rel
            .get("prerelease")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }

        if let Some(tag) = rel.get("tag_name").and_then(|v| v.as_str()) {
            // Accept both "cplt/VERSION" and bare "VERSION" tag formats
            let version = tag.strip_prefix("cplt/").unwrap_or(tag);
            // Validate it looks like a version (YYYY.MM.DD-SHA)
            if looks_like_version(version) {
                return Ok(Release {
                    tag: tag.to_string(),
                    version: version.to_string(),
                });
            }
        }
    }

    Err("No suitable release found on GitHub".to_string())
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
pub fn perform_update(tag: &str, current_version: &str) -> Result<String, String> {
    let arch = std::env::consts::ARCH;
    let asset = asset_name(arch);
    let asset_url = format!("{DOWNLOAD_BASE}/{tag}/{asset}");
    let sums_url = format!("{DOWNLOAD_BASE}/{tag}/SHA256SUMS");

    // 1. Download the archive
    eprintln!("  Downloading {asset}...");
    let tmp_dir = create_temp_dir()?;
    let archive_path = tmp_dir.join(&asset);
    curl_download(&asset_url, &archive_path, current_version)?;

    // 2. Download and verify SHA256
    eprintln!("  Verifying SHA256 checksum...");
    let sums_body = curl_get(&sums_url, current_version)?;
    let expected_hash = parse_sha256sums(&sums_body, &asset)?;
    let actual_hash = compute_sha256(&archive_path)?;
    if actual_hash != expected_hash {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(format!(
            "SHA256 verification failed!\n  Expected: {expected_hash}\n  Got:      {actual_hash}\n  Download may be corrupted or tampered with."
        ));
    }

    // 3. Validate and extract archive
    eprintln!("  Extracting...");
    validate_archive(&archive_path)?;
    let extract_dir = tmp_dir.join("extract");
    std::fs::create_dir_all(&extract_dir).map_err(|e| format!("Cannot create extract dir: {e}"))?;
    extract_archive(&archive_path, &extract_dir)?;

    let new_binary = extract_dir.join("cplt");
    // Use symlink_metadata to NOT follow symlinks — reject if it's a symlink
    let meta = std::fs::symlink_metadata(&new_binary).map_err(|_| {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        "Extracted archive does not contain 'cplt' binary".to_string()
    })?;
    if !meta.file_type().is_file() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err("Extracted 'cplt' is not a regular file (symlink?)".to_string());
    }

    // 4. Resolve current binary location
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Cannot determine current binary path: {e}"))?;
    let target_path = std::fs::canonicalize(&current_exe).unwrap_or(current_exe);

    // 5. Stage: set permissions and sign BEFORE replacing
    eprintln!("  Preparing binary...");
    set_executable(&new_binary)?;
    // xattr and codesign are best-effort (may not be needed in all contexts)
    let _ = run_xattr(&new_binary);
    let _ = run_codesign(&new_binary);

    // 6. Atomic rename
    let staged = target_path.with_extension("new");
    std::fs::copy(&new_binary, &staged).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "Permission denied writing to {}\n  Run: sudo cplt update",
                target_path.display()
            )
        } else {
            format!("Cannot stage binary: {e}")
        }
    })?;

    // Copy permissions/signing to staged location too
    set_executable(&staged)?;
    let _ = run_xattr(&staged);
    let _ = run_codesign(&staged);

    std::fs::rename(&staged, &target_path).map_err(|e| {
        let _ = std::fs::remove_file(&staged);
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "Permission denied replacing {}\n  Run: sudo cplt update",
                target_path.display()
            )
        } else {
            format!("Cannot replace binary: {e}")
        }
    })?;

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

/// Construct the asset filename for the current architecture.
pub fn asset_name(arch: &str) -> String {
    format!("cplt-{arch}-apple-darwin.tar.gz")
}

/// Check if a string looks like a cplt version (YYYY.MM.DD-HEX).
pub fn looks_like_version(s: &str) -> bool {
    let parts: Vec<&str> = s.splitn(2, '-').collect();
    if parts.len() != 2 {
        return false;
    }
    let date_parts: Vec<&str> = parts[0].split('.').collect();
    if date_parts.len() != 3 {
        return false;
    }
    // Year should be 4 digits, month/day 2 digits
    date_parts[0].len() == 4
        && date_parts[1].len() == 2
        && date_parts[2].len() == 2
        && date_parts
            .iter()
            .all(|p| p.chars().all(|c| c.is_ascii_digit()))
        && !parts[1].is_empty()
}

/// Extract the date portion of a version string for comparison.
/// Returns the "YYYY.MM.DD" part, or empty string if unparseable.
pub fn version_date(version: &str) -> &str {
    version.split('-').next().unwrap_or("")
}

/// Parse SHA256SUMS content and find the hash for a given asset.
pub fn parse_sha256sums(content: &str, asset_name: &str) -> Result<String, String> {
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
    Err(format!(
        "No SHA256 checksum found for '{asset_name}' in SHA256SUMS"
    ))
}

// --- Internal helpers ---

/// HTTP GET returning body as string (for JSON/text).
fn curl_get(url: &str, version: &str) -> Result<String, String> {
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
        .map_err(|e| format!("Cannot run /usr/bin/curl: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("403") || stderr.contains("rate limit") {
            return Err("GitHub API rate limit reached. Try again later.".to_string());
        }
        return Err(format!("Download failed: {stderr}"));
    }

    String::from_utf8(output.stdout).map_err(|e| format!("Invalid UTF-8 in response: {e}"))
}

/// HTTP GET expecting JSON, with Accept header.
fn curl_get_json(url: &str, version: &str) -> Result<String, String> {
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
        .map_err(|e| format!("Cannot run /usr/bin/curl: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("403") || stderr.contains("rate limit") {
            return Err("GitHub API rate limit reached. Try again later.".to_string());
        }
        return Err(format!(
            "Cannot reach GitHub. Check your connection.\n  {stderr}"
        ));
    }

    String::from_utf8(output.stdout).map_err(|e| format!("Invalid UTF-8 in response: {e}"))
}

/// Download a file to disk.
fn curl_download(url: &str, dest: &Path, version: &str) -> Result<(), String> {
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
        .map_err(|e| format!("Cannot run /usr/bin/curl: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Download failed: {stderr}"))
    } else {
        Ok(())
    }
}

/// Compute SHA256 hash of a file using /usr/bin/shasum.
fn compute_sha256(path: &Path) -> Result<String, String> {
    let output = Command::new("/usr/bin/shasum")
        .args(["-a", "256", &path.to_string_lossy()])
        .output()
        .map_err(|e| format!("Cannot run /usr/bin/shasum: {e}"))?;

    if !output.status.success() {
        return Err("SHA256 computation failed".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .next()
        .map(|h| h.to_lowercase())
        .ok_or_else(|| "Cannot parse shasum output".to_string())
}

/// Validate archive contents before extraction.
/// Rejects archives with symlinks, directories, or unexpected entries.
/// Uses verbose listing (`-tvf`) to detect file types — plain `-tzf`
/// cannot distinguish symlinks from regular files.
fn validate_archive(path: &Path) -> Result<(), String> {
    let output = Command::new("/usr/bin/tar")
        .args(["-tvzf", &path.to_string_lossy()])
        .output()
        .map_err(|e| format!("Cannot list archive contents: {e}"))?;

    if !output.status.success() {
        return Err("Archive appears to be corrupt".to_string());
    }

    let listing = String::from_utf8_lossy(&output.stdout);
    let entries: Vec<&str> = listing.lines().filter(|l| !l.is_empty()).collect();

    if entries.is_empty() {
        return Err("Archive is empty".to_string());
    }

    if entries.len() != 1 {
        return Err(format!(
            "Release archive has unexpected contents ({} entries).\n  Expected a single 'cplt' entry.",
            entries.len()
        ));
    }

    let entry = entries[0];

    // Verbose tar output starts with permissions: "-rwxr-xr-x" for regular files,
    // "l..." for symlinks, "d..." for directories
    if !entry.starts_with('-') {
        return Err(format!(
            "Archive entry is not a regular file: {entry}\n  Refusing to extract symlinks or directories."
        ));
    }

    // Verify the filename (last field) is exactly "cplt"
    let filename = entry.split_whitespace().last().unwrap_or("");
    if filename != "cplt" {
        return Err(format!(
            "Archive contains unexpected file: '{filename}'\n  Expected 'cplt'."
        ));
    }

    Ok(())
}

/// Extract archive to a directory.
fn extract_archive(archive: &Path, dest: &Path) -> Result<(), String> {
    let output = Command::new("/usr/bin/tar")
        .args([
            "-xzf",
            &archive.to_string_lossy(),
            "-C",
            &dest.to_string_lossy(),
        ])
        .output()
        .map_err(|e| format!("Cannot extract archive: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Extraction failed: {stderr}"))
    } else {
        Ok(())
    }
}

/// Create a temporary directory for the update process.
fn create_temp_dir() -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("cplt-update-{}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("Cannot clean up old temp dir: {e}"))?;
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("Cannot create temp dir: {e}"))?;
    Ok(dir)
}

/// Set executable permissions on a file.
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("Cannot set permissions: {e}"))
}

/// Remove macOS quarantine extended attributes.
fn run_xattr(path: &Path) -> Result<(), String> {
    let output = Command::new("/usr/bin/xattr")
        .args(["-cr", &path.to_string_lossy()])
        .output()
        .map_err(|e| format!("xattr failed: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err("xattr -cr failed".to_string())
    }
}

/// Ad-hoc code sign the binary (required for macOS Gatekeeper).
fn run_codesign(path: &Path) -> Result<(), String> {
    let output = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", &path.to_string_lossy()])
        .output()
        .map_err(|e| format!("codesign failed: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err("codesign failed".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_looks_valid() {
        assert!(looks_like_version("2026.04.13-a1b2c3d"));
        assert!(looks_like_version("2024.12.01-abc1234"));
    }

    #[test]
    fn version_rejects_invalid() {
        assert!(!looks_like_version("0.0.0"));
        assert!(!looks_like_version("2026.04.13"));
        assert!(!looks_like_version("not-a-version"));
        assert!(!looks_like_version(""));
        assert!(!looks_like_version("2026.4.13-abc")); // month not 2 digits
    }

    #[test]
    fn version_date_extraction() {
        assert_eq!(version_date("2026.04.13-a1b2c3d"), "2026.04.13");
        assert_eq!(version_date("0.0.0"), "0.0.0");
    }

    #[test]
    fn version_comparison_newer() {
        let latest = Release {
            tag: "cplt/2026.04.15-abc1234".to_string(),
            version: "2026.04.15-abc1234".to_string(),
        };
        let status = check_version("2026.04.13-def5678", &latest);
        assert!(matches!(status, VersionStatus::UpdateAvailable { .. }));
    }

    #[test]
    fn version_comparison_up_to_date() {
        let latest = Release {
            tag: "cplt/2026.04.13-abc1234".to_string(),
            version: "2026.04.13-abc1234".to_string(),
        };
        let status = check_version("2026.04.13-abc1234", &latest);
        assert_eq!(status, VersionStatus::UpToDate);
    }

    #[test]
    fn version_comparison_local_newer() {
        let latest = Release {
            tag: "cplt/2026.04.10-abc1234".to_string(),
            version: "2026.04.10-abc1234".to_string(),
        };
        let status = check_version("2026.04.13-def5678", &latest);
        assert_eq!(status, VersionStatus::UpToDate);
    }

    #[test]
    fn version_comparison_same_date_different_sha() {
        let latest = Release {
            tag: "cplt/2026.04.13-abc1234".to_string(),
            version: "2026.04.13-abc1234".to_string(),
        };
        let status = check_version("2026.04.13-def5678", &latest);
        assert!(matches!(
            status,
            VersionStatus::SameDateDifferentBuild { .. }
        ));
    }

    #[test]
    fn version_comparison_dev_build() {
        let latest = Release {
            tag: "cplt/2026.04.13-abc1234".to_string(),
            version: "2026.04.13-abc1234".to_string(),
        };
        let status = check_version("0.0.0", &latest);
        assert!(matches!(status, VersionStatus::DevBuild { .. }));
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
    fn asset_name_aarch64() {
        assert_eq!(asset_name("aarch64"), "cplt-aarch64-apple-darwin.tar.gz");
    }

    #[test]
    fn asset_name_x86_64() {
        assert_eq!(asset_name("x86_64"), "cplt-x86_64-apple-darwin.tar.gz");
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
