//! Trust store for per-repo config approval.
//!
//! When a `.cplt.toml` file proposes expansive permissions (relaxing the sandbox),
//! the user must explicitly approve them. Approval decisions are stored in
//! `~/.config/cplt/trust/<repo-fingerprint>.toml`.
//!
//! The trust store is protected by the sandbox (write access to `~/.config/cplt/`
//! is denied inside the sandbox), so the agent cannot approve its own proposals.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Subdirectory within the cplt config dir for trust entries.
const TRUST_DIR: &str = "trust";

/// A trust entry recording which proposals have been approved for a repo.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct TrustEntry {
    /// Repository identification.
    pub repo: RepoIdentity,
    /// Approved proposal keys.
    pub accepted: AcceptedProposals,
}

/// Identifies the repository this trust entry applies to.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct RepoIdentity {
    /// Canonical remote URL (e.g. "github.com/navikt/spleis").
    #[serde(default)]
    pub remote: String,
    /// Absolute path on disk (for repos without remotes).
    #[serde(default)]
    pub path: String,
}

/// Which proposal keys have been approved.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct AcceptedProposals {
    /// List of approved key names (e.g. `["allow_localhost_any", "allow_jvm_attach"]`).
    #[serde(default)]
    pub keys: Vec<String>,
    /// When approval was last updated (ISO 8601).
    #[serde(default)]
    pub approved_at: String,
    /// SHA-256 hash of the proposal values at approval time.
    /// If the .cplt.toml proposals change, this hash won't match and
    /// approvals are invalidated (user must re-approve).
    #[serde(default)]
    pub content_hash: String,
}

/// Compute a stable fingerprint for a repository.
///
/// Uses the canonical remote URL (preferred) or the canonicalized absolute
/// project path as fallback. Returns a hex-encoded SHA-256 (full 64 chars)
/// for use as a filename. This ensures collision resistance and stability
/// across Rust versions/platforms.
///
/// # Security — the fingerprint is NOT an authenticity signal
///
/// The remote URL is attacker-controllable (`git remote set-url origin
/// <victim>`), so the fingerprint alone cannot prove that a repo is the one an
/// approval was granted for. Consumers MUST additionally verify the local
/// checkout path with [`approved_path_matches`] before applying a trust
/// entry's approved keys. See that function's docs for the confused-deputy
/// attack this defends against.
pub fn repo_fingerprint(project_dir: &Path) -> String {
    let identity = canonical_remote(project_dir).unwrap_or_else(|| {
        // Canonicalize to handle symlinks/relative paths consistently
        std::fs::canonicalize(project_dir).map_or_else(
            |_| project_dir.to_string_lossy().into_owned(),
            |p| p.to_string_lossy().into_owned(),
        )
    });

    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(identity.as_bytes());
    // Full SHA-256 hex (64 chars) — collision-resistant
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Get the canonical remote URL for the git repo at `project_dir`.
///
/// Normalizes: strips `.git` suffix, lowercases host, converts SSH to HTTPS style.
fn canonical_remote(project_dir: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(project_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let url = String::from_utf8(output.stdout).ok()?;
    Some(normalize_remote_url(url.trim()))
}

/// Normalize a git remote URL to a canonical form.
///
/// - `git@github.com:org/repo.git` → `github.com/org/repo`
/// - `https://github.com/org/repo.git` → `github.com/org/repo`
/// - Lowercases the host portion.
pub fn normalize_remote_url(url: &str) -> String {
    let url = url.trim();

    // SSH scheme: ssh://[user@]host[:port]/org/repo.git
    if let Some(rest) = url.strip_prefix("ssh://") {
        // Strip user@ prefix if present
        let rest = if let Some((_user, after)) = rest.split_once('@') {
            after
        } else {
            rest
        };
        // Strip optional :port before path
        let rest = rest.trim_end_matches(".git").trim_end_matches('/');
        if let Some((host_port, path)) = rest.split_once('/') {
            let host = host_port.split(':').next().unwrap_or(host_port);
            return format!("{}/{}", host.to_lowercase(), path);
        }
        return rest.to_lowercase();
    }

    // SSH shorthand: git@host:org/repo.git (also handles user@host:path)
    if let Some((user_host, path)) = url.split_once(':')
        && !path.starts_with("//")
        && user_host.contains('@')
    {
        let host = user_host.rsplit_once('@').map_or(user_host, |(_, h)| h);
        let path = path.trim_end_matches(".git").trim_end_matches('/');
        return format!("{}/{}", host.to_lowercase(), path);
    }

    // HTTPS/HTTP: https://host/org/repo.git
    if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        let rest = rest.trim_end_matches(".git").trim_end_matches('/');
        // Strip optional user@ (e.g., https://token@github.com/org/repo)
        let rest = if let Some((_cred, after)) = rest.split_once('@') {
            after
        } else {
            rest
        };
        // Lowercase only the host portion
        if let Some((host, path)) = rest.split_once('/') {
            return format!("{}/{}", host.to_lowercase(), path);
        }
        return rest.to_lowercase();
    }

    // Fallback: use as-is
    url.to_string()
}

/// Resolve the trust store directory path.
///
/// Returns `~/.config/cplt/trust/` by default, or `<parent of $CPLT_CONFIG>/trust/`
/// if the `CPLT_CONFIG` env var overrides the config file location.
pub fn trust_dir() -> Option<PathBuf> {
    let config_dir = crate::config::config_dir()?;
    Some(config_dir.join(TRUST_DIR))
}

/// Load the trust entry for a repository.
///
/// Returns `None` if no trust file exists (repo has never been approved).
pub fn load_trust(project_dir: &Path) -> Option<TrustEntry> {
    let fingerprint = repo_fingerprint(project_dir);
    let trust_file = trust_dir()?.join(format!("{fingerprint}.toml"));

    let content = std::fs::read_to_string(&trust_file).ok()?;
    toml::from_str(&content).ok()
}

/// Save a trust entry for a repository.
///
/// Creates the trust directory if it doesn't exist.
/// Uses atomic write (temp file + rename) to prevent corruption on crash.
pub fn save_trust(project_dir: &Path, entry: &TrustEntry) -> Result<(), String> {
    let dir = trust_dir().ok_or("Cannot determine trust store directory")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("Cannot create trust directory: {e}"))?;

    let fingerprint = repo_fingerprint(project_dir);
    let trust_file = dir.join(format!("{fingerprint}.toml"));
    let tmp_file = dir.join(format!(".{fingerprint}.toml.tmp"));

    let content =
        toml::to_string_pretty(entry).map_err(|e| format!("Cannot serialize trust entry: {e}"))?;

    // Write to temp file first, then atomically rename
    std::fs::write(&tmp_file, &content)
        .map_err(|e| format!("Cannot write temp trust file: {e}"))?;
    std::fs::rename(&tmp_file, &trust_file)
        .map_err(|e| format!("Cannot rename trust file: {e}"))?;

    Ok(())
}

/// Remove the trust entry for a repository.
pub fn revoke_trust(project_dir: &Path) -> Result<(), String> {
    let fingerprint = repo_fingerprint(project_dir);
    let Some(dir) = trust_dir() else {
        return Ok(());
    };
    let trust_file = dir.join(format!("{fingerprint}.toml"));

    if trust_file.exists() {
        std::fs::remove_file(&trust_file).map_err(|e| format!("Cannot remove trust file: {e}"))?;
    }
    Ok(())
}

/// Check if a specific key is approved for a repository.
pub fn is_key_approved(trust: &TrustEntry, key: &str) -> bool {
    trust.accepted.keys.iter().any(|k| k == key)
}

/// Filter a list of proposed keys to only those that are approved.
pub fn filter_approved<'a>(proposed: &[&'a str], trust: &TrustEntry) -> Vec<&'a str> {
    proposed
        .iter()
        .filter(|&&key| is_key_approved(trust, key))
        .copied()
        .collect()
}

/// Filter a list of proposed keys to only those NOT yet approved.
pub fn filter_unapproved<'a>(proposed: &[&'a str], trust: &TrustEntry) -> Vec<&'a str> {
    proposed
        .iter()
        .filter(|&&key| !is_key_approved(trust, key))
        .copied()
        .collect()
}

/// Get the current timestamp in ISO 8601 format (UTC).
///
/// Uses `std::time::SystemTime` — no external dependencies or shell-outs.
pub fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Convert unix timestamp to UTC date components
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Civil date from days since epoch (algorithm from Howard Hinnant)
    let z = days as i64 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Compute a stable content hash of the proposal section.
///
/// This hash captures the *values* of all proposals so that if the
/// `.cplt.toml` changes (e.g. adding new paths to `allow.read`),
/// existing approvals are invalidated and the user must re-approve.
///
/// Arrays are sorted before hashing so reordering entries does not
/// invalidate approvals. Full SHA-256 hex is used (64 chars) for
/// collision resistance.
pub fn proposal_content_hash(propose: &crate::repo_config::ProposeSection) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    // Boolean proposals — sorted by key name for stability
    let bools: &[(&str, Option<bool>)] = &[
        ("allow_browser", propose.allow_browser),
        ("allow_docker", propose.allow_docker),
        ("allow_env_files", propose.allow_env_files),
        ("allow_gpg_signing", propose.allow_gpg_signing),
        ("allow_jvm_attach", propose.allow_jvm_attach),
        ("allow_lifecycle_scripts", propose.allow_lifecycle_scripts),
        ("allow_localhost_any", propose.allow_localhost_any),
        ("allow_tmp_exec", propose.allow_tmp_exec),
    ];
    for (name, val) in bools {
        if let Some(v) = val {
            hasher.update(format!("{name}={v}\n").as_bytes());
        }
    }

    // Path/port proposals — sorted for order-independence
    let mut read: Vec<&str> = propose
        .allow
        .read
        .iter()
        .map(std::string::String::as_str)
        .collect();
    read.sort_unstable();
    for p in &read {
        hasher.update(format!("allow.read={p}\n").as_bytes());
    }

    let mut write: Vec<&str> = propose
        .allow
        .write
        .iter()
        .map(std::string::String::as_str)
        .collect();
    write.sort_unstable();
    for p in &write {
        hasher.update(format!("allow.write={p}\n").as_bytes());
    }

    // Unix-socket proposals are proposable AND applied (apply_repo_config), and a
    // socket like /var/run/docker.sock is a host-escape vector. They MUST be part
    // of the pinned content so a trusted repo cannot later add or change
    // `[propose.allow] socket=[…]` without re-approval.
    let mut socket: Vec<&str> = propose
        .allow
        .socket
        .iter()
        .map(std::string::String::as_str)
        .collect();
    socket.sort_unstable();
    for p in &socket {
        hasher.update(format!("allow.socket={p}\n").as_bytes());
    }

    let mut ports: Vec<u16> = propose.allow.ports.clone();
    ports.sort_unstable();
    for port in &ports {
        hasher.update(format!("allow.ports={port}\n").as_bytes());
    }

    let mut localhost: Vec<u16> = propose.allow.localhost.clone();
    localhost.sort_unstable();
    for port in &localhost {
        hasher.update(format!("allow.localhost={port}\n").as_bytes());
    }

    let mut domains: Vec<&str> = propose
        .proxy
        .allow_private_domains
        .iter()
        .map(std::string::String::as_str)
        .collect();
    domains.sort_unstable();
    for d in &domains {
        hasher.update(format!("proxy.allow_private_domains={d}\n").as_bytes());
    }

    let hash = hasher.finalize();
    // Full SHA-256 hex (64 chars) — collision-resistant content pinning
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decide whether a stored approval is stale relative to the current proposal
/// content hash and must be re-approved before its keys can be applied.
///
/// Security: an EMPTY `stored_hash` is a legacy trust file written before content
/// pinning existed. It pins nothing, so it MUST be treated as stale — never as a
/// match. If it were treated as "matches", the previously-approved keys would be
/// applied against arbitrary (possibly malicious) proposal *values* with no
/// re-prompt. Any mismatch — including empty-vs-current — invalidates, forcing a
/// one-time re-approval that writes a real hash.
pub fn approval_is_stale(stored_hash: &str, current_hash: &str) -> bool {
    stored_hash != current_hash
}

/// Check whether a trust entry was approved at the current local checkout path.
///
/// # Why (Finding 4 — trust identity is a spoofable git origin URL)
///
/// [`repo_fingerprint`] keys the trust store on the normalized git remote URL,
/// which the repo can forge: a malicious checkout can `git remote set-url
/// origin <victim>` and copy the victim's approved `[propose]` block verbatim
/// (so the pinned content hash matches too) to inherit the victim's approved
/// dangerous permissions with no re-prompt — a classic confused-deputy
/// escalation. An origin-URL match is therefore NOT sufficient authentication.
///
/// To defeat this we additionally bind every approval to the absolute *local
/// checkout path* where it was granted (recorded in `repo.path`). Presenting a
/// trusted fingerprint from a DIFFERENT on-disk location no longer auto-applies
/// — the user must re-approve. An attacker cannot place their repo at the
/// victim's exact path without already controlling that location.
///
/// Both sides are canonicalized (resolving symlinks / `.` / `..`) so cosmetic
/// path differences don't force spurious re-approval — the same repo at the
/// same path stays trusted. A legacy entry with an empty `path` (written before
/// path binding existed) matches nothing, forcing a one-time re-approval that
/// records the real path.
///
/// # Fail-closed
///
/// This is a security gate, so canonicalization failure MUST be treated as a
/// mismatch, never as a match. If *either* the stored approved path or the
/// current project path cannot be canonicalized (missing, unreadable, symlink
/// loop, …) the comparison of raw strings could be spoofed or could silently
/// pass on non-normalized input, so we return `false` (not trusted → re-approval
/// required) rather than falling back to a lexical comparison.
pub fn approved_path_matches(entry: &TrustEntry, project_dir: &Path) -> bool {
    if entry.repo.path.is_empty() {
        return false;
    }
    // Fail closed: a canonicalize error on either side means "not trusted".
    let (Ok(stored), Ok(current)) = (
        std::fs::canonicalize(Path::new(&entry.repo.path)),
        std::fs::canonicalize(project_dir),
    ) else {
        return false;
    };
    stored == current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_ssh_url() {
        assert_eq!(
            normalize_remote_url("git@github.com:navikt/spleis.git"),
            "github.com/navikt/spleis"
        );
    }

    #[test]
    fn normalize_https_url() {
        assert_eq!(
            normalize_remote_url("https://github.com/navikt/spleis.git"),
            "github.com/navikt/spleis"
        );
    }

    #[test]
    fn normalize_https_no_git_suffix() {
        assert_eq!(
            normalize_remote_url("https://github.com/navikt/spleis"),
            "github.com/navikt/spleis"
        );
    }

    #[test]
    fn normalize_trailing_slash() {
        assert_eq!(
            normalize_remote_url("https://github.com/navikt/spleis/"),
            "github.com/navikt/spleis"
        );
    }

    #[test]
    fn normalize_lowercases_host() {
        assert_eq!(
            normalize_remote_url("https://GitHub.COM/navikt/spleis.git"),
            "github.com/navikt/spleis"
        );
    }

    #[test]
    fn normalize_ssh_scheme_url() {
        assert_eq!(
            normalize_remote_url("ssh://git@github.com/navikt/spleis.git"),
            "github.com/navikt/spleis"
        );
    }

    #[test]
    fn normalize_ssh_scheme_with_port() {
        assert_eq!(
            normalize_remote_url("ssh://git@github.com:22/navikt/spleis.git"),
            "github.com/navikt/spleis"
        );
    }

    #[test]
    fn normalize_ssh_deploy_user() {
        // deploy@ instead of git@
        assert_eq!(
            normalize_remote_url("deploy@github.com:navikt/spleis.git"),
            "github.com/navikt/spleis"
        );
    }

    #[test]
    fn normalize_https_with_token() {
        // CI often uses https://x-access-token:TOKEN@github.com/org/repo
        assert_eq!(
            normalize_remote_url("https://x-access-token:ghp_abc@github.com/navikt/spleis.git"),
            "github.com/navikt/spleis"
        );
    }

    #[test]
    fn normalize_all_variants_same_fingerprint() {
        let variants = [
            "git@github.com:navikt/spleis.git",
            "https://github.com/navikt/spleis.git",
            "ssh://git@github.com/navikt/spleis.git",
            "ssh://git@github.com:22/navikt/spleis.git",
            "https://github.com/navikt/spleis",
            "deploy@github.com:navikt/spleis.git",
            "https://x-token:abc@github.com/navikt/spleis.git",
        ];
        let normalized: Vec<_> = variants.iter().map(|u| normalize_remote_url(u)).collect();
        for n in &normalized {
            assert_eq!(n, "github.com/navikt/spleis", "failed for variant");
        }
    }

    #[test]
    fn fingerprint_is_stable() {
        let fp1 = repo_fingerprint(Path::new("/home/user/project"));
        let fp2 = repo_fingerprint(Path::new("/home/user/project"));
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // Full SHA-256 hex
    }

    #[test]
    fn fingerprint_differs_for_different_paths() {
        let fp1 = repo_fingerprint(Path::new("/home/user/project-a"));
        let fp2 = repo_fingerprint(Path::new("/home/user/project-b"));
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn is_key_approved_works() {
        let entry = TrustEntry {
            accepted: AcceptedProposals {
                keys: vec![
                    "allow_localhost_any".to_string(),
                    "allow_jvm_attach".to_string(),
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(is_key_approved(&entry, "allow_localhost_any"));
        assert!(is_key_approved(&entry, "allow_jvm_attach"));
        assert!(!is_key_approved(&entry, "allow_docker"));
    }

    #[test]
    fn filter_approved_returns_intersection() {
        let entry = TrustEntry {
            accepted: AcceptedProposals {
                keys: vec!["allow_localhost_any".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let proposed = vec!["allow_localhost_any", "allow_jvm_attach", "allow_docker"];
        let approved = filter_approved(&proposed, &entry);
        assert_eq!(approved, vec!["allow_localhost_any"]);
    }

    #[test]
    fn filter_unapproved_returns_difference() {
        let entry = TrustEntry {
            accepted: AcceptedProposals {
                keys: vec!["allow_localhost_any".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let proposed = vec!["allow_localhost_any", "allow_jvm_attach"];
        let unapproved = filter_unapproved(&proposed, &entry);
        assert_eq!(unapproved, vec!["allow_jvm_attach"]);
    }

    #[test]
    fn trust_entry_roundtrip_serialization() {
        let entry = TrustEntry {
            repo: RepoIdentity {
                remote: "github.com/navikt/spleis".to_string(),
                path: "/home/user/spleis".to_string(),
            },
            accepted: AcceptedProposals {
                keys: vec![
                    "allow_localhost_any".to_string(),
                    "allow_jvm_attach".to_string(),
                ],
                approved_at: "2026-05-07T12:00:00Z".to_string(),
                content_hash: "a1b2c3d4e5f6a7b8".to_string(),
            },
        };

        let serialized = toml::to_string_pretty(&entry).unwrap();
        let deserialized: TrustEntry = toml::from_str(&serialized).unwrap();
        assert_eq!(entry, deserialized);
    }

    #[test]
    fn old_trust_file_without_content_hash_deserializes() {
        // Backward compat: trust files from before content pinning have no content_hash
        let toml_str = r#"
[repo]
remote = "github.com/navikt/spleis"
path = "/home/user/spleis"

[accepted]
keys = ["allow_localhost_any"]
approved_at = "2026-05-01T12:00:00Z"
"#;
        let entry: TrustEntry = toml::from_str(toml_str).unwrap();
        assert_eq!(entry.accepted.content_hash, ""); // empty = legacy, accepted
        assert_eq!(entry.accepted.keys, vec!["allow_localhost_any"]);
    }

    #[test]
    fn empty_stored_hash_is_stale() {
        // Legacy trust files have an empty content_hash. It must NOT be treated
        // as "matches" — it should invalidate and force re-approval. A non-empty
        // matching hash stays fresh; a non-empty differing hash is stale.
        let current = "a".repeat(64);
        assert!(
            approval_is_stale("", &current),
            "empty (legacy) stored hash must be treated as stale"
        );
        assert!(
            approval_is_stale("deadbeef", &current),
            "differing stored hash must be stale"
        );
        assert!(
            !approval_is_stale(&current, &current),
            "matching non-empty stored hash must stay fresh (no false re-prompt)"
        );
    }

    #[test]
    fn approved_path_matches_same_path() {
        // Same remote + same local checkout path → still trusted (no false re-prompt).
        let dir = std::env::temp_dir();
        let entry = TrustEntry {
            repo: RepoIdentity {
                remote: "github.com/navikt/spleis".to_string(),
                path: dir.to_string_lossy().into_owned(),
            },
            ..Default::default()
        };
        assert!(approved_path_matches(&entry, &dir));
    }

    #[test]
    fn approved_path_mismatch_is_not_trusted() {
        // Finding 4: a malicious repo with the victim's remote (same fingerprint,
        // same copied content hash) presented from a DIFFERENT local path must
        // NOT inherit the victim's approval — origin match alone is insufficient.
        let entry = TrustEntry {
            repo: RepoIdentity {
                remote: "github.com/navikt/spleis".to_string(),
                path: "/home/victim/spleis".to_string(),
            },
            ..Default::default()
        };
        assert!(!approved_path_matches(
            &entry,
            Path::new("/home/attacker/evil-clone")
        ));
    }

    #[test]
    fn approved_path_empty_legacy_is_not_trusted() {
        // A legacy entry (empty path, pre path-binding) pins no location, so it
        // must force a one-time re-approval rather than auto-trusting anywhere.
        let entry = TrustEntry {
            repo: RepoIdentity {
                remote: "github.com/navikt/spleis".to_string(),
                path: String::new(),
            },
            ..Default::default()
        };
        assert!(!approved_path_matches(
            &entry,
            Path::new("/home/user/spleis")
        ));
    }

    #[test]
    fn approved_path_noncanonicalizable_is_not_trusted() {
        // Fail-closed: if the stored approved path cannot be canonicalized (here,
        // a nonexistent path that is byte-for-byte identical to the current one),
        // the gate must NOT trust it. A lexical fallback would return `true` for
        // two identical raw strings even though neither resolves on disk, which
        // would let a spoofed/non-normalized path inherit an approval — so the
        // gate returns `false` and forces a re-approval instead.
        let missing = "/nonexistent-cplt-test-path/attacker/spleis";
        let entry = TrustEntry {
            repo: RepoIdentity {
                remote: "github.com/navikt/spleis".to_string(),
                path: missing.to_string(),
            },
            ..Default::default()
        };
        assert!(!approved_path_matches(&entry, Path::new(missing)));
    }

    #[test]
    fn proposal_content_hash_is_stable() {
        use crate::repo_config::{ProposeAllowSection, ProposeSection};

        let propose = ProposeSection {
            allow_docker: Some(true),
            allow: ProposeAllowSection {
                read: vec!["~/.gradle/gradle.properties".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let hash1 = proposal_content_hash(&propose);
        let hash2 = proposal_content_hash(&propose);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // Full SHA-256 hex
    }

    #[test]
    fn proposal_content_hash_changes_on_path_change() {
        use crate::repo_config::{ProposeAllowSection, ProposeSection};

        let propose1 = ProposeSection {
            allow: ProposeAllowSection {
                read: vec!["~/.gradle/gradle.properties".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let propose2 = ProposeSection {
            allow: ProposeAllowSection {
                read: vec!["/etc/shadow".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        assert_ne!(
            proposal_content_hash(&propose1),
            proposal_content_hash(&propose2)
        );
    }

    #[test]
    fn proposal_content_hash_changes_on_socket_change() {
        // Security: `propose.allow.socket` is applied by apply_repo_config and a
        // socket like /var/run/docker.sock is a host-escape vector. Changing it
        // must invalidate an existing approval, so it must alter the content hash.
        use crate::repo_config::{ProposeAllowSection, ProposeSection};

        let base = ProposeSection {
            allow: ProposeAllowSection {
                read: vec!["~/.gradle/gradle.properties".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let with_socket = ProposeSection {
            allow: ProposeAllowSection {
                read: vec!["~/.gradle/gradle.properties".to_string()],
                socket: vec!["/var/run/docker.sock".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        assert_ne!(
            proposal_content_hash(&base),
            proposal_content_hash(&with_socket),
            "adding a proposed socket must change the content hash"
        );

        // Changing the socket path must also change the hash.
        let with_other_socket = ProposeSection {
            allow: ProposeAllowSection {
                read: vec!["~/.gradle/gradle.properties".to_string()],
                socket: vec!["/tmp/other.sock".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_ne!(
            proposal_content_hash(&with_socket),
            proposal_content_hash(&with_other_socket),
            "changing a proposed socket path must change the content hash"
        );
    }

    #[test]
    fn proposal_content_hash_order_independent() {
        use crate::repo_config::{ProposeAllowSection, ProposeSection};

        let propose1 = ProposeSection {
            allow: ProposeAllowSection {
                read: vec!["b.txt".to_string(), "a.txt".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let propose2 = ProposeSection {
            allow: ProposeAllowSection {
                read: vec!["a.txt".to_string(), "b.txt".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(
            proposal_content_hash(&propose1),
            proposal_content_hash(&propose2)
        );
    }

    #[test]
    fn now_iso8601_format_valid() {
        let ts = now_iso8601();
        // Should match YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
    }
}
