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
    /// List of approved key names (e.g. ["allow_localhost_any", "allow_jvm_attach"]).
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
/// Uses the canonical remote URL (preferred) or the absolute project path
/// as fallback. Returns a hex-encoded SHA-256 prefix (16 chars) for use
/// as a filename.
///
/// Uses SHA-256 (truncated to 64 bits) for cross-version stability.
/// `DefaultHasher` is explicitly non-portable across Rust versions.
pub fn repo_fingerprint(project_dir: &Path) -> String {
    let identity =
        canonical_remote(project_dir).unwrap_or_else(|| project_dir.to_string_lossy().into_owned());

    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(identity.as_bytes());
    // First 8 bytes → 16 hex chars (same length as before)
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]
    )
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
fn normalize_remote_url(url: &str) -> String {
    let url = url.trim();

    // SSH: git@host:org/repo.git
    if let Some(rest) = url.strip_prefix("git@")
        && let Some((host, path)) = rest.split_once(':')
    {
        let path = path.trim_end_matches(".git").trim_end_matches('/');
        return format!("{}/{}", host.to_lowercase(), path);
    }

    // HTTPS: https://host/org/repo.git
    if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        let rest = rest.trim_end_matches(".git").trim_end_matches('/');
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
/// Returns `~/.config/cplt/trust/` (or `$CPLT_CONFIG/../trust/` if overridden).
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
pub fn save_trust(project_dir: &Path, entry: &TrustEntry) -> Result<(), String> {
    let dir = trust_dir().ok_or("Cannot determine trust store directory")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("Cannot create trust directory: {e}"))?;

    let fingerprint = repo_fingerprint(project_dir);
    let trust_file = dir.join(format!("{fingerprint}.toml"));

    let content =
        toml::to_string_pretty(entry).map_err(|e| format!("Cannot serialize trust entry: {e}"))?;

    std::fs::write(&trust_file, content).map_err(|e| format!("Cannot write trust file: {e}"))?;

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

/// Get the current timestamp in ISO 8601 format.
pub fn now_iso8601() -> String {
    // Simple implementation without chrono dependency
    let output = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok();

    output
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Compute a stable content hash of the proposal section.
///
/// This hash captures the *values* of all proposals so that if the
/// `.cplt.toml` changes (e.g. adding new paths to `allow.read`),
/// existing approvals are invalidated and the user must re-approve.
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

    // Path/port proposals
    for p in &propose.allow.read {
        hasher.update(format!("allow.read={p}\n").as_bytes());
    }
    for p in &propose.allow.write {
        hasher.update(format!("allow.write={p}\n").as_bytes());
    }
    for port in &propose.allow.ports {
        hasher.update(format!("allow.ports={port}\n").as_bytes());
    }
    for port in &propose.allow.localhost {
        hasher.update(format!("allow.localhost={port}\n").as_bytes());
    }
    for d in &propose.proxy.allow_private_domains {
        hasher.update(format!("proxy.allow_private_domains={d}\n").as_bytes());
    }

    let hash = hasher.finalize();
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]
    )
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
    fn fingerprint_is_stable() {
        let fp1 = repo_fingerprint(Path::new("/home/user/project"));
        let fp2 = repo_fingerprint(Path::new("/home/user/project"));
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);
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
        assert_eq!(hash1.len(), 16); // 8 bytes = 16 hex chars
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
}
