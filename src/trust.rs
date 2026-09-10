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
    /// Repositories linked by approving `[propose] repos`, with the path each
    /// identity resolved to at approval time (#491).
    ///
    /// Recorded so `cplt trust revoke repos` can remove exactly the roots this
    /// approval created and leave the ones the user added by hand. Without it,
    /// `repos` would be the only proposal key whose grant survives its own
    /// revocation — the launch reads `sandbox.repo_dirs` and never consults the
    /// trust store.
    #[serde(default)]
    pub linked: Vec<LinkedRepo>,

    /// SHA-256 hash of the proposal values at approval time.
    /// If the .cplt.toml proposals change, this hash won't match and
    /// approvals are invalidated (user must re-approve).
    #[serde(default)]
    pub content_hash: String,
}

/// One repository linked by an approval: the identity that was approved, and
/// the path it resolved to on this machine.
///
/// The path is what the grant is. It is re-validated on every launch like any
/// other named root, and never re-resolved from the identity — otherwise a
/// later directory rename would silently redirect a grant the user approved for
/// a specific tree.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct LinkedRepo {
    pub identity: String,
    pub path: String,
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
pub(crate) fn canonical_remote(project_dir: &Path) -> Option<String> {
    let output = crate::git::command(project_dir, &["remote", "get-url", "origin"])?
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let url = String::from_utf8(output.stdout).ok()?;
    Some(normalize_remote_url(url.trim()))
}

/// Split `[user@]host[:port]/path` (a URL with its scheme already stripped)
/// into a lowercased host plus the path, dropping a trailing `.git` or `/`.
///
/// The authority ends at the FIRST `/`, and `user@` is stripped from *that
/// segment only*. Splitting the whole remainder on the first `@` — what both
/// the `ssh://` and the HTTPS branch used to do — let an `@` anywhere in the
/// path discard the real host: `https://evil.example/x@github.com/me/fork`
/// normalized to `github.com/me/fork` while git connected to `evil.example`,
/// which defeated `allow_push` URL pinning, the trust store and the gh
/// repo-scope comparison alike (GHSA-xcvh-hxfg-f4cg).
fn host_and_path(rest: &str) -> String {
    // Trailing slash first: `repo.git/` does not end in `.git`, so trimming the
    // suffix before the slash left it in place and an otherwise identical URL
    // normalized differently.
    let rest = rest
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .trim_end_matches('/');
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (rest, None),
    };
    // `rsplit_once`: the host is what follows the LAST `@` of the authority,
    // so a `user:pass@` containing an `@` cannot smuggle a host in either.
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.split(':').next().unwrap_or(host).to_lowercase();
    match path {
        Some(path) => format!("{host}/{path}"),
        None => host,
    }
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
        return host_and_path(rest);
    }

    // SSH shorthand: git@host:org/repo.git (also handles user@host:path)
    if let Some((user_host, path)) = url.split_once(':')
        && !path.starts_with("//")
        && user_host.contains('@')
    {
        let host = user_host.rsplit_once('@').map_or(user_host, |(_, h)| h);
        let path = path
            .trim_end_matches('/')
            .trim_end_matches(".git")
            .trim_end_matches('/');
        return format!("{}/{}", host.to_lowercase(), path);
    }

    // HTTPS/HTTP: https://[user@]host[:port]/org/repo.git
    if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        return host_and_path(rest);
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

/// Hash of everything a repository proposes, pinning an approval to the exact
/// values the user reviewed.
///
/// A stored hash that no longer matches makes the approval stale
/// ([`approval_is_stale`]), so the approved keys stop applying until the user
/// reviews the file again. That is the whole defence against a repository being
/// approved for one thing and later committing another.
///
/// The full SHA-256 hex (64 chars) is stored, not a prefix: this pins content
/// an adversary chooses, so collision resistance is the property being paid
/// for.
///
/// Two behaviours worth knowing:
///
/// - **Arrays are sorted first**, so reordering a proposal is not a change and
///   costs nobody a re-approval.
/// - **Unknown keys are hashed** (see [`crate::repo_config::RepoConfig::unknown`]),
///   which is a change from the hand-written hash this replaced. A key this
///   version cannot see grants nothing, so hashing it means an inert addition
///   costs one re-approval. The trade is deliberate: the alternative is a hash
///   that ignores part of the file it is supposed to pin, and it was exactly
///   that shape of exception — a field the hash did not cover — that let an
///   approval for `pass_env = ["TZ"]` survive into
///   `pass_env = ["AWS_SECRET_ACCESS_KEY"]` (#492).
pub fn proposal_content_hash(propose: &crate::repo_config::ProposeSection) -> String {
    use sha2::{Digest, Sha256};

    // Serialized whole, never field by field. The hand-written version listed
    // the fields it knew about, and `pass_env` was added to `[propose]` in #443
    // and never added here: an approval granted for `pass_env = ["TZ"]` went on
    // covering `pass_env = ["AWS_SECRET_ACCESS_KEY"]` with no re-prompt, because
    // the hash did not change. `gradle_init` was missing the same way. A list
    // that has to be updated in a second file every time a proposal is added is
    // a list that will be out of date again.
    //
    // JSON rather than TOML: `unknown` is a flattened map, and TOML refuses a
    // value emitted after a table, so a future key would make this fail to
    // serialize. Serialization order is the struct's declaration order and, for
    // `unknown`, the `BTreeMap`'s — both stable across runs and builds.
    //
    // `unknown` is included deliberately. A key this version cannot see grants
    // nothing, but the next version may understand it, and an approval given
    // when it was inert must not survive into a cplt that acts on it.
    // Lists are sorted first, so reordering a proposal is not a change and does
    // not cost the user a re-approval. A future list field that is not sorted
    // here simply hashes in its written order — stricter, never looser.
    let mut normalized = propose.clone();
    normalized.pass_env.sort_unstable();
    normalized.repos.sort_unstable();
    normalized.allow.read.sort_unstable();
    normalized.allow.write.sort_unstable();
    normalized.allow.socket.sort_unstable();
    normalized.allow.ports.sort_unstable();
    normalized.allow.localhost.sort_unstable();
    normalized.allow.domains.sort_unstable();
    normalized.proxy.allow_private_domains.sort_unstable();

    // The fallback cannot collide with a real serialization: it is tagged, and
    // it carries the error. `ProposeSection` is plain data, so this is not
    // reachable today — but a hash that silently changed format would be a
    // security boundary failing quietly, which is the one thing it must not do.
    let canonical = serde_json::to_string(&normalized)
        .unwrap_or_else(|e| format!("cplt-proposal-hash-fallback:{e}:{normalized:?}"));

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
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

    /// GHSA-xcvh-hxfg-f4cg: an `@` in the *path* must not be mistaken for the
    /// userinfo delimiter, or a crafted remote normalizes to a host git never
    /// contacts — and every URL comparison built on this (allow_push pinning,
    /// the trust store, the gh repo scope) authorizes the wrong repository.
    #[test]
    fn normalize_ignores_a_trailing_slash_after_dot_git() {
        // `repo.git/` does not end in `.git`, so trimming the suffix first left
        // it in place and two spellings of one remote compared unequal.
        for url in [
            "https://github.com/org/repo.git/",
            "https://github.com/org/repo.git",
            "https://github.com/org/repo/",
            "https://github.com/org/repo",
            "ssh://git@github.com/org/repo.git/",
            "git@github.com:org/repo.git/",
        ] {
            assert_eq!(
                normalize_remote_url(url),
                "github.com/org/repo",
                "{url} should normalize to the same remote"
            );
        }
    }

    #[test]
    fn normalize_keeps_the_host_when_the_path_contains_an_at_sign() {
        for url in [
            "https://evil.example/x@github.com/me/fork.git",
            "http://evil.example/x@github.com/me/fork.git",
            "ssh://git@evil.example/x@github.com/me/fork.git",
            // Several `@`: the host is still the authority's last segment.
            "https://a@b@evil.example/x@github.com/me/fork.git",
        ] {
            let normalized = normalize_remote_url(url);
            assert!(
                normalized.starts_with("evil.example/"),
                "{url} normalized to {normalized}, which names a host it does not contact"
            );
        }
    }

    /// Degenerate `@` placements stay inside the authority/path split rather
    /// than reshuffling the two.
    #[test]
    fn normalize_handles_degenerate_at_signs() {
        // Empty userinfo, and userinfo with nothing after the `@`.
        assert_eq!(
            normalize_remote_url("https://@github.com/navikt/spleis.git"),
            "github.com/navikt/spleis"
        );
        assert_eq!(
            normalize_remote_url("https://user@/navikt/spleis.git"),
            "/navikt/spleis"
        );
        // A path segment that merely *begins* with `@` is path, not userinfo.
        assert_eq!(
            normalize_remote_url("https://github.com/@navikt/spleis.git"),
            "github.com/@navikt/spleis"
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
                linked: Vec::new(),
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

    /// The bug this hash exists to prevent, in the shape it actually shipped:
    /// `pass_env` was added to `[propose]` in #443 and never added to the
    /// hand-written hash, so an approval for `["TZ"]` covered a later
    /// `["AWS_SECRET_ACCESS_KEY"]` with no re-prompt. Verified end to end
    /// before the fix: the variable reached the agent.
    #[test]
    fn every_proposed_field_is_pinned() {
        use crate::repo_config::{ProposeAllowSection, ProposeProxySection, ProposeSection};

        // Destructured exhaustively: a new field added to `[propose]` breaks
        // this test to compile, which is the moment to check it is covered.
        let ProposeSection {
            allow_localhost_any: _,
            allow_jvm_attach: _,
            allow_msbuild: _,
            gradle_init: _,
            allow_docker: _,
            allow_tmp_exec: _,
            allow_gpg_signing: _,
            allow_lifecycle_scripts: _,
            allow_browser: _,
            allow_env_files: _,
            gh_guard: _,
            git_push_prevention: _,
            pass_env: _,
            repos: _,
            allow: _,
            proxy: _,
            unknown: _,
        } = ProposeSection::default();

        let base = ProposeSection::default();
        let variants: Vec<(&str, ProposeSection)> = vec![
            (
                "allow_localhost_any",
                ProposeSection {
                    allow_localhost_any: Some(true),
                    ..Default::default()
                },
            ),
            (
                "allow_jvm_attach",
                ProposeSection {
                    allow_jvm_attach: Some(true),
                    ..Default::default()
                },
            ),
            (
                "allow_msbuild",
                ProposeSection {
                    allow_msbuild: Some(true),
                    ..Default::default()
                },
            ),
            (
                "gradle_init",
                ProposeSection {
                    gradle_init: Some(true),
                    ..Default::default()
                },
            ),
            (
                "allow_docker",
                ProposeSection {
                    allow_docker: Some(true),
                    ..Default::default()
                },
            ),
            (
                "allow_tmp_exec",
                ProposeSection {
                    allow_tmp_exec: Some(true),
                    ..Default::default()
                },
            ),
            (
                "allow_gpg_signing",
                ProposeSection {
                    allow_gpg_signing: Some(true),
                    ..Default::default()
                },
            ),
            (
                "allow_lifecycle_scripts",
                ProposeSection {
                    allow_lifecycle_scripts: Some(true),
                    ..Default::default()
                },
            ),
            (
                "allow_browser",
                ProposeSection {
                    allow_browser: Some(true),
                    ..Default::default()
                },
            ),
            (
                "allow_env_files",
                ProposeSection {
                    allow_env_files: Some(true),
                    ..Default::default()
                },
            ),
            (
                "gh_guard",
                ProposeSection {
                    gh_guard: Some(false),
                    ..Default::default()
                },
            ),
            (
                "git_push_prevention",
                ProposeSection {
                    git_push_prevention: Some(false),
                    ..Default::default()
                },
            ),
            (
                "pass_env",
                ProposeSection {
                    pass_env: vec!["AWS_SECRET_ACCESS_KEY".to_string()],
                    ..Default::default()
                },
            ),
            (
                "allow.read",
                ProposeSection {
                    allow: ProposeAllowSection {
                        read: vec!["/etc".to_string()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "allow.write",
                ProposeSection {
                    allow: ProposeAllowSection {
                        write: vec!["/etc".to_string()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "allow.socket",
                ProposeSection {
                    allow: ProposeAllowSection {
                        socket: vec!["/var/run/docker.sock".to_string()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "allow.ports",
                ProposeSection {
                    allow: ProposeAllowSection {
                        ports: vec![8080],
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "allow.localhost",
                ProposeSection {
                    allow: ProposeAllowSection {
                        localhost: vec![8080],
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "allow.domains",
                ProposeSection {
                    allow: ProposeAllowSection {
                        domains: vec!["evil.example".to_string()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "proxy.allow_private_domains",
                ProposeSection {
                    proxy: ProposeProxySection {
                        allow_private_domains: vec!["evil.internal".to_string()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "unknown",
                ProposeSection {
                    unknown: [("future_key".to_string(), toml::Value::Boolean(true))]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                },
            ),
        ];

        let base_hash = proposal_content_hash(&base);
        let mut seen = std::collections::BTreeSet::new();
        for (name, variant) in &variants {
            let hash = proposal_content_hash(variant);
            assert_ne!(
                base_hash, hash,
                "{name} is not pinned: an approval survives a change to it"
            );
            assert!(
                seen.insert(hash),
                "{name} collides with another field's change"
            );
        }
    }

    /// Changing one entry of a list must invalidate, not just adding one.
    #[test]
    fn a_changed_pass_env_value_invalidates_the_approval() {
        use crate::repo_config::ProposeSection;

        let approved = ProposeSection {
            pass_env: vec!["TZ".to_string()],
            ..Default::default()
        };
        let later = ProposeSection {
            pass_env: vec!["AWS_SECRET_ACCESS_KEY".to_string()],
            ..Default::default()
        };

        assert!(approval_is_stale(
            &proposal_content_hash(&approved),
            &proposal_content_hash(&later)
        ));
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
