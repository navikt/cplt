//! Per-repo configuration from `.cplt.toml`.
//!
//! Provides project-specific sandbox settings committed to the repository.
//! Uses a two-tier trust model:
//!   - `[deny]` keys unconditionally tighten the sandbox (no approval needed)
//!   - `[propose]` keys relax the sandbox and require explicit user approval
//!
//! The file is read from `git HEAD` (committed state) to prevent the sandboxed
//! agent from modifying its own config mid-session.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The filename we look for in the project root.
pub const REPO_CONFIG_FILE: &str = ".cplt.toml";

/// Per-repo configuration parsed from `.cplt.toml`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RepoConfig {
    /// Keys that tighten the sandbox — applied automatically without approval.
    pub deny: DenySection,
    /// Keys that relax the sandbox — require user approval.
    pub propose: ProposeSection,
}

/// Restrictive keys — can only tighten the sandbox.
/// Applied unconditionally (the agent has no incentive to restrict itself).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DenySection {
    /// Additional paths to deny access to (beyond the default deny list).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Environment variables to strip (beyond the default blocklist).
    #[serde(default)]
    pub env: Vec<String>,
}

/// Expansive keys — relax the sandbox. Require user trust approval.
///
/// Note: policy presets (`sandbox.preset`) are intentionally NOT proposable
/// here. A preset composes several dangerous permissions at once (docker, tmp
/// exec, ...) into a single opaque baseline, which would defeat the per-key
/// trust review. Repos must request individual keys so each is reviewed and
/// trusted on its own. `deny_unknown_fields` rejects a stray `preset` key.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ProposeSection {
    pub allow_localhost_any: Option<bool>,
    pub allow_jvm_attach: Option<bool>,
    pub allow_msbuild: Option<bool>,
    /// Propose installing the cplt-managed Gradle init script (see
    /// `sandbox.gradle_init`). Writes to the Gradle user home, so it goes
    /// through the same trust review as other sandbox relaxations.
    pub gradle_init: Option<bool>,
    pub allow_docker: Option<bool>,
    pub allow_tmp_exec: Option<bool>,
    pub allow_gpg_signing: Option<bool>,
    pub allow_lifecycle_scripts: Option<bool>,
    pub allow_browser: Option<bool>,
    pub allow_env_files: Option<bool>,
    #[serde(alias = "gh_proxy")]
    pub gh_guard: Option<bool>,
    pub git_push_prevention: Option<bool>,

    /// Proposed path/port expansions.
    #[serde(default)]
    pub allow: ProposeAllowSection,

    /// Proposed proxy settings.
    #[serde(default)]
    pub proxy: ProposeProxySection,
}

/// Proposed allow expansions (paths, ports).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ProposeAllowSection {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub socket: Vec<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub localhost: Vec<u16>,
}

/// Proposed proxy settings.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ProposeProxySection {
    #[serde(default)]
    pub allow_private_domains: Vec<String>,
}

/// How the repo config was loaded — used for user-facing messages.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum RepoConfigSource {
    /// Read from `git cat-file blob HEAD:.cplt.toml` (tamper-proof).
    GitHead,
    /// Fallback: read from working tree (with warning to user).
    WorkingTree,
}

/// Result of attempting to load repo config.
#[derive(Debug)]
pub struct LoadedRepoConfig {
    pub config: RepoConfig,
    pub source: RepoConfigSource,
}

/// Read `.cplt.toml` from the project directory.
///
/// Prefers reading from git HEAD (committed state) for tamper-proofing.
/// Falls back to the working tree if git is unavailable or the file isn't tracked
/// (macOS only — on Linux/Landlock we cannot deny individual file writes within
/// the project dir, so the fallback is skipped to prevent agent tampering).
/// Returns `None` if no `.cplt.toml` exists.
pub fn load_repo_config(project_dir: &Path) -> Result<Option<LoadedRepoConfig>, String> {
    // Try git HEAD first (tamper-proof source)
    if let Some(content) = read_from_git_head(project_dir) {
        let config = parse_repo_config(&content)?;
        validate_repo_config(&config)?;
        return Ok(Some(LoadedRepoConfig {
            config,
            source: RepoConfigSource::GitHead,
        }));
    }

    // On Linux, skip working tree fallback — Landlock cannot deny individual
    // file writes within the project dir, so the agent could tamper with the file.
    if cfg!(target_os = "linux") {
        return Ok(None);
    }

    // Fallback: working tree (macOS only — SBPL denies .cplt.toml writes)
    let file_path = project_dir.join(REPO_CONFIG_FILE);
    if file_path.is_file() {
        let content = std::fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read {}: {e}", file_path.display()))?;
        let config = parse_repo_config(&content)?;
        validate_repo_config(&config)?;
        return Ok(Some(LoadedRepoConfig {
            config,
            source: RepoConfigSource::WorkingTree,
        }));
    }

    Ok(None)
}

/// Read `.cplt.toml` from git HEAD (the latest committed version).
///
/// Uses `git cat-file blob HEAD:.cplt.toml` which reads from the object store,
/// not the working tree. This prevents mid-session tampering by the agent.
fn read_from_git_head(project_dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["cat-file", "blob", &format!("HEAD:{REPO_CONFIG_FILE}")])
        .current_dir(project_dir)
        .output()
        .ok()?;

    if output.status.success() {
        String::from_utf8(output.stdout).ok()
    } else {
        None
    }
}

/// Where `.cplt.toml` stands relative to git HEAD.
///
/// cplt reads the config from HEAD, not the working tree (see
/// [`load_repo_config`]), so "no config" from cplt's point of view covers
/// several very different situations on disk. Telling them apart is what turns
/// a misleading "not found" into an actionable message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoConfigState {
    /// Committed, and the working tree copy matches what cplt reads.
    Committed,
    /// Committed, but the working tree copy differs — local edits are not in effect.
    Drifted,
    /// In the working tree only: untracked (possibly gitignored), or staged but
    /// not committed. Never read by cplt on Linux, and never trustworthy.
    Uncommitted,
    /// Not a git repository at all; `has_file` tells whether a `.cplt.toml` is
    /// sitting there being ignored.
    NotAGitRepo { has_file: bool },
    /// No `.cplt.toml` in HEAD nor in the working tree.
    Missing,
}

/// What an uncommitted `.cplt.toml` actually does — which differs by platform,
/// so the message must too. Linux skips the working-tree fallback entirely; on
/// macOS the file IS loaded (see [`load_repo_config`]), it just can never be
/// approved. Claiming it is inert on macOS would be wrong in the permissive
/// direction.
const UNCOMMITTED_EFFECT: &str = if cfg!(target_os = "linux") {
    "Until then cplt ignores it entirely."
} else {
    "Until then cplt loads it from the working tree — unaudited, so its [deny] keys \
     apply but its [propose] keys cannot be approved."
};

impl RepoConfigState {
    /// A user-facing explanation of why cplt is not treating the `.cplt.toml`
    /// the user is looking at as trustworthy. `None` when there is nothing to
    /// explain.
    #[must_use]
    pub fn explain(self) -> Option<String> {
        match self {
            Self::Committed => None,
            Self::Drifted => Some(format!(
                "{REPO_CONFIG_FILE} differs from the version committed in git HEAD.\n  \
                 cplt reads it from HEAD, so your local edits are not in effect until committed."
            )),
            Self::Uncommitted => Some(format!(
                "{REPO_CONFIG_FILE} exists in the working tree but not in git HEAD.\n  \
                 cplt trusts only the committed copy, so permissions stay auditable in git \
                 history and a sandboxed agent cannot grant itself more mid-session.\n  \
                 {UNCOMMITTED_EFFECT}\n  \
                 Commit it first:\n    \
                 git add {REPO_CONFIG_FILE} && git commit -m \"chore: add cplt sandbox config\"\n  \
                 (if {REPO_CONFIG_FILE} is listed in .gitignore, un-ignore it — an ignored \
                 file can never reach HEAD)"
            )),
            Self::NotAGitRepo { has_file: true } => Some(format!(
                "{REPO_CONFIG_FILE} exists here, but this is not a git repository.\n  \
                 cplt trusts only a copy committed to git, so its permissions are auditable.\n  \
                 {UNCOMMITTED_EFFECT}"
            )),
            Self::NotAGitRepo { has_file: false } => Some(format!(
                "No {REPO_CONFIG_FILE} found, and this is not a git repository."
            )),
            Self::Missing => Some(format!("No {REPO_CONFIG_FILE} found in this repository.")),
        }
    }
}

/// Diagnose where `.cplt.toml` lives, for user-facing messages only.
///
/// Reading the working tree here does not make it trusted — only
/// [`load_repo_config`] decides what is applied.
#[must_use]
pub fn repo_config_state(project_dir: &Path) -> RepoConfigState {
    let in_working_tree = project_dir.join(REPO_CONFIG_FILE).is_file();

    // Existence in HEAD is what closes the gitignore hole: `git status` says
    // nothing at all about an ignored file, so it cannot answer this.
    if read_from_git_head(project_dir).is_some() {
        // Whether the checkout still MATCHES HEAD is git's question to answer.
        // Byte-comparing the raw blob against the file on disk would call every
        // .gitattributes filter (eol=crlf, LFS, git-crypt, ident) permanent
        // drift and make a correctly committed config ungrantable.
        if !in_working_tree
            || git_succeeds(
                project_dir,
                &["diff", "--quiet", "HEAD", "--", REPO_CONFIG_FILE],
            )
        {
            return RepoConfigState::Committed;
        }
        return RepoConfigState::Drifted;
    }

    if git_succeeds(project_dir, &["rev-parse", "--git-dir"]) {
        if in_working_tree {
            RepoConfigState::Uncommitted
        } else {
            RepoConfigState::Missing
        }
    } else {
        RepoConfigState::NotAGitRepo {
            has_file: in_working_tree,
        }
    }
}

fn git_succeeds(project_dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(project_dir)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Parse and validate a `.cplt.toml` content string.
/// Returns an error if the TOML is invalid or violates safety constraints.
pub fn parse_and_validate(content: &str) -> Result<RepoConfig, String> {
    let config = parse_repo_config(content)?;
    validate_repo_config(&config)?;
    Ok(config)
}

/// Parse TOML content into a RepoConfig.
fn parse_repo_config(content: &str) -> Result<RepoConfig, String> {
    toml::from_str(content).map_err(|e| format!("Invalid .cplt.toml: {e}"))
}

/// Reject paths containing `..` components which could bypass SBPL literal matching.
fn reject_path_traversal(path: &str, context: &str) -> Result<(), String> {
    for component in std::path::Path::new(path).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(format!(
                "{context} entry {path:?} contains '..' traversal (not allowed in repo config)"
            ));
        }
    }
    Ok(())
}

/// Validate the repo config for safety.
fn validate_repo_config(config: &RepoConfig) -> Result<(), String> {
    // Validate deny paths don't contain SBPL injection characters or traversal
    for path in &config.deny.paths {
        reject_path_traversal(path, "deny.paths")?;
        crate::sandbox::validate_sbpl_path(&PathBuf::from(path))?;
    }

    // Validate proposed read/write/socket paths
    for path in config
        .propose
        .allow
        .read
        .iter()
        .chain(config.propose.allow.write.iter())
        .chain(config.propose.allow.socket.iter())
    {
        reject_path_traversal(path, "propose.allow.read/write/socket")?;
        crate::sandbox::validate_sbpl_path(&PathBuf::from(path))?;
    }

    // Validate deny env vars: must be non-empty alphanumeric/underscore identifiers
    for var in &config.deny.env {
        if var.is_empty() {
            return Err("deny.env contains empty variable name".to_string());
        }
        if !var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!(
                "deny.env variable {var:?} contains invalid characters (expected [A-Za-z0-9_])"
            ));
        }
    }

    // Validate private domains: must be non-empty, no whitespace
    for domain in &config.propose.proxy.allow_private_domains {
        if domain.is_empty() || domain.trim().is_empty() {
            return Err(
                "propose.proxy.allow_private_domains contains empty domain name".to_string(),
            );
        }
        if domain.contains(char::is_whitespace) {
            return Err(format!(
                "propose.proxy.allow_private_domains entry {domain:?} contains whitespace"
            ));
        }
    }

    Ok(())
}

/// Collect all proposed key names from a ProposeSection.
///
/// Returns the list of keys that would relax the sandbox if approved.
/// Used to show the user what a repo is requesting and to intersect
/// with the trust store's accepted list.
pub fn proposed_keys(propose: &ProposeSection) -> Vec<&'static str> {
    let mut keys = Vec::new();

    if propose.allow_localhost_any == Some(true) {
        keys.push("allow_localhost_any");
    }
    if propose.allow_jvm_attach == Some(true) {
        keys.push("allow_jvm_attach");
    }
    if propose.allow_msbuild == Some(true) {
        keys.push("allow_msbuild");
    }
    if propose.gradle_init == Some(true) {
        keys.push("gradle_init");
    }
    if propose.allow_docker == Some(true) {
        keys.push("allow_docker");
    }
    if propose.allow_tmp_exec == Some(true) {
        keys.push("allow_tmp_exec");
    }
    if propose.allow_gpg_signing == Some(true) {
        keys.push("allow_gpg_signing");
    }
    if propose.allow_lifecycle_scripts == Some(true) {
        keys.push("allow_lifecycle_scripts");
    }
    if propose.allow_browser == Some(true) {
        keys.push("allow_browser");
    }
    if propose.allow_env_files == Some(true) {
        keys.push("allow_env_files");
    }
    if propose.gh_guard == Some(true) {
        keys.push("gh_guard");
    }
    if propose.git_push_prevention == Some(true) {
        keys.push("git_push_prevention");
    }
    if !propose.allow.read.is_empty() {
        keys.push("allow.read");
    }
    if !propose.allow.write.is_empty() {
        keys.push("allow.write");
    }
    if !propose.allow.socket.is_empty() {
        keys.push("allow.socket");
    }
    if !propose.allow.ports.is_empty() {
        keys.push("allow.ports");
    }
    if !propose.allow.localhost.is_empty() {
        keys.push("allow.localhost");
    }
    if !propose.proxy.allow_private_domains.is_empty() {
        keys.push("proxy.allow_private_domains");
    }

    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_config() {
        let config = parse_repo_config("").unwrap();
        assert_eq!(config, RepoConfig::default());
    }

    #[test]
    fn parse_deny_only() {
        let toml = r#"
[deny]
paths = ["~/secrets", "~/.vault"]
env = ["MY_SECRET", "VAULT_TOKEN"]
"#;
        let config = parse_repo_config(toml).unwrap();
        assert_eq!(config.deny.paths, vec!["~/secrets", "~/.vault"]);
        assert_eq!(config.deny.env, vec!["MY_SECRET", "VAULT_TOKEN"]);
        assert_eq!(config.propose, ProposeSection::default());
    }

    #[test]
    fn parse_propose_booleans() {
        let toml = r"
[propose]
allow_localhost_any = true
allow_jvm_attach = true
allow_docker = true
";
        let config = parse_repo_config(toml).unwrap();
        assert_eq!(config.propose.allow_localhost_any, Some(true));
        assert_eq!(config.propose.allow_jvm_attach, Some(true));
        assert_eq!(config.propose.allow_docker, Some(true));
        assert_eq!(config.propose.allow_tmp_exec, None);
    }

    #[test]
    fn parse_propose_allow_section() {
        let toml = r#"
[propose.allow]
read = ["~/.gradle/gradle.properties"]
ports = [8080, 5432]
localhost = [5432]
"#;
        let config = parse_repo_config(toml).unwrap();
        assert_eq!(
            config.propose.allow.read,
            vec!["~/.gradle/gradle.properties"]
        );
        assert_eq!(config.propose.allow.ports, vec![8080, 5432]);
        assert_eq!(config.propose.allow.localhost, vec![5432]);
    }

    #[test]
    fn parse_propose_proxy_section() {
        let toml = r#"
[propose.proxy]
allow_private_domains = ["intern.nav.no", "nais.io"]
"#;
        let config = parse_repo_config(toml).unwrap();
        assert_eq!(
            config.propose.proxy.allow_private_domains,
            vec!["intern.nav.no", "nais.io"]
        );
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[deny]
paths = ["~/secrets"]
env = ["SECRET_KEY"]

[propose]
allow_localhost_any = true
allow_jvm_attach = true

[propose.allow]
read = ["~/.gradle/gradle.properties"]
ports = [8080]

[propose.proxy]
allow_private_domains = ["intern.nav.no"]
"#;
        let config = parse_repo_config(toml).unwrap();
        assert_eq!(config.deny.paths, vec!["~/secrets"]);
        assert_eq!(config.deny.env, vec!["SECRET_KEY"]);
        assert_eq!(config.propose.allow_localhost_any, Some(true));
        assert_eq!(config.propose.allow_jvm_attach, Some(true));
        assert_eq!(
            config.propose.allow.read,
            vec!["~/.gradle/gradle.properties"]
        );
        assert_eq!(config.propose.allow.ports, vec![8080]);
        assert_eq!(
            config.propose.proxy.allow_private_domains,
            vec!["intern.nav.no"]
        );
    }

    #[test]
    fn reject_unknown_top_level_key() {
        let toml = r"
unknown_key = true
";
        let err = parse_repo_config(toml).unwrap_err();
        assert!(err.contains("unknown field"), "got: {err}");
    }

    #[test]
    fn reject_unknown_propose_key() {
        let toml = r"
[propose]
allow_network = true
";
        let err = parse_repo_config(toml).unwrap_err();
        assert!(err.contains("unknown field"), "got: {err}");
    }

    #[test]
    fn validate_rejects_invalid_env_var() {
        let config = RepoConfig {
            deny: DenySection {
                env: vec!["VALID_VAR".to_string(), "invalid-var".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_repo_config(&config).unwrap_err();
        assert!(err.contains("invalid-var"), "got: {err}");
    }

    #[test]
    fn validate_rejects_empty_env_var() {
        let config = RepoConfig {
            deny: DenySection {
                env: vec!["".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_repo_config(&config).unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn proposed_keys_lists_active_proposals() {
        let propose = ProposeSection {
            allow_localhost_any: Some(true),
            allow_jvm_attach: Some(true),
            allow_docker: None,
            allow: ProposeAllowSection {
                ports: vec![8080],
                ..Default::default()
            },
            ..Default::default()
        };
        let keys = proposed_keys(&propose);
        assert!(keys.contains(&"allow_localhost_any"));
        assert!(keys.contains(&"allow_jvm_attach"));
        assert!(keys.contains(&"allow.ports"));
        assert!(!keys.contains(&"allow_docker"));
    }

    #[test]
    fn proposed_keys_empty_for_default() {
        let keys = proposed_keys(&ProposeSection::default());
        assert!(keys.is_empty());
    }

    #[test]
    fn rejects_path_traversal_in_deny() {
        let toml_str = r#"
[deny]
paths = ["~/secrets/../.ssh"]
"#;
        let config = parse_repo_config(toml_str).unwrap();
        let result = validate_repo_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("'..'"));
    }

    #[test]
    fn rejects_path_traversal_in_propose_read() {
        let toml_str = r#"
[propose.allow]
read = ["~/.gradle/../../.ssh/id_rsa"]
"#;
        let config = parse_repo_config(toml_str).unwrap();
        let result = validate_repo_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("'..'"));
    }

    #[test]
    fn accepts_normal_paths() {
        let toml_str = r#"
[deny]
paths = ["~/secrets", "/tmp/sensitive"]

[propose.allow]
read = ["~/.gradle/gradle.properties"]
write = ["~/.m2/repository"]
"#;
        let config = parse_repo_config(toml_str).unwrap();
        assert!(validate_repo_config(&config).is_ok());
    }
}
