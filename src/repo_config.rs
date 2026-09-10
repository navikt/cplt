//! Per-repo configuration from `.cplt.toml`.
//!
//! Provides project-specific sandbox settings committed to the repository.
//! Uses a two-tier trust model:
//!   - `[deny]` keys unconditionally tighten the sandbox (no approval needed)
//!   - `[propose]` keys relax the sandbox and require explicit user approval
//!
//! The file is read from `git HEAD` (committed state) to prevent the sandboxed
//! agent from modifying its own config mid-session.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The filename we look for in the project root.
pub const REPO_CONFIG_FILE: &str = ".cplt.toml";

/// Per-repo configuration parsed from `.cplt.toml`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct RepoConfig {
    /// Keys that tighten the sandbox — applied automatically without approval.
    pub deny: DenySection,
    /// Keys that relax the sandbox — require user approval.
    pub propose: ProposeSection,
    /// Top-level keys this version does not know.
    ///
    /// Collected rather than refused so a `.cplt.toml` can adopt a key a newer
    /// cplt understands without breaking every developer who has not upgraded
    /// yet (#484). Before this, one unknown key failed the whole parse: the
    /// launch repository lost its `[deny]` too, and a named repository stopped
    /// the launch outright.
    ///
    /// Ignoring is safe in the direction that matters. A `[propose]` key this
    /// version cannot see grants nothing, so it fails closed — which is also
    /// what makes a smuggled `preset` a non-event, the case
    /// `deny_unknown_fields` was there for. A `[deny]` key that is ignored is a
    /// restriction the author expected and did not get, which is why every
    /// unknown key is reported rather than dropped in silence.
    #[serde(flatten)]
    pub unknown: std::collections::BTreeMap<String, toml::Value>,
}

/// Restrictive keys — can only tighten the sandbox.
/// Applied unconditionally (the agent has no incentive to restrict itself).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct DenySection {
    /// Additional paths to deny access to (beyond the default deny list).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Environment variables to strip (beyond the default blocklist).
    #[serde(default)]
    pub env: Vec<String>,
    /// See [`RepoConfig::unknown`]. An ignored deny is a restriction its author
    /// expected, so this is the section whose unknown keys matter most to
    /// report.
    #[serde(flatten)]
    pub unknown: std::collections::BTreeMap<String, toml::Value>,
}

/// Expansive keys — relax the sandbox. Require user trust approval.
///
/// Note: policy presets (`sandbox.preset`) are intentionally NOT proposable
/// here. A preset composes several dangerous permissions at once (docker, tmp
/// exec, ...) into a single opaque baseline, which would defeat the per-key
/// trust review. Repos must request individual keys so each is reviewed and
/// trusted on its own. A stray `preset` key lands in [`Self::unknown`] and is
/// ignored, which is the same outcome `deny_unknown_fields` used to produce by
/// refusing the file — without taking the rest of the config down with it.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
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

    /// Environment variables the project needs passed through.
    ///
    /// `pass_env` names a variable in the *parent's* environment, so a
    /// committed entry pulls whatever the machine running the agent happens to
    /// have under that name. That is why it is a proposal rather than a `deny`:
    /// the repository states what the build needs, a reviewer sees the list in
    /// the diff, and each developer accepts it on their own machine — where an
    /// edit changes the file's hash and de-activates the approval (#443).
    ///
    /// Plenty of these are the application's rather than the machine's —
    /// `NODE_ENV`, `TZ`, `SPRING_PROFILES_ACTIVE` — and none of those is
    /// sensitive. The refusal used to claim otherwise.
    #[serde(default)]
    pub pass_env: Vec<String>,

    /// Repositories this project usually spans, as `<owner>/<name>` (#491).
    ///
    /// An identity, never a path: the repository states what the *project* is,
    /// and the user's machine decides where that repository lives. Approving
    /// resolves each one locally, verifies its origin, and records the path —
    /// so what a repository can put in front of the user is a name, and what
    /// grants access is a path the user approved.
    ///
    /// Unlike every other proposal, this one is not a value the launch applies.
    /// `cplt trust accept repos` performs the linking; after that the entries
    /// are ordinary `sandbox.repo_dirs` roots. Nothing here is consulted at
    /// launch, which is also why `--accept-repo-config` cannot use it: a
    /// per-run flag must not write a persistent grant.
    #[serde(default)]
    pub repos: Vec<String>,

    /// Proposed path/port expansions.
    #[serde(default)]
    pub allow: ProposeAllowSection,

    /// Proposed proxy settings.
    #[serde(default)]
    pub proxy: ProposeProxySection,
    /// See [`RepoConfig::unknown`]. A `[propose]` key this version cannot see
    /// grants nothing, so ignoring it fails closed.
    #[serde(flatten)]
    pub unknown: std::collections::BTreeMap<String, toml::Value>,
}

impl ProposeSection {
    /// The parts of a `[propose]` section that only ever make the sandbox
    /// stricter, with every grant removed.
    ///
    /// `gh_guard = true` and `git_push_prevention = true` turn a guard **on**.
    /// They are `[deny]`-shaped: they need no approval, no layer takes them
    /// back off, and they survive `--no-gh-guard` (see `PROPOSE_BOOLS` and
    /// `apply_repo_config`). Clearing the whole section for an uncommitted file
    /// would therefore have been a silent *loosening* — the opposite of what
    /// #206 is for, and invisible, since `proposed_keys` does not count them.
    ///
    /// Everything else is dropped, including the unknown keys: a key this
    /// version cannot see may be a grant in the next one.
    #[must_use]
    pub fn tightenings_only(&self) -> Self {
        // Destructured exhaustively: a new `[propose]` field breaks this to
        // compile, which is the moment to decide which side of the line it is
        // on. Getting that decision by default is how a grant would slip
        // through an uncommitted file.
        let Self {
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
            gh_guard,
            git_push_prevention,
            pass_env: _,
            repos: _,
            allow: _,
            proxy: _,
            unknown: _,
        } = self;

        Self {
            // Only `Some(true)` is a tightening. `Some(false)` asks for the
            // guard to be off, which is a grant, and is dropped with the rest.
            gh_guard: gh_guard.filter(|on| *on),
            git_push_prevention: git_push_prevention.filter(|on| *on),
            ..Self::default()
        }
    }
}

/// Proposed allow expansions (paths, ports).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
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
    /// Domains the project asks to add to the proxy allowlist (#482).
    ///
    /// Proposable like the rest of `[propose.allow]`, and inert until
    /// `cplt trust accept` on each machine. It widens an allowlist already in
    /// force and cannot turn one on, so an approved entry can only let a
    /// fail-closed session reach one more host — it can never open a session
    /// that was not filtering to begin with.
    #[serde(default)]
    pub domains: Vec<String>,
    /// See [`RepoConfig::unknown`].
    #[serde(flatten)]
    pub unknown: std::collections::BTreeMap<String, toml::Value>,
}

/// Proposed proxy settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ProposeProxySection {
    #[serde(default)]
    pub allow_private_domains: Vec<String>,
    /// See [`RepoConfig::unknown`].
    #[serde(flatten)]
    pub unknown: std::collections::BTreeMap<String, toml::Value>,
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
    /// The directory the `.cplt.toml` was read from — the anchor for its
    /// relative paths. This is NOT always `project_dir`: `git cat-file blob
    /// HEAD:.cplt.toml` resolves repo-root-relative regardless of cwd, so a
    /// `--project-dir <subdir>` run reads the *root's* config and its paths
    /// must anchor to the root. Anchoring to the subdir instead would emit a
    /// deny rule for a directory the repo never named — a plausible-looking
    /// absolute rule protecting the wrong place.
    pub dir: PathBuf,
    /// The file was read from the working tree and had a `[propose]` section,
    /// which was dropped before this value was returned (#206).
    ///
    /// Only for telling the user why nothing was proposed. The proposals are
    /// already gone from `config` by the time anyone sees this — the boundary
    /// removes them, so no caller can approve them by forgetting to check.
    pub propose_dropped: bool,
}

/// Environment variables a `.cplt.toml` may not deny, because cplt sets them
/// for the agent itself. Prefix `__CPLT_` is refused separately.
const RESERVED_DENY_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
];

/// Read `.cplt.toml` from the project directory.
///
/// Read from git HEAD when the file is committed, so what grants permissions is
/// what a reviewer saw and what git history records.
///
/// An uncommitted file is still read, on every platform, but **only its
/// `[deny]` survives**: the `[propose]` section is stripped here, at the
/// boundary. A tightening needs no audit trail — it can only reduce what the
/// session may do, and dropping it would silently remove a restriction its
/// author believed was in force. A relaxation needs one, and a commit is it.
///
/// This is one rule on both platforms. It used to be two: the fallback was
/// skipped entirely on Linux, because Landlock cannot deny a write to a single
/// file inside the project directory, so a sandboxed agent could rewrite
/// `.cplt.toml` between sessions. The same file was therefore live on macOS and
/// inert on Linux, and no single honest sentence described both (#206). The
/// Landlock argument still holds, and it is the reason `[propose]` is dropped
/// rather than trusted — but it argues for dropping grants, not for discarding
/// a repository's restrictions on one platform only.
///
/// Returns `None` if no `.cplt.toml` exists.
pub fn load_repo_config(project_dir: &Path) -> Result<Option<LoadedRepoConfig>, String> {
    // Try git HEAD first (tamper-proof source)
    if let Some(content) = read_from_git_head(project_dir) {
        let config = parse_repo_config(&content)?;
        validate_repo_config(&config)?;
        return Ok(Some(LoadedRepoConfig {
            config,
            source: RepoConfigSource::GitHead,
            dir: canonical(git_toplevel(project_dir).unwrap_or_else(|| project_dir.to_path_buf())),
            propose_dropped: false,
        }));
    }

    // Fallback: the working tree, on every platform, for `[deny]` only.
    let file_path = project_dir.join(REPO_CONFIG_FILE);
    if file_path.is_file() {
        let content = std::fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read {}: {e}", file_path.display()))?;
        let mut config = parse_repo_config(&content)?;
        validate_repo_config(&config)?;
        // The widening proposals are removed HERE, at the boundary, rather than
        // refused at each place that could approve them. Three separate holes
        // were found one at a time in the old arrangement — a gitignored file,
        // a non-git directory, and `--accept-repo-config` — because the guard
        // lived in `trust_accept` and every other route around it had to
        // remember the rule. A grant that never leaves this function cannot be
        // approved by a caller that forgets (#206).
        let propose_dropped = !proposed_keys(&config.propose).is_empty();
        config.propose = config.propose.tightenings_only();
        return Ok(Some(LoadedRepoConfig {
            config,
            source: RepoConfigSource::WorkingTree,
            // The working-tree fallback reads `<project_dir>/.cplt.toml`
            // literally, so here the project dir *is* the config's directory.
            dir: canonical(project_dir.to_path_buf()),
            propose_dropped,
        }));
    }

    Ok(None)
}

/// Canonicalize, keeping the input on failure.
///
/// `dir` anchors every relative path in the config AND is the containment
/// boundary for approved allow paths, which are compared against it with
/// `starts_with`. Both need it to match what `canonicalize` produces for paths
/// under it, or a repo behind a symlinked checkout would read as "outside the
/// repo". Callers already pass a canonical path on the enforcing path; this is
/// belt-and-braces for the ones that may not.
fn canonical(path: PathBuf) -> PathBuf {
    path.canonicalize().unwrap_or(path)
}

/// The git toplevel for `project_dir` — the directory `HEAD:.cplt.toml`
/// resolves against. `None` when git cannot answer (not a repo, git missing).
fn git_toplevel(project_dir: &Path) -> Option<PathBuf> {
    let output = crate::git::command(project_dir, &["rev-parse", "--show-toplevel"])?
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let root = String::from_utf8(output.stdout).ok()?;
    let root = root.trim();
    if root.is_empty() {
        return None;
    }
    Some(PathBuf::from(root))
}

/// Read `.cplt.toml` from git HEAD (the latest committed version).
///
/// Uses `git cat-file blob HEAD:.cplt.toml` which reads from the object store,
/// not the working tree. This prevents mid-session tampering by the agent.
fn read_from_git_head(project_dir: &Path) -> Option<String> {
    let output = crate::git::command(
        project_dir,
        &["cat-file", "blob", &format!("HEAD:{REPO_CONFIG_FILE}")],
    )?
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
    /// not committed. Read for its `[deny]` on every platform since #206; never
    /// a source of grants.
    Uncommitted,
    /// Not a git repository at all; `has_file` tells whether a `.cplt.toml` is
    /// sitting there being ignored.
    NotAGitRepo { has_file: bool },
    /// No `.cplt.toml` in HEAD nor in the working tree.
    Missing,
}

/// What an uncommitted `.cplt.toml` actually does. One sentence, both
/// platforms, since #206 — it used to be two, because the behaviour was two.
const UNCOMMITTED_EFFECT: &str = "Until then it grants nothing. Its [deny] keys still apply, and so does a [propose] \
     key that only tightens, such as gh_guard = true.";

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
                 (if {REPO_CONFIG_FILE} is listed in .gitignore, un-ignore it, because an \
                 ignored file can never reach HEAD)"
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

/// Run a hardened `git` in `project_dir` and report whether it exited 0.
///
/// Returns `false` when [`crate::git::command`] refuses the invocation — the
/// repository defines a content filter git would execute in the parent (#210).
/// For the `diff --quiet` caller that means `Drifted` is reported without the
/// working tree having been compared. Note this does NOT stop the config being
/// applied: [`load_repo_config`] reads it from the object store with
/// `cat-file`, which cannot reach a filter and is never refused. What it does
/// block is `cplt trust accept`, which approves only `Committed`.
fn git_succeeds(project_dir: &Path, args: &[&str]) -> bool {
    crate::git::command(project_dir, args)
        .and_then(|mut c| c.output().ok())
        .is_some_and(|o| o.status.success())
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

/// Reject a path that names a whole tree root rather than something within it.
///
/// `""`, `"."` and `"./"` all normalize to nothing, so they anchor to the repo
/// root; `"/"` is the filesystem root. As a deny entry, either one blocks read
/// AND write of the entire checkout (or the entire machine) — a committed
/// version bricks cplt for everyone who clones. `"."` meaning "the repo" is at
/// least arguable; an empty string landing in the same place is not, and neither
/// is worth supporting when `[deny]` exists to carve out parts of a tree.
fn reject_root_path(path: &str, context: &str) -> Result<(), String> {
    let normalized = crate::config::lexically_normalized(std::path::Path::new(path));
    if normalized.as_os_str().is_empty() {
        return Err(format!(
            "{context} entry {path:?} resolves to the repository root, which would deny \
             the entire checkout. Name a path inside the repo instead."
        ));
    }
    if normalized == std::path::Path::new("/") {
        return Err(format!(
            "{context} entry {path:?} is the filesystem root, which would deny everything."
        ));
    }
    Ok(())
}

/// Validate the repo config for safety.
fn validate_repo_config(config: &RepoConfig) -> Result<(), String> {
    // Validate deny paths don't contain SBPL injection characters or traversal
    for path in &config.deny.paths {
        reject_path_traversal(path, "deny.paths")?;
        reject_root_path(path, "deny.paths")?;
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

    // `[propose] repos` entries are identities. The value reaches path
    // construction on the user's machine — `<parent>/<name>` — so a `..` or a
    // slash in the wrong place would have cplt look in a directory this file
    // chose. Refused here, where the file is read, rather than at the resolver.
    for repo in &config.propose.repos {
        if !crate::link::is_valid_identity(repo) {
            return Err(format!(
                "propose.repos entry {repo:?} is not a repository identity. \
                 Name repositories as <owner>/<name>, for example navikt/cplt."
            ));
        }
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
        // The deny sweep runs after cplt has set up the child's environment, so
        // these names strip cplt's own wiring rather than the repository's
        // secrets: `PATH` carries the guard shims, `__CPLT_TRUST_LOCKED` stops
        // a nested session editing the trust store, and the proxy variables
        // point the agent at the proxy. None of them is a secret a repository
        // could want denied, and since #206 an agent-written uncommitted file
        // reaches this list on Linux too.
        if RESERVED_DENY_ENV.contains(&var.as_str()) || var.starts_with("__CPLT_") {
            return Err(format!(
                "deny.env may not name {var:?}: it is cplt's own, set for the agent \
                 after this list is applied, so denying it removes a protection rather \
                 than a secret."
            ));
        }
    }

    // Both domain lists get the same checks, and one they did not have before:
    // a `*` matches no host, because matching is exact host plus subdomains.
    // `cplt config set` refuses a wildcard while the user is still typing;
    // a `.cplt.toml` is written in an editor, so the equivalent moment is here.
    // Without it a repository proposes `*.example.com`, every developer
    // approves it, and it reaches nothing on any of their machines.
    for (label, domains) in [
        (
            "propose.proxy.allow_private_domains",
            &config.propose.proxy.allow_private_domains,
        ),
        ("propose.allow.domains", &config.propose.allow.domains),
    ] {
        for domain in domains {
            if domain.is_empty() || domain.trim().is_empty() {
                return Err(format!("{label} contains empty domain name"));
            }
            if domain.contains(char::is_whitespace) {
                return Err(format!("{label} entry {domain:?} contains whitespace"));
            }
            if let Some(bare) = domain.strip_prefix("*.") {
                return Err(format!(
                    "{label} entry {domain:?} matches no host. Matching is exact host plus \
                     subdomains, so {bare:?} already covers it and everything under it"
                ));
            }
            if domain.contains('*') {
                return Err(format!(
                    "{label} entry {domain:?} contains a wildcard, which matches no host. \
                     Name the domain itself and every subdomain is covered"
                ));
            }
        }
    }

    Ok(())
}

/// Collect the proposed key names a ProposeSection puts up for approval.
///
/// Returns the keys that would RELAX the sandbox if approved. Tighten-only
/// rows (`gh_guard`, `git_push_prevention`) are deliberately absent: they turn
/// a guard on, apply without approval and are removed by no layer, so every
/// surface that reads this list — the untrusted-repo "wants to relax" warning,
/// `cplt trust show`/`accept`/`revoke`, the working-tree note and the
/// unapproved-proposal list — would otherwise describe an already-applied
/// tightening as a pending relaxation. Filtering here fixes all of them at
/// once. A consumer that wants "every boolean this file sets", such as
/// `cplt init --merge`, must walk `PROPOSE_BOOLS` itself.
/// Keys in a `.cplt.toml` that this cplt does not understand, dotted and
/// sorted.
///
/// Reported rather than refused (#484). The two sections fail in opposite
/// directions and the message says so: an unknown `[propose]` key grants
/// nothing, while an unknown `[deny]` key is a restriction the author wrote and
/// this version will not apply.
#[must_use]
pub fn unknown_keys(config: &RepoConfig) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |prefix: &str, map: &std::collections::BTreeMap<String, toml::Value>| {
        for k in map.keys() {
            out.push(if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            });
        }
    };
    push("", &config.unknown);
    push("deny", &config.deny.unknown);
    push("propose", &config.propose.unknown);
    push("propose.allow", &config.propose.allow.unknown);
    push("propose.proxy", &config.propose.proxy.unknown);
    out.sort();
    out
}

/// Whether any unknown key sits in a section that TIGHTENS the sandbox.
///
/// Worth separating because the consequence differs. An ignored `[propose]`
/// key costs the repository a relaxation it asked for, which is a failure the
/// user will notice as "my build cannot do X". An ignored `[deny]` key costs a
/// restriction its author believed was in force, and nothing else in the
/// session will ever mention it.
#[must_use]
pub fn has_unknown_tightening_keys(config: &RepoConfig) -> bool {
    !config.deny.unknown.is_empty()
}

pub fn proposed_keys(propose: &ProposeSection) -> Vec<&'static str> {
    let mut keys = Vec::new();

    for row in crate::config::PROPOSE_BOOLS {
        if !row.tighten_only && (row.propose)(propose) == Some(true) {
            keys.push(row.key);
        }
    }

    if !propose.repos.is_empty() {
        keys.push("repos");
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
    if !propose.pass_env.is_empty() {
        keys.push("sandbox.pass_env");
    }
    if !propose.allow.ports.is_empty() {
        keys.push("allow.ports");
    }
    if !propose.allow.localhost.is_empty() {
        keys.push("allow.localhost");
    }
    if !propose.allow.domains.is_empty() {
        keys.push("allow.domains");
    }
    if !propose.proxy.allow_private_domains.is_empty() {
        keys.push("proxy.allow_private_domains");
    }

    keys
}

/// Format the proposed values for a key for display.
pub fn propose_key_detail(propose: &ProposeSection, key: &str) -> Option<String> {
    match key {
        "allow.read" if !propose.allow.read.is_empty() => Some(format!("{:?}", propose.allow.read)),
        "allow.write" if !propose.allow.write.is_empty() => {
            Some(format!("{:?}", propose.allow.write))
        }
        "allow.ports" if !propose.allow.ports.is_empty() => {
            Some(format!("{:?}", propose.allow.ports))
        }
        "allow.localhost" if !propose.allow.localhost.is_empty() => {
            Some(format!("{:?}", propose.allow.localhost))
        }
        "proxy.allow_private_domains" if !propose.proxy.allow_private_domains.is_empty() => {
            Some(format!("{:?}", propose.proxy.allow_private_domains))
        }
        // Named, not counted: "repos" alone says nothing about what approving
        // it would put in scope, and this is the one proposal whose effect is a
        // whole other repository being read, written and executed in.
        // Named, but bounded. The list is a repository's committed text, and a
        // file proposing two hundred repositories would otherwise print one
        // 3 KB line — which is how the whole warning stops being read. The
        // entries themselves cannot carry escapes: `validate_repo_config`
        // refuses anything that is not `<owner>/<name>`.
        "repos" if !propose.repos.is_empty() => {
            const SHOWN: usize = 5;
            let shown = propose
                .repos
                .iter()
                .take(SHOWN)
                .cloned()
                .collect::<Vec<_>>();
            let rest = propose.repos.len().saturating_sub(shown.len());
            let listed = shown.join(", ");
            Some(if rest == 0 {
                format!("{listed} (each resolved and origin-verified on this machine)")
            } else {
                format!("{listed}, and {rest} more — see `cplt trust`")
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {

    /// #484: a `.cplt.toml` must be able to use a key a newer cplt understands
    /// without breaking every developer who has not upgraded. Before this, one
    /// unknown key failed the whole parse — the launch repository lost its
    /// `[deny]` too, and a named repository stopped the launch outright.
    #[test]
    fn an_unknown_key_is_collected_and_the_known_ones_still_parse() {
        let cfg: RepoConfig = toml::from_str(
            r#"
future_top_level = 1

[deny]
paths = ["secrets"]
future_deny = ["x"]

[propose]
allow_docker = true
preset = "full-trust"

[propose.allow]
ports = [5432]
future_allow = ["y"]

[propose.proxy]
allow_private_domains = ["intern.nav.no"]
future_proxy = true
"#,
        )
        .expect("unknown keys must not fail the parse");

        // The known values are intact — this is what the old behaviour threw away.
        assert_eq!(cfg.deny.paths, vec!["secrets".to_string()]);
        assert_eq!(cfg.propose.allow_docker, Some(true));
        assert_eq!(cfg.propose.allow.ports, vec![5432]);
        assert_eq!(
            cfg.propose.proxy.allow_private_domains,
            vec!["intern.nav.no".to_string()]
        );

        // Every unknown is reported, dotted by section so the reader can find it.
        assert_eq!(
            unknown_keys(&cfg),
            vec![
                "deny.future_deny".to_string(),
                "future_top_level".to_string(),
                "propose.allow.future_allow".to_string(),
                "propose.preset".to_string(),
                "propose.proxy.future_proxy".to_string(),
            ]
        );
        assert!(
            has_unknown_tightening_keys(&cfg),
            "a [deny] key that is ignored is the one worth saying loudly"
        );
    }

    /// The security property `deny_unknown_fields` was there for: a repository
    /// must not smuggle a `preset` past the per-key trust review. Ignoring it
    /// achieves the same outcome as refusing the file, without taking the rest
    /// of the config down with it.
    #[test]
    fn a_smuggled_preset_is_inert_rather_than_fatal() {
        let cfg: RepoConfig = toml::from_str(
            "[propose]
preset = \"full-trust\"\n",
        )
        .expect("no longer fatal");
        assert!(unknown_keys(&cfg).contains(&"propose.preset".to_string()));
        // Nothing about a preset reached the proposal, so nothing can approve it.
        assert!(proposed_keys(&cfg.propose).is_empty());
        assert!(!has_unknown_tightening_keys(&cfg), "preset is not a deny");
    }

    /// Malformed TOML is not a version-skew problem and must stay an error.
    #[test]
    fn a_syntax_error_is_still_an_error() {
        assert!(toml::from_str::<RepoConfig>("this is = = not toml [[[\n").is_err());
    }
    use super::*;

    /// Runs a git command in `dir` with a fixed identity, for the loader tests.
    #[allow(clippy::disallowed_methods)] // test fixture: PATH is the harness's, not an agent's
    fn git_in(dir: &Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e.x")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e.x")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("git runs")
            .success();
        assert!(ok, "git {args:?} failed");
    }

    /// #206: an uncommitted `.cplt.toml` keeps its restrictions and loses its
    /// requests, on every platform. The proposals are removed at the loader, so
    /// no caller downstream — `trust accept`, the launch path,
    /// `--accept-repo-config` — can approve them by forgetting the rule.
    #[test]
    fn an_uncommitted_file_keeps_its_deny_and_loses_its_propose() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().canonicalize().expect("canonical");
        git_in(&path, &["init", "-q"]);
        std::fs::write(path.join("seed"), "x").expect("seed");
        git_in(&path, &["add", "seed"]);
        git_in(&path, &["commit", "-qm", "init"]);
        std::fs::write(
            path.join(REPO_CONFIG_FILE),
            "[propose]\nallow_docker = true\n\n[deny]\npaths = [\"secrets\"]\n",
        )
        .expect("write config");

        let loaded = load_repo_config(&path)
            .expect("loads")
            .expect("file is there");

        assert_eq!(loaded.source, RepoConfigSource::WorkingTree);
        assert_eq!(
            loaded.config.deny.paths,
            vec!["secrets"],
            "a tightening needs no commit: dropping it would remove a restriction \
             its author believed was in force"
        );
        assert_eq!(
            proposed_keys(&loaded.config.propose),
            Vec::<&str>::new(),
            "a relaxation needs an audit trail, and a commit is it"
        );
        assert!(
            loaded.propose_dropped,
            "the user must be told why nothing was proposed"
        );
    }

    /// A tighten-only proposal is `[deny]`-shaped: `gh_guard = true` turns a
    /// guard ON with no approval and survives `--no-gh-guard`. Clearing the
    /// whole section for an uncommitted file would have switched a guard off
    /// silently — and invisibly, since `proposed_keys` does not count these.
    ///
    /// Read from the registry rather than a second hand-written list, so the
    /// two cannot drift: every `tighten_only` row must survive, every other
    /// must not.
    #[test]
    fn an_uncommitted_file_keeps_the_proposals_that_only_tighten() {
        for row in crate::config::PROPOSE_BOOLS {
            // Set this row's field by round-tripping through TOML: the registry
            // gives a reader, not a writer, and the key name is the field name.
            let proposed: ProposeSection =
                toml::from_str(&format!("{} = true\n", row.key)).expect("parses");
            assert_eq!(
                (row.propose)(&proposed),
                Some(true),
                "fixture did not set {}",
                row.key
            );

            let kept = proposed.tightenings_only();
            assert_eq!(
                (row.propose)(&kept),
                if row.tighten_only { Some(true) } else { None },
                "{} survived an uncommitted file when it should not have, or the reverse",
                row.key
            );
        }

        // A guard asked OFF is a grant, whatever the row says.
        let off: ProposeSection = toml::from_str("gh_guard = false\n").expect("parses");
        assert_eq!(off.tightenings_only(), ProposeSection::default());
    }

    /// The same file, committed, proposes normally — the guard is about where
    /// the bytes came from, not about the keys.
    #[test]
    fn the_same_file_committed_proposes_normally() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().canonicalize().expect("canonical");
        git_in(&path, &["init", "-q"]);
        std::fs::write(
            path.join(REPO_CONFIG_FILE),
            "[propose]\nallow_docker = true\n\n[deny]\npaths = [\"secrets\"]\n",
        )
        .expect("write config");
        git_in(&path, &["add", REPO_CONFIG_FILE]);
        git_in(&path, &["commit", "-qm", "cfg"]);

        let loaded = load_repo_config(&path)
            .expect("loads")
            .expect("file is there");

        assert_eq!(loaded.source, RepoConfigSource::GitHead);
        assert_eq!(proposed_keys(&loaded.config.propose), vec!["allow_docker"]);
        assert!(!loaded.propose_dropped);
    }

    /// #491: a repository proposes *identities*, never paths. The value is
    /// used to build paths on the user's machine, so a `..` or a stray slash
    /// would have cplt look in a directory this file chose — and print the
    /// result back to the operator as if it were a repository.
    #[test]
    fn a_proposed_repo_must_be_an_identity_not_a_path() {
        for bad in [
            "../../etc",
            "navikt/../../etc",
            "/absolute/path",
            "navikt",
            "navikt/cplt/extra",
            "",
        ] {
            let cfg =
                parse_repo_config(&format!("[propose]\nrepos = [\"{bad}\"]\n")).expect("parses");
            let err = validate_repo_config(&cfg).expect_err("{bad} must be refused");
            assert!(err.contains("identity"), "say what is wrong: {err}");
        }

        let cfg = parse_repo_config("[propose]\nrepos = [\"navikt/cplt\"]\n").expect("parses");
        validate_repo_config(&cfg).expect("an identity is the point of the key");
    }

    /// The launch names the repositories an unapproved `repos` would put in
    /// scope, and the list is a repository's committed text. Bounded, because a
    /// warning that prints a 3 KB line is a warning nobody reads.
    #[test]
    fn a_long_repos_proposal_is_summarised_not_dumped() {
        let many: Vec<String> = (0..200).map(|i| format!("navikt/repo-{i}")).collect();
        let cfg = parse_repo_config(&format!(
            "[propose]\nrepos = [{}]\n",
            many.iter()
                .map(|r| format!("{r:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .expect("parses");
        validate_repo_config(&cfg).expect("identities are valid");

        let detail = propose_key_detail(&cfg.propose, "repos").expect("has a detail");
        assert!(
            detail.len() < 200,
            "one line, not a wall: {} chars",
            detail.len()
        );
        assert!(
            detail.contains("and 195 more"),
            "and it says how many: {detail}"
        );
    }

    /// It is a grant — it puts another repository in read/write/exec scope — so
    /// an uncommitted file cannot make it (#206).
    #[test]
    fn proposed_repos_do_not_survive_an_uncommitted_file() {
        let cfg = parse_repo_config("[propose]\nrepos = [\"navikt/cplt\"]\n").expect("parses");
        assert!(cfg.propose.tightenings_only().repos.is_empty());
    }

    /// The deny sweep runs after cplt sets up the child's environment, so these
    /// names would strip cplt's own wiring — the guard shims on `PATH`, the
    /// trust soft-lock, the proxy variables — rather than a repository's
    /// secrets. Since #206 an agent-written uncommitted file reaches this list
    /// on Linux too, which is what made it worth refusing rather than noting.
    #[test]
    fn deny_env_may_not_name_cplts_own_variables() {
        for name in ["PATH", "HOME", "HTTPS_PROXY", "__CPLT_TRUST_LOCKED"] {
            let cfg = parse_repo_config(&format!("[deny]\nenv = [\"{name}\"]\n")).expect("parses");
            let err = validate_repo_config(&cfg).expect_err("must be refused");
            assert!(err.contains(name), "the error must name it: {err}");
        }
        // An ordinary secret is still deniable — this must not become a blanket
        // refusal.
        let cfg = parse_repo_config("[deny]\nenv = [\"VAULT_TOKEN\"]\n").expect("parses");
        validate_repo_config(&cfg).expect("a real secret is the point of the key");
    }

    /// A `[deny]`-only uncommitted file is not "dropped proposals" — the notice
    /// would be noise, and a notice that appears when nothing happened is how
    /// the real one stops being read.
    #[test]
    fn a_deny_only_uncommitted_file_reports_nothing_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().canonicalize().expect("canonical");
        git_in(&path, &["init", "-q"]);
        std::fs::write(path.join("seed"), "x").expect("seed");
        git_in(&path, &["add", "seed"]);
        git_in(&path, &["commit", "-qm", "init"]);
        std::fs::write(
            path.join(REPO_CONFIG_FILE),
            "[deny]\npaths = [\"secrets\"]\n",
        )
        .expect("write config");

        let loaded = load_repo_config(&path).expect("loads").expect("there");
        assert!(!loaded.propose_dropped);
        assert_eq!(loaded.config.deny.paths, vec!["secrets"]);
    }

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
    /// Was `reject_unknown_top_level_key`. Unknown keys are collected and
    /// reported rather than refused (#484), so a `.cplt.toml` can adopt a key a
    /// newer cplt understands without breaking developers who have not
    /// upgraded. The assertion moved from "this fails" to "this is visible".
    fn collect_unknown_top_level_key() {
        let toml = r"
unknown_key = true
";
        let config = parse_repo_config(toml).expect("no longer refused");
        assert_eq!(unknown_keys(&config), vec!["unknown_key".to_string()]);
    }

    #[test]
    /// Was `reject_unknown_propose_key`. An unknown `[propose]` key grants
    /// nothing, so ignoring it fails closed — and `proposed_keys` must not
    /// offer it for approval, or the trust prompt would list a permission cplt
    /// cannot apply.
    fn collect_unknown_propose_key() {
        let toml = r"
[propose]
allow_network = true
";
        let config = parse_repo_config(toml).expect("no longer refused");
        assert_eq!(
            unknown_keys(&config),
            vec!["propose.allow_network".to_string()]
        );
        assert!(proposed_keys(&config.propose).is_empty());
    }

    /// A repository proposing `*.example.com` would be approved by every
    /// developer and reach nothing on any of their machines. `config set`
    /// refuses a wildcard while the user is typing; a `.cplt.toml` is written
    /// in an editor, so validation is the equivalent moment.
    #[test]
    fn validate_rejects_a_wildcard_in_either_domain_list() {
        for toml in [
            "[propose.allow]\ndomains = [\"*.example.com\"]\n",
            "[propose.proxy]\nallow_private_domains = [\"*.intern.nav.no\"]\n",
        ] {
            let err = parse_and_validate(toml).unwrap_err();
            assert!(
                err.contains("matches no host"),
                "must name the problem, got: {err}"
            );
        }
        // The bare form is what works, and must still pass.
        assert!(parse_and_validate("[propose.allow]\ndomains = [\"example.com\"]\n").is_ok());
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

    /// A guard-on proposal is not a request to relax anything: it applies
    /// without approval and no layer removes it, so every surface driven by
    /// this list — "wants to relax", `trust show`'s pending rows, the
    /// `trust accept <key>` hint — must not mention it. #427.
    #[test]
    fn proposed_keys_omits_the_tighten_only_rows() {
        let propose = ProposeSection {
            gh_guard: Some(true),
            git_push_prevention: Some(true),
            allow_docker: Some(true),
            ..Default::default()
        };
        assert_eq!(proposed_keys(&propose), vec!["allow_docker"]);

        // A file proposing ONLY guards puts nothing up for approval at all.
        let guards_only = ProposeSection {
            gh_guard: Some(true),
            ..Default::default()
        };
        assert!(proposed_keys(&guards_only).is_empty());
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
    fn rejects_deny_paths_naming_a_whole_tree_root() {
        // A committed `""` or `"."` denies read AND write of the entire
        // checkout, bricking cplt for everyone who clones. All spellings that
        // normalize to nothing land on the repo root, so all are rejected.
        for entry in ["\"\"", "\".\"", "\"./\"", "\"./.\""] {
            let toml_str = format!("[deny]\npaths = [{entry}]\n");
            let config = parse_repo_config(&toml_str).unwrap();
            let err = validate_repo_config(&config)
                .expect_err("{entry} must be rejected, not silently denied as the repo root");
            assert!(
                err.contains("repository root"),
                "{entry}: unexpected error {err}"
            );
        }
        // The filesystem root gets its own message — it is not the repo root.
        let config = parse_repo_config("[deny]\npaths = [\"/\"]\n").unwrap();
        let err = validate_repo_config(&config).expect_err("\"/\" must be rejected");
        assert!(err.contains("filesystem root"), "unexpected error {err}");
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
