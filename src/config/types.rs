//! Configuration types: structs, enums, and defaults.

use serde::Deserialize;
use std::path::PathBuf;

/// Tri-state for CLI flag pairs like `--with-proxy` / `--no-proxy`.
///
/// Keeps Clap's two boolean flags but converts them to a single value
/// at the merge boundary. `from_pair()` rejects contradictory inputs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum FeatureToggle {
    /// Explicitly enabled via CLI flag (e.g. `--with-proxy`).
    ForceOn,
    /// Explicitly disabled via CLI flag (e.g. `--no-proxy`).
    ForceOff,
    /// Neither flag given — use config file value or hardcoded default.
    #[default]
    UseDefault,
}

impl FeatureToggle {
    /// Convert a Clap boolean pair into a `FeatureToggle`.
    ///
    /// Clap's `conflicts_with` should prevent both being true, but we
    /// handle it defensively: `off` wins if both are set.
    pub fn from_pair(on: bool, off: bool) -> Self {
        match (on, off) {
            (_, true) => Self::ForceOff,
            (true, false) => Self::ForceOn,
            (false, false) => Self::UseDefault,
        }
    }

    /// Resolve to a concrete bool given the config/default value.
    pub fn resolve(self, config_default: bool) -> bool {
        match self {
            Self::ForceOn => true,
            Self::ForceOff => false,
            Self::UseDefault => config_default,
        }
    }
}

/// Default config directory relative to $HOME.
pub(super) const CONFIG_DIR: &str = ".config/cplt";
pub(super) const CONFIG_FILE: &str = "config.toml";

/// Top-level config file structure.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Schema/format version for forward compatibility (default: 1).
    pub config_version: Option<u32>,
    pub proxy: ProxyConfig,
    pub allow: AllowConfig,
    pub deny: DenyConfig,
    pub sandbox: SandboxConfig,
    pub gh_guard: GhGuardConfig,
    pub git_guard: GitGuardConfig,
    pub audit: AuditConfig,
}

/// Enforcement mode for security gates — controls rollout aggressiveness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Hard block: command is denied and process exits non-zero.
    #[default]
    Block,
    /// Warn: prints a warning to stderr but allows the command through.
    /// Use during initial adoption to discover what would break.
    Warn,
    /// Audit: allows the command through but logs the decision to stderr.
    /// Use in CI or when collecting telemetry before enabling enforcement.
    Audit,
}

impl std::fmt::Display for EnforcementMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block => write!(f, "block"),
            Self::Warn => write!(f, "warn"),
            Self::Audit => write!(f, "audit"),
        }
    }
}

impl<'de> Deserialize<'de> for EnforcementMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "block" => Ok(Self::Block),
            "warn" => Ok(Self::Warn),
            "audit" => Ok(Self::Audit),
            other => Err(serde::de::Error::custom(format!(
                "invalid mode '{other}': expected \"block\", \"warn\", or \"audit\""
            ))),
        }
    }
}

/// Policy for unknown (unclassified) gh CLI commands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UnknownCommandPolicy {
    /// Block unknown commands (secure default — new gh commands are denied until classified).
    #[default]
    Block,
    /// Allow unknown commands to pass through (permissive — use during testing/adoption).
    Allow,
}

impl std::fmt::Display for UnknownCommandPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block => write!(f, "block"),
            Self::Allow => write!(f, "allow"),
        }
    }
}

impl<'de> Deserialize<'de> for UnknownCommandPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "block" => Ok(Self::Block),
            "allow" => Ok(Self::Allow),
            other => Err(serde::de::Error::custom(format!(
                "invalid unknown_command value '{other}': expected \"block\" or \"allow\""
            ))),
        }
    }
}

/// `[gh_guard]` — gh CLI command filtering for sandboxed agents.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GhGuardConfig {
    /// Enable the gh CLI proxy (default: false for soft rollout).
    pub enabled: Option<bool>,
    /// Enforcement mode: "block" (default), "warn", or "audit".
    /// Controls how violations are handled across all gh proxy decisions.
    pub mode: Option<EnforcementMode>,
    /// Enforce repository scope checking for write operations (default: true).
    /// When enabled, commands like `gh pr merge -R other/repo` are blocked.
    pub scope_check: Option<bool>,
    /// Block `gh auth token` to prevent token exfiltration (default: true).
    pub block_auth_token: Option<bool>,
    /// Pre-extract GH_TOKEN before sandbox launch for Copilot agent (default: false).
    /// Only meaningful when block_auth_token is true — provides the token via env var
    /// while blocking the command that would expose it to arbitrary tools.
    pub inject_token: Option<bool>,
    /// Policy for commands not in the classification table (default: "block").
    /// "block" = secure default-deny; "allow" = permissive pass-through.
    pub unknown_command: Option<UnknownCommandPolicy>,
}

/// `[git_guard]` — git command prevention for sandboxed agents.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GitGuardConfig {
    /// Enable git command interception (default: false for soft rollout).
    pub enabled: Option<bool>,
    /// Enforcement mode: "block" (default), "warn", or "audit".
    pub mode: Option<EnforcementMode>,
    /// Block git push, request-pull, and send-pack (default: true).
    pub prevent_push: Option<bool>,
    /// Block git push --force/--force-with-lease (default: true).
    /// Only meaningful when prevent_push is false — blocks destructive pushes
    /// while allowing regular pushes.
    pub prevent_force_push: Option<bool>,
    /// Only protect default branch (main/master). Allows pushes to feature branches.
    /// When true, `prevent_push` only blocks pushes targeting main/master.
    pub protect_default_branch_only: Option<bool>,
    /// Structured push exceptions. Each entry specifies conditions under which
    /// push is allowed despite prevent_push being enabled.
    pub allow_push: Vec<GitPushRule>,
}

/// A structured rule that permits `git push` under specific conditions.
/// All specified fields must match (AND logic).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GitPushRule {
    /// Remote name to allow pushing to (e.g. `"fork"`, `"origin"`).
    pub remote: Option<String>,
    /// Branch glob patterns to allow (e.g. `["agent/*", "copilot/*"]`).
    pub branches: Vec<String>,
    /// Allow force push in this rule (default: false).
    pub force: Option<bool>,
}

/// `[audit]` — global audit logging for sandbox decisions.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Enable audit logging (default: false).
    pub enabled: Option<bool>,
    /// Where to write audit entries: "stderr" or a file path (default: "stderr").
    pub destination: Option<String>,
    /// What to log: "blocked" (only blocked), "decisions" (all gate decisions),
    /// "all" (includes allowed passthrough). Default: "blocked".
    pub level: Option<String>,
    /// Output format: "text" (human-readable) or "jsonl" (machine-parseable).
    /// Default: "text".
    pub format: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Enable the CONNECT proxy (default: true when not set in config).
    pub enabled: Option<bool>,
    /// Proxy listen port (default: 0, OS-assigned ephemeral port).
    pub port: Option<u16>,
    /// Path to blocked domains file.
    pub blocked_domains: Option<String>,
    /// Path to allowed domains file. When set, only listed domains are permitted.
    pub allowed_domains: Option<String>,
    /// Path to write proxy audit log (one line per CONNECT).
    pub log_file: Option<String>,
    /// Stderr verbosity level: "none", "error", "blocked", "all" (default: "none").
    pub log_level: Option<String>,
    /// Domains allowed to resolve to private/internal IPs.
    /// For each listed domain, the post-DNS private IP check is skipped.
    /// Use for corporate internal services (e.g. "intern.nav.no").
    pub allow_private_domains: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct AllowConfig {
    /// Additional paths to allow reading.
    pub read: Vec<String>,
    /// Additional paths to allow writing.
    pub write: Vec<String>,
    /// Additional outbound TCP ports beyond 443.
    pub ports: Vec<u16>,
    /// Localhost ports to allow (localhost is blocked by default).
    pub localhost: Vec<u16>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct DenyConfig {
    /// Additional paths to explicitly deny.
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    /// Preferred AI coding agent (default: auto-detect from PATH).
    /// Use this instead of always passing --agent on the command line.
    pub agent: Option<String>,
    /// Run sandbox-exec validation test on startup (default: true).
    pub validate: Option<bool>,
    /// Allow reading .env files and private keys in project dir (default: false).
    pub allow_env_files: Option<bool>,
    /// Allow all localhost outbound (default: false).
    pub allow_localhost_any: Option<bool>,
    /// Extra env vars to pass through to the sandbox (beyond the safe allowlist).
    pub pass_env: Vec<String>,
    /// Inherit ALL env vars instead of using the safe allowlist (default: false).
    /// DANGEROUS: exposes cloud credentials, npm tokens, database URLs, etc.
    pub inherit_env: Option<bool>,
    /// Allow npm/yarn/pnpm lifecycle scripts (postinstall hooks) to run (default: false).
    /// These are blocked by default to prevent supply chain attacks.
    pub allow_lifecycle_scripts: Option<bool>,
    /// Allow GPG commit/tag signing inside the sandbox (default: false).
    /// DANGEROUS: exposes GPG agent socket, allowing signature requests.
    /// Private keys remain protected — only the agent socket and public
    /// keyring are accessible. See SECURITY.md for risk analysis.
    pub allow_gpg_signing: Option<bool>,
    /// Allow JVM Attach API unix sockets in /tmp (default: false).
    /// Needed for JVM testing frameworks that use runtime self-attach
    /// (MockK inline mocking, Mockito inline, ByteBuddy agent loading).
    /// Only allows sockets matching /tmp/.java_pid<PID> — SSH agent and
    /// all other unix sockets remain blocked.
    pub allow_jvm_attach: Option<bool>,
    /// Allow Docker/Colima/OrbStack access inside the sandbox (default: false).
    /// DANGEROUS: Docker can mount any host path via container volumes, completely
    /// bypassing sandbox filesystem restrictions. Only enable if you trust the
    /// agent's container usage.
    pub allow_docker: Option<bool>,
    /// Allow process execution from system temp directories (default: false).
    /// DANGEROUS: re-enables exec from /private/tmp and /private/var/folders.
    pub allow_tmp_exec: Option<bool>,
    /// Specific ~/Library/Caches subdirectories to allow process execution from.
    /// e.g. `["ms-playwright", "pnpm/dlx"]` to allow Playwright and pnpm dlx caches.
    /// No exec is allowed from ~/Library/Caches by default (binary-drop staging risk).
    pub allow_cache_exec: Vec<String>,
    /// Allow process execution from ALL ~/Library/Caches subdirectories (default: false).
    /// DANGEROUS: much broader than allow_cache_exec — prefer specific subdirs.
    pub allow_cache_exec_any: Option<bool>,
    /// Allow Launch Services (`open` command) for OAuth browser flows (default: false).
    /// Lets the sandboxed agent open URLs in your default browser.
    pub allow_browser: Option<bool>,
    /// Enable per-session scratch directory for TMPDIR redirect (default: true).
    /// Creates an executable temp dir so tools like `go test` and `mise` can work.
    pub scratch_dir: Option<bool>,
    /// Suppress the startup configuration summary and non-essential info messages.
    /// Errors and warnings are always shown. (default: false)
    pub quiet: Option<bool>,
    /// Enable the gh CLI proxy that blocks destructive GitHub operations (default: false).
    /// When enabled, a wrapper script intercepts `gh` commands and applies a policy that
    /// blocks destructive write operations (delete repo, merge PR, etc.) while allowing
    /// safe reads. Default-deny for unrecognized commands.
    pub gh_proxy: Option<bool>,
    /// Enable git push prevention (default: false).
    /// When enabled, a wrapper script intercepts `git` commands and blocks `push` and
    /// `request-pull` while allowing all other git operations.
    pub git_push_prevention: Option<bool>,
}

/// Resolved gh proxy policy — immutable once computed at sandbox launch.
/// Passed to the `gate()` function and baked into wrapper script flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhGuardPolicy {
    pub enabled: bool,
    pub mode: EnforcementMode,
    pub scope_check: bool,
    pub block_auth_token: bool,
    pub inject_token: bool,
    pub unknown_command: UnknownCommandPolicy,
}

impl Default for GhGuardPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: EnforcementMode::Block,
            scope_check: true,
            block_auth_token: true,
            inject_token: false,
            unknown_command: UnknownCommandPolicy::Block,
        }
    }
}

/// Resolved git guard policy — immutable once computed at sandbox launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitGuardPolicy {
    pub enabled: bool,
    pub mode: EnforcementMode,
    pub prevent_push: bool,
    pub prevent_force_push: bool,
    pub protect_default_branch_only: bool,
    pub allow_push: Vec<ResolvedPushRule>,
}

impl Default for GitGuardPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: EnforcementMode::Block,
            prevent_push: true,
            prevent_force_push: true,
            protect_default_branch_only: false,
            allow_push: Vec::new(),
        }
    }
}

/// Resolved push rule (validated at config load time).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedPushRule {
    pub remote: Option<String>,
    pub branches: Vec<String>,
    pub force: bool,
}

/// Resolved configuration after merging config file + CLI flags.
/// All paths are expanded and canonicalized.
#[derive(Debug)]
pub struct Resolved {
    pub with_proxy: bool,
    pub proxy_port: u16,
    pub blocked_domains: Option<PathBuf>,
    pub allowed_domains: Option<PathBuf>,
    pub proxy_log_file: Option<PathBuf>,
    pub proxy_log_level: crate::proxy::ProxyLogLevel,
    pub allow_private_domains: Vec<String>,
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    pub deny_paths: Vec<PathBuf>,
    pub allow_ports: Vec<u16>,
    pub allow_localhost: Vec<u16>,
    pub allow_localhost_any: bool,
    pub allow_env_files: bool,
    pub no_validate: bool,
    pub pass_env: Vec<String>,
    pub inherit_env: bool,
    pub allow_lifecycle_scripts: bool,
    pub allow_gpg_signing: bool,
    pub allow_jvm_attach: bool,
    pub allow_docker: bool,
    pub allow_tmp_exec: bool,
    pub allow_cache_exec: Vec<String>,
    pub allow_cache_exec_any: bool,
    pub allow_browser: bool,
    pub scratch_dir: bool,
    pub quiet: bool,
    pub gh_guard: GhGuardPolicy,
    pub git_guard: GitGuardPolicy,
    /// Preferred agent from config (None = auto-detect).
    pub agent: Option<String>,
    /// Env vars to strip from the sandbox environment (from repo config [deny] section).
    pub deny_env: Vec<String>,
}

/// CLI flag values to merge with the config file.
///
/// Booleans default to `false` (secure default). The merge logic treats
/// `true` as an explicit CLI override.
#[derive(Debug, Default)]
pub struct CliFlags {
    pub proxy: FeatureToggle,
    pub proxy_port: Option<u16>,
    pub blocked_domains: Option<PathBuf>,
    pub allowed_domains: Option<PathBuf>,
    pub proxy_log_file: Option<PathBuf>,
    pub proxy_log_level: Option<crate::proxy::ProxyLogLevel>,
    pub allow_private_domains: Vec<String>,
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    pub deny_paths: Vec<PathBuf>,
    pub allow_ports: Vec<u16>,
    pub allow_localhost: Vec<u16>,
    pub allow_localhost_any: bool,
    pub allow_env_files: bool,
    pub no_validate: bool,
    pub pass_env: Vec<String>,
    pub inherit_env: bool,
    pub allow_lifecycle_scripts: bool,
    pub allow_gpg_signing: bool,
    pub allow_jvm_attach: bool,
    pub allow_docker: bool,
    pub allow_tmp_exec: bool,
    pub allow_cache_exec: Vec<String>,
    pub allow_cache_exec_any: bool,
    pub allow_browser: bool,
    pub scratch: FeatureToggle,
    pub quiet: FeatureToggle,
    pub gh_guard: FeatureToggle,
    pub git_push_prevention: FeatureToggle,
}

/// Result of loading a config file from disk.
pub struct LoadedConfig {
    pub config: Config,
    pub path: PathBuf,
    /// Raw TOML text (retained for validation).
    pub raw: String,
}
