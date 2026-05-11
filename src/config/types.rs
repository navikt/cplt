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
    pub proxy: ProxyConfig,
    pub allow: AllowConfig,
    pub deny: DenyConfig,
    pub sandbox: SandboxConfig,
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
}

/// Result of loading a config file from disk.
pub struct LoadedConfig {
    pub config: Config,
    pub path: PathBuf,
    /// Raw TOML text (retained for validation).
    pub raw: String,
}
