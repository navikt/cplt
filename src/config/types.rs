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

    /// Project onto a tri-state `Option<bool>` for options whose config layer
    /// is itself tri-state (`Some(true)`/`Some(false)`/`None`) rather than a
    /// plain bool with a hardcoded default.
    ///
    /// `ForceOn`/`ForceOff` are explicit CLI overrides; `UseDefault` yields
    /// `None` so the caller can fall through to the config value (e.g. via
    /// `.or(config_value)`). Preserves the "off wins if both flags are set"
    /// convention of `from_pair`, since a contradictory pair resolves to
    /// `ForceOff` → `Some(false)`.
    pub fn to_option(self) -> Option<bool> {
        match self {
            Self::ForceOn => Some(true),
            Self::ForceOff => Some(false),
            Self::UseDefault => None,
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

/// Named policy preset — a security *posture*, not just a filesystem/exec
/// permission profile. Sets a baseline across two axes with one flag/key:
/// the five sandbox toggles AND the safety features (`gh_guard`, `git_guard`,
/// forced-proxy egress). Individual flags and config values still override the
/// baseline (see the merge logic in `loading.rs`).
///
/// Only `Strict` enables the safety features; `Standard`/`Permissive`/
/// `FullTrust` leave them at their default (off). `Standard` is a no-op
/// baseline (all five toggles off, no guards, no forced proxy) identical to
/// cplt's hardcoded defaults, so passing no preset behaves exactly like
/// `standard`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Preset {
    /// Locked-down posture: no localhost, env files, tmp exec, docker, or
    /// lifecycle scripts, AND gh_guard + git_guard + forced-proxy egress on.
    Strict,
    /// The current defaults (scratch dir stays on; all five toggles off, no
    /// guards, no forced proxy).
    Standard,
    /// Developer-friendly: localhost, tmp exec, and lifecycle scripts on.
    Permissive,
    /// Everything allowed (equivalent to enabling all five toggles).
    #[value(name = "full-trust")]
    FullTrust,
}

/// The baseline a [`Preset`] establishes: the five sandbox toggles plus the
/// four safety features (gh_guard, git_guard, forced proxy, default allowlist).
/// The toggles
/// *weaken* the sandbox (dangerous when on); the safety features *harden* it
/// (never dangerous). Only [`enabled_dangerous_names`](Self::enabled_dangerous_names)
/// — keyed on the five toggles — gates the `--force`/validate safeguards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresetBaseline {
    pub allow_localhost_any: bool,
    pub allow_env_files: bool,
    pub allow_tmp_exec: bool,
    pub allow_docker: bool,
    pub allow_lifecycle_scripts: bool,
    /// Safety feature: gate `gh`/GitHub-API traffic through the guard.
    pub gh_guard_enabled: bool,
    /// Safety feature: block dangerous `git` operations (push/force-push).
    pub git_guard_enabled: bool,
    /// Safety feature: mandatory proxy, kernel egress locked to the proxy port.
    pub proxy_forced: bool,
    /// Safety feature: fail-closed domain allowlist (#52). Restricts egress to
    /// the agent's built-in default allowlist merged with any `allowed_domains`;
    /// every other domain is blocked. Combined with `proxy_forced` this makes
    /// `strict` a full network lockdown (forced egress + domain filtering).
    pub default_allowlist: bool,
}

impl PresetBaseline {
    /// Human-readable names of the toggles this baseline turns **on**, in a
    /// stable display order. Every one of these five toggles is treated as
    /// dangerous when set explicitly (each has `dangerous: true` in the
    /// registry and its own `config validate` warning), so this doubles as
    /// "the dangerous settings this preset enables" — used to warn about and
    /// name exactly what a dangerous preset turns on.
    ///
    /// Deriving the list from the actual toggle values means a preset warning
    /// can never drift out of sync with what [`Preset::baseline`] enables.
    pub fn enabled_dangerous_names(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.allow_tmp_exec {
            names.push("tmp-exec");
        }
        if self.allow_localhost_any {
            names.push("localhost-any");
        }
        if self.allow_lifecycle_scripts {
            names.push("lifecycle-scripts");
        }
        if self.allow_docker {
            names.push("docker");
        }
        if self.allow_env_files {
            names.push("env-files");
        }
        names
    }
}

impl Preset {
    /// Parse a preset from its canonical string name (as used in the config
    /// file and on the CLI). Shared by `Deserialize` and by
    /// validation/`config set` so the accepted names cannot drift between
    /// parsing paths.
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "strict" => Some(Self::Strict),
            "standard" => Some(Self::Standard),
            "permissive" => Some(Self::Permissive),
            "full-trust" => Some(Self::FullTrust),
            _ => None,
        }
    }

    /// The dangerous sandbox toggles this preset enables, by name. Empty for
    /// `strict`/`standard` (no-op baselines); non-empty for `permissive` and
    /// `full-trust`. A non-empty result means the preset weakens the sandbox
    /// and should trigger the same dangerous-setting safeguards as the
    /// individual toggles it turns on.
    pub fn enabled_dangerous_names(self) -> Vec<&'static str> {
        self.baseline().enabled_dangerous_names()
    }

    /// Map the preset to its baseline values (five sandbox toggles + four
    /// safety features).
    ///
    /// `Strict` and `Standard` share the same five *toggle* values (all off),
    /// but differ on the safety features: only `Strict` turns on gh_guard,
    /// git_guard, forced-proxy egress, and the fail-closed default allowlist —
    /// a genuine locked-down posture (full network lockdown).
    /// `Standard` is the no-op baseline (everything off), identical to cplt's
    /// hardcoded defaults. The scratch dir is not a preset-controlled toggle
    /// and stays at its default (on) for every preset.
    pub fn baseline(self) -> PresetBaseline {
        match self {
            Self::Strict => PresetBaseline {
                allow_localhost_any: false,
                allow_env_files: false,
                allow_tmp_exec: false,
                allow_docker: false,
                allow_lifecycle_scripts: false,
                gh_guard_enabled: true,
                git_guard_enabled: true,
                proxy_forced: true,
                default_allowlist: true,
            },
            Self::Standard => PresetBaseline {
                allow_localhost_any: false,
                allow_env_files: false,
                allow_tmp_exec: false,
                allow_docker: false,
                allow_lifecycle_scripts: false,
                gh_guard_enabled: false,
                git_guard_enabled: false,
                proxy_forced: false,
                default_allowlist: false,
            },
            Self::Permissive => PresetBaseline {
                allow_localhost_any: true,
                allow_env_files: false,
                allow_tmp_exec: true,
                allow_docker: false,
                allow_lifecycle_scripts: true,
                gh_guard_enabled: false,
                git_guard_enabled: false,
                proxy_forced: false,
                default_allowlist: false,
            },
            Self::FullTrust => PresetBaseline {
                allow_localhost_any: true,
                allow_env_files: true,
                allow_tmp_exec: true,
                allow_docker: true,
                allow_lifecycle_scripts: true,
                gh_guard_enabled: false,
                git_guard_enabled: false,
                proxy_forced: false,
                default_allowlist: false,
            },
        }
    }
}

impl std::fmt::Display for Preset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Standard => write!(f, "standard"),
            Self::Permissive => write!(f, "permissive"),
            Self::FullTrust => write!(f, "full-trust"),
        }
    }
}

impl<'de> Deserialize<'de> for Preset {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_name(&s).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "invalid preset '{s}': expected \"strict\", \"standard\", \"permissive\", or \"full-trust\""
            ))
        })
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
    /// Allow `gh api` write operations (POST/PATCH/PUT/DELETE and input flags).
    /// When true, write requests are scope-checked to the current repo.
    /// GraphQL is always blocked regardless of this setting (default: false).
    pub allow_api_write: Option<bool>,
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
    /// Force all egress through the proxy (default: false).
    /// When true, the CONNECT proxy is mandatory and kernel-level egress is
    /// restricted to the proxy port only (no direct `*:443`). Fails closed:
    /// if the proxy cannot start, the agent is not launched. See #53.
    pub forced: Option<bool>,
    /// Proxy listen port (default: 0, OS-assigned ephemeral port).
    pub port: Option<u16>,
    /// Path to blocked domains file.
    pub blocked_domains: Option<String>,
    /// Path to allowed domains file. When set, only listed domains are permitted.
    pub allowed_domains: Option<String>,
    /// Opt-in fail-closed networking (issue #52, default: false). When true, the
    /// proxy restricts egress to the running agent's built-in default allowlist
    /// (e.g. GitHub Copilot infra + package registries for Copilot) MERGED with
    /// any `allowed_domains` — every other domain is blocked. Overridden for a
    /// single run by `--allow-all-domains`. Enabling this does NOT change any
    /// other default; flipping the global default is tracked separately (#71).
    pub default_allowlist: Option<bool>,
    /// Path to write proxy audit log (one line per CONNECT).
    pub log_file: Option<String>,
    /// Stderr verbosity level: "none", "error", "blocked", "all" (default: "none").
    pub log_level: Option<String>,
    /// Domains allowed to resolve to private/internal IPs.
    /// For each listed domain, the post-DNS private IP check is skipped.
    /// Use for corporate internal services (e.g. "intern.nav.no").
    pub allow_private_domains: Option<Vec<String>>,
    /// Proxy read/write timeout in seconds (default: 60).
    pub timeout: Option<u64>,
    /// Upstream (corporate) proxy URL to forward CONNECT tunnels through,
    /// e.g. "http://corporate-proxy.example.com:8080". When set, cplt still
    /// enforces ALL of its domain filtering, logging, and port checks first,
    /// then forwards approved tunnels to this proxy instead of connecting
    /// directly. Optional basic-auth userinfo is supported
    /// ("http://user:pass@host:8080"); only the http scheme is supported.
    pub upstream: Option<String>,
    /// Hosts that BYPASS the upstream proxy and are connected to DIRECTLY by
    /// cplt (standard NO_PROXY behavior). Only meaningful when `upstream` is set
    /// — a no-op otherwise. Suffix matching (`example.com` covers all
    /// subdomains), like the other domain lists. Merged with any explicit CLI
    /// entries and the ambient `NO_PROXY`/`no_proxy` environment variable.
    /// A no-proxy host is still subject to ALL of cplt's filtering (domain
    /// allow/block, port policy, resolved-IP SSRF guard); it is simply connected
    /// directly instead of being forwarded to the corporate proxy.
    pub upstream_no_proxy: Option<Vec<String>>,
    /// Subscribable blocklists (issue #144, Phase 1). GLOBAL-only, tighten-only.
    /// Cached lists UNION into the effective blocklist. Rejected in repo config.
    pub subscriptions: SubscriptionsConfig,
}

/// `[proxy.subscriptions]` — subscribable domain lists (issue #144).
///
/// Phase 1 is BLOCKLIST subscriptions only: tighten-only, fail-open, low-risk.
/// This is GLOBAL-only config (`~/.config/cplt/config.toml`) — the repo config
/// schema has no `[proxy]` table, so a `.cplt.toml` can never add a subscription.
/// Allowlist subscriptions (security-critical, fail-closed) are a future feature.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct SubscriptionsConfig {
    /// Refresh cadence: "manual" (default), "daily", or "weekly".
    pub refresh: Option<String>,
    /// Blocklist subscription sources. Each entry is a bare URL string or a
    /// `{ url, sha256 }` table with an optional pinned hash (recommended).
    pub blocklists: Vec<BlocklistSource>,
}

/// One blocklist subscription source: a bare URL, or a table with an optional
/// pinned SHA256. Deserialized untagged so both TOML forms work:
///
/// ```toml
/// blocklists = [
///   "https://example.com/blocklist.txt",
///   { url = "https://example.com/pinned.txt", sha256 = "abc123..." },
/// ]
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum BlocklistSource {
    /// A bare URL string (unpinned — loads because blocklists are tighten-only).
    Url(String),
    /// A URL with an optional pinned SHA256 (verified after download).
    Pinned {
        url: String,
        #[serde(default)]
        sha256: Option<String>,
    },
}

impl BlocklistSource {
    /// The subscription URL, regardless of form.
    pub fn url(&self) -> &str {
        match self {
            Self::Url(u) | Self::Pinned { url: u, .. } => u,
        }
    }

    /// The pinned SHA256, if any.
    pub fn sha256(&self) -> Option<&str> {
        match self {
            Self::Url(_) => None,
            Self::Pinned { sha256, .. } => sha256.as_deref(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct AllowConfig {
    /// Additional paths to allow reading.
    pub read: Vec<String>,
    /// Additional paths to allow writing.
    pub write: Vec<String>,
    /// Unix socket paths to allow access to.
    pub socket: Vec<String>,
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
    /// Named policy preset that sets a baseline for the five sandbox toggles
    /// (allow_localhost_any, allow_env_files, allow_tmp_exec, allow_docker,
    /// allow_lifecycle_scripts). Individual keys/flags still override it.
    /// One of "strict", "standard", "permissive", "full-trust". Default: none
    /// (equivalent to "standard" — a no-op baseline).
    pub preset: Option<Preset>,
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
    /// Allow MSBuild worker-node unix sockets in /tmp (default: false).
    /// Needed for `dotnet build`, which forks worker nodes that communicate
    /// with the client over a Unix domain socket at /tmp/MSBuild<PID>.
    /// This does NOT allow the persistent MSBuild Server (MSBuildServer-<hash>),
    /// which stays blocked — reuse of that server is also disabled via
    /// DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER=1. SSH agent and all other unix
    /// sockets remain blocked.
    pub allow_msbuild: Option<bool>,
    /// Install a cplt-managed Gradle init script in the Gradle user home
    /// (`$GRADLE_USER_HOME/init.d/` or `~/.gradle/init.d/`) that applies the
    /// preferIPv4Stack workaround inside the sandbox (default: false).
    /// Opt-in: writes to a tool config dir, so it is off unless the
    /// user asks for it.
    pub gradle_init: Option<bool>,
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
    /// Print the post-session project-change audit report (default: true).
    /// After the sandboxed agent exits, cplt diffs the working tree against a
    /// pinned baseline commit (captured before the run) and prints the net
    /// changes to stderr. Also suppressed by `quiet`.
    pub audit: Option<bool>,
    /// Use Bubblewrap for namespace isolation on Linux (default: auto-detect).
    /// - `true`: Always use bwrap (fail if unavailable)
    /// - `false`: Never use bwrap (Landlock+seccomp only)
    /// - Not set: Auto-detect and use if available (graceful degradation)
    pub use_bubblewrap: Option<bool>,
    /// Suppress the startup configuration summary and non-essential info messages.
    /// Errors and warnings are always shown. (default: false)
    pub quiet: Option<bool>,
    /// Skip the confirmation prompt at startup (default: false).
    /// Equivalent to always passing --yes on the command line.
    pub yes: Option<bool>,
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
    /// Allow `gh api` write operations (POST/PATCH/PUT and input flags),
    /// scope-checked to the current repo. GraphQL remains blocked.
    pub allow_api_write: bool,
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
            allow_api_write: false,
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
    /// Force all egress through the proxy (proxy mandatory, kernel egress
    /// restricted to the proxy port, fail-closed). See #53.
    pub proxy_forced: bool,
    pub proxy_port: u16,
    pub blocked_domains: Option<PathBuf>,
    pub allowed_domains: Option<PathBuf>,
    /// Fail-closed networking opt-in (#52): restrict egress to the agent's
    /// built-in default allowlist merged with `allowed_domains`. Already
    /// reconciled with `--allow-all-domains` (which forces this off).
    pub default_allowlist: bool,
    /// Escape hatch (#52): force allow-all for this run, disabling BOTH the
    /// default allowlist and any explicit `allowed_domains` file.
    pub allow_all_domains: bool,
    pub proxy_log_file: Option<PathBuf>,
    pub proxy_log_level: crate::proxy::ProxyLogLevel,
    pub proxy_timeout: std::time::Duration,
    /// Parsed upstream (corporate) proxy to forward CONNECT tunnels through.
    /// `None` = direct connections (unchanged behavior).
    pub proxy_upstream: Option<crate::proxy::UpstreamProxy>,
    /// Normalized hosts that bypass the upstream proxy and connect directly
    /// (NO_PROXY semantics). Merged from config, CLI, and the `NO_PROXY` env.
    /// A no-op when `proxy_upstream` is `None`.
    pub proxy_upstream_no_proxy: Vec<String>,
    /// Resolved blocklist subscriptions (issue #144, Phase 1). Empty blocklists
    /// = feature off (behaviour byte-identical to today). Cached lists are
    /// UNIONed into the effective blocklist. GLOBAL-only, tighten-only, fail-open.
    pub proxy_subscriptions: crate::subscriptions::SubscriptionSet,
    pub allow_private_domains: Vec<String>,
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    pub allow_socket: Vec<PathBuf>,
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
    pub deny_clipboard: bool,
    pub allow_jvm_attach: bool,
    pub allow_msbuild: bool,
    pub gradle_init: bool,
    pub allow_docker: bool,
    pub allow_tmp_exec: bool,
    pub allow_cache_exec: Vec<String>,
    pub allow_cache_exec_any: bool,
    pub allow_browser: bool,
    pub scratch_dir: bool,
    pub use_bubblewrap: Option<bool>,
    pub quiet: bool,
    /// Print the post-session project-change audit report (default: true).
    pub audit: bool,
    pub yes: bool,
    pub gh_guard: GhGuardPolicy,
    pub git_guard: GitGuardPolicy,
    /// Active policy preset after merging CLI + config (None = no preset given).
    /// Purely informational — the baseline it implies is already applied to the
    /// individual toggle fields above. Used for the startup summary / config show.
    pub preset: Option<Preset>,
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
    /// Policy preset from `--preset` (None = not given). CLI wins over config.
    pub preset: Option<Preset>,
    pub proxy: FeatureToggle,
    pub proxy_forced: FeatureToggle,
    pub proxy_port: Option<u16>,
    pub blocked_domains: Option<PathBuf>,
    pub allowed_domains: Option<PathBuf>,
    /// `--default-allowlist` (on) vs `--allow-all-domains` (off); off wins.
    /// Resolved against `proxy.default_allowlist` config.
    pub default_allowlist: FeatureToggle,
    /// `--allow-all-domains`: force allow-all for this run (escape hatch).
    pub allow_all_domains: bool,
    pub proxy_log_file: Option<PathBuf>,
    pub proxy_log_level: Option<crate::proxy::ProxyLogLevel>,
    pub proxy_timeout: Option<u64>,
    /// Upstream proxy URL from `--proxy-upstream` (unparsed; validated in merge).
    pub proxy_upstream: Option<String>,
    /// Hosts to bypass the upstream proxy, from `--proxy-upstream-no-proxy`
    /// (repeatable). When non-empty, overrides the config list; the ambient
    /// `NO_PROXY` env is merged on top of whichever wins.
    pub proxy_upstream_no_proxy: Vec<String>,
    pub allow_private_domains: Vec<String>,
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    pub allow_socket: Vec<PathBuf>,
    pub deny_paths: Vec<PathBuf>,
    pub allow_ports: Vec<u16>,
    pub allow_localhost: Vec<u16>,
    /// Preset-controlled toggle: tri-state so `--no-allow-localhost-any` can
    /// force it off, overriding a permissive/full-trust preset baseline.
    pub allow_localhost_any: FeatureToggle,
    /// Preset-controlled toggle (see `allow_localhost_any`).
    pub allow_env_files: FeatureToggle,
    pub no_validate: bool,
    pub pass_env: Vec<String>,
    pub inherit_env: bool,
    /// Preset-controlled toggle (see `allow_localhost_any`).
    pub allow_lifecycle_scripts: FeatureToggle,
    pub allow_gpg_signing: bool,
    pub deny_clipboard: bool,
    pub allow_jvm_attach: bool,
    pub allow_msbuild: bool,
    pub gradle_init: bool,
    /// Preset-controlled toggle (see `allow_localhost_any`).
    pub allow_docker: FeatureToggle,
    /// Preset-controlled toggle (see `allow_localhost_any`).
    pub allow_tmp_exec: FeatureToggle,
    pub allow_cache_exec: Vec<String>,
    pub allow_cache_exec_any: bool,
    pub allow_browser: bool,
    pub scratch: FeatureToggle,
    pub use_bubblewrap: FeatureToggle,
    pub quiet: FeatureToggle,
    /// Post-session project-change audit report (default on; `--no-audit` off).
    pub audit: FeatureToggle,
    pub yes: FeatureToggle,
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
