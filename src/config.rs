//! User configuration loaded from `~/.config/cplt/config.toml`.
//!
//! The config file is optional — cplt works without it.
//! CLI flags always override config values for scalar fields.
//! For list fields (allow/deny paths), CLI and config values are merged (union).
//!
//! Override config location with `CPLT_CONFIG` env var.

use crate::sandbox::{HardeningCategory, validate_sbpl_path};
use serde::Deserialize;
use std::path::PathBuf;

/// Default config directory relative to $HOME.
const CONFIG_DIR: &str = ".config/cplt";
const CONFIG_FILE: &str = "config.toml";

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
    /// Enable the CONNECT proxy (default: false).
    pub enabled: Option<bool>,
    /// Proxy listen port (default: 18080).
    pub port: Option<u16>,
    /// Path to blocked domains file.
    pub blocked_domains: Option<String>,
    /// Path to allowed domains file. When set, only listed domains are permitted.
    pub allowed_domains: Option<String>,
    /// Path to write proxy audit log (one line per CONNECT).
    pub log_file: Option<String>,
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
    /// Allow process execution from system temp directories (default: false).
    /// DANGEROUS: re-enables exec from /private/tmp and /private/var/folders.
    pub allow_tmp_exec: Option<bool>,
    /// Enable per-session scratch directory for TMPDIR redirect (default: false).
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
    pub allow_tmp_exec: bool,
    pub scratch_dir: bool,
    pub quiet: bool,
}

/// CLI flag values to merge with the config file.
///
/// Booleans default to `false` (secure default). The merge logic treats
/// `true` as an explicit CLI override.
#[derive(Debug, Default)]
pub struct CliFlags {
    pub with_proxy: bool,
    pub no_proxy: bool,
    pub proxy_port: Option<u16>,
    pub blocked_domains: Option<PathBuf>,
    pub allowed_domains: Option<PathBuf>,
    pub proxy_log_file: Option<PathBuf>,
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
    pub allow_tmp_exec: bool,
    pub scratch_dir: bool,
    pub quiet: bool,
    pub no_quiet: bool,
}

/// Result of loading a config file from disk.
pub struct LoadedConfig {
    pub config: Config,
    pub path: PathBuf,
    /// Raw TOML text (retained for validation).
    pub raw: String,
}

impl Config {
    /// Load config from `~/.config/cplt/config.toml` (or CPLT_CONFIG).
    /// Returns `Config::default()` if the file doesn't exist.
    /// Returns an error if the file exists but is malformed or unreadable.
    /// Prints the config path to stderr on success.
    pub fn load() -> Result<Self, String> {
        match Self::load_file()? {
            Some(loaded) => {
                eprintln!(
                    "\x1b[0;34m[cplt]\x1b[0m Config:   {}",
                    loaded.path.display()
                );
                Ok(loaded.config)
            }
            None => Ok(Config::default()),
        }
    }

    /// Load config file without printing anything.
    /// Returns `None` if no config file exists (HOME unset or file absent).
    /// Returns `Err` if the file exists but can't be read or parsed.
    pub fn load_file() -> Result<Option<LoadedConfig>, String> {
        let Some(path) = config_path() else {
            return Ok(None);
        };

        if !path.exists() {
            return Ok(None);
        }

        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "\x1b[0;34m[cplt]\x1b[0m Cannot read config file {}: {e}",
                    path.display()
                );
                return Ok(None);
            }
            Err(e) => {
                return Err(format!("Cannot read config file {}: {e}", path.display()));
            }
        };

        let config: Config =
            toml::from_str(&raw).map_err(|e| format!("Invalid TOML in {}: {e}", path.display()))?;

        Ok(Some(LoadedConfig { config, path, raw }))
    }

    /// Parse config from a TOML string (no I/O, no side effects).
    pub fn parse(s: &str) -> Result<Self, String> {
        toml::from_str(s).map_err(|e| format!("Invalid TOML: {e}"))
    }

    /// Merge config file values with CLI flags.
    ///
    /// Precedence rules:
    /// - Booleans: explicit CLI flag > config > default
    /// - Scalars: CLI (if Some) > config > hardcoded default
    /// - Lists: union of config + CLI (both contribute)
    ///
    /// Returns an error if a deny path from config cannot be resolved
    /// (security-critical: silently dropping deny rules is dangerous).
    pub fn merge(&self, cli: CliFlags) -> Result<Resolved, String> {
        // Proxy: --no-proxy always wins, then --with-proxy, then config, then false (default off).
        let with_proxy = if cli.no_proxy {
            false
        } else if cli.with_proxy {
            true
        } else {
            self.proxy.enabled.unwrap_or(false)
        };

        // Port: CLI (if provided) > config > 18080
        let proxy_port = cli.proxy_port.or(self.proxy.port).unwrap_or(18080);

        // Blocked domains: CLI > config > exe_dir fallback (handled later in main)
        let blocked_domains = cli
            .blocked_domains
            .or_else(|| self.proxy.blocked_domains.as_ref().map(|s| expand_tilde(s)));

        // Allowed domains: CLI > config
        let allowed_domains = cli
            .allowed_domains
            .or_else(|| self.proxy.allowed_domains.as_ref().map(|s| expand_tilde(s)));

        // Proxy log file: CLI > config
        let proxy_log_file = cli
            .proxy_log_file
            .or_else(|| self.proxy.log_file.as_ref().map(|s| expand_tilde(s)));

        // Allow-read: merge config + CLI
        let config_dir = config_path().and_then(|p| p.parent().map(|d| d.to_path_buf()));
        let mut allow_read: Vec<PathBuf> = Vec::new();
        for s in &self.allow.read {
            match resolve_config_path(s, config_dir.as_ref()) {
                Ok(p) => allow_read.push(p),
                Err(e) => {
                    eprintln!("\x1b[0;33m[cplt]\x1b[0m Warning: allow.read path {s:?}: {e}");
                }
            }
        }
        allow_read.extend(cli.allow_read);

        // Allow-write: merge config + CLI
        let mut allow_write: Vec<PathBuf> = Vec::new();
        for s in &self.allow.write {
            match resolve_config_path(s, config_dir.as_ref()) {
                Ok(p) => allow_write.push(p),
                Err(e) => {
                    eprintln!("\x1b[0;33m[cplt]\x1b[0m Warning: allow.write path {s:?}: {e}");
                }
            }
        }
        allow_write.extend(cli.allow_write);

        // Deny-paths: merge config + CLI
        // SECURITY: config deny paths MUST resolve — a silently dropped deny is dangerous
        let mut deny_paths: Vec<PathBuf> = Vec::new();
        for s in &self.deny.paths {
            match resolve_config_path(s, config_dir.as_ref()) {
                Ok(p) => deny_paths.push(p),
                Err(e) => {
                    return Err(format!(
                        "deny.paths entry {s:?} cannot be resolved: {e}\n\
                         Fix the path in your config or remove it. \
                         Silently dropping deny rules is a security risk."
                    ));
                }
            }
        }
        deny_paths.extend(cli.deny_paths);

        // Validate: --no-validate wins, then config, then true (validate by default)
        let no_validate = if cli.no_validate {
            true
        } else {
            !self.sandbox.validate.unwrap_or(true)
        };

        // Allow-env-files: CLI flag wins, then config, then false (deny by default)
        let allow_env_files = if cli.allow_env_files {
            true
        } else {
            self.sandbox.allow_env_files.unwrap_or(false)
        };

        // Allow-ports: merge config + CLI
        let mut allow_ports = self.allow.ports.clone();
        allow_ports.extend(cli.allow_ports);
        allow_ports.sort_unstable();
        allow_ports.dedup();

        // Allow-localhost: merge config + CLI
        let mut allow_localhost = self.allow.localhost.clone();
        allow_localhost.extend(cli.allow_localhost);
        allow_localhost.sort_unstable();
        allow_localhost.dedup();

        // Allow-localhost-any: CLI flag wins, then config, then false
        let allow_localhost_any = if cli.allow_localhost_any {
            true
        } else {
            self.sandbox.allow_localhost_any.unwrap_or(false)
        };

        // Pass-env: merge config + CLI
        let mut pass_env = self.sandbox.pass_env.clone();
        pass_env.extend(cli.pass_env);
        pass_env.sort_unstable();
        pass_env.dedup();

        // Inherit-env: CLI flag wins, then config, then false (secure by default)
        let inherit_env = if cli.inherit_env {
            true
        } else {
            self.sandbox.inherit_env.unwrap_or(false)
        };

        // Allow-lifecycle-scripts: CLI flag wins, then config, then false (blocked by default)
        let allow_lifecycle_scripts = if cli.allow_lifecycle_scripts {
            true
        } else {
            self.sandbox.allow_lifecycle_scripts.unwrap_or(false)
        };

        // Allow-tmp-exec: CLI flag wins, then config, then false (blocked by default)
        let allow_tmp_exec = if cli.allow_tmp_exec {
            true
        } else {
            self.sandbox.allow_tmp_exec.unwrap_or(false)
        };

        // Scratch-dir: CLI flag wins, then config, then false (off by default)
        let scratch_dir = if cli.scratch_dir {
            true
        } else {
            self.sandbox.scratch_dir.unwrap_or(false)
        };

        // Quiet: --no-quiet always wins, then --quiet, then config, then false
        let quiet = if cli.no_quiet {
            false
        } else if cli.quiet {
            true
        } else {
            self.sandbox.quiet.unwrap_or(false)
        };

        // Validate all paths for SBPL injection characters
        for p in allow_read
            .iter()
            .chain(allow_write.iter())
            .chain(deny_paths.iter())
        {
            validate_sbpl_path(p)?;
        }

        Ok(Resolved {
            with_proxy,
            proxy_port,
            blocked_domains,
            allowed_domains,
            proxy_log_file,
            allow_read,
            allow_write,
            deny_paths,
            allow_ports,
            allow_localhost,
            allow_localhost_any,
            allow_env_files,
            no_validate,
            pass_env,
            inherit_env,
            allow_lifecycle_scripts,
            allow_tmp_exec,
            scratch_dir,
            quiet,
        })
    }
}

impl Resolved {
    /// Returns the hardening categories that are disabled by user configuration.
    pub fn disabled_hardening_categories(&self) -> Vec<HardeningCategory> {
        let mut disabled = Vec::new();
        if self.allow_lifecycle_scripts {
            disabled.push(HardeningCategory::LifecycleScripts);
        }
        disabled
    }

    /// Print comprehensive sandbox configuration summary to stderr.
    ///
    /// Shows ALL effective settings including defaults so the user can make
    /// an informed decision before Copilot is launched. This is a security
    /// tool — the sandbox boundary must never be hidden.
    pub fn print_summary(&self, project_dir: &std::path::Path, home_dir: &std::path::Path) {
        let blue = "\x1b[0;34m";
        let dim = "\x1b[2m";
        let green = "\x1b[0;32m";
        let yellow = "\x1b[0;33m";
        let nc = "\x1b[0m";

        eprintln!();
        eprintln!("{blue}[cplt]{nc} ── Sandbox Configuration ─────────────────────────");
        eprintln!();

        // Filesystem
        eprintln!("{blue}[cplt]{nc}  {dim}Filesystem:{nc}");
        eprintln!(
            "{blue}[cplt]{nc}    Project:       {green}read/write{nc}  {}",
            project_dir.display()
        );
        if !self.allow_read.is_empty() {
            for p in &self.allow_read {
                eprintln!(
                    "{blue}[cplt]{nc}    Extra read:    {green}allowed{nc}     {}",
                    p.display()
                );
            }
        }
        if !self.allow_write.is_empty() {
            for p in &self.allow_write {
                eprintln!(
                    "{blue}[cplt]{nc}    Extra write:   {yellow}allowed{nc}     {}",
                    p.display()
                );
            }
        }
        if !self.deny_paths.is_empty() {
            for p in &self.deny_paths {
                eprintln!(
                    "{blue}[cplt]{nc}    Deny:          blocked     {}",
                    p.display()
                );
            }
        }
        if self.allow_env_files {
            eprintln!(
                "{blue}[cplt]{nc}    .env/.pem/.key {yellow}allowed{nc}     {dim}(--allow-env-files){nc}"
            );
        } else {
            eprintln!("{blue}[cplt]{nc}    .env/.pem/.key blocked     {dim}secrets protected{nc}");
        }
        if self.allow_lifecycle_scripts {
            eprintln!(
                "{blue}[cplt]{nc}    Lifecycle:     {yellow}allowed{nc}     {dim}(--allow-lifecycle-scripts){nc}"
            );
        } else {
            eprintln!(
                "{blue}[cplt]{nc}    Lifecycle:     blocked     {dim}npm/yarn postinstall hooks{nc}"
            );
        }
        if self.scratch_dir {
            eprintln!(
                "{blue}[cplt]{nc}    Scratch dir:   {green}enabled{nc}     {dim}TMPDIR redirected (--scratch-dir){nc}"
            );
        }
        if self.allow_tmp_exec {
            let red = "\x1b[0;31m";
            eprintln!(
                "{blue}[cplt]{nc}    Tmp exec:      {red}ALLOWED{nc}     {dim}⚠ /tmp + /var/folders exec enabled{nc}"
            );
        }
        eprintln!(
            "{blue}[cplt]{nc}    SSH/GPG/cloud: blocked     {dim}~/.ssh, ~/.gnupg, ~/.aws, ...{nc}"
        );
        eprintln!("{blue}[cplt]{nc}    Copilot dir:   {green}allowed{nc}     {dim}~/.copilot{nc}");
        eprintln!(
            "{blue}[cplt]{nc}    Keychain:      {green}allowed{nc}     {dim}~/Library/Keychains{nc}"
        );
        eprintln!(
            "{blue}[cplt]{nc}    GH CLI config: {green}read-only{nc}   {dim}~/.config/gh/{{hosts,config}}.yml{nc}"
        );
        eprintln!();

        // Network
        eprintln!("{blue}[cplt]{nc}  {dim}Network:{nc}");
        if self.allow_ports.is_empty() {
            eprintln!(
                "{blue}[cplt]{nc}    Outbound:      {green}443{nc}          {dim}HTTPS only{nc}"
            );
        } else {
            let ports: Vec<String> = self.allow_ports.iter().map(|p| p.to_string()).collect();
            eprintln!(
                "{blue}[cplt]{nc}    Outbound:      {green}443, {}{nc}",
                ports.join(", ")
            );
        }
        if self.allow_localhost_any {
            eprintln!(
                "{blue}[cplt]{nc}    Localhost:     {yellow}all ports{nc}   {dim}(--allow-localhost-any){nc}"
            );
        } else if !self.allow_localhost.is_empty() {
            let ports: Vec<String> = self
                .allow_localhost
                .iter()
                .map(|p| format!(":{p}"))
                .collect();
            eprintln!(
                "{blue}[cplt]{nc}    Localhost:     {yellow}{}{nc}",
                ports.join(", ")
            );
        } else {
            eprintln!(
                "{blue}[cplt]{nc}    Localhost:     blocked     {dim}use --allow-localhost <PORT>{nc}"
            );
        }
        if self.with_proxy {
            eprintln!(
                "{blue}[cplt]{nc}    Proxy:         {green}on{nc}          {dim}localhost:{}{nc}",
                self.proxy_port
            );
            if self.allowed_domains.is_some() {
                eprintln!(
                    "{blue}[cplt]{nc}    Allowlist:     {green}on{nc}          {dim}only listed domains{nc}"
                );
            }
            if let Some(ref lf) = self.proxy_log_file {
                eprintln!(
                    "{blue}[cplt]{nc}    Audit log:     {green}on{nc}          {dim}{}{nc}",
                    lf.display()
                );
            }
        } else {
            eprintln!("{blue}[cplt]{nc}    Proxy:         off         {dim}direct connections{nc}");
        }
        eprintln!("{blue}[cplt]{nc}    SSH agent:     blocked     {dim}use HTTPS, not SSH{nc}");
        eprintln!();

        // Environment
        eprintln!("{blue}[cplt]{nc}  {dim}Environment:{nc}");
        if self.inherit_env {
            let red = "\x1b[0;31m";
            eprintln!(
                "{blue}[cplt]{nc}    Mode:          {red}INHERITED{nc}   {dim}⚠ all env vars passed (--inherit-env){nc}"
            );
        } else if !self.pass_env.is_empty() {
            eprintln!(
                "{blue}[cplt]{nc}    Mode:          {green}sanitized{nc}   {dim}allowlist + {} extra{nc}",
                self.pass_env.len()
            );
            for var in &self.pass_env {
                eprintln!("{blue}[cplt]{nc}    Extra:         {yellow}{var}{nc}");
            }
        } else {
            eprintln!(
                "{blue}[cplt]{nc}    Mode:          {green}sanitized{nc}   {dim}safe allowlist only{nc}"
            );
        }
        eprintln!(
            "{blue}[cplt]{nc}    Stripped:      {dim}AWS_*, NPM_TOKEN, DATABASE_URL, SSH_AUTH_SOCK, ...{nc}"
        );
        eprintln!();

        eprintln!(
            "{blue}[cplt]{nc}  {dim}Home:{nc}           {}",
            home_dir.display()
        );
        if self.no_validate {
            eprintln!(
                "{blue}[cplt]{nc}  {dim}Validation:{nc}     skipped     {dim}(--no-validate){nc}"
            );
        }
        eprintln!("{blue}[cplt]{nc}  {dim}Full profile:{nc}   cplt --print-profile");
        eprintln!(
            "{blue}[cplt]{nc}  {yellow}Tip:{nc}            {dim}use --quiet or: cplt config set sandbox.quiet true{nc}"
        );
        eprintln!("{blue}[cplt]{nc} ──────────────────────────────────────────────────────");
    }
}

/// Return the config file path.
/// Checks `CPLT_CONFIG` env var first, then `~/.config/cplt/config.toml`.
pub fn config_path() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("CPLT_CONFIG") {
        return Some(expand_tilde(&custom));
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(CONFIG_DIR).join(CONFIG_FILE))
}

/// Generate a default config file with comments explaining each option.
pub fn default_config_contents() -> String {
    r#"# cplt configuration
#
# This file configures default behavior for cplt.
# CLI flags always override these settings.
# Location: ~/.config/cplt/config.toml
# Override: CPLT_CONFIG=/path/to/config.toml

# ─── Proxy ───────────────────────────────────────────────────
# Optional CONNECT proxy that logs and filters outbound HTTPS connections.
# When enabled, HTTP_PROXY/HTTPS_PROXY and NODE_USE_ENV_PROXY=1 are injected
# so all traffic (Copilot, gh, curl) routes through the proxy.
# The proxy enforces the same port policy as the sandbox (443 + allow-port).
# Disabled by default. Enable with --with-proxy or set enabled = true below.
[proxy]
# enabled = false
# port = 18080
# blocked_domains = "~/.config/cplt/blocked-domains.txt"
# allowed_domains = "~/.config/cplt/allowed-domains.txt"
# log_file = "~/.config/cplt/proxy.log"

# ─── Allowed paths ──────────────────────────────────────────
# Additional paths the sandboxed process may access.
# These are merged with any --allow-read / --allow-write CLI flags.
# Tilde (~/) is expanded to $HOME.
# Relative paths are resolved from this config file's directory.
[allow]
# read = [
#     "~/some/reference/docs",
# ]
# write = []
#
# Additional outbound TCP ports beyond 443.
# Use for external services.
# ports = [8080]
#
# Localhost ports to allow (localhost is blocked by default).
# Use for MCP servers, dev servers, or local APIs.
# localhost = [3000, 8080]

# ─── Denied paths ───────────────────────────────────────────
# Additional paths to explicitly block (overrides allows).
# Merged with any --deny-path CLI flags.
# WARNING: paths that cannot be resolved will cause a startup error
# (silently dropping deny rules is a security risk).
[deny]
# paths = [
#     "~/.config/gcloud",
#     "~/.config/op",
# ]

# ─── Sandbox behavior ───────────────────────────────────────
[sandbox]
# Run sandbox-exec validation test on every launch (default: true).
# Disable to save ~200ms startup if you trust your config.
# validate = true
#
# Allow Copilot to read .env files and private keys (.pem, .key)
# in the project directory. Blocked by default — these often contain
# secrets that a rogue agent could exfiltrate via HTTPS.
# allow_env_files = false
#
# Allow npm/yarn/pnpm lifecycle scripts (postinstall hooks) to run.
# Blocked by default — supply chain attacks (e.g. axios March 2026)
# use postinstall hooks to execute malicious payloads.
# allow_lifecycle_scripts = false
#
# Allow outbound TCP to localhost on ALL ports.
# Needed for build tools like Turbopack (Next.js), Vite, and esbuild
# that spawn workers communicating via TCP on random localhost ports.
# allow_localhost_any = false
#
# Extra environment variables to pass through to the sandbox.
# By default, only a safe allowlist is passed (PATH, HOME, TERM, etc.)
# and cloud credentials are stripped. Use this for tool-specific vars.
# pass_env = ["MY_API_KEY", "CUSTOM_TOOL_CONFIG"]
#
# DANGEROUS: Inherit ALL environment variables (disables sanitization).
# Cloud credentials, npm tokens, database URLs, etc. will be visible.
# inherit_env = false
#
# Enable per-session scratch directory for TMPDIR redirect.
# Creates ~/Library/Caches/cplt/tmp/{session}/ with write+exec permissions
# so tools like `go test`, `mise` inline tasks, and `node-gyp` can work.
# Cleaned up automatically on exit.
# scratch_dir = false
#
# DANGEROUS: Allow process execution from system temp directories.
# Re-enables exec from /private/tmp and /private/var/folders.
# Prefer scratch_dir which creates a controlled executable temp dir.
# allow_tmp_exec = false
#
# Suppress the startup configuration summary and non-essential messages.
# Errors and warnings are always shown. Useful once you've reviewed the
# sandbox settings and don't need to see them every time.
# Override with --no-quiet for a single run.
# quiet = false
"#
    .to_string()
}

/// Expand leading `~/` to `$HOME/`. Only this form is supported.
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if path == "~"
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home);
    }
    PathBuf::from(path)
}

/// Expand tilde, resolve relative paths against config dir, and canonicalize.
fn resolve_config_path(path: &str, config_dir: Option<&PathBuf>) -> Result<PathBuf, String> {
    let expanded = expand_tilde(path);

    // If relative and we know the config dir, resolve from there
    let full = if expanded.is_relative() {
        if let Some(dir) = config_dir {
            dir.join(&expanded)
        } else {
            expanded
        }
    } else {
        expanded
    };

    std::fs::canonicalize(&full).map_err(|e| format!("path does not exist or is inaccessible: {e}"))
}

// ── Config validation (unknown key detection) ────────────────────────

/// Valid keys for each TOML section. Used by `validate_config` to detect typos.
const VALID_PROXY_KEYS: &[&str] = &[
    "enabled",
    "port",
    "blocked_domains",
    "allowed_domains",
    "log_file",
];
const VALID_ALLOW_KEYS: &[&str] = &["read", "write", "ports", "localhost"];
const VALID_DENY_KEYS: &[&str] = &["paths"];
const VALID_SANDBOX_KEYS: &[&str] = &[
    "validate",
    "allow_env_files",
    "allow_localhost_any",
    "pass_env",
    "inherit_env",
    "allow_lifecycle_scripts",
    "allow_tmp_exec",
    "scratch_dir",
    "quiet",
];
const VALID_SECTIONS: &[&str] = &["proxy", "allow", "deny", "sandbox"];

/// A single validation diagnostic.
#[derive(Debug)]
pub struct ConfigDiagnostic {
    pub level: DiagnosticLevel,
    pub message: String,
}

#[derive(Debug, PartialEq)]
pub enum DiagnosticLevel {
    Error,
    Warning,
}

impl std::fmt::Display for ConfigDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = match self.level {
            DiagnosticLevel::Error => "error",
            DiagnosticLevel::Warning => "warning",
        };
        write!(f, "{prefix}: {}", self.message)
    }
}

/// Validate a TOML config string for unknown keys and dangerous settings.
///
/// This is stricter than runtime loading — runtime silently ignores unknown keys
/// for forward compatibility, but `config validate` reports them so typos like
/// `inherit_evn = true` don't silently fail.
pub fn validate_config(toml_text: &str) -> Vec<ConfigDiagnostic> {
    let mut diagnostics = Vec::new();

    // First check: is it valid TOML at all?
    let table: toml::Table = match toml_text.parse() {
        Ok(t) => t,
        Err(e) => {
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Error,
                message: format!("invalid TOML syntax: {e}"),
            });
            return diagnostics;
        }
    };

    // Check top-level keys (should all be known section names)
    for key in table.keys() {
        if !VALID_SECTIONS.contains(&key.as_str()) {
            let suggestion = suggest_key(key, VALID_SECTIONS);
            let hint = suggestion
                .map(|s| format!(" (did you mean '{s}'?)"))
                .unwrap_or_default();
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Error,
                message: format!("unknown section [{key}]{hint}"),
            });
        }
    }

    // Check keys within each known section
    check_section_keys(&table, "proxy", VALID_PROXY_KEYS, &mut diagnostics);
    check_section_keys(&table, "allow", VALID_ALLOW_KEYS, &mut diagnostics);
    check_section_keys(&table, "deny", VALID_DENY_KEYS, &mut diagnostics);
    check_section_keys(&table, "sandbox", VALID_SANDBOX_KEYS, &mut diagnostics);

    // Also verify it deserializes correctly (catches type errors)
    if diagnostics
        .iter()
        .all(|d| d.level != DiagnosticLevel::Error)
        && let Err(e) = toml::from_str::<Config>(toml_text)
    {
        diagnostics.push(ConfigDiagnostic {
            level: DiagnosticLevel::Error,
            message: format!("type error: {e}"),
        });
    }

    // Warn about dangerous settings
    if let Some(sandbox) = table.get("sandbox").and_then(|v| v.as_table()) {
        if sandbox.get("inherit_env").and_then(|v| v.as_bool()) == Some(true) {
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Warning,
                message: "sandbox.inherit_env = true: all env vars will be exposed (DANGEROUS)"
                    .to_string(),
            });
        }
        if sandbox.get("allow_tmp_exec").and_then(|v| v.as_bool()) == Some(true) {
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Warning,
                message: "sandbox.allow_tmp_exec = true: exec from temp dirs enabled (DANGEROUS)"
                    .to_string(),
            });
        }
    }

    diagnostics
}

fn check_section_keys(
    table: &toml::Table,
    section: &str,
    valid_keys: &[&str],
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let Some(section_value) = table.get(section) else {
        return;
    };
    let Some(section_table) = section_value.as_table() else {
        diagnostics.push(ConfigDiagnostic {
            level: DiagnosticLevel::Error,
            message: format!(
                "[{section}] must be a table, not a {}",
                value_type_name(section_value)
            ),
        });
        return;
    };

    for key in section_table.keys() {
        if !valid_keys.contains(&key.as_str()) {
            let suggestion = suggest_key(key, valid_keys);
            let hint = suggestion
                .map(|s| format!(" (did you mean '{s}'?)"))
                .unwrap_or_default();
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Error,
                message: format!("unknown key '{key}' in [{section}]{hint}"),
            });
        }
    }
}

/// Suggest the closest valid key using simple edit distance.
fn suggest_key<'a>(input: &str, valid: &[&'a str]) -> Option<&'a str> {
    let input_lower = input.to_lowercase();
    valid
        .iter()
        .filter_map(|&candidate| {
            let dist = edit_distance(&input_lower, candidate);
            // Only suggest if reasonably close (at most 3 edits and less than half the key length)
            if dist <= 3 && dist < candidate.len() / 2 + 1 {
                Some((candidate, dist))
            } else {
                None
            }
        })
        .min_by_key(|(_, d)| *d)
        .map(|(s, _)| s)
}

/// Simple Levenshtein edit distance.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut matrix = vec![vec![0usize; b.len() + 1]; a.len() + 1];

    for (i, row) in matrix.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, val) in matrix[0].iter_mut().enumerate() {
        *val = j;
    }
    for (i, a_char) in a.iter().enumerate() {
        for (j, b_char) in b.iter().enumerate() {
            let cost = if a_char == b_char { 0 } else { 1 };
            matrix[i + 1][j + 1] = (matrix[i][j + 1] + 1)
                .min(matrix[i + 1][j] + 1)
                .min(matrix[i][j] + cost);
        }
    }
    matrix[a.len()][b.len()]
}

fn value_type_name(v: &toml::Value) -> &'static str {
    match v {
        toml::Value::String(_) => "string",
        toml::Value::Integer(_) => "integer",
        toml::Value::Float(_) => "float",
        toml::Value::Boolean(_) => "boolean",
        toml::Value::Datetime(_) => "datetime",
        toml::Value::Array(_) => "array",
        toml::Value::Table(_) => "table",
    }
}

// ── Config key registry (for get/set) ────────────────────────────────

/// The type of a config value, used for parsing and display.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConfigValueType {
    Bool,
    U16,
    Str,
    U16Array,
    StrArray,
}

/// Metadata about a single config key.
#[derive(Debug, Clone)]
pub struct ConfigKeyInfo {
    pub section: &'static str,
    pub key: &'static str,
    pub value_type: ConfigValueType,
    pub dangerous: bool,
    /// Default value as displayed to the user.
    pub default_display: &'static str,
    /// Human-readable description of what this key does.
    pub description: &'static str,
}

/// All known config keys with their metadata.
const CONFIG_KEYS: &[ConfigKeyInfo] = &[
    // [proxy]
    ConfigKeyInfo {
        section: "proxy",
        key: "enabled",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Enable the CONNECT proxy for outbound HTTPS traffic logging and domain filtering.",
    },
    ConfigKeyInfo {
        section: "proxy",
        key: "port",
        value_type: ConfigValueType::U16,
        dangerous: false,
        default_display: "18080",
        description: "Local port for the CONNECT proxy listener.",
    },
    ConfigKeyInfo {
        section: "proxy",
        key: "blocked_domains",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "",
        description: "Path to a file listing domains to block through the proxy (one per line).",
    },
    ConfigKeyInfo {
        section: "proxy",
        key: "allowed_domains",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "",
        description: "Path to a file listing the only domains allowed through the proxy (allowlist mode).",
    },
    ConfigKeyInfo {
        section: "proxy",
        key: "log_file",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "",
        description: "Path to write proxy connection logs (CONNECT requests and outcomes).",
    },
    // [allow]
    ConfigKeyInfo {
        section: "allow",
        key: "read",
        value_type: ConfigValueType::StrArray,
        dangerous: false,
        default_display: "[]",
        description: "Extra directories to allow read access (e.g., shared libraries outside the project).",
    },
    ConfigKeyInfo {
        section: "allow",
        key: "write",
        value_type: ConfigValueType::StrArray,
        dangerous: false,
        default_display: "[]",
        description: "Extra directories to allow write access (use sparingly — project dir is already writable).",
    },
    ConfigKeyInfo {
        section: "allow",
        key: "ports",
        value_type: ConfigValueType::U16Array,
        dangerous: false,
        default_display: "[]",
        description: "Additional outbound ports to allow (443 is always allowed).",
    },
    ConfigKeyInfo {
        section: "allow",
        key: "localhost",
        value_type: ConfigValueType::U16Array,
        dangerous: false,
        default_display: "[]",
        description: "Specific localhost ports to allow outbound connections to (e.g., local dev servers).",
    },
    // [deny]
    ConfigKeyInfo {
        section: "deny",
        key: "paths",
        value_type: ConfigValueType::StrArray,
        dangerous: false,
        default_display: "[]",
        description: "Extra paths to deny access to (overrides project-dir allows for sensitive subdirs).",
    },
    // [sandbox]
    ConfigKeyInfo {
        section: "sandbox",
        key: "validate",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "true",
        description: "Validate the sandbox profile with sandbox-exec before launching Copilot.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "allow_env_files",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Allow Copilot to read .env, .pem, .key files in the project directory.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "allow_localhost_any",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Allow outbound connections to any localhost port (for local dev servers).",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "pass_env",
        value_type: ConfigValueType::StrArray,
        dangerous: false,
        default_display: "[]",
        description: "Extra environment variables to pass through to the sandbox (exact names).",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "inherit_env",
        value_type: ConfigValueType::Bool,
        dangerous: true,
        default_display: "false",
        description: "⚠️  DANGEROUS: Pass ALL environment variables instead of the safe allowlist. May leak secrets.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "allow_lifecycle_scripts",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Allow npm/yarn/pnpm lifecycle scripts (postinstall, prepare, etc.) to run.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "allow_tmp_exec",
        value_type: ConfigValueType::Bool,
        dangerous: true,
        default_display: "false",
        description: "⚠️  DANGEROUS: Allow executing binaries from /tmp and /var/folders. Weakens code-exec isolation.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "scratch_dir",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Create a per-session scratch directory and redirect TMPDIR into it.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "quiet",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Hide the startup configuration summary (sandbox rules, network, env info).",
    },
];

/// Look up a config key by "section.key" dotted notation.
pub fn lookup_key(dotted: &str) -> Result<&'static ConfigKeyInfo, String> {
    let (section, key) = dotted.split_once('.').ok_or_else(|| {
        format!("invalid key format '{dotted}': expected section.key (e.g., sandbox.quiet)")
    })?;

    CONFIG_KEYS
        .iter()
        .find(|k| k.section == section && k.key == key)
        .ok_or_else(|| {
            // Try to give a helpful suggestion
            let all_dotted: Vec<String> = CONFIG_KEYS
                .iter()
                .map(|k| format!("{}.{}", k.section, k.key))
                .collect();
            let all_refs: Vec<&str> = all_dotted.iter().map(|s| s.as_str()).collect();
            let suggestion = suggest_key(dotted, &all_refs);
            let hint = suggestion
                .map(|s| format!("\n  Did you mean '{s}'?"))
                .unwrap_or_default();
            format!(
                "unknown config key '{dotted}'{hint}\n  Valid keys: {}",
                all_dotted.join(", ")
            )
        })
}

fn type_label(vt: ConfigValueType) -> &'static str {
    match vt {
        ConfigValueType::Bool => "bool",
        ConfigValueType::U16 => "integer (1-65535)",
        ConfigValueType::Str => "string",
        ConfigValueType::U16Array => "integer array",
        ConfigValueType::StrArray => "string array",
    }
}

/// Print explanation of a single config key.
pub fn explain_key(key_info: &ConfigKeyInfo) {
    let blue = "\x1b[0;34m";
    let bold = "\x1b[1m";
    let dim = "\x1b[2m";
    let yellow = "\x1b[0;33m";
    let nc = "\x1b[0m";

    eprintln!("{bold}{}.{}{nc}", key_info.section, key_info.key);
    eprintln!("  {}", key_info.description);
    eprintln!("  {dim}Type:{nc}    {}", type_label(key_info.value_type));
    eprintln!("{dim}  Default:{nc} {}", key_info.default_display);
    if key_info.dangerous {
        eprintln!("  {yellow}Requires --force to enable{nc}");
    }
    eprintln!(
        "  {blue}Set:{nc}     cplt config set {}.{} <value>",
        key_info.section, key_info.key
    );
}

/// Print explanation of all config keys, grouped by section.
pub fn explain_all() {
    let blue = "\x1b[0;34m";
    let bold = "\x1b[1m";
    let dim = "\x1b[2m";
    let yellow = "\x1b[0;33m";
    let nc = "\x1b[0m";

    let mut current_section = "";
    for key in CONFIG_KEYS {
        if key.section != current_section {
            if !current_section.is_empty() {
                eprintln!();
            }
            eprintln!("{blue}[{bold}{}{nc}{blue}]{nc}", key.section);
            current_section = key.section;
        }
        let danger = if key.dangerous {
            format!(" {yellow}⚠{nc}")
        } else {
            String::new()
        };
        eprintln!(
            "  {bold}{:<25}{nc} {dim}{:<15}{nc} {}{danger}",
            format!("{}.{}", key.section, key.key),
            format!("({})", type_label(key.value_type)),
            key.description.trim_start_matches("⚠️  DANGEROUS: "),
        );
    }
}

/// Get the effective value of a config key.
/// Returns `(value_string, is_from_file)`.
#[allow(clippy::collapsible_if)]
pub fn get_config_value(key_info: &ConfigKeyInfo, loaded: Option<&LoadedConfig>) -> (String, bool) {
    if let Some(loaded) = loaded {
        if let Ok(root) = loaded.raw.parse::<toml::Table>() {
            if let Some(section) = root.get(key_info.section) {
                if let Some(val) = section.get(key_info.key) {
                    return (format_toml_value(val), true);
                }
            }
        }
    }

    (key_info.default_display.to_string(), false)
}

fn format_toml_value(val: &toml::Value) -> String {
    match val {
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::String(s) => s.clone(),
        toml::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_toml_value).collect();
            format!("[{}]", items.join(", "))
        }
        other => other.to_string(),
    }
}

/// Parse a CLI value string into the correct TOML type for the given key.
fn parse_value_for_key(key_info: &ConfigKeyInfo, value: &str) -> Result<toml_edit::Value, String> {
    match key_info.value_type {
        ConfigValueType::Bool => match value {
            "true" => Ok(toml_edit::value(true).into_value().unwrap()),
            "false" => Ok(toml_edit::value(false).into_value().unwrap()),
            _ => Err(format!(
                "invalid boolean value '{value}' for {}.{}: expected 'true' or 'false'",
                key_info.section, key_info.key
            )),
        },
        ConfigValueType::U16 => {
            let n: u16 = value.parse().map_err(|_| {
                format!(
                    "invalid port value '{value}' for {}.{}: expected 1-65535",
                    key_info.section, key_info.key
                )
            })?;
            if n == 0 {
                return Err(format!(
                    "port 0 is not valid for {}.{}",
                    key_info.section, key_info.key
                ));
            }
            Ok(toml_edit::value(n as i64).into_value().unwrap())
        }
        ConfigValueType::Str => Ok(toml_edit::value(value).into_value().unwrap()),
        ConfigValueType::U16Array => {
            // Comma-separated: "8080,9090" or single "8080"
            let mut arr = toml_edit::Array::new();
            for item in value.split(',') {
                let item = item.trim();
                let n: u16 = item
                    .parse()
                    .map_err(|_| format!("invalid port value '{item}': expected 1-65535"))?;
                if n == 0 {
                    return Err("port 0 is not valid".to_string());
                }
                arr.push(n as i64);
            }
            Ok(toml_edit::Value::Array(arr))
        }
        ConfigValueType::StrArray => {
            // Comma-separated: "path1,path2" or single "path1"
            let mut arr = toml_edit::Array::new();
            for item in value.split(',') {
                arr.push(item.trim());
            }
            Ok(toml_edit::Value::Array(arr))
        }
    }
}

/// Parse a single element value for appending to an array.
fn parse_element_for_key(
    key_info: &ConfigKeyInfo,
    value: &str,
) -> Result<toml_edit::Value, String> {
    match key_info.value_type {
        ConfigValueType::U16Array => {
            let n: u16 = value
                .parse()
                .map_err(|_| format!("invalid port value '{value}': expected 1-65535"))?;
            if n == 0 {
                return Err("port 0 is not valid".to_string());
            }
            Ok(toml_edit::value(n as i64).into_value().unwrap())
        }
        ConfigValueType::StrArray => Ok(toml_edit::value(value).into_value().unwrap()),
        _ => Err(format!(
            "{}.{} is not an array key — use 'set' without --append",
            key_info.section, key_info.key
        )),
    }
}

/// Set a value in a TOML document, creating the section if needed.
pub fn set_value_in_doc(
    doc: &mut toml_edit::DocumentMut,
    key_info: &ConfigKeyInfo,
    value: &str,
) -> Result<(), String> {
    let typed_value = parse_value_for_key(key_info, value)?;

    // Ensure section exists
    if !doc.contains_table(key_info.section) {
        doc[key_info.section] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    doc[key_info.section][key_info.key] = toml_edit::Item::Value(typed_value);
    Ok(())
}

/// Append a value to an array in a TOML document.
pub fn append_value_in_doc(
    doc: &mut toml_edit::DocumentMut,
    key_info: &ConfigKeyInfo,
    value: &str,
) -> Result<(), String> {
    let element = parse_element_for_key(key_info, value)?;

    // Ensure section exists
    if !doc.contains_table(key_info.section) {
        doc[key_info.section] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    let section = doc[key_info.section].as_table_mut().unwrap();
    match section.get_mut(key_info.key) {
        Some(item) => {
            if let Some(arr) = item.as_array_mut() {
                arr.push_formatted(element);
                Ok(())
            } else {
                Err(format!(
                    "{}.{} exists but is not an array",
                    key_info.section, key_info.key
                ))
            }
        }
        None => {
            let mut arr = toml_edit::Array::new();
            arr.push_formatted(element);
            section.insert(
                key_info.key,
                toml_edit::Item::Value(toml_edit::Value::Array(arr)),
            );
            Ok(())
        }
    }
}

/// Remove a key from a TOML document (--unset).
pub fn unset_value_in_doc(doc: &mut toml_edit::DocumentMut, key_info: &ConfigKeyInfo) {
    if let Some(section) = doc.get_mut(key_info.section).and_then(|s| s.as_table_mut()) {
        section.remove(key_info.key);
    }
}

/// The full set/get/unset operation on a config file.
/// Handles file creation, validation, and write-back.
pub struct ConfigSetOp {
    pub key_info: &'static ConfigKeyInfo,
    pub path: PathBuf,
}

impl ConfigSetOp {
    pub fn new(dotted_key: &str) -> Result<Self, String> {
        let key_info = lookup_key(dotted_key)?;
        let path = config_path().ok_or("cannot determine config path ($HOME not set)")?;
        Ok(Self { key_info, path })
    }

    /// Load the existing TOML document, or create an empty one.
    pub fn load_document(&self) -> Result<toml_edit::DocumentMut, String> {
        if self.path.exists() {
            let raw = std::fs::read_to_string(&self.path)
                .map_err(|e| format!("cannot read {}: {e}", self.path.display()))?;
            raw.parse::<toml_edit::DocumentMut>()
                .map_err(|e| format!("invalid TOML in {}: {e}", self.path.display()))
        } else {
            Ok(toml_edit::DocumentMut::new())
        }
    }

    /// Write the document back, creating parent dirs if needed.
    /// Only verifies the result is valid TOML (not full key validation —
    /// an existing typo elsewhere shouldn't block a valid set operation).
    pub fn write_document(&self, doc: &toml_edit::DocumentMut) -> Result<(), String> {
        let output = doc.to_string();

        // Sanity check: the result must still be valid TOML
        if output.parse::<toml::Table>().is_err() {
            return Err("modification produced invalid TOML (this is a bug)".to_string());
        }

        // Create parent dirs
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create config directory: {e}"))?;
        }

        std::fs::write(&self.path, output)
            .map_err(|e| format!("cannot write {}: {e}", self.path.display()))
    }
}

// ── Config display (effective config) ────────────────────────────────

/// Display the effective configuration from a config file merged with defaults.
/// Shows what cplt would use at runtime (without CLI flag overrides).
pub fn display_config(loaded: Option<&LoadedConfig>) {
    let blue = "\x1b[0;34m";
    let dim = "\x1b[2m";
    let green = "\x1b[0;32m";
    let yellow = "\x1b[0;33m";
    let nc = "\x1b[0m";

    let config = loaded.map(|l| &l.config);
    let c = config.cloned().unwrap_or_default();

    // Source label helper
    let src =
        |has_file_value: bool| -> &'static str { if has_file_value { "" } else { " (default)" } };

    eprintln!("{blue}[cplt]{nc} ── Effective Configuration ──────────────────────");
    eprintln!();

    // Config file path
    if let Some(l) = loaded {
        eprintln!("{blue}[cplt]{nc}  {dim}File:{nc}  {}", l.path.display());
    } else if let Some(p) = config_path() {
        eprintln!(
            "{blue}[cplt]{nc}  {dim}File:{nc}  {dim}(not found: {}){nc}",
            p.display()
        );
    } else {
        eprintln!("{blue}[cplt]{nc}  {dim}File:{nc}  {dim}(no config path — $HOME not set){nc}");
    }
    eprintln!();

    // [proxy]
    eprintln!("{blue}[cplt]{nc}  {dim}[proxy]{nc}");
    let proxy_enabled = c.proxy.enabled.unwrap_or(false);
    eprintln!(
        "{blue}[cplt]{nc}    enabled          = {}{}{nc}{}",
        if proxy_enabled { yellow } else { green },
        proxy_enabled,
        src(c.proxy.enabled.is_some())
    );
    eprintln!(
        "{blue}[cplt]{nc}    port             = {}{}",
        c.proxy.port.unwrap_or(18080),
        src(c.proxy.port.is_some())
    );
    if let Some(ref bd) = c.proxy.blocked_domains {
        eprintln!("{blue}[cplt]{nc}    blocked_domains  = \"{bd}\"");
    }
    if let Some(ref ad) = c.proxy.allowed_domains {
        eprintln!("{blue}[cplt]{nc}    allowed_domains  = \"{ad}\"");
    }
    if let Some(ref lf) = c.proxy.log_file {
        eprintln!("{blue}[cplt]{nc}    log_file         = \"{lf}\"");
    }
    eprintln!();

    // [allow]
    eprintln!("{blue}[cplt]{nc}  {dim}[allow]{nc}");
    if c.allow.read.is_empty() {
        eprintln!("{blue}[cplt]{nc}    read             = {dim}[]{nc}");
    } else {
        eprintln!("{blue}[cplt]{nc}    read             = {:?}", c.allow.read);
    }
    if c.allow.write.is_empty() {
        eprintln!("{blue}[cplt]{nc}    write            = {dim}[]{nc}");
    } else {
        eprintln!(
            "{blue}[cplt]{nc}    write            = {yellow}{:?}{nc}",
            c.allow.write
        );
    }
    if c.allow.ports.is_empty() {
        eprintln!("{blue}[cplt]{nc}    ports            = {dim}[]{nc}");
    } else {
        eprintln!("{blue}[cplt]{nc}    ports            = {:?}", c.allow.ports);
    }
    if c.allow.localhost.is_empty() {
        eprintln!("{blue}[cplt]{nc}    localhost         = {dim}[]{nc}");
    } else {
        eprintln!(
            "{blue}[cplt]{nc}    localhost         = {:?}",
            c.allow.localhost
        );
    }
    eprintln!();

    // [deny]
    eprintln!("{blue}[cplt]{nc}  {dim}[deny]{nc}");
    if c.deny.paths.is_empty() {
        eprintln!("{blue}[cplt]{nc}    paths            = {dim}[]{nc}");
    } else {
        eprintln!("{blue}[cplt]{nc}    paths            = {:?}", c.deny.paths);
    }
    eprintln!();

    // [sandbox]
    eprintln!("{blue}[cplt]{nc}  {dim}[sandbox]{nc}");
    let validate = c.sandbox.validate.unwrap_or(true);
    eprintln!(
        "{blue}[cplt]{nc}    validate              = {}{}",
        validate,
        src(c.sandbox.validate.is_some())
    );
    let allow_env_files = c.sandbox.allow_env_files.unwrap_or(false);
    eprintln!(
        "{blue}[cplt]{nc}    allow_env_files       = {}{}",
        allow_env_files,
        src(c.sandbox.allow_env_files.is_some())
    );
    let allow_localhost_any = c.sandbox.allow_localhost_any.unwrap_or(false);
    eprintln!(
        "{blue}[cplt]{nc}    allow_localhost_any    = {}{}",
        allow_localhost_any,
        src(c.sandbox.allow_localhost_any.is_some())
    );
    if !c.sandbox.pass_env.is_empty() {
        eprintln!(
            "{blue}[cplt]{nc}    pass_env              = {:?}",
            c.sandbox.pass_env
        );
    }
    let inherit_env = c.sandbox.inherit_env.unwrap_or(false);
    if inherit_env {
        let red = "\x1b[0;31m";
        eprintln!("{blue}[cplt]{nc}    inherit_env           = {red}true{nc} ⚠ DANGEROUS");
    } else {
        eprintln!(
            "{blue}[cplt]{nc}    inherit_env           = false{}",
            src(c.sandbox.inherit_env.is_some())
        );
    }
    let allow_lifecycle = c.sandbox.allow_lifecycle_scripts.unwrap_or(false);
    eprintln!(
        "{blue}[cplt]{nc}    allow_lifecycle_scripts = {}{}",
        allow_lifecycle,
        src(c.sandbox.allow_lifecycle_scripts.is_some())
    );
    let allow_tmp = c.sandbox.allow_tmp_exec.unwrap_or(false);
    if allow_tmp {
        let red = "\x1b[0;31m";
        eprintln!("{blue}[cplt]{nc}    allow_tmp_exec        = {red}true{nc} ⚠ DANGEROUS");
    } else {
        eprintln!(
            "{blue}[cplt]{nc}    allow_tmp_exec        = false{}",
            src(c.sandbox.allow_tmp_exec.is_some())
        );
    }
    let scratch = c.sandbox.scratch_dir.unwrap_or(false);
    eprintln!(
        "{blue}[cplt]{nc}    scratch_dir           = {}{}",
        scratch,
        src(c.sandbox.scratch_dir.is_some())
    );
    let quiet = c.sandbox.quiet.unwrap_or(false);
    eprintln!(
        "{blue}[cplt]{nc}    quiet                 = {}{}",
        quiet,
        src(c.sandbox.quiet.is_some())
    );

    eprintln!("{blue}[cplt]{nc} ──────────────────────────────────────────────────────");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid_toml() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.proxy.enabled.is_none());
        assert!(config.proxy.port.is_none());
        assert!(config.allow.read.is_empty());
        assert!(config.deny.paths.is_empty());
        assert!(config.sandbox.validate.is_none());
    }

    #[test]
    fn parses_full_config() {
        let toml_str = r#"
[proxy]
enabled = true
port = 9090
blocked_domains = "~/my-blocklist.txt"

[allow]
read = ["/opt/homebrew/share"]
write = ["/tmp/sandbox-out"]

[deny]
paths = ["~/.config/gcloud"]

[sandbox]
validate = false
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.proxy.enabled, Some(true));
        assert_eq!(config.proxy.port, Some(9090));
        assert_eq!(
            config.proxy.blocked_domains,
            Some("~/my-blocklist.txt".to_string())
        );
        assert_eq!(config.allow.read, vec!["/opt/homebrew/share"]);
        assert_eq!(config.allow.write, vec!["/tmp/sandbox-out"]);
        assert_eq!(config.deny.paths, vec!["~/.config/gcloud"]);
        assert_eq!(config.sandbox.validate, Some(false));
    }

    #[test]
    fn partial_config_uses_defaults() {
        let toml_str = "[proxy]\nenabled = true\n";
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.proxy.enabled, Some(true));
        assert!(config.proxy.port.is_none());
        assert!(config.allow.read.is_empty());
    }

    #[test]
    fn expand_tilde_replaces_home() {
        let expanded = expand_tilde("~/some/path");
        let home = std::env::var("HOME").unwrap();
        assert_eq!(expanded, PathBuf::from(format!("{home}/some/path")));
    }

    #[test]
    fn expand_tilde_bare() {
        let expanded = expand_tilde("~");
        let home = std::env::var("HOME").unwrap();
        assert_eq!(expanded, PathBuf::from(home));
    }

    #[test]
    fn expand_tilde_no_tilde() {
        let expanded = expand_tilde("/absolute/path");
        assert_eq!(expanded, PathBuf::from("/absolute/path"));
    }

    #[test]
    fn expand_tilde_not_at_start() {
        // Only leading ~/ is expanded; mid-path ~ is left alone
        let expanded = expand_tilde("some/~/path");
        assert_eq!(expanded, PathBuf::from("some/~/path"));
    }

    #[test]
    fn cli_proxy_flag_overrides_config() {
        let config: Config = toml::from_str("[proxy]\nenabled = false\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                with_proxy: true,
                ..Default::default()
            })
            .unwrap();
        assert!(resolved.with_proxy);
    }

    #[test]
    fn no_proxy_flag_overrides_config_enabled() {
        let config: Config = toml::from_str("[proxy]\nenabled = true\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                no_proxy: true,
                ..Default::default()
            })
            .unwrap();
        assert!(!resolved.with_proxy);
    }

    #[test]
    fn config_proxy_used_when_no_cli_flag() {
        let config: Config = toml::from_str("[proxy]\nenabled = true\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(resolved.with_proxy);
    }

    #[test]
    fn cli_port_overrides_config() {
        let config: Config = toml::from_str("[proxy]\nport = 9090\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                proxy_port: Some(12345),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(resolved.proxy_port, 12345);
    }

    #[test]
    fn config_port_used_when_cli_none() {
        let config: Config = toml::from_str("[proxy]\nport = 9090\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert_eq!(resolved.proxy_port, 9090);
    }

    #[test]
    fn default_port_when_neither_set() {
        let config = Config::default();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert_eq!(resolved.proxy_port, 18080);
    }

    #[test]
    fn cli_no_validate_overrides_config() {
        let config: Config = toml::from_str("[sandbox]\nvalidate = true\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                no_validate: true,
                ..Default::default()
            })
            .unwrap();
        assert!(resolved.no_validate);
    }

    #[test]
    fn config_validate_false_sets_no_validate() {
        let config: Config = toml::from_str("[sandbox]\nvalidate = false\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(resolved.no_validate);
    }

    #[test]
    fn deny_paths_merged_from_config_and_cli() {
        // Use /tmp which always exists and can be canonicalized
        let config: Config = toml::from_str("[deny]\npaths = [\"/tmp\"]\n").unwrap();
        let cli_deny = vec![PathBuf::from("/var")];
        let resolved = config
            .merge(CliFlags {
                deny_paths: cli_deny,
                ..Default::default()
            })
            .unwrap();
        assert!(
            resolved
                .deny_paths
                .iter()
                .any(|p| p.to_string_lossy().contains("tmp"))
        );
        assert!(resolved.deny_paths.contains(&PathBuf::from("/var")));
    }

    #[test]
    fn deny_path_config_error_on_nonexistent() {
        let config: Config =
            toml::from_str("[deny]\npaths = [\"/nonexistent/path/xyz\"]\n").unwrap();
        let result = config.merge(CliFlags::default());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be resolved"));
    }

    #[test]
    fn default_config_contents_is_valid_toml() {
        let contents = default_config_contents();
        let config: Config = toml::from_str(&contents).unwrap();
        assert!(config.proxy.enabled.is_none());
    }

    #[test]
    fn proxy_disabled_by_default_when_no_config_or_flags() {
        let config = Config::default();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(
            !resolved.with_proxy,
            "Proxy should be disabled by default — it's a passive logging tool, not required for Copilot"
        );
    }

    #[test]
    fn sbpl_injection_rejected() {
        let path = PathBuf::from("/tmp/evil\")(allow file-read* (subpath \"/");
        let result = validate_sbpl_path(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsafe character"));
    }

    #[test]
    fn normal_paths_pass_sbpl_validation() {
        let path = PathBuf::from("/Users/hans/projects/my-app");
        assert!(validate_sbpl_path(&path).is_ok());
    }

    #[test]
    fn cli_allow_env_files_overrides_default() {
        let config = Config::default();
        let resolved = config
            .merge(CliFlags {
                allow_env_files: true,
                ..Default::default()
            })
            .unwrap();
        assert!(resolved.allow_env_files);
    }

    #[test]
    fn config_allow_env_files_used_when_cli_false() {
        let config: Config = toml::from_str("[sandbox]\nallow_env_files = true\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(resolved.allow_env_files);
    }

    #[test]
    fn env_files_denied_by_default() {
        let config = Config::default();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(!resolved.allow_env_files);
    }

    #[test]
    fn quiet_disabled_by_default() {
        let config = Config::default();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(!resolved.quiet);
    }

    #[test]
    fn cli_quiet_flag_enables_quiet() {
        let config = Config::default();
        let resolved = config
            .merge(CliFlags {
                quiet: true,
                ..Default::default()
            })
            .unwrap();
        assert!(resolved.quiet);
    }

    #[test]
    fn config_quiet_used_when_cli_false() {
        let config: Config = toml::from_str("[sandbox]\nquiet = true\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(resolved.quiet);
    }

    #[test]
    fn no_quiet_flag_overrides_config_quiet() {
        let config: Config = toml::from_str("[sandbox]\nquiet = true\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                no_quiet: true,
                ..Default::default()
            })
            .unwrap();
        assert!(!resolved.quiet);
    }

    #[test]
    fn no_quiet_wins_over_quiet_flag() {
        let config = Config::default();
        let resolved = config
            .merge(CliFlags {
                quiet: true,
                no_quiet: true,
                ..Default::default()
            })
            .unwrap();
        assert!(!resolved.quiet, "--no-quiet should always win over --quiet");
    }

    // ── Validation tests ────────────────────────────────────────

    #[test]
    fn validate_valid_config_no_diagnostics() {
        let toml = r#"
[proxy]
enabled = true
port = 9090

[allow]
read = ["/opt/homebrew"]
ports = [8080]

[deny]
paths = ["~/.config/gcloud"]

[sandbox]
validate = true
quiet = false
"#;
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.is_empty(),
            "valid config should have no diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_empty_config_no_diagnostics() {
        let diagnostics = validate_config("");
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn validate_detects_unknown_top_level_section() {
        let toml = "[proxxy]\nenabled = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.iter().any(|d| {
                d.level == DiagnosticLevel::Error && d.message.contains("unknown section [proxxy]")
            }),
            "should detect unknown section: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_suggests_similar_section() {
        let toml = "[sandox]\nquiet = true\n";
        let diagnostics = validate_config(toml);
        let msg = diagnostics
            .iter()
            .find(|d| d.message.contains("sandox"))
            .unwrap();
        assert!(
            msg.message.contains("did you mean 'sandbox'?"),
            "should suggest: {}",
            msg.message
        );
    }

    #[test]
    fn validate_detects_unknown_key_in_section() {
        let toml = "[sandbox]\ninherit_evn = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.iter().any(|d| {
                d.level == DiagnosticLevel::Error && d.message.contains("unknown key 'inherit_evn'")
            }),
            "should detect typo: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_suggests_similar_key() {
        let toml = "[sandbox]\ninherit_evn = true\n";
        let diagnostics = validate_config(toml);
        let msg = diagnostics
            .iter()
            .find(|d| d.message.contains("inherit_evn"))
            .unwrap();
        assert!(
            msg.message.contains("did you mean 'inherit_env'?"),
            "should suggest: {}",
            msg.message
        );
    }

    #[test]
    fn validate_detects_invalid_toml_syntax() {
        let toml = "[sandbox\nquiet = true\n";
        let diagnostics = validate_config(toml);
        assert!(diagnostics.iter().any(|d| {
            d.level == DiagnosticLevel::Error && d.message.contains("invalid TOML syntax")
        }));
    }

    #[test]
    fn validate_warns_about_dangerous_inherit_env() {
        let toml = "[sandbox]\ninherit_env = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.iter().any(|d| {
                d.level == DiagnosticLevel::Warning && d.message.contains("DANGEROUS")
            }),
            "should warn about dangerous: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_warns_about_dangerous_tmp_exec() {
        let toml = "[sandbox]\nallow_tmp_exec = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.iter().any(|d| {
                d.level == DiagnosticLevel::Warning && d.message.contains("DANGEROUS")
            })
        );
    }

    #[test]
    fn validate_no_warning_for_safe_settings() {
        let toml = "[sandbox]\nquiet = true\nscratch_dir = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.is_empty(),
            "safe settings should have no diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_detects_type_error() {
        let toml = "[proxy]\nport = \"not a number\"\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics
                .iter()
                .any(|d| { d.level == DiagnosticLevel::Error && d.message.contains("type error") }),
            "should catch type errors: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_detects_section_used_as_scalar() {
        let toml = "proxy = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.iter().any(|d| {
                d.level == DiagnosticLevel::Error && d.message.contains("must be a table")
            }),
            "should detect section as scalar: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_default_config_template() {
        let contents = default_config_contents();
        let diagnostics = validate_config(&contents);
        assert!(
            diagnostics.is_empty(),
            "default template should validate clean: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_multiple_unknown_keys_reported() {
        let toml = "[sandbox]\nquiet_mode = true\nfast = true\n";
        let diagnostics = validate_config(toml);
        let errors: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.level == DiagnosticLevel::Error)
            .collect();
        assert_eq!(
            errors.len(),
            2,
            "should report both unknown keys: {diagnostics:?}"
        );
    }

    #[test]
    fn edit_distance_identical() {
        assert_eq!(edit_distance("hello", "hello"), 0);
    }

    #[test]
    fn edit_distance_one_char_diff() {
        assert_eq!(edit_distance("inherit_env", "inherit_evn"), 2);
    }

    #[test]
    fn edit_distance_empty_strings() {
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("abc", ""), 3);
    }

    // ── from_str tests ────────────────────────────────────────

    #[test]
    fn config_parse_valid() {
        let config = Config::parse("[sandbox]\nquiet = true\n").unwrap();
        assert_eq!(config.sandbox.quiet, Some(true));
    }

    #[test]
    fn config_parse_invalid() {
        let result = Config::parse("[broken");
        assert!(result.is_err());
    }

    // ── set/get infrastructure tests ──────────────────────────

    #[test]
    fn lookup_key_valid_keys() {
        assert!(lookup_key("sandbox.quiet").is_ok());
        assert!(lookup_key("proxy.port").is_ok());
        assert!(lookup_key("allow.ports").is_ok());
        assert!(lookup_key("deny.paths").is_ok());
    }

    #[test]
    fn lookup_key_invalid_format() {
        assert!(lookup_key("nope").is_err());
        assert!(lookup_key("a.b.c").is_err());
        assert!(lookup_key("").is_err());
    }

    #[test]
    fn lookup_key_unknown_suggests() {
        let err = lookup_key("sandbox.queit").unwrap_err();
        assert!(err.contains("quiet"), "should suggest 'quiet': {err}");
    }

    #[test]
    fn lookup_key_unknown_section() {
        let err = lookup_key("bogus.key").unwrap_err();
        assert!(err.contains("unknown config key"), "{err}");
    }

    #[test]
    fn get_config_value_returns_default_when_no_file() {
        let info = lookup_key("sandbox.quiet").unwrap();
        let (val, from_file) = get_config_value(info, None);
        assert_eq!(val, "false");
        assert!(!from_file);
    }

    #[test]
    fn get_config_value_returns_file_value() {
        let info = lookup_key("sandbox.quiet").unwrap();
        let loaded = LoadedConfig {
            config: Config::parse("[sandbox]\nquiet = true\n").unwrap(),
            raw: "[sandbox]\nquiet = true\n".to_string(),
            path: std::path::PathBuf::from("/tmp/fake"),
        };
        let (val, from_file) = get_config_value(info, Some(&loaded));
        assert_eq!(val, "true");
        assert!(from_file);
    }

    #[test]
    fn get_config_value_returns_array_from_file() {
        let info = lookup_key("allow.ports").unwrap();
        let raw = "[allow]\nports = [8080, 9090]\n";
        let loaded = LoadedConfig {
            config: Config::parse(raw).unwrap(),
            raw: raw.to_string(),
            path: std::path::PathBuf::from("/tmp/fake"),
        };
        let (val, from_file) = get_config_value(info, Some(&loaded));
        assert!(from_file);
        assert!(val.contains("8080"));
        assert!(val.contains("9090"));
    }

    #[test]
    fn set_value_in_doc_creates_section_and_key() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        set_value_in_doc(&mut doc, info, "true").unwrap();
        let result = doc.to_string();
        assert!(result.contains("[sandbox]"));
        assert!(result.contains("quiet = true"));
    }

    #[test]
    fn set_value_in_doc_overwrites_existing() {
        let mut doc = "[sandbox]\nquiet = false\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        set_value_in_doc(&mut doc, info, "true").unwrap();
        let result = doc.to_string();
        assert!(result.contains("quiet = true"));
        assert!(!result.contains("quiet = false"));
    }

    #[test]
    fn set_value_in_doc_preserves_comments() {
        let input = "# Important security comment\n[sandbox]\n# This is quiet\nquiet = false\n";
        let mut doc = input.parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        set_value_in_doc(&mut doc, info, "true").unwrap();
        let result = doc.to_string();
        assert!(result.contains("Important security comment"));
        assert!(result.contains("quiet = true"));
    }

    #[test]
    fn set_value_in_doc_port_number() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("proxy.port").unwrap();
        set_value_in_doc(&mut doc, info, "9090").unwrap();
        let result = doc.to_string();
        assert!(result.contains("port = 9090"));
    }

    #[test]
    fn set_value_in_doc_string_value() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("proxy.log_file").unwrap();
        set_value_in_doc(&mut doc, info, "/tmp/proxy.log").unwrap();
        let result = doc.to_string();
        assert!(result.contains("log_file = \"/tmp/proxy.log\""));
    }

    #[test]
    fn set_value_in_doc_array_replacement() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("allow.ports").unwrap();
        set_value_in_doc(&mut doc, info, "8080,9090").unwrap();
        let result = doc.to_string();
        assert!(result.contains("8080"));
        assert!(result.contains("9090"));
    }

    #[test]
    fn set_value_rejects_invalid_bool() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        assert!(set_value_in_doc(&mut doc, info, "yes").is_err());
    }

    #[test]
    fn set_value_rejects_invalid_port() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("proxy.port").unwrap();
        assert!(set_value_in_doc(&mut doc, info, "99999").is_err());
        assert!(set_value_in_doc(&mut doc, info, "abc").is_err());
    }

    #[test]
    fn append_value_in_doc_new_array() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("allow.ports").unwrap();
        append_value_in_doc(&mut doc, info, "3000").unwrap();
        let result = doc.to_string();
        assert!(result.contains("3000"));
    }

    #[test]
    fn append_value_in_doc_existing_array() {
        let mut doc = "[allow]\nports = [8080]\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("allow.ports").unwrap();
        append_value_in_doc(&mut doc, info, "9090").unwrap();
        let result = doc.to_string();
        assert!(result.contains("8080"));
        assert!(result.contains("9090"));
    }

    #[test]
    fn append_rejects_non_array_key() {
        let info = lookup_key("sandbox.quiet").unwrap();
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        assert!(append_value_in_doc(&mut doc, info, "true").is_err());
    }

    #[test]
    fn unset_value_removes_key() {
        let mut doc = "[sandbox]\nquiet = true\nvalidate = true\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        unset_value_in_doc(&mut doc, info);
        let result = doc.to_string();
        assert!(!result.contains("quiet"));
        assert!(result.contains("validate = true"));
    }

    #[test]
    fn unset_value_noop_if_missing() {
        let mut doc = "[sandbox]\nvalidate = true\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        unset_value_in_doc(&mut doc, info);
        let result = doc.to_string();
        assert!(result.contains("validate = true"));
    }

    #[test]
    fn dangerous_keys_are_marked() {
        let inherit = lookup_key("sandbox.inherit_env").unwrap();
        assert!(inherit.dangerous);
        let tmp_exec = lookup_key("sandbox.allow_tmp_exec").unwrap();
        assert!(tmp_exec.dangerous);

        let quiet = lookup_key("sandbox.quiet").unwrap();
        assert!(!quiet.dangerous);
    }
}
