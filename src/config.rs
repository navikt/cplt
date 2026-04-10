//! User configuration loaded from `~/.config/cplt/config.toml`.
//!
//! The config file is optional — cplt works without it.
//! CLI flags always override config values for scalar fields.
//! For list fields (allow/deny paths), CLI and config values are merged (union).
//!
//! Override config location with `CPLT_CONFIG` env var.

use crate::sandbox::HardeningCategory;
use serde::Deserialize;
use std::path::PathBuf;

/// Default config directory relative to $HOME.
const CONFIG_DIR: &str = ".config/cplt";
const CONFIG_FILE: &str = "config.toml";

// Characters that would break SBPL profile string interpolation.
const SBPL_UNSAFE_CHARS: &[char] = &['"', ')', '(', ';', '\\', '\n', '\r', '\0'];

/// Top-level config file structure.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub allow: AllowConfig,
    pub deny: DenyConfig,
    pub sandbox: SandboxConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Enable the CONNECT proxy (default: false).
    pub enabled: Option<bool>,
    /// Proxy listen port (default: 18080).
    pub port: Option<u16>,
    /// Path to blocked domains file.
    pub blocked_domains: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
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

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DenyConfig {
    /// Additional paths to explicitly deny.
    pub paths: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
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
}

/// Resolved configuration after merging config file + CLI flags.
/// All paths are expanded and canonicalized.
#[derive(Debug)]
pub struct Resolved {
    pub with_proxy: bool,
    pub proxy_port: u16,
    pub blocked_domains: Option<PathBuf>,
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
}

impl Config {
    /// Load config from `~/.config/cplt/config.toml` (or CPLT_CONFIG).
    /// Returns `Config::default()` if the file doesn't exist.
    /// Returns an error if the file exists but is malformed or unreadable.
    pub fn load() -> Result<Self, String> {
        let Some(path) = config_path() else {
            return Ok(Config::default());
        };

        if !path.exists() {
            return Ok(Config::default());
        }

        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("Cannot read config file {}: {e}", path.display()))?;

        let config: Config = toml::from_str(&contents)
            .map_err(|e| format!("Invalid TOML in {}: {e}", path.display()))?;

        eprintln!("\x1b[0;34m[cplt]\x1b[0m Config:   {}", path.display());

        Ok(config)
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
    #[allow(clippy::too_many_arguments)]
    pub fn merge(
        &self,
        cli_with_proxy: bool,
        cli_no_proxy: bool,
        cli_proxy_port: Option<u16>,
        cli_blocked_domains: Option<PathBuf>,
        cli_allow_read: Vec<PathBuf>,
        cli_allow_write: Vec<PathBuf>,
        cli_deny_paths: Vec<PathBuf>,
        cli_allow_ports: Vec<u16>,
        cli_allow_localhost: Vec<u16>,
        cli_allow_localhost_any: bool,
        cli_allow_env_files: bool,
        cli_no_validate: bool,
        cli_pass_env: Vec<String>,
        cli_inherit_env: bool,
        cli_allow_lifecycle_scripts: bool,
    ) -> Result<Resolved, String> {
        // Proxy: --no-proxy always wins, then --with-proxy, then config, then false (default off).
        // The proxy is a passive logging tool — Copilot CLI doesn't use it (Node.js ignores
        // http_proxy env vars). It's useful for logging traffic from tools like `gh` or `curl`.
        let with_proxy = if cli_no_proxy {
            false
        } else if cli_with_proxy {
            true
        } else {
            self.proxy.enabled.unwrap_or(false)
        };

        // Port: CLI (if provided) > config > 18080
        let proxy_port = cli_proxy_port.or(self.proxy.port).unwrap_or(18080);

        // Blocked domains: CLI > config > exe_dir fallback (handled later in main)
        let blocked_domains = cli_blocked_domains
            .or_else(|| self.proxy.blocked_domains.as_ref().map(|s| expand_tilde(s)));

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
        allow_read.extend(cli_allow_read);

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
        allow_write.extend(cli_allow_write);

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
        deny_paths.extend(cli_deny_paths);

        // Validate: --no-validate wins, then config, then true (validate by default)
        let no_validate = if cli_no_validate {
            true
        } else {
            !self.sandbox.validate.unwrap_or(true)
        };

        // Allow-env-files: CLI flag wins, then config, then false (deny by default)
        let allow_env_files = if cli_allow_env_files {
            true
        } else {
            self.sandbox.allow_env_files.unwrap_or(false)
        };

        // Allow-ports: merge config + CLI
        let mut allow_ports = self.allow.ports.clone();
        allow_ports.extend(cli_allow_ports);
        allow_ports.sort_unstable();
        allow_ports.dedup();

        // Allow-localhost: merge config + CLI
        let mut allow_localhost = self.allow.localhost.clone();
        allow_localhost.extend(cli_allow_localhost);
        allow_localhost.sort_unstable();
        allow_localhost.dedup();

        // Allow-localhost-any: CLI flag wins, then config, then false
        let allow_localhost_any = if cli_allow_localhost_any {
            true
        } else {
            self.sandbox.allow_localhost_any.unwrap_or(false)
        };

        // Pass-env: merge config + CLI
        let mut pass_env = self.sandbox.pass_env.clone();
        pass_env.extend(cli_pass_env);
        pass_env.sort_unstable();
        pass_env.dedup();

        // Inherit-env: CLI flag wins, then config, then false (secure by default)
        let inherit_env = if cli_inherit_env {
            true
        } else {
            self.sandbox.inherit_env.unwrap_or(false)
        };

        // Allow-lifecycle-scripts: CLI flag wins, then config, then false (blocked by default)
        let allow_lifecycle_scripts = if cli_allow_lifecycle_scripts {
            true
        } else {
            self.sandbox.allow_lifecycle_scripts.unwrap_or(false)
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
# Optional CONNECT proxy that logs outbound HTTPS connections.
# Disabled by default — Copilot CLI connects directly to its APIs
# and does not use http_proxy/https_proxy env vars.
# Enable with --with-proxy for connection visibility and domain blocking.
# The proxy is a passive logging tool, not a security boundary.
[proxy]
# enabled = false
# port = 18080
# blocked_domains = "~/.config/cplt/blocked-domains.txt"

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

/// Validate that a path doesn't contain characters that could break SBPL string interpolation.
fn validate_sbpl_path(path: &std::path::Path) -> Result<(), String> {
    let s = path.to_string_lossy();
    for c in SBPL_UNSAFE_CHARS {
        if s.contains(*c) {
            return Err(format!(
                "Path contains unsafe character '{c}' for sandbox profile: {s}\n\
                 This could be used for SBPL injection. Remove or rename the path."
            ));
        }
    }
    Ok(())
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
            .merge(
                true,
                false,
                None,
                None,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
                false,
                false,
                vec![],
                false,
                false,
            )
            .unwrap();
        assert!(resolved.with_proxy);
    }

    #[test]
    fn no_proxy_flag_overrides_config_enabled() {
        let config: Config = toml::from_str("[proxy]\nenabled = true\n").unwrap();
        let resolved = config
            .merge(
                false,
                true,
                None,
                None,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
                false,
                false,
                vec![],
                false,
                false,
            )
            .unwrap();
        assert!(!resolved.with_proxy);
    }

    #[test]
    fn config_proxy_used_when_no_cli_flag() {
        let config: Config = toml::from_str("[proxy]\nenabled = true\n").unwrap();
        let resolved = config
            .merge(
                false,
                false,
                None,
                None,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
                false,
                false,
                vec![],
                false,
                false,
            )
            .unwrap();
        assert!(resolved.with_proxy);
    }

    #[test]
    fn cli_port_overrides_config() {
        let config: Config = toml::from_str("[proxy]\nport = 9090\n").unwrap();
        let resolved = config
            .merge(
                false,
                false,
                Some(12345),
                None,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
                false,
                false,
                vec![],
                false,
                false,
            )
            .unwrap();
        assert_eq!(resolved.proxy_port, 12345);
    }

    #[test]
    fn config_port_used_when_cli_none() {
        let config: Config = toml::from_str("[proxy]\nport = 9090\n").unwrap();
        let resolved = config
            .merge(
                false,
                false,
                None,
                None,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
                false,
                false,
                vec![],
                false,
                false,
            )
            .unwrap();
        assert_eq!(resolved.proxy_port, 9090);
    }

    #[test]
    fn default_port_when_neither_set() {
        let config = Config::default();
        let resolved = config
            .merge(
                false,
                false,
                None,
                None,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
                false,
                false,
                vec![],
                false,
                false,
            )
            .unwrap();
        assert_eq!(resolved.proxy_port, 18080);
    }

    #[test]
    fn cli_no_validate_overrides_config() {
        let config: Config = toml::from_str("[sandbox]\nvalidate = true\n").unwrap();
        let resolved = config
            .merge(
                false,
                false,
                None,
                None,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
                false,
                true,
                vec![],
                false,
                false,
            )
            .unwrap();
        assert!(resolved.no_validate);
    }

    #[test]
    fn config_validate_false_sets_no_validate() {
        let config: Config = toml::from_str("[sandbox]\nvalidate = false\n").unwrap();
        let resolved = config
            .merge(
                false,
                false,
                None,
                None,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
                false,
                false,
                vec![],
                false,
                false,
            )
            .unwrap();
        assert!(resolved.no_validate);
    }

    #[test]
    fn deny_paths_merged_from_config_and_cli() {
        // Use /tmp which always exists and can be canonicalized
        let config: Config = toml::from_str("[deny]\npaths = [\"/tmp\"]\n").unwrap();
        let cli_deny = vec![PathBuf::from("/var")];
        let resolved = config
            .merge(
                false,
                false,
                None,
                None,
                vec![],
                vec![],
                cli_deny,
                vec![],
                vec![],
                false,
                false,
                false,
                vec![],
                false,
                false,
            )
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
        let result = config.merge(
            false,
            false,
            None,
            None,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            false,
            false,
            false,
            vec![],
            false,
            false,
        );
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
        let resolved = config
            .merge(
                false,
                false,
                None,
                None,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
                false,
                false,
                vec![],
                false,
                false,
            )
            .unwrap();
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
            .merge(
                false,
                false,
                None,
                None,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
                true,
                false,
                vec![],
                false,
                false,
            )
            .unwrap();
        assert!(resolved.allow_env_files);
    }

    #[test]
    fn config_allow_env_files_used_when_cli_false() {
        let config: Config = toml::from_str("[sandbox]\nallow_env_files = true\n").unwrap();
        let resolved = config
            .merge(
                false,
                false,
                None,
                None,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
                false,
                false,
                vec![],
                false,
                false,
            )
            .unwrap();
        assert!(resolved.allow_env_files);
    }

    #[test]
    fn env_files_denied_by_default() {
        let config = Config::default();
        let resolved = config
            .merge(
                false,
                false,
                None,
                None,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
                false,
                false,
                vec![],
                false,
                false,
            )
            .unwrap();
        assert!(!resolved.allow_env_files);
    }
}
