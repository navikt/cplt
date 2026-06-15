//! Config file path resolution.

use std::path::PathBuf;

use super::error::ConfigError;
use super::types::{CONFIG_DIR, CONFIG_FILE};

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

/// Return the cplt config directory path (`~/.config/cplt/`).
pub fn config_dir() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("CPLT_CONFIG") {
        // If custom config path is set, use its parent directory
        return expand_tilde(&custom)
            .parent()
            .map(std::path::Path::to_path_buf);
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(CONFIG_DIR))
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
# CONNECT proxy that logs and filters outbound HTTPS connections.
# Enabled by default. HTTP_PROXY/HTTPS_PROXY and NODE_USE_ENV_PROXY=1 are
# injected so all traffic (Copilot, gh, curl) routes through the proxy.
# The proxy enforces the same port policy as the sandbox (443 + allow-port).
# Disable with --no-proxy or set enabled = false below.
[proxy]
# enabled = true
# port = 0  # 0 = OS-assigned ephemeral port (avoids conflicts, default)
# blocked_domains = "~/.config/cplt/blocked-domains.txt"
# allowed_domains = "~/.config/cplt/allowed-domains.txt"
# log_file = "~/.config/cplt/proxy.log"
# Stderr verbosity: "none" (default/silent), "error", "blocked", or "all".
# The log_file always records everything regardless of this setting.
# log_level = "none"
# Domains allowed to resolve to private/internal IPs (bypasses DNS-rebinding block).
# Use for corporate internal services, e.g. MCP servers on your company's intranet.
# Suffix matching: "intern.nav.no" covers all its subdomains.
# allow_private_domains = ["intern.nav.no"]

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
# Preferred AI coding agent. Auto-detected from PATH if not set.
# Supported: copilot, opencode, gemini, antigravity, pi, claude, shell
# agent = "copilot"
#
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
# DANGEROUS: Allow GPG commit/tag signing inside the sandbox.
# Exposes the GPG agent socket so gpg can request signatures.
# Private keys remain protected — only the public keyring and agent
# socket are accessible. A compromised process cannot extract the key,
# but it CAN request arbitrary signatures while the session is active.
# allow_gpg_signing = false
#
# Allow JVM Attach API unix sockets in /tmp.
# Needed for JVM testing frameworks that use runtime self-attach:
# MockK inline mocking, Mockito inline agents, ByteBuddy, JMX tools.
# Only allows sockets matching /tmp/.java_pid<PID> — SSH agent and
# all other unix sockets in /tmp remain blocked.
# Enable this if you work with Kotlin/Java projects that use inline mocking.
# allow_jvm_attach = false
#
# DANGEROUS: Allow Docker/Colima/OrbStack access inside the sandbox.
# Exposes ~/.docker config (read-only) and Docker daemon unix sockets.
# WARNING: Docker container volumes can mount any host path, completely
# bypassing sandbox filesystem restrictions. Only enable if you trust
# the agent's container usage.
# allow_docker = false
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
# Enable per-session scratch directory for TMPDIR redirect (default: true).
# Creates ~/.cache/cplt/tmp/{session}/ (Linux) or
# ~/Library/Caches/cplt/tmp/{session}/ (macOS) with write+exec permissions
# so tools like `go test`, `mise` inline tasks, and `node-gyp` can work.
# Cleaned up automatically on exit.
# scratch_dir = true
#
# DANGEROUS: Allow process execution from system temp directories.
# Re-enables exec from /tmp (Linux) or /private/tmp, /private/var/folders (macOS).
# Prefer scratch_dir which creates a controlled executable temp dir.
# allow_tmp_exec = false
#
# Allow process execution from specific ~/Library/Caches subdirectories.
# By default, exec is blocked from ~/Library/Caches to prevent binary-drop
# staging attacks. Use this to unblock specific tools that store and run
# executables there, such as Playwright browsers or pnpm dlx cached packages.
# Example: allow_cache_exec = ["ms-playwright"]
# allow_cache_exec = []
#
# DANGEROUS: Allow process execution from ALL ~/Library/Caches subdirectories.
# Much broader than allow_cache_exec — prefer specifying exact subdirs.
# allow_cache_exec_any = false
#
# Allow the agent to open URLs in your default browser.
# Needed for OAuth code flows (MCP servers, Gemini CLI, gh auth login).
# Disabled by default because it lets the agent leverage your browser session.
# allow_browser = false
#
# Suppress the startup configuration summary and non-essential messages.
# Errors and warnings are always shown. Useful once you've reviewed the
# sandbox settings and don't need to see them every time.
# Override with --no-quiet for a single run.
# quiet = false

# ── gh CLI proxy ────────────────────────────────────────────────────────────
# Intercepts `gh` commands and enforces a command-level policy.
# [gh_guard]
# enabled = false             # enable the proxy (blocks destructive GitHub operations)
# mode = "block"              # "block" | "warn" | "audit"
# scope_check = true          # enforce same-repo check on write commands
# block_auth_token = true     # deny 'gh auth token' exfiltration
# inject_token = false        # pre-inject GH_TOKEN into sandbox (opt-in)
# unknown_command = "block"   # policy for commands not in classification table
# allow_api_write = false     # allow gh api POST/PATCH/PUT to current repo (opt-in)

# ── git guard ───────────────────────────────────────────────────────────────
# Intercepts `git` commands to prevent accidental pushes.
# [git_guard]
# enabled = false             # enable git command interception
# mode = "block"              # "block" | "warn" | "audit"
# prevent_push = true         # block push, request-pull, send-pack
# prevent_force_push = true   # block force push (only when prevent_push = false)
# [[git_guard.allow_push]]   # structured push exceptions
# remote = "fork"
# branches = ["agent/*"]
# force = false

# ── audit logging ───────────────────────────────────────────────────────────
# Global audit log for all sandbox gate decisions.
# [audit]
# enabled = false
# destination = "stderr"      # "stderr" or file path
# level = "blocked"           # "blocked" | "decisions" | "all"
# format = "text"             # "text" | "jsonl"
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

/// Replace the user's home directory prefix with `~` for portable storage.
/// Only collapses exact `$HOME` or `$HOME/...` boundaries (component-aware).
/// Returns the original string unchanged if it doesn't start with `$HOME`.
pub fn collapse_tilde(path: &str) -> String {
    let Ok(home) = std::env::var("HOME") else {
        return path.to_string();
    };
    let home_path = std::path::Path::new(&home);
    let input_path = std::path::Path::new(path);
    if let Ok(rest) = input_path.strip_prefix(home_path) {
        if rest.as_os_str().is_empty() {
            "~".to_string()
        } else {
            format!("~/{}", rest.display())
        }
    } else {
        path.to_string()
    }
}

/// Expand tilde, resolve relative paths against config dir, and canonicalize.
pub(super) fn resolve_config_path(
    path: &str,
    config_dir: Option<&PathBuf>,
) -> Result<PathBuf, ConfigError> {
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

    std::fs::canonicalize(&full).map_err(|_| {
        ConfigError::Validation(format!(
            "path does not exist or is inaccessible: {}",
            full.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn default_config_contents_is_valid_toml() {
        use crate::config::Config;
        let contents = default_config_contents();
        let config: Config = toml::from_str(&contents).unwrap();
        assert!(config.proxy.enabled.is_none());
    }

    #[test]
    fn collapse_tilde_home_subpath() {
        let home = std::env::var("HOME").unwrap();
        let input = format!("{home}/.config/gcloud/creds.json");
        assert_eq!(collapse_tilde(&input), "~/.config/gcloud/creds.json");
    }

    #[test]
    fn collapse_tilde_exact_home() {
        let home = std::env::var("HOME").unwrap();
        assert_eq!(collapse_tilde(&home), "~");
    }

    #[test]
    fn collapse_tilde_non_home_path() {
        assert_eq!(collapse_tilde("/tmp/foo"), "/tmp/foo");
    }

    #[test]
    fn collapse_tilde_similar_prefix_not_collapsed() {
        // e.g. HOME=/Users/hans but path is /Users/hans2/foo — must NOT collapse
        let home = std::env::var("HOME").unwrap();
        let similar = format!("{home}2/foo");
        assert_eq!(collapse_tilde(&similar), similar);
    }

    #[test]
    fn collapse_tilde_already_tilde() {
        assert_eq!(collapse_tilde("~/.ssh/config"), "~/.ssh/config");
    }

    #[test]
    fn collapse_tilde_roundtrip_with_expand() {
        let home = std::env::var("HOME").unwrap();
        let original = "~/.config/test";
        let expanded = expand_tilde(original);
        assert_eq!(expanded, PathBuf::from(format!("{home}/.config/test")));
        let collapsed = collapse_tilde(expanded.to_str().unwrap());
        assert_eq!(collapsed, original);
    }
}
