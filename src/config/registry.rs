//! Config key metadata registry (names, types, docs).

use super::error::ConfigError;
use super::validation::suggest_key;

// ── Config key registry (for get/set) ────────────────────────────────

/// The type of a config value, used for parsing and display.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum ConfigValueType {
    Bool,
    U16,
    U64,
    Str,
    U16Array,
    StrArray,
    /// Array of TOML tables (e.g. `[[git_guard.allow_push]]`).
    ArrayOfTables,
}

impl ConfigValueType {
    pub fn is_array(self) -> bool {
        matches!(self, Self::U16Array | Self::StrArray | Self::ArrayOfTables)
    }
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
pub(super) const CONFIG_KEYS: &[ConfigKeyInfo] = &[
    // [proxy]
    ConfigKeyInfo {
        section: "proxy",
        key: "enabled",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "true",
        description: "Enable the CONNECT proxy for outbound HTTPS traffic logging and domain filtering.",
    },
    ConfigKeyInfo {
        section: "proxy",
        key: "forced",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Force all egress through the proxy: make the proxy mandatory and restrict kernel-level egress to the proxy port only (no direct *:443). Fails closed if the proxy cannot start.",
    },
    ConfigKeyInfo {
        section: "proxy",
        key: "port",
        value_type: ConfigValueType::U16,
        dangerous: false,
        default_display: "0",
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
        key: "default_allowlist",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Fail-closed networking (opt-in): restrict egress to the agent's built-in default allowlist (e.g. GitHub Copilot infrastructure + package registries) merged with allowed_domains; block all other domains. Override for one run with --allow-all-domains.",
    },
    ConfigKeyInfo {
        section: "proxy",
        key: "log_file",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "",
        description: "Path to write proxy connection logs (CONNECT requests and outcomes).",
    },
    ConfigKeyInfo {
        section: "proxy",
        key: "log_level",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "none",
        description: "Stderr verbosity for proxy events: \"none\" (silent), \"error\" (DNS/connect failures), \"blocked\" (errors + blocked connections), \"all\" (everything including CONNECTED).",
    },
    ConfigKeyInfo {
        section: "proxy",
        key: "timeout",
        value_type: ConfigValueType::U64,
        dangerous: false,
        default_display: "60",
        description: "Timeout in seconds for proxy request/header reads. Established tunnels may idle up to 1h.",
    },
    ConfigKeyInfo {
        section: "proxy",
        key: "upstream",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "",
        description: "Upstream (corporate) proxy URL to forward CONNECT tunnels through, e.g. \"http://corporate-proxy.example.com:8080\". cplt still enforces all domain filtering, logging, and port checks before forwarding. Optional basic-auth userinfo is supported; only the http scheme is supported.",
    },
    ConfigKeyInfo {
        section: "proxy",
        key: "upstream_no_proxy",
        value_type: ConfigValueType::StrArray,
        dangerous: false,
        default_display: "[]",
        description: "Hosts that BYPASS the upstream proxy and are connected to directly (like NO_PROXY). Only meaningful with proxy.upstream. Suffix matching: \"example.com\" covers all subdomains; CIDR/IP ranges are NOT honored. Merged additively with the ambient NO_PROXY/no_proxy environment. All of cplt's domain/port/SSRF filtering still applies — so an internal host that resolves to a private IP is BLOCKED (403) unless you ALSO add it to proxy.allow_private_domains.",
    },
    ConfigKeyInfo {
        section: "proxy",
        key: "allow_private_domains",
        value_type: ConfigValueType::StrArray,
        dangerous: false,
        default_display: "[]",
        description: "Domains allowed to resolve to private/internal IPs (opt-in DNS-rebinding bypass). Use for corporate intranet services. Suffix matching: \"intern.nav.no\" covers all subdomains.",
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
        key: "socket",
        value_type: ConfigValueType::StrArray,
        dangerous: false,
        default_display: "[]",
        description: "Unix socket paths to allow access to.",
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
    ConfigKeyInfo {
        section: "deny",
        key: "env",
        value_type: ConfigValueType::StrArray,
        dangerous: false,
        default_display: "[]",
        description: "Environment variables to strip from the sandbox (repo-local only: tightens env filtering).",
    },
    // [sandbox]
    ConfigKeyInfo {
        section: "sandbox",
        key: "agent",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "",
        description: "Preferred AI coding agent (copilot, opencode, gemini, antigravity, pi, claude, shell). Auto-detected from PATH if not set.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "preset",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "standard",
        description: "Security posture baseline: \"strict\" (all toggles off AND gh_guard + git_guard + proxy.forced ON — locked down), \"standard\" (default, no-op), \"permissive\", or \"full-trust\". Only strict enables the guards/forced proxy; the others leave them at default. Individual keys/flags override it.",
    },
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
        dangerous: true,
        default_display: "false",
        description: "Allow npm/yarn/pnpm lifecycle scripts (postinstall, prepare, etc.) to run.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "allow_gpg_signing",
        value_type: ConfigValueType::Bool,
        dangerous: true,
        default_display: "false",
        description: "⚠️  DANGEROUS: Allow GPG commit/tag signing. Exposes the GPG agent socket for signature requests. Private keys stay protected.",
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
        default_display: "true",
        description: "Create a per-session scratch directory and redirect TMPDIR into it.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "audit",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "true",
        description: "Print the post-session project-change audit report (net file changes vs a pinned baseline commit). Suppressed by quiet.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "use_bubblewrap",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "auto-detect",
        description: "Linux only: wrap the sandbox in Bubblewrap namespaces (PID/IPC/UTS/cgroup/user + private /tmp) for defense-in-depth. Unset = auto-detect with fallback to Landlock-only.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "quiet",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Hide the startup configuration summary (sandbox rules, network, env info).",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "yes",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Skip the confirmation prompt at startup (equivalent to --yes).",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "allow_jvm_attach",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Allow JVM Attach API unix sockets for ByteBuddy/MockK/Mockito inline mocking.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "allow_msbuild",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Allow MSBuild worker-node unix sockets for `dotnet build` (not the persistent MSBuild Server).",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "gradle_init",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Install a cplt-managed Gradle init script in the Gradle user home ($GRADLE_USER_HOME/init.d/ or ~/.gradle/init.d/cplt-sandbox.gradle) that applies the preferIPv4Stack workaround inside the sandbox. Inert outside sandbox builds.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "allow_docker",
        value_type: ConfigValueType::Bool,
        dangerous: true,
        default_display: "false",
        description: "⚠️  DANGEROUS: Allow Docker/Colima/OrbStack access. Exposes daemon socket and ~/.docker config. Container mounts bypass sandbox.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "allow_cache_exec",
        value_type: ConfigValueType::StrArray,
        dangerous: false,
        default_display: "[]",
        description: "~/Library/Caches subdirs to allow exec from (e.g. [\"ms-playwright\"] for Playwright browsers).",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "allow_cache_exec_any",
        value_type: ConfigValueType::Bool,
        dangerous: true,
        default_display: "false",
        description: "⚠️  DANGEROUS: Allow exec from ALL ~/Library/Caches subdirs. Prefer allow_cache_exec with specific subdirs.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "allow_browser",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Allow the agent to open URLs in your default browser (needed for OAuth code flows).",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "gh_proxy",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "DEPRECATED: use [gh_guard] section instead. Enables gh CLI proxy.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "git_push_prevention",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "DEPRECATED: use [git_guard] section instead. Enables git push prevention.",
    },
    // [gh_guard]
    ConfigKeyInfo {
        section: "gh_guard",
        key: "enabled",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Enable gh CLI proxy that blocks destructive GitHub operations (delete repo, merge PR, etc.).",
    },
    ConfigKeyInfo {
        section: "gh_guard",
        key: "mode",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "block",
        description: "Enforcement mode: \"block\" (deny and exit), \"warn\" (print warning, allow), or \"audit\" (silent log).",
    },
    ConfigKeyInfo {
        section: "gh_guard",
        key: "scope_check",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "true",
        description: "Enforce same-repo check — blocks operations targeting other repositories via -R flag.",
    },
    ConfigKeyInfo {
        section: "gh_guard",
        key: "block_auth_token",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "true",
        description: "Block 'gh auth token' command to prevent credential exfiltration.",
    },
    ConfigKeyInfo {
        section: "gh_guard",
        key: "inject_token",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Pre-extract GH_TOKEN before sandbox launch (only for Copilot agent).",
    },
    ConfigKeyInfo {
        section: "gh_guard",
        key: "unknown_command",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "block",
        description: "Policy for commands not in the classification table: \"block\" (default-deny) or \"allow\" (permissive).",
    },
    ConfigKeyInfo {
        section: "gh_guard",
        key: "allow_api_write",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Allow 'gh api' write operations (POST/PATCH/PUT and input flags). Writes are scope-checked to the current repo. GraphQL is always blocked.",
    },
    // [git_guard]
    ConfigKeyInfo {
        section: "git_guard",
        key: "enabled",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Enable git command interception (blocks git push, request-pull, send-pack).",
    },
    ConfigKeyInfo {
        section: "git_guard",
        key: "mode",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "block",
        description: "Enforcement mode: \"block\" (deny and exit), \"warn\" (print warning, allow), or \"audit\" (silent log).",
    },
    ConfigKeyInfo {
        section: "git_guard",
        key: "prevent_push",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "true",
        description: "Block git push, request-pull, and send-pack.",
    },
    ConfigKeyInfo {
        section: "git_guard",
        key: "prevent_force_push",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "true",
        description: "Block force push (only meaningful when prevent_push is false).",
    },
    ConfigKeyInfo {
        section: "git_guard",
        key: "protect_default_branch_only",
        value_type: ConfigValueType::Bool,
        dangerous: true,
        default_display: "false",
        description: "Only block pushes to default branch (main/master). Allows feature branch pushes.",
    },
    ConfigKeyInfo {
        section: "git_guard",
        key: "allow_push",
        value_type: ConfigValueType::ArrayOfTables,
        dangerous: true,
        default_display: "[]",
        description: "Structured push exceptions. Each entry specifies remote/branches/force conditions under which push is allowed.",
    },
    // [audit]
    ConfigKeyInfo {
        section: "audit",
        key: "enabled",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "Enable audit logging for all sandbox gate decisions.",
    },
    ConfigKeyInfo {
        section: "audit",
        key: "destination",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "stderr",
        description: "Where to write audit entries: \"stderr\" or a file path.",
    },
    ConfigKeyInfo {
        section: "audit",
        key: "level",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "blocked",
        description: "What to log: \"blocked\" (only blocked), \"decisions\" (all gate decisions), or \"all\" (including passthrough).",
    },
    ConfigKeyInfo {
        section: "audit",
        key: "format",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "text",
        description: "Output format: \"text\" (human-readable) or \"jsonl\" (machine-parseable).",
    },
];

/// Returns all registered config keys. Used by tests to ensure every key is
/// covered by `config show` output and other config commands.
pub fn all_config_keys() -> &'static [ConfigKeyInfo] {
    CONFIG_KEYS
}

/// Look up a config key by "section.key" dotted notation.
pub fn lookup_key(dotted: &str) -> Result<&'static ConfigKeyInfo, ConfigError> {
    let (section, key) = dotted.split_once('.').ok_or_else(|| {
        ConfigError::Validation(format!(
            "invalid key format '{dotted}': expected section.key (e.g., sandbox.quiet)"
        ))
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
            let all_refs: Vec<&str> = all_dotted.iter().map(std::string::String::as_str).collect();
            let suggestion = suggest_key(dotted, &all_refs);
            let hint = suggestion
                .map(|s| format!("\n  Did you mean '{s}'?"))
                .unwrap_or_default();
            ConfigError::Validation(format!(
                "unknown config key '{dotted}'{hint}\n  Valid keys: {}",
                all_dotted.join(", ")
            ))
        })
}

pub(super) fn type_label(vt: ConfigValueType) -> &'static str {
    match vt {
        ConfigValueType::Bool => "bool",
        ConfigValueType::U16 => "integer (1-65535)",
        ConfigValueType::U64 => "integer",
        ConfigValueType::Str => "string",
        ConfigValueType::U16Array => "integer array",
        ConfigValueType::StrArray => "string array",
        ConfigValueType::ArrayOfTables => "array of tables",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_key_valid_keys() {
        assert!(lookup_key("sandbox.quiet").is_ok());
        assert!(lookup_key("sandbox.allow_jvm_attach").is_ok());
        assert!(lookup_key("sandbox.allow_msbuild").is_ok());
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
        assert!(
            err.to_string().contains("quiet"),
            "should suggest 'quiet': {err}"
        );
    }

    #[test]
    fn lookup_key_unknown_section() {
        let err = lookup_key("bogus.key").unwrap_err();
        assert!(err.to_string().contains("unknown config key"), "{err}");
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
