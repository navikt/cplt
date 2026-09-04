//! Config key metadata registry (names, types, docs).

use super::error::ConfigError;
use super::types::{CliFlags, Config, FeatureToggle, PresetBaseline, Resolved};
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
        description: "Hosts that BYPASS the upstream proxy and are connected to directly (like NO_PROXY). Only meaningful with proxy.upstream. Suffix matching: \"example.com\" covers all subdomains; CIDR/IP ranges are NOT honored. Merged additively with the ambient NO_PROXY/no_proxy environment. All of cplt's domain/port/SSRF filtering still applies, so an internal host that resolves to a private IP is BLOCKED (403) unless you ALSO add it to proxy.allow_private_domains.",
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
        description: "Extra directories to allow write access (use sparingly, the project dir is already writable).",
    },
    ConfigKeyInfo {
        section: "allow",
        key: "exec",
        value_type: ConfigValueType::StrArray,
        dangerous: true,
        default_display: "[]",
        description: "\u{26a0}\u{fe0f}  DANGEROUS: Trees the agent may execute binaries from (e.g. a relocated Homebrew prefix). Read + execute, never write. Refused for an unsafe root (/, /tmp, $HOME and its parents, the platform system dirs) and for any tree that overlaps a writable one \u{2014} writable + executable is a binary-drop path.",
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
        description: "Preferred AI coding agent (copilot, opencode, gemini, antigravity, pi, claude, goose, shell). Auto-detected from PATH if not set.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "preset",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "standard",
        description: "Security posture baseline: \"strict\" (all toggles off AND gh_guard + git_guard + proxy.forced ON, fully locked down), \"standard\" (default, no-op), \"permissive\", or \"full-trust\". Only strict enables the guards/forced proxy; the others leave them at default. Individual keys/flags override it.",
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
        key: "brief",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "EXPERIMENTAL: Write the per-session agent-facing sandbox brief (CPLT_BRIEF.md) to the scratch dir. Unstable — may change or be removed in a future release.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "agents_md",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "EXPERIMENTAL: Also inject the managed cplt sandbox block into the project's AGENTS.md on launch (writes into the repo). Requires sandbox.brief. Unstable — may change or be removed in a future release.",
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
        key: "deny_clipboard",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "true",
        description: "Deny the macOS clipboard (com.apple.pasteboard) to the agent, so `pbpaste` cannot read whatever was last copied. Override for one run with --allow-clipboard. No effect on Linux.",
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
        dangerous: true,
        default_display: "false",
        description: "⚠️  DANGEROUS: Launch Services grant for OAuth code flows. Lets the agent launch ANY application outside the sandbox, via launchd. Cannot be scoped.",
    },
    ConfigKeyInfo {
        section: "sandbox",
        key: "keychain_substitute",
        value_type: ConfigValueType::Bool,
        dangerous: false,
        default_display: "false",
        description: "EXPERIMENTAL: drop the macOS Keychain grant when the agent has a credential it can reach without it.",
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
        default_display: "true",
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
        description: "Enforce same-repo check. Blocks operations targeting other repositories via the -R flag.",
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
        default_display: "true",
        description: "Enable git command interception (blocks git push, request-pull, send-pack).",
    },
    ConfigKeyInfo {
        section: "git_guard",
        key: "mode",
        value_type: ConfigValueType::Str,
        dangerous: false,
        default_display: "warn",
        description: "Enforcement mode: \"warn\" (default: print warning, allow), \"block\" (deny and exit; the default under --preset strict), or \"audit\" (silent log).",
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

// ── Boolean precedence, driven by the key registry ───────────────────

/// The one precedence rule for every boolean setting in cplt:
///
/// > explicit CLI flag > config file value > preset baseline > hardcoded default
///
/// Every boolean key resolves through this function and nowhere else. Writing
/// the ladder once is the point: the failure mode it removes is a hand-written
/// chain that silently drops a layer (typically the preset baseline), which in
/// a sandbox means a restriction the user asked for quietly not applying.
///
/// Keys with no preset baseline pass their hardcoded default as `baseline` —
/// the bottom layer is always supplied, never omitted.
fn resolve_bool(cli: FeatureToggle, config: Option<bool>, baseline: bool) -> bool {
    cli.to_option().or(config).unwrap_or(baseline)
}

/// A registry row for a boolean config key: which key it is, and how to read
/// its final value back off a [`Resolved`].
///
/// `resolved` exists so a consumer reporting the *effective* value reads it
/// from this table instead of keeping its own parallel list of keys — a list
/// that drifts, silently, behind a catch-all arm. `cplt settings` is the only
/// such consumer today; `config show` renders the config file, not the
/// resolved result, so it has no use for this.
pub struct BoolKeyRow {
    pub section: &'static str,
    pub key: &'static str,
    pub resolved: fn(&Resolved) -> bool,
}

/// Look up the boolean registry row for a config key, if it has one.
pub fn bool_key(section: &str, key: &str) -> Option<&'static BoolKeyRow> {
    BOOL_KEYS
        .iter()
        .find(|row| row.section == section && row.key == key)
}

macro_rules! bool_keys {
    ($(
        $(#[$meta:meta])*
        $field:ident, $section:literal, $key:literal,
            cli = $cli:expr,
            config = $config:expr,
            baseline = $baseline:expr,
            resolved = $resolved:expr;
    )*) => {
        /// Every boolean setting after the precedence ladder has been applied.
        ///
        /// Built once per run by [`ResolvedBools::resolve`]; `Config::merge`
        /// copies the fields into [`Resolved`]. Nothing here is resolved by
        /// hand.
        #[derive(Debug, Clone, Copy)]
        pub struct ResolvedBools {
            $( $(#[$meta])* pub $field: bool, )*
        }

        /// Registry rows for every boolean key, in declaration order.
        pub static BOOL_KEYS: &[BoolKeyRow] = &[
            $( BoolKeyRow {
                section: $section,
                key: $key,
                resolved: $resolved,
            }, )*
        ];

        impl ResolvedBools {
            /// Resolve every boolean key through [`resolve_bool`].
            pub(super) fn resolve(
                cli: &CliFlags,
                config: &Config,
                baseline: PresetBaseline,
            ) -> Self {
                Self {
                    $( $field: resolve_bool(
                        ($cli)(cli),
                        ($config)(config),
                        ($baseline)(baseline),
                    ), )*
                }
            }
        }
    };
}

// Columns: struct field, config section, config key, then the three layers and
// the read-back accessor.
//
// `cli` projects the CLI layer onto a `FeatureToggle`. A key with a proper
// `--x`/`--no-x` pair carries one directly. A ONE-WAY flag — one that can only
// push the value in one direction, because the opposite flag does not exist —
// is written with a literal `false` on the side it lacks, and its row says so
// in a `one-way` doc comment. That is the point of the column: one-way-ness
// used to be implied by the shape of an `if cli.x { true } else { .. }` in
// `merge` and stated nowhere. The set of one-way keys is pinned by
// `precedence::one_way_cli_flags_are_declared_as_such`, so growing or losing
// one is a test failure, not a silent change. A config-only key passes
// `UseDefault`.
//
// `baseline` is `|b| b.<field>` for the nine preset-controlled keys and a
// literal for the rest. It is a required column: a key cannot be declared
// without stating its bottom layer.
bool_keys! {
    with_proxy, "proxy", "enabled",
        cli = |c: &CliFlags| c.proxy,
        config = |c: &Config| c.proxy.enabled,
        baseline = |_: PresetBaseline| true,
        resolved = |r: &Resolved| r.with_proxy;

    proxy_forced, "proxy", "forced",
        cli = |c: &CliFlags| c.proxy_forced,
        config = |c: &Config| c.proxy.forced,
        baseline = |b: PresetBaseline| b.proxy_forced,
        resolved = |r: &Resolved| r.proxy_forced;

    default_allowlist, "proxy", "default_allowlist",
        cli = |c: &CliFlags| c.default_allowlist,
        config = |c: &Config| c.proxy.default_allowlist,
        baseline = |b: PresetBaseline| b.default_allowlist,
        resolved = |r: &Resolved| r.default_allowlist;

    /// `sandbox.validate`, stored inverted on `Resolved` as `no_validate`.
    /// One-way in the OFF direction: `--no-validate` only, no `--validate`.
    validate, "sandbox", "validate",
        cli = |c: &CliFlags| FeatureToggle::from_pair(false, c.no_validate),
        config = |c: &Config| c.sandbox.validate,
        baseline = |_: PresetBaseline| true,
        resolved = |r: &Resolved| !r.no_validate;

    brief, "sandbox", "brief",
        cli = |c: &CliFlags| c.brief,
        config = |c: &Config| c.sandbox.brief,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.brief;

    /// Raw value only. `Config::merge` additionally gates the AGENTS.md block
    /// on `brief`, so `Resolved::agents_md` can be false while this is true.
    agents_md, "sandbox", "agents_md",
        cli = |c: &CliFlags| c.agents_md,
        config = |c: &Config| c.sandbox.agents_md,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.agents_md;

    allow_env_files, "sandbox", "allow_env_files",
        cli = |c: &CliFlags| c.allow_env_files,
        config = |c: &Config| c.sandbox.allow_env_files,
        baseline = |b: PresetBaseline| b.allow_env_files,
        resolved = |r: &Resolved| r.allow_env_files;

    allow_localhost_any, "sandbox", "allow_localhost_any",
        cli = |c: &CliFlags| c.allow_localhost_any,
        config = |c: &Config| c.sandbox.allow_localhost_any,
        baseline = |b: PresetBaseline| b.allow_localhost_any,
        resolved = |r: &Resolved| r.allow_localhost_any;

    /// One-way: `--inherit-env` turns it on, there is no `--no-inherit-env`.
    inherit_env, "sandbox", "inherit_env",
        cli = |c: &CliFlags| FeatureToggle::from_pair(c.inherit_env, false),
        config = |c: &Config| c.sandbox.inherit_env,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.inherit_env;

    allow_lifecycle_scripts, "sandbox", "allow_lifecycle_scripts",
        cli = |c: &CliFlags| c.allow_lifecycle_scripts,
        config = |c: &Config| c.sandbox.allow_lifecycle_scripts,
        baseline = |b: PresetBaseline| b.allow_lifecycle_scripts,
        resolved = |r: &Resolved| r.allow_lifecycle_scripts;

    /// Default-on since #147's clipboard hardening: `--deny-clipboard` still
    /// exists and is now a no-op restatement of the default, and
    /// `--allow-clipboard` is the flag that does something.
    deny_clipboard, "sandbox", "deny_clipboard",
        cli = |c: &CliFlags| c.deny_clipboard,
        config = |c: &Config| c.sandbox.deny_clipboard,
        baseline = |_: PresetBaseline| true,
        resolved = |r: &Resolved| r.deny_clipboard;

    /// One-way: `--allow-gpg-signing` only. A config `true` cannot be undone
    /// for a single run.
    allow_gpg_signing, "sandbox", "allow_gpg_signing",
        cli = |c: &CliFlags| FeatureToggle::from_pair(c.allow_gpg_signing, false),
        config = |c: &Config| c.sandbox.allow_gpg_signing,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.allow_gpg_signing;

    allow_tmp_exec, "sandbox", "allow_tmp_exec",
        cli = |c: &CliFlags| c.allow_tmp_exec,
        config = |c: &Config| c.sandbox.allow_tmp_exec,
        baseline = |b: PresetBaseline| b.allow_tmp_exec,
        resolved = |r: &Resolved| r.allow_tmp_exec;

    scratch_dir, "sandbox", "scratch_dir",
        cli = |c: &CliFlags| c.scratch,
        config = |c: &Config| c.sandbox.scratch_dir,
        baseline = |_: PresetBaseline| true,
        resolved = |r: &Resolved| r.scratch_dir;

    /// One-way in the OFF direction: `--no-audit` only, no `--audit`.
    audit, "sandbox", "audit",
        cli = |c: &CliFlags| c.audit,
        config = |c: &Config| c.sandbox.audit,
        baseline = |_: PresetBaseline| true,
        resolved = |r: &Resolved| r.audit;

    quiet, "sandbox", "quiet",
        cli = |c: &CliFlags| c.quiet,
        config = |c: &Config| c.sandbox.quiet,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.quiet;

    yes, "sandbox", "yes",
        cli = |c: &CliFlags| c.yes,
        config = |c: &Config| c.sandbox.yes,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.yes;

    /// One-way: `--allow-jvm-attach` only.
    allow_jvm_attach, "sandbox", "allow_jvm_attach",
        cli = |c: &CliFlags| FeatureToggle::from_pair(c.allow_jvm_attach, false),
        config = |c: &Config| c.sandbox.allow_jvm_attach,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.allow_jvm_attach;

    /// One-way: `--allow-msbuild` only.
    allow_msbuild, "sandbox", "allow_msbuild",
        cli = |c: &CliFlags| FeatureToggle::from_pair(c.allow_msbuild, false),
        config = |c: &Config| c.sandbox.allow_msbuild,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.allow_msbuild;

    /// Config-only: writes into the Gradle user home, so there is deliberately
    /// no CLI flag to turn it on for one run.
    gradle_init, "sandbox", "gradle_init",
        cli = |_: &CliFlags| FeatureToggle::UseDefault,
        config = |c: &Config| c.sandbox.gradle_init,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.gradle_init;

    allow_docker, "sandbox", "allow_docker",
        cli = |c: &CliFlags| c.allow_docker,
        config = |c: &Config| c.sandbox.allow_docker,
        baseline = |b: PresetBaseline| b.allow_docker,
        resolved = |r: &Resolved| r.allow_docker;

    /// One-way: `--allow-cache-exec-any` only.
    allow_cache_exec_any, "sandbox", "allow_cache_exec_any",
        cli = |c: &CliFlags| FeatureToggle::from_pair(c.allow_cache_exec_any, false),
        config = |c: &Config| c.sandbox.allow_cache_exec_any,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.allow_cache_exec_any;

    /// One-way: `--allow-browser` only.
    allow_browser, "sandbox", "allow_browser",
        cli = |c: &CliFlags| FeatureToggle::from_pair(c.allow_browser, false),
        config = |c: &Config| c.sandbox.allow_browser,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.allow_browser;

    /// Experimental, config-only (#242).
    keychain_substitute, "sandbox", "keychain_substitute",
        cli = |_: &CliFlags| FeatureToggle::UseDefault,
        config = |c: &Config| c.sandbox.keychain_substitute,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.keychain_substitute;

    /// The config layer folds in the deprecated `sandbox.gh_proxy` spelling.
    gh_guard_enabled, "gh_guard", "enabled",
        cli = |c: &CliFlags| c.gh_guard,
        config = |c: &Config| c.gh_guard.enabled.or(c.sandbox.gh_proxy),
        baseline = |b: PresetBaseline| b.gh_guard_enabled,
        resolved = |r: &Resolved| r.gh_guard.enabled;

    gh_scope_check, "gh_guard", "scope_check",
        cli = |_: &CliFlags| FeatureToggle::UseDefault,
        config = |c: &Config| c.gh_guard.scope_check,
        baseline = |_: PresetBaseline| true,
        resolved = |r: &Resolved| r.gh_guard.scope_check;

    gh_block_auth_token, "gh_guard", "block_auth_token",
        cli = |_: &CliFlags| FeatureToggle::UseDefault,
        config = |c: &Config| c.gh_guard.block_auth_token,
        baseline = |_: PresetBaseline| true,
        resolved = |r: &Resolved| r.gh_guard.block_auth_token;

    gh_inject_token, "gh_guard", "inject_token",
        cli = |_: &CliFlags| FeatureToggle::UseDefault,
        config = |c: &Config| c.gh_guard.inject_token,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.gh_guard.inject_token;

    gh_allow_api_write, "gh_guard", "allow_api_write",
        cli = |_: &CliFlags| FeatureToggle::UseDefault,
        config = |c: &Config| c.gh_guard.allow_api_write,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.gh_guard.allow_api_write;

    /// The config layer folds in the deprecated `sandbox.git_push_prevention`
    /// spelling.
    git_guard_enabled, "git_guard", "enabled",
        cli = |c: &CliFlags| c.git_push_prevention,
        config = |c: &Config| c.git_guard.enabled.or(c.sandbox.git_push_prevention),
        baseline = |b: PresetBaseline| b.git_guard_enabled,
        resolved = |r: &Resolved| r.git_guard.enabled;

    git_prevent_push, "git_guard", "prevent_push",
        cli = |_: &CliFlags| FeatureToggle::UseDefault,
        config = |c: &Config| c.git_guard.prevent_push,
        baseline = |_: PresetBaseline| true,
        resolved = |r: &Resolved| r.git_guard.prevent_push;

    git_prevent_force_push, "git_guard", "prevent_force_push",
        cli = |_: &CliFlags| FeatureToggle::UseDefault,
        config = |c: &Config| c.git_guard.prevent_force_push,
        baseline = |_: PresetBaseline| true,
        resolved = |r: &Resolved| r.git_guard.prevent_force_push;

    git_protect_default_branch_only, "git_guard", "protect_default_branch_only",
        cli = |_: &CliFlags| FeatureToggle::UseDefault,
        config = |c: &Config| c.git_guard.protect_default_branch_only,
        baseline = |_: PresetBaseline| false,
        resolved = |r: &Resolved| r.git_guard.protect_default_branch_only;
}

/// Boolean registry keys deliberately absent from [`BOOL_KEYS`], with the
/// reason. Pinned by a test so a *new* boolean key cannot be added to the
/// registry without either joining the ladder or being listed here.
#[cfg(test)]
pub(super) const BOOL_KEYS_EXEMPT: &[(&str, &str, &str)] = &[
    (
        "sandbox",
        "gh_proxy",
        "deprecated spelling of gh_guard.enabled; folded into that key's config layer",
    ),
    (
        "sandbox",
        "git_push_prevention",
        "deprecated spelling of git_guard.enabled; folded into that key's config layer",
    ),
    (
        "sandbox",
        "use_bubblewrap",
        "resolves to Option<bool>, not bool: `None` means auto-detect, a third \
         state the bool ladder cannot express",
    ),
    (
        "audit",
        "enabled",
        "the [audit] section is parsed and displayed but has no consumer yet — \
         it resolves to nothing, so there is no precedence to describe",
    ),
];

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
