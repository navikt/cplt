//! Config file loading, parsing, and CLI-flag merging.

use std::path::{Path, PathBuf};

use super::error::ConfigError;
use super::path::{config_dir, config_path, expand_tilde, resolve_config_path, resolve_repo_path};
use super::types::{
    CliFlags, Config, EnforcementMode, GhGuardPolicy, GitGuardPolicy, LoadedConfig, Preset,
    Resolved, ResolvedPushRule, UnknownCommandPolicy,
};
use crate::sandbox::{HardeningCategory, validate_sbpl_path};
use crate::ui;

impl Config {
    /// Load config file without printing anything.
    /// Returns `None` if no config file exists (HOME unset or file absent).
    /// Returns `Err` if the file exists but can't be read or parsed.
    pub fn load_file() -> Result<Option<LoadedConfig>, ConfigError> {
        let Some(path) = config_path() else {
            return Ok(None);
        };

        if !path.exists() {
            return Ok(None);
        }

        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                ui::info(&format!("Cannot read config file {}: {e}", path.display()));
                return Ok(None);
            }
            Err(e) => {
                return Err(ConfigError::FileRead { path, source: e });
            }
        };

        // Forward-compatible load: unknown keys (e.g. options from a newer cplt
        // version, or typos) are collected and warned about but do NOT fail the
        // load. Validity is derived from the struct definitions via serde_ignored,
        // so there is no key list to keep in sync with the config schema.
        let (config, unknown_keys) = super::validation::deserialize_collecting_unknowns(&raw)
            .map_err(|e| ConfigError::TomlParse {
                path: path.display().to_string(),
                source: e,
            })?;

        for key_path in &unknown_keys {
            // describe_unknown_key already includes "in [section]"; append the
            // file and the ignored note without repeating "in".
            ui::warn(&format!(
                "{}, ignored ({})",
                super::validation::describe_unknown_key(key_path),
                path.display()
            ));
        }

        Ok(Some(LoadedConfig { config, path, raw }))
    }

    /// Parse config from a TOML string (no I/O, no side effects).
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(ConfigError::Toml)
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
    pub fn merge(&self, cli: CliFlags) -> Result<Resolved, ConfigError> {
        self.merge_with_no_proxy_env(cli, no_proxy_env_value())
    }

    /// Same as [`merge`](Self::merge) but with the ambient `NO_PROXY`/`no_proxy`
    /// value injected explicitly rather than read from the process environment.
    ///
    /// `merge` is the normal entry point (it reads the real environment); this
    /// variant exists so tests can exercise the NO_PROXY-merge path
    /// deterministically without mutating process-global env — which is UB under
    /// concurrent test threads (edition 2024) and would clobber a developer's
    /// real setting. Pass `None` for "no ambient NO_PROXY".
    pub fn merge_with_no_proxy_env(
        &self,
        cli: CliFlags,
        no_proxy_env: Option<String>,
    ) -> Result<Resolved, ConfigError> {
        // Policy preset: sets a BASELINE spanning two axes — the five sandbox
        // toggles below AND the three safety features (gh_guard, git_guard,
        // proxy.forced). Precedence for the preset itself: CLI (--preset) wins
        // over config ([sandbox] preset). The baseline it implies is the
        // *lowest* layer for each field — explicit individual CLI flags and
        // config values still override it (see each
        // `*.to_option().or(config).unwrap_or(baseline)` for toggles and the
        // `.resolve(config.or(...).unwrap_or(baseline))` for the guards/proxy).
        let preset = cli.preset.or(self.sandbox.preset);
        // No preset == "standard" == cplt's hardcoded defaults (all five
        // toggles off, no guards, no forced proxy). Only `strict` turns the
        // safety features on.
        let baseline = preset.unwrap_or(Preset::Standard).baseline();

        // Proxy: FeatureToggle resolves --with-proxy/--no-proxy against config default (true).
        let with_proxy = cli.proxy.resolve(self.proxy.enabled.unwrap_or(true));

        // Proxy-forced: FeatureToggle resolves --proxy-forced/--no-proxy-forced,
        // then the explicit config value, then the preset baseline (false unless
        // `strict`). Precedence: CLI flag > config > preset > default(off) —
        // mirrors the toggle pattern, with the preset threaded in as the lowest
        // layer. When true, the proxy is mandatory and kernel egress is locked
        // to the proxy port (#53). Orchestration in main.rs enforces proxy-on +
        // fail-closed; the conflict with an explicitly disabled proxy is
        // reported there (so `--preset strict` with proxy.enabled=false fails
        // closed rather than silently).
        let proxy_forced = cli
            .proxy_forced
            .resolve(self.proxy.forced.unwrap_or(baseline.proxy_forced));

        // Port: CLI (if provided) > config > 0 (OS-assigned ephemeral port)
        let proxy_port = cli.proxy_port.or(self.proxy.port).unwrap_or(0);

        // Blocked domains: CLI > config > exe_dir fallback (handled later in main)
        let blocked_domains = cli
            .blocked_domains
            .or_else(|| self.proxy.blocked_domains.as_ref().map(|s| expand_tilde(s)));

        // Allowed domains: CLI > config
        let allowed_domains = cli
            .allowed_domains
            .or_else(|| self.proxy.allowed_domains.as_ref().map(|s| expand_tilde(s)));

        // Fail-closed networking opt-in (#52). `cli.default_allowlist` is a
        // FeatureToggle where `--default-allowlist` is the ON side and
        // `--allow-all-domains` is the OFF side (off wins), resolved against the
        // explicit `proxy.default_allowlist` config, then the preset baseline
        // (true only for `strict`, false otherwise). Precedence: CLI flag /
        // `--allow-all-domains` escape hatch > config > preset > default(off) —
        // mirrors `proxy_forced`, with the preset threaded in as the lowest
        // layer. So `--preset strict` fails closed to the domain allowlist,
        // while an explicit `--allow-all-domains` (OFF wins) or
        // `proxy.default_allowlist = false` still overrides strict's baseline.
        // `--allow-all-domains` additionally forces allow-all: main.rs uses
        // `allow_all_domains` to clear any explicit `allowed_domains` file for
        // the run. With no preset the baseline is Standard (false), so this
        // resolves exactly as before — no regression.
        let default_allowlist = cli.default_allowlist.resolve(
            self.proxy
                .default_allowlist
                .unwrap_or(baseline.default_allowlist),
        );
        let allow_all_domains = cli.allow_all_domains;

        // Proxy log file: CLI > config
        let proxy_log_file = cli
            .proxy_log_file
            .or_else(|| self.proxy.log_file.as_ref().map(|s| expand_tilde(s)));

        // Proxy log level: CLI > config > default (none)
        let proxy_log_level = if let Some(level) = cli.proxy_log_level {
            level
        } else if let Some(ref level_str) = self.proxy.log_level {
            level_str.parse::<crate::proxy::ProxyLogLevel>()?
        } else {
            crate::proxy::ProxyLogLevel::None
        };

        // Proxy timeout: CLI > config > default (60s)
        let proxy_timeout =
            std::time::Duration::from_secs(cli.proxy_timeout.or(self.proxy.timeout).unwrap_or(60));

        // Upstream (corporate) proxy: CLI > config. Parse+validate the URL here so
        // a malformed value fails config loading (fail-closed) rather than being
        // silently ignored at connection time.
        let proxy_upstream = match cli.proxy_upstream.or_else(|| self.proxy.upstream.clone()) {
            Some(url) => Some(
                crate::proxy::UpstreamProxy::parse(&url)
                    .map_err(|e| ConfigError::Validation(format!("proxy.upstream: {e}")))?,
            ),
            None => None,
        };

        // Upstream no-proxy list: hosts that BYPASS the upstream and connect
        // DIRECTLY (standard NO_PROXY behavior). CLI over config (mirrors
        // proxy.upstream's precedence), then MERGE the ambient NO_PROXY/no_proxy
        // env so an existing corporate setup works out of the box. Every entry is
        // normalized (lowercase, leading dots stripped; empty and bare `*`
        // dropped). This is a no-op at runtime when proxy.upstream is unset — the
        // list is only consulted on the upstream-forward branch of the proxy.
        let proxy_upstream_no_proxy = {
            let base: Vec<String> = if cli.proxy_upstream_no_proxy.is_empty() {
                self.proxy.upstream_no_proxy.clone().unwrap_or_default()
            } else {
                cli.proxy_upstream_no_proxy.clone()
            };
            let mut merged: Vec<String> = base
                .iter()
                .filter_map(|e| crate::proxy::normalize_no_proxy_entry(e))
                .collect();
            if let Some(env) = no_proxy_env {
                merged.extend(crate::proxy::parse_no_proxy_list(&env));
            }
            merged.sort_unstable();
            merged.dedup();
            merged
        };

        // Blocklist subscriptions (issue #144, Phase 1). GLOBAL-only, tighten-only.
        // Parsed here so an invalid `refresh` value fails config loading (a typo
        // is surfaced, not silently ignored). The cache lives under the cplt
        // config dir (`~/.config/cplt/subscriptions/`) — OUTSIDE the sandbox's
        // writable set, so the agent cannot poison it. When no blocklists are
        // configured the set is empty and networking is unchanged from today.
        let proxy_subscriptions = {
            let refresh = match self.proxy.subscriptions.refresh.as_deref() {
                Some(s) => crate::subscriptions::RefreshInterval::parse(s)
                    .map_err(|e| ConfigError::Validation(format!("proxy.subscriptions.{e}")))?,
                None => crate::subscriptions::RefreshInterval::Manual,
            };
            let mut blocklists = Vec::new();
            for entry in &self.proxy.subscriptions.blocklists {
                let url = entry.url().trim().to_string();
                if url.is_empty() {
                    return Err(ConfigError::Validation(
                        "proxy.subscriptions.blocklists entry has an empty url".to_string(),
                    ));
                }
                // Scheme allowlist, enforced at config-load time. Only https:// is
                // fetched in production; file:// is permitted for a local mirror /
                // offline + test path. Rejecting anything else here catches junk,
                // `http://`, and `-`-prefixed values (which curl would otherwise try
                // to parse as flags) before they ever reach the fetcher.
                if !(url.starts_with("https://") || url.starts_with("file://")) {
                    return Err(ConfigError::Validation(format!(
                        "proxy.subscriptions.blocklists url {url:?} must start with \
                         https:// (or file:// for a local mirror)"
                    )));
                }
                blocklists.push(crate::subscriptions::BlocklistSubscription {
                    url,
                    sha256: entry.sha256().map(|s| s.trim().to_ascii_lowercase()),
                });
            }
            let cache_dir = config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("subscriptions");
            crate::subscriptions::SubscriptionSet {
                refresh,
                blocklists,
                cache_dir,
            }
        };

        // Allow private domains: merge CLI + config list, sort+dedup.
        // Validates that entries are non-empty (empty string would bypass private IP
        // check for all domains that match is_domain_match("", _), which is none — but
        // reject it anyway for clarity).
        // Normalized (lowercase, no trailing dot) at ingest: `is_domain_match`
        // normalizes the hostname but compares it against the raw pattern, so an
        // un-normalized entry like "Intern.NAV.no" or "a.nav.no." would never
        // match anything — contradicting the documented case-insensitive,
        // trailing-dot-stripped matching. File-sourced lists are already
        // normalized by `parse_lines_file`; this is the config/CLI path.
        let mut allow_private_domains: Vec<String> = self
            .proxy
            .allow_private_domains
            .clone()
            .unwrap_or_default()
            .into_iter()
            .chain(cli.allow_private_domains)
            .map(|d| crate::proxy::normalize_hostname(&d))
            .collect();
        allow_private_domains.sort_unstable();
        allow_private_domains.dedup();
        for domain in &allow_private_domains {
            if domain.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "proxy.allow_private_domains entry must not be empty".to_string(),
                ));
            }
        }

        // Allow-read: merge config + CLI
        let config_dir = config_path().and_then(|p| p.parent().map(std::path::Path::to_path_buf));
        let mut allow_read: Vec<PathBuf> = Vec::new();
        for s in &self.allow.read {
            match resolve_config_path(s, config_dir.as_ref()) {
                Ok(p) => allow_read.push(p),
                Err(e) => {
                    ui::warn(&format!("Warning: allow.read path {s:?}: {e}"));
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
                    ui::warn(&format!("Warning: allow.write path {s:?}: {e}"));
                }
            }
        }
        allow_write.extend(cli.allow_write);

        // Allow-socket: merge config + CLI
        let mut allow_socket: Vec<PathBuf> = Vec::new();
        for s in &self.allow.socket {
            match resolve_config_path(s, config_dir.as_ref()) {
                Ok(p) => allow_socket.push(p),
                Err(e) => {
                    ui::warn(&format!("Warning: allow.socket path {s:?}: {e}"));
                }
            }
        }
        allow_socket.extend(cli.allow_socket);

        // Deny-paths: merge config + CLI
        // SECURITY: config deny paths MUST resolve — a silently dropped deny is dangerous
        let mut deny_paths: Vec<PathBuf> = Vec::new();
        for s in &self.deny.paths {
            match resolve_config_path(s, config_dir.as_ref()) {
                Ok(p) => deny_paths.push(p),
                Err(e) => {
                    return Err(ConfigError::Validation(format!(
                        "deny.paths entry {s:?} cannot be resolved: {e}\n\
                         Fix the path in your config or remove it. \
                         Silently dropping deny rules is a security risk."
                    )));
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

        // Allow-env-files: explicit CLI flag wins, then explicit config value,
        // then the preset baseline (false when no preset — deny by default).
        let allow_env_files = cli
            .allow_env_files
            .to_option()
            .or(self.sandbox.allow_env_files)
            .unwrap_or(baseline.allow_env_files);

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

        // Allow-localhost-any: explicit CLI flag wins, then explicit config
        // value, then the preset baseline (false when no preset).
        let allow_localhost_any = cli
            .allow_localhost_any
            .to_option()
            .or(self.sandbox.allow_localhost_any)
            .unwrap_or(baseline.allow_localhost_any);

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

        // Allow-lifecycle-scripts: explicit CLI flag wins, then explicit config
        // value, then the preset baseline (false when no preset — blocked).
        let allow_lifecycle_scripts = cli
            .allow_lifecycle_scripts
            .to_option()
            .or(self.sandbox.allow_lifecycle_scripts)
            .unwrap_or(baseline.allow_lifecycle_scripts);

        // Allow-gpg-signing: CLI flag wins, then config, then false (blocked by default)
        let allow_gpg_signing = if cli.allow_gpg_signing {
            true
        } else {
            self.sandbox.allow_gpg_signing.unwrap_or(false)
        };

        // Deny-clipboard: CLI-only tightening flag (defaults to false).
        let deny_clipboard = cli.deny_clipboard;

        // Allow-jvm-attach: CLI flag wins, then config, then false (blocked by default)
        let allow_jvm_attach = if cli.allow_jvm_attach {
            true
        } else {
            self.sandbox.allow_jvm_attach.unwrap_or(false)
        };

        // Allow-msbuild: CLI flag wins, then config, then false (blocked by default)
        let allow_msbuild = if cli.allow_msbuild {
            true
        } else {
            self.sandbox.allow_msbuild.unwrap_or(false)
        };

        // Gradle init script: config-only opt-in (default false). Writes a
        // cplt-managed file into the Gradle user home — behavior change the
        // user must explicitly ask for.
        let gradle_init = self.sandbox.gradle_init.unwrap_or(false);

        // Allow-docker: explicit CLI flag wins, then explicit config value,
        // then the preset baseline (false when no preset — blocked).
        let allow_docker = cli
            .allow_docker
            .to_option()
            .or(self.sandbox.allow_docker)
            .unwrap_or(baseline.allow_docker);

        // Allow-tmp-exec: explicit CLI flag wins, then explicit config value,
        // then the preset baseline (false when no preset — blocked).
        let allow_tmp_exec = cli
            .allow_tmp_exec
            .to_option()
            .or(self.sandbox.allow_tmp_exec)
            .unwrap_or(baseline.allow_tmp_exec);

        // Allow-cache-exec: merge config + CLI (list of subdir names)
        let mut allow_cache_exec = self.sandbox.allow_cache_exec.clone();
        allow_cache_exec.extend(cli.allow_cache_exec);
        allow_cache_exec.sort_unstable();
        allow_cache_exec.dedup();

        // Allow-cache-exec-any: CLI flag wins, then config, then false (blocked by default)
        let allow_cache_exec_any = if cli.allow_cache_exec_any {
            true
        } else {
            self.sandbox.allow_cache_exec_any.unwrap_or(false)
        };

        // Allow-browser: CLI flag wins, then config, then false (blocked by default)
        let allow_browser = if cli.allow_browser {
            true
        } else {
            self.sandbox.allow_browser.unwrap_or(false)
        };

        // Keychain substitution (#242): experimental, config-only, default off.
        // With it off the Keychain grant is exactly what `needs_keychain()` says,
        // matching every release before this key existed.
        let keychain_substitute = self.sandbox.keychain_substitute.unwrap_or(false);

        // Scratch-dir: FeatureToggle resolves --scratch-dir/--no-scratch-dir (default: on)
        let scratch_dir = cli
            .scratch
            .resolve(self.sandbox.scratch_dir.unwrap_or(true));

        // Use-bubblewrap: tri-state. --use-bubblewrap/--no-bubblewrap resolve via
        // FeatureToggle (off wins if both set); otherwise fall through to config,
        // then None (auto-detect).
        let use_bubblewrap = cli
            .use_bubblewrap
            .to_option()
            .or(self.sandbox.use_bubblewrap);

        // Quiet: FeatureToggle resolves --quiet/--no-quiet (default: off)
        let quiet = cli.quiet.resolve(self.sandbox.quiet.unwrap_or(false));

        // Audit: FeatureToggle resolves --no-audit against config (default: on).
        // The post-session report is on by default; --no-audit forces it off.
        let audit = cli.audit.resolve(self.sandbox.audit.unwrap_or(true));

        // Yes: FeatureToggle resolves --yes/--no-yes (default: off)
        let yes = cli.yes.resolve(self.sandbox.yes.unwrap_or(false));

        // gh-guard: CLI flag overrides enabled; sub-options come from [gh_proxy] config.
        // Backward compat: old `sandbox.gh_proxy = true` is treated as `gh_guard.enabled = true`.
        // Precedence: CLI flag > config value > preset baseline > default(off).
        // Only `strict` sets the baseline on — every other preset (and none)
        // leaves it at `false`, so resolution is unchanged for them.
        let gh_guard_enabled_default = self
            .gh_guard
            .enabled
            .or(self.sandbox.gh_proxy)
            .unwrap_or(baseline.gh_guard_enabled);
        let gh_guard_enabled = cli.gh_guard.resolve(gh_guard_enabled_default);
        let gh_guard = GhGuardPolicy {
            enabled: gh_guard_enabled,
            mode: self.gh_guard.mode.unwrap_or(EnforcementMode::Block),
            scope_check: self.gh_guard.scope_check.unwrap_or(true),
            block_auth_token: self.gh_guard.block_auth_token.unwrap_or(true),
            inject_token: self.gh_guard.inject_token.unwrap_or(false),
            unknown_command: self
                .gh_guard
                .unknown_command
                .unwrap_or(UnknownCommandPolicy::Block),
            allow_api_write: self.gh_guard.allow_api_write.unwrap_or(false),
        };

        // git-guard: CLI flag overrides enabled. Backward compat from sandbox.git_push_prevention.
        // Precedence: CLI flag > config value > preset baseline > default(off).
        // Only `strict` sets the baseline on; unchanged for every other case.
        let git_guard_enabled_default = self
            .git_guard
            .enabled
            .or(self.sandbox.git_push_prevention)
            .unwrap_or(baseline.git_guard_enabled);
        let git_guard_enabled = cli.git_push_prevention.resolve(git_guard_enabled_default);
        let git_guard = GitGuardPolicy {
            enabled: git_guard_enabled,
            mode: self.git_guard.mode.unwrap_or(EnforcementMode::Block),
            prevent_push: self.git_guard.prevent_push.unwrap_or(true),
            prevent_force_push: self.git_guard.prevent_force_push.unwrap_or(true),
            protect_default_branch_only: self
                .git_guard
                .protect_default_branch_only
                .unwrap_or(false),
            allow_push: self
                .git_guard
                .allow_push
                .iter()
                .map(|r| ResolvedPushRule {
                    remote: r.remote.clone(),
                    branches: r.branches.clone(),
                    force: r.force.unwrap_or(false),
                })
                .collect(),
        };

        // Validate all paths for SBPL injection characters
        for p in allow_read
            .iter()
            .chain(allow_write.iter())
            .chain(allow_socket.iter())
            .chain(deny_paths.iter())
        {
            validate_sbpl_path(p)?;
        }
        // Validate cache exec subdirs — interpolated into SBPL string literals.
        // Reject chars that could break the profile and path-traversal components
        // that would escape ~/Library/Caches (e.g. "../Applications").
        for subdir in &allow_cache_exec {
            if subdir.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "allow_cache_exec subdir must not be empty (would grant exec to all of ~/Library/Caches)"
                        .to_string(),
                ));
            }
            for c in ['"', ')', '(', ';', '\\', '\n', '\r', '\0'] {
                if subdir.contains(c) {
                    return Err(ConfigError::Validation(format!(
                        "allow_cache_exec subdir {subdir:?} contains unsafe characters"
                    )));
                }
            }
            for component in subdir.trim_matches('/').split('/') {
                if component == ".." || component == "." {
                    return Err(ConfigError::Validation(format!(
                        "allow_cache_exec subdir {subdir:?} contains path traversal"
                    )));
                }
            }
        }

        Ok(Resolved {
            with_proxy,
            repo_private_domains: Vec::new(),
            proxy_forced,
            proxy_port,
            blocked_domains,
            allowed_domains,
            default_allowlist,
            allow_all_domains,
            proxy_log_file,
            proxy_log_level,
            proxy_timeout,
            proxy_upstream,
            proxy_upstream_no_proxy,
            proxy_subscriptions,
            allow_private_domains,
            allow_read,
            allow_write,
            allow_socket,
            deny_paths,
            allow_ports,
            allow_localhost,
            allow_localhost_any,
            allow_env_files,
            no_validate,
            pass_env,
            inherit_env,
            allow_lifecycle_scripts,
            allow_gpg_signing,
            deny_clipboard,
            allow_jvm_attach,
            allow_msbuild,
            gradle_init,
            allow_docker,
            allow_tmp_exec,
            allow_cache_exec,
            allow_cache_exec_any,
            allow_browser,
            keychain_substitute,
            scratch_dir,
            use_bubblewrap,
            quiet,
            audit,
            yes,
            gh_guard,
            git_guard,
            preset,
            agent: self.sandbox.agent.clone(),
            deny_env: Vec::new(),
        })
    }
}

/// Which `allow.write` grants overlap a path the unsandboxed parent executes.
///
/// Split out from [`Resolved::write_grants_over_trusted_bins`] so the predicate
/// can be tested against an injected list. Resolving the real binaries makes the
/// caller machine-dependent; the rule itself is not, and the rule is the part
/// worth pinning.
///
/// `extra` holds already-resolved binary paths (a Homebrew `bin/git` symlink
/// followed into `Cellar`, say) — matching those, rather than whole trusted
/// roots, is what keeps the warning off ordinary `/opt/homebrew/var` grants.
fn grants_over_trusted_paths(
    allow_write: &[PathBuf],
    extra: &[String],
) -> Vec<(PathBuf, Vec<String>)> {
    allow_write
        .iter()
        .filter_map(|granted| {
            let mut hit: Vec<String> = crate::git::TRUSTED_BIN_DIRS
                .iter()
                .map(|d| (*d).to_string())
                .chain(extra.iter().cloned())
                .filter(|d| {
                    let dir = Path::new(d);
                    dir.starts_with(granted) || granted.starts_with(dir)
                })
                .collect();
            // A resolved binary usually lives under a bin dir, so one grant can
            // match both; report each path once. Sorted first because `dedup`
            // only collapses adjacent duplicates.
            hit.sort_unstable();
            hit.dedup();
            (!hit.is_empty()).then(|| (granted.clone(), hit))
        })
        .collect()
}

/// Read the ambient `NO_PROXY`/`no_proxy` environment value, if any. Kept as a
/// tiny standalone fn so there is a single place cplt reaches into the process
/// environment for upstream-proxy-bypass configuration. cplt runs OUTSIDE the
/// sandbox, so this reads the user's own shell environment — exactly the
/// existing corporate `NO_PROXY` setup we want to honor.
fn no_proxy_env_value() -> Option<String> {
    std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .ok()
        .filter(|v| !v.trim().is_empty())
}

impl Resolved {
    /// Returns the hardening categories that are disabled by user configuration.
    pub fn disabled_hardening_categories(&self) -> Vec<HardeningCategory> {
        let mut disabled = Vec::new();
        if self.allow_lifecycle_scripts {
            disabled.push(HardeningCategory::LifecycleScripts);
        }
        if self.allow_gpg_signing {
            disabled.push(HardeningCategory::GitSigning);
        }
        disabled
    }

    /// Reconcile `proxy_forced` with `allow_localhost_any`, which are mutually
    /// exclusive.
    ///
    /// Security-critical (#53): `proxy_forced` locks kernel egress to the proxy
    /// port (Linux drops the default `*:443` Landlock allow; macOS SBPL pins
    /// `localhost:<proxy_port>`). `allow_localhost_any`, by contrast, disables
    /// kernel-level TCP-connect restriction *entirely* (Landlock net rules are
    /// port-based and cannot pin localhost, so honoring "any localhost port"
    /// means not restricting connect at all). Enforcing both would leave direct
    /// egress to any `host:443` wide open under the exact flag meant to close it.
    ///
    /// Rather than refuse to launch — `allow_localhost_any` is commonly set in
    /// user config or proposed by JVM/Gradle repos, so erroring would make
    /// `proxy.forced` unusable there — `proxy.forced` **wins**: this forces
    /// `allow_localhost_any` off so `restrict_net_connect` stays on and egress is
    /// actually locked. Returns `true` when it superseded `allow_localhost_any`
    /// (the caller should warn). Call AFTER `apply_repo_config` so it also
    /// overrides a repo-proposed value.
    #[must_use]
    pub fn reconcile_proxy_forced(&mut self) -> bool {
        if self.proxy_forced && self.allow_localhost_any {
            self.allow_localhost_any = false;
            return true;
        }
        false
    }

    /// Write grants that overlap [`crate::git::TRUSTED_BIN_DIRS`], as
    /// `(granted path, every trusted dir it overlaps)`. Empty is the normal case.
    ///
    /// Grouped by grant, not one row per pair: a grant on `/usr` or `/` overlaps
    /// several trusted directories at once, and that is still **one** thing the
    /// user has to go edit. Emitting a warning per pair would print the same
    /// advice six times for one line of config.
    ///
    /// `allow.write` accepts an absolute path as-is — `resolve_config_path`
    /// only expands `~` and canonicalizes — so nothing stops a grant on
    /// `/opt/homebrew/bin`, which is exactly what a user reaches for to make
    /// `brew install` work from inside the sandbox. cplt resolves its own
    /// `git`, `bwrap` and `sandbox-exec` from those directories and runs them
    /// in the **unsandboxed parent**, so such a grant hands the agent
    /// unsandboxed execution on the next launch and undoes the whole point of
    /// [`crate::git::trusted_binary`].
    ///
    /// A warning, not a refusal: erroring would break configs that work today.
    /// Call after `apply_repo_config`, so the repo-proposed grants are in too.
    ///
    /// Both directions of `starts_with` count. A grant *inside* a trusted dir
    /// is the direct hole; a grant on an ancestor (`/usr`, or `/`) is the same
    /// hole one level up.
    ///
    /// The *resolved* helper binaries count too, not just the bin dirs.
    /// `trusted_binary` follows a symlink and accepts any final target under
    /// [`crate::git::TRUSTED_BIN_ROOTS`], which is what makes Homebrew's
    /// `bin/git -> ../Cellar/git/*/bin/git` work — so a grant on the Cellar path
    /// that binary actually resolves to never touches a *bin* dir yet still lets
    /// the agent rewrite the file the parent executes.
    ///
    /// Matched against those resolved paths rather than the roots wholesale.
    /// The roots are an acceptance filter for symlink targets, and reusing them
    /// as a warning predicate fires on every ordinary grant under
    /// `/opt/homebrew` or `/usr/local` — `var/` for a brew-managed database,
    /// `lib/node_modules` for `npm -g` — none of which can reach the parent's
    /// git unless the bin symlink already points there. A warning nobody can
    /// act on is a warning everybody learns to skip.
    #[must_use]
    pub fn write_grants_over_trusted_bins(&self) -> Vec<(PathBuf, Vec<String>)> {
        // Resolution is filesystem-only (no spawn), so this is safe to do while
        // building the warning. `None` for a binary that is not installed.
        // Every helper the unsandboxed parent resolves this way and then
        // spawns. `mise`/`asdf` matter as much as git: `resolve_mise_shim`
        // runs them in the parent, and the warning text names mise explicitly,
        // so leaving them out promises coverage the check does not deliver.
        // `sandbox-exec` is absent deliberately — it is the fixed
        // /usr/bin/sandbox-exec, never resolved.
        let resolved: Vec<String> = ["git", "gh", "bwrap", "mise", "asdf"]
            .iter()
            .filter_map(|n| crate::git::trusted_binary(n))
            .map(|p| {
                std::fs::canonicalize(&p)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        grants_over_trusted_paths(&self.allow_write, &resolved)
    }

    /// Print comprehensive sandbox configuration summary to stderr.
    ///
    /// Shows ALL effective settings including defaults so the user can make
    /// an informed decision before Copilot is launched. This is a security
    /// tool — the sandbox boundary must never be hidden.
    pub fn print_summary(
        &self,
        project_dir: &std::path::Path,
        home_dir: &std::path::Path,
        agent: crate::agent::Agent,
    ) {
        let blue = ui::color(ui::BLUE);
        let dim = ui::color(ui::DIM);
        let green = ui::color(ui::GREEN);
        let yellow = ui::color(ui::YELLOW);
        let nc = ui::color(ui::RESET);

        eprintln!();
        eprintln!("{blue}[cplt]{nc} ── Sandbox Configuration ─────────────────────────");
        eprintln!();

        if let Some(preset) = self.preset {
            eprintln!(
                "{blue}[cplt]{nc}  {dim}Preset:{nc}        {green}{preset}{nc}         {dim}baseline, individual flags still override{nc}"
            );
            eprintln!();
        }

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
        if !self.allow_socket.is_empty() {
            for p in &self.allow_socket {
                eprintln!(
                    "{blue}[cplt]{nc}    Socket:        {yellow}allowed{nc}     {}",
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
        if !self.scratch_dir {
            eprintln!(
                "{blue}[cplt]{nc}    Scratch dir:   disabled    {dim}TMPDIR not redirected (--no-scratch-dir){nc}"
            );
        }
        if self.allow_tmp_exec {
            let red = ui::color(ui::RED);
            eprintln!(
                "{blue}[cplt]{nc}    Tmp exec:      {red}ALLOWED{nc}     {dim}⚠ /tmp + /var/folders exec enabled{nc}"
            );
        }
        if self.allow_cache_exec_any {
            let red = ui::color(ui::RED);
            eprintln!(
                "{blue}[cplt]{nc}    Cache exec:    {red}ALLOWED{nc}     {dim}⚠ all ~/Library/Caches exec enabled{nc}"
            );
        } else if !self.allow_cache_exec.is_empty() {
            eprintln!(
                "{blue}[cplt]{nc}    Cache exec:    {yellow}allowed{nc}     {dim}~/Library/Caches/{}{nc}",
                self.allow_cache_exec.join(", ~/Library/Caches/")
            );
        }
        if self.allow_gpg_signing {
            let red = ui::color(ui::RED);
            eprintln!(
                "{blue}[cplt]{nc}    GPG signing:   {red}ALLOWED{nc}     {dim}⚠ agent socket exposed (--allow-gpg-signing){nc}"
            );
            eprintln!(
                "{blue}[cplt]{nc}    SSH/cloud:     blocked     {dim}~/.ssh, ~/.aws, ...{nc}"
            );
        } else {
            eprintln!(
                "{blue}[cplt]{nc}    SSH/GPG/cloud: blocked     {dim}~/.ssh, ~/.gnupg, ~/.aws, ...{nc}"
            );
        }
        if self.allow_docker {
            let red = ui::color(ui::RED);
            eprintln!(
                "{blue}[cplt]{nc}    Docker:        {red}ALLOWED{nc}     {dim}⚠ container mounts bypass sandbox (--allow-docker){nc}"
            );
        }
        if self.allow_jvm_attach {
            eprintln!(
                "{blue}[cplt]{nc}    JVM attach:    {yellow}allowed{nc}     {dim}.java_pid* sockets (--allow-jvm-attach){nc}"
            );
        }
        if self.allow_msbuild {
            eprintln!(
                "{blue}[cplt]{nc}    MSBuild:       {yellow}allowed{nc}     {dim}MSBuild<pid> sockets (--allow-msbuild){nc}"
            );
        }
        if self.allow_browser {
            eprintln!(
                "{blue}[cplt]{nc}    Browser:       {yellow}allowed{nc}     {dim}OAuth flows via open (--allow-browser){nc}"
            );
        }
        if agent.needs_copilot_dir() {
            eprintln!(
                "{blue}[cplt]{nc}    Copilot dir:   {green}allowed{nc}     {dim}~/.copilot{nc}"
            );
        }
        if agent.needs_keychain() {
            #[cfg(target_os = "macos")]
            match agent.credential_outside_keychain(
                home_dir,
                &self.deny_env,
                self.keychain_substitute,
            ) {
                // The whole-Keychain grant is dropped: the agent has a
                // credential it can reach without it (#242).
                Some(source) => eprintln!(
                    "{blue}[cplt]{nc}    Keychain:      {green}denied{nc}      {dim}{source} used instead{nc}"
                ),
                None => eprintln!(
                    "{blue}[cplt]{nc}    Keychain:      {yellow}allowed{nc}     {dim}~/Library/Keychains — every item {agent} can unlock{nc}"
                ),
            }
        }
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
            let ports: Vec<String> = self
                .allow_ports
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            eprintln!(
                "{blue}[cplt]{nc}    Outbound:      {green}443, {}{nc}",
                ports.join(", ")
            );
        }
        if self.allow_localhost_any && self.allow_jvm_attach {
            let red = ui::color(ui::RED);
            eprintln!(
                "{blue}[cplt]{nc}    Localhost:     {red}ALL TCP{nc}     {dim}⚠ all outbound TCP (JVM IPv4-mapped workaround){nc}"
            );
        } else if self.allow_localhost_any {
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
            let port_display = if self.proxy_port == 0 {
                "ephemeral".to_string()
            } else {
                format!("{}", self.proxy_port)
            };
            eprintln!(
                "{blue}[cplt]{nc}    Proxy:         {green}on{nc}          {dim}localhost:{port_display}{nc}"
            );
            if self.allowed_domains.is_some() {
                eprintln!(
                    "{blue}[cplt]{nc}    Allowlist:     {green}on{nc}          {dim}only listed domains{nc}"
                );
            }
            if !self.allow_private_domains.is_empty() {
                eprintln!(
                    "{blue}[cplt]{nc}    Private:       {yellow}allowed{nc}     {dim}{}{}",
                    self.allow_private_domains.join(", "),
                    nc
                );
            }
            if let Some(ref up) = self.proxy_upstream {
                eprintln!(
                    "{blue}[cplt]{nc}    Upstream:      {green}on{nc}          {dim}{}:{}{nc}",
                    up.host, up.port
                );
            }
            if let Some(ref lf) = self.proxy_log_file {
                eprintln!(
                    "{blue}[cplt]{nc}    Audit log:     {green}on{nc}          {dim}{}{nc}",
                    lf.display()
                );
            }
            if self.proxy_log_level != crate::proxy::ProxyLogLevel::None {
                eprintln!(
                    "{blue}[cplt]{nc}    Log level:     {green}{}{nc}",
                    self.proxy_log_level.as_str()
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
            let red = ui::color(ui::RED);
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
        if !self.deny_env.is_empty() {
            eprintln!(
                "{blue}[cplt]{nc}    Repo deny:     {dim}{}{nc}",
                self.deny_env.join(", ")
            );
        }
        eprintln!();

        // Command guards
        if self.gh_guard.enabled || self.git_guard.enabled {
            eprintln!("{blue}[cplt]{nc}  {dim}Command guards:{nc}");
            if self.gh_guard.enabled {
                if self.scratch_dir {
                    let policy_note = match self.gh_guard.unknown_command {
                        UnknownCommandPolicy::Block => "default-deny",
                        UnknownCommandPolicy::Allow => "permissive",
                    };
                    let mode_note = match self.gh_guard.mode {
                        EnforcementMode::Block => "",
                        EnforcementMode::Warn => " [WARN MODE]",
                        EnforcementMode::Audit => " [AUDIT MODE]",
                    };
                    eprintln!(
                        "{blue}[cplt]{nc}    gh guard:      {green}on{nc}          {dim}{policy_note}, scope_check={}{mode_note}{nc}",
                        if self.gh_guard.scope_check {
                            "on"
                        } else {
                            "off"
                        }
                    );
                } else {
                    let yellow = ui::color(ui::YELLOW);
                    eprintln!(
                        "{blue}[cplt]{nc}    gh guard:      {yellow}inactive{nc}    {dim}requires scratch_dir{nc}"
                    );
                }
            }
            if self.git_guard.enabled {
                if self.scratch_dir {
                    let mode_note = match self.git_guard.mode {
                        EnforcementMode::Block => "",
                        EnforcementMode::Warn => " [WARN MODE]",
                        EnforcementMode::Audit => " [AUDIT MODE]",
                    };
                    eprintln!(
                        "{blue}[cplt]{nc}    git guard:     {green}on{nc}          {dim}blocks git push{mode_note}{nc}"
                    );
                } else {
                    let yellow = ui::color(ui::YELLOW);
                    eprintln!(
                        "{blue}[cplt]{nc}    git guard:     {yellow}inactive{nc}    {dim}requires scratch_dir{nc}"
                    );
                }
            }
            eprintln!();
        }

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
            "{blue}[cplt]{nc}  {yellow}Tip:{nc}            {dim}use --quiet, or cplt config set sandbox.quiet true{nc}"
        );
        eprintln!("{blue}[cplt]{nc} ──────────────────────────────────────────────────────");
    }

    /// Apply per-repo config (.cplt.toml) to the resolved configuration.
    ///
    /// - `[deny]` section is applied automatically (tightens the sandbox).
    /// - `[propose]` section only applies for keys that are approved in the trust store.
    ///
    /// Approved proposals are additive — they can set boolean flags to `true` but
    /// never override an explicit `true` back to `false`. Path/port proposals extend
    /// the existing lists.
    ///
    /// Path values (`deny.paths`, `propose.allow.read/write/socket`) are
    /// resolved against `config_dir` so a relative entry can never reach the
    /// sandbox unenforced. See `resolve_repo_path`.
    ///
    /// `config_dir` must be `LoadedRepoConfig::dir` — the directory the
    /// `.cplt.toml` was actually read from — NOT the project dir. Under
    /// `--project-dir <subdir>` the two differ: the config comes from the git
    /// root, so anchoring to the subdir would emit deny rules for directories
    /// the repo never named while looking perfectly enforced.
    ///
    /// Returns a list of unapproved proposal keys (for display to the user).
    pub fn apply_repo_config(
        &mut self,
        repo_config: &crate::repo_config::RepoConfig,
        config_dir: &std::path::Path,
        approved_keys: &[&str],
    ) -> Vec<String> {
        // ── Deny section: applied automatically ──────────────────────────
        for path_str in &repo_config.deny.paths {
            let path = resolve_repo_path(path_str, config_dir);
            if !self.deny_paths.contains(&path) {
                self.deny_paths.push(path);
            }
        }
        // deny.env is stored separately — the caller must use it when building
        // the sandbox environment (strip these vars). We store them on the resolved
        // struct for that purpose.
        self.deny_env.extend(repo_config.deny.env.iter().cloned());
        self.deny_env.sort_unstable();
        self.deny_env.dedup();

        // ── Propose section: only approved keys ──────────────────
        let is_approved = |key: &str| approved_keys.contains(&key);
        let all_proposed = crate::repo_config::proposed_keys(&repo_config.propose);

        // Boolean proposals (additive: false→true only)
        if repo_config.propose.allow_localhost_any == Some(true)
            && is_approved("allow_localhost_any")
        {
            self.allow_localhost_any = true;
        }
        if repo_config.propose.allow_jvm_attach == Some(true) && is_approved("allow_jvm_attach") {
            self.allow_jvm_attach = true;
        }
        if repo_config.propose.allow_msbuild == Some(true) && is_approved("allow_msbuild") {
            self.allow_msbuild = true;
        }
        if repo_config.propose.gradle_init == Some(true) && is_approved("gradle_init") {
            self.gradle_init = true;
        }
        if repo_config.propose.allow_docker == Some(true) && is_approved("allow_docker") {
            self.allow_docker = true;
        }
        if repo_config.propose.allow_tmp_exec == Some(true) && is_approved("allow_tmp_exec") {
            self.allow_tmp_exec = true;
        }
        if repo_config.propose.allow_gpg_signing == Some(true) && is_approved("allow_gpg_signing") {
            self.allow_gpg_signing = true;
        }
        if repo_config.propose.allow_lifecycle_scripts == Some(true)
            && is_approved("allow_lifecycle_scripts")
        {
            self.allow_lifecycle_scripts = true;
        }
        if repo_config.propose.allow_browser == Some(true) && is_approved("allow_browser") {
            self.allow_browser = true;
        }
        if repo_config.propose.allow_env_files == Some(true) && is_approved("allow_env_files") {
            self.allow_env_files = true;
        }
        if repo_config.propose.gh_guard == Some(true) && is_approved("gh_guard") {
            self.gh_guard.enabled = true;
        }
        if repo_config.propose.git_push_prevention == Some(true)
            && is_approved("git_push_prevention")
        {
            self.git_guard.enabled = true;
        }

        // Path proposals
        if is_approved("allow.read") {
            for path_str in &repo_config.propose.allow.read {
                let Some(path) =
                    resolve_repo_allow_path(path_str, config_dir, "propose.allow.read")
                else {
                    continue;
                };
                if !self.allow_read.contains(&path) {
                    self.allow_read.push(path);
                }
            }
        }
        if is_approved("allow.write") {
            for path_str in &repo_config.propose.allow.write {
                let Some(path) =
                    resolve_repo_allow_path(path_str, config_dir, "propose.allow.write")
                else {
                    continue;
                };
                if !self.allow_write.contains(&path) {
                    self.allow_write.push(path);
                }
            }
        }
        if is_approved("allow.socket") {
            for path_str in &repo_config.propose.allow.socket {
                let Some(path) =
                    resolve_repo_allow_path(path_str, config_dir, "propose.allow.socket")
                else {
                    continue;
                };
                if !self.allow_socket.contains(&path) {
                    self.allow_socket.push(path);
                }
            }
        }

        // Port proposals
        if is_approved("allow.ports") {
            for &port in &repo_config.propose.allow.ports {
                if !self.allow_ports.contains(&port) {
                    self.allow_ports.push(port);
                }
            }
            self.allow_ports.sort_unstable();
            self.allow_ports.dedup();
        }
        if is_approved("allow.localhost") {
            for &port in &repo_config.propose.allow.localhost {
                if !self.allow_localhost.contains(&port) {
                    self.allow_localhost.push(port);
                }
            }
            self.allow_localhost.sort_unstable();
            self.allow_localhost.dedup();
        }

        // Proxy proposals
        if is_approved("proxy.allow_private_domains") {
            for domain in &repo_config.propose.proxy.allow_private_domains {
                let domain = crate::proxy::normalize_hostname(domain);
                // The config/CLI path rejects empty entries above; `.cplt.toml`
                // validation rejects "" but not "." or " ", which normalize to
                // the same nothing. Skip them here so the two paths agree.
                if domain.is_empty() {
                    continue;
                }
                if !self.allow_private_domains.contains(&domain) {
                    self.allow_private_domains.push(domain.clone());
                }
                self.repo_private_domains.push(domain);
            }
            self.allow_private_domains.sort_unstable();
            self.allow_private_domains.dedup();
            self.repo_private_domains.sort_unstable();
            self.repo_private_domains.dedup();
        }

        // Return unapproved keys for display
        all_proposed
            .into_iter()
            .filter(|key| !is_approved(key))
            .map(std::string::ToString::to_string)
            .collect()
    }
}

/// Resolve an approved `propose.allow.*` path, refusing one that leaves the repo.
///
/// The trust store pins a hash of the `.cplt.toml` *bytes*
/// (`trust::proposal_content_hash`), so an approval only ever vouches for what
/// those bytes name. A relative entry names a location inside the repo. Once
/// paths are resolved, a committed symlink can make that entry point anywhere —
/// `allow.read = ["data"]` with `data -> ./safe` gets approved, a later commit
/// repoints `data -> /`, and the hash is unchanged because `.cplt.toml` is
/// unchanged. The stale approval would then grant read of `/` with no re-prompt.
///
/// So: a repo-anchored allow entry may only resolve to somewhere inside the
/// repo. Escaping is refused and reported, never silently applied.
///
/// Absolute and `~/` entries are exempt: they are written literally in
/// `.cplt.toml`, so the pinned hash does cover what they name.
///
/// Deny paths deliberately get no such check — `[deny]` needs no approval and
/// can only tighten, so a repointed deny symlink cannot escalate.
fn resolve_repo_allow_path(path_str: &str, config_dir: &Path, key: &str) -> Option<PathBuf> {
    let resolved = resolve_repo_path(path_str, config_dir);
    if expand_tilde(path_str).is_relative() && !resolved.starts_with(config_dir) {
        ui::warn(&format!(
            "{key} entry {path_str:?} resolves outside the repository ({}), so cplt is ignoring it.\n  \
             A symlink target is not covered by the trust approval, so a later commit could \
             repoint it without re-approval. Name the target directly in .cplt.toml if you \
             mean to grant it.",
            resolved.display()
        ));
        return None;
    }
    Some(resolved)
}

#[cfg(test)]
mod tests {
    use super::super::types::{FeatureToggle, Preset};
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
    fn gradle_init_defaults_false_and_config_enables() {
        // Default: off (opt-in — cplt does not write tool config dirs unprompted)
        let resolved = Config::default().merge(CliFlags::default()).unwrap();
        assert!(!resolved.gradle_init);

        // Config opt-in
        let config: Config = toml::from_str("[sandbox]\ngradle_init = true\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(resolved.gradle_init);
    }

    #[test]
    fn cli_proxy_flag_overrides_config() {
        let config: Config = toml::from_str("[proxy]\nenabled = false\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                proxy: FeatureToggle::ForceOn,
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
                proxy: FeatureToggle::ForceOff,
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
    fn cli_proxy_forced_flag_overrides_config_disabled() {
        let config: Config = toml::from_str("[proxy]\nforced = false\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                proxy_forced: FeatureToggle::ForceOn,
                ..Default::default()
            })
            .unwrap();
        assert!(resolved.proxy_forced);
    }

    #[test]
    fn no_proxy_forced_flag_overrides_config_enabled() {
        let config: Config = toml::from_str("[proxy]\nforced = true\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                proxy_forced: FeatureToggle::ForceOff,
                ..Default::default()
            })
            .unwrap();
        assert!(!resolved.proxy_forced);
    }

    #[test]
    fn config_proxy_forced_used_when_no_cli_flag() {
        let config: Config = toml::from_str("[proxy]\nforced = true\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(resolved.proxy_forced);
    }

    // ── proxy.default_allowlist (#52) precedence ────────────────────────

    #[test]
    fn default_allowlist_off_by_default() {
        // Critical: no config, no flags => feature stays OFF (allow-all).
        let config: Config = toml::from_str("").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(
            !resolved.default_allowlist,
            "default must be OFF (no behaviour change)"
        );
        assert!(!resolved.allow_all_domains);
    }

    #[test]
    fn config_default_allowlist_used_when_no_cli_flag() {
        let config: Config = toml::from_str("[proxy]\ndefault_allowlist = true\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(resolved.default_allowlist);
    }

    #[test]
    fn cli_default_allowlist_overrides_config_disabled() {
        let config: Config = toml::from_str("[proxy]\ndefault_allowlist = false\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                default_allowlist: FeatureToggle::ForceOn,
                ..Default::default()
            })
            .unwrap();
        assert!(resolved.default_allowlist);
    }

    #[test]
    fn allow_all_domains_overrides_config_enabled() {
        // --allow-all-domains is the OFF side of the toggle: it wins over the
        // config default AND records the escape-hatch flag.
        let config: Config = toml::from_str("[proxy]\ndefault_allowlist = true\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                default_allowlist: FeatureToggle::from_pair(false, true),
                allow_all_domains: true,
                ..Default::default()
            })
            .unwrap();
        assert!(
            !resolved.default_allowlist,
            "--allow-all-domains must disable the default allowlist"
        );
        assert!(resolved.allow_all_domains);
    }

    #[test]
    fn proxy_forced_supersedes_allow_localhost_any() {
        // #53: proxy.forced (lock egress to proxy port) and allow_localhost_any
        // (disable kernel net restriction) are mutually exclusive. proxy.forced
        // wins: allow_localhost_any is forced off (so net restriction stays on)
        // rather than erroring, which would make proxy.forced unusable wherever
        // allow_localhost_any is set. The caller warns when this returns true.
        let config: Config =
            toml::from_str("[proxy]\nforced = true\n[sandbox]\nallow_localhost_any = true\n")
                .unwrap();
        let mut resolved = config.merge(CliFlags::default()).unwrap();
        assert!(resolved.proxy_forced);
        assert!(resolved.allow_localhost_any);
        assert!(
            resolved.reconcile_proxy_forced(),
            "must report that it superseded allow_localhost_any"
        );
        assert!(
            !resolved.allow_localhost_any,
            "allow_localhost_any must be forced off so net restriction stays on"
        );
    }

    #[test]
    fn proxy_forced_supersedes_repo_proposed_allow_localhost_any() {
        // Must supersede regardless of WHERE allow_localhost_any came from: here
        // it is enabled via an approved repo proposal, applied after merge —
        // exactly the silent-downgrade path the reconciliation must override.
        let config: Config = toml::from_str("[proxy]\nforced = true\n").unwrap();
        let mut resolved = config.merge(CliFlags::default()).unwrap();
        assert!(!resolved.reconcile_proxy_forced());
        let repo_config = crate::repo_config::RepoConfig {
            propose: crate::repo_config::ProposeSection {
                allow_localhost_any: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        resolved.apply_repo_config(
            &repo_config,
            std::path::Path::new("/nonexistent-repo"),
            &["allow_localhost_any"],
        );
        assert!(resolved.allow_localhost_any);
        assert!(resolved.reconcile_proxy_forced());
        assert!(!resolved.allow_localhost_any);
    }

    #[test]
    fn proxy_forced_alone_supersedes_nothing() {
        let config: Config = toml::from_str("[proxy]\nforced = true\n").unwrap();
        let mut resolved = config.merge(CliFlags::default()).unwrap();
        assert!(!resolved.reconcile_proxy_forced());
    }

    #[test]
    fn allow_localhost_any_alone_is_untouched() {
        let config: Config = toml::from_str("[sandbox]\nallow_localhost_any = true\n").unwrap();
        let mut resolved = config.merge(CliFlags::default()).unwrap();
        assert!(resolved.allow_localhost_any);
        assert!(!resolved.proxy_forced);
        assert!(!resolved.reconcile_proxy_forced());
        assert!(
            resolved.allow_localhost_any,
            "allow_localhost_any must be preserved when proxy.forced is off"
        );
    }

    #[test]
    fn proxy_forced_defaults_false_when_neither_flag_nor_config() {
        let config = Config::default();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(!resolved.proxy_forced);
    }

    #[test]
    fn no_proxy_forced_wins_over_proxy_forced_flag() {
        let config = Config::default();
        let resolved = config
            .merge(CliFlags {
                proxy_forced: FeatureToggle::from_pair(true, true),
                ..Default::default()
            })
            .unwrap();
        assert!(!resolved.proxy_forced);
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
        assert_eq!(resolved.proxy_port, 0);
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
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("cannot be resolved")
        );
    }

    #[test]
    fn proxy_enabled_by_default_when_no_config_or_flags() {
        let config = Config::default();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(
            resolved.with_proxy,
            "Proxy should be enabled by default — connection logging and domain filtering out of the box"
        );
    }

    #[test]
    fn sbpl_injection_rejected() {
        use crate::sandbox::validate_sbpl_path;
        let path = PathBuf::from("/tmp/evil\")(allow file-read* (subpath \"/");
        let result = validate_sbpl_path(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsafe character"));
    }

    #[test]
    fn normal_paths_pass_sbpl_validation() {
        use crate::sandbox::validate_sbpl_path;
        let path = PathBuf::from("/Users/hans/projects/my-app");
        assert!(validate_sbpl_path(&path).is_ok());
    }

    #[test]
    fn cli_allow_env_files_overrides_default() {
        let config = Config::default();
        let resolved = config
            .merge(CliFlags {
                allow_env_files: FeatureToggle::ForceOn,
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
                quiet: FeatureToggle::ForceOn,
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
                quiet: FeatureToggle::ForceOff,
                ..Default::default()
            })
            .unwrap();
        assert!(!resolved.quiet);
    }

    #[test]
    fn no_quiet_wins_over_quiet_flag() {
        let config = Config::default();
        // FeatureToggle::from_pair(true, true) → ForceOff (off wins)
        let resolved = config
            .merge(CliFlags {
                quiet: FeatureToggle::from_pair(true, true),
                ..Default::default()
            })
            .unwrap();
        assert!(!resolved.quiet, "--no-quiet should always win over --quiet");
    }

    #[test]
    fn cli_use_bubblewrap_overrides_config_disabled() {
        let config: Config = toml::from_str("[sandbox]\nuse_bubblewrap = false\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                use_bubblewrap: FeatureToggle::ForceOn,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(resolved.use_bubblewrap, Some(true));
    }

    #[test]
    fn cli_no_bubblewrap_overrides_config_enabled() {
        let config: Config = toml::from_str("[sandbox]\nuse_bubblewrap = true\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                use_bubblewrap: FeatureToggle::ForceOff,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(resolved.use_bubblewrap, Some(false));
    }

    #[test]
    fn config_use_bubblewrap_used_when_no_cli_flag() {
        let config: Config = toml::from_str("[sandbox]\nuse_bubblewrap = true\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert_eq!(
            resolved.use_bubblewrap,
            Some(true),
            "config value should be deserialized and used when no CLI flag is set"
        );
    }

    #[test]
    fn use_bubblewrap_none_when_neither_flag_nor_config() {
        let config = Config::default();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert_eq!(
            resolved.use_bubblewrap, None,
            "no flag and no config → None (auto-detect)"
        );
    }

    #[test]
    fn no_bubblewrap_wins_over_use_bubblewrap_flag() {
        let config = Config::default();
        // FeatureToggle::from_pair(true, true) → ForceOff (off wins)
        let resolved = config
            .merge(CliFlags {
                use_bubblewrap: FeatureToggle::from_pair(true, true),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            resolved.use_bubblewrap,
            Some(false),
            "--no-bubblewrap should always win over --use-bubblewrap"
        );
    }

    #[test]
    fn yes_disabled_by_default() {
        let config = Config::default();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(!resolved.yes);
    }

    #[test]
    fn config_yes_enables_auto_confirm() {
        let config: Config = toml::from_str("[sandbox]\nyes = true\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(resolved.yes);
    }

    #[test]
    fn no_yes_flag_overrides_config_yes() {
        let config: Config = toml::from_str("[sandbox]\nyes = true\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                yes: FeatureToggle::ForceOff,
                ..Default::default()
            })
            .unwrap();
        assert!(!resolved.yes);
    }

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

    /// The grant that reopens #236: `trusted_binary` refuses `PATH` so the
    /// parent's `git` can only come from a root-owned directory, and a write
    /// grant on that directory hands it straight back. Warned about, not
    /// blocked, so this asserts on the pairs the warning is built from.
    ///
    /// Driven through `grants_over_trusted_paths` with an injected resolved
    /// binary: resolving the real one would make the expectations depend on
    /// whether this machine has Homebrew.
    #[test]
    fn write_grant_over_a_trusted_bin_dir_is_reported() {
        let grants = vec![
            PathBuf::from("/opt/homebrew/bin"),
            PathBuf::from("/usr"), // ancestor: same hole, one level up
            PathBuf::from("/usr/bin/subdir"), // inside: the direct hole
        ];
        let found = grants_over_trusted_paths(&grants, &[]);
        assert!(
            found
                .iter()
                .any(|(g, dirs)| g == Path::new("/opt/homebrew/bin")
                    && dirs == &["/opt/homebrew/bin".to_string()]),
            "the exact-match grant must be reported: {found:?}"
        );
        assert!(
            found.iter().any(|(g, _)| g == Path::new("/usr")),
            "a grant on an ancestor of a trusted dir must be reported: {found:?}"
        );
        assert!(
            found.iter().any(|(g, _)| g == Path::new("/usr/bin/subdir")),
            "a grant inside a trusted dir must be reported: {found:?}"
        );
        assert_eq!(
            found.len(),
            3,
            "one row per grant, not per (grant, trusted dir) pair: {found:?}"
        );
    }

    /// One grant, many overlaps, one warning: `/` contains every trusted
    /// directory, and six copies of the same advice is how a real warning gets
    /// scrolled past.
    #[test]
    fn a_grant_over_many_trusted_dirs_is_reported_once() {
        let found = grants_over_trusted_paths(&[PathBuf::from("/")], &[]);
        assert_eq!(found.len(), 1, "one logical overlap, one row: {found:?}");
        for expected in crate::git::TRUSTED_BIN_DIRS {
            assert!(
                found[0].1.iter().any(|h| h == expected),
                "the row must name every trusted dir it swallows, missing {expected}: {found:?}"
            );
        }
        // Set-based, not `dedup`-based: `dedup` only collapses ADJACENT
        // duplicates, so asserting on it would pass if the sort were dropped.
        let unique: std::collections::BTreeSet<&String> = found[0].1.iter().collect();
        assert_eq!(
            unique.len(),
            found[0].1.len(),
            "each path named once: {found:?}"
        );
    }

    /// The F3 case: `trusted_binary` follows `/opt/homebrew/bin/git` to its
    /// target under `Cellar`, so a grant there lets the agent rewrite the file
    /// the parent executes — without ever naming a *bin* directory.
    ///
    /// Matched against the resolved binary, not the whole `/opt/homebrew` root:
    /// warning on the root would also fire on `/opt/homebrew/var`, which cannot
    /// reach the parent's git at all.
    #[test]
    fn a_write_grant_over_a_resolved_binary_is_reported() {
        let resolved = vec!["/opt/homebrew/Cellar/git/2.51.0/bin/git".to_string()];
        let found = grants_over_trusted_paths(&[PathBuf::from("/opt/homebrew/Cellar")], &resolved);
        assert_eq!(
            found.len(),
            1,
            "a grant containing the resolved binary must be reported: {found:?}"
        );
        assert!(
            found[0].1.iter().any(|h| h.contains("Cellar")),
            "the row must name the resolved binary it covers: {found:?}"
        );
    }

    /// A resolved binary that IS a trusted bin dir entry (a `git` living
    /// directly in `/usr/bin`, no symlink) puts the same string in the chain
    /// twice, non-adjacently. `dedup` alone only collapses adjacent duplicates,
    /// so this fails if the sort before it is ever dropped.
    #[test]
    fn a_path_reachable_two_ways_is_named_once() {
        let resolved = vec!["/usr/bin".to_string()];
        let found = grants_over_trusted_paths(&[PathBuf::from("/")], &resolved);
        assert_eq!(found.len(), 1);
        let hits = &found[0].1;
        assert_eq!(
            hits.iter().filter(|h| *h == "/usr/bin").count(),
            1,
            "/usr/bin arrives from both the dir list and the resolved binary, \
             and must still be named once: {hits:?}"
        );
    }

    /// The counterpart, and the reason this is matched on resolved binaries
    /// rather than on `TRUSTED_BIN_ROOTS`: a brew-managed database directory is
    /// an ordinary grant that cannot reach the parent's git.
    #[test]
    fn an_ordinary_grant_under_a_trusted_root_is_not_reported() {
        let resolved = vec!["/opt/homebrew/Cellar/git/2.51.0/bin/git".to_string()];
        for ordinary in ["/opt/homebrew/var", "/usr/local/lib/node_modules"] {
            let found = grants_over_trusted_paths(&[PathBuf::from(ordinary)], &resolved);
            assert!(
                found.is_empty(),
                "{ordinary} cannot reach the parent's binaries and must not warn: {found:?}"
            );
        }
    }

    /// The other direction, so the warning stays rare enough to be read: an
    /// ordinary build-output or cache grant must produce nothing.
    #[test]
    fn ordinary_write_grants_are_not_reported() {
        let mut resolved = Config::default().merge(CliFlags::default()).unwrap();
        resolved.allow_write = vec![
            PathBuf::from("/home/u/project/build"),
            PathBuf::from("/tmp/sandbox-out"),
            PathBuf::from("/home/u/.cache/go-build"),
            // Neither a prefix of a trusted dir nor prefixed by one: `starts_with`
            // is component-wise, so this must not match `/usr/bin`.
            PathBuf::from("/usr/binaries"),
        ];
        assert_eq!(
            resolved.write_grants_over_trusted_bins(),
            vec![],
            "an ordinary write grant must not warn"
        );
    }

    #[test]
    fn apply_repo_config_anchors_relative_paths_to_the_repo() {
        // Issue #179: relative repo-config paths were only tilde-expanded, so
        // they reached the sandbox backends unusable and unenforced —
        // `(deny file-read* (subpath "secrets"))` on macOS (compiles, matches
        // nothing) and a silent drop on Linux (`!path.is_absolute()` in
        // build_deny_masks). Every path must now come out absolute.
        let mut resolved = Config::default().merge(CliFlags::default()).unwrap();
        let repo_config = crate::repo_config::RepoConfig {
            deny: crate::repo_config::DenySection {
                paths: vec!["secrets".to_string()],
                env: vec![],
            },
            propose: crate::repo_config::ProposeSection {
                allow: crate::repo_config::ProposeAllowSection {
                    read: vec!["docs/ref".to_string()],
                    write: vec!["build/out".to_string()],
                    socket: vec!["run/app.sock".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        resolved.apply_repo_config(
            &repo_config,
            std::path::Path::new("/nonexistent-repo"),
            &["allow.read", "allow.write", "allow.socket"],
        );

        assert!(
            resolved
                .deny_paths
                .contains(&PathBuf::from("/nonexistent-repo/secrets"))
        );
        assert!(
            resolved
                .allow_read
                .contains(&PathBuf::from("/nonexistent-repo/docs/ref"))
        );
        assert!(
            resolved
                .allow_write
                .contains(&PathBuf::from("/nonexistent-repo/build/out"))
        );
        assert!(
            resolved
                .allow_socket
                .contains(&PathBuf::from("/nonexistent-repo/run/app.sock"))
        );
        // Nothing may be dropped, and nothing may stay relative.
        for path in resolved
            .deny_paths
            .iter()
            .chain(&resolved.allow_read)
            .chain(&resolved.allow_write)
            .chain(&resolved.allow_socket)
        {
            assert!(path.is_absolute(), "{} is not absolute", path.display());
        }
    }

    #[test]
    fn approved_allow_path_escaping_the_repo_is_refused() {
        // The trust store pins a hash of the `.cplt.toml` bytes, so an approval
        // only vouches for what those bytes name. A repo can commit
        // `allow.read = ["data"]` with `data -> ./safe`, get it approved, then
        // repoint `data -> /` in a later commit: `.cplt.toml` is untouched, the
        // hash still matches, and the stale approval would grant read of `/`.
        // A repo-anchored allow entry may therefore only resolve inside the repo.
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir(root.join("safe")).unwrap();
        std::os::unix::fs::symlink("safe", root.join("inside")).unwrap();
        std::os::unix::fs::symlink("/", root.join("escaped")).unwrap();

        let apply = |entry: &str| {
            let mut resolved = Config::default().merge(CliFlags::default()).unwrap();
            let repo_config = crate::repo_config::RepoConfig {
                propose: crate::repo_config::ProposeSection {
                    allow: crate::repo_config::ProposeAllowSection {
                        read: vec![entry.to_string()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            };
            resolved.apply_repo_config(&repo_config, &root, &["allow.read"]);
            resolved.allow_read
        };

        // A symlink that stays inside the repo is fine — the pinned bytes do
        // name a location in the repo, and that is where it lands.
        assert!(
            apply("inside").contains(&root.join("safe")),
            "an in-repo symlink target must still be granted"
        );
        // One that leaves the repo is refused outright, not silently narrowed.
        let escaped = apply("escaped");
        assert!(
            !escaped.iter().any(|p| p == std::path::Path::new("/")),
            "must not grant read of / : {escaped:?}"
        );
        assert!(
            escaped.iter().all(|p| p.starts_with(&root)),
            "no granted path may sit outside the repo: {escaped:?}"
        );
    }

    #[test]
    fn approved_allow_path_named_literally_is_not_repo_confined() {
        // Absolute and `~/` entries are written literally in `.cplt.toml`, so
        // the pinned hash does cover them — they are exempt from the
        // containment rule and must keep working outside the repo.
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let outside = std::fs::canonicalize(std::env::temp_dir()).unwrap();

        let mut resolved = Config::default().merge(CliFlags::default()).unwrap();
        let repo_config = crate::repo_config::RepoConfig {
            propose: crate::repo_config::ProposeSection {
                allow: crate::repo_config::ProposeAllowSection {
                    read: vec![outside.to_string_lossy().into_owned()],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        resolved.apply_repo_config(&repo_config, &root, &["allow.read"]);
        assert!(
            resolved.allow_read.contains(&outside),
            "a literally-named absolute path must still be granted"
        );
    }

    #[test]
    fn apply_repo_config_deny_always_applied() {
        let config = Config::default();
        let mut resolved = config.merge(CliFlags::default()).unwrap();

        let repo_config = crate::repo_config::RepoConfig {
            deny: crate::repo_config::DenySection {
                paths: vec!["~/secrets".to_string()],
                env: vec!["MY_SECRET".to_string(), "VAULT_TOKEN".to_string()],
            },
            ..Default::default()
        };

        // Apply with NO approved keys — deny should still work
        let unapproved = resolved.apply_repo_config(
            &repo_config,
            std::path::Path::new("/nonexistent-repo"),
            &[],
        );
        assert!(unapproved.is_empty()); // no proposals, so nothing unapproved
        assert!(
            resolved
                .deny_paths
                .iter()
                .any(|p| p.to_string_lossy().contains("secrets"))
        );
        assert!(resolved.deny_env.contains(&"MY_SECRET".to_string()));
        assert!(resolved.deny_env.contains(&"VAULT_TOKEN".to_string()));
    }

    #[test]
    fn apply_repo_config_proposals_need_approval() {
        let config = Config::default();
        let mut resolved = config.merge(CliFlags::default()).unwrap();

        let repo_config = crate::repo_config::RepoConfig {
            propose: crate::repo_config::ProposeSection {
                allow_jvm_attach: Some(true),
                allow_docker: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };

        // No keys approved
        let unapproved = resolved.apply_repo_config(
            &repo_config,
            std::path::Path::new("/nonexistent-repo"),
            &[],
        );
        assert!(!resolved.allow_jvm_attach);
        assert!(!resolved.allow_docker);
        assert_eq!(unapproved.len(), 2);
        assert!(unapproved.contains(&"allow_jvm_attach".to_string()));
        assert!(unapproved.contains(&"allow_docker".to_string()));
    }

    #[test]
    fn apply_repo_config_approved_proposals_take_effect() {
        let config = Config::default();
        let mut resolved = config.merge(CliFlags::default()).unwrap();

        let repo_config = crate::repo_config::RepoConfig {
            propose: crate::repo_config::ProposeSection {
                allow_jvm_attach: Some(true),
                allow_docker: Some(true),
                allow_localhost_any: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };

        // Only approve jvm_attach and localhost_any
        let unapproved = resolved.apply_repo_config(
            &repo_config,
            std::path::Path::new("/nonexistent-repo"),
            &["allow_jvm_attach", "allow_localhost_any"],
        );
        assert!(resolved.allow_jvm_attach);
        assert!(resolved.allow_localhost_any);
        assert!(!resolved.allow_docker); // not approved
        assert_eq!(unapproved, vec!["allow_docker"]);
    }

    #[test]
    fn apply_repo_config_gradle_init_proposal_needs_approval() {
        let repo_config = crate::repo_config::RepoConfig {
            propose: crate::repo_config::ProposeSection {
                gradle_init: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };

        // Proposed key surfaces in the trust review list
        assert_eq!(
            crate::repo_config::proposed_keys(&repo_config.propose),
            vec!["gradle_init"]
        );

        // Without approval: stays off
        let mut resolved = Config::default().merge(CliFlags::default()).unwrap();
        let unapproved = resolved.apply_repo_config(
            &repo_config,
            std::path::Path::new("/nonexistent-repo"),
            &[],
        );
        assert!(!resolved.gradle_init);
        assert_eq!(unapproved, vec!["gradle_init"]);

        // With approval: takes effect
        let mut resolved = Config::default().merge(CliFlags::default()).unwrap();
        let unapproved = resolved.apply_repo_config(
            &repo_config,
            std::path::Path::new("/nonexistent-repo"),
            &["gradle_init"],
        );
        assert!(resolved.gradle_init);
        assert!(unapproved.is_empty());
    }

    #[test]
    fn apply_repo_config_path_proposals() {
        let config = Config::default();
        let mut resolved = config.merge(CliFlags::default()).unwrap();

        let repo_config = crate::repo_config::RepoConfig {
            propose: crate::repo_config::ProposeSection {
                allow: crate::repo_config::ProposeAllowSection {
                    read: vec!["~/.gradle/gradle.properties".to_string()],
                    ports: vec![8080, 5432],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        // Approve read and ports
        let unapproved = resolved.apply_repo_config(
            &repo_config,
            std::path::Path::new("/nonexistent-repo"),
            &["allow.read", "allow.ports"],
        );
        assert!(unapproved.is_empty());
        assert!(
            resolved
                .allow_read
                .iter()
                .any(|p| p.to_string_lossy().contains("gradle.properties"))
        );
        assert!(resolved.allow_ports.contains(&8080));
        assert!(resolved.allow_ports.contains(&5432));
    }

    #[test]
    fn apply_repo_config_proxy_proposals() {
        // The global config already allows one of the proposed domains, so the
        // overlap case is the one under test: it must still be recorded as
        // repo-approved, or the proxy leaves it in the TTL cache and the first
        // config reload wipes it (#186).
        let config = Config::parse("[proxy]\nallow_private_domains = [\"intern.nav.no\"]\n")
            .expect("config parses");
        let mut resolved = config.merge(CliFlags::default()).unwrap();

        let repo_config = crate::repo_config::RepoConfig {
            propose: crate::repo_config::ProposeSection {
                proxy: crate::repo_config::ProposeProxySection {
                    allow_private_domains: vec![
                        "Intern.NAV.no".to_string(),
                        "mimir.nav.cloud.nais.io.".to_string(),
                        ".".to_string(),
                    ],
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let unapproved = resolved.apply_repo_config(
            &repo_config,
            std::path::Path::new("/nonexistent-repo"),
            &["proxy.allow_private_domains"],
        );
        assert!(unapproved.is_empty());
        assert_eq!(
            resolved.allow_private_domains,
            vec![
                "intern.nav.no".to_string(),
                "mimir.nav.cloud.nais.io".to_string()
            ]
        );
        assert_eq!(
            resolved.repo_private_domains,
            vec![
                "intern.nav.no".to_string(),
                "mimir.nav.cloud.nais.io".to_string()
            ],
            "every approved proposal is repo-approved, including one the global \
             config already allowed"
        );
    }

    // ── Policy presets (issue #59) ───────────────────────────────────
    //
    // The preset sets a BASELINE for five toggles; explicit individual
    // flags/config values override it. `standard`/no-preset is a no-op
    // baseline equal to cplt's hardcoded defaults.

    /// Snapshot of the five preset-controlled toggle values, for terse asserts.
    fn toggle_snapshot(r: &Resolved) -> (bool, bool, bool, bool, bool) {
        (
            r.allow_localhost_any,
            r.allow_env_files,
            r.allow_tmp_exec,
            r.allow_docker,
            r.allow_lifecycle_scripts,
        )
    }

    #[test]
    fn preset_strict_maps_to_all_off() {
        let resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Strict),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            toggle_snapshot(&resolved),
            (false, false, false, false, false)
        );
        assert_eq!(resolved.preset, Some(Preset::Strict));
    }

    #[test]
    fn preset_standard_maps_to_all_off() {
        let resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Standard),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            toggle_snapshot(&resolved),
            (false, false, false, false, false)
        );
        // scratch dir stays on by default — not a preset-controlled toggle.
        assert!(resolved.scratch_dir);
    }

    #[test]
    fn preset_permissive_maps_localhost_tmp_lifecycle_on() {
        let resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Permissive),
                ..Default::default()
            })
            .unwrap();
        // localhost, tmp exec, lifecycle ON; env files + docker OFF.
        assert_eq!(toggle_snapshot(&resolved), (true, false, true, false, true));
    }

    #[test]
    fn preset_full_trust_maps_to_all_on() {
        let resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::FullTrust),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(toggle_snapshot(&resolved), (true, true, true, true, true));
    }

    #[test]
    fn preset_from_name_roundtrips_canonical_names() {
        assert_eq!(Preset::from_name("strict"), Some(Preset::Strict));
        assert_eq!(Preset::from_name("standard"), Some(Preset::Standard));
        assert_eq!(Preset::from_name("permissive"), Some(Preset::Permissive));
        assert_eq!(Preset::from_name("full-trust"), Some(Preset::FullTrust));
        assert_eq!(Preset::from_name("bogus"), None);
    }

    #[test]
    fn preset_enabled_dangerous_names_matches_toggles() {
        // Safe presets enable nothing dangerous.
        assert!(Preset::Strict.enabled_dangerous_names().is_empty());
        assert!(Preset::Standard.enabled_dangerous_names().is_empty());
        // Permissive names exactly its three toggles, in display order.
        assert_eq!(
            Preset::Permissive.enabled_dangerous_names(),
            vec!["tmp-exec", "localhost-any", "lifecycle-scripts"]
        );
        // Full-trust adds docker + env-files.
        assert_eq!(
            Preset::FullTrust.enabled_dangerous_names(),
            vec![
                "tmp-exec",
                "localhost-any",
                "lifecycle-scripts",
                "docker",
                "env-files"
            ]
        );
    }

    #[test]
    fn no_preset_equals_standard_defaults() {
        // No preset must be byte-for-byte the same five toggles as `standard`
        // (and as today's hardcoded defaults) — no behavior change.
        let none = Config::default().merge(CliFlags::default()).unwrap();
        let standard = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Standard),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(toggle_snapshot(&none), (false, false, false, false, false));
        assert_eq!(toggle_snapshot(&none), toggle_snapshot(&standard));
        assert_eq!(none.preset, None);
    }

    #[test]
    fn explicit_config_value_overrides_preset() {
        // preset = permissive (tmp exec ON) but an explicit config value pins it
        // OFF → tmp exec is off, everything else follows permissive.
        let config: Config =
            toml::from_str("[sandbox]\npreset = \"permissive\"\nallow_tmp_exec = false\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(
            !resolved.allow_tmp_exec,
            "explicit config value must win over preset"
        );
        assert!(
            resolved.allow_localhost_any,
            "other permissive toggles still apply"
        );
        assert!(resolved.allow_lifecycle_scripts);
    }

    #[test]
    fn explicit_cli_flag_overrides_preset() {
        // --preset permissive --no-allow-tmp-exec → permissive-except-tmp-exec.
        let resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Permissive),
                allow_tmp_exec: FeatureToggle::ForceOff,
                ..Default::default()
            })
            .unwrap();
        assert!(
            !resolved.allow_tmp_exec,
            "explicit CLI flag must win over preset"
        );
        assert!(resolved.allow_localhost_any);
        assert!(resolved.allow_lifecycle_scripts);
    }

    #[test]
    fn cli_flag_forces_toggle_on_over_strict_preset() {
        // --preset strict --allow-docker → docker on despite the strict baseline.
        let resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Strict),
                allow_docker: FeatureToggle::ForceOn,
                ..Default::default()
            })
            .unwrap();
        assert!(resolved.allow_docker);
        assert!(!resolved.allow_tmp_exec, "other strict toggles remain off");
    }

    #[test]
    fn cli_preset_overrides_config_preset() {
        // config preset = full-trust, CLI --preset strict → strict wins.
        let config: Config = toml::from_str("[sandbox]\npreset = \"full-trust\"\n").unwrap();
        let resolved = config
            .merge(CliFlags {
                preset: Some(Preset::Strict),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            toggle_snapshot(&resolved),
            (false, false, false, false, false)
        );
        assert_eq!(resolved.preset, Some(Preset::Strict));
    }

    #[test]
    fn config_preset_applies_when_no_cli_preset() {
        let config: Config = toml::from_str("[sandbox]\npreset = \"full-trust\"\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert_eq!(toggle_snapshot(&resolved), (true, true, true, true, true));
        assert_eq!(resolved.preset, Some(Preset::FullTrust));
    }

    #[test]
    fn preset_deserialize_rejects_unknown_value() {
        let err = toml::from_str::<Config>("[sandbox]\npreset = \"yolo\"\n").unwrap_err();
        assert!(err.to_string().contains("invalid preset"), "got: {err}");
    }

    /// Snapshot of the four safety-feature values a preset can set as a
    /// baseline: (gh_guard.enabled, git_guard.enabled, proxy_forced,
    /// default_allowlist).
    fn posture_snapshot(r: &Resolved) -> (bool, bool, bool, bool) {
        (
            r.gh_guard.enabled,
            r.git_guard.enabled,
            r.proxy_forced,
            r.default_allowlist,
        )
    }

    #[test]
    fn preset_strict_enables_guards_and_forced_proxy() {
        // strict is a real posture: five toggles off, but the safety features on.
        // Full network lockdown: gh_guard + git_guard + proxy_forced +
        // fail-closed default_allowlist all on together.
        let resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Strict),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            toggle_snapshot(&resolved),
            (false, false, false, false, false)
        );
        assert_eq!(posture_snapshot(&resolved), (true, true, true, true));
        // proxy.forced (kernel egress) and default_allowlist (domain filtering)
        // are orthogonal and compose — both apply under strict.
        assert!(resolved.proxy_forced && resolved.default_allowlist);
    }

    #[test]
    fn preset_strict_enables_default_allowlist() {
        // strict's baseline flips the fail-closed domain allowlist ON — the glue
        // that turns strict into a FULL network lockdown.
        let resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Strict),
                ..Default::default()
            })
            .unwrap();
        assert!(resolved.default_allowlist);
    }

    #[test]
    fn explicit_config_default_allowlist_false_overrides_strict() {
        // Explicit `proxy.default_allowlist = false` must win over strict's
        // baseline (explicit config > preset) — opt into strict but disable the
        // allowlist.
        let config: Config =
            toml::from_str("[sandbox]\npreset = \"strict\"\n[proxy]\ndefault_allowlist = false\n")
                .unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(
            !resolved.default_allowlist,
            "explicit config false must override strict baseline"
        );
        // The rest of strict's posture is untouched.
        assert!(resolved.proxy_forced && resolved.gh_guard.enabled && resolved.git_guard.enabled);
    }

    #[test]
    fn allow_all_domains_escape_hatch_overrides_strict() {
        // `--preset strict --allow-all-domains`: the OFF side of the toggle wins
        // over strict's baseline (explicit off > preset), so the allowlist is
        // disabled while the rest of strict's lockdown stays on.
        let resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Strict),
                default_allowlist: FeatureToggle::from_pair(false, true),
                allow_all_domains: true,
                ..Default::default()
            })
            .unwrap();
        assert!(
            !resolved.default_allowlist,
            "--allow-all-domains must override strict's baseline allowlist"
        );
        assert!(resolved.allow_all_domains);
        // strict's other safety features are unaffected by the escape hatch.
        assert!(resolved.proxy_forced && resolved.gh_guard.enabled && resolved.git_guard.enabled);
    }

    #[test]
    fn preset_standard_leaves_guards_and_proxy_off() {
        let resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Standard),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(posture_snapshot(&resolved), (false, false, false, false));
    }

    #[test]
    fn preset_permissive_leaves_guards_and_proxy_off() {
        let resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Permissive),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(posture_snapshot(&resolved), (false, false, false, false));
    }

    #[test]
    fn preset_full_trust_leaves_guards_and_proxy_off() {
        // full-trust weakens the sandbox but does NOT touch the safety features.
        let resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::FullTrust),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(posture_snapshot(&resolved), (false, false, false, false));
    }

    #[test]
    fn no_preset_equals_standard_posture_defaults() {
        // The critical no-regression test: no preset must resolve EXACTLY like
        // `standard` (and today's hardcoded defaults) across every posture
        // field — guards off, forced proxy off, default allowlist off — not
        // just the five toggles.
        let none = Config::default().merge(CliFlags::default()).unwrap();
        let standard = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Standard),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(posture_snapshot(&none), (false, false, false, false));
        assert_eq!(posture_snapshot(&none), posture_snapshot(&standard));
        assert_eq!(toggle_snapshot(&none), toggle_snapshot(&standard));
        // No preset must NOT enable the fail-closed allowlist — today's behavior.
        assert!(!none.default_allowlist);
    }

    #[test]
    fn explicit_config_gh_guard_disabled_overrides_strict() {
        // preset = strict (gh_guard baseline ON) but an explicit config value
        // pins it OFF → explicit wins; git_guard + forced proxy still follow strict.
        let config: Config =
            toml::from_str("[sandbox]\npreset = \"strict\"\n[gh_guard]\nenabled = false\n")
                .unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(
            !resolved.gh_guard.enabled,
            "explicit gh_guard.enabled=false must win over strict baseline"
        );
        assert!(resolved.git_guard.enabled, "git_guard still follows strict");
        assert!(resolved.proxy_forced, "proxy.forced still follows strict");
    }

    #[test]
    fn explicit_config_git_guard_disabled_overrides_strict() {
        let config: Config =
            toml::from_str("[sandbox]\npreset = \"strict\"\n[git_guard]\nenabled = false\n")
                .unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(
            !resolved.git_guard.enabled,
            "explicit git_guard.enabled=false must win over strict baseline"
        );
        assert!(resolved.gh_guard.enabled);
        assert!(resolved.proxy_forced);
    }

    #[test]
    fn explicit_config_proxy_forced_disabled_overrides_strict() {
        let config: Config =
            toml::from_str("[sandbox]\npreset = \"strict\"\n[proxy]\nforced = false\n").unwrap();
        let resolved = config.merge(CliFlags::default()).unwrap();
        assert!(
            !resolved.proxy_forced,
            "explicit proxy.forced=false must win over strict baseline"
        );
        assert!(resolved.gh_guard.enabled);
        assert!(resolved.git_guard.enabled);
    }

    #[test]
    fn strict_preset_plus_allow_localhost_any_reconciles_off() {
        // #53 interaction: --preset strict turns proxy.forced ON (baseline);
        // an explicit --allow-localhost-any turns that toggle ON (CLI wins over
        // baseline). The two are mutually exclusive, so reconcile forces
        // allow_localhost_any back off (with the caller warning) — proxy.forced
        // wins and kernel egress stays locked.
        let mut resolved = Config::default()
            .merge(CliFlags {
                preset: Some(Preset::Strict),
                allow_localhost_any: FeatureToggle::ForceOn,
                ..Default::default()
            })
            .unwrap();
        assert!(resolved.proxy_forced, "strict forces the proxy");
        assert!(
            resolved.allow_localhost_any,
            "explicit flag set it on first"
        );
        assert!(
            resolved.reconcile_proxy_forced(),
            "reconcile must report it superseded allow_localhost_any"
        );
        assert!(
            !resolved.allow_localhost_any,
            "proxy.forced wins: localhost-any forced off"
        );
    }
}
