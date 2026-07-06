//! Config file loading, parsing, and CLI-flag merging.

use std::path::PathBuf;

use super::error::ConfigError;
use super::path::{config_path, expand_tilde, resolve_config_path};
use super::types::{
    CliFlags, Config, EnforcementMode, GhGuardPolicy, GitGuardPolicy, LoadedConfig, Resolved,
    ResolvedPushRule, UnknownCommandPolicy,
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
                "{} — ignored ({})",
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
        // Proxy: FeatureToggle resolves --with-proxy/--no-proxy against config default (true).
        let with_proxy = cli.proxy.resolve(self.proxy.enabled.unwrap_or(true));

        // Proxy-forced: FeatureToggle resolves --proxy-forced/--no-proxy-forced
        // against config default (false). When true, the proxy is mandatory and
        // kernel egress is locked to the proxy port (#53). Orchestration in main.rs
        // enforces proxy-on + fail-closed; the conflict with an explicitly disabled
        // proxy is reported there.
        let proxy_forced = cli.proxy_forced.resolve(self.proxy.forced.unwrap_or(false));

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

        // Allow private domains: merge CLI + config list, sort+dedup.
        // Validates that entries are non-empty (empty string would bypass private IP
        // check for all domains that match is_domain_match("", _), which is none — but
        // reject it anyway for clarity).
        let mut allow_private_domains =
            self.proxy.allow_private_domains.clone().unwrap_or_default();
        allow_private_domains.extend(cli.allow_private_domains);
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

        // Allow-docker: CLI flag wins, then config, then false (blocked by default)
        let allow_docker = if cli.allow_docker {
            true
        } else {
            self.sandbox.allow_docker.unwrap_or(false)
        };

        // Allow-tmp-exec: CLI flag wins, then config, then false (blocked by default)
        let allow_tmp_exec = if cli.allow_tmp_exec {
            true
        } else {
            self.sandbox.allow_tmp_exec.unwrap_or(false)
        };

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

        // Yes: FeatureToggle resolves --yes/--no-yes (default: off)
        let yes = cli.yes.resolve(self.sandbox.yes.unwrap_or(false));

        // gh-guard: CLI flag overrides enabled; sub-options come from [gh_proxy] config.
        // Backward compat: old `sandbox.gh_proxy = true` is treated as `gh_guard.enabled = true`.
        let gh_guard_enabled_default = self
            .gh_guard
            .enabled
            .or(self.sandbox.gh_proxy)
            .unwrap_or(false);
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
        let git_guard_enabled_default = self
            .git_guard
            .enabled
            .or(self.sandbox.git_push_prevention)
            .unwrap_or(false);
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
            proxy_forced,
            proxy_port,
            blocked_domains,
            allowed_domains,
            proxy_log_file,
            proxy_log_level,
            proxy_timeout,
            proxy_upstream,
            proxy_upstream_no_proxy,
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
            allow_docker,
            allow_tmp_exec,
            allow_cache_exec,
            allow_cache_exec_any,
            allow_browser,
            scratch_dir,
            use_bubblewrap,
            quiet,
            yes,
            gh_guard,
            git_guard,
            agent: self.sandbox.agent.clone(),
            deny_env: Vec::new(),
        })
    }
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
            eprintln!(
                "{blue}[cplt]{nc}    Keychain:      {green}allowed{nc}     {dim}~/Library/Keychains{nc}"
            );
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
            "{blue}[cplt]{nc}  {yellow}Tip:{nc}            {dim}use --quiet or: cplt config set sandbox.quiet true{nc}"
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
    /// Returns a list of unapproved proposal keys (for display to the user).
    pub fn apply_repo_config(
        &mut self,
        repo_config: &crate::repo_config::RepoConfig,
        approved_keys: &[&str],
    ) -> Vec<String> {
        // ── Deny section: applied automatically ──────────────────────────
        for path_str in &repo_config.deny.paths {
            let path = expand_tilde(path_str);
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
                let path = expand_tilde(path_str);
                if !self.allow_read.contains(&path) {
                    self.allow_read.push(path);
                }
            }
        }
        if is_approved("allow.write") {
            for path_str in &repo_config.propose.allow.write {
                let path = expand_tilde(path_str);
                if !self.allow_write.contains(&path) {
                    self.allow_write.push(path);
                }
            }
        }
        if is_approved("allow.socket") {
            for path_str in &repo_config.propose.allow.socket {
                let path = expand_tilde(path_str);
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
                if !self.allow_private_domains.contains(domain) {
                    self.allow_private_domains.push(domain.clone());
                }
            }
            self.allow_private_domains.sort_unstable();
            self.allow_private_domains.dedup();
        }

        // Return unapproved keys for display
        all_proposed
            .into_iter()
            .filter(|key| !is_approved(key))
            .map(std::string::ToString::to_string)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::FeatureToggle;
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
        resolved.apply_repo_config(&repo_config, &["allow_localhost_any"]);
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
        let unapproved = resolved.apply_repo_config(&repo_config, &[]);
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
        let unapproved = resolved.apply_repo_config(&repo_config, &[]);
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
        let unapproved =
            resolved.apply_repo_config(&repo_config, &["allow_jvm_attach", "allow_localhost_any"]);
        assert!(resolved.allow_jvm_attach);
        assert!(resolved.allow_localhost_any);
        assert!(!resolved.allow_docker); // not approved
        assert_eq!(unapproved, vec!["allow_docker"]);
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
        let unapproved = resolved.apply_repo_config(&repo_config, &["allow.read", "allow.ports"]);
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
        let config = Config::default();
        let mut resolved = config.merge(CliFlags::default()).unwrap();

        let repo_config = crate::repo_config::RepoConfig {
            propose: crate::repo_config::ProposeSection {
                proxy: crate::repo_config::ProposeProxySection {
                    allow_private_domains: vec!["intern.nav.no".to_string()],
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let unapproved = resolved.apply_repo_config(&repo_config, &["proxy.allow_private_domains"]);
        assert!(unapproved.is_empty());
        assert!(
            resolved
                .allow_private_domains
                .contains(&"intern.nav.no".to_string())
        );
    }
}
