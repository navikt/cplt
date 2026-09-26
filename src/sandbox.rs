//! Sandbox profile generation, environment hardening, and execution.
//!
//! # Architecture
//!
//! The sandbox uses different kernel enforcement mechanisms per platform:
//! - **macOS**: Seatbelt/SBPL via `sandbox-exec`
//! - **Linux**: Landlock LSM + seccomp-BPF, optionally wrapped in Bubblewrap
//!   namespace isolation (see `bubblewrap` module for the layering)
//!
//! The public API is platform-agnostic:
//! - [`prepare()`] validates configuration and compiles it into a [`PreparedSandbox`]
//! - [`describe()`] returns a human-readable representation of the policy
//! - [`preflight()`] verifies the sandbox mechanism works on this system
//! - [`exec_sandboxed()`] runs a command inside the sandbox
//!
//! Platform-specific details are handled by internal modules:
//! - `profile`: SBPL profile generation (macOS — also compiled cross-platform for testing)
//! - `exec`: sandbox-exec (macOS) / Landlock+seccomp (Linux) invocation
//! - `landlock_mod`: Landlock rule generation (cross-platform) and application (Linux)
//! - `bubblewrap`: optional namespace isolation layer (Linux only)
//!
//! # Submodule layout
//!
//! Submodules use `#[path]` because the sandbox blocks directory creation.
//! To reorganize to standard `src/sandbox/mod.rs` layout, move the files
//! into `src/sandbox/` and remove the `#[path]` attributes.

use std::path::{Path, PathBuf};

use crate::agent::{Agent, AgentDir};
#[cfg(target_os = "linux")]
use crate::ui;

#[cfg(target_os = "linux")]
#[path = "sandbox_bubblewrap.rs"]
mod bubblewrap;
/// The bounded nested-repository walk, shared with the session-end `.git`
/// check in `audit` (#576) so both look at the same set.
pub(crate) use policy::{NESTED_SCAN_LIMIT, WalkExtras, has_dot_git_or_is_bare, repo_walk};
#[path = "sandbox_env.rs"]
mod env;

/// The two bubblewrap probes `cplt doctor` reports from — the same trusted
/// lookup and the same `bwrap … /bin/true` the launch runs, against an empty
/// rule set, so "installed" and "usable" stay two different answers.
#[cfg(target_os = "linux")]
pub(crate) mod bubblewrap_probe {
    pub(crate) use super::bubblewrap::check_availability;

    pub(crate) fn test_empty(bwrap: &std::path::Path) -> Result<(), String> {
        super::bubblewrap::test_functionality(
            bwrap,
            &[],
            super::bubblewrap::Overlays::default(),
            &super::bubblewrap::DenyMasks::default(),
        )
    }
}
#[path = "sandbox_exec.rs"]
mod exec;
#[path = "sandbox_landlock.rs"]
pub(crate) mod landlock_mod;
#[path = "sandbox_policy.rs"]
mod policy;
#[path = "sandbox_profile.rs"]
mod profile;

// ── Re-exports: shared policy types and constants ──────────────
//
// These are platform-agnostic and used by tests, discover, config, etc.

pub use policy::{
    AppDir, AppDirKind, BUILD_CREDENTIAL_FILES, CacheEnv, DENIED_DOTFILES, DENIED_FILES,
    DENIED_HOME_SUBPATHS, ENV_ALLOWLIST, ENV_PREFIX_ALLOWLIST, EXEC_IN_WRITABLE, ExecInWritable,
    HARDENING_ENV_VARS, HOME_TOOL_DIRS, HardeningCategory, HardeningEnvVar, HomeToolDir,
    LinuxCoverage, PLAYWRIGHT_SOCKET_BASE_MAX_BYTES, PLAYWRIGHT_SOCKET_DIR_PREFIX,
    PLAYWRIGHT_SOCKET_PATH_LIMIT, PLAYWRIGHT_SOCKET_ROOT, PLAYWRIGHT_SOCKET_WORST_CASE_SUFFIX,
    PROTECTED_IN_GITDIR, PROTECTED_IN_ROOT, PathBinDir, Protected, ResolvedToolDir,
    SENSITIVE_PROJECT_PATTERNS, TOOL_PATH_ENV_VARS, ToolPathEnvVar, ToolPathOverride, ToolRoot,
    active_tool_dirs, app_dirs, build_credential_grants, copilot_default_pkg_dir, copilot_pkg_dir,
    copilot_pkg_dirs, copilot_ro_protect_paths, credential_link_hop, current_uid,
    cypress_app_data_dir, cypress_app_data_dir_with_env, cypress_runtime_intent,
    exec_write_conflicts, home_config_link_targets, home_tool_dirs, linux_docker_socket_paths,
    linux_runtime_dirs, mise_ro_protect_paths, nested_alternation, no_cache_env, path_bin_dirs,
    playwright_runtime_intent, process_env, relocatable_tool_prefix, shim_ro_protect_paths,
    socket_mask_paths, tool_override_path_is_safe, tool_path_env_overrides,
    validate_playwright_socket_dir, validate_sbpl_path, xdg_cache_dir, xdg_cache_dir_with_env,
    xdg_runtime_dir_env,
};

// SBPL profile generation — kept public for unit tests.
// The SBPL module is pure string manipulation with no macOS dependencies,
// so tests run cross-platform even though the output is macOS-specific.
pub use profile::{generate_profile, generate_profile_with_playwright_socket_dir};

// Environment construction — already platform-agnostic.
pub use env::{
    SandboxEnv, build_sandbox_env, copilot_sandbox_support_overridden, npmrc_explicitly_allowed,
    npmrc_userconfig_override, npmrc_userconfig_stale_variants, playwright_mcp_sandbox_disabled,
    playwright_sockets_dir_override,
};

// The in-process PATH lookup. Re-exported (rather than opening the whole `exec`
// module) for `discover::which_resolved`, which must not spawn `which`.
pub(crate) use exec::which_binary;

// Landlock policy types — cross-platform for testing.
pub use landlock_mod::{
    FsAccess, FsRule, LandlockPolicy, NetRule, blocked_syscall_names, describe_policy,
    generate_policy,
};
// Kernel capability probe — used by integration tests (securityfs is
// root-only on some hosts, so tests cannot read abi_version from there).
#[cfg(target_os = "linux")]
pub use landlock_mod::available_abi_version;

// ── Platform-agnostic sandbox API ──────────────────────────────

/// Platform-agnostic sandbox configuration.
///
/// Captures all policy decisions (filesystem access, network ports,
/// tool directories, scratch dir) needed to construct a sandbox.
/// Use [`prepare()`] to validate and compile this into a
/// platform-specific [`PreparedSandbox`].
///
/// This struct borrows all data from the caller — no allocations needed
/// to construct it. Owned copies are made inside [`prepare()`] for the
/// fields that [`PreparedSandbox`] needs at execution time.
pub struct SandboxConfig<'a> {
    pub project_dir: &'a Path,
    /// Repositories named with `--repo-dir` / `sandbox.repo_dirs`.
    ///
    /// Project-grade roots: read, write and execute, with the same protected
    /// paths as the project directory. That is what distinguishes them from an
    /// `allow.write` grant, which is deliberately non-executable (#319) — a
    /// repository the user named is a place to build and test, exactly as the
    /// project directory is.
    ///
    /// A root nested inside `project_dir` already inherits the project grant,
    /// so naming it adds no file access; listing it here is still load-bearing,
    /// because the protected-path tables and the bubblewrap read-only binds are
    /// emitted per root and a nested repository's `.git` was covered only by
    /// the macOS-only nested regex before.
    pub named_roots: &'a [PathBuf],
    /// The real `.git` of each named root whose repository data does NOT live
    /// at `<root>/.git` — a linked worktree, a bare checkout, or a root that
    /// points inside a repository.
    ///
    /// Granted read+write for the same reason [`Self::git_common_dir`] is for
    /// the project: without it `git status` in that root fails with `not a git
    /// repository`, because the tree is reachable and the directory holding its
    /// objects and refs is not. Resolved parent-side by
    /// [`crate::sandbox::named_root_git_dirs`], so a surface that builds a
    /// policy cannot forget it (#447).
    pub named_root_git_dirs: &'a [PathBuf],
    /// The managed worktree root (#531), also present in `named_roots`.
    /// `Some` adds the macOS pins that only matter with the key on: the root's
    /// name, and each `<gitdir>/worktrees/<name>/commondir` against rewrite.
    pub managed_worktree_root: Option<&'a Path>,
    pub home_dir: &'a Path,
    pub extra_read: &'a [PathBuf],
    pub extra_write: &'a [PathBuf],
    /// Trees the agent may execute binaries from (`allow.exec` / `--allow-exec`).
    /// Read + execute, never write; see [`validate_exec_grants`].
    pub extra_exec: &'a [PathBuf],
    pub extra_socket: &'a [PathBuf],
    pub extra_deny: &'a [PathBuf],
    /// If `Some`, only include these home tool dirs (tighter profile via discovery,
    /// with relocated tool homes such as `CARGO_HOME` already resolved).
    /// If `None`, all known home tool dirs are included at their defaults.
    pub existing_home_tool_dirs: Option<&'a [ResolvedToolDir]>,
    /// If `Some`, only include these app dirs (tighter profile via discovery).
    /// If `None`, all known app dirs are included.
    pub existing_app_dirs: Option<&'a [String]>,
    pub extra_ports: &'a [u16],
    pub localhost_ports: &'a [u16],
    pub proxy_port: Option<u16>,
    /// Force all egress through the proxy: restrict kernel-level egress to the
    /// proxy port only, dropping the default `*:443` allowance (#53). Consumed
    /// by the Landlock net-rule builder.
    pub proxy_forced: bool,
    pub allow_env_files: bool,
    pub allow_localhost_any: bool,
    pub scratch_dir: Option<&'a Path>,
    /// Validated cplt-owned macOS directory for Playwright control sockets.
    /// Always `None` on non-macOS platforms and for caller-owned overrides.
    pub playwright_socket_dir: Option<&'a Path>,
    pub allow_tmp_exec: bool,
    /// Copilot CLI package directory (resolved from the binary location).
    pub copilot_install_dir: Option<&'a Path>,
    /// Where the Copilot cache variables are read from (#374):
    /// [`process_env`] for a real launch, [`no_cache_env`] for a policy that
    /// should cover only the default SEA cache.
    pub copilot_cache_env: &'a CacheEnv<'a>,
    /// JAVA_HOME directory — grants JDK read + dylib loading.
    pub java_home: Option<&'a Path>,
    /// DOTNET_ROOT directory — grants .NET SDK read + dylib loading.
    pub dotnet_root: Option<&'a Path>,
    /// Global git hooks directory from `core.hooksPath`.
    pub git_hooks_path: Option<&'a Path>,
    /// Shared .git directory for git worktrees.
    pub git_common_dir: Option<&'a Path>,
    /// `AGENTS.md` at the repository root when `--project-dir` is a
    /// subdirectory and `sandbox.agents_md` is on (#252). cplt writes its
    /// managed block there, and the project grant does not reach it, so both
    /// backends grant read on this one file — never write, never the root.
    /// `None` when the file is inside `project_dir` already.
    pub root_agents_md: Option<&'a Path>,
    pub allow_gpg_signing: bool,
    pub deny_clipboard: bool,
    /// `sandbox.deny_nested_git` (#576): deny creating a `.git` entry below a
    /// writable root. macOS only; Linux has no way to express it.
    pub deny_nested_git: bool,
    /// `sandbox.deny_copilot_dir_exec` (#324). The grant itself is withdrawn
    /// in `agent_dirs` before this config is built; the flag is here so the
    /// Linux launch can warn about what Landlock unions back in.
    pub deny_copilot_dir_exec: bool,
    /// Allow JVM Attach API unix sockets in /tmp (.java_pid* pattern only).
    pub allow_jvm_attach: bool,
    /// Allow MSBuild worker-node unix sockets in /tmp (MSBuild<pid> pattern only).
    pub allow_msbuild: bool,
    /// Allow Docker/Colima/OrbStack access (daemon socket + ~/.docker read).
    pub allow_docker: bool,
    /// Electron app bundle Contents directory (macOS only, ignored on Linux).
    pub electron_app_dir: Option<&'a Path>,
    /// Which AI coding agent is being sandboxed.
    pub agent: Agent,
    /// Agent-specific directories that need sandbox access.
    pub agent_dirs: &'a [AgentDir],
    /// Specific ~/Library/Caches subdirs where process-exec is allowed.
    pub allow_cache_exec: &'a [String],
    /// Allow process-exec from all of ~/Library/Caches.
    pub allow_cache_exec_any: bool,
    /// Let the sandboxed agent launch ANY application outside the sandbox.
    ///
    /// Granted for OAuth code flows, but Launch Services starts the target
    /// through launchd, outside the Seatbelt profile. Cannot be scoped: SBPL's
    /// `lsopen` takes no filter, and LSOpenCFURLRef() reaches it without the
    /// `open` binary (#251).
    pub allow_browser: bool,
    /// The credential this agent can use *instead of* the login Keychain, if
    /// any (#242). `Some` drops the Keychain grant from the profile and, for an
    /// env-var substitute, forwards that variable into the sandbox — those two
    /// derive from this one field so they cannot disagree. `None` keeps the
    /// grant and forwards nothing extra. Inert on Linux.
    pub keychain_substitute: Option<crate::agent::KeychainSubstitute>,
    /// Use Bubblewrap for namespace isolation (Linux only).
    /// - `Some(true)`: Always use bwrap (fail if unavailable)
    /// - `Some(false)`: Never use bwrap (Landlock+seccomp only)
    /// - `None`: Auto-detect and use if available (graceful degradation)
    pub use_bubblewrap: Option<bool>,
}

/// A validated, platform-specific sandbox ready for execution.
///
/// Created by [`prepare()`]. On macOS this contains the compiled SBPL
/// profile text. On Linux it contains the Landlock ruleset configuration.
///
/// Use [`describe()`] for a human-readable representation,
/// [`preflight()`] to verify the mechanism works, and
/// [`exec_sandboxed()`] to run a command inside the sandbox.
pub struct PreparedSandbox {
    project_dir: PathBuf,
    home_dir: PathBuf,
    /// macOS: SBPL profile text.
    /// Linux: human-readable Landlock policy summary.
    profile_text: String,
    scratch_dir: Option<PathBuf>,
    pnpm_shadow_dir: Option<PathBuf>,
    /// Exact automatic Playwright socket base authorized by the macOS profile.
    playwright_socket_dir: Option<PathBuf>,
    /// Explicit `ms-playwright` opt-in, the same intent that gates the browser
    /// runtime rules. Chromium cannot nest its own sandbox inside cplt's, so
    /// this also turns off Playwright MCP's nested sandbox for the child.
    playwright_runtime: bool,
    proxy_port: Option<u16>,
    agent: Agent,
    /// Specific localhost ports the user has explicitly opened.
    allow_localhost: Vec<u16>,
    /// Whether all localhost ports are open (`--allow-localhost-any`).
    allow_localhost_any: bool,
    /// Whether the user explicitly re-allowed `$HOME/.npmrc` via `allow.read`.
    /// Suppresses the `NPM_CONFIG_USERCONFIG` redirect (see #180).
    npmrc_allowed: bool,
    /// The credential forwarded into the sandbox in place of the Keychain
    /// grant, if any (#242). `None` on every run where the trade did not apply.
    pub(crate) keychain_substitute: Option<crate::agent::KeychainSubstitute>,
    /// Exported to the child as `CPLT_WORKTREE_ROOT` (#531). Set by the
    /// launcher with [`Self::set_worktree_root`] after `prepare`; the grant
    /// itself comes from `SandboxConfig::named_roots`.
    worktree_root: Option<PathBuf>,
    /// Landlock + seccomp pre-computed sandbox data (Linux only).
    /// Built in the parent process; applied in pre_exec.
    #[cfg(target_os = "linux")]
    precomputed: landlock_mod::PrecomputedSandbox,
    /// Bubblewrap execution wrapper (Linux only).
    /// If Some, bwrap is used to wrap the execution.
    #[cfg(target_os = "linux")]
    bwrap_wrapper: Option<bubblewrap::BubblewrapWrapper>,
}

impl PreparedSandbox {
    /// The project directory this sandbox is configured for.
    pub fn project_dir(&self) -> &Path {
        &self.project_dir
    }

    /// The home directory this sandbox is configured for.
    pub fn home_dir(&self) -> &Path {
        &self.home_dir
    }

    /// What stands in for the Keychain grant this run, for the startup summary.
    pub fn keychain_substitute(&self) -> Option<&crate::agent::KeychainSubstitute> {
        self.keychain_substitute.as_ref()
    }

    /// Name the managed worktree root to the child as `CPLT_WORKTREE_ROOT`.
    ///
    /// Environment only: the root must already be among the policy's named
    /// roots, or the variable would name a directory the agent cannot use.
    pub fn set_worktree_root(&mut self, root: Option<&Path>) {
        self.worktree_root = root.map(Path::to_path_buf);
    }

    /// Withdraw the read grant on the root `AGENTS.md` (#252).
    ///
    /// The grant is built before cplt writes the managed block, so it assumes
    /// the write will land. When it did not (ambiguous markers, a failed
    /// write), the file holds nothing cplt put there and the agent has no
    /// reason to read outside its project, so the launch drops the grant.
    pub fn revoke_root_agents_md(&mut self, file: &Path) {
        // The macOS profile is the enforced text itself; the Linux text is the
        // `describe()` summary, kept in step with the rules removed below.
        #[cfg(target_os = "macos")]
        let chunk = profile::root_agents_md_sbpl(file);
        #[cfg(target_os = "linux")]
        let chunk = landlock_mod::root_agents_md_description(file);
        // A refused path (`grant_is_refused`) was never emitted: nothing to
        // withdraw. On Linux the rule index is the truth, since the text may
        // already omit a grant bubblewrap does not give.
        #[cfg(target_os = "macos")]
        if !self.profile_text.contains(&chunk) {
            return;
        }
        #[cfg(target_os = "linux")]
        if self.precomputed.deferred_plain_file.take().is_none() {
            return;
        }
        self.profile_text = self.profile_text.replacen(&chunk, "", 1);
        #[cfg(target_os = "linux")]
        {
            if let Some(w) = &mut self.bwrap_wrapper
                && let Some(i) = w.plain_file.take()
            {
                w.fs_rules.remove(i);
            }
        }
    }
}

/// Validate configuration and compile it into a platform-specific sandbox.
///
/// On macOS, this generates an SBPL profile and validates all paths for
/// SBPL injection safety. On Linux, this builds a Landlock policy.
///
/// Returns an error if:
/// - A path contains characters that could cause profile injection (macOS)
/// - A Playwright socket directory is supplied on a non-macOS platform
/// - The platform does not support sandboxing
pub fn prepare(config: &SandboxConfig) -> Result<PreparedSandbox, String> {
    prepare_with_pnpm_shadow(config, None, false)
}

/// Validate and compile a sandbox with a cplt-owned pnpm shadow.
///
/// `inspect_only` is for callers that print or check the policy and never
/// launch it (`--print-profile`, `cplt check`): it keeps prepare from writing
/// to the host, and the profile lists what a launch would create instead.
pub fn prepare_with_pnpm_shadow(
    config: &SandboxConfig,
    pnpm_shadow_dir: Option<&Path>,
    inspect_only: bool,
) -> Result<PreparedSandbox, String> {
    validate_playwright_socket_capability(config.playwright_socket_dir)?;
    validate_hard_denied_grants(config)?;
    validate_pnpm_tool_dirs(config)?;
    validate_cache_exec_dirs(config)?;
    validate_exec_grants(config)?;
    prepare_cypress_app_data(config, inspect_only)?;
    validate_copilot_cache_env(config)?;
    if !inspect_only {
        create_default_copilot_pkg_dir(config)?;
    }
    if let Some(shadow) = pnpm_shadow_dir
        && !config.extra_exec.iter().any(|path| path == shadow)
    {
        return Err(format!(
            "pnpm shadow {} is not present in the executable grants",
            shadow.display()
        ));
    }
    // The named roots' resolved gitdirs join the write grants' here: they are
    // granted (see `named_root_git_dirs`) and therefore need the same
    // persistence denies and the same bubblewrap read-only binds.
    let mut git_dirs = extra_git_dirs(config.extra_write);
    for dir in config.named_root_git_dirs {
        if !git_dirs.contains(dir) {
            git_dirs.push(dir.clone());
        }
    }
    git_dirs.sort();
    git_dirs.dedup();
    prepare_impl(config, &git_dirs, pnpm_shadow_dir, inspect_only)
}

fn validate_pnpm_tool_dirs(config: &SandboxConfig) -> Result<(), String> {
    let tool_dirs = policy::active_tool_dirs(config.home_dir, config.existing_home_tool_dirs);
    for package_store in tool_dirs.iter().filter(|dir| {
        Path::new(dir.dir.path)
            .file_name()
            .is_some_and(|name| name == "package-manager-store")
    }) {
        let resolved = crate::config::canonicalize_deepest(&package_store.path);
        let expected = package_store
            .path
            .strip_prefix(config.home_dir)
            .map_or_else(
                |_| package_store.path.clone(),
                |relative| crate::config::canonicalize_deepest(config.home_dir).join(relative),
            );
        if resolved != expected {
            return Err(format!(
                "pnpm package-manager-store {} resolves through a symlink to {}. \
                 cplt refuses a writable executable store whose target differs from its \
                 configured path.",
                package_store.path.display(),
                resolved.display()
            ));
        }
        for writable in tool_dirs
            .iter()
            .filter(|dir| dir.dir.write && dir.path != package_store.path)
        {
            if package_store.path.starts_with(&writable.path)
                || writable.path.starts_with(&package_store.path)
            {
                return Err(format!(
                    "pnpm package-manager-store {} overlaps writable tool directory {}. \
                     A nested writable executable store would let the agent drop and run \
                     a binary; move PNPM_HOME outside writable cache trees.",
                    package_store.path.display(),
                    writable.path.display()
                ));
            }
        }
    }
    Ok(())
}

/// Refuse cache-exec entries that resolve outside their configured cache path.
///
/// Landlock opens each entry with `O_PATH`, which follows symlinks and grants
/// the target read, write, and execute. A link planted during one session must
/// therefore stop the next launch instead of turning a narrow cache opt-in into
/// permissions on an arbitrary target.
fn validate_cache_exec_dirs(config: &SandboxConfig) -> Result<(), String> {
    if config.allow_cache_exec.is_empty() && !config.allow_cache_exec_any {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    let cache_base = config.home_dir.join("Library/Caches");
    #[cfg(not(target_os = "macos"))]
    let cache_base = policy::xdg_cache_dir_with_env(config.home_dir, config.copilot_cache_env);

    let expected_base = if let Ok(relative) = cache_base.strip_prefix(config.home_dir) {
        std::fs::canonicalize(config.home_dir)
            .map_err(|e| format!("Cannot resolve HOME {}: {e}", config.home_dir.display()))?
            .join(relative)
    } else {
        cache_base.clone()
    };
    let resolved_base = crate::config::canonicalize_deepest(&cache_base);
    if resolved_base != expected_base {
        return Err(format!(
            "Cache-exec root {} resolves through a symlink to {}. cplt refuses to grant \
             writable executable cache access through a redirected root. Replace the symlink \
             with a real directory.",
            cache_base.display(),
            resolved_base.display()
        ));
    }
    if !policy::tool_override_path_is_safe(&resolved_base, config.home_dir) {
        return Err(format!(
            "Cache-exec root {} is not a safe cache directory. It cannot be `/`, `/tmp`, \
             `$HOME`, an ancestor of `$HOME`, or a platform system directory.",
            cache_base.display()
        ));
    }

    for subdir in config.allow_cache_exec {
        if !policy::cache_exec_subdir_is_safe(subdir) {
            return Err(format!(
                "allow_cache_exec subdir {subdir:?} must be a non-empty relative cache path \
                 without `.` or `..` components"
            ));
        }
        let named = cache_base.join(subdir);
        let expected = resolved_base.join(subdir);
        let resolved = crate::config::canonicalize_deepest(&named);
        if resolved != expected {
            return Err(format!(
                "allow_cache_exec path {} resolves through a symlink to {}. cplt refuses a \
                 writable executable cache whose target differs from its configured path. \
                 Replace the symlink with a real directory.",
                named.display(),
                resolved.display()
            ));
        }
    }
    Ok(())
}

/// Validate Cypress's persistent state before either backend grants it write.
///
/// Landlock follows symlinks and unions rules, so a link into any executable
/// tree would turn the state grant into write+execute. Creating the fixed path
/// here also ensures Bubblewrap sees it while constructing writable bind mounts.
fn prepare_cypress_app_data(config: &SandboxConfig, inspect_only: bool) -> Result<(), String> {
    if !policy::cypress_runtime_intent(config.allow_cache_exec, config.allow_cache_exec_any) {
        return Ok(());
    }

    let named = policy::cypress_app_data_dir_with_env(config.home_dir, config.copilot_cache_env);
    let expected = if let Ok(relative) = named.strip_prefix(config.home_dir) {
        std::fs::canonicalize(config.home_dir)
            .map_err(|e| format!("Cannot resolve HOME {}: {e}", config.home_dir.display()))?
            .join(relative)
    } else {
        named.clone()
    };
    let resolved = crate::config::canonicalize_deepest(&named);
    if resolved != expected {
        return Err(format!(
            "Cypress app state {} resolves through a symlink to {}. cplt refuses to grant \
             persistent write access where another rule may also grant execution. Replace the \
             symlink with a real directory.",
            named.display(),
            resolved.display()
        ));
    }

    let parent = resolved
        .parent()
        .expect("Cypress app state must have a parent");
    for (writable, source) in canonical_writable_trees(config) {
        if parent.starts_with(&writable) {
            return Err(format!(
                "Cypress app state parent {} is inside {source} {}. A sandboxed process could \
                 replace the state directory with a symlink after validation and combine its \
                 write grant with execution elsewhere. Narrow the writable path so it does not \
                 include Cypress's application-support parent.",
                parent.display(),
                writable.display()
            ));
        }
    }

    let mut executable: Vec<PathBuf> = landlock_mod::generate_policy(config)
        .fs_rules
        .into_iter()
        .filter(|rule| rule.access.execute)
        .map(|rule| rule.path)
        .collect();
    executable.extend(config.electron_app_dir.map(Path::to_path_buf));

    for path in executable {
        let path = crate::config::canonicalize_deepest(&path);
        if resolved.starts_with(&path) || path.starts_with(&resolved) {
            return Err(format!(
                "Cypress app state {} overlaps executable tree {}. Landlock unions filesystem \
                 permissions, so this would make writable browser state executable. Move the \
                 project or executable path away from Cypress's application-support directory.",
                named.display(),
                path.display()
            ));
        }
    }

    if !inspect_only {
        std::fs::create_dir_all(&named).map_err(|e| {
            format!(
                "Cannot create Cypress app state directory {}: {e}",
                named.display()
            )
        })?;
        let created = std::fs::canonicalize(&named).map_err(|e| {
            format!(
                "Cannot resolve Cypress app state directory {} after creating it: {e}",
                named.display()
            )
        })?;
        if created != expected {
            return Err(format!(
                "Cypress app state {} changed to resolve to {} while cplt prepared it. Refusing \
                 to grant persistent write access.",
                named.display(),
                created.display()
            ));
        }
    }

    Ok(())
}

/// Refuse to launch when a grant names a hard-denied file or a credential
/// directory.
///
/// [`policy::DENIED_FILES`] is documented as not overridable, unlike
/// [`policy::DENIED_HOME_SUBPATHS`], which `allow.read` is meant to reopen.
/// A hard error rather than a dropped rule and a warning: the grant is written
/// in config, it will be read back as fact, and a user who believes a rule is
/// in force when it is not is exactly the failure this list exists to prevent.
/// It also lands on both backends at once — silently ineffective on macOS,
/// silently effective on Linux, which is how #207 stayed invisible.
///
/// cplt's own state directory is refused as a whole *subtree*
/// ([`policy::cplt_state_dir_grant`]), which is the one place the per-file
/// override below does not apply: every file in it — config, trust store,
/// blocklist cache, per-repo local files — decides what the next run is
/// allowed to do, so a grant on any of them is self-perpetuating.
///
/// [`policy::DENIED_DOTFILES`] directories are refused for the same reason
/// pointing the other way (#291): the grant was silently ineffective on macOS
/// and silently *effective* on Linux, where it opened `~/.ssh` wholesale. The
/// error names the per-file grant, which is supported on both backends, so the
/// Linux behaviour change arrives as a message with its own fix rather than as
/// a rule that quietly stopped applying. Only the directory itself matches —
/// a grant on a file inside it is the supported override and still works.
fn validate_hard_denied_grants(config: &SandboxConfig) -> Result<(), String> {
    for (key, paths) in [
        ("allow.read", config.extra_read),
        ("allow.write", config.extra_write),
        ("allow.exec", config.extra_exec),
        ("allow.socket", config.extra_socket),
    ] {
        for p in paths {
            validate_grant_path(key, p, config.home_dir)?;
        }
    }
    Ok(())
}

/// Refuse one grant that no launch can honour, with the reason.
///
/// Shared with `cplt config set` (#306). The tool used to accept
/// `allow.read ~/.netrc` at write time and refuse it at every launch after —
/// the same question answered in two places, differently, which is the actual
/// defect. One predicate now, so a check added here reaches both.
///
/// Only the checks that need nothing but the path and `$HOME` live here.
/// Whether an exec grant overlaps a writable tree depends on the resolved
/// config (tool dirs, `allow.write`, named repositories), so it stays in
/// [`validate_exec_grants`] and `config set` approximates it separately.
///
/// # Errors
/// The refusal text, ready to print.
pub fn validate_grant_path(key: &str, p: &Path, home_dir: &Path) -> Result<(), String> {
    if let Some(dir) = policy::cplt_state_dir_grant(home_dir, p) {
        return Err(format!(
            "{key} names {} — inside cplt's own state directory ({}). Nothing in there \
             can be granted, not even a single file: it holds the config, the trust \
             store, the blocklist cache and the per-repo local files, which decide what \
             the next launch allows. Reading them tells an agent exactly which \
             protections to work around; writing them lets it approve its own next \
             launch. Remove it from your config or command line.",
            p.display(),
            dir.display()
        ));
    }
    if let Some(file) = policy::hard_denied_file(home_dir, p) {
        return Err(format!(
            "{key} names {} (~/{file}), which is on the hard-deny list and cannot be granted explicitly. Remove it from your config or command line.",
            p.display()
        ));
    }
    if let Some(dir) = policy::denied_dotfile_dir(home_dir, p) {
        return Err(format!(
            "{key} names {} (~/{dir}), a credential directory that cannot be granted \
             whole: macOS denies it whatever the grant says, so honouring it on Linux \
             alone would mean the same config opens every key in it on one platform \
             and nothing on the other. Name the specific path you need inside it \
             instead, e.g. ~/{dir}/<file> — that grant works on both.",
            p.display()
        ));
    }
    Ok(())
}

/// Refuse an exec grant that is unbounded or that overlaps a writable tree.
///
/// `allow.exec` is the one grant that hands the agent *execute* rights on a
/// tree of its own choosing, so two things are refused outright:
///
/// 1. `/`, `$HOME`, and any ancestor of `$HOME`
///    ([`policy::tool_override_path_is_safe`]) — an exec grant that wide is
///    indistinguishable from no sandbox.
/// 2. Any overlap, in either direction, with a writable tree: the project
///    directory or an `allow.write` grant (including the ones
///    `merge_tool_path_env_overrides` derives from `CARGO_HOME` and friends —
///    this runs after that merge, which is why the check lives here and not in
///    `Config::resolve`).
///
/// Overlap is a hard error rather than a warning or a narrowed rule because a
/// tree that is both agent-writable and executable is a binary-drop staging
/// path: the agent writes a binary and runs it, which is the class of hole the
/// non-executable cache and tmp defaults exist to close.
///
/// It cannot be mitigated instead of refused. Landlock is additive: a write
/// rule on an ancestor unions with an exec rule on a child and there is no way
/// to subtract it, so on Linux the only alternatives are refusing or a
/// bubblewrap `ro_protect` mount — and bubblewrap is absent on any host without
/// user namespaces, which would make the control silently missing exactly where
/// it is needed. Refusing is also the only answer that is identical on macOS
/// and Linux; a control that holds on one backend and not the other is how #207
/// survived for months.
fn validate_exec_grants(config: &SandboxConfig) -> Result<(), String> {
    for exec in config.extra_exec {
        if !policy::tool_override_path_is_safe(exec, config.home_dir) {
            return Err(format!(
                "allow.exec names {} \u{2014} an unsafe root cannot be granted execute \
                 rights: `/`, `/tmp`, `$HOME` and any parent of `$HOME`, and the platform \
                 system directories. A grant that wide defeats the sandbox. Name the \
                 specific tool prefix instead, e.g. ~/.linuxbrew.",
                exec.display()
            ));
        }
        for (write, source) in writable_trees(config) {
            let write = write.as_path();
            if !(exec.starts_with(write) || write.starts_with(exec)) {
                continue;
            }
            // The temp dirs cannot be narrowed — they are writable with no
            // grant to withdraw — so that case needs its own remedy or the
            // message tells the user to do something impossible.
            #[cfg(not(target_os = "macos"))]
            let shm = source == SHM_SOURCE;
            #[cfg(target_os = "macos")]
            let shm = false;
            let remedy = if shm {
                "/dev/shm is writable for POSIX shared memory and there is no grant to \
                 withdraw. Use the scratch dir, which is write+exec by design."
            } else if source == TEMP_DIR_SOURCE {
                "Move the tree somewhere the sandbox does not make writable, or use the \
                 scratch dir, which is write+exec by design. `--allow-tmp-exec` opens \
                 execute on all of temp if that is really what you want."
            } else {
                "Narrow one of the two so they do not overlap \u{2014} exec grants belong \
                 on read-only tool prefixes."
            };
            return Err(format!(
                "allow.exec {} overlaps {source} {}: a tree that is both writable and \
                 executable lets the agent drop a binary and run it. Neither backend can \
                 subtract the write grant from the exec grant, so cplt refuses the pair \
                 instead of pretending to. {remedy}",
                exec.display(),
                write.display()
            ));
        }
    }
    Ok(())
}

/// [`writable_trees`] canonicalized, for matching against the canonical paths
/// a dotfiles link or a cache variable resolves to. `canonicalize_deepest`, as
/// on that side, so a missing `allow.write` path under a symlinked ancestor
/// still matches what lies under it.
fn canonical_writable_trees(config: &SandboxConfig) -> Vec<(PathBuf, &'static str)> {
    writable_trees(config)
        .into_iter()
        .map(|(t, why)| (crate::config::canonicalize_deepest(&t), why))
        .collect()
}

/// Copilot's SEA `pkg` directories for `os` (`policy::copilot_pkg_dirs`). A
/// refused cache variable leaves only the default, and
/// [`validate_copilot_cache_env`] stops that launch.
fn copilot_pkg_grants(config: &SandboxConfig, os: &str) -> Vec<PathBuf> {
    policy::granted_copilot_pkg_dirs(
        config.copilot_cache_env,
        config.home_dir,
        os,
        &canonical_writable_trees(config),
    )
}

/// #374: stop on a Copilot cache variable cplt refuses, unsafe or inside a
/// writable tree. Copilot would still extract into that directory, and the
/// preflight runs `copilot` from it outside the sandbox, after this check.
fn validate_copilot_cache_env(config: &SandboxConfig) -> Result<(), String> {
    if !config.agent.needs_copilot_dir() {
        return Ok(());
    }
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let dirs = policy::copilot_pkg_dirs(
        config.copilot_cache_env,
        config.home_dir,
        os,
        &canonical_writable_trees(config),
    )?;
    // A moved `pkg` gets its own read allow on macOS, emitted after the user's
    // denies, so it would reopen one that covers it (SBPL: last match wins).
    // The default is left out: it is a tool dir with its own handling.
    let denies: Vec<PathBuf> = config
        .extra_deny
        .iter()
        .flat_map(|d| [d.clone(), crate::config::canonicalize_deepest(d)])
        .collect();
    for dir in dirs.iter().skip(1) {
        if let Some(deny) = profile::overlapping_deny(&denies, dir) {
            return Err(format!(
                "cplt refuses the Copilot cache {}: it overlaps the deny path {}. \
                 Copilot must read the runtime it extracts there. Move the cache \
                 out of the denied path, or drop the deny.",
                dir.display(),
                deny.display()
            ));
        }
    }
    Ok(())
}

/// Create the default Copilot `pkg` directory, and `copilot` above it, as real
/// directories before the sandbox starts.
///
/// The write deny and rename pin name that path, and bubblewrap skips a
/// missing one, so they only hold once it exists. Missing, it sits in a
/// writable cache (`~/Library/Caches`, `~/.cache`): the agent could
/// `ln -s <its dir> ~/Library/Caches/copilot` mid-session, and Copilot's
/// loader searches the default for a newer runtime even when a cache variable
/// moved extraction, so a later host `copilot` would run what it planted. The
/// preflight creates only the extraction directory, and not at all for a
/// project-local binary or an unsupported arch, so this runs regardless.
///
/// `mkdir` never follows a final symlink, so a link planted between the
/// check and the call fails the launch instead of being used. An existing
/// entry is left alone: `validate_copilot_cache_env` has already refused a
/// symlink the agent could re-point.
fn create_default_copilot_pkg_dir(config: &SandboxConfig) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    if !config.agent.needs_copilot_dir() {
        return Ok(());
    }
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let pkg = policy::copilot_default_pkg_dir(config.home_dir, os);
    let copilot = pkg.parent().expect("pkg has a parent");
    let fail = |dir: &Path, e: std::io::Error| {
        format!(
            "Failed to create the Copilot cache directory {}: {e}. cplt protects it \
             from the sandbox, which needs it to exist before launch.",
            dir.display()
        )
    };
    if let Some(caches) = copilot.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(caches)
            .map_err(|e| fail(caches, e))?;
    }
    for dir in [copilot, pkg.as_path()] {
        if std::fs::symlink_metadata(dir).is_ok() {
            continue;
        }
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .map_err(|e| fail(dir, e))?;
    }
    Ok(())
}

/// The dotfiles `targets` that sit inside a writable tree, with that tree's
/// description (#524). On Linux these are read-only only under Bubblewrap and
/// the caller warns when it is absent; on macOS one the profile cannot name is
/// refused at launch.
fn home_config_targets_in_writable_trees(
    config: &SandboxConfig,
    targets: Vec<PathBuf>,
) -> Vec<(PathBuf, &'static str)> {
    let trees = canonical_writable_trees(config);
    targets
        .into_iter()
        .filter_map(|t| {
            let (_, why) = trees.iter().find(|(tree, _)| t.starts_with(tree))?;
            Some((t, *why))
        })
        .collect()
}

/// The directories above each dotfiles target that must keep their names
/// (#524): a deny or read-only bind on the target holds only while its path
/// still leads to it, and `mv dotfiles d2 && mkdir dotfiles` would leave
/// `~/.gitconfig` resolving to a fresh, writable file.
///
/// Only the directories strictly inside the outermost writable tree holding
/// the target are returned — those are the ones the agent can rename. That
/// tree's root is left out, and so is everything above it. Moving the root
/// away is harmless: recreating it needs write on its parent, and that parent
/// lies in no writable tree (if it did, that tree would hold the target and be
/// the outermost one). So the link dangles at a path the agent cannot create.
/// Pinning the root would instead stop the user moving or deleting their own
/// project, `--repo-dir` root or `allow.write` grant inside the sandbox.
fn home_config_target_pins(config: &SandboxConfig, targets: &[PathBuf]) -> Vec<PathBuf> {
    let trees: Vec<PathBuf> = canonical_writable_trees(config)
        .into_iter()
        // A self-bind pin under the private `/tmp` would be what exposed it.
        .filter(|(t, why)| cfg!(target_os = "macos") || !bwrap_private(t, why))
        .map(|(t, _)| t)
        .collect();
    let mut pins = Vec::new();
    for target in targets {
        let Some(root) = trees
            .iter()
            .filter(|r| target.starts_with(r))
            .min_by_key(|r| r.components().count())
        else {
            continue;
        };
        pins.extend(
            target
                .ancestors()
                .skip(1)
                .take_while(|a| a.starts_with(root) && a != root)
                .map(Path::to_path_buf),
        );
    }
    pins
}

/// A writable tree that is not the host's under Bubblewrap: it gives the
/// sandbox a private `/tmp` and `/dev/shm`, so nothing of the host's is
/// reachable there.
fn bwrap_private(tree: &Path, why: &str) -> bool {
    why == TEMP_DIR_SOURCE || tree == Path::new("/dev/shm")
}

/// A missing home Git config target to create empty: the `git` directory
/// under a linked `~/.config` when that is missing too, then the file.
#[cfg(any(target_os = "linux", test))]
type MissingConfig = (Option<PathBuf>, PathBuf);

/// The home Git config files a link points at inside a writable tree but that
/// do not exist yet (#553): what to create, or why not.
///
/// Bubblewrap cannot bind a file that does not exist, so without this the
/// agent could create `config` behind a linked `~/.config/git` (or the target
/// of a dangling `~/.gitconfig`) and set `core.fsmonitor` for the host's next
/// git command. Once the file exists, `home_config_link_targets` resolves it
/// and it gets the same read-only bind and rename pins as any other target.
///
/// The tree the file lands in holds content the agent, or whoever wrote the
/// repo, controls, so that content must not choose where: [`creation_path`]
/// follows only the user's own link in `$HOME` and links outside every
/// writable tree, and a path inside a gitdir is refused (an empty
/// `index.lock` breaks git). A directory is created only for `git` under a
/// linked `~/.config`. The private `/tmp` and `/dev/shm` are skipped: a file
/// created there on the host protects nothing inside the sandbox.
#[cfg(any(target_os = "linux", test))]
fn plan_missing_home_config_targets(config: &SandboxConfig) -> Vec<Result<MissingConfig, String>> {
    let trees = canonical_writable_trees(config);
    let all: Vec<PathBuf> = trees.iter().map(|(t, _)| t.clone()).collect();
    let home = config.home_dir;
    policy::read_only_home_config()
        .filter_map(|rel| {
            let named = home.join(rel);
            if std::fs::canonicalize(&named).is_ok() {
                return None;
            }
            let refuse = |why: String| Some(Err(format!("{} ({why})", named.display())));
            let leaf = match creation_path(home, Path::new(rel), &all) {
                Ok(Some(leaf)) => leaf,
                Ok(None) => return None,
                Err(why) => return refuse(why),
            };
            if !trees
                .iter()
                .any(|(t, why)| leaf.starts_with(t) && !bwrap_private(t, why))
            {
                return None;
            }
            if leaf.ancestors().any(is_gitdir) {
                return refuse(format!("{} is inside a git directory", leaf.display()));
            }
            let missing = leaf
                .ancestors()
                .take_while(|a| a.symlink_metadata().is_err())
                .last()?;
            if missing == leaf {
                return Some(Ok((None, leaf)));
            }
            let git_under_linked_config = rel.starts_with(".config/git/")
                && home.join(".config").is_symlink()
                && leaf.parent() == Some(missing)
                && missing.file_name() == Some(std::ffi::OsStr::new("git"));
            if !git_under_linked_config {
                return refuse(format!("{} does not exist", missing.display()));
            }
            Some(Ok((Some(missing.to_path_buf()), leaf)))
        })
        .collect()
}

/// Where `rel` under `home` resolves, following a symlink only when it is the
/// first one on the way (the user's own link in `$HOME`) or lies outside
/// every writable tree. `Ok(None)` when no link was followed: the file is not
/// behind a link, so it is `$HOME`'s and read-only already.
///
/// Every existing component of the result was checked with `lstat` on the
/// way down, so it holds no symlink.
#[cfg(any(target_os = "linux", test))]
fn creation_path(home: &Path, rel: &Path, trees: &[PathBuf]) -> Result<Option<PathBuf>, String> {
    use std::path::Component;
    let mut cur = std::fs::canonicalize(home).map_err(|e| e.to_string())?;
    let mut todo: std::collections::VecDeque<PathBuf> = rel
        .components()
        .map(|c| PathBuf::from(c.as_os_str()))
        .collect();
    let mut followed = 0u32;
    while let Some(part) = todo.pop_front() {
        match part.components().next() {
            Some(Component::RootDir) => cur = PathBuf::from("/"),
            Some(Component::ParentDir) => {
                cur.pop();
            }
            Some(Component::Normal(name)) => {
                let next = cur.join(name);
                if !next.is_symlink() {
                    cur = next;
                    continue;
                }
                if followed > 0 && trees.iter().any(|t| next.starts_with(t)) {
                    return Err(format!(
                        "{} is a symlink inside a writable tree",
                        next.display()
                    ));
                }
                followed += 1;
                if followed > 40 {
                    return Err("too many levels of symbolic links".to_string());
                }
                let target = std::fs::read_link(&next).map_err(|e| e.to_string())?;
                for c in target.components().rev() {
                    todo.push_front(PathBuf::from(c.as_os_str()));
                }
            }
            _ => {}
        }
    }
    Ok((followed > 0).then_some(cur))
}

/// A `.git` directory, or one laid out like a gitdir (a bare repo, a
/// worktree's common dir).
#[cfg(any(target_os = "linux", test))]
fn is_gitdir(dir: &Path) -> bool {
    dir.file_name() == Some(std::ffi::OsStr::new(".git"))
        || (dir.join("HEAD").is_file() && dir.join("objects").is_dir())
}

/// Create `file` empty, and `dir`, its parent, first when given.
///
/// Every component is resolved with `RESOLVE_NO_SYMLINKS`, so a link swapped
/// into the path after [`creation_path`] checked it fails the call instead of
/// steering it. Kernels before 5.6 have no `openat2`, and there only the leaf
/// is guarded ([`create_empty_config_leaf_only`]).
#[cfg(target_os = "linux")]
fn create_empty_config(dir: Option<&Path>, file: &Path) -> std::io::Result<Vec<PathBuf>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let base = dir
        .unwrap_or(file)
        .parent()
        .ok_or(std::io::ErrorKind::InvalidInput)?;
    let parent = match openat2_no_symlinks(
        libc::AT_FDCWD,
        base,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    ) {
        Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {
            return create_empty_config_leaf_only(dir, file);
        }
        r => r?,
    };
    let mut made = Vec::new();
    if let Some(d) = dir {
        let name = std::ffi::CString::new(d.file_name().unwrap_or_default().as_bytes())?;
        // SAFETY: `parent` is an open directory fd and `name` is NUL-terminated.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) } == 0 {
            made.push(d.to_path_buf());
        } else {
            // EEXIST: an earlier file in the same directory created it. A
            // symlink there fails the `openat2` below.
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EEXIST) {
                return Err(e);
            }
        }
    }
    let rel = file.strip_prefix(base).map_err(std::io::Error::other)?;
    openat2_no_symlinks(
        parent.as_raw_fd(),
        rel,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o644,
    )?;
    made.push(file.to_path_buf());
    Ok(made)
}

/// `openat2(2)` with `RESOLVE_NO_SYMLINKS`, which the `libc` crate has no
/// wrapper for.
#[cfg(target_os = "linux")]
fn openat2_no_symlinks(
    dirfd: libc::c_int,
    path: &Path,
    flags: libc::c_int,
    mode: u32,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `open_how` is three integers, and all-zero is valid for each.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = u64::try_from(flags).map_err(std::io::Error::other)?;
    how.mode = u64::from(mode);
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: `path` is NUL-terminated, `how` outlives the call, and the size
    // is that of the struct passed.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &raw const how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = libc::c_int::try_from(fd).map_err(std::io::Error::other)?;
    // SAFETY: the kernel just returned this fd and nothing else owns it.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[cfg(all(test, not(target_os = "linux")))]
fn create_empty_config(dir: Option<&Path>, file: &Path) -> std::io::Result<Vec<PathBuf>> {
    create_empty_config_leaf_only(dir, file)
}

/// The fallback without `openat2`: `create_new` is `O_CREAT|O_EXCL`, which
/// never follows a symlink at the leaf, and `O_NOFOLLOW` says so explicitly.
/// A directory above the leaf swapped for a link after [`creation_path`]
/// checked it is followed.
#[cfg(any(target_os = "linux", test))]
fn create_empty_config_leaf_only(dir: Option<&Path>, file: &Path) -> std::io::Result<Vec<PathBuf>> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut made = Vec::new();
    if let Some(d) = dir {
        match std::fs::create_dir(d) {
            Ok(()) => made.push(d.to_path_buf()),
            // An earlier file in the same directory created it.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && d.is_dir() => {}
            Err(e) => return Err(e),
        }
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(file)?;
    made.push(file.to_path_buf());
    Ok(made)
}

/// Every tree the sandbox makes writable, paired with a name for the error.
///
/// The `allow.write` grants include the ones `merge_tool_path_env_overrides`
/// derives from `CARGO_HOME` and friends, since that merge happens before
/// `prepare`. The home tool dirs are here because several of them (`~/.gradle`,
/// `~/.m2`, `~/.cache`) are writable by design, and an exec grant on one of them
/// would be the same write+exec pair by a different route — the route
/// `--allow-cache-exec` exists to handle deliberately.
fn writable_trees(config: &SandboxConfig) -> Vec<(PathBuf, &'static str)> {
    let mut trees = vec![(config.project_dir.to_path_buf(), "the project directory")];
    // Project-grade, so write+exec by design and never a tree an `allow.exec`
    // grant may overlap — the same rule the project directory carries.
    trees.extend(
        config
            .named_roots
            .iter()
            .map(|r| (r.clone(), "the named repository")),
    );
    trees.extend(
        config
            .extra_write
            .iter()
            .map(|w| (w.clone(), "the allow.write grant")),
    );
    match config.existing_home_tool_dirs {
        Some(dirs) => trees.extend(
            dirs.iter()
                .filter(|d| d.dir.write)
                .map(|d| (d.path.clone(), "the writable tool directory")),
        ),
        None => trees.extend(
            policy::HOME_TOOL_DIRS
                .iter()
                .filter(|d| d.write)
                .map(|d| (config.home_dir.join(d.path), "the writable tool directory")),
        ),
    }
    // The agent's own data dirs are writable by the same construction as the
    // tool dirs, and they were missing here: `~/.local/share/opencode`,
    // `~/.claude`, `~/.pi/agent` and friends are granted write by
    // `emit_home_access` and `generate_policy`, not by config, so an
    // `allow.exec` on an ancestor (`~/.local`, the pipx layout) passed
    // validation and then unioned with them under Landlock into exactly the
    // writable-and-executable tree this function exists to refuse. On macOS
    // `emit_exec_write_denies` runs last and takes the write back, so the same
    // config broke loudly there and silently held on Linux — the #207 shape.
    for dir in config.agent_dirs {
        if dir.write {
            trees.push((dir.path.clone(), "the writable agent directory"));
        }
        // A file-level write grant inside a read-only agent dir (OpenCode's
        // `auth.json`) is a writable path too, just a one-entry one.
        trees.extend(
            dir.write_files
                .iter()
                .map(|f| (dir.path.join(f), "the writable agent file")),
        );
    }
    if policy::cypress_runtime_intent(config.allow_cache_exec, config.allow_cache_exec_any) {
        trees.push((
            policy::cypress_app_data_dir_with_env(config.home_dir, config.copilot_cache_env),
            "the writable Cypress state directory",
        ));
    }
    // A worktree's or bare repo's real `.git` is granted write so git can
    // update refs and the index from inside the sandbox.
    if let Some(p) = config.git_common_dir {
        trees.push((p.to_path_buf(), "the git common directory"));
    }
    // The system temp dirs are made writable by the backends themselves, not by
    // config, which is why they were missing here (#299). An exec grant under
    // one is the same writable-plus-executable staging pair as a grant under
    // `~/.cache`, and the three code paths disagree about it today: on macOS
    // the grant wins (`emit_user_allows` runs after `emit_temp_rules`, and
    // last-match-wins), on Linux without bubblewrap it unions with the
    // always-writable `/tmp` rule into exactly the binary-drop pair this
    // function exists to refuse, and under bubblewrap the private `/tmp` tmpfs
    // hides it so the grant does nothing at all. Refusing is the one answer
    // that is the same on all three.
    trees.extend(
        SYSTEM_TEMP_DIRS
            .iter()
            .map(|d| (PathBuf::from(d), TEMP_DIR_SOURCE)),
    );
    // `/dev/shm` is the same class as `/tmp`: Landlock seeds it read+write for
    // POSIX shared memory, so an exec grant over it is the same binary-drop
    // pair. It is only reachable with `--no-bubblewrap` — bubblewrap's
    // `--dev /dev` replaces it with a fresh devtmpfs and the grant does nothing
    // at all — and refusing is the one answer that is identical in both modes.
    #[cfg(not(target_os = "macos"))]
    trees.push((PathBuf::from("/dev/shm"), SHM_SOURCE));
    trees
}

/// Every tree a session can write, for callers that need the answer **before**
/// a [`SandboxConfig`] exists.
///
/// `writable_trees` is the full version and runs at profile build time. The
/// proxy starts earlier than that and has to know the same thing: a domain list
/// file inside any of these is one the agent can rewrite between reloads
/// (#426). Kept next to `writable_trees` so the two cannot drift on the trees
/// that are writable by construction rather than by config — the system temp
/// dirs and `/dev/shm`, which no grant creates and none can withdraw.
#[must_use]
pub fn session_writable_roots(
    project_dir: &Path,
    named_roots: &[PathBuf],
    allow_write: &[PathBuf],
    scratch_dir: Option<&Path>,
) -> Vec<PathBuf> {
    let mut roots = vec![project_dir.to_path_buf()];
    roots.extend(named_roots.iter().cloned());
    roots.extend(allow_write.iter().cloned());
    roots.extend(scratch_dir.map(Path::to_path_buf));
    roots.extend(SYSTEM_TEMP_DIRS.iter().map(PathBuf::from));
    #[cfg(not(target_os = "macos"))]
    roots.push(PathBuf::from("/dev/shm"));
    #[cfg(not(target_os = "macos"))]
    roots.push(PathBuf::from("/tmp"));
    roots
}

/// Names the temp-dir collision in the refusal, and selects its remedy: a temp
/// dir is writable with no grant to withdraw, so "narrow one of the two" is not
/// advice a user can act on there.
const TEMP_DIR_SOURCE: &str = "the always-writable system temp dir";

/// Same idea for `/dev/shm`, which `--allow-tmp-exec` does not cover, so it
/// needs its own remedy rather than the temp dir's.
#[cfg(not(target_os = "macos"))]
const SHM_SOURCE: &str = "the always-writable shared-memory dir";

/// Temp roots the backends grant write on unconditionally: Landlock seeds a
/// read+write rule for `/tmp`, and the SBPL profile does the same for
/// `/private/tmp` and `/private/var/folders` (the canonical form of the macOS
/// `TMPDIR`). Grants reach [`validate_exec_grants`] canonicalized, so the
/// macOS entries are the `/private` forms.
#[cfg(target_os = "macos")]
const SYSTEM_TEMP_DIRS: &[&str] = &["/private/tmp", "/private/var/folders"];
#[cfg(not(target_os = "macos"))]
const SYSTEM_TEMP_DIRS: &[&str] = &["/tmp"];

/// Resolve the real `.git` directory of every writable granted path whose repo
/// data does NOT live at `<path>/.git` — a worktree, a bare repo, or a grant
/// that points *inside* a repo (#212).
///
/// The `<path>/.git/...` denies the backends emit unconditionally already cover
/// the ordinary case, so anything resolving to `<path>/.git` is dropped here.
/// A path that is not a repository at all resolves to `None` and is skipped —
/// a no-op, never an error.
///
/// This spawns `git rev-parse --git-common-dir` once per granted path, in the
/// PARENT process, with the granted repo's config in scope — so it routes
/// through the hardened invoker (`git::command`, #211) like every other
/// parent-side git invocation.
fn extra_git_dirs(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = roots
        .iter()
        .filter_map(|root| {
            let dir = crate::discover::git_dir_of(root)?;
            // Ordinary repo — already covered by the `<root>/.git` denies.
            (dir != root.join(".git")).then_some(dir)
        })
        .collect();
    // The same repo can be granted twice, and two grants can share one `.git`
    // (two worktrees of one repo); duplicate denies are harmless but noisy.
    dirs.sort();
    dirs.dedup();
    dirs
}

/// The real `.git` of every named root that does not keep it at `<root>/.git`.
///
/// The same resolution `extra_git_dirs` performs for write grants, exposed
/// because the answer is *granted* for a named root rather than only denied:
/// a linked worktree's objects and refs live in the main checkout's gitdir, and
/// without it `git` inside the named root fails with `not a git repository`.
/// Callers build the policy from it, so it is resolved once, parent-side,
/// through the hardened invoker.
#[must_use]
pub fn named_root_git_dirs(roots: &[PathBuf]) -> Vec<PathBuf> {
    extra_git_dirs(roots)
}

/// The credential that stands in for the login Keychain this run, if any
/// (#242). `None` keeps the grant. Always `None` with `enabled` false, which is
/// `sandbox.keychain_substitute` and defaults off.
///
/// `Agent::credential_outside_keychain_on` answers from what the parent already
/// has. This adds the Copilot case it cannot see (#277): a user signed in
/// through `gh` who exported nothing. cplt runs `gh auth token` (trusted path,
/// github.com pinned) and hands the result over as the first token var the
/// repo's `deny.env` does not strip.
pub fn keychain_substitute(
    agent: Agent,
    home: &Path,
    deny_env: &[String],
    enabled: bool,
) -> Option<crate::agent::KeychainSubstitute> {
    keychain_substitute_with(
        agent,
        home,
        deny_env,
        enabled,
        cfg!(target_os = "macos"),
        exec::extract_gh_token,
    )
}

/// [`keychain_substitute`] with the platform and the `gh` call as parameters,
/// so tests can drive both without a host `gh`.
pub(crate) fn keychain_substitute_with(
    agent: Agent,
    home: &Path,
    deny_env: &[String],
    enabled: bool,
    macos: bool,
    extract: impl FnOnce() -> Option<String>,
) -> Option<crate::agent::KeychainSubstitute> {
    if let Some(found) = agent.credential_outside_keychain_on(home, deny_env, enabled, macos) {
        return Some(found);
    }
    if !enabled || !macos || agent != Agent::Copilot {
        return None;
    }
    let var = exec::GH_TOKEN_VARS
        .iter()
        .find(|v| !deny_env.iter().any(|d| d == *v))?;
    Some(crate::agent::KeychainSubstitute::GhToken {
        var,
        token: crate::agent::SecretToken::new(extract()?),
    })
}

/// Human-readable representation of the sandbox policy.
///
/// On macOS, returns the SBPL profile text (useful for `--print-profile`).
/// On Linux, returns a formatted Landlock rule summary.
pub fn describe(sandbox: &PreparedSandbox) -> &str {
    &sandbox.profile_text
}

/// Verify the sandbox mechanism works on this system.
///
/// On macOS, runs `/usr/bin/true` inside `sandbox-exec`, with the profile
/// passed inline (`-p`), to confirm enforcement is active.
///
/// On Linux, this is a no-op (ABI checks happen during prepare).
pub fn preflight(sandbox: &PreparedSandbox) -> Result<(), String> {
    exec::preflight(sandbox)
}

/// Execute a command inside the sandbox, forwarding signals to the child.
///
/// Handles platform-specific sandbox setup internally:
/// - macOS: invokes `sandbox-exec` with the SBPL profile passed inline (`-p`)
/// - Linux: applies Landlock ruleset + seccomp filter via `pre_exec`
///
/// Environment handling is controlled by `extra_pass_env`, `inherit_env`,
/// and `disabled_categories` — see [`build_sandbox_env()`] for details.
/// `deny_env` contains additional env vars to strip (from repo config [deny] section).
/// `repo_dirs` are the validated `--repo-dir` roots — first-class repositories
/// alongside the launch one, whose identity the gh guard's scope set is built from.
#[allow(clippy::too_many_arguments)]
pub fn exec_sandboxed(
    sandbox: &PreparedSandbox,
    copilot_bin: &Path,
    copilot_args: &[String],
    launch_dir: &Path,
    repo_dirs: &[PathBuf],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    deny_env: &[String],
    gh_guard: &crate::config::GhGuardPolicy,
    git_guard: &crate::config::GitGuardPolicy,
    quiet: bool,
) -> u8 {
    exec::exec(
        sandbox,
        copilot_bin,
        copilot_args,
        launch_dir,
        repo_dirs,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        deny_env,
        gh_guard,
        git_guard,
        quiet,
    )
}

// ── Platform-specific prepare implementations ─────────────────

#[cfg(target_os = "macos")]
fn prepare_impl(
    config: &SandboxConfig,
    extra_git_dirs: &[PathBuf],
    pnpm_shadow_dir: Option<&Path>,
    _inspect_only: bool,
) -> Result<PreparedSandbox, String> {
    validate_config_paths(config)?;
    // Interpolated into the profile like every other path — same injection check.
    for p in extra_git_dirs {
        policy::validate_sbpl_path(p).map_err(|e| format!("Granted repo .git dir: {e}"))?;
    }
    let playwright_socket_dir =
        policy::playwright_runtime_intent(config.allow_cache_exec, config.allow_cache_exec_any)
            .then_some(config.playwright_socket_dir)
            .flatten();

    let profile_text = profile::generate_profile_with_playwright_socket_dir(
        config,
        extra_git_dirs,
        playwright_socket_dir,
    );

    Ok(PreparedSandbox {
        project_dir: config.project_dir.to_path_buf(),
        home_dir: config.home_dir.to_path_buf(),
        profile_text,
        scratch_dir: config.scratch_dir.map(Path::to_path_buf),
        pnpm_shadow_dir: pnpm_shadow_dir.map(Path::to_path_buf),
        playwright_socket_dir: playwright_socket_dir.map(Path::to_path_buf),
        playwright_runtime: policy::playwright_runtime_intent(
            config.allow_cache_exec,
            config.allow_cache_exec_any,
        ),
        proxy_port: config.proxy_port,
        agent: config.agent,
        allow_localhost: config.localhost_ports.to_vec(),
        allow_localhost_any: config.allow_localhost_any,
        npmrc_allowed: env::npmrc_explicitly_allowed(config.home_dir, config.extra_read),
        keychain_substitute: config.keychain_substitute.clone(),
        worktree_root: None,
    })
}

/// Report which of the three UNIX-socket regimes this run lands in.
///
/// Pathname UNIX sockets are the one part of the Linux policy where the
/// protection depends on *both* the kernel version and whether bubblewrap
/// wrapped the run, and the three outcomes are genuinely different:
///
/// | Kernel      | bwrap | Outcome                                          |
/// |-------------|-------|--------------------------------------------------|
/// | >= 7.1 (v9) | any   | `connect(2)` is kernel-mediated: only granted paths |
/// | < 7.1       | yes   | listed sockets are mount-masked; others reachable |
/// | < 7.1       | no    | no restriction at all                             |
///
/// Kernel 7.1 lands mid-2026, so the third row is the common case today and
/// the message must not pretend otherwise. This mirrors the style of the other
/// Linux enforceability notes above rather than adding a new surface.
#[cfg(target_os = "linux")]
fn report_unix_socket_regime(bwrap_active: bool, socket_masks: usize) {
    use landlock::ABI;

    if landlock_mod::check_availability().is_ok_and(|abi| abi >= ABI::V9) {
        ui::info(
            "UNIX-socket connect is kernel-enforced (Landlock ABI v9+): the agent can \
             only reach sockets the policy grants.",
        );
    } else if bwrap_active {
        ui::info(&format!(
            "UNIX-socket connect is NOT kernel-enforced (needs Landlock ABI v9 / kernel 7.1). \
             Bubblewrap masks {socket_masks} known escape socket(s) (D-Bus, systemd, \
             container runtimes); any other pathname socket on the host stays reachable."
        ));
    } else {
        ui::warn(
            "UNIX sockets are NOT restricted in this run: Landlock cannot gate connect(2) \
             below ABI v9 (kernel 7.1) and Bubblewrap is not active, so nothing masks them. \
             An agent can reach the D-Bus session bus or a container daemon socket and \
             execute code outside the sandbox. Install bubblewrap to close the known paths.",
        );
    }
}

/// Every path the bubblewrap overlay must re-bind read-only.
///
/// Extracted from the Linux `prepare_impl` so the whole set is assertable in
/// one place. It was not, and it mattered: a mutation that deleted the Copilot
/// entry from the caller passed Linux CI green, because each helper had a test
/// and the wiring that consumes them had none.
/// The writable roots and git directories both bubblewrap path sets are keyed
/// on. Shared so `ro_protect_paths` and `pin_paths` cannot drift apart — a
/// gitdir missing from the pin set silently re-opens the rename walk-around
/// that the read-only binds depend on being closed.
#[cfg(target_os = "linux")]
fn git_roots<'a>(
    config: &'a SandboxConfig,
    extra_git_dirs: &'a [PathBuf],
) -> (Vec<&'a Path>, Vec<&'a Path>) {
    let mut write_roots: Vec<&Path> = vec![config.project_dir];
    write_roots.extend(config.named_roots.iter().map(PathBuf::as_path));
    write_roots.extend(config.extra_write.iter().map(PathBuf::as_path));
    let mut git_dirs: Vec<&Path> = config.git_common_dir.into_iter().collect();
    git_dirs.extend(extra_git_dirs.iter().map(PathBuf::as_path));
    (write_roots, git_dirs)
}

/// Paths bind-mounted read-write onto themselves so they become mountpoints and
/// can no longer be renamed or removed. See `bubblewrap::rename_pin_paths`.
#[cfg(target_os = "linux")]
fn pin_paths(
    config: &SandboxConfig,
    extra_git_dirs: &[PathBuf],
    nested_repos: &[PathBuf],
) -> Vec<PathBuf> {
    let (mut write_roots, git_dirs) = git_roots(config, extra_git_dirs);
    // A nested repository is pinned exactly as a root is. Without this the
    // read-only binds on its `.git/hooks` and `.claude/settings.json` are
    // walk-aroundable by `mv .git g2 && mkdir .git`.
    write_roots.extend(nested_repos.iter().map(PathBuf::as_path));
    let mut pins = bubblewrap::rename_pin_paths(&write_roots, &git_dirs);
    // GHSA-8qmv-wxp3-526v, Linux half. A read-only bind pins a path's content,
    // not its name: `~/.cache/copilot` sits inside the writable `~/.cache`
    // grant, so moving it aside left `pkg` writable under a name no bind
    // covered. Self-binding the parent makes it a mountpoint, and `rename`/
    // `rmdir` of a mountpoint return `EBUSY`. Derived from the read-only set
    // rather than spelled out, so a package dir added there cannot arrive
    // unpinned. Empty for every agent but Copilot.
    //
    // The first two entries are the fixed defaults, whose parents sit directly
    // in a writable grant. A directory a cache variable moved lies outside
    // every writable tree (`copilot_pkg_grants`), so it gets the same
    // "strictly inside the outermost writable tree" pins as a dotfiles
    // target: none today, and never a project or `allow.write` root.
    let copilot = copilot_ro_protect_paths(
        config.agent,
        config.home_dir,
        config.copilot_cache_env,
        &canonical_writable_trees(config),
    );
    let (defaults, moved) = copilot.split_at(copilot.len().min(2));
    pins.extend(
        defaults
            .iter()
            .filter_map(|p| p.parent().map(Path::to_path_buf)),
    );
    pins.extend(home_config_target_pins(config, moved));
    // GHSA-7mcc-xg5v-hv8v, Linux half — the same reasoning one class over, for
    // the exec-only agent grants the read-only overlay covers above.
    // OpenCode's `~/.cache/opencode/bin` is read-only bound, but its parent
    // sits in the writable `~/.cache` grant, so moving `~/.cache/opencode`
    // aside left `bin` writable under a name no bind covers. Derived from the
    // same filter as that overlay entry, so a future exec-only grant is pinned
    // with it. `~/.cache/opencode` itself stays writable.
    pins.extend(
        config
            .agent_dirs
            .iter()
            .filter(|d| !d.write && d.process_exec)
            .filter_map(|d| d.path.parent().map(Path::to_path_buf)),
    );
    // #524: the read-only bind on a dotfiles target pins its content, not
    // its name — `mv git git.old && mkdir git` would leave `~/.gitconfig`
    // resolving to a fresh, writable file. Same set as the macOS unlink denies.
    pins.extend(home_config_target_pins(
        config,
        &home_config_link_targets(config.home_dir),
    ));
    // #514: the read-only bind on the shim dir pins its content, not its
    // name, so `mv cplt cplt.old && mkdir -p cplt/bin` under a writable
    // ancestor would leave PATH naming a fresh, writable directory.
    pins.extend(home_config_target_pins(
        config,
        &shim_ro_protect_paths(config.home_dir)
            .into_iter()
            .map(|d| std::fs::canonicalize(&d).unwrap_or(d))
            .collect::<Vec<_>>(),
    ));
    pins.sort();
    pins.dedup();
    pins
}

#[cfg(target_os = "linux")]
fn ro_protect_paths(
    config: &SandboxConfig,
    extra_git_dirs: &[PathBuf],
    nested_repos: &[PathBuf],
) -> Vec<PathBuf> {
    // Finding 1: Landlock cannot deny subpaths inside the writable project tree,
    // so the project's .git/hooks (and other git-persistence files) stay
    // writable — a persistence-escape vector. When Bubblewrap is active we
    // re-bind those pre-existing paths read-only to restore macOS parity. In a
    // git worktree the real hooks live under the shared git_common_dir (which
    // the sandbox grants write access to), so pass it through to cover them too.
    //
    // #212: every writable granted path is a candidate too — a sibling repo's
    // .git/hooks was fully writable before, and hooks run unsandboxed.
    let (mut write_roots, git_dirs) = git_roots(config, extra_git_dirs);
    // Nested repositories are ordinary roots to this table: macOS matches them
    // with an any-depth regex, and bubblewrap needs the paths named.
    write_roots.extend(nested_repos.iter().map(PathBuf::as_path));
    let mut ro_protect = bubblewrap::git_persistence_paths(&write_roots, &git_dirs);

    // #237: same class, different tree — the agent's own config dir is granted
    // writable, and some files in it auto-execute on the host the next time the
    // agent runs outside cplt (Claude hooks, Pi extensions). macOS
    // emits these as SBPL write-denies; Landlock cannot carve a sub-deny out of
    // an allowed tree, so the bwrap read-only overlay is the only mechanism here
    // — WITHOUT bwrap this is unenforced on Linux.
    //
    // KNOWN GAP: even with bwrap, `build_bwrap_args` skips a path that does not
    // exist, because bwrap cannot bind a missing source. `.git/hooks` rarely
    // hits this (`git init` creates it) but `extensions/` does not exist until
    // the first extension is installed, so that deny is nominal in the common
    // case. Masking a missing path with the `deny_masks` machinery (a `--tmpfs`
    // over a directory, a mode-000 placeholder `--ro-bind` over a file) would
    // close it, but it also makes the path *appear to exist* as an empty dir or
    // empty file, which changes what the agent reads at startup. That is not a
    // change to make untested, and this is a macOS host. Documented in
    // SECURITY.md instead of half-done.
    ro_protect.extend(config.agent.host_persistence_paths(config.agent_dirs));

    // H-13/H-05: an agent's exec-only grant that sits inside a writable tree.
    // macOS denies the write for exactly these dirs in
    // `emit_host_persistence_denies` (the `exec_only` chain at the tail of the
    // profile); this is that rule's Linux half. The write comes from an
    // ancestor Landlock cannot subtract, so the bwrap bind is the only
    // mechanism — and, as everywhere in this list, WITHOUT bwrap it is absent.
    //
    // OpenCode's `~/.cache/opencode/bin` is the entry that needs it: the
    // writable ancestor is `~/.cache` from HOME_TOOL_DIRS, granted to every
    // agent, so narrowing OpenCode's own cache grant would take nothing away —
    // the same shape as `~/.cache/copilot/pkg` below.
    //
    // For Pi this bind IS the control, not belt-and-braces — the comment here
    // said the opposite until #449. Pi's root carries a create-only grant so it
    // can take its trust lock, and `MakeDir | RemoveDir` on a parent is
    // sufficient for a *same-directory* rename (Landlock does not require
    // `Refer` for one). So `mv bin bin.old; mv tmp bin` is permitted by the
    // ruleset alone; what stops it is that this bind makes `bin/` a mountpoint,
    // and rename of a mountpoint is `EBUSY`. Measured, not argued: removing
    // this extend makes `pi_trust_lock_works_under_bwrap_and_bin_cannot_be_renamed`
    // fail with the rename succeeding.
    //
    // Which is also why the create-only grant is withheld on Linux when
    // bubblewrap is unavailable: without this bind there is nothing left.
    ro_protect.extend(
        config
            .agent_dirs
            .iter()
            .filter(|d| !d.write && d.process_exec)
            .map(|d| d.path.clone()),
    );

    // #238: mise's `shims/` and `installs/` are PATH-resolved binary drop
    // points sitting inside the mise data dir, which stays writable for the
    // rest of mise's state. The other PATH-resolved dirs (~/.bun/bin,
    // ~/.deno/bin, $PNPM_HOME) need nothing here: HOME_TOOL_DIRS grants write
    // to their sibling caches rather than to the parent, so Landlock enforces
    // them on its own, with or without bwrap. Same "must already exist" caveat
    // as everything else in this list.
    ro_protect.extend(mise_ro_protect_paths(config.home_dir));

    // #514: cplt's own PATH shims, when the user opted in. Same class as the
    // mise shims above: what the user's next unsandboxed launch runs.
    ro_protect.extend(shim_ro_protect_paths(config.home_dir));

    // #328: Copilot's package dirs. macOS write-denies both in the profile;
    // Landlock cannot — `~/.copilot` is granted write wholesale, and
    // `~/.cache/copilot/pkg`'s execute rule unions with the `~/.cache` write
    // grant from HOME_TOOL_DIRS, leaving the SEA runtime writable AND
    // executable. Only the bwrap overlay can take the write back. Empty for
    // every other agent.
    ro_protect.extend(copilot_ro_protect_paths(
        config.agent,
        config.home_dir,
        config.copilot_cache_env,
        &canonical_writable_trees(config),
    ));

    // #524: a dotfiles-managed `~/.gitconfig` resolves to its target, and the
    // target can sit inside the writable project. Landlock follows the link
    // for the read grant and cannot subtract the write the project grant
    // gives, so this bind is the only thing keeping the config read-only —
    // and without bwrap nothing does (`prepare_impl` warns at launch).
    ro_protect.extend(home_config_link_targets(config.home_dir));

    ro_protect.sort();
    ro_protect.dedup();
    ro_protect
}

/// Launch warnings for the credential entries a symlink moves into a grant
/// and no mount mask covers (#551): which entry, where it resolves, which
/// grant. `masks` is `None` when bubblewrap is not active, and then every
/// link is exposed: Landlock cannot deny inside a grant.
#[cfg(target_os = "linux")]
fn unmasked_credential_warnings(
    links: &[landlock_mod::CredentialLink],
    masks: Option<&bubblewrap::DenyMasks>,
) -> Vec<String> {
    let (why, fix) = if masks.is_some() {
        ("Bubblewrap could not mask it there", "Move")
    } else {
        (
            "Landlock cannot deny a path inside a grant, and Bubblewrap is not active",
            "Install bubblewrap, or move",
        )
    };
    links
        .iter()
        .filter(|l| !masks.is_some_and(|m| m.covers(&l.target)))
        .map(|l| {
            format!(
                "~/{} resolves to {}, inside the granted {}. {why}, so the agent can \
                 read it, and write it if that grant is writable. {fix} the credential \
                 out of that tree.",
                l.rel,
                l.target.display(),
                l.grant.display()
            )
        })
        .collect()
}

/// Create the planned missing home Git config files (#553) and return what
/// was made, or with `inspect_only`, what a launch would make.
#[cfg(target_os = "linux")]
fn create_missing_home_config(config: &SandboxConfig, inspect_only: bool) -> Vec<PathBuf> {
    let mut made = Vec::new();
    for planned in plan_missing_home_config_targets(config) {
        let result = planned.and_then(|(dir, file)| {
            if inspect_only {
                return Ok(dir.into_iter().chain([file]).collect());
            }
            create_empty_config(dir.as_deref(), &file)
                .map_err(|e| format!("{} ({e})", file.display()))
        });
        match result {
            Ok(paths) => made.extend(paths),
            Err(what) => ui::warn(&format!(
                "Could not create {what}. Git on the host reads it through your home Git \
                 config symlink once it exists, and it sits in a writable tree, so the \
                 agent can create it in this run."
            )),
        }
    }
    if !inspect_only && !made.is_empty() {
        let list: Vec<String> = made.iter().map(|p| p.display().to_string()).collect();
        ui::info(&format!(
            "Created empty {} so Bubblewrap can bind it read-only: git on the host \
             reads it through your home Git config symlink, and it sits in a writable \
             tree. Git reads an empty one the same as a missing one, but `git config \
             --global` writes to ~/.config/git/config once it exists and ~/.gitconfig \
             does not.",
            list.join(", ")
        ));
    }
    made
}

#[cfg(target_os = "linux")]
fn prepare_impl(
    config: &SandboxConfig,
    extra_git_dirs: &[PathBuf],
    pnpm_shadow_dir: Option<&Path>,
    inspect_only: bool,
) -> Result<PreparedSandbox, String> {
    // Warn about config options that Linux cannot enforce at kernel level.
    // (Deny paths are handled after bwrap resolution below — with Bubblewrap
    // they ARE enforced, via mount masks.)
    if !config.allow_env_files {
        ui::warn(
            "allow_env_files=false is not fully enforceable on Linux: \
             Landlock grants the project directory full read access, so .env files \
             within it remain readable. Differs from macOS Seatbelt behavior.",
        );
    }
    // Landlock network rules are port-based, not address-based — localhost
    // cannot be distinguished from remote hosts at the kernel level.
    if config.proxy_port.is_none()
        && (!config.localhost_ports.is_empty() || config.allow_localhost_any)
    {
        ui::warn(
            "Localhost protection limited on Linux without proxy: \
             Landlock cannot distinguish localhost from remote hosts. \
             Use --with-proxy for localhost SSRF protection.",
        );
    }
    // proxy.forced now denies every non-TCP IP socket at the seccomp layer.
    // Without this line the failure is a bare "Operation not permitted" from
    // socket(2) with nothing naming cplt, which is a miserable thing to debug.
    if config.proxy_forced {
        ui::info(
            "proxy.forced also blocks non-TCP IP sockets (UDP, raw, SCTP): they would \
             bypass the proxy entirely. Anything that opens one gets EPERM from \
             socket() — a UDP tool reached via --allow-localhost, and also code that \
             merely enumerates network interfaces through an AF_INET datagram socket \
             (the JDK's SIOCGIFCONF path, so Gradle). seccomp cannot see the \
             destination address, so there is no loopback exemption.",
        );
    }
    // A restriction the user asked for and cannot have is said out loud, not
    // dropped (AGENTS.md "No silent grants").
    if config.deny_nested_git {
        ui::warn(
            "sandbox.deny_nested_git has no effect on Linux: Landlock cannot deny a \
             path inside a tree it allows, and bubblewrap only protects paths that \
             exist at launch. A .git created during the session is reported when it \
             ends, not blocked.",
        );
    }
    if config.allow_docker {
        ui::warn(
            "--allow-docker on Linux grants the Docker/Podman daemon sockets and \
             exempts them from the Bubblewrap socket masks — daemon socket access is \
             effectively host root. ~/.docker is readable (not writable), including \
             any registry credentials stored inline in config.json and, unlike macOS, \
             ~/.docker/trust/private: Landlock cannot deny a subpath of a granted \
             directory.",
        );
    }
    // Finding 2: on Linux, allow_localhost_any drops EVERY Landlock TCP-connect
    // rule (any host, any port), not just localhost — Landlock is port-based and
    // cannot express "all localhost ports only". This disables kernel network
    // restriction entirely; an agent can raw-socket to any remote host:port.
    // macOS still pins localhost at the kernel level, so this is Linux-specific.
    // proxy.forced supersedes it (reconciled earlier) and is the safe choice.
    if config.allow_localhost_any {
        ui::warn(
            "--allow-localhost-any DISABLES kernel network restriction entirely on Linux: \
             Landlock is port-based and cannot allow 'all localhost ports' without allowing \
             the same ports on every remote host, so ALL Landlock TCP-connect rules are dropped \
             (an agent can then connect to any host:port directly). macOS still pins localhost. \
             Prefer --proxy-forced (which supersedes this flag) or specific --allow-localhost <PORT>.",
        );
    }

    let mut policy = landlock_mod::generate_policy(config);
    let mut profile_text = landlock_mod::describe_policy(&policy);

    // A withdrawn grant another rule quietly gives back is said out loud
    // (#324). Resolved the way `canonicalize_agent_dirs` resolves the rule.
    if config.deny_copilot_dir_exec && config.agent.needs_copilot_dir() {
        let copilot = config.home_dir.join(".copilot");
        let copilot = std::fs::canonicalize(&copilot).unwrap_or(copilot);
        for w in landlock_mod::copilot_dir_exec_residuals(
            &policy.fs_rules,
            &copilot,
            config.copilot_install_dir,
        ) {
            ui::warn(&w);
        }
    }

    // Repositories nested inside a writable root, found once and given to BOTH
    // path sets. The leaf binds and the rename pins have to see the same list:
    // a read-only bind pins content, not the name, so a nested `.git` that is
    // bound but not pinned can be renamed aside and recreated writable —
    // GHSA-39xf-9j26-f82m one directory down (#498 review).
    let (nested_repos, nested_capped) = {
        let (write_roots, _) = git_roots(config, extra_git_dirs);
        bubblewrap::nested_repo_roots(&write_roots)
    };
    // #551: a credential entry linked into a granted tree (`~/.ssh ->
    // ~/dotfiles/ssh` with the dotfiles repo as the project) is readable at
    // its target, and Landlock cannot take that back. Bubblewrap masks it
    // there, and pins the directories above it so `mv ssh ssh2 && mkdir ssh`
    // cannot swap in a fresh one under the link.
    let credential_links = landlock_mod::credential_links(config.home_dir, &policy.fs_rules);
    let credential_targets: Vec<PathBuf> =
        credential_links.iter().map(|l| l.target.clone()).collect();
    // Built again after #553 creates files below, since both sets only cover
    // paths that exist.
    let overlay_paths = || {
        let ro_protect = ro_protect_paths(config, extra_git_dirs, &nested_repos);
        let mut pins = pin_paths(config, extra_git_dirs, &nested_repos);
        pins.extend(home_config_target_pins(config, &credential_targets));
        pins.sort();
        pins.dedup();
        (ro_protect, pins)
    };
    let (mut ro_protect, mut pins) = overlay_paths();

    // Deny-path masks: Landlock cannot deny subpaths within allowed
    // directories, but Bubblewrap can shadow them at the mount level — denied
    // files read as EACCES, denied dirs read as empty (macOS gives EACCES for
    // both; the content is unreachable either way).
    // Built-in UNIX-socket masks (Finding A): D-Bus, systemd's private socket
    // and — unless --allow-docker — the container-runtime sockets. Each is an
    // escape *out of* the sandbox, and below kernel 7.1 Landlock cannot gate
    // connect(2) to a pathname socket at all, so a bwrap mount mask is the only
    // thing that can take them away. Non-existent entries are dropped here so
    // they never show up in the "could not be mount-masked" warning; the masks
    // are only ever applied when bwrap actually wraps the run.
    let socket_masks: Vec<PathBuf> = policy::socket_mask_paths(
        config.home_dir,
        policy::current_uid(),
        policy::xdg_runtime_dir_env().as_deref(),
        config.allow_docker,
    )
    .into_iter()
    .filter(|p| p.exists())
    .collect();
    let deny_masks = bubblewrap::build_deny_masks(
        config.extra_deny,
        &socket_masks,
        &credential_links,
        config.scratch_dir,
    );

    // Decide bubblewrap wrapping before `precompute()` consumes `policy`.
    // `resolve()` only clones `fs_rules`/`net_rules` on the arms that actually
    // build a wrapper (explicit-on, or auto-detect with bwrap available) — the
    // disabled and fallback arms borrow and clone nothing.
    let mut bwrap_wrapper = bubblewrap::resolve(
        config.use_bubblewrap,
        &policy,
        bubblewrap::Overlays {
            read_only: &ro_protect,
            pins: &pins,
        },
        &deny_masks,
    )?;

    // #553: a home Git config file a link points at inside a writable tree,
    // but which does not exist yet, gets no bind, so the agent could create
    // it. Only once Bubblewrap has passed its probe and will wrap this run:
    // created any earlier, a probe failure would fall back to Landlock, which
    // cannot protect the file inside the tree. The warning further down
    // covers that case. The wrapper is then rebuilt, probe included, so the
    // read-only bind and the rename pins cover the new files. A call that
    // only inspects the policy creates nothing and says what a launch would.
    if let Some(strict) = bwrap_wrapper.as_ref().map(|w| w.strict) {
        let made = create_missing_home_config(config, inspect_only);
        if inspect_only && !made.is_empty() {
            use std::fmt::Write as _;
            profile_text
                .push_str("## Would create empty at launch (home Git config link targets, #553)\n");
            for p in &made {
                let _ = writeln!(profile_text, "  {}", p.display());
            }
            profile_text.push('\n');
        } else if !made.is_empty() {
            (ro_protect, pins) = overlay_paths();
            let overlays = bubblewrap::Overlays {
                read_only: &ro_protect,
                pins: &pins,
            };
            let rebuilt = bubblewrap::build_wrapper(&policy, overlays, &deny_masks, strict)
                .map_err(|e| {
                    format!(
                        "Bubblewrap failed after cplt created the empty home Git config files \
                         it binds read-only: {e}. Not starting without that bind."
                    )
                })?;
            bwrap_wrapper = Some(rebuilt);
        }
    }

    // Under bubblewrap a root AGENTS.md below the private /tmp gets no mount
    // (`mount_rules`), so the launch gives no grant: do not print one.
    if bwrap_wrapper.is_some()
        && let Some(rule) = policy.plain_file.map(|i| &policy.fs_rules[i])
        && rule.path.starts_with("/tmp")
    {
        profile_text =
            profile_text.replacen(&landlock_mod::root_agents_md_description(&rule.path), "", 1);
    }

    // Said only where it is true: without bubblewrap none of these binds exist,
    // so warning about a bounded scan there would imply a protection the host
    // does not have. With bubblewrap, a truncated scan means a `.git/hooks`
    // deeper in that tree really did stay writable, and that is worth a line.
    if nested_capped && bwrap_wrapper.is_some() {
        ui::warn(&format!(
            "Stopped looking for repositories nested inside the writable roots after {} \
             directories, so a repository deeper in one of them gets none of the \
             protections a nested repository should have: .git/hooks, .cplt.toml, \
             .github/hooks and the agent auto-exec paths all stay writable there. Name the \
             repositories you work in with --repo-dir, or grant a narrower tree.",
            policy::NESTED_SCAN_LIMIT
        ));
    }

    // #551: Landlock alone cannot deny inside a grant, so a credential linked
    // into one stays readable unless bubblewrap masked it. Say so per entry.
    let masks = bwrap_wrapper.is_some().then_some(&deny_masks);
    for w in unmasked_credential_warnings(&credential_links, masks) {
        ui::warn(&w);
    }

    // #524: the read-only bind on a dotfiles target is bwrap's; Landlock
    // alone leaves it writable through the tree it sits in. Say so rather
    // than let SECURITY.md's "read-only" stand for this run.
    if bwrap_wrapper.is_none() {
        for (target, tree) in
            home_config_targets_in_writable_trees(config, home_config_link_targets(config.home_dir))
        {
            ui::warn(&format!(
                "{} is the target of a home Git config symlink and sits inside {tree}. \
                 cplt keeps that config read-only only with Bubblewrap, which is not active, \
                 so the agent can edit it in this run. Install bubblewrap, or move the file \
                 out of the writable tree.",
                target.display()
            ));
        }
        // #553: one that does not exist yet can be created, with the same
        // effect on the host's next git command.
        for (target, tree) in home_config_targets_in_writable_trees(
            config,
            policy::missing_home_config_link_targets(config.home_dir),
        ) {
            ui::warn(&format!(
                "{} is where a home Git config symlink points, inside {tree}, and does not \
                 exist yet. Without Bubblewrap cplt cannot stop the agent creating it in \
                 this run, and git on the host would read it. Install bubblewrap, or point \
                 the link out of the writable tree.",
                target.display()
            ));
        }
    }

    // `AgentDir::create_dirs` (Pi's mkdir-based trust lock) needs
    // MakeDir|RemoveDir on the parent, and Landlock cannot scope those to a
    // name. Same-directory rename needs exactly those two rights and nothing
    // else (`current_check_refer_path` in security/landlock/fs.c: REFER is only
    // consulted when the parents differ), so on a plain-Landlock host the grant
    // would let the agent `mv bin bin.old; mv tmp bin` — the H-13/H-05 escape
    // the read-only root exists to close. Under bubblewrap it holds: every
    // exec-only child and writable sibling is a mountpoint (`ro_protect`,
    // `pins`, the writable binds), and rename/rmdir of a mountpoint is EBUSY.
    // So the grant is kept only when bubblewrap actually resolved; otherwise
    // the root stays read-only and Pi does not start, which `cplt doctor`
    // explains. Cleared here, after `resolve` consumed the rules, so the
    // writable bind it needs is still emitted when bwrap IS active.
    if bwrap_wrapper.is_none() {
        let mut cleared = Vec::new();
        for rule in policy.fs_rules.iter_mut().filter(|r| r.access.create_dirs) {
            rule.access.create_dirs = false;
            cleared.push(rule.path.display().to_string());
        }
        if !cleared.is_empty() {
            ui::warn(&format!(
                "Create-only grant on {} is NOT applied without Bubblewrap: Landlock \
                 cannot stop a same-directory rename, so it would make the exec-only \
                 child replaceable. The directory stays read-only; the agent may fail \
                 to start. Install bubblewrap to enable it.",
                cleared.join(", ")
            ));
        }
    }

    // UNIX-socket reachability has three distinct regimes and they are not
    // interchangeable, so say which one this run is in rather than implying the
    // hole is closed (or that it is still open when it is not).
    report_unix_socket_regime(bwrap_wrapper.is_some(), deny_masks.socket_mask_count());

    if !config.extra_deny.is_empty() {
        if bwrap_wrapper.is_some() {
            let masked = deny_masks.mask_count();
            if masked > 0 {
                ui::info(&format!(
                    "Deny paths enforced via Bubblewrap mount masks ({masked} masked)."
                ));
            }
            let skipped = deny_masks.skipped();
            if !skipped.is_empty() {
                let list = skipped
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                ui::warn(&format!(
                    "{} deny path(s) could not be mount-masked and are NOT \
                     enforced: {list}",
                    skipped.len()
                ));
                if let Some(reason) = deny_masks.placeholder_error() {
                    ui::warn(&format!("File deny paths were skipped: {reason}."));
                }
            }
        } else {
            ui::warn(
                "Deny paths are NOT enforced without Bubblewrap: Landlock cannot \
                 deny subpaths within allowed directories. Proxy and env hardening \
                 provide defense-in-depth.",
            );
            for file in
                policy::unenforced_build_credential_denies(config.home_dir, config.extra_deny)
            {
                ui::warn(&format!(
                    "{} stays readable and writable despite the deny: it sits inside \
                     a granted tool directory, and without Bubblewrap nothing can take \
                     it back.",
                    file.display()
                ));
            }
        }
    }

    // Pre-compute everything in the parent process.
    // ABI check, BPF construction, and all allocation happens here.
    // The pre_exec hook only makes raw syscalls.
    let precomputed = landlock_mod::precompute(policy)?;

    Ok(PreparedSandbox {
        project_dir: config.project_dir.to_path_buf(),
        home_dir: config.home_dir.to_path_buf(),
        profile_text,
        scratch_dir: config.scratch_dir.map(Path::to_path_buf),
        pnpm_shadow_dir: pnpm_shadow_dir.map(Path::to_path_buf),
        // The automatic capability is macOS-only; direct Linux callers cannot
        // introduce a new /tmp path lifecycle or child environment override.
        playwright_socket_dir: None,
        // Chromium's nested sandbox is unavailable on both platforms: seccomp
        // denies the namespace syscalls it needs here, Seatbelt refuses the
        // reinitialization there. The opt-in signal is the same.
        playwright_runtime: policy::playwright_runtime_intent(
            config.allow_cache_exec,
            config.allow_cache_exec_any,
        ),
        proxy_port: config.proxy_port,
        agent: config.agent,
        allow_localhost: config.localhost_ports.to_vec(),
        allow_localhost_any: config.allow_localhost_any,
        npmrc_allowed: env::npmrc_explicitly_allowed(config.home_dir, config.extra_read),
        keychain_substitute: config.keychain_substitute.clone(),
        worktree_root: None,
        precomputed,
        bwrap_wrapper,
    })
}

// ── Internal helpers (macOS only) ──────────────────────────────

/// Validate all paths in a [`SandboxConfig`] for backend-specific injection.
///
/// On macOS, SBPL profiles use string interpolation — paths containing
/// `"`, `;`, `(`, etc. could inject malicious rules. This validates every
/// path that will be interpolated into the profile.
///
/// Linux uses Landlock's fd-based API which is immune to path injection.
#[cfg(target_os = "macos")]
fn validate_config_paths(config: &SandboxConfig) -> Result<(), String> {
    policy::validate_sbpl_path(config.project_dir).map_err(|e| format!("Project dir: {e}"))?;
    for root in config.named_roots {
        policy::validate_sbpl_path(root).map_err(|e| format!("Named repository: {e}"))?;
    }
    for dir in config.named_root_git_dirs {
        policy::validate_sbpl_path(dir).map_err(|e| format!("Named repository .git dir: {e}"))?;
    }
    policy::validate_sbpl_path(config.home_dir).map_err(|e| format!("Home dir: {e}"))?;
    // #524: the profile keeps a dotfiles target read-only only with a rule
    // naming it. One the profile cannot name inside a writable tree would stay
    // writable, so refuse, as for every other path here. Outside a writable
    // tree nothing grants the write, so the missing rule costs nothing.
    let targets = policy::home_config_link_targets(config.home_dir)
        .into_iter()
        .chain(policy::missing_home_config_link_targets(config.home_dir))
        .collect();
    for (target, _) in home_config_targets_in_writable_trees(config, targets) {
        policy::validate_sbpl_path(&target)
            .map_err(|e| format!("Home Git config symlink target: {e}"))?;
    }

    // Checked on its own, not only as one of `named_roots`: the profile
    // interpolates it into the managed-root rules as well (#574).
    if let Some(root) = config.managed_worktree_root {
        policy::validate_sbpl_path(root).map_err(|e| format!("Managed worktree root: {e}"))?;
    }
    if let Some(dir) = config.copilot_install_dir {
        policy::validate_sbpl_path(dir).map_err(|e| format!("Copilot install dir: {e}"))?;
    }
    if let Some(dir) = config.java_home {
        policy::validate_sbpl_path(dir).map_err(|e| format!("JAVA_HOME: {e}"))?;
    }
    if let Some(dir) = config.dotnet_root {
        policy::validate_sbpl_path(dir).map_err(|e| format!("DOTNET_ROOT: {e}"))?;
    }
    for d in config.existing_home_tool_dirs.unwrap_or(&[]) {
        policy::validate_sbpl_path(&d.path).map_err(|e| format!("Tool dir: {e}"))?;
    }
    if let Some(p) = config.git_hooks_path {
        policy::validate_sbpl_path(p).map_err(|e| format!("Git hooks path: {e}"))?;
    }
    if let Some(p) = config.git_common_dir {
        policy::validate_sbpl_path(p).map_err(|e| format!("Git common dir: {e}"))?;
    }
    if let Some(p) = config.root_agents_md {
        policy::validate_sbpl_path(p).map_err(|e| format!("Root AGENTS.md: {e}"))?;
    }
    if let Some(dir) = config.electron_app_dir {
        policy::validate_sbpl_path(dir).map_err(|e| format!("Electron app path: {e}"))?;
    }
    if let Some(dir) = config.scratch_dir {
        policy::validate_sbpl_path(dir).map_err(|e| format!("Scratch dir: {e}"))?;
    }
    for ad in config.agent_dirs {
        policy::validate_sbpl_path(&ad.path).map_err(|e| format!("Agent dir: {e}"))?;
    }
    for p in config.extra_read {
        policy::validate_sbpl_path(p).map_err(|e| format!("--allow-read path: {e}"))?;
    }
    for p in config.extra_write {
        policy::validate_sbpl_path(p).map_err(|e| format!("--allow-write path: {e}"))?;
    }
    for p in config.extra_exec {
        policy::validate_sbpl_path(p).map_err(|e| format!("--allow-exec path: {e}"))?;
    }
    for p in config.extra_socket {
        policy::validate_sbpl_path(p).map_err(|e| format!("--allow-socket path: {e}"))?;
    }
    for p in config.extra_deny {
        policy::validate_sbpl_path(p).map_err(|e| format!("--deny-path path: {e}"))?;
    }

    // allow_cache_exec subdirs are interpolated into SBPL string literals — validate here
    // as a second line of defence (config::merge already validates, but SandboxConfig can
    // be constructed directly by callers who bypass that path).
    for subdir in config.allow_cache_exec {
        if subdir.trim().is_empty() {
            return Err(
                "allow_cache_exec subdir must not be empty (would grant exec to all of ~/Library/Caches)"
                    .to_string(),
            );
        }
        for c in ['"', ')', '(', ';', '\\', '\n', '\r', '\0'] {
            if subdir.contains(c) {
                return Err(format!(
                    "allow_cache_exec subdir {subdir:?} contains unsafe characters"
                ));
            }
        }
        for component in subdir.trim_matches('/').split('/') {
            if component == ".." || component == "." {
                return Err(format!(
                    "allow_cache_exec subdir {subdir:?} contains path traversal"
                ));
            }
        }
    }

    Ok(())
}

/// Validate the platform-specific automatic Playwright socket capability.
///
/// macOS rechecks both the path shape and the created directory before adding
/// its narrow SBPL rules. Other platforms fail closed instead of accepting a
/// path whose lifecycle and policy grant they do not implement.
#[cfg(target_os = "macos")]
fn validate_playwright_socket_capability(path: Option<&Path>) -> Result<(), String> {
    if let Some(path) = path {
        policy::validate_playwright_socket_dir(path)
            .map_err(|e| format!("Playwright socket dir: {e}"))?;
        validate_created_playwright_socket_dir(path)?;
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn validate_playwright_socket_capability(path: Option<&Path>) -> Result<(), String> {
    if path.is_some() {
        return Err(
            "Playwright socket directories are supported only on macOS; refusing configured path"
                .to_string(),
        );
    }
    Ok(())
}

/// Recheck the filesystem object represented by the automatic capability.
///
/// Shape validation prevents SBPL interpolation/path widening; this check
/// prevents a direct library caller or stale guard from authorizing a symlink,
/// caller-owned replacement, or permissive pre-existing directory.
#[cfg(target_os = "macos")]
fn validate_created_playwright_socket_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = path
        .symlink_metadata()
        .map_err(|_| "Playwright socket dir does not exist".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("Playwright socket dir must be a real directory".to_string());
    }
    if metadata.uid() != policy::current_uid() {
        return Err("Playwright socket dir must be owned by the current user".to_string());
    }
    if metadata.mode() & 0o777 != 0o700 {
        return Err("Playwright socket dir must have mode 0700".to_string());
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|_| "Playwright socket dir cannot be canonicalized".to_string())?;
    if canonical != path {
        return Err("Playwright socket dir must not resolve through a symlink".to_string());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test code: no unsandboxed parent to protect (#239)
mod tests {
    use super::*;

    /// #551: without bubblewrap a credential linked into a grant is named at
    /// launch with its target and the grant; under bubblewrap only one the
    /// masks do not cover is, and with a reason that says so.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_linked_credential_warns_unless_bubblewrap_masked_it() {
        let base = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let dotfiles = base.path().canonicalize().unwrap();
        let ssh = dotfiles.join("ssh");
        std::fs::create_dir(&ssh).unwrap();
        let links = [landlock_mod::CredentialLink {
            rel: ".ssh",
            named: dotfiles.join(".ssh"),
            target: ssh.clone(),
            grant: dotfiles.clone(),
        }];

        let w = unmasked_credential_warnings(&links, None);
        assert_eq!(w.len(), 1, "{w:?}");
        for part in [
            "~/.ssh".to_string(),
            format!("resolves to {}", ssh.display()),
            format!("granted {}", dotfiles.display()),
            "Bubblewrap is not active".to_string(),
        ] {
            assert!(w[0].contains(&part), "missing {part:?} in {}", w[0]);
        }

        let masked = bubblewrap::build_deny_masks(&[], &[], &links, None);
        assert!(unmasked_credential_warnings(&links, Some(&masked)).is_empty());

        let unmasked = bubblewrap::build_deny_masks(&[], &[], &[], None);
        let w = unmasked_credential_warnings(&links, Some(&unmasked));
        assert!(w.len() == 1 && w[0].contains("could not mask"), "{w:?}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn validates_only_a_live_created_playwright_socket_capability() {
        let guard = crate::scratch::PlaywrightSocketDir::create().expect("create socket dir");
        let path = guard.path().to_path_buf();

        validate_playwright_socket_capability(Some(&path)).expect("live capability must validate");
        drop(guard);

        assert_eq!(
            validate_playwright_socket_capability(Some(&path)).unwrap_err(),
            "Playwright socket dir does not exist"
        );
    }

    fn test_config<'a>(home_dir: &'a Path, grants: &'a [PathBuf]) -> SandboxConfig<'a> {
        SandboxConfig {
            project_dir: Path::new("/project"),
            home_dir,
            extra_read: grants,
            extra_write: &[],
            extra_exec: &[],
            extra_socket: &[],
            extra_deny: &[],
            named_roots: &[],
            named_root_git_dirs: &[],
            managed_worktree_root: None,
            existing_home_tool_dirs: None,
            existing_app_dirs: None,
            extra_ports: &[],
            localhost_ports: &[],
            proxy_port: None,
            proxy_forced: false,
            allow_env_files: false,
            allow_localhost_any: false,
            scratch_dir: None,
            keychain_substitute: None,
            playwright_socket_dir: None,
            allow_tmp_exec: false,
            copilot_install_dir: None,
            copilot_cache_env: &crate::sandbox::no_cache_env,
            java_home: None,
            dotnet_root: None,
            git_hooks_path: None,
            git_common_dir: None,
            root_agents_md: None,
            allow_gpg_signing: false,
            deny_clipboard: false,
            deny_nested_git: false,
            deny_copilot_dir_exec: false,
            allow_jvm_attach: false,
            allow_msbuild: false,
            allow_docker: false,
            electron_app_dir: None,
            agent: Agent::Copilot,
            agent_dirs: &[],
            allow_cache_exec: &[],
            allow_cache_exec_any: false,
            allow_browser: false,
            use_bubblewrap: None,
        }
    }

    /// #252: revoking the root AGENTS.md grant removes exactly that rule, on
    /// both backends and in the text `describe()` prints. A user `allow.read`
    /// naming the same file is a separate grant and survives the revoke.
    #[test]
    fn revoke_root_agents_md_removes_only_the_tagged_rule() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let file = root.join("AGENTS.md");
        std::fs::write(&file, "x").unwrap();
        let user = [file.clone()];
        let mut config = test_config(&home, &user);
        config.root_agents_md = Some(&file);
        config.use_bubblewrap = Some(false);
        let mut sandbox = prepare(&config).unwrap();

        #[cfg(target_os = "macos")]
        let chunk = profile::root_agents_md_sbpl(&file);
        #[cfg(target_os = "linux")]
        let chunk = landlock_mod::root_agents_md_description(&file);
        assert!(describe(&sandbox).contains(&chunk), "not granted");

        // prepare() ran Landlock-only; stand in the wrapper resolve() builds
        // when bwrap is present, the user's rule and the tagged one side by side.
        #[cfg(target_os = "linux")]
        {
            assert!(sandbox.precomputed.deferred_plain_file.is_some());
            let rule = |path: &Path| landlock_mod::FsRule {
                path: path.to_path_buf(),
                access: landlock_mod::FsAccess {
                    read: true,
                    write: false,
                    execute: false,
                    ioctl: false,
                    create_dirs: false,
                },
            };
            sandbox.bwrap_wrapper = Some(bubblewrap::BubblewrapWrapper {
                bwrap_path: PathBuf::from("/usr/bin/bwrap"),
                bwrap_args: vec![],
                fs_rules: vec![rule(&file), rule(&file)],
                net_rules: vec![],
                restrict_net_connect: true,
                strict: false,
                deny_mask_count: 0,
                socket_mask_count: 0,
                proxy_forced: false,
                plain_file: Some(1),
            });
        }

        sandbox.revoke_root_agents_md(&file);
        let text = describe(&sandbox);
        assert!(!text.contains(&chunk), "grant still described");
        assert!(
            text.contains(&file.display().to_string()),
            "the user's own allow.read went with it"
        );
        #[cfg(target_os = "linux")]
        {
            assert!(sandbox.precomputed.deferred_plain_file.is_none());
            let w = sandbox.bwrap_wrapper.as_ref().unwrap();
            assert!(w.plain_file.is_none());
            assert_eq!(
                w.fs_rules.len(),
                1,
                "user rule removed, or tagged rule kept"
            );
        }
    }

    /// A refused root AGENTS.md is never emitted, yet the launch still revokes
    /// it when the block is not written. That must be a no-op, not a panic.
    #[test]
    fn revoke_root_agents_md_of_a_refused_path_is_a_no_op() {
        let temp = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(temp.path()).unwrap();
        let refused = home.join(".netrc");
        let mut config = test_config(&home, &[]);
        config.root_agents_md = Some(&refused);
        config.use_bubblewrap = Some(false);
        let mut sandbox = prepare(&config).unwrap();
        let before = describe(&sandbox).to_string();
        sandbox.revoke_root_agents_md(&refused);
        assert_eq!(describe(&sandbox), before);
    }

    fn pnpm_tool_dir(path: &str) -> &'static HomeToolDir {
        HOME_TOOL_DIRS
            .iter()
            .find(|dir| dir.path == path)
            .expect("pnpm tool dir")
    }

    #[test]
    fn pnpm_package_manager_store_must_not_overlap_a_writable_store() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let store = home.join(".local/share/pnpm/store");
        let package_store = store.join("custom/package-manager-store");
        std::fs::create_dir_all(&package_store).unwrap();
        let dirs = [
            ResolvedToolDir {
                path: store,
                target: None,
                dir: pnpm_tool_dir(".local/share/pnpm/store"),
            },
            ResolvedToolDir {
                path: package_store,
                target: None,
                dir: pnpm_tool_dir(".local/share/pnpm/package-manager-store"),
            },
        ];
        let mut config = test_config(home, &[]);
        config.existing_home_tool_dirs = Some(&dirs);

        let error = validate_pnpm_tool_dirs(&config).expect_err("overlap must be refused");
        assert!(error.contains("overlaps writable tool directory"));
    }

    #[test]
    fn pnpm_package_manager_store_must_not_resolve_through_a_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let target = temp.path().join("target");
        std::fs::create_dir_all(home.join(".local/share/pnpm")).unwrap();
        std::fs::create_dir(&target).unwrap();
        let package_store = home.join(".local/share/pnpm/package-manager-store");
        symlink(&target, &package_store).unwrap();
        let dirs = [ResolvedToolDir {
            path: package_store,
            target: None,
            dir: pnpm_tool_dir(".local/share/pnpm/package-manager-store"),
        }];
        let mut config = test_config(&home, &[]);
        config.existing_home_tool_dirs = Some(&dirs);

        let error = validate_pnpm_tool_dirs(&config).expect_err("symlink must be refused");
        assert!(error.contains("resolves through a symlink"));
    }

    #[test]
    fn ordinary_exec_grant_is_not_treated_as_a_pnpm_shadow() {
        // A real home: `prepare` creates the Copilot cache in it.
        let (_guard, root) = copilot_cache_tree();
        let home = root.join("home");
        let project = home.join("project");
        let grant = home.join(".cplt-pnpm-shadow/user-selected");
        let grants = [grant];
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;
        config.extra_exec = &grants;

        let prepared = prepare(&config).expect("ordinary grant must prepare");
        assert_eq!(prepared.pnpm_shadow_dir, None);
    }

    /// Finding A: the agent's own writable data dirs are granted by the
    /// backends, not by config, so an `allow.exec` over an ancestor of one was
    /// accepted and then unioned with the write grant by Landlock into the
    /// binary-drop pair `validate_exec_grants` exists to refuse. The concrete
    /// case is `allow.exec = ["~/.local"]` — the pipx layout — with OpenCode,
    /// whose data dir is `~/.local/share/opencode`.
    #[test]
    fn exec_grant_over_an_agent_data_dir_is_refused() {
        let home = Path::new("/home/test");
        let agent_dirs = [AgentDir {
            path: home.join(".local/share/opencode"),
            write: true,
            map_exec: false,
            process_exec: false,
            write_files: vec![],
            create_dirs: vec![],
        }];
        let exec = [home.join(".local")];
        let mut config = test_config(home, &[]);
        // No tool dirs, so the refusal can only come from the agent dir.
        config.existing_home_tool_dirs = Some(&[]);
        config.agent_dirs = &agent_dirs;
        config.extra_exec = &exec;

        let error = validate_exec_grants(&config).expect_err("the overlap must be refused");
        assert!(error.contains(".local/share/opencode"), "{error}");
        assert!(error.contains("writable agent directory"), "{error}");
    }

    #[test]
    fn exec_grant_over_cypress_app_data_is_refused() {
        let home = Path::new("/home/test");
        let allow_cache_exec = ["Cypress".to_string()];
        let app_data = policy::cypress_app_data_dir_with_env(home, &policy::no_cache_env);
        let exec = [app_data
            .parent()
            .expect("Cypress app data must have a parent")
            .to_path_buf()];
        let mut config = test_config(home, &[]);
        config.existing_home_tool_dirs = Some(&[]);
        config.allow_cache_exec = &allow_cache_exec;
        config.extra_exec = &exec;

        let error = validate_exec_grants(&config).expect_err("the overlap must be refused");
        assert!(error.contains(&app_data.display().to_string()), "{error}");
        assert!(
            error.contains("writable Cypress state directory"),
            "{error}"
        );
    }

    #[test]
    fn symlinked_cache_exec_directory_is_refused() {
        let (_guard, root) = copilot_cache_tree();
        let home = root.join("home");
        let project = root.join("project");
        #[cfg(target_os = "macos")]
        let cache = home.join("Library/Caches");
        #[cfg(not(target_os = "macos"))]
        let cache = policy::xdg_cache_dir(&home);
        std::fs::create_dir_all(&cache).unwrap();
        std::os::unix::fs::symlink(&project, cache.join("Cypress")).unwrap();
        let allow_cache_exec = ["Cypress".to_string()];
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;
        config.existing_home_tool_dirs = Some(&[]);
        config.allow_cache_exec = &allow_cache_exec;
        config.use_bubblewrap = Some(false);

        let Err(error) = prepare(&config) else {
            panic!("symlinked cache-exec directory must be refused");
        };
        assert!(error.contains("allow_cache_exec path"), "{error}");
        assert!(error.contains(&project.display().to_string()), "{error}");
    }

    #[test]
    fn symlinked_cache_exec_root_is_refused_for_allow_any() {
        let (_guard, root) = copilot_cache_tree();
        let home = root.join("home");
        let project = root.join("project");
        #[cfg(target_os = "macos")]
        let cache = home.join("Library/Caches");
        #[cfg(not(target_os = "macos"))]
        let cache = home.join(".cache");
        std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&project, &cache).unwrap();
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;
        config.existing_home_tool_dirs = Some(&[]);
        config.allow_cache_exec_any = true;
        config.use_bubblewrap = Some(false);

        let Err(error) = prepare(&config) else {
            panic!("symlinked cache-exec root must be refused");
        };
        assert!(error.contains("Cache-exec root"), "{error}");
        assert!(error.contains(&project.display().to_string()), "{error}");
    }

    #[test]
    fn cypress_app_data_is_created_before_backend_preparation() {
        let (_guard, root) = copilot_cache_tree();
        let home = root.join("home");
        let project = root.join("project");
        let allow_cache_exec = ["Cypress".to_string()];
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;
        config.existing_home_tool_dirs = Some(&[]);
        config.allow_cache_exec = &allow_cache_exec;
        config.use_bubblewrap = Some(false);
        let app_data = policy::cypress_app_data_dir_with_env(&home, &policy::no_cache_env);

        prepare_with_pnpm_shadow(&config, None, true).expect("inspection must validate");
        assert!(!app_data.exists(), "inspection must not create app state");

        prepare(&config).expect("launch must prepare app state");
        assert!(app_data.is_dir(), "launch must create app state");
    }

    #[test]
    fn cypress_app_data_symlink_is_refused() {
        let (_guard, root) = copilot_cache_tree();
        let home = root.join("home");
        let project = root.join("project");
        let allow_cache_exec = ["Cypress".to_string()];
        let app_data = policy::cypress_app_data_dir_with_env(&home, &policy::no_cache_env);
        std::fs::create_dir_all(app_data.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&project, &app_data).unwrap();
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;
        config.existing_home_tool_dirs = Some(&[]);
        config.allow_cache_exec = &allow_cache_exec;
        config.use_bubblewrap = Some(false);

        let Err(error) = prepare(&config) else {
            panic!("symlinked state must be refused");
        };
        assert!(error.contains("resolves through a symlink"), "{error}");
        assert!(error.contains(&project.display().to_string()), "{error}");
    }

    #[test]
    fn writable_cypress_app_data_parent_is_refused() {
        let (_guard, root) = copilot_cache_tree();
        let home = root.join("home");
        let project = root.join("project");
        let allow_cache_exec = ["Cypress".to_string()];
        let app_data = policy::cypress_app_data_dir_with_env(&home, &policy::no_cache_env);
        let writes = [app_data.parent().unwrap().to_path_buf()];
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;
        config.extra_write = &writes;
        config.existing_home_tool_dirs = Some(&[]);
        config.allow_cache_exec = &allow_cache_exec;
        config.use_bubblewrap = Some(false);

        let Err(error) = prepare(&config) else {
            panic!("writable parent must be refused");
        };
        assert!(
            error.contains("could replace the state directory"),
            "{error}"
        );
        assert!(error.contains(&writes[0].display().to_string()), "{error}");
    }

    /// The ro_protect set the bwrap overlay consumes, end to end.
    ///
    /// A nested repository must reach BOTH assembled sets — the read-only binds
    /// and the rename pins. A bind without a pin is walk-aroundable: a
    /// read-only bind pins content, not the name, so `mv .git g2 && mkdir .git`
    /// gives back a writable `.git/hooks` under a name no bind covers.
    ///
    /// Asserted on the assembled sets, not on the helpers: the first version of
    /// this feature had correct helpers and passed the nested list to only one
    /// of them (#498 review), and a test that calls `rename_pin_paths` directly
    /// cannot see that — mine did not, which is why this one exists here.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_nested_repository_reaches_both_the_binds_and_the_pins() {
        let repo = tempfile::tempdir().expect("tempdir");
        let nested = repo.path().join("libs/model");
        std::fs::create_dir_all(nested.join(".git/hooks")).expect("nested hooks");
        let home = Path::new("/home/test");
        let config = test_config(home, &[]);

        let binds = super::ro_protect_paths(&config, &[], std::slice::from_ref(&nested));
        assert!(
            binds.contains(&nested.join(".git/hooks")),
            "nested hooks must be bound read-only: {binds:?}"
        );

        let pins = super::pin_paths(&config, &[], std::slice::from_ref(&nested));
        assert!(
            pins.contains(&nested.join(".git")),
            "and its .git must be a mountpoint, or the bind can be renamed around: {pins:?}"
        );
    }

    /// The helpers each had a test; the wiring that assembles them did not, and
    /// a mutation deleting the Copilot line from the caller passed Linux CI
    /// green. This asserts the assembled set, which is what the overlay
    /// actually re-binds.
    /// #306: the same question must not be answered twice, differently.
    /// `cplt config set allow.read ~/.netrc` used to succeed and then be
    /// refused at every launch, so the user found out later, about a line they
    /// had forgotten writing. One predicate serves both now.
    #[test]
    fn a_grant_no_launch_can_honour_is_refused_by_one_predicate() {
        let home = Path::new("/home/test");

        for (key, path) in [
            ("allow.read", home.join(".netrc")),
            ("allow.write", home.join(".ssh")),
            ("allow.read", home.join(".config/cplt/config.toml")),
        ] {
            let err =
                super::validate_grant_path(key, &path, home).expect_err("{path:?} must be refused");
            assert!(err.contains(key), "the refusal names the key: {err}");
        }

        super::validate_grant_path("allow.read", Path::new("/opt/homebrew"), home)
            .expect("an ordinary grant is the point of the feature");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ro_protect_set_carries_the_copilot_package_dirs_for_copilot_only() {
        let home = Path::new("/home/test");
        let mut config = test_config(home, &[]);
        config.agent = Agent::Copilot;
        let paths = super::ro_protect_paths(&config, &[], &[]);
        for expected in [home.join(".copilot/pkg"), home.join(".cache/copilot/pkg")] {
            assert!(
                paths.contains(&expected),
                "{} must be in the bwrap read-only set, got {paths:?}",
                expected.display()
            );
        }

        config.agent = Agent::Claude;
        let paths = super::ro_protect_paths(&config, &[], &[]);
        assert!(
            !paths.iter().any(|p| p.starts_with(home.join(".copilot"))),
            "no Copilot package binds for a non-Copilot agent, got {paths:?}"
        );
    }

    /// #514, Linux half: once the PATH shim dir exists it is bound read-only,
    /// and the directories between it and a writable ancestor grant are pinned
    /// against rename. Absent until then, so the policy does not change for a
    /// user who never opted in.
    #[test]
    fn shim_dir_is_read_only_protected_once_it_exists() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = std::fs::canonicalize(tmp.path()).expect("canonical home");
        let shims = home.join(".local/share/cplt/bin");
        assert!(super::shim_ro_protect_paths(&home).is_empty());
        std::fs::create_dir_all(&shims).expect("mkdir shims");
        assert_eq!(super::shim_ro_protect_paths(&home), vec![shims.clone()]);

        #[cfg(target_os = "linux")]
        {
            let grants = [home.join(".local")];
            let mut config = test_config(&home, &[]);
            config.extra_write = &grants;
            let ro = super::ro_protect_paths(&config, &[], &[]);
            assert!(ro.contains(&shims), "shim dir missing from {ro:?}");
            let pins = super::pin_paths(&config, &[], &[]);
            for pinned in [home.join(".local/share/cplt"), home.join(".local/share")] {
                assert!(
                    pins.contains(&pinned),
                    "{} missing from {pins:?}",
                    pinned.display()
                );
            }
            assert!(!pins.contains(&home.join(".local")), "{pins:?}");
        }
    }

    /// `~/.gitconfig -> <project>/dotfiles/gitconfig`: a dotfiles repo being
    /// edited as the project (#524). Returns a canonical `(home, project,
    /// target)` and keeps the tempdirs alive.
    fn dotfiles_in_project() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let home = root.join("home");
        let project = root.join("project");
        let target = project.join("dotfiles/gitconfig");
        std::fs::create_dir_all(&home).expect("mkdir home");
        std::fs::create_dir_all(target.parent().unwrap()).expect("mkdir dotfiles");
        std::fs::write(&target, "[user]\n\tname = cplt\n").expect("write target");
        std::os::unix::fs::symlink(&target, home.join(".gitconfig")).expect("symlink");
        (tmp, home, project, target)
    }

    /// The launch warning's predicate: a target inside the project is
    /// reported as the project's, and stops being so once the project moves.
    #[test]
    fn home_config_target_in_the_project_is_reported_as_writable() {
        let (_tmp, home, project, target) = dotfiles_in_project();
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;
        assert_eq!(
            super::home_config_targets_in_writable_trees(&config, home_config_link_targets(&home)),
            vec![(target, "the project directory")]
        );

        // The tempdir is itself under a system temp dir, which is a writable
        // tree too, so only the project attribution can be checked here.
        config.project_dir = Path::new("/elsewhere");
        let found =
            super::home_config_targets_in_writable_trees(&config, home_config_link_targets(&home));
        assert!(
            found.iter().all(|(_, why)| *why != "the project directory"),
            "{found:?}"
        );
    }

    /// Linux half of #524: Landlock cannot take the project's write back from
    /// a file inside it, so the bwrap overlay must bind the target read-only
    /// and pin the directory between it and the root against a rename.
    #[cfg(target_os = "linux")]
    #[test]
    fn ro_protect_set_carries_a_symlinked_home_git_config_target() {
        let (_tmp, home, project, target) = dotfiles_in_project();
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;
        let ro = super::ro_protect_paths(&config, &[], &[]);
        assert!(ro.contains(&target), "target missing from {ro:?}");
        let pins = super::pin_paths(&config, &[], &[]);
        assert!(
            pins.contains(&project.join("dotfiles")),
            "dotfiles dir missing from {pins:?}"
        );
        assert!(!pins.contains(&project), "the root is not pinned: {pins:?}");

        // A linked `~/.config/git`: an existing `config` there is bound
        // read-only too, or the agent could plant `core.fsmonitor` in it.
        let xdg = project.join("xdg-git");
        std::fs::create_dir_all(&xdg).expect("mkdir xdg");
        std::fs::write(xdg.join("config"), "").expect("write xdg config");
        std::fs::create_dir_all(home.join(".config")).expect("mkdir .config");
        std::os::unix::fs::symlink(&xdg, home.join(".config/git")).expect("symlink");
        let ro = super::ro_protect_paths(&config, &[], &[]);
        assert!(
            ro.contains(&xdg.join("config")),
            "xdg config missing from {ro:?}"
        );

        // Any writable tree counts, not only the project and grants: here the
        // writable `~/.cache` tool dir.
        let cached = home.join(".cache/dots/local");
        std::fs::create_dir_all(cached.parent().unwrap()).expect("mkdir cache dots");
        std::fs::write(&cached, "").expect("write cached");
        std::os::unix::fs::symlink(&cached, home.join(".gitconfig.local")).expect("symlink");
        let pins = super::pin_paths(&config, &[], &[]);
        assert!(
            pins.contains(&home.join(".cache/dots")),
            "cache dots dir missing from {pins:?}"
        );
        assert!(!pins.contains(&home.join(".cache")), "{pins:?}");
    }

    /// A target the profile cannot name inside a writable tree would get no
    /// deny and stay writable, so launch is refused, as for every other path
    /// the profile interpolates.
    #[cfg(target_os = "macos")]
    #[test]
    fn unnameable_home_config_target_in_the_project_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let home = root.join("home");
        let project = root.join("project");
        let target = project.join("dot(files)/gitconfig");
        std::fs::create_dir_all(&home).expect("mkdir home");
        std::fs::create_dir_all(target.parent().unwrap()).expect("mkdir dotfiles");
        std::fs::write(&target, "").expect("write target");
        std::os::unix::fs::symlink(&target, home.join(".gitconfig")).expect("symlink");
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;
        let err = super::validate_config_paths(&config).expect_err("must refuse");
        assert!(err.contains("Home Git config symlink target"), "{err}");
    }

    /// #574 review item 7: the managed worktree root is interpolated into the
    /// profile, so it is validated in its own right, not only when it is also
    /// one of `named_roots`.
    #[cfg(target_os = "macos")]
    #[test]
    fn unnameable_managed_worktree_root_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let root = home.join(".cplt-worktrees/a\"b");
        let mut config = test_config(&home, &[]);
        config.managed_worktree_root = Some(&root);
        let err = super::validate_config_paths(&config).expect_err("must refuse");
        assert!(err.contains("Managed worktree root"), "{err}");
    }

    /// #553: files are created only once Bubblewrap will wrap the run. With
    /// `bwrap` installed but failing its probe, auto mode falls back to
    /// Landlock, which cannot protect a file inside the writable tree, so
    /// nothing is created and the launch warns that the target is missing.
    #[cfg(target_os = "linux")]
    #[test]
    fn missing_home_config_is_not_created_when_bwrap_falls_back() {
        if bubblewrap::check_availability().is_none() {
            eprintln!("skipped: bwrap not installed");
            return;
        }
        let tmp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(&home).expect("mkdir home");
        std::fs::create_dir_all(&project).expect("mkdir project");
        let target = project.join("gitconfig");
        std::os::unix::fs::symlink(&target, home.join(".gitconfig")).expect("symlink");
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;

        bubblewrap::FAIL_PROBE.set(true);
        let prepared = prepare(&config);
        bubblewrap::FAIL_PROBE.set(false);
        assert!(prepared.expect("prepare").bwrap_wrapper.is_none());
        assert!(!target.exists(), "created without a wrapper");
        // What the "does not exist yet" launch warning iterates.
        assert_eq!(
            home_config_targets_in_writable_trees(
                &config,
                policy::missing_home_config_link_targets(&home)
            )
            .len(),
            1
        );

        // Control: with a working probe the same setup does create it.
        let prepared = prepare(&config).expect("prepare");
        assert!(prepared.bwrap_wrapper.is_some() && target.is_file());
    }

    /// What a launch under Bubblewrap does with the plan: create each entry,
    /// and return what was made alongside what was refused.
    fn create_missing(config: &SandboxConfig) -> (Vec<PathBuf>, Vec<String>) {
        let (mut made, mut refused) = (Vec::new(), Vec::new());
        for planned in super::plan_missing_home_config_targets(config) {
            match planned {
                Ok((dir, file)) => {
                    made.extend(super::create_empty_config(dir.as_deref(), &file).expect("create"));
                }
                Err(why) => refused.push(why),
            }
        }
        made.sort();
        (made, refused)
    }

    /// #553: a home Git config file a link points at, missing and inside a
    /// writable tree, is created empty; one outside every writable tree is
    /// left alone, and an existing one is not touched.
    #[test]
    fn missing_home_config_targets_are_created_only_inside_a_writable_tree() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let tmp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let home = root.join("home");
        let project = root.join("project");
        let xdg = project.join("xdg-git");
        let dotfiles = project.join("dotfiles");
        let outside = root.join("outside");
        for d in [
            home.join(".config"),
            xdg.clone(),
            dotfiles.clone(),
            outside.clone(),
        ] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        std::fs::write(xdg.join("ignore"), "keep\n").expect("write ignore");
        symlink(&xdg, home.join(".config/git")).expect("symlink");
        // Dangling: the targets do not exist yet.
        symlink(dotfiles.join("gitconfig"), home.join(".gitconfig")).expect("symlink");
        symlink(outside.join("ignore"), home.join(".gitignore_global")).expect("symlink");
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;

        let (created, refused) = create_missing(&config);
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(
            created,
            vec![
                dotfiles.join("gitconfig"),
                xdg.join("attributes"),
                xdg.join("config"),
            ]
        );
        for f in &created {
            let meta = f.symlink_metadata().expect("created");
            assert!(meta.is_file() && meta.len() == 0, "{f:?} must be empty");
            assert_eq!(meta.permissions().mode() & 0o7133, 0, "{f:?} mode");
        }
        assert_eq!(
            std::fs::read_to_string(xdg.join("ignore")).unwrap(),
            "keep\n"
        );
        assert!(
            !outside.join("ignore").exists(),
            "outside every writable tree"
        );
        assert!(
            super::plan_missing_home_config_targets(&config).is_empty(),
            "a second launch has nothing left to create"
        );

        // Once they exist, the Linux overlay binds and pins them.
        #[cfg(target_os = "linux")]
        {
            let ro = super::ro_protect_paths(&config, &[], &[]);
            let pins = super::pin_paths(&config, &[], &[]);
            for f in &created {
                assert!(ro.contains(f), "{f:?} missing from {ro:?}");
            }
            assert!(pins.contains(&xdg) && pins.contains(&dotfiles), "{pins:?}");
        }
    }

    /// `~/.config` itself links into the project and has no `git` directory:
    /// the directory is created, then the three files in it.
    #[test]
    fn missing_git_dir_under_a_linked_config_is_created_with_its_files() {
        let tmp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let home = root.join("home");
        let project = root.join("project");
        let dot_config = project.join("dot-config");
        std::fs::create_dir_all(&home).expect("mkdir home");
        std::fs::create_dir_all(&dot_config).expect("mkdir dot-config");
        std::os::unix::fs::symlink(&dot_config, home.join(".config")).expect("symlink");
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;

        let (created, _) = create_missing(&config);
        let git = dot_config.join("git");
        assert_eq!(
            created,
            vec![
                git.clone(),
                git.join("attributes"),
                git.join("config"),
                git.join("ignore"),
            ]
        );
        assert!(git.symlink_metadata().unwrap().is_dir());
    }

    /// A dangling `~/.gitconfig` whose directory is missing gets no directory:
    /// only `git` under a linked `~/.config` is ever created. Nor does a link
    /// into a missing `git` directory that `~/.config/git` itself is.
    #[test]
    fn a_missing_directory_is_created_only_for_git_under_a_linked_config() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(home.join(".config")).expect("mkdir home");
        std::fs::create_dir_all(&project).expect("mkdir project");
        symlink(project.join("sub/gitconfig"), home.join(".gitconfig")).expect("symlink");
        symlink(project.join("git"), home.join(".config/git")).expect("symlink");
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;

        let (created, refused) = create_missing(&config);
        assert!(created.is_empty(), "{created:?}");
        assert_eq!(refused.len(), 4, "{refused:?}");
        assert!(!project.join("sub").exists() && !project.join("git").exists());
    }

    /// #553 review: the repo must not choose where the file lands. A
    /// committed `gitconfig` that is itself a dangling link is not followed,
    /// wherever it points; only the user's own link in `$HOME` is.
    #[test]
    fn a_symlink_inside_the_writable_tree_is_not_followed() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(&home).expect("mkdir home");
        std::fs::create_dir_all(project.join(".git")).expect("mkdir .git");
        std::fs::create_dir_all(project.join("elsewhere")).expect("mkdir");
        symlink(project.join("gitconfig"), home.join(".gitconfig")).expect("symlink");
        symlink(project.join("elsewhere/x"), project.join("gitconfig")).expect("symlink");
        symlink(project.join("gitignore"), home.join(".gitignore_global")).expect("symlink");
        symlink(".git/index.lock", project.join("gitignore")).expect("symlink");
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;

        let (created, refused) = create_missing(&config);
        assert!(created.is_empty(), "{created:?}");
        assert_eq!(refused.len(), 2, "{refused:?}");
        assert!(
            refused
                .iter()
                .all(|r| r.contains("symlink inside a writable tree")),
            "{refused:?}"
        );
        assert!(!project.join("elsewhere/x").exists());
        assert!(!project.join(".git/index.lock").exists());
    }

    /// A target inside a gitdir is refused even when the user's own link
    /// points there directly.
    #[test]
    fn a_target_inside_a_gitdir_is_not_created() {
        let tmp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(home.join(".config")).expect("mkdir home");
        std::fs::create_dir_all(project.join(".git")).expect("mkdir .git");
        std::os::unix::fs::symlink(project.join(".git"), home.join(".config/git"))
            .expect("symlink");
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;

        let (created, refused) = create_missing(&config);
        assert!(created.is_empty(), "{created:?}");
        assert_eq!(refused.len(), 3, "{refused:?}");
        assert!(refused.iter().all(|r| r.contains("inside a git directory")));
    }

    /// Bubblewrap gives the sandbox a private `/tmp`, so a target under the
    /// host's system temp dir is not created: nothing in the sandbox could
    /// reach it, and the file would only litter the host.
    #[test]
    fn a_target_under_the_system_temp_dir_is_not_created() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let home = root.join("home");
        let dotfiles = root.join("dotfiles");
        std::fs::create_dir_all(&home).expect("mkdir home");
        std::fs::create_dir_all(&dotfiles).expect("mkdir dotfiles");
        std::os::unix::fs::symlink(dotfiles.join("gitconfig"), home.join(".gitconfig"))
            .expect("symlink");
        let config = test_config(&home, &[]);
        assert!(
            super::canonical_writable_trees(&config)
                .iter()
                .any(|(t, _)| root.starts_with(t)),
            "the fixture must sit in a system temp dir"
        );

        let plan = super::plan_missing_home_config_targets(&config);
        assert!(plan.is_empty(), "{plan:?}");
    }

    /// The creation never follows a symlink at the leaf.
    #[test]
    fn creating_a_missing_home_config_refuses_a_symlink_at_the_leaf() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let leaf = root.join("config");
        let elsewhere = root.join("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, &leaf).expect("symlink");
        super::create_empty_config(None, &leaf).expect_err("symlink at the leaf");
        assert!(!elsewhere.exists(), "the link target must not be created");
    }

    /// Only a real link counts. A `$HOME` reached through a symlinked parent
    /// (`/var/folders` on macOS, `/home -> /var/home`) canonicalizes elsewhere
    /// without any of its files being links; a symlinked directory inside
    /// `$HOME` does make its files links.
    #[test]
    fn home_config_link_targets_needs_a_link_inside_home() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let real_home = root.join("real/home");
        std::fs::create_dir_all(&real_home).expect("mkdir home");
        std::fs::write(real_home.join(".gitconfig"), "").expect("write gitconfig");
        std::os::unix::fs::symlink(root.join("real"), root.join("alias")).expect("symlink");
        let home = root.join("alias/home");
        assert_eq!(home_config_link_targets(&home), Vec::<PathBuf>::new());

        let dots = root.join("dots");
        std::fs::create_dir_all(dots.join("git")).expect("mkdir dots");
        std::fs::write(dots.join("git/config"), "").expect("write config");
        std::os::unix::fs::symlink(&dots, real_home.join(".config")).expect("symlink");
        assert_eq!(
            home_config_link_targets(&home),
            vec![dots.join("git/config")]
        );
    }

    /// The agent's own `host_persistence_denies` must reach the overlay too.
    ///
    /// `ro_protect_paths` extends with `host_persistence_paths(agent_dirs)`,
    /// and that line had no test for any agent — the assembly test above uses
    /// a config with `agent_dirs: &[]`, so it never exercised it. Both agents
    /// with a writable config-dir grant are checked here, so the composition
    /// is asserted rather than inferred: the denies each agent declares, the
    /// grant they are joined onto, and the overlay set they end up in.
    #[cfg(target_os = "linux")]
    #[test]
    fn ro_protect_set_carries_the_agent_config_dir_denies() {
        temp_env::with_var_unset("CLAUDE_CONFIG_DIR", || {
            let home = Path::new("/home/test");
            for (agent, dir) in [
                (Agent::Claude, home.join(".claude")),
                (Agent::Copilot, home.join(".copilot")),
            ] {
                let agent_dirs = agent.config_dirs(home);
                let mut config = test_config(home, &[]);
                config.agent = agent;
                config.agent_dirs = &agent_dirs;

                let paths = super::ro_protect_paths(&config, &[], &[]);
                for sub in agent.host_persistence_denies() {
                    let expected = dir.join(sub);
                    assert!(
                        paths.contains(&expected),
                        "{} must be in the bwrap read-only set, got {paths:?}",
                        expected.display()
                    );
                }
            }
        });
    }

    /// H-13/H-05: an agent's exec-only grant must reach the overlay too.
    ///
    /// OpenCode's `~/.cache/opencode/bin` holds the managed `rg`/`fd` it runs,
    /// and its writable ancestor is `~/.cache` from `HOME_TOOL_DIRS` — granted
    /// to every agent, so narrowing OpenCode's own cache grant would take
    /// nothing away. Landlock cannot subtract, macOS denies the write in
    /// `emit_host_persistence_denies`, and this bind is the Linux half.
    #[cfg(target_os = "linux")]
    #[test]
    fn ro_protect_set_carries_the_exec_only_agent_dirs() {
        crate::with_env_lock_no_xdg(|| {
            let home = Path::new("/home/test");
            let agent_dirs = Agent::OpenCode.config_dirs(home);
            let mut config = test_config(home, &[]);
            config.agent = Agent::OpenCode;
            config.agent_dirs = &agent_dirs;

            let paths = super::ro_protect_paths(&config, &[], &[]);
            assert!(
                paths.contains(&home.join(".cache/opencode/bin")),
                "the managed-binary dir must be re-bound read-only, got {paths:?}"
            );
        });
    }

    /// Same class, the file-level half: OpenCode's `auth.json` is a write grant
    /// inside an otherwise read-only agent dir.
    #[test]
    fn exec_grant_over_a_writable_agent_file_is_refused() {
        let home = Path::new("/home/test");
        let agent_dirs = [AgentDir {
            path: home.join(".config/opencode"),
            write: false,
            map_exec: false,
            process_exec: false,
            write_files: vec!["auth.json"],
            create_dirs: vec![],
        }];
        let exec = [home.join(".config/opencode")];
        let mut config = test_config(home, &[]);
        config.existing_home_tool_dirs = Some(&[]);
        config.agent_dirs = &agent_dirs;
        config.extra_exec = &exec;

        let error = validate_exec_grants(&config).expect_err("the overlap must be refused");
        assert!(error.contains("auth.json"), "{error}");
    }

    /// Same class again: a worktree's real `.git` is granted write so git can
    /// update refs from inside the sandbox.
    #[test]
    fn exec_grant_over_the_git_common_dir_is_refused() {
        let home = Path::new("/home/test");
        let common = home.join("repo/.git");
        let exec = [home.join("repo")];
        let mut config = test_config(home, &[]);
        config.existing_home_tool_dirs = Some(&[]);
        config.git_common_dir = Some(&common);
        config.extra_exec = &exec;

        let error = validate_exec_grants(&config).expect_err("the overlap must be refused");
        assert!(error.contains("git common directory"), "{error}");
    }

    /// `/dev/shm` is seeded read+write by the Landlock policy exactly as `/tmp`
    /// is, so an exec grant over it is the same pair. Bubblewrap's `--dev /dev`
    /// replaces it and the grant does nothing at all there; refusing is the one
    /// answer that is the same in both modes.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn exec_grant_over_dev_shm_is_refused() {
        let home = Path::new("/home/test");
        let exec = [PathBuf::from("/dev/shm")];
        let mut config = test_config(home, &[]);
        config.existing_home_tool_dirs = Some(&[]);
        config.extra_exec = &exec;

        let error = validate_exec_grants(&config).expect_err("the overlap must be refused");
        assert!(error.contains("/dev/shm"), "{error}");
        assert!(error.contains("shared memory"), "{error}");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn prepare_rejects_playwright_socket_capability_off_macos() {
        let mut config = test_config(Path::new("/home/test"), &[]);
        config.playwright_socket_dir = Some(Path::new(
            "/private/tmp/cplt-pw-0123456789abcdef0123456789abcdef",
        ));

        let error = prepare(&config).err().expect("non-macOS must fail closed");
        assert_eq!(
            error,
            "Playwright socket directories are supported only on macOS; refusing configured path"
        );
    }

    /// `DENIED_FILES` is documented as not overridable. A grant naming one is a
    /// config error, not a rule to drop quietly — see
    /// [`validate_hard_denied_grants`]. Same answer on both backends (#207).
    #[test]
    fn prepare_rejects_a_grant_on_a_hard_denied_file() {
        let home = Path::new("/home/test");
        for &file in policy::DENIED_FILES {
            let granted = vec![home.join(file)];

            let mut config = test_config(home, &granted);
            let error = prepare(&config).err().expect("allow.read must be refused");
            assert!(error.contains("allow.read"), "{error}");
            assert!(error.contains(file), "{error}");

            config.extra_read = &[];
            config.extra_write = &granted;
            let error = prepare(&config).err().expect("allow.write must be refused");
            assert!(error.contains("allow.write"), "{error}");

            config.extra_write = &[];
            config.extra_socket = &granted;
            let error = prepare(&config)
                .err()
                .expect("allow.socket must be refused");
            assert!(error.contains("allow.socket"), "{error}");
        }
    }

    /// A grant naming a `DENIED_DOTFILES` directory is refused on every key and
    /// on both backends (#291).
    ///
    /// It was never honoured on macOS — the generic allow is emitted before the
    /// subpath deny and loses to it — while Linux granted it for real. Refusing
    /// is what makes the two the same; the error has to name the per-file grant,
    /// because that is the route that still works.
    #[test]
    fn prepare_rejects_a_grant_on_a_denied_dotfile_directory() {
        let home = Path::new("/home/test");
        for &dir in policy::DENIED_DOTFILES {
            let granted = vec![home.join(dir)];

            let mut config = test_config(home, &granted);
            let error = prepare(&config).err().expect("allow.read must be refused");
            assert!(error.contains("allow.read"), "{error}");
            assert!(error.contains(dir), "{error}");
            // cplt's own state directory has no per-file grant to point at —
            // it is refused as a whole subtree and says so instead.
            if dir == policy::CPLT_STATE_DIR {
                assert!(error.contains("state directory"), "{error}");
                assert!(!error.contains("Name the specific path"), "{error}");
            } else {
                assert!(
                    error.contains("Name the specific path"),
                    "the error must point at the grant that does work: {error}"
                );
            }

            config.extra_read = &[];
            config.extra_write = &granted;
            let error = prepare(&config).err().expect("allow.write must be refused");
            assert!(error.contains("allow.write"), "{error}");

            config.extra_write = &[];
            config.extra_socket = &granted;
            let error = prepare(&config)
                .err()
                .expect("allow.socket must be refused");
            assert!(error.contains("allow.socket"), "{error}");

            config.extra_socket = &[];
            config.extra_exec = &granted;
            let error = prepare(&config).err().expect("allow.exec must be refused");
            assert!(error.contains("allow.exec"), "{error}");
        }
    }

    /// The per-file grant is the supported route and must survive: refusing it
    /// would close the only door SSH has left on macOS, `~/.ssh/known_hosts`
    /// included.
    ///
    /// `~/.nav-pilot` is in the list for a different reason and the same rule
    /// carries it: the directory is refused because the consent record and the
    /// pinned revisions in it decide what the next launch does, but a Tier 2
    /// nav-pilot launch hands cplt `--allow-read` on the one pinned payload it
    /// is about to run, and that grant has to reach the ruleset
    /// (navikt/copilot#858).
    #[test]
    fn prepare_accepts_a_grant_inside_a_denied_dotfile_directory() {
        let home = Path::new("/home/test");
        let granted = vec![
            home.join(".ssh/id_ed25519"),
            home.join(".ssh/known_hosts"),
            home.join(".config/gcloud/application_default_credentials.json"),
            home.join(".nav-pilot/pakker/nais-pilot/abc123/copilot/full"),
        ];

        let mut config = test_config(home, &granted);
        assert_eq!(validate_hard_denied_grants(&config), Ok(()));
        config.extra_read = &[];
        config.extra_write = &granted;
        assert_eq!(validate_hard_denied_grants(&config), Ok(()));
    }

    /// cplt's own state directory is the exception to the per-file override:
    /// every file in it decides what the *next* run may do — the trust store
    /// approves a repo's `.cplt.toml [propose]`, the config carries the grants,
    /// the blocklist cache carries the egress policy — so a grant on any of
    /// them is self-perpetuating. Refused as a subtree, on every grant key,
    /// including a path that does not exist yet (naming a file before creating
    /// it would otherwise walk straight through a canonicalize-only check).
    #[test]
    fn prepare_rejects_a_grant_inside_the_cplt_state_directory() {
        let home = Path::new("/home/test");
        let state = home.join(policy::CPLT_STATE_DIR);
        for tail in ["", "trust", "local", "config.toml", "not/created/yet"] {
            let granted = vec![if tail.is_empty() {
                state.clone()
            } else {
                state.join(tail)
            }];
            let mut config = test_config(home, &granted);

            for key in ["allow.read", "allow.write", "allow.exec", "allow.socket"] {
                config.extra_read = &[];
                config.extra_write = &[];
                config.extra_exec = &[];
                config.extra_socket = &[];
                match key {
                    "allow.read" => config.extra_read = &granted,
                    "allow.write" => config.extra_write = &granted,
                    "allow.exec" => config.extra_exec = &granted,
                    _ => config.extra_socket = &granted,
                }
                let error = prepare(&config)
                    .err()
                    .unwrap_or_else(|| panic!("{key} on {tail:?} must be refused"));
                assert!(error.contains(key), "{error}");
                assert!(error.contains(".config/cplt"), "{error}");
                assert!(
                    error.contains("state directory"),
                    "the error must name the reason: {error}"
                );
            }
        }
    }

    /// The subtree rule is cplt's own directory, not `~/.config` at large.
    #[test]
    fn a_grant_on_another_config_subdirectory_is_untouched() {
        let home = Path::new("/home/test");
        let granted = vec![home.join(".config/foo"), home.join(".config/cpltish")];
        let config = test_config(home, &granted);
        assert_eq!(validate_hard_denied_grants(&config), Ok(()));
    }

    /// `CPLT_CONFIG` moves the real files, so the refusal has to move with
    /// them — the state directory is wherever the config actually lives.
    #[test]
    fn a_grant_inside_a_relocated_state_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&dir).unwrap();
        let granted = vec![dir.join("trust")];

        temp_env::with_var("CPLT_CONFIG", Some(dir.join("config.toml")), || {
            let config = test_config(Path::new("/home/test"), &granted);
            let error = validate_hard_denied_grants(&config)
                .expect_err("a grant in the relocated state dir must be refused");
            assert!(error.contains("state directory"), "{error}");
        });
    }

    /// `--allow-docker` grants `~/.docker` read-only, and `~/.docker` is a
    /// `DENIED_DOTFILES` entry. It is a first-party rule the backends emit, not
    /// a user grant, so the #291 refusal must not be able to see it — otherwise
    /// the flag would refuse every run it is set on.
    #[test]
    fn prepare_does_not_refuse_the_allow_docker_dotfile_grant() {
        let (_guard, root) = copilot_cache_tree();
        let home = root.join("home");
        let mut config = test_config(&home, &[]);
        config.allow_docker = true;

        assert_eq!(validate_hard_denied_grants(&config), Ok(()));
        assert!(
            prepare(&config).is_ok(),
            "--allow-docker must not be caught by the denied-dotfile refusal"
        );
    }

    /// A tree for the #374 launch checks, outside the system temp dir (itself
    /// a writable tree): `<t>/home`, `<t>/project` and `<t>/w`.
    fn copilot_cache_tree() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/target")).unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for d in ["home", "project", "w"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        (tmp, root)
    }

    /// `prepare` for Copilot in that tree with `var=value` and `write` as
    /// the `allow.write` grants.
    fn prepare_with_copilot_cache(
        root: &Path,
        var: &str,
        value: &Path,
        write: &[PathBuf],
    ) -> Result<(), String> {
        let (home, project) = (root.join("home"), root.join("project"));
        let (var, value) = (var.to_owned(), value.as_os_str().to_owned());
        let env = move |k: &str| (k == var).then(|| value.clone());
        let mut config = test_config(&home, &[]);
        config.project_dir = &project;
        config.extra_write = write;
        config.copilot_cache_env = &env;
        config.use_bubblewrap = Some(false);
        prepare(&config).map(drop)
    }

    /// #374: a Copilot cache variable in a writable tree stops the launch in
    /// `prepare`, before the preflight runs `copilot` from that directory
    /// outside the sandbox.
    #[test]
    fn prepare_refuses_a_copilot_cache_in_a_writable_tree() {
        let (_guard, root) = copilot_cache_tree();
        let write = [root.join("w")];
        let mut cases = vec![
            ("COPILOT_CACHE_HOME", root.join("project/.cache")),
            ("COPILOT_PKG_CACHE_HOME", root.join("w/cache")),
            (
                "COPILOT_CACHE_HOME",
                PathBuf::from("/tmp/cplt-copilot-cache"),
            ),
        ];
        if cfg!(target_os = "linux") {
            cases.push(("XDG_CACHE_HOME", root.join("project/.cache")));
        }
        for (var, value) in cases {
            let error = prepare_with_copilot_cache(&root, var, &value, &write)
                .expect_err("the launch must stop");
            for part in [
                format!("cplt refuses {var}={}: ", value.display()),
                "which the sandbox can write".into(),
                format!("Unset {var}, or point it"),
                "outside the project and every writable path".into(),
            ] {
                assert!(error.contains(&part), "{part:?} missing from: {error}");
            }
        }
    }

    /// A value spelled through the project is refused even when it resolves
    /// outside every tree: the agent can re-point the link before extraction.
    #[test]
    fn prepare_refuses_a_copilot_cache_linked_from_the_project() {
        let (_guard, root) = copilot_cache_tree();
        std::fs::create_dir_all(root.join("outside")).unwrap();
        std::os::unix::fs::symlink(root.join("outside"), root.join("project/x")).unwrap();
        let value = root.join("project/x");
        prepare_with_copilot_cache(&root, "COPILOT_CACHE_HOME", &root.join("outside"), &[])
            .expect("the target itself is outside every tree");
        let error = prepare_with_copilot_cache(&root, "COPILOT_CACHE_HOME", &value, &[])
            .expect_err("a project link must stop the launch");
        assert!(
            error.contains("the project directory")
                && error.contains("which the sandbox can write"),
            "{error}"
        );
    }

    /// `<home>` with Copilot's default `pkg` directories on both platforms.
    fn copilot_cache_home(root: &Path) -> PathBuf {
        let home = root.join("home");
        for d in [".cache/copilot/pkg", "Library/Caches/copilot/pkg"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        home
    }

    /// The platform default spelled out is the directory cplt already
    /// protects, so it launches even though `~/.cache` and `~/Library/Caches`
    /// are writable tool trees. `XDG_CACHE_HOME=$HOME/.cache` is a common
    /// explicit setting on Linux.
    #[test]
    fn prepare_accepts_a_copilot_cache_spelled_as_the_default() {
        let (_guard, root) = copilot_cache_tree();
        let home = copilot_cache_home(&root);
        let slashed = |rel: &str| PathBuf::from(format!("{}/{rel}/", home.display()));
        let cases = if cfg!(target_os = "macos") {
            vec![
                ("COPILOT_CACHE_HOME", home.join("Library/Caches/copilot")),
                ("COPILOT_CACHE_HOME", slashed("Library/Caches/copilot")),
            ]
        } else {
            vec![
                ("XDG_CACHE_HOME", home.join(".cache")),
                ("XDG_CACHE_HOME", slashed(".cache")),
                ("COPILOT_CACHE_HOME", home.join(".cache/copilot")),
            ]
        };
        for (var, value) in cases {
            prepare_with_copilot_cache(&root, var, &value, &[])
                .unwrap_or_else(|e| panic!("{var}={} must launch: {e}", value.display()));
        }
    }

    /// `prepare` creates the default `copilot/pkg` as real directories, with a
    /// cache variable set or not: the preflight creates only the extraction
    /// directory, and nothing at all for a project-local binary, so this is
    /// what keeps the agent from planting a `copilot` symlink mid-session. A
    /// call that only inspects the policy creates nothing.
    #[test]
    fn prepare_creates_the_default_copilot_cache() {
        use std::os::unix::fs::PermissionsExt;
        for var in ["COPILOT_PKG_CACHE_HOME", "UNSET"] {
            let (_guard, root) = copilot_cache_tree();
            let home = root.join("home");
            let os = if cfg!(target_os = "macos") {
                "macos"
            } else {
                "linux"
            };
            let pkg = policy::copilot_default_pkg_dir(&home, os);
            let moved = root.join("moved");
            let (var_s, value) = (var.to_owned(), moved.clone().into_os_string());
            let env = move |k: &str| (k == var_s).then(|| value.clone());
            let project = root.join("project");
            let mut config = test_config(&home, &[]);
            config.project_dir = &project;
            config.copilot_cache_env = &env;
            config.use_bubblewrap = Some(false);

            prepare_with_pnpm_shadow(&config, None, true).unwrap();
            assert!(!pkg.parent().unwrap().exists(), "{var}: inspect wrote");

            prepare(&config).unwrap_or_else(|e| panic!("{var}: {e}"));
            for dir in [pkg.parent().unwrap(), pkg.as_path()] {
                let meta = std::fs::symlink_metadata(dir).unwrap();
                assert!(meta.is_dir(), "{var}: {} must be a real dir", dir.display());
                assert_eq!(meta.permissions().mode() & 0o777, 0o700, "{var}");
            }
            assert!(!moved.exists(), "{var}: the override is Copilot's to make");
        }
    }

    /// The default reached through a link in its writable cache
    /// (`~/.cache/copilot -> ~/copilot`, or at `pkg`) is refused, set or
    /// unset: the agent can re-point that link, and the host runs Copilot
    /// from wherever it leads. Same stance as for an override (#570).
    #[test]
    fn prepare_refuses_the_default_copilot_cache_behind_a_writable_link() {
        for linked in ["copilot", "copilot/pkg"] {
            let (_guard, root) = copilot_cache_tree();
            let home = root.join("home");
            std::fs::create_dir_all(home.join("real/pkg")).unwrap();
            for d in [".cache", "Library/Caches"] {
                let at = home.join(d).join(linked);
                std::fs::create_dir_all(at.parent().unwrap()).unwrap();
                let to = home.join(if linked == "copilot" {
                    "real"
                } else {
                    "real/pkg"
                });
                std::os::unix::fs::symlink(to, at).unwrap();
            }
            let (var, value) = if cfg!(target_os = "macos") {
                ("COPILOT_CACHE_HOME", home.join("Library/Caches/copilot"))
            } else {
                ("XDG_CACHE_HOME", home.join(".cache"))
            };
            for var in [var, "UNSET"] {
                let error = prepare_with_copilot_cache(&root, var, &value, &[])
                    .expect_err("a linked default must stop the launch");
                assert!(
                    error.contains("the writable tool directory")
                        && error.contains("which the sandbox can write"),
                    "{linked} with {var}: {error}"
                );
            }
        }
    }

    /// A symlinked `~/Library/Caches` whose target the profile cannot name
    /// stops the launch: Seatbelt matches the resolved path, so the default
    /// cache would get no exec carve-out, write deny or pin.
    #[cfg(target_os = "macos")]
    #[test]
    fn prepare_refuses_a_default_copilot_cache_it_cannot_name() {
        let (_guard, root) = copilot_cache_tree();
        let target = root.join("bad\"caches");
        std::fs::create_dir_all(target.join("copilot/pkg")).unwrap();
        std::fs::create_dir_all(root.join("home/Library")).unwrap();
        std::os::unix::fs::symlink(&target, root.join("home/Library/Caches")).unwrap();
        let error = prepare_with_copilot_cache(&root, "UNSET", Path::new("/"), &[])
            .expect_err("an unnameable default must stop the launch");
        assert!(
            error.contains("the sandbox profile cannot name") && error.contains("bad\"caches"),
            "{error}"
        );
    }

    /// Reaching the default through a symlink outside every writable tree is
    /// the default too: nothing the agent can write decides where it points.
    #[test]
    fn prepare_accepts_a_copilot_cache_linked_to_the_default_from_outside() {
        let (_guard, root) = copilot_cache_tree();
        let home = copilot_cache_home(&root);
        let default = if cfg!(target_os = "macos") {
            home.join("Library/Caches/copilot")
        } else {
            home.join(".cache/copilot")
        };
        std::os::unix::fs::symlink(&default, root.join("alias")).unwrap();
        prepare_with_copilot_cache(&root, "COPILOT_CACHE_HOME", &root.join("alias"), &[])
            .expect("an outside link to the default must launch");
    }

    /// A link inside a writable tree is refused even when it points at the
    /// default: the agent can re-point it before Copilot extracts. That holds
    /// for a project link reached through an outside link, too.
    #[test]
    fn prepare_refuses_a_project_link_to_the_default_copilot_cache() {
        let (_guard, root) = copilot_cache_tree();
        let home = copilot_cache_home(&root);
        let link = |to: PathBuf, at: &str| std::os::unix::fs::symlink(to, root.join(at)).unwrap();
        link(home.join(".cache"), "project/x");
        link(home.join("Library/Caches"), "project/y");
        link(root.join("project"), "hop");
        link(root.join("project/y/copilot"), "chain");
        let mut cases = vec![
            ("COPILOT_CACHE_HOME", root.join("project/x/copilot")),
            ("COPILOT_CACHE_HOME", root.join("project/y/copilot")),
            ("COPILOT_CACHE_HOME", root.join("hop/y/copilot")),
            ("COPILOT_CACHE_HOME", root.join("chain")),
        ];
        if cfg!(target_os = "linux") {
            cases.push(("XDG_CACHE_HOME", root.join("project/x")));
        }
        for (var, value) in cases {
            let error = prepare_with_copilot_cache(&root, var, &value, &[])
                .expect_err("a project link must stop the launch");
            assert!(
                error.contains("the project directory")
                    && error.contains("which the sandbox can write"),
                "{var}={}: {error}",
                value.display()
            );
        }
    }

    /// A moved cache under a user deny path is refused: its read allow comes
    /// after the deny in the profile and would reopen it.
    #[test]
    fn prepare_refuses_a_copilot_cache_under_a_deny_path() {
        let (_guard, root) = copilot_cache_tree();
        let (home, project) = (root.join("home"), root.join("project"));
        let env = |k: &str| (k == "COPILOT_CACHE_HOME").then(|| "/opt/cplt-copilot-cache".into());
        for (deny, refused) in [
            ("/opt", true),
            ("/opt/cplt-copilot-cache/pkg/darwin-arm64", true),
            ("/opt/other", false),
        ] {
            let denies = [PathBuf::from(deny)];
            let mut config = test_config(&home, &[]);
            config.project_dir = &project;
            config.extra_deny = &denies;
            config.copilot_cache_env = &env;
            config.use_bubblewrap = Some(false);
            match prepare(&config) {
                Err(e) if refused => assert!(
                    e.contains("overlaps the deny path") && e.contains(deny),
                    "{e}"
                ),
                Ok(_) if !refused => {}
                other => panic!("deny {deny}: {:?}", other.map(drop)),
            }
        }
    }

    /// An override outside every writable tree still launches.
    #[test]
    fn prepare_accepts_a_copilot_cache_under_opt() {
        let (_guard, root) = copilot_cache_tree();
        let value = Path::new("/opt/cplt-copilot-cache");
        prepare_with_copilot_cache(&root, "COPILOT_CACHE_HOME", value, &[root.join("w")])
            .expect("/opt must be accepted");
    }

    /// #374: a missing `allow.write` path under a symlinked ancestor is
    /// canonicalized the way the cache value is, so the overlap is still seen.
    #[test]
    fn prepare_refuses_a_copilot_cache_under_a_missing_symlinked_grant() {
        let (_guard, root) = copilot_cache_tree();
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let value = root.join("real/missing/cache");
        let write = [root.join("link/missing")];
        let error = prepare_with_copilot_cache(&root, "COPILOT_CACHE_HOME", &value, &write)
            .expect_err("the missing grant must still be matched");
        assert!(
            error.contains("COPILOT_CACHE_HOME") && error.contains("the allow.write grant"),
            "{error}"
        );
    }

    /// `/` and `$HOME` are refused: an exec grant that wide is not a sandbox.
    /// `$HOME`'s ancestors go with it — granting `/home` reaches every user.
    #[test]
    fn prepare_refuses_an_unbounded_exec_grant() {
        let home = Path::new("/home/test");
        for wide in ["/", "/tmp", "/home/test"] {
            let granted = vec![PathBuf::from(wide)];
            let mut config = test_config(home, &[]);
            config.extra_exec = &granted;

            let error = prepare(&config)
                .err()
                .unwrap_or_else(|| panic!("allow.exec {wide} must be refused"));
            assert!(error.contains("allow.exec"), "{error}");
            assert!(error.contains("defeats the sandbox"), "{error}");
        }
    }

    /// The system temp dirs are writable without any `allow.write`, so an exec
    /// grant under one is the same write+exec staging pair (#299). It has to be
    /// refused rather than honoured because the three code paths otherwise
    /// disagree: macOS honours it (the user allow is emitted after
    /// `emit_temp_rules`), Linux without bubblewrap honours it *and* unions it
    /// with the always-writable `/tmp` rule, and Linux under bubblewrap drops it
    /// silently behind the private tmpfs.
    ///
    /// The roots are spelled out rather than read from `SYSTEM_TEMP_DIRS`, so
    /// emptying that constant fails this test instead of vacuously passing it.
    #[test]
    fn prepare_refuses_an_exec_grant_under_the_system_temp_dir() {
        #[cfg(target_os = "macos")]
        let roots = ["/private/tmp", "/private/var/folders"];
        #[cfg(not(target_os = "macos"))]
        let roots = ["/tmp"];

        let home = Path::new("/home/test");
        for root in roots {
            let exec = Path::new(root).join("build-xyz/bin");
            let exec_paths = vec![exec.clone()];
            let mut config = test_config(home, &[]);
            config.extra_exec = &exec_paths;

            let error = prepare(&config).err().unwrap_or_else(|| {
                panic!("allow.exec under {root} must be refused, not silently honoured")
            });
            assert!(error.contains("allow.exec"), "{error}");
            assert!(
                error.contains(&exec.display().to_string()),
                "the refusal must name the grant: {error}"
            );
            assert!(
                error.contains(root),
                "the refusal must name the temp dir it collides with: {error}"
            );
            // "Narrow one of the two" is not actionable for a tree that is
            // writable with no grant to withdraw — the message must say where
            // to put the binaries instead.
            assert!(
                error.contains("Move the tree") && error.contains("scratch dir"),
                "the refusal must tell the user what to do instead: {error}"
            );
        }
    }

    /// A grant on a sibling path that merely *starts with* the temp root's name
    /// is not under it, and must still be accepted.
    #[test]
    fn prepare_accepts_an_exec_grant_beside_the_system_temp_dir() {
        let (_guard, root) = copilot_cache_tree();
        let home = root.join("home");
        let exec_paths = vec![PathBuf::from("/tmpfoo/bin")];
        let mut config = test_config(&home, &[]);
        config.extra_exec = &exec_paths;
        assert!(
            prepare(&config).is_ok(),
            "/tmpfoo is not under /tmp and must not be refused"
        );
    }

    /// The overlap refusal, in both directions and against both sources of
    /// write: an `allow.write` grant and the project directory.
    ///
    /// Not a warning and not a narrowed rule. Landlock unions a write rule on
    /// an ancestor with an exec rule on a child and cannot subtract it, so an
    /// overlapping pair really is writable + executable — a binary-drop staging
    /// path — on the one backend where it cannot be mitigated without
    /// bubblewrap. Refusing is the only answer both backends give alike.
    #[test]
    fn prepare_refuses_an_exec_grant_overlapping_a_writable_tree() {
        let home = Path::new("/home/test");
        let cases: [(&str, &str); 5] = [
            // exec inside the writable grant, and the reverse
            ("/home/test/tools/bin", "/home/test/tools"),
            ("/home/test/tools", "/home/test/tools/bin"),
            // the same tree granted twice
            ("/home/test/tools", "/home/test/tools"),
            // exec inside the project directory
            ("/project/vendor/bin", "/project"),
            // exec inside a writable HOME_TOOL_DIRS entry — the same write+exec
            // pair by another route; `--allow-cache-exec` is the way in there.
            ("/home/test/.cache/ms-playwright", "/home/test/.cache"),
        ];
        for (exec, write) in cases {
            let exec_paths = vec![PathBuf::from(exec)];
            let write_paths = vec![PathBuf::from(write)];
            let mut config = test_config(home, &[]);
            config.extra_exec = &exec_paths;
            // "/project" is `test_config`'s project dir and `~/.cache` a
            // writable HOME_TOOL_DIRS entry; both are writable without any
            // `allow.write` at all.
            if write != "/project" && !write.starts_with("/home/test/.cache") {
                config.extra_write = &write_paths;
            }

            let error = prepare(&config).err().unwrap_or_else(|| {
                panic!("allow.exec {exec} over writable {write} must be refused")
            });
            assert!(error.contains("allow.exec"), "{error}");
            assert!(error.contains(exec), "{error}");
            assert!(error.contains(write), "{error}");
            assert!(
                error.contains("writable and") && error.contains("executable"),
                "the error must say why, not just no: {error}"
            );
        }
    }

    /// The case from #202: a relocated Homebrew prefix under `$HOME`. It is not
    /// `$HOME`, not an ancestor of it, and overlaps nothing writable, so it is
    /// accepted — this is the grant that makes the reporter's
    /// `~/.linuxbrew/bin/git` runnable.
    #[test]
    fn prepare_accepts_a_relocated_tool_prefix_exec_grant() {
        let home = Path::new("/home/test");
        let granted = vec![home.join(".linuxbrew")];
        let mut config = test_config(home, &[]);
        config.extra_exec = &granted;

        assert_eq!(validate_exec_grants(&config), Ok(()));
    }

    /// The overridable list keeps working: refusing these would be a regression.
    #[test]
    fn prepare_accepts_a_grant_on_an_overridable_credential_file() {
        let home = Path::new("/home/test");
        let granted: Vec<PathBuf> = policy::DENIED_HOME_SUBPATHS
            .iter()
            .map(|f| home.join(f))
            .collect();

        let config = test_config(home, &granted);
        assert_eq!(validate_hard_denied_grants(&config), Ok(()));
    }

    /// The invariant behind [`crate::git::TRUSTED_BIN_DIRS`], not just its
    /// contents: every directory cplt resolves a parent-side binary from must be
    /// one the sandbox grants **read** access to and nothing more. A directory
    /// the sandbox also granted write to would be planted into exactly as easily
    /// as a `PATH` directory, and the whole fix would be theatre.
    ///
    /// Lives here rather than in `git.rs` because both grant lists are private
    /// to this module, and one test reaching in is cheaper than opening them to
    /// the crate.
    ///
    /// Checked against both platform lists because the resolver is shared; each
    /// entry only has to be covered by one of them (`/opt/homebrew/bin` is
    /// macOS-only, `/run/current-system/sw/bin` NixOS-only).
    ///
    /// Scope, so the name does not promise more than it checks: this asserts
    /// membership in the read-only tool-dir grants, and it only covers the
    /// **built-in** grant lists. It does not scan those for a write overlap
    /// because every built-in write grant is `$HOME`-relative or a per-tool
    /// config dir, so none of them can name an absolute system bin dir; if a
    /// built-in absolute write grant is ever added, extend this.
    ///
    /// User configuration is outside that scope. `allow.write` paths go through
    /// `resolve_config_path`, which accepts an absolute path as-is, so a user
    /// can grant write on `/usr/local/bin` and overlap a trusted directory. No
    /// test can see that from here — it is a property of the running config, not
    /// of the constants.
    #[test]
    fn every_trusted_dir_is_covered_by_a_tool_read_grant() {
        let granted: Vec<&str> = policy::TOOL_READ_DIRS
            .iter()
            .chain(landlock_mod::LINUX_TOOL_DIRS)
            .copied()
            .collect();
        for dir in crate::git::TRUSTED_BIN_DIRS {
            assert!(
                Path::new(dir).is_absolute(),
                "{dir} must be an absolute path"
            );
            assert!(
                granted.iter().any(|g| Path::new(dir).starts_with(g)),
                "{dir} is not covered by a read-only tool dir grant — either it is \
                 unreachable from the sandbox's own view or, worse, it is writable"
            );
        }
    }

    /// Linux only, and it actually runs in CI: `bwrap` is the sandbox driver,
    /// executed by the unsandboxed parent, so it must never come off `PATH`.
    ///
    /// Asserting only "the result is inside TRUSTED_BIN_DIRS" does not test
    /// anything: every distro installs bwrap to `/usr/bin`, which is itself
    /// trusted, so a `PATH` lookup satisfies it on every ordinary host. This
    /// plants a decoy `bwrap` first on `PATH` instead — a `PATH` lookup returns
    /// the decoy, trusted resolution cannot, whether or not a real bwrap exists.
    #[cfg(target_os = "linux")]
    #[test]
    fn bwrap_is_never_resolved_from_path() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().expect("tempdir");
        let decoy = tmp.path().join("bwrap");
        std::fs::write(&decoy, "#!/bin/sh\nexit 0\n").expect("write decoy");
        std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o755))
            .expect("chmod decoy");

        let path = format!(
            "{}:{}",
            tmp.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let found = temp_env::with_var("PATH", Some(&path), bubblewrap::check_availability);

        assert_ne!(
            found.as_deref(),
            Some(decoy.as_path()),
            "bwrap was resolved from PATH — a planted binary would drive the sandbox"
        );
        assert!(
            found.as_ref().is_none_or(|p| crate::git::TRUSTED_BIN_DIRS
                .iter()
                .any(|d| p.starts_with(d))),
            "bwrap resolved to {found:?}, outside TRUSTED_BIN_DIRS"
        );
    }

    /// `extra_git_dirs` is the wiring between `prepare()` and the profile: the
    /// emitter test proves the denies get written, this proves the right
    /// directories reach it. Without it, making this function return an empty
    /// Vec kills the whole #212 fix with every host-independent suite green —
    /// only the seatbelt-gated e2e tests catch that, and they never run on
    /// Linux CI.
    ///
    /// Same shape as `discover::git_dir_of_resolves_every_repo_shape`, one
    /// layer up.
    #[test]
    fn extra_git_dirs_resolves_only_the_roots_that_need_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Canonicalized the way `main.rs` canonicalizes every granted path: the
        // `dir != root.join(".git")` filter compares against the RESOLVED dir,
        // so an uncanonicalized root would slip past it (a harmless duplicate
        // deny, but the filter itself would go untested).
        let base = std::fs::canonicalize(tmp.path()).expect("canonicalize base");
        let git = |args: &[&str], cwd: &Path| {
            let ok = std::process::Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@e")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@e")
                .output()
                .expect("run git")
                .status
                .success();
            assert!(ok, "git {args:?} should succeed");
        };

        let repo = base.join("repo");
        std::fs::create_dir(&repo).unwrap();
        git(&["init", "--quiet"], &repo);
        git(&["commit", "--quiet", "--allow-empty", "-m", "x"], &repo);
        let repo_git = repo.join(".git");

        let wt = base.join("wt");
        git(
            &[
                "worktree",
                "add",
                "--quiet",
                "-b",
                "b2",
                wt.to_str().unwrap(),
            ],
            &repo,
        );

        let bare = base.join("bare.git");
        std::fs::create_dir(&bare).unwrap();
        git(&["init", "--bare", "--quiet"], &bare);

        let plain = base.join("plain");
        std::fs::create_dir(&plain).unwrap();

        // An ordinary repo root resolves to <root>/.git, which the path-shaped
        // denies already cover — filtered out, not emitted twice.
        assert!(
            extra_git_dirs(std::slice::from_ref(&repo)).is_empty(),
            "an ordinary repo root must be dropped by dir != root.join(\".git\")"
        );
        // A non-repo grant is a no-op, never an error. (Guarded: a tempdir
        // inside a checkout would make git walk up and find that repo.)
        if crate::discover::git_dir_of(&base).is_none() {
            assert!(
                extra_git_dirs(&[plain.clone(), base.join("gone")]).is_empty(),
                "a non-repo and a missing path must contribute nothing"
            );
        }
        // A worktree needs the MAIN repo's .git; a bare repo needs itself.
        // Neither is reachable through the <root>/.git rules.
        assert_eq!(
            extra_git_dirs(&[wt.clone(), bare.clone()]),
            vec![bare.clone(), repo_git.clone()],
            "worktree must resolve to the main repo's .git, bare repo to itself (sorted)"
        );
        // Every shape at once, with the worktree granted twice: deduplicated.
        assert_eq!(
            extra_git_dirs(&[wt.clone(), repo, plain, bare.clone(), wt]),
            vec![bare, repo_git],
            "overlapping and repeated grants must not emit duplicate denies"
        );
    }
}
