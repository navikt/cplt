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
#[path = "sandbox_env.rs"]
mod env;
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
    AppDir, AppDirKind, DENIED_DOTFILES, DENIED_FILES, DENIED_HOME_SUBPATHS, ENV_ALLOWLIST,
    ENV_PREFIX_ALLOWLIST, HARDENING_ENV_VARS, HOME_TOOL_DIRS, HardeningCategory, HardeningEnvVar,
    HomeToolDir, app_dirs, home_tool_dirs, validate_sbpl_path,
};

// SBPL profile generation — kept public for unit tests.
// The SBPL module is pure string manipulation with no macOS dependencies,
// so tests run cross-platform even though the output is macOS-specific.
pub use profile::{ProfileOptions, generate_profile};

// Environment construction — already platform-agnostic.
pub use env::{SandboxEnv, build_sandbox_env};

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
    pub home_dir: &'a Path,
    pub extra_read: &'a [PathBuf],
    pub extra_write: &'a [PathBuf],
    pub extra_socket: &'a [PathBuf],
    pub extra_deny: &'a [PathBuf],
    /// If `Some`, only include these home tool dirs (tighter profile via discovery).
    /// If `None`, all known home tool dirs are included.
    pub existing_home_tool_dirs: Option<&'a [String]>,
    /// If `Some`, only include these app dirs (tighter profile via discovery).
    /// If `None`, all known app dirs are included.
    pub existing_app_dirs: Option<&'a [String]>,
    pub extra_ports: &'a [u16],
    pub localhost_ports: &'a [u16],
    pub proxy_port: Option<u16>,
    pub allow_env_files: bool,
    pub allow_localhost_any: bool,
    pub scratch_dir: Option<&'a Path>,
    pub allow_tmp_exec: bool,
    /// Copilot CLI package directory (resolved from the binary location).
    pub copilot_install_dir: Option<&'a Path>,
    /// JAVA_HOME directory — grants JDK read + dylib loading.
    pub java_home: Option<&'a Path>,
    /// Global git hooks directory from `core.hooksPath`.
    pub git_hooks_path: Option<&'a Path>,
    /// Shared .git directory for git worktrees.
    pub git_common_dir: Option<&'a Path>,
    pub allow_gpg_signing: bool,
    pub deny_clipboard: bool,
    /// Allow JVM Attach API unix sockets in /tmp (.java_pid* pattern only).
    pub allow_jvm_attach: bool,
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
    /// Allow Launch Services (`open` command) for OAuth browser flows.
    pub allow_browser: bool,
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
    proxy_port: Option<u16>,
    agent: Agent,
    /// Specific localhost ports the user has explicitly opened.
    allow_localhost: Vec<u16>,
    /// Whether all localhost ports are open (`--allow-localhost-any`).
    allow_localhost_any: bool,
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
}

/// Validate configuration and compile it into a platform-specific sandbox.
///
/// On macOS, this generates an SBPL profile and validates all paths for
/// SBPL injection safety. On Linux, this builds a Landlock policy.
///
/// Returns an error if:
/// - A path contains characters that could cause profile injection (macOS)
/// - The platform does not support sandboxing
pub fn prepare(config: &SandboxConfig) -> Result<PreparedSandbox, String> {
    prepare_impl(config)
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
/// On macOS, writes the profile to a temp file and runs `/usr/bin/true`
/// inside `sandbox-exec` to confirm enforcement is active.
///
/// On Linux, this is a no-op (ABI checks happen during prepare).
pub fn preflight(sandbox: &PreparedSandbox) -> Result<(), String> {
    exec::preflight(sandbox)
}

/// Execute a command inside the sandbox, forwarding signals to the child.
///
/// Handles platform-specific sandbox setup internally:
/// - macOS: writes SBPL profile to temp file, invokes `sandbox-exec`
/// - Linux: applies Landlock ruleset + seccomp filter via `pre_exec`
///
/// Environment handling is controlled by `extra_pass_env`, `inherit_env`,
/// and `disabled_categories` — see [`build_sandbox_env()`] for details.
/// `deny_env` contains additional env vars to strip (from repo config [deny] section).
#[allow(clippy::too_many_arguments)]
pub fn exec_sandboxed(
    sandbox: &PreparedSandbox,
    copilot_bin: &Path,
    copilot_args: &[String],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    deny_env: &[String],
    gh_guard: &crate::config::GhGuardPolicy,
    git_guard: &crate::config::GitGuardPolicy,
) -> u8 {
    exec::exec(
        sandbox,
        copilot_bin,
        copilot_args,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        deny_env,
        gh_guard,
        git_guard,
    )
}

// ── Platform-specific prepare implementations ─────────────────

#[cfg(target_os = "macos")]
fn prepare_impl(config: &SandboxConfig) -> Result<PreparedSandbox, String> {
    validate_config_paths(config)?;

    let profile_text = profile::generate_profile(&profile::ProfileOptions {
        project_dir: config.project_dir,
        home_dir: config.home_dir,
        extra_read: config.extra_read,
        extra_write: config.extra_write,
        allow_socket: config.extra_socket,
        extra_deny: config.extra_deny,
        existing_home_tool_dirs: config.existing_home_tool_dirs,
        existing_app_dirs: config.existing_app_dirs,
        extra_ports: config.extra_ports,
        localhost_ports: config.localhost_ports,
        proxy_port: config.proxy_port,
        allow_env_files: config.allow_env_files,
        allow_localhost_any: config.allow_localhost_any,
        scratch_dir: config.scratch_dir,
        allow_tmp_exec: config.allow_tmp_exec,
        copilot_install_dir: config.copilot_install_dir,
        java_home: config.java_home,
        git_hooks_path: config.git_hooks_path,
        git_common_dir: config.git_common_dir,
        allow_gpg_signing: config.allow_gpg_signing,
        deny_clipboard: config.deny_clipboard,
        allow_jvm_attach: config.allow_jvm_attach,
        allow_docker: config.allow_docker,
        electron_app_dir: config.electron_app_dir,
        agent: config.agent,
        agent_dirs: config.agent_dirs,
        allow_cache_exec: config.allow_cache_exec,
        allow_cache_exec_any: config.allow_cache_exec_any,
        allow_browser: config.allow_browser,
    });

    Ok(PreparedSandbox {
        project_dir: config.project_dir.to_path_buf(),
        home_dir: config.home_dir.to_path_buf(),
        profile_text,
        scratch_dir: config.scratch_dir.map(Path::to_path_buf),
        proxy_port: config.proxy_port,
        agent: config.agent,
        allow_localhost: config.localhost_ports.to_vec(),
        allow_localhost_any: config.allow_localhost_any,
    })
}

#[cfg(target_os = "linux")]
fn prepare_impl(config: &SandboxConfig) -> Result<PreparedSandbox, String> {
    // Warn about config options that Linux cannot enforce at kernel level.
    if !config.extra_deny.is_empty() {
        ui::warn(
            "--deny-path has no effect on Linux: \
             Landlock cannot deny subpaths within allowed directories. \
             Proxy and env hardening provide defense-in-depth.",
        );
    }
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
    if config.allow_docker {
        ui::warn(
            "--allow-docker has no effect on Linux: \
             Docker socket access is not yet implemented in the Landlock backend.",
        );
    }

    let policy = landlock_mod::generate_policy(config);
    let profile_text = landlock_mod::describe_policy(&policy);

    // Decide bubblewrap wrapping before `precompute()` consumes `policy`.
    // `resolve()` only clones `fs_rules`/`net_rules` on the arms that actually
    // build a wrapper (explicit-on, or auto-detect with bwrap available) — the
    // disabled and fallback arms borrow and clone nothing.
    let bwrap_wrapper = bubblewrap::resolve(
        config.use_bubblewrap,
        &policy.fs_rules,
        &policy.net_rules,
        policy.restrict_net_connect,
    )?;

    // Pre-compute everything in the parent process.
    // ABI check, BPF construction, and all allocation happens here.
    // The pre_exec hook only makes raw syscalls.
    let precomputed = landlock_mod::precompute(policy)?;

    Ok(PreparedSandbox {
        project_dir: config.project_dir.to_path_buf(),
        home_dir: config.home_dir.to_path_buf(),
        profile_text,
        scratch_dir: config.scratch_dir.map(Path::to_path_buf),
        proxy_port: config.proxy_port,
        agent: config.agent,
        allow_localhost: config.localhost_ports.to_vec(),
        allow_localhost_any: config.allow_localhost_any,
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
    policy::validate_sbpl_path(config.home_dir).map_err(|e| format!("Home dir: {e}"))?;

    if let Some(dir) = config.copilot_install_dir {
        policy::validate_sbpl_path(dir).map_err(|e| format!("Copilot install dir: {e}"))?;
    }
    if let Some(dir) = config.java_home {
        policy::validate_sbpl_path(dir).map_err(|e| format!("JAVA_HOME: {e}"))?;
    }
    if let Some(p) = config.git_hooks_path {
        policy::validate_sbpl_path(p).map_err(|e| format!("Git hooks path: {e}"))?;
    }
    if let Some(p) = config.git_common_dir {
        policy::validate_sbpl_path(p).map_err(|e| format!("Git common dir: {e}"))?;
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
