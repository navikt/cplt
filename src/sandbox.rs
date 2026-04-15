//! Sandbox profile generation, environment hardening, and execution.
//!
//! # Architecture
//!
//! The sandbox uses different kernel enforcement mechanisms per platform:
//! - **macOS**: Seatbelt/SBPL via `sandbox-exec`
//! - **Linux**: Landlock LSM + seccomp-BPF
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
//!
//! # Submodule layout
//!
//! Submodules use `#[path]` because the sandbox blocks directory creation.
//! To reorganize to standard `src/sandbox/mod.rs` layout, move the files
//! into `src/sandbox/` and remove the `#[path]` attributes.

use std::path::{Path, PathBuf};

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
    DENIED_DOTFILES, DENIED_FILES, ENV_ALLOWLIST, ENV_PREFIX_ALLOWLIST, HARDENING_ENV_VARS,
    HOME_TOOL_DIRS, HardeningCategory, HardeningEnvVar, HomeToolDir, home_tool_dirs,
    validate_sbpl_path,
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
    pub extra_deny: &'a [PathBuf],
    /// If `Some`, only include these home tool dirs (tighter profile via discovery).
    /// If `None`, all known home tool dirs are included.
    pub existing_home_tool_dirs: Option<&'a [String]>,
    pub extra_ports: &'a [u16],
    pub localhost_ports: &'a [u16],
    pub proxy_port: Option<u16>,
    pub allow_env_files: bool,
    pub allow_localhost_any: bool,
    pub scratch_dir: Option<&'a Path>,
    pub allow_tmp_exec: bool,
    /// Copilot CLI package directory (resolved from the binary location).
    pub copilot_install_dir: Option<&'a Path>,
    /// Global git hooks directory from `core.hooksPath`.
    pub git_hooks_path: Option<&'a Path>,
    pub allow_gpg_signing: bool,
    /// Electron app bundle Contents directory (macOS only, ignored on Linux).
    pub electron_app_dir: Option<&'a Path>,
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
    /// Landlock + seccomp pre-computed sandbox data (Linux only).
    /// Built in the parent process; applied in pre_exec.
    #[cfg(target_os = "linux")]
    precomputed: landlock_mod::PrecomputedSandbox,
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
pub fn exec_sandboxed(
    sandbox: &PreparedSandbox,
    copilot_bin: &Path,
    copilot_args: &[String],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
) -> u8 {
    exec::exec(
        sandbox,
        copilot_bin,
        copilot_args,
        extra_pass_env,
        inherit_env,
        disabled_categories,
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
        extra_deny: config.extra_deny,
        existing_home_tool_dirs: config.existing_home_tool_dirs,
        extra_ports: config.extra_ports,
        localhost_ports: config.localhost_ports,
        proxy_port: config.proxy_port,
        allow_env_files: config.allow_env_files,
        allow_localhost_any: config.allow_localhost_any,
        scratch_dir: config.scratch_dir,
        allow_tmp_exec: config.allow_tmp_exec,
        copilot_install_dir: config.copilot_install_dir,
        git_hooks_path: config.git_hooks_path,
        allow_gpg_signing: config.allow_gpg_signing,
        electron_app_dir: config.electron_app_dir,
    });

    Ok(PreparedSandbox {
        project_dir: config.project_dir.to_path_buf(),
        home_dir: config.home_dir.to_path_buf(),
        profile_text,
        scratch_dir: config.scratch_dir.map(Path::to_path_buf),
        proxy_port: config.proxy_port,
    })
}

#[cfg(target_os = "linux")]
fn prepare_impl(config: &SandboxConfig) -> Result<PreparedSandbox, String> {
    // Warn about config options that Linux cannot enforce at kernel level.
    if !config.extra_deny.is_empty() {
        eprintln!(
            "\x1b[0;33m[cplt]\x1b[0m --deny-path has no effect on Linux: \
             Landlock cannot deny subpaths within allowed directories. \
             Proxy and env hardening provide defense-in-depth."
        );
    }
    if !config.allow_env_files {
        eprintln!(
            "\x1b[0;33m[cplt]\x1b[0m allow_env_files=false is not fully enforceable on Linux: \
             Landlock grants the project directory full read access, so .env files \
             within it remain readable. Differs from macOS Seatbelt behavior."
        );
    }

    let policy = landlock_mod::generate_policy(config);
    let profile_text = landlock_mod::describe_policy(&policy);

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
        precomputed,
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
    if let Some(p) = config.git_hooks_path {
        policy::validate_sbpl_path(p).map_err(|e| format!("Git hooks path: {e}"))?;
    }
    if let Some(dir) = config.electron_app_dir {
        policy::validate_sbpl_path(dir).map_err(|e| format!("Electron app path: {e}"))?;
    }
    if let Some(dir) = config.scratch_dir {
        policy::validate_sbpl_path(dir).map_err(|e| format!("Scratch dir: {e}"))?;
    }
    for p in config.extra_read {
        policy::validate_sbpl_path(p).map_err(|e| format!("--allow-read path: {e}"))?;
    }
    for p in config.extra_write {
        policy::validate_sbpl_path(p).map_err(|e| format!("--allow-write path: {e}"))?;
    }
    for p in config.extra_deny {
        policy::validate_sbpl_path(p).map_err(|e| format!("--deny-path path: {e}"))?;
    }

    Ok(())
}
