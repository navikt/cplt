//! Sandbox profile generation, environment hardening, and execution.
//!
//! # Architecture
//!
//! The sandbox uses different kernel enforcement mechanisms per platform:
//! - **macOS**: Seatbelt/SBPL via `sandbox-exec`
//! - **Linux**: Landlock LSM + seccomp-BPF (planned — see issue #16)
//!
//! The public API is platform-agnostic:
//! - [`prepare()`] validates configuration and compiles it into a [`PreparedSandbox`]
//! - [`describe()`] returns a human-readable representation of the policy
//! - [`preflight()`] verifies the sandbox mechanism works on this system
//! - [`exec_sandboxed()`] runs a command inside the sandbox
//!
//! Platform-specific details are handled by internal modules:
//! - `profile`: SBPL profile generation (macOS — also compiled cross-platform for testing)
//! - `exec`: `sandbox-exec` invocation (macOS runtime only)
//! - Future: `landlock`, `seccomp` modules for Linux
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
#[path = "sandbox_policy.rs"]
mod policy;
#[path = "sandbox_profile.rs"]
mod profile;

// ── Re-exports: shared policy types and constants ──────────────
//
// These are platform-agnostic and used by tests, discover, config, etc.

pub use policy::{
    DENIED_DOTFILES, DENIED_FILES, ENV_ALLOWLIST, ENV_PREFIX_ALLOWLIST, HARDENING_ENV_VARS,
    HOME_TOOL_DIRS, HardeningCategory, HardeningEnvVar, HomeToolDir, validate_sbpl_path,
};

// SBPL profile generation — kept public for unit tests.
// The SBPL module is pure string manipulation with no macOS dependencies,
// so tests run cross-platform even though the output is macOS-specific.
pub use profile::{ProfileOptions, generate_profile};

// Environment construction — already platform-agnostic.
pub use env::{SandboxEnv, build_sandbox_env};

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
    /// Allow JVM Attach API unix sockets in /tmp (.java_pid* pattern only).
    pub allow_jvm_attach: bool,
    /// Electron app bundle Contents directory (macOS only, ignored on Linux).
    pub electron_app_dir: Option<&'a Path>,
}

/// A validated, platform-specific sandbox ready for execution.
///
/// Created by [`prepare()`]. On macOS this contains the compiled SBPL
/// profile text. On Linux (future) it will contain the Landlock ruleset
/// and seccomp filter configuration.
///
/// Use [`describe()`] for a human-readable representation,
/// [`preflight()`] to verify the mechanism works, and
/// [`exec_sandboxed()`] to run a command inside the sandbox.
pub struct PreparedSandbox {
    project_dir: PathBuf,
    home_dir: PathBuf,
    /// macOS: SBPL profile text.
    /// Linux: human-readable policy summary (future).
    profile_text: String,
    scratch_dir: Option<PathBuf>,
    proxy_port: Option<u16>,
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
/// SBPL injection safety. On Linux (future), this will build a Landlock
/// ruleset.
///
/// Returns an error if:
/// - A path contains characters that could cause profile injection
/// - The platform does not support sandboxing (yet)
pub fn prepare(config: &SandboxConfig) -> Result<PreparedSandbox, String> {
    // Validate all paths that will be interpolated into the sandbox profile.
    // On macOS, SBPL uses string interpolation — characters like `"`, `;`, `(`
    // could break or inject rules. This validation is centralized here so
    // callers don't need to know about backend-specific injection risks.
    validate_config_paths(config)?;

    // Generate platform-specific sandbox profile.
    // Currently macOS-only; Linux will use Landlock ruleset builder.
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
        allow_jvm_attach: config.allow_jvm_attach,
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

/// Human-readable representation of the sandbox policy.
///
/// On macOS, returns the SBPL profile text (useful for `--print-profile`).
/// On Linux (future), returns a formatted Landlock rule summary.
pub fn describe(sandbox: &PreparedSandbox) -> &str {
    &sandbox.profile_text
}

/// Verify the sandbox mechanism works on this system.
///
/// On macOS, writes the profile to a temp file and runs `/usr/bin/true`
/// inside `sandbox-exec` to confirm enforcement is active.
///
/// On Linux (future), checks Landlock ABI availability and kernel version.
pub fn preflight(sandbox: &PreparedSandbox) -> Result<(), String> {
    let profile_path = write_temp_profile(&sandbox.profile_text)?;
    let result = exec::validate(&profile_path, &sandbox.project_dir, &sandbox.home_dir);
    let _ = std::fs::remove_file(&profile_path);
    result
}

/// Execute a command inside the sandbox, forwarding signals to the child.
///
/// Handles platform-specific sandbox setup internally:
/// - macOS: writes SBPL profile to temp file, invokes `sandbox-exec`
/// - Linux (future): applies Landlock ruleset + seccomp filter, then `execvp`
///
/// Environment handling is controlled by `extra_pass_env`, `inherit_env`,
/// and `disabled_categories` — see [`build_sandbox_env()`] for details.
#[allow(clippy::too_many_arguments)]
pub fn exec_sandboxed(
    sandbox: &PreparedSandbox,
    copilot_bin: &Path,
    copilot_args: &[String],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
) -> u8 {
    let profile_path = match write_temp_profile(&sandbox.profile_text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\x1b[0;31m[cplt]\x1b[0m {e}");
            return 1;
        }
    };

    let exit_code = exec::exec(
        copilot_bin,
        &profile_path,
        &sandbox.project_dir,
        copilot_args,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        sandbox.scratch_dir.as_deref(),
        sandbox.proxy_port,
    );

    let _ = std::fs::remove_file(&profile_path);
    exit_code
}

// ── Internal helpers ───────────────────────────────────────────

/// Validate all paths in a [`SandboxConfig`] for backend-specific injection.
///
/// On macOS, SBPL profiles use string interpolation — paths containing
/// `"`, `;`, `(`, etc. could inject malicious rules. This validates every
/// path that will be interpolated into the profile.
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

/// Write SBPL profile text to a temp file with secure creation.
///
/// Uses O_CREAT|O_EXCL (create_new) to prevent symlink-following attacks,
/// and mode 0600 to restrict read access.
fn write_temp_profile(profile_text: &str) -> Result<PathBuf, String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let path = std::env::temp_dir().join(format!(
        "cplt-{}-{}.sb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("Cannot create sandbox profile: {e}"))?;

    file.write_all(profile_text.as_bytes()).map_err(|e| {
        let _ = std::fs::remove_file(&path);
        format!("Cannot write sandbox profile: {e}")
    })?;

    Ok(path)
}
