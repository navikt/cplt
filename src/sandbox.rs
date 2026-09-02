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
    HomeToolDir, TOOL_PATH_ENV_VARS, ToolPathEnvVar, ToolPathOverride, app_dirs, current_uid,
    home_tool_dirs, linux_docker_socket_paths, socket_mask_paths, tool_override_path_is_safe,
    tool_path_env_overrides, validate_sbpl_path,
};

// SBPL profile generation — kept public for unit tests.
// The SBPL module is pure string manipulation with no macOS dependencies,
// so tests run cross-platform even though the output is macOS-specific.
pub use profile::{ProfileOptions, generate_profile};

// Environment construction — already platform-agnostic.
pub use env::{
    SandboxEnv, build_sandbox_env, npmrc_explicitly_allowed, npmrc_userconfig_override,
    npmrc_userconfig_stale_variants,
};

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
    /// Force all egress through the proxy: restrict kernel-level egress to the
    /// proxy port only, dropping the default `*:443` allowance (#53). Consumed
    /// by the Landlock net-rule builder.
    pub proxy_forced: bool,
    pub allow_env_files: bool,
    pub allow_localhost_any: bool,
    pub scratch_dir: Option<&'a Path>,
    pub allow_tmp_exec: bool,
    /// Copilot CLI package directory (resolved from the binary location).
    pub copilot_install_dir: Option<&'a Path>,
    /// JAVA_HOME directory — grants JDK read + dylib loading.
    pub java_home: Option<&'a Path>,
    /// DOTNET_ROOT directory — grants .NET SDK read + dylib loading.
    pub dotnet_root: Option<&'a Path>,
    /// Global git hooks directory from `core.hooksPath`.
    pub git_hooks_path: Option<&'a Path>,
    /// Shared .git directory for git worktrees.
    pub git_common_dir: Option<&'a Path>,
    pub allow_gpg_signing: bool,
    pub deny_clipboard: bool,
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
    /// Whether the user explicitly re-allowed `$HOME/.npmrc` via `allow.read`.
    /// Suppresses the `NPM_CONFIG_USERCONFIG` redirect (see #180).
    npmrc_allowed: bool,
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
    prepare_impl(config, &extra_git_dirs(config.extra_write))
}

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
fn extra_git_dirs(extra_write: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = extra_write
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
fn prepare_impl(
    config: &SandboxConfig,
    extra_git_dirs: &[PathBuf],
) -> Result<PreparedSandbox, String> {
    validate_config_paths(config)?;
    // Interpolated into the profile like every other path — same injection check.
    for p in extra_git_dirs {
        policy::validate_sbpl_path(p).map_err(|e| format!("Granted repo .git dir: {e}"))?;
    }

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
        proxy_forced: config.proxy_forced,
        allow_env_files: config.allow_env_files,
        allow_localhost_any: config.allow_localhost_any,
        scratch_dir: config.scratch_dir,
        allow_tmp_exec: config.allow_tmp_exec,
        copilot_install_dir: config.copilot_install_dir,
        java_home: config.java_home,
        dotnet_root: config.dotnet_root,
        git_hooks_path: config.git_hooks_path,
        git_common_dir: config.git_common_dir,
        extra_git_dirs,
        allow_gpg_signing: config.allow_gpg_signing,
        deny_clipboard: config.deny_clipboard,
        allow_jvm_attach: config.allow_jvm_attach,
        allow_msbuild: config.allow_msbuild,
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
        npmrc_allowed: env::npmrc_explicitly_allowed(config.home_dir, config.extra_read),
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

#[cfg(target_os = "linux")]
fn prepare_impl(
    config: &SandboxConfig,
    extra_git_dirs: &[PathBuf],
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
    if config.allow_docker {
        ui::warn(
            "--allow-docker on Linux grants the Docker/Podman daemon sockets and \
             exempts them from the Bubblewrap socket masks — daemon socket access is \
             effectively host root. ~/.docker stays denied, so Docker CLI contexts and \
             registry auth are still unavailable (#155).",
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

    let policy = landlock_mod::generate_policy(config);
    let profile_text = landlock_mod::describe_policy(&policy);

    // Finding 1: Landlock cannot deny subpaths inside the writable project tree,
    // so the project's .git/hooks (and other git-persistence files) stay
    // writable — a persistence-escape vector. When Bubblewrap is active we
    // re-bind those pre-existing paths read-only to restore macOS parity. In a
    // git worktree the real hooks live under the shared git_common_dir (which
    // the sandbox grants write access to), so pass it through to cover them too.
    //
    // #212: every writable granted path is a candidate too — a sibling repo's
    // .git/hooks was fully writable before, and hooks run unsandboxed.
    let mut write_roots: Vec<&Path> = vec![config.project_dir];
    write_roots.extend(config.extra_write.iter().map(PathBuf::as_path));
    let mut git_dirs: Vec<&Path> = config.git_common_dir.into_iter().collect();
    git_dirs.extend(extra_git_dirs.iter().map(PathBuf::as_path));
    let ro_protect = bubblewrap::git_persistence_paths(&write_roots, &git_dirs);

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
    let socket_masks: Vec<PathBuf> =
        policy::socket_mask_paths(policy::current_uid(), config.allow_docker)
            .into_iter()
            .filter(|p| p.exists())
            .collect();
    let deny_masks =
        bubblewrap::build_deny_masks(config.extra_deny, &socket_masks, config.scratch_dir);

    // Decide bubblewrap wrapping before `precompute()` consumes `policy`.
    // `resolve()` only clones `fs_rules`/`net_rules` on the arms that actually
    // build a wrapper (explicit-on, or auto-detect with bwrap available) — the
    // disabled and fallback arms borrow and clone nothing.
    let bwrap_wrapper = bubblewrap::resolve(
        config.use_bubblewrap,
        &policy.fs_rules,
        &policy.net_rules,
        policy.restrict_net_connect,
        config.proxy_forced,
        &ro_protect,
        &deny_masks,
    )?;

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
        proxy_port: config.proxy_port,
        agent: config.agent,
        allow_localhost: config.localhost_ports.to_vec(),
        allow_localhost_any: config.allow_localhost_any,
        npmrc_allowed: env::npmrc_explicitly_allowed(config.home_dir, config.extra_read),
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
    if let Some(dir) = config.dotnet_root {
        policy::validate_sbpl_path(dir).map_err(|e| format!("DOTNET_ROOT: {e}"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
