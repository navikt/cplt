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
    ENV_PREFIX_ALLOWLIST, EXEC_IN_WRITABLE, ExecInWritable, HARDENING_ENV_VARS, HOME_TOOL_DIRS,
    HardeningCategory, HardeningEnvVar, HomeToolDir, LinuxCoverage,
    PLAYWRIGHT_SOCKET_BASE_MAX_BYTES, PLAYWRIGHT_SOCKET_DIR_PREFIX, PLAYWRIGHT_SOCKET_PATH_LIMIT,
    PLAYWRIGHT_SOCKET_ROOT, PLAYWRIGHT_SOCKET_WORST_CASE_SUFFIX, PROTECTED_IN_GITDIR,
    PROTECTED_IN_ROOT, PathBinDir, Protected, ResolvedToolDir, TOOL_PATH_ENV_VARS, ToolPathEnvVar,
    ToolPathOverride, ToolRoot, active_tool_dirs, app_dirs, copilot_ro_protect_paths, current_uid,
    home_tool_dirs, linux_docker_socket_paths, linux_runtime_dirs, mise_ro_protect_paths,
    nested_alternation, path_bin_dirs, playwright_runtime_intent, relocatable_tool_prefix,
    socket_mask_paths, tool_override_path_is_safe, tool_path_env_overrides,
    validate_playwright_socket_dir, validate_sbpl_path, xdg_runtime_dir_env,
};

// SBPL profile generation — kept public for unit tests.
// The SBPL module is pure string manipulation with no macOS dependencies,
// so tests run cross-platform even though the output is macOS-specific.
pub use profile::{generate_profile, generate_profile_with_playwright_socket_dir};

// Environment construction — already platform-agnostic.
pub use env::{
    SandboxEnv, build_sandbox_env, npmrc_explicitly_allowed, npmrc_userconfig_override,
    npmrc_userconfig_stale_variants, playwright_mcp_sandbox_disabled,
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
/// - A Playwright socket directory is supplied on a non-macOS platform
/// - The platform does not support sandboxing
pub fn prepare(config: &SandboxConfig) -> Result<PreparedSandbox, String> {
    validate_playwright_socket_capability(config.playwright_socket_dir)?;
    validate_hard_denied_grants(config)?;
    validate_exec_grants(config)?;
    prepare_impl(config, &extra_git_dirs(config.extra_write))
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
            if let Some(file) = policy::hard_denied_file(config.home_dir, p) {
                return Err(format!(
                    "{key} names {} (~/{file}), which is on the hard-deny list and cannot be granted explicitly. Remove it from your config or command line.",
                    p.display()
                ));
            }
            if let Some(dir) = policy::denied_dotfile_dir(config.home_dir, p) {
                return Err(format!(
                    "{key} names {} (~/{dir}), a credential directory that cannot be granted \
                     whole: macOS denies it whatever the grant says, so honouring it on Linux \
                     alone would mean the same config opens every key in it on one platform \
                     and nothing on the other. Name the specific path you need inside it \
                     instead, e.g. ~/{dir}/<file> — that grant works on both.",
                    p.display()
                ));
            }
        }
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
#[cfg(target_os = "linux")]
fn ro_protect_paths(config: &SandboxConfig, extra_git_dirs: &[PathBuf]) -> Vec<PathBuf> {
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

    // #238: mise's `shims/` and `installs/` are PATH-resolved binary drop
    // points sitting inside the mise data dir, which stays writable for the
    // rest of mise's state. The other PATH-resolved dirs (~/.bun/bin,
    // ~/.deno/bin, $PNPM_HOME) need nothing here: HOME_TOOL_DIRS grants write
    // to their sibling caches rather than to the parent, so Landlock enforces
    // them on its own, with or without bwrap. Same "must already exist" caveat
    // as everything else in this list.
    ro_protect.extend(mise_ro_protect_paths(config.home_dir));

    // #328: Copilot's package dirs. macOS write-denies both in the profile;
    // Landlock cannot — `~/.copilot` is granted write wholesale, and
    // `~/.cache/copilot/pkg`'s execute rule unions with the `~/.cache` write
    // grant from HOME_TOOL_DIRS, leaving the SEA runtime writable AND
    // executable. Only the bwrap overlay can take the write back. Empty for
    // every other agent.
    ro_protect.extend(copilot_ro_protect_paths(config.agent, config.home_dir));

    ro_protect.sort();
    ro_protect.dedup();
    ro_protect
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

    let policy = landlock_mod::generate_policy(config);
    let profile_text = landlock_mod::describe_policy(&policy);

    let ro_protect = ro_protect_paths(config, extra_git_dirs);

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
        policy::current_uid(),
        policy::xdg_runtime_dir_env().as_deref(),
        config.allow_docker,
    )
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
    for d in config.existing_home_tool_dirs.unwrap_or(&[]) {
        policy::validate_sbpl_path(&d.path).map_err(|e| format!("Tool dir: {e}"))?;
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
mod tests {
    use super::*;

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
            java_home: None,
            dotnet_root: None,
            git_hooks_path: None,
            git_common_dir: None,
            allow_gpg_signing: false,
            deny_clipboard: false,
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

    /// The ro_protect set the bwrap overlay consumes, end to end.
    ///
    /// The helpers each had a test; the wiring that assembles them did not, and
    /// a mutation deleting the Copilot line from the caller passed Linux CI
    /// green. This asserts the assembled set, which is what the overlay
    /// actually re-binds.
    #[cfg(target_os = "linux")]
    #[test]
    fn ro_protect_set_carries_the_copilot_package_dirs_for_copilot_only() {
        let home = Path::new("/home/test");
        let mut config = test_config(home, &[]);
        config.agent = Agent::Copilot;
        let paths = super::ro_protect_paths(&config, &[]);
        for expected in [home.join(".copilot/pkg"), home.join(".cache/copilot/pkg")] {
            assert!(
                paths.contains(&expected),
                "{} must be in the bwrap read-only set, got {paths:?}",
                expected.display()
            );
        }

        config.agent = Agent::Claude;
        let paths = super::ro_protect_paths(&config, &[]);
        assert!(
            !paths.iter().any(|p| p.starts_with(home.join(".copilot"))),
            "no Copilot package binds for a non-Copilot agent, got {paths:?}"
        );
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
            assert!(
                error.contains("Name the specific path"),
                "the error must point at the grant that does work: {error}"
            );

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
    #[test]
    fn prepare_accepts_a_grant_inside_a_denied_dotfile_directory() {
        let home = Path::new("/home/test");
        let granted = vec![
            home.join(".ssh/id_ed25519"),
            home.join(".ssh/known_hosts"),
            home.join(".config/gcloud/application_default_credentials.json"),
        ];

        let mut config = test_config(home, &granted);
        assert_eq!(validate_hard_denied_grants(&config), Ok(()));
        config.extra_read = &[];
        config.extra_write = &granted;
        assert_eq!(validate_hard_denied_grants(&config), Ok(()));
    }

    /// `--allow-docker` grants `~/.docker` read-only, and `~/.docker` is a
    /// `DENIED_DOTFILES` entry. It is a first-party rule the backends emit, not
    /// a user grant, so the #291 refusal must not be able to see it — otherwise
    /// the flag would refuse every run it is set on.
    #[test]
    fn prepare_does_not_refuse_the_allow_docker_dotfile_grant() {
        let home = Path::new("/home/test");
        let mut config = test_config(home, &[]);
        config.allow_docker = true;

        assert_eq!(validate_hard_denied_grants(&config), Ok(()));
        assert!(
            prepare(&config).is_ok(),
            "--allow-docker must not be caught by the denied-dotfile refusal"
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
        let home = Path::new("/home/test");
        let exec_paths = vec![PathBuf::from("/tmpfoo/bin")];
        let mut config = test_config(home, &[]);
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
