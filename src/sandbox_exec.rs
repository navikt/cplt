//! Sandbox process execution and signal forwarding.
//!
//! Launches the agent binary inside the OS sandbox (`sandbox-exec` on macOS,
//! Landlock+seccomp on Linux), forwarding signals and translating exit codes.

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::env::build_sandbox_env;
use super::policy::HardeningCategory;
use crate::agent::Agent;
use crate::ui;

/// Config filenames that mise searches for in ancestor directories.
const MISE_CONFIG_FILENAMES: &[&str] = &[".tool-versions", ".mise.toml", "mise.toml"];

/// Compute `MISE_IGNORED_CONFIG_PATHS` for ancestor directories the sandbox can't read.
///
/// mise traverses from CWD up to `/` looking for config files. The sandbox allows reading
/// `$HOME/.tool-versions` (literal) and the project dir (subpath), but ancestor directories
/// between home and project are blocked. We scan for actual config files in those ancestors
/// and tell mise to skip them, preventing "Operation not permitted" errors.
fn compute_mise_ignored_paths(project_dir: &Path, home: &Path) -> Vec<PathBuf> {
    let mut ignored = Vec::new();

    // Walk ancestors of project_dir (exclusive) up to home (exclusive).
    // These are directories inside $HOME that aren't the project and aren't $HOME itself.
    let mut dir = project_dir.parent();
    while let Some(ancestor) = dir {
        if ancestor == home || !ancestor.starts_with(home) {
            break;
        }
        for filename in MISE_CONFIG_FILENAMES {
            let candidate = ancestor.join(filename);
            if candidate.exists() {
                ignored.push(candidate);
            }
        }
        dir = ancestor.parent();
    }

    ignored
}

// ── Shared command setup ──────────────────────────────────────

/// Configure environment, proxy, and common args on a sandboxed Command.
///
/// Both macOS (Seatbelt) and Linux (Landlock) paths call this to apply the
/// identical env filtering, proxy routing, and recursion guard.
#[allow(clippy::too_many_arguments)]
fn configure_command(
    cmd: &mut Command,
    copilot_args: &[String],
    project_dir: &Path,
    home_dir: &Path,
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    scratch_dir: Option<&Path>,
    proxy_port: Option<u16>,
    allow_localhost: &[u16],
    allow_localhost_any: bool,
    agent: Agent,
    gh_guard: &crate::config::GhGuardPolicy,
    git_guard: &crate::config::GitGuardPolicy,
) {
    for arg in copilot_args {
        cmd.arg(arg);
    }

    cmd.current_dir(project_dir);

    // Build and apply environment
    let parent_env: Vec<(String, String)> = std::env::vars().collect();
    let sandbox_env = build_sandbox_env(
        &parent_env,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        scratch_dir,
        agent,
    );

    if sandbox_env.clear_first {
        cmd.env_clear();
        for (key, val) in &sandbox_env.vars {
            cmd.env(key, val);
        }
    } else {
        for var in &sandbox_env.remove {
            cmd.env_remove(var);
        }
        for (key, val) in &sandbox_env.vars {
            cmd.env(key, val);
        }
    }

    // Tell mise to ignore config files in ancestor directories that the sandbox blocks.
    let ignored = compute_mise_ignored_paths(project_dir, home_dir);
    if !ignored.is_empty() {
        let paths: Vec<String> = ignored
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        cmd.env("MISE_IGNORED_CONFIG_PATHS", paths.join(":"));
    }

    // Recursion guard: if copilot somehow re-invokes cplt (e.g. via symlink),
    // cplt will see this and bail before launching another sandbox.
    cmd.env("__CPLT_WRAPPED", "1");

    // When proxy is enabled, tell Node.js (bundled in Copilot CLI) to route
    // traffic through our CONNECT proxy. NODE_USE_ENV_PROXY is required for
    // Node.js ≥24.5.0 to honor HTTP_PROXY/HTTPS_PROXY natively.
    if let Some(port) = proxy_port {
        let proxy_url = format!("http://127.0.0.1:{port}");
        cmd.env("NODE_USE_ENV_PROXY", "1");
        cmd.env("HTTP_PROXY", &proxy_url);
        cmd.env("HTTPS_PROXY", &proxy_url);
        cmd.env("http_proxy", &proxy_url);
        cmd.env("https_proxy", &proxy_url);
        // Exclude loopback from proxying when localhost access is explicitly enabled:
        //   - macOS: always excluded — Seatbelt enforces localhost at the kernel level.
        //   - Linux: excluded only when the user opened specific localhost ports or
        //     --allow-localhost-any. Without explicit localhost access, the proxy is
        //     the sole mechanism blocking loopback connections (Landlock is port-based
        //     only and cannot distinguish localhost from remote hosts).
        #[cfg(target_os = "macos")]
        let set_no_proxy = {
            let _ = (allow_localhost, allow_localhost_any); // used on Linux only
            true
        };
        #[cfg(not(target_os = "macos"))]
        let set_no_proxy = allow_localhost_any || !allow_localhost.is_empty();
        if set_no_proxy {
            cmd.env("NO_PROXY", "localhost,127.0.0.1,::1");
            cmd.env("no_proxy", "localhost,127.0.0.1,::1");
        }
    }

    // Install command wrappers if scratch dir exists and features are enabled.
    // - gh proxy: intercepts gh commands and blocks destructive operations
    // - git push prevention: blocks git push while allowing all other git operations
    if let Some(scratch) = scratch_dir {
        if gh_guard.enabled {
            // Inject GH_TOKEN into env only when explicitly requested.
            if gh_guard.inject_token {
                inject_gh_token_if_needed(cmd, agent);
            }
            // Cache token to file so the wrapper can serve `gh auth token`
            // requests without exposing the token as an env var to all child
            // processes. NOTE (Finding 3): this is best-effort, NOT a same-UID
            // boundary. The scratch dir is the agent's TMPDIR, and the gh
            // wrapper runs as the agent's UID *inside* the sandbox, so whatever
            // the wrapper can read the agent can read too. What this buys: the
            // token is not an inherited env var (so it can't leak via `/proc/*/
            // environ` of every child), and the file is 0600 and deleted after
            // the first read (see `serve_cached_gh_token`), which narrows — but
            // does not close — the window. A determined agent that reads
            // `$TMPDIR/.gh-token` before the legitimate consumer still wins.
            if gh_guard.block_auth_token {
                cache_gh_token_to_file(scratch, agent);
            }
        }
        install_command_wrappers(cmd, scratch, project_dir, gh_guard, git_guard);
    }
}

/// Inject GH_TOKEN into the command env if not already present.
///
/// Runs `gh auth token` outside the sandbox to extract the token from
/// `~/.config/gh/hosts.yml`, then injects it as GH_TOKEN. This allows
/// the gh proxy to safely block `gh auth token` inside the sandbox
/// while still giving the agent API access.
///
/// Only injects for agents that need GitHub access (Copilot).
fn inject_gh_token_if_needed(cmd: &mut Command, agent: Agent) {
    // Only inject for Copilot — other agents have their own auth
    if agent != Agent::Copilot {
        return;
    }

    // Skip if any GitHub token is already set (non-empty) in the environment
    let has_token = |key| std::env::var(key).is_ok_and(|v| !v.is_empty());
    if has_token("GH_TOKEN") || has_token("GITHUB_TOKEN") || has_token("COPILOT_GITHUB_TOKEN") {
        return;
    }

    // Extract token from gh CLI config (outside sandbox)
    let Ok(output) = std::process::Command::new("gh")
        .args(["auth", "token"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
    else {
        return;
    };

    if !output.status.success() {
        return;
    }

    let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !token.is_empty() {
        cmd.env("GH_TOKEN", &token);
    }
}

/// Cache the GitHub token to a file in the scratch dir.
///
/// The gh wrapper script reads this file to serve `gh auth token` requests
/// without exposing the token as an environment variable to all child processes.
/// The file is owner-readable only (mode 0o600) and is deleted after the first
/// read (see `serve_cached_gh_token`).
///
/// # Security scope (Finding 3): best-effort, not a same-UID boundary
///
/// The scratch dir IS the agent's `TMPDIR`, and the gh wrapper that consumes
/// this file runs as the agent's own UID *inside* the sandbox. Anything the
/// wrapper can read the agent can read at the same UID, so a filesystem `deny`
/// on this path is not viable (it would break the wrapper). What
/// `block_auth_token` genuinely delivers is keeping the token OUT of the
/// process environment so it can't be scraped from every child's `/proc/*/
/// environ`; the 0600 mode + one-time-read deletion narrow the file's exposure
/// window. They do NOT prevent a determined same-UID agent from `cat`-ing
/// `$TMPDIR/.gh-token` before the legitimate read. Do not treat this as
/// confidentiality against an adversarial agent.
fn cache_gh_token_to_file(scratch_dir: &Path, agent: Agent) {
    // Only cache for Copilot — other agents have their own auth
    if agent != Agent::Copilot {
        return;
    }

    // Skip if any GitHub token is already set (non-empty) in the environment —
    // in that case Copilot will use the env var directly.
    let has_token = |key| std::env::var(key).is_ok_and(|v| !v.is_empty());
    if has_token("GH_TOKEN") || has_token("GITHUB_TOKEN") || has_token("COPILOT_GITHUB_TOKEN") {
        return;
    }

    // Extract token from gh CLI config (outside sandbox)
    let Ok(output) = std::process::Command::new("gh")
        .args(["auth", "token"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
    else {
        return;
    };

    if !output.status.success() {
        return;
    }

    let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if token.is_empty() {
        return;
    }

    // Write token to file, creating it with 0600 from the start to avoid a
    // permissions window where the file is world-readable.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let token_path = scratch_dir.join(".gh-token");
    let Ok(mut file) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&token_path)
    else {
        return;
    };
    let _ = file.write_all(token.as_bytes());
}

/// Install gh and git wrapper scripts into the scratch dir and prepend to PATH.
///
/// Both wrappers follow the same pattern: intercept the command, call back to
/// cplt for a policy decision, then exec the real binary or block.
/// Policy is baked into the wrapper invocation — not re-read from config at gate time.
fn install_command_wrappers(
    cmd: &mut Command,
    scratch_dir: &Path,
    project_dir: &Path,
    gh_guard: &crate::config::GhGuardPolicy,
    git_guard: &crate::config::GitGuardPolicy,
) {
    use std::os::unix::fs::PermissionsExt;

    // Find cplt binary (ourselves)
    let Ok(cplt_bin) = std::env::current_exe() else {
        return;
    };

    let bin_dir = scratch_dir.join("bin");
    if std::fs::create_dir_all(&bin_dir).is_err() {
        return;
    }

    let cplt_str = cplt_bin.to_string_lossy();
    let mut installed_any = false;

    // Install gh wrapper (only if gh_proxy enabled)
    if gh_guard.enabled
        && let Some(real_gh) = which_binary("gh")
    {
        let repo_scope = if gh_guard.scope_check {
            if let Some(real_git) = which_binary("git") {
                match crate::gh_proxy::detect_current_repo(&real_git, project_dir) {
                    Ok(repo) => Some(repo),
                    Err(reason) => {
                        ui::warn(&format!(
                            "gh guard could not capture repository scope: {reason}. \
                             Scope-checked commands will be blocked."
                        ));
                        None
                    }
                }
            } else {
                ui::warn(
                    "gh guard could not find Git to capture repository scope. \
                     Scope-checked commands will be blocked.",
                );
                None
            }
        } else {
            None
        };
        let script = crate::gh_proxy::generate_wrapper_script(
            &real_gh.to_string_lossy(),
            repo_scope.as_deref(),
            &cplt_str,
            gh_guard,
        );
        let wrapper_path = bin_dir.join("gh");
        if std::fs::write(&wrapper_path, script).is_ok() {
            let _ = std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755));
            installed_any = true;
        }
    }

    // Install git guard wrapper (only if git_guard enabled)
    if git_guard.enabled
        && let Some(real_git) = which_binary("git")
    {
        let script = crate::gh_proxy::generate_git_wrapper_script(
            &real_git.to_string_lossy(),
            &cplt_str,
            git_guard,
        );
        let wrapper_path = bin_dir.join("git");
        if std::fs::write(&wrapper_path, script).is_ok() {
            let _ = std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755));
            installed_any = true;
        }
    }

    // Prepend {scratch}/bin to PATH so wrappers shadow the real binaries.
    if installed_any {
        let bin_dir_str = bin_dir.to_string_lossy().to_string();
        let new_path = if let Some(current_path) = std::env::var_os("PATH") {
            format!("{}:{}", bin_dir_str, current_path.to_string_lossy())
        } else {
            bin_dir_str
        };
        cmd.env("PATH", &new_path);
    }
}

/// Find a binary in PATH by name.
pub(crate) fn which_binary(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Ignore SIGTTOU/SIGTTIN — copilot (Node.js) may manipulate terminal
/// settings (raw mode), and when the child exits the terminal state can
/// cause these signals to be sent to us.
fn ignore_terminal_stop_signals() {
    unsafe {
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
    }
}

fn restore_terminal_stop_signals() {
    unsafe {
        libc::signal(libc::SIGTTOU, libc::SIG_DFL);
        libc::signal(libc::SIGTTIN, libc::SIG_DFL);
    }
}

/// Forward SIGTERM/SIGHUP to an already-spawned child and wait for it,
/// translating the exit status to a u8 exit code (128 + signal if killed).
fn forward_and_wait(mut child: std::process::Child) -> u8 {
    let child_pid = child.id() as i32;
    install_signal_forwarding(child_pid);

    match child.wait() {
        Ok(status) => status
            .code()
            .unwrap_or_else(|| status.signal().map_or(1, |s| 128 + s)) as u8,
        Err(e) => {
            ui::error(&format!("Error waiting for child: {e}"));
            unsafe {
                libc::kill(child_pid, libc::SIGTERM);
            }
            1
        }
    }
}

/// Spawn a sandboxed command, forward signals, and wait for exit.
///
/// Handles SIGTTOU/SIGTTIN suppression (Node.js terminal raw mode),
/// SIGTERM/SIGHUP forwarding to the child, and cleanup on exit.
fn spawn_and_wait(cmd: &mut Command) -> u8 {
    ignore_terminal_stop_signals();

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            ui::error(&format!("Failed to start sandboxed process: {e}"));
            restore_terminal_stop_signals();
            return 1;
        }
    };

    let status = forward_and_wait(child);
    restore_terminal_stop_signals();
    status
}

fn install_signal_forwarding(child_pid: i32) {
    use std::sync::atomic::{AtomicI32, Ordering};

    static CHILD_PID: AtomicI32 = AtomicI32::new(0);
    CHILD_PID.store(child_pid, Ordering::SeqCst);

    extern "C" fn forward_signal(sig: i32) {
        use std::sync::atomic::Ordering;
        let pid = CHILD_PID.load(Ordering::SeqCst);
        if pid > 0 {
            unsafe {
                libc::kill(pid, sig);
            }
        }
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
        }
    }

    unsafe {
        libc::signal(
            libc::SIGTERM,
            forward_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGHUP,
            forward_signal as *const () as libc::sighandler_t,
        );
    }
}

// ── macOS: Seatbelt / sandbox-exec ────────────────────────────

/// Verify the SBPL profile works by running `/usr/bin/true` inside sandbox-exec.
#[cfg(target_os = "macos")]
pub fn preflight(sandbox: &super::PreparedSandbox) -> Result<(), String> {
    let profile_path = write_temp_profile(&sandbox.profile_text)?;
    let output = Command::new("sandbox-exec")
        .arg("-f")
        .arg(&profile_path)
        .arg("/usr/bin/true")
        .output()
        .map_err(|e| format!("Failed to run sandbox-exec: {e}"));
    let _ = std::fs::remove_file(&profile_path);

    let output = output?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "sandbox-exec exited with {}: {stderr}",
            output.status
        ))
    }
}

/// Execute copilot inside the macOS Seatbelt sandbox.
///
/// Writes the SBPL profile to a temp file, invokes `sandbox-exec`, and
/// cleans up the profile file on exit.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
pub fn exec(
    sandbox: &super::PreparedSandbox,
    copilot_bin: &Path,
    copilot_args: &[String],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    deny_env: &[String],
    gh_guard: &crate::config::GhGuardPolicy,
    git_guard: &crate::config::GitGuardPolicy,
) -> u8 {
    let profile_path = match write_temp_profile(&sandbox.profile_text) {
        Ok(p) => p,
        Err(e) => {
            ui::error(&e.clone());
            return 1;
        }
    };

    let mut cmd = Command::new("sandbox-exec");
    cmd.arg("-f").arg(&profile_path).arg(copilot_bin);

    configure_command(
        &mut cmd,
        copilot_args,
        &sandbox.project_dir,
        &sandbox.home_dir,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        sandbox.scratch_dir.as_deref(),
        sandbox.proxy_port,
        &sandbox.allow_localhost,
        sandbox.allow_localhost_any,
        sandbox.agent,
        gh_guard,
        git_guard,
    );

    // Strip repo-config denied env vars
    for var in deny_env {
        cmd.env_remove(var);
    }

    let exit_code = spawn_and_wait(&mut cmd);
    let _ = std::fs::remove_file(&profile_path);
    exit_code
}

/// Write SBPL profile text to a temp file with secure creation.
///
/// Uses O_CREAT|O_EXCL (create_new) to prevent symlink-following attacks,
/// and mode 0600 to restrict read access.
#[cfg(target_os = "macos")]
fn write_temp_profile(profile_text: &str) -> Result<std::path::PathBuf, String> {
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

// ── Linux: Landlock + seccomp ─────────────────────────────────

/// Verify Landlock sandbox readiness (no-op: ABI already checked in prepare).
///
/// Returns `Result` to match the macOS preflight signature (which can fail).
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
pub fn preflight(_sandbox: &super::PreparedSandbox) -> Result<(), String> {
    Ok(())
}

/// Execute the agent inside a Landlock + seccomp sandbox, optionally wrapped
/// with Bubblewrap namespaces.
///
/// # Layering
///
/// - **Without bwrap**: Landlock + seccomp are applied via a `pre_exec` hook
///   that runs in the child between `fork()` and `execve()`.
/// - **With bwrap**: the pre_exec hook is deliberately **not** installed on the
///   `bwrap` process — our seccomp filter `EPERM`s `unshare`/`mount` and the
///   Landlock domain blocks the bind-mount sources, either of which would
///   prevent bwrap from building its namespaces. Instead bwrap runs
///   unrestricted and re-execs this binary as an in-namespace helper (see
///   [`super::bubblewrap`]) which applies Landlock + seccomp to itself and then
///   `execve`s the agent. Landlock + seccomp therefore end up enforced on the
///   agent, never on bwrap and never dropped.
///
/// If the bwrap path cannot start (auto-detect only), it degrades gracefully to
/// the direct Landlock + seccomp path below.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn exec(
    sandbox: &super::PreparedSandbox,
    copilot_bin: &Path,
    copilot_args: &[String],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    deny_env: &[String],
    gh_guard: &crate::config::GhGuardPolicy,
    git_guard: &crate::config::GitGuardPolicy,
) -> u8 {
    use std::os::unix::process::CommandExt as _;

    // Bubblewrap-wrapped path (namespaces + in-namespace Landlock/seccomp).
    if let Some(wrapper) = sandbox.bwrap_wrapper.as_ref() {
        match exec_bwrap(
            sandbox,
            wrapper,
            copilot_bin,
            copilot_args,
            extra_pass_env,
            inherit_env,
            disabled_categories,
            deny_env,
            gh_guard,
            git_guard,
        ) {
            BwrapOutcome::Ran(code) => return code,
            BwrapOutcome::Fallback => {
                ui::warn("Bubblewrap could not start; using Landlock + seccomp only.");
                if wrapper.deny_mask_count > 0 {
                    // prepare() already announced these as enforced.
                    ui::warn(&format!(
                        "{} deny path(s) are NOT enforced in this run: the mount masks \
                         went with Bubblewrap, and Landlock cannot deny subpaths within \
                         allowed directories.",
                        wrapper.deny_mask_count
                    ));
                }
                // fall through to the direct path
            }
        }
    }

    // Direct Landlock + seccomp path (also the auto-detect fallback).
    let mut cmd = Command::new(copilot_bin);

    configure_command(
        &mut cmd,
        copilot_args,
        &sandbox.project_dir,
        &sandbox.home_dir,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        sandbox.scratch_dir.as_deref(),
        sandbox.proxy_port,
        &sandbox.allow_localhost,
        sandbox.allow_localhost_any,
        sandbox.agent,
        gh_guard,
        git_guard,
    );

    // Strip repo-config denied env vars
    for var in deny_env {
        cmd.env_remove(var);
    }

    // Apply pre-computed sandbox in the child process, between fork and exec.
    // Safety: The proxy thread is running (multi-threaded at fork), making this
    // technically not async-signal-safe. The Landlock crate performs small heap
    // allocations internally. This works reliably in practice because the proxy
    // thread is blocked in I/O syscalls during fork, minimizing allocator lock
    // contention. See SECURITY.md "Pre-exec safety" for full analysis.
    let precomputed = sandbox.precomputed.clone();
    unsafe {
        cmd.pre_exec(move || super::landlock_mod::apply_precomputed(&precomputed));
    }

    spawn_and_wait(&mut cmd)
}

/// Outcome of attempting the bubblewrap-wrapped execution.
#[cfg(target_os = "linux")]
enum BwrapOutcome {
    /// The wrapped process ran (or bwrap failed under explicit `--use-bubblewrap`,
    /// which is a hard error rather than a fallback); carries the exit code.
    Ran(u8),
    /// bwrap could not start on the auto-detect path — caller should fall back.
    Fallback,
}

/// Run the agent under bwrap: `bwrap [ns args] -- <cplt re-entry helper>`.
///
/// bwrap builds the namespaces, then re-execs this binary as the in-namespace
/// helper (dispatched by the `.init_array` constructor in [`super::bubblewrap`]
/// via the [`super::bubblewrap::ENV_INNER_POLICY`] env var). The helper applies
/// Landlock + seccomp bound to the in-namespace inodes and `execve`s the agent.
///
/// A confirm pipe carries one byte from the helper (written just before it
/// `execve`s the agent). If the parent sees EOF instead — i.e. the helper never
/// applied the sandbox and the agent never ran — auto-detect falls back cleanly
/// with no risk of running the agent twice.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn exec_bwrap(
    sandbox: &super::PreparedSandbox,
    wrapper: &super::bubblewrap::BubblewrapWrapper,
    copilot_bin: &Path,
    copilot_args: &[String],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    deny_env: &[String],
    gh_guard: &crate::config::GhGuardPolicy,
    git_guard: &crate::config::GitGuardPolicy,
) -> BwrapOutcome {
    // The re-entry helper is this very binary; bwrap execs it by absolute path
    // (visible inside the namespace via `--ro-bind / /`).
    let cplt_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return bwrap_setup_failed(wrapper, &format!("cannot locate cplt binary: {e}")),
    };

    // Serialize the Landlock policy + agent argv for the helper to re-apply.
    let policy_bytes = match super::bubblewrap::serialize_policy(wrapper, copilot_bin, copilot_args)
    {
        Ok(b) => b,
        Err(e) => return bwrap_setup_failed(wrapper, &format!("policy setup failed: {e}")),
    };

    // Policy pipe: parent pre-loads the serialized policy; the helper inherits
    // the read end through bwrap (our pipe fds are not CLOEXEC and bwrap passes
    // inherited fds through). A pipe rather than a file because the namespace's
    // fresh `--tmpfs /tmp` would shadow a policy file in the host temp dir, and
    // no policy data touches the disk. Writing before spawn is deadlock-free
    // only while the payload fits the pipe buffer (64 KiB on Linux) — enforced.
    if policy_bytes.len() > 60_000 {
        return bwrap_setup_failed(wrapper, "policy too large for the transfer pipe");
    }
    let mut policy_fds = [0i32; 2];
    if unsafe { libc::pipe(policy_fds.as_mut_ptr()) } != 0 {
        return bwrap_setup_failed(wrapper, "cannot create policy pipe");
    }
    let (policy_read_fd, policy_write_fd) = (policy_fds[0], policy_fds[1]);
    let written = unsafe {
        libc::write(
            policy_write_fd,
            policy_bytes.as_ptr().cast(),
            policy_bytes.len(),
        )
    };
    // Close the write end now so the helper sees EOF after the payload.
    unsafe {
        libc::close(policy_write_fd);
    }
    if written != policy_bytes.len() as isize {
        unsafe {
            libc::close(policy_read_fd);
        }
        return bwrap_setup_failed(wrapper, "short write to policy pipe");
    }

    // Confirm pipe: read end stays in the parent (CLOEXEC), write end is
    // inherited through bwrap into the helper.
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        unsafe {
            libc::close(policy_read_fd);
        }
        return bwrap_setup_failed(wrapper, "cannot create confirm pipe");
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);
    unsafe {
        libc::fcntl(read_fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }

    let mut bwrap_argv = wrapper.bwrap_args.clone();
    bwrap_argv.push("--".to_string());
    bwrap_argv.push(cplt_exe.to_string_lossy().into_owned());

    let mut cmd = Command::new(&wrapper.bwrap_path);
    cmd.args(&bwrap_argv);
    configure_command(
        &mut cmd,
        &[],
        &sandbox.project_dir,
        &sandbox.home_dir,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        sandbox.scratch_dir.as_deref(),
        sandbox.proxy_port,
        &sandbox.allow_localhost,
        sandbox.allow_localhost_any,
        sandbox.agent,
        gh_guard,
        git_guard,
    );
    for var in deny_env {
        cmd.env_remove(var);
    }
    // Set the re-entry env AFTER configure_command so a `clear_first` env build
    // cannot wipe them.
    cmd.env(
        super::bubblewrap::ENV_INNER_POLICY,
        policy_read_fd.to_string(),
    );
    cmd.env(super::bubblewrap::ENV_CONFIRM_FD, write_fd.to_string());

    ignore_terminal_stop_signals();
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            restore_terminal_stop_signals();
            unsafe {
                libc::close(policy_read_fd);
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return bwrap_setup_failed(wrapper, &format!("failed to spawn bwrap: {e}"));
        }
    };

    // Close the parent's copies: the helper has its own inherited descriptors,
    // and dropping the confirm write end makes EOF observable if the helper
    // never writes the confirm byte.
    unsafe {
        libc::close(policy_read_fd);
        libc::close(write_fd);
    }
    let confirm = read_confirm_byte(read_fd);
    unsafe {
        libc::close(read_fd);
    }

    if matches!(confirm, ConfirmResult::Eof) {
        // Helper never applied the sandbox and never execed the agent — reap
        // the child and fall back (agent has not run, so no double execution).
        let _ = forward_and_wait(child);
        restore_terminal_stop_signals();
        return bwrap_setup_failed(wrapper, "namespace helper did not apply the sandbox");
    }

    let code = forward_and_wait(child);
    restore_terminal_stop_signals();
    BwrapOutcome::Ran(code)
}

/// Map a bwrap start-up failure to an outcome: hard error when bwrap was
/// explicitly requested, graceful fallback on auto-detect.
#[cfg(target_os = "linux")]
fn bwrap_setup_failed(
    wrapper: &super::bubblewrap::BubblewrapWrapper,
    detail: &str,
) -> BwrapOutcome {
    if wrapper.strict {
        ui::error(&format!("Bubblewrap requested but {detail}."));
        BwrapOutcome::Ran(1)
    } else {
        BwrapOutcome::Fallback
    }
}

/// Result of waiting for the confirm byte from the bwrap re-entry helper.
#[cfg(target_os = "linux")]
enum ConfirmResult {
    /// The helper applied the sandbox and is about to run the agent.
    Confirmed,
    /// All write ends closed with no byte — the helper did not apply the sandbox.
    Eof,
    /// Timed out or errored; treat as "probably running" to avoid a double run.
    Unknown,
}

/// Wait (bounded) for the helper's confirm byte.
///
/// The helper writes the byte within milliseconds of startup; the generous
/// timeout only guards against a stuck descriptor and is treated as `Unknown`
/// (proceed to wait) rather than a fallback, so the agent is never run twice.
#[cfg(target_os = "linux")]
fn read_confirm_byte(fd: i32) -> ConfirmResult {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let r = unsafe { libc::poll(&raw mut pfd, 1, 15_000) };
        if r < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return ConfirmResult::Unknown;
        }
        if r == 0 {
            return ConfirmResult::Unknown; // timeout
        }
        let mut buf = [0u8; 1];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), 1) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return ConfirmResult::Unknown;
        }
        if n == 0 {
            return ConfirmResult::Eof;
        }
        return ConfirmResult::Confirmed;
    }
}
