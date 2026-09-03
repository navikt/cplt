//! Sandbox process execution and signal forwarding.
//!
//! Launches the agent binary inside the OS sandbox (`sandbox-exec` on macOS,
//! Landlock+seccomp on Linux), forwarding signals and translating exit codes.

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use super::env::build_sandbox_env;
use super::policy::{GITHUB_TOKEN_VARS, HardeningCategory};
use crate::agent::Agent;
use crate::ui;

/// Config filenames that mise searches for in ancestor directories.
const MISE_CONFIG_FILENAMES: &[&str] = &[".tool-versions", ".mise.toml", "mise.toml"];
const GH_AUTH_TOKEN_TIMEOUT: Duration = Duration::from_secs(5);

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
    // Repo-config denied env vars. The callers also strip these *after* this
    // function, but it needs them here to avoid a futile `GH_TOKEN` injection
    // (and the sibling-var clearing that comes with it) when `deny.env` will
    // remove `GH_TOKEN` anyway.
    deny_env: &[String],
    resolved_gh_token: Option<&str>,
    // The pre-extracted token is the agent's ONLY credential, because the
    // Keychain grant was dropped on the strength of having it. Forces the
    // `GH_TOKEN` env injection even when gh_guard is off — without it the
    // agent would launch with no way to authenticate at all.
    token_is_sole_credential: bool,
    gh_guard: &crate::config::GhGuardPolicy,
    git_guard: &crate::config::GitGuardPolicy,
    npmrc_allowed: bool,
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

    // Default DOTNET_CLI_HOME to the already-resolved, already-validated sandbox
    // home dir. Newer .NET SDKs no longer fall back to $HOME when resolving
    // their CLI home directory, and their fallback (a getpwuid-based lookup)
    // fails inside the sandbox — without DOTNET_CLI_HOME set, `dotnet build`
    // crashes at startup with "The user's home directory could not be
    // determined" before it ever reaches the project. Skipped when the parent
    // env already has a DOTNET_CLI_HOME (it's in ENV_ALLOWLIST, so it would
    // otherwise pass through unchanged) — the user's own value may legitimately
    // differ from HOME (e.g. a relocated CLI state dir) and must not be
    // clobbered.
    let user_dotnet_cli_home = parent_env
        .iter()
        .any(|(k, v)| k == "DOTNET_CLI_HOME" && !v.is_empty());
    if !user_dotnet_cli_home {
        cmd.env("DOTNET_CLI_HOME", home_dir);
    }

    // Point npm-family tools at a nonexistent user config inside the scratch dir so
    // the denied ~/.npmrc reads as ENOENT instead of EACCES/EPERM — yarn 1 aborts the
    // whole install on the latter (#180). See `npmrc_userconfig_override` for the cases
    // where this must not fire.
    if let Some(path) =
        super::env::npmrc_userconfig_override(&parent_env, scratch_dir, npmrc_allowed)
    {
        // Drop the other spellings first: npm and yarn lowercase every
        // `npm_config_*` key, so a leftover (necessarily empty) lowercase
        // variant would collide with the injection and could win the merge.
        for key in super::env::npmrc_userconfig_stale_variants(&parent_env) {
            cmd.env_remove(key);
        }
        cmd.env("NPM_CONFIG_USERCONFIG", path);
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
    // Token delivery is deliberately NOT gated on gh_guard. Two separate
    // reasons to put GH_TOKEN in the child env:
    //   - gh_guard.inject_token: the user asked for it.
    //   - token_is_sole_credential: cplt pre-extracted the token and dropped
    //     the Keychain grant on that basis, so this env var is the only
    //     credential the agent has. The gh wrapper's 0600 file does not cover
    //     this case — it only answers `gh auth token`, while the agent itself
    //     reads GH_TOKEN.
    // `deny_env` is applied by the callers *after* this and still wins — so when
    // it strips `GH_TOKEN` we skip the whole block: injecting would be undone,
    // and clearing the sibling vars would wrongly drop a `GITHUB_TOKEN` /
    // `COPILOT_GITHUB_TOKEN` the user set, which stays the agent's credential
    // when only `GH_TOKEN` is denied (see the startup warning in `main.rs`).
    if should_manage_token_env(gh_guard, token_is_sole_credential, deny_env) {
        // Clear every token var first so the one cplt resolved is the one the
        // agent sees. Without this an ambient `COPILOT_GITHUB_TOKEN` would
        // still shadow the injected `GH_TOKEN` for readers that prefer it —
        // and under `copilot_auth = "gh_only"`, whose whole promise is that the
        // credential comes from gh's store, an inherited env token would
        // quietly win.
        if resolved_gh_token.is_some_and(|t| !t.trim().is_empty()) {
            for var in GITHUB_TOKEN_VARS {
                cmd.env_remove(var);
            }
        }
        inject_gh_token_if_needed(cmd, resolved_gh_token);
    }

    if let Some(scratch) = scratch_dir {
        if gh_guard.enabled {
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
            if let Some(token) = resolved_gh_token.filter(|_| gh_guard.block_auth_token) {
                cache_gh_token_to_file(scratch, token);
            }
        }
        install_command_wrappers(cmd, scratch, project_dir, gh_guard, git_guard);
    }
}

/// `gh`, resolved from [`crate::git::TRUSTED_BIN_DIRS`], warning once when the
/// only `gh` on this machine is somewhere else.
///
/// Before the trusted-lookup change, `gh` came off `PATH`, so an installation in
/// `~/.local/bin` or a mise shim worked. It no longer does — correctly, since a
/// planted `gh` hands the agent both unsandboxed execution and a channel into
/// the next agent's environment. But the failure is invisible: no token is
/// injected, and the user sees Copilot's GitHub API calls fail with nothing
/// pointing at cplt. A `gh` that exists on `PATH` and is not trusted is the one
/// case worth a line on stderr.
///
/// Warned once per process: both token paths call this, and two identical
/// warnings at launch read like two different problems.
pub(crate) fn trusted_gh() -> Option<PathBuf> {
    if let Some(gh) = crate::git::trusted_binary("gh") {
        return Some(gh);
    }
    static WARNED: std::sync::Once = std::sync::Once::new();
    if let Some(untrusted) = which_binary("gh") {
        WARNED.call_once(|| {
            ui::warn(&format!(
                "gh is installed at {} — outside the directories cplt trusts for \
                 unsandboxed helpers ({}).\n  \
                 The GitHub token is NOT injected, so the agent's GitHub API calls \
                 will fail. cplt runs `gh auth token` as you, outside the sandbox, \
                 so it will not run a `gh` a previous session could have replaced.\n  \
                 Install gh into one of those directories (`brew install gh`, or your \
                 distro's package), or export GH_TOKEN yourself before launching.",
                untrusted.display(),
                crate::git::TRUSTED_BIN_DIRS.join(", ")
            ));
        });
    }
    None
}

fn extract_gh_token_from_cli() -> Option<String> {
    let gh = trusted_gh()?;
    let mut cmd = std::process::Command::new(&gh);
    // Pin the host: with several hosts logged in (github.com plus a GHES
    // instance) a bare `gh auth token` resolves against the *active* host, so
    // the agent could be handed an enterprise token for github.com work.
    cmd.args(["auth", "token", "--hostname", "github.com"]);
    for var in GITHUB_TOKEN_VARS {
        cmd.env_remove(var);
    }
    extract_gh_token_from_command(cmd, GH_AUTH_TOKEN_TIMEOUT)
}

fn extract_gh_token_from_command(
    mut cmd: std::process::Command,
    timeout: Duration,
) -> Option<String> {
    use std::io::Read as _;
    use std::process::Stdio;
    use std::thread;

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            ui::warn(&format!("gh auth token failed to start: {err}"));
            return None;
        }
    };

    let stdout_reader = child.stdout.take().map(|mut stdout| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
            buf
        })
    });
    let stderr_reader = child.stderr.take().map(|mut stderr| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr.read_to_end(&mut buf);
            buf
        })
    });

    let join_readers = |out: Option<thread::JoinHandle<Vec<u8>>>,
                        err: Option<thread::JoinHandle<Vec<u8>>>| {
        if let Some(h) = out {
            let _ = h.join();
        }
        if let Some(h) = err {
            let _ = h.join();
        }
    };

    let deadline = Instant::now() + timeout;
    let status = loop {
        if Instant::now() >= deadline {
            let _ = child.kill();
            if let Err(err) = child.wait() {
                ui::warn(&format!("gh auth token wait failed after timeout: {err}"));
            }
            join_readers(stdout_reader, stderr_reader);
            ui::warn(&format!(
                "gh auth token timed out after {}s",
                timeout.as_secs()
            ));
            return None;
        }

        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                join_readers(stdout_reader, stderr_reader);
                ui::warn(&format!("gh auth token wait failed: {err}"));
                return None;
            }
        }
    };

    let stdout = stdout_reader
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    let stderr = stderr_reader
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();

    if !status.success() {
        if stderr.is_empty() {
            ui::warn(&format!("gh auth token failed with status {status}"));
        } else {
            ui::warn(&format!(
                "gh auth token failed with status {status} (stderr omitted for safety)"
            ));
        }
        return None;
    }

    let token = String::from_utf8_lossy(&stdout).trim().to_string();
    if token.is_empty() { None } else { Some(token) }
}

fn resolve_gh_token_from_cli_if_needed(agent: Agent) -> Option<String> {
    if agent != Agent::Copilot {
        return None;
    }

    extract_gh_token_from_cli()
}

fn evaluate_exec_github_token_presence(
    has_effective_env_token: bool,
    needs_runtime_gh_token: bool,
    agent: Agent,
    injectable_token: Option<&str>,
) -> bool {
    has_effective_env_token
        || (needs_runtime_gh_token
            && agent == Agent::Copilot
            && injectable_token.is_some_and(|token| !token.trim().is_empty()))
}

fn should_resolve_gh_token_for_exec(
    has_effective_env_token: bool,
    needs_runtime_gh_token: bool,
    agent: Agent,
) -> bool {
    !has_effective_env_token && needs_runtime_gh_token && agent == Agent::Copilot
}

fn resolve_gh_token_for_exec_with_resolver<F>(
    has_effective_env_token: bool,
    needs_runtime_gh_token: bool,
    agent: Agent,
    resolver: F,
) -> Option<String>
where
    F: FnOnce(Agent) -> Option<String>,
{
    if !should_resolve_gh_token_for_exec(has_effective_env_token, needs_runtime_gh_token, agent) {
        return None;
    }

    let resolved_token = resolver(agent);

    if evaluate_exec_github_token_presence(
        has_effective_env_token,
        needs_runtime_gh_token,
        agent,
        resolved_token.as_deref(),
    ) {
        resolved_token
    } else {
        None
    }
}

/// Resolve a GitHub token for exec-time injection/caching.
///
/// Has side effects — it spawns `gh auth token`, which may read the login
/// store or the Keychain — so it must run in the unsandboxed parent, and only
/// when a token is actually needed (`should_resolve_gh_token_for_exec`). It is
/// a read: no launch happens here. cplt calls it *before* the confirmation
/// prompt on purpose, so the resolved token can narrow the Keychain grant
/// shown in the summary; the launch itself stays gated by that prompt.
pub fn resolve_gh_token_for_exec(
    has_effective_env_token: bool,
    needs_runtime_gh_token: bool,
    agent: Agent,
) -> Option<String> {
    resolve_gh_token_for_exec_with_resolver(
        has_effective_env_token,
        needs_runtime_gh_token,
        agent,
        resolve_gh_token_from_cli_if_needed,
    )
}

/// Inject GH_TOKEN into the command env if not already present.
///
/// The token is resolved once in `configure_command()` and passed here.
fn inject_gh_token_if_needed(cmd: &mut Command, token: Option<&str>) {
    if let Some(token) = token.filter(|token| !token.trim().is_empty()) {
        cmd.env("GH_TOKEN", token);
    }
}

/// Whether repo `deny.env` will strip `GH_TOKEN` — the sole injection target —
/// from the child. When true, `configure_command` must not inject it or clear
/// the sibling token vars: the injection would be undone, and a `GITHUB_TOKEN`
/// / `COPILOT_GITHUB_TOKEN` the user set stays the agent's credential.
fn deny_env_strips_gh_token(deny_env: &[String]) -> bool {
    deny_env.iter().any(|v| v == "GH_TOKEN")
}

/// Whether `configure_command` should take over the child's GitHub token env —
/// inject the resolved `GH_TOKEN` and normalize the sibling vars around it.
///
/// True when something wants a `GH_TOKEN` in the child (`gh_guard.inject_token`,
/// or the pre-extracted token being the sole credential) **and** repo
/// `deny.env` will not strip `GH_TOKEN` straight back out. In the denied case
/// the injection is futile and clearing `GITHUB_TOKEN` / `COPILOT_GITHUB_TOKEN`
/// would wrongly drop a credential the user set that a `GH_TOKEN`-only deny is
/// meant to leave alone.
fn should_manage_token_env(
    gh_guard: &crate::config::GhGuardPolicy,
    token_is_sole_credential: bool,
    deny_env: &[String],
) -> bool {
    let inject_wanted = (gh_guard.enabled && gh_guard.inject_token) || token_is_sole_credential;
    inject_wanted && !deny_env_strips_gh_token(deny_env)
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
fn cache_gh_token_to_file(scratch_dir: &Path, token: &str) {
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
        let real_git = if gh_guard.scope_check {
            // Trusted, not PATH: this git runs in the UNSANDBOXED parent, at
            // launch. A `git` the previous session planted in ~/.bun/bin (or any
            // other write+exec grant on PATH) would otherwise execute as the
            // user here, one session later.
            if let Some(real_git) = crate::git::trusted_git() {
                Some(real_git.to_path_buf())
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
        let repo_scope = if gh_guard.scope_check {
            if let Some(real_git) = real_git.as_deref() {
                match crate::gh_proxy::detect_current_repo(real_git, project_dir) {
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
                None
            }
        } else {
            None
        };
        let real_git_str = real_git
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned());
        let script = crate::gh_proxy::generate_wrapper_script(
            &real_gh.to_string_lossy(),
            repo_scope.as_deref(),
            real_git_str.as_deref(),
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
    // Trusted first, then PATH — the same call the gh wrapper above makes. The
    // wrapper's real_git runs INSIDE the sandbox, never in the parent, so a
    // planted git there gains the agent nothing it does not already have.
    // Requiring a trusted git removed the guard outright on mise/asdf/nix hosts.
    if git_guard.enabled
        && let Some(real_git) = crate::git::trusted_git()
            .map(std::path::Path::to_path_buf)
            .or_else(|| which_binary("git"))
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
    resolved_gh_token: Option<&str>,
    // The pre-extracted token is the agent's ONLY credential, because the
    // Keychain grant was dropped on the strength of having it. Forces the
    // `GH_TOKEN` env injection even when gh_guard is off — without it the
    // agent would launch with no way to authenticate at all.
    token_is_sole_credential: bool,
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
        deny_env,
        resolved_gh_token,
        token_is_sole_credential,
        gh_guard,
        git_guard,
        sandbox.npmrc_allowed,
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
    resolved_gh_token: Option<&str>,
    // The pre-extracted token is the agent's ONLY credential, because the
    // Keychain grant was dropped on the strength of having it. Forces the
    // `GH_TOKEN` env injection even when gh_guard is off — without it the
    // agent would launch with no way to authenticate at all.
    token_is_sole_credential: bool,
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
            resolved_gh_token,
            token_is_sole_credential,
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
                if wrapper.socket_mask_count > 0 {
                    // Security-relevant, not just a downgrade: below Landlock
                    // ABI v9 (kernel 7.1) nothing else restricts connect(2) to
                    // a pathname UNIX socket, so losing the masks re-opens the
                    // D-Bus / systemd / container-daemon escape entirely.
                    ui::warn(&format!(
                        "{} UNIX-socket mask(s) are NOT applied in this run (D-Bus, systemd, \
                         container runtimes). Below kernel 7.1 Landlock cannot gate connect(2) \
                         to a pathname socket, so those sockets are reachable from the agent.",
                        wrapper.socket_mask_count
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
        deny_env,
        resolved_gh_token,
        token_is_sole_credential,
        gh_guard,
        git_guard,
        sandbox.npmrc_allowed,
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
    resolved_gh_token: Option<&str>,
    // The pre-extracted token is the agent's ONLY credential, because the
    // Keychain grant was dropped on the strength of having it. Forces the
    // `GH_TOKEN` env injection even when gh_guard is off — without it the
    // agent would launch with no way to authenticate at all.
    token_is_sole_credential: bool,
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
        deny_env,
        resolved_gh_token,
        token_is_sole_credential,
        gh_guard,
        git_guard,
        sandbox.npmrc_allowed,
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

#[cfg(test)]
mod tests {
    use super::{
        deny_env_strips_gh_token, evaluate_exec_github_token_presence,
        extract_gh_token_from_command, inject_gh_token_if_needed,
        resolve_gh_token_for_exec_with_resolver, should_manage_token_env,
    };
    use crate::agent::Agent;
    use std::cell::Cell;
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    fn write_script(dir: &tempfile::TempDir, name: &str, body: &str) -> PathBuf {
        // Write to a staging name and rename into place. `Command::spawn` forks,
        // and on Linux a fork that happens while ANOTHER thread holds this file
        // open for writing inherits that writable fd, so the exec fails with
        // ETXTBSY ("Text file busy"). The tests in this module run in parallel
        // and several of them write scripts, so that race is reachable — it
        // failed CI here. A rename publishes a path that never had a writable
        // descriptor, which closes it.
        let staged = dir.path().join(format!("{name}.staged"));
        let script_path = dir.path().join(name);
        fs::write(&staged, body).expect("should write script");
        let mut permissions = fs::metadata(&staged)
            .expect("script metadata should exist")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&staged, permissions).expect("script should be executable");
        fs::rename(&staged, &script_path).expect("script should be published atomically");
        script_path
    }

    fn exec_tempdir(prefix: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("tempdir should be created")
    }

    #[test]
    fn effective_env_token_always_wins() {
        assert!(evaluate_exec_github_token_presence(
            true,
            false,
            Agent::Copilot,
            None
        ));
    }

    #[test]
    fn copilot_with_injection_and_token_has_token() {
        assert!(evaluate_exec_github_token_presence(
            false,
            true,
            Agent::Copilot,
            Some("ghp_abc123")
        ));
    }

    #[test]
    fn copilot_with_injection_but_no_token_has_no_token() {
        assert!(!evaluate_exec_github_token_presence(
            false,
            true,
            Agent::Copilot,
            None
        ));
    }

    #[test]
    fn non_copilot_does_not_get_injected_token() {
        assert!(!evaluate_exec_github_token_presence(
            false,
            true,
            Agent::OpenCode,
            Some("ghp_abc123")
        ));
    }

    #[test]
    fn disabled_injection_keeps_no_token_without_env_token() {
        assert!(!evaluate_exec_github_token_presence(
            false,
            false,
            Agent::Copilot,
            Some("ghp_abc123")
        ));
    }

    #[test]
    fn whitespace_token_is_not_treated_as_usable() {
        assert!(!evaluate_exec_github_token_presence(
            false,
            true,
            Agent::Copilot,
            Some("   ")
        ));
    }

    #[test]
    fn inject_skips_whitespace_token() {
        let mut cmd = Command::new("true");
        inject_gh_token_if_needed(&mut cmd, Some("   "));
        let has_token = cmd
            .get_envs()
            .any(|(key, value)| key == OsStr::new("GH_TOKEN") && value.is_some());
        assert!(!has_token, "whitespace token must not set GH_TOKEN");
    }

    #[test]
    fn inject_sets_non_empty_token() {
        let mut cmd = Command::new("true");
        inject_gh_token_if_needed(&mut cmd, Some("ghp_abc123"));
        let has_token = cmd.get_envs().any(|(key, value)| {
            key == OsStr::new("GH_TOKEN") && value == Some(OsStr::new("ghp_abc123"))
        });
        assert!(has_token, "non-empty token must set GH_TOKEN");
    }

    #[test]
    fn deny_env_strips_gh_token_detects_exact_match() {
        let deny = vec!["FOO".to_string(), "GH_TOKEN".to_string()];
        assert!(deny_env_strips_gh_token(&deny));
    }

    #[test]
    fn deny_env_strips_gh_token_ignores_other_vars() {
        let deny = vec!["GITHUB_TOKEN".to_string(), "FOO".to_string()];
        assert!(!deny_env_strips_gh_token(&deny));
    }

    fn gh_guard_injecting() -> crate::config::GhGuardPolicy {
        crate::config::GhGuardPolicy {
            enabled: true,
            inject_token: true,
            ..Default::default()
        }
    }

    #[test]
    fn should_manage_token_env_true_when_inject_token_and_gh_token_not_denied() {
        assert!(should_manage_token_env(&gh_guard_injecting(), false, &[]));
    }

    #[test]
    fn should_manage_token_env_true_when_sole_credential_and_gh_token_not_denied() {
        assert!(should_manage_token_env(
            &crate::config::GhGuardPolicy::default(),
            true,
            &["GITHUB_TOKEN".to_string()],
        ));
    }

    #[test]
    fn should_manage_token_env_false_when_gh_token_denied() {
        // Even with inject_token AND sole-credential, a GH_TOKEN deny means the
        // injection is doomed — leave the child's token vars untouched.
        let deny = vec!["GH_TOKEN".to_string()];
        assert!(!should_manage_token_env(&gh_guard_injecting(), true, &deny));
    }

    #[test]
    fn should_manage_token_env_false_when_nothing_wants_a_token() {
        assert!(!should_manage_token_env(
            &crate::config::GhGuardPolicy::default(),
            false,
            &[],
        ));
    }

    #[test]
    fn resolve_plan_does_not_call_resolver_when_injection_disabled() {
        let called = Cell::new(0);
        let resolved =
            resolve_gh_token_for_exec_with_resolver(false, false, Agent::Copilot, |_| {
                called.set(called.get() + 1);
                Some("ghp_abc123".to_string())
            });
        assert!(resolved.is_none());
        assert_eq!(called.get(), 0);
    }

    #[test]
    fn resolve_plan_does_not_call_resolver_when_env_token_exists() {
        let called = Cell::new(0);
        let resolved = resolve_gh_token_for_exec_with_resolver(true, true, Agent::Copilot, |_| {
            called.set(called.get() + 1);
            Some("ghp_abc123".to_string())
        });
        assert!(resolved.is_none());
        assert_eq!(called.get(), 0);
    }

    #[test]
    fn resolve_plan_non_copilot_skips_resolver() {
        let called = Cell::new(0);
        let resolved =
            resolve_gh_token_for_exec_with_resolver(false, true, Agent::OpenCode, |_| {
                called.set(called.get() + 1);
                Some("ghp_abc123".to_string())
            });
        assert!(resolved.is_none());
        assert_eq!(called.get(), 0);
    }

    #[test]
    fn resolve_plan_rejects_whitespace_token() {
        let called = Cell::new(0);
        let resolved = resolve_gh_token_for_exec_with_resolver(false, true, Agent::Copilot, |_| {
            called.set(called.get() + 1);
            Some("   ".to_string())
        });
        assert!(resolved.is_none());
        assert_eq!(called.get(), 1);
    }

    #[test]
    fn resolve_plan_accepts_non_empty_token_for_copilot() {
        let called = Cell::new(0);
        let resolved = resolve_gh_token_for_exec_with_resolver(false, true, Agent::Copilot, |_| {
            called.set(called.get() + 1);
            Some("ghp_abc123".to_string())
        });
        assert_eq!(resolved.as_deref(), Some("ghp_abc123"));
        assert_eq!(called.get(), 1);
    }

    #[test]
    fn resolve_plan_ignores_parent_env_token_when_effective_env_missing_token() {
        temp_env::with_var("GH_TOKEN", Some("ghp_env_token"), || {
            let called = Cell::new(0);
            let resolved =
                resolve_gh_token_for_exec_with_resolver(false, true, Agent::Copilot, |_| {
                    called.set(called.get() + 1);
                    Some("ghp_abc123".to_string())
                });
            assert_eq!(resolved.as_deref(), Some("ghp_abc123"));
            assert_eq!(called.get(), 1);
        });
    }

    #[test]
    fn extract_gh_token_command_returns_stdout_token_on_success() {
        let dir = exec_tempdir(".cplt-extract-gh-success-");
        let script = write_script(&dir, "gh-success.sh", "#!/bin/sh\necho 'ghp_abc123'\n");
        let token = extract_gh_token_from_command(Command::new(script), Duration::from_secs(3));
        assert_eq!(token.as_deref(), Some("ghp_abc123"));
    }

    #[test]
    fn extract_gh_token_command_returns_none_on_non_zero_exit() {
        let dir = exec_tempdir(".cplt-extract-gh-fail-");
        let script = write_script(&dir, "gh-fail.sh", "#!/bin/sh\necho 'boom' 1>&2\nexit 17\n");
        let token = extract_gh_token_from_command(Command::new(script), Duration::from_secs(3));
        assert!(token.is_none(), "non-zero exit must not return a token");
    }

    #[test]
    fn extract_gh_token_command_times_out_and_returns_none() {
        let dir = exec_tempdir(".cplt-extract-gh-timeout-");
        let script = write_script(&dir, "gh-timeout.sh", "#!/bin/sh\nsleep 1\necho late\n");
        let token = extract_gh_token_from_command(Command::new(script), Duration::from_millis(50));
        assert!(token.is_none(), "timeout must return no token");
    }

    #[test]
    fn extract_gh_token_command_timeout_kills_child_process() {
        let dir = exec_tempdir(".cplt-extract-gh-timeout-kill-");
        let script = write_script(
            &dir,
            "gh-timeout-kill.sh",
            // `exec sleep` keeps the recorded pid ($$) as the live process and
            // stays alive well past the timeout without burning a CPU core.
            "#!/bin/sh\necho $$ > \"$1\"\nexec sleep 30\n",
        );
        let pid_file = dir.path().join("child.pid");
        let mut cmd = Command::new(script);
        cmd.arg(&pid_file);

        let token = extract_gh_token_from_command(cmd, Duration::from_secs(2));
        assert!(token.is_none(), "timeout must return no token");

        for _ in 0..80 {
            if pid_file.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let pid = std::fs::read_to_string(&pid_file)
            .expect("child pid file should exist before timeout kill verification")
            .trim()
            .parse::<libc::pid_t>()
            .expect("child pid should parse");

        let rc = unsafe { libc::kill(pid, 0) };
        assert_eq!(rc, -1, "child process should not still be running");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "child process should be gone after timeout kill"
        );
    }

    #[test]
    fn extract_gh_token_command_captures_stdout_with_whitespace_trim() {
        let dir = exec_tempdir(".cplt-extract-gh-stdout-");
        let script = write_script(
            &dir,
            "gh-stdout.sh",
            "#!/bin/sh\nprintf '  ghp_trimmed  \\n'\n",
        );
        let token = extract_gh_token_from_command(Command::new(script), Duration::from_secs(3));
        assert_eq!(token.as_deref(), Some("ghp_trimmed"));
    }

    #[test]
    fn extract_gh_token_command_handles_stderr_without_token_leak() {
        let dir = exec_tempdir(".cplt-extract-gh-stderr-");
        let script = write_script(
            &dir,
            "gh-stderr.sh",
            "#!/bin/sh\necho 'auth failed' 1>&2\nexit 1\n",
        );
        let token = extract_gh_token_from_command(Command::new(script), Duration::from_secs(3));
        assert!(token.is_none(), "stderr failure must not return a token");
    }

    #[test]
    fn extract_gh_token_command_handles_quick_exit_without_double_wait() {
        let dir = exec_tempdir(".cplt-extract-gh-quick-");
        let script = write_script(&dir, "gh-quick.sh", "#!/bin/sh\necho ghp_fast\nexit 0\n");
        let token = extract_gh_token_from_command(Command::new(script), Duration::from_secs(3));
        assert_eq!(token.as_deref(), Some("ghp_fast"));
    }

    #[test]
    fn extract_gh_token_command_supports_repeated_invocation() {
        for _ in 0..3 {
            let mut cmd = Command::new("/bin/sh");
            cmd.arg("-c").arg("echo ghp_repeat");
            let token = extract_gh_token_from_command(cmd, Duration::from_secs(3));
            assert_eq!(token.as_deref(), Some("ghp_repeat"));
        }
    }
}
