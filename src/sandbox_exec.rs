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

/// Strip repo-config denied env vars, then forward the Keychain substitute.
///
/// Both steps live here so the ordering is local and cannot drift: the
/// substitute is applied *after* the deny sweep, and it can never name a denied
/// variable in the first place because `sandbox::keychain_substitute`
/// filters `deny_env` before returning one (#242).
///
/// The forwarded variable is deliberately NOT in `ENV_ALLOWLIST` — it reaches
/// the agent only as part of this trade, so with `sandbox.keychain_substitute`
/// off the child environment is exactly what it was before the key existed.
pub(super) fn apply_deny_env_and_credential(
    cmd: &mut Command,
    deny_env: &[String],
    substitute: Option<&crate::agent::KeychainSubstitute>,
) {
    for var in deny_env {
        cmd.env_remove(var);
    }
    if let Some((var, val)) = substitute.and_then(crate::agent::KeychainSubstitute::env_value)
        // `deny_env` wins here too, not only in `sandbox::keychain_substitute`.
        // That filter is what keeps a denied var from becoming a substitute in
        // the first place, so today this is unreachable — but this function
        // removes and then re-adds, and re-adding a var the repo denied is the
        // one mistake its shape invites. The check costs nothing and does not
        // depend on a caller two modules away staying correct.
        && !deny_env.iter().any(|d| d == var)
    {
        cmd.env(var, val);
    }
}

/// Configure environment, proxy, and common args on a sandboxed Command.
///
/// Both macOS (Seatbelt) and Linux (Landlock) paths call this to apply the
/// identical env filtering, proxy routing, and recursion guard.
#[allow(clippy::too_many_arguments)]
fn configure_command(
    cmd: &mut Command,
    copilot_args: &[String],
    project_dir: &Path,
    launch_dir: &Path,
    repo_dirs: &[PathBuf],
    home_dir: &Path,
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    scratch_dir: Option<&Path>,
    pnpm_shadow_dir: Option<&Path>,
    proxy_port: Option<u16>,
    allow_localhost: &[u16],
    allow_localhost_any: bool,
    agent: Agent,
    gh_guard: &crate::config::GhGuardPolicy,
    git_guard: &crate::config::GitGuardPolicy,
    // Startup notices are suppressed under `--quiet`, which `cplt exec`
    // defaults to: its stdout and stderr must stay clean for pipes.
    quiet: bool,
    npmrc_allowed: bool,
    playwright_socket_dir: Option<&Path>,
    playwright_runtime: bool,
    // Consulted before extracting a token: these names are stripped from the
    // child afterwards, so a parent value that is about to be denied must not
    // suppress the extraction. See `child_keeps_a_github_token`.
    deny_env: &[String],
    worktree_root: Option<&Path>,
    // The Keychain substitute this run resolved. A `GhToken` one already puts
    // gh's token in the child, so neither channel below runs `gh` again.
    keychain_substitute: Option<&crate::agent::KeychainSubstitute>,
) {
    for arg in copilot_args {
        cmd.arg(arg);
    }

    cmd.current_dir(launch_dir);

    // Build and apply environment
    let parent_env: Vec<(String, String)> = std::env::vars().collect();
    let sandbox_env = build_sandbox_env(
        &parent_env,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        scratch_dir,
        proxy_port,
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

    // The cplt PATH shim dir (#514) stays outside: in here the agent's own
    // name must resolve to the real binary, not to a shim that would start
    // cplt again. A PATH without the dir is left exactly as it was.
    if let Some(path) = std::env::var("PATH")
        .ok()
        .and_then(|p| crate::shim::path_without_shims(home_dir, &p))
    {
        cmd.env("PATH", path);
    }

    // Playwright's internal control server binds Unix sockets below this short,
    // random, policy-authorized per-session directory.
    // This runs after filtering so ambient values cannot displace the safe
    // default; only an explicit --pass-env requests a caller override.
    if let Some(path) =
        super::env::playwright_sockets_dir_override(extra_pass_env, playwright_socket_dir)
    {
        cmd.env("PWTEST_SOCKETS_DIR", path);
    }

    // Playwright MCP re-enables Chromium's own sandbox, which cannot start
    // inside cplt's. Disabling it here keeps the fix inside the boundary that
    // needs it, instead of putting a cplt-only flag in the server configuration
    // every editor and CLI shares.
    if super::env::playwright_mcp_sandbox_disabled(extra_pass_env, playwright_runtime) {
        cmd.env("PLAYWRIGHT_MCP_SANDBOX", "false");
    }

    // Copilot CLI 1.0.83 gave itself a command sandbox that cannot start inside
    // cplt's: on Linux it builds a network namespace, and cplt's seccomp filter
    // denies `unshare`/`setns`. Copilot's own opt-out tells it the host has no
    // sandbox support, so it stands down for the session, says so, and leaves
    // the user's saved setting alone. See `copilot_sandbox_support_overridden`.
    if super::env::copilot_sandbox_support_overridden(extra_pass_env, agent) {
        cmd.env("COPILOT_CLI_SANDBOX_SUPPORT_OVERRIDE", "unsupported");
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

    // #531: set after filtering, so an inherited or passed-through value can
    // never point the agent at a directory the policy does not grant. Removed
    // when the key is off for the same reason.
    match worktree_root {
        Some(root) => cmd.env(crate::worktrees::ENV, root),
        None => cmd.env_remove(crate::worktrees::ENV),
    };

    // Point the agent at its own brief, so it does not have to know the
    // `$TMPDIR/CPLT_BRIEF.md` convention to find it. Gated on the files
    // actually existing: the brief is opt-in (`sandbox.brief`), and a variable
    // naming a file that is not there is worse than no variable — it is the one
    // thing the AGENTS.md block currently has to hedge about in prose.
    if let Some(scratch) = scratch_dir {
        for (var, name) in [
            ("CPLT_BRIEF", crate::brief::BRIEF_MD),
            ("CPLT_BRIEF_JSON", crate::brief::BRIEF_JSON),
        ] {
            let path = scratch.join(name);
            if path.is_file() {
                cmd.env(var, &path);
            }
        }
    }

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
                inject_gh_token_if_needed(cmd, agent, deny_env, keychain_substitute);
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
                cache_gh_token_to_file(scratch, agent, deny_env, keychain_substitute);
            }
        }
        install_command_wrappers(
            cmd,
            scratch,
            project_dir,
            repo_dirs,
            gh_guard,
            git_guard,
            quiet,
            pnpm_shadow_dir,
        );
    } else if let Some(shadow) = pnpm_shadow_dir {
        prepend_path(cmd, &[shadow]);
    }
}

/// Inject GH_TOKEN into the command env if not already present.
///
/// Runs `gh auth token` outside the sandbox to extract the token from
/// `~/.config/gh/hosts.yml`, then injects it as GH_TOKEN. This allows
/// the gh proxy to safely block `gh auth token` inside the sandbox
/// while still giving the agent API access.
///
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
fn trusted_gh() -> Option<PathBuf> {
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

/// Only injects for agents that need GitHub access (Copilot).
/// The env vars that carry a GitHub token into the agent.
///
/// Mirrors `sandbox_env::COPILOT_ONLY_VARS`; kept here because this module both
/// strips them from the `gh` subprocess and consults them to decide whether
/// extraction is needed at all.
pub(super) const GH_TOKEN_VARS: &[&str] = &["GH_TOKEN", "GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN"];

/// The GitHub token `gh` holds, or `None` when there is nothing to hand over.
///
/// Trusted path, not PATH: this runs in the unsandboxed parent at launch and
/// its stdout is treated as a GitHub token, so a planted `gh` would get both
/// code execution as the user and a free channel into the agent's environment.
///
/// `--hostname github.com` is not optional. `gh auth token` without it resolves
/// against the *active* host, which `GH_HOST` can steer and which is a GHES
/// instance on a machine logged into one — so the agent would be handed a token
/// for the wrong host. The token vars are stripped from the subprocess so `gh`
/// answers from its own credential store rather than echoing back an ambient
/// value.
pub(super) fn extract_gh_token() -> Option<String> {
    gh_auth_token(&trusted_gh()?, GH_AUTH_TOKEN_TIMEOUT)
}

/// Ceiling on the `gh auth token` handover. A local credential store answers in
/// milliseconds; this only bounds a `gh` that never answers at all.
///
/// Unbounded, this was the single blocking wait between the startup banner and
/// exec: `configure_command` reaches it on every Copilot launch (the gh guard's
/// `block_auth_token` defaults on), so a wedged `gh` hung cplt itself with the
/// banner as the last thing on screen and nothing pointing at the cause.
const GH_AUTH_TOKEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long to wait for the drained stdout after `gh` has already exited.
///
/// Everything `gh` wrote is in the pipe by then, so the reader reaches EOF at
/// once — unless a descendant `gh` left behind still holds the write end, which
/// is the one case this bounds.
const GH_AUTH_TOKEN_EOF_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// Run `gh auth token` and return what it printed, or `None` on any failure —
/// a non-zero exit, unreadable output, or a `gh` that outlives `timeout`.
///
/// Degrading is the whole point: no token means the agent's GitHub API calls
/// fail, which is recoverable and visible. A hang means cplt never starts.
///
/// Bounded in the same shape as [`crate::audit`]'s git probe: stdout is drained
/// on a helper thread so `gh` can never block writing into a full pipe while the
/// main thread polls, and on timeout the child is killed and reaped.
///
/// The reader is never joined, on either path. A descendant that outlives `gh`
/// keeps the write end of the pipe open, so the reader sees no EOF even once
/// `try_wait` reports the child gone — joining there would reinstate exactly the
/// hang this exists to remove. It hands its buffer over a channel instead, and
/// both the wait for the child and the wait for that buffer are bounded.
///
/// `stdin` is closed explicitly. `Command::output` gave the child a null stdin
/// for free; a spawned child inherits the terminal instead, and a `gh` that
/// decides to prompt would then block on a read nobody answers.
#[allow(clippy::disallowed_methods)] // gh resolved by trusted_gh() at the call site
fn gh_auth_token(gh: &Path, timeout: std::time::Duration) -> Option<String> {
    use std::io::Read as _;
    use std::time::{Duration, Instant};

    let mut cmd = std::process::Command::new(gh);
    cmd.args(["auth", "token", "--hostname", "github.com"]);
    for var in GH_TOKEN_VARS {
        cmd.env_remove(var);
    }
    let mut child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    let mut stdout = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };

    // The child is gone, so its own write end is closed. A descendant it left
    // behind may still hold the other one, which is why this wait is bounded
    // too: an unbounded one here is the same hang in a different place.
    let buf = rx.recv_timeout(GH_AUTH_TOKEN_EOF_GRACE).ok()?;
    if !status.success() {
        return None;
    }
    let token = String::from_utf8_lossy(&buf).trim().to_string();
    (!token.is_empty()).then_some(token)
}

/// Whether the child will already have a usable GitHub token in its own
/// environment, making extraction unnecessary.
///
/// `deny_env` is consulted because the caller strips those names from the child
/// AFTER this runs. Without it a repo `deny.env = ["GH_TOKEN"]` produced a
/// child with no token at all: the parent's value suppressed the extraction,
/// and then the deny removed the variable it was suppressed in favour of.
fn child_keeps_a_github_token(deny_env: &[String]) -> bool {
    GH_TOKEN_VARS.iter().any(|var| {
        !deny_env.iter().any(|d| d == var) && std::env::var(var).is_ok_and(|v| !v.trim().is_empty())
    })
}

/// Whether the Keychain trade already hands gh's token to the child (#277).
/// Then the inject and cache channels would only run `gh auth token` again.
fn substitute_carries_gh_token(substitute: Option<&crate::agent::KeychainSubstitute>) -> bool {
    matches!(
        substitute,
        Some(crate::agent::KeychainSubstitute::GhToken { .. })
    )
}

fn inject_gh_token_if_needed(
    cmd: &mut Command,
    agent: Agent,
    deny_env: &[String],
    substitute: Option<&crate::agent::KeychainSubstitute>,
) {
    // Only inject for Copilot — other agents have their own auth.
    if agent != Agent::Copilot
        || child_keeps_a_github_token(deny_env)
        || substitute_carries_gh_token(substitute)
    {
        return;
    }
    // Into the first name the deny list does not strip. Injecting into
    // GH_TOKEN unconditionally would hand the token to a variable
    // `apply_deny_env_and_credential` removes moments later, so a repo denying
    // GH_TOKEN alone would leave the agent tokenless even though Copilot reads
    // GITHUB_TOKEN too. All three names are denied means no channel is left, so
    // there is nothing to inject into.
    let Some(target) = GH_TOKEN_VARS
        .iter()
        .find(|var| !deny_env.iter().any(|d| d == *var))
    else {
        return;
    };
    if let Some(token) = extract_gh_token() {
        cmd.env(target, &token);
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
/// Whether the resolved token should be written to the scratch cache.
///
/// Split out because the two channels want opposite things from `deny_env`.
/// For the ENV channel a denied name means "extract, and inject into one that
/// survives" — the agent should still get a credential. For the CACHE channel a
/// denied name means silence: `deny.env` on the token vars is a repo saying the
/// agent gets no GitHub credential, and serving one through `gh auth token`
/// inside the sandbox would honour the letter of that and not the intent
/// (#225).
///
/// So: cache only for Copilot, only when `GH_TOKEN` itself is not denied, and
/// only when the child would not already have one of its own.
fn should_cache_token(
    agent: Agent,
    deny_env: &[String],
    substitute: Option<&crate::agent::KeychainSubstitute>,
) -> bool {
    if agent != Agent::Copilot || substitute_carries_gh_token(substitute) {
        return false;
    }
    // GH_TOKEN specifically, not any of the three. #225 asks for the cache to
    // follow the injection target: denying GH_TOKEN is the repo saying "no
    // GitHub credential", while denying only COPILOT_GITHUB_TOKEN is a narrower
    // statement that should not cost the agent the cache channel as well.
    let target_denied = deny_env.iter().any(|d| d == "GH_TOKEN");
    !target_denied && !child_keeps_a_github_token(deny_env)
}

fn cache_gh_token_to_file(
    scratch_dir: &Path,
    agent: Agent,
    deny_env: &[String],
    substitute: Option<&crate::agent::KeychainSubstitute>,
) {
    if !should_cache_token(agent, deny_env, substitute) {
        return;
    }
    let Some(token) = extract_gh_token() else {
        return;
    };

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
#[allow(clippy::too_many_arguments)]
fn install_command_wrappers(
    cmd: &mut Command,
    scratch_dir: &Path,
    project_dir: &Path,
    repo_dirs: &[PathBuf],
    gh_guard: &crate::config::GhGuardPolicy,
    git_guard: &crate::config::GitGuardPolicy,
    quiet: bool,
    pnpm_shadow_dir: Option<&Path>,
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

    // The git both wrappers bake in and run INSIDE the sandbox.
    //
    // PATH first, `trusted_git()` only as a fallback — the reverse of the
    // parent-side rule, and deliberately so. `trusted_git()` scans
    // `TRUSTED_BIN_DIRS` in a fixed order with `/usr/bin` first, which on macOS
    // is `xcrun`'s shim, not git. The shim dlopens `libxcrun.dylib` out of
    // whatever `xcode-select` points at; where that is a full `Xcode.app` rather
    // than the Command Line Tools, the sandbox does not grant `/Applications`
    // and *every* git through the wrapper dies with
    // "unable to load libxcrun ... (file system sandbox blocked open())" —
    // `git status`, `git log`, `git --version`, not just `git push`.
    //
    // Preferring PATH makes the guard run the same git the agent would have run
    // without it. That is the invariant that was broken: a guard decides
    // *whether* a command runs, and must not silently change *which* binary it
    // is. The same substitution hits every machine whose PATH git comes from
    // Homebrew, mise, asdf, nix-profile or snap; the Xcode shim is just the case
    // that fails loudly instead of quietly running a different git.
    //
    // Safe because this path is only ever executed inside the sandbox, by the
    // agent's own shell. A git planted on the agent's PATH gains it nothing: it
    // can invoke any git by absolute path and skip the wrapper entirely, so the
    // guard is a policy on intent, not a boundary. Parent-side git — the audit,
    // repo-config trust, the gh guard's repo scope and allow_push URL pinning —
    // stays on `trusted_git()` below, where a planted binary WOULD run
    // unsandboxed as the user.
    let sandbox_git =
        which_binary("git").or_else(|| crate::git::trusted_git().map(std::path::Path::to_path_buf));

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
        // The gh scope is a SET: the launch repository plus every `--repo-dir`
        // root whose origin is on GitHub. Each member's `owner/name` is captured
        // here, parent-side with the trusted git, and baked into the wrapper —
        // the gate never re-derives it from inside the sandbox.
        let mut repo_scope: Vec<String> = Vec::new();
        if gh_guard.scope_check
            && let Some(real_git) = real_git.as_deref()
        {
            match crate::gh_proxy::detect_current_repo(real_git, project_dir) {
                Ok(repo) => repo_scope.push(repo),
                Err(reason) => {
                    ui::warn(&format!(
                        "gh guard could not capture repository scope: {reason}. \
                         Scope-checked commands will be blocked."
                    ));
                }
            }
            for dir in repo_dirs {
                let root = crate::gh_proxy::capture_named_root(real_git, dir);
                match root.repo {
                    // A named root can be a second checkout of a repository
                    // already in the set; the set dedups. Case-insensitively:
                    // `Navikt/LAUNCH.git` and `navikt/launch` are one repository,
                    // and letting both in would turn a single-repository session
                    // into an ambiguous multi-member one that pins nothing.
                    Some(repo)
                        if !repo_scope
                            .iter()
                            .any(|member| crate::gh_proxy::repos_match(member, &repo)) =>
                    {
                        repo_scope.push(repo);
                    }
                    Some(_) => {}
                    None => {
                        if !quiet {
                            // "--repo-dir" would be a lie for a root that came
                            // from `sandbox.repo_dirs` in the local config —
                            // the source is not carried this far — so name the
                            // root, which is true either way. The reason comes
                            // from the capture itself, so "no origin at all"
                            // and "an origin cplt cannot parse as a GitHub
                            // repository" do not read the same.
                            let reason = crate::gh_proxy::detect_current_repo(real_git, dir)
                                .err()
                                .unwrap_or_else(|| "no GitHub origin".to_string());
                            ui::warn(&format!(
                                "named repository {} is not in the gh scope: {reason}. \
                                 gh commands targeting it are refused.",
                                dir.display()
                            ));
                        }
                    }
                }
            }
        }
        // `real_git` above is the parent-side probe and stays trusted. What the
        // wrapper carries is the sandbox git: `gh-gate` re-runs it inside the
        // sandbox to resolve scope, so a git that cannot start there turns every
        // scope-checked `gh` command into a refusal.
        let real_git_str = if real_git.is_some() {
            sandbox_git
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
        } else {
            None
        };
        let script = crate::gh_proxy::generate_wrapper_script(
            &real_gh.to_string_lossy(),
            &repo_scope,
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

    // Install git guard wrapper (only if git_guard enabled). It runs
    // `sandbox_git` — see the reasoning where that is resolved above.
    if git_guard.enabled
        && let Some(real_git) = sandbox_git.clone()
    {
        // Pin each allow_push rule's remote name to the URL that name has in
        // the launch repository, so the rule identifies a repository and not
        // just a name — without it a rule for this repo's `origin` also
        // authorizes a push to an unrelated repo's `origin` (#215). Baked into
        // the wrapper, the same shape as the gh guard's repo scope.
        //
        // Pinning requires `trusted_git`, not the PATH git the wrapper itself
        // uses: this call runs in the UNSANDBOXED parent, where a planted git
        // would execute as the user. With no trusted git the rules stay
        // unpinned, and an unpinned rule authorizes nothing, so the operator is
        // warned rather than left with a rule that silently does not apply.
        let mut git_guard = git_guard.clone();
        // Capture the launch repository's facts — today the default branch of
        // each remote — with the TRUSTED git, in the unsandboxed parent, and
        // bake them into the wrapper. The guard used to ask
        // `git symbolic-ref refs/remotes/<remote>/HEAD` at gate time inside the
        // sandbox; that ref file is agent-writable, so the agent could rewrite
        // the guard's yardstick and push to the real default branch
        // (GHSA-cm6f-3wjh-x9qx). Same treatment as the gh guard's repo scope.
        // The launch repository's facts, plus one member per named root: a push
        // inside a named root has to be judged by THAT repository's default
        // branch, and before this it had no baked answer at all, so every push
        // there failed closed with wording about the launch repository.
        let mut repo_facts = crate::git::trusted_git()
            .map(|git| crate::gh_proxy::capture_repo_facts(git, project_dir))
            .unwrap_or_default();
        if let Some(git) = crate::git::trusted_git() {
            repo_facts.named = repo_dirs
                .iter()
                .map(|dir| crate::gh_proxy::capture_repo_facts(git, dir))
                .collect();
        }
        // Two conditions narrow this to the case the operator can act on.
        // `!quiet`, because `cplt exec` defaults to quiet and its stderr must
        // stay clean for pipes (`e2e_exec_no_output_contamination`) — the same
        // rule every other launch notice follows. And `has_remotes`, because a
        // repo with no remote has nowhere to push: nothing is being refused
        // that could have succeeded, and `git remote set-head origin -a` is
        // advice for a remote that does not exist. What is left — remotes
        // configured, no `refs/remotes/*/HEAD` recorded (a `git init` + `git
        // remote add`, or a clone whose set-head never ran) — is exactly where
        // every push really is refused.
        if !quiet
            && git_guard.protect_default_branch_only
            && repo_facts.default_branches.is_empty()
            && repo_facts
                .named
                .iter()
                .all(|n| n.default_branches.is_empty())
            && crate::git::trusted_git()
                .is_some_and(|git| crate::gh_proxy::has_remotes(git, project_dir))
        {
            ui::warn(
                "git guard: no remote's default branch could be captured at launch, so \
                 protect_default_branch_only cannot tell a feature branch from the protected \
                 one and every push is refused. Run `git remote set-head origin -a` in the \
                 project repository and start a new session.",
            );
        }
        // An allow_push rule also requires the push to run in a repository the
        // session has in scope (#424). That needs the scope to have been
        // captured; when it could not be, the rule falls back to URL identity
        // alone. Say so rather than leaving the operator with a rule that is
        // quieter than they think.
        if !git_guard.allow_push.is_empty()
            && repo_facts.git_common_dir.is_empty()
            && repo_facts.named.iter().all(|n| n.git_common_dir.is_empty())
            && !quiet
        {
            ui::warn(
                "git guard: the repositories in scope could not be identified at launch, so \
                 allow_push rules authorize by destination URL alone. A push from a clone \
                 made inside the project to a URL a rule pins is then authorized too.",
            );
        }
        if !git_guard.allow_push.is_empty() {
            if let Some(trusted) = crate::git::trusted_git() {
                // Every repository in scope, not only the launch one: a rule
                // naming `origin` is about the origin of a repository in THIS
                // session, and a named root's origin is one of them (#424).
                let scope: Vec<&Path> = std::iter::once(project_dir)
                    .chain(repo_dirs.iter().map(PathBuf::as_path))
                    .collect();
                git_guard.allow_push =
                    crate::gh_proxy::resolve_push_rule_urls(trusted, &scope, &git_guard.allow_push);
                for rule in &git_guard.allow_push {
                    if rule.url.is_none()
                        && let Some(name) = rule.remote.as_deref()
                    {
                        ui::warn(&format!(
                            "git guard: allow_push remote {name:?} does not exist in any \
                             repository in scope, so the rule cannot be pinned to a repository \
                             and authorizes no push. Add the remote before launch \
                             (`git remote add {name} <url>`), or drop the rule."
                        ));
                    }
                }
            } else {
                ui::warn(
                    "git guard could not find a trusted Git to pin allow_push remotes to \
                     their URLs. Rules naming a remote authorize no push until they can be \
                     pinned — a bare remote name would also match a same-named remote in \
                     another repository.",
                );
            }
        }
        let script = crate::gh_proxy::generate_git_wrapper_script(
            &real_git.to_string_lossy(),
            &cplt_str,
            &git_guard,
            &repo_facts,
        );
        let wrapper_path = bin_dir.join("git");
        if std::fs::write(&wrapper_path, script).is_ok() {
            let _ = std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755));
            installed_any = true;
        }
    }

    // Prepend {scratch}/bin to PATH so wrappers shadow the real binaries.
    let mut prefixes = Vec::new();
    if installed_any {
        prefixes.push(bin_dir.as_path());
    }
    if let Some(shadow) = pnpm_shadow_dir {
        prefixes.push(shadow);
    }
    if !prefixes.is_empty() {
        prepend_path(cmd, &prefixes);
    }
}

fn prepend_path(cmd: &mut Command, prefixes: &[&Path]) {
    let mut paths: Vec<PathBuf> = prefixes.iter().map(|path| path.to_path_buf()).collect();
    // The PATH already set on `cmd` wins over ours, so the shim dir that
    // `configure_command` took out does not come back here.
    let set = cmd
        .get_envs()
        .find(|(k, _)| *k == "PATH")
        .and_then(|(_, v)| v.map(std::ffi::OsStr::to_os_string));
    if let Some(current_path) = set.or_else(|| std::env::var_os("PATH")) {
        paths.extend(std::env::split_paths(&current_path));
    }
    if let Ok(path) = std::env::join_paths(paths) {
        cmd.env("PATH", path);
    }
}

/// Find an executable in PATH by name.
///
/// Executability matters: `which` and `execvp` both skip a file the caller may
/// not execute, so accepting one here would report a stub as the tool's
/// location (`cplt doctor`) or hand a caller a path that can only ever fail
/// with `EACCES`. Deliberately the same predicate as the trusted-directory
/// lookup — [`crate::git::is_executable_file`], an `X_OK` check, not a
/// mode-bit test — so the two resolvers cannot disagree about what counts.
pub(crate) fn which_binary(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(|p| crate::git::is_executable_file(p))
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

/// Why a sandboxed process would not start.
///
/// `E2BIG` gets its own sentence on macOS: the SBPL profile travels in the
/// argument list (`sandbox-exec -p`), so an unusually large grant set is the
/// one configuration that can exceed `kern.argmax` — and `preflight` is
/// skippable with `--no-validate`, which makes this the only place some users
/// will see the reason.
fn spawn_error_message(e: &std::io::Error) -> String {
    #[cfg(target_os = "macos")]
    if e.raw_os_error() == Some(libc::E2BIG) {
        return format!(
            "Failed to start sandboxed process: {e}. The SBPL profile is passed to \
             sandbox-exec as an argument, and it must fit in kern.argmax (1 MiB) \
             alongside the environment. Reduce the number of allow/deny grants."
        );
    }
    format!("Failed to start sandboxed process: {e}")
}

/// Make every descriptor above stderr close on `execve`, keeping only `keep`.
///
/// # Why
///
/// The sandbox gates what the agent can *open*. It says nothing about what is
/// already open when the agent starts. Whatever launched cplt — an IDE, a
/// wrapper script, a service manager — may be holding descriptors on files the
/// policy denies, or on sockets the policy would never allow, and a non-CLOEXEC
/// descriptor is inherited straight through `sandbox-exec` (and through bwrap)
/// into the agent. `cat <&3` then reads a denied `.env` with no `open(2)` for
/// the kernel to refuse. Path rules and socket rules both walk past it.
///
/// # Why CLOEXEC rather than `close(2)`
///
/// This runs as a `pre_exec` hook, and at that point `std` is still holding a
/// CLOEXEC pipe it uses to report `execve` failure back to the parent. Closing
/// descriptors blindly closes that pipe too, and the parent then reads EOF and
/// concludes the exec succeeded. Setting `FD_CLOEXEC` leaves it working: it is
/// already CLOEXEC, so nothing changes for it, and every other descriptor is
/// gone the moment `execve` succeeds.
///
/// `keep` is cleared afterwards, so a descriptor that is *meant* to reach the
/// child survives — the Linux bubblewrap path passes two such pipes deliberately.
///
/// Register this before any other `pre_exec` hook. Descriptors a later hook
/// opens for itself (Landlock's ruleset, for one) must not be sealed.
fn seal_inherited_fds(cmd: &mut Command, keep: Vec<std::os::unix::io::RawFd>) {
    use std::os::unix::process::CommandExt as _;

    // Read in the parent so the hook itself is nothing but `fcntl`.
    let max = fd_sweep_ceiling();

    // The audit's settle probe is the one descriptor that is *meant* to reach
    // the session: cplt created the pipe, holds the only read end, and detects
    // stragglers by waiting for every inherited copy of this write end to close
    // (GHSA-c47q-c3c8-7wrf). Exempting it here rather than at the three call
    // sites means a fourth spawn path cannot silently re-seal it — and the
    // failure is silent, since a sealed probe reports every session settled.
    let mut keep = keep;
    let probe = crate::audit::SETTLE_PROBE_FD.load(std::sync::atomic::Ordering::Relaxed);
    if probe >= 3 {
        keep.push(probe);
    }

    // SAFETY: the closure runs between fork and exec. `seal_fds` makes only
    // `fcntl` calls — no allocation, no locks, async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            seal_fds(max, &keep);
            Ok(())
        });
    }
}

/// One past the highest descriptor [`seal_fds`] has to touch when it cannot use
/// `close_range`.
///
/// `getdtablesize()` is the soft `RLIMIT_NOFILE` verbatim, and on Linux that is
/// whatever started cplt says it is: `LimitNOFILE=infinity` makes it
/// 1073741816, and a sweep that long is minutes of `fcntl` between fork and
/// exec with nothing on screen (#525). `/proc/self/fd` is the kernel's own
/// answer to what is open, and nothing above its highest entry can need
/// sealing.
///
/// Darwin needs no such help: `getdtablesize()` there is clamped to
/// `kern.maxfilesperproc` (61440 by default), so it cannot run away.
///
/// This is a parent-side snapshot, so a descriptor opened between here and the
/// fork is outside it. That is sound for what this bounds: the descriptors the
/// seal exists to catch are the caller's, which predate the process, and
/// everything cplt opens for itself is `O_CLOEXEC` already — the deliberate
/// exceptions, the settle probe and the bwrap pipes, exist before this runs and
/// travel in `keep`. The `close_range` path in [`seal_fds`] has no window at
/// all, and it is the one that runs on any kernel from 5.11.
fn fd_sweep_ceiling() -> libc::c_int {
    // SAFETY: getdtablesize() takes no arguments, touches no memory, and has no
    // failure mode.
    let table = unsafe { libc::getdtablesize() };

    #[cfg(target_os = "linux")]
    if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
        let highest = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name();
                name.to_str()?.parse::<libc::c_int>().ok()
            })
            .max();
        if let Some(highest) = highest {
            return highest.saturating_add(1).min(table);
        }
    }

    table
}

/// Set `FD_CLOEXEC` on every descriptor from 3 up, in one syscall.
///
/// `false` when the kernel will not do it — `ENOSYS` before 5.9, `EINVAL` for
/// the flag before 5.11 — which leaves the caller to sweep instead. Any failure
/// is that same answer, so no errno read is needed to tell them apart.
///
/// The raw syscall rather than glibc's `close_range()` wrapper: the wrapper is
/// glibc 2.34+, and linking it would put a versioned symbol in the binary that
/// makes it refuse to start on anything older. Release binaries are built on
/// Ubuntu 22.04 and run wherever people put them. A syscall number asks nothing
/// of libc at runtime.
///
/// Called between fork and exec: one `syscall(2)`, no allocation, no locks.
#[cfg(target_os = "linux")]
fn close_range_cloexec() -> bool {
    // `c_long` arguments, not `c_uint`: `syscall` is variadic and reads each
    // argument as a `long`, and an `unsigned int` is not promoted to one. The
    // kernel takes three `unsigned int` and ignores the upper half of each.
    // SAFETY: a syscall with three scalar arguments; it touches no memory here.
    unsafe {
        libc::syscall(
            libc::SYS_close_range,
            libc::c_long::from(3_u32),
            libc::c_long::from(libc::c_uint::MAX),
            libc::c_long::from(libc::CLOSE_RANGE_CLOEXEC),
        ) == 0
    }
}

/// No `close_range` outside Linux; [`seal_fds`] sweeps.
#[cfg(not(target_os = "linux"))]
fn close_range_cloexec() -> bool {
    false
}

/// The seal itself, as it runs between fork and exec.
///
/// Named rather than inlined into the hook so a test can call the code that
/// actually ships and measure what it costs.
///
/// `keep` is cleared last, and that is what keeps the settle probe alive:
/// `CLOSE_RANGE_CLOEXEC` cannot skip a descriptor in the middle of its range,
/// so the probe is sealed with everything else and then un-sealed by name —
/// the same order, and the same exemption, as the sweep it replaces.
///
/// Async-signal-safe: one `syscall` and some `fcntl`, no allocation, no locks.
fn seal_fds(max: libc::c_int, keep: &[std::os::unix::io::RawFd]) {
    // stdin/stdout/stderr are already dup2'd into place by std before pre_exec
    // hooks run, so 0..=2 are ours and must stay.
    if !close_range_cloexec() {
        for fd in 3..max {
            // EBADF on an unused descriptor is expected and ignored.
            // SAFETY: `fcntl` with a scalar argument; an invalid fd returns EBADF.
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
    }
    for &fd in keep {
        // SAFETY: as above.
        unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
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
            ui::error(&spawn_error_message(&e));
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

/// The Seatbelt driver. Absolute on purpose: a bare program name is resolved
/// from the parent's PATH at spawn time, and the sandbox grants the agent
/// write+exec on directories that sit on it (see `TRUSTED_BIN_DIRS` in git.rs).
#[cfg(target_os = "macos")]
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Verify the SBPL profile works by running `/usr/bin/true` inside sandbox-exec.
#[cfg(target_os = "macos")]
#[allow(clippy::disallowed_methods)] // SANDBOX_EXEC is the fixed /usr/bin/sandbox-exec
pub fn preflight(sandbox: &super::PreparedSandbox) -> Result<(), String> {
    // Absolute: `sandbox-exec` only ever lives in /usr/bin (SIP-protected), and
    // resolving it by name would go through the parent's PATH, which contains
    // directories the sandbox itself grants the agent write+exec on.
    let output = Command::new(SANDBOX_EXEC)
        .arg("-p")
        .arg(&sandbox.profile_text)
        .arg("/usr/bin/true")
        .output()
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::E2BIG) {
                format!(
                    "Sandbox profile is too large to pass to sandbox-exec ({} bytes; the \
                     argument list must fit in kern.argmax, 1 MiB, alongside the environment). \
                     Reduce the number of allow/deny grants.",
                    sandbox.profile_text.len()
                )
            } else {
                format!("Failed to run sandbox-exec: {e}")
            }
        });

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
/// The profile is passed to `sandbox-exec -p` as an argument, never as a
/// pathname. A temp file would be a cross-session policy-replacement race: the
/// profile itself grants every sandbox write throughout `/private/tmp` and
/// `/private/var/folders`, so another sandboxed session could swap the file
/// between our write and the kernel's read and choose the policy we enforce.
/// `-p` leaves nothing to swap. Oversized profiles fail loudly with `E2BIG`
/// (`preflight` explains it); the kernel never sees a truncated profile.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::disallowed_methods)] // SANDBOX_EXEC is the fixed /usr/bin/sandbox-exec
pub fn exec(
    sandbox: &super::PreparedSandbox,
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
    let mut cmd = Command::new(SANDBOX_EXEC);
    cmd.arg("-p").arg(&sandbox.profile_text).arg(copilot_bin);

    configure_command(
        &mut cmd,
        copilot_args,
        &sandbox.project_dir,
        launch_dir,
        repo_dirs,
        &sandbox.home_dir,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        sandbox.scratch_dir.as_deref(),
        sandbox.pnpm_shadow_dir.as_deref(),
        sandbox.proxy_port,
        &sandbox.allow_localhost,
        sandbox.allow_localhost_any,
        sandbox.agent,
        gh_guard,
        git_guard,
        quiet,
        sandbox.npmrc_allowed,
        sandbox.playwright_socket_dir.as_deref(),
        sandbox.playwright_runtime,
        deny_env,
        sandbox.worktree_root.as_deref(),
        sandbox.keychain_substitute.as_ref(),
    );

    apply_deny_env_and_credential(&mut cmd, deny_env, sandbox.keychain_substitute.as_ref());
    // Nothing the caller was holding open crosses into the agent.
    seal_inherited_fds(&mut cmd, Vec::new());

    spawn_and_wait(&mut cmd)
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
#[allow(clippy::disallowed_methods)] // spawns the resolved agent binary path, not a bare name
pub fn exec(
    sandbox: &super::PreparedSandbox,
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
    use std::os::unix::process::CommandExt as _;

    // Bubblewrap-wrapped path (namespaces + in-namespace Landlock/seccomp).
    if let Some(wrapper) = sandbox.bwrap_wrapper.as_ref() {
        match exec_bwrap(
            sandbox,
            wrapper,
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
        launch_dir,
        repo_dirs,
        &sandbox.home_dir,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        sandbox.scratch_dir.as_deref(),
        sandbox.pnpm_shadow_dir.as_deref(),
        sandbox.proxy_port,
        &sandbox.allow_localhost,
        sandbox.allow_localhost_any,
        sandbox.agent,
        gh_guard,
        git_guard,
        quiet,
        sandbox.npmrc_allowed,
        sandbox.playwright_socket_dir.as_deref(),
        sandbox.playwright_runtime,
        deny_env,
        sandbox.worktree_root.as_deref(),
        sandbox.keychain_substitute.as_ref(),
    );

    apply_deny_env_and_credential(&mut cmd, deny_env, sandbox.keychain_substitute.as_ref());
    // Before the Landlock hook below: that hook opens descriptors of its own,
    // and they must not be sealed.
    seal_inherited_fds(&mut cmd, Vec::new());

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
#[allow(clippy::disallowed_methods)] // bwrap_path comes from git::trusted_binary("bwrap")
fn exec_bwrap(
    sandbox: &super::PreparedSandbox,
    wrapper: &super::bubblewrap::BubblewrapWrapper,
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
        launch_dir,
        repo_dirs,
        &sandbox.home_dir,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        sandbox.scratch_dir.as_deref(),
        sandbox.pnpm_shadow_dir.as_deref(),
        sandbox.proxy_port,
        &sandbox.allow_localhost,
        sandbox.allow_localhost_any,
        sandbox.agent,
        gh_guard,
        git_guard,
        quiet,
        sandbox.npmrc_allowed,
        sandbox.playwright_socket_dir.as_deref(),
        sandbox.playwright_runtime,
        deny_env,
        sandbox.worktree_root.as_deref(),
        sandbox.keychain_substitute.as_ref(),
    );
    apply_deny_env_and_credential(&mut cmd, deny_env, sandbox.keychain_substitute.as_ref());
    // Set the re-entry env AFTER configure_command so a `clear_first` env build
    // cannot wipe them.
    cmd.env(
        super::bubblewrap::ENV_INNER_POLICY,
        policy_read_fd.to_string(),
    );
    cmd.env(super::bubblewrap::ENV_CONFIRM_FD, write_fd.to_string());
    // bwrap forwards inherited descriptors into the namespace, so the caller's
    // leak reaches the agent here too. The policy and confirm pipes are the
    // only two that are meant to: both are deliberately not CLOEXEC, and the
    // re-entry helper reads them by the fd numbers set above.
    seal_inherited_fds(&mut cmd, vec![policy_read_fd, write_fd]);

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
mod gh_token_extraction_tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// A `gh` stub at `dir/gh` running `body`, executable.
    fn gh_stub(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let gh = dir.join("gh");
        std::fs::write(&gh, format!("#!/bin/sh\n{body}\n")).expect("write gh stub");
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        gh
    }

    /// The launch must survive a `gh` that never answers.
    ///
    /// This call sits between the "Starting … in sandbox" banner and exec, and
    /// it runs on every Copilot launch. Unbounded it took the whole process
    /// down with it: cplt printed the banner and then waited forever, with
    /// nothing on screen naming `gh` as the thing being waited on.
    #[test]
    fn a_gh_that_never_answers_does_not_block_the_launch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gh = gh_stub(dir.path(), "sleep 300");

        let timeout = Duration::from_millis(200);
        let started = Instant::now();
        let token = gh_auth_token(&gh, timeout);
        let waited = started.elapsed();

        assert_eq!(token, None, "a wedged gh has no token to hand over");
        // Measured against the timeout that was passed, not against some
        // generous outer bound: an assertion loose enough to pass on a
        // materially weaker bound proves nothing about the bound. The margin
        // covers process spawn and the 20 ms poll granularity on a loaded CI
        // box.
        assert!(
            waited < timeout + Duration::from_secs(2),
            "the wait must be bounded by the {timeout:?} timeout, not by gh; waited {waited:?}"
        );
    }

    /// The child exiting is not the same as its stdout reaching EOF: a
    /// descendant `gh` leaves behind holds the write end open, and the reader
    /// never sees EOF. Waiting on that unbounded is the same launch hang one
    /// step further along, so the post-exit read is bounded too.
    #[test]
    fn a_descendant_holding_stdout_open_does_not_block_the_launch() {
        let dir = tempfile::tempdir().expect("tempdir");
        // `gh` exits at once; the backgrounded child inherits stdout and keeps
        // the pipe open well past it.
        let gh = gh_stub(dir.path(), "sleep 300 &\necho ghp_leaked");

        let started = Instant::now();
        let token = gh_auth_token(&gh, Duration::from_secs(10));
        let waited = started.elapsed();

        assert_eq!(token, None, "no EOF means no token to trust");
        assert!(
            waited < Duration::from_secs(5),
            "the post-exit read must be bounded by the EOF grace; waited {waited:?}"
        );
    }

    /// The bound must not cost the feature it bounds: a `gh` that answers still
    /// gets its token read, through the draining reader rather than `output()`.
    #[test]
    fn a_gh_that_answers_still_hands_the_token_over() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gh = gh_stub(dir.path(), "echo ghp_fromstub");
        assert_eq!(
            gh_auth_token(&gh, Duration::from_secs(10)),
            Some("ghp_fromstub".to_string())
        );
    }

    /// A `gh` that fails hands over nothing — including when it prints to
    /// stdout on the way out, which `.trim()` alone would have accepted.
    #[test]
    fn a_failing_gh_hands_over_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gh = gh_stub(dir.path(), "echo not-a-token; exit 1");
        assert_eq!(gh_auth_token(&gh, Duration::from_secs(10)), None);
    }

    /// A repo `deny.env` on a token var used to leave the child with NO token:
    /// the parent's value suppressed the extraction, then the deny stripped the
    /// very variable it was suppressed in favour of. The suppression check has
    /// to see the deny list for the same reason the injection does.
    #[test]
    fn a_denied_parent_token_does_not_suppress_extraction() {
        temp_env::with_var("GH_TOKEN", Some("ghp_parent"), || {
            assert!(
                child_keeps_a_github_token(&[]),
                "an undenied parent token reaches the child, so no extraction is needed"
            );
            assert!(
                !child_keeps_a_github_token(&["GH_TOKEN".to_string()]),
                "a denied token is stripped from the child, so extraction must still run"
            );
        });
    }

    /// #225: a repo denying the token vars means the agent gets no GitHub
    /// credential by ANY channel. The env channel is stripped already; the
    /// scratch cache would otherwise still serve one through `gh auth token`
    /// inside the sandbox, honouring the letter of the deny and not the intent.
    #[test]
    fn a_denied_gh_token_suppresses_the_scratch_cache() {
        temp_env::with_vars(
            [
                ("GH_TOKEN", None::<&str>),
                ("GITHUB_TOKEN", None),
                ("COPILOT_GITHUB_TOKEN", None),
            ],
            || {
                assert!(
                    should_cache_token(Agent::Copilot, &[], None),
                    "no deny and no ambient token: the cache is the only channel"
                );
                assert!(
                    !should_cache_token(Agent::Copilot, &["GH_TOKEN".to_string()], None),
                    "denying the injection target must silence the cache too"
                );
                // Narrower denies do not cost the cache. #225 ties the cache to
                // GH_TOKEN specifically: denying only COPILOT_GITHUB_TOKEN is a
                // statement about that variable, not "no GitHub credential".
                for other in ["GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN"] {
                    assert!(
                        should_cache_token(Agent::Copilot, &[other.to_string()], None),
                        "{other} denied alone must leave the cache channel open"
                    );
                }
            },
        );
    }

    /// The cache was always Copilot-only; the new predicate must not widen it.
    #[test]
    fn other_agents_never_get_the_token_cache() {
        for agent in [Agent::Claude, Agent::OpenCode, Agent::Shell, Agent::Goose] {
            assert!(!should_cache_token(agent, &[], None), "{agent:?}");
        }
    }

    /// #277: when the Keychain trade already hands gh's token over, the cache
    /// channel must not run `gh auth token` a second time. An env-var or file
    /// substitute changes nothing here.
    #[test]
    fn a_gh_token_substitute_skips_the_second_extraction() {
        use crate::agent::{KeychainSubstitute, SecretToken};
        temp_env::with_vars(
            [
                ("GH_TOKEN", None::<&str>),
                ("GITHUB_TOKEN", None),
                ("COPILOT_GITHUB_TOKEN", None),
            ],
            || {
                let gh = KeychainSubstitute::GhToken {
                    var: "GH_TOKEN",
                    token: SecretToken::new("tok".into()),
                };
                assert!(!should_cache_token(Agent::Copilot, &[], Some(&gh)));
                assert!(substitute_carries_gh_token(Some(&gh)));
                let file = KeychainSubstitute::File("/tmp/tok".into());
                assert!(should_cache_token(Agent::Copilot, &[], Some(&file)));
                assert!(!substitute_carries_gh_token(Some(&file)));
                assert!(!substitute_carries_gh_token(None));
            },
        );
    }

    /// Injecting into a denied name hands the token to a variable that is
    /// stripped moments later. With GH_TOKEN denied and GITHUB_TOKEN free,
    /// the surviving name is the one to use.
    #[test]
    fn injection_target_skips_denied_names() {
        let pick = |deny: &[String]| -> Option<&'static str> {
            GH_TOKEN_VARS
                .iter()
                .find(|var| !deny.iter().any(|d| d.as_str() == **var))
                .copied()
        };
        assert_eq!(pick(&[]), Some("GH_TOKEN"), "no deny, first name wins");
        assert_eq!(
            pick(&["GH_TOKEN".to_string()]),
            Some("GITHUB_TOKEN"),
            "a denied name is skipped for the next surviving one"
        );
        assert_eq!(
            pick(&[
                "GH_TOKEN".to_string(),
                "GITHUB_TOKEN".to_string(),
                "COPILOT_GITHUB_TOKEN".to_string(),
            ]),
            None,
            "all three denied leaves no channel to inject into"
        );
    }

    /// Denying one variable says nothing about the others.
    #[test]
    fn denying_one_token_var_leaves_the_others_counting() {
        temp_env::with_vars(
            [
                ("GH_TOKEN", None::<&str>),
                ("GITHUB_TOKEN", Some("ghp_other")),
                ("COPILOT_GITHUB_TOKEN", None),
            ],
            || {
                assert!(
                    child_keeps_a_github_token(&["GH_TOKEN".to_string()]),
                    "GITHUB_TOKEN survives the deny and still reaches the child"
                );
            },
        );
    }

    /// Whitespace is not a credential.
    #[test]
    fn a_blank_token_does_not_count() {
        temp_env::with_vars(
            [
                ("GH_TOKEN", Some("   ")),
                ("GITHUB_TOKEN", None),
                ("COPILOT_GITHUB_TOKEN", None),
            ],
            || assert!(!child_keeps_a_github_token(&[])),
        );
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test code: no unsandboxed parent to protect (#239)
mod keychain_substitute_tests {
    use super::*;
    use crate::agent::KeychainSubstitute;

    /// The forwarded variable is not in `ENV_ALLOWLIST`, so this helper is the
    /// only thing that puts it in the child environment (#242). If it stops
    /// working the agent silently loses the credential it traded the Keychain
    /// for, which is the failure this whole change exists to avoid.
    #[test]
    fn env_var_substitute_is_forwarded_and_file_substitute_is_not() {
        temp_env::with_var("CPLT_TEST_SUBSTITUTE", Some("tok"), || {
            let mut cmd = Command::new("/usr/bin/true");
            apply_deny_env_and_credential(
                &mut cmd,
                &[],
                Some(&KeychainSubstitute::EnvVar("CPLT_TEST_SUBSTITUTE")),
            );
            let set: Vec<_> = cmd.get_envs().collect();
            assert!(
                set.iter()
                    .any(|(k, v)| *k == "CPLT_TEST_SUBSTITUTE" && *v == Some("tok".as_ref())),
                "an env-var substitute must be forwarded: {set:?}"
            );

            // A file substitute needs nothing forwarded — the agent reads it.
            let mut cmd = Command::new("/usr/bin/true");
            apply_deny_env_and_credential(
                &mut cmd,
                &[],
                Some(&KeychainSubstitute::File("/tmp/tok".into())),
            );
            assert_eq!(cmd.get_envs().count(), 0);

            // No substitute: nothing forwarded, deny sweep still applies.
            let mut cmd = Command::new("/usr/bin/true");
            apply_deny_env_and_credential(&mut cmd, &["FOO".to_string()], None);
            let set: Vec<_> = cmd.get_envs().collect();
            assert_eq!(set, vec![("FOO".as_ref(), None)]);
        });
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test code: no unsandboxed parent to protect (#239)
mod spawn_error_tests {
    use super::*;

    /// `preflight` is skippable (`--no-validate`), so this is the only message
    /// some users get when a large grant set overflows the argument list. It
    /// has to say what to do about it, not just "argument list too long".
    #[test]
    #[cfg(target_os = "macos")]
    fn oversized_profile_spawn_failure_says_what_to_shrink() {
        let msg = spawn_error_message(&std::io::Error::from_raw_os_error(libc::E2BIG));
        assert!(
            msg.contains("kern.argmax") && msg.contains("allow/deny grants"),
            "E2BIG must be explained in terms of the profile, got: {msg}"
        );
    }

    #[test]
    fn other_spawn_failures_are_reported_verbatim() {
        let msg = spawn_error_message(&std::io::Error::from_raw_os_error(libc::ENOENT));
        assert!(
            !msg.contains("kern.argmax"),
            "unexpected profile advice: {msg}"
        );
        assert!(
            msg.starts_with("Failed to start sandboxed process:"),
            "{msg}"
        );
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test code: no unsandboxed parent to protect (#239)
mod inherited_fd_tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::io::{AsRawFd, RawFd};

    const SECRET: &str = "SUPER-SECRET-TOKEN";

    /// A file holding [`SECRET`], for the caller to leak a descriptor on.
    fn secret_file() -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(f, "{SECRET}").expect("write");
        f.flush().expect("flush");
        f
    }

    /// Open `file` and leave the descriptor non-CLOEXEC, exactly the way a
    /// wrapper or IDE leaves one when it launches cplt.
    ///
    /// A *fresh* handle per launch on purpose: two children sharing one open
    /// file description also share its offset, so a first child that reads to
    /// EOF makes the second read nothing whether it is sealed or not. That
    /// mistake makes this whole test pass for the wrong reason.
    fn leak(file: &tempfile::NamedTempFile) -> std::fs::File {
        let handle = std::fs::File::open(file.path()).expect("reopen");
        assert_eq!(
            unsafe { libc::fcntl(handle.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        handle
    }

    /// Read the inherited descriptor directly (`<&3`), never by path. Opening
    /// `/dev/fd/3` would be an `open(2)` the sandbox could refuse on its own;
    /// a redirect from an already-open descriptor is the capability that
    /// bypasses every path rule.
    ///
    /// `source` is dup2'd onto fd 3 first. Not cosmetic: `/bin/sh` is dash on
    /// Debian-family CI, and dash accepts only a single digit in `<&N`, so a
    /// descriptor that happens to land on fd 10 fails with "Bad fd number"
    /// rather than proving anything. Pinning it also matches how the leak was
    /// demonstrated.
    fn read_through_fd(source: RawFd, keep_fd3: bool, seal: bool) -> String {
        read_through_fd_at(source, 3, |cmd| {
            if seal {
                seal_inherited_fds(cmd, if keep_fd3 { vec![3] } else { Vec::new() });
            }
        })
    }

    /// [`read_through_fd`] with the descriptor number and the sealing step
    /// chosen by the caller, so a test can decide what `keep` holds — and when
    /// — rather than taking the two cases the bool pair offers.
    ///
    /// `target` stays a single digit for dash's sake, as above.
    fn read_through_fd_at(source: RawFd, target: RawFd, seal: impl FnOnce(&mut Command)) -> String {
        use std::os::unix::process::CommandExt as _;

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("cat <&{target}"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // SAFETY: dup2 only, between fork and exec. Registered before the seal
        // so the descriptor exists by the time the sweep runs.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(source, target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        seal(&mut cmd);
        let out = cmd.output().expect("spawn /bin/sh");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    #[test]
    fn an_inherited_descriptor_does_not_reach_the_child() {
        let file = secret_file();

        // Baseline: without the seal the descriptor is readable. If this stops
        // holding, the assertion below is proving nothing.
        let unsealed = leak(&file);
        assert!(
            read_through_fd(unsealed.as_raw_fd(), false, false).contains(SECRET),
            "the leak this test guards against no longer reproduces unsealed"
        );

        let sealed_fd = leak(&file);
        let sealed = read_through_fd(sealed_fd.as_raw_fd(), false, true);
        assert!(
            !sealed.contains(SECRET),
            "a descriptor the caller left open reached the child: {sealed}"
        );
    }

    #[test]
    fn a_kept_descriptor_still_reaches_the_child() {
        // The Linux bubblewrap path hands the re-entry helper two pipes on
        // purpose. Sealing must not take those away.
        let file = secret_file();
        let kept = leak(&file);
        let fd = kept.as_raw_fd();

        let got = read_through_fd(fd, true, true);
        assert!(
            got.contains(SECRET),
            "an explicitly kept descriptor must survive exec: {got}"
        );
    }

    #[test]
    fn stdio_survives_sealing() {
        // std dup2s the stdio pipes into 0/1/2 before pre_exec hooks run, so
        // sealing 3.. must leave them alone. A regression here looks like the
        // agent losing its terminal.
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("echo out; echo err >&2; cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        seal_inherited_fds(&mut cmd, Vec::new());
        let mut child = cmd.spawn().expect("spawn");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"echoed\n")
            .expect("write stdin");
        let out = child.wait_with_output().expect("wait");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "out\nechoed\n");
        assert_eq!(String::from_utf8_lossy(&out.stderr), "err\n");
    }

    #[test]
    fn a_failed_exec_is_still_reported() {
        // Sealing sets FD_CLOEXEC rather than calling close(2) precisely so
        // std's exec-failure pipe keeps working. Closing it would make this
        // spawn return Ok for a binary that does not exist.
        let mut cmd = Command::new("/nonexistent/cplt-seal-test");
        seal_inherited_fds(&mut cmd, Vec::new());
        assert!(
            cmd.output().is_err(),
            "a failed execve must still surface as a spawn error"
        );
    }

    /// GHSA-c47q-c3c8-7wrf: the audit's settle probe is the one descriptor the
    /// session is *meant* to inherit, and the seal is the single place that can
    /// take it away. Sealing it is silent — the read end sees EOF immediately
    /// and every session reports itself settled — so the exemption needs a test
    /// that fails when it stops working, not a comment.
    ///
    /// The probe is published to a process-global, which `seal_inherited_fds`
    /// reads once, in the parent, on the way in. Store and retract around that
    /// call alone: the audit's own tests arm real probes in this same binary,
    /// and a wider window would trade one flake for another.
    #[test]
    fn the_settle_probe_survives_sealing() {
        use std::sync::atomic::Ordering;

        // Not fd 3: the other tests here assert on 3, and the exemption is a
        // global they would see.
        const PROBE: RawFd = 9;

        let file = secret_file();
        let held = leak(&file);
        let got = read_through_fd_at(held.as_raw_fd(), PROBE, |cmd| {
            crate::audit::SETTLE_PROBE_FD.store(PROBE, Ordering::Relaxed);
            seal_inherited_fds(cmd, Vec::new());
            crate::audit::SETTLE_PROBE_FD.store(-1, Ordering::Relaxed);
        });

        assert!(
            got.contains(SECRET),
            "the settle probe was sealed shut, so every session would report \
             itself settled (GHSA-c47q-c3c8-7wrf): {got}"
        );
    }

    /// The seal must not cost more because the host raised `RLIMIT_NOFILE`.
    ///
    /// `getdtablesize()` is the soft limit, and a unit with
    /// `LimitNOFILE=infinity` makes that 1073741816 — roughly a billion `fcntl`
    /// calls between fork and exec, pinning a core with no output, no timeout
    /// and nothing on screen after "Starting <agent> in sandbox…" (#525).
    ///
    /// Measured rather than compared against a constant: the property is the
    /// scaling, and the absolute numbers belong to whatever host runs this.
    ///
    /// Linux only. Darwin clamps `getdtablesize()` to `kern.maxfilesperproc`
    /// (61440 by default), so the ceiling cannot follow the limit up there and
    /// this test would be measuring the clamp instead of the fix.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_seal_does_not_scale_with_rlimit_nofile() {
        use std::time::{Duration, Instant};

        /// The shape this replaced: one `fcntl` per descriptor number, all the
        /// way to the ceiling. Written out here rather than kept in production
        /// so the comparison below has something honest to beat.
        fn sweep_every_number(max: libc::c_int) {
            for fd in 3..max {
                // SAFETY: scalar `fcntl`; an unused descriptor returns EBADF.
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            }
        }

        fn nofile() -> (u64, u64) {
            let mut r = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `r` is a valid rlimit the kernel fills in.
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut r) },
                0
            );
            (r.rlim_cur, r.rlim_max)
        }

        fn set_nofile(soft: u64, hard: u64) {
            let r = libc::rlimit {
                rlim_cur: soft,
                rlim_max: hard,
            };
            // SAFETY: `r` is a valid rlimit; soft never exceeds hard here.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const r) },
                0,
                "could not set RLIMIT_NOFILE soft={soft}"
            );
        }

        /// Repetitions per measurement. The suite runs in parallel, so a single
        /// sample can be a scheduling artefact; the minimum of a few is not.
        const REPS: u32 = 5;

        /// Fastest of `reps`: noise only ever adds time, so the minimum is the
        /// closest this gets to the cost itself.
        fn fastest(reps: u32, mut f: impl FnMut()) -> Duration {
            (0..reps)
                .map(|_| {
                    let start = Instant::now();
                    f();
                    start.elapsed()
                })
                .min()
                .expect("at least one rep")
        }

        /// What the sweep costs, and what bound it used, at one soft limit.
        fn measure(soft: u64, hard: u64) -> (libc::c_int, libc::c_int, Duration, Duration) {
            set_nofile(soft, hard);
            // SAFETY: no arguments, no memory, no failure mode.
            let table = unsafe { libc::getdtablesize() };
            let ceiling = fd_sweep_ceiling();
            (
                table,
                ceiling,
                fastest(REPS, || sweep_every_number(table)),
                fastest(REPS, || seal_fds(ceiling, &[])),
            )
        }

        let (original, hard) = nofile();
        // 1024 rather than something closer to `high`: GitHub's Linux runners
        // cap the hard limit at 65536, and the premise below needs the two
        // limits to be far enough apart to tell scaling from noise.
        let low = 1024;
        let high = hard.min(1 << 20);

        let (table_low, ceiling_low, old_low, new_low) = measure(low, hard);
        let (table_high, ceiling_high, old_high, new_high) = measure(high, hard);
        set_nofile(original, hard);

        let report = format!(
            "soft {low} → {high} (hard {hard}): table {table_low} → {table_high}, \
             ceiling {ceiling_low} → {ceiling_high}, old sweep {old_low:?} → {old_high:?}, \
             seal {new_low:?} → {new_high:?}"
        );

        // Premises. Without both of these the comparison proves nothing: the
        // limit has to actually move the old bound, and moving it has to
        // actually cost time.
        assert!(
            table_high >= table_low * 16,
            "this host will not raise RLIMIT_NOFILE far enough to demonstrate \
             anything — {report}"
        );
        assert!(
            old_high >= old_low * 8,
            "the sweep this replaced did not visibly scale — {report}"
        );

        // Against the limit-derived bound, not against `ceiling_low`: the suite
        // runs in parallel and other tests open and close descriptors between
        // the two measurements, so the ceiling drifts by a few either way. What
        // must not happen is it tracking the limit.
        assert!(
            i64::from(ceiling_high) * 16 <= i64::from(table_high),
            "the seal's ceiling still follows RLIMIT_NOFILE — {report}"
        );
        assert!(
            new_high <= new_low * 4 + Duration::from_millis(1),
            "the seal still costs more at a higher RLIMIT_NOFILE — {report}"
        );
        assert!(
            new_high * 20 <= old_high,
            "the seal is no cheaper than the sweep it replaced — {report}"
        );
    }
}
