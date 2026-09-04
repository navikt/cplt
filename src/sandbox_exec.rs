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
/// variable in the first place because `Agent::credential_outside_keychain`
/// filters `deny_env` before returning one (#242).
///
/// The forwarded variable is deliberately NOT in `ENV_ALLOWLIST` — it reaches
/// the agent only as part of this trade, so with `sandbox.keychain_substitute`
/// off the child environment is exactly what it was before the key existed.
fn apply_deny_env_and_credential(
    cmd: &mut Command,
    deny_env: &[String],
    substitute: Option<&crate::agent::KeychainSubstitute>,
) {
    for var in deny_env {
        cmd.env_remove(var);
    }
    if let Some(var) = substitute.and_then(crate::agent::KeychainSubstitute::env_var)
        // `deny_env` wins here too, not only in `credential_outside_keychain`.
        // That filter is what keeps a denied var from becoming a substitute in
        // the first place, so today this is unreachable — but this function
        // removes and then re-adds, and re-adding a var the repo denied is the
        // one mistake its shape invites. The check costs nothing and does not
        // depend on a caller two modules away staying correct.
        && !deny_env.iter().any(|d| d == var)
        && let Ok(val) = std::env::var(var)
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
    npmrc_allowed: bool,
    playwright_socket_dir: Option<&Path>,
    playwright_runtime: bool,
    // Consulted before extracting a token: these names are stripped from the
    // child afterwards, so a parent value that is about to be denied must not
    // suppress the extraction. See `child_keeps_a_github_token`.
    deny_env: &[String],
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
    if let Some(scratch) = scratch_dir {
        if gh_guard.enabled {
            // Inject GH_TOKEN into env only when explicitly requested.
            if gh_guard.inject_token {
                inject_gh_token_if_needed(cmd, agent, deny_env);
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
                cache_gh_token_to_file(scratch, agent, deny_env);
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
const GH_TOKEN_VARS: &[&str] = &["GH_TOKEN", "GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN"];

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
fn extract_gh_token() -> Option<String> {
    let gh = trusted_gh()?;
    let mut cmd = std::process::Command::new(&gh);
    cmd.args(["auth", "token", "--hostname", "github.com"]);
    for var in GH_TOKEN_VARS {
        cmd.env_remove(var);
    }
    let output = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
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

fn inject_gh_token_if_needed(cmd: &mut Command, agent: Agent, deny_env: &[String]) {
    // Only inject for Copilot — other agents have their own auth.
    if agent != Agent::Copilot || child_keeps_a_github_token(deny_env) {
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
fn should_cache_token(agent: Agent, deny_env: &[String]) -> bool {
    if agent != Agent::Copilot {
        return false;
    }
    // GH_TOKEN specifically, not any of the three. #225 asks for the cache to
    // follow the injection target: denying GH_TOKEN is the repo saying "no
    // GitHub credential", while denying only COPILOT_GITHUB_TOKEN is a narrower
    // statement that should not cost the agent the cache channel as well.
    let target_denied = deny_env.iter().any(|d| d == "GH_TOKEN");
    !target_denied && !child_keeps_a_github_token(deny_env)
}

fn cache_gh_token_to_file(scratch_dir: &Path, agent: Agent, deny_env: &[String]) {
    if !should_cache_token(agent, deny_env) {
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
        if !git_guard.allow_push.is_empty() {
            if let Some(trusted) = crate::git::trusted_git() {
                git_guard.allow_push = crate::gh_proxy::resolve_push_rule_urls(
                    trusted,
                    project_dir,
                    &git_guard.allow_push,
                );
                for rule in &git_guard.allow_push {
                    if rule.url.is_none()
                        && let Some(name) = rule.remote.as_deref()
                    {
                        ui::warn(&format!(
                            "git guard: allow_push remote {name:?} does not exist in this \
                             repository, so the rule cannot be pinned to a repository and \
                             authorizes no push. Add the remote before launch \
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

    // The upper bound is the soft RLIMIT_NOFILE, read here in the parent so the
    // hook itself is nothing but `fcntl`. A machine with a very high limit pays
    // a linear sweep once per agent launch (~250ms at 2^20); Linux
    // `close_range(.., CLOSE_RANGE_CLOEXEC)` would fix that if it ever shows up
    // in a profile.
    // SAFETY: getdtablesize() takes no arguments, touches no memory, and has no
    // failure mode.
    let max = unsafe { libc::getdtablesize() };

    // SAFETY: the closure runs between fork and exec. It makes only `fcntl`
    // calls — no allocation, no locks, async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            // stdin/stdout/stderr are already dup2'd into place by std before
            // pre_exec hooks run, so 0..=2 are ours and must stay.
            for fd in 3..max {
                // EBADF on an unused descriptor is expected and ignored.
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            for &fd in &keep {
                libc::fcntl(fd, libc::F_SETFD, 0);
            }
            Ok(())
        });
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
    let mut cmd = Command::new(SANDBOX_EXEC);
    cmd.arg("-p").arg(&sandbox.profile_text).arg(copilot_bin);

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
        sandbox.npmrc_allowed,
        sandbox.playwright_socket_dir.as_deref(),
        sandbox.playwright_runtime,
        deny_env,
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
        gh_guard,
        git_guard,
        sandbox.npmrc_allowed,
        sandbox.playwright_socket_dir.as_deref(),
        sandbox.playwright_runtime,
        deny_env,
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
        sandbox.npmrc_allowed,
        sandbox.playwright_socket_dir.as_deref(),
        sandbox.playwright_runtime,
        deny_env,
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
                    should_cache_token(Agent::Copilot, &[]),
                    "no deny and no ambient token: the cache is the only channel"
                );
                assert!(
                    !should_cache_token(Agent::Copilot, &["GH_TOKEN".to_string()]),
                    "denying the injection target must silence the cache too"
                );
                // Narrower denies do not cost the cache. #225 ties the cache to
                // GH_TOKEN specifically: denying only COPILOT_GITHUB_TOKEN is a
                // statement about that variable, not "no GitHub credential".
                for other in ["GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN"] {
                    assert!(
                        should_cache_token(Agent::Copilot, &[other.to_string()]),
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
            assert!(!should_cache_token(agent, &[]), "{agent:?}");
        }
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
        use std::os::unix::process::CommandExt as _;

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("cat <&3")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // SAFETY: dup2 only, between fork and exec. Registered before the seal
        // so fd 3 exists by the time the sweep runs.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(source, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        if seal {
            seal_inherited_fds(&mut cmd, if keep_fd3 { vec![3] } else { Vec::new() });
        }
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
}
