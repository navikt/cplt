//! Environment variable construction for sandboxed processes.
//!
//! Filters the parent environment through an allowlist and injects
//! hardening variables (e.g. `TMPDIR`, `NODE_OPTIONS`).

use std::path::Path;

use crate::agent::Agent;

use super::policy::{
    ENV_ALLOWLIST, ENV_ALWAYS_DENY, ENV_PREFIX_ALLOWLIST, HARDENING_ENV_VARS, HardeningCategory,
    SCRATCH_DIR_ENV_VARS, is_secret_suffix,
};

/// Environment configuration for the sandboxed process.
pub struct SandboxEnv {
    /// Variables to set (name, value).
    pub vars: Vec<(String, String)>,
    /// Variables to remove (only used when `clear_first` is false).
    pub remove: Vec<String>,
    /// Whether to clear all env vars before applying `vars`.
    pub clear_first: bool,
}

/// Environment variables that are Copilot-specific and should not be exposed
/// to other agents. These contain GitHub auth tokens that OpenCode doesn't need.
const COPILOT_ONLY_VARS: &[&str] = &["GH_TOKEN", "GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN"];

/// Environment variable prefix that is Copilot-specific.
const COPILOT_ONLY_PREFIXES: &[&str] = &["COPILOT_"];

/// Returns true if this env var should be suppressed for the given agent.
fn is_agent_suppressed(key: &str, agent: Agent) -> bool {
    if agent == Agent::Copilot {
        return false; // Copilot gets everything in the allowlist
    }
    if COPILOT_ONLY_VARS.contains(&key) {
        return true;
    }
    if COPILOT_ONLY_PREFIXES
        .iter()
        .any(|prefix| key.starts_with(prefix))
    {
        return true;
    }
    false
}

/// Build the environment variable map for the sandboxed process.
///
/// Pure function (takes parent env as input) for testability.
/// Returns (vars_to_set, vars_to_remove, should_clear).
///
/// - `should_clear`: if true, caller must `env_clear()` first, then set all vars from `vars_to_set`.
/// - `vars_to_remove`: only relevant when `should_clear` is false (inherit mode).
/// - `scratch_dir`: if Some, TMPDIR/TMP/TEMP/GOTMPDIR are redirected to this path
///   (unless explicitly overridden by user via `extra_pass_env`).
/// - `agent`: which agent is being sandboxed — Copilot-specific env vars are suppressed for other agents.
pub fn build_sandbox_env(
    parent_env: &[(String, String)],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    scratch_dir: Option<&Path>,
    agent: Agent,
) -> SandboxEnv {
    let mut env = SandboxEnv {
        vars: Vec::new(),
        remove: Vec::new(),
        clear_first: !inherit_env,
    };

    if inherit_env {
        // Legacy mode: inherit everything, strip known-bad vars
        for var in ENV_ALWAYS_DENY {
            env.remove.push(var.to_string());
        }
        // Also strip agent-specific vars in inherit mode
        for (key, _) in parent_env {
            if is_agent_suppressed(key, agent) {
                env.remove.push(key.clone());
            }
        }
    } else {
        // Secure mode: only allowlisted vars, filtered by agent
        for &var in ENV_ALLOWLIST {
            if is_agent_suppressed(var, agent) {
                continue;
            }
            if let Some((_, val)) = parent_env.iter().find(|(k, _)| k == var) {
                env.vars.push((var.to_string(), val.clone()));
            }
        }
        for (key, val) in parent_env {
            if is_agent_suppressed(key, agent) {
                continue;
            }
            if ENV_PREFIX_ALLOWLIST
                .iter()
                .any(|prefix| key.starts_with(prefix))
                && !is_secret_suffix(key)
            {
                // Avoid duplicates from the explicit allowlist
                if !env.vars.iter().any(|(k, _)| k == key) {
                    env.vars.push((key.clone(), val.clone()));
                }
            }
        }
        for var in extra_pass_env {
            if let Some((_, val)) = parent_env.iter().find(|(k, _)| k == var)
                && !env.vars.iter().any(|(k, _)| k == var)
            {
                env.vars.push((var.clone(), val.clone()));
            }
        }
    }

    // Apply security hardening: inject vars unless the category is disabled
    // or the user has explicitly set the var (via --pass-env or parent env in inherit mode).
    for hvar in HARDENING_ENV_VARS {
        if disabled_categories.contains(&hvar.category) {
            continue;
        }
        // Only skip hardening if the user *explicitly* requested it via --pass-env.
        // In sanitized mode, prefix-matched vars (e.g. YARN_ENABLE_SCRIPTS from
        // parent env via the YARN_ prefix) must NOT prevent hardening injection —
        // otherwise a parent env setting silently bypasses security controls.
        let user_has_set = extra_pass_env.iter().any(|v| v == hvar.name);
        if !user_has_set {
            // Remove any prefix-matched value before injecting the hardened one.
            // e.g. YARN_ENABLE_SCRIPTS=true from parent env must be replaced with false.
            env.vars.retain(|(k, _)| k != hvar.name);
            env.vars
                .push((hvar.name.to_string(), hvar.value.to_string()));
        }
    }

    // The oh-my-openagent OpenCode plugin implements Claude Code hooks and writes
    // transcripts to $CLAUDE_CONFIG_DIR/transcripts (default ~/.claude), which the
    // sandbox denies for non-Claude agents — the append fails with EACCES and the
    // OpenCode server aborts the prompt. Redirect the plugin's config dir into the
    // OpenCode state dir (write-allowed, auto-created at startup) so the hooks
    // feature works inside the sandbox. A user-set CLAUDE_CONFIG_DIR is respected;
    // they are expected to --allow-write that path themselves.
    if agent == Agent::OpenCode {
        // An empty CLAUDE_CONFIG_DIR is treated as unset: the plugin would resolve
        // it to a relative "transcripts/" path inside the project and hit EACCES.
        let user_set = extra_pass_env.iter().any(|v| v == "CLAUDE_CONFIG_DIR")
            || parent_env
                .iter()
                .any(|(k, v)| k == "CLAUDE_CONFIG_DIR" && !v.is_empty());
        if !user_set && let Some((_, home)) = parent_env.iter().find(|(k, _)| k == "HOME") {
            // Drop any empty entry the allowlist may have passed through.
            env.vars.retain(|(k, _)| k != "CLAUDE_CONFIG_DIR");
            let state_base = parent_env
                .iter()
                .find(|(k, _)| k == "XDG_STATE_HOME")
                .map(|(_, v)| v.clone())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("{home}/.local/state"));
            env.vars.push((
                "CLAUDE_CONFIG_DIR".to_string(),
                format!("{state_base}/opencode/claude-config"),
            ));
        }
    }

    // Redirect temp directories to scratch dir if provided.
    // --scratch-dir means "redirect TMPDIR to the scratch dir" — this overrides any
    // inherited or allowlisted TMPDIR value. The user can prevent this for a specific
    // var by passing --pass-env TMPDIR, which signals "use my value, not scratch".
    if let Some(scratch) = scratch_dir {
        let scratch_str = scratch.to_string_lossy().to_string();
        for var in SCRATCH_DIR_ENV_VARS {
            let user_override = extra_pass_env.iter().any(|v| v == var);
            if !user_override {
                // Remove any existing value (e.g., system TMPDIR from allowlist)
                env.vars.retain(|(k, _)| k != var);
                env.vars.push((var.to_string(), scratch_str.clone()));
            }
        }

        // Inject JVM temp dir, RMI, and IPv4 stack properties via JAVA_TOOL_OPTIONS.
        // On macOS, the JVM ignores TMPDIR — it uses confstr(_CS_DARWIN_USER_TEMP_DIR)
        // which always returns /var/folders/... where the sandbox blocks exec.
        // JAVA_TOOL_OPTIONS is the standard way to inject flags into ALL JVM processes,
        // including Maven Surefire forks and the Kotlin compiler daemon.
        // Also sets jansi.tmpdir (Java system property, not env var) for Jansi native lib extraction.
        // Also sets java.rmi.server.hostname=localhost to force RMI (used by Kotlin daemon)
        // to use localhost — without this, InetAddress.getLocalHost() may resolve to a
        // non-loopback IP via mDNS, which the sandbox blocks on non-443 ports.
        //
        // On macOS: forces IPv4 stack so localhost connections use AF_INET4 (127.0.0.1)
        // instead of IPv6 dual-stack which produces IPv4-mapped addresses (::ffff:127.0.0.1).
        // SBPL's "localhost:*" filter doesn't match IPv4-mapped addresses, so without this
        // flag, Java can't use port-specific localhost rules (--allow-localhost <PORT>).
        // This is macOS-only because Linux Landlock handles addresses differently.
        if !extra_pass_env.iter().any(|v| v == "JAVA_TOOL_OPTIONS") {
            let base_flags = format!(
                "-Djava.io.tmpdir={scratch_str} -Djansi.tmpdir={scratch_str} -Djava.rmi.server.hostname=localhost"
            );
            #[cfg(target_os = "macos")]
            let jvm_flags = format!("{base_flags} -Djava.net.preferIPv4Stack=true");
            #[cfg(not(target_os = "macos"))]
            let jvm_flags = base_flags;
            // Append to existing JAVA_TOOL_OPTIONS if present, otherwise create new
            if let Some(pos) = env.vars.iter().position(|(k, _)| k == "JAVA_TOOL_OPTIONS") {
                let existing = env.vars[pos].1.clone();
                if existing.is_empty() {
                    env.vars[pos].1 = jvm_flags;
                } else {
                    env.vars[pos].1 = format!("{existing} {jvm_flags}");
                }
            } else {
                env.vars.push(("JAVA_TOOL_OPTIONS".to_string(), jvm_flags));
            }
        }
    }

    // Disable Gradle's own macOS sandbox (Gradle 9+). Gradle uses sandbox-exec
    // internally, which conflicts with cplt's sandbox (nested sandboxes fail with
    // "Operation not permitted"). cplt already provides kernel-level sandboxing,
    // so Gradle's is redundant.
    #[cfg(target_os = "macos")]
    if !extra_pass_env.iter().any(|v| v == "GRADLE_MACOS_SANDBOX") {
        env.vars.retain(|(k, _)| k != "GRADLE_MACOS_SANDBOX");
        env.vars
            .push(("GRADLE_MACOS_SANDBOX".to_string(), "off".to_string()));
    }

    // Disable dotnet CLI / MSBuild persistent build server reuse. Without this,
    // `dotnet build` defaults to starting (or reusing) a long-lived MSBuild Server
    // process listening on a Unix domain socket named MSBuildServer-<hash> — a
    // predictable path that a sandboxed process could otherwise use to reach, or
    // be reached by, a server instance started outside the sandbox. cplt's
    // --allow-msbuild only ever opens the differently-named worker-node socket
    // (MSBuild<pid>), never the server one, but this env var removes the
    // persistent-server code path entirely rather than relying solely on the
    // socket-path allowlist to keep it unreachable.
    if !extra_pass_env
        .iter()
        .any(|v| v == "DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER")
    {
        env.vars
            .retain(|(k, _)| k != "DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER");
        env.vars.push((
            "DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER".to_string(),
            "1".to_string(),
        ));
    }

    // Sanitize NODE_OPTIONS: strip dangerous directives that allow preload injection.
    // NODE_OPTIONS passes through the allowlist for legitimate use (--max-old-space-size),
    // but --require/--loader/--import can inject code into all Node.js child processes.
    sanitize_node_options(&mut env.vars);

    env
}

/// Whether the user explicitly re-allowed `$HOME/.npmrc` via `--allow-read` / `allow.read`.
///
/// Both entry points canonicalize before the path reaches `extra_read`
/// (`canonicalize_paths` in main.rs, `resolve_config_path` in config/path.rs), so a
/// stow/chezmoi `~/.npmrc -> ~/dotfiles/npmrc` is stored as the link *target*. Compare
/// canonicalized, or the flag reads false for exactly the users who opted in and the
/// `NPM_CONFIG_USERCONFIG` redirect silently ignores the token they asked for.
pub fn npmrc_explicitly_allowed(home_dir: &Path, extra_read: &[std::path::PathBuf]) -> bool {
    let npmrc = home_dir.join(".npmrc");
    let resolved = std::fs::canonicalize(&npmrc).unwrap_or(npmrc);
    extra_read.iter().any(|p| p == &resolved)
}

/// Where to point `NPM_CONFIG_USERCONFIG`, or `None` when the injection must be skipped.
///
/// The sandbox denies `~/.npmrc` (it holds registry auth tokens). npm, pnpm and bun
/// treat the resulting EACCES/EPERM as "no user config"; yarn 1 only tolerates
/// ENOENT/EISDIR and aborts the whole install (#180). Pointing the user-config path
/// at a file that does not exist inside the scratch dir turns the denial into ENOENT,
/// which every one of them handles. Semantically a no-op: the real `~/.npmrc` was
/// unreadable in the sandbox either way.
///
/// Skipped when:
/// - the user opted back into `~/.npmrc` via `allow.read` (`npmrc_allowed`) — they
///   want the token, and redirecting would silently break private-registry auth;
/// - the user set `NPM_CONFIG_USERCONFIG` themselves (it is on `ENV_ALLOWLIST`);
/// - there is no scratch dir — without one there is no session-scoped writable location
///   to point at, and leaving the denial in place is better than inventing a target.
pub fn npmrc_userconfig_override(
    parent_env: &[(String, String)],
    scratch_dir: Option<&Path>,
    npmrc_allowed: bool,
) -> Option<std::path::PathBuf> {
    if npmrc_allowed {
        return None;
    }
    // Case-insensitive: npm and yarn both lowercase `npm_config_*` env keys, so a user's
    // `npm_config_userconfig` (which `--inherit-env` passes through) is the same setting.
    // Injecting the uppercase form alongside it makes which one wins depend on env order.
    if parent_env
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("NPM_CONFIG_USERCONFIG") && !v.is_empty())
    {
        return None;
    }
    // "npmrc" (no dot) so it cannot collide with a real dotfile the agent creates.
    Some(scratch_dir?.join("npmrc"))
}

/// Dangerous NODE_OPTIONS flags that allow code preloading or module interception.
const NODE_OPTIONS_DANGEROUS: &[&str] = &[
    "--require",
    "-r",
    "--loader",
    "--experimental-loader",
    "--import",
    "--experimental-vm-modules",
    "--experimental-policy",
    "--conditions",
];

/// Strip dangerous directives from NODE_OPTIONS while preserving safe ones.
///
/// Dangerous flags (--require, --loader, --import, etc.) allow preload injection
/// across all Node.js child processes inside the sandbox. Safe flags like
/// --max-old-space-size and --openssl-legacy-provider are preserved.
fn sanitize_node_options(vars: &mut Vec<(String, String)>) {
    let Some(pos) = vars.iter().position(|(k, _)| k == "NODE_OPTIONS") else {
        return;
    };
    let original = vars[pos].1.clone();
    let sanitized = strip_dangerous_node_flags(&original);
    if sanitized.is_empty() {
        vars.remove(pos);
    } else {
        vars[pos].1 = sanitized;
    }
}

/// Parse NODE_OPTIONS and remove dangerous flags (and their arguments).
fn strip_dangerous_node_flags(value: &str) -> String {
    let parts: Vec<&str> = value.split_whitespace().collect();
    let mut result = Vec::new();
    let mut i = 0;
    while i < parts.len() {
        let part = parts[i];
        // Check if this flag (or its --flag=value form) is dangerous
        let flag_name = part.split('=').next().unwrap_or(part);
        if NODE_OPTIONS_DANGEROUS.contains(&flag_name) {
            // Skip this flag and its argument (if separate, not --flag=value)
            if !part.contains('=') && i + 1 < parts.len() && !parts[i + 1].starts_with('-') {
                i += 1; // skip the argument too
            }
        } else {
            result.push(part);
        }
        i += 1;
    }
    result.join(" ")
}
