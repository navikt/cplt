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

/// Loopback spellings that must NEVER be sent to the CONNECT proxy.
///
/// This is deliberately the same set `crate::proxy::handle_connect` recognises
/// as loopback (`localhost`, `*.localhost` per RFC 6761, and any IP literal that
/// `is_loopback()`), plus `0.0.0.0` — the wildcard bind address a JVM dev server
/// or test container reports for itself. Keeping the two in step means the list
/// bypasses exactly what the proxy would refuse anyway (loopback is only
/// reachable through it under `--allow-localhost`), and nothing more: no public
/// host is silently exempted from logging or filtering.
///
/// Java's `nonProxyHosts` grammar is `|`-separated with `*` as the only
/// wildcard, and it is matched against the URI host — which for an IPv6 literal
/// keeps its brackets in some JDK paths and loses them in others, hence both
/// spellings of `::1`.
const JVM_NON_PROXY_HOSTS: &str = "localhost|*.localhost|127.*|[::1]|::1|0.0.0.0";

/// Build the `JAVA_TOOL_OPTIONS` value, or `None` when there is nothing to say.
///
/// `JAVA_TOOL_OPTIONS` is the standard way to inject flags into ALL JVM
/// processes, including Maven Surefire forks, the Kotlin compiler daemon and the
/// Gradle daemon (started by the launcher with an inherited environment).
///
/// Scratch-dir flags (only when a scratch dir exists):
/// - `java.io.tmpdir` — on macOS the JVM ignores `TMPDIR` and uses
///   `confstr(_CS_DARWIN_USER_TEMP_DIR)`, which returns `/var/folders/...` where
///   the sandbox blocks exec.
/// - `jansi.tmpdir` — where Jansi extracts its native library.
/// - `java.rmi.server.hostname` — forces RMI (used by the Kotlin daemon) to
///   localhost; otherwise `InetAddress.getLocalHost()` can resolve to a
///   non-loopback IP via mDNS, which the sandbox blocks on non-443 ports.
/// - `java.net.preferIPv4Stack` (macOS only) — keeps localhost connections on
///   AF_INET so SBPL's `localhost:*` filter matches; it cannot match the
///   IPv4-mapped `::ffff:127.0.0.1` a dual-stack socket produces. Linux Landlock
///   handles addresses differently.
///
/// Proxy flags (only when the proxy is running): the JVM has no `HTTP_PROXY`
/// support — it reads `http.proxyHost`/`https.proxyHost` system properties and
/// nothing else — so without these every Gradle and Maven dependency fetch goes
/// straight out through the kernel's `*:443` allowance, invisible to the proxy
/// log and unfiltered by the blocklist.
fn java_tool_options(scratch_dir: Option<&Path>, proxy_port: Option<u16>) -> Option<String> {
    let mut flags: Vec<String> = Vec::new();

    if let Some(scratch) = scratch_dir {
        let s = scratch.to_string_lossy();
        flags.push(format!("-Djava.io.tmpdir={s}"));
        flags.push(format!("-Djansi.tmpdir={s}"));
        flags.push("-Djava.rmi.server.hostname=localhost".to_string());
        #[cfg(target_os = "macos")]
        flags.push("-Djava.net.preferIPv4Stack=true".to_string());
    }

    if let Some(port) = proxy_port {
        // Both schemes: `mavenCentral()` and the Gradle plugin portal are HTTPS,
        // but plenty of repository declarations and redirects are still plain
        // HTTP, and an unproxied HTTP fetch is exactly the hole this closes.
        // `https.nonProxyHosts` is not read by the JDK's own ProxySelector, but
        // Gradle documents and honours it — setting both costs one flag.
        for scheme in ["http", "https"] {
            flags.push(format!("-D{scheme}.proxyHost=127.0.0.1"));
            flags.push(format!("-D{scheme}.proxyPort={port}"));
            flags.push(format!("-D{scheme}.nonProxyHosts={JVM_NON_PROXY_HOSTS}"));
        }
    }

    (!flags.is_empty()).then(|| flags.join(" "))
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
/// - `proxy_port`: if Some, JVM proxy system properties pointing at
///   `127.0.0.1:<port>` are injected into `JAVA_TOOL_OPTIONS`.
/// - `agent`: which agent is being sandboxed — Copilot-specific env vars are suppressed for other agents.
pub fn build_sandbox_env(
    parent_env: &[(String, String)],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    scratch_dir: Option<&Path>,
    proxy_port: Option<u16>,
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
    }

    // Inject JVM temp dir, RMI, IPv4-stack and proxy properties via JAVA_TOOL_OPTIONS.
    // JAVA_TOOL_OPTIONS is the standard way to inject flags into ALL JVM processes,
    // including Maven Surefire forks, the Kotlin compiler daemon and the Gradle daemon
    // (which inherits the launcher's environment). See `java_tool_options` for what
    // each flag is for. Deliberately NOT nested inside the scratch-dir branch: the
    // proxy flags must be injected whenever the proxy runs, with or without a scratch
    // dir.
    if !extra_pass_env.iter().any(|v| v == "JAVA_TOOL_OPTIONS")
        && let Some(jvm_flags) = java_tool_options(scratch_dir, proxy_port)
    {
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

/// The cplt-owned Playwright socket base to inject, unless the caller overrides it.
///
/// An explicit `--pass-env PWTEST_SOCKETS_DIR` is an override signal even when
/// the parent has no value. Ambient values are not considered: callers apply
/// this after normal environment filtering so the short automatic value replaces
/// inherited or allowlisted values unless the user explicitly passed the key.
pub fn playwright_sockets_dir_override<'a>(
    extra_pass_env: &[String],
    playwright_socket_dir: Option<&'a Path>,
) -> Option<&'a Path> {
    if extra_pass_env.iter().any(|var| var == "PWTEST_SOCKETS_DIR") {
        return None;
    }
    playwright_socket_dir
}

/// Whether to turn off Playwright MCP's nested Chromium sandbox for the child.
///
/// Chromium cannot run its own sandbox inside cplt's: macOS rejects the second
/// Seatbelt initialization, and cplt's seccomp filter denies the namespace
/// syscalls Linux needs. Playwright as a library already launches without it,
/// but Playwright MCP turns it back on, so browser operations fail inside cplt
/// unless it is disabled. cplt is the enforcing kernel boundary either way, so
/// it disables the redundant inner sandbox the same way it does for Gradle,
/// rather than making every client's server configuration carry a cplt-only
/// flag. Requires the explicit `ms-playwright` opt-in, and an explicit
/// `--pass-env PLAYWRIGHT_MCP_SANDBOX` hands the choice back to the caller.
pub fn playwright_mcp_sandbox_disabled(
    extra_pass_env: &[String],
    playwright_runtime: bool,
) -> bool {
    playwright_runtime
        && !extra_pass_env
            .iter()
            .any(|var| var == "PLAYWRIGHT_MCP_SANDBOX")
}

/// Keys in `parent_env` that name the same npm setting as `NPM_CONFIG_USERCONFIG`
/// but are spelled differently, and so must be dropped when the override is injected.
///
/// npm and yarn both build their config by lowercasing every `npm_config_*` key
/// (yarn 1's `NpmRegistry.getConfigFromEnv`, npm's own `npm-conf`), so
/// `npm_config_userconfig` and `NPM_CONFIG_USERCONFIG` collapse to one entry and
/// the last one the environ happens to yield wins. `npmrc_userconfig_override`
/// deliberately treats an *empty* value as unset, so it can inject alongside an
/// empty lowercase variant — and if that variant survives, the merge may pick the
/// empty string, drop the redirect, and put `~/.npmrc` (and yarn 1's abort) back.
/// Removing the variants leaves exactly one value in play instead of relying on
/// iteration order.
pub fn npmrc_userconfig_stale_variants(parent_env: &[(String, String)]) -> Vec<&str> {
    parent_env
        .iter()
        .map(|(k, _)| k.as_str())
        .filter(|k| {
            k.eq_ignore_ascii_case("NPM_CONFIG_USERCONFIG") && *k != "NPM_CONFIG_USERCONFIG"
        })
        .collect()
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
