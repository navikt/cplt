use std::path::Path;

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

/// Build the environment variable map for the sandboxed process.
///
/// Pure function (takes parent env as input) for testability.
/// Returns (vars_to_set, vars_to_remove, should_clear).
///
/// - `should_clear`: if true, caller must `env_clear()` first, then set all vars from `vars_to_set`.
/// - `vars_to_remove`: only relevant when `should_clear` is false (inherit mode).
/// - `scratch_dir`: if Some, TMPDIR/TMP/TEMP/GOTMPDIR are redirected to this path
///   (unless explicitly overridden by user via `extra_pass_env`).
pub fn build_sandbox_env(
    parent_env: &[(String, String)],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    scratch_dir: Option<&Path>,
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
    } else {
        // Secure mode: only allowlisted vars
        for &var in ENV_ALLOWLIST {
            if let Some((_, val)) = parent_env.iter().find(|(k, _)| k == var) {
                env.vars.push((var.to_string(), val.clone()));
            }
        }
        for (key, val) in parent_env {
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

        // Inject JVM temp dir and RMI properties via JAVA_TOOL_OPTIONS.
        // On macOS, the JVM ignores TMPDIR — it uses confstr(_CS_DARWIN_USER_TEMP_DIR)
        // which always returns /var/folders/... where the sandbox blocks exec.
        // JAVA_TOOL_OPTIONS is the standard way to inject flags into ALL JVM processes,
        // including Maven Surefire forks and the Kotlin compiler daemon.
        // Also sets jansi.tmpdir (Java system property, not env var) for Jansi native lib extraction.
        // Also sets java.rmi.server.hostname=localhost to force RMI (used by Kotlin daemon)
        // to use localhost — without this, InetAddress.getLocalHost() may resolve to a
        // non-loopback IP via mDNS, which the sandbox blocks on non-443 ports.
        if !extra_pass_env.iter().any(|v| v == "JAVA_TOOL_OPTIONS") {
            let jvm_tmpdir_flags = format!(
                "-Djava.io.tmpdir={scratch_str} -Djansi.tmpdir={scratch_str} -Djava.rmi.server.hostname=localhost"
            );
            // Append to existing JAVA_TOOL_OPTIONS if present, otherwise create new
            if let Some(pos) = env.vars.iter().position(|(k, _)| k == "JAVA_TOOL_OPTIONS") {
                let existing = env.vars[pos].1.clone();
                if existing.is_empty() {
                    env.vars[pos].1 = jvm_tmpdir_flags;
                } else {
                    env.vars[pos].1 = format!("{existing} {jvm_tmpdir_flags}");
                }
            } else {
                env.vars
                    .push(("JAVA_TOOL_OPTIONS".to_string(), jvm_tmpdir_flags));
            }
        }
    }

    env
}
