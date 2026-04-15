use std::path::Path;

#[cfg(target_os = "macos")]
use super::env::build_sandbox_env;
#[cfg(target_os = "macos")]
use super::policy::HardeningCategory;

/// Validate the profile by running a simple command inside the sandbox.
#[cfg(target_os = "macos")]
pub fn validate(profile_path: &Path, _project_dir: &Path, _home_dir: &Path) -> Result<(), String> {
    let output = std::process::Command::new("sandbox-exec")
        .arg("-f")
        .arg(profile_path)
        .arg("/usr/bin/true")
        .output()
        .map_err(|e| format!("Failed to run sandbox-exec: {e}"))?;

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

/// Execute copilot inside the sandbox, forwarding signals to the child process group.
///
/// Environment handling:
/// - Default (inherit_env=false): env_clear() + allowlist only. Cloud credentials,
///   npm tokens, database URLs, etc. are stripped. Use `extra_pass_env` for extras.
/// - Legacy (inherit_env=true): all env vars inherited, only SSH_AUTH_SOCK and
///   color vars are stripped. Use only when the default breaks something.
/// - Security hardening env vars are injected unless their category is disabled.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
pub fn exec(
    copilot_bin: &Path,
    profile_path: &Path,
    project_dir: &Path,
    copilot_args: &[String],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    scratch_dir: Option<&Path>,
    proxy_port: Option<u16>,
) -> u8 {
    let mut cmd = std::process::Command::new("sandbox-exec");
    cmd.arg("-f").arg(profile_path).arg(copilot_bin);

    // Prevent Copilot from trying to auto-update inside the sandbox
    // (writes to ~/.copilot/pkg are denied, so it would fail anyway).
    cmd.arg("--no-auto-update");

    for arg in copilot_args {
        cmd.arg(arg);
    }

    // Set working directory to project
    cmd.current_dir(project_dir);

    // Build and apply environment
    let parent_env: Vec<(String, String)> = std::env::vars().collect();
    let sandbox_env = build_sandbox_env(
        &parent_env,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        scratch_dir,
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

    // Recursion guard: if copilot somehow re-invokes cplt (e.g. via symlink),
    // cplt will see this and bail before launching another sandbox.
    cmd.env("__CPLT_WRAPPED", "1");

    // When proxy is enabled, tell Node.js (bundled in Copilot CLI) to route
    // traffic through our CONNECT proxy. NODE_USE_ENV_PROXY is required for
    // Node.js ≥24.5.0 to honor HTTP_PROXY/HTTPS_PROXY natively.
    // Both cases are set for compatibility with non-Node tools (curl, gh, etc).
    if let Some(port) = proxy_port {
        let proxy_url = format!("http://127.0.0.1:{port}");
        cmd.env("NODE_USE_ENV_PROXY", "1");
        cmd.env("HTTP_PROXY", &proxy_url);
        cmd.env("HTTPS_PROXY", &proxy_url);
        cmd.env("http_proxy", &proxy_url);
        cmd.env("https_proxy", &proxy_url);
        // Exclude loopback from proxying — MCP servers, dev servers, etc.
        // on localhost should connect directly, not through our CONNECT proxy.
        cmd.env("NO_PROXY", "localhost,127.0.0.1,::1");
        cmd.env("no_proxy", "localhost,127.0.0.1,::1");
    }

    // Child inherits our process group — terminal signals (Ctrl+C)
    // reach both parent and child naturally. No setpgid/tcsetpgrp needed.
    //
    // Ignore SIGTTOU/SIGTTIN — copilot (Node.js) may manipulate terminal
    // settings (raw mode), and when the child exits the terminal state can
    // cause these signals to be sent to us.
    unsafe {
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("\x1b[0;31m[cplt]\x1b[0m Failed to start sandbox-exec: {e}");
            return 1;
        }
    };

    let child_pid = child.id() as i32;

    // Forward SIGTERM/SIGHUP to the child (these aren't sent by the terminal)
    install_signal_forwarding(child_pid);

    let status = match child.wait() {
        Ok(status) => status.code().unwrap_or(1) as u8,
        Err(e) => {
            eprintln!("\x1b[0;31m[cplt]\x1b[0m Error waiting for child: {e}");
            unsafe {
                libc::kill(child_pid, libc::SIGTERM);
            }
            1
        }
    };

    // Restore default signal handling
    unsafe {
        libc::signal(libc::SIGTTOU, libc::SIG_DFL);
        libc::signal(libc::SIGTTIN, libc::SIG_DFL);
    }

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
        // Reset to default — second signal kills us immediately
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

/// Execute copilot inside a Landlock + seccomp sandbox (Linux only).
///
/// The sandbox is applied via a `pre_exec` hook that runs in the child
/// process between fork() and exec(). This ensures only the child is
/// restricted — the parent (cplt) keeps full access.
///
/// The pre_exec hook:
/// 1. Applies the Landlock ruleset (filesystem + network restrictions)
/// 2. Applies the seccomp filter (blocks dangerous syscalls)
/// 3. Both are irreversible — the child cannot remove them
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn exec_linux(
    copilot_bin: &Path,
    project_dir: &Path,
    copilot_args: &[String],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    scratch_dir: Option<&Path>,
    proxy_port: Option<u16>,
    precomputed: &super::landlock_mod::PrecomputedSandbox,
) -> u8 {
    use std::os::unix::process::CommandExt as _;

    let mut cmd = std::process::Command::new(copilot_bin);

    // Prevent Copilot from trying to auto-update inside the sandbox.
    cmd.arg("--no-auto-update");

    for arg in copilot_args {
        cmd.arg(arg);
    }

    cmd.current_dir(project_dir);

    // Build and apply environment (same as macOS path)
    let parent_env: Vec<(String, String)> = std::env::vars().collect();
    let sandbox_env = build_sandbox_env(
        &parent_env,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        scratch_dir,
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

    // Recursion guard
    cmd.env("__CPLT_WRAPPED", "1");

    // Proxy setup (same as macOS)
    if let Some(port) = proxy_port {
        let proxy_url = format!("http://127.0.0.1:{port}");
        cmd.env("NODE_USE_ENV_PROXY", "1");
        cmd.env("HTTP_PROXY", &proxy_url);
        cmd.env("HTTPS_PROXY", &proxy_url);
        cmd.env("http_proxy", &proxy_url);
        cmd.env("https_proxy", &proxy_url);
        cmd.env("NO_PROXY", "localhost,127.0.0.1,::1");
        cmd.env("no_proxy", "localhost,127.0.0.1,::1");
    }

    // Terminal signal handling (same as macOS)
    unsafe {
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
    }

    // Apply pre-computed sandbox in the child process, between fork and exec.
    // All allocation and I/O was done in the parent — the closure only makes
    // raw syscalls via the Landlock crate and prctl for seccomp.
    let sandbox = precomputed.clone();
    unsafe {
        cmd.pre_exec(move || super::landlock_mod::apply_precomputed(&sandbox));
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("\x1b[0;31m[cplt]\x1b[0m Failed to start sandboxed process: {e}");
            return 1;
        }
    };

    let child_pid = child.id() as i32;
    install_signal_forwarding(child_pid);

    let status = match child.wait() {
        Ok(status) => status.code().unwrap_or(1) as u8,
        Err(e) => {
            eprintln!("\x1b[0;31m[cplt]\x1b[0m Error waiting for child: {e}");
            unsafe {
                libc::kill(child_pid, libc::SIGTERM);
            }
            1
        }
    };

    // Restore default signal handling
    unsafe {
        libc::signal(libc::SIGTTOU, libc::SIG_DFL);
        libc::signal(libc::SIGTTIN, libc::SIG_DFL);
    }

    status
}
