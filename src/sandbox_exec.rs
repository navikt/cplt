use std::path::Path;
use std::process::Command;

use super::env::build_sandbox_env;
use super::policy::HardeningCategory;

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
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    scratch_dir: Option<&Path>,
    proxy_port: Option<u16>,
) {
    // Prevent Copilot from trying to auto-update inside the sandbox
    // (writes to the pkg dir are denied, so it would fail anyway).
    cmd.arg("--no-auto-update");

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
    if let Some(port) = proxy_port {
        let proxy_url = format!("http://127.0.0.1:{port}");
        cmd.env("NODE_USE_ENV_PROXY", "1");
        cmd.env("HTTP_PROXY", &proxy_url);
        cmd.env("HTTPS_PROXY", &proxy_url);
        cmd.env("http_proxy", &proxy_url);
        cmd.env("https_proxy", &proxy_url);
        // Exclude loopback from proxying — MCP servers, dev servers, etc.
        cmd.env("NO_PROXY", "localhost,127.0.0.1,::1");
        cmd.env("no_proxy", "localhost,127.0.0.1,::1");
    }
}

/// Spawn a sandboxed command, forward signals, and wait for exit.
///
/// Handles SIGTTOU/SIGTTIN suppression (Node.js terminal raw mode),
/// SIGTERM/SIGHUP forwarding to the child, and cleanup on exit.
fn spawn_and_wait(cmd: &mut Command) -> u8 {
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
            eprintln!("\x1b[0;31m[cplt]\x1b[0m Failed to start sandboxed process: {e}");
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
pub fn exec(
    sandbox: &super::PreparedSandbox,
    copilot_bin: &Path,
    copilot_args: &[String],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
) -> u8 {
    let profile_path = match write_temp_profile(&sandbox.profile_text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\x1b[0;31m[cplt]\x1b[0m {e}");
            return 1;
        }
    };

    let mut cmd = Command::new("sandbox-exec");
    cmd.arg("-f").arg(&profile_path).arg(copilot_bin);

    configure_command(
        &mut cmd,
        copilot_args,
        &sandbox.project_dir,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        sandbox.scratch_dir.as_deref(),
        sandbox.proxy_port,
    );

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
#[cfg(target_os = "linux")]
pub fn preflight(_sandbox: &super::PreparedSandbox) -> Result<(), String> {
    Ok(())
}

/// Execute copilot inside a Landlock + seccomp sandbox.
///
/// The sandbox is applied via a `pre_exec` hook that runs in the child
/// process between fork() and exec(). All allocation and I/O was done
/// in the parent via `precompute()` — the hook only makes raw syscalls.
#[cfg(target_os = "linux")]
pub fn exec(
    sandbox: &super::PreparedSandbox,
    copilot_bin: &Path,
    copilot_args: &[String],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
) -> u8 {
    use std::os::unix::process::CommandExt as _;

    let mut cmd = Command::new(copilot_bin);

    configure_command(
        &mut cmd,
        copilot_args,
        &sandbox.project_dir,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        sandbox.scratch_dir.as_deref(),
        sandbox.proxy_port,
    );

    // Apply pre-computed sandbox in the child process, between fork and exec.
    let precomputed = sandbox.precomputed.clone();
    unsafe {
        cmd.pre_exec(move || super::landlock_mod::apply_precomputed(&precomputed));
    }

    spawn_and_wait(&mut cmd)
}
