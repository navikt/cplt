//! Bubblewrap namespace isolation for Linux.
//!
//! # Purpose
//!
//! Adds defense-in-depth namespace isolation on top of Landlock + seccomp-BPF:
//! - **PID namespace**: Agent cannot see or signal host processes
//! - **Mount namespace**: Only necessary paths visible, everything else invisible
//! - **Network namespace**: Only loopback + proxy port visible (enforces proxy routing)
//! - **User namespace**: Unprivileged operation (no root needed)
//!
//! # Design
//!
//! Bubblewrap (`bwrap`) is invoked as a wrapper around the sandboxed process.
//! The execution flow becomes:
//!
//! ```text
//! cplt → bwrap → copilot (with Landlock+seccomp applied via pre_exec)
//! ```
//!
//! Bwrap sets up namespaces and filesystem mounts, then execs the copilot binary.
//! The Landlock+seccomp layer is still applied in the pre_exec hook (after bwrap's
//! setup but before the final exec), providing multiple layers of defense.
//!
//! # Graceful degradation
//!
//! If `bwrap` is not available or namespace creation fails, the sandbox falls back
//! to Landlock+seccomp only. This ensures cplt works on systems without Bubblewrap.
//!
//! # Configuration
//!
//! Controlled by the `use_bubblewrap` option in `SandboxConfig`:
//! - `Some(true)`: Always use bwrap (fail if unavailable)
//! - `Some(false)`: Never use bwrap
//! - `None` (default): Auto-detect and use if available

use std::path::{Path, PathBuf};
use std::process::Command;

/// Check if bubblewrap is available on this system.
///
/// Returns the path to the `bwrap` binary if found in PATH.
#[cfg(target_os = "linux")]
pub fn check_availability() -> Option<PathBuf> {
    which::which("bwrap").ok()
}

/// Non-Linux platforms don't support bubblewrap.
#[cfg(not(target_os = "linux"))]
pub fn check_availability() -> Option<PathBuf> {
    None
}

/// Test if bubblewrap actually works by running a minimal sandbox.
///
/// Returns `Ok(())` if bwrap can create namespaces, `Err(msg)` otherwise.
/// This catches systems where bwrap exists but namespaces are disabled.
#[cfg(target_os = "linux")]
pub fn test_functionality(bwrap_path: &Path) -> Result<(), String> {
    let output = Command::new(bwrap_path)
        .args([
            "--unshare-all",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "/bin/true",
        ])
        .output()
        .map_err(|e| format!("Failed to spawn bwrap test: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "bwrap test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn test_functionality(_bwrap_path: &Path) -> Result<(), String> {
    Err("Bubblewrap not supported on this platform".to_string())
}

/// Build the bwrap command arguments for namespace isolation.
///
/// # Arguments
///
/// - `project_dir`: Project directory to mount read-write
/// - `home_dir`: User's home directory
/// - `scratch_dir`: Scratch directory for temp files (if enabled)
/// - `proxy_port`: Proxy port for network isolation (if enabled)
/// - `extra_read`: Additional directories to mount read-only
/// - `extra_write`: Additional directories to mount read-write
/// - `agent_dirs`: Agent-specific directories to mount
///
/// # Returns
///
/// Vector of command-line arguments for `bwrap`.
#[cfg(target_os = "linux")]
pub fn build_bwrap_args(
    project_dir: &Path,
    home_dir: &Path,
    scratch_dir: Option<&Path>,
    extra_read: &[PathBuf],
    extra_write: &[PathBuf],
) -> Vec<String> {
    let mut args = Vec::new();

    // ── Namespace isolation ────────────────────────────────────

    // Unshare all namespaces except user (we'll do that separately)
    args.extend([
        "--unshare-pid".to_string(), // PID namespace (agent can't see host processes)
        "--unshare-net".to_string(), // Network namespace (only loopback available)
        "--unshare-ipc".to_string(), // IPC namespace (no shared memory with host)
        "--unshare-uts".to_string(), // UTS namespace (hostname isolation)
        "--unshare-cgroup".to_string(), // Cgroup namespace (process tree isolation)
    ]);

    // User namespace for unprivileged operation
    args.extend([
        "--unshare-user".to_string(),
        "--uid".to_string(),
        "0".to_string(), // Map to UID 0 inside namespace
        "--gid".to_string(),
        "0".to_string(), // Map to GID 0 inside namespace
    ]);

    // ── Filesystem setup ───────────────────────────────────────

    // Start with empty root filesystem
    args.push("--clearenv".to_string());

    // Mount essential system directories (read-only)
    for sys_dir in ["/usr", "/lib", "/lib64", "/bin", "/sbin"] {
        if Path::new(sys_dir).exists() {
            args.extend([
                "--ro-bind".to_string(),
                sys_dir.to_string(),
                sys_dir.to_string(),
            ]);
        }
    }

    // Mount /etc read-only (needed for DNS, SSL certs, etc.)
    args.extend([
        "--ro-bind".to_string(),
        "/etc".to_string(),
        "/etc".to_string(),
    ]);

    // Mount /proc (required for PID namespace)
    args.extend(["--proc".to_string(), "/proc".to_string()]);

    // Mount /dev (device files)
    args.extend(["--dev".to_string(), "/dev".to_string()]);

    // Mount /sys read-only
    if Path::new("/sys").exists() {
        args.extend([
            "--ro-bind".to_string(),
            "/sys".to_string(),
            "/sys".to_string(),
        ]);
    }

    // ── User home directory ────────────────────────────────────

    // Mount home directory - we'll let Landlock handle fine-grained access control
    // within it, so we just make it available here
    args.extend([
        "--bind".to_string(),
        home_dir.to_string_lossy().to_string(),
        home_dir.to_string_lossy().to_string(),
    ]);

    // ── Project directory ──────────────────────────────────────

    // Mount project directory read-write
    args.extend([
        "--bind".to_string(),
        project_dir.to_string_lossy().to_string(),
        project_dir.to_string_lossy().to_string(),
    ]);

    // ── Scratch directory ──────────────────────────────────────

    if let Some(scratch) = scratch_dir {
        args.extend([
            "--bind".to_string(),
            scratch.to_string_lossy().to_string(),
            scratch.to_string_lossy().to_string(),
        ]);
    }

    // Mount a tmpfs for /tmp if no scratch dir
    if scratch_dir.is_none() {
        args.extend(["--tmpfs".to_string(), "/tmp".to_string()]);
    }

    // ── Extra read/write paths ─────────────────────────────────

    for path in extra_read {
        if path.exists() {
            args.extend([
                "--ro-bind".to_string(),
                path.to_string_lossy().to_string(),
                path.to_string_lossy().to_string(),
            ]);
        }
    }

    for path in extra_write {
        if path.exists() {
            args.extend([
                "--bind".to_string(),
                path.to_string_lossy().to_string(),
                path.to_string_lossy().to_string(),
            ]);
        }
    }

    // ── Network configuration ──────────────────────────────────

    // With --unshare-net, only loopback is available
    // The proxy will be bound to 127.0.0.1 and accessible
    // All other network access is blocked at the kernel level

    args
}

#[cfg(not(target_os = "linux"))]
pub fn build_bwrap_args(
    _project_dir: &Path,
    _home_dir: &Path,
    _scratch_dir: Option<&Path>,
    _extra_read: &[PathBuf],
    _extra_write: &[PathBuf],
) -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn builds_basic_bwrap_args() {
        let args = build_bwrap_args(
            Path::new("/home/user/project"),
            Path::new("/home/user"),
            Some(Path::new("/tmp/cplt-scratch")),
            &[],
            &[],
        );

        // Should have namespace isolation flags
        assert!(args.contains(&"--unshare-pid".to_string()));
        assert!(args.contains(&"--unshare-net".to_string()));
        assert!(args.contains(&"--unshare-user".to_string()));

        // Should mount project dir
        assert!(args.contains(&"--bind".to_string()));
        assert!(args.contains(&"/home/user/project".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn includes_system_mounts() {
        let args = build_bwrap_args(
            Path::new("/home/user/project"),
            Path::new("/home/user"),
            None,
            &[],
            &[],
        );

        // Should have /proc
        assert!(args.contains(&"--proc".to_string()));
        assert!(args.contains(&"/proc".to_string()));

        // Should have /dev
        assert!(args.contains(&"--dev".to_string()));
        assert!(args.contains(&"/dev".to_string()));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn check_availability_returns_none_on_non_linux() {
        assert_eq!(check_availability(), None);
    }
}
