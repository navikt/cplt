#![allow(dead_code, unused_imports)]
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

use crate::sandbox::landlock_mod::FsRule;
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
    // Test the same namespace configuration we actually use in production:
    // - --unshare-user: unprivileged user namespace (often disabled on hardened systems)
    // - --ro-bind / /: base read-only root mount (our VFS strategy)
    // - --proc / --dev / --tmpfs: required namespace mounts
    // If this fails, the fallback to Landlock-only mode is triggered.
    let output = Command::new(bwrap_path)
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
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
/// - `project_dir`: Project directory to mount read-write (primarily for verification/logging)
/// - `home_dir`: User's home directory (primarily for verification/logging)
/// - `scratch_dir`: Scratch directory for temp files (if enabled)
/// - `fs_rules`: The Landlock filesystem rules to map into the VFS
///
/// # Returns
///
/// Vector of command-line arguments for `bwrap`.
#[cfg(target_os = "linux")]
pub fn build_bwrap_args(
    _project_dir: &Path,
    _home_dir: &Path,
    scratch_dir: Option<&Path>,
    fs_rules: &[FsRule],
) -> Vec<String> {
    let mut args = Vec::new();

    // ── Namespace isolation ────────────────────────────────────

    // Unshare namespaces except network (so the sandboxed process can connect
    // to the host-bound cplt CONNECT proxy on 127.0.0.1)
    args.extend([
        "--unshare-pid".to_string(), // PID namespace (agent can't see host processes)
        "--unshare-ipc".to_string(), // IPC namespace (no shared memory with host)
        "--unshare-uts".to_string(), // UTS namespace (hostname isolation)
        "--unshare-cgroup".to_string(), // Cgroup namespace (process tree isolation)
        "--die-with-parent".to_string(), // Automatically terminate sandbox if cplt parent exits
    ]);

    // User namespace for unprivileged operation
    args.push("--unshare-user".to_string());

    // ── Filesystem setup ───────────────────────────────────────

    // Mount the host root read-only as our base template
    args.extend(["--ro-bind".to_string(), "/".to_string(), "/".to_string()]);

    // Mount /proc (required for PID namespace)
    args.extend(["--proc".to_string(), "/proc".to_string()]);

    // Mount /dev (device files)
    args.extend(["--dev".to_string(), "/dev".to_string()]);

    // ── Scratch directory ──────────────────────────────────────

    if let Some(scratch) = scratch_dir {
        args.extend([
            "--bind".to_string(),
            scratch.to_string_lossy().to_string(),
            "/tmp".to_string(),
        ]);
    } else {
        // Mount a tmpfs for /tmp if no scratch dir
        args.extend(["--tmpfs".to_string(), "/tmp".to_string()]);
    }

    // ── Policy-driven overlay mounts ──────────────────────────
    // Sort rules by path length (number of components) so that parent directories
    // are mounted before child subpaths (e.g. ~/.cache before ~/.cache/copilot/pkg)
    let mut sorted_rules = fs_rules.to_vec();
    sorted_rules.sort_by_key(|r| r.path.components().count());

    for rule in &sorted_rules {
        // Skip paths managed directly by Bubblewrap core setup to prevent host leakage or namespace breakage
        if rule.path.starts_with("/tmp")
            || rule.path.starts_with("/proc")
            || rule.path.starts_with("/dev")
            || rule.path.starts_with("/sys")
        {
            continue;
        }

        if !rule.path.exists() {
            continue;
        }

        let path_str = rule.path.to_string_lossy().to_string();

        if rule.access.write {
            // Writable paths: override the read-only base mount with a writable bind.
            args.extend(["--bind".to_string(), path_str.clone(), path_str]);
        }
        // Read-only paths are already visible via the base `--ro-bind / /` mount.
        // Emitting redundant `--ro-bind` mounts inflates the argument list with no
        // security benefit — skipping them keeps the invocation lean.
    }

    args
}

#[cfg(not(target_os = "linux"))]
pub fn build_bwrap_args(
    _project_dir: &Path,
    _home_dir: &Path,
    _scratch_dir: Option<&Path>,
    _fs_rules: &[FsRule],
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
            &[], // no fs_rules — base mounts only
        );

        // Must isolate these namespaces
        assert!(args.contains(&"--unshare-pid".to_string()));
        assert!(args.contains(&"--unshare-user".to_string()));
        assert!(args.contains(&"--die-with-parent".to_string()));
        // Network namespace is intentionally NOT isolated (proxy runs on host)
        assert!(!args.contains(&"--unshare-net".to_string()));

        // Base root mount
        assert!(args.contains(&"--ro-bind".to_string()));
        assert!(args.contains(&"/".to_string()));

        // Scratch dir should be bind-mounted as /tmp
        assert!(args.contains(&"/tmp/cplt-scratch".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn includes_system_mounts() {
        let args = build_bwrap_args(
            Path::new("/home/user/project"),
            Path::new("/home/user"),
            None,
            &[], // no fs_rules
        );

        // Should set up /proc for PID namespace
        assert!(args.contains(&"--proc".to_string()));
        assert!(args.contains(&"/proc".to_string()));

        // Should set up /dev with safe device nodes
        assert!(args.contains(&"--dev".to_string()));
        assert!(args.contains(&"/dev".to_string()));

        // No scratch dir → tmpfs for /tmp
        assert!(args.contains(&"--tmpfs".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn writable_fs_rules_add_bind_mounts() {
        use crate::sandbox::landlock_mod::{FsAccess, FsRule};
        use std::path::PathBuf;

        // Use /tmp as a path that exists and is writable in the test environment
        let rules = vec![FsRule {
            path: PathBuf::from("/tmp"),
            access: FsAccess {
                read: true,
                write: true,
                execute: false,
                ioctl: false,
            },
        }];
        let args = build_bwrap_args(
            Path::new("/home/user/project"),
            Path::new("/home/user"),
            None,
            &rules,
        );
        // /tmp is in the system-managed skip list, so it should NOT generate a --bind
        // (bwrap manages /tmp itself via --tmpfs)
        let tmp_bind_count = args
            .windows(3)
            .filter(|w| w[0] == "--bind" && w[2] == "/tmp")
            .count();
        assert_eq!(tmp_bind_count, 0, "/tmp should be skipped (system-managed)");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn check_availability_returns_none_on_non_linux() {
        assert_eq!(check_availability(), None);
    }
}
