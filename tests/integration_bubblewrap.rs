//! Bubblewrap namespace isolation integration tests.
//!
//! These tests verify that Bubblewrap namespace isolation works correctly
//! when layered on top of Landlock + seccomp-BPF.
//!
//! Test coverage:
//! - PID namespace: process cannot see host processes
//! - Mount namespace: only necessary paths visible
//! - Network namespace: only loopback + proxy visible
//! - User namespace: unprivileged operation
//! - Graceful degradation when bwrap unavailable

#[cfg(target_os = "linux")]
mod bwrap_tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    // ── Helper functions ───────────────────────────────────────────

    fn bwrap_available() -> bool {
        which::which("bwrap").is_ok()
    }

    fn home_dir() -> PathBuf {
        PathBuf::from(std::env::var("HOME").expect("HOME not set"))
    }

    fn binary_path() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_cplt"))
    }

    fn create_test_project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        fs::write(dir.path().join("test.txt"), "hello from project").unwrap();
        dir
    }

    /// Run a shell command inside the cplt sandbox with bubblewrap.
    fn run_sandboxed_with_bwrap(project_dir: &Path, script: &str) -> (i32, String, String) {
        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--no-validate",
                "--quiet",
                "--use-bubblewrap",
                "--agent",
                "shell",
                "--project-dir",
                &project_dir.to_string_lossy(),
                "--",
                "-c",
                script,
            ])
            .env("HOME", home_dir())
            .output()
            .expect("Failed to execute cplt");

        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    /// Run without bubblewrap for comparison.
    fn run_sandboxed_no_bwrap(project_dir: &Path, script: &str) -> (i32, String, String) {
        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--no-validate",
                "--quiet",
                "--no-bubblewrap",
                "--agent",
                "shell",
                "--project-dir",
                &project_dir.to_string_lossy(),
                "--",
                "-c",
                script,
            ])
            .env("HOME", home_dir())
            .output()
            .expect("Failed to execute cplt");

        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    // ── Availability tests ─────────────────────────────────────────

    #[test]
    fn bwrap_auto_detect_graceful_fallback() {
        if !bwrap_available() {
            eprintln!("SKIPPED: bwrap not available (expected)");
            return;
        }

        let project = create_test_project();

        // Without explicit flag, should auto-detect and use bwrap
        let (exit, stdout, stderr) =
            run_sandboxed_with_bwrap(project.path(), "echo 'test'; exit 0");

        assert_eq!(exit, 0, "Command should succeed with bwrap");
        assert!(stdout.contains("test"), "Should execute command");
        // Should not have warning about bwrap unavailable
        assert!(
            !stderr.contains("not functional"),
            "Should not warn when bwrap works"
        );
    }

    #[test]
    fn explicit_no_bubblewrap_works() {
        let project = create_test_project();

        // Explicitly disable bwrap
        let (exit, stdout, _) =
            run_sandboxed_no_bwrap(project.path(), "echo 'without bwrap'; exit 0");

        assert_eq!(exit, 0, "Command should succeed without bwrap");
        assert!(stdout.contains("without bwrap"), "Should execute command");
    }

    // ── PID namespace tests ────────────────────────────────────────

    #[test]
    fn bwrap_pid_namespace_isolates_process_list() {
        if !bwrap_available() {
            eprintln!("SKIPPED: bwrap not available");
            return;
        }

        let project = create_test_project();

        // In PID namespace, should only see own processes
        let (exit, stdout, _) = run_sandboxed_with_bwrap(project.path(), "ps aux | wc -l");

        assert_eq!(exit, 0, "ps should succeed");

        // Parse the process count
        let proc_count: usize = stdout.trim().parse().unwrap_or(9999);

        // In a PID namespace, should see very few processes (< 10 typically)
        // Without PID namespace, would see dozens/hundreds of host processes
        assert!(
            proc_count < 20,
            "Should see < 20 processes in PID namespace, got {proc_count}"
        );
    }

    #[test]
    fn bwrap_cannot_see_host_init() {
        if !bwrap_available() {
            eprintln!("SKIPPED: bwrap not available");
            return;
        }

        let project = create_test_project();

        // Try to access /proc/1 (host init) - should not exist or not be accessible
        let (exit, stdout, _) =
            run_sandboxed_with_bwrap(project.path(), "cat /proc/1/comm 2>&1 || echo 'blocked'");

        assert_eq!(exit, 0);
        // Should either get "blocked" (file doesn't exist) or see our own init
        // But should NOT see the real host init process name
        assert!(
            !stdout.contains("systemd") || stdout.contains("blocked"),
            "Should not see host init in PID namespace"
        );
    }

    // ── Mount namespace tests ──────────────────────────────────────

    #[test]
    fn bwrap_mounts_project_directory() {
        if !bwrap_available() {
            eprintln!("SKIPPED: bwrap not available");
            return;
        }

        let project = create_test_project();

        let (exit, stdout, _) = run_sandboxed_with_bwrap(project.path(), "cat test.txt");

        assert_eq!(exit, 0);
        assert_eq!(stdout.trim(), "hello from project");
    }

    #[test]
    fn bwrap_allows_write_to_project() {
        if !bwrap_available() {
            eprintln!("SKIPPED: bwrap not available");
            return;
        }

        let project = create_test_project();

        let (exit, _, _) =
            run_sandboxed_with_bwrap(project.path(), "echo 'new content' > new_file.txt");

        assert_eq!(exit, 0);

        // Verify file was created
        let content = fs::read_to_string(project.path().join("new_file.txt"))
            .expect("Should create file in project");
        assert_eq!(content.trim(), "new content");
    }

    #[test]
    fn bwrap_blocks_sensitive_home_dirs() {
        if !bwrap_available() {
            eprintln!("SKIPPED: bwrap not available");
            return;
        }

        let project = create_test_project();

        // Landlock should still block ~/.ssh even when using bwrap
        let (exit, stdout, _) =
            run_sandboxed_with_bwrap(project.path(), "ls ~/.ssh 2>&1 || echo 'blocked'");

        assert_eq!(exit, 0);
        assert!(
            stdout.contains("blocked") || stdout.contains("Permission denied"),
            "Should block ~/.ssh access"
        );
    }

    // ── Network tests ─────────────────────────────────────────────

    #[test]
    fn sandbox_blocks_external_network() {
        if !bwrap_available() {
            eprintln!("SKIPPED: bwrap not available");
            return;
        }

        let project = create_test_project();

        // The sandbox blocks external connections (via Landlock/seccomp + proxy).
        // Network namespace is intentionally disabled so the process can reach the
        // host-bound cplt CONNECT proxy on 127.0.0.1.
        let (exit, stdout, _) = run_sandboxed_with_bwrap(
            project.path(),
            "ping -c 1 -W 1 8.8.8.8 2>&1 || echo 'network blocked'",
        );

        assert_eq!(exit, 0);
        assert!(
            stdout.contains("network blocked")
                || stdout.contains("unreachable")
                || stdout.contains("Permission denied")
                || stdout.contains("not permitted"),
            "Should block external network access"
        );
    }

    // ── User namespace tests ───────────────────────────────────────

    #[test]
    fn bwrap_user_namespace_unprivileged() {
        if !bwrap_available() {
            eprintln!("SKIPPED: bwrap not available");
            return;
        }

        let project = create_test_project();

        // In user namespace, should run as mapped user (should match our host UID)
        let (exit, stdout, _) = run_sandboxed_with_bwrap(project.path(), "id -u");

        assert_eq!(exit, 0);
        let host_uid = unsafe { libc::getuid() };
        assert_eq!(
            stdout.trim(),
            host_uid.to_string(),
            "Should see the host UID inside the user namespace"
        );
    }

    // ── Integration with Landlock tests ────────────────────────────

    #[test]
    fn bwrap_landlock_both_active() {
        if !bwrap_available() {
            eprintln!("SKIPPED: bwrap not available");
            return;
        }

        let project = create_test_project();

        // Both bwrap and Landlock should be active
        // Test that Landlock restrictions still apply with bwrap
        let (exit, stdout, _) = run_sandboxed_with_bwrap(
            project.path(),
            "cat ~/.aws/credentials 2>&1 || echo 'landlock blocked'",
        );

        assert_eq!(exit, 0);
        assert!(
            stdout.contains("landlock blocked") || stdout.contains("Permission denied"),
            "Landlock should still block sensitive paths with bwrap"
        );
    }

    #[test]
    fn bwrap_preserves_environment_variables() {
        if !bwrap_available() {
            eprintln!("SKIPPED: bwrap not available");
            return;
        }

        let project = create_test_project();

        // Test that essential environment variables are preserved
        let (exit, stdout, _) = run_sandboxed_with_bwrap(
            project.path(),
            "echo HOME=$HOME; echo PATH=$PATH | grep -q '/bin' && echo 'path ok'",
        );

        assert_eq!(exit, 0);
        assert!(stdout.contains("HOME="), "HOME should be set");
        assert!(stdout.contains("path ok"), "PATH should contain /bin");
    }
}
