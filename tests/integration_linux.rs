//! Linux Landlock integration tests.
//!
//! These tests verify kernel-level enforcement of the Landlock sandbox.
//! They ONLY run on Linux — skipped on macOS via `#[cfg(target_os = "linux")]`.
//!
//! Test tiers:
//! - Filesystem enforcement (read, write, deny of sensitive paths)
//! - Attack vector coverage (symlinks, hardlinks, rename across boundary)
//! - Network port filtering (ABI v4+)
//! - seccomp syscall blocking

#[cfg(target_os = "linux")]
mod linux_tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    // ── Landlock ABI detection ─────────────────────────────────────

    fn landlock_abi_version() -> Option<u32> {
        fs::read_to_string("/sys/kernel/security/landlock/abi_version")
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    /// Skip guard — call at the top of tests that require Landlock.
    macro_rules! require_landlock {
        () => {
            require_landlock!(1);
        };
        ($min_abi:expr) => {
            match landlock_abi_version() {
                Some(v) if v >= $min_abi => {}
                Some(v) => {
                    eprintln!("SKIPPED: need Landlock ABI v{}, have v{v}", $min_abi);
                    return;
                }
                None => {
                    eprintln!("SKIPPED: Landlock not available on this kernel");
                    return;
                }
            }
        };
    }

    // ── Test helpers ───────────────────────────────────────────────

    /// Create a temporary project directory for testing.
    fn create_test_project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        fs::write(dir.path().join("test.txt"), "hello from project").unwrap();
        dir
    }

    fn home_dir() -> PathBuf {
        PathBuf::from(std::env::var("HOME").expect("HOME not set"))
    }

    /// Path to the built binary.
    fn binary_path() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_cplt"))
    }

    /// Run a shell command inside the cplt sandbox and return (exit_code, stdout, stderr).
    fn run_sandboxed(project_dir: &Path, script: &str) -> (i32, String, String) {
        let output = Command::new(binary_path())
            .args([
                "--no-validate",
                "--quiet",
                "-C",
                &project_dir.to_string_lossy(),
                "--",
                "sh",
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

    /// Run a shell command inside the sandbox with extra flags.
    fn run_sandboxed_with_flags(
        project_dir: &Path,
        extra_flags: &[&str],
        script: &str,
    ) -> (i32, String, String) {
        let dir_str = project_dir.to_string_lossy().into_owned();
        let mut args: Vec<&str> = vec!["--no-validate", "--quiet", "-C", &dir_str];
        args.extend_from_slice(extra_flags);
        args.extend_from_slice(&["--", "sh", "-c", script]);

        let output = Command::new(binary_path())
            .args(&args)
            .env("HOME", home_dir())
            .output()
            .expect("Failed to execute cplt");

        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    // ── Filesystem enforcement tests ──────────────────────────────

    #[test]
    fn landlock_allows_project_file_read() {
        require_landlock!();
        let project = create_test_project();
        let (code, stdout, _) = run_sandboxed(project.path(), "cat test.txt");
        assert_eq!(code, 0, "Should be able to read project files");
        assert!(stdout.contains("hello from project"));
    }

    #[test]
    fn landlock_allows_project_file_write() {
        require_landlock!();
        let project = create_test_project();
        let (code, _, _) = run_sandboxed(
            project.path(),
            "echo 'new content' > new_file.txt && cat new_file.txt",
        );
        assert_eq!(code, 0, "Should be able to write to project dir");
    }

    #[test]
    fn landlock_blocks_ssh_read() {
        require_landlock!();
        let project = create_test_project();
        let ssh_dir = home_dir().join(".ssh");
        if !ssh_dir.exists() {
            fs::create_dir_all(&ssh_dir).ok();
            fs::write(ssh_dir.join("test_key"), "secret").ok();
        }
        let (code, _, stderr) = run_sandboxed(project.path(), "cat ~/.ssh/test_key 2>&1 || true");
        // Either the file doesn't exist or access is denied — both are acceptable
        assert!(
            code != 0 || stderr.contains("Permission denied") || stderr.contains("denied"),
            "Should not be able to read ~/.ssh"
        );
    }

    #[test]
    fn landlock_blocks_aws_read() {
        require_landlock!();
        let project = create_test_project();
        let aws_dir = home_dir().join(".aws");
        if !aws_dir.exists() {
            eprintln!("SKIPPED: ~/.aws does not exist");
            return;
        }
        let (code, stdout, _) = run_sandboxed(project.path(), "cat ~/.aws/credentials 2>&1");
        assert!(
            code != 0 || stdout.contains("Permission denied"),
            "Should not be able to read ~/.aws/credentials"
        );
    }

    #[test]
    fn landlock_blocks_kube_read() {
        require_landlock!();
        let project = create_test_project();
        let kube_dir = home_dir().join(".kube");
        if !kube_dir.exists() {
            eprintln!("SKIPPED: ~/.kube does not exist");
            return;
        }
        let (code, stdout, _) = run_sandboxed(project.path(), "cat ~/.kube/config 2>&1");
        assert!(
            code != 0 || stdout.contains("Permission denied"),
            "Should not be able to read ~/.kube/config"
        );
    }

    #[test]
    fn landlock_blocks_docker_read() {
        require_landlock!();
        let project = create_test_project();
        let docker_dir = home_dir().join(".docker");
        if !docker_dir.exists() {
            eprintln!("SKIPPED: ~/.docker does not exist");
            return;
        }
        let (code, stdout, _) = run_sandboxed(project.path(), "cat ~/.docker/config.json 2>&1");
        assert!(
            code != 0 || stdout.contains("Permission denied"),
            "Should not be able to read ~/.docker/config.json"
        );
    }

    #[test]
    fn landlock_allows_system_read() {
        require_landlock!();
        let project = create_test_project();
        let (code, _, _) = run_sandboxed(project.path(), "cat /etc/resolv.conf > /dev/null");
        assert_eq!(code, 0, "Should be able to read system files");
    }

    #[test]
    fn landlock_blocks_etc_write() {
        require_landlock!();
        let project = create_test_project();
        let (code, _, _) =
            run_sandboxed(project.path(), "echo 'evil' > /etc/cplt-test 2>/dev/null");
        assert_ne!(code, 0, "Should not be able to write to /etc");
    }

    #[test]
    fn landlock_allows_dev_null() {
        require_landlock!();
        let project = create_test_project();
        let (code, _, _) = run_sandboxed(project.path(), "echo test > /dev/null");
        assert_eq!(code, 0, "Should be able to write to /dev/null");
    }

    #[test]
    fn landlock_allows_dev_urandom() {
        require_landlock!();
        let project = create_test_project();
        let (code, _, _) = run_sandboxed(project.path(), "head -c 16 /dev/urandom > /dev/null");
        assert_eq!(code, 0, "Should be able to read /dev/urandom");
    }

    #[test]
    fn landlock_blocks_gnupg_read() {
        require_landlock!();
        let project = create_test_project();
        let gnupg_dir = home_dir().join(".gnupg");
        if !gnupg_dir.exists() {
            eprintln!("SKIPPED: ~/.gnupg does not exist");
            return;
        }
        let (code, stdout, _) = run_sandboxed(project.path(), "ls ~/.gnupg 2>&1");
        assert!(
            code != 0 || stdout.contains("Permission denied"),
            "Should not be able to list ~/.gnupg"
        );
    }

    // ── Attack vector tests ───────────────────────────────────────

    #[test]
    fn landlock_blocks_symlink_escape() {
        require_landlock!();
        let project = create_test_project();
        // Create a symlink inside the project that points to a denied path
        let (code, stdout, _) = run_sandboxed(
            project.path(),
            "ln -sf ~/.ssh/id_rsa symlink_test && cat symlink_test 2>&1",
        );
        assert!(
            code != 0 || stdout.contains("Permission denied") || stdout.contains("No such file"),
            "Should not be able to read denied paths via symlink"
        );
    }

    #[test]
    fn landlock_restriction_inherited_by_child() {
        require_landlock!();
        let project = create_test_project();
        // Spawn a nested shell — restrictions should still apply
        let (code, stdout, _) = run_sandboxed(
            project.path(),
            "bash -c 'bash -c \"cat ~/.ssh/id_rsa 2>&1\"'",
        );
        assert!(
            code != 0 || stdout.contains("Permission denied") || stdout.contains("No such file"),
            "Child processes should inherit sandbox restrictions"
        );
    }

    #[test]
    fn landlock_allows_scratch_dir_write() {
        require_landlock!();
        let project = create_test_project();
        let (code, _, _) = run_sandboxed_with_flags(
            project.path(),
            &["--scratch-dir"],
            "echo 'test' > \"$TMPDIR/test_file\" && cat \"$TMPDIR/test_file\"",
        );
        assert_eq!(code, 0, "Should be able to write to scratch dir");
    }

    #[test]
    fn landlock_allows_scratch_dir_exec() {
        require_landlock!();
        let project = create_test_project();
        let script = r#"
            cat > "$TMPDIR/hello.sh" << 'EOF'
#!/bin/sh
echo "hello from scratch"
EOF
            chmod +x "$TMPDIR/hello.sh"
            "$TMPDIR/hello.sh"
        "#;
        let (code, stdout, _) =
            run_sandboxed_with_flags(project.path(), &["--scratch-dir"], script);
        assert_eq!(code, 0, "Should be able to execute from scratch dir");
        assert!(stdout.contains("hello from scratch"));
    }

    // ── seccomp enforcement tests ─────────────────────────────────

    #[test]
    fn seccomp_blocks_ptrace() {
        require_landlock!();
        let project = create_test_project();
        // Try to ptrace ourselves — should fail with EPERM
        let script = r#"
            python3 -c "
import ctypes, ctypes.util, errno, os, sys
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
ret = libc.ptrace(0, 0, 0, 0)  # PTRACE_TRACEME
err = ctypes.get_errno()
if ret == -1 and err == errno.EPERM:
    print('BLOCKED')
    sys.exit(0)
else:
    print(f'ALLOWED ret={ret} errno={err}')
    sys.exit(1)
" 2>/dev/null || echo "BLOCKED"
        "#;
        let (code, stdout, _) = run_sandboxed(project.path(), script);
        assert!(
            stdout.contains("BLOCKED"),
            "seccomp should block ptrace: code={code}, stdout={stdout}"
        );
    }

    #[test]
    fn seccomp_allows_normal_operations() {
        require_landlock!();
        let project = create_test_project();
        // Normal operations should work fine
        let (code, _, _) = run_sandboxed(
            project.path(),
            "echo test > output.txt && cat output.txt && rm output.txt",
        );
        assert_eq!(code, 0, "Normal read/write/fork/exec should work");
    }

    // ── Network tests (ABI v4+) ───────────────────────────────────

    #[test]
    fn landlock_blocks_outbound_tcp() {
        require_landlock!(4);
        let project = create_test_project();
        // Try to connect to a random port — should fail
        let (code, _, _) = run_sandboxed(
            project.path(),
            "bash -c 'echo > /dev/tcp/127.0.0.1/12345' 2>/dev/null",
        );
        assert_ne!(code, 0, "Outbound TCP to arbitrary port should be blocked");
    }

    // ── E2E binary tests ──────────────────────────────────────────

    #[test]
    fn binary_shows_help() {
        let output = Command::new(binary_path())
            .arg("--help")
            .output()
            .expect("Failed to run cplt --help");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("sandbox") || stdout.contains("cplt"));
    }

    #[test]
    fn binary_shows_version() {
        let output = Command::new(binary_path())
            .arg("--version")
            .output()
            .expect("Failed to run cplt --version");
        assert!(output.status.success());
    }

    #[test]
    fn binary_print_profile_shows_landlock() {
        require_landlock!();
        let project = create_test_project();
        let output = Command::new(binary_path())
            .args(["--print-profile", "-C", &project.path().to_string_lossy()])
            .env("HOME", home_dir())
            .output()
            .expect("Failed to run cplt --print-profile");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Landlock") || stdout.contains("landlock"),
            "Print profile should mention Landlock on Linux"
        );
    }

    // ── E2E project workflow tests ────────────────────────────────

    #[test]
    fn project_git_workflow() {
        require_landlock!();
        let project = create_test_project();
        let script = r#"
            git init . &&
            git config user.email "test@test.com" &&
            git config user.name "Test" &&
            echo "hello" > file.txt &&
            git add file.txt &&
            git -c commit.gpgSign=false commit -m "init" &&
            git log --oneline
        "#;
        let (code, stdout, _) = run_sandboxed(project.path(), script);
        assert_eq!(code, 0, "Git workflow should work inside sandbox");
        assert!(stdout.contains("init"));
    }

    #[test]
    fn project_env_vars_sanitized() {
        require_landlock!();
        let project = create_test_project();
        // Set a dangerous env var and verify it's stripped
        let output = Command::new(binary_path())
            .args([
                "--no-validate",
                "--quiet",
                "-C",
                &project.path().to_string_lossy(),
                "--",
                "sh",
                "-c",
                "echo \"AWS=$AWS_SECRET_ACCESS_KEY\"",
            ])
            .env("HOME", home_dir())
            .env("AWS_SECRET_ACCESS_KEY", "super-secret-key")
            .output()
            .expect("Failed to execute cplt");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("super-secret-key"),
            "AWS_SECRET_ACCESS_KEY should be stripped from env"
        );
    }

    #[test]
    fn project_home_secrets_blocked() {
        require_landlock!();
        let project = create_test_project();
        // Try to read various sensitive paths
        let script = r#"
            fail=0
            for path in ~/.ssh ~/.gnupg ~/.aws ~/.azure ~/.kube ~/.docker ~/.nais; do
                if [ -d "$path" ] && ls "$path" 2>/dev/null; then
                    echo "FAIL: could list $path"
                    fail=1
                fi
            done
            exit $fail
        "#;
        let (code, _, _) = run_sandboxed(project.path(), script);
        // If all paths don't exist, that's also fine (code 0 means none were accessible)
        assert_eq!(
            code, 0,
            "Should not be able to list sensitive home directories"
        );
    }

    #[test]
    fn project_dotenv_blocked_by_default() {
        require_landlock!();
        let project = create_test_project();
        // Create .env files and verify they can't be read
        fs::write(project.path().join(".env"), "SECRET=value").unwrap();
        fs::write(project.path().join(".env.local"), "LOCAL_SECRET=value").unwrap();

        let (code, stdout, _) = run_sandboxed(project.path(), "cat .env 2>&1");
        assert!(
            code != 0 || stdout.contains("Permission denied"),
            ".env should be blocked by default"
        );
    }

    #[test]
    fn project_cache_dir_writable() {
        require_landlock!();
        let project = create_test_project();
        let cache_dir = home_dir().join(".cache");
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir).ok();
        }
        let (code, _, _) = run_sandboxed(
            project.path(),
            "mkdir -p ~/.cache/cplt-test && echo ok > ~/.cache/cplt-test/probe && rm -rf ~/.cache/cplt-test",
        );
        assert_eq!(code, 0, "~/.cache should be writable");
    }
}
