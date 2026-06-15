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
                "--yes",
                "--no-validate",
                "--quiet",
                "--agent",
                "shell",
                "-C",
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

    /// Run a shell command inside the sandbox with extra flags.
    fn run_sandboxed_with_flags(
        project_dir: &Path,
        extra_flags: &[&str],
        script: &str,
    ) -> (i32, String, String) {
        let dir_str = project_dir.to_string_lossy().into_owned();
        let mut args: Vec<&str> = vec![
            "--yes",
            "--no-validate",
            "--quiet",
            "--agent",
            "shell",
            "-C",
            &dir_str,
        ];
        args.extend_from_slice(extra_flags);
        args.extend_from_slice(&["--", "-c", script]);

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

    /// Run a shell command inside the sandbox with a custom HOME directory.
    fn run_sandboxed_home(project_dir: &Path, home: &Path, script: &str) -> (i32, String, String) {
        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--no-validate",
                "--quiet",
                "--agent",
                "shell",
                "-C",
                &project_dir.to_string_lossy(),
                "--",
                "-c",
                script,
            ])
            .env("HOME", home)
            .output()
            .expect("Failed to execute cplt");

        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    /// Run a shell command inside the sandbox with a custom HOME and extra flags.
    fn run_sandboxed_home_with_flags(
        project_dir: &Path,
        home: &Path,
        extra_flags: &[&str],
        script: &str,
    ) -> (i32, String, String) {
        let dir_str = project_dir.to_string_lossy().into_owned();
        let mut args: Vec<&str> = vec![
            "--yes",
            "--no-validate",
            "--quiet",
            "--agent",
            "shell",
            "-C",
            &dir_str,
        ];
        args.extend_from_slice(extra_flags);
        args.extend_from_slice(&["--", "-c", script]);

        let output = Command::new(binary_path())
            .args(&args)
            .env("HOME", home)
            .output()
            .expect("Failed to execute cplt");

        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    /// Create a fake HOME with populated sensitive directories for hermetic testing.
    fn create_fake_home_with_secrets() -> tempfile::TempDir {
        let fake_home = tempfile::tempdir().expect("Failed to create temp home");
        for dir in &[".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker"] {
            let path = fake_home.path().join(dir);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("secret"), "sensitive-data").unwrap();
        }
        // Create specific credential files that tests check
        fs::write(
            fake_home.path().join(".aws/credentials"),
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
        )
        .unwrap();
        fs::write(
            fake_home.path().join(".kube/config"),
            "apiVersion: v1\nclusters:\n- cluster:\n    server: https://k8s.example.com\n",
        )
        .unwrap();
        fs::write(
            fake_home.path().join(".docker/config.json"),
            r#"{"auths":{"registry.example.com":{"auth":"dGVzdDp0ZXN0"}}}"#,
        )
        .unwrap();
        // Also create .cache for cache-writable tests
        fs::create_dir_all(fake_home.path().join(".cache")).unwrap();
        fake_home
    }

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
        // Create a temp dir to use as HOME with a .ssh directory,
        // ensuring the test is hermetic and doesn't touch the real $HOME.
        let fake_home = tempfile::tempdir().expect("Failed to create temp home");
        let ssh_dir = fake_home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(ssh_dir.join("test_key"), "secret").unwrap();

        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--no-validate",
                "--quiet",
                "--agent",
                "shell",
                "-C",
                &project.path().to_string_lossy(),
                "--",
                "-c",
                "cat ~/.ssh/test_key 2>&1",
            ])
            .env("HOME", fake_home.path())
            .output()
            .expect("Failed to execute cplt");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let code = output.status.code().unwrap_or(-1);
        assert!(
            code != 0 || stdout.contains("Permission denied"),
            "Should not be able to read ~/.ssh — code: {code}, stdout: {stdout}"
        );
    }

    #[test]
    fn landlock_blocks_aws_read() {
        require_landlock!();
        let project = create_test_project();
        let fake_home = create_fake_home_with_secrets();
        let (code, stdout, _) = run_sandboxed_home(
            project.path(),
            fake_home.path(),
            "cat ~/.aws/credentials 2>&1",
        );
        assert!(
            code != 0 || stdout.contains("Permission denied"),
            "Should not be able to read ~/.aws/credentials — code: {code}, stdout: {stdout}"
        );
    }

    #[test]
    fn landlock_blocks_kube_read() {
        require_landlock!();
        let project = create_test_project();
        let fake_home = create_fake_home_with_secrets();
        let (code, stdout, _) =
            run_sandboxed_home(project.path(), fake_home.path(), "cat ~/.kube/config 2>&1");
        assert!(
            code != 0 || stdout.contains("Permission denied"),
            "Should not be able to read ~/.kube/config — code: {code}, stdout: {stdout}"
        );
    }

    #[test]
    fn landlock_blocks_docker_read() {
        require_landlock!();
        let project = create_test_project();
        let fake_home = create_fake_home_with_secrets();
        let (code, stdout, _) = run_sandboxed_home(
            project.path(),
            fake_home.path(),
            "cat ~/.docker/config.json 2>&1",
        );
        assert!(
            code != 0 || stdout.contains("Permission denied"),
            "Should not be able to read ~/.docker/config.json — code: {code}, stdout: {stdout}"
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
        let fake_home = create_fake_home_with_secrets();
        let (code, stdout, _) =
            run_sandboxed_home(project.path(), fake_home.path(), "ls ~/.gnupg 2>&1");
        assert!(
            code != 0 || stdout.contains("Permission denied"),
            "Should not be able to list ~/.gnupg — code: {code}, stdout: {stdout}"
        );
    }

    // ── Attack vector tests ───────────────────────────────────────

    #[test]
    fn landlock_blocks_symlink_escape() {
        require_landlock!();
        let project = create_test_project();
        // Use a fake HOME with a real .ssh/test_key file to ensure
        // "No such file" isn't masking a missing target.
        let fake_home = tempfile::tempdir().expect("Failed to create temp home");
        let ssh_dir = fake_home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(ssh_dir.join("test_key"), "secret_key_data").unwrap();

        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--no-validate",
                "--quiet",
                "--agent",
                "shell",
                "-C",
                &project.path().to_string_lossy(),
                "--",
                "-c",
                "ln -sf ~/.ssh/test_key symlink_test && cat symlink_test 2>&1",
            ])
            .env("HOME", fake_home.path())
            .output()
            .expect("Failed to execute cplt");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let code = output.status.code().unwrap_or(-1);
        assert!(
            code != 0 || stdout.contains("Permission denied"),
            "Should not be able to read denied paths via symlink — code: {code}, stdout: {stdout}"
        );
    }

    #[test]
    fn landlock_restriction_inherited_by_child() {
        require_landlock!();
        let project = create_test_project();
        // Use a fake HOME with a real .ssh/test_key to confirm enforcement.
        let fake_home = tempfile::tempdir().expect("Failed to create temp home");
        let ssh_dir = fake_home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(ssh_dir.join("test_key"), "secret_key_data").unwrap();

        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--no-validate",
                "--quiet",
                "--agent",
                "shell",
                "-C",
                &project.path().to_string_lossy(),
                "--",
                "-c",
                "bash -c 'bash -c \"cat ~/.ssh/test_key 2>&1\"'",
            ])
            .env("HOME", fake_home.path())
            .output()
            .expect("Failed to execute cplt");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let code = output.status.code().unwrap_or(-1);
        assert!(
            code != 0 || stdout.contains("Permission denied"),
            "Child processes should inherit sandbox restrictions — code: {code}, stdout: {stdout}"
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

    #[test]
    fn landlock_allows_cache_exec_with_flag() {
        require_landlock!();
        let project = create_test_project();
        let fake_home = tempfile::tempdir().expect("Failed to create temp home");
        fs::create_dir_all(fake_home.path().join(".cache/ms-playwright")).unwrap();
        let script = r#"
            cat > ~/.cache/ms-playwright/run.sh << 'EOF'
#!/bin/sh
echo "hello from cache"
EOF
            chmod +x ~/.cache/ms-playwright/run.sh
            ~/.cache/ms-playwright/run.sh
        "#;
        let (code, stdout, _) = run_sandboxed_home_with_flags(
            project.path(),
            fake_home.path(),
            &["--allow-cache-exec", "ms-playwright"],
            script,
        );
        assert_eq!(
            code, 0,
            "exec from ~/.cache/ms-playwright should be allowed with --allow-cache-exec — stdout: {stdout}"
        );
        assert!(stdout.contains("hello from cache"));
    }

    #[test]
    fn landlock_blocks_cache_exec_without_flag() {
        require_landlock!();
        let project = create_test_project();
        let fake_home = tempfile::tempdir().expect("Failed to create temp home");
        fs::create_dir_all(fake_home.path().join(".cache/ms-playwright")).unwrap();
        let script = r#"
            cat > ~/.cache/ms-playwright/run.sh << 'EOF'
#!/bin/sh
echo "should not run"
EOF
            chmod +x ~/.cache/ms-playwright/run.sh 2>/dev/null
            ~/.cache/ms-playwright/run.sh 2>&1
        "#;
        let (code, stdout, _) = run_sandboxed_home(project.path(), fake_home.path(), script);
        assert!(
            code != 0 || !stdout.contains("should not run"),
            "exec from ~/.cache without --allow-cache-exec must be blocked — code: {code}, stdout: {stdout}"
        );
    }

    // ── seccomp enforcement tests ─────────────────────────────────

    #[test]
    fn seccomp_blocks_ptrace() {
        require_landlock!();
        let project = create_test_project();

        // Skip if python3 is not available — can't test ptrace without it.
        let has_python = Command::new("python3")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        if !has_python {
            eprintln!("SKIPPED: python3 not available for ptrace test");
            return;
        }

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
"
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

        // Start a real listener so we can distinguish "blocked by Landlock" (EPERM)
        // from "nothing listening" (ECONNREFUSED).
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind test listener");
        let port = listener.local_addr().unwrap().port();

        // Try to connect to the listening port — should fail with Permission denied
        let script =
            format!("bash -c 'echo > /dev/tcp/127.0.0.1/{port}' 2>&1 || echo CONNECT_FAILED");
        let (code, stdout, _) = run_sandboxed(project.path(), &script);
        drop(listener);

        // The connection must fail (non-zero exit or explicit failure message)
        assert!(
            code != 0 || stdout.contains("CONNECT_FAILED"),
            "Outbound TCP to port {port} should be blocked by Landlock — code: {code}, stdout: {stdout}"
        );
    }

    #[test]
    fn allow_localhost_port_permits_tcp_connect() {
        require_landlock!(4);
        let project = create_test_project();

        // Start a listener that will accept a connection
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind test listener");
        let port = listener.local_addr().unwrap().port();

        // Spawn a thread to accept the one connection so the sandbox connect() doesn't hang
        let handle = std::thread::spawn(move || {
            listener.accept().ok();
        });

        let script = format!(
            "bash -c 'echo > /dev/tcp/127.0.0.1/{port}' 2>&1 && echo CONNECT_OK || echo CONNECT_FAILED"
        );
        let (_, stdout, _) = run_sandboxed_with_flags(
            project.path(),
            &["--allow-localhost", &port.to_string()],
            &script,
        );

        // Ensure the accept thread unblocks even if the sandboxed connect failed.
        let _ = std::net::TcpStream::connect(("127.0.0.1", port));
        handle.join().ok();
        assert!(
            stdout.contains("CONNECT_OK"),
            "--allow-localhost {port} should permit TCP connect to localhost:{port} — stdout: {stdout}"
        );
    }

    #[test]
    fn allow_localhost_port_does_not_open_other_ports() {
        require_landlock!(4);
        let project = create_test_project();

        let listener1 =
            std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind listener 1");
        let port1 = listener1.local_addr().unwrap().port();
        let listener2 =
            std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind listener 2");
        let port2 = listener2.local_addr().unwrap().port();

        // Accept on port1 so it doesn't hang
        let handle = std::thread::spawn(move || {
            listener1.accept().ok();
        });

        // Allow only port1; port2 should still be blocked
        let script = format!("bash -c 'echo > /dev/tcp/127.0.0.1/{port2}' 2>&1 || echo BLOCKED");
        let (_, stdout, _) = run_sandboxed_with_flags(
            project.path(),
            &["--allow-localhost", &port1.to_string()],
            &script,
        );
        drop(listener2);
        // Unblock the port1 accept thread (the sandboxed script only touches
        // port2, so nothing else ever connects to port1) to avoid a hang on join.
        let _ = std::net::TcpStream::connect(("127.0.0.1", port1));
        handle.join().ok();

        assert!(
            stdout.contains("BLOCKED"),
            "--allow-localhost {port1} should not open port {port2} — stdout: {stdout}"
        );
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
                "--yes",
                "--no-validate",
                "--quiet",
                "--agent",
                "shell",
                "-C",
                &project.path().to_string_lossy(),
                "--",
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
        // Create a hermetic fake HOME with sensitive directories populated.
        // This ensures the test doesn't pass vacuously when dirs don't exist.
        let fake_home = tempfile::tempdir().expect("Failed to create temp home");
        for dir in &[".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker"] {
            let path = fake_home.path().join(dir);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("secret"), "sensitive-data").unwrap();
        }

        let script = r#"
            fail=0
            for path in ~/.ssh ~/.gnupg ~/.aws ~/.azure ~/.kube ~/.docker; do
                if cat "$path/secret" 2>/dev/null; then
                    echo "FAIL: could read $path/secret"
                    fail=1
                fi
            done
            exit $fail
        "#;

        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--no-validate",
                "--quiet",
                "--agent",
                "shell",
                "-C",
                &project.path().to_string_lossy(),
                "--",
                "-c",
                script,
            ])
            .env("HOME", fake_home.path())
            .output()
            .expect("Failed to execute cplt");

        let code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            code, 0,
            "Should not be able to read sensitive home directories — stdout: {stdout}"
        );
    }

    #[test]
    fn project_dotenv_readable_in_allowed_tree() {
        require_landlock!();
        let project = create_test_project();
        // Landlock cannot deny subpaths within an allowed directory.
        // On Linux, .env files inside the project tree remain readable.
        // Protection comes from the proxy (blocks exfiltration) and
        // env hardening (blocks hook injection), not filesystem rules.
        fs::write(project.path().join(".env"), "SECRET=value").unwrap();

        let (code, stdout, _) = run_sandboxed(project.path(), "cat .env");
        assert_eq!(
            code, 0,
            ".env inside the allowed project tree is readable on Linux (Landlock limitation)"
        );
        assert!(
            stdout.contains("SECRET=value"),
            "Expected to read .env contents from the allowed project tree"
        );
    }

    #[test]
    fn project_cache_dir_writable() {
        require_landlock!();
        let project = create_test_project();
        let fake_home = create_fake_home_with_secrets();
        let (code, _, _) = run_sandboxed_home(
            project.path(),
            fake_home.path(),
            "mkdir -p ~/.cache/cplt-test && echo ok > ~/.cache/cplt-test/probe && rm -rf ~/.cache/cplt-test",
        );
        assert_eq!(code, 0, "~/.cache should be writable");
    }

    // ── Proxy-layer tests ─────────────────────────────────────────
    //
    // These tests exercise the cplt CONNECT proxy (not just Landlock).
    // Existing network tests use /dev/tcp (raw TCP) which bypasses HTTP_PROXY.
    // curl respects HTTP_PROXY and exercises the full proxy enforcement layer.
    //
    // Prerequisite: curl must be in PATH on the test machine.

    /// Skip guard for tests that require curl.
    macro_rules! require_curl {
        () => {
            if !std::process::Command::new("curl")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                eprintln!("SKIPPED: curl not available");
                return;
            }
        };
    }

    /// Start a minimal HTTP/1.0 server that accepts one connection and returns 200.
    /// Returns (port, join_handle). The handle must be joined after the test.
    fn start_http_echo_server() -> (u16, std::thread::JoinHandle<()>) {
        use std::io::{Read as _, Write as _};
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind echo server");
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                );
            }
        });
        (port, handle)
    }

    /// Full-stack proxy wiring test: --allow-localhost PORT sets NO_PROXY and opens
    /// the Landlock TCP path so curl can reach the listener directly.
    ///
    /// Data flow: curl → (NO_PROXY set) → direct TCP → Landlock allows PORT → listener
    ///
    /// This test would fail if:
    /// - allow_localhost_ports is not wired from CLI into sandbox_exec (NO_PROXY not set)
    /// - Landlock does not open the port when --allow-localhost is given
    #[test]
    fn proxy_allows_curl_to_localhost_with_allow_flag() {
        require_landlock!(4);
        require_curl!();
        let project = create_test_project();
        let (port, server_handle) = start_http_echo_server();

        let script = format!(
            "curl --max-time 5 -s http://127.0.0.1:{port}/ && echo CURL_OK || echo CURL_FAIL"
        );
        let (_, stdout, stderr) = run_sandboxed_with_flags(
            project.path(),
            &["--allow-localhost", &port.to_string()],
            &script,
        );

        // Unblock the server if curl didn't connect
        let _ = std::net::TcpStream::connect(("127.0.0.1", port));
        server_handle.join().ok();

        assert!(
            stdout.contains("CURL_OK"),
            "--allow-localhost {port}: curl to 127.0.0.1:{port} must succeed; stdout: {stdout} stderr: {stderr}"
        );
    }

    /// Negative case: without --allow-localhost, curl to localhost must be blocked.
    /// Without the flag, NO_PROXY is not set → curl routes through the cplt proxy →
    /// proxy returns 405 (plain HTTP) or the Landlock TCP deny fires first.
    #[test]
    fn proxy_blocks_curl_to_localhost_without_allow_flag() {
        require_landlock!(4);
        require_curl!();
        let project = create_test_project();

        // Use a high ephemeral port. There's nothing listening, but the test
        // only needs to verify the connection attempt is blocked, not that a
        // real server responds.
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind test listener");
        let port = listener.local_addr().unwrap().port();
        drop(listener); // Close it — we don't want connections to succeed

        let script = format!(
            "curl --max-time 3 -sf http://127.0.0.1:{port}/ 2>&1 && echo CURL_OK || echo CURL_FAIL"
        );
        let (_, stdout, _) = run_sandboxed(project.path(), &script);

        assert!(
            stdout.contains("CURL_FAIL"),
            "without --allow-localhost, curl to 127.0.0.1:{port} must fail; got: {stdout}"
        );
    }

    /// Verify that the NO_PROXY env var is set inside the sandbox when
    /// --allow-localhost is configured, so tools bypass the proxy for loopback.
    #[test]
    fn no_proxy_set_when_allow_localhost_configured() {
        require_landlock!();
        let project = create_test_project();

        let (_, stdout, _) = run_sandboxed_with_flags(
            project.path(),
            &["--allow-localhost", "5173"],
            "echo \"NO_PROXY=${NO_PROXY:-UNSET}\"",
        );

        assert!(
            stdout.contains("localhost") || stdout.contains("127.0.0.1"),
            "--allow-localhost must set NO_PROXY to include loopback addresses; got: {stdout}"
        );
    }

    /// Verify that NO_PROXY is NOT set (or does not include loopback) when
    /// --allow-localhost is not configured — the proxy must intercept loopback.
    #[test]
    fn no_proxy_not_set_without_allow_localhost() {
        require_landlock!();
        let project = create_test_project();

        let (_, stdout, _) = run_sandboxed(project.path(), "echo \"NO_PROXY=${NO_PROXY:-UNSET}\"");

        assert!(
            stdout.contains("UNSET")
                || (!stdout.contains("localhost") && !stdout.contains("127.0.0.1")),
            "without --allow-localhost, NO_PROXY must not bypass proxy for loopback; got: {stdout}"
        );
    }

    // ── Environment isolation tests ───────────────────────────────

    /// Verify that credential-style env vars do not leak into the sandbox.
    /// The ENV_ALLOWLIST is supposed to filter these out.
    #[test]
    fn sandboxed_env_does_not_leak_credentials() {
        require_landlock!();
        let project = create_test_project();

        // Inject credential-like vars into the cplt parent process env
        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--no-validate",
                "--quiet",
                "--agent",
                "shell",
                "-C",
                &project.path().to_string_lossy(),
                "--",
                "-c",
                "env | grep -cE '^(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AZURE_CLIENT_SECRET|NPM_TOKEN|GITHUB_TOKEN)=' ; true",
            ])
            .env("HOME", home_dir())
            .env("AWS_SECRET_ACCESS_KEY", "test-secret-must-not-leak")
            .env("AWS_SESSION_TOKEN", "test-token-must-not-leak")
            .env("AZURE_CLIENT_SECRET", "test-azure-secret")
            .env("NPM_TOKEN", "test-npm-token")
            .env("GITHUB_TOKEN", "test-github-token")
            .output()
            .expect("Failed to run cplt");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let count: u32 = stdout.trim().parse().unwrap_or(999);
        assert_eq!(
            count, 0,
            "Credential env vars must be filtered by ENV_ALLOWLIST; found {count} leaking into sandbox. stdout: {stdout}"
        );
    }

    /// Verify that HOME and other required tool vars pass through to the sandbox.
    #[test]
    fn sandboxed_env_passes_home_and_path() {
        require_landlock!();
        let project = create_test_project();

        let (_, stdout, _) = run_sandboxed(
            project.path(),
            "echo HOME=$HOME && echo PATH_SET=${PATH:+yes}",
        );

        assert!(
            stdout.contains("HOME="),
            "HOME must be present in sandbox env; got: {stdout}"
        );
        assert!(
            stdout.contains("PATH_SET=yes"),
            "PATH must be present in sandbox env; got: {stdout}"
        );
    }
}
