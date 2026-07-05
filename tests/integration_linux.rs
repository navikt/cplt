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
        // Probe via the landlock_create_ruleset syscall (through the lib's
        // check_availability), NOT /sys/kernel/security/landlock/abi_version:
        // securityfs is root-only on GitHub Actions runners, so the file read
        // reports "unavailable" on kernels where Landlock works fine.
        cplt::sandbox::available_abi_version()
    }

    /// When `CPLT_TEST_REQUIRE_SANDBOX=1` is set (CI), a missing sandbox
    /// capability must FAIL the test rather than silently skip. This closes the
    /// gap where a runner regression that disables Landlock/bwrap would leave CI
    /// green because every kernel-enforcement test self-skipped. Default (unset)
    /// behaviour is unchanged for local dev on non-Linux or capability-poor hosts.
    fn require_sandbox_enforced() -> bool {
        std::env::var("CPLT_TEST_REQUIRE_SANDBOX").as_deref() == Ok("1")
    }

    /// Skip guard — call at the top of tests that require Landlock.
    ///
    /// With `CPLT_TEST_REQUIRE_SANDBOX=1` the skip branches panic instead, so a
    /// missing capability turns the job red.
    macro_rules! require_landlock {
        () => {
            require_landlock!(1);
        };
        ($min_abi:expr) => {
            match landlock_abi_version() {
                Some(v) if v >= $min_abi => {}
                Some(v) => {
                    if require_sandbox_enforced() {
                        panic!(
                            "Landlock ABI v{} required by CPLT_TEST_REQUIRE_SANDBOX but only v{v} available",
                            $min_abi
                        );
                    }
                    eprintln!("SKIPPED: need Landlock ABI v{}, have v{v}", $min_abi);
                    return;
                }
                None => {
                    if require_sandbox_enforced() {
                        panic!(
                            "Landlock required by CPLT_TEST_REQUIRE_SANDBOX but unavailable: not present on this kernel"
                        );
                    }
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
            "--project-dir",
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
                "--project-dir",
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
            "--project-dir",
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
                "--project-dir",
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
                "--project-dir",
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
                "--project-dir",
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

    // ── Capability probe matrix (issue #113) ─────────────────────
    //
    // These probes start the real cplt binary with a shell script and assert
    // BOTH directions of a documented guarantee (see SECURITY.md's platform
    // comparison table). They fill gaps left by the tests above: exec-from-/tmp
    // on the default Landlock path, write-outside-project as a positive/negative
    // pair, and exec of a script written into the project tree.

    /// Exec: a freshly written+chmod'd binary in /tmp must NOT run. /tmp carries
    /// a read+write Landlock rule but deliberately no execute (allow_tmp_exec is
    /// off by default), so the exec is kernel-denied even though the write and
    /// chmod succeed. This is the default-path analogue of the bwrap-variant
    /// `bwrap_exec_from_tmp_still_denied`.
    #[test]
    fn landlock_denies_exec_from_tmp() {
        require_landlock!();
        let project = create_test_project();
        let marker = format!("/tmp/cplt-exec-probe-{}", std::process::id());
        let script = format!(
            "cp /bin/true {marker} && chmod +x {marker} && {marker} && echo RAN || echo EXEC_DENIED"
        );
        let (_, stdout, _) = run_sandboxed(project.path(), &script);
        let _ = fs::remove_file(&marker);
        assert!(
            stdout.contains("EXEC_DENIED") && !stdout.contains("RAN"),
            "exec of a binary dropped in /tmp must be Landlock-denied — stdout: {stdout}"
        );
    }

    /// FS positive (exec): a script written into the project tree can be
    /// executed. The project dir carries read+write+execute, so drop-then-run
    /// inside it is allowed — the mirror image of the /tmp denial above.
    #[test]
    fn landlock_allows_exec_in_project() {
        require_landlock!();
        let project = create_test_project();
        let script = r"
            printf '#!/bin/sh\necho ran-in-project\n' > ./probe.sh
            chmod +x ./probe.sh
            ./probe.sh
        ";
        let (code, stdout, stderr) = run_sandboxed(project.path(), script);
        assert_eq!(
            code, 0,
            "exec of a project-local script should work: {stderr}"
        );
        assert!(
            stdout.contains("ran-in-project"),
            "project-local script should run — stdout: {stdout}"
        );
    }

    /// FS negative: writing outside the project and outside every writable rule
    /// (project dir, /tmp, scratch cache subtree) must be kernel-denied. Targets
    /// the real HOME root: a fake HOME from `tempfile::tempdir()` would live
    /// under /tmp, which is writable by design (read+write, non-exec), so it
    /// cannot demonstrate the deny.
    #[test]
    fn landlock_denies_write_outside_project() {
        require_landlock!();
        let project = create_test_project();
        let escape = home_dir().join("cplt-landlock-escape-probe.txt");
        let _ = fs::remove_file(&escape);
        let script = format!(
            "echo escape > '{}' 2>&1 && echo WROTE || echo WRITE_DENIED",
            escape.display()
        );
        let (code, stdout, stderr) = run_sandboxed(project.path(), &script);
        let created = escape.exists();
        let _ = fs::remove_file(&escape);
        assert!(
            stdout.contains("WRITE_DENIED") && !stdout.contains("WROTE"),
            "writing to the HOME root outside the project must be denied — code: {code}, stdout: {stdout}, stderr: {stderr}"
        );
        assert!(
            !created,
            "no file should have been created outside the project"
        );
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
            .args([
                "--print-profile",
                "--project-dir",
                &project.path().to_string_lossy(),
            ])
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
        let (code, stdout, stderr) = run_sandboxed(project.path(), script);
        assert_eq!(
            code, 0,
            "Git workflow should work inside sandbox — stdout: {stdout}, stderr: {stderr}"
        );
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
                "--project-dir",
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
                "--project-dir",
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
    ///
    /// curl is not a sandbox capability but is guaranteed on the CI runner, so
    /// under `CPLT_TEST_REQUIRE_SANDBOX=1` a missing curl fails the job too —
    /// otherwise the proxy-layer tests would silently vanish from coverage.
    macro_rules! require_curl {
        () => {
            if !std::process::Command::new("curl")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                if require_sandbox_enforced() {
                    panic!(
                        "curl required by CPLT_TEST_REQUIRE_SANDBOX but unavailable: not found in PATH"
                    );
                }
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
                "--project-dir",
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
    #[test]
    fn sandboxed_copilot_can_execute_pkg_binary() {
        require_landlock!();
        use std::os::unix::fs::PermissionsExt;

        let project = create_test_project();
        let home = tempfile::tempdir().expect("Failed to create temp home");

        // 1. Create the fake universal copilot pkg extraction dir
        let pkg_dir = home.path().join(".cache/copilot/pkg/universal/1.0.63");
        fs::create_dir_all(&pkg_dir).unwrap();

        // 2. Create the dummy executable (e.g. dummy ripgrep)
        let dummy_rg = pkg_dir.join("rg");
        fs::write(
            &dummy_rg,
            "#!/bin/sh\necho \"dummy_rg executed successfully\"\n",
        )
        .unwrap();
        fs::set_permissions(&dummy_rg, fs::Permissions::from_mode(0o755)).unwrap();

        // 3. Create the fake copilot binary in $PATH (inside project_dir so it gets exec)
        let bin_dir = project.path().join(".fake-bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let fake_copilot = bin_dir.join("copilot");

        let script = format!("#!/bin/sh\n\"{}\"\n", dummy_rg.display());
        fs::write(&fake_copilot, script).unwrap();
        fs::set_permissions(&fake_copilot, fs::Permissions::from_mode(0o755)).unwrap();

        // 4. Run cplt with the fake copilot in PATH
        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.display(), current_path);

        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--no-validate",
                "--quiet",
                "--agent",
                "copilot",
                "--project-dir",
                &project.path().to_string_lossy(),
                "--",
                "--version",
            ])
            .env("HOME", home.path())
            .env("PATH", new_path)
            .output()
            .expect("Failed to execute cplt");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "fake copilot should run successfully without EACCES. stdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("dummy_rg executed successfully"),
            "sandbox should allow execution of binaries in copilot pkg dir. stdout: {stdout}"
        );
    }

    // ── Bubblewrap namespace isolation ─────────────────────────────
    //
    // These tests verify the optional Bubblewrap layer on top of Landlock +
    // seccomp. What bwrap actually provides (and what these tests assert):
    // - pid/ipc/uts/cgroup/user namespaces (host process tree invisible,
    //   unprivileged operation)
    // - full host filesystem visible READ-ONLY inside the mount namespace,
    //   with Landlock still providing the access control (deny-by-default)
    // - the host network is deliberately SHARED (no --unshare-net) so the
    //   agent can reach the host-bound CONNECT proxy on 127.0.0.1
    // - Landlock + seccomp are re-applied inside the namespaces by the cplt
    //   re-entry helper, so kernel access control is never weakened by bwrap

    /// Check if `bwrap` is available. Tests that require it should call this
    /// and return early if false.
    fn bwrap_available() -> bool {
        Command::new("which")
            .arg("bwrap")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Skip guard for tests that need a working bubblewrap.
    ///
    /// With `CPLT_TEST_REQUIRE_SANDBOX=1` a missing bwrap panics instead of
    /// skipping, so an uninstalled bubblewrap (issue #113's root cause) turns
    /// the job red rather than silently passing. Accepts an optional minimum
    /// Landlock ABI, mirroring `require_landlock!`, for net-rule tests.
    macro_rules! require_bwrap {
        () => {
            require_bwrap!(1);
        };
        ($min_abi:expr) => {
            require_landlock!($min_abi);
            if !bwrap_available() {
                if require_sandbox_enforced() {
                    panic!(
                        "Bubblewrap required by CPLT_TEST_REQUIRE_SANDBOX but unavailable: bwrap not found in PATH"
                    );
                }
                eprintln!("SKIPPED: bwrap not available");
                return;
            }
        };
    }

    /// Run inside the sandbox with bubblewrap explicitly enabled.
    fn run_sandboxed_bwrap(project_dir: &Path, script: &str) -> (i32, String, String) {
        run_sandboxed_with_flags(project_dir, &["--use-bubblewrap"], script)
    }

    #[test]
    fn bwrap_auto_detect_default_runs() {
        require_landlock!();
        let project = create_test_project();

        // No bubblewrap flag at all — the true auto-detect default. Must work
        // both when bwrap is available (namespaces active) and when it is not
        // (graceful fallback to Landlock+seccomp only).
        let (exit, stdout, stderr) = run_sandboxed(project.path(), "echo auto-ok");

        assert_eq!(
            exit, 0,
            "auto-detect default must not brick the run: {stderr}"
        );
        assert!(stdout.contains("auto-ok"));
    }

    #[test]
    fn bwrap_explicit_disable_works() {
        require_landlock!();
        let project = create_test_project();

        let (exit, stdout, _) =
            run_sandboxed_with_flags(project.path(), &["--no-bubblewrap"], "echo 'without bwrap'");

        assert_eq!(exit, 0, "Command should succeed without bwrap");
        assert!(stdout.contains("without bwrap"));
    }

    #[test]
    fn bwrap_pid_namespace_isolates_process_list() {
        require_bwrap!();
        let project = create_test_project();

        let (exit, stdout, stderr) = run_sandboxed_bwrap(project.path(), "ps aux | wc -l");
        assert_eq!(exit, 0, "ps should succeed: {stderr}");

        // In a PID namespace only the agent's own tree is visible.
        let proc_count: usize = stdout.trim().parse().unwrap_or(9999);
        assert!(
            proc_count < 20,
            "Should see < 20 processes in PID namespace, got {proc_count}"
        );
    }

    #[test]
    fn bwrap_cannot_see_host_init() {
        require_bwrap!();
        let project = create_test_project();

        let (exit, stdout, _) =
            run_sandboxed_bwrap(project.path(), "cat /proc/1/comm 2>&1 || echo 'blocked'");
        assert_eq!(exit, 0);
        // PID 1 inside the namespace is bwrap/the helper, never the host init.
        assert!(
            !stdout.contains("systemd") || stdout.contains("blocked"),
            "Should not see host init in PID namespace: {stdout}"
        );
    }

    #[test]
    fn bwrap_project_dir_readable_and_writable() {
        require_bwrap!();
        let project = create_test_project();

        let (exit, stdout, stderr) = run_sandboxed_bwrap(
            project.path(),
            "cat test.txt && echo 'new content' > new_file.txt",
        );
        assert_eq!(exit, 0, "project read+write should work: {stderr}");
        assert_eq!(stdout.trim(), "hello from project");

        let content = fs::read_to_string(project.path().join("new_file.txt"))
            .expect("Should create file in project");
        assert_eq!(content.trim(), "new content");
    }

    #[test]
    fn bwrap_project_dir_under_tmp_is_visible() {
        require_bwrap!();

        // Regression (PR #64 review): the namespace shadows /tmp with a fresh
        // tmpfs, so a project dir under /tmp must be explicitly bind-mounted
        // back or it vanishes (cwd falls back to /, all project IO fails).
        let base = tempfile::Builder::new()
            .prefix("cplt-bwrap-tmp-proj")
            .tempdir_in("/tmp")
            .expect("Failed to create project under /tmp");
        fs::write(base.path().join("test.txt"), "hello from tmp project").unwrap();

        let (exit, stdout, stderr) = run_sandboxed_bwrap(
            base.path(),
            "cat test.txt && echo ok > written.txt && cat written.txt",
        );
        assert_eq!(exit, 0, "project under /tmp must stay usable: {stderr}");
        assert!(stdout.contains("hello from tmp project"));
        assert!(stdout.contains("ok"));
        assert!(base.path().join("written.txt").exists());
    }

    #[test]
    fn bwrap_exec_from_tmp_still_denied() {
        require_bwrap!();
        let project = create_test_project();

        // SECURITY: the "exec from /tmp is denied" guarantee must hold with
        // bwrap active. /tmp inside the namespace is a bare tmpfs whose
        // Landlock rule grants no execute — the scratch dir (write+exec) is
        // never overlaid on /tmp.
        let (exit, stdout, _) = run_sandboxed_bwrap(
            project.path(),
            "cp /bin/true /tmp/evil && chmod +x /tmp/evil && /tmp/evil 2>&1 || echo 'exec blocked'",
        );
        assert_eq!(exit, 0);
        assert!(
            stdout.contains("exec blocked") || stdout.contains("Permission denied"),
            "exec from /tmp must be denied under bwrap: {stdout}"
        );
    }

    #[test]
    fn bwrap_landlock_still_blocks_sensitive_paths() {
        require_bwrap!();
        let project = create_test_project();

        // Landlock (applied in-namespace by the re-entry helper) must still
        // deny credential paths even though --ro-bind / / makes them visible
        // in the mount table.
        let (exit, stdout, _) = run_sandboxed_bwrap(
            project.path(),
            "ls ~/.ssh 2>&1 || cat ~/.aws/credentials 2>&1 || echo 'landlock blocked'",
        );
        assert_eq!(exit, 0);
        assert!(
            stdout.contains("landlock blocked") || stdout.contains("Permission denied"),
            "Landlock must still deny sensitive paths with bwrap: {stdout}"
        );
    }

    #[test]
    fn bwrap_user_namespace_maps_host_uid() {
        require_bwrap!();
        let project = create_test_project();

        let (exit, stdout, _) = run_sandboxed_bwrap(project.path(), "id -u");
        assert_eq!(exit, 0);
        let host_uid = unsafe { libc::getuid() };
        assert_eq!(
            stdout.trim(),
            host_uid.to_string(),
            "Should see the host UID inside the user namespace"
        );
    }

    #[test]
    fn bwrap_preserves_environment_variables() {
        require_bwrap!();
        let project = create_test_project();

        let (exit, stdout, _) = run_sandboxed_bwrap(
            project.path(),
            "echo HOME=$HOME; echo PATH=$PATH | grep -q '/bin' && echo 'path ok'",
        );
        assert_eq!(exit, 0);
        assert!(stdout.contains("HOME="), "HOME should be set");
        assert!(stdout.contains("path ok"), "PATH should contain /bin");
    }

    #[test]
    fn bwrap_seccomp_still_blocks_unshare() {
        require_bwrap!();
        let project = create_test_project();

        // seccomp is applied by the re-entry helper inside the namespaces —
        // the agent must not be able to build nested namespaces.
        let (exit, stdout, _) = run_sandboxed_bwrap(
            project.path(),
            "unshare --user true 2>&1 || echo 'unshare blocked'",
        );
        assert_eq!(exit, 0);
        assert!(
            stdout.contains("unshare blocked")
                || stdout.contains("Operation not permitted")
                || stdout.contains("not permitted"),
            "unshare must stay seccomp-blocked inside bwrap: {stdout}"
        );
    }

    // ── Bubblewrap capability probes (issue #113) ─────────────────
    //
    // These complement the bwrap tests above with PLANTED secrets in a fake
    // HOME (the existing `bwrap_landlock_still_blocks_sensitive_paths` uses the
    // real HOME and can pass vacuously) plus the two bwrap-only mount-namespace
    // guarantees not yet asserted: a private /tmp that hides host temp files,
    // and a read-only host filesystem.

    /// Run inside the sandbox with bubblewrap enabled and a custom HOME.
    fn run_sandboxed_home_bwrap(
        project_dir: &Path,
        home: &Path,
        script: &str,
    ) -> (i32, String, String) {
        run_sandboxed_home_with_flags(project_dir, home, &["--use-bubblewrap"], script)
    }

    /// SECURITY (credential confidentiality under bwrap): a real `~/.ssh/id_rsa`
    /// planted in a fake HOME is visible in the read-only mount table (`--ro-bind
    /// / /`) but must be Landlock-denied — bwrap changes topology, not access
    /// control. Non-vacuous because the file genuinely exists.
    #[test]
    fn bwrap_cannot_read_planted_ssh_key() {
        require_bwrap!();
        let project = create_test_project();
        let fake_home = tempfile::tempdir().expect("Failed to create temp home");
        let ssh_dir = fake_home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(
            ssh_dir.join("id_rsa"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();

        let (exit, stdout, _) = run_sandboxed_home_bwrap(
            project.path(),
            fake_home.path(),
            "cat ~/.ssh/id_rsa 2>&1 && echo READ_OK || echo READ_DENIED",
        );
        assert_eq!(exit, 0, "shell wrapper itself should exit cleanly");
        assert!(
            stdout.contains("READ_DENIED") && !stdout.contains("BEGIN OPENSSH"),
            "planted ~/.ssh/id_rsa must stay Landlock-denied under bwrap — stdout: {stdout}"
        );
    }

    /// Same guarantee for a planted `~/.aws/credentials`.
    #[test]
    fn bwrap_cannot_read_planted_aws_credentials() {
        require_bwrap!();
        let project = create_test_project();
        let fake_home = tempfile::tempdir().expect("Failed to create temp home");
        let aws_dir = fake_home.path().join(".aws");
        fs::create_dir_all(&aws_dir).unwrap();
        fs::write(
            aws_dir.join("credentials"),
            "[default]\naws_secret_access_key = PLANTED_SECRET_MUST_NOT_LEAK\n",
        )
        .unwrap();

        let (exit, stdout, _) = run_sandboxed_home_bwrap(
            project.path(),
            fake_home.path(),
            "cat ~/.aws/credentials 2>&1 && echo READ_OK || echo READ_DENIED",
        );
        assert_eq!(exit, 0);
        assert!(
            stdout.contains("READ_DENIED") && !stdout.contains("PLANTED_SECRET"),
            "planted ~/.aws/credentials must stay Landlock-denied under bwrap — stdout: {stdout}"
        );
    }

    /// bwrap mount-namespace property: `/tmp` is a fresh private tmpfs, so a
    /// file created on the HOST `/tmp` before the run is NOT visible inside.
    #[test]
    fn bwrap_private_tmp_hides_host_file() {
        require_bwrap!();
        let project = create_test_project();

        let host_marker = format!("/tmp/cplt-host-marker-{}", std::process::id());
        fs::write(&host_marker, "visible-on-host").unwrap();

        let script = format!("test -e {host_marker} && echo VISIBLE || echo HIDDEN");
        let (exit, stdout, stderr) = run_sandboxed_bwrap(project.path(), &script);
        let _ = fs::remove_file(&host_marker);

        assert_eq!(exit, 0, "probe should run: {stderr}");
        assert!(
            stdout.contains("HIDDEN") && !stdout.contains("VISIBLE"),
            "host /tmp file must not be visible in the private tmpfs — stdout: {stdout}"
        );
    }

    /// bwrap mount-namespace property: the host filesystem is bind-mounted
    /// read-only. A Landlock-allowed system file (`/etc/hosts`) is readable, but
    /// writing it fails — both the `--ro-bind` and the absence of a write rule
    /// enforce this.
    #[test]
    fn bwrap_host_fs_visible_read_only() {
        require_bwrap!();
        let project = create_test_project();

        let (exit, stdout, _) = run_sandboxed_bwrap(
            project.path(),
            "cat /etc/hosts > /dev/null && echo READ_OK; \
             echo x >> /etc/hosts 2>&1 && echo WROTE || echo WRITE_DENIED",
        );
        assert_eq!(exit, 0);
        assert!(
            stdout.contains("READ_OK"),
            "an allowed system file should be readable under bwrap — stdout: {stdout}"
        );
        assert!(
            stdout.contains("WRITE_DENIED") && !stdout.contains("WROTE"),
            "the read-only host fs must reject writes under bwrap — stdout: {stdout}"
        );
    }

    /// Network enforcement is unchanged by bwrap (the net namespace is shared so
    /// the proxy stays reachable; Landlock TCP-connect rules remain the control).
    /// A direct connect to a disallowed port must be kernel-blocked. A live
    /// listener distinguishes "blocked" (EPERM) from "nothing listening"
    /// (ECONNREFUSED).
    #[test]
    fn bwrap_blocks_outbound_tcp() {
        require_bwrap!(4);
        let project = create_test_project();

        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind test listener");
        let port = listener.local_addr().unwrap().port();

        let script =
            format!("bash -c 'echo > /dev/tcp/127.0.0.1/{port}' 2>&1 || echo CONNECT_FAILED");
        let (code, stdout, _) = run_sandboxed_bwrap(project.path(), &script);
        drop(listener);

        assert!(
            code != 0 || stdout.contains("CONNECT_FAILED"),
            "outbound TCP to port {port} must stay Landlock-blocked under bwrap — code: {code}, stdout: {stdout}"
        );
    }
}
