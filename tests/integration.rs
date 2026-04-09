//! Integration tests for cplt.
//!
//! These tests invoke sandbox-exec and verify kernel-level enforcement.
//! They ONLY run on macOS — skipped on Linux/CI via #[cfg(target_os = "macos")].

#[cfg(target_os = "macos")]
mod macos_tests {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Path to the built binary.
    fn binary_path() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_cplt"))
    }

    fn home_dir() -> PathBuf {
        let home = std::env::var("HOME").unwrap();
        fs::canonicalize(&home).unwrap()
    }

    /// Generate a unique temp profile path per test invocation.
    fn unique_profile_path() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("cplt-test-{}-{id}.sb", std::process::id()))
    }

    /// Generate a minimal sandbox profile for testing, write to temp, return path.
    fn write_test_profile(project_dir: &str, deny_network: bool) -> PathBuf {
        let home = home_dir();
        let home_str = home.to_string_lossy();

        let mut profile = String::new();
        use std::fmt::Write;

        writeln!(profile, "(version 1)").unwrap();
        writeln!(profile, "(deny default)").unwrap();
        writeln!(
            profile,
            "(import \"/System/Library/Sandbox/Profiles/bsd.sb\")"
        )
        .unwrap();
        writeln!(profile, "(allow process-exec)").unwrap();
        writeln!(profile, "(allow process-fork)").unwrap();

        // Project dir
        writeln!(profile, "(allow file-read* (subpath \"{project_dir}\"))").unwrap();
        writeln!(profile, "(allow file-write* (subpath \"{project_dir}\"))").unwrap();

        // Copilot config
        writeln!(
            profile,
            "(allow file-read* (subpath \"{home_str}/.copilot\"))"
        )
        .unwrap();
        writeln!(
            profile,
            "(allow file-read* (literal \"{home_str}/.gitconfig\"))"
        )
        .unwrap();

        // Tools
        for dir in &["/usr/local", "/opt/homebrew"] {
            writeln!(profile, "(allow file-read* (subpath \"{dir}\"))").unwrap();
            writeln!(profile, "(allow file-map-executable (subpath \"{dir}\"))").unwrap();
        }

        // System config
        writeln!(profile, "(allow file-read* (subpath \"/private/etc/ssl\"))").unwrap();
        writeln!(
            profile,
            "(allow file-read* (literal \"/private/etc/resolv.conf\"))"
        )
        .unwrap();
        writeln!(
            profile,
            "(allow file-read* (literal \"/private/etc/hosts\"))"
        )
        .unwrap();

        // Temp
        for dir in &["/private/tmp", "/private/var/folders"] {
            writeln!(profile, "(allow file-read* (subpath \"{dir}\"))").unwrap();
            writeln!(profile, "(allow file-write* (subpath \"{dir}\"))").unwrap();
        }

        // Deny sensitive dirs (AFTER allows so they override)
        for dir in &[".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker"] {
            writeln!(profile, "(deny file-read* (subpath \"{home_str}/{dir}\"))").unwrap();
            writeln!(profile, "(deny file-write* (subpath \"{home_str}/{dir}\"))").unwrap();
        }

        // Network
        if deny_network {
            writeln!(profile, "(deny network*)").unwrap();
            writeln!(
                profile,
                "(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))"
            )
            .unwrap();
        }

        let path = unique_profile_path();
        fs::write(&path, &profile).unwrap();
        path
    }

    /// Run a shell command inside the sandbox and return (combined output, success).
    fn run_sandboxed(profile_path: &PathBuf, shell_cmd: &str) -> (String, bool) {
        let output = Command::new("sandbox-exec")
            .arg("-f")
            .arg(profile_path)
            .arg("/bin/bash")
            .arg("-c")
            .arg(shell_cmd)
            .output()
            .expect("failed to run sandbox-exec");

        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        (combined, output.status.success())
    }

    // ============================================================
    // File system isolation tests
    // ============================================================

    #[test]
    fn sandbox_allows_project_file_read() {
        let project = fs::canonicalize(".").unwrap();
        let profile = write_test_profile(&project.to_string_lossy(), false);

        let (output, success) = run_sandboxed(&profile, "cat Cargo.toml | head -1");
        fs::remove_file(&profile).ok();
        assert!(success, "should be able to read project files");
        assert!(
            output.contains("[package]"),
            "should see Cargo.toml content, got: {output}"
        );
    }

    #[test]
    fn sandbox_allows_project_file_write() {
        let project = fs::canonicalize(".").unwrap();
        let profile = write_test_profile(&project.to_string_lossy(), false);

        let test_file = project.join("test-sandbox-write.tmp");
        let cmd = format!(
            "echo 'sandbox-test' > '{}' && cat '{}'",
            test_file.display(),
            test_file.display()
        );
        let (output, success) = run_sandboxed(&profile, &cmd);
        fs::remove_file(&test_file).ok();
        fs::remove_file(&profile).ok();
        assert!(success, "should be able to write project files");
        assert!(output.contains("sandbox-test"));
    }

    #[test]
    fn sandbox_blocks_ssh_read() {
        let home = home_dir();
        let ssh_dir = home.join(".ssh");
        if !ssh_dir.exists() {
            eprintln!("Skipping: ~/.ssh does not exist");
            return;
        }

        let project = fs::canonicalize(".").unwrap();
        let profile = write_test_profile(&project.to_string_lossy(), false);

        let cmd = format!("ls '{}' 2>&1; echo EXIT:$?", ssh_dir.display());
        let (output, _) = run_sandboxed(&profile, &cmd);
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "~/.ssh should be blocked by sandbox, got: {output}"
        );
    }

    #[test]
    fn sandbox_blocks_kube_read() {
        let home = home_dir();
        let kube_dir = home.join(".kube");
        if !kube_dir.exists() {
            eprintln!("Skipping: ~/.kube does not exist");
            return;
        }

        let project = fs::canonicalize(".").unwrap();
        let profile = write_test_profile(&project.to_string_lossy(), false);

        let cmd = format!("ls '{}' 2>&1; echo EXIT:$?", kube_dir.display());
        let (output, _) = run_sandboxed(&profile, &cmd);
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "~/.kube should be blocked by sandbox, got: {output}"
        );
    }

    #[test]
    fn sandbox_blocks_docker_read() {
        let home = home_dir();
        let docker_dir = home.join(".docker");
        if !docker_dir.exists() {
            eprintln!("Skipping: ~/.docker does not exist");
            return;
        }

        let project = fs::canonicalize(".").unwrap();
        let profile = write_test_profile(&project.to_string_lossy(), false);

        let cmd = format!("ls '{}' 2>&1; echo EXIT:$?", docker_dir.display());
        let (output, _) = run_sandboxed(&profile, &cmd);
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "~/.docker should be blocked by sandbox, got: {output}"
        );
    }

    #[test]
    fn sandbox_blocks_aws_read() {
        let home = home_dir();
        let aws_dir = home.join(".aws");
        if !aws_dir.exists() {
            eprintln!("Skipping: ~/.aws does not exist");
            return;
        }

        let project = fs::canonicalize(".").unwrap();
        let profile = write_test_profile(&project.to_string_lossy(), false);

        let cmd = format!("ls '{}' 2>&1; echo EXIT:$?", aws_dir.display());
        let (output, _) = run_sandboxed(&profile, &cmd);
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "~/.aws should be blocked by sandbox, got: {output}"
        );
    }

    #[test]
    fn sandbox_allows_copilot_config() {
        let home = home_dir();
        let copilot_dir = home.join(".copilot");
        if !copilot_dir.exists() {
            eprintln!("Skipping: ~/.copilot does not exist");
            return;
        }

        let project = fs::canonicalize(".").unwrap();
        let profile = write_test_profile(&project.to_string_lossy(), false);

        let cmd = format!("ls '{}' 2>&1 | head -3", copilot_dir.display());
        let (output, success) = run_sandboxed(&profile, &cmd);
        fs::remove_file(&profile).ok();
        assert!(success, "~/.copilot should be accessible, got: {output}");
        assert!(
            !output.contains("Operation not permitted"),
            "~/.copilot should not be blocked"
        );
    }

    // ============================================================
    // Network isolation tests
    // ============================================================

    #[test]
    fn sandbox_blocks_outbound_network() {
        let project = fs::canonicalize(".").unwrap();
        let profile = write_test_profile(&project.to_string_lossy(), true);

        // Use bash /dev/tcp to avoid curl dependency
        let cmd = "exec 3<>/dev/tcp/1.1.1.1/80 2>&1; echo EXIT:$?";
        let (output, _) = run_sandboxed(&profile, cmd);
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted")
                || output.contains("Connection refused")
                || output.contains("EXIT:1"),
            "external network should be blocked, got: {output}"
        );
    }

    #[test]
    fn sandbox_allows_process_execution() {
        let project = fs::canonicalize(".").unwrap();
        let profile = write_test_profile(&project.to_string_lossy(), false);

        let (output, success) = run_sandboxed(&profile, "whoami");
        fs::remove_file(&profile).ok();
        assert!(success, "should be able to run whoami");
        assert!(!output.trim().is_empty(), "whoami should return a username");
    }

    #[test]
    fn sandbox_allows_temp_write() {
        let project = fs::canonicalize(".").unwrap();
        let profile = write_test_profile(&project.to_string_lossy(), false);

        let test_file = format!("/tmp/cplt-integ-{}.txt", std::process::id());
        let cmd = format!("echo test > '{test_file}' && cat '{test_file}' && rm '{test_file}'");
        let (output, success) = run_sandboxed(&profile, &cmd);
        fs::remove_file(&profile).ok();
        assert!(success, "should be able to write to /tmp");
        assert!(output.contains("test"));
    }

    // ============================================================
    // Binary CLI tests
    // ============================================================

    #[test]
    fn binary_shows_help() {
        let output = Command::new(binary_path())
            .arg("--help")
            .output()
            .expect("binary should exist");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success());
        assert!(stdout.contains("cplt"));
        assert!(stdout.contains("--with-proxy"));
    }

    #[test]
    fn binary_shows_version() {
        let output = Command::new(binary_path())
            .arg("--version")
            .output()
            .expect("binary should exist");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success());
        assert!(stdout.contains("cplt"));
    }

    #[test]
    fn binary_rejects_root_project_dir() {
        let output = Command::new(binary_path())
            .args(["--project-dir", "/", "--no-validate", "--", "--version"])
            .output()
            .expect("binary should exist");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "should reject / as project dir");
        assert!(
            stderr.contains("too broad"),
            "error should mention 'too broad', got: {stderr}"
        );
    }

    #[test]
    fn binary_rejects_home_project_dir() {
        let home = std::env::var("HOME").unwrap();
        let output = Command::new(binary_path())
            .args(["--project-dir", &home, "--no-validate", "--", "--version"])
            .output()
            .expect("binary should exist");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "should reject $HOME as project dir"
        );
        assert!(
            stderr.contains("too broad"),
            "error should mention 'too broad', got: {stderr}"
        );
    }
}
