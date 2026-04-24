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

    /// Check if sandbox-exec can apply a trivial profile.
    /// Returns false when running inside an existing sandbox (nested sandbox-exec is denied).
    fn sandbox_exec_available() -> bool {
        Command::new("sandbox-exec")
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Skip guard — call at the top of tests that invoke sandbox-exec.
    macro_rules! require_sandbox {
        () => {
            if !sandbox_exec_available() {
                eprintln!("SKIPPED: sandbox-exec not available (likely already sandboxed)");
                return;
            }
        };
    }

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
        require_sandbox!();
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
        require_sandbox!();
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
        require_sandbox!();
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
        require_sandbox!();
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
        require_sandbox!();
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
        require_sandbox!();
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
        require_sandbox!();
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
        require_sandbox!();
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
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let profile = write_test_profile(&project.to_string_lossy(), false);

        let (output, success) = run_sandboxed(&profile, "whoami");
        fs::remove_file(&profile).ok();
        assert!(success, "should be able to run whoami");
        assert!(!output.trim().is_empty(), "whoami should return a username");
    }

    #[test]
    fn sandbox_allows_temp_write() {
        require_sandbox!();
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
    // Real-profile integration tests
    //
    // These use generate_profile() to produce the REAL shipped profile,
    // then verify kernel enforcement via sandbox-exec. This tests the
    // full pipeline: profile generation → SBPL → kernel enforcement.
    // ============================================================

    use cplt::sandbox::{ProfileOptions, generate_profile};

    /// Write a real cplt-generated profile to a temp file.
    fn write_real_profile(opts: &ProfileOptions) -> PathBuf {
        let profile = generate_profile(opts);
        let path = unique_profile_path();
        fs::write(&path, &profile).unwrap();
        path
    }

    /// Default ProfileOptions pointing at the given project/home dirs.
    fn default_opts<'a>(
        project: &'a std::path::Path,
        home: &'a std::path::Path,
    ) -> ProfileOptions<'a> {
        ProfileOptions {
            project_dir: project,
            home_dir: home,
            extra_read: &[],
            extra_write: &[],
            extra_deny: &[],
            existing_home_tool_dirs: None,
            extra_ports: &[],
            localhost_ports: &[],
            proxy_port: None,
            allow_env_files: false,
            allow_localhost_any: false,
            scratch_dir: None,
            allow_tmp_exec: false,
            copilot_install_dir: None,
            git_hooks_path: None,
            allow_gpg_signing: false,
            allow_jvm_attach: false,
            electron_app_dir: None,
        }
    }

    // ── Git persistence prevention ────────────────────────────────

    #[test]
    fn real_profile_blocks_git_hooks_write() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let tmp = project.join(format!(".cplt-git-test-{}", std::process::id()));
        fs::create_dir_all(tmp.join(".git/hooks")).unwrap();
        let tmp = fs::canonicalize(&tmp).unwrap();
        let home = home_dir();

        let opts = default_opts(&tmp, &home);
        let profile = write_real_profile(&opts);

        let hook_path = tmp.join(".git/hooks/post-checkout");
        let cmd = format!(
            "echo '#!/bin/sh' > '{}' 2>&1; echo EXIT:$?",
            hook_path.display()
        );
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_dir_all(&tmp).ok();
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "writing to .git/hooks should be blocked, got: {output}"
        );
    }

    #[test]
    fn real_profile_blocks_git_config_write() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let tmp = project.join(format!(".cplt-gitcfg-{}", std::process::id()));
        fs::create_dir_all(tmp.join(".git")).unwrap();
        fs::write(tmp.join(".git/config"), "[core]\n").unwrap();
        let tmp = fs::canonicalize(&tmp).unwrap();
        let home = home_dir();

        let opts = default_opts(&tmp, &home);
        let profile = write_real_profile(&opts);

        let config_path = tmp.join(".git/config");
        let cmd = format!(
            "echo 'injected' >> '{}' 2>&1; echo EXIT:$?",
            config_path.display()
        );
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_dir_all(&tmp).ok();
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "writing to .git/config should be blocked, got: {output}"
        );
    }

    #[test]
    fn real_profile_blocks_gitmodules_write() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let tmp = project.join(format!(".cplt-gitmod-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join(".gitmodules"), "").unwrap();
        let tmp = fs::canonicalize(&tmp).unwrap();
        let home = home_dir();

        let opts = default_opts(&tmp, &home);
        let profile = write_real_profile(&opts);

        let gitmod_path = tmp.join(".gitmodules");
        let cmd = format!(
            "echo 'injected' >> '{}' 2>&1; echo EXIT:$?",
            gitmod_path.display()
        );
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_dir_all(&tmp).ok();
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "writing to .gitmodules should be blocked, got: {output}"
        );
    }

    // ── Temp exec denial (write-then-exec attack) ─────────────────

    #[test]
    fn real_profile_blocks_tmp_exec() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        // Write a real executable to /tmp, then try to exec it directly.
        // This tests the process-exec deny, not interpreter-based exec.
        let bin_path = format!("/tmp/cplt-exec-test-{}", std::process::id());
        let cmd = format!(
            "cp /usr/bin/true '{bin_path}' && chmod +x '{bin_path}' && '{bin_path}' 2>&1; echo EXIT:$?"
        );
        let (output, _) = run_sandboxed(&profile, &cmd);

        // Cleanup (may fail if write was denied too, that's fine)
        let cleanup_profile = write_test_profile(&project.to_string_lossy(), false);
        run_sandboxed(&cleanup_profile, &format!("rm -f '{bin_path}'"));
        fs::remove_file(&cleanup_profile).ok();
        fs::remove_file(&profile).ok();

        assert!(
            output.contains("Operation not permitted")
                || output.contains("Killed")
                || output.contains("EXIT:1"),
            "executing binary from /tmp should be blocked, got: {output}"
        );
    }

    #[test]
    fn real_profile_allow_tmp_exec_permits_execution() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let mut opts = default_opts(&project, &home);
        opts.allow_tmp_exec = true;
        let profile = write_real_profile(&opts);

        let bin_path = format!("/tmp/cplt-exec-allow-{}", std::process::id());
        let cmd = format!(
            "cp /usr/bin/true '{bin_path}' && chmod +x '{bin_path}' && '{bin_path}' && echo EXEC_OK"
        );
        let (output, success) = run_sandboxed(&profile, &cmd);

        // Cleanup
        let cleanup_profile = write_test_profile(&project.to_string_lossy(), false);
        run_sandboxed(&cleanup_profile, &format!("rm -f '{bin_path}'"));
        fs::remove_file(&cleanup_profile).ok();
        fs::remove_file(&profile).ok();

        assert!(
            success && output.contains("EXEC_OK"),
            "with allow_tmp_exec, executing from /tmp should work, got: {output}"
        );
    }

    // ── Scratch dir ───────────────────────────────────────────────

    #[test]
    fn real_profile_scratch_dir_allows_exec() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let scratch = std::env::temp_dir().join(format!("cplt-scratch-{}", std::process::id()));
        fs::create_dir_all(&scratch).unwrap();
        let scratch = fs::canonicalize(&scratch).unwrap();

        let mut opts = default_opts(&project, &home);
        opts.scratch_dir = Some(&scratch);
        let profile = write_real_profile(&opts);

        let bin_path = scratch.join("test-exec");
        let cmd = format!(
            "cp /usr/bin/true '{}' && chmod +x '{}' && '{}' && echo SCRATCH_EXEC_OK",
            bin_path.display(),
            bin_path.display(),
            bin_path.display()
        );
        let (output, success) = run_sandboxed(&profile, &cmd);

        fs::remove_dir_all(&scratch).ok();
        fs::remove_file(&profile).ok();
        assert!(
            success && output.contains("SCRATCH_EXEC_OK"),
            "scratch dir should allow exec, got: {output}"
        );
    }

    // ── Copilot pkg write denial ──────────────────────────────────

    #[test]
    fn real_profile_blocks_copilot_pkg_write() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let copilot_pkg = home.join(".copilot/pkg");
        if !copilot_pkg.exists() {
            eprintln!("Skipping: ~/.copilot/pkg does not exist");
            return;
        }

        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        let test_file = copilot_pkg.join(format!("cplt-write-test-{}.tmp", std::process::id()));
        let cmd = format!(
            "echo 'malicious' > '{}' 2>&1; echo EXIT:$?",
            test_file.display()
        );
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_file(&test_file).ok(); // cleanup if it somehow succeeded
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "writing to ~/.copilot/pkg should be blocked, got: {output}"
        );
    }

    // ── .env file read denial ─────────────────────────────────────

    #[test]
    fn real_profile_blocks_env_file_read() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let tmp = project.join(format!(".cplt-envtest-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join(".env"), "SECRET=hunter2\n").unwrap();
        let tmp = fs::canonicalize(&tmp).unwrap();
        let home = home_dir();

        let opts = default_opts(&tmp, &home);
        let profile = write_real_profile(&opts);

        let env_path = tmp.join(".env");
        let cmd = format!("cat '{}' 2>&1; echo EXIT:$?", env_path.display());
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_dir_all(&tmp).ok();
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            ".env read should be blocked by default, got: {output}"
        );
    }

    #[test]
    fn real_profile_allows_env_file_when_opted_in() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let tmp = project.join(format!(".cplt-envallow-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join(".env"), "SECRET=hunter2\n").unwrap();
        let tmp = fs::canonicalize(&tmp).unwrap();
        let home = home_dir();

        let mut opts = default_opts(&tmp, &home);
        opts.allow_env_files = true;
        let profile = write_real_profile(&opts);

        let env_path = tmp.join(".env");
        let cmd = format!("cat '{}'", env_path.display());
        let (output, success) = run_sandboxed(&profile, &cmd);

        fs::remove_dir_all(&tmp).ok();
        fs::remove_file(&profile).ok();
        assert!(
            success && output.contains("SECRET=hunter2"),
            "with allow_env_files, .env should be readable, got: {output}"
        );
    }

    // ── Denied files (not just dirs) ──────────────────────────────

    #[test]
    fn real_profile_blocks_netrc_read() {
        require_sandbox!();
        let home = home_dir();
        let netrc = home.join(".netrc");
        if !netrc.exists() {
            eprintln!("Skipping: ~/.netrc does not exist");
            return;
        }

        let project = fs::canonicalize(".").unwrap();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        let cmd = format!("cat '{}' 2>&1; echo EXIT:$?", netrc.display());
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "~/.netrc should be blocked, got: {output}"
        );
    }

    #[test]
    fn real_profile_blocks_npmrc_read() {
        require_sandbox!();
        let home = home_dir();
        let npmrc = home.join(".npmrc");
        if !npmrc.exists() {
            eprintln!("Skipping: ~/.npmrc does not exist");
            return;
        }

        let project = fs::canonicalize(".").unwrap();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        let cmd = format!("cat '{}' 2>&1; echo EXIT:$?", npmrc.display());
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "~/.npmrc should be blocked, got: {output}"
        );
    }

    // ── GPG signing ─────────────────────────────────────────────

    #[test]
    fn real_profile_blocks_gnupg_by_default() {
        require_sandbox!();
        let home = home_dir();
        let gnupg = home.join(".gnupg");
        if !gnupg.exists() {
            eprintln!("Skipping: ~/.gnupg does not exist");
            return;
        }

        let project = fs::canonicalize(".").unwrap();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        let cmd = format!("ls '{}' 2>&1; echo EXIT:$?", gnupg.display());
        let (output, _) = run_sandboxed(&profile, &cmd);
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "~/.gnupg should be blocked by default, got: {output}"
        );
    }

    #[test]
    fn real_profile_gpg_signing_allows_pubring_read() {
        require_sandbox!();
        let home = home_dir();
        let pubring = home.join(".gnupg/pubring.kbx");
        if !pubring.exists() {
            eprintln!("Skipping: ~/.gnupg/pubring.kbx does not exist");
            return;
        }

        let project = fs::canonicalize(".").unwrap();
        let mut opts = default_opts(&project, &home);
        opts.allow_gpg_signing = true;
        let profile = write_real_profile(&opts);

        // Should be able to read pubring.kbx (it's a binary file, just check exit code)
        let cmd = format!(
            "cat '{}' > /dev/null 2>&1 && echo READ_OK || echo READ_FAIL",
            pubring.display()
        );
        let (output, _) = run_sandboxed(&profile, &cmd);
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("READ_OK"),
            "with allow_gpg_signing, pubring.kbx should be readable, got: {output}"
        );
    }

    #[test]
    fn real_profile_gpg_signing_blocks_private_keys() {
        require_sandbox!();
        let home = home_dir();
        let privdir = home.join(".gnupg/private-keys-v1.d");
        if !privdir.exists() {
            eprintln!("Skipping: ~/.gnupg/private-keys-v1.d does not exist");
            return;
        }

        let project = fs::canonicalize(".").unwrap();
        let mut opts = default_opts(&project, &home);
        opts.allow_gpg_signing = true;
        let profile = write_real_profile(&opts);

        let cmd = format!("ls '{}' 2>&1; echo EXIT:$?", privdir.display());
        let (output, _) = run_sandboxed(&profile, &cmd);
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "private-keys-v1.d should STILL be blocked even with allow_gpg_signing, got: {output}"
        );
    }

    #[test]
    fn real_profile_gpg_signing_blocks_gnupg_write() {
        require_sandbox!();
        let home = home_dir();
        let gnupg = home.join(".gnupg");
        if !gnupg.exists() {
            eprintln!("Skipping: ~/.gnupg does not exist");
            return;
        }

        let project = fs::canonicalize(".").unwrap();
        let mut opts = default_opts(&project, &home);
        opts.allow_gpg_signing = true;
        let profile = write_real_profile(&opts);

        let test_file = gnupg.join(format!("cplt-write-test-{}.tmp", std::process::id()));
        let cmd = format!("echo 'test' > '{}' 2>&1; echo EXIT:$?", test_file.display());
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_file(&test_file).ok(); // cleanup if it somehow succeeded
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "writing to ~/.gnupg should be blocked even with allow_gpg_signing, got: {output}"
        );
    }

    // ── Deny path wins over allow ─────────────────────────────────

    #[test]
    fn real_profile_deny_overrides_extra_read() {
        require_sandbox!();
        let tmp = std::env::temp_dir().join(format!("cplt-deny-override-{}", std::process::id()));
        let denied = tmp.join("secret");
        fs::create_dir_all(&denied).unwrap();
        fs::write(denied.join("data.txt"), "top-secret\n").unwrap();
        let tmp = fs::canonicalize(&tmp).unwrap();
        let denied = fs::canonicalize(&denied).unwrap();
        let home = home_dir();
        let project = fs::canonicalize(".").unwrap();

        let extra_read = vec![tmp.clone()];
        let extra_deny = vec![denied.clone()];
        let mut opts = default_opts(&project, &home);
        opts.extra_read = &extra_read;
        opts.extra_deny = &extra_deny;
        let profile = write_real_profile(&opts);

        // The parent dir should be readable
        let cmd = format!("ls '{}' 2>&1", tmp.display());
        let (output, success) = run_sandboxed(&profile, &cmd);
        assert!(success, "parent dir should be readable, got: {output}");

        // The denied subdir should be blocked
        let cmd = format!("cat '{}/data.txt' 2>&1; echo EXIT:$?", denied.display());
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_dir_all(&tmp).ok();
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "deny-path should override allow-read, got: {output}"
        );
    }

    // ── Localhost blocking ────────────────────────────────────────

    #[test]
    fn real_profile_blocks_localhost_by_default() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        // Try to connect to a likely-unused localhost port
        let cmd = "exec 3<>/dev/tcp/127.0.0.1/19999 2>&1; echo EXIT:$?";
        let (output, _) = run_sandboxed(&profile, cmd);

        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted")
                || output.contains("Connection refused")
                || output.contains("EXIT:1"),
            "localhost should be blocked by default, got: {output}"
        );
    }

    #[test]
    fn real_profile_allows_localhost_when_opted_in() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let mut opts = default_opts(&project, &home);
        opts.allow_localhost_any = true;
        let profile = write_real_profile(&opts);

        // Start a tiny listener, connect to it
        let cmd = "\
            /bin/bash -c '\
            # Start background listener\n\
            exec 3<>/dev/tcp/127.0.0.1/19876 2>/dev/null && echo CONNECT_OK || echo CONNECT_FAIL\n\
            ' 2>&1";
        let (output, _) = run_sandboxed(&profile, cmd);

        fs::remove_file(&profile).ok();
        // With allow_localhost_any, the connection attempt should not get
        // "Operation not permitted" — it may get "Connection refused" (no listener)
        // but that's a network error, not a sandbox denial.
        assert!(
            !output.contains("Operation not permitted"),
            "with allow_localhost_any, localhost should not be denied by sandbox, got: {output}"
        );
    }

    #[test]
    fn real_profile_allows_jvm_attach_socket_in_tmp() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let mut opts = default_opts(&project, &home);
        opts.allow_jvm_attach = true;
        let profile = write_real_profile(&opts);

        // Simulate JVM Attach API: bind+connect a .java_pid<PID> socket
        let cmd = r#"python3 -c "
import socket, os, threading, time
SOCK = '/tmp/.java_pid99999'
try: os.unlink(SOCK)
except: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(SOCK)
s.listen(1)
s.settimeout(3)
def accept():
    try:
        c,_ = s.accept()
        c.send(b'OK')
        c.close()
    except: pass
t = threading.Thread(target=accept)
t.start()
time.sleep(0.2)
c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
c.connect(SOCK)
print(c.recv(10).decode())
c.close()
s.close()
os.unlink(SOCK)
t.join(2)
""#;
        let (output, _) = run_sandboxed(&profile, cmd);

        fs::remove_file(&profile).ok();
        assert!(
            output.contains("OK"),
            "JVM Attach socket (.java_pid*) should be allowed, got: {output}"
        );
    }

    #[test]
    fn real_profile_blocks_ssh_agent_socket() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        // SSH_AUTH_SOCK on macOS is /private/tmp/com.apple.launchd.*/Listeners
        // The sandbox must NOT allow connecting to it — even though .java_pid* is allowed.
        let cmd = r#"python3 -c "
import socket, os
sock_path = os.environ.get('SSH_AUTH_SOCK', '')
if not sock_path:
    print('NO_SSH_AGENT')
else:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(sock_path)
        print('EXPOSED')
    except PermissionError:
        print('BLOCKED')
    except OSError as e:
        if e.errno == 1:
            print('BLOCKED')
        else:
            print(f'ERROR:{e}')
    finally:
        s.close()
""#;
        let (output, _) = run_sandboxed(&profile, cmd);

        fs::remove_file(&profile).ok();
        // If no SSH agent running, skip the assertion
        if !output.contains("NO_SSH_AGENT") {
            assert!(
                output.contains("BLOCKED"),
                "SSH agent socket must be blocked by sandbox, got: {output}"
            );
        }
    }

    #[test]
    fn real_profile_blocks_arbitrary_unix_socket_in_tmp() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        // Non-.java_pid sockets in /tmp must be blocked
        let cmd = r#"python3 -c "
import socket, os
SOCK = '/tmp/.cplt_evil_test'
try: os.unlink(SOCK)
except: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.bind(SOCK)
    print('EXPOSED')
    s.close()
    os.unlink(SOCK)
except PermissionError:
    print('BLOCKED')
except OSError as e:
    if e.errno == 1:
        print('BLOCKED')
    else:
        print(f'ERROR:{e}')
finally:
    s.close()
""#;
        let (output, _) = run_sandboxed(&profile, cmd);

        fs::remove_file(&profile).ok();
        assert!(
            output.contains("BLOCKED"),
            "Arbitrary unix sockets in /tmp must be blocked, got: {output}"
        );
    }

    // ── Process spawning of common tools ──────────────────────────

    #[test]
    fn real_profile_allows_git_execution() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        let (output, success) = run_sandboxed(&profile, "git --version");
        fs::remove_file(&profile).ok();
        assert!(
            success,
            "git should be executable inside sandbox, got: {output}"
        );
        assert!(
            output.contains("git version"),
            "should see git version string, got: {output}"
        );
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
