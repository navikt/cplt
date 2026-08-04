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

    /// When `CPLT_TEST_REQUIRE_SANDBOX=1` is set (CI), a missing sandbox
    /// capability must FAIL the test rather than silently skip. Mirrors the Linux
    /// `require_sandbox_enforced()` in `integration_linux.rs`: a `sandbox-exec`
    /// regression on the macOS runner turns the job red instead of leaving CI
    /// green while nothing is enforced. Default (unset) behaviour is unchanged for
    /// local dev / nested-sandbox runs.
    fn require_sandbox_enforced() -> bool {
        std::env::var("CPLT_TEST_REQUIRE_SANDBOX").as_deref() == Ok("1")
    }

    /// Skip guard — call at the top of tests that invoke sandbox-exec.
    ///
    /// Under `CPLT_TEST_REQUIRE_SANDBOX=1` the skip branch panics instead, so a
    /// missing/broken `sandbox-exec` on the CI runner turns the job red.
    macro_rules! require_sandbox {
        () => {
            if !sandbox_exec_available() {
                if require_sandbox_enforced() {
                    panic!(
                        "sandbox-exec required by CPLT_TEST_REQUIRE_SANDBOX but unavailable \
                         (a trivial profile failed to apply — Seatbelt/sandbox-exec regression?)"
                    );
                }
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
            allow_socket: &[],
            extra_deny: &[],
            existing_home_tool_dirs: None,
            existing_app_dirs: None,
            extra_ports: &[],
            localhost_ports: &[],
            proxy_port: None,
            proxy_forced: false,
            allow_env_files: false,
            allow_localhost_any: false,
            scratch_dir: None,
            allow_tmp_exec: false,
            copilot_install_dir: None,
            java_home: None,
            dotnet_root: None,
            git_hooks_path: None,
            git_common_dir: None,
            allow_gpg_signing: false,
            deny_clipboard: false,
            allow_jvm_attach: false,
            allow_msbuild: false,
            allow_docker: false,
            electron_app_dir: None,
            agent: cplt::agent::Agent::Copilot,
            agent_dirs: &[],
            allow_cache_exec: &[],
            allow_cache_exec_any: false,
            allow_browser: false,
        }
    }

    #[test]
    fn real_profile_allows_local_git_config_and_global_ignore() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let temp_home = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(temp_home.path()).unwrap();
        let local_config = home.join(".gitconfig.local");
        let global_ignore = home.join(".gitignore_global");
        fs::write(
            home.join(".gitconfig"),
            format!("[include]\npath = {}\n", local_config.display()),
        )
        .unwrap();
        fs::write(
            &local_config,
            format!(
                "[user]\nname = cplt-test-user\n[core]\nexcludesFile = {}\n",
                global_ignore.display()
            ),
        )
        .unwrap();
        fs::write(&global_ignore, "ignored-by-cplt-test\n").unwrap();

        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);
        let read_config_cmd = format!("cat '{}' 2>&1", local_config.display());
        let (config_output, config_success) = run_sandboxed(&profile, &read_config_cmd);
        let read_ignore_cmd = format!("cat '{}' 2>&1", global_ignore.display());
        let (ignore_output, ignore_success) = run_sandboxed(&profile, &read_ignore_cmd);
        let write_cmd = format!(
            "echo injected >> '{}' 2>&1; echo EXIT:$?",
            local_config.display()
        );
        let (write_output, _) = run_sandboxed(&profile, &write_cmd);
        let write_ignore_cmd = format!(
            "echo injected >> '{}' 2>&1; echo EXIT:$?",
            global_ignore.display()
        );
        let (write_ignore_output, _) = run_sandboxed(&profile, &write_ignore_cmd);

        fs::remove_file(&profile).ok();
        assert!(
            config_success && config_output.contains("cplt-test-user"),
            "~/.gitconfig.local should be readable: {config_output}"
        );
        assert!(
            ignore_success && ignore_output.contains("ignored-by-cplt-test"),
            "git's conventional global ignore file should be readable: {ignore_output}"
        );
        assert!(
            write_output.contains("Operation not permitted") || write_output.contains("EXIT:1"),
            "~/.gitconfig.local must remain read-only: {write_output}"
        );
        assert!(
            write_ignore_output.contains("Operation not permitted")
                || write_ignore_output.contains("EXIT:1"),
            "~/.gitignore_global must remain read-only: {write_ignore_output}"
        );
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

    #[test]
    fn real_profile_blocks_cplt_toml_write() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let tmp = project.join(format!(".cplt-toml-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join(".cplt.toml"), "").unwrap();
        let tmp = fs::canonicalize(&tmp).unwrap();
        let home = home_dir();

        let opts = default_opts(&tmp, &home);
        let profile = write_real_profile(&opts);

        let toml_path = tmp.join(".cplt.toml");
        let cmd = format!(
            "echo 'tampered' >> '{}' 2>&1; echo EXIT:$?",
            toml_path.display()
        );
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_dir_all(&tmp).ok();
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "writing to .cplt.toml should be blocked, got: {output}"
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
    fn real_profile_blocks_env_file_symlink_read() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let tmp = project.join(format!(".cplt-envsymtest-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join(".env"), "SECRET=hunter2\n").unwrap();
        let tmp = fs::canonicalize(&tmp).unwrap();
        let home = home_dir();

        // Create symlink innocuous-name -> .env
        let env_path = tmp.join(".env");
        let link_path = tmp.join("innocuous-name");
        std::os::unix::fs::symlink(&env_path, &link_path).unwrap();

        let opts = default_opts(&tmp, &home);
        let profile = write_real_profile(&opts);

        let cmd = format!("cat '{}' 2>&1; echo EXIT:$?", link_path.display());
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_dir_all(&tmp).ok();
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            "symlink to .env should be blocked by default, got: {output}"
        );
    }

    #[test]
    fn real_profile_blocks_env_file_delete() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let tmp = project.join(format!(".cplt-envdel-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join(".env"), "SECRET=hunter2\n").unwrap();
        let tmp = fs::canonicalize(&tmp).unwrap();
        let home = home_dir();

        let opts = default_opts(&tmp, &home);
        let profile = write_real_profile(&opts);

        let env_path = tmp.join(".env");
        let cmd = format!("rm '{}' 2>&1; echo EXIT:$?", env_path.display());
        let (output, _) = run_sandboxed(&profile, &cmd);

        // File should still exist — deletion was blocked
        let still_exists = tmp.join(".env").exists();
        fs::remove_dir_all(&tmp).ok();
        fs::remove_file(&profile).ok();
        assert!(
            output.contains("Operation not permitted") || output.contains("EXIT:1"),
            ".env delete should be blocked by default, got: {output}"
        );
        assert!(
            still_exists,
            ".env file should still exist after blocked rm"
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

    // ── Credential-dir read denial (planted secrets in a temp HOME) ──
    //
    // #126 Tier 1a: the older `sandbox_blocks_ssh_read`/`_aws`/... tests build a
    // HAND-WRITTEN SBPL profile and self-skip whenever ~/.ssh etc. are absent
    // (always true on a fresh CI runner), so dropping a credential deny from
    // cplt's REAL profile shipped green. This test closes that gap:
    //   • it points `home_dir` at a throwaway temp HOME and PLANTS fake secrets,
    //   • it generates cplt's REAL profile via `generate_profile` (write_real_profile),
    //   • it asserts each planted secret read is DENIED at the kernel level and the
    //     sentinel contents never leak, with an allowed project-file read as a
    //     positive control.
    //
    // Crucially it is NOT vacuous: `.m2/settings.xml` and `.gradle/gradle.properties`
    // sit UNDER the broad `~/.m2` / `~/.gradle` tool-dir read allows (DENIED_HOME_SUBPATHS),
    // so if the credential deny is removed from `emit_deny_rules` — or reordered
    // before its allow — those reads succeed and this test turns red.
    #[test]
    fn real_profile_blocks_planted_credentials_in_temp_home() {
        require_sandbox!();

        // Positive control lives in the REAL project dir (allowed for read).
        let project = fs::canonicalize(".").unwrap();

        // Throwaway HOME with planted secrets — never touches the developer's real ~.
        let home = std::env::temp_dir().join(format!("cplt-credhome-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();

        // (relative path under HOME, sentinel contents). The `.ssh`/`.aws` entries
        // cover the hard-denied dotfiles; `.m2`/`.gradle` cover credential files that
        // live inside otherwise-allowed tool dirs (the real last-match-wins case).
        let planted: &[(&str, &str)] = &[
            (".ssh/id_rsa", "SENTINEL_SSH_PRIVATE_KEY_c0ffee"),
            (".aws/credentials", "SENTINEL_AWS_SECRET_deadbeef"),
            (".m2/settings.xml", "SENTINEL_M2_REGISTRY_PASSWORD_1234"),
            (".gradle/gradle.properties", "SENTINEL_GRADLE_TOKEN_5678"),
        ];
        for (rel, contents) in planted {
            let path = home.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, contents).unwrap();
        }

        let home = fs::canonicalize(&home).unwrap();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        // Every planted secret must be unreadable AND its sentinel must never leak.
        let mut failures: Vec<String> = Vec::new();
        for (rel, sentinel) in planted {
            let secret = home.join(rel);
            let cmd = format!("cat '{}' 2>&1; echo EXIT:$?", secret.display());
            let (output, _) = run_sandboxed(&profile, &cmd);
            let denied = output.contains("Operation not permitted") || output.contains("EXIT:1");
            let leaked = output.contains(sentinel);
            if !denied || leaked {
                failures.push(format!(
                    "{rel}: denied={denied} leaked={leaked} output={output:?}"
                ));
            }
        }

        // Positive control: an allowed project file must still be readable.
        let (ctrl_out, ctrl_ok) = run_sandboxed(&profile, "cat Cargo.toml | head -1");

        fs::remove_dir_all(&home).ok();
        fs::remove_file(&profile).ok();

        assert!(
            failures.is_empty(),
            "cplt's real profile must DENY planted credential reads: {failures:?}"
        );
        assert!(
            ctrl_ok && ctrl_out.contains("[package]"),
            "positive control: allowed project file must be readable, got: {ctrl_out}"
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
    fn real_profile_java_localhost_with_prefer_ipv4_stack() {
        require_sandbox!();
        // Skip if Java is not available (macOS shim reports success but no JRE)
        if Command::new("java")
            .arg("-version")
            .output()
            .map(|o| {
                let stderr = String::from_utf8_lossy(&o.stderr);
                !o.status.success() || stderr.contains("Unable to locate")
            })
            .unwrap_or(true)
        {
            eprintln!("SKIP: java not found");
            return;
        }
        let java_home = std::env::var("JAVA_HOME").ok().map(PathBuf::from);
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let mut opts = default_opts(&project, &home);
        // Allow localhost on a specific port (not allow_localhost_any)
        opts.localhost_ports = &[19877];
        opts.java_home = java_home.as_deref();
        let profile = write_real_profile(&opts);

        // Java program that binds to 19877 and connects to it.
        // With preferIPv4Stack=true, the connection uses AF_INET4 and matches
        // SBPL "localhost:19877". Without it, Java uses IPv6 dual-stack which
        // produces ::ffff:127.0.0.1 — not matched by SBPL.
        let java_code = r#"
import java.net.*;
public class T {
    public static void main(String[] a) throws Exception {
        try (ServerSocket ss = new ServerSocket(19877, 1, InetAddress.getByName("127.0.0.1"))) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", 19877), 1000);
                System.out.println("JAVA_LOCALHOST_OK");
            }
        }
    }
}
"#;
        // Write, compile and run inside sandbox with preferIPv4Stack
        let cmd = format!(
            "cd /tmp && cat > T.java << 'JAVA'\n{java_code}\nJAVA\n\
             javac T.java 2>&1 && \
             java -Djava.net.preferIPv4Stack=true T 2>&1"
        );
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_file(&profile).ok();
        assert!(
            output.contains("JAVA_LOCALHOST_OK"),
            "Java with preferIPv4Stack=true should connect to localhost:19877, got: {output}"
        );
    }

    #[test]
    fn real_profile_java_localhost_blocked_without_prefer_ipv4_stack() {
        require_sandbox!();
        if Command::new("java")
            .arg("-version")
            .output()
            .map(|o| {
                let stderr = String::from_utf8_lossy(&o.stderr);
                !o.status.success() || stderr.contains("Unable to locate")
            })
            .unwrap_or(true)
        {
            eprintln!("SKIP: java not found");
            return;
        }
        let java_home = std::env::var("JAVA_HOME").ok().map(PathBuf::from);
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let mut opts = default_opts(&project, &home);
        opts.localhost_ports = &[19878];
        opts.java_home = java_home.as_deref();
        let profile = write_real_profile(&opts);

        // Same test but WITHOUT preferIPv4Stack — should fail due to IPv4-mapped
        let java_code = r#"
import java.net.*;
public class T2 {
    public static void main(String[] a) throws Exception {
        try (ServerSocket ss = new ServerSocket(19878, 1, InetAddress.getByName("127.0.0.1"))) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", 19878), 1000);
                System.out.println("JAVA_LOCALHOST_OK");
            }
        } catch (Exception e) {
            System.out.println("JAVA_BLOCKED:" + e.getMessage());
        }
    }
}
"#;
        let cmd = format!(
            "cd /tmp && cat > T2.java << 'JAVA'\n{java_code}\nJAVA\n\
             javac T2.java 2>&1 && \
             java -Djava.net.preferIPv4Stack=false T2 2>&1"
        );
        let (output, _) = run_sandboxed(&profile, &cmd);

        fs::remove_file(&profile).ok();
        // Should be blocked — either "Operation not permitted" or our marker
        assert!(
            output.contains("Operation not permitted") || output.contains("JAVA_BLOCKED"),
            "Java without preferIPv4Stack should be blocked on port-specific localhost, got: {output}"
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
    fn real_profile_allows_jvm_attach_socket_in_var_folders() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let mut opts = default_opts(&project, &home);
        opts.allow_jvm_attach = true;
        let profile = write_real_profile(&opts);

        // The JDK on macOS uses confstr(_CS_DARWIN_USER_TEMP_DIR) which returns
        // /var/folders/<xx>/<hash>/T/ — test bind+accept+connect at this path.
        let cmd = r#"python3 -c "
import socket, os, threading, time, ctypes, ctypes.util
# Get the real darwin user temp dir via confstr(_CS_DARWIN_USER_TEMP_DIR = 65537)
libc = ctypes.CDLL(ctypes.util.find_library('c'))
buf = ctypes.create_string_buffer(1024)
libc.confstr(65537, buf, 1024)
tmpdir = buf.value.decode().rstrip('/')
SOCK = tmpdir + '/.java_pid88888'
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
            "JVM Attach socket in /var/folders should be allowed, got: {output}"
        );
    }

    #[test]
    fn real_profile_allows_msbuild_socket_in_tmp() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let mut opts = default_opts(&project, &home);
        opts.allow_msbuild = true;
        let profile = write_real_profile(&opts);

        // Simulate MSBuild worker-node IPC: bind+connect a MSBuild<pid> socket
        let cmd = r#"python3 -c "
import socket, os, threading, time
SOCK = '/tmp/MSBuild99999'
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
            "MSBuild socket (MSBuild<pid>) should be allowed, got: {output}"
        );
    }

    #[test]
    fn real_profile_blocks_msbuild_socket_without_flag() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        // Without --allow-msbuild, binding a MSBuild<pid> socket must be denied.
        let cmd = r#"python3 -c "
import socket, os
SOCK = '/tmp/MSBuild88888'
try: os.unlink(SOCK)
except: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.bind(SOCK)
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
        assert!(
            output.contains("BLOCKED") || output.contains("Operation not permitted"),
            "MSBuild socket must be blocked without --allow-msbuild, got: {output}"
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

    // ── Clipboard (pasteboard) access control ─────────────────────

    /// Verify `--deny-clipboard` kernel enforcement via `pbpaste`.
    ///
    /// `pbpaste` communicates with the pasteboard server via the Mach service
    /// `com.apple.pasteboard.1`. The profile emits a targeted `(deny mach-lookup …)`
    /// immediately after `(allow mach-lookup)` so last-match-wins in SBPL blocks
    /// only the pasteboard Mach service while leaving DNS, Keychain, and all
    /// other Mach services intact.
    #[test]
    fn real_profile_deny_clipboard_blocks_pbpaste() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let mut opts = default_opts(&project, &home);
        opts.deny_clipboard = true;
        let profile = write_real_profile(&opts);

        // pbpaste connects to com.apple.pasteboard.1 via mach-lookup.
        // With deny_clipboard the Mach lookup is denied, so pbpaste exits non-zero.
        let cmd = "pbpaste 2>&1; echo EXIT:$?";
        let (output, _) = run_sandboxed(&profile, cmd);

        fs::remove_file(&profile).ok();

        // pbpaste must fail when the pasteboard service is denied. Assert a
        // non-zero exit (the paired allow-by-default test confirms it exits 0
        // otherwise) rather than matching a specific code or localized text.
        assert!(
            !output.contains("EXIT:0"),
            "pbpaste should be blocked when deny_clipboard is set, got: {output}"
        );
    }

    /// Verify `--deny-clipboard` also blocks clipboard writes via `pbcopy`.
    ///
    /// This complements the `pbpaste` read test so both read and write
    /// operations are covered against the same pasteboard Mach deny.
    #[test]
    fn real_profile_deny_clipboard_blocks_pbcopy() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let mut opts = default_opts(&project, &home);
        opts.deny_clipboard = true;
        let profile = write_real_profile(&opts);

        let cmd = "echo cplt-test | pbcopy 2>&1; echo EXIT:$?";
        let (output, _) = run_sandboxed(&profile, cmd);

        fs::remove_file(&profile).ok();
        assert!(
            !output.contains("EXIT:0"),
            "pbcopy should be blocked when deny_clipboard is set, got: {output}"
        );
    }

    /// Without `--deny-clipboard`, `pbpaste` must still exit successfully.
    ///
    /// This guards against accidentally breaking the pasteboard in the default
    /// profile — the clipboard must remain accessible unless the user opts out.
    #[test]
    fn real_profile_allows_pbpaste_by_default() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        // pbpaste may output nothing if the clipboard is empty, but exit 0.
        let cmd = "pbpaste > /dev/null 2>&1 && echo EXIT:0 || echo EXIT:1";
        let (output, _) = run_sandboxed(&profile, cmd);

        fs::remove_file(&profile).ok();
        assert!(
            output.contains("EXIT:0"),
            "pbpaste should succeed by default (clipboard open), got: {output}"
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

    // ── Network bind enforcement ─────────────────────────────────
    // Verify kernel-level network-bind behavior with the real generated profile.
    // These are the ground truth for what SBPL actually enforces.

    #[test]
    fn real_profile_allows_localhost_tcp_bind() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        // IPv4 localhost bind
        let (output, success) = run_sandboxed(
            &profile,
            r#"python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(1)
port = s.getsockname()[1]
s.close()
print(f'OK:{port}')
""#,
        );
        assert!(
            success && output.contains("OK:"),
            "IPv4 localhost bind should be allowed.\noutput: {output}"
        );

        // IPv6 localhost bind
        let (output, success) = run_sandboxed(
            &profile,
            r#"python3 -c "
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('::1', 0))
s.listen(1)
port = s.getsockname()[1]
s.close()
print(f'OK:{port}')
""#,
        );
        assert!(
            success && output.contains("OK:"),
            "IPv6 localhost bind should be allowed.\noutput: {output}"
        );

        let _ = fs::remove_file(&profile);
    }

    /// SBPL platform limitation: `(local ip "localhost:*")` matches INADDR_ANY (0.0.0.0).
    /// SBPL only accepts `*` or `localhost` as host — literal IPs are rejected.
    /// This test documents the gap: wildcard bind is NOT denied by the sandbox.
    #[test]
    fn real_profile_wildcard_bind_is_sbpl_limitation() {
        require_sandbox!();
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let opts = default_opts(&project, &home);
        let profile = write_real_profile(&opts);

        let (output, success) = run_sandboxed(
            &profile,
            r#"python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('0.0.0.0', 18998))
    s.listen(1)
    s.close()
    print('ALLOWED')
except Exception as e:
    print(f'DENIED:{e}')
""#,
        );

        // This SHOULD be denied but SBPL can't distinguish localhost from INADDR_ANY.
        // If SBPL is ever fixed (or we find a workaround), this test will start
        // failing with "DENIED" — update it to assert denied at that point.
        assert!(
            success && output.contains("ALLOWED"),
            "SBPL limitation: wildcard bind should (unfortunately) be allowed.\n\
             If this fails with DENIED, great — SBPL behavior changed and we can \n\
             now properly restrict bind. Update this test and remove the limitation \n\
             documentation.\noutput: {output}"
        );

        let _ = fs::remove_file(&profile);
    }

    // ── Proxy-forced networking (#53) ─────────────────────────────
    //
    // `--proxy-forced` makes the CONNECT proxy mandatory and, on macOS, pins the
    // SBPL `network-outbound` rule to `localhost:{proxy_port}` while dropping the
    // default `*:443` allowance. Unlike Landlock (port-based), SBPL can pin to
    // localhost, so macOS gets full enforcement with no residual.

    /// Positive + negative in one profile: the generated SBPL profile with
    /// `proxy_forced = true` and a concrete `proxy_port` must (a) pin outbound to
    /// `localhost:{proxy_port}` and (b) NOT allow direct `*:443` egress.
    ///
    /// This inspects the REAL profile via `generate_profile` (the same path the
    /// other `real_profile_*` tests use) rather than `--print-profile`, on
    /// purpose: `--print-profile` never starts the proxy, so `proxy_port` is
    /// `None` there and the `localhost:{port}` pin can never appear — asserting
    /// the pin against `--print-profile` output would be a false premise. Setting
    /// a concrete `proxy_port` here is the honest way to observe the pin. No
    /// `require_sandbox!` guard: this is pure profile-string generation and does
    /// not invoke `sandbox-exec`.
    #[test]
    fn real_profile_proxy_forced_pins_localhost_and_drops_443() {
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let mut opts = default_opts(&project, &home);
        opts.proxy_forced = true;
        opts.proxy_port = Some(45123);
        let profile = generate_profile(&opts);

        assert!(
            profile.contains("(allow network-outbound (remote ip \"localhost:45123\"))"),
            "proxy-forced profile must pin outbound to localhost:45123, got:\n{profile}"
        );
        assert!(
            !profile.contains("\"*:443\""),
            "proxy-forced profile must NOT allow direct *:443 egress, got:\n{profile}"
        );
    }

    /// Contrast control that keeps the negative assertion above meaningful: the
    /// DEFAULT profile (proxy_forced = false) DOES allow `*:443`. Without this,
    /// "profile lacks *:443" could pass vacuously if the rule were renamed or
    /// removed for unrelated reasons.
    #[test]
    fn real_profile_default_allows_wildcard_443() {
        let project = fs::canonicalize(".").unwrap();
        let home = home_dir();
        let opts = default_opts(&project, &home);
        let profile = generate_profile(&opts);

        assert!(
            profile.contains("\"*:443\""),
            "default (non-proxy-forced) profile must allow *:443, got:\n{profile}"
        );
    }

    /// Binary-level smoke: `cplt --proxy-forced --print-profile` must not emit a
    /// direct `*:443` allowance. NOTE (coverage limit): `--print-profile` does
    /// NOT start the proxy, so `proxy_port` is `None` and the
    /// `localhost:{port}` pin cannot appear in this output — that positive is
    /// covered by `real_profile_proxy_forced_pins_localhost_and_drops_443`, which
    /// sets a concrete port. Asserting the pin here would be a false premise, so
    /// this test only checks the `*:443` drop.
    #[test]
    fn binary_print_profile_proxy_forced_drops_443() {
        // No require_sandbox!(): `--print-profile` only generates and prints the
        // SBPL text; it never invokes sandbox-exec, so it runs even when nested.
        let project = fs::canonicalize(".").unwrap();
        let output = Command::new(binary_path())
            .args([
                "--proxy-forced",
                "--print-profile",
                "--project-dir",
                &project.to_string_lossy(),
            ])
            .env("HOME", home_dir())
            .output()
            .expect("Failed to run cplt --print-profile");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("\"*:443\""),
            "`--proxy-forced --print-profile` must not allow direct *:443 egress, got:\n{stdout}"
        );
    }
}
