//! End-to-end tests for cplt.
//!
//! These tests exercise the full pipeline: binary → profile generation → sandbox-exec → copilot.
//! They require macOS, Copilot CLI installed, and (for live tests) valid GitHub auth.
//!
//! Run all non-live E2E tests:
//!   cargo test --test e2e
//!
//! Run live tests that hit the Copilot API:
//!   cargo test --test e2e -- --ignored

#[cfg(target_os = "macos")]
mod e2e_tests {
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU32, Ordering};

    static FAKE_COPILOT_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn binary_path() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_cplt"))
    }

    fn project_dir() -> PathBuf {
        std::fs::canonicalize(".").unwrap()
    }

    /// Check if `copilot` CLI is available. Tests that require it should call this
    /// and return early if false — allows the test suite to pass in CI where
    /// Copilot CLI is not installed.
    fn copilot_cli_available() -> bool {
        Command::new("which")
            .arg("copilot")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if sandbox-exec can apply a trivial profile.
    /// Returns false when running inside an existing sandbox (nested sandbox-exec is denied).
    fn sandbox_exec_available() -> bool {
        Command::new("sandbox-exec")
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Skip guard — call at the top of tests that need Copilot CLI.
    /// Returns true if the test should be skipped.
    macro_rules! require_copilot {
        () => {
            if !copilot_cli_available() {
                eprintln!("SKIPPED: copilot CLI not found in PATH");
                return;
            }
        };
    }

    /// Skip guard — call at the top of tests that invoke sandbox-exec.
    /// Skips when already inside a sandbox (nested sandbox-exec is denied by macOS).
    macro_rules! require_sandbox {
        () => {
            if !sandbox_exec_available() {
                eprintln!("SKIPPED: sandbox-exec not available (likely already sandboxed)");
                return;
            }
        };
    }

    // ============================================================
    // Full pipeline tests (sandbox-exec → copilot child process)
    // ============================================================

    #[test]
    fn e2e_copilot_version_inside_sandbox() {
        require_copilot!();
        require_sandbox!();
        let output = Command::new(binary_path())
            .args(["--yes", "--no-validate", "--", "--version"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");

        assert!(
            output.status.success(),
            "copilot --version inside sandbox should succeed.\nOutput: {combined}"
        );
        assert!(
            stdout.contains("Copilot CLI") || stdout.contains("GitHub Copilot"),
            "should contain Copilot version string.\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_sandbox_validation_passes() {
        require_copilot!();
        require_sandbox!();
        let output = Command::new(binary_path())
            .args(["--yes", "--", "--version"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "sandbox with validation should succeed.\nstderr: {stderr}"
        );
        assert!(
            stderr.contains("validated"),
            "should show validation passed.\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_proxy_starts_with_version() {
        require_copilot!();
        require_sandbox!();
        // Use a high unique port to avoid collisions
        let port = 19200 + (std::process::id() % 800) as u16;

        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--with-proxy",
                "--proxy-port",
                &port.to_string(),
                "--no-validate",
                "--",
                "--version",
            ])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "should succeed with proxy.\nstderr: {stderr}\nstdout: {stdout}"
        );
        assert!(
            stderr.contains("Proxy running"),
            "should show proxy started.\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_show_denials_doesnt_crash() {
        require_copilot!();
        require_sandbox!();
        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--show-denials",
                "--no-validate",
                "--",
                "--version",
            ])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            output.status.success(),
            "should succeed with --show-denials.\nstderr: {stderr}\nstdout: {stdout}"
        );
        assert!(
            stderr.contains("denial logs"),
            "should mention denial log streaming.\nstderr: {stderr}"
        );
    }

    // ============================================================
    // CLI profile generation tests (--print-profile)
    // ============================================================

    #[test]
    fn e2e_print_profile_contains_deny_default() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "should succeed");
        assert!(
            stdout.contains("(deny default)"),
            "profile should contain deny default.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_print_profile_blocks_sensitive_dirs() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        for dir in &[".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker"] {
            assert!(
                stdout.contains(&format!("/{dir}\")")),
                "profile should deny {dir}.\nstdout: {stdout}"
            );
        }
    }

    #[test]
    fn e2e_print_profile_allows_project_dir() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // The binary auto-detects the git root, extract it from stderr
        let project_str = stderr
            .lines()
            .find(|l| l.contains("Project:"))
            .and_then(|l| l.split("Project:").nth(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| project_dir().to_string_lossy().to_string());

        assert!(output.status.success());
        assert!(
            stdout.contains(&format!("(allow file-read* (subpath \"{project_str}\"))")),
            "profile should allow project dir read.\nproject: {project_str}\nstdout: {stdout}"
        );
        assert!(
            stdout.contains(&format!("(allow file-write* (subpath \"{project_str}\"))")),
            "profile should allow project dir write.\nproject: {project_str}\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_print_profile_restricts_network() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        // Port-restricted outbound (443 only, no blanket allow)
        assert!(
            stdout.contains("(allow network-outbound (remote ip \"*:443\"))"),
            "profile should allow port 443.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains("(deny network-outbound (remote tcp))"),
            "profile should deny general TCP before port allows.\nstdout: {stdout}"
        );
        // Localhost blocked
        assert!(
            stdout.contains("(deny network-outbound (remote ip \"localhost:*\"))"),
            "profile should block localhost outbound.\nstdout: {stdout}"
        );
        // SSH agent blocked (no unix-socket allow)
        assert!(
            !stdout.contains("(allow network-outbound (remote unix-socket))"),
            "profile should NOT allow unix-socket (blocks SSH agent).\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_print_profile_allows_gh_config_readonly() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        assert!(
            stdout.contains(".config/gh"),
            "profile should reference .config/gh.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains("(allow file-read*") && stdout.contains(".config/gh"),
            "profile should allow read on .config/gh.\nstdout: {stdout}"
        );
        // Verify NO write access to .config/gh
        let lines: Vec<&str> = stdout.lines().collect();
        for line in &lines {
            if line.contains(".config/gh") {
                assert!(
                    !line.contains("file-write"),
                    ".config/gh should be read-only, found write rule: {line}"
                );
            }
        }
    }

    #[test]
    fn e2e_deny_path_overrides_project() {
        require_copilot!();
        // Create a temp subdir inside the project to deny
        let project = project_dir();
        let deny_dir = project.join("test-deny-e2e-target");
        std::fs::create_dir_all(&deny_dir).unwrap();
        let deny_dir_canonical = std::fs::canonicalize(&deny_dir).unwrap();

        let output = Command::new(binary_path())
            .args([
                "--deny-path",
                &deny_dir.to_string_lossy(),
                "--print-profile",
            ])
            .current_dir(&project)
            .output()
            .expect("binary should run");

        // Cleanup
        std::fs::remove_dir(&deny_dir).ok();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let deny_str = deny_dir_canonical.to_string_lossy();

        assert!(output.status.success(), "should succeed");
        assert!(
            stdout.contains(&format!("(deny file-read* (subpath \"{deny_str}\"))")),
            "deny path should appear.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains(&format!("(deny file-write* (subpath \"{deny_str}\"))")),
            "deny write should appear.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_allow_read_appears_in_profile() {
        require_copilot!();
        // Create a temp dir outside the project to allow-read
        let allow_dir = std::env::temp_dir().join(format!("cplt-e2e-allow-{}", std::process::id()));
        std::fs::create_dir_all(&allow_dir).unwrap();
        let allow_dir_canonical = std::fs::canonicalize(&allow_dir).unwrap();

        let output = Command::new(binary_path())
            .args([
                "--allow-read",
                &allow_dir.to_string_lossy(),
                "--print-profile",
            ])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        // Cleanup
        std::fs::remove_dir(&allow_dir).ok();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let allow_str = allow_dir_canonical.to_string_lossy();

        assert!(output.status.success(), "should succeed");
        // The allowed dir should appear as a read-only allow
        assert!(
            stdout.contains(&format!("(allow file-read* (subpath \"{allow_str}\"))")),
            "allow-read path should appear in profile.\nstdout: {stdout}"
        );
        // But NOT as a write allow
        assert!(
            !stdout.contains(&format!("(allow file-write* (subpath \"{allow_str}\"))")),
            "allow-read should NOT grant write access.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_custom_project_dir() {
        require_copilot!();
        let custom_dir =
            std::env::temp_dir().join(format!("cplt-e2e-project-{}", std::process::id()));
        std::fs::create_dir_all(&custom_dir).unwrap();

        let output = Command::new(binary_path())
            .args([
                "--project-dir",
                &custom_dir.to_string_lossy(),
                "--print-profile",
            ])
            .output()
            .expect("binary should run");

        // Cleanup
        std::fs::remove_dir(&custom_dir).ok();

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success(), "should succeed");
        assert!(
            stdout.contains(&custom_dir.to_string_lossy().to_string()),
            "profile should reference custom project dir.\nstdout: {stdout}"
        );
    }

    // ============================================================
    // Doctor command tests
    // ============================================================

    #[test]
    fn e2e_doctor_exits_successfully() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--doctor"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "--doctor should exit 0 when copilot is installed.\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_doctor_reports_auth_section() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--doctor"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            stderr.contains("[doctor]") && stderr.contains("Auth"),
            "--doctor should print Auth section.\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_doctor_reports_copilot_section() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--doctor"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            stderr.contains("Copilot CLI") && stderr.contains("Version"),
            "--doctor should show Copilot CLI section with version.\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_doctor_reports_tools_section() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--doctor"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            stderr.contains("Tools") && stderr.contains("git"),
            "--doctor should show Tools section with git.\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_doctor_reports_sandbox_paths() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--doctor"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            stderr.contains("Sandbox paths") && stderr.contains("Protected"),
            "--doctor should show Sandbox paths with protected dirs.\nstderr: {stderr}"
        );
    }

    // ============================================================
    // CLI flag profile tests — new scenarios
    // ============================================================

    #[test]
    fn e2e_print_profile_allow_tmp_exec_removes_denies() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--allow-tmp-exec", "--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        assert!(
            !stdout.contains("(deny process-exec (subpath \"/private/tmp\"))"),
            "--allow-tmp-exec should remove tmp exec denies.\nstdout: {stdout}"
        );
        assert!(
            !stdout.contains("(deny process-exec (subpath \"/private/var/folders\"))"),
            "--allow-tmp-exec should remove var/folders exec denies.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_print_profile_allow_localhost_any() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--allow-localhost-any", "--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        assert!(
            stdout.contains("(allow network-outbound (remote ip \"localhost:*\"))"),
            "--allow-localhost-any should allow all localhost.\nstdout: {stdout}"
        );
        assert!(
            !stdout.contains("(deny network-outbound (remote ip \"localhost:*\"))"),
            "--allow-localhost-any should remove localhost deny.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_print_profile_allow_localhost_port() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--allow-localhost", "3000", "--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        assert!(
            stdout.contains("(allow network-outbound (remote ip \"localhost:3000\"))"),
            "--allow-localhost 3000 should add port carve-out.\nstdout: {stdout}"
        );
        // Localhost should still be denied generally
        assert!(
            stdout.contains("(deny network-outbound (remote ip \"localhost:*\"))"),
            "general localhost deny should remain.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_print_profile_allow_port() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--allow-port", "8080", "--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        assert!(
            stdout.contains("(allow network-outbound (remote ip \"*:8080\"))"),
            "--allow-port 8080 should appear.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_print_profile_allow_write() {
        require_copilot!();
        let allow_dir =
            std::env::temp_dir().join(format!("cplt-e2e-allow-write-{}", std::process::id()));
        std::fs::create_dir_all(&allow_dir).unwrap();
        let allow_dir_canonical = std::fs::canonicalize(&allow_dir).unwrap();

        let output = Command::new(binary_path())
            .args([
                "--allow-write",
                &allow_dir.to_string_lossy(),
                "--print-profile",
            ])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        std::fs::remove_dir(&allow_dir).ok();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let allow_str = allow_dir_canonical.to_string_lossy();

        assert!(output.status.success());
        assert!(
            stdout.contains(&format!("(allow file-read* (subpath \"{allow_str}\"))")),
            "--allow-write should grant read.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains(&format!("(allow file-write* (subpath \"{allow_str}\"))")),
            "--allow-write should grant write.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_print_profile_allow_env_files() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--allow-env-files", "--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        // With --allow-env-files, the .env deny rules should NOT appear
        assert!(
            !stdout.contains(r"\.env\$"),
            "--allow-env-files should remove .env deny rules.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_print_profile_scratch_dir_appears() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--scratch-dir", "--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        assert!(
            stdout.contains("scratch directory"),
            "scratch dir section should appear in profile.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains("(allow process-exec (subpath"),
            "scratch dir should allow process-exec.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_print_profile_copilot_pkg_write_denied() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        assert!(
            stdout.contains("(deny file-write* (subpath") && stdout.contains(".copilot/pkg"),
            "profile should deny writes to .copilot/pkg.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_print_profile_git_persistence_blocked() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        assert!(
            stdout.contains(".git/hooks"),
            "profile should deny .git/hooks writes.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains(".git/config"),
            "profile should deny .git/config writes.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains(".gitmodules"),
            "profile should deny .gitmodules writes.\nstdout: {stdout}"
        );
    }

    // ============================================================
    // Environment isolation tests
    //
    // These use a fake "copilot" script that dumps its environment,
    // placed earlier in PATH to intercept cplt's exec call.
    // ============================================================

    /// Create a fake copilot script that prints its environment and exits.
    /// Placed inside the project dir so the sandbox allows execution
    /// (process-exec is denied in /tmp).
    fn create_fake_copilot() -> PathBuf {
        let id = FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = project_dir().join(format!(".cplt-fake-copilot-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("copilot");
        std::fs::write(&script, "#!/bin/sh\nenv | sort\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        dir
    }

    /// Run cplt with fake copilot and capture the environment output.
    fn run_with_fake_copilot(extra_args: &[&str], extra_env: &[(&str, &str)]) -> (String, String) {
        let fake_dir = create_fake_copilot();
        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_dir.display());

        let mut cmd = Command::new(binary_path());
        cmd.args(["--yes", "--no-validate"])
            .args(extra_args)
            .args(["--", "--version"]) // fake copilot ignores args, prints env
            .current_dir(project_dir())
            .env("PATH", &new_path);

        for (key, val) in extra_env {
            cmd.env(key, val);
        }

        let output = cmd.output().expect("binary should run");
        std::fs::remove_dir_all(&fake_dir).ok();

        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    #[test]
    fn e2e_env_strips_cloud_credentials() {
        require_sandbox!();
        let (stdout, stderr) = run_with_fake_copilot(
            &[],
            &[
                ("AWS_SECRET_ACCESS_KEY", "FAKESECRET"),
                ("AWS_ACCESS_KEY_ID", "FAKEKEY"),
                ("NPM_TOKEN", "npm_faketoken"),
                ("DATABASE_URL", "postgres://localhost/db"),
            ],
        );

        assert!(
            !stdout.contains("FAKESECRET"),
            "AWS_SECRET_ACCESS_KEY should be stripped.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            !stdout.contains("npm_faketoken"),
            "NPM_TOKEN should be stripped.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            !stdout.contains("postgres://"),
            "DATABASE_URL should be stripped.\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_env_passes_safe_vars() {
        require_sandbox!();
        let (stdout, _) = run_with_fake_copilot(&[], &[]);

        assert!(
            stdout.contains("HOME="),
            "HOME should pass through.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains("PATH="),
            "PATH should pass through.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_env_injects_hardening_vars() {
        require_sandbox!();
        let (stdout, _) = run_with_fake_copilot(&[], &[]);

        assert!(
            stdout.contains("npm_config_ignore_scripts=true"),
            "npm_config_ignore_scripts should be injected.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains("YARN_ENABLE_SCRIPTS=false"),
            "YARN_ENABLE_SCRIPTS should be injected.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains("GIT_TERMINAL_PROMPT=0"),
            "GIT_TERMINAL_PROMPT should be injected.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_env_lifecycle_opt_out_removes_hardening() {
        require_sandbox!();
        let (stdout, _) = run_with_fake_copilot(&["--allow-lifecycle-scripts"], &[]);

        assert!(
            !stdout.contains("npm_config_ignore_scripts=true"),
            "--allow-lifecycle-scripts should remove npm hardening.\nstdout: {stdout}"
        );
        assert!(
            !stdout.contains("YARN_ENABLE_SCRIPTS=false"),
            "--allow-lifecycle-scripts should remove yarn hardening.\nstdout: {stdout}"
        );
        // Git hardening should remain — it's a separate category
        assert!(
            stdout.contains("GIT_TERMINAL_PROMPT=0"),
            "git hardening should remain.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_env_pass_env_adds_specific_var() {
        require_sandbox!();
        let (stdout, _) = run_with_fake_copilot(
            &["--pass-env", "MY_CUSTOM_VAR"],
            &[("MY_CUSTOM_VAR", "custom_value")],
        );

        assert!(
            stdout.contains("MY_CUSTOM_VAR=custom_value"),
            "--pass-env should pass the specified var.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_env_inherit_still_strips_ssh() {
        require_sandbox!();
        let (stdout, _) = run_with_fake_copilot(
            &["--inherit-env"],
            &[("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock")],
        );

        assert!(
            !stdout.contains("SSH_AUTH_SOCK"),
            "--inherit-env should still strip SSH_AUTH_SOCK.\nstdout: {stdout}"
        );
    }

    // ============================================================
    // Live tests — require Copilot auth + network
    // ============================================================

    #[test]
    #[ignore = "requires Copilot auth and network — run with: cargo test --test e2e -- --ignored"]
    fn e2e_live_prompt_responds() {
        require_copilot!();
        require_sandbox!();
        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--no-validate",
                "--",
                "-p",
                "respond with only the word hello",
            ])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "live prompt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.to_lowercase().contains("hello"),
            "response should contain 'hello'.\nstdout: {stdout}"
        );
    }

    #[test]
    #[ignore = "requires Copilot auth and network — run with: cargo test --test e2e -- --ignored"]
    fn e2e_live_prompt_with_proxy() {
        require_copilot!();
        require_sandbox!();
        let port = 19300 + (std::process::id() % 700) as u16;

        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--with-proxy",
                "--proxy-port",
                &port.to_string(),
                "--no-validate",
                "--",
                "-p",
                "respond with only the word hello",
            ])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "live prompt with proxy should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.to_lowercase().contains("hello"),
            "response should contain 'hello'.\nstdout: {stdout}"
        );
        assert!(
            stderr.contains("Proxy running"),
            "proxy should have started.\nstderr: {stderr}"
        );
    }
}
