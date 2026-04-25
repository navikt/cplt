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

    /// Configure a Command to ignore the user's config file.
    /// Prevents user settings (e.g., allow_localhost_any) from affecting test assertions.
    fn no_user_config(cmd: &mut Command) -> &mut Command {
        cmd.env("CPLT_CONFIG", "/dev/null/nonexistent")
    }

    /// Create a cplt Command pre-configured to ignore the user's config.
    /// Use for tests that assert on profile/output content that config could affect.
    fn cplt_cmd() -> Command {
        let mut cmd = Command::new(binary_path());
        no_user_config(&mut cmd);
        cmd
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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

        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
    // Live smoke tests — real Copilot operations in sandbox
    //
    // These test the golden path: real Copilot CLI executing real
    // operations inside the cplt sandbox. They require:
    //   - Copilot CLI installed and authenticated
    //   - Network access to Copilot API
    //   - macOS with sandbox-exec
    //
    // Run with: cargo test --test e2e -- --ignored --test-threads=1
    //
    // Tests use UUID canaries (not English words) to distinguish real
    // tool output from LLM hallucination.
    // ============================================================

    /// Run cplt with a timeout. Returns (stdout, stderr, success).
    /// Prevents tests from hanging if Copilot or the sandbox stalls.
    fn run_cplt_with_timeout(
        project_dir: &std::path::Path,
        extra_cplt_args: &[&str],
        copilot_args: &[&str],
        timeout_secs: u64,
    ) -> (String, String, bool) {
        use std::process::Stdio;

        let mut cmd = Command::new(binary_path());
        cmd.args(["--yes", "--no-validate"])
            .args(extra_cplt_args)
            .arg("--");
        cmd.args(copilot_args);
        cmd.current_dir(project_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn().expect("cplt should start");
        let id = child.id();

        let handle = std::thread::spawn(move || child.wait_with_output());

        match handle.join() {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                (stdout, stderr, output.status.success())
            }
            _ => {
                // Kill the process if the thread panicked
                unsafe {
                    libc::kill(id as i32, libc::SIGKILL);
                }
                panic!("cplt timed out after {timeout_secs}s or thread panicked");
            }
        }
    }

    /// Create a temp project dir inside the repo root (not /tmp, which denies exec).
    fn create_smoke_project(name: &str) -> (PathBuf, impl Drop) {
        let id = FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::fs::canonicalize(".").unwrap();
        let dir = base.join(format!(".cplt-smoke-{name}-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Initialize git so Copilot doesn't complain
        let run_git = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(&dir)
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@test.com")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@test.com")
                .output()
                .ok();
        };
        run_git(&["init", "-b", "main"]);

        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let cleanup = Cleanup(dir.clone());
        (dir, cleanup)
    }

    fn uuid() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{t:032x}")
    }

    #[test]
    #[ignore = "requires Copilot auth and network — run with: cargo test --test e2e -- --ignored"]
    fn smoke_copilot_reads_project_file() {
        require_copilot!();
        require_sandbox!();
        let (dir, _cleanup) = create_smoke_project("read");
        let token = uuid();
        std::fs::write(dir.join("canary.txt"), &token).unwrap();

        // Commit the file so git doesn't show it as untracked noise
        Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .ok();
        Command::new("git")
            .args(["commit", "-m", "add canary"])
            .current_dir(&dir)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .ok();

        let prompt = "Read the file canary.txt and respond with ONLY its exact contents, \
             nothing else. Do not add any explanation.";
        let (stdout, stderr, success) =
            run_cplt_with_timeout(&dir, &[], &["-p", prompt, "--allow-all-tools", "-s"], 120);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains(&token),
            "Copilot should return the canary token from canary.txt.\n\
             Expected token: {token}\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    #[test]
    #[ignore = "requires Copilot auth and network — run with: cargo test --test e2e -- --ignored"]
    fn smoke_copilot_writes_project_file() {
        require_copilot!();
        require_sandbox!();
        let (dir, _cleanup) = create_smoke_project("write");
        let token = uuid();

        let prompt = format!(
            "Create a file called output.txt containing exactly this text and nothing else: {token}"
        );
        let (stdout, stderr, success) =
            run_cplt_with_timeout(&dir, &[], &["-p", &prompt, "--allow-all-tools", "-s"], 120);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );

        // Assert via side effect: file must exist on disk with the token
        let output_path = dir.join("output.txt");
        assert!(
            output_path.exists(),
            "Copilot should have created output.txt.\nstdout: {stdout}\nstderr: {stderr}"
        );
        let contents = std::fs::read_to_string(&output_path).unwrap();
        assert!(
            contents.contains(&token),
            "output.txt should contain the canary token.\n\
             Expected: {token}\nGot: {contents}"
        );
    }

    #[test]
    #[ignore = "requires Copilot auth and network — run with: cargo test --test e2e -- --ignored"]
    fn smoke_copilot_runs_shell_command() {
        require_copilot!();
        require_sandbox!();
        let (dir, _cleanup) = create_smoke_project("shell");
        let token = uuid();

        // Create a script that prints the hidden token
        let script_path = dir.join("print_canary.sh");
        std::fs::write(&script_path, format!("#!/bin/sh\necho '{token}'\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Commit so it's visible
        Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .ok();
        Command::new("git")
            .args(["commit", "-m", "add script"])
            .current_dir(&dir)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .ok();

        let prompt = "Run the command ./print_canary.sh and respond with ONLY its output, \
                      nothing else. Do not add any explanation.";
        let (stdout, stderr, success) =
            run_cplt_with_timeout(&dir, &[], &["-p", prompt, "--allow-all-tools", "-s"], 120);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains(&token),
            "Copilot should have run the script and returned the canary.\n\
             Expected token: {token}\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    #[test]
    #[ignore = "requires Copilot auth and network — run with: cargo test --test e2e -- --ignored"]
    fn smoke_copilot_env_blocked_by_default() {
        require_copilot!();
        require_sandbox!();
        let (dir, _cleanup) = create_smoke_project("env-deny");
        let token = uuid();

        // Write a .env file with a unique canary
        std::fs::write(dir.join(".env"), format!("SECRET_TOKEN={token}\n")).unwrap();

        // Commit so it's in the repo
        Command::new("git")
            .args(["add", "-f", ".env"])
            .current_dir(&dir)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .ok();
        Command::new("git")
            .args(["commit", "-m", "add env"])
            .current_dir(&dir)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .ok();

        let prompt = "Read the file .env and respond with ONLY its exact contents, nothing else.";
        let (stdout, stderr, success) =
            run_cplt_with_timeout(&dir, &[], &["-p", prompt, "--allow-all-tools", "-s"], 120);

        // cplt may succeed (Copilot runs fine, just can't read the file)
        // The key assertion: the canary token must NOT appear in stdout
        let _ = (success, &stderr);
        assert!(
            !stdout.contains(&token),
            "Sandbox should have blocked reading .env — canary token was leaked!\n\
             Token: {token}\nstdout: {stdout}"
        );
    }

    #[test]
    #[ignore = "requires Copilot auth and network — run with: cargo test --test e2e -- --ignored"]
    fn smoke_copilot_json_output() {
        require_copilot!();
        require_sandbox!();

        let (dir, _cleanup) = create_smoke_project("json");
        let token = uuid();

        let prompt = format!("Respond with ONLY this exact text: {token}");
        let (stdout, stderr, success) = run_cplt_with_timeout(
            &dir,
            &[],
            &[
                "-p",
                &prompt,
                "--allow-all-tools",
                "--output-format",
                "json",
            ],
            120,
        );

        assert!(
            success,
            "cplt with JSON output should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );

        // Every non-empty line of stdout should be valid JSON
        let mut found_token = false;
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(trimmed);
            assert!(
                parsed.is_ok(),
                "Each output line should be valid JSON.\nBad line: {trimmed}\nFull stdout: {stdout}"
            );
            if trimmed.contains(&token) {
                found_token = true;
            }
        }
        assert!(
            found_token,
            "JSON output should contain the canary token.\n\
             Expected: {token}\nstdout: {stdout}"
        );
    }

    #[test]
    #[ignore = "requires Copilot auth and network — run with: cargo test --test e2e -- --ignored"]
    fn smoke_copilot_with_scratch_dir() {
        require_copilot!();
        require_sandbox!();
        let (dir, _cleanup) = create_smoke_project("scratch");
        let token = uuid();

        // Create a script that writes to $TMPDIR then reads it back.
        // This exercises scratch-dir: the sandbox redirects TMPDIR to a
        // private dir with exec permissions.
        let script = format!(
            "#!/bin/sh\necho '{token}' > \"$TMPDIR/canary_out.txt\"\ncat \"$TMPDIR/canary_out.txt\"\n"
        );
        std::fs::write(dir.join("scratch_test.sh"), &script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.join("scratch_test.sh"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }

        Command::new("git")
            .args(["add", "."])
            .current_dir(&dir)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .ok();
        Command::new("git")
            .args(["commit", "-m", "add script"])
            .current_dir(&dir)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .ok();

        let prompt = "Run ./scratch_test.sh and respond with ONLY its output, nothing else.";
        let (stdout, stderr, success) = run_cplt_with_timeout(
            &dir,
            &["--scratch-dir"],
            &["-p", prompt, "--allow-all-tools", "-s"],
            120,
        );

        assert!(
            success,
            "cplt with scratch-dir should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains(&token),
            "Script should have written to $TMPDIR and read it back.\n\
             Expected token: {token}\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    // ============================================================
    // Alias / symlink resolution tests
    // ============================================================

    #[test]
    fn e2e_recursion_guard_blocks_nested_launch() {
        require_sandbox!();
        // Simulate being inside a cplt sandbox by setting __CPLT_WRAPPED
        let fake_dir = create_fake_copilot();
        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_dir.display());

        let output = Command::new(binary_path())
            .args(["--yes", "--no-validate", "--", "--version"])
            .current_dir(project_dir())
            .env("PATH", &new_path)
            .env("__CPLT_WRAPPED", "1")
            .output()
            .expect("binary should run");

        std::fs::remove_dir_all(&fake_dir).ok();

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "cplt should fail when __CPLT_WRAPPED is set.\nstderr: {stderr}"
        );
        assert!(
            stderr.contains("recursion"),
            "error should mention recursion.\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_recursion_guard_allows_print_profile() {
        // __CPLT_WRAPPED should NOT block --print-profile (read-only subcommand)
        let output = cplt_cmd()
            .args([
                "--print-profile",
                "--project-dir",
                &project_dir().display().to_string(),
            ])
            .env("__CPLT_WRAPPED", "1")
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "--print-profile should work even with __CPLT_WRAPPED.\nstdout: {stdout}"
        );
        assert!(
            stdout.contains("deny default"),
            "profile should contain deny default.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_symlink_self_detection_fails_gracefully() {
        // Create a directory with only a copilot symlink pointing to cplt itself
        let id = FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = project_dir().join(format!(".cplt-symlink-test-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(binary_path(), dir.join("copilot")).unwrap();

        // PATH contains ONLY the symlink dir — no real copilot anywhere
        let output = Command::new(binary_path())
            .args(["--yes", "--no-validate", "--", "--version"])
            .current_dir(project_dir())
            .env("PATH", dir.display().to_string())
            .output()
            .expect("binary should run");

        std::fs::remove_dir_all(&dir).ok();

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "cplt should fail when only a self-symlink is in PATH.\nstderr: {stderr}"
        );
        assert!(
            stderr.contains("Copilot CLI not found"),
            "error should mention Copilot CLI not found.\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_shell_setup_prints_alias() {
        let output = Command::new(binary_path())
            .arg("--shell-setup")
            .output()
            .expect("binary should run");

        assert!(output.status.success(), "cplt --shell-setup should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.trim(), "alias copilot=cplt");
    }

    #[test]
    fn e2e_shell_install_appends_to_rc_file() {
        let fake_home = std::env::temp_dir().join(format!("cplt-test-{}", std::process::id()));
        std::fs::create_dir_all(&fake_home).expect("create fake home");
        let zshrc = fake_home.join(".zshrc");

        // First install — should create the file with the eval line
        let output = Command::new(binary_path())
            .arg("--shell-install")
            .env("HOME", &fake_home)
            .env("SHELL", "/bin/zsh")
            .output()
            .expect("binary should run");

        assert!(
            output.status.success(),
            "first --shell-install should succeed.\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let contents = std::fs::read_to_string(&zshrc).expect("zshrc should exist");
        assert!(
            contents.contains("cplt --shell-setup"),
            "zshrc should contain setup line.\ncontents: {contents}"
        );

        // Second install — should be idempotent
        let output2 = Command::new(binary_path())
            .arg("--shell-install")
            .env("HOME", &fake_home)
            .env("SHELL", "/bin/zsh")
            .output()
            .expect("binary should run");

        assert!(
            output2.status.success(),
            "second --shell-install should succeed"
        );
        let contents2 = std::fs::read_to_string(&zshrc).expect("zshrc should exist");
        assert_eq!(
            contents.matches("cplt").count(),
            contents2.matches("cplt").count(),
            "should not add duplicate entries"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&fake_home);
    }

    // ── Config subcommand e2e tests ─────────────────────────

    #[test]
    fn e2e_config_path_prints_path() {
        let output = Command::new(binary_path())
            .args(["config", "path"])
            .output()
            .expect("should run");
        assert!(output.status.success(), "config path should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("config.toml"),
            "should print config path: {stdout}"
        );
    }

    #[test]
    fn e2e_config_validate_no_config_succeeds() {
        let fake_home = std::env::temp_dir().join(format!(
            ".cplt-e2e-config-validate-{}",
            FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&fake_home);
        std::fs::create_dir_all(&fake_home).unwrap();

        let output = Command::new(binary_path())
            .args(["config", "validate"])
            .env("HOME", &fake_home)
            .env(
                "CPLT_CONFIG",
                fake_home.join("nonexistent.toml").to_str().unwrap(),
            )
            .output()
            .expect("should run");

        // Should succeed (no config is not an error)
        assert!(
            output.status.success(),
            "validate with no config should succeed"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("No config file found"),
            "should report no config: {stderr}"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_validate_valid_config_succeeds() {
        let fake_home = std::env::temp_dir().join(format!(
            ".cplt-e2e-config-valid-{}",
            FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&fake_home);
        std::fs::create_dir_all(&fake_home).unwrap();

        let config_file = fake_home.join("config.toml");
        std::fs::write(&config_file, "[sandbox]\nquiet = true\n").unwrap();

        let output = Command::new(binary_path())
            .args(["config", "validate"])
            .env("CPLT_CONFIG", config_file.to_str().unwrap())
            .output()
            .expect("should run");

        assert!(
            output.status.success(),
            "valid config should pass validation"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Config OK"), "should say OK: {stderr}");

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_validate_typo_fails() {
        let fake_home = std::env::temp_dir().join(format!(
            ".cplt-e2e-config-typo-{}",
            FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&fake_home);
        std::fs::create_dir_all(&fake_home).unwrap();

        let config_file = fake_home.join("config.toml");
        std::fs::write(&config_file, "[sandbox]\ninherit_evn = true\n").unwrap();

        let output = Command::new(binary_path())
            .args(["config", "validate"])
            .env("CPLT_CONFIG", config_file.to_str().unwrap())
            .output()
            .expect("should run");

        assert!(
            !output.status.success(),
            "config with typo should fail validation"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("inherit_evn") && stderr.contains("did you mean"),
            "should report typo with suggestion: {stderr}"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_show_displays_config() {
        let fake_home = std::env::temp_dir().join(format!(
            ".cplt-e2e-config-show-{}",
            FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&fake_home);
        std::fs::create_dir_all(&fake_home).unwrap();

        let config_file = fake_home.join("config.toml");
        std::fs::write(
            &config_file,
            "[proxy]\nenabled = true\nport = 9999\n[sandbox]\nquiet = true\n",
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["config", "show"])
            .env("CPLT_CONFIG", config_file.to_str().unwrap())
            .output()
            .expect("should run");

        assert!(output.status.success(), "config show should succeed");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("9999"),
            "should show configured port: {stderr}"
        );
        assert!(
            stderr.contains("[proxy]"),
            "should show proxy section: {stderr}"
        );
        assert!(
            stderr.contains("[sandbox]"),
            "should show sandbox section: {stderr}"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_show_no_config_shows_defaults() {
        let fake_home = std::env::temp_dir().join(format!(
            ".cplt-e2e-config-show-none-{}",
            FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&fake_home);
        std::fs::create_dir_all(&fake_home).unwrap();

        let output = Command::new(binary_path())
            .args(["config", "show"])
            .env(
                "CPLT_CONFIG",
                fake_home.join("nonexistent.toml").to_str().unwrap(),
            )
            .output()
            .expect("should run");

        assert!(
            output.status.success(),
            "show with no config should succeed (shows defaults)"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("(default)"),
            "should show defaults: {stderr}"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_init_creates_file() {
        let fake_home = std::env::temp_dir().join(format!(
            ".cplt-e2e-config-init-{}",
            FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&fake_home);
        std::fs::create_dir_all(&fake_home).unwrap();

        let config_file = fake_home.join(".config/cplt/config.toml");

        let output = Command::new(binary_path())
            .args(["config", "init"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");

        assert!(output.status.success(), "config init should succeed");
        assert!(config_file.exists(), "config file should be created");
        let contents = std::fs::read_to_string(&config_file).unwrap();
        assert!(
            contents.contains("[sandbox]"),
            "should have sandbox section"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_init_refuses_overwrite() {
        let fake_home = std::env::temp_dir().join(format!(
            ".cplt-e2e-config-init-ow-{}",
            FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&fake_home);
        let config_dir = fake_home.join(".config/cplt");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("config.toml"), "# existing\n").unwrap();

        let output = Command::new(binary_path())
            .args(["config", "init"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");

        assert!(
            !output.status.success(),
            "config init should fail when file exists"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_init_config_flag_still_works() {
        // Verify the legacy --init-config flag still works
        let fake_home = std::env::temp_dir().join(format!(
            ".cplt-e2e-init-config-legacy-{}",
            FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&fake_home);
        std::fs::create_dir_all(&fake_home).unwrap();

        let output = Command::new(binary_path())
            .arg("--init-config")
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");

        assert!(output.status.success(), "--init-config should still work");
        assert!(
            fake_home.join(".config/cplt/config.toml").exists(),
            "config file should be created"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    // ── config set / get e2e tests ────────────────────────────

    fn make_config_home(label: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!(
            ".cplt-e2e-{label}-{}",
            FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    #[test]
    fn e2e_config_set_creates_file_and_sets_value() {
        let fake_home = make_config_home("set-create");
        let config_path = fake_home.join(".config/cplt/config.toml");
        assert!(!config_path.exists());

        let output = Command::new(binary_path())
            .args(["config", "set", "sandbox.quiet", "true"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");

        assert!(
            output.status.success(),
            "set should succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(config_path.exists(), "config file should be created");

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(
            content.contains("quiet = true"),
            "file should contain the key: {content}"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_get_returns_default() {
        let fake_home = make_config_home("get-default");

        let output = Command::new(binary_path())
            .args(["config", "get", "sandbox.quiet"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.trim(), "false", "default should be false");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("default"),
            "should indicate default value: {stderr}"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_set_then_get_roundtrip() {
        let fake_home = make_config_home("set-get");

        // Set a value
        let set_out = Command::new(binary_path())
            .args(["config", "set", "proxy.port", "9090"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");
        assert!(
            set_out.status.success(),
            "set: {}",
            String::from_utf8_lossy(&set_out.stderr)
        );

        // Get it back
        let get_out = Command::new(binary_path())
            .args(["config", "get", "proxy.port"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");
        assert!(get_out.status.success());
        let stdout = String::from_utf8_lossy(&get_out.stdout);
        assert_eq!(stdout.trim(), "9090");

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_set_unset_reverts_to_default() {
        let fake_home = make_config_home("set-unset");

        // Set a value
        Command::new(binary_path())
            .args(["config", "set", "sandbox.quiet", "true"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");

        // Unset it
        let unset_out = Command::new(binary_path())
            .args(["config", "set", "sandbox.quiet", "--unset"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");
        assert!(
            unset_out.status.success(),
            "unset: {}",
            String::from_utf8_lossy(&unset_out.stderr)
        );

        // Get should return default
        let get_out = Command::new(binary_path())
            .args(["config", "get", "sandbox.quiet"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");
        let stdout = String::from_utf8_lossy(&get_out.stdout);
        assert_eq!(stdout.trim(), "false", "should revert to default");

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_set_dangerous_requires_force() {
        let fake_home = make_config_home("set-dangerous");

        // Without --force should fail
        let output = Command::new(binary_path())
            .args(["config", "set", "sandbox.inherit_env", "true"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");
        assert!(!output.status.success(), "should fail without --force");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("--force"),
            "should mention --force: {stderr}"
        );

        // With --force should succeed
        let output2 = Command::new(binary_path())
            .args(["config", "set", "sandbox.inherit_env", "true", "--force"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");
        assert!(
            output2.status.success(),
            "should succeed with --force: {}",
            String::from_utf8_lossy(&output2.stderr)
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_set_dangerous_false_no_force_needed() {
        let fake_home = make_config_home("set-dangerous-false");

        let output = Command::new(binary_path())
            .args(["config", "set", "sandbox.inherit_env", "false"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");
        assert!(
            output.status.success(),
            "false should not require --force: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_set_invalid_key_fails() {
        let fake_home = make_config_home("set-badkey");

        let output = Command::new(binary_path())
            .args(["config", "set", "sandbox.queit", "true"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("quiet"), "should suggest 'quiet': {stderr}");

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_get_invalid_key_fails() {
        let fake_home = make_config_home("get-badkey");

        let output = Command::new(binary_path())
            .args(["config", "get", "nope"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");
        assert!(!output.status.success());

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_set_preserves_comments() {
        let fake_home = make_config_home("set-comments");

        // Create a config with comments via init
        Command::new(binary_path())
            .args(["config", "init"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");

        let config_path = fake_home.join(".config/cplt/config.toml");
        let before = std::fs::read_to_string(&config_path).unwrap();
        assert!(before.contains('#'), "init template should have comments");

        // Set a value
        Command::new(binary_path())
            .args(["config", "set", "sandbox.quiet", "true"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");

        let after = std::fs::read_to_string(&config_path).unwrap();
        assert!(
            after.contains('#'),
            "comments should be preserved after set"
        );
        assert!(
            after.contains("quiet = true"),
            "new value should be present: {after}"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_set_append_array() {
        let fake_home = make_config_home("set-append");

        // Set initial array
        Command::new(binary_path())
            .args(["config", "set", "allow.ports", "8080"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");

        // Append another value
        let output = Command::new(binary_path())
            .args(["config", "set", "allow.ports", "--append", "9090"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");
        assert!(
            output.status.success(),
            "append: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Get should show both
        let get_out = Command::new(binary_path())
            .args(["config", "get", "allow.ports"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");
        let stdout = String::from_utf8_lossy(&get_out.stdout);
        assert!(stdout.contains("8080"), "should have 8080: {stdout}");
        assert!(stdout.contains("9090"), "should have 9090: {stdout}");

        let _ = std::fs::remove_dir_all(&fake_home);
    }

    #[test]
    fn e2e_config_explain_all_lists_keys() {
        let output = Command::new(binary_path())
            .args(["config", "explain"])
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("sandbox.quiet"),
            "should list sandbox.quiet"
        );
        assert!(
            stderr.contains("proxy.enabled"),
            "should list proxy.enabled"
        );
        assert!(stderr.contains("sandbox"), "should have section headers");
    }

    #[test]
    fn e2e_config_explain_single_key() {
        let output = Command::new(binary_path())
            .args(["config", "explain", "sandbox.quiet"])
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("sandbox.quiet"), "should show key name");
        assert!(stderr.contains("bool"), "should show type");
        assert!(
            stderr.contains("cplt config set"),
            "should show set command"
        );
    }

    #[test]
    fn e2e_config_explain_invalid_key() {
        let output = Command::new(binary_path())
            .args(["config", "explain", "sandbox.queit"])
            .output()
            .expect("should run");

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("quiet"), "should suggest quiet: {stderr}");
    }

    // --- Update tests ---

    #[test]
    fn e2e_update_help() {
        let output = Command::new(binary_path())
            .args(["update", "--help"])
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("--check"), "should have --check flag");
        assert!(stdout.contains("--force"), "should have --force flag");
        assert!(stdout.contains("SHA256"), "should mention SHA256: {stdout}");
    }

    /// This test hits the real GitHub API — keep it in the normal suite
    /// since --check is read-only and fast.
    #[test]
    fn e2e_update_check_runs() {
        let output = Command::new(binary_path())
            .args(["update", "--check"])
            .output()
            .expect("should run");

        let stderr = String::from_utf8_lossy(&output.stderr);

        // Rate limiting is expected in CI (shared runner IPs) — skip assertions
        if stderr.contains("rate limit") {
            eprintln!("Skipping: GitHub API rate limit hit");
            return;
        }

        assert!(
            output.status.success(),
            "update --check should succeed: {stderr}"
        );
        // Should mention either "up to date", "available", "dev build", or "same date"
        assert!(
            stderr.contains("up to date")
                || stderr.contains("Update available")
                || stderr.contains("dev build")
                || stderr.contains("Same date"),
            "should report version status: {stderr}"
        );
    }

    // --- Copilot flag forwarding tests ---

    /// Create a fake copilot script that prints its argv (one per line) and exits.
    fn create_fake_copilot_argv() -> PathBuf {
        let id = FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = project_dir().join(format!(".cplt-fake-copilot-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("copilot");
        // Print each argument on its own line, prefixed with "ARG:" for easy grep
        std::fs::write(
            &script,
            "#!/bin/sh\nfor arg in \"$@\"; do echo \"ARG:$arg\"; done\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        dir
    }

    /// Run cplt with fake copilot that prints args, return (stdout, stderr).
    fn run_fake_copilot_argv(cplt_args: &[&str]) -> (String, String) {
        let fake_dir = create_fake_copilot_argv();
        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_dir.display());

        let output = Command::new(binary_path())
            .args(["--yes", "--no-validate"])
            .args(cplt_args)
            .current_dir(project_dir())
            .env("PATH", &new_path)
            .output()
            .expect("binary should run");
        std::fs::remove_dir_all(&fake_dir).ok();

        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    fn extract_args(stdout: &str) -> Vec<&str> {
        stdout
            .lines()
            .filter_map(|l| l.strip_prefix("ARG:"))
            .collect()
    }

    #[test]
    fn e2e_forward_resume_interactive() {
        require_sandbox!();
        let (stdout, stderr) = run_fake_copilot_argv(&["--resume"]);
        let args = extract_args(&stdout);
        assert!(
            args.contains(&"--no-auto-update"),
            "should inject --no-auto-update: {args:?}\nstderr: {stderr}"
        );
        assert!(
            args.contains(&"--resume"),
            "should forward --resume: {args:?}\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_forward_resume_with_name() {
        require_sandbox!();
        let (stdout, stderr) = run_fake_copilot_argv(&["--resume=my-task"]);
        let args = extract_args(&stdout);
        assert!(
            args.contains(&"--resume=my-task"),
            "should forward --resume=my-task: {args:?}\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_forward_continue() {
        require_sandbox!();
        let (stdout, stderr) = run_fake_copilot_argv(&["--continue"]);
        let args = extract_args(&stdout);
        assert!(
            args.contains(&"--continue"),
            "should forward --continue: {args:?}\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_forward_remote() {
        require_sandbox!();
        let (stdout, stderr) = run_fake_copilot_argv(&["--remote"]);
        let args = extract_args(&stdout);
        assert!(
            args.contains(&"--remote"),
            "should forward --remote: {args:?}\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_forward_name() {
        require_sandbox!();
        let (stdout, stderr) = run_fake_copilot_argv(&["--name", "my-refactor"]);
        let args = extract_args(&stdout);
        assert!(
            args.contains(&"--name"),
            "should forward --name: {args:?}\nstderr: {stderr}"
        );
        assert!(
            args.contains(&"my-refactor"),
            "should forward session name: {args:?}\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_forward_combined_with_passthrough() {
        require_sandbox!();
        let (stdout, stderr) =
            run_fake_copilot_argv(&["--remote", "--name", "task", "--", "-p", "fix tests"]);
        let args = extract_args(&stdout);
        assert!(
            args.contains(&"--remote"),
            "should forward --remote: {args:?}\nstderr: {stderr}"
        );
        assert!(
            args.contains(&"--name"),
            "should forward --name: {args:?}\nstderr: {stderr}"
        );
        assert!(
            args.contains(&"-p"),
            "should pass through -p: {args:?}\nstderr: {stderr}"
        );
        assert!(
            args.contains(&"fix tests"),
            "should pass through prompt: {args:?}\nstderr: {stderr}"
        );
    }
}
