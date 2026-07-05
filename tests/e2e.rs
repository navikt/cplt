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
    use std::path::{Path, PathBuf};
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
            .map_or_else(
                || project_dir().to_string_lossy().to_string(),
                |s| s.trim().to_string(),
            );

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
        // Create a temp project with a subdir to deny. TempDir auto-cleans on
        // drop (including panic); the project path is passed explicitly so no
        // fixture is written into the repo checkout.
        let project = tempfile::tempdir().unwrap();
        let deny_dir = project.path().join("test-deny-e2e-target");
        std::fs::create_dir_all(&deny_dir).unwrap();
        let deny_dir_canonical = std::fs::canonicalize(&deny_dir).unwrap();

        let output = cplt_cmd()
            .args([
                "--project-dir",
                &project.path().to_string_lossy(),
                "--deny-path",
                &deny_dir.to_string_lossy(),
                "--print-profile",
            ])
            .output()
            .expect("binary should run");

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

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            stdout.contains("[doctor]") && stdout.contains("Auth"),
            "--doctor should print Auth section.\nstdout: {stdout}"
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

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            stdout.contains("Agents") && stdout.contains("Copilot"),
            "--doctor should show Agents section with Copilot.\nstdout: {stdout}"
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

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            stdout.contains("Tools") && stdout.contains("git"),
            "--doctor should show Tools section with git.\nstdout: {stdout}"
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

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            stdout.contains("Sandbox paths") && stdout.contains("Protected"),
            "--doctor should show Sandbox paths with protected dirs.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_doctor_subcommand_works() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["doctor"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "cplt doctor should exit 0.\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("[doctor]"),
            "should have doctor output.\nstdout: {stdout}"
        );
        // No deprecation warning for subcommand form
        assert!(
            !stderr.contains("deprecated"),
            "subcommand should not warn.\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_doctor_flag_shows_deprecation() {
        require_copilot!();
        let output = Command::new(binary_path())
            .args(["--doctor"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "--doctor should still work.\nstderr: {stderr}"
        );
        assert!(
            stderr.contains("deprecated") && stderr.contains("cplt doctor"),
            "--doctor should show deprecation warning.\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_doctor_shows_project_ecosystems() {
        // Create a project with a Cargo.toml so ecosystems are detected
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["doctor"])
            .current_dir(dir.path())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Doctor may exit non-zero if no agent/auth is found (CI), but it
        // should still print ecosystem detection results regardless.
        assert!(
            stdout.contains("Project ecosystems") && stdout.contains("Rust"),
            "should detect Rust ecosystem.\nstdout: {stdout}"
        );
    }

    // ============================================================
    // Color environment variable tests
    // ============================================================

    #[test]
    fn e2e_no_color_suppresses_ansi() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["doctor"])
            .current_dir(dir.path())
            .env("NO_COLOR", "1")
            .env_remove("FORCE_COLOR")
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("\x1b["),
            "NO_COLOR should suppress ANSI codes in stdout.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_term_dumb_suppresses_ansi() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["doctor"])
            .current_dir(dir.path())
            .env("TERM", "dumb")
            .env_remove("NO_COLOR")
            .env_remove("FORCE_COLOR")
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("\x1b["),
            "TERM=dumb should suppress ANSI codes in stdout.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_force_color_overrides_no_color() {
        // Create a project dir so doctor has something to detect
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["doctor"])
            .current_dir(dir.path())
            .env("NO_COLOR", "1")
            .env("FORCE_COLOR", "1")
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("\x1b["),
            "FORCE_COLOR should override NO_COLOR and emit ANSI.\nstdout: {stdout}"
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
    fn e2e_print_profile_deny_clipboard_emits_pasteboard_deny() {
        require_copilot!();
        let output = cplt_cmd()
            .args(["--deny-clipboard", "--print-profile"])
            .current_dir(project_dir())
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        let allow_idx = stdout
            .find("(allow mach-lookup)")
            .expect("profile should include mach-lookup allow");
        let deny_idx = stdout
            .find(r#"(deny mach-lookup (global-name-regex #"^com\.apple\.pasteboard(\.|$)"))"#)
            .expect("profile should include pasteboard deny when --deny-clipboard is set");
        assert!(
            deny_idx > allow_idx,
            "pasteboard deny must appear after mach allow (SBPL last-match-wins).\nstdout: {stdout}"
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
    /// Placed inside the project dir (repo root) so the sandbox allows execution
    /// (process-exec is denied in /tmp and /private/var/folders).
    ///
    /// Returns a `tempfile::TempDir` that removes the script directory on drop —
    /// including on panic (Drop runs during unwind). The `.cplt-e2e-` prefix
    /// keeps the single defensive `.gitignore` pattern effective on SIGKILL.
    fn create_fake_copilot() -> tempfile::TempDir {
        let dir = tempfile::Builder::new()
            .prefix(".cplt-e2e-fake-copilot-")
            .tempdir_in(project_dir())
            .expect("create fake copilot dir");
        let script = dir.path().join("copilot");
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
        let new_path = format!("{}:{current_path}", fake_dir.path().display());

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

        if let Ok(Ok(output)) = handle.join() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            (stdout, stderr, output.status.success())
        } else {
            // Kill the process if the thread panicked
            unsafe {
                libc::kill(id as i32, libc::SIGKILL);
            }
            panic!("cplt timed out after {timeout_secs}s or thread panicked");
        }
    }

    /// Create a temp project dir inside the repo root (not /tmp, which denies exec).
    ///
    /// Backed by `tempfile::TempDir`, so it auto-deletes on drop — including on
    /// panic (Drop runs during unwind). Callers keep the returned `TempDir`
    /// alive for the duration of the test. The `.cplt-e2e-` prefix keeps the
    /// single defensive `.gitignore` pattern effective on SIGKILL.
    fn create_smoke_project(name: &str) -> tempfile::TempDir {
        let dir = tempfile::Builder::new()
            .prefix(&format!(".cplt-e2e-smoke-{name}-"))
            .tempdir_in(project_dir())
            .expect("create smoke project dir");

        // Initialize git so Copilot doesn't complain
        let run_git = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@test.com")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@test.com")
                .output()
                .ok();
        };
        run_git(&["init", "-b", "main"]);

        dir
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
        let tmp = create_smoke_project("read");
        let dir = tmp.path().to_path_buf();
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
        let tmp = create_smoke_project("write");
        let dir = tmp.path().to_path_buf();
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
        let tmp = create_smoke_project("shell");
        let dir = tmp.path().to_path_buf();
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
        let tmp = create_smoke_project("env-deny");
        let dir = tmp.path().to_path_buf();
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

        let tmp = create_smoke_project("json");
        let dir = tmp.path().to_path_buf();
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
        let tmp = create_smoke_project("scratch");
        let dir = tmp.path().to_path_buf();
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
        let new_path = format!("{}:{current_path}", fake_dir.path().display());

        let output = Command::new(binary_path())
            .args(["--yes", "--no-validate", "--", "--version"])
            .current_dir(project_dir())
            .env("PATH", &new_path)
            .env("__CPLT_WRAPPED", "1")
            .output()
            .expect("binary should run");

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
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "--print-profile should work even with __CPLT_WRAPPED.\n\
             exit code: {:?}\nstdout: {stdout}\nstderr: {stderr}",
            output.status.code()
        );
        assert!(
            stdout.contains("deny default"),
            "profile should contain deny default.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_symlink_self_detection_fails_gracefully() {
        // Create a directory with only a copilot symlink pointing to cplt itself.
        // TempDir (under the repo root, exec-allowed) auto-cleans on drop/panic.
        let dir = tempfile::Builder::new()
            .prefix(".cplt-e2e-symlink-test-")
            .tempdir_in(project_dir())
            .expect("create symlink test dir");

        #[cfg(unix)]
        std::os::unix::fs::symlink(binary_path(), dir.path().join("copilot")).unwrap();

        // PATH contains ONLY the symlink dir — no real copilot anywhere
        let output = Command::new(binary_path())
            .args(["--yes", "--no-validate", "--", "--version"])
            .current_dir(project_dir())
            .env("PATH", dir.path().display().to_string())
            .output()
            .expect("binary should run");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "cplt should fail when only a self-symlink is in PATH.\nstderr: {stderr}"
        );
        assert!(
            stderr.contains("No supported AI coding agent found")
                || stderr.contains("not found in PATH"),
            "error should mention agent not found.\nstderr: {stderr}"
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
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("9999"),
            "should show configured port: {stdout}"
        );
        assert!(
            stdout.contains("[proxy]"),
            "should show proxy section: {stdout}"
        );
        assert!(
            stdout.contains("[sandbox]"),
            "should show sandbox section: {stdout}"
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
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("(default)"),
            "should show defaults: {stdout}"
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

    // ── config set --repo e2e tests ──────────────────────────────

    fn make_repo_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            ".cplt-e2e-repo-{label}-{}",
            FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Initialize git repo (required for repo detection)
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&dir)
            .output()
            .unwrap();
        dir
    }

    #[test]
    fn e2e_config_set_repo_creates_cplt_toml_with_propose() {
        let repo = make_repo_dir("set-repo-create");
        let cplt_toml = repo.join(".cplt.toml");
        assert!(!cplt_toml.exists());

        let output = Command::new(binary_path())
            .args([
                "config",
                "set",
                "--repo",
                "sandbox.allow_jvm_attach",
                "true",
            ])
            .current_dir(&repo)
            .output()
            .expect("should run");

        assert!(
            output.status.success(),
            "set --repo should succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(cplt_toml.exists(), ".cplt.toml should be created");

        let content = std::fs::read_to_string(&cplt_toml).unwrap();
        assert!(
            content.contains("[propose]"),
            "should have [propose] section: {content}"
        );
        assert!(
            content.contains("allow_jvm_attach = true"),
            "should have the key: {content}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_config_set_repo_deny_paths() {
        let repo = make_repo_dir("set-repo-deny");

        let output = Command::new(binary_path())
            .args(["config", "set", "--repo", "deny.paths", "~/secrets"])
            .current_dir(&repo)
            .output()
            .expect("should run");

        assert!(
            output.status.success(),
            "set --repo deny: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let content = std::fs::read_to_string(repo.join(".cplt.toml")).unwrap();
        assert!(
            content.contains("[deny]"),
            "should have [deny] section: {content}"
        );
        assert!(
            content.contains("\"~/secrets\""),
            "should have the path: {content}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_config_set_repo_propose_allow_array() {
        let repo = make_repo_dir("set-repo-allow-arr");

        // Set first read path
        Command::new(binary_path())
            .args([
                "config",
                "set",
                "--repo",
                "allow.read",
                "~/.gradle/gradle.properties",
            ])
            .current_dir(&repo)
            .output()
            .expect("should run");

        // Append second
        let output = Command::new(binary_path())
            .args([
                "config",
                "set",
                "--repo",
                "allow.read",
                "~/.m2/settings.xml",
            ])
            .current_dir(&repo)
            .output()
            .expect("should run");

        assert!(
            output.status.success(),
            "append: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let content = std::fs::read_to_string(repo.join(".cplt.toml")).unwrap();
        assert!(
            content.contains("[propose.allow]"),
            "should have [propose.allow]: {content}"
        );
        assert!(
            content.contains("~/.gradle/gradle.properties"),
            "should have first path: {content}"
        );
        assert!(
            content.contains("~/.m2/settings.xml"),
            "should have second path: {content}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_config_set_repo_rejects_invalid_key() {
        let repo = make_repo_dir("set-repo-invalid");

        let output = Command::new(binary_path())
            .args(["config", "set", "--repo", "sandbox.quiet", "true"])
            .current_dir(&repo)
            .output()
            .expect("should run");

        assert!(!output.status.success(), "should fail for invalid repo key");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("not valid in repo config"),
            "should explain why: {stderr}"
        );
        assert!(
            stderr.contains("local CLI output"),
            "should give reason: {stderr}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_config_set_repo_rejects_false_proposal() {
        let repo = make_repo_dir("set-repo-false");

        let output = Command::new(binary_path())
            .args([
                "config",
                "set",
                "--repo",
                "sandbox.allow_jvm_attach",
                "false",
            ])
            .current_dir(&repo)
            .output()
            .expect("should run");

        assert!(!output.status.success(), "should reject false proposals");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("no effect"),
            "should explain false has no effect: {stderr}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_config_set_repo_dangerous_requires_force() {
        let repo = make_repo_dir("set-repo-danger");

        // Without --force
        let output = Command::new(binary_path())
            .args(["config", "set", "--repo", "sandbox.allow_docker", "true"])
            .current_dir(&repo)
            .output()
            .expect("should run");

        assert!(!output.status.success(), "should fail without --force");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("dangerous"),
            "should warn about danger: {stderr}"
        );

        // With --force
        let output = Command::new(binary_path())
            .args([
                "config",
                "set",
                "--repo",
                "sandbox.allow_docker",
                "true",
                "--force",
            ])
            .current_dir(&repo)
            .output()
            .expect("should run");

        assert!(
            output.status.success(),
            "should succeed with --force: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let content = std::fs::read_to_string(repo.join(".cplt.toml")).unwrap();
        assert!(
            content.contains("allow_docker = true"),
            "should be set: {content}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_config_set_repo_unset_removes_proposal() {
        let repo = make_repo_dir("set-repo-unset");

        // Set a value first
        Command::new(binary_path())
            .args([
                "config",
                "set",
                "--repo",
                "sandbox.allow_jvm_attach",
                "true",
            ])
            .current_dir(&repo)
            .output()
            .expect("should run");

        // Unset it
        let output = Command::new(binary_path())
            .args([
                "config",
                "set",
                "--repo",
                "sandbox.allow_jvm_attach",
                "--unset",
            ])
            .current_dir(&repo)
            .output()
            .expect("should run");

        assert!(
            output.status.success(),
            "unset: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let content = std::fs::read_to_string(repo.join(".cplt.toml")).unwrap();
        assert!(
            !content.contains("allow_jvm_attach"),
            "key should be removed: {content}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_config_set_repo_port_array() {
        let repo = make_repo_dir("set-repo-ports");

        let output = Command::new(binary_path())
            .args(["config", "set", "--repo", "allow.ports", "8080"])
            .current_dir(&repo)
            .output()
            .expect("should run");

        assert!(
            output.status.success(),
            "port set: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let content = std::fs::read_to_string(repo.join(".cplt.toml")).unwrap();
        assert!(content.contains("8080"), "should have port: {content}");

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_config_set_repo_idempotent_no_duplicates() {
        let repo = make_repo_dir("set-repo-idem");

        // Set same value twice
        for _ in 0..2 {
            Command::new(binary_path())
                .args(["config", "set", "--repo", "allow.read", "~/.gradle"])
                .current_dir(&repo)
                .output()
                .expect("should run");
        }

        let content = std::fs::read_to_string(repo.join(".cplt.toml")).unwrap();
        let count = content.matches("~/.gradle").count();
        assert_eq!(count, 1, "should not duplicate: {content}");

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_config_set_repo_proxy_private_domains() {
        let repo = make_repo_dir("set-repo-proxy");

        let output = Command::new(binary_path())
            .args([
                "config",
                "set",
                "--repo",
                "proxy.allow_private_domains",
                "intern.nav.no",
            ])
            .current_dir(&repo)
            .output()
            .expect("should run");

        assert!(
            output.status.success(),
            "proxy domain: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let content = std::fs::read_to_string(repo.join(".cplt.toml")).unwrap();
        assert!(
            content.contains("[propose.proxy]"),
            "should have [propose.proxy]: {content}"
        );
        assert!(
            content.contains("intern.nav.no"),
            "should have domain: {content}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_config_set_repo_deny_env() {
        let repo = make_repo_dir("set-repo-deny-env");

        let output = Command::new(binary_path())
            .args(["config", "set", "--repo", "deny.env", "VAULT_TOKEN"])
            .current_dir(&repo)
            .output()
            .expect("should run");

        assert!(
            output.status.success(),
            "deny.env: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let content = std::fs::read_to_string(repo.join(".cplt.toml")).unwrap();
        assert!(content.contains("[deny]"), "should have [deny]: {content}");
        assert!(
            content.contains("\"VAULT_TOKEN\""),
            "should have env var: {content}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_config_explain_all_lists_keys() {
        let output = Command::new(binary_path())
            .args(["config", "explain"])
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("sandbox.quiet"),
            "should list sandbox.quiet"
        );
        assert!(
            stdout.contains("proxy.enabled"),
            "should list proxy.enabled"
        );
        assert!(stdout.contains("sandbox"), "should have section headers");
    }

    #[test]
    fn e2e_config_explain_single_key() {
        let output = Command::new(binary_path())
            .args(["config", "explain", "sandbox.quiet"])
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("sandbox.quiet"), "should show key name");
        assert!(stdout.contains("bool"), "should show type");
        assert!(
            stdout.contains("cplt config set"),
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
    ///
    /// Returns a `tempfile::TempDir` (under the repo root, exec-allowed) that
    /// auto-deletes on drop, including on panic.
    fn create_fake_copilot_argv() -> tempfile::TempDir {
        let dir = tempfile::Builder::new()
            .prefix(".cplt-e2e-fake-copilot-")
            .tempdir_in(project_dir())
            .expect("create fake copilot dir");
        let script = dir.path().join("copilot");
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
        let new_path = format!("{}:{current_path}", fake_dir.path().display());

        let output = Command::new(binary_path())
            .args(["--yes", "--no-validate"])
            .args(cplt_args)
            .current_dir(project_dir())
            .env("PATH", &new_path)
            .output()
            .expect("binary should run");

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

    // ============================================================
    // Trust model e2e tests
    // ============================================================

    /// Create a git repo with a committed .cplt.toml and an isolated config dir.
    /// Returns (repo_dir, config_file_path).
    fn make_trust_repo(label: &str, cplt_toml_content: &str) -> (PathBuf, PathBuf) {
        let id = FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let repo = std::env::temp_dir().join(format!(".cplt-e2e-trust-{label}-{id}"));
        let _ = std::fs::remove_dir_all(&repo);
        std::fs::create_dir_all(&repo).unwrap();

        // Init git repo and commit .cplt.toml
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&repo)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(&repo)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(&repo)
            .output()
            .unwrap();

        std::fs::write(repo.join(".cplt.toml"), cplt_toml_content).unwrap();
        Command::new("git")
            .args(["add", ".cplt.toml"])
            .current_dir(&repo)
            .output()
            .unwrap();
        Command::new("git")
            .args([
                "-c",
                "commit.gpgSign=false",
                "commit",
                "-m",
                "init",
                "--quiet",
            ])
            .current_dir(&repo)
            .output()
            .unwrap();

        // Isolated config dir (no interference from user's real config)
        let config_dir = repo.join(".cplt-config");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("config.toml");
        std::fs::write(&config_file, "").unwrap();

        (repo, config_file)
    }

    /// Build a Command for the cplt binary with trust-related env vars cleared.
    /// Trust tests must not inherit __CPLT_TRUST_LOCKED from a parent sandbox.
    fn trust_cmd(repo: &Path, config_file: &Path) -> Command {
        let mut cmd = Command::new(binary_path());
        cmd.current_dir(repo)
            .env("CPLT_CONFIG", config_file.to_str().unwrap())
            .env_remove("__CPLT_TRUST_LOCKED");
        cmd
    }

    #[test]
    fn e2e_trust_show_displays_proposals() {
        let (repo, config_file) = make_trust_repo(
            "show",
            "[propose]\nallow_localhost_any = true\n\n[deny]\nenv = [\"VAULT_TOKEN\"]\n",
        );

        let output = trust_cmd(&repo, &config_file)
            .args(["trust"])
            .output()
            .expect("should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "trust show failed (stderr: {}, stdout: {})",
            String::from_utf8_lossy(&output.stderr),
            stdout
        );
        assert!(
            stdout.contains("allow_localhost_any"),
            "should show proposed key: {stdout}"
        );
        assert!(
            stdout.contains("VAULT_TOKEN"),
            "should show denied env: {stdout}"
        );
        assert!(
            stdout.contains("pending") || stdout.contains("○"),
            "should show pending status: {stdout}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_trust_accept_all_approves_proposals() {
        let (repo, config_file) =
            make_trust_repo("accept-all", "[propose]\nallow_localhost_any = true\n");

        // Before accept: should show pending
        let output = trust_cmd(&repo, &config_file)
            .args(["trust"])
            .output()
            .expect("should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("pending") || stdout.contains("○"),
            "before accept, should be pending: {stdout}"
        );

        // Accept all
        let output = trust_cmd(&repo, &config_file)
            .args(["trust", "accept", "--all"])
            .output()
            .expect("should run");
        assert!(
            output.status.success(),
            "accept should succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // After accept: should show approved
        let output = trust_cmd(&repo, &config_file)
            .args(["trust"])
            .output()
            .expect("should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("approved") || stdout.contains("✓"),
            "after accept, should be approved: {stdout}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_trust_accept_single_key_is_selective() {
        let (repo, config_file) = make_trust_repo(
            "accept-key",
            "[propose]\nallow_localhost_any = true\nallow_docker = true\n",
        );

        // Accept only one key
        let output = trust_cmd(&repo, &config_file)
            .args(["trust", "accept", "allow_localhost_any"])
            .output()
            .expect("should run");
        assert!(output.status.success());

        // Check status: one approved, one pending
        let output = trust_cmd(&repo, &config_file)
            .args(["trust"])
            .output()
            .expect("should run");
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Find lines for each key
        let localhost_line = stdout
            .lines()
            .find(|l| l.contains("allow_localhost_any"))
            .unwrap_or("");
        let docker_line = stdout
            .lines()
            .find(|l| l.contains("allow_docker"))
            .unwrap_or("");

        assert!(
            localhost_line.contains("✓") || localhost_line.contains("approved"),
            "allow_localhost_any should be approved: {localhost_line}"
        );
        assert!(
            docker_line.contains("○") || docker_line.contains("pending"),
            "allow_docker should be pending: {docker_line}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_trust_revoke_removes_approval() {
        let (repo, config_file) =
            make_trust_repo("revoke", "[propose]\nallow_localhost_any = true\n");

        // Accept, then revoke
        trust_cmd(&repo, &config_file)
            .args(["trust", "accept", "--all"])
            .output()
            .expect("accept should run");

        let output = trust_cmd(&repo, &config_file)
            .args(["trust", "revoke", "--all"])
            .output()
            .expect("revoke should run");
        assert!(output.status.success());

        // After revoke: should show pending
        let output = trust_cmd(&repo, &config_file)
            .args(["trust"])
            .output()
            .expect("should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("pending") || stdout.contains("○"),
            "after revoke, should be pending: {stdout}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_trust_content_hash_invalidation() {
        let (repo, config_file) = make_trust_repo(
            "hash-invalidation",
            "[propose]\nallow_localhost_any = true\n",
        );

        // Accept all
        trust_cmd(&repo, &config_file)
            .args(["trust", "accept", "--all"])
            .output()
            .expect("accept should run");

        // Modify and re-commit .cplt.toml with different proposals
        std::fs::write(
            repo.join(".cplt.toml"),
            "[propose]\nallow_localhost_any = true\nallow_docker = true\n",
        )
        .unwrap();
        Command::new("git")
            .args(["add", ".cplt.toml"])
            .current_dir(&repo)
            .output()
            .unwrap();
        Command::new("git")
            .args([
                "-c",
                "commit.gpgSign=false",
                "commit",
                "-m",
                "change proposals",
                "--quiet",
            ])
            .current_dir(&repo)
            .output()
            .unwrap();

        // After change: should show changed warning and pending status
        let output = trust_cmd(&repo, &config_file)
            .args(["trust"])
            .output()
            .expect("should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("changed") || stdout.contains("⚠"),
            "should warn about changed permissions: {stdout}"
        );
        // Keys should show pending (not approved) due to hash mismatch
        assert!(
            stdout.contains("pending") || stdout.contains("○"),
            "keys should be pending after hash change: {stdout}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_trust_isolation_between_repos() {
        let (repo_a, config_file) =
            make_trust_repo("isolation-a", "[propose]\nallow_localhost_any = true\n");
        let (repo_b, _) = make_trust_repo("isolation-b", "[propose]\nallow_localhost_any = true\n");

        // Accept in repo A (using shared config dir)
        trust_cmd(&repo_a, &config_file)
            .args(["trust", "accept", "--all"])
            .output()
            .expect("accept should run");

        // Repo A should show approved
        let output = trust_cmd(&repo_a, &config_file)
            .args(["trust"])
            .output()
            .expect("should run");
        let stdout_a = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout_a.contains("approved") || stdout_a.contains("✓"),
            "repo A should be approved: {stdout_a}"
        );

        // Repo B should still show pending (different fingerprint)
        let output = trust_cmd(&repo_b, &config_file)
            .args(["trust"])
            .output()
            .expect("should run");
        let stdout_b = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout_b.contains("pending") || stdout_b.contains("○"),
            "repo B should be pending (trust is per-repo): {stdout_b}"
        );

        let _ = std::fs::remove_dir_all(&repo_a);
        let _ = std::fs::remove_dir_all(&repo_b);
    }

    #[test]
    fn e2e_trust_deny_env_strips_variable() {
        require_sandbox!();
        let (repo, config_file) = make_trust_repo("deny-env", "[deny]\nenv = [\"VAULT_TOKEN\"]\n");

        // Create fake copilot in a repo-root TempDir (sandbox allows exec there;
        // auto-cleans on drop/panic).
        let fake_dir = tempfile::Builder::new()
            .prefix(".cplt-e2e-fake-deny-env-")
            .tempdir_in(project_dir())
            .expect("create fake copilot dir");
        let script = fake_dir.path().join("copilot");
        std::fs::write(&script, "#!/bin/sh\nenv | sort\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_dir.path().display());

        let output = Command::new(binary_path())
            .args(["--yes", "--no-validate", "--", "--version"])
            .current_dir(&repo)
            .env("PATH", &new_path)
            .env("CPLT_CONFIG", config_file.to_str().unwrap())
            .env("VAULT_TOKEN", "secret-value-123")
            .output()
            .expect("should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("secret-value-123"),
            "VAULT_TOKEN should be stripped by deny.env: {stdout}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_accept_repo_config_flag_does_not_persist() {
        require_sandbox!();
        let (repo, config_file) =
            make_trust_repo("accept-flag", "[propose]\nallow_localhost_any = true\n");

        // Create fake copilot in a repo-root TempDir (sandbox allows exec there;
        // auto-cleans on drop/panic).
        let fake_dir = tempfile::Builder::new()
            .prefix(".cplt-e2e-fake-accept-flag-")
            .tempdir_in(project_dir())
            .expect("create fake copilot dir");
        let script = fake_dir.path().join("copilot");
        std::fs::write(&script, "#!/bin/sh\necho ok\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_dir.path().display());

        // Run with flag — should succeed
        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--no-validate",
                "--accept-repo-config",
                "--",
                "--version",
            ])
            .current_dir(&repo)
            .env("PATH", &new_path)
            .env("CPLT_CONFIG", config_file.to_str().unwrap())
            .output()
            .expect("should run");
        assert!(
            output.status.success(),
            "--accept-repo-config should succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // After running with flag, trust should NOT be persisted
        let output = trust_cmd(&repo, &config_file)
            .args(["trust"])
            .output()
            .expect("should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("pending") || stdout.contains("○"),
            "--accept-repo-config should not persist trust: {stdout}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_trust_head_preferred_over_working_tree() {
        let (repo, config_file) =
            make_trust_repo("head-vs-wt", "[propose]\nallow_localhost_any = true\n");

        // Modify working tree with different content (not committed)
        std::fs::write(
            repo.join(".cplt.toml"),
            "[propose]\nallow_localhost_any = true\nallow_docker = true\nallow_tmp_exec = true\n",
        )
        .unwrap();

        // Trust show should use HEAD version (only allow_localhost_any)
        let output = trust_cmd(&repo, &config_file)
            .args(["trust"])
            .output()
            .expect("should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("allow_localhost_any"),
            "should show HEAD proposal: {stdout}"
        );
        assert!(
            !stdout.contains("allow_docker"),
            "should NOT show working-tree-only proposal: {stdout}"
        );
        assert!(
            stdout.contains("git HEAD"),
            "should indicate source is git HEAD: {stdout}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn e2e_trust_locked_inside_sandbox() {
        require_sandbox!();
        let (repo, config_file) =
            make_trust_repo("trust-locked", "[propose]\nallow_localhost_any = true\n");

        // Create fake copilot in a repo-root TempDir (sandbox allows exec there;
        // auto-cleans on drop/panic).
        let fake_dir = tempfile::Builder::new()
            .prefix(".cplt-e2e-fake-trust-locked-")
            .tempdir_in(project_dir())
            .expect("create fake copilot dir");
        let cplt_binary = binary_path();
        let script = fake_dir.path().join("copilot");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n# If not inside sandbox (extraction trigger), just print version\nif [ -z \"$__CPLT_WRAPPED\" ]; then echo \"fake-version\"; exit 0; fi\n# Inside sandbox: attempt trust modification (should be blocked)\nresult=$({} trust accept --all 2>&1)\nrc=$?\necho \"TRUST_OUTPUT:$result\"\necho \"EXIT:$rc\"\n",
                cplt_binary.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_dir.path().display());

        let output = Command::new(binary_path())
            .args([
                "--yes",
                "--no-validate",
                "--accept-repo-config",
                "--",
                "--version",
            ])
            .current_dir(&repo)
            .env("PATH", &new_path)
            .env("CPLT_CONFIG", config_file.to_str().unwrap())
            .output()
            .expect("should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        // The inner cplt trust accept should fail (trust locked)
        assert!(
            stdout.contains("EXIT:1")
                || stdout.contains("locked")
                || stdout.contains("cannot modify"),
            "cplt trust should be blocked inside sandbox: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Verify trust was NOT actually modified
        let output = trust_cmd(&repo, &config_file)
            .args(["trust"])
            .output()
            .expect("should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("pending") || stdout.contains("○"),
            "trust should remain unapproved after sandbox escape attempt: {stdout}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    // ── cplt init e2e tests ────────────────────────────────────────

    #[test]
    fn e2e_init_detects_node_project() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"test","scripts":{"dev":"next dev --port 3001"},"dependencies":{"next":"^14"}}"#,
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Node.js"),
            "should detect Node.js: {stdout}"
        );
        assert!(
            stdout.contains("allow_localhost_any"),
            "should suggest localhost_any for next: {stdout}"
        );
        assert!(stdout.contains("3001"), "should detect port 3001: {stdout}");
    }

    #[test]
    fn e2e_init_detects_multi_ecosystem() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname=\"x\"").unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "FROM rust:1.80").unwrap();

        let output = Command::new(binary_path())
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Rust"), "should detect Rust: {stdout}");
        assert!(stdout.contains("Docker"), "should detect Docker: {stdout}");
        assert!(
            stdout.contains("allow_docker"),
            "should suggest allow_docker: {stdout}"
        );
    }

    #[test]
    fn e2e_init_empty_project_succeeds() {
        let dir = tempfile::tempdir().unwrap();

        let output = Command::new(binary_path())
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("No project tooling detected"),
            "should say nothing detected on stderr: {stderr}"
        );
        // stdout should be empty (pipe-friendly)
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.is_empty(), "stdout should be empty: {stdout}");
    }

    #[test]
    fn e2e_init_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "FROM node:20").unwrap();

        let output = Command::new(binary_path())
            .args(["init", "--write"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let config_path = dir.path().join(".cplt.toml");
        assert!(config_path.exists(), ".cplt.toml should be created");
        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(
            content.contains("allow_docker"),
            "should contain allow_docker: {content}"
        );
    }

    #[test]
    fn e2e_init_write_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "FROM node:20").unwrap();
        std::fs::write(dir.path().join(".cplt.toml"), "# existing").unwrap();

        let output = Command::new(binary_path())
            .args(["init", "--write"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("already exists"),
            "should mention file exists: {stderr}"
        );
    }

    #[test]
    fn e2e_init_write_force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "FROM node:20").unwrap();
        std::fs::write(dir.path().join(".cplt.toml"), "# old content").unwrap();

        let output = Command::new(binary_path())
            .args(["init", "--write", "--force"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let content = std::fs::read_to_string(dir.path().join(".cplt.toml")).unwrap();
        assert!(
            content.contains("allow_docker"),
            "should overwrite with new content: {content}"
        );
    }

    #[test]
    fn e2e_init_quiet_outputs_only_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "FROM node:20").unwrap();

        let output = Command::new(binary_path())
            .args(["init", "--quiet"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should NOT have the "Detected ecosystems:" header
        assert!(
            !stdout.contains("Detected ecosystems"),
            "quiet mode should suppress report: {stdout}"
        );
        // Should have TOML content
        assert!(
            stdout.contains("allow_docker"),
            "should output TOML: {stdout}"
        );
    }

    #[test]
    fn e2e_init_detects_env_secrets() {
        let dir = tempfile::tempdir().unwrap();
        if std::fs::write(dir.path().join(".env.example"), "test=1").is_err() {
            eprintln!("SKIP: .env writes blocked (running inside sandbox)");
            return;
        }
        std::fs::write(
            dir.path().join(".env.example"),
            "DATABASE_URL=x\nSECRET_KEY=y\nDEBUG=true\n",
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("SECRET_KEY"),
            "should detect SECRET_KEY: {stdout}"
        );
        assert!(
            stdout.contains("[deny]"),
            "should have deny section: {stdout}"
        );
    }

    #[test]
    fn e2e_init_global_outputs_config() {
        let home = tempfile::tempdir().unwrap();
        // Create gradle wrapper dir so detection triggers
        std::fs::create_dir_all(home.path().join(".gradle/wrapper/dists/gradle-8.5")).unwrap();

        let output = Command::new(binary_path())
            .args(["init", "--global"])
            .env("HOME", home.path())
            .env("CPLT_CONFIG", home.path().join("config.toml"))
            .output()
            .expect("should run");

        assert!(output.status.success(), "exit: {:?}", output.status);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("allow_cache_exec"),
            "should suggest cache_exec: {stdout}"
        );
        assert!(stdout.contains("gradle"), "should detect gradle: {stdout}");
    }

    #[test]
    fn e2e_init_global_write() {
        let home = tempfile::tempdir().unwrap();
        // Create gradle wrapper to trigger detection
        std::fs::create_dir_all(home.path().join(".gradle/wrapper/dists/gradle-8.5")).unwrap();
        let config_path = home.path().join("cplt/config.toml");

        let output = Command::new(binary_path())
            .args(["init", "--global", "--write"])
            .env("HOME", home.path())
            .env("CPLT_CONFIG", &config_path)
            .output()
            .expect("should run");

        assert!(
            output.status.success(),
            "exit: {:?}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(config_path.exists(), "config file should be created");
        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("[sandbox]"));
        assert!(content.contains("allow_cache_exec"));
    }

    #[test]
    fn e2e_init_global_empty_home() {
        let home = tempfile::tempdir().unwrap();

        let output = Command::new(binary_path())
            .args(["init", "--global"])
            .env("HOME", home.path())
            .env("CPLT_CONFIG", home.path().join("config.toml"))
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("No machine-level"),
            "should report nothing detected: {stderr}"
        );
        // stdout should be empty
        assert!(
            output.stdout.is_empty(),
            "stdout should be empty when nothing detected"
        );
    }

    // ── Monorepo workspace detection e2e tests ────────────────────────

    #[test]
    fn e2e_init_detects_npm_monorepo() {
        let dir = tempfile::tempdir().unwrap();
        // Root package.json with workspaces and a framework dep
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"mono","workspaces":["apps/*"],"devDependencies":{"vite":"^5"}}"#,
        )
        .unwrap();
        // Workspace member with its own package.json
        std::fs::create_dir_all(dir.path().join("apps/web")).unwrap();
        std::fs::write(
            dir.path().join("apps/web/package.json"),
            r#"{"name":"web","dependencies":{"next":"^14"}}"#,
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("apps/web"),
            "should show workspace member: {stdout}"
        );
        assert!(
            stdout.contains("Node.js"),
            "should detect Node.js: {stdout}"
        );
    }

    #[test]
    fn e2e_init_detects_cargo_workspace() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("crates/core")).unwrap();
        std::fs::write(
            dir.path().join("crates/core/Cargo.toml"),
            "[package]\nname = \"core\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("crates/cli")).unwrap();
        std::fs::write(
            dir.path().join("crates/cli/Cargo.toml"),
            "[package]\nname = \"cli\"\n",
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("crates/core"),
            "should show workspace member core: {stdout}"
        );
        assert!(
            stdout.contains("crates/cli"),
            "should show workspace member cli: {stdout}"
        );
        assert!(stdout.contains("Rust"), "should detect Rust: {stdout}");
    }

    #[test]
    fn e2e_init_detects_mixed_monorepo() {
        let dir = tempfile::tempdir().unwrap();
        // Root package.json with workspaces
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"mono","workspaces":["packages/*"]}"#,
        )
        .unwrap();
        // Node frontend
        std::fs::create_dir_all(dir.path().join("packages/frontend")).unwrap();
        std::fs::write(
            dir.path().join("packages/frontend/package.json"),
            r#"{"name":"frontend","dependencies":{"next":"^14"}}"#,
        )
        .unwrap();
        // JVM backend (Gradle)
        std::fs::create_dir_all(dir.path().join("packages/backend")).unwrap();
        std::fs::write(
            dir.path().join("packages/backend/build.gradle.kts"),
            "plugins { id(\"org.springframework.boot\") }",
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("packages/frontend"),
            "should show frontend member: {stdout}"
        );
        assert!(
            stdout.contains("packages/backend"),
            "should show backend member: {stdout}"
        );
    }

    #[test]
    fn e2e_init_fallback_detects_subprojects() {
        let dir = tempfile::tempdir().unwrap();
        // No workspace config — pure fallback scan
        std::fs::create_dir_all(dir.path().join("services/api")).unwrap();
        std::fs::write(
            dir.path().join("services/api/Cargo.toml"),
            "[package]\nname = \"api\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("services/web")).unwrap();
        std::fs::write(
            dir.path().join("services/web/package.json"),
            r#"{"name":"web"}"#,
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Fallback should find subprojects
        assert!(
            stdout.contains("api") || stdout.contains("web"),
            "should detect subprojects via fallback: {stdout}"
        );
    }

    #[test]
    fn e2e_init_monorepo_toml_has_provenance() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"mono","workspaces":["apps/*"],"devDependencies":{"vite":"^5"}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("apps/web")).unwrap();
        std::fs::write(
            dir.path().join("apps/web/package.json"),
            r#"{"name":"web","dependencies":{"next":"^14"}}"#,
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["init", "--quiet"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        // TOML output should contain provenance comments
        assert!(
            stdout.contains("# Suggested by:") || stdout.contains("Workspace members:"),
            "TOML should include provenance or workspace info: {stdout}"
        );
    }

    #[test]
    fn e2e_doctor_shows_workspace_members() {
        require_copilot!();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"mono","workspaces":["apps/*"]}"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("apps/web")).unwrap();
        std::fs::write(
            dir.path().join("apps/web/package.json"),
            r#"{"name":"web"}"#,
        )
        .unwrap();

        let output = Command::new(binary_path())
            .args(["doctor"])
            .current_dir(dir.path())
            .output()
            .expect("should run");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");
        assert!(
            combined.contains("apps/web"),
            "doctor should show workspace member: {combined}"
        );
    }

    // ============================================================
    // cplt exec tests
    // ============================================================

    #[test]
    fn e2e_exec_runs_true() {
        require_sandbox!();
        let output = cplt_cmd()
            .args(["--no-validate", "exec", "--", "/usr/bin/true"])
            .current_dir(project_dir())
            .output()
            .expect("cplt exec should run");

        assert!(
            output.status.success(),
            "cplt exec -- /usr/bin/true should exit 0.\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn e2e_exec_exit_code_pass_through() {
        require_sandbox!();
        let output = cplt_cmd()
            .args(["--no-validate", "exec", "--", "/usr/bin/false"])
            .current_dir(project_dir())
            .output()
            .expect("cplt exec should run");

        assert!(
            !output.status.success(),
            "cplt exec -- /usr/bin/false should exit non-zero"
        );
        assert_eq!(
            output.status.code(),
            Some(1),
            "exit code should be 1 (from /usr/bin/false)"
        );
    }

    #[test]
    fn e2e_exec_shell_c_mode() {
        require_sandbox!();
        let output = cplt_cmd()
            .args(["--no-validate", "exec", "-c", "echo hello-from-exec"])
            .current_dir(project_dir())
            .output()
            .expect("cplt exec -c should run");

        assert!(
            output.status.success(),
            "cplt exec -c 'echo ...' should exit 0.\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("hello-from-exec"),
            "stdout should contain echo output.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_exec_no_output_contamination() {
        // exec must not contaminate stdout or stderr with cplt startup messages —
        // both must be clean so it is safe to use in pipes and shell aliases.
        require_sandbox!();
        let output = cplt_cmd()
            .args(["--no-validate", "exec", "--", "/usr/bin/true"])
            .current_dir(project_dir())
            .output()
            .expect("cplt exec should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.is_empty(),
            "exec stdout should be clean (no banner).\nstdout: {stdout}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.is_empty(),
            "exec stderr should be empty by default (quiet).\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_exec_env_credentials_filtered() {
        require_sandbox!();
        let output = cplt_cmd()
            .args(["--no-validate", "exec", "--", "/usr/bin/env"])
            .current_dir(project_dir())
            .env("AWS_SECRET_ACCESS_KEY", "should-be-stripped")
            .env("DATABASE_URL", "postgres://secret")
            .output()
            .expect("cplt exec should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("should-be-stripped"),
            "AWS_SECRET_ACCESS_KEY must be stripped from sandbox env.\nstdout: {stdout}"
        );
        assert!(
            !stdout.contains("postgres://secret"),
            "DATABASE_URL must be stripped from sandbox env.\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_exec_no_command_errors() {
        let output = cplt_cmd()
            .args(["exec"])
            .current_dir(project_dir())
            .output()
            .expect("cplt exec with no cmd should run");

        assert!(
            !output.status.success(),
            "cplt exec with no command should exit non-zero"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("exec")
                || stderr.contains("Usage")
                || stderr.contains("CMD")
                || stderr.contains("no command"),
            "stderr should contain usage hint.\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_exec_relative_path() {
        require_sandbox!();
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = project_dir();
        let script = dir.join("cplt_exec_test_script.sh");
        fs::write(&script, "#!/bin/sh\nexit 0\n").expect("write test script");
        let mut perms = fs::metadata(&script).expect("stat script").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod script");

        let output = cplt_cmd()
            .args(["--no-validate", "exec", "--", "./cplt_exec_test_script.sh"])
            .current_dir(&dir)
            .output()
            .expect("cplt exec with relative path should run");

        let _ = fs::remove_file(&script);

        assert!(
            output.status.success(),
            "cplt exec -- ./script.sh should exit 0.\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn e2e_exec_no_quiet_shows_summary() {
        require_sandbox!();
        let output = cplt_cmd()
            .args([
                "--no-validate",
                "--no-quiet",
                "--yes",
                "exec",
                "--",
                "/usr/bin/true",
            ])
            .current_dir(project_dir())
            .output()
            .expect("cplt exec --no-quiet should run");

        assert!(
            output.status.success(),
            "cplt exec --no-quiet should still succeed.\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        // --no-quiet should print sandbox configuration summary
        assert!(
            stderr.contains("Project") || stderr.contains("project"),
            "exec --no-quiet should print sandbox summary.\nstderr: {stderr}"
        );
    }
}
