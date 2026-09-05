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

// This turns off the #239 *security* lint only: a test binary is not the
// unsandboxed parent around an agent session, so the PATH-hijack hazard
// `disallowed_methods` guards against does not apply here. It grants no
// licence to spawn ad hoc: the #245 isolation rule stands unchanged, and every
// `Command` a test spawns is still built through the `tests/common` helpers,
// which no lint can enforce and review does.
#![allow(clippy::disallowed_methods)]
mod common;

#[cfg(target_os = "macos")]
mod e2e_tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use crate::common::{binary_path, cplt_cmd, cplt_cmd_with_ambient_config, git_cmd};
    use std::sync::atomic::{AtomicU32, Ordering};

    static FAKE_COPILOT_COUNTER: AtomicU32 = AtomicU32::new(0);

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
            .is_ok_and(|o| o.status.success())
    }

    /// Check if sandbox-exec can apply a trivial profile.
    /// Returns false when running inside an existing sandbox (nested sandbox-exec is denied).
    fn sandbox_exec_available() -> bool {
        Command::new("sandbox-exec")
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// When `CPLT_TEST_REQUIRE_SANDBOX=1` is set (CI), a missing sandbox
    /// capability must FAIL the test rather than silently skip. This mirrors the
    /// Linux `require_sandbox_enforced()` in `integration_linux.rs` and closes the
    /// gap where a `sandbox-exec`/Seatbelt regression on the macOS runner would
    /// leave CI green because every enforcement test self-skipped. Default (unset)
    /// behaviour is unchanged for local dev / nested-sandbox runs.
    fn require_sandbox_enforced() -> bool {
        std::env::var("CPLT_TEST_REQUIRE_SANDBOX").as_deref() == Ok("1")
    }

    /// Skip guard — call at the top of tests that need the REAL Copilot CLI.
    ///
    /// Copilot cannot be installed/authenticated in CI, so this always self-skips
    /// (never a require-mode). Only tests whose intent genuinely depends on the
    /// real Copilot binary/output keep this guard; sandbox/proxy/profile behaviour
    /// is exercised via `--print-profile`, the default Copilot agent (no binary
    /// needed), or the fake-copilot fixtures instead. The `SKIPPED (copilot):`
    /// marker is grepped by the CI summary step so the residual skip count is
    /// surfaced as a `::warning::`.
    macro_rules! require_copilot {
        () => {
            if !copilot_cli_available() {
                eprintln!(
                    "SKIPPED (copilot): copilot CLI not found in PATH — test genuinely requires the real Copilot binary"
                );
                return;
            }
        };
    }

    /// Skip guard — call at the top of tests that invoke sandbox-exec.
    ///
    /// Skips when already inside a sandbox (nested sandbox-exec is denied by
    /// macOS). Under `CPLT_TEST_REQUIRE_SANDBOX=1` the skip branch panics instead,
    /// so a missing/broken `sandbox-exec` on the CI runner turns the job red.
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

    // ============================================================
    // Full pipeline tests (sandbox-exec → copilot child process)
    // ============================================================

    #[test]
    fn e2e_copilot_version_inside_sandbox() {
        require_copilot!();
        require_sandbox!();
        let output = cplt_cmd()
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
        require_sandbox!();
        // Fake copilot on PATH (not the real binary): sandbox validation passing
        // and the agent launching is agent-agnostic, so this runs in CI.
        let (mut cmd, _fake) = cplt_cmd_with_fake_copilot();
        let output = cmd
            .args(["--yes", "--", "--version"])
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
        require_sandbox!();
        // Fake copilot on PATH: proxy startup is agent-agnostic, so this runs in CI.
        // Use a high unique port to avoid collisions
        let port = 19200 + (std::process::id() % 800) as u16;

        let (mut cmd, _fake) = cplt_cmd_with_fake_copilot();
        let output = cmd
            .args([
                "--yes",
                "--with-proxy",
                "--proxy-port",
                &port.to_string(),
                "--no-validate",
                "--",
                "--version",
            ])
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
        require_sandbox!();
        // Fake copilot on PATH: denial-log streaming is agent-agnostic, runs in CI.
        let (mut cmd, _fake) = cplt_cmd_with_fake_copilot();
        let output = cmd
            .args([
                "--yes",
                "--show-denials",
                "--no-validate",
                "--",
                "--version",
            ])
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
        // No require_copilot!: --print-profile defaults to the Copilot agent and
        // needs no Copilot binary (see main.rs), so this runs in CI.
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
        let output = cplt_cmd()
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
        // No require_copilot!: doctor always prints the Auth section header
        // regardless of whether Copilot is installed, so this runs in CI.
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        // No require_copilot!: doctor always prints the Tools section (git is
        // present on the runner) regardless of Copilot, so this runs in CI.
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let mut cmd = cplt_cmd();
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

    /// Build a `cplt` Command with a fake `copilot` prepended to PATH, for
    /// pipeline tests that exercise sandbox/proxy/denial *wiring* (agent-agnostic)
    /// rather than real Copilot behaviour — so they run in CI without the real
    /// binary. The returned `TempDir` holds the fake script and must stay alive
    /// for the duration of the run (its Drop removes it), so bind it (`let (_, _f)`).
    fn cplt_cmd_with_fake_copilot() -> (Command, tempfile::TempDir) {
        let fake_dir = create_fake_copilot();
        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_dir.path().display());
        let mut cmd = cplt_cmd();
        cmd.current_dir(project_dir()).env("PATH", &new_path);
        (cmd, fake_dir)
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

        let mut cmd = cplt_cmd();
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
            git_cmd(dir.path())
                .args(args)
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
        git_cmd(&dir)
            .args(["add", "."])
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .ok();
        git_cmd(&dir)
            .args(["commit", "-m", "add canary"])
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
        git_cmd(&dir)
            .args(["add", "."])
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .ok();
        git_cmd(&dir)
            .args(["commit", "-m", "add script"])
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
        git_cmd(&dir)
            .args(["add", "-f", ".env"])
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .ok();
        git_cmd(&dir)
            .args(["commit", "-m", "add env"])
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

        git_cmd(&dir)
            .args(["add", "."])
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .ok();
        git_cmd(&dir)
            .args(["commit", "-m", "add script"])
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

        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output2 = cplt_cmd()
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
        // Asserts config *discovery*, so CPLT_CONFIG must stay unset — but the
        // fallback is $HOME-derived, so point HOME at a temp dir and assert the
        // exact path instead of the substring the reader's machine happens to
        // produce.
        let home = tempfile::tempdir().unwrap();
        let output = cplt_cmd_with_ambient_config()
            .args(["config", "path"])
            .env("HOME", home.path())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");
        assert!(output.status.success(), "config path should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let expected = home.path().join(".config/cplt/config.toml");
        assert!(
            stdout.contains(&*expected.to_string_lossy()),
            "should print the HOME-derived config path {}: {stdout}",
            expected.display()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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
    fn e2e_settings_requires_interactive_terminal() {
        let output = cplt_cmd()
            .arg("settings")
            .env_remove("__CPLT_TRUST_LOCKED")
            .output()
            .expect("should run");

        assert!(
            !output.status.success(),
            "settings must not run without a controlling terminal"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("requires an interactive terminal"),
            "should explain the scriptable alternative: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn e2e_config_set_creates_file_and_sets_value() {
        let fake_home = make_config_home("set-create");
        let config_path = fake_home.join(".config/cplt/config.toml");
        assert!(!config_path.exists());

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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
        let set_out = cplt_cmd()
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
        let get_out = cplt_cmd()
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
        cplt_cmd()
            .args(["config", "set", "sandbox.quiet", "true"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");

        // Unset it
        let unset_out = cplt_cmd()
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
        let get_out = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output2 = cplt_cmd()
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

        let output = cplt_cmd()
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
    fn e2e_config_set_dangerous_preset_requires_force() {
        // sandbox.preset is not a `dangerous` KEY, but permissive/full-trust
        // are dangerous VALUES (they enable guarded toggles), so setting them
        // must trip the same --force safeguard as a dangerous bool.
        for preset in ["permissive", "full-trust"] {
            let fake_home = make_config_home(&format!("set-preset-{preset}"));

            // Without --force should fail and name what it enables.
            let output = cplt_cmd()
                .args(["config", "set", "sandbox.preset", preset])
                .env("HOME", fake_home.to_str().unwrap())
                .env_remove("CPLT_CONFIG")
                .output()
                .expect("should run");
            assert!(
                !output.status.success(),
                "preset={preset} should fail without --force"
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("--force"),
                "preset={preset} should mention --force: {stderr}"
            );

            // With --force should succeed.
            let output2 = cplt_cmd()
                .args(["config", "set", "sandbox.preset", preset, "--force"])
                .env("HOME", fake_home.to_str().unwrap())
                .env_remove("CPLT_CONFIG")
                .output()
                .expect("should run");
            assert!(
                output2.status.success(),
                "preset={preset} should succeed with --force: {}",
                String::from_utf8_lossy(&output2.stderr)
            );

            let _ = std::fs::remove_dir_all(&fake_home);
        }
    }

    #[test]
    fn e2e_config_set_safe_preset_no_force_needed() {
        // strict/standard are no-op-or-safer baselines — no --force required.
        for preset in ["strict", "standard"] {
            let fake_home = make_config_home(&format!("set-safe-preset-{preset}"));

            let output = cplt_cmd()
                .args(["config", "set", "sandbox.preset", preset])
                .env("HOME", fake_home.to_str().unwrap())
                .env_remove("CPLT_CONFIG")
                .output()
                .expect("should run");
            assert!(
                output.status.success(),
                "preset={preset} should not require --force: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let _ = std::fs::remove_dir_all(&fake_home);
        }
    }

    #[test]
    fn e2e_config_set_invalid_key_fails() {
        let fake_home = make_config_home("set-badkey");

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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
        cplt_cmd()
            .args(["config", "init"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");

        let config_path = fake_home.join(".config/cplt/config.toml");
        let before = std::fs::read_to_string(&config_path).unwrap();
        assert!(before.contains('#'), "init template should have comments");

        // Set a value
        cplt_cmd()
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
        cplt_cmd()
            .args(["config", "set", "allow.ports", "8080"])
            .env("HOME", fake_home.to_str().unwrap())
            .env_remove("CPLT_CONFIG")
            .output()
            .expect("should run");

        // Append another value
        let output = cplt_cmd()
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
        let get_out = cplt_cmd()
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
        git_cmd(&dir).args(["init", "--quiet"]).output().unwrap();
        dir
    }

    // ============================================================
    // Repo config (.cplt.toml) path resolution — navikt/cplt#179
    // ============================================================

    /// Build a git repo with a committed `.cplt.toml`, so `--print-profile`
    /// exercises the tamper-proof `git cat-file blob HEAD:.cplt.toml` path
    /// rather than the working-tree fallback.
    fn repo_with_committed_cplt_toml(label: &str, toml: &str) -> PathBuf {
        let repo = make_repo_dir(label);
        std::fs::write(repo.join(".cplt.toml"), toml).unwrap();
        let git = |args: &[&str]| {
            let out = git_cmd(&repo).args(args).output().unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        git(&["add", "-A"]);
        git(&[
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "commit",
            "--quiet",
            "-m",
            "init",
        ]);
        repo
    }

    #[test]
    fn e2e_repo_deny_path_spellings_all_emit_enforcing_rules() {
        // navikt/cplt#179 follow-up. Seatbelt accepts a rule it cannot match and
        // says nothing, so an unenforceable spelling looks enforced in the
        // profile. Verified against the kernel: `(subpath "<dir>/./secrets")`,
        // `"<dir>/secrets/."` and `"<dir>//secrets"` all read the file fine,
        // while `"<dir>/secrets"` gives EPERM. Every spelling a user might
        // reasonably write must therefore normalize to the enforcing form.
        //
        // Each spelling is tested twice: against a directory that exists (where
        // canonicalize does the work) and one that does not (where only the
        // lexical pass can, and where canonicalize necessarily fails). The
        // not-yet-created case is the one repo config uniquely supports.
        let repo = repo_with_committed_cplt_toml(
            "deny-spellings",
            r#"
[deny]
paths = [
  "plain", "./dotslash", "dotend/.", "double//slash", "trailing/",
  "nx-plain", "./nx-dotslash", "nx-dotend/.", "nx-double//slash", "nx-trailing/",
]
"#,
        );
        for existing in ["plain", "dotslash", "dotend", "double/slash", "trailing"] {
            std::fs::create_dir_all(repo.join(existing)).unwrap();
        }
        let root = std::fs::canonicalize(&repo).unwrap();

        let output = cplt_cmd()
            .args([
                "--project-dir",
                &repo.to_string_lossy(),
                "--agent",
                "shell",
                "--print-profile",
            ])
            .output()
            .expect("binary should run");
        assert!(output.status.success(), "should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);

        for name in [
            "plain",
            "dotslash",
            "dotend",
            "double/slash",
            "trailing",
            "nx-plain",
            "nx-dotslash",
            "nx-dotend",
            "nx-double/slash",
            "nx-trailing",
        ] {
            let want = root.join(name);
            let want = want.to_string_lossy();
            assert!(
                stdout.contains(&format!("(deny file-read* (subpath \"{want}\"))")),
                "{name}: expected an enforcing deny rule for {want}\nstdout: {stdout}"
            );
        }
        // The inert spellings must not survive anywhere in the profile.
        for inert in ["/./", "//", "/.\"", "\"plain\"", "\"nx-plain\""] {
            assert!(
                !stdout.contains(inert),
                "profile still contains the unenforceable form {inert:?}\nstdout: {stdout}"
            );
        }
    }

    #[test]
    fn e2e_repo_deny_path_symlink_resolves_to_target() {
        // SBPL matches the *resolved* path, so a deny naming a symlink protects
        // nothing — reading through the link is denied, reading the real path is
        // not. Canonicalizing when the target exists closes that.
        let repo = repo_with_committed_cplt_toml(
            "deny-symlink",
            "[deny]\npaths = [\"link-to-secrets\"]\n",
        );
        std::fs::create_dir_all(repo.join("real-secrets")).unwrap();
        std::os::unix::fs::symlink("real-secrets", repo.join("link-to-secrets")).unwrap();
        let root = std::fs::canonicalize(&repo).unwrap();

        let output = cplt_cmd()
            .args([
                "--project-dir",
                &repo.to_string_lossy(),
                "--agent",
                "shell",
                "--print-profile",
            ])
            .output()
            .expect("binary should run");
        let stdout = String::from_utf8_lossy(&output.stdout);

        let target = root.join("real-secrets");
        let target = target.to_string_lossy();
        assert!(
            stdout.contains(&format!("(deny file-read* (subpath \"{target}\"))")),
            "deny must name the symlink target, which is what SBPL matches\nstdout: {stdout}"
        );
        assert!(
            !stdout.contains("link-to-secrets"),
            "the symlink path alone would protect nothing\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_repo_deny_path_anchors_to_git_root_under_project_dir_subdir() {
        // `git cat-file blob HEAD:.cplt.toml` resolves repo-root-relative
        // regardless of cwd, so `--project-dir <subdir>` still reads the ROOT's
        // config. Anchoring its relative paths to the subdir would emit
        // `<root>/sub/secrets` — a confident-looking absolute deny rule
        // protecting a directory the repo never named, while `<root>/secrets`
        // stays readable. Worse than the original bug, which was merely inert.
        let repo =
            repo_with_committed_cplt_toml("deny-anchor-subdir", "[deny]\npaths = [\"secrets\"]\n");
        std::fs::create_dir_all(repo.join("secrets")).unwrap();
        std::fs::create_dir_all(repo.join("sub")).unwrap();
        let root = std::fs::canonicalize(&repo).unwrap();

        let output = cplt_cmd()
            .args([
                "--project-dir",
                &repo.join("sub").to_string_lossy(),
                "--agent",
                "shell",
                "--print-profile",
            ])
            .output()
            .expect("binary should run");
        assert!(output.status.success(), "should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);

        let want = root.join("secrets");
        let want = want.to_string_lossy();
        assert!(
            stdout.contains(&format!("(deny file-read* (subpath \"{want}\"))")),
            "repo-root config must anchor to the git root\nstdout: {stdout}"
        );
        let wrong = root.join("sub/secrets");
        let wrong = wrong.to_string_lossy();
        assert!(
            !stdout.contains(wrong.as_ref()),
            "must not deny {wrong} — the repo never named it\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_repo_deny_path_resolves_symlink_above_an_absent_leaf() {
        // The not-yet-created case is only sound when the lexical location is
        // where the file will actually land. `link/secret` with `link -> real`
        // and no `secret` yet breaks that: canonicalize fails on the whole path,
        // and the emitted rule names the link. Verified against the kernel —
        // that rule blocks reads of NEITHER `link/secret` nor `real/secret`,
        // while a rule naming `real/secret` blocks both.
        let repo = repo_with_committed_cplt_toml(
            "deny-mid-symlink",
            "[deny]\npaths = [\"link/secret\"]\n",
        );
        std::fs::create_dir_all(repo.join("real")).unwrap();
        std::os::unix::fs::symlink("real", repo.join("link")).unwrap();
        // `secret` deliberately does NOT exist when the profile is generated.
        let root = std::fs::canonicalize(&repo).unwrap();

        let output = cplt_cmd()
            .args([
                "--project-dir",
                &repo.to_string_lossy(),
                "--agent",
                "shell",
                "--print-profile",
            ])
            .output()
            .expect("binary should run");
        assert!(output.status.success(), "should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);

        let want = root.join("real/secret");
        let want = want.to_string_lossy();
        assert!(
            stdout.contains(&format!("(deny file-read* (subpath \"{want}\"))")),
            "the rule must name the resolved path, which is where the file lands\nstdout: {stdout}"
        );
        assert!(
            !stdout.contains("/link/secret"),
            "a rule naming the symlink matches nothing\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_repo_allow_path_repointed_outside_the_repo_is_refused() {
        // The trust store pins a hash of the `.cplt.toml` BYTES, so an approval
        // only vouches for what those bytes name. Here the repo gets
        // `allow.read = ["data"]` approved while `data -> safe`, then repoints
        // `data -> /` in a later commit. `.cplt.toml` never changes, so the
        // pinned hash still matches and the approval stays live — the grant must
        // be refused on resolution instead, and said out loud.
        let repo =
            repo_with_committed_cplt_toml("allow-escape", "[propose.allow]\nread = [\"data\"]\n");
        std::fs::create_dir_all(repo.join("safe")).unwrap();
        std::os::unix::fs::symlink("safe", repo.join("data")).unwrap();
        let root = std::fs::canonicalize(&repo).unwrap();

        let profile = |repo: &Path| {
            let out = cplt_cmd()
                .args([
                    "--project-dir",
                    &repo.to_string_lossy(),
                    "--agent",
                    "shell",
                    "--accept-repo-config",
                    "--print-profile",
                ])
                .output()
                .expect("binary should run");
            (
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        };

        // Baseline: an in-repo symlink target is granted normally.
        let (stdout, _) = profile(&repo);
        let safe = root.join("safe");
        let safe = safe.to_string_lossy();
        assert!(
            stdout.contains(&format!("(allow file-read* (subpath \"{safe}\"))")),
            "an in-repo symlink target should be granted\nstdout: {stdout}"
        );

        // Repoint outside the repo, leaving `.cplt.toml` untouched.
        std::fs::remove_file(repo.join("data")).unwrap();
        std::os::unix::fs::symlink("/", repo.join("data")).unwrap();

        let (stdout, stderr) = profile(&repo);
        assert!(
            !stdout.contains("(allow file-read* (subpath \"/\"))"),
            "a repointed symlink must not grant read of / on a stale approval\nstdout: {stdout}"
        );
        assert!(
            stderr.contains("resolves outside the repository"),
            "the refusal must be reported, not silent\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_repo_deny_relative_path_is_kernel_enforced() {
        // The property the whole change exists for, checked against the kernel
        // rather than the profile string: a relative deny path in a committed
        // `.cplt.toml`, written the way people actually write one, blocks the
        // read. Pre-fix this printed the file contents.
        if !sandbox_exec_available() {
            assert!(
                !require_sandbox_enforced(),
                "CPLT_TEST_REQUIRE_SANDBOX=1 but sandbox-exec is unavailable"
            );
            return;
        }
        let repo =
            repo_with_committed_cplt_toml("deny-kernel", "[deny]\npaths = [\"./secrets\"]\n");
        std::fs::create_dir_all(repo.join("secrets")).unwrap();
        std::fs::write(repo.join("secrets/pw.txt"), "hunter2").unwrap();

        let output = cplt_cmd()
            .args([
                "--project-dir",
                &repo.to_string_lossy(),
                "--agent",
                "shell",
                "--quiet",
                "--no-proxy",
                "--yes",
                "--",
                "-c",
                "cat secrets/pw.txt",
            ])
            .output()
            .expect("binary should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("hunter2"),
            "a committed relative deny path must be enforced\nstdout: {stdout}"
        );
    }

    #[test]
    fn e2e_config_set_repo_creates_cplt_toml_with_propose() {
        let repo = make_repo_dir("set-repo-create");
        let cplt_toml = repo.join(".cplt.toml");
        assert!(!cplt_toml.exists());

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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
        cplt_cmd()
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
        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        cplt_cmd()
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
        let output = cplt_cmd()
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

        let output = cplt_cmd()
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
            cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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
        let output = cplt_cmd()
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

        let output = cplt_cmd()
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
        git_cmd(&repo).args(["init", "--quiet"]).output().unwrap();
        git_cmd(&repo)
            .args(["config", "user.email", "test@test.com"])
            .output()
            .unwrap();
        git_cmd(&repo)
            .args(["config", "user.name", "Test"])
            .output()
            .unwrap();

        std::fs::write(repo.join(".cplt.toml"), cplt_toml_content).unwrap();
        git_cmd(&repo).args(["add", ".cplt.toml"]).output().unwrap();
        git_cmd(&repo)
            .args([
                "-c",
                "commit.gpgSign=false",
                "commit",
                "-m",
                "init",
                "--quiet",
            ])
            .output()
            .unwrap();

        // Isolated config dir (no interference from user's real config).
        // Deliberately NOT inside the repo: cplt refuses a CPLT_CONFIG the
        // project controls (issue #261).
        //
        // Wiped first: the path is deterministic, and it holds the trust store
        // (`<parent of CPLT_CONFIG>/trust/`) keyed on the equally deterministic
        // repo path. A store left behind by an earlier run made this repo start
        // out *approved*, so "before accept, should be pending" failed
        // intermittently — intermittently because `id` depends on how many
        // other tests ran first.
        let config_dir = std::env::temp_dir().join(format!(".cplt-e2e-trust-cfg-{label}-{id}"));
        let _ = std::fs::remove_dir_all(&config_dir);
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("config.toml");
        std::fs::write(&config_file, "").unwrap();

        (repo, config_file)
    }

    /// Build a Command for the cplt binary with trust-related env vars cleared.
    /// Trust tests must not inherit __CPLT_TRUST_LOCKED from a parent sandbox.
    fn trust_cmd(repo: &Path, config_file: &Path) -> Command {
        let mut cmd = cplt_cmd();
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
        git_cmd(&repo).args(["add", ".cplt.toml"]).output().unwrap();
        git_cmd(&repo)
            .args([
                "-c",
                "commit.gpgSign=false",
                "commit",
                "-m",
                "change proposals",
                "--quiet",
            ])
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

    /// Read every entry file in the trust store belonging to `config_file`'s
    /// config dir. The store is keyed on a repo fingerprint, so tests assert on
    /// the file set rather than recomputing the hash.
    fn trust_store_files(config_file: &Path) -> Vec<(PathBuf, String)> {
        let dir = config_file.parent().unwrap().join("trust");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        entries
            .filter_map(|e| {
                let path = e.ok()?.path();
                if path.extension()? != "toml" {
                    return None;
                }
                let content = std::fs::read_to_string(&path).ok()?;
                Some((path, content))
            })
            .collect()
    }

    /// Accepting one key must not renew approvals whose *values* changed since
    /// they were granted. The maintainer widens `allow.read` from a cache dir to
    /// `~/.ssh`; accepting only the newly added key must drop the stale
    /// `allow.read` approval, not re-pin it at its new, broader value.
    #[test]
    fn e2e_trust_partial_accept_does_not_renew_stale_keys() {
        let (repo, config_file) = make_trust_repo(
            "partial-stale",
            "[propose]\nallow_localhost_any = true\n\n[propose.allow]\nread = [\"~/.gradle/caches\"]\n",
        );

        let output = trust_cmd(&repo, &config_file)
            .args(["trust", "accept", "--all"])
            .output()
            .expect("accept should run");
        assert!(output.status.success());

        let before = trust_store_files(&config_file);
        assert_eq!(before.len(), 1, "one trust entry expected: {before:?}");
        assert!(
            before[0].1.contains("allow.read"),
            "allow.read should start approved: {}",
            before[0].1
        );

        // Widen allow.read and add a new key, then commit.
        std::fs::write(
            repo.join(".cplt.toml"),
            "[propose]\nallow_localhost_any = true\nallow_docker = true\n\n[propose.allow]\nread = [\"~/.ssh\", \"~/.aws\"]\n",
        )
        .unwrap();
        git_cmd(&repo).args(["add", ".cplt.toml"]).output().unwrap();
        git_cmd(&repo)
            .args([
                "-c",
                "commit.gpgSign=false",
                "commit",
                "-m",
                "widen allow.read",
                "--quiet",
            ])
            .output()
            .unwrap();

        // Accept only the new key.
        let output = trust_cmd(&repo, &config_file)
            .args(["trust", "accept", "allow_docker"])
            .output()
            .expect("accept should run");
        assert!(
            output.status.success(),
            "accept failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("changed"),
            "dropping the other approvals must be announced, not silent: {stdout}"
        );

        let after = trust_store_files(&config_file);
        assert_eq!(after.len(), 1, "one trust entry expected: {after:?}");
        let content = &after[0].1;
        assert!(
            content.contains("allow_docker"),
            "the accepted key should be approved: {content}"
        );
        assert!(
            !content.contains("allow.read"),
            "allow.read changed value and must NOT be renewed by a partial accept: {content}"
        );
        assert!(
            !content.contains("allow_localhost_any"),
            "approvals from the stale hash must not survive a partial accept: {content}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    /// The trust store is keyed on the git origin URL, which any repo can forge.
    /// A second checkout presenting the same origin must not inherit the first
    /// checkout's approved keys, nor overwrite its entry.
    #[test]
    fn e2e_trust_accept_refuses_foreign_origin_entry() {
        let propose = "[propose]\nallow_localhost_any = true\nallow_docker = true\n";
        let (victim, config_file) = make_trust_repo("origin-victim", propose);
        let (attacker, _attacker_config) = make_trust_repo("origin-attacker", propose);
        for repo in [&victim, &attacker] {
            git_cmd(repo)
                .args([
                    "remote",
                    "add",
                    "origin",
                    "https://github.com/victim/repo.git",
                ])
                .output()
                .unwrap();
        }

        let output = trust_cmd(&victim, &config_file)
            .args(["trust", "accept", "--all"])
            .output()
            .expect("accept should run");
        assert!(
            output.status.success(),
            "victim accept failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let before = trust_store_files(&config_file);
        assert_eq!(
            before.len(),
            1,
            "victim should own one trust entry: {before:?}"
        );

        // Same forged origin, different checkout, accepting one innocuous key.
        let output = trust_cmd(&attacker, &config_file)
            .args(["trust", "accept", "allow_docker"])
            .output()
            .expect("accept should run");
        assert!(
            !output.status.success(),
            "accept from a different checkout with the same origin must be refused: {}",
            String::from_utf8_lossy(&output.stdout)
        );

        let after = trust_store_files(&config_file);
        assert_eq!(
            after, before,
            "the other checkout's entry must be untouched"
        );
        assert!(
            after[0].1.contains("origin-victim"),
            "entry must stay bound to the original checkout: {}",
            after[0].1
        );
        assert!(
            !after[0].1.contains("origin-attacker"),
            "entry must not be rebound to the other checkout: {}",
            after[0].1
        );

        let _ = std::fs::remove_dir_all(&victim);
        let _ = std::fs::remove_dir_all(&attacker);
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

        let output = cplt_cmd()
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
        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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
        // Create the Playwright browser cache so cache-exec detection triggers
        std::fs::create_dir_all(home.path().join("Library/Caches/ms-playwright")).unwrap();
        std::fs::create_dir_all(home.path().join(".cache/ms-playwright")).unwrap();

        let output = cplt_cmd()
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
        assert!(
            stdout.contains("ms-playwright"),
            "should detect Playwright: {stdout}"
        );
    }

    #[test]
    fn e2e_init_global_write() {
        let home = tempfile::tempdir().unwrap();
        // Create the Playwright browser cache to trigger detection
        std::fs::create_dir_all(home.path().join("Library/Caches/ms-playwright")).unwrap();
        std::fs::create_dir_all(home.path().join(".cache/ms-playwright")).unwrap();
        let config_path = home.path().join("cplt/config.toml");

        let output = cplt_cmd()
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
        // `init --global` detects machine-level config from PATH as well as
        // HOME: an agent binary the developer happens to have installed makes
        // "nothing detected" false. Empty PATH means empty detection.
        let output = cplt_cmd()
            .args(["init", "--global"])
            .env("HOME", home.path())
            .env("PATH", "")
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

        let output = cplt_cmd()
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

    /// #343 review: `exec` ignores the agent `resolve_context` detected and
    /// always builds the Shell profile, so a warning about the detected agent's
    /// directories describes a session that was never assembled. The tool-dir
    /// half of the same warning must stay live on `exec`, or this test would
    /// pass on a warning that had simply stopped working.
    #[test]
    fn e2e_exec_does_not_warn_about_an_agent_it_does_not_run() {
        require_sandbox!();
        let fake_home = std::env::temp_dir().join(format!(
            ".cplt-e2e-exec-agent-warn-{}",
            FAKE_COPILOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&fake_home);
        std::fs::create_dir_all(fake_home.join(".copilot")).unwrap();
        std::fs::create_dir_all(fake_home.join(".rustup")).unwrap();

        let output = cplt_cmd()
            .args([
                "--no-validate",
                "--agent",
                "copilot",
                "--allow-write",
                fake_home.join(".copilot").to_str().unwrap(),
                "--allow-write",
                fake_home.join(".rustup").to_str().unwrap(),
                "exec",
                "--",
                "/usr/bin/true",
            ])
            .env("HOME", fake_home.to_str().unwrap())
            .current_dir(project_dir())
            .output()
            .expect("cplt exec should run");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(".rustup"),
            "exec must still warn about a shadowed tool directory: {stderr}"
        );
        assert!(
            !stderr.contains(".copilot"),
            "exec builds the Shell profile and never emits Copilot's rules, so it \
             must not blame the grant for withdrawing exec there: {stderr}"
        );

        let _ = std::fs::remove_dir_all(&fake_home);
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

    /// Pull `KEY=value` out of `env` output.
    fn env_value<'a>(stdout: &'a str, key: &str) -> Option<&'a str> {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
    }

    /// #180: the sandbox denies `~/.npmrc`, and yarn 1 aborts on the denial errno where
    /// it tolerates ENOENT. cplt redirects `NPM_CONFIG_USERCONFIG` at a nonexistent path
    /// in the scratch dir so the read misses instead of being refused.
    #[test]
    fn e2e_exec_npmrc_userconfig_redirected_to_scratch() {
        require_sandbox!();
        let output = cplt_cmd()
            .args(["--no-validate", "exec", "--", "/usr/bin/env"])
            .current_dir(project_dir())
            // A developer's own value legitimately suppresses the injection.
            .env_remove("NPM_CONFIG_USERCONFIG")
            .env_remove("npm_config_userconfig")
            .output()
            .expect("cplt exec should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let tmpdir = env_value(&stdout, "TMPDIR").expect("scratch dir is on by default");
        let userconfig = env_value(&stdout, "NPM_CONFIG_USERCONFIG").unwrap_or_else(|| {
            panic!("NPM_CONFIG_USERCONFIG must be injected by default.\nstdout: {stdout}")
        });

        assert_eq!(
            userconfig,
            format!("{tmpdir}/npmrc"),
            "NPM_CONFIG_USERCONFIG must point inside the session scratch dir.\nstdout: {stdout}"
        );
        assert!(
            !std::path::Path::new(userconfig).exists(),
            "the redirect target must not exist, or the read is not ENOENT"
        );
    }

    #[test]
    fn e2e_exec_npmrc_userconfig_absent_without_scratch_dir() {
        require_sandbox!();
        let output = cplt_cmd()
            .args([
                "--no-validate",
                "--no-scratch-dir",
                "exec",
                "--",
                "/usr/bin/env",
            ])
            .current_dir(project_dir())
            .env_remove("NPM_CONFIG_USERCONFIG")
            .env_remove("npm_config_userconfig")
            .output()
            .expect("cplt exec should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            env_value(&stdout, "NPM_CONFIG_USERCONFIG").is_none(),
            "without a scratch dir there is nowhere to point, so nothing is injected.\n\
             stdout: {stdout}"
        );
    }

    fn is_automatic_playwright_socket_dir(value: &str) -> bool {
        value
            .strip_prefix("/private/tmp/cplt-pw-")
            .is_some_and(|suffix| {
                suffix.len() == 32
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    }

    fn playwright_env_output(args: &[&str], ambient: Option<&str>) -> std::process::Output {
        let mut command = cplt_cmd();
        command
            .arg("--no-validate")
            .args(args)
            .args(["exec", "--", "/usr/bin/env"])
            .current_dir(project_dir());
        if let Some(value) = ambient {
            command.env("PWTEST_SOCKETS_DIR", value);
        } else {
            command.env_remove("PWTEST_SOCKETS_DIR");
        }
        command.output().expect("cplt exec should run")
    }

    #[test]
    fn e2e_exec_playwright_socket_dir_for_exact_and_versioned_intent() {
        require_sandbox!();
        for cache_entry in ["ms-playwright", "ms-playwright/chromium-1243"] {
            let output = playwright_env_output(
                &["--allow-cache-exec", cache_entry],
                Some("/ambient/playwright-sockets"),
            );

            assert!(
                output.status.success(),
                "Playwright child-env assertion should exit 0 for {cache_entry:?}.\nstderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            let sockets_dir = env_value(&stdout, "PWTEST_SOCKETS_DIR")
                .expect("PWTEST_SOCKETS_DIR must be injected for Playwright");
            assert!(
                is_automatic_playwright_socket_dir(sockets_dir),
                "automatic path must have the short fixed shape: {sockets_dir:?}"
            );
            assert!(
                !std::path::Path::new(sockets_dir).exists(),
                "RAII guard must remove the socket directory after the child exits"
            );
        }
    }

    #[test]
    fn e2e_exec_playwright_socket_dir_absent_without_exact_intent() {
        require_sandbox!();
        for (label, args) in [
            ("no opt-in", Vec::<&str>::new()),
            (
                "unrelated opt-in",
                vec!["--allow-cache-exec", "some-other-tool"],
            ),
            (
                "near-miss opt-in",
                vec!["--allow-cache-exec", "ms-playwright-evil"],
            ),
            ("allow-cache-exec-any alone", vec!["--allow-cache-exec-any"]),
        ] {
            let output = playwright_env_output(&args, None);
            assert!(
                output.status.success(),
                "{label} child-env assertion should exit 0.\nstderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                env_value(&stdout, "PWTEST_SOCKETS_DIR").is_none(),
                "{label} must not expose an automatic socket directory"
            );
        }
    }

    #[test]
    fn e2e_exec_playwright_socket_dir_is_independent_of_scratch() {
        require_sandbox!();
        let output = playwright_env_output(
            &["--allow-cache-exec", "ms-playwright", "--no-scratch-dir"],
            None,
        );
        assert!(
            output.status.success(),
            "no-scratch child-env assertion should exit 0.\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let sockets_dir = env_value(&stdout, "PWTEST_SOCKETS_DIR")
            .expect("Playwright socket directory must not depend on scratch");
        assert!(is_automatic_playwright_socket_dir(sockets_dir));
        if let Some(tmpdir) = env_value(&stdout, "TMPDIR") {
            assert_ne!(
                sockets_dir, tmpdir,
                "the automatic socket base must remain independent of ambient TMPDIR"
            );
        }
    }

    #[test]
    fn e2e_exec_playwright_socket_dir_overrides_inherited_ambient_value() {
        require_sandbox!();
        let output = playwright_env_output(
            &["--allow-cache-exec", "ms-playwright", "--inherit-env"],
            Some("/ambient/playwright-sockets"),
        );
        assert!(
            output.status.success(),
            "inherit-env child-env assertion should exit 0.\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let sockets_dir = env_value(&stdout, "PWTEST_SOCKETS_DIR")
            .expect("automatic socket path must replace inherited ambient value");
        assert!(is_automatic_playwright_socket_dir(sockets_dir));
    }

    #[test]
    fn e2e_exec_playwright_explicit_pass_env_preserves_caller_without_grant() {
        require_sandbox!();
        let caller_path = "/caller/playwright-sockets";
        let output = playwright_env_output(
            &[
                "--allow-cache-exec",
                "ms-playwright",
                "--pass-env",
                "PWTEST_SOCKETS_DIR",
            ],
            Some(caller_path),
        );
        assert!(
            output.status.success(),
            "explicit pass-env child assertion should exit 0.\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(env_value(&stdout, "PWTEST_SOCKETS_DIR"), Some(caller_path));

        let profile = cplt_cmd()
            .args([
                "--allow-cache-exec",
                "ms-playwright",
                "--pass-env",
                "PWTEST_SOCKETS_DIR",
                "--print-profile",
            ])
            .current_dir(project_dir())
            .output()
            .expect("cplt should print the explicit-override profile");
        assert!(profile.status.success());
        let profile = String::from_utf8_lossy(&profile.stdout);
        assert!(
            !profile.contains("Per-session Playwright control sockets")
                && !profile.contains("/private/tmp/cplt-pw-"),
            "caller-owned override must not receive an automatic socket grant"
        );
    }

    #[test]
    fn e2e_exec_playwright_mcp_sandbox_is_disabled_only_for_exact_intent() {
        require_sandbox!();

        let opted_in = playwright_env_output(&["--allow-cache-exec", "ms-playwright"], None);
        assert!(opted_in.status.success());
        assert_eq!(
            env_value(
                &String::from_utf8_lossy(&opted_in.stdout),
                "PLAYWRIGHT_MCP_SANDBOX"
            ),
            Some("false"),
            "Chromium cannot nest its sandbox inside cplt's, so the opt-in must turn \
             Playwright MCP's back off"
        );

        for (label, args) in [
            ("no opt-in", Vec::<&str>::new()),
            (
                "unrelated opt-in",
                vec!["--allow-cache-exec", "some-other-tool"],
            ),
            ("allow-cache-exec-any alone", vec!["--allow-cache-exec-any"]),
        ] {
            let output = playwright_env_output(&args, None);
            assert!(output.status.success(), "{label} should run");
            assert_eq!(
                env_value(
                    &String::from_utf8_lossy(&output.stdout),
                    "PLAYWRIGHT_MCP_SANDBOX"
                ),
                None,
                "{label} must not weaken a browser it was never asked to run"
            );
        }
    }

    #[test]
    fn e2e_exec_playwright_mcp_sandbox_pass_env_returns_the_choice_to_the_caller() {
        require_sandbox!();
        let output = cplt_cmd()
            .args([
                "--no-validate",
                "--allow-cache-exec",
                "ms-playwright",
                "--pass-env",
                "PLAYWRIGHT_MCP_SANDBOX",
                "exec",
                "--",
                "/usr/bin/env",
            ])
            .current_dir(project_dir())
            .env("PLAYWRIGHT_MCP_SANDBOX", "true")
            .output()
            .expect("cplt exec should run");
        assert!(output.status.success());
        assert_eq!(
            env_value(
                &String::from_utf8_lossy(&output.stdout),
                "PLAYWRIGHT_MCP_SANDBOX"
            ),
            Some("true"),
            "an explicit pass-through must not be overwritten by cplt's default"
        );
    }

    #[test]
    fn e2e_exec_playwright_pass_env_without_value_warns_about_the_missing_socket_dir() {
        require_sandbox!();
        let output = playwright_env_output(
            &[
                "--allow-cache-exec",
                "ms-playwright",
                "--pass-env",
                "PWTEST_SOCKETS_DIR",
            ],
            None,
        );
        assert!(
            output.status.success(),
            "the child should still run.\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            env_value(&stdout, "PWTEST_SOCKETS_DIR"),
            None,
            "an override with no value must not be replaced by the automatic path"
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("PWTEST_SOCKETS_DIR is passed through but has no value"),
            "cplt must name the cause instead of leaving Playwright to fail on \
             a too-long socket path.\nstderr: {stderr}"
        );
    }

    #[test]
    fn e2e_exec_playwright_socket_dir_obeys_repo_deny_env_last() {
        require_sandbox!();
        let (repo, config_file) = make_trust_repo(
            "playwright-deny-env",
            "[deny]\nenv = [\"PWTEST_SOCKETS_DIR\"]\n",
        );
        let output = cplt_cmd()
            .args([
                "--no-validate",
                "--allow-cache-exec",
                "ms-playwright",
                "exec",
                "--",
                "/usr/bin/env",
            ])
            .current_dir(&repo)
            .env("CPLT_CONFIG", &config_file)
            .env_remove("PWTEST_SOCKETS_DIR")
            .output()
            .expect("cplt exec should apply repo deny.env");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "deny.env child assertion should exit 0.\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            env_value(&stdout, "PWTEST_SOCKETS_DIR").is_none(),
            "repo deny.env must remove the automatic value after command setup"
        );
        let _ = std::fs::remove_dir_all(repo);
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

    // ============================================================
    // `cplt check` — verify & explain sandbox enforcement (#142)
    // ============================================================

    /// A fresh, safe project directory for `check` (temp dirs are not rejected
    /// as "too broad" the way /tmp itself is).
    fn check_project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        // A .git marker makes it a proper project root.
        std::fs::create_dir_all(dir.path().join(".git")).ok();
        dir
    }

    #[test]
    fn e2e_check_battery_enforcing() {
        require_sandbox!();
        let proj = check_project();
        // check is a diagnostic and must not require an installed agent in CI.
        // Pin the always-available shell profile so the test is deterministic.
        let output = cplt_cmd()
            .args(["--agent", "shell"])
            .arg("--project-dir")
            .arg(proj.path())
            .arg("check")
            .output()
            .expect("cplt check should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "battery should be enforcing (exit 0).\nstdout: {stdout}\nstderr: {stderr}"
        );
        // A working sandbox: project ALLOWED, credentials/home/exec BLOCKED.
        assert!(stdout.contains("ENFORCING"), "verdict:\n{stdout}");
        assert!(
            stdout.contains("ALLOWED"),
            "should show allowed items:\n{stdout}"
        );
        assert!(
            stdout.contains("BLOCKED"),
            "should show blocked items:\n{stdout}"
        );
    }

    #[test]
    fn e2e_check_battery_json_shape() {
        require_sandbox!();
        let proj = check_project();
        let output = cplt_cmd()
            .args(["--agent", "shell"])
            .arg("--project-dir")
            .arg(proj.path())
            .args(["check", "--json"])
            .output()
            .expect("cplt check --json should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "json battery exit 0.\n{stdout}");
        // Shape assertions.
        assert!(stdout.contains("\"enforcing\": true"), "json:\n{stdout}");
        assert!(stdout.contains("\"verified\":"), "json:\n{stdout}");
        assert!(stdout.contains("\"items\":"), "json:\n{stdout}");
        assert!(
            stdout.contains("\"decision\": \"blocked\""),
            "json should contain a blocked decision:\n{stdout}"
        );
        assert!(
            stdout.contains("\"decision\": \"allowed\""),
            "json should contain an allowed decision:\n{stdout}"
        );
    }

    #[test]
    fn e2e_check_path_protected_blocked() {
        require_sandbox!();
        let proj = check_project();
        let home = std::env::var("HOME").expect("HOME");
        let ssh = format!("{home}/.ssh");
        let output = cplt_cmd()
            .args(["--agent", "shell"])
            .arg("--project-dir")
            .arg(proj.path())
            .args(["check", "path", &ssh])
            .output()
            .expect("cplt check path should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("BLOCKED"),
            "~/.ssh read should be blocked:\n{stdout}"
        );
        assert!(
            stdout.contains("credential"),
            "should explain it as a credential path:\n{stdout}"
        );
    }

    #[test]
    fn e2e_check_path_project_allowed() {
        require_sandbox!();
        let proj = check_project();
        let output = cplt_cmd()
            .args(["--agent", "shell"])
            .arg("--project-dir")
            .arg(proj.path())
            .arg("check")
            .arg("path")
            .arg(proj.path())
            .arg("--write")
            .output()
            .expect("cplt check path should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "targeted check exits 0:\n{stdout}");
        assert!(
            stdout.matches("ALLOWED").count() >= 2,
            "project dir read+write should both be ALLOWED:\n{stdout}"
        );
    }

    // The net/exec explain layer is static (no kernel sandbox needed), so these
    // run in CI regardless of sandbox-exec availability.

    #[test]
    fn e2e_check_net_metadata_blocked() {
        let proj = check_project();
        let output = cplt_cmd()
            .arg("--project-dir")
            .arg(proj.path())
            .args([
                "--agent",
                "shell",
                "check",
                "net",
                "169.254.169.254",
                "--no-connect",
            ])
            .output()
            .expect("cplt check net should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("BLOCKED"),
            "metadata IP should be blocked:\n{stdout}"
        );
        assert!(
            stdout.contains("SSRF"),
            "should explain it as an SSRF block:\n{stdout}"
        );
    }

    #[test]
    fn e2e_check_net_default_allowed() {
        let proj = check_project();
        let output = cplt_cmd()
            .arg("--project-dir")
            .arg(proj.path())
            .args([
                "--agent",
                "shell",
                "check",
                "net",
                "githubcopilot.com",
                "--no-connect",
            ])
            .output()
            .expect("cplt check net should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("ALLOWED"),
            "an allow-listed default domain should be allowed:\n{stdout}"
        );
    }

    #[test]
    fn e2e_check_net_strict_allowlist_blocks_unknown() {
        let proj = check_project();
        let output = cplt_cmd()
            .arg("--project-dir")
            .arg(proj.path())
            .args([
                "--agent",
                "shell",
                "--preset",
                "strict",
                "check",
                "net",
                "totally-unknown.example",
                "--no-connect",
            ])
            .output()
            .expect("cplt check net should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("BLOCKED") && stdout.contains("allowlist"),
            "strict allowlist should block an unknown domain:\n{stdout}"
        );
    }

    #[test]
    fn e2e_check_exec_docker_blocked() {
        let proj = check_project();
        let output = cplt_cmd()
            .arg("--project-dir")
            .arg(proj.path())
            .args(["--agent", "shell", "check", "exec", "docker", "ps"])
            .output()
            .expect("cplt check exec should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("BLOCKED"),
            "docker should be gated off by default:\n{stdout}"
        );
        assert!(
            stdout.contains("--allow-docker"),
            "should name the exact fix flag:\n{stdout}"
        );
    }

    #[test]
    fn e2e_check_exec_docker_allowed_with_flag() {
        let proj = check_project();
        let output = cplt_cmd()
            .arg("--project-dir")
            .arg(proj.path())
            .args([
                "--agent",
                "shell",
                "--allow-docker",
                "check",
                "exec",
                "docker",
                "ps",
            ])
            .output()
            .expect("cplt check exec should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("ALLOWED"),
            "docker should be allowed with --allow-docker:\n{stdout}"
        );
    }

    // ── CPLT_CONFIG visibility and containment (issue #261) ─────
    //
    // CPLT_CONFIG replaces the whole user config, [sandbox] keys included, so
    // it walks around the repo-config trust machinery. Both messages must
    // survive --quiet: a quiet run is when a silent swap costs the most.

    /// A git repo with a HOME of its own, so nothing here can see the real
    /// user's config. Returns (home, project).
    fn cplt_config_fixture(tag: &str) -> (tempfile::TempDir, tempfile::TempDir) {
        let home = tempfile::tempdir().expect("home");
        let project = tempfile::tempdir().expect("project");
        std::fs::create_dir_all(home.path().join(".config/cplt")).unwrap();
        let status = git_cmd(project.path())
            .args(["init", "-q"])
            .status()
            .unwrap_or_else(|e| panic!("git init for {tag}: {e}"));
        assert!(status.success(), "git init should succeed for {tag}");
        (home, project)
    }

    #[test]
    fn e2e_cplt_config_outside_user_dir_warns_even_when_quiet() {
        let (home, project) = cplt_config_fixture("outside");
        let elsewhere = tempfile::tempdir().unwrap();
        let config = elsewhere.path().join("config.toml");
        std::fs::write(&config, "[sandbox]\n").unwrap();

        let output = cplt_cmd()
            .args(["--quiet", "--print-profile", "--agent", "copilot"])
            .current_dir(project.path())
            .env("HOME", home.path())
            .env("CPLT_CONFIG", &config)
            .output()
            .expect("should run");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "a config outside the project is allowed: {stderr}"
        );
        assert!(
            stderr.contains("CPLT_CONFIG replaces your whole cplt config"),
            "--quiet must not swallow the warning: {stderr}"
        );
    }

    #[test]
    fn e2e_cplt_config_under_user_dir_is_silent() {
        let (home, project) = cplt_config_fixture("normal");
        let config = home.path().join(".config/cplt/config.toml");
        std::fs::write(&config, "[sandbox]\n").unwrap();

        let output = cplt_cmd()
            .args(["--quiet", "--print-profile", "--agent", "copilot"])
            .current_dir(project.path())
            .env("HOME", home.path())
            .env("CPLT_CONFIG", &config)
            .output()
            .expect("should run");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "normal location works: {stderr}");
        assert!(
            !stderr.contains("CPLT_CONFIG"),
            "the normal location must not be flagged: {stderr}"
        );
    }

    #[test]
    fn e2e_cplt_config_inside_project_is_refused() {
        let (home, project) = cplt_config_fixture("inside");
        let config = project.path().join("ci/cplt.toml");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, "[sandbox]\nallow_env_files = true\n").unwrap();

        let output = cplt_cmd()
            .args(["--quiet", "--print-profile", "--agent", "copilot"])
            .current_dir(project.path())
            .env("HOME", home.path())
            .env("CPLT_CONFIG", &config)
            .output()
            .expect("should run");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "repo-controlled config must not launch: {stderr}"
        );
        assert!(
            stderr.contains("points inside the project directory"),
            "refusal should say why: {stderr}"
        );
    }

    #[test]
    fn e2e_cplt_config_symlinked_into_project_is_refused() {
        // The sidestep the containment check exists for: an innocent-looking
        // path outside the repo that is a symlink back into it.
        let (home, project) = cplt_config_fixture("symlink");
        let elsewhere = tempfile::tempdir().unwrap();
        let real = project.path().join("cplt.toml");
        std::fs::write(&real, "[sandbox]\n").unwrap();
        let link = elsewhere.path().join("innocent.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let output = cplt_cmd()
            .args(["--quiet", "--print-profile", "--agent", "copilot"])
            .current_dir(project.path())
            .env("HOME", home.path())
            .env("CPLT_CONFIG", &link)
            .output()
            .expect("should run");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "a symlink into the repo must be refused too: {stderr}"
        );
        assert!(
            stderr.contains("points inside the project directory"),
            "refusal should say why: {stderr}"
        );
    }

    // ============================================================
    // Cross-session SBPL profile replacement
    // ============================================================

    /// `cplt-<pid>-<nanos>.sb`, the name the launcher used to give the profile
    /// it wrote to the system temp dir — and nothing else that lives there.
    fn is_generated_profile_name(name: &str) -> bool {
        let Some(stem) = name
            .strip_prefix("cplt-")
            .and_then(|rest| rest.strip_suffix(".sb"))
        else {
            return false;
        };
        let mut parts = stem.split('-');
        let (Some(pid), Some(nanos), None) = (parts.next(), parts.next(), parts.next()) else {
            return false;
        };
        !pid.is_empty()
            && !nanos.is_empty()
            && pid.bytes().all(|b| b.is_ascii_digit())
            && nanos.bytes().all(|b| b.is_ascii_digit())
    }

    /// The profile must never reach the kernel as a pathname.
    ///
    /// The generated profile grants every sandbox write throughout
    /// `/private/tmp` and `/private/var/folders`. While cplt handed
    /// `sandbox-exec` a `-f <path>` under the system temp dir, any other
    /// sandboxed session could overwrite that file between our write and the
    /// kernel's read and choose the policy actually enforced — not a denial of
    /// service, a complete policy replacement.
    ///
    /// This is that attack, run for real: a thread rewrites every `cplt-*.sb`
    /// it sees with `(allow default)` while cplt launches repeatedly with a
    /// canary file explicitly denied. If even one launch reads the canary, the
    /// kernel enforced the attacker's profile. With the profile passed inline
    /// (`-p`) there is no file to swap and every launch is denied.
    #[test]
    fn profile_cannot_be_swapped_by_another_session() {
        require_sandbox!();

        let project = project_dir();
        // Canary and fake agent both live in the TempDir, so an early panic
        // cannot leave either behind in the checkout.
        let fake_dir = tempfile::Builder::new()
            .prefix(".cplt-e2e-fake-copilot-")
            .tempdir_in(&project)
            .expect("create fake copilot dir");
        let canary = fake_dir.path().join("canary");
        std::fs::write(&canary, "canary").expect("write canary");
        let script = fake_dir.path().join("copilot");
        // Relative to the agent's cwd, which `configure_command` pins to the
        // project dir. An absolute path would have to survive `sh` word
        // splitting, and a checkout under "~/My Projects" would then fail the
        // read for the wrong reason; the TempDir's own name never needs quoting.
        let canary_rel = format!(
            "{}/canary",
            fake_dir
                .path()
                .file_name()
                .expect("tempdir has a name")
                .to_string_lossy()
        );
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nif cat {canary_rel} >/dev/null 2>&1; then echo READ_ALLOWED; \
                 else echo READ_DENIED; fi\n"
            ),
        )
        .expect("write fake copilot");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake copilot");
        }

        // The attacker: another sandboxed cplt session, which the profile lets
        // write anywhere under the system temp dir.
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hits = std::sync::Arc::new(AtomicU32::new(0));
        let attacker = {
            let stop = std::sync::Arc::clone(&stop);
            let hits = std::sync::Arc::clone(&hits);
            std::thread::spawn(move || {
                let temp = std::env::temp_dir();
                // Bounded, not just flagged: a panic anywhere below skips the
                // explicit stop, and a detached thread scanning the temp dir
                // for the rest of the process would slow every test after it.
                let deadline = std::time::Instant::now() + std::time::Duration::from_mins(2);
                while !stop.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
                    // A scan every millisecond, not a spin: `read_dir` over the
                    // whole system temp dir pinned a core for the length of the
                    // test and starved the other tests sharing the binary. The
                    // window a real attacker gets is the whole gap between our
                    // write and the kernel's read, so 1ms costs the attack
                    // nothing — it still lands 15/15 against the old code.
                    std::thread::sleep(std::time::Duration::from_micros(500));
                    let Ok(entries) = std::fs::read_dir(&temp) else {
                        continue;
                    };
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name = name.to_string_lossy();
                        // `cplt-<pid>-<nanos>.sb` exactly. Other tests park
                        // their own fixtures in the temp dir as `cplt-test-*.sb`
                        // and `cplt-portfilter-*.sb`; overwriting one of those
                        // with `(allow default)` would turn a sibling test green
                        // while proving nothing.
                        if is_generated_profile_name(&name)
                            && std::fs::write(entry.path(), "(version 1)\n(allow default)\n")
                                .is_ok()
                        {
                            hits.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
        };

        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_dir.path().display());
        let mut allowed = 0;
        let mut denied = 0;
        let mut transcript = String::new();
        for attempt in 0..25 {
            let output = cplt_cmd()
                .args(["--yes", "--deny-path"])
                .arg(&canary)
                .args(["--", "--version"])
                .current_dir(&project)
                .env("PATH", &new_path)
                .output()
                .expect("binary should run");
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            if stdout.contains("READ_ALLOWED") {
                allowed += 1;
            } else if stdout.contains("READ_DENIED") {
                denied += 1;
            }
            use std::fmt::Write as _;
            let _ = writeln!(transcript, "attempt {attempt}: {}", stdout.trim());
        }

        stop.store(true, Ordering::Relaxed);
        attacker.join().expect("attacker thread");

        assert_eq!(
            allowed,
            0,
            "an attacker's SBPL profile replaced ours in {allowed}/25 launches \
             ({} temp-file overwrites landed) — the profile must not reach the \
             kernel as a pathname:\n{transcript}",
            hits.load(Ordering::Relaxed)
        );
        // Guard against a vacuous pass: the launches must actually have reached
        // the fake agent inside the sandbox.
        assert!(
            denied > 0,
            "no launch reached the sandboxed agent, so nothing was proven:\n{transcript}"
        );
    }

    /// A descriptor the caller leaves open reaches the agent through
    /// `sandbox-exec`, and reading it needs no `open(2)` for the sandbox to
    /// refuse. Any wrapper, IDE or service that launches cplt holding a
    /// non-CLOEXEC `.env` or a connected socket would hand that capability
    /// straight past every path and socket rule.
    #[test]
    fn e2e_inherited_descriptor_does_not_reach_the_agent() {
        require_sandbox!();
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        use std::os::unix::io::AsRawFd as _;
        use std::os::unix::process::CommandExt as _;

        const MARKER: &str = "LEAKED-THROUGH-FD-3";

        let mut secret = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(secret, "{MARKER}").expect("write");
        secret.flush().expect("flush");
        // A fresh read handle at offset 0, with CLOEXEC cleared: exactly the
        // state a parent process leaves a descriptor in.
        let handle = std::fs::File::open(secret.path()).expect("reopen");
        let leaked = handle.as_raw_fd();
        assert_eq!(unsafe { libc::fcntl(leaked, libc::F_SETFD, 0) }, 0);

        // The agent reads the inherited descriptor directly. `<&3` is a
        // redirect from an already-open fd, not a path lookup, so nothing in
        // the SBPL profile is consulted.
        let fake_dir = tempfile::Builder::new()
            .prefix(".cplt-e2e-fake-copilot-")
            .tempdir_in(project_dir())
            .expect("create fake copilot dir");
        let script = fake_dir.path().join("copilot");
        std::fs::write(&script, "#!/bin/sh\ncat <&3 2>/dev/null\necho AGENT-RAN\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_dir.path().display());
        let mut cmd = cplt_cmd();
        cmd.args(["--yes", "--no-validate", "--", "--version"])
            .current_dir(project_dir())
            .env("PATH", &new_path);
        // Put the leak on fd 3 inside cplt, the way the reviewer demonstrated it.
        // SAFETY: dup2 only; runs between fork and exec, no allocation.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(leaked, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let output = cmd.output().expect("binary should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            stdout.contains("AGENT-RAN"),
            "the fake agent did not run, so this test proves nothing.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            !stdout.contains(MARKER),
            "the agent read a descriptor cplt inherited from its caller.\nstdout: {stdout}"
        );
    }
}
