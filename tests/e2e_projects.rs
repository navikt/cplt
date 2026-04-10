//! End-to-end tests with realistic project structures.
//!
//! These tests create temporary project directories that look like real
//! Node.js, Go, Python, and Rust projects, then run cplt with a fake
//! copilot script to verify sandbox behavior end-to-end.
//!
//! The fake copilot scripts simulate agent operations (file reads, writes,
//! git commands, secret access) and produce structured output:
//!   RESULT:<operation>:OK
//!   RESULT:<operation>:FAIL
//!
//! Run: cargo test --test e2e_projects

#[cfg(target_os = "macos")]
mod project_tests {
    use std::fmt::Write as _;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU32, Ordering};

    static PROJECT_COUNTER: AtomicU32 = AtomicU32::new(0);

    // ── Guards ─────────────────────────────────────────────────────

    fn sandbox_exec_available() -> bool {
        Command::new("sandbox-exec")
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    macro_rules! require_sandbox {
        () => {
            if !sandbox_exec_available() {
                eprintln!("SKIPPED: sandbox-exec not available (likely already sandboxed)");
                return;
            }
        };
    }

    fn binary_path() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_cplt"))
    }

    // ── TempProject ────────────────────────────────────────────────

    /// A temporary project directory with realistic file structure.
    /// Cleaned up on drop.
    struct TempProject {
        root: PathBuf,
    }

    impl TempProject {
        /// Create a temp project dir inside the cplt repo (not /tmp).
        /// Process-exec is denied in /private/tmp and /private/var/folders,
        /// so temp projects must live in a path that allows exec. The cplt
        /// repo dir (CARGO_MANIFEST_DIR) is in a normal filesystem location.
        fn new(name: &str) -> Self {
            let id = PROJECT_COUNTER.fetch_add(1, Ordering::SeqCst);
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let root = base.join(format!(".cplt-e2e-{name}-{}-{id}", std::process::id()));
            fs::create_dir_all(&root).expect("create project dir");
            TempProject { root }
        }

        fn path(&self) -> &Path {
            &self.root
        }

        fn canonical_path(&self) -> PathBuf {
            fs::canonicalize(&self.root).expect("canonicalize project dir")
        }

        /// Write a file relative to project root, creating parent dirs.
        fn write_file(&self, rel_path: &str, content: &str) {
            let path = self.root.join(rel_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent dirs");
            }
            fs::write(&path, content).expect("write file");
        }

        /// Initialize a git repo with an initial commit.
        fn git_init(&self) {
            let run = |args: &[&str]| {
                Command::new("git")
                    .args(args)
                    .current_dir(&self.root)
                    .env("GIT_AUTHOR_NAME", "Test")
                    .env("GIT_AUTHOR_EMAIL", "test@example.com")
                    .env("GIT_COMMITTER_NAME", "Test")
                    .env("GIT_COMMITTER_EMAIL", "test@example.com")
                    .output()
                    .expect("git command");
            };
            run(&["init", "-b", "main"]);
            run(&["add", "."]);
            run(&["commit", "-m", "Initial commit", "--allow-empty"]);
        }

        // ── Project scaffolding ────────────────────────────────────

        fn scaffold_node() -> Self {
            let p = Self::new("node");
            p.write_file(
                "package.json",
                r#"{"name": "test-app", "version": "1.0.0", "main": "src/index.js"}"#,
            );
            p.write_file(
                "src/index.js",
                "const http = require('http');\nconst port = 3000;\nconsole.log('hello');\n",
            );
            p.write_file(
                "src/utils.js",
                "module.exports = { add: (a, b) => a + b };\n",
            );
            p.write_file("README.md", "# Test Node App\n\nA sample project.\n");
            p.write_file(".gitignore", "node_modules/\n.env*\n*.pem\n*.key\n");
            p.git_init();
            // Sensitive files written AFTER git init so they're untracked.
            // If committed, `git diff` would fail because the sandbox blocks
            // reading .env files, causing git's working-tree comparison to error.
            p.write_file(
                ".env",
                "DATABASE_URL=postgres://localhost/prod\nAPI_KEY=sk-secret-key\n",
            );
            p.write_file(".env.local", "LOCAL_SECRET=hunter2\n");
            p
        }

        fn scaffold_go() -> Self {
            let p = Self::new("go");
            p.write_file("go.mod", "module example.com/testapp\n\ngo 1.22\n");
            p.write_file(
                "main.go",
                "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n",
            );
            p.write_file(
                "internal/handler.go",
                "package internal\n\nfunc Handle() string { return \"ok\" }\n",
            );
            p.write_file("README.md", "# Test Go App\n");
            p.write_file(".gitignore", ".env*\n");
            p.git_init();
            p.write_file(".env", "DB_HOST=localhost\nDB_PASS=secret\n");
            p
        }

        fn scaffold_python() -> Self {
            let p = Self::new("python");
            p.write_file("requirements.txt", "flask==3.0.0\nrequests==2.31.0\n");
            p.write_file("app.py", "from flask import Flask\napp = Flask(__name__)\n");
            p.write_file("tests/test_app.py", "def test_hello():\n    assert True\n");
            p.write_file("README.md", "# Test Python App\n");
            p.write_file(".gitignore", ".env*\n__pycache__/\n");
            p.git_init();
            p.write_file(".env", "SECRET_KEY=super-secret\nDEBUG=true\n");
            p.write_file(".env.production", "SECRET_KEY=prod-key\nDEBUG=false\n");
            p
        }

        fn scaffold_rust() -> Self {
            let p = Self::new("rust");
            p.write_file(
                "Cargo.toml",
                "[package]\nname = \"test-app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            );
            p.write_file("src/main.rs", "fn main() {\n    println!(\"hello\");\n}\n");
            p.write_file(
                "src/lib.rs",
                "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
            );
            p.write_file("README.md", "# Test Rust App\n");
            p.write_file(".gitignore", ".env*\ntarget/\n");
            p.git_init();
            p.write_file(".env", "RUST_LOG=debug\nSECRET=hidden\n");
            p
        }
    }

    impl Drop for TempProject {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    // ── FakeCopilot ────────────────────────────────────────────────

    /// Create a fake copilot script inside the project directory.
    /// Returns the directory containing the script (to prepend to PATH).
    ///
    /// The script is placed inside the project dir so the sandbox allows
    /// execution (process-exec is denied in /tmp and /var/folders).
    fn create_fake_copilot(project: &TempProject, script_body: &str) -> PathBuf {
        let id = PROJECT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = project.path().join(format!(".fake-copilot-{id}"));
        fs::create_dir_all(&dir).expect("create fake copilot dir");

        let mut script = String::from("#!/bin/sh\nset -eu\n");
        script.push_str(script_body);

        let script_path = dir.join("copilot");
        fs::write(&script_path, &script).expect("write fake copilot");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        dir
    }

    // ── Test runner ────────────────────────────────────────────────

    /// Run cplt with a fake copilot against a project. Returns (stdout, stderr, success).
    fn run_cplt(
        project: &TempProject,
        fake_copilot_dir: &Path,
        extra_args: &[&str],
    ) -> (String, String, bool) {
        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_copilot_dir.display());

        let output = Command::new(binary_path())
            .args(["--yes", "--no-validate"])
            .args(["--project-dir", &project.canonical_path().to_string_lossy()])
            .args(extra_args)
            .args(["--", "--version"]) // fake copilot ignores this
            .env("PATH", &new_path)
            .output()
            .expect("cplt should run");

        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
            output.status.success(),
        )
    }

    /// Assert that a RESULT line is present and OK.
    fn assert_result_ok(stdout: &str, operation: &str) {
        let expected = format!("RESULT:{operation}:OK");
        assert!(
            stdout.contains(&expected),
            "Expected {expected} in output.\nstdout:\n{stdout}"
        );
    }

    /// Assert that a RESULT line is present and FAIL.
    fn assert_result_fail(stdout: &str, operation: &str) {
        let expected = format!("RESULT:{operation}:FAIL");
        assert!(
            stdout.contains(&expected),
            "Expected {expected} in output.\nstdout:\n{stdout}"
        );
    }

    // ── File operations script builder ─────────────────────────────

    /// Script that reads source files, writes new files, and creates directories.
    fn script_file_ops(files_to_read: &[&str], file_to_write: &str) -> String {
        let mut s = String::new();
        for file in files_to_read {
            writeln!(
                s,
                r#"if cat "{file}" >/dev/null 2>&1; then echo "RESULT:read_{file}:OK"; else echo "RESULT:read_{file}:FAIL"; fi"#,
            )
            .unwrap();
        }
        // Write a new file (creating parent dir)
        writeln!(
            s,
            r#"if mkdir -p "$(dirname "{file_to_write}")" 2>/dev/null && echo "generated content" > "{file_to_write}" 2>/dev/null; then echo "RESULT:write_{file_to_write}:OK"; else echo "RESULT:write_{file_to_write}:FAIL"; fi"#,
        )
        .unwrap();
        // Create a new directory + file
        writeln!(
            s,
            r#"if mkdir -p new-dir && echo "data" > new-dir/output.txt 2>/dev/null; then echo "RESULT:create_dir:OK"; else echo "RESULT:create_dir:FAIL"; fi"#,
        )
        .unwrap();
        s
    }

    /// Script that attempts to read sensitive files.
    fn script_read_secrets(project_files: &[&str], home_dirs: &[&str]) -> String {
        let mut s = String::new();
        for file in project_files {
            // Normalize name for result key (replace dots and slashes)
            let key = file.replace(['/', '.'], "_");
            writeln!(
                s,
                r#"if cat "{file}" >/dev/null 2>&1; then echo "RESULT:{key}:OK"; else echo "RESULT:{key}:FAIL"; fi"#,
            )
            .unwrap();
        }
        for dir in home_dirs {
            let key = dir.replace(['/', '.'], "_");
            writeln!(
                s,
                r#"if ls "$HOME/{dir}" >/dev/null 2>&1; then echo "RESULT:home_{key}:OK"; else echo "RESULT:home_{key}:FAIL"; fi"#,
            )
            .unwrap();
        }
        s
    }

    /// Script that runs git operations.
    fn script_git_ops() -> String {
        r#"
if git status >/dev/null 2>&1; then echo "RESULT:git_status:OK"; else echo "RESULT:git_status:FAIL"; fi
if git log --oneline -1 >/dev/null 2>&1; then echo "RESULT:git_log:OK"; else echo "RESULT:git_log:FAIL"; fi
if git diff --stat >/dev/null 2>&1; then echo "RESULT:git_diff:OK"; else echo "RESULT:git_diff:FAIL"; fi
if git branch >/dev/null 2>&1; then echo "RESULT:git_branch:OK"; else echo "RESULT:git_branch:FAIL"; fi
"#
        .to_string()
    }

    /// Script that performs a multi-step read→modify→write→verify workflow.
    fn script_multi_step(source_file: &str, target_file: &str) -> String {
        format!(
            r#"
# Step 1: Read source
CONTENT=$(cat "{source_file}" 2>/dev/null) || {{ echo "RESULT:read_source:FAIL"; exit 0; }}
echo "RESULT:read_source:OK"

# Step 2: Transform content
MODIFIED=$(echo "$CONTENT" | sed 's/hello/goodbye/g' 2>/dev/null) || {{ echo "RESULT:transform:FAIL"; exit 0; }}
echo "RESULT:transform:OK"

# Step 3: Write to new file
echo "$MODIFIED" > "{target_file}" 2>/dev/null || {{ echo "RESULT:write_target:FAIL"; exit 0; }}
echo "RESULT:write_target:OK"

# Step 4: Verify
if grep -q "goodbye" "{target_file}" 2>/dev/null; then echo "RESULT:verify:OK"; else echo "RESULT:verify:FAIL"; fi
"#
        )
    }

    /// Script that tests git persistence vectors.
    fn script_git_persistence(project_path: &str) -> String {
        format!(
            r#"
# Try to write a git hook
if echo '#!/bin/sh' > "{project_path}/.git/hooks/post-checkout" 2>/dev/null; then
    echo "RESULT:git_hook_write:OK"
else
    echo "RESULT:git_hook_write:FAIL"
fi

# Try to modify .git/config
if echo 'injected' >> "{project_path}/.git/config" 2>/dev/null; then
    echo "RESULT:git_config_write:OK"
else
    echo "RESULT:git_config_write:FAIL"
fi

# Try to modify .gitmodules
if echo '[submodule "evil"]' >> "{project_path}/.gitmodules" 2>/dev/null; then
    echo "RESULT:gitmodules_write:OK"
else
    echo "RESULT:gitmodules_write:FAIL"
fi
"#
        )
    }

    // ============================================================
    // Per-language happy-path tests
    // ============================================================

    #[test]
    fn project_node_file_ops() {
        require_sandbox!();
        let project = TempProject::scaffold_node();
        let script = script_file_ops(
            &["package.json", "src/index.js", "src/utils.js", "README.md"],
            "dist/bundle.js",
        );
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "read_package.json");
        assert_result_ok(&stdout, "read_src/index.js");
        assert_result_ok(&stdout, "read_src/utils.js");
        assert_result_ok(&stdout, "read_README.md");
        assert_result_ok(&stdout, "write_dist/bundle.js");
        assert_result_ok(&stdout, "create_dir");
    }

    #[test]
    fn project_go_file_ops() {
        require_sandbox!();
        let project = TempProject::scaffold_go();
        let script = script_file_ops(
            &["go.mod", "main.go", "internal/handler.go"],
            "internal/handler_test.go",
        );
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "read_go.mod");
        assert_result_ok(&stdout, "read_main.go");
        assert_result_ok(&stdout, "read_internal/handler.go");
        assert_result_ok(&stdout, "write_internal/handler_test.go");
        assert_result_ok(&stdout, "create_dir");
    }

    #[test]
    fn project_python_file_ops() {
        require_sandbox!();
        let project = TempProject::scaffold_python();
        let script = script_file_ops(
            &["requirements.txt", "app.py", "tests/test_app.py"],
            "tests/test_new.py",
        );
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "read_requirements.txt");
        assert_result_ok(&stdout, "read_app.py");
        assert_result_ok(&stdout, "read_tests/test_app.py");
        assert_result_ok(&stdout, "write_tests/test_new.py");
        assert_result_ok(&stdout, "create_dir");
    }

    #[test]
    fn project_rust_file_ops() {
        require_sandbox!();
        let project = TempProject::scaffold_rust();
        let script = script_file_ops(&["Cargo.toml", "src/main.rs", "src/lib.rs"], "src/utils.rs");
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "read_Cargo.toml");
        assert_result_ok(&stdout, "read_src/main.rs");
        assert_result_ok(&stdout, "read_src/lib.rs");
        assert_result_ok(&stdout, "write_src/utils.rs");
        assert_result_ok(&stdout, "create_dir");
    }

    // ============================================================
    // Workflow tests
    // ============================================================

    #[test]
    fn project_git_workflow() {
        require_sandbox!();
        let project = TempProject::scaffold_node();
        let script = script_git_ops();
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "git_status");
        assert_result_ok(&stdout, "git_log");
        assert_result_ok(&stdout, "git_diff");
        assert_result_ok(&stdout, "git_branch");
    }

    #[test]
    fn project_multi_step_edit() {
        require_sandbox!();
        let project = TempProject::scaffold_node();
        // index.js contains "hello"
        let script = script_multi_step("src/index.js", "src/index.modified.js");
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "read_source");
        assert_result_ok(&stdout, "transform");
        assert_result_ok(&stdout, "write_target");
        assert_result_ok(&stdout, "verify");
    }

    // ============================================================
    // Security matrix tests
    // ============================================================

    #[test]
    fn project_secrets_blocked_by_default() {
        require_sandbox!();
        let project = TempProject::scaffold_node();
        // The sandbox blocks dot-prefixed filenames: .env, .env.*, .pem, .key
        // It does NOT block server.pem or server.key (only literal .pem/.key).
        let script = script_read_secrets(&[".env", ".env.local"], &[]);
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_fail(&stdout, "_env"); // .env
        assert_result_fail(&stdout, "_env_local"); // .env.local
    }

    #[test]
    fn project_home_secrets_blocked() {
        require_sandbox!();
        let project = TempProject::scaffold_node();

        // Only test dirs that actually exist on this machine
        let mut home_dirs = Vec::new();
        let home = std::env::var("HOME").unwrap();
        for dir in &[".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker"] {
            if Path::new(&home).join(dir).exists() {
                home_dirs.push(*dir);
            }
        }
        if home_dirs.is_empty() {
            eprintln!("SKIPPED: no sensitive home dirs exist to test");
            return;
        }

        let script = script_read_secrets(&[], &home_dirs);
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        for dir in &home_dirs {
            let key = dir.replace('.', "_");
            assert_result_fail(&stdout, &format!("home_{key}"));
        }
    }

    // ============================================================
    // Git persistence prevention
    // ============================================================

    #[test]
    fn project_git_hooks_blocked() {
        require_sandbox!();
        let project = TempProject::scaffold_node();
        // Create .git/hooks dir and a .gitmodules file so write attempts are meaningful
        fs::create_dir_all(project.path().join(".git/hooks")).ok();
        fs::write(project.path().join(".gitmodules"), "").ok();

        let project_path = project.canonical_path().to_string_lossy().to_string();
        let script = script_git_persistence(&project_path);
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        // All git persistence vectors should be blocked
        assert_result_fail(&stdout, "git_hook_write");
        assert_result_fail(&stdout, "git_config_write");
        assert_result_fail(&stdout, "gitmodules_write");
    }

    // ============================================================
    // Mode combination tests
    // ============================================================

    #[test]
    fn project_with_allow_env_files() {
        require_sandbox!();
        let project = TempProject::scaffold_node();
        let script = script_read_secrets(&[".env", ".env.local"], &[]);
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &["--allow-env-files"]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        // With --allow-env-files, .env files should be readable
        assert_result_ok(&stdout, "_env");
        assert_result_ok(&stdout, "_env_local");
    }

    #[test]
    fn project_with_scratch_dir_exec() {
        require_sandbox!();
        let project = TempProject::scaffold_go();
        let script = r#"
# The scratch dir is set as TMPDIR — write a binary there and execute it
SCRATCH="$TMPDIR"
if [ -z "$SCRATCH" ] || [ "$SCRATCH" = "/tmp" ] || [ "$SCRATCH" = "/private/tmp" ]; then
    echo "RESULT:scratch_env:FAIL"
    exit 0
fi
echo "RESULT:scratch_env:OK"

# Copy a real binary to scratch and execute it (simulates go test compile)
if cp /usr/bin/true "$SCRATCH/test-binary" 2>/dev/null && chmod +x "$SCRATCH/test-binary" 2>/dev/null; then
    echo "RESULT:scratch_write:OK"
else
    echo "RESULT:scratch_write:FAIL"
    exit 0
fi

if "$SCRATCH/test-binary" 2>/dev/null; then
    echo "RESULT:scratch_exec:OK"
else
    echo "RESULT:scratch_exec:FAIL"
fi
"#;
        let fake_dir = create_fake_copilot(&project, script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &["--scratch-dir"]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "scratch_env");
        assert_result_ok(&stdout, "scratch_write");
        assert_result_ok(&stdout, "scratch_exec");
    }

    #[test]
    fn project_with_deny_path() {
        require_sandbox!();
        let project = TempProject::scaffold_node();
        // Create a secrets subdir within the project
        project.write_file("config/secrets/db.yml", "password: hunter2\n");
        let secrets_dir = project.canonical_path().join("config/secrets");

        let script = r#"
# Should be able to read normal config
if cat config/secrets/../secrets/../secrets/../../package.json >/dev/null 2>&1; then
    echo "RESULT:read_normal:OK"
else
    echo "RESULT:read_normal:FAIL"
fi

# Should NOT be able to read denied path
if cat config/secrets/db.yml >/dev/null 2>&1; then
    echo "RESULT:read_denied:OK"
else
    echo "RESULT:read_denied:FAIL"
fi

# Should NOT be able to write to denied path
if echo "injected" > config/secrets/evil.yml 2>/dev/null; then
    echo "RESULT:write_denied:OK"
else
    echo "RESULT:write_denied:FAIL"
fi
"#;
        let fake_dir = create_fake_copilot(&project, script);
        let (stdout, stderr, success) = run_cplt(
            &project,
            &fake_dir,
            &["--deny-path", &secrets_dir.to_string_lossy()],
        );

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "read_normal");
        assert_result_fail(&stdout, "read_denied");
        assert_result_fail(&stdout, "write_denied");
    }

    #[test]
    fn project_with_config_file() {
        require_sandbox!();
        let project = TempProject::scaffold_node();

        // Create a temporary config file
        let config_dir = project.path().join(".cplt-config-test");
        fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("config.toml");
        fs::write(
            &config_path,
            r#"
[sandbox]
allow_env_files = true
"#,
        )
        .unwrap();

        // Fake copilot that tries to read .env (should succeed via config)
        let script = script_read_secrets(&[".env"], &[]);
        let fake_dir = create_fake_copilot(&project, &script);

        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_dir.display());

        let output = Command::new(binary_path())
            .args(["--yes", "--no-validate"])
            .args(["--project-dir", &project.canonical_path().to_string_lossy()])
            .args(["--", "--version"])
            .env("PATH", &new_path)
            .env("CPLT_CONFIG", config_path.to_string_lossy().as_ref())
            .output()
            .expect("cplt should run");

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        assert!(
            output.status.success(),
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        // Config enables allow_env_files, so .env should be readable
        assert_result_ok(&stdout, "_env");
    }

    #[test]
    fn project_with_allow_read_external() {
        require_sandbox!();
        let project = TempProject::scaffold_node();

        // Create an external directory with shared code
        let external = TempProject::new("external-libs");
        external.write_file(
            "shared/utils.js",
            "module.exports = { helper: () => 42 };\n",
        );

        let script = format!(
            r#"
# Should be able to read external dir
if cat "{}/shared/utils.js" >/dev/null 2>&1; then
    echo "RESULT:read_external:OK"
else
    echo "RESULT:read_external:FAIL"
fi

# Should NOT be able to write to external dir (it's allow-read, not allow-write)
if echo "injected" > "{}/shared/evil.js" 2>/dev/null; then
    echo "RESULT:write_external:OK"
else
    echo "RESULT:write_external:FAIL"
fi
"#,
            external.canonical_path().display(),
            external.canonical_path().display(),
        );

        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(
            &project,
            &fake_dir,
            &["--allow-read", &external.canonical_path().to_string_lossy()],
        );

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "read_external");
        assert_result_fail(&stdout, "write_external");
    }

    #[test]
    fn project_with_proxy_mode() {
        require_sandbox!();
        let project = TempProject::scaffold_node();
        let port = 19400 + (std::process::id() % 600) as u16;

        // Fake copilot that just reads a file (basic smoke test with proxy)
        let script = script_file_ops(&["package.json"], "output.txt");
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(
            &project,
            &fake_dir,
            &["--with-proxy", "--proxy-port", &port.to_string()],
        );

        assert!(
            success,
            "cplt should succeed with proxy.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "read_package.json");
        assert!(
            stderr.contains("Proxy running"),
            "proxy should have started.\nstderr: {stderr}"
        );
    }

    #[test]
    fn project_env_vars_sanitized() {
        require_sandbox!();
        let project = TempProject::scaffold_node();

        // Fake copilot that dumps specific env vars.
        // Use ${var:-} to avoid set -u errors on unset vars.
        let script = r#"
# Safe vars should be present
if [ -n "${HOME:-}" ]; then echo "RESULT:env_home:OK"; else echo "RESULT:env_home:FAIL"; fi
if [ -n "${PATH:-}" ]; then echo "RESULT:env_path:OK"; else echo "RESULT:env_path:FAIL"; fi

# Dangerous vars should be stripped
if [ -n "${AWS_SECRET_ACCESS_KEY:-}" ]; then echo "RESULT:env_aws:OK"; else echo "RESULT:env_aws:FAIL"; fi
if [ -n "${DATABASE_URL:-}" ]; then echo "RESULT:env_dburl:OK"; else echo "RESULT:env_dburl:FAIL"; fi
if [ -n "${NPM_TOKEN:-}" ]; then echo "RESULT:env_npm:OK"; else echo "RESULT:env_npm:FAIL"; fi

# Hardening vars should be injected
if [ "${npm_config_ignore_scripts:-}" = "true" ]; then echo "RESULT:env_hardening_npm:OK"; else echo "RESULT:env_hardening_npm:FAIL"; fi
if [ "${GIT_TERMINAL_PROMPT:-}" = "0" ]; then echo "RESULT:env_hardening_git:OK"; else echo "RESULT:env_hardening_git:FAIL"; fi
"#;
        let fake_dir = create_fake_copilot(&project, script);

        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_dir.display());

        let output = Command::new(binary_path())
            .args(["--yes", "--no-validate"])
            .args(["--project-dir", &project.canonical_path().to_string_lossy()])
            .args(["--", "--version"])
            .env("PATH", &new_path)
            .env("AWS_SECRET_ACCESS_KEY", "FAKESECRET")
            .env("DATABASE_URL", "postgres://localhost/prod")
            .env("NPM_TOKEN", "npm_faketoken")
            .output()
            .expect("cplt should run");

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        assert!(
            output.status.success(),
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );

        // Safe vars present
        assert_result_ok(&stdout, "env_home");
        assert_result_ok(&stdout, "env_path");

        // Dangerous vars stripped
        assert_result_fail(&stdout, "env_aws");
        assert_result_fail(&stdout, "env_dburl");
        assert_result_fail(&stdout, "env_npm");

        // Hardening vars injected
        assert_result_ok(&stdout, "env_hardening_npm");
        assert_result_ok(&stdout, "env_hardening_git");
    }

    #[test]
    fn project_dotenv_variants_all_blocked() {
        require_sandbox!();
        let project = TempProject::scaffold_python();
        // Python project already has .env and .env.production
        // Add more variants
        project.write_file(".env.staging", "STAGING=true\n");
        project.write_file(".env.test", "TEST=true\n");

        let script = script_read_secrets(
            &[".env", ".env.production", ".env.staging", ".env.test"],
            &[],
        );
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        // All .env variants should be blocked
        assert_result_fail(&stdout, "_env");
        assert_result_fail(&stdout, "_env_production");
        assert_result_fail(&stdout, "_env_staging");
        assert_result_fail(&stdout, "_env_test");
    }

    #[test]
    fn project_can_spawn_common_tools() {
        require_sandbox!();
        let project = TempProject::scaffold_node();

        let script = r#"
# Test common developer tools that should be executable
if /usr/bin/true 2>/dev/null; then echo "RESULT:exec_true:OK"; else echo "RESULT:exec_true:FAIL"; fi
if /bin/cat /dev/null 2>/dev/null; then echo "RESULT:exec_cat:OK"; else echo "RESULT:exec_cat:FAIL"; fi
if /usr/bin/wc -l < /dev/null 2>/dev/null; then echo "RESULT:exec_wc:OK"; else echo "RESULT:exec_wc:FAIL"; fi
if git --version >/dev/null 2>&1; then echo "RESULT:exec_git:OK"; else echo "RESULT:exec_git:FAIL"; fi
if /bin/mkdir -p test-spawn-dir 2>/dev/null; then echo "RESULT:exec_mkdir:OK"; else echo "RESULT:exec_mkdir:FAIL"; fi
if /bin/rm -rf test-spawn-dir 2>/dev/null; then echo "RESULT:exec_rm:OK"; else echo "RESULT:exec_rm:FAIL"; fi
"#;
        let fake_dir = create_fake_copilot(&project, script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "exec_true");
        assert_result_ok(&stdout, "exec_cat");
        assert_result_ok(&stdout, "exec_wc");
        assert_result_ok(&stdout, "exec_git");
        assert_result_ok(&stdout, "exec_mkdir");
        assert_result_ok(&stdout, "exec_rm");
    }
}
