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
    use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

    static PROJECT_COUNTER: AtomicU32 = AtomicU32::new(0);
    /// Each proxy test gets a unique port to avoid collisions in parallel runs.
    static PROXY_PORT_COUNTER: AtomicU16 = AtomicU16::new(0);

    fn next_proxy_port() -> u16 {
        19400 + PROXY_PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
    }

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

        fn scaffold_kotlin_ktor() -> Self {
            let p = Self::new("kotlin-ktor");
            p.write_file(
                "build.gradle.kts",
                r#"plugins {
    kotlin("jvm") version "2.1.20"
    id("io.ktor.plugin") version "3.1.2"
}

group = "com.example"
version = "0.0.1"

application {
    mainClass = "com.example.ApplicationKt"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.ktor:ktor-server-core")
    implementation("io.ktor:ktor-server-netty")
    testImplementation("io.ktor:ktor-server-test-host")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit")
}
"#,
            );
            p.write_file(
                "settings.gradle.kts",
                "rootProject.name = \"test-ktor-app\"\n",
            );
            p.write_file(
                "src/main/kotlin/com/example/Application.kt",
                r#"package com.example

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun main() {
    embeddedServer(Netty, port = 8080) {
        routing {
            get("/") {
                call.respondText("Hello, world!")
            }
        }
    }.start(wait = true)
}
"#,
            );
            p.write_file("README.md", "# Test Kotlin Ktor App\n");
            p.write_file(".gitignore", ".env*\nbuild/\n.gradle/\n");
            p.git_init();
            p.write_file(".env", "DB_URL=jdbc:postgresql://localhost/prod\n");
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
        let port = next_proxy_port();

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

    #[test]
    fn project_proxy_env_vars_injected() {
        require_sandbox!();
        let project = TempProject::scaffold_node();
        let port = next_proxy_port();

        let script = r#"
# Proxy env vars should be set when --with-proxy is used
if [ -n "${NODE_USE_ENV_PROXY:-}" ]; then echo "RESULT:node_use_env_proxy:OK"; else echo "RESULT:node_use_env_proxy:FAIL"; fi
if echo "${HTTP_PROXY:-}" | grep -q '127.0.0.1'; then echo "RESULT:http_proxy_upper:OK"; else echo "RESULT:http_proxy_upper:FAIL"; fi
if echo "${HTTPS_PROXY:-}" | grep -q '127.0.0.1'; then echo "RESULT:https_proxy_upper:OK"; else echo "RESULT:https_proxy_upper:FAIL"; fi
if echo "${http_proxy:-}" | grep -q '127.0.0.1'; then echo "RESULT:http_proxy_lower:OK"; else echo "RESULT:http_proxy_lower:FAIL"; fi
if echo "${https_proxy:-}" | grep -q '127.0.0.1'; then echo "RESULT:https_proxy_lower:OK"; else echo "RESULT:https_proxy_lower:FAIL"; fi
if [ -n "${NO_PROXY:-}" ]; then echo "RESULT:no_proxy_upper:OK"; else echo "RESULT:no_proxy_upper:FAIL"; fi
if [ -n "${no_proxy:-}" ]; then echo "RESULT:no_proxy_lower:OK"; else echo "RESULT:no_proxy_lower:FAIL"; fi
"#;
        let fake_dir = create_fake_copilot(&project, script);
        let (stdout, stderr, success) = run_cplt(
            &project,
            &fake_dir,
            &["--with-proxy", "--proxy-port", &port.to_string()],
        );

        assert!(
            success,
            "cplt should succeed with proxy.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "node_use_env_proxy");
        assert_result_ok(&stdout, "http_proxy_upper");
        assert_result_ok(&stdout, "https_proxy_upper");
        assert_result_ok(&stdout, "http_proxy_lower");
        assert_result_ok(&stdout, "https_proxy_lower");
        assert_result_ok(&stdout, "no_proxy_upper");
        assert_result_ok(&stdout, "no_proxy_lower");
    }

    #[test]
    fn project_proxy_port_filtering() {
        require_sandbox!();
        let project = TempProject::scaffold_node();
        let port = next_proxy_port();

        // Script that tries to connect to various ports through the proxy.
        // For port 443 we use a non-existent host — the proxy allows the port
        // but fails DNS, returning 502. This proves port filtering passed.
        let script = format!(
            r#"
# Port 443: allowed → proxy tries DNS, fails → 502 (proves port check passed)
RESP443=$(printf 'CONNECT nonexistent.invalid:443 HTTP/1.1\r\nHost: nonexistent.invalid:443\r\n\r\n' | nc -w 3 127.0.0.1 {port} 2>/dev/null | head -1)
if echo "$RESP443" | grep -q "502"; then echo "RESULT:port_443:OK"; else echo "RESULT:port_443:FAIL:$RESP443"; fi

# Port 80: blocked → 403 (port filter rejects before DNS)
RESP80=$(printf 'CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n' | nc -w 2 127.0.0.1 {port} 2>/dev/null | head -1)
if echo "$RESP80" | grep -q "403"; then echo "RESULT:port_80:OK"; else echo "RESULT:port_80:FAIL:$RESP80"; fi

# Port 8080: blocked → 403
RESP8080=$(printf 'CONNECT example.com:8080 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n' | nc -w 2 127.0.0.1 {port} 2>/dev/null | head -1)
if echo "$RESP8080" | grep -q "403"; then echo "RESULT:port_8080:OK"; else echo "RESULT:port_8080:FAIL:$RESP8080"; fi
"#
        );
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(
            &project,
            &fake_dir,
            &["--with-proxy", "--proxy-port", &port.to_string()],
        );

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "port_443");
        assert_result_ok(&stdout, "port_80");
        assert_result_ok(&stdout, "port_8080");
    }

    #[test]
    fn project_no_proxy_env_without_flag() {
        require_sandbox!();
        let project = TempProject::scaffold_node();

        // Without --with-proxy, proxy env vars should NOT be present
        let script = r#"
if [ -z "${NODE_USE_ENV_PROXY:-}" ]; then echo "RESULT:no_node_proxy:OK"; else echo "RESULT:no_node_proxy:FAIL"; fi
if [ -z "${HTTP_PROXY:-}" ]; then echo "RESULT:no_http_proxy:OK"; else echo "RESULT:no_http_proxy:FAIL"; fi
if [ -z "${HTTPS_PROXY:-}" ]; then echo "RESULT:no_https_proxy:OK"; else echo "RESULT:no_https_proxy:FAIL"; fi
"#;
        let fake_dir = create_fake_copilot(&project, script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "no_node_proxy");
        assert_result_ok(&stdout, "no_http_proxy");
        assert_result_ok(&stdout, "no_https_proxy");
    }

    #[test]
    fn project_proxy_allowlist_blocks_unlisted() {
        require_sandbox!();
        let project = TempProject::scaffold_node();
        let port = next_proxy_port();

        // Create an allowlist with only one domain
        let allowlist_path = project.path().join("allowed-domains.txt");
        std::fs::write(&allowlist_path, "only-this.example.com\n").unwrap();

        // Try to CONNECT to a domain NOT in the allowlist
        let script = format!(
            r#"
RESP=$(printf 'CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com:443\r\n\r\n' | nc -w 2 127.0.0.1 {port} 2>/dev/null | head -1)
if echo "$RESP" | grep -q "403"; then echo "RESULT:blocked_unlisted:OK"; else echo "RESULT:blocked_unlisted:FAIL:$RESP"; fi
"#
        );
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(
            &project,
            &fake_dir,
            &[
                "--with-proxy",
                "--proxy-port",
                &port.to_string(),
                "--allowed-domains",
                &allowlist_path.to_string_lossy(),
            ],
        );

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "blocked_unlisted");
    }

    #[test]
    fn project_proxy_audit_log_written() {
        require_sandbox!();
        let project = TempProject::scaffold_node();
        let port = next_proxy_port();
        let log_path = project.path().join("proxy-audit.log");

        // Send a CONNECT through the proxy to generate a log entry
        let script = format!(
            r#"
printf 'CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n' | nc -w 2 127.0.0.1 {port} 2>/dev/null >/dev/null
echo "RESULT:sent:OK"
"#
        );
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(
            &project,
            &fake_dir,
            &[
                "--with-proxy",
                "--proxy-port",
                &port.to_string(),
                "--proxy-log",
                &log_path.to_string_lossy(),
            ],
        );

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "sent");

        let log_contents = std::fs::read_to_string(&log_path)
            .unwrap_or_else(|e| panic!("Audit log should exist at {}: {e}", log_path.display()));
        assert!(
            log_contents.contains("example.com:80"),
            "Audit log should contain the target.\nlog:\n{log_contents}"
        );
        assert!(
            log_contents.contains("BLOCKED-PORT"),
            "Port 80 should be blocked.\nlog:\n{log_contents}"
        );
    }

    // ============================================================
    // Go toolchain sandbox tests
    // ============================================================

    fn gradle_available() -> bool {
        Command::new("gradle")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn go_available() -> bool {
        Command::new("go")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Go build to a project-local path works without --scratch-dir.
    /// The compiled binary lives in the project dir (exec allowed).
    #[test]
    fn project_go_build_and_run_in_sandbox() {
        require_sandbox!();
        if !go_available() {
            eprintln!("SKIPPED: go not available");
            return;
        }

        let project = TempProject::scaffold_go();
        let script = r#"
export GOTOOLCHAIN=local

# go build writes the binary to the project dir (exec allowed there)
if go build -o ./testapp . 2>&1; then
    echo "RESULT:go_build:OK"
else
    echo "RESULT:go_build:FAIL"
fi

# Execute the locally-built binary
if ./testapp 2>/dev/null; then
    echo "RESULT:go_exec:OK"
else
    echo "RESULT:go_exec:FAIL"
fi
"#;
        let fake_dir = create_fake_copilot(&project, script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "go_build");
        assert_result_ok(&stdout, "go_exec");
    }

    /// Go test works with --scratch-dir: GOTMPDIR is redirected to a
    /// controlled dir with exec permissions, so the compiled test binary
    /// can be executed.
    #[test]
    fn project_go_test_with_scratch_dir() {
        require_sandbox!();
        if !go_available() {
            eprintln!("SKIPPED: go not available");
            return;
        }

        let project = TempProject::scaffold_go();
        project.write_file(
            "main_test.go",
            "package main\n\nimport \"testing\"\n\nfunc TestHello(t *testing.T) {\n\tt.Log(\"hello from sandbox\")\n}\n",
        );

        let script = r#"
export GOTOOLCHAIN=local

# Verify GOTMPDIR is redirected away from system temp dirs
GOTMP="${GOTMPDIR:-unset}"
case "$GOTMP" in
    unset|/tmp|/private/tmp|/var/folders/*|/private/var/folders/*)
        echo "RESULT:gotmpdir_redirected:FAIL:GOTMPDIR=$GOTMP"
        ;;
    *)
        echo "RESULT:gotmpdir_redirected:OK"
        ;;
esac

# go test compiles a test binary to GOTMPDIR then executes it.
# With --scratch-dir, GOTMPDIR points to a dir with exec permissions.
if go test -count=1 . 2>&1; then
    echo "RESULT:go_test:OK"
else
    echo "RESULT:go_test:FAIL"
fi
"#;
        let fake_dir = create_fake_copilot(&project, script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &["--scratch-dir"]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "gotmpdir_redirected");
        assert_result_ok(&stdout, "go_test");
    }

    /// Without --scratch-dir, go test is blocked because the compiled test
    /// binary lands in a temp dir where process-exec is denied.
    #[test]
    fn project_go_test_blocked_without_scratch() {
        require_sandbox!();
        if !go_available() {
            eprintln!("SKIPPED: go not available");
            return;
        }

        let project = TempProject::scaffold_go();
        project.write_file(
            "main_test.go",
            "package main\n\nimport \"testing\"\n\nfunc TestHello(t *testing.T) {\n\tt.Log(\"hello from sandbox\")\n}\n",
        );

        // Capture stderr so we can assert the deny signature.
        // Explicitly unset GOTMPDIR and set TMPDIR to a denied path
        // so the test isn't flaky on machines with custom TMPDIR.
        // Use `if` wrapper to prevent set -e from killing the script
        // when go test returns non-zero.
        let script = r#"
export GOTOOLCHAIN=local
unset GOTMPDIR 2>/dev/null || true
export TMPDIR=/private/tmp

if GO_OUTPUT=$(go test -count=1 . 2>&1); then
    echo "RESULT:go_test_no_scratch:OK"
else
    echo "RESULT:go_test_no_scratch:FAIL"
fi

# Verify the failure is actually a permission deny, not some other error
case "$GO_OUTPUT" in
    *"not permitted"*|*"permission denied"*|*"signal: killed"*)
        echo "RESULT:deny_signature:OK"
        ;;
    *)
        echo "RESULT:deny_signature:FAIL:output=$GO_OUTPUT"
        ;;
esac
"#;
        let fake_dir = create_fake_copilot(&project, script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        // go test should be blocked: sandbox denies exec from temp dirs
        assert_result_fail(&stdout, "go_test_no_scratch");
        assert_result_ok(&stdout, "deny_signature");
    }

    // ============================================================
    // Gradle/Kotlin/Ktor tests
    // ============================================================

    /// Gradle build is blocked in the sandbox due to socket permission
    /// restrictions. Gradle's daemon (and even --no-daemon mode) requires
    /// Unix domain sockets that `(deny default)` blocks.
    #[test]
    fn project_gradle_build_blocked_by_socket_deny() {
        require_sandbox!();
        if !gradle_available() {
            eprintln!("SKIPPED: gradle not available");
            return;
        }

        let project = TempProject::scaffold_kotlin_ktor();

        let script = r#"
# Run gradle with --no-daemon to avoid background daemon complexity.
# Even --no-daemon still needs sockets for internal JVM communication.
if GRADLE_OUTPUT=$(gradle build --no-daemon 2>&1); then
    echo "RESULT:gradle_build:OK"
else
    echo "RESULT:gradle_build:FAIL"
fi

# Verify the failure is a socket/permission deny, not some other error
case "$GRADLE_OUTPUT" in
    *"socket"*|*"not permitted"*|*"permission denied"*|*"Operation not permitted"*|*"sandbox"*)
        echo "RESULT:deny_signature:OK"
        ;;
    *)
        echo "RESULT:deny_signature:FAIL:output=$GRADLE_OUTPUT"
        ;;
esac
"#;
        let fake_dir = create_fake_copilot(&project, script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        // Gradle build should be blocked: sandbox denies socket operations
        assert_result_fail(&stdout, "gradle_build");
        assert_result_ok(&stdout, "deny_signature");
    }

    /// Kotlin/Ktor project file operations work normally in the sandbox.
    /// Reading and writing project files is unaffected by the socket deny.
    #[test]
    fn project_kotlin_ktor_file_ops() {
        require_sandbox!();
        let project = TempProject::scaffold_kotlin_ktor();
        let script = script_file_ops(
            &[
                "build.gradle.kts",
                "settings.gradle.kts",
                "src/main/kotlin/com/example/Application.kt",
                "README.md",
            ],
            "src/test/kotlin/com/example/ApplicationTest.kt",
        );
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "read_build.gradle.kts");
        assert_result_ok(&stdout, "read_settings.gradle.kts");
        assert_result_ok(&stdout, "read_src/main/kotlin/com/example/Application.kt");
        assert_result_ok(&stdout, "read_README.md");
        assert_result_ok(
            &stdout,
            "write_src/test/kotlin/com/example/ApplicationTest.kt",
        );
        assert_result_ok(&stdout, "create_dir");
    }

    // ============================================================
    // Maven / Kotlin developer workflow tests
    // ============================================================

    impl TempProject {
        fn scaffold_maven() -> Self {
            let p = Self::new("maven");
            p.write_file(
                "pom.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-app</artifactId>
    <version>1.0-SNAPSHOT</version>
    <properties>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
    </properties>
    <dependencies>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
"#,
            );
            p.write_file(
                "src/main/java/com/example/App.java",
                r#"package com.example;

public class App {
    public static void main(String[] args) {
        System.out.println("Hello, Maven!");
    }

    public int add(int a, int b) {
        return a + b;
    }
}
"#,
            );
            p.write_file(
                "src/test/java/com/example/AppTest.java",
                r#"package com.example;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class AppTest {
    @Test
    public void testAdd() {
        assertEquals(3, new App().add(1, 2));
    }
}
"#,
            );
            p.write_file(
                "src/main/resources/application.properties",
                "app.name=test\napp.version=1.0\n",
            );
            p.write_file(".mvn/maven.config", "--no-transfer-progress\n-T1C\n");
            p.write_file(
                ".mvn/wrapper/maven-wrapper.properties",
                "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip\n",
            );
            p.write_file("README.md", "# Test Maven App\n");
            p.write_file(".gitignore", ".env*\ntarget/\n");
            p.git_init();
            p.write_file(
                ".env",
                "DB_URL=jdbc:postgresql://localhost/prod\nDB_PASS=secret\n",
            );
            p
        }

        fn scaffold_kotlin_maven() -> Self {
            let p = Self::new("kotlin-maven");
            p.write_file(
                "pom.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>kotlin-app</artifactId>
    <version>1.0-SNAPSHOT</version>
    <properties>
        <kotlin.version>2.1.20</kotlin.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.jetbrains.kotlin</groupId>
            <artifactId>kotlin-stdlib</artifactId>
            <version>${kotlin.version}</version>
        </dependency>
    </dependencies>
    <build>
        <plugins>
            <plugin>
                <groupId>org.jetbrains.kotlin</groupId>
                <artifactId>kotlin-maven-plugin</artifactId>
                <version>${kotlin.version}</version>
                <executions>
                    <execution>
                        <id>compile</id>
                        <goals><goal>compile</goal></goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
"#,
            );
            p.write_file(
                "src/main/kotlin/com/example/App.kt",
                r#"package com.example

fun main() {
    println("Hello, Kotlin!")
}

data class Config(val name: String, val port: Int = 8080)
"#,
            );
            p.write_file(
                "src/test/kotlin/com/example/AppTest.kt",
                r#"package com.example

import kotlin.test.Test
import kotlin.test.assertEquals

class AppTest {
    @Test
    fun testConfig() {
        val config = Config("test")
        assertEquals(8080, config.port)
    }
}
"#,
            );
            p.write_file("README.md", "# Test Kotlin Maven App\n");
            p.write_file(".gitignore", ".env*\ntarget/\n");
            p.git_init();
            p.write_file(".env", "API_KEY=secret-key\n");
            p
        }

        fn scaffold_maven_multi_module() -> Self {
            let p = Self::new("maven-multi");
            p.write_file(
                "pom.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0-SNAPSHOT</version>
    <packaging>pom</packaging>
    <modules>
        <module>api</module>
        <module>core</module>
    </modules>
</project>
"#,
            );
            p.write_file(".mvn/maven.config", "--no-transfer-progress\n");
            p.write_file(
                "api/pom.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>1.0-SNAPSHOT</version>
    </parent>
    <artifactId>api</artifactId>
    <dependencies>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>core</artifactId>
            <version>${project.version}</version>
        </dependency>
    </dependencies>
</project>
"#,
            );
            p.write_file(
                "api/src/main/kotlin/com/example/api/Routes.kt",
                r#"package com.example.api

import com.example.core.UserService

fun configureRoutes() {
    val service = UserService()
    println("Routes configured with ${service.greeting()}")
}
"#,
            );
            p.write_file(
                "core/pom.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>1.0-SNAPSHOT</version>
    </parent>
    <artifactId>core</artifactId>
</project>
"#,
            );
            p.write_file(
                "core/src/main/kotlin/com/example/core/UserService.kt",
                r#"package com.example.core

class UserService {
    fun greeting(): String = "Hello from core"
}
"#,
            );
            p.write_file("README.md", "# Multi-module Maven project\n");
            p.write_file(".gitignore", ".env*\ntarget/\n");
            p.git_init();
            p.write_file(".env", "DB_PASSWORD=secret\n");
            p
        }
    }

    /// Maven project: read sources, config, .mvn hidden dir, write new files.
    #[test]
    fn project_maven_file_ops() {
        require_sandbox!();
        let project = TempProject::scaffold_maven();
        let script = script_file_ops(
            &[
                "pom.xml",
                "src/main/java/com/example/App.java",
                "src/test/java/com/example/AppTest.java",
                "src/main/resources/application.properties",
                "README.md",
            ],
            "src/main/java/com/example/NewService.java",
        );
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "read_pom.xml");
        assert_result_ok(&stdout, "read_src/main/java/com/example/App.java");
        assert_result_ok(&stdout, "read_src/test/java/com/example/AppTest.java");
        assert_result_ok(&stdout, "read_src/main/resources/application.properties");
        assert_result_ok(&stdout, "read_README.md");
        assert_result_ok(&stdout, "write_src/main/java/com/example/NewService.java");
        assert_result_ok(&stdout, "create_dir");
    }

    /// Maven hidden config dir (.mvn/) is readable — Maven wrapper properties,
    /// maven.config flags, and extensions.xml all live here.
    #[test]
    fn project_maven_dotdir_accessible() {
        require_sandbox!();
        let project = TempProject::scaffold_maven();
        let script = r#"
# .mvn/maven.config should be readable (build flags like -T1C)
if cat .mvn/maven.config >/dev/null 2>&1; then
    echo "RESULT:mvn_config:OK"
else
    echo "RESULT:mvn_config:FAIL"
fi

# .mvn/wrapper/maven-wrapper.properties should be readable
if cat .mvn/wrapper/maven-wrapper.properties >/dev/null 2>&1; then
    echo "RESULT:mvn_wrapper_props:OK"
else
    echo "RESULT:mvn_wrapper_props:FAIL"
fi

# Should be able to write new files in .mvn/ (e.g., agent creates extensions.xml)
if echo '<extensions/>' > .mvn/extensions.xml 2>/dev/null; then
    echo "RESULT:mvn_write_extensions:OK"
else
    echo "RESULT:mvn_write_extensions:FAIL"
fi
"#;
        let fake_dir = create_fake_copilot(&project, script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "mvn_config");
        assert_result_ok(&stdout, "mvn_wrapper_props");
        assert_result_ok(&stdout, "mvn_write_extensions");
    }

    /// Kotlin Maven project: read/write across Kotlin source directories.
    #[test]
    fn project_kotlin_maven_file_ops() {
        require_sandbox!();
        let project = TempProject::scaffold_kotlin_maven();
        let script = script_file_ops(
            &[
                "pom.xml",
                "src/main/kotlin/com/example/App.kt",
                "src/test/kotlin/com/example/AppTest.kt",
            ],
            "src/main/kotlin/com/example/Repository.kt",
        );
        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "read_pom.xml");
        assert_result_ok(&stdout, "read_src/main/kotlin/com/example/App.kt");
        assert_result_ok(&stdout, "read_src/test/kotlin/com/example/AppTest.kt");
        assert_result_ok(&stdout, "write_src/main/kotlin/com/example/Repository.kt");
        assert_result_ok(&stdout, "create_dir");
    }

    /// Multi-module Maven project: agent can read/write across module boundaries.
    #[test]
    fn project_maven_multi_module_file_ops() {
        require_sandbox!();
        let project = TempProject::scaffold_maven_multi_module();
        let script = r#"
# Read parent pom and .mvn config
if cat pom.xml >/dev/null 2>&1; then echo "RESULT:read_parent_pom:OK"; else echo "RESULT:read_parent_pom:FAIL"; fi
if cat .mvn/maven.config >/dev/null 2>&1; then echo "RESULT:read_mvn_config:OK"; else echo "RESULT:read_mvn_config:FAIL"; fi

# Read module poms
if cat api/pom.xml >/dev/null 2>&1; then echo "RESULT:read_api_pom:OK"; else echo "RESULT:read_api_pom:FAIL"; fi
if cat core/pom.xml >/dev/null 2>&1; then echo "RESULT:read_core_pom:OK"; else echo "RESULT:read_core_pom:FAIL"; fi

# Read sources in different modules
if cat api/src/main/kotlin/com/example/api/Routes.kt >/dev/null 2>&1; then echo "RESULT:read_api_src:OK"; else echo "RESULT:read_api_src:FAIL"; fi
if cat core/src/main/kotlin/com/example/core/UserService.kt >/dev/null 2>&1; then echo "RESULT:read_core_src:OK"; else echo "RESULT:read_core_src:FAIL"; fi

# Write new files across modules (agent modifying multiple modules)
if mkdir -p api/src/test/kotlin/com/example/api 2>/dev/null && \
   echo 'package com.example.api' > api/src/test/kotlin/com/example/api/RoutesTest.kt 2>/dev/null; then
    echo "RESULT:write_api_test:OK"
else
    echo "RESULT:write_api_test:FAIL"
fi

if mkdir -p core/src/test/kotlin/com/example/core 2>/dev/null && \
   echo 'package com.example.core' > core/src/test/kotlin/com/example/core/UserServiceTest.kt 2>/dev/null; then
    echo "RESULT:write_core_test:OK"
else
    echo "RESULT:write_core_test:FAIL"
fi
"#;
        let fake_dir = create_fake_copilot(&project, script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "read_parent_pom");
        assert_result_ok(&stdout, "read_mvn_config");
        assert_result_ok(&stdout, "read_api_pom");
        assert_result_ok(&stdout, "read_core_pom");
        assert_result_ok(&stdout, "read_api_src");
        assert_result_ok(&stdout, "read_core_src");
        assert_result_ok(&stdout, "write_api_test");
        assert_result_ok(&stdout, "write_core_test");
    }

    /// Java/Maven env vars pass through the sandbox: MAVEN_OPTS,
    /// JAVA_TOOL_OPTIONS, JAVA_HOME are on the allowlist. CLASSPATH is not.
    #[test]
    fn project_maven_env_vars_passthrough() {
        require_sandbox!();
        let project = TempProject::scaffold_maven();
        let script = r#"
# Allowed JVM/Maven env vars should pass through
if [ -n "${JAVA_HOME:-}" ]; then echo "RESULT:env_java_home:OK"; else echo "RESULT:env_java_home:FAIL"; fi
if [ -n "${MAVEN_OPTS:-}" ]; then echo "RESULT:env_maven_opts:OK"; else echo "RESULT:env_maven_opts:FAIL"; fi
if [ -n "${JAVA_TOOL_OPTIONS:-}" ]; then echo "RESULT:env_java_tool_options:OK"; else echo "RESULT:env_java_tool_options:FAIL"; fi
if [ -n "${MAVEN_HOME:-}" ]; then echo "RESULT:env_maven_home:OK"; else echo "RESULT:env_maven_home:FAIL"; fi
if [ -n "${M2_HOME:-}" ]; then echo "RESULT:env_m2_home:OK"; else echo "RESULT:env_m2_home:FAIL"; fi
if [ -n "${GRADLE_HOME:-}" ]; then echo "RESULT:env_gradle_home:OK"; else echo "RESULT:env_gradle_home:FAIL"; fi

# CLASSPATH should be stripped (not on allowlist — potential injection vector)
if [ -n "${CLASSPATH:-}" ]; then echo "RESULT:env_classpath:OK"; else echo "RESULT:env_classpath:FAIL"; fi
"#;
        let fake_dir = create_fake_copilot(&project, script);

        let current_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{current_path}", fake_dir.display());

        let output = Command::new(binary_path())
            .args(["--yes", "--no-validate"])
            .args(["--project-dir", &project.canonical_path().to_string_lossy()])
            .args(["--", "--version"])
            .env("PATH", &new_path)
            .env("JAVA_HOME", "/opt/java/21")
            .env("MAVEN_OPTS", "-Xmx512m -Djava.io.tmpdir=/tmp")
            .env("JAVA_TOOL_OPTIONS", "-Dfile.encoding=UTF-8")
            .env("MAVEN_HOME", "/opt/maven")
            .env("M2_HOME", "/opt/maven")
            .env("GRADLE_HOME", "/opt/gradle")
            .env("CLASSPATH", "/evil/path/injected.jar:/another/bad.jar")
            .output()
            .expect("cplt should run");

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        assert!(
            output.status.success(),
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );

        // Allowed env vars pass through
        assert_result_ok(&stdout, "env_java_home");
        assert_result_ok(&stdout, "env_maven_opts");
        assert_result_ok(&stdout, "env_java_tool_options");
        assert_result_ok(&stdout, "env_maven_home");
        assert_result_ok(&stdout, "env_m2_home");
        assert_result_ok(&stdout, "env_gradle_home");

        // CLASSPATH should be stripped
        assert_result_fail(&stdout, "env_classpath");
    }

    /// With --scratch-dir, JANSI_TMPDIR is redirected to the scratch directory
    /// so Maven's jansi terminal library extracts native libs there.
    #[test]
    fn project_maven_jansi_tmpdir_with_scratch() {
        require_sandbox!();
        let project = TempProject::scaffold_maven();
        let script = r#"
# JANSI_TMPDIR should be set and point to the scratch dir (same as TMPDIR)
JANSI="${JANSI_TMPDIR:-unset}"
TMPVAL="${TMPDIR:-unset}"

# Should not be unset or pointing to system temp
case "$JANSI" in
    unset|/tmp|/private/tmp|/var/folders/*|/private/var/folders/*)
        echo "RESULT:jansi_redirected:FAIL:JANSI_TMPDIR=$JANSI"
        ;;
    *)
        echo "RESULT:jansi_redirected:OK"
        ;;
esac

# JANSI_TMPDIR should match TMPDIR (both redirected to same scratch dir)
if [ "$JANSI" = "$TMPVAL" ]; then
    echo "RESULT:jansi_matches_tmpdir:OK"
else
    echo "RESULT:jansi_matches_tmpdir:FAIL:JANSI=$JANSI,TMPDIR=$TMPVAL"
fi

# Should be able to write to the JANSI_TMPDIR (native lib extraction)
if echo "native-lib-data" > "$JANSI/libjansi.so" 2>/dev/null; then
    echo "RESULT:jansi_writable:OK"
else
    echo "RESULT:jansi_writable:FAIL"
fi
"#;
        let fake_dir = create_fake_copilot(&project, script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &["--scratch-dir"]);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "jansi_redirected");
        assert_result_ok(&stdout, "jansi_matches_tmpdir");
        assert_result_ok(&stdout, "jansi_writable");
    }

    /// JVM cache dirs (~/.m2, ~/.gradle) allow writes and map-exec (for loading
    /// JARs) but deny process-exec (prevent executing arbitrary binaries from
    /// dependency caches — defense against supply-chain attacks).
    #[test]
    fn project_jvm_cache_dirs_permissions() {
        require_sandbox!();
        let project = TempProject::scaffold_maven();

        // Create fake .m2 and .gradle dirs under the real HOME so the
        // sandbox profile's home-tool-dir rules apply.
        let home = std::env::var("HOME").expect("HOME must be set");
        let m2_dir = PathBuf::from(&home).join(".m2/repository/com/example");
        let gradle_dir = PathBuf::from(&home).join(".gradle/caches/test-cplt-e2e");

        // Create dirs (may already exist — that's fine)
        fs::create_dir_all(&m2_dir).ok();
        fs::create_dir_all(&gradle_dir).ok();

        let script = format!(
            r#"
# ~/.m2 should be writable (dependency caching)
if echo "fake-jar-data" > "{m2}/test-artifact.jar" 2>/dev/null; then
    echo "RESULT:m2_write:OK"
else
    echo "RESULT:m2_write:FAIL"
fi

# ~/.gradle should be writable (Gradle cache)
if echo "fake-cache-data" > "{gradle}/test-cache.bin" 2>/dev/null; then
    echo "RESULT:gradle_write:OK"
else
    echo "RESULT:gradle_write:FAIL"
fi

# ~/.m2 should NOT allow process-exec (security: no running binaries from cache)
if cp /usr/bin/true "{m2}/evil-binary" 2>/dev/null && chmod +x "{m2}/evil-binary" 2>/dev/null; then
    if "{m2}/evil-binary" 2>/dev/null; then
        echo "RESULT:m2_exec_denied:FAIL"
    else
        echo "RESULT:m2_exec_denied:OK"
    fi
else
    # Can't even copy — still counts as denied
    echo "RESULT:m2_exec_denied:OK"
fi

# ~/.gradle should NOT allow process-exec
if cp /usr/bin/true "{gradle}/evil-binary" 2>/dev/null && chmod +x "{gradle}/evil-binary" 2>/dev/null; then
    if "{gradle}/evil-binary" 2>/dev/null; then
        echo "RESULT:gradle_exec_denied:FAIL"
    else
        echo "RESULT:gradle_exec_denied:OK"
    fi
else
    echo "RESULT:gradle_exec_denied:OK"
fi
"#,
            m2 = m2_dir.display(),
            gradle = gradle_dir.display(),
        );

        let fake_dir = create_fake_copilot(&project, &script);
        let (stdout, stderr, success) = run_cplt(&project, &fake_dir, &[]);

        // Clean up test artifacts
        let _ = fs::remove_file(m2_dir.join("test-artifact.jar"));
        let _ = fs::remove_file(m2_dir.join("evil-binary"));
        let _ = fs::remove_file(gradle_dir.join("test-cache.bin"));
        let _ = fs::remove_file(gradle_dir.join("evil-binary"));
        let _ = fs::remove_dir(&gradle_dir);

        assert!(
            success,
            "cplt should succeed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_result_ok(&stdout, "m2_write");
        assert_result_ok(&stdout, "gradle_write");
        assert_result_ok(&stdout, "m2_exec_denied");
        assert_result_ok(&stdout, "gradle_exec_denied");
    }
}
