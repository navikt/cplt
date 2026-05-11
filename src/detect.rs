//! Project ecosystem detection for `cplt init`.
//!
//! Scans a project directory for build files, config files, and dependency
//! manifests to determine which sandbox permissions the project needs.
//!
//! Architecture:
//! - Each ecosystem has a standalone detector function
//! - Detectors are registered in `DETECTORS` — adding a new one is one function + one entry
//! - Detection is pure: no I/O formatting, no side effects beyond reading files
//! - A `DetectContext` provides safe file access with size limits and caching

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

// ── Permission types ─────────────────────────────────────────────────

/// Boolean sandbox flags that can be proposed by detection.
/// Typed to prevent stringly-typed config key errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[non_exhaustive]
pub enum SandboxFlag {
    AllowJvmAttach,
    AllowDocker,
    AllowLifecycleScripts,
    AllowBrowser,
    AllowEnvFiles,
    AllowLocalhostAny,
    AllowGpgSigning,
    AllowTmpExec,
}

impl SandboxFlag {
    /// The config key name as it appears in .cplt.toml `[propose]` section.
    pub fn key_name(self) -> &'static str {
        match self {
            Self::AllowJvmAttach => "allow_jvm_attach",
            Self::AllowDocker => "allow_docker",
            Self::AllowLifecycleScripts => "allow_lifecycle_scripts",
            Self::AllowBrowser => "allow_browser",
            Self::AllowEnvFiles => "allow_env_files",
            Self::AllowLocalhostAny => "allow_localhost_any",
            Self::AllowGpgSigning => "allow_gpg_signing",
            Self::AllowTmpExec => "allow_tmp_exec",
        }
    }
}

/// A single config suggestion from detection.
/// Encompasses both "propose" (relaxing) and "deny" (tightening) suggestions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Suggestion {
    /// Boolean sandbox flag to propose enabling.
    Propose(SandboxFlag),
    /// Path to allow reading.
    AllowRead(String),
    /// Path to allow writing.
    AllowWrite(String),
    /// TCP port to allow outbound.
    AllowPort(u16),
    /// Localhost port to allow.
    AllowLocalhost(u16),
    /// Cache exec subdirectory to allow.
    AllowCacheExec(String),
    /// Environment variable to deny (tightening).
    DenyEnv(String),
    /// Path to deny (tightening).
    DenyPath(String),
    /// Private domain for proxy.
    AllowPrivateDomain(String),
}

// ── Detection result types ───────────────────────────────────────────

/// Why a detector fired — structured for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// A file exists at this relative path.
    FileExists { path: String },
    /// A file contains relevant content.
    FileContains { path: String, reason: &'static str },
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signal::FileExists { path } => write!(f, "{path}"),
            Signal::FileContains { path, reason } => write!(f, "{path} ({reason})"),
        }
    }
}

/// Result from a single ecosystem detector.
#[derive(Debug, Clone)]
pub struct Detection {
    /// Human-readable ecosystem name (e.g., "JVM (Gradle)").
    pub name: &'static str,
    /// Files/content that triggered this detection.
    pub signals: Vec<Signal>,
    /// Proposed config suggestions.
    pub suggestions: Vec<Suggestion>,
}

/// A diagnostic from a detector (e.g., unreadable file).
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub detector: &'static str,
    pub message: String,
}

/// Output from a single detector invocation.
pub struct DetectorOutput {
    pub detection: Option<Detection>,
    pub diagnostics: Vec<Diagnostic>,
}

impl DetectorOutput {
    fn none() -> Self {
        Self {
            detection: None,
            diagnostics: Vec::new(),
        }
    }

    fn detected(detection: Detection) -> Self {
        Self {
            detection: Some(detection),
            diagnostics: Vec::new(),
        }
    }
}

/// Aggregated detection results with deduplication.
#[derive(Debug)]
pub struct DetectionReport {
    /// Individual ecosystem detections (for display/explainability).
    pub detections: Vec<Detection>,
    /// Merged, deduplicated suggestions (for TOML generation).
    pub suggestions: BTreeSet<Suggestion>,
    /// Non-fatal diagnostics from detection.
    pub diagnostics: Vec<Diagnostic>,
}

// ── Detection context ────────────────────────────────────────────────

/// Safe file access for detectors. Centralizes I/O policy:
/// - Only reads files relative to project root
/// - Rejects path traversal (`..`)
/// - Enforces max file size
/// - Tolerates I/O errors gracefully
pub struct DetectContext {
    root: PathBuf,
}

/// Max file size to read for content scanning (256 KB).
const MAX_READ_SIZE: u64 = 256 * 1024;

impl DetectContext {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    /// Check if a relative path exists as a file.
    pub fn exists(&self, relative: &str) -> bool {
        if Self::is_traversal(relative) {
            return false;
        }
        self.root.join(relative).is_file()
    }

    /// Check if a relative path exists as a directory.
    pub fn dir_exists(&self, relative: &str) -> bool {
        if Self::is_traversal(relative) {
            return false;
        }
        self.root.join(relative).is_dir()
    }

    /// Read file contents (limited size, best-effort).
    /// Returns None if file doesn't exist, is too large, or can't be read.
    pub fn read_text(&self, relative: &str) -> Option<String> {
        if Self::is_traversal(relative) {
            return None;
        }
        let path = self.root.join(relative);
        let meta = std::fs::metadata(&path).ok()?;
        if meta.len() > MAX_READ_SIZE {
            return None;
        }
        std::fs::read_to_string(&path).ok()
    }

    /// Project root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn is_traversal(relative: &str) -> bool {
        relative.contains("..")
    }
}

// ── Detector registry ────────────────────────────────────────────────

/// Metadata for a registered detector.
pub struct DetectorSpec {
    /// Unique identifier (for diagnostics and filtering).
    pub id: &'static str,
    /// The detection function.
    pub detect: fn(&DetectContext) -> DetectorOutput,
}

/// All registered detectors. Adding a new ecosystem = one function + one entry here.
pub const DETECTORS: &[DetectorSpec] = &[
    DetectorSpec {
        id: "jvm",
        detect: detect_jvm,
    },
    DetectorSpec {
        id: "node",
        detect: detect_node,
    },
    DetectorSpec {
        id: "docker",
        detect: detect_docker,
    },
    DetectorSpec {
        id: "python",
        detect: detect_python,
    },
    DetectorSpec {
        id: "rust",
        detect: detect_rust,
    },
    DetectorSpec {
        id: "go",
        detect: detect_go,
    },
    DetectorSpec {
        id: "playwright",
        detect: detect_playwright,
    },
    DetectorSpec {
        id: "env_files",
        detect: detect_env_files,
    },
];

/// Run all detectors against a project directory.
pub fn detect_project(dir: &Path) -> DetectionReport {
    let ctx = DetectContext::new(dir);
    let mut detections = Vec::new();
    let mut diagnostics = Vec::new();

    for spec in DETECTORS {
        let output = (spec.detect)(&ctx);
        if let Some(detection) = output.detection {
            detections.push(detection);
        }
        diagnostics.extend(output.diagnostics);
    }

    let suggestions = detections
        .iter()
        .flat_map(|d| d.suggestions.iter().cloned())
        .collect::<BTreeSet<_>>();

    DetectionReport {
        detections,
        suggestions,
        diagnostics,
    }
}

// ── Ecosystem detectors ──────────────────────────────────────────────

fn detect_jvm(ctx: &DetectContext) -> DetectorOutput {
    let gradle_files = [
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
    ];
    let maven_files = ["pom.xml"];

    let mut signals = Vec::new();
    let mut is_gradle = false;
    let mut is_maven = false;

    for file in &gradle_files {
        if ctx.exists(file) {
            signals.push(Signal::FileExists {
                path: (*file).to_string(),
            });
            is_gradle = true;
        }
    }
    for file in &maven_files {
        if ctx.exists(file) {
            signals.push(Signal::FileExists {
                path: (*file).to_string(),
            });
            is_maven = true;
        }
    }

    if !is_gradle && !is_maven {
        return DetectorOutput::none();
    }

    let mut suggestions = vec![Suggestion::Propose(SandboxFlag::AllowJvmAttach)];

    // Check for ~/.gradle/gradle.properties (common for credentials/proxy config)
    suggestions.push(Suggestion::AllowRead(
        "~/.gradle/gradle.properties".to_string(),
    ));

    // Content scan: check for mocking frameworks that need JVM attach
    if is_gradle {
        for build_file in &["build.gradle.kts", "build.gradle"] {
            if let Some(content) = ctx.read_text(build_file)
                && (content.contains("mockk") || content.contains("mockito"))
            {
                signals.push(Signal::FileContains {
                    path: (*build_file).to_string(),
                    reason: "contains mocking framework (needs JVM attach)",
                });
                break;
            }
        }
    }

    let name = if is_gradle && is_maven {
        "JVM (Gradle + Maven)"
    } else if is_gradle {
        "JVM (Gradle)"
    } else {
        "JVM (Maven)"
    };

    DetectorOutput::detected(Detection {
        name,
        signals,
        suggestions,
    })
}

fn detect_node(ctx: &DetectContext) -> DetectorOutput {
    if !ctx.exists("package.json") {
        return DetectorOutput::none();
    }

    let mut signals = vec![Signal::FileExists {
        path: "package.json".to_string(),
    }];
    let mut suggestions: Vec<Suggestion> = Vec::new();

    // Content scan: look for dev server ports in scripts
    if let Some(content) = ctx.read_text("package.json") {
        // Check for postinstall/prepare scripts (lifecycle scripts)
        if content.contains("\"postinstall\"")
            || content.contains("\"prepare\"")
            || content.contains("\"preinstall\"")
        {
            signals.push(Signal::FileContains {
                path: "package.json".to_string(),
                reason: "has lifecycle scripts (postinstall/prepare)",
            });
            suggestions.push(Suggestion::Propose(SandboxFlag::AllowLifecycleScripts));
        }

        // Detect common dev server ports from scripts
        if let Some(port) = detect_port_in_scripts(&content) {
            signals.push(Signal::FileContains {
                path: "package.json".to_string(),
                reason: "dev server detected",
            });
            suggestions.push(Suggestion::AllowLocalhost(port));
        }

        // Check for Next.js/Vite/Turbopack (localhost worker ports)
        if content.contains("\"next\"")
            || content.contains("\"vite\"")
            || content.contains("\"turbo\"")
        {
            suggestions.push(Suggestion::Propose(SandboxFlag::AllowLocalhostAny));
        }
    }

    DetectorOutput::detected(Detection {
        name: "Node.js",
        signals,
        suggestions,
    })
}

fn detect_docker(ctx: &DetectContext) -> DetectorOutput {
    let docker_files = [
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ];

    let mut signals = Vec::new();

    for file in &docker_files {
        if ctx.exists(file) {
            signals.push(Signal::FileExists {
                path: (*file).to_string(),
            });
        }
    }

    if signals.is_empty() {
        return DetectorOutput::none();
    }

    let mut suggestions = vec![Suggestion::Propose(SandboxFlag::AllowDocker)];

    // Content scan: extract port mappings from compose files
    for compose_file in &[
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ] {
        if let Some(content) = ctx.read_text(compose_file) {
            for port in extract_compose_ports(&content) {
                suggestions.push(Suggestion::AllowPort(port));
            }
        }
    }

    DetectorOutput::detected(Detection {
        name: "Docker",
        signals,
        suggestions,
    })
}

fn detect_python(ctx: &DetectContext) -> DetectorOutput {
    let python_files = [
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "setup.cfg",
        "Pipfile",
    ];

    let mut signals = Vec::new();

    for file in &python_files {
        if ctx.exists(file) {
            signals.push(Signal::FileExists {
                path: (*file).to_string(),
            });
        }
    }

    if signals.is_empty() {
        return DetectorOutput::none();
    }

    let mut suggestions: Vec<Suggestion> = Vec::new();

    // Content scan: detect web frameworks → common ports
    let files_to_scan = ["pyproject.toml", "requirements.txt", "Pipfile"];
    for file in &files_to_scan {
        if let Some(content) = ctx.read_text(file)
            && (content.contains("django")
                || content.contains("Django")
                || content.contains("flask")
                || content.contains("Flask")
                || content.contains("fastapi")
                || content.contains("FastAPI")
                || content.contains("uvicorn"))
        {
            signals.push(Signal::FileContains {
                path: (*file).to_string(),
                reason: "contains web framework",
            });
            suggestions.push(Suggestion::AllowLocalhost(8000));
            break;
        }
    }

    DetectorOutput::detected(Detection {
        name: "Python",
        signals,
        suggestions,
    })
}

fn detect_rust(ctx: &DetectContext) -> DetectorOutput {
    if !ctx.exists("Cargo.toml") {
        return DetectorOutput::none();
    }

    // Rust projects work well with cplt defaults — minimal permissions needed
    DetectorOutput::detected(Detection {
        name: "Rust",
        signals: vec![Signal::FileExists {
            path: "Cargo.toml".to_string(),
        }],
        suggestions: Vec::new(),
    })
}

fn detect_go(ctx: &DetectContext) -> DetectorOutput {
    if !ctx.exists("go.mod") {
        return DetectorOutput::none();
    }

    // Go projects work well with cplt defaults — minimal permissions needed
    DetectorOutput::detected(Detection {
        name: "Go",
        signals: vec![Signal::FileExists {
            path: "go.mod".to_string(),
        }],
        suggestions: Vec::new(),
    })
}

fn detect_playwright(ctx: &DetectContext) -> DetectorOutput {
    let Some(content) = ctx.read_text("package.json") else {
        return DetectorOutput::none();
    };

    if !content.contains("@playwright/test") && !content.contains("\"playwright\"") {
        return DetectorOutput::none();
    }

    DetectorOutput::detected(Detection {
        name: "Playwright",
        signals: vec![Signal::FileContains {
            path: "package.json".to_string(),
            reason: "contains Playwright dependency",
        }],
        suggestions: vec![Suggestion::AllowCacheExec("ms-playwright".to_string())],
    })
}

fn detect_env_files(ctx: &DetectContext) -> DetectorOutput {
    let example_files = [".env.example", ".env.sample", ".env.template"];

    let mut found_file = None;
    for file in &example_files {
        if ctx.exists(file) {
            found_file = Some(*file);
            break;
        }
    }

    let Some(file) = found_file else {
        return DetectorOutput::none();
    };

    let Some(content) = ctx.read_text(file) else {
        return DetectorOutput::none();
    };

    let mut deny_vars = Vec::new();
    let sensitive_patterns = [
        "SECRET",
        "KEY",
        "TOKEN",
        "PASSWORD",
        "CREDENTIAL",
        "PRIVATE",
    ];

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(var_name) = line.split('=').next() {
            let var_upper = var_name.trim().to_uppercase();
            if sensitive_patterns.iter().any(|pat| var_upper.contains(pat)) {
                deny_vars.push(var_name.trim().to_string());
            }
        }
    }

    if deny_vars.is_empty() {
        return DetectorOutput::none();
    }

    let suggestions = deny_vars
        .iter()
        .map(|v| Suggestion::DenyEnv(v.clone()))
        .collect();

    DetectorOutput::detected(Detection {
        name: "Environment secrets",
        signals: vec![Signal::FileContains {
            path: file.to_string(),
            reason: "contains sensitive variable names",
        }],
        suggestions,
    })
}

// ── Helper functions ─────────────────────────────────────────────────

/// Extract a port number from package.json scripts (best-effort).
/// Looks for patterns like `--port 3000`, `--port=3000`, `-p 8080`.
fn detect_port_in_scripts(package_json: &str) -> Option<u16> {
    // Simple heuristic: find --port followed by a number
    for pattern in ["--port ", "--port=", "-p "] {
        if let Some(idx) = package_json.find(pattern) {
            let after = &package_json[idx + pattern.len()..];
            let num_str: String = after.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(port) = num_str.parse::<u16>()
                && port > 0
            {
                return Some(port);
            }
        }
    }
    None
}

/// Extract port numbers from docker-compose port mappings.
/// Handles formats like `"8080:80"`, `"5432:5432"`, `- "3000:3000"`.
fn extract_compose_ports(content: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim().trim_start_matches('-').trim();
        let trimmed = trimmed.trim_matches('"').trim_matches('\'');
        // Match patterns: "HOST:CONTAINER" or "HOST:CONTAINER/protocol"
        if let Some((host_part, _)) = trimmed.split_once(':') {
            // Host part might be "IP:PORT" or just "PORT"
            let port_str = host_part.rsplit_once(':').map_or(host_part, |(_, p)| p);
            if let Ok(port) = port_str.parse::<u16>()
                && port > 0
                && !ports.contains(&port)
            {
                ports.push(port);
            }
        }
    }
    ports
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    // ── DetectContext tests ──────────────────────────────────────────

    #[test]
    fn context_rejects_traversal() {
        let dir = setup_dir();
        let ctx = DetectContext::new(dir.path());
        assert!(!ctx.exists("../etc/passwd"));
        assert!(ctx.read_text("../../secret").is_none());
        assert!(!ctx.dir_exists("../.."));
    }

    #[test]
    fn context_reads_small_file() {
        let dir = setup_dir();
        fs::write(dir.path().join("test.txt"), "hello").unwrap();
        let ctx = DetectContext::new(dir.path());
        assert!(ctx.exists("test.txt"));
        assert_eq!(ctx.read_text("test.txt"), Some("hello".to_string()));
    }

    #[test]
    fn context_skips_large_file() {
        let dir = setup_dir();
        let big = vec![b'x'; (MAX_READ_SIZE + 1) as usize];
        fs::write(dir.path().join("big.txt"), &big).unwrap();
        let ctx = DetectContext::new(dir.path());
        assert!(ctx.exists("big.txt"));
        assert!(ctx.read_text("big.txt").is_none());
    }

    #[test]
    fn context_missing_file() {
        let dir = setup_dir();
        let ctx = DetectContext::new(dir.path());
        assert!(!ctx.exists("nope.txt"));
        assert!(ctx.read_text("nope.txt").is_none());
    }

    // ── JVM detector ─────────────────────────────────────────────────

    #[test]
    fn jvm_detects_gradle() {
        let dir = setup_dir();
        fs::write(dir.path().join("build.gradle.kts"), "plugins { }").unwrap();
        let report = detect_project(dir.path());
        let jvm = report.detections.iter().find(|d| d.name.contains("Gradle"));
        assert!(jvm.is_some());
        assert!(
            report
                .suggestions
                .contains(&Suggestion::Propose(SandboxFlag::AllowJvmAttach))
        );
    }

    #[test]
    fn jvm_detects_maven() {
        let dir = setup_dir();
        fs::write(dir.path().join("pom.xml"), "<project/>").unwrap();
        let report = detect_project(dir.path());
        let jvm = report.detections.iter().find(|d| d.name.contains("Maven"));
        assert!(jvm.is_some());
    }

    #[test]
    fn jvm_detects_mockk_signal() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("build.gradle.kts"),
            r#"dependencies { testImplementation("io.mockk:mockk:1.13") }"#,
        )
        .unwrap();
        let report = detect_project(dir.path());
        let jvm = report
            .detections
            .iter()
            .find(|d| d.name.contains("JVM"))
            .unwrap();
        assert!(jvm.signals.iter().any(
            |s| matches!(s, Signal::FileContains { reason, .. } if reason.contains("mocking"))
        ));
    }

    #[test]
    fn jvm_not_detected_without_files() {
        let dir = setup_dir();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().all(|d| !d.name.contains("JVM")));
    }

    // ── Node detector ────────────────────────────────────────────────

    #[test]
    fn node_detects_package_json() {
        let dir = setup_dir();
        fs::write(dir.path().join("package.json"), r#"{"name":"test"}"#).unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Node.js"));
    }

    #[test]
    fn node_detects_port_in_scripts() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"dev":"next dev --port 4000"}}"#,
        )
        .unwrap();
        let report = detect_project(dir.path());
        assert!(
            report
                .suggestions
                .contains(&Suggestion::AllowLocalhost(4000))
        );
    }

    #[test]
    fn node_detects_lifecycle_scripts() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"postinstall":"patch-package"}}"#,
        )
        .unwrap();
        let report = detect_project(dir.path());
        assert!(
            report
                .suggestions
                .contains(&Suggestion::Propose(SandboxFlag::AllowLifecycleScripts))
        );
    }

    #[test]
    fn node_detects_vite_localhost_any() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"vite":"^5.0"}}"#,
        )
        .unwrap();
        let report = detect_project(dir.path());
        assert!(
            report
                .suggestions
                .contains(&Suggestion::Propose(SandboxFlag::AllowLocalhostAny))
        );
    }

    // ── Docker detector ──────────────────────────────────────────────

    #[test]
    fn docker_detects_dockerfile() {
        let dir = setup_dir();
        fs::write(dir.path().join("Dockerfile"), "FROM node:20").unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Docker"));
        assert!(
            report
                .suggestions
                .contains(&Suggestion::Propose(SandboxFlag::AllowDocker))
        );
    }

    #[test]
    fn docker_extracts_compose_ports() {
        let dir = setup_dir();
        let compose = r#"
services:
  db:
    ports:
      - "5432:5432"
  web:
    ports:
      - "8080:80"
"#;
        fs::write(dir.path().join("docker-compose.yml"), compose).unwrap();
        let report = detect_project(dir.path());
        assert!(report.suggestions.contains(&Suggestion::AllowPort(5432)));
        assert!(report.suggestions.contains(&Suggestion::AllowPort(8080)));
    }

    // ── Python detector ──────────────────────────────────────────────

    #[test]
    fn python_detects_requirements() {
        let dir = setup_dir();
        fs::write(dir.path().join("requirements.txt"), "requests==2.31\n").unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Python"));
    }

    #[test]
    fn python_detects_web_framework() {
        let dir = setup_dir();
        fs::write(dir.path().join("requirements.txt"), "fastapi\nuvicorn\n").unwrap();
        let report = detect_project(dir.path());
        assert!(
            report
                .suggestions
                .contains(&Suggestion::AllowLocalhost(8000))
        );
    }

    // ── Rust detector ────────────────────────────────────────────────

    #[test]
    fn rust_detects_cargo_toml() {
        let dir = setup_dir();
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Rust"));
    }

    // ── Go detector ──────────────────────────────────────────────────

    #[test]
    fn go_detects_go_mod() {
        let dir = setup_dir();
        fs::write(dir.path().join("go.mod"), "module example.com/test").unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Go"));
    }

    // ── Playwright detector ──────────────────────────────────────────

    #[test]
    fn playwright_detects_from_package_json() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("package.json"),
            r#"{"devDependencies":{"@playwright/test":"^1.40"}}"#,
        )
        .unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Playwright"));
        assert!(
            report
                .suggestions
                .contains(&Suggestion::AllowCacheExec("ms-playwright".to_string()))
        );
    }

    // ── Env files detector ───────────────────────────────────────────

    #[test]
    fn env_detects_sensitive_vars() {
        let dir = setup_dir();
        fs::write(
            dir.path().join(".env.example"),
            "DATABASE_URL=postgres://...\nAPI_SECRET_KEY=changeme\nDEBUG=true\n",
        )
        .unwrap();
        let report = detect_project(dir.path());
        assert!(
            report
                .detections
                .iter()
                .any(|d| d.name == "Environment secrets")
        );
        assert!(
            report
                .suggestions
                .contains(&Suggestion::DenyEnv("API_SECRET_KEY".to_string()))
        );
        // DEBUG should not be flagged
        assert!(
            !report
                .suggestions
                .contains(&Suggestion::DenyEnv("DEBUG".to_string()))
        );
    }

    #[test]
    fn env_ignores_non_sensitive_vars() {
        let dir = setup_dir();
        fs::write(
            dir.path().join(".env.example"),
            "PORT=3000\nDEBUG=true\nLOG_LEVEL=info\n",
        )
        .unwrap();
        let report = detect_project(dir.path());
        // No sensitive vars → no detection
        assert!(
            report
                .detections
                .iter()
                .all(|d| d.name != "Environment secrets")
        );
    }

    // ── Integration: multi-ecosystem ─────────────────────────────────

    #[test]
    fn multi_ecosystem_project() {
        let dir = setup_dir();
        fs::write(dir.path().join("build.gradle.kts"), "plugins {}").unwrap();
        fs::write(dir.path().join("Dockerfile"), "FROM openjdk:17").unwrap();
        fs::write(
            dir.path().join("docker-compose.yml"),
            "services:\n  db:\n    ports:\n      - \"5432:5432\"\n",
        )
        .unwrap();

        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name.contains("JVM")));
        assert!(report.detections.iter().any(|d| d.name == "Docker"));
        // Suggestions merged from both
        assert!(
            report
                .suggestions
                .contains(&Suggestion::Propose(SandboxFlag::AllowJvmAttach))
        );
        assert!(
            report
                .suggestions
                .contains(&Suggestion::Propose(SandboxFlag::AllowDocker))
        );
        assert!(report.suggestions.contains(&Suggestion::AllowPort(5432)));
    }

    #[test]
    fn empty_project_no_detections() {
        let dir = setup_dir();
        let report = detect_project(dir.path());
        assert!(report.detections.is_empty());
        assert!(report.suggestions.is_empty());
        assert!(report.diagnostics.is_empty());
    }

    // ── Helper function tests ────────────────────────────────────────

    #[test]
    fn port_detection_patterns() {
        assert_eq!(
            detect_port_in_scripts(r#""dev": "next dev --port 3001""#),
            Some(3001)
        );
        assert_eq!(
            detect_port_in_scripts(r#""dev": "vite --port=5173""#),
            Some(5173)
        );
        assert_eq!(
            detect_port_in_scripts(r#""dev": "webpack serve -p 8080""#),
            Some(8080)
        );
        assert_eq!(detect_port_in_scripts(r#""dev": "node server.js""#), None);
    }

    #[test]
    fn compose_port_extraction() {
        let content = r#"
services:
  web:
    ports:
      - "3000:3000"
      - "8443:443"
  db:
    ports:
      - "5432:5432"
"#;
        let ports = extract_compose_ports(content);
        assert!(ports.contains(&3000));
        assert!(ports.contains(&8443));
        assert!(ports.contains(&5432));
    }

    // ── SandboxFlag coverage ─────────────────────────────────────────

    #[test]
    fn sandbox_flag_key_names() {
        assert_eq!(SandboxFlag::AllowJvmAttach.key_name(), "allow_jvm_attach");
        assert_eq!(SandboxFlag::AllowDocker.key_name(), "allow_docker");
        assert_eq!(
            SandboxFlag::AllowLifecycleScripts.key_name(),
            "allow_lifecycle_scripts"
        );
        assert_eq!(SandboxFlag::AllowBrowser.key_name(), "allow_browser");
        assert_eq!(SandboxFlag::AllowEnvFiles.key_name(), "allow_env_files");
        assert_eq!(
            SandboxFlag::AllowLocalhostAny.key_name(),
            "allow_localhost_any"
        );
        assert_eq!(SandboxFlag::AllowGpgSigning.key_name(), "allow_gpg_signing");
        assert_eq!(SandboxFlag::AllowTmpExec.key_name(), "allow_tmp_exec");
    }
}
