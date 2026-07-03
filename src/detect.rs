//! Project ecosystem detection for `cplt init`.
//!
//! Scans a project directory for build files, config files, and dependency
//! manifests to determine which sandbox permissions the project needs.
//!
//! Architecture:
//! - Each ecosystem has a standalone detector function
//! - Detectors are registered in `DETECTORS` — adding a new one is one function + one entry
//! - Detection is pure: no I/O formatting, no side effects beyond reading files
//! - A `DetectContext` provides safe file access with size limits

use std::collections::{BTreeMap, BTreeSet};
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

    /// Risk warning for dangerous permissions. None means safe to suggest.
    pub fn risk_warning(self) -> Option<&'static str> {
        match self {
            Self::AllowLifecycleScripts => {
                Some("runs arbitrary scripts on install — only enable if builds fail without it")
            }
            Self::AllowDocker => {
                Some("grants access to Docker socket — effectively root on the host")
            }
            Self::AllowTmpExec => Some("allows code execution from /tmp"),
            _ => None,
        }
    }

    /// Iterate over all variants (for lookup by key name).
    pub fn iter_all() -> impl Iterator<Item = Self> {
        [
            Self::AllowJvmAttach,
            Self::AllowDocker,
            Self::AllowLifecycleScripts,
            Self::AllowBrowser,
            Self::AllowEnvFiles,
            Self::AllowLocalhostAny,
            Self::AllowGpgSigning,
            Self::AllowTmpExec,
        ]
        .into_iter()
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
    /// A directory exists at this relative path.
    DirExists { path: String },
    /// A file contains relevant content.
    FileContains { path: String, reason: &'static str },
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signal::FileExists { path } | Signal::DirExists { path } => write!(f, "{path}"),
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
    /// Workspace members discovered (empty for non-monorepo projects).
    pub workspace_members: Vec<WorkspaceMember>,
    /// Maps each suggestion to the relative paths that produced it.
    /// Empty when `detect_project()` is used (no provenance tracking).
    pub provenance: BTreeMap<Suggestion, BTreeSet<String>>,
}

impl DetectionReport {
    /// Create a report from detections, suggestions, and diagnostics.
    /// Initializes workspace fields to empty (for non-monorepo use).
    pub fn new(
        detections: Vec<Detection>,
        suggestions: BTreeSet<Suggestion>,
        diagnostics: Vec<Diagnostic>,
    ) -> Self {
        Self {
            detections,
            suggestions,
            diagnostics,
            workspace_members: Vec::new(),
            provenance: BTreeMap::new(),
        }
    }
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
    /// Rejects symlinks pointing outside the project root.
    pub fn exists(&self, relative: &str) -> bool {
        if Self::is_traversal(relative) {
            return false;
        }
        let path = self.root.join(relative);
        if !self.is_confined(&path) {
            return false;
        }
        path.is_file()
    }

    /// Check if a relative path exists as a directory.
    /// Rejects symlinks pointing outside the project root.
    pub fn dir_exists(&self, relative: &str) -> bool {
        if Self::is_traversal(relative) {
            return false;
        }
        let path = self.root.join(relative);
        if !self.is_confined(&path) {
            return false;
        }
        path.is_dir()
    }

    /// Read file contents (limited size, best-effort).
    /// Returns None if file doesn't exist, is too large, can't be read,
    /// or resolves (via symlink) to a location outside the project root.
    pub fn read_text(&self, relative: &str) -> Option<String> {
        if Self::is_traversal(relative) {
            return None;
        }
        let path = self.root.join(relative);
        if !self.is_confined(&path) {
            return None;
        }
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

    /// Reject path traversal and absolute paths.
    fn is_traversal(relative: &str) -> bool {
        use std::path::Component;
        let path = Path::new(relative);
        path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir))
    }

    /// Verify a path's canonical target is within the project root.
    /// Prevents symlink-based escapes.
    fn is_confined(&self, path: &Path) -> bool {
        // Canonicalize resolves all symlinks atomically.
        // Non-existent paths return false — the caller's metadata/read will
        // also fail, and this avoids a TOCTOU gap where a symlink could be
        // created between this check and the subsequent I/O.
        let Ok(canonical) = path.canonicalize() else {
            return false;
        };
        let Ok(root_canonical) = self.root.canonicalize() else {
            return false;
        };
        canonical.starts_with(&root_canonical)
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
    DetectorSpec {
        id: "spring_boot",
        detect: detect_spring_boot,
    },
    DetectorSpec {
        id: "ktor",
        detect: detect_ktor,
    },
    DetectorSpec {
        id: "testcontainers",
        detect: detect_testcontainers,
    },
    DetectorSpec {
        id: "next_config",
        detect: detect_next_config,
    },
    DetectorSpec {
        id: "vite_config",
        detect: detect_vite_config,
    },
    DetectorSpec {
        id: "flyway",
        detect: detect_flyway,
    },
    DetectorSpec {
        id: "cypress",
        detect: detect_cypress,
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

    DetectionReport::new(detections, suggestions, diagnostics)
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

    // Check for credentials/proxy config files
    if is_gradle {
        suggestions.push(Suggestion::AllowRead(
            "~/.gradle/gradle.properties".to_string(),
        ));
    }
    if is_maven {
        suggestions.push(Suggestion::AllowRead("~/.m2/settings.xml".to_string()));
    }

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
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    // Content scan: look for dev server ports in scripts
    if let Some(content) = ctx.read_text("package.json") {
        // Check for postinstall/prepare scripts — warn but don't auto-suggest
        if content.contains("\"postinstall\"")
            || content.contains("\"prepare\"")
            || content.contains("\"preinstall\"")
        {
            signals.push(Signal::FileContains {
                path: "package.json".to_string(),
                reason: "has lifecycle scripts (postinstall/prepare)",
            });
            diagnostics.push(Diagnostic {
                detector: "node",
                message: "lifecycle scripts detected — only add allow_lifecycle_scripts if npm install fails without it (runs arbitrary code)".to_string(),
            });
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

        // If local .npmrc exists or package.json specifies a registry, suggest ~/.npmrc
        if ctx.exists(".npmrc")
            || content.contains("\"registry\"")
            || content.contains("publishConfig")
        {
            suggestions.push(Suggestion::AllowRead("~/.npmrc".to_string()));
        }
    }

    DetectorOutput {
        detection: Some(Detection {
            name: "Node.js",
            signals,
            suggestions,
        }),
        diagnostics,
    }
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
    let primary_compose_files = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ];

    for compose_file in &primary_compose_files {
        if let Some(content) = ctx.read_text(compose_file) {
            for port in extract_compose_ports(&content) {
                suggestions.push(Suggestion::AllowPort(port));
            }
            // Follow extends.file references to find ports in referenced files
            for referenced in extract_extends_files(&content) {
                if let Some(ref_content) = ctx.read_text(&referenced) {
                    for port in extract_compose_ports(&ref_content) {
                        suggestions.push(Suggestion::AllowPort(port));
                    }
                }
            }
        }
    }

    // Scan alternate compose files (docker-compose.*.yml, compose.*.yml)
    for alt_file in find_alternate_compose_files(ctx) {
        if primary_compose_files.contains(&alt_file.as_str()) {
            continue;
        }
        if let Some(content) = ctx.read_text(&alt_file) {
            for port in extract_compose_ports(&content) {
                suggestions.push(Suggestion::AllowPort(port));
            }
            for referenced in extract_extends_files(&content) {
                if let Some(ref_content) = ctx.read_text(&referenced) {
                    for port in extract_compose_ports(&ref_content) {
                        suggestions.push(Suggestion::AllowPort(port));
                    }
                }
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
            let var_name = var_name.trim();
            // Only emit vars matching valid identifier pattern [A-Za-z0-9_]
            if !var_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                continue;
            }
            let var_upper = var_name.to_uppercase();
            if sensitive_patterns.iter().any(|pat| var_upper.contains(pat)) {
                deny_vars.push(var_name.to_string());
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

// ── NAIS / Nav-specific detectors ────────────────────────────────────

fn detect_spring_boot(ctx: &DetectContext) -> DetectorOutput {
    // Detect Spring Boot specifically (beyond generic JVM)
    let app_file = if ctx.exists("src/main/resources/application.yml") {
        "src/main/resources/application.yml"
    } else if ctx.exists("src/main/resources/application.yaml") {
        "src/main/resources/application.yaml"
    } else {
        return DetectorOutput::none();
    };

    // Verify it's actually Spring Boot
    let (gradle_file, gradle_content) = if let Some(c) = ctx.read_text("build.gradle.kts") {
        ("build.gradle.kts", c)
    } else if let Some(c) = ctx.read_text("build.gradle") {
        ("build.gradle", c)
    } else {
        return DetectorOutput::none();
    };

    let is_spring =
        gradle_content.contains("spring-boot") || gradle_content.contains("org.springframework");

    if !is_spring {
        return DetectorOutput::none();
    }

    let mut signals = vec![Signal::FileContains {
        path: gradle_file.to_string(),
        reason: "Spring Boot project",
    }];
    let mut suggestions = vec![
        Suggestion::Propose(SandboxFlag::AllowJvmAttach),
        Suggestion::AllowLocalhost(8080),
    ];

    // Check application.yml for specific features
    let app_content = ctx.read_text(app_file);

    if let Some(content) = &app_content {
        if content.contains("flyway") {
            signals.push(Signal::FileContains {
                path: app_file.to_string(),
                reason: "Flyway migrations enabled",
            });
        }
        if content.contains("kafka") {
            signals.push(Signal::FileContains {
                path: app_file.to_string(),
                reason: "Kafka configured",
            });
        }
        if content.contains("datasource") || content.contains("postgresql") {
            signals.push(Signal::FileContains {
                path: app_file.to_string(),
                reason: "PostgreSQL datasource",
            });
            suggestions.push(Suggestion::AllowPort(5432));
        }
    }

    DetectorOutput::detected(Detection {
        name: "Spring Boot",
        signals,
        suggestions,
    })
}

fn detect_ktor(ctx: &DetectContext) -> DetectorOutput {
    // Ktor uses application.conf (HOCON) instead of Spring's application.yml
    let has_app_conf = ctx.exists("src/main/resources/application.conf");

    let (gradle_file, gradle_content) = if let Some(c) = ctx.read_text("build.gradle.kts") {
        ("build.gradle.kts", c)
    } else if let Some(c) = ctx.read_text("build.gradle") {
        ("build.gradle", c)
    } else {
        return DetectorOutput::none();
    };

    let is_ktor = gradle_content.contains("ktor") || gradle_content.contains("io.ktor");

    if !is_ktor {
        return DetectorOutput::none();
    }

    let mut signals = vec![Signal::FileContains {
        path: gradle_file.to_string(),
        reason: "Ktor project",
    }];

    if has_app_conf {
        signals.push(Signal::FileExists {
            path: "src/main/resources/application.conf".to_string(),
        });
    }

    let mut suggestions = vec![
        Suggestion::Propose(SandboxFlag::AllowJvmAttach),
        Suggestion::AllowLocalhost(8080),
    ];

    // Scan gradle for test dependencies
    if gradle_content.contains("testcontainers") {
        signals.push(Signal::FileContains {
            path: gradle_file.to_string(),
            reason: "TestContainers in test dependencies",
        });
        suggestions.push(Suggestion::Propose(SandboxFlag::AllowDocker));
    }

    DetectorOutput::detected(Detection {
        name: "Ktor",
        signals,
        suggestions,
    })
}

fn detect_testcontainers(ctx: &DetectContext) -> DetectorOutput {
    let (gradle_file, content) = if let Some(c) = ctx.read_text("build.gradle.kts") {
        ("build.gradle.kts", c)
    } else if let Some(c) = ctx.read_text("build.gradle") {
        ("build.gradle", c)
    } else {
        return DetectorOutput::none();
    };

    if !content.contains("testcontainers") {
        return DetectorOutput::none();
    }

    let mut signals = vec![Signal::FileContains {
        path: gradle_file.to_string(),
        reason: "TestContainers dependency",
    }];

    // Detect which containers are used
    if content.contains("testcontainers:postgresql")
        || content.contains("testcontainers.postgresql")
    {
        signals.push(Signal::FileContains {
            path: gradle_file.to_string(),
            reason: "PostgreSQL TestContainer",
        });
    }
    if content.contains("testcontainers:kafka") || content.contains("testcontainers.kafka") {
        signals.push(Signal::FileContains {
            path: gradle_file.to_string(),
            reason: "Kafka TestContainer",
        });
    }

    DetectorOutput::detected(Detection {
        name: "TestContainers",
        signals,
        suggestions: vec![
            Suggestion::Propose(SandboxFlag::AllowDocker),
            Suggestion::Propose(SandboxFlag::AllowLocalhostAny),
        ],
    })
}

fn detect_next_config(ctx: &DetectContext) -> DetectorOutput {
    let config_files = ["next.config.ts", "next.config.js", "next.config.mjs"];

    let mut found = None;
    for file in &config_files {
        if ctx.exists(file) {
            found = Some(*file);
            break;
        }
    }

    let Some(config_file) = found else {
        return DetectorOutput::none();
    };

    DetectorOutput::detected(Detection {
        name: "Next.js",
        signals: vec![Signal::FileExists {
            path: config_file.to_string(),
        }],
        suggestions: vec![
            Suggestion::Propose(SandboxFlag::AllowLocalhostAny),
            Suggestion::AllowLocalhost(3000),
        ],
    })
}

fn detect_vite_config(ctx: &DetectContext) -> DetectorOutput {
    let config_files = ["vite.config.ts", "vite.config.js", "vite.config.mjs"];

    let mut found = None;
    for file in &config_files {
        if ctx.exists(file) {
            found = Some(*file);
            break;
        }
    }

    let Some(config_file) = found else {
        return DetectorOutput::none();
    };

    DetectorOutput::detected(Detection {
        name: "Vite",
        signals: vec![Signal::FileExists {
            path: config_file.to_string(),
        }],
        suggestions: vec![
            Suggestion::Propose(SandboxFlag::AllowLocalhostAny),
            Suggestion::AllowLocalhost(5173),
        ],
    })
}

fn detect_flyway(ctx: &DetectContext) -> DetectorOutput {
    // Two common directory patterns in navikt repos
    let migration_dirs = [
        "src/main/resources/db/migration",
        "src/main/resources/db/migrations",
    ];

    let mut signals = Vec::new();

    for dir in &migration_dirs {
        if ctx.dir_exists(dir) {
            signals.push(Signal::DirExists {
                path: (*dir).to_string(),
            });
        }
    }

    if signals.is_empty() {
        return DetectorOutput::none();
    }

    DetectorOutput::detected(Detection {
        name: "Flyway",
        signals,
        suggestions: vec![Suggestion::AllowPort(5432)],
    })
}

fn detect_cypress(ctx: &DetectContext) -> DetectorOutput {
    let config_file = if ctx.exists("cypress.config.ts") {
        Some("cypress.config.ts")
    } else if ctx.exists("cypress.config.js") {
        Some("cypress.config.js")
    } else if ctx.exists("cypress.config.mjs") {
        Some("cypress.config.mjs")
    } else {
        None
    };
    let has_dir = ctx.dir_exists("cypress");

    if config_file.is_none() && !has_dir {
        return DetectorOutput::none();
    }

    let mut signals = Vec::new();
    if let Some(file) = config_file {
        signals.push(Signal::FileExists {
            path: file.to_string(),
        });
    }
    if has_dir {
        signals.push(Signal::DirExists {
            path: "cypress/".to_string(),
        });
    }

    DetectorOutput::detected(Detection {
        name: "Cypress",
        signals,
        suggestions: vec![
            Suggestion::Propose(SandboxFlag::AllowBrowser),
            Suggestion::Propose(SandboxFlag::AllowLocalhostAny),
        ],
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
/// Max ports to extract from a single compose file (prevents noise flooding).
const MAX_COMPOSE_PORTS: usize = 20;

fn extract_compose_ports(content: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim().trim_start_matches('-').trim();
        let trimmed = trimmed.trim_matches('"').trim_matches('\'');
        // Strip protocol suffix (e.g., "/tcp", "/udp")
        let trimmed = trimmed.split('/').next().unwrap_or(trimmed);
        // Formats: "HOST:CONTAINER", "IP:HOST:CONTAINER"
        let mut parts = trimmed.splitn(3, ':');
        let first = parts.next();
        let second = parts.next();
        let third = parts.next();
        let port_str = match (first, second, third) {
            (Some(host), Some(_), None) => host,    // HOST:CONTAINER
            (Some(_), Some(host), Some(_)) => host, // IP:HOST:CONTAINER
            _ => continue,
        };
        if let Ok(port) = port_str.parse::<u16>()
            && port > 0
            && !ports.contains(&port)
        {
            ports.push(port);
            if ports.len() >= MAX_COMPOSE_PORTS {
                break;
            }
        }
    }
    ports
}

/// Extract `extends.file` references from a docker-compose file.
/// Returns relative paths to referenced compose files.
fn extract_extends_files(content: &str) -> Vec<String> {
    let mut files = Vec::new();
    let mut in_extends = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("extends:") {
            in_extends = true;
            continue;
        }
        if in_extends {
            if trimmed.starts_with("file:") {
                let value = trimmed.trim_start_matches("file:").trim();
                let value = value.trim_matches('"').trim_matches('\'');
                if !value.is_empty()
                    && !value.contains("..")
                    && !std::path::Path::new(value).is_absolute()
                {
                    files.push(value.to_string());
                }
                in_extends = false;
            } else if !trimmed.starts_with("service:") && !trimmed.is_empty() {
                in_extends = false;
            }
        }
    }

    files
}

/// Find alternate compose files matching docker-compose.*.y[a]ml / compose.*.y[a]ml.
fn find_alternate_compose_files(ctx: &DetectContext) -> Vec<String> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(ctx.root()) else {
        return files;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !entry.path().is_file() {
            continue;
        }
        let is_alt = (name_str.starts_with("docker-compose.") || name_str.starts_with("compose."))
            && (name_str.ends_with(".yml") || name_str.ends_with(".yaml"))
            && name_str != "docker-compose.yml"
            && name_str != "docker-compose.yaml"
            && name_str != "compose.yml"
            && name_str != "compose.yaml";
        if is_alt {
            files.push(name_str.to_string());
        }
    }
    files
}

/// How a workspace member was discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceSource {
    /// Parsed from `package.json` `"workspaces"` field.
    PackageJson,
    /// Parsed from `pnpm-workspace.yaml` `packages` field.
    PnpmWorkspace,
    /// Parsed from `Cargo.toml` `[workspace].members`.
    CargoWorkspace,
    /// Parsed from `settings.gradle(.kts)` `include(...)` calls.
    GradleSettings,
    /// Parsed from `go.work` `use` directives.
    GoWork,
    /// Found by heuristic directory scan (no workspace config).
    Fallback,
}

impl std::fmt::Display for WorkspaceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PackageJson => write!(f, "package.json workspaces"),
            Self::PnpmWorkspace => write!(f, "pnpm-workspace.yaml"),
            Self::CargoWorkspace => write!(f, "Cargo.toml [workspace]"),
            Self::GradleSettings => write!(f, "settings.gradle"),
            Self::GoWork => write!(f, "go.work"),
            Self::Fallback => write!(f, "heuristic scan"),
        }
    }
}

/// A discovered workspace member directory.
#[derive(Debug, Clone)]
pub struct WorkspaceMember {
    /// Relative path from repo root (e.g., `apps/web`).
    pub relative_path: String,
    /// How this member was discovered.
    pub source: WorkspaceSource,
    /// Ecosystems detected in this member (filled after detection).
    pub detections: Vec<Detection>,
}

/// Directories to skip during heuristic fallback scan.
const SCAN_SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    ".turbo",
    ".nx",
    "vendor",
    "__pycache__",
    ".venv",
    ".gradle",
    ".idea",
    ".vscode",
    ".next",
    "out",
    "coverage",
    ".cache",
];

/// Manifest files that indicate a project root.
const MANIFEST_FILES: &[&str] = &[
    "package.json",
    "Cargo.toml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "pyproject.toml",
];

/// Max depth for heuristic fallback scan.
const SCAN_MAX_DEPTH: usize = 4;

/// Max directory entries to visit during fallback scan.
const SCAN_MAX_ENTRIES: usize = 10_000;

/// Max file size for workspace config files (512 KiB — same as DetectContext).
const WORKSPACE_MAX_FILE_SIZE: usize = 512 * 1024;

/// Discover workspace members from explicit workspace configuration files.
///
/// Checks for workspace definitions in this order:
/// 1. `pnpm-workspace.yaml` (pnpm)
/// 2. `package.json` workspaces (npm/yarn/bun)
/// 3. `Cargo.toml` `[workspace]` (Rust)
/// 4. `settings.gradle(.kts)` (Gradle/JVM)
/// 5. `go.work` (Go)
///
/// Returns discovered members and any diagnostics. Members use canonical relative
/// paths and are deduplicated. Paths outside the repo root are rejected with a diagnostic.
pub fn discover_workspace_members(root: &Path) -> (Vec<WorkspaceMember>, Vec<Diagnostic>) {
    let mut members = Vec::new();
    let mut diagnostics = Vec::new();

    // Try each workspace format — they can coexist (e.g., pnpm + turbo)
    parse_pnpm_workspace(root, &mut members, &mut diagnostics);
    parse_package_json_workspaces(root, &mut members, &mut diagnostics);
    parse_cargo_workspace(root, &mut members, &mut diagnostics);
    parse_gradle_settings(root, &mut members, &mut diagnostics);
    parse_go_work(root, &mut members, &mut diagnostics);

    // Deduplicate by relative path (all paths are canonical from try_add_member)
    let mut seen = BTreeSet::new();
    members.retain(|m| seen.insert(m.relative_path.clone()));

    (members, diagnostics)
}

/// Validate and add a workspace member path. Rejects traversal, absolute paths,
/// symlinks escaping root, and the root directory itself.
fn try_add_member(
    root: &Path,
    relative: &str,
    source: WorkspaceSource,
    members: &mut Vec<WorkspaceMember>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    // Reject traversal and absolute paths
    if DetectContext::is_traversal(relative) {
        diagnostics.push(Diagnostic {
            detector: "workspace",
            message: format!(
                "Skipped workspace member {relative:?} — path traversal or absolute path"
            ),
        });
        return;
    }

    // Skip root itself (`.` or empty)
    let trimmed = relative.trim_matches('/');
    if trimmed.is_empty() || trimmed == "." {
        return;
    }

    let abs_path = root.join(trimmed);

    // Must be a directory
    if !abs_path.is_dir() {
        return;
    }

    // Canonicalize and verify within root.
    // Use canonical relative path for consistent dedup with scan_dir_recursive.
    let Ok(canonical) = abs_path.canonicalize() else {
        return;
    };
    let Ok(root_canonical) = root.canonicalize() else {
        return;
    };
    if !canonical.starts_with(&root_canonical) {
        diagnostics.push(Diagnostic {
            detector: "workspace",
            message: format!(
                "Skipped workspace member {relative:?} — resolves outside repository root"
            ),
        });
        return;
    }
    let Ok(canonical_relative) = canonical.strip_prefix(&root_canonical) else {
        return;
    };
    let Some(canonical_rel_str) = canonical_relative.to_str() else {
        return;
    };

    members.push(WorkspaceMember {
        relative_path: canonical_rel_str.to_string(),
        source,
        detections: Vec::new(),
    });
}

/// Expand a simple glob pattern with a single `*` wildcard.
/// Only supports patterns like `packages/*` — one trailing `*` matching
/// direct subdirectories. Returns matching directory names.
fn expand_simple_glob(root: &Path, pattern: &str) -> Vec<String> {
    // Skip negation patterns (pnpm `!` prefix)
    if pattern.starts_with('!') {
        return Vec::new();
    }

    let pattern = pattern.trim_matches('/');

    // If no wildcard, treat as literal path
    if !pattern.contains('*') {
        return vec![pattern.to_string()];
    }

    // Only support trailing `/*` (one level) — e.g., `packages/*`
    // For `**` or mid-pattern wildcards, fall back to literal sans wildcard
    if !pattern.ends_with("/*") && !pattern.ends_with("\\*") {
        // Unsupported pattern — skip
        return Vec::new();
    }

    let prefix = &pattern[..pattern.len() - 2]; // strip `/*`

    // Reject traversal in prefix
    if DetectContext::is_traversal(prefix) {
        return Vec::new();
    }

    let dir = root.join(prefix);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };

    let mut results = Vec::new();
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|ft| ft.is_dir())
            && let Some(name) = entry.file_name().to_str()
        {
            // Skip hidden directories
            if !name.starts_with('.') {
                results.push(format!("{prefix}/{name}"));
            }
        }
    }
    results
}

// ── Workspace parsers ────────────────────────────────────────────────

/// Parse `pnpm-workspace.yaml` for workspace members.
fn parse_pnpm_workspace(
    root: &Path,
    members: &mut Vec<WorkspaceMember>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let path = root.join("pnpm-workspace.yaml");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return;
    };

    // Bound file size
    if content.len() > WORKSPACE_MAX_FILE_SIZE {
        return;
    }

    // Simple YAML parsing — look for `packages:` array.
    // We don't pull in a YAML dependency; the format is simple enough.
    let mut in_packages = false;
    for line in content.lines() {
        let trimmed = line.trim();

        // Skip YAML comments
        if trimmed.starts_with('#') {
            continue;
        }

        if trimmed == "packages:" {
            in_packages = true;
            continue;
        }
        if in_packages {
            // End of array: non-indented, non-dash, non-empty, non-comment line
            if !trimmed.starts_with('-') && !trimmed.is_empty() {
                break;
            }
            if let Some(pattern) = trimmed.strip_prefix('-') {
                // Strip inline comments (e.g., `- 'apps/*' # comment`)
                let pattern = pattern.split('#').next().unwrap_or("").trim();
                let pattern = pattern.trim_matches(|c| c == '\'' || c == '"');
                if pattern.is_empty() || pattern.starts_with('!') {
                    continue;
                }
                for expanded in expand_simple_glob(root, pattern) {
                    try_add_member(
                        root,
                        &expanded,
                        WorkspaceSource::PnpmWorkspace,
                        members,
                        diagnostics,
                    );
                }
            }
        }
    }
}

/// Parse `package.json` `"workspaces"` field for workspace members.
/// Handles both array form and Yarn Classic object form `{packages: [...]}`.
fn parse_package_json_workspaces(
    root: &Path,
    members: &mut Vec<WorkspaceMember>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let path = root.join("package.json");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return;
    };
    if content.len() > WORKSPACE_MAX_FILE_SIZE {
        return;
    }

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Try array form first: { "workspaces": ["packages/*"] }
    // Then Yarn Classic object form: { "workspaces": { "packages": ["..."] } }
    let patterns: Vec<&str> = if let Some(arr) = json.get("workspaces").and_then(|w| w.as_array()) {
        arr.iter().filter_map(|v| v.as_str()).collect()
    } else if let Some(arr) = json
        .get("workspaces")
        .and_then(|w| w.get("packages"))
        .and_then(|p| p.as_array())
    {
        arr.iter().filter_map(|v| v.as_str()).collect()
    } else {
        return;
    };

    for pattern in patterns {
        for expanded in expand_simple_glob(root, pattern) {
            try_add_member(
                root,
                &expanded,
                WorkspaceSource::PackageJson,
                members,
                diagnostics,
            );
        }
    }
}

/// Parse `Cargo.toml` `[workspace].members` and `[workspace].exclude`.
fn parse_cargo_workspace(
    root: &Path,
    members: &mut Vec<WorkspaceMember>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let path = root.join("Cargo.toml");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return;
    };
    if content.len() > WORKSPACE_MAX_FILE_SIZE {
        return;
    }

    let table: toml::Table = match content.parse() {
        Ok(v) => v,
        Err(_) => return,
    };

    let Some(workspace) = table.get("workspace") else {
        return;
    };

    // Collect exclude patterns for filtering
    let excludes: BTreeSet<String> = workspace
        .get("exclude")
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim_matches('/').to_string())
                .collect()
        })
        .unwrap_or_default();

    let Some(member_patterns) = workspace.get("members").and_then(|m| m.as_array()) else {
        return;
    };

    for pattern in member_patterns {
        let Some(pattern) = pattern.as_str() else {
            continue;
        };
        for expanded in expand_simple_glob(root, pattern) {
            if !excludes.contains(&expanded) {
                try_add_member(
                    root,
                    &expanded,
                    WorkspaceSource::CargoWorkspace,
                    members,
                    diagnostics,
                );
            }
        }
    }
}

/// Parse `settings.gradle` or `settings.gradle.kts` for `include(...)` calls.
/// Converts Gradle colon-separated paths (`:services:api`) to filesystem paths (`services/api`).
fn parse_gradle_settings(
    root: &Path,
    members: &mut Vec<WorkspaceMember>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let content = if let Ok(c) = std::fs::read_to_string(root.join("settings.gradle.kts")) {
        c
    } else if let Ok(c) = std::fs::read_to_string(root.join("settings.gradle")) {
        c
    } else {
        return;
    };
    if content.len() > WORKSPACE_MAX_FILE_SIZE {
        return;
    }

    // Match both: include("app", "lib") and include 'app', 'lib'
    // Also: include(":services:api") → services/api
    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }

        // Match `include(...)` or `include '...'` or `include "..."`
        let args = if let Some(rest) = trimmed.strip_prefix("include(") {
            rest.trim_end_matches(')')
        } else if let Some(rest) = trimmed.strip_prefix("include ") {
            rest
        } else {
            continue;
        };

        // Extract quoted strings from the arguments
        for part in args.split(',') {
            let part = part
                .trim()
                .trim_matches(|c: char| c == '\'' || c == '"' || c.is_whitespace());
            if part.is_empty() {
                continue;
            }

            // Convert Gradle colon path to filesystem path:
            // ":services:api" → "services/api"
            // "app" → "app"
            let fs_path = part.trim_start_matches(':').replace(':', "/");
            try_add_member(
                root,
                &fs_path,
                WorkspaceSource::GradleSettings,
                members,
                diagnostics,
            );
        }
    }
}

/// Parse `go.work` for `use` directives.
fn parse_go_work(
    root: &Path,
    members: &mut Vec<WorkspaceMember>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let path = root.join("go.work");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return;
    };
    if content.len() > WORKSPACE_MAX_FILE_SIZE {
        return;
    }

    let mut in_block = false;
    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.starts_with("//") || trimmed.is_empty() {
            continue;
        }

        // Block form: use ( ... )
        if trimmed == "use (" {
            in_block = true;
            continue;
        }
        if in_block && trimmed == ")" {
            in_block = false;
            continue;
        }

        let use_path = if in_block {
            trimmed
        } else if let Some(rest) = trimmed.strip_prefix("use ") {
            rest.trim()
        } else {
            continue;
        };

        // Strip leading `./`
        let relative = use_path.strip_prefix("./").unwrap_or(use_path);
        try_add_member(
            root,
            relative,
            WorkspaceSource::GoWork,
            members,
            diagnostics,
        );
    }
}

// ── Heuristic fallback scan ──────────────────────────────────────────

/// Bounded directory scan for subprojects when no workspace config is found.
/// Walks up to [`SCAN_MAX_DEPTH`] levels, skipping known non-project directories,
/// and looks for manifest files that indicate a project root.
pub fn scan_for_subprojects(root: &Path) -> (Vec<WorkspaceMember>, Vec<Diagnostic>) {
    let mut members = Vec::new();
    let mut diagnostics = Vec::new();
    let mut entry_count: usize = 0;
    let mut limit_hit = false;

    let Ok(root_canonical) = root.canonicalize() else {
        return (members, diagnostics);
    };

    scan_dir_recursive(
        root,
        &root_canonical,
        0,
        &mut members,
        &mut entry_count,
        &mut limit_hit,
    );

    if limit_hit {
        diagnostics.push(Diagnostic {
            detector: "workspace",
            message: format!(
                "Heuristic scan stopped after {SCAN_MAX_ENTRIES} entries; \
                 some subprojects may not have been detected"
            ),
        });
    }

    (members, diagnostics)
}

fn scan_dir_recursive(
    dir: &Path,
    root_canonical: &Path,
    depth: usize,
    members: &mut Vec<WorkspaceMember>,
    entry_count: &mut usize,
    limit_hit: &mut bool,
) {
    if depth > SCAN_MAX_DEPTH || *limit_hit {
        return;
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        *entry_count += 1;
        if *entry_count > SCAN_MAX_ENTRIES {
            *limit_hit = true;
            return;
        }

        // Only process directories (don't follow symlinks)
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() || !ft.is_dir() {
            continue;
        }

        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };

        // Skip hidden dirs and known non-project dirs
        if name_str.starts_with('.') || SCAN_SKIP_DIRS.contains(&name_str) {
            continue;
        }

        let subdir = entry.path();

        // Check if this directory contains a manifest file
        let has_manifest = MANIFEST_FILES
            .iter()
            .any(|manifest| subdir.join(manifest).is_file());

        if has_manifest {
            // Verify it's within root (no symlink escape)
            if let Ok(canonical) = subdir.canonicalize()
                && canonical.starts_with(root_canonical)
                && let Ok(relative) = canonical.strip_prefix(root_canonical)
                && let Some(rel_str) = relative.to_str()
            {
                members.push(WorkspaceMember {
                    relative_path: rel_str.to_string(),
                    source: WorkspaceSource::Fallback,
                    detections: Vec::new(),
                });
            }
        }

        // Continue scanning deeper
        scan_dir_recursive(
            &subdir,
            root_canonical,
            depth + 1,
            members,
            entry_count,
            limit_hit,
        );
    }
}

// ── Recursive (monorepo-aware) detection ─────────────────────────────

/// Run all detectors against a project directory and its workspace members.
///
/// This is the monorepo-aware version of [`detect_project`]. It:
/// 1. Detects ecosystems at the repo root
/// 2. Discovers workspace members (explicit configs, or heuristic fallback)
/// 3. Runs all detectors on each member subdirectory
/// 4. Merges suggestions with provenance tracking
pub fn detect_project_recursive(root: &Path) -> DetectionReport {
    // Step 1: root-level detection
    let mut report = detect_project(root);

    // Step 2: discover workspace members
    let (mut members, ws_diagnostics) = discover_workspace_members(root);
    report.diagnostics.extend(ws_diagnostics);

    // If no explicit workspace config found, try heuristic scan
    if members.is_empty() {
        let (fallback_members, fb_diagnostics) = scan_for_subprojects(root);
        members = fallback_members;
        report.diagnostics.extend(fb_diagnostics);
    }

    // Step 3: run detectors on each member
    let mut provenance: BTreeMap<Suggestion, BTreeSet<String>> = BTreeMap::new();

    // Record root-level provenance
    for suggestion in &report.suggestions {
        provenance
            .entry(suggestion.clone())
            .or_default()
            .insert(".".to_string());
    }

    for member in &mut members {
        let member_dir = root.join(&member.relative_path);
        let member_report = detect_project(&member_dir);

        // Record per-member provenance
        for suggestion in &member_report.suggestions {
            provenance
                .entry(suggestion.clone())
                .or_default()
                .insert(member.relative_path.clone());
        }

        // Merge suggestions and detections
        report.suggestions.extend(member_report.suggestions);
        member.detections = member_report.detections;
        report.diagnostics.extend(member_report.diagnostics);
    }

    report.workspace_members = members;
    report.provenance = provenance;
    report
}

// ══════════════════════════════════════════════════════════════════════

/// Suggestions specific to personal/global config (~/.config/cplt/config.toml).
/// These map to `[sandbox]` and `[allow]` keys in the global config file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum GlobalSuggestion {
    /// `sandbox.allow_cache_exec += [...]`
    CacheExec(String),
    /// `sandbox.allow_gpg_signing = true`
    GpgSigning,
    /// `allow.read += [...]`
    AllowRead(String),
    /// `sandbox.agent = "..."`
    SetAgent(String),
}

/// Result of a global (machine-level) detection.
#[derive(Debug, Clone)]
pub struct GlobalDetection {
    pub name: &'static str,
    pub reason: String,
    pub suggestions: Vec<GlobalSuggestion>,
}

/// Full report from global machine scanning.
#[derive(Debug)]
pub struct GlobalDetectionReport {
    pub detections: Vec<GlobalDetection>,
}

/// Scan the user's home directory and environment for tool configurations
/// that need personal config settings. Only detects tools commonly used
/// by Nav developers.
pub fn detect_global(home: &Path) -> GlobalDetectionReport {
    let mut detections = Vec::new();

    // Gradle cache exec (for wrapper downloads)
    if let Some(d) = detect_global_gradle(home) {
        detections.push(d);
    }

    // Playwright browser cache
    if let Some(d) = detect_global_playwright(home) {
        detections.push(d);
    }

    // GPG signing configuration
    if let Some(d) = detect_global_gpg(home) {
        detections.push(d);
    }

    // Gradle credentials (private registry access)
    if let Some(d) = detect_global_gradle_credentials(home) {
        detections.push(d);
    }

    // npm credentials (private registry access)
    if let Some(d) = detect_global_npmrc(home) {
        detections.push(d);
    }

    // Maven credentials (private registry access)
    if let Some(d) = detect_global_m2_settings(home) {
        detections.push(d);
    }

    // Preferred agent from PATH
    if let Some(d) = detect_global_agent() {
        detections.push(d);
    }

    GlobalDetectionReport { detections }
}

fn detect_global_gradle(home: &Path) -> Option<GlobalDetection> {
    // Gradle wrapper downloads executables to ~/.gradle/wrapper/dists/
    let wrapper_dir = home.join(".gradle/wrapper/dists");
    if !wrapper_dir.is_dir() {
        return None;
    }
    Some(GlobalDetection {
        name: "Gradle wrapper",
        reason: "~/.gradle/wrapper/dists/ exists (Gradle wrapper executables)".to_string(),
        suggestions: vec![GlobalSuggestion::CacheExec("gradle".to_string())],
    })
}

fn detect_global_playwright(home: &Path) -> Option<GlobalDetection> {
    // Playwright installs browsers to ~/Library/Caches/ms-playwright/ (macOS)
    // or ~/.cache/ms-playwright/ (Linux)
    let mac_path = home.join("Library/Caches/ms-playwright");
    let linux_path = home.join(".cache/ms-playwright");
    if !mac_path.is_dir() && !linux_path.is_dir() {
        return None;
    }
    Some(GlobalDetection {
        name: "Playwright browsers",
        reason: "ms-playwright cache directory exists".to_string(),
        suggestions: vec![GlobalSuggestion::CacheExec("ms-playwright".to_string())],
    })
}

fn detect_global_gpg(home: &Path) -> Option<GlobalDetection> {
    // GPG signing requires sandbox access to gpg-agent socket and keyring
    if !home.join(".gnupg").is_dir() {
        return None;
    }
    // Enhance reason with git config info when available
    let git_signing = std::process::Command::new("git")
        .args(["config", "--global", "commit.gpgsign"])
        .output()
        .ok()
        .is_some_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "true");

    let reason = if git_signing {
        "~/.gnupg/ exists and git commit.gpgsign=true"
    } else {
        "~/.gnupg/ exists (GPG keyring present)"
    };
    Some(GlobalDetection {
        name: "GPG signing",
        reason: reason.to_string(),
        suggestions: vec![GlobalSuggestion::GpgSigning],
    })
}

fn detect_global_gradle_credentials(home: &Path) -> Option<GlobalDetection> {
    // ~/.gradle/gradle.properties is denied by default (may contain Nexus passwords).
    // If it exists and contains repository credentials, suggest allowing read access.
    let props_path = home.join(".gradle/gradle.properties");
    if !props_path.is_file() {
        return None;
    }
    // Check if it actually contains credential-like entries
    let content = std::fs::read_to_string(&props_path).ok()?;
    let has_registry = content.lines().any(|line| {
        let lower = line.to_lowercase();
        lower.contains("repository") || lower.contains("nexus") || lower.contains("artifactory")
    });
    if !has_registry {
        return None;
    }
    Some(GlobalDetection {
        name: "Gradle registry credentials",
        reason: "~/.gradle/gradle.properties contains repository configuration".to_string(),
        suggestions: vec![GlobalSuggestion::AllowRead(
            "~/.gradle/gradle.properties".to_string(),
        )],
    })
}

fn detect_global_npmrc(home: &Path) -> Option<GlobalDetection> {
    // ~/.npmrc is denied by default (may contain authentication tokens).
    // If it exists and contains registry configurations/tokens, suggest allowing read access.
    let npmrc_path = home.join(".npmrc");
    if !npmrc_path.is_file() {
        return None;
    }
    let content = std::fs::read_to_string(&npmrc_path).ok()?;
    let has_registry = content.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#')
            && (trimmed.contains("registry") || trimmed.contains("_authToken"))
    });
    if !has_registry {
        return None;
    }
    Some(GlobalDetection {
        name: "npm registry credentials",
        reason: "~/.npmrc contains registry or token configuration".to_string(),
        suggestions: vec![GlobalSuggestion::AllowRead("~/.npmrc".to_string())],
    })
}

fn detect_global_m2_settings(home: &Path) -> Option<GlobalDetection> {
    // ~/.m2/settings.xml is denied by default (may contain repository server credentials).
    // If it exists and contains custom servers/profiles, suggest allowing read access.
    let settings_path = home.join(".m2/settings.xml");
    if !settings_path.is_file() {
        return None;
    }
    let content = std::fs::read_to_string(&settings_path).ok()?;
    let has_registry = content.contains("<server>")
        || content.contains("<mirror>")
        || content.contains("<repository>");
    if !has_registry {
        return None;
    }
    Some(GlobalDetection {
        name: "Maven repository settings",
        reason: "~/.m2/settings.xml contains repository server configurations".to_string(),
        suggestions: vec![GlobalSuggestion::AllowRead(
            "~/.m2/settings.xml".to_string(),
        )],
    })
}

fn detect_global_agent() -> Option<GlobalDetection> {
    // Detect which agent binary is available in PATH
    let agents = [
        ("copilot", "copilot"),
        ("opencode", "opencode"),
        ("aider", "aider"),
        ("gemini", "gemini"),
        ("claude", "claude"),
    ];

    let mut found: Vec<&str> = Vec::new();
    for (name, binary) in &agents {
        if which_exists(binary) {
            found.push(name);
        }
    }

    // Only suggest if exactly one agent is found (clear default)
    // or if a non-copilot agent is the only one (copilot is already the default)
    if found.len() == 1 && found[0] != "copilot" {
        return Some(GlobalDetection {
            name: "Default agent",
            reason: format!("{} found in PATH", found[0]),
            suggestions: vec![GlobalSuggestion::SetAgent(found[0].to_string())],
        });
    }

    None
}

fn which_exists(binary: &str) -> bool {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path_var).any(|dir| dir.join(binary).is_file())
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
    fn context_rejects_absolute_paths() {
        let dir = setup_dir();
        let ctx = DetectContext::new(dir.path());
        assert!(!ctx.exists("/etc/passwd"));
        assert!(ctx.read_text("/etc/hosts").is_none());
        assert!(!ctx.dir_exists("/tmp"));
    }

    #[cfg(unix)]
    #[test]
    fn context_rejects_symlink_escape() {
        let dir = setup_dir();
        // Create a symlink pointing outside the project
        let link_path = dir.path().join("escape.txt");
        std::os::unix::fs::symlink("/etc/hosts", &link_path).unwrap();
        let ctx = DetectContext::new(dir.path());
        assert!(
            !ctx.exists("escape.txt"),
            "symlink outside root should be rejected"
        );
        assert!(
            ctx.read_text("escape.txt").is_none(),
            "should not read through symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn context_allows_symlink_within_project() {
        let dir = setup_dir();
        fs::write(dir.path().join("real.txt"), "content").unwrap();
        let link_path = dir.path().join("link.txt");
        std::os::unix::fs::symlink(dir.path().join("real.txt"), &link_path).unwrap();
        let ctx = DetectContext::new(dir.path());
        assert!(ctx.exists("link.txt"), "symlink within root should work");
        assert_eq!(ctx.read_text("link.txt").unwrap(), "content");
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
    fn node_detects_lifecycle_scripts_as_warning() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"postinstall":"patch-package"}}"#,
        )
        .unwrap();
        let report = detect_project(dir.path());
        // Should NOT auto-suggest (dangerous), but should warn via diagnostic
        assert!(
            !report
                .suggestions
                .contains(&Suggestion::Propose(SandboxFlag::AllowLifecycleScripts))
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.message.contains("lifecycle scripts")),
            "should emit a diagnostic warning"
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

    /// Returns true if we can write .env files (blocked inside cplt sandbox).
    fn can_write_env_files() -> bool {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env.example"), "test=1").is_ok()
    }

    #[test]
    fn env_detects_sensitive_vars() {
        if !can_write_env_files() {
            eprintln!("SKIP: .env writes blocked (running inside sandbox)");
            return;
        }
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
        if !can_write_env_files() {
            eprintln!("SKIP: .env writes blocked (running inside sandbox)");
            return;
        }
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

    #[test]
    fn env_skips_invalid_var_names() {
        if !can_write_env_files() {
            eprintln!("SKIP: .env writes blocked (running inside sandbox)");
            return;
        }
        let dir = setup_dir();
        fs::write(
            dir.path().join(".env.example"),
            "SECRET-KEY=foo\nSECRET.TOKEN=bar\nDB_PASSWORD=xxx\nAPI_KEY=yyy\n",
        )
        .unwrap();
        let report = detect_project(dir.path());
        let det = report
            .detections
            .iter()
            .find(|d| d.name == "Environment secrets")
            .unwrap();
        // Only valid identifiers should be suggested
        let deny_envs: Vec<_> = det
            .suggestions
            .iter()
            .filter_map(|s| match s {
                Suggestion::DenyEnv(v) => Some(v.as_str()),
                _ => None,
            })
            .collect();
        assert!(deny_envs.contains(&"DB_PASSWORD"));
        assert!(deny_envs.contains(&"API_KEY"));
        assert!(
            !deny_envs.contains(&"SECRET-KEY"),
            "hyphenated name should be skipped"
        );
        assert!(
            !deny_envs.contains(&"SECRET.TOKEN"),
            "dotted name should be skipped"
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

    #[test]
    fn compose_extends_file_extraction() {
        let content = r#"
services:
  grafana:
    extends:
      file: .config/docker-compose-base.yaml
      service: grafana
  mimir:
    ports:
      - "9009:9009"
"#;
        let files = extract_extends_files(content);
        assert_eq!(files, vec![".config/docker-compose-base.yaml"]);
    }

    #[test]
    fn compose_extends_rejects_traversal() {
        let content = r"
services:
  evil:
    extends:
      file: ../../etc/passwd
      service: hack
";
        let files = extract_extends_files(content);
        assert!(files.is_empty(), "path traversal should be rejected");
    }

    #[test]
    fn docker_follows_extends_for_ports() {
        let dir = setup_dir();
        let config_dir = dir.path().join(".config");
        fs::create_dir_all(&config_dir).unwrap();

        fs::write(
            dir.path().join("docker-compose.yaml"),
            r#"services:
  grafana:
    extends:
      file: .config/docker-compose-base.yaml
      service: grafana
  mimir:
    ports:
      - "9009:9009"
"#,
        )
        .unwrap();

        fs::write(
            config_dir.join("docker-compose-base.yaml"),
            "services:\n  grafana:\n    ports:\n      - 3000:3000/tcp\n      - 2345:2345/tcp\n",
        )
        .unwrap();

        let report = detect_project(dir.path());
        assert!(report.suggestions.contains(&Suggestion::AllowPort(9009)));
        assert!(report.suggestions.contains(&Suggestion::AllowPort(3000)));
        assert!(report.suggestions.contains(&Suggestion::AllowPort(2345)));
    }

    #[test]
    fn docker_scans_alternate_compose_files() {
        let dir = setup_dir();
        fs::write(dir.path().join("Dockerfile"), "FROM node:20").unwrap();
        fs::write(
            dir.path().join("docker-compose.yaml"),
            "services:\n  web:\n    ports:\n      - \"3000:3000\"\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("docker-compose.demo.yaml"),
            "services:\n  demo:\n    ports:\n      - \"8080:8080\"\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("compose.dev.yml"),
            "services:\n  dev:\n    ports:\n      - \"4200:4200\"\n",
        )
        .unwrap();

        let report = detect_project(dir.path());
        assert!(report.suggestions.contains(&Suggestion::AllowPort(3000)));
        assert!(report.suggestions.contains(&Suggestion::AllowPort(8080)));
        assert!(report.suggestions.contains(&Suggestion::AllowPort(4200)));
    }

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

    // ── Spring Boot detector ─────────────────────────────────────────

    #[test]
    fn spring_boot_detected() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("build.gradle.kts"),
            r#"plugins { id("org.springframework.boot") version "4.0" }"#,
        )
        .unwrap();
        let res_dir = dir.path().join("src/main/resources");
        fs::create_dir_all(&res_dir).unwrap();
        fs::write(
            res_dir.join("application.yml"),
            "spring:\n  datasource:\n    url: jdbc:postgresql://localhost/db\n",
        )
        .unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Spring Boot"));
        assert!(
            report
                .suggestions
                .contains(&Suggestion::AllowLocalhost(8080))
        );
        assert!(report.suggestions.contains(&Suggestion::AllowPort(5432)));
    }

    #[test]
    fn spring_boot_not_detected_without_gradle() {
        let dir = setup_dir();
        let res_dir = dir.path().join("src/main/resources");
        fs::create_dir_all(&res_dir).unwrap();
        fs::write(
            res_dir.join("application.yml"),
            "spring:\n  profiles: dev\n",
        )
        .unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().all(|d| d.name != "Spring Boot"));
    }

    // ── Ktor detector ────────────────────────────────────────────────

    #[test]
    fn ktor_detected() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("build.gradle.kts"),
            "plugins {\n  alias(libs.plugins.ktor)\n}\ndependencies {\n  implementation(libs.ktor.server.core)\n}\n",
        )
        .unwrap();
        let res_dir = dir.path().join("src/main/resources");
        fs::create_dir_all(&res_dir).unwrap();
        fs::write(res_dir.join("application.conf"), "ktor { }").unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Ktor"));
        assert!(
            report
                .suggestions
                .contains(&Suggestion::AllowLocalhost(8080))
        );
    }

    // ── TestContainers detector ──────────────────────────────────────

    #[test]
    fn testcontainers_detected() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("build.gradle.kts"),
            "dependencies {\n  testImplementation(\"org.testcontainers:postgresql:1.19\")\n  testImplementation(\"org.testcontainers:kafka:1.19\")\n}\n",
        )
        .unwrap();
        let report = detect_project(dir.path());
        let tc = report
            .detections
            .iter()
            .find(|d| d.name == "TestContainers")
            .unwrap();
        assert!(tc.signals.iter().any(
            |s| matches!(s, Signal::FileContains { reason, .. } if reason.contains("PostgreSQL"))
        ));
        assert!(
            report
                .suggestions
                .contains(&Suggestion::Propose(SandboxFlag::AllowDocker))
        );
        assert!(
            report
                .suggestions
                .contains(&Suggestion::Propose(SandboxFlag::AllowLocalhostAny))
        );
    }

    // ── Next.js config detector ──────────────────────────────────────

    #[test]
    fn nextjs_config_detected() {
        let dir = setup_dir();
        fs::write(dir.path().join("next.config.ts"), "export default {}").unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Next.js"));
        assert!(
            report
                .suggestions
                .contains(&Suggestion::AllowLocalhost(3000))
        );
        assert!(
            report
                .suggestions
                .contains(&Suggestion::Propose(SandboxFlag::AllowLocalhostAny))
        );
    }

    // ── Vite config detector ─────────────────────────────────────────

    #[test]
    fn vite_config_detected() {
        let dir = setup_dir();
        fs::write(dir.path().join("vite.config.ts"), "export default {}").unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Vite"));
        assert!(
            report
                .suggestions
                .contains(&Suggestion::AllowLocalhost(5173))
        );
    }

    // ── Flyway detector ──────────────────────────────────────────────

    #[test]
    fn flyway_detected_from_migration_dir() {
        let dir = setup_dir();
        let migration_dir = dir.path().join("src/main/resources/db/migration");
        fs::create_dir_all(&migration_dir).unwrap();
        fs::write(
            migration_dir.join("V1__init.sql"),
            "CREATE TABLE t(id INT);",
        )
        .unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Flyway"));
        assert!(report.suggestions.contains(&Suggestion::AllowPort(5432)));
    }

    #[test]
    fn flyway_detected_ktor_style() {
        let dir = setup_dir();
        let migration_dir = dir.path().join("src/main/resources/db/migrations");
        fs::create_dir_all(&migration_dir).unwrap();
        fs::write(
            migration_dir.join("V1__init.sql"),
            "CREATE TABLE t(id INT);",
        )
        .unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Flyway"));
    }

    // ── Cypress detector ─────────────────────────────────────────────

    #[test]
    fn cypress_detected() {
        let dir = setup_dir();
        fs::write(dir.path().join("cypress.config.ts"), "export default {}").unwrap();
        fs::create_dir(dir.path().join("cypress")).unwrap();
        let report = detect_project(dir.path());
        assert!(report.detections.iter().any(|d| d.name == "Cypress"));
        assert!(
            report
                .suggestions
                .contains(&Suggestion::Propose(SandboxFlag::AllowBrowser))
        );
    }

    // ── Nav full-stack archetype ──────────────────────────────────────

    #[test]
    fn nav_spring_boot_archetype() {
        let dir = setup_dir();
        // Gradle + Spring Boot
        fs::write(
            dir.path().join("build.gradle.kts"),
            "plugins { id(\"org.springframework.boot\") }\ndependencies { testImplementation(\"org.testcontainers:postgresql:1.19\") }\n",
        )
        .unwrap();
        // application.yml
        let res_dir = dir.path().join("src/main/resources");
        fs::create_dir_all(&res_dir).unwrap();
        fs::write(
            res_dir.join("application.yml"),
            "spring:\n  datasource:\n    url: jdbc:postgresql://localhost\n",
        )
        .unwrap();
        // Flyway
        let migration_dir = res_dir.join("db/migration");
        fs::create_dir_all(&migration_dir).unwrap();
        fs::write(
            migration_dir.join("V1__init.sql"),
            "CREATE TABLE t(id INT);",
        )
        .unwrap();
        // Docker
        fs::write(dir.path().join("Dockerfile"), "FROM eclipse-temurin:21").unwrap();

        let report = detect_project(dir.path());
        let names: Vec<&str> = report.detections.iter().map(|d| d.name).collect();
        assert!(names.contains(&"JVM (Gradle)"), "missing JVM: {names:?}");
        assert!(names.contains(&"Docker"), "missing Docker: {names:?}");
        assert!(
            names.contains(&"Spring Boot"),
            "missing Spring Boot: {names:?}"
        );
        assert!(
            names.contains(&"TestContainers"),
            "missing TestContainers: {names:?}"
        );
        assert!(names.contains(&"Flyway"), "missing Flyway: {names:?}");

        // Merged suggestions
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
        assert!(
            report
                .suggestions
                .contains(&Suggestion::AllowLocalhost(8080))
        );
    }

    // ── Global detector tests ────────────────────────────────────────

    #[test]
    fn global_detect_gradle_wrapper() {
        let home = tempfile::tempdir().unwrap();
        let dists = home.path().join(".gradle/wrapper/dists");
        std::fs::create_dir_all(&dists).unwrap();
        std::fs::write(dists.join("gradle-8.5-bin"), "").unwrap();

        let report = detect_global(home.path());
        assert!(report.detections.iter().any(|d| d.name == "Gradle wrapper"));
        assert!(
            report
                .detections
                .iter()
                .flat_map(|d| &d.suggestions)
                .any(|s| matches!(s, GlobalSuggestion::CacheExec(v) if v == "gradle"))
        );
    }

    #[test]
    fn global_detect_gradle_missing() {
        let home = tempfile::tempdir().unwrap();
        let report = detect_global(home.path());
        assert!(!report.detections.iter().any(|d| d.name == "Gradle wrapper"));
    }

    #[test]
    fn global_detect_playwright_cache() {
        let home = tempfile::tempdir().unwrap();
        // macOS path
        let pw = home.path().join("Library/Caches/ms-playwright");
        std::fs::create_dir_all(&pw).unwrap();

        let report = detect_global(home.path());
        assert!(
            report
                .detections
                .iter()
                .any(|d| d.name == "Playwright browsers")
        );
    }

    #[test]
    fn global_detect_gpg_dir() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".gnupg")).unwrap();

        let report = detect_global(home.path());
        // GPG dir alone triggers detection (even without git config)
        assert!(report.detections.iter().any(|d| d.name == "GPG signing"));
    }

    #[test]
    fn global_detect_gradle_credentials() {
        let home = tempfile::tempdir().unwrap();
        let props = home.path().join(".gradle/gradle.properties");
        std::fs::create_dir_all(props.parent().unwrap()).unwrap();
        std::fs::write(&props, "nexusUrl=https://maven.nav.no\n").unwrap();

        let report = detect_global(home.path());
        assert!(
            report
                .detections
                .iter()
                .any(|d| d.name == "Gradle registry credentials")
        );
        assert!(report.detections.iter().flat_map(|d| &d.suggestions).any(
            |s| matches!(s, GlobalSuggestion::AllowRead(p) if p.contains("gradle.properties"))
        ));
    }

    #[test]
    fn global_detect_gradle_credentials_no_match() {
        let home = tempfile::tempdir().unwrap();
        let props = home.path().join(".gradle/gradle.properties");
        std::fs::create_dir_all(props.parent().unwrap()).unwrap();
        std::fs::write(&props, "org.gradle.daemon=true\n").unwrap();

        let report = detect_global(home.path());
        assert!(
            !report
                .detections
                .iter()
                .any(|d| d.name == "Gradle registry credentials")
        );
    }

    #[test]
    fn global_detect_npmrc_credentials() {
        let home = tempfile::tempdir().unwrap();
        let npmrc = home.path().join(".npmrc");
        std::fs::write(
            &npmrc,
            "registry=https://npm.pkg.github.com\n_authToken=secret",
        )
        .unwrap();

        let report = detect_global(home.path());
        assert!(
            report
                .detections
                .iter()
                .any(|d| d.name == "npm registry credentials")
        );
        assert!(
            report
                .detections
                .iter()
                .flat_map(|d| &d.suggestions)
                .any(|s| matches!(s, GlobalSuggestion::AllowRead(p) if p.contains(".npmrc")))
        );
    }

    #[test]
    fn global_detect_npmrc_no_match() {
        let home = tempfile::tempdir().unwrap();
        let npmrc = home.path().join(".npmrc");
        std::fs::write(&npmrc, "# just a comment").unwrap();

        let report = detect_global(home.path());
        assert!(
            !report
                .detections
                .iter()
                .any(|d| d.name == "npm registry credentials")
        );
    }

    #[test]
    fn global_detect_m2_settings_credentials() {
        let home = tempfile::tempdir().unwrap();
        let settings = home.path().join(".m2/settings.xml");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(
            &settings,
            "<settings><servers><server><id>nexus</id></server></servers></settings>",
        )
        .unwrap();

        let report = detect_global(home.path());
        assert!(
            report
                .detections
                .iter()
                .any(|d| d.name == "Maven repository settings")
        );
        assert!(
            report
                .detections
                .iter()
                .flat_map(|d| &d.suggestions)
                .any(|s| matches!(s, GlobalSuggestion::AllowRead(p) if p.contains("settings.xml")))
        );
    }

    // ── Workspace discovery tests ───────────────────────────────────

    #[test]
    fn workspace_npm_workspaces_array() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"mono","workspaces":["packages/*","apps/web"]}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("packages/ui")).unwrap();
        fs::create_dir_all(dir.path().join("packages/utils")).unwrap();
        fs::create_dir_all(dir.path().join("apps/web")).unwrap();

        let (members, diagnostics) = discover_workspace_members(dir.path());
        assert!(diagnostics.is_empty(), "diagnostics: {diagnostics:?}");

        let paths: Vec<&str> = members.iter().map(|m| m.relative_path.as_str()).collect();
        assert!(paths.contains(&"apps/web"), "missing apps/web: {paths:?}");
        assert!(
            paths.contains(&"packages/ui"),
            "missing packages/ui: {paths:?}"
        );
        assert!(
            paths.contains(&"packages/utils"),
            "missing packages/utils: {paths:?}"
        );
        assert!(
            members
                .iter()
                .all(|m| m.source == WorkspaceSource::PackageJson),
            "wrong source"
        );
    }

    #[test]
    fn workspace_yarn_classic_object_form() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"mono","workspaces":{"packages":["libs/*"]}}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("libs/shared")).unwrap();

        let (members, _) = discover_workspace_members(dir.path());
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].relative_path, "libs/shared");
    }

    #[test]
    fn workspace_pnpm_workspace_yaml() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n  - '!packages/legacy'\n  - 'apps/web'\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("packages/ui")).unwrap();
        fs::create_dir_all(dir.path().join("packages/legacy")).unwrap();
        fs::create_dir_all(dir.path().join("apps/web")).unwrap();

        let (members, _) = discover_workspace_members(dir.path());
        let paths: Vec<&str> = members.iter().map(|m| m.relative_path.as_str()).collect();
        assert!(
            paths.contains(&"packages/ui"),
            "missing packages/ui: {paths:?}"
        );
        assert!(paths.contains(&"apps/web"), "missing apps/web: {paths:?}");
        assert!(
            members
                .iter()
                .all(|m| m.source == WorkspaceSource::PnpmWorkspace),
            "wrong source"
        );
    }

    #[test]
    fn workspace_cargo_workspace() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/experimental\"]\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("crates/core")).unwrap();
        fs::create_dir_all(dir.path().join("crates/cli")).unwrap();
        fs::create_dir_all(dir.path().join("crates/experimental")).unwrap();

        let (members, _) = discover_workspace_members(dir.path());
        let paths: Vec<&str> = members.iter().map(|m| m.relative_path.as_str()).collect();
        assert!(paths.contains(&"crates/core"), "missing crates/core");
        assert!(paths.contains(&"crates/cli"), "missing crates/cli");
        assert!(
            !paths.contains(&"crates/experimental"),
            "experimental should be excluded"
        );
        assert!(
            members
                .iter()
                .all(|m| m.source == WorkspaceSource::CargoWorkspace),
            "wrong source"
        );
    }

    #[test]
    fn workspace_gradle_settings() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("settings.gradle.kts"),
            "rootProject.name = \"mono\"\ninclude(\"app\", \"lib\")\ninclude(\":services:api\")\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("app")).unwrap();
        fs::create_dir_all(dir.path().join("lib")).unwrap();
        fs::create_dir_all(dir.path().join("services/api")).unwrap();

        let (members, _) = discover_workspace_members(dir.path());
        let paths: Vec<&str> = members.iter().map(|m| m.relative_path.as_str()).collect();
        assert!(paths.contains(&"app"), "missing app: {paths:?}");
        assert!(paths.contains(&"lib"), "missing lib: {paths:?}");
        assert!(
            paths.contains(&"services/api"),
            "missing services/api: {paths:?}"
        );
    }

    #[test]
    fn workspace_gradle_groovy() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("settings.gradle"),
            "include 'app', 'core'\ninclude ':services:worker'\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("app")).unwrap();
        fs::create_dir_all(dir.path().join("core")).unwrap();
        fs::create_dir_all(dir.path().join("services/worker")).unwrap();

        let (members, _) = discover_workspace_members(dir.path());
        let paths: Vec<&str> = members.iter().map(|m| m.relative_path.as_str()).collect();
        assert!(paths.contains(&"app"), "missing app: {paths:?}");
        assert!(paths.contains(&"core"), "missing core: {paths:?}");
        assert!(
            paths.contains(&"services/worker"),
            "missing services/worker: {paths:?}"
        );
    }

    #[test]
    fn workspace_go_work() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("go.work"),
            "go 1.23.0\n\nuse (\n    ./service-a\n    ./service-b\n)\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("service-a")).unwrap();
        fs::create_dir_all(dir.path().join("service-b")).unwrap();

        let (members, _) = discover_workspace_members(dir.path());
        let paths: Vec<&str> = members.iter().map(|m| m.relative_path.as_str()).collect();
        assert!(paths.contains(&"service-a"), "missing service-a: {paths:?}");
        assert!(paths.contains(&"service-b"), "missing service-b: {paths:?}");
        assert!(
            members.iter().all(|m| m.source == WorkspaceSource::GoWork),
            "wrong source"
        );
    }

    #[test]
    fn workspace_go_work_single_line() {
        let dir = setup_dir();
        fs::write(dir.path().join("go.work"), "go 1.23.0\n\nuse ./mymod\n").unwrap();
        fs::create_dir_all(dir.path().join("mymod")).unwrap();

        let (members, _) = discover_workspace_members(dir.path());
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].relative_path, "mymod");
    }

    #[test]
    fn workspace_rejects_traversal() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces":["../escape","packages/*"]}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("packages/ok")).unwrap();

        let (members, diagnostics) = discover_workspace_members(dir.path());
        assert!(
            !members.iter().any(|m| m.relative_path.contains("escape")),
            "traversal should be rejected"
        );
        assert!(
            diagnostics.iter().any(|d| d.message.contains("traversal")),
            "should have traversal diagnostic"
        );
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].relative_path, "packages/ok");
    }

    #[test]
    fn workspace_skips_root_member() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces":[".","packages/*"]}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("packages/ui")).unwrap();

        let (members, _) = discover_workspace_members(dir.path());
        assert_eq!(members.len(), 1, "root should be skipped");
        assert_eq!(members[0].relative_path, "packages/ui");
    }

    #[test]
    fn workspace_deduplicates_members() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'apps/web'\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces":["apps/web"]}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("apps/web")).unwrap();

        let (members, _) = discover_workspace_members(dir.path());
        assert_eq!(members.len(), 1, "duplicate should be removed");
    }

    #[test]
    fn workspace_nonexistent_dirs_ignored() {
        let dir = setup_dir();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces":["packages/*","ghost"]}"#,
        )
        .unwrap();

        let (members, _) = discover_workspace_members(dir.path());
        assert!(members.is_empty(), "nonexistent dirs should be skipped");
    }

    #[cfg(unix)]
    #[test]
    fn workspace_rejects_symlink_outside_root() {
        let dir = setup_dir();
        let outside = setup_dir();
        fs::create_dir_all(outside.path().join("evil")).unwrap();

        std::os::unix::fs::symlink(outside.path().join("evil"), dir.path().join("escape")).unwrap();

        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces":["escape"]}"#,
        )
        .unwrap();

        let (members, diagnostics) = discover_workspace_members(dir.path());
        assert!(
            members.is_empty(),
            "symlink outside root should be rejected"
        );
        assert!(
            diagnostics.iter().any(|d| d.message.contains("outside")),
            "should have outside-root diagnostic"
        );
    }

    // ── Fallback scan tests ─────────────────────────────────────────

    #[test]
    fn fallback_finds_subprojects() {
        let dir = setup_dir();
        fs::create_dir_all(dir.path().join("apps/web")).unwrap();
        fs::write(dir.path().join("apps/web/package.json"), "{}").unwrap();
        fs::create_dir_all(dir.path().join("services/api")).unwrap();
        fs::write(dir.path().join("services/api/Cargo.toml"), "").unwrap();

        let (members, diagnostics) = scan_for_subprojects(dir.path());
        assert!(diagnostics.is_empty());
        let paths: Vec<&str> = members.iter().map(|m| m.relative_path.as_str()).collect();
        assert!(
            paths.iter().any(|p| p.contains("web")),
            "missing web: {paths:?}"
        );
        assert!(
            paths.iter().any(|p| p.contains("api")),
            "missing api: {paths:?}"
        );
        assert!(
            members
                .iter()
                .all(|m| m.source == WorkspaceSource::Fallback),
            "wrong source"
        );
    }

    #[test]
    fn fallback_skips_node_modules() {
        let dir = setup_dir();
        fs::create_dir_all(dir.path().join("node_modules/foo")).unwrap();
        fs::write(dir.path().join("node_modules/foo/package.json"), "{}").unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();

        let (members, _) = scan_for_subprojects(dir.path());
        assert!(
            !members
                .iter()
                .any(|m| m.relative_path.contains("node_modules")),
            "node_modules should be skipped"
        );
    }

    #[test]
    fn fallback_skips_hidden_dirs() {
        let dir = setup_dir();
        fs::create_dir_all(dir.path().join(".hidden/sub")).unwrap();
        fs::write(dir.path().join(".hidden/sub/package.json"), "{}").unwrap();

        let (members, _) = scan_for_subprojects(dir.path());
        assert!(members.is_empty(), "hidden dirs should be skipped");
    }

    #[cfg(unix)]
    #[test]
    fn fallback_skips_symlinks() {
        let dir = setup_dir();
        let target = setup_dir();
        fs::write(target.path().join("package.json"), "{}").unwrap();

        std::os::unix::fs::symlink(target.path(), dir.path().join("linked")).unwrap();

        let (members, _) = scan_for_subprojects(dir.path());
        assert!(
            !members.iter().any(|m| m.relative_path.contains("linked")),
            "symlinks should be skipped in fallback"
        );
    }

    // ── Recursive detection tests ───────────────────────────────────

    #[test]
    fn recursive_detects_monorepo_ecosystems() {
        let dir = setup_dir();
        // Root package.json with workspace config and vite dependency (triggers AllowLocalhostAny)
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"mono","workspaces":["apps/*"],"devDependencies":{"vite":"^5"}}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("apps/backend")).unwrap();
        fs::write(
            dir.path().join("apps/backend/Cargo.toml"),
            "[package]\nname = \"backend\"\n",
        )
        .unwrap();

        let report = detect_project_recursive(dir.path());

        assert!(
            report.detections.iter().any(|d| d.name.contains("Node")),
            "root should detect Node"
        );
        assert_eq!(report.workspace_members.len(), 1);
        assert!(
            report.workspace_members[0]
                .detections
                .iter()
                .any(|d| d.name.contains("Rust")),
            "workspace member should detect Rust"
        );
        assert!(
            !report.suggestions.is_empty(),
            "vite should generate suggestions"
        );
        assert!(
            !report.provenance.is_empty(),
            "provenance should track suggestion origins"
        );
    }

    #[test]
    fn recursive_falls_back_to_heuristic() {
        let dir = setup_dir();
        fs::create_dir_all(dir.path().join("services/api")).unwrap();
        fs::write(
            dir.path().join("services/api/Cargo.toml"),
            "[package]\nname = \"api\"\n",
        )
        .unwrap();

        let report = detect_project_recursive(dir.path());
        assert!(
            !report.workspace_members.is_empty(),
            "fallback should find subprojects"
        );
        assert!(
            report.workspace_members[0].source == WorkspaceSource::Fallback,
            "should be marked as fallback"
        );
    }
}
