//! Runtime environment discovery for cplt.
//!
//! Probes the local environment to determine:
//! - Which auth mechanism Copilot will use
//! - Where Copilot CLI is installed and what native modules it has
//! - Which developer tools are available
//! - Which sandbox-critical paths exist
//!
//! All checks are read-only, local (no network), and fast (<500ms total).

use std::path::{Path, PathBuf};

use crate::sandbox::{DENIED_DOTFILES, DENIED_FILES};

// ── Result types ────────────────────────────────────────────────

/// Overall discovery result from all probes.
#[derive(Debug)]
pub struct Discovery {
    pub auth: AuthDiscovery,
    pub copilot: CopilotDiscovery,
    pub tools: ToolDiscovery,
    pub paths: PathDiscovery,
}

#[derive(Debug)]
pub struct AuthDiscovery {
    /// Which env var tokens are set (name only, never the value).
    pub env_tokens: Vec<String>,
    /// Whether `gh auth token` succeeds.
    pub gh_cli_auth: bool,
    /// Whether `~/.config/gh/hosts.yml` exists.
    pub gh_config_exists: bool,
    /// Whether `/usr/bin/security` exists and is executable.
    pub security_cli_exists: bool,
    /// Paths to discovered `keytar.node` files.
    pub keytar_nodes: Vec<PathBuf>,
}

#[derive(Debug)]
pub struct CopilotDiscovery {
    /// Resolved path to the `copilot` binary (after symlink resolution).
    pub binary_path: Option<PathBuf>,
    /// Copilot CLI version string (e.g. "1.0.21").
    pub version: Option<String>,
    /// All discovered native `.node` modules with their names.
    pub native_modules: Vec<NativeModule>,
}

#[derive(Debug)]
pub struct NativeModule {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug)]
pub struct ToolDiscovery {
    /// Discovered tools with their resolved paths.
    pub tools: Vec<ToolInfo>,
    /// Homebrew prefix (e.g. `/opt/homebrew` or `/usr/local`).
    pub homebrew_prefix: Option<PathBuf>,
    /// Which HOME_TOOL_DIRS actually exist on disk.
    pub existing_home_tool_dirs: Vec<String>,
}

#[derive(Debug)]
pub struct ToolInfo {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug)]
pub struct PathDiscovery {
    /// Sensitive dotfile dirs that actually exist (will be denied).
    pub existing_denied_dirs: Vec<String>,
    /// Sensitive files that actually exist (will be denied).
    pub existing_denied_files: Vec<String>,
    /// Whether ~/.copilot exists.
    pub copilot_dir_exists: bool,
    /// Whether ~/Library/Keychains exists.
    pub keychains_dir_exists: bool,
    /// Whether the project dir is inside a git repo.
    pub is_git_repo: bool,
    /// Whether /private/var/db/mds exists (Security framework).
    pub security_db_exists: bool,
}

// ── Auth discovery ──────────────────────────────────────────────

const AUTH_ENV_VARS: &[&str] = &["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"];

pub fn discover_auth(home_dir: &Path) -> AuthDiscovery {
    let env_tokens: Vec<String> = AUTH_ENV_VARS
        .iter()
        .filter(|var| std::env::var(var).is_ok_and(|v| !v.is_empty()))
        .map(|s| s.to_string())
        .collect();

    let gh_cli_auth = std::process::Command::new("gh")
        .args(["auth", "token"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    let gh_config_exists = home_dir.join(".config/gh/hosts.yml").exists();

    // macOS Keychain CLI — not applicable on Linux.
    #[cfg(target_os = "macos")]
    let security_cli_exists = Path::new("/usr/bin/security").exists();
    #[cfg(not(target_os = "macos"))]
    let security_cli_exists = false;

    let keytar_nodes = find_native_modules(home_dir, "keytar.node");

    AuthDiscovery {
        env_tokens,
        gh_cli_auth,
        gh_config_exists,
        security_cli_exists,
        keytar_nodes,
    }
}

impl AuthDiscovery {
    /// Returns true if at least one auth mechanism is available.
    pub fn any_auth_available(&self) -> bool {
        !self.env_tokens.is_empty()
            || self.gh_cli_auth
            || self.security_cli_exists
            || !self.keytar_nodes.is_empty()
    }
}

// ── Copilot CLI discovery ───────────────────────────────────────

pub fn discover_copilot(home_dir: &Path) -> CopilotDiscovery {
    let binary_path = which_resolved("copilot");

    let version = std::process::Command::new("copilot")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                let stdout = String::from_utf8_lossy(&o.stdout);
                // Parse "GitHub Copilot CLI 1.0.21." → "1.0.21"
                stdout
                    .split_whitespace()
                    .find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))
                    .map(|v| v.trim_end_matches('.').to_string())
            } else {
                None
            }
        });

    // Scan for all native modules across all versions
    let mut native_modules = Vec::new();
    for name in &["keytar.node", "pty.node", "computer.node"] {
        for path in find_native_modules(home_dir, name) {
            native_modules.push(NativeModule {
                name: name.to_string(),
                path,
            });
        }
    }
    // Deduplicate by name (keep the latest version path)
    native_modules.sort_by(|a, b| a.path.cmp(&b.path));
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    native_modules.retain(|m| {
        // Keep the last (highest version) of each name
        seen_names.insert(m.name.clone())
    });
    // We want the latest, so reverse-sort and re-dedup
    native_modules.sort_by(|a, b| b.path.cmp(&a.path));
    seen_names.clear();
    native_modules.retain(|m| seen_names.insert(m.name.clone()));

    CopilotDiscovery {
        binary_path,
        version,
        native_modules,
    }
}

// ── Tool discovery ──────────────────────────────────────────────

const TOOLS_TO_CHECK: &[&str] = &[
    "gh", "git", "node", "mise", "cargo", "python3", "java", "go", "gradle", "yarn", "pnpm",
];

use crate::sandbox::home_tool_dirs;

pub fn discover_tools(home_dir: &Path) -> ToolDiscovery {
    let tools: Vec<ToolInfo> = TOOLS_TO_CHECK
        .iter()
        .filter_map(|name| {
            which_resolved(name).map(|path| ToolInfo {
                name: name.to_string(),
                path,
            })
        })
        .collect();

    let homebrew_prefix = ["/opt/homebrew", "/usr/local/Homebrew"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists());

    let existing_home_tool_dirs: Vec<String> = home_tool_dirs()
        .iter()
        // Writable cache dirs are always included: tools create them on first use,
        // and the profile must permit the write that creates the directory.
        // Non-writable dirs (tool runtimes) are pruned to existing only.
        .filter(|d| d.write || home_dir.join(d.path).exists())
        .map(|d| d.path.to_string())
        .collect();

    ToolDiscovery {
        tools,
        homebrew_prefix,
        existing_home_tool_dirs,
    }
}

// ── Path discovery ──────────────────────────────────────────────

pub fn discover_paths(home_dir: &Path, project_dir: &Path) -> PathDiscovery {
    let existing_denied_dirs: Vec<String> = DENIED_DOTFILES
        .iter()
        .filter(|d| home_dir.join(d).exists())
        .map(|s| s.to_string())
        .collect();

    let existing_denied_files: Vec<String> = DENIED_FILES
        .iter()
        .filter(|f| home_dir.join(f).exists())
        .map(|s| s.to_string())
        .collect();

    let copilot_dir_exists = home_dir.join(".copilot").exists();

    // macOS-only: Keychain and Security framework database.
    #[cfg(target_os = "macos")]
    let keychains_dir_exists = home_dir.join("Library/Keychains").exists();
    #[cfg(not(target_os = "macos"))]
    let keychains_dir_exists = false;

    let is_git_repo = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(project_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    #[cfg(target_os = "macos")]
    let security_db_exists = Path::new("/private/var/db/mds").exists();
    #[cfg(not(target_os = "macos"))]
    let security_db_exists = false;

    PathDiscovery {
        existing_denied_dirs,
        existing_denied_files,
        copilot_dir_exists,
        keychains_dir_exists,
        is_git_repo,
        security_db_exists,
    }
}

// ── Full discovery ──────────────────────────────────────────────

/// Run all discovery probes and return a complete report.
pub fn discover_all(home_dir: &Path, project_dir: &Path) -> Discovery {
    Discovery {
        auth: discover_auth(home_dir),
        copilot: discover_copilot(home_dir),
        tools: discover_tools(home_dir),
        paths: discover_paths(home_dir, project_dir),
    }
}

// ── Reporting ───────────────────────────────────────────────────

const GREEN: &str = "\x1b[0;32m";
const YELLOW: &str = "\x1b[0;33m";
const RED: &str = "\x1b[0;31m";
const BLUE: &str = "\x1b[0;34m";
const BOLD: &str = "\x1b[1m";
const NC: &str = "\x1b[0m";

impl Discovery {
    /// Print a human-readable diagnostic report. Returns true if all critical checks pass.
    pub fn print_report(&self) -> bool {
        let mut critical_ok = true;

        // Auth section
        eprintln!("{BOLD}{BLUE}[doctor]{NC} {BOLD}Auth{NC}");
        if !self.auth.env_tokens.is_empty() {
            for var in &self.auth.env_tokens {
                eprintln!("  {GREEN}✓{NC} Env token: {var} is set");
            }
        } else {
            eprintln!(
                "  {YELLOW}⚠{NC} No env token set (COPILOT_GITHUB_TOKEN, GH_TOKEN, GITHUB_TOKEN)"
            );
        }
        if self.auth.gh_cli_auth {
            eprintln!("  {GREEN}✓{NC} gh CLI: authenticated (gh auth token succeeds)");
        } else if self.auth.gh_config_exists {
            eprintln!(
                "  {YELLOW}⚠{NC} gh CLI: config exists (~/.config/gh/hosts.yml) but gh auth token fails"
            );
        } else {
            eprintln!("  {YELLOW}⚠{NC} gh CLI: no config found (~/.config/gh/hosts.yml)");
        }
        #[cfg(target_os = "macos")]
        if self.auth.security_cli_exists {
            eprintln!("  {GREEN}✓{NC} Keychain CLI: /usr/bin/security exists");
        } else {
            eprintln!("  {YELLOW}⚠{NC} Keychain CLI: /usr/bin/security not found");
        }
        if !self.auth.keytar_nodes.is_empty() {
            eprintln!("  {GREEN}✓{NC} keytar.node: found in ~/.copilot/pkg/");
        } else {
            eprintln!("  {YELLOW}⚠{NC} keytar.node: not found in ~/.copilot/pkg/");
        }
        if !self.auth.any_auth_available() {
            eprintln!(
                "  {RED}✗{NC} No auth mechanism available — Copilot will fail to authenticate"
            );
            critical_ok = false;
        }
        eprintln!();

        // Copilot CLI section
        eprintln!("{BOLD}{BLUE}[doctor]{NC} {BOLD}Copilot CLI{NC}");
        if let Some(ref path) = self.copilot.binary_path {
            eprintln!("  {GREEN}✓{NC} Path: {}", path.display());
        } else {
            eprintln!("  {RED}✗{NC} copilot not found in PATH");
            critical_ok = false;
        }
        if let Some(ref version) = self.copilot.version {
            eprintln!("  {GREEN}✓{NC} Version: {version}");
        } else if self.copilot.binary_path.is_some() {
            eprintln!("  {YELLOW}⚠{NC} Could not determine version");
        }
        if !self.copilot.native_modules.is_empty() {
            let names: Vec<&str> = self
                .copilot
                .native_modules
                .iter()
                .map(|m| m.name.as_str())
                .collect();
            eprintln!("  {GREEN}✓{NC} Native modules: {}", names.join(", "));
        } else {
            eprintln!("  {YELLOW}⚠{NC} No native .node modules found in ~/.copilot/pkg/");
        }
        eprintln!();

        // Tools section
        eprintln!("{BOLD}{BLUE}[doctor]{NC} {BOLD}Tools{NC}");
        for tool in &self.tools.tools {
            eprintln!("  {GREEN}✓{NC} {}: {}", tool.name, tool.path.display());
        }
        let missing: Vec<&&str> = TOOLS_TO_CHECK
            .iter()
            .filter(|name| !self.tools.tools.iter().any(|t| t.name == **name))
            .collect();
        for name in &missing {
            eprintln!("  {YELLOW}⚠{NC} {name}: not found");
        }
        if let Some(ref prefix) = self.tools.homebrew_prefix {
            eprintln!("  {GREEN}✓{NC} Homebrew: {}", prefix.display());
        }
        if !self.tools.existing_home_tool_dirs.is_empty() {
            eprintln!(
                "  {GREEN}✓{NC} Tool dirs: ~/{}",
                self.tools.existing_home_tool_dirs.join(", ~/")
            );
        }
        let missing_dirs: Vec<&str> = home_tool_dirs()
            .iter()
            .map(|d| d.path)
            .filter(|p| !self.tools.existing_home_tool_dirs.iter().any(|e| e == p))
            .collect();
        if !missing_dirs.is_empty() {
            let joined: Vec<String> = missing_dirs.iter().map(|d| format!("~/{d}")).collect();
            eprintln!(
                "  {YELLOW}⚠{NC} Not found (skippable): {}",
                joined.join(", ")
            );
        }
        eprintln!();

        // Paths section
        eprintln!("{BOLD}{BLUE}[doctor]{NC} {BOLD}Sandbox paths{NC}");
        if self.paths.is_git_repo {
            eprintln!("  {GREEN}✓{NC} Project: inside a git repository");
        } else {
            eprintln!("  {YELLOW}⚠{NC} Project: not a git repo (using cwd)");
        }
        if self.paths.copilot_dir_exists {
            eprintln!("  {GREEN}✓{NC} ~/.copilot exists");
        } else {
            eprintln!("  {RED}✗{NC} ~/.copilot not found — Copilot CLI may not be installed");
            critical_ok = false;
        }
        #[cfg(target_os = "macos")]
        {
            if self.paths.keychains_dir_exists {
                eprintln!("  {GREEN}✓{NC} ~/Library/Keychains exists");
            } else {
                eprintln!("  {YELLOW}⚠{NC} ~/Library/Keychains not found");
            }
            if self.paths.security_db_exists {
                eprintln!("  {GREEN}✓{NC} /private/var/db/mds exists (Security framework)");
            }
        }

        let n_denied =
            self.paths.existing_denied_dirs.len() + self.paths.existing_denied_files.len();
        if n_denied > 0 {
            let dirs: Vec<String> = self
                .paths
                .existing_denied_dirs
                .iter()
                .map(|d| format!("~/{d}"))
                .collect();
            let files: Vec<String> = self
                .paths
                .existing_denied_files
                .iter()
                .map(|f| format!("~/{f}"))
                .collect();
            let all: Vec<&str> = dirs
                .iter()
                .chain(files.iter())
                .map(|s| s.as_str())
                .collect();
            eprintln!(
                "  {GREEN}✓{NC} Protected ({n_denied} found): {}",
                all.join(", ")
            );
        }
        eprintln!();

        // Sandbox mechanism section
        eprintln!("{BOLD}{BLUE}[doctor]{NC} {BOLD}Sandbox mechanism{NC}");
        #[cfg(target_os = "macos")]
        {
            let sandbox_exec_exists = Path::new("/usr/bin/sandbox-exec").exists();
            if sandbox_exec_exists {
                eprintln!("  {GREEN}✓{NC} Seatbelt: /usr/bin/sandbox-exec available");
            } else {
                eprintln!("  {RED}✗{NC} Seatbelt: /usr/bin/sandbox-exec not found");
                critical_ok = false;
            }
        }
        #[cfg(target_os = "linux")]
        {
            match std::fs::read_to_string("/sys/kernel/security/landlock/abi_version") {
                Ok(s) => {
                    let abi = s.trim();
                    eprintln!("  {GREEN}✓{NC} Landlock: ABI v{abi}");
                    if let Ok(v) = abi.parse::<u32>()
                        && v < 4
                    {
                        eprintln!(
                            "  {YELLOW}⚠{NC} Landlock ABI < v4: TCP port filtering unavailable (kernel < 6.7)"
                        );
                        eprintln!("      Network security provided by proxy only.");
                    }
                }
                Err(_) => {
                    eprintln!("  {RED}✗{NC} Landlock: not available");
                    eprintln!("      Requires Linux 5.13+ with Landlock enabled.");
                    eprintln!("      Check: cat /sys/kernel/security/lsm");
                    critical_ok = false;
                }
            }
            if let Ok(uname) = std::process::Command::new("uname").arg("-r").output()
                && uname.status.success()
            {
                let kernel = String::from_utf8_lossy(&uname.stdout);
                eprintln!("  {GREEN}✓{NC} Kernel: {}", kernel.trim());
            }
            eprintln!("  {GREEN}✓{NC} seccomp: available (built-in on modern kernels)");
        }
        eprintln!();

        // Summary
        if critical_ok {
            eprintln!("{GREEN}[doctor]{NC} All critical checks passed ✓");
        } else {
            eprintln!("{RED}[doctor]{NC} Critical issues found — sandbox may not work correctly");
        }

        critical_ok
    }
}

// ── Helpers ─────────────────────────────────────────────────────

/// Find the Copilot CLI package root from the resolved binary path.
///
/// Walks up at most 4 ancestor directories looking for a `package.json`
/// whose `"name"` field is `"@github/copilot"`. This handles any npm-like
/// package manager (npm, pnpm, yarn, bun) and any install prefix (`n`,
/// `nvm`, `volta`, `fnm`, `mise`, custom `--prefix`, etc.).
///
/// Returns `None` when:
/// - the binary is standalone (no `package.json` ancestor) — e.g. Homebrew cask
/// - the nearest `package.json` belongs to a different package
/// - the path would resolve to an unsafe root (`/`, `$HOME`, `/tmp`)
pub fn copilot_pkg_dir(copilot_bin: &Path, home_dir: &Path) -> Option<PathBuf> {
    let mut dir = copilot_bin.parent()?;
    for _ in 0..4 {
        let pkg_json = dir.join("package.json");
        if pkg_json.is_file() && is_copilot_package(&pkg_json) {
            // Reject overly broad directories
            if crate::is_unsafe_root(dir, home_dir) {
                return None;
            }
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
    None
}

/// Check if a `package.json` file belongs to `@github/copilot`.
fn is_copilot_package(pkg_json: &Path) -> bool {
    let Ok(contents) = std::fs::read_to_string(pkg_json) else {
        return false;
    };
    // Fast-path: skip JSON parsing if the package name isn't mentioned at all
    if !contents.contains("@github/copilot") {
        return false;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return false;
    };
    v.get("name").and_then(|n| n.as_str()) == Some("@github/copilot")
}

/// Discover the global git hooks directory from `core.hooksPath`.
///
/// Runs `git config --global core.hooksPath`, expands `~`, canonicalizes,
/// and validates the result. Returns `None` when:
/// - `core.hooksPath` is not set or the directory doesn't exist
/// - the path resolves to an unsafe root
/// - the path is not under `$HOME` (prevents arbitrary filesystem reads)
/// - the path is too shallow under `$HOME` (must be ≥3 components deep,
///   e.g. `~/.config/git/hooks` OK, `~/hooks` rejected as too broad)
pub fn git_hooks_path(home_dir: &Path) -> Option<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["config", "--global", "core.hooksPath"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if raw.is_empty() {
        return None;
    }
    // Expand ~ to home dir
    let expanded = if let Some(rest) = raw.strip_prefix("~/") {
        home_dir.join(rest)
    } else {
        PathBuf::from(&raw)
    };
    // Canonicalize to resolve symlinks
    let resolved = std::fs::canonicalize(&expanded).unwrap_or(expanded);
    // Safety: reject unsafe roots
    if crate::is_unsafe_root(&resolved, home_dir) {
        return None;
    }
    // Must be under $HOME — prevents punching read holes in arbitrary fs paths
    let suffix = resolved.strip_prefix(home_dir).ok()?;
    // Must be ≥3 components deep under $HOME to prevent overly broad reads.
    // e.g. ~/.config/git/hooks (3 components) is OK,
    //      ~/hooks (1 component) is too broad.
    if suffix.components().count() < 3 {
        return None;
    }
    if resolved.is_dir() {
        Some(resolved)
    } else {
        None
    }
}

/// Discover the Electron `.app` bundle used by a VS Code-installed Copilot CLI.
///
/// When Copilot is installed via the VS Code extension, the `copilot` binary is a
/// shell script shim that invokes VS Code's Electron runtime:
/// ```text
/// ELECTRON_RUN_AS_NODE=1 "/Applications/Visual Studio Code.app/.../Code Helper (Plugin)" \
///   "/path/to/copilotCLIShim.js" "$@"
/// ```
///
/// The Electron Framework (loaded by `dyld` at startup) lives inside the `.app`
/// bundle. Without read + `file-map-executable` access the sandbox blocks `dyld`
/// from loading it, causing an immediate `SIGABRT`.
///
/// Returns `<bundle>.app/Contents` (not the whole bundle) to limit scope.
/// Also works for VS Code Insiders, Cursor, Windsurf, and other Electron editors.
pub fn discover_electron_app(copilot_bin: &Path) -> Option<PathBuf> {
    // Only process shell scripts (text files), not compiled binaries
    let content = std::fs::read_to_string(copilot_bin).ok()?;
    if !content.starts_with("#!") {
        return None;
    }

    // Must be a Copilot CLI shim — not some unrelated script
    if !content.contains("copilotCLIShim.js") {
        return None;
    }

    // Extract the .app bundle from quoted paths in the shim.
    // The shim uses double-quoted paths: "/.../Something.app/.../Binary"
    for path in extract_quoted_paths(&content) {
        if let Some(app_contents) = find_app_contents(&path) {
            // Verify it's a real macOS app bundle
            if !app_contents.join("Info.plist").is_file() {
                continue;
            }
            // Canonicalize to resolve symlinks, then verify the resolved path
            // still has the .app/Contents structure. Without this check, a
            // symlinked Contents/ could resolve to an arbitrary directory and
            // punch a read+exec hole through the sandbox.
            let canonical = std::fs::canonicalize(&app_contents).unwrap_or(app_contents);
            if canonical.file_name().is_some_and(|n| n == "Contents")
                && canonical
                    .parent()
                    .and_then(|p| p.extension())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
            {
                return Some(canonical);
            }
        }
    }
    None
}

/// Extract double-quoted absolute paths from shell script content.
fn extract_quoted_paths(content: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            // Find the closing quote
            if let Some(end) = content[i + 1..].find('"') {
                let inner = &content[i + 1..i + 1 + end];
                if inner.starts_with('/') {
                    paths.push(PathBuf::from(inner));
                }
                i += 2 + end;
                continue;
            }
        }
        i += 1;
    }
    paths
}

/// Walk up from a path to find the outermost `<something>.app/Contents`.
/// Returns the `Contents` directory of the top-level `.app` bundle.
///
/// Electron editors nest helper apps inside the main bundle:
/// `Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/...`
/// We need the outermost bundle (`Visual Studio Code.app/Contents`) because that's
/// where `Electron Framework.framework` lives.
fn find_app_contents(path: &Path) -> Option<PathBuf> {
    let mut result: Option<PathBuf> = None;
    let mut current = path;
    loop {
        if let Some(name) = current.file_name()
            && name == "Contents"
            && let Some(parent) = current.parent()
            && parent
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
        {
            // Keep going — we want the outermost match
            result = Some(current.to_path_buf());
        }
        match current.parent() {
            Some(p) if p != current => current = p,
            _ => break,
        }
    }
    result
}

/// Resolve a command name to its real path (following symlinks).
fn which_resolved(name: &str) -> Option<PathBuf> {
    let output = std::process::Command::new("which")
        .arg(name)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    // Follow symlinks to get the real path
    std::fs::canonicalize(&path).ok().or(Some(path))
}

/// Find native `.node` modules matching a name in `~/.copilot/pkg/`.
fn find_native_modules(home_dir: &Path, module_name: &str) -> Vec<PathBuf> {
    let pkg_dir = home_dir.join(".copilot/pkg/universal");
    let Ok(entries) = std::fs::read_dir(&pkg_dir) else {
        return Vec::new();
    };

    let mut results = Vec::new();
    for entry in entries.flatten() {
        let prebuilds = entry.path().join("prebuilds");
        if !prebuilds.exists() {
            continue;
        }
        // Check all arch directories (darwin-arm64, darwin-x64, etc.)
        if let Ok(arch_entries) = std::fs::read_dir(&prebuilds) {
            for arch_entry in arch_entries.flatten() {
                let module_path = arch_entry.path().join(module_name);
                if module_path.exists() {
                    results.push(module_path);
                }
            }
        }
    }
    results.sort();
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_resolved_finds_common_tools() {
        // /usr/bin/true should always exist on macOS/Linux
        let result = which_resolved("true");
        assert!(result.is_some(), "should find 'true' in PATH");
    }

    #[test]
    fn which_resolved_returns_none_for_missing() {
        let result = which_resolved("nonexistent-tool-xyz-12345");
        assert!(result.is_none());
    }

    #[test]
    fn find_native_modules_handles_missing_dir() {
        let fake_home = PathBuf::from("/nonexistent/home/xyz");
        let result = find_native_modules(&fake_home, "keytar.node");
        assert!(result.is_empty());
    }

    #[test]
    fn auth_discovery_detects_env_vars() {
        // Temporarily set a test env var
        unsafe { std::env::set_var("COPILOT_GITHUB_TOKEN", "test-token-value") };
        let home = PathBuf::from(std::env::var("HOME").unwrap());
        let auth = discover_auth(&home);
        unsafe { std::env::remove_var("COPILOT_GITHUB_TOKEN") };

        assert!(
            auth.env_tokens
                .contains(&"COPILOT_GITHUB_TOKEN".to_string())
        );
    }

    #[test]
    fn auth_any_available_with_env_token() {
        let auth = AuthDiscovery {
            env_tokens: vec!["GH_TOKEN".to_string()],
            gh_cli_auth: false,
            gh_config_exists: false,
            security_cli_exists: false,
            keytar_nodes: vec![],
        };
        assert!(auth.any_auth_available());
    }

    #[test]
    fn auth_none_available_when_empty() {
        let auth = AuthDiscovery {
            env_tokens: vec![],
            gh_cli_auth: false,
            gh_config_exists: false,
            security_cli_exists: false,
            keytar_nodes: vec![],
        };
        assert!(!auth.any_auth_available());
    }

    #[test]
    fn tool_discovery_finds_git() {
        let home = PathBuf::from(std::env::var("HOME").unwrap());
        let tools = discover_tools(&home);
        assert!(
            tools.tools.iter().any(|t| t.name == "git"),
            "git should be found on any dev machine"
        );
    }

    #[test]
    fn path_discovery_runs_without_panic() {
        let home = PathBuf::from(std::env::var("HOME").unwrap());
        let project = std::env::current_dir().unwrap();
        let paths = discover_paths(&home, &project);
        // Just verify it doesn't panic and returns plausible results
        let _ = paths.copilot_dir_exists;
    }

    // ── Electron app discovery ──────────────────────────────────

    #[test]
    fn extract_quoted_paths_finds_absolute_paths() {
        let content = r#"#!/bin/sh
ELECTRON_RUN_AS_NODE=1 "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)" "/Users/test/copilotCLIShim.js" "$@"
"#;
        let paths = extract_quoted_paths(content);
        assert_eq!(paths.len(), 2);
        assert_eq!(
            paths[0],
            PathBuf::from(
                "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)"
            )
        );
        assert_eq!(paths[1], PathBuf::from("/Users/test/copilotCLIShim.js"));
    }

    #[test]
    fn extract_quoted_paths_skips_relative_and_variables() {
        let content = r#"#!/bin/sh
"relative/path" "$@" "/absolute/path"
"#;
        let paths = extract_quoted_paths(content);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], PathBuf::from("/absolute/path"));
    }

    #[test]
    fn find_app_contents_outermost_bundle() {
        // Nested .app bundles — should return the outermost .app/Contents
        let path = PathBuf::from(
            "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)",
        );
        let result = find_app_contents(&path);
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/Applications/Visual Studio Code.app/Contents")
        );
    }

    #[test]
    fn find_app_contents_single_bundle() {
        let path = PathBuf::from("/Applications/Cursor.app/Contents/MacOS/Cursor");
        let result = find_app_contents(&path);
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/Applications/Cursor.app/Contents")
        );
    }

    #[test]
    fn find_app_contents_no_bundle() {
        let path = PathBuf::from("/usr/local/bin/node");
        let result = find_app_contents(&path);
        assert!(result.is_none());
    }

    #[test]
    fn find_app_contents_home_applications() {
        let path = PathBuf::from(
            "/Users/test/Applications/Visual Studio Code - Insiders.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper",
        );
        let result = find_app_contents(&path);
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/Users/test/Applications/Visual Studio Code - Insiders.app/Contents")
        );
    }

    #[test]
    fn discover_electron_app_non_shim_returns_none() {
        // A compiled binary (non-text) should return None
        let tmp = std::env::temp_dir().join("cplt-test-binary");
        std::fs::write(&tmp, [0x7f, 0x45, 0x4c, 0x46]).unwrap(); // ELF magic
        let result = discover_electron_app(&tmp);
        std::fs::remove_file(&tmp).ok();
        assert!(result.is_none());
    }

    #[test]
    fn discover_electron_app_non_copilot_shim_returns_none() {
        // A shell script without copilotCLIShim.js marker
        let tmp = std::env::temp_dir().join("cplt-test-non-copilot");
        std::fs::write(&tmp, "#!/bin/sh\necho hello\n").unwrap();
        let result = discover_electron_app(&tmp);
        std::fs::remove_file(&tmp).ok();
        assert!(result.is_none());
    }
}
