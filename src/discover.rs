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

    let security_cli_exists = Path::new("/usr/bin/security").exists();

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

const TOOLS_TO_CHECK: &[&str] = &["gh", "git", "node", "mise", "cargo"];

/// Tool directories under $HOME that get read access (must match sandbox.rs).
const HOME_TOOL_DIRS: &[&str] = &[
    ".local",
    ".mise",
    ".nvm",
    ".cargo",
    ".rustup",
    ".gradle",
    ".m2",
    ".sdkman",
    "go/bin",
    "go/pkg",
    "Library/Caches",
    "Library/pnpm",
];

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

    let existing_home_tool_dirs: Vec<String> = HOME_TOOL_DIRS
        .iter()
        .filter(|dir| home_dir.join(dir).exists())
        .map(|s| s.to_string())
        .collect();

    ToolDiscovery {
        tools,
        homebrew_prefix,
        existing_home_tool_dirs,
    }
}

// ── Path discovery ──────────────────────────────────────────────

/// Must match sandbox.rs DENIED_DOTFILES.
const DENIED_DOTFILES: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".nais",
    ".password-store",
    ".config/gcloud",
    ".config/op",
    ".terraform.d",
];

/// Must match sandbox.rs DENIED_FILES.
const DENIED_FILES: &[&str] = &[
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".gem/credentials",
    ".vault-token",
];

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
    let keychains_dir_exists = home_dir.join("Library/Keychains").exists();

    let is_git_repo = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(project_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    let security_db_exists = Path::new("/private/var/db/mds").exists();

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
        let missing_dirs: Vec<&&str> = HOME_TOOL_DIRS
            .iter()
            .filter(|d| !self.tools.existing_home_tool_dirs.iter().any(|e| e == *d))
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
        if self.paths.keychains_dir_exists {
            eprintln!("  {GREEN}✓{NC} ~/Library/Keychains exists");
        } else {
            eprintln!("  {YELLOW}⚠{NC} ~/Library/Keychains not found");
        }
        if self.paths.security_db_exists {
            eprintln!("  {GREEN}✓{NC} /private/var/db/mds exists (Security framework)");
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
}
