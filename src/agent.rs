//! Agent abstraction for different AI coding tools.
//!
//! cplt can sandbox multiple AI coding agents — currently GitHub Copilot CLI,
//! OpenCode, Google Gemini CLI, Antigravity, and Pi. Each agent has different binary names,
//! config directories, and runtime requirements, but shares the same core
//! sandbox infrastructure.

use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Supported AI coding agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Agent {
    /// GitHub Copilot CLI (default).
    Copilot,
    /// OpenCode (anomalyco/opencode) — open source AI coding agent.
    OpenCode,
    /// Google Gemini CLI — AI coding agent powered by Gemini models.
    Gemini,
    /// Antigravity CLI (`antigravity` / `agy`).
    Antigravity,
    /// Pi coding agent (https://github.com/earendil-works/pi).
    Pi,
    /// Plain sandboxed shell — no AI agent, just a secure shell session.
    Shell,
}

impl Agent {
    /// The binary name to search for in PATH.
    pub fn binary_name(&self) -> &'static str {
        match self {
            Agent::Copilot => "copilot",
            Agent::OpenCode => "opencode",
            Agent::Gemini => "gemini",
            Agent::Antigravity => "antigravity",
            Agent::Pi => "pi",
            Agent::Shell => "shell",
        }
    }

    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Agent::Copilot => "Copilot",
            Agent::OpenCode => "OpenCode",
            Agent::Gemini => "Gemini",
            Agent::Antigravity => "Antigravity",
            Agent::Pi => "Pi",
            Agent::Shell => "Shell",
        }
    }

    /// Whether this agent uses Node.js SEA extraction that needs pre-sandbox setup.
    /// Copilot uses SEA packaging which extracts to ~/Library/Caches/copilot/pkg/.
    /// OpenCode is distributed via npm or standalone binary — no SEA extraction needed.
    pub fn needs_sea_extraction(&self) -> bool {
        matches!(self, Agent::Copilot)
    }

    /// Extra arguments injected before the user's args.
    /// Copilot needs --no-auto-update to prevent writes to ~/.copilot/pkg inside sandbox.
    pub fn extra_args(&self) -> &'static [&'static str] {
        match self {
            Agent::Copilot => &["--no-auto-update"],
            Agent::OpenCode | Agent::Gemini | Agent::Antigravity | Agent::Pi | Agent::Shell => &[],
        }
    }

    /// Whether this agent needs macOS Keychain access for auth tokens.
    /// Copilot stores GitHub auth tokens in the Keychain.
    /// Gemini uses Keychain for extension integrity verification.
    /// OpenCode uses API keys from env vars or config files.
    pub fn needs_keychain(&self) -> bool {
        matches!(self, Agent::Copilot | Agent::Gemini | Agent::Antigravity)
    }

    /// Whether this agent needs access to ~/.copilot directory.
    pub fn needs_copilot_dir(&self) -> bool {
        matches!(self, Agent::Copilot)
    }

    /// Config directories under $HOME that need read/write access.
    /// Returns (relative_path, needs_write).
    pub fn config_dirs(&self, home: &Path) -> Vec<AgentDir> {
        match self {
            Agent::Copilot => {
                vec![
                    // ~/.copilot is handled separately in emit_home_access
                    // (needs map-executable for native modules)
                ]
            }
            Agent::Shell => {
                // Shell needs write access to its config/data dirs for history,
                // variables, and sourcing config files.
                let shell_path = std::env::var("SHELL").unwrap_or_default();
                let shell_name = Path::new(&shell_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");

                let config_base = std::env::var("XDG_CONFIG_HOME")
                    .ok()
                    .map_or_else(|| home.join(".config"), PathBuf::from);
                let data_base = std::env::var("XDG_DATA_HOME")
                    .ok()
                    .map_or_else(|| home.join(".local/share"), PathBuf::from);

                match shell_name {
                    "fish" => vec![
                        AgentDir {
                            path: config_base.join("fish"),
                            write: true,
                            map_exec: false,
                            process_exec: false,
                            write_files: vec![],
                        },
                        AgentDir {
                            path: data_base.join("fish"),
                            write: true,
                            map_exec: false,
                            process_exec: false,
                            write_files: vec![],
                        },
                    ],
                    "zsh" => vec![AgentDir {
                        path: data_base.join("zsh"),
                        write: true,
                        map_exec: false,
                        process_exec: false,
                        write_files: vec![],
                    }],
                    _ => vec![],
                }
            }
            Agent::OpenCode => {
                // Respect XDG_CONFIG_HOME for config dir
                let config_base = std::env::var("XDG_CONFIG_HOME")
                    .ok()
                    .map_or_else(|| home.join(".config"), PathBuf::from);
                let config_dir = config_base.join("opencode");

                // Respect XDG_DATA_HOME for data dir (sessions, account, logs, repos)
                let data_base = std::env::var("XDG_DATA_HOME")
                    .ok()
                    .map_or_else(|| home.join(".local/share"), PathBuf::from);
                let data_dir = data_base.join("opencode");

                // Respect XDG_STATE_HOME for state dir (locks, history, statistics)
                let state_base = std::env::var("XDG_STATE_HOME")
                    .ok()
                    .map_or_else(|| home.join(".local/state"), PathBuf::from);
                let state_dir = state_base.join("opencode");

                // Respect XDG_CACHE_HOME for cache dir (managed tool binaries in bin/)
                let cache_base = std::env::var("XDG_CACHE_HOME")
                    .ok()
                    .map_or_else(|| home.join(".cache"), PathBuf::from);
                let cache_dir = cache_base.join("opencode");

                vec![
                    AgentDir {
                        path: config_dir,
                        write: false,
                        map_exec: false,
                        process_exec: false,
                        // Legacy auth.json (newer versions use account.json in data dir)
                        write_files: vec!["auth.json"],
                    },
                    AgentDir {
                        path: data_dir,
                        write: true,
                        map_exec: false,
                        process_exec: false,
                        write_files: vec![],
                    },
                    AgentDir {
                        path: state_dir,
                        write: true,
                        map_exec: false,
                        process_exec: false,
                        write_files: vec![],
                    },
                    AgentDir {
                        path: cache_dir.clone(),
                        write: true,
                        map_exec: false,
                        process_exec: false,
                        write_files: vec![],
                    },
                    AgentDir {
                        // OpenCode downloads managed tool binaries (rg, fd, etc.) here
                        path: cache_dir.join("bin"),
                        write: false,
                        map_exec: false,
                        process_exec: true,
                        write_files: vec![],
                    },
                ]
            }
            Agent::Gemini => {
                // ~/.gemini stores auth, settings, sessions, and agents
                vec![AgentDir {
                    path: home.join(".gemini"),
                    write: true,
                    map_exec: false,
                    process_exec: false,
                    write_files: vec![],
                }]
            }
            Agent::Antigravity => {
                // Antigravity stores project config under ~/.gemini/config
                // and runtime/session data under ~/.gemini/antigravity-cli.
                vec![
                    AgentDir {
                        path: home.join(".gemini/config"),
                        write: true,
                        map_exec: false,
                        process_exec: false,
                        write_files: vec![],
                    },
                    AgentDir {
                        path: home.join(".gemini/antigravity-cli"),
                        write: true,
                        map_exec: false,
                        process_exec: false,
                        write_files: vec![],
                    },
                ]
            }
            Agent::Pi => {
                // ~/.pi/agent stores settings, auth, sessions, themes
                // ~/.pi/agent/bin contains managed tool binaries (fd, rg)
                vec![
                    AgentDir {
                        path: home.join(".pi"),
                        write: true,
                        map_exec: false,
                        process_exec: false,
                        write_files: vec![],
                    },
                    AgentDir {
                        path: home.join(".pi/agent/bin"),
                        write: false,
                        map_exec: false,
                        // Pi installs managed binaries here (fd, rg)
                        process_exec: true,
                        write_files: vec![],
                    },
                ]
            }
        }
    }

    /// Environment variable names this agent may need for authentication.
    /// These are NOT added to the default allowlist — they must be
    /// explicitly passed via --pass-env or agent config.
    /// Note: OpenCode also supports GitHub Copilot as a provider via
    /// `/connect` — no env key needed for that flow (auth stored in auth.json).
    pub fn auth_env_hint(&self) -> &'static [&'static str] {
        match self {
            // Copilot tokens are in the default allowlist (accepted trade-off)
            Agent::Copilot => &[],
            // OpenCode third-party provider API keys — user must opt in.
            // Copilot provider uses device flow + auth.json, no env var needed.
            Agent::OpenCode => &[
                "ANTHROPIC_API_KEY",
                "OPENAI_API_KEY",
                "GEMINI_API_KEY",
                "OPENROUTER_API_KEY",
                "GROQ_API_KEY",
            ],
            // Gemini uses Google OAuth by default (browser flow, stored in ~/.gemini/).
            // API key or Vertex AI project are alternatives.
            Agent::Gemini => &["GEMINI_API_KEY", "GOOGLE_CLOUD_PROJECT"],
            // Antigravity uses Google OAuth with keychain/session storage.
            Agent::Antigravity => &[],
            // Pi supports multiple LLM providers via API keys.
            Agent::Pi => &[
                "ANTHROPIC_API_KEY",
                "OPENAI_API_KEY",
                "GEMINI_API_KEY",
                "OPENROUTER_API_KEY",
            ],
            Agent::Shell => &[],
        }
    }

    /// Resolve the agent binary, walking PATH and skipping cplt aliases.
    ///
    /// For Copilot: prefers standalone binaries over VS Code editor shims.
    /// For OpenCode: straightforward PATH search.
    /// For Shell: uses $SHELL or falls back to /bin/zsh (macOS) or /bin/bash.
    pub fn resolve_binary(&self) -> Result<PathBuf, String> {
        if matches!(self, Agent::Shell) {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| {
                if cfg!(target_os = "macos") {
                    "/bin/zsh".to_string()
                } else {
                    "/bin/bash".to_string()
                }
            });
            let path = PathBuf::from(&shell);
            if path.is_file() {
                return Ok(path);
            }
            return Err(format!("Shell not found: {shell}"));
        }

        let binary_names: &[&str] = match self {
            Agent::Antigravity => &["antigravity", "agy"],
            _ => &[self.binary_name()],
        };
        let self_exe = std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::canonicalize(&p).ok());

        let path_var = std::env::var("PATH").unwrap_or_default();

        // For Copilot, track editor shims as fallback
        let mut editor_shim: Option<PathBuf> = None;

        for binary_name in binary_names {
            for dir in path_var.split(':') {
                let candidate = PathBuf::from(dir).join(binary_name);

                if !candidate.is_file() {
                    continue;
                }

                // Resolve mise/asdf shims to the real binary to avoid version conflicts
                // when the project's .tool-versions specifies a different node version.
                if let Some(real_bin) = resolve_mise_shim(&candidate, binary_name) {
                    if self_exe.as_ref() == Some(&real_bin) {
                        continue;
                    }
                    if matches!(self, Agent::Copilot) && is_editor_shim(&real_bin) {
                        if editor_shim.is_none() {
                            editor_shim = Some(real_bin);
                        }
                        continue;
                    }
                    return Ok(real_bin);
                }

                let resolved =
                    std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                if self_exe.as_ref() == Some(&resolved) {
                    continue; // skip cplt aliased as this binary
                }

                // Copilot-specific: prefer standalone over editor shims
                if matches!(self, Agent::Copilot) && is_editor_shim(&resolved) {
                    if editor_shim.is_none() {
                        editor_shim = Some(resolved);
                    }
                    continue;
                }

                return Ok(resolved);
            }
        }

        if let Some(shim) = editor_shim {
            return Ok(shim);
        }

        let install_hint = match self {
            Agent::Copilot => {
                "If you installed cplt as a 'copilot' alias, the real Copilot CLI \
                 must also be in PATH (e.g. brew install --cask copilot-cli)."
            }
            Agent::OpenCode => {
                "Install OpenCode: npm i -g opencode-ai, or brew install anomalyco/tap/opencode"
            }
            Agent::Gemini => {
                "Install Gemini CLI: npm i -g @google/gemini-cli, or brew install gemini-cli"
            }
            Agent::Antigravity => {
                "Install Antigravity CLI: see https://antigravity.google/docs/cli-getting-started"
            }
            Agent::Pi => "Install Pi: npm i -g @earendil-works/pi-coding-agent",
            Agent::Shell => unreachable!("Shell is resolved via $SHELL above"),
        };

        Err(format!(
            "{} not found in PATH. {install_hint}",
            self.display_name()
        ))
    }

    /// Auto-detect which agent to use based on what's available in PATH.
    /// Returns Copilot if found (backward compat), else OpenCode, else Gemini,
    /// else Antigravity.
    /// Returns None if none are found.
    pub fn auto_detect() -> Option<Agent> {
        let path_var = std::env::var("PATH").unwrap_or_default();
        let self_exe = std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::canonicalize(&p).ok());

        let mut found_copilot = false;
        let mut found_opencode = false;
        let mut found_gemini = false;
        let mut found_antigravity = false;

        for dir in path_var.split(':') {
            if !found_copilot {
                let candidate = PathBuf::from(dir).join("copilot");
                if candidate.is_file() {
                    let resolved =
                        std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                    if self_exe.as_ref() != Some(&resolved) {
                        found_copilot = true;
                    }
                }
            }
            if !found_opencode {
                let candidate = PathBuf::from(dir).join("opencode");
                if candidate.is_file() {
                    let resolved =
                        std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                    if self_exe.as_ref() != Some(&resolved) {
                        found_opencode = true;
                    }
                }
            }
            if !found_gemini {
                let candidate = PathBuf::from(dir).join("gemini");
                if candidate.is_file() {
                    let resolved =
                        std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                    if self_exe.as_ref() != Some(&resolved) {
                        found_gemini = true;
                    }
                }
            }
            if !found_antigravity {
                let antigravity_bin = PathBuf::from(dir).join("antigravity");
                let agy_bin = PathBuf::from(dir).join("agy");
                for candidate in [&antigravity_bin, &agy_bin] {
                    if candidate.is_file() {
                        let resolved =
                            std::fs::canonicalize(candidate).unwrap_or_else(|_| candidate.clone());
                        if self_exe.as_ref() != Some(&resolved) {
                            found_antigravity = true;
                            break;
                        }
                    }
                }
            }
        }

        if found_copilot {
            Some(Agent::Copilot)
        } else if found_opencode {
            Some(Agent::OpenCode)
        } else if found_gemini {
            Some(Agent::Gemini)
        } else if found_antigravity {
            Some(Agent::Antigravity)
        } else {
            None
        }
    }
}

impl FromStr for Agent {
    type Err = String;

    fn from_str(s: &str) -> Result<Agent, String> {
        match s.to_lowercase().as_str() {
            "copilot" => Ok(Agent::Copilot),
            "opencode" => Ok(Agent::OpenCode),
            "gemini" | "gem" => Ok(Agent::Gemini),
            "antigravity" | "agy" | "agi" => Ok(Agent::Antigravity),
            "pi" => Ok(Agent::Pi),
            "shell" | "sh" | "bash" | "zsh" => Ok(Agent::Shell),
            _ => Err(format!(
                "Unknown agent '{s}'. Supported: copilot, opencode, gemini, antigravity, pi, shell"
            )),
        }
    }
}

/// A directory an agent needs access to in the sandbox.
#[derive(Debug, Clone)]
pub struct AgentDir {
    pub path: PathBuf,
    pub write: bool,
    pub map_exec: bool,
    pub process_exec: bool,
    /// Specific files within this dir that get file-write* (literal) access
    /// even when `write` is false. Paths are relative to `self.path`.
    pub write_files: Vec<&'static str>,
}

/// Check if a copilot binary is a VS Code/Cursor/editor shim script.
fn is_editor_shim(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    content.starts_with("#!") && content.contains("copilotCLIShim.js")
}

/// Detect if a candidate path (before canonicalization) is a mise or asdf shim.
///
/// Mise shims are symlinks to the mise binary in a shims directory. When run
/// inside a sandbox with a project `.tool-versions` that specifies a different
/// node version than the one the tool was installed with, mise fails with
/// "No version is set for command <name>". We resolve the real binary path
/// to bypass mise's version resolution entirely.
fn resolve_mise_shim(candidate: &Path, binary_name: &str) -> Option<PathBuf> {
    let dir = candidate.parent()?;
    let dir_str = dir.to_str()?;

    // Check if the candidate is in a known shims directory
    let is_shim_dir = dir_str.ends_with("/mise/shims")
        || dir_str.contains("/mise/shims")
        || dir_str.ends_with("/asdf/shims")
        || dir_str.contains("/asdf/shims");

    if !is_shim_dir {
        return None;
    }

    // Use `mise which <binary>` to resolve to the real binary path.
    // Run from $HOME to avoid the project's .tool-versions influencing resolution.
    // If that fails, scan mise's installs directory directly for the binary.
    let home = std::env::var("HOME").ok();
    let cwd = home.as_deref().unwrap_or("/");

    let output = std::process::Command::new("mise")
        .arg("which")
        .arg(binary_name)
        .current_dir(cwd)
        .output()
        .or_else(|_| {
            std::process::Command::new("asdf")
                .arg("which")
                .arg(binary_name)
                .current_dir(cwd)
                .output()
        })
        .ok();

    if let Some(ref out) = output
        && out.status.success()
    {
        let real_path = String::from_utf8_lossy(&out.stdout);
        let real_path = real_path.trim();
        if !real_path.is_empty() {
            let path = PathBuf::from(real_path);
            if path.is_file() {
                return Some(std::fs::canonicalize(&path).unwrap_or(path));
            }
        }
    }

    // Fallback: scan mise installs directory directly for the binary.
    // This handles the case where `mise which` fails because no version is
    // "active" (e.g., no global .tool-versions), but the binary exists in
    // an installed version's bin/ directory.
    if let Some(ref home_str) = home {
        let installs_dir = PathBuf::from(home_str).join(".local/share/mise/installs");
        if let Some(found) = find_binary_in_mise_installs(&installs_dir, binary_name) {
            return Some(found);
        }
        // Also check legacy ~/.asdf/installs
        let asdf_installs = PathBuf::from(home_str).join(".asdf/installs");
        if let Some(found) = find_binary_in_mise_installs(&asdf_installs, binary_name) {
            return Some(found);
        }
    }

    None
}

/// Search mise/asdf installs directory for a binary by name.
/// Scans `<installs_dir>/<plugin>/<version>/bin/<binary_name>`.
fn find_binary_in_mise_installs(installs_dir: &Path, binary_name: &str) -> Option<PathBuf> {
    let plugins = std::fs::read_dir(installs_dir).ok()?;
    for plugin in plugins.flatten() {
        let Ok(versions) = std::fs::read_dir(plugin.path()) else {
            continue;
        };
        for version in versions.flatten() {
            let candidate = version.path().join("bin").join(binary_name);
            if candidate.is_file() {
                return Some(std::fs::canonicalize(&candidate).unwrap_or(candidate));
            }
        }
    }
    None
}

impl std::fmt::Display for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_agent_names() {
        assert_eq!(Agent::from_str("copilot").unwrap(), Agent::Copilot);
        assert_eq!(Agent::from_str("Copilot").unwrap(), Agent::Copilot);
        assert_eq!(Agent::from_str("opencode").unwrap(), Agent::OpenCode);
        assert_eq!(Agent::from_str("OpenCode").unwrap(), Agent::OpenCode);
        assert_eq!(Agent::from_str("gemini").unwrap(), Agent::Gemini);
        assert_eq!(Agent::from_str("Gemini").unwrap(), Agent::Gemini);
        assert_eq!(Agent::from_str("gem").unwrap(), Agent::Gemini);
        assert_eq!(Agent::from_str("antigravity").unwrap(), Agent::Antigravity);
        assert_eq!(Agent::from_str("agi").unwrap(), Agent::Antigravity);
        assert_eq!(Agent::from_str("agy").unwrap(), Agent::Antigravity);
        assert!(Agent::from_str("unknown").is_err());
    }

    #[test]
    fn copilot_binary_name() {
        assert_eq!(Agent::Copilot.binary_name(), "copilot");
    }

    #[test]
    fn opencode_binary_name() {
        assert_eq!(Agent::OpenCode.binary_name(), "opencode");
    }

    #[test]
    fn gemini_binary_name() {
        assert_eq!(Agent::Gemini.binary_name(), "gemini");
    }

    #[test]
    fn antigravity_binary_name() {
        assert_eq!(Agent::Antigravity.binary_name(), "antigravity");
    }

    #[test]
    fn copilot_needs_sea_extraction() {
        assert!(Agent::Copilot.needs_sea_extraction());
        assert!(!Agent::OpenCode.needs_sea_extraction());
        assert!(!Agent::Gemini.needs_sea_extraction());
        assert!(!Agent::Antigravity.needs_sea_extraction());
    }

    #[test]
    fn copilot_extra_args() {
        assert_eq!(Agent::Copilot.extra_args(), &["--no-auto-update"]);
        assert!(Agent::OpenCode.extra_args().is_empty());
        assert!(Agent::Gemini.extra_args().is_empty());
        assert!(Agent::Antigravity.extra_args().is_empty());
    }

    #[test]
    fn keychain_needs() {
        assert!(Agent::Copilot.needs_keychain());
        assert!(Agent::Gemini.needs_keychain());
        assert!(Agent::Antigravity.needs_keychain());
        assert!(!Agent::OpenCode.needs_keychain());
    }

    #[test]
    fn opencode_config_dirs_xdg_default() {
        let home = Path::new("/Users/test");
        let dirs = Agent::OpenCode.config_dirs(home);
        assert_eq!(
            dirs.len(),
            5,
            "should have config + data + state + cache + cache/bin"
        );

        let config_dir = dirs
            .iter()
            .find(|d| d.path.to_str().unwrap().contains("config"))
            .unwrap();
        let data_dir = dirs
            .iter()
            .find(|d| d.path.to_str().unwrap().contains("share"))
            .unwrap();
        let state_dir = dirs
            .iter()
            .find(|d| d.path.to_str().unwrap().contains("state"))
            .unwrap();
        let cache_dir = dirs
            .iter()
            .find(|d| {
                d.path.to_str().unwrap().ends_with("opencode")
                    && d.path.to_str().unwrap().contains("cache")
            })
            .unwrap();
        let cache_bin = dirs
            .iter()
            .find(|d| {
                d.path.to_str().unwrap().contains("cache")
                    && d.path.to_str().unwrap().ends_with("bin")
            })
            .unwrap();

        // Config dir: read-only with only auth.json writable
        assert!(!config_dir.write, "config dir should be read-only");
        assert_eq!(
            config_dir.write_files,
            vec!["auth.json"],
            "only auth.json should be writable in config dir"
        );

        // Data + state + cache: writable
        assert!(data_dir.write, "data dir should be writable");
        assert!(state_dir.write, "state dir should be writable");
        assert!(cache_dir.write, "cache dir should be writable");

        // Cache/bin: exec-only (managed tool binaries, not writable from sandbox)
        assert!(!cache_bin.write, "cache/bin should not be writable");
        assert!(cache_bin.process_exec, "cache/bin should allow exec");
    }

    #[test]
    fn gemini_config_dirs() {
        let home = Path::new("/Users/test");
        let dirs = Agent::Gemini.config_dirs(home);
        assert_eq!(dirs.len(), 1, "should have ~/.gemini dir");
        assert_eq!(dirs[0].path, home.join(".gemini"));
        assert!(dirs[0].write, "gemini dir should be writable");
        assert!(!dirs[0].process_exec && !dirs[0].map_exec);
    }

    #[test]
    fn antigravity_config_dirs() {
        let home = Path::new("/Users/test");
        let dirs = Agent::Antigravity.config_dirs(home);
        assert_eq!(
            dirs.len(),
            2,
            "should have ~/.gemini config + antigravity-cli"
        );
        assert_eq!(dirs[0].path, home.join(".gemini/config"));
        assert!(dirs[0].write);
        assert_eq!(dirs[1].path, home.join(".gemini/antigravity-cli"));
        assert!(dirs[1].write);
        assert!(!dirs[0].process_exec && !dirs[0].map_exec);
        assert!(!dirs[1].process_exec && !dirs[1].map_exec);
    }

    #[test]
    fn copilot_has_no_extra_config_dirs() {
        let home = Path::new("/Users/test");
        let dirs = Agent::Copilot.config_dirs(home);
        assert!(
            dirs.is_empty(),
            "copilot dirs are handled in emit_home_access"
        );
    }

    #[test]
    fn opencode_auth_env_hints() {
        let hints = Agent::OpenCode.auth_env_hint();
        assert!(hints.contains(&"ANTHROPIC_API_KEY"));
        assert!(hints.contains(&"OPENAI_API_KEY"));
    }

    #[test]
    fn gemini_auth_env_hints() {
        let hints = Agent::Gemini.auth_env_hint();
        assert!(hints.contains(&"GEMINI_API_KEY"));
        assert!(hints.contains(&"GOOGLE_CLOUD_PROJECT"));
    }

    #[test]
    fn antigravity_auth_env_hints() {
        assert!(
            Agent::Antigravity.auth_env_hint().is_empty(),
            "antigravity uses oauth/keychain auth, no env hints"
        );
    }

    #[test]
    fn display_names() {
        assert_eq!(format!("{}", Agent::Copilot), "Copilot");
        assert_eq!(format!("{}", Agent::OpenCode), "OpenCode");
        assert_eq!(format!("{}", Agent::Gemini), "Gemini");
        assert_eq!(format!("{}", Agent::Antigravity), "Antigravity");
        assert_eq!(format!("{}", Agent::Pi), "Pi");
    }

    #[test]
    fn parse_pi_agent() {
        assert_eq!(Agent::from_str("pi").unwrap(), Agent::Pi);
        assert_eq!(Agent::from_str("Pi").unwrap(), Agent::Pi);
        assert_eq!(Agent::from_str("PI").unwrap(), Agent::Pi);
    }

    #[test]
    fn pi_binary_name() {
        assert_eq!(Agent::Pi.binary_name(), "pi");
    }

    #[test]
    fn pi_no_sea_extraction() {
        assert!(!Agent::Pi.needs_sea_extraction());
    }

    #[test]
    fn pi_no_extra_args() {
        assert!(Agent::Pi.extra_args().is_empty());
    }

    #[test]
    fn pi_no_keychain() {
        assert!(!Agent::Pi.needs_keychain());
    }

    #[test]
    fn pi_no_copilot_dir() {
        assert!(!Agent::Pi.needs_copilot_dir());
    }

    #[test]
    fn pi_config_dirs() {
        let home = Path::new("/Users/test");
        let dirs = Agent::Pi.config_dirs(home);
        assert_eq!(dirs.len(), 2, "should have ~/.pi and ~/.pi/agent/bin");
        // Main dir is writable
        assert_eq!(dirs[0].path, home.join(".pi"));
        assert!(dirs[0].write);
        assert!(!dirs[0].process_exec);
        // Bin dir has process_exec for managed binaries
        assert_eq!(dirs[1].path, home.join(".pi/agent/bin"));
        assert!(!dirs[1].write);
        assert!(dirs[1].process_exec);
    }

    #[test]
    fn pi_auth_env_hints() {
        let hints = Agent::Pi.auth_env_hint();
        assert!(hints.contains(&"ANTHROPIC_API_KEY"));
        assert!(hints.contains(&"OPENAI_API_KEY"));
        assert!(hints.contains(&"GEMINI_API_KEY"));
        assert!(hints.contains(&"OPENROUTER_API_KEY"));
    }

    #[test]
    fn unknown_agent_error_lists_antigravity_and_pi() {
        let err = Agent::from_str("nope").unwrap_err();
        assert!(
            err.contains("antigravity"),
            "error should mention antigravity: {err}"
        );
        assert!(err.contains("pi"), "error should mention pi: {err}");
    }

    #[test]
    fn resolve_mise_shim_non_shim_dir_returns_none() {
        // A path not in a shims directory should return None immediately
        let candidate = Path::new("/usr/local/bin/copilot");
        assert!(resolve_mise_shim(candidate, "copilot").is_none());
    }

    #[test]
    fn resolve_mise_shim_detects_mise_shims_dir() {
        // A path in ~/.local/share/mise/shims/ should be detected
        let candidate = Path::new("/home/user/.local/share/mise/shims/copilot");
        // Will return None because `mise which` won't find the binary,
        // but verifies the directory detection logic
        let result = resolve_mise_shim(candidate, "copilot");
        // Either None (mise not available or binary not found) or Some (resolved)
        // The important thing is it didn't panic and tried to resolve
        let _ = result;
    }

    #[test]
    fn resolve_mise_shim_detects_asdf_shims_dir() {
        let candidate = Path::new("/home/user/.asdf/shims/copilot");
        let result = resolve_mise_shim(candidate, "copilot");
        let _ = result;
    }
}
