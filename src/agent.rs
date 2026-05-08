//! Agent abstraction for different AI coding tools.
//!
//! cplt can sandbox multiple AI coding agents — currently GitHub Copilot CLI,
//! OpenCode, and Google Gemini CLI. Each agent has different binary names,
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
            Agent::Shell => "shell",
        }
    }

    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Agent::Copilot => "Copilot",
            Agent::OpenCode => "OpenCode",
            Agent::Gemini => "Gemini",
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
            Agent::OpenCode | Agent::Gemini | Agent::Shell => &[],
        }
    }

    /// Whether this agent needs macOS Keychain access for auth tokens.
    /// Copilot stores GitHub auth tokens in the Keychain.
    /// Gemini uses Keychain for extension integrity verification.
    /// OpenCode uses API keys from env vars or config files.
    pub fn needs_keychain(&self) -> bool {
        matches!(self, Agent::Copilot | Agent::Gemini)
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
                        },
                        AgentDir {
                            path: data_base.join("fish"),
                            write: true,
                            map_exec: false,
                            process_exec: false,
                        },
                    ],
                    "zsh" => vec![AgentDir {
                        path: data_base.join("zsh"),
                        write: true,
                        map_exec: false,
                        process_exec: false,
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

                // Respect XDG_DATA_HOME for data dir (sessions, SQLite DB)
                let data_base = std::env::var("XDG_DATA_HOME")
                    .ok()
                    .map_or_else(|| home.join(".local/share"), PathBuf::from);
                let data_dir = data_base.join("opencode");

                // Respect XDG_STATE_HOME for state data dir (locks, history, statistics)
                let state_base = std::env::var("XDG_STATE_HOME")
                    .ok()
                    .map_or_else(|| home.join(".local/state"), PathBuf::from);
                let state_dir = state_base.join("opencode");

                vec![
                    AgentDir {
                        path: config_dir,
                        write: false,
                        map_exec: false,
                        process_exec: false,
                    },
                    AgentDir {
                        path: data_dir,
                        write: true,
                        map_exec: false,
                        // Explicitly deny exec on writable data dir
                        process_exec: false,
                    },
                    AgentDir {
                        path: state_dir,
                        write: true,
                        map_exec: false,
                        // Explicitly deny exec on writable state data dir
                        process_exec: false,
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
                }]
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

        let binary_name = self.binary_name();
        let self_exe = std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::canonicalize(&p).ok());

        let path_var = std::env::var("PATH").unwrap_or_default();

        // For Copilot, track editor shims as fallback
        let mut editor_shim: Option<PathBuf> = None;

        for dir in path_var.split(':') {
            let candidate = PathBuf::from(dir).join(binary_name);

            if !candidate.is_file() {
                continue;
            }

            let resolved = std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
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
            Agent::Shell => unreachable!("Shell is resolved via $SHELL above"),
        };

        Err(format!(
            "{} not found in PATH. {install_hint}",
            self.display_name()
        ))
    }

    /// Auto-detect which agent to use based on what's available in PATH.
    /// Returns Copilot if found (backward compat), else OpenCode, else Gemini.
    /// Returns None if none are found.
    pub fn auto_detect() -> Option<Agent> {
        let path_var = std::env::var("PATH").unwrap_or_default();
        let self_exe = std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::canonicalize(&p).ok());

        let mut found_copilot = false;
        let mut found_opencode = false;
        let mut found_gemini = false;

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
        }

        if found_copilot {
            Some(Agent::Copilot)
        } else if found_opencode {
            Some(Agent::OpenCode)
        } else if found_gemini {
            Some(Agent::Gemini)
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
            "shell" | "sh" | "bash" | "zsh" => Ok(Agent::Shell),
            _ => Err(format!(
                "Unknown agent '{s}'. Supported: copilot, opencode, gemini, shell"
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
}

/// Check if a copilot binary is a VS Code/Cursor/editor shim script.
fn is_editor_shim(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    content.starts_with("#!") && content.contains("copilotCLIShim.js")
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
    fn copilot_needs_sea_extraction() {
        assert!(Agent::Copilot.needs_sea_extraction());
        assert!(!Agent::OpenCode.needs_sea_extraction());
        assert!(!Agent::Gemini.needs_sea_extraction());
    }

    #[test]
    fn copilot_extra_args() {
        assert_eq!(Agent::Copilot.extra_args(), &["--no-auto-update"]);
        assert!(Agent::OpenCode.extra_args().is_empty());
        assert!(Agent::Gemini.extra_args().is_empty());
    }

    #[test]
    fn keychain_needs() {
        assert!(Agent::Copilot.needs_keychain());
        assert!(Agent::Gemini.needs_keychain());
        assert!(!Agent::OpenCode.needs_keychain());
    }

    #[test]
    fn opencode_config_dirs_xdg_default() {
        let home = Path::new("/Users/test");
        let dirs = Agent::OpenCode.config_dirs(home);
        assert!(dirs.len() >= 2, "should have config + data + state dirs");
        // Config dir is read-only, data dir and state dir are writable
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
        assert!(!config_dir.write, "config dir should be read-only");
        assert!(data_dir.write, "data dir should be writable");
        assert!(state_dir.write, "state data dir should be writable");
        // None should be executable
        assert!(dirs.iter().all(|d| !d.process_exec && !d.map_exec));
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
    fn display_names() {
        assert_eq!(format!("{}", Agent::Copilot), "Copilot");
        assert_eq!(format!("{}", Agent::OpenCode), "OpenCode");
        assert_eq!(format!("{}", Agent::Gemini), "Gemini");
    }
}
