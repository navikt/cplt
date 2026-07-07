//! Agent abstraction for different AI coding tools.
//!
//! cplt can sandbox multiple AI coding agents — currently GitHub Copilot CLI,
//! OpenCode, Google Gemini CLI, Antigravity, Pi, and Claude Code. Each agent has
//! different binary names, config directories, and runtime requirements, but
//! shares the same core sandbox infrastructure.

use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Package registries that virtually every coding agent needs to fetch
/// dependencies (npm, Yarn, Maven, Gradle, crates.io, PyPI). This is the
/// shared base for every agent's built-in allowlist so that, when fail-closed
/// networking is opted into, a normal `npm/pip/cargo install` still works.
///
/// Entries are bare registrable domains: the proxy's `is_domain_match` does
/// exact-or-subdomain matching, so `crates.io` also covers `static.crates.io`
/// (both are listed explicitly for clarity, matching issue #52).
const PACKAGE_REGISTRY_DOMAINS: &[&str] = &[
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "repo.maven.apache.org",
    "plugins.gradle.org",
    "crates.io",
    "static.crates.io",
    "pypi.org",
    "files.pythonhosted.org",
];

/// GitHub Copilot infrastructure domains (issue #52). These are the endpoints
/// the Copilot CLI itself talks to for auth, model access, and telemetry.
///
/// The list uses BARE domains, not `*.wildcard` syntax: the proxy allowlist
/// matcher (`crate::proxy::is_domain_match`) treats each entry as an
/// exact-or-subdomain match, so `githubcopilot.com` already covers
/// `api.githubcopilot.com`, `proxy.githubcopilot.com`, etc. — the same effect
/// the issue's `*.githubcopilot.com` intends — and `actions.githubusercontent.com`
/// covers `*.actions.githubusercontent.com`. Do not add a leading `*.`; the
/// matcher does not interpret glob syntax.
const COPILOT_INFRA_DOMAINS: &[&str] = &[
    "githubcopilot.com",
    "api.github.com",
    "github.com",
    "copilot-proxy.githubusercontent.com",
    "actions.githubusercontent.com",
    "default.exp2.cds.s9ch.io",
];

/// Google AI infrastructure shared by the Gemini CLI and Antigravity (both are
/// Google products; Antigravity stores its config under `~/.gemini`). Covers
/// the Gemini API, the Code Assist backend, and Google OAuth for login.
///
/// BARE domains, matched exact-or-subdomain by `crate::proxy::is_domain_match`.
/// Do not add a leading `*.`; the matcher does not interpret glob syntax.
///
/// Google Gemini API + Code Assist backend + Google OAuth. High confidence.
const GOOGLE_AI_DOMAINS: &[&str] = &[
    "generativelanguage.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "oauth2.googleapis.com",
    "accounts.google.com",
];

/// Antigravity's own endpoint, used in addition to `GOOGLE_AI_DOMAINS`.
/// Antigravity lives at antigravity.google.
///
/// BARE domain — see `COPILOT_INFRA_DOMAINS` for the no-glob convention.
const ANTIGRAVITY_DOMAINS: &[&str] = &["antigravity.google"];

/// Anthropic infrastructure for Claude Code: the API, the console/login site,
/// and feature-flag telemetry.
///
/// BARE domains, matched exact-or-subdomain — see `COPILOT_INFRA_DOMAINS`.
///
/// Anthropic API + console/login + feature-flag telemetry. High confidence.
const ANTHROPIC_DOMAINS: &[&str] = &[
    "api.anthropic.com",
    "console.anthropic.com",
    "claude.ai",
    "statsig.anthropic.com",
];

/// OpenCode's OWN infrastructure only. OpenCode is provider-agnostic: it routes
/// model traffic to a user-configured provider (Anthropic/OpenAI/Google/…), so
/// enabling `default_allowlist` for OpenCode requires adding that provider's
/// domain via `allowed_domains`. Only OpenCode's own infra is listed here.
///
/// BARE domains, matched exact-or-subdomain — see `COPILOT_INFRA_DOMAINS`.
const OPENCODE_DOMAINS: &[&str] = &["opencode.ai", "models.dev"];

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
    /// Claude Code (Anthropic's `claude` CLI).
    Claude,
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
            Agent::Claude => "claude",
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
            Agent::Claude => "Claude Code",
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
            Agent::OpenCode
            | Agent::Gemini
            | Agent::Antigravity
            | Agent::Pi
            | Agent::Claude
            | Agent::Shell => &[],
        }
    }

    /// Translate cplt's session-management convenience flags into this agent's
    /// native CLI flags.
    ///
    /// cplt exposes `--resume`, `--continue`, `--remote`, and `--name` for
    /// convenience. Each agent spells these differently (or not at all):
    /// - Copilot: `--resume[=ID]`, `--continue`, `--remote`, `--name NAME`
    /// - OpenCode: `--continue`, `--session ID` (no remote/name)
    /// - Antigravity (`agy`): `--continue`, `--conversation ID` (no remote/name)
    ///
    /// Flags an agent doesn't support are silently dropped (documented in the
    /// CLI help as "ignored for other agents"). A bare `--resume` (interactive
    /// session picker) maps to "continue last session" for agents that lack an
    /// interactive picker, which is the closest equivalent.
    pub fn session_args(
        &self,
        resume: Option<&str>,
        continue_session: bool,
        session_name: Option<&str>,
        remote: bool,
    ) -> Vec<String> {
        let mut args = Vec::new();
        match self {
            Agent::Copilot => {
                if remote {
                    args.push("--remote".to_string());
                }
                if let Some(session) = resume {
                    if session.is_empty() {
                        args.push("--resume".to_string());
                    } else {
                        args.push(format!("--resume={session}"));
                    }
                }
                if continue_session {
                    args.push("--continue".to_string());
                }
                if let Some(name) = session_name {
                    args.push("--name".to_string());
                    args.push(name.to_string());
                }
            }
            Agent::OpenCode => {
                // opencode: -c/--continue continues the last session;
                // -s/--session <id> resumes a specific session by id.
                if continue_session {
                    args.push("--continue".to_string());
                }
                if let Some(session) = resume {
                    if session.is_empty() {
                        args.push("--continue".to_string());
                    } else {
                        args.push("--session".to_string());
                        args.push(session.to_string());
                    }
                }
                // --remote and --name have no opencode equivalent; dropped.
            }
            Agent::Antigravity => {
                // agy: --continue continues the most recent conversation;
                // --conversation <id> resumes a specific conversation by id.
                if continue_session {
                    args.push("--continue".to_string());
                }
                if let Some(session) = resume {
                    if session.is_empty() {
                        args.push("--continue".to_string());
                    } else {
                        args.push("--conversation".to_string());
                        args.push(session.to_string());
                    }
                }
                // --remote and --name have no agy equivalent; dropped.
            }
            Agent::Claude => {
                // claude: -c/--continue continues the most recent session;
                // -r/--resume [id] resumes a session. Bare --resume opens an
                // interactive picker, so it maps directly (unlike opencode/agy).
                if continue_session {
                    args.push("--continue".to_string());
                }
                if let Some(session) = resume {
                    args.push("--resume".to_string());
                    if !session.is_empty() {
                        args.push(session.to_string());
                    }
                }
                // --remote and --name have no claude equivalent; dropped.
            }
            // Gemini still receives auto-resume handling in main.rs; Pi and Shell
            // have no recognized session flags. None get explicit translation here.
            Agent::Gemini | Agent::Pi | Agent::Shell => {}
        }
        args
    }

    /// Whether this agent needs macOS Keychain access for auth tokens.
    /// Copilot stores GitHub auth tokens in the Keychain.
    /// Gemini uses Keychain for extension integrity verification.
    /// Claude Code stores its OAuth token in the login Keychain on macOS
    /// ("Claude Code-credentials"); on Linux it uses ~/.claude/.credentials.json.
    /// OpenCode uses API keys from env vars or config files.
    pub fn needs_keychain(&self) -> bool {
        matches!(
            self,
            Agent::Copilot | Agent::Gemini | Agent::Antigravity | Agent::Claude
        )
    }

    /// Whether this agent needs access to ~/.copilot directory.
    pub fn needs_copilot_dir(&self) -> bool {
        matches!(self, Agent::Copilot)
    }

    /// The agent's built-in default domain allowlist — the set of domains the
    /// agent legitimately needs to reach.
    ///
    /// This is the fail-closed base for `proxy.default_allowlist` (issue #52):
    /// when that opt-in is enabled, the proxy permits ONLY these domains (merged
    /// with any user-configured `allowed_domains`) and blocks everything else,
    /// so a compromised agent cannot exfiltrate to an arbitrary HTTPS endpoint.
    ///
    /// Every agent gets the shared package-registry base. On top of that, each
    /// agent with documented infrastructure gets its own endpoints: Copilot the
    /// GitHub Copilot infra (#52), Gemini/Antigravity the Google AI infra
    /// (Antigravity additionally its own domain), Claude the Anthropic infra,
    /// and OpenCode only its own infra (see below). Entries are bare domains
    /// matched by `crate::proxy::is_domain_match` (exact or subdomain).
    ///
    /// NOTE: this is opt-in and does NOT change the default behaviour. Two gaps
    /// remain where enabling `default_allowlist` today still needs the user to
    /// add domains via `allowed_domains`:
    ///   - OpenCode is provider-agnostic: its model traffic goes to a
    ///     user-configured provider (Anthropic/OpenAI/Google/…), which is NOT
    ///     included here — only OpenCode's own infra is.
    ///   - Pi's infrastructure endpoints are not yet documented here.
    ///
    /// These are best-effort defaults for an opt-in feature: blocked domains are
    /// logged (BLOCKED-ALLOWLIST) so users can add any that are missing.
    pub fn default_allowed_domains(&self) -> Vec<&'static str> {
        // Per-agent infrastructure endpoints, layered on top of the shared
        // package-registry base below. Pi and Shell get the base only: Pi's
        // endpoints are not yet documented (contributions welcome), and Shell
        // is not an AI agent so it has no model/auth traffic of its own.
        let infra: &[&[&str]] = match self {
            Agent::Copilot => &[COPILOT_INFRA_DOMAINS],
            Agent::Gemini => &[GOOGLE_AI_DOMAINS],
            Agent::Antigravity => &[GOOGLE_AI_DOMAINS, ANTIGRAVITY_DOMAINS],
            Agent::Claude => &[ANTHROPIC_DOMAINS],
            Agent::OpenCode => &[OPENCODE_DOMAINS],
            Agent::Pi | Agent::Shell => &[],
        };
        let mut domains: Vec<&'static str> = Vec::new();
        for slice in infra {
            domains.extend_from_slice(slice);
        }
        domains.extend_from_slice(PACKAGE_REGISTRY_DOMAINS);
        domains
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
                // ~/.pi/agent/ stores all global data: settings.json, trust.json,
                // sessions/, npm/ packages. Per https://pi.dev/docs/latest/settings
                // ~/.pi/agent/bin contains managed tool binaries (fd, rg)
                vec![
                    AgentDir {
                        path: home.join(".pi/agent"),
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
            Agent::Claude => {
                // CLAUDE_CONFIG_DIR relocates BOTH the data dir and .claude.json
                // under a single root, so granting that subtree covers everything.
                // Must stay in sync with ENV_ALLOWLIST (the var has to reach the
                // child for it to use the same dir we grant). Mirrors OpenCode XDG.
                let custom_dir = std::env::var("CLAUDE_CONFIG_DIR")
                    .ok()
                    .filter(|s| !s.is_empty());
                if let Some(dir) = custom_dir {
                    return vec![AgentDir {
                        path: PathBuf::from(dir),
                        write: true,
                        map_exec: false,
                        process_exec: false,
                        write_files: vec![],
                    }];
                }
                // Default layout: ~/.claude holds sessions, projects, history,
                // settings, and the OAuth token (.credentials.json on Linux).
                // ~/.claude.json is the top-level config (projects, MCP servers,
                // account) — a single file at home root, granted via a file path
                // (Seatbelt subpath / Landlock PathBeneath both match a file).
                vec![
                    AgentDir {
                        path: home.join(".claude"),
                        write: true,
                        map_exec: false,
                        process_exec: false,
                        write_files: vec![],
                    },
                    AgentDir {
                        path: home.join(".claude.json"),
                        write: true,
                        map_exec: false,
                        process_exec: false,
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
            // Source of truth: https://opencode.ai/docs/providers/
            Agent::OpenCode => &[
                // Anthropic
                "ANTHROPIC_API_KEY",
                // OpenAI + Azure OpenAI
                "OPENAI_API_KEY",
                "AZURE_OPENAI_API_KEY",
                // AWS Bedrock (bearer token auth — SigV4 via AWS_ACCESS_KEY_ID requires --pass-env per-var)
                "AWS_BEARER_TOKEN_BEDROCK",
                // Google
                "GEMINI_API_KEY",
                // Popular API providers
                "XAI_API_KEY",
                "MISTRAL_API_KEY",
                "DEEPSEEK_API_KEY",
                "GROQ_API_KEY",
                "CEREBRAS_API_KEY",
                "NVIDIA_API_KEY",
                "OPENROUTER_API_KEY",
                "TOGETHER_API_KEY",
                "FIREWORKS_API_KEY",
                "CLOUDFLARE_API_TOKEN",
                "GITLAB_TOKEN",
            ],
            // Gemini uses Google OAuth by default (browser flow, stored in ~/.gemini/).
            // API key or Vertex AI project are alternatives.
            Agent::Gemini => &["GEMINI_API_KEY", "GOOGLE_CLOUD_PROJECT"],
            // Antigravity uses Google OAuth with keychain/session storage.
            Agent::Antigravity => &[],
            // Pi supports many LLM providers via API keys.
            // Source of truth: https://github.com/earendil-works/pi/blob/main/packages/ai/src/env-api-keys.ts
            Agent::Pi => &[
                // Anthropic (classic key + OAuth token)
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_OAUTH_TOKEN",
                // OpenAI + Azure OpenAI
                "OPENAI_API_KEY",
                "AZURE_OPENAI_API_KEY",
                // AWS Bedrock (bearer token auth — SigV4 via AWS_ACCESS_KEY_ID requires --pass-env per-var)
                "AWS_BEARER_TOKEN_BEDROCK",
                // Google
                "GEMINI_API_KEY",
                // Popular API providers
                "XAI_API_KEY",
                "MISTRAL_API_KEY",
                "DEEPSEEK_API_KEY",
                "GROQ_API_KEY",
                "CEREBRAS_API_KEY",
                "NVIDIA_API_KEY",
                "OPENROUTER_API_KEY",
                "TOGETHER_API_KEY",
                "FIREWORKS_API_KEY",
                "HF_TOKEN",
                "CLOUDFLARE_API_KEY",
                "OPENCODE_API_KEY",
            ],
            // Claude Code authenticates via the OAuth token in ~/.claude
            // (or macOS Keychain) by default — no env var needed for the
            // subscription flow. These are for API-key / enterprise routing.
            Agent::Claude => &[
                // Anthropic API direct
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "ANTHROPIC_BASE_URL",
                // Long-lived OAuth token from `claude setup-token`
                "CLAUDE_CODE_OAUTH_TOKEN",
                // Amazon Bedrock routing
                "CLAUDE_CODE_USE_BEDROCK",
                "AWS_BEARER_TOKEN_BEDROCK",
                // Google Vertex AI routing
                "CLAUDE_CODE_USE_VERTEX",
                "ANTHROPIC_VERTEX_PROJECT_ID",
                "GOOGLE_CLOUD_PROJECT",
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
            Agent::Claude => {
                "Install Claude Code: npm i -g @anthropic-ai/claude-code, \
                 or see https://docs.anthropic.com/en/docs/claude-code"
            }
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
    /// Pi and Claude are explicit-only (`--agent pi` / `--agent claude`) and are
    /// never auto-detected, to avoid silently changing the default for existing users.
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
            "claude" | "cc" | "claude-code" => Ok(Agent::Claude),
            "shell" | "sh" | "bash" | "zsh" => Ok(Agent::Shell),
            _ => Err(format!(
                "Unknown agent '{s}'. Supported: copilot, opencode, gemini, antigravity, pi, claude, shell"
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
    fn session_args_copilot() {
        assert_eq!(
            Agent::Copilot.session_args(Some(""), false, None, false),
            vec!["--resume"]
        );
        assert_eq!(
            Agent::Copilot.session_args(Some("task1"), false, None, false),
            vec!["--resume=task1"]
        );
        assert_eq!(
            Agent::Copilot.session_args(None, true, None, false),
            vec!["--continue"]
        );
        assert_eq!(
            Agent::Copilot.session_args(None, false, Some("my-task"), true),
            vec!["--remote", "--name", "my-task"]
        );
    }

    #[test]
    fn session_args_opencode() {
        // --continue maps to opencode's --continue.
        assert_eq!(
            Agent::OpenCode.session_args(None, true, None, false),
            vec!["--continue"]
        );
        // --resume=ID maps to opencode's --session ID.
        assert_eq!(
            Agent::OpenCode.session_args(Some("abc123"), false, None, false),
            vec!["--session", "abc123"]
        );
        // Bare --resume (no picker in opencode) maps to --continue.
        assert_eq!(
            Agent::OpenCode.session_args(Some(""), false, None, false),
            vec!["--continue"]
        );
        // --remote and --name are dropped (no opencode equivalent).
        assert!(
            Agent::OpenCode
                .session_args(None, false, Some("x"), true)
                .is_empty()
        );
    }

    #[test]
    fn session_args_antigravity() {
        // --continue maps to agy's --continue.
        assert_eq!(
            Agent::Antigravity.session_args(None, true, None, false),
            vec!["--continue"]
        );
        // --resume=ID maps to agy's --conversation ID.
        assert_eq!(
            Agent::Antigravity.session_args(Some("conv42"), false, None, false),
            vec!["--conversation", "conv42"]
        );
        // Bare --resume maps to --continue.
        assert_eq!(
            Agent::Antigravity.session_args(Some(""), false, None, false),
            vec!["--continue"]
        );
        // --remote and --name are dropped (no agy equivalent).
        assert!(
            Agent::Antigravity
                .session_args(None, false, Some("x"), true)
                .is_empty()
        );
    }

    #[test]
    fn session_args_claude() {
        // --continue maps to claude's --continue.
        assert_eq!(
            Agent::Claude.session_args(None, true, None, false),
            vec!["--continue"]
        );
        // --resume=ID maps to claude's --resume ID.
        assert_eq!(
            Agent::Claude.session_args(Some("sess99"), false, None, false),
            vec!["--resume", "sess99"]
        );
        // Bare --resume maps to --resume (interactive picker).
        assert_eq!(
            Agent::Claude.session_args(Some(""), false, None, false),
            vec!["--resume"]
        );
        // --remote and --name are dropped (no claude equivalent).
        assert!(
            Agent::Claude
                .session_args(None, false, Some("x"), true)
                .is_empty()
        );
    }

    #[test]
    fn session_args_unsupported_agents_drop_all() {
        for agent in [Agent::Gemini, Agent::Pi, Agent::Shell] {
            assert!(
                agent
                    .session_args(Some("id"), true, Some("name"), true)
                    .is_empty(),
                "{agent:?} should not translate any session flags"
            );
        }
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
        assert!(hints.contains(&"AWS_BEARER_TOKEN_BEDROCK"));
        assert!(hints.contains(&"XAI_API_KEY"));
        assert!(hints.contains(&"MISTRAL_API_KEY"));
        assert!(hints.contains(&"DEEPSEEK_API_KEY"));
        assert!(hints.contains(&"GROQ_API_KEY"));
        assert!(hints.contains(&"CLOUDFLARE_API_TOKEN"));
        assert!(hints.contains(&"GITLAB_TOKEN"));
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
        assert_eq!(dirs.len(), 2, "should have ~/.pi/agent and ~/.pi/agent/bin");
        // Main dir: ~/.pi/agent — all global data (settings, sessions, trust, npm)
        assert_eq!(dirs[0].path, home.join(".pi/agent"));
        assert!(dirs[0].write);
        assert!(!dirs[0].process_exec);
        // Bin dir has process_exec for managed binaries (fd, rg)
        assert_eq!(dirs[1].path, home.join(".pi/agent/bin"));
        assert!(!dirs[1].write);
        assert!(dirs[1].process_exec);
    }

    #[test]
    fn pi_auth_env_hints() {
        let hints = Agent::Pi.auth_env_hint();
        assert!(hints.contains(&"ANTHROPIC_API_KEY"));
        assert!(hints.contains(&"ANTHROPIC_OAUTH_TOKEN"));
        assert!(hints.contains(&"OPENAI_API_KEY"));
        assert!(hints.contains(&"AWS_BEARER_TOKEN_BEDROCK"));
        assert!(hints.contains(&"GEMINI_API_KEY"));
        assert!(hints.contains(&"XAI_API_KEY"));
        assert!(hints.contains(&"MISTRAL_API_KEY"));
        assert!(hints.contains(&"DEEPSEEK_API_KEY"));
        assert!(hints.contains(&"GROQ_API_KEY"));
        assert!(hints.contains(&"HF_TOKEN"));
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
        assert!(err.contains("claude"), "error should mention claude: {err}");
    }

    #[test]
    fn parse_claude_agent() {
        assert_eq!(Agent::from_str("claude").unwrap(), Agent::Claude);
        assert_eq!(Agent::from_str("Claude").unwrap(), Agent::Claude);
        assert_eq!(Agent::from_str("cc").unwrap(), Agent::Claude);
        assert_eq!(Agent::from_str("claude-code").unwrap(), Agent::Claude);
    }

    #[test]
    fn claude_binary_name() {
        assert_eq!(Agent::Claude.binary_name(), "claude");
    }

    #[test]
    fn claude_display_name() {
        assert_eq!(format!("{}", Agent::Claude), "Claude Code");
    }

    #[test]
    fn claude_no_sea_extraction() {
        assert!(!Agent::Claude.needs_sea_extraction());
    }

    #[test]
    fn claude_no_extra_args() {
        assert!(Agent::Claude.extra_args().is_empty());
    }

    #[test]
    fn claude_needs_keychain() {
        // macOS stores the Claude Code OAuth token in the login Keychain
        assert!(Agent::Claude.needs_keychain());
    }

    #[test]
    fn claude_no_copilot_dir() {
        assert!(!Agent::Claude.needs_copilot_dir());
    }

    #[test]
    fn claude_config_dirs() {
        temp_env::with_var_unset("CLAUDE_CONFIG_DIR", || {
            let home = Path::new("/Users/test");
            let dirs = Agent::Claude.config_dirs(home);
            assert_eq!(dirs.len(), 2, "should have ~/.claude and ~/.claude.json");
            assert_eq!(dirs[0].path, home.join(".claude"));
            assert!(dirs[0].write, "~/.claude should be writable");
            assert!(!dirs[0].process_exec && !dirs[0].map_exec);
            assert_eq!(dirs[1].path, home.join(".claude.json"));
            assert!(dirs[1].write, "~/.claude.json should be writable");
        });
    }

    #[test]
    fn claude_config_dir_override() {
        temp_env::with_var("CLAUDE_CONFIG_DIR", Some("/custom/claude"), || {
            let home = Path::new("/Users/test");
            let dirs = Agent::Claude.config_dirs(home);
            assert_eq!(
                dirs.len(),
                1,
                "override collapses to the single custom root"
            );
            assert_eq!(dirs[0].path, PathBuf::from("/custom/claude"));
            assert!(dirs[0].write, "custom config dir should be writable");
            assert!(!dirs[0].process_exec && !dirs[0].map_exec);
        });
    }

    #[test]
    fn claude_config_dir_empty_falls_back_to_default() {
        temp_env::with_var("CLAUDE_CONFIG_DIR", Some(""), || {
            let home = Path::new("/Users/test");
            let dirs = Agent::Claude.config_dirs(home);
            assert_eq!(dirs.len(), 2, "empty override is ignored");
            assert_eq!(dirs[0].path, home.join(".claude"));
        });
    }

    #[test]
    fn claude_auth_env_hints() {
        let hints = Agent::Claude.auth_env_hint();
        assert!(hints.contains(&"ANTHROPIC_API_KEY"));
        assert!(hints.contains(&"ANTHROPIC_AUTH_TOKEN"));
        assert!(hints.contains(&"CLAUDE_CODE_OAUTH_TOKEN"));
        assert!(hints.contains(&"CLAUDE_CODE_USE_BEDROCK"));
        assert!(hints.contains(&"CLAUDE_CODE_USE_VERTEX"));
    }

    #[test]
    fn claude_not_auto_detected() {
        // Claude is explicit-only; auto_detect must never return it.
        // (We can't easily fake PATH here, but the detection loop has no
        // claude branch — this guards against a regression in intent.)
        assert_ne!(Agent::auto_detect(), Some(Agent::Claude));
    }

    #[test]
    fn copilot_default_allowed_domains_matches_issue_52() {
        let domains = Agent::Copilot.default_allowed_domains();
        // 6 GitHub Copilot infra domains + 8 package registries = 14.
        assert_eq!(domains.len(), 14, "copilot list: infra + registries");
        // GitHub Copilot infrastructure (bare forms of the issue's wildcards).
        for d in [
            "githubcopilot.com",
            "api.github.com",
            "github.com",
            "copilot-proxy.githubusercontent.com",
            "actions.githubusercontent.com",
            "default.exp2.cds.s9ch.io",
        ] {
            assert!(domains.contains(&d), "copilot infra must include {d}");
        }
        // Package registries.
        for d in [
            "registry.npmjs.org",
            "registry.yarnpkg.com",
            "repo.maven.apache.org",
            "plugins.gradle.org",
            "crates.io",
            "static.crates.io",
            "pypi.org",
            "files.pythonhosted.org",
        ] {
            assert!(domains.contains(&d), "copilot list must include {d}");
        }
        // No glob syntax — the proxy matcher does exact/subdomain matching only.
        assert!(
            domains.iter().all(|d| !d.contains('*')),
            "default domains must be bare (no wildcard syntax)"
        );
    }

    #[test]
    fn copilot_default_domains_cover_subdomains_via_matcher() {
        // The bare `githubcopilot.com` entry must cover `*.githubcopilot.com`
        // through the proxy's subdomain matcher — this is the contract that lets
        // us drop the issue's `*.` prefix.
        let domains: Vec<String> = Agent::Copilot
            .default_allowed_domains()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(crate::proxy::is_domain_match(
            "api.githubcopilot.com",
            &domains
        ));
        assert!(crate::proxy::is_domain_match(
            "run.actions.githubusercontent.com",
            &domains
        ));
        assert!(crate::proxy::is_domain_match("github.com", &domains));
        assert!(!crate::proxy::is_domain_match("evil.com", &domains));
    }

    #[test]
    fn gemini_default_domains_include_google_ai_and_registry() {
        let domains = Agent::Gemini.default_allowed_domains();
        assert!(
            domains.contains(&"generativelanguage.googleapis.com"),
            "Gemini must include the Gemini API endpoint"
        );
        assert!(domains.contains(&"accounts.google.com"));
        assert!(
            domains.contains(&"registry.npmjs.org"),
            "Gemini must include the package-registry base"
        );
        assert!(
            !domains.contains(&"githubcopilot.com"),
            "Gemini must not get Copilot infra"
        );
    }

    #[test]
    fn antigravity_default_domains_include_google_and_own_domain() {
        let domains = Agent::Antigravity.default_allowed_domains();
        // Google AI infra (shared with Gemini)...
        assert!(domains.contains(&"generativelanguage.googleapis.com"));
        // ...plus Antigravity's own domain.
        assert!(
            domains.contains(&"antigravity.google"),
            "Antigravity must include its own domain"
        );
        assert!(domains.contains(&"registry.npmjs.org"));
    }

    #[test]
    fn claude_default_domains_include_anthropic_and_registry() {
        let domains = Agent::Claude.default_allowed_domains();
        assert!(
            domains.contains(&"api.anthropic.com"),
            "Claude must include the Anthropic API endpoint"
        );
        assert!(domains.contains(&"claude.ai"));
        assert!(domains.contains(&"statsig.anthropic.com"));
        assert!(domains.contains(&"registry.npmjs.org"));
    }

    #[test]
    fn opencode_default_domains_include_own_infra_only() {
        let domains = Agent::OpenCode.default_allowed_domains();
        assert!(
            domains.contains(&"opencode.ai"),
            "OpenCode must include its own infra"
        );
        assert!(domains.contains(&"models.dev"));
        assert!(domains.contains(&"registry.npmjs.org"));
        // OpenCode is provider-agnostic: no provider LLM domain is baked in.
        assert!(
            !domains.contains(&"api.anthropic.com")
                && !domains.contains(&"generativelanguage.googleapis.com"),
            "OpenCode must not assume a specific model provider"
        );
    }

    #[test]
    fn pi_and_shell_get_registry_base_only() {
        // Pi's infra is not yet documented; Shell is not an AI agent. Both get
        // only the shared package-registry base (8 domains).
        for agent in [Agent::Pi, Agent::Shell] {
            let domains = agent.default_allowed_domains();
            assert_eq!(domains.len(), 8, "{agent:?} gets registry base only");
            assert!(domains.contains(&"registry.npmjs.org"));
            assert!(
                !domains.contains(&"githubcopilot.com"),
                "{agent:?} must not get Copilot infra"
            );
        }
    }

    #[test]
    fn every_agent_default_domains_nonempty_bare_and_registry_backed() {
        // Contract across ALL agents: non-empty, registry base present, and no
        // glob syntax (the proxy matcher does exact/subdomain matching only).
        for agent in [
            Agent::Copilot,
            Agent::OpenCode,
            Agent::Gemini,
            Agent::Antigravity,
            Agent::Pi,
            Agent::Claude,
            Agent::Shell,
        ] {
            let domains = agent.default_allowed_domains();
            assert!(!domains.is_empty(), "{agent:?} list must not be empty");
            assert!(
                domains.contains(&"registry.npmjs.org"),
                "{agent:?} must include the package-registry base"
            );
            assert!(
                domains.iter().all(|d| !d.starts_with("*.")),
                "{agent:?} domains must be bare (no `*.` glob prefix)"
            );
            assert!(
                domains.iter().all(|d| !d.contains('*')),
                "{agent:?} domains must be bare (no wildcard syntax)"
            );
        }
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
