//! Agent abstraction for different AI coding tools.
//!
//! cplt can sandbox multiple AI coding agents — currently GitHub Copilot CLI,
//! OpenCode, Google Gemini CLI, Antigravity, Pi, Claude Code, and goose. Each agent has
//! different binary names, config directories, and runtime requirements, but
//! shares the same core sandbox infrastructure.

use crate::ui;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::OnceLock;

// ── Per-agent default allowlists ─────────────────────────────────────────────
//
// These lists are the fail-closed egress allowlist each agent gets under
// `--default-allowlist` / `proxy.default_allowlist`. They should be captured
// EMPIRICALLY, not guessed: run the agent under discovery mode and paste the
// observed set. See the "Verifying / generating an agent's domain allowlist"
// section in docs/proxy.md for the workflow:
//
//     cplt --agent <X> --observe-domains -- <do a representative task>
//
// Convention: when you add or refresh an agent's list, record its PROVENANCE in
// a comment on the const — which agent + version and the date the domains were
// observed — so a reviewer can tell whether the list is current, e.g.:
//     // Observed with copilot 0.24.1 on 2026-01-15 via `--observe-domains`.
// The existing lists below predate this convention and carry NO verified
// provenance yet; do not fabricate one — capture it the next time each is run.

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

/// Google AI infrastructure used by Antigravity (a Google product, which stores
/// its config under `~/.gemini`). Covers the Gemini API, the Code Assist
/// backend, and Google OAuth for login.
///
/// BARE domains, matched exact-or-subdomain by `crate::proxy::is_domain_match`.
/// Do not add a leading `*.`; the matcher does not interpret glob syntax.
///
/// Gemini API + Code Assist backend + Google OAuth. High confidence.
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

/// A credential an agent can use instead of the macOS login Keychain (#242).
///
/// Returned by [`Agent::credential_outside_keychain`]. The variants exist
/// because the two kinds need different handling downstream: an env var has to
/// be forwarded into the sandbox explicitly (credential vars that were not
/// already in `ENV_ALLOWLIST` on main are deliberately still not in it, so they
/// reach the agent only as part of this trade), while a file the agent reads
/// itself needs nothing forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainSubstitute {
    /// A credential already set in the parent environment.
    EnvVar(&'static str),
    /// A credential file inside a directory the sandbox already grants.
    File(PathBuf),
}

impl KeychainSubstitute {
    /// The variable to forward into the sandbox, if this substitute is one.
    pub fn env_var(&self) -> Option<&'static str> {
        match self {
            KeychainSubstitute::EnvVar(v) => Some(v),
            KeychainSubstitute::File(_) => None,
        }
    }
}

impl std::fmt::Display for KeychainSubstitute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeychainSubstitute::EnvVar(v) => write!(f, "${v}"),
            KeychainSubstitute::File(p) => write!(f, "{}", p.display()),
        }
    }
}

/// Supported AI coding agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Agent {
    /// GitHub Copilot CLI (default).
    Copilot,
    /// OpenCode (anomalyco/opencode) — open source AI coding agent.
    OpenCode,
    /// Antigravity CLI (`antigravity` / `agy`).
    Antigravity,
    /// Pi coding agent (https://github.com/earendil-works/pi).
    Pi,
    /// Claude Code (Anthropic's `claude` CLI).
    Claude,
    /// goose — open-source AI agent (github.com/aaif-goose/goose).
    Goose,
    /// Plain sandboxed shell — no AI agent, just a secure shell session.
    Shell,
}

impl Agent {
    /// Every agent variant, for exhaustive iteration in tests and lookups.
    pub const ALL: &'static [Agent] = &[
        Agent::Copilot,
        Agent::OpenCode,
        Agent::Antigravity,
        Agent::Pi,
        Agent::Claude,
        Agent::Goose,
        Agent::Shell,
    ];

    /// The binary name to search for in PATH.
    pub fn binary_name(&self) -> &'static str {
        match self {
            Agent::Copilot => "copilot",
            Agent::OpenCode => "opencode",
            Agent::Antigravity => "antigravity",
            Agent::Pi => "pi",
            Agent::Claude => "claude",
            Agent::Goose => "goose",
            Agent::Shell => "shell",
        }
    }

    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Agent::Copilot => "Copilot",
            Agent::OpenCode => "OpenCode",
            Agent::Antigravity => "Antigravity",
            Agent::Pi => "Pi",
            Agent::Claude => "Claude Code",
            Agent::Goose => "goose",
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
            | Agent::Antigravity
            | Agent::Pi
            | Agent::Claude
            | Agent::Goose
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
            Agent::Goose => {
                // Verified against goose 1.48.0 (`goose --help`, `goose session
                // --help`): the session flags live on the `session` SUBCOMMAND,
                // not the top level — `goose --resume` is rejected with
                // "unexpected argument '--resume' found". Bare `goose` already
                // starts a session, so only emit the subcommand when there is
                // something to translate.
                //
                // `-r/--resume` continues the most recent session;
                // `--session-id ID` (requires `--resume`) selects one by id and
                // `-n/--name NAME` selects one by name. They are alternative
                // selectors, so at most one is emitted — cplt's explicit
                // `--resume=ID` wins over `--name`.
                let resuming = resume.is_some() || continue_session;
                let selector = resume.filter(|s| !s.is_empty());
                // Same emptiness filter as `selector` above: `--name ""` is not
                // a session goose can select, and emitting it would turn a bare
                // run into a rejected `session --name ""`.
                let session_name = session_name.filter(|s| !s.is_empty());
                if resuming || session_name.is_some() {
                    args.push("session".to_string());
                }
                if resuming {
                    args.push("--resume".to_string());
                }
                if let Some(id) = selector {
                    args.push("--session-id".to_string());
                    args.push(id.to_string());
                } else if let Some(name) = session_name {
                    args.push("--name".to_string());
                    args.push(name.to_string());
                }
                // --remote has no goose equivalent; dropped.
            }
            // Pi and Shell have no recognized session flags, so they get no
            // explicit translation here.
            Agent::Pi | Agent::Shell => {}
        }
        args
    }

    /// Whether this agent needs macOS Keychain access for auth tokens.
    ///
    /// Copilot stores GitHub auth tokens in the Keychain (`copilot-cli`).
    /// Gemini CLI bundles `@github/keytar` with the service name
    /// `gemini-cli-oauth` and refreshes that token in place.
    /// Antigravity's `agy` stores its Google OAuth token under
    /// `gemini`/`antigravity` and refreshes it there.
    /// Claude Code stores its OAuth token in the login Keychain on macOS
    /// ("Claude Code-credentials"); on Linux it uses ~/.claude/.credentials.json.
    /// OpenCode authenticates via the `/connect` device flow by default;
    /// third-party providers use API keys from env vars or config files.
    /// goose stores provider API keys in the OS keyring by default (the macOS
    /// login Keychain); `GOOSE_DISABLE_KEYRING=1` switches it to a plaintext
    /// `secrets.yaml` in the config dir instead, which needs no grant.
    ///
    /// This is the *base* term only. Whether a given run actually gets the grant
    /// is decided at launch by [`Agent::credential_outside_keychain`] (#242).
    pub fn needs_keychain(&self) -> bool {
        matches!(
            self,
            Agent::Copilot | Agent::Antigravity | Agent::Claude | Agent::Goose
        )
    }

    /// Environment variables that fully replace this agent's Keychain
    /// credential, in the agent's own precedence order.
    ///
    /// Only variables carrying a credential that is **durable for a session**
    /// belong here. The Keychain items themselves are refresh blobs: Claude
    /// Code's `Claude Code-credentials` holds an access token that expires in
    /// hours and is rewritten in place, and Antigravity's `gemini`/`antigravity`
    /// item is likewise rewritten. Pre-extracting *those* would hand the agent a
    /// token that dies mid-session with no way to refresh and no Keychain left
    /// to re-authenticate against, so cplt does not do it.
    ///
    /// `ANTHROPIC_AUTH_TOKEN` is omitted deliberately: Claude Code treats it as a
    /// gateway token it may itself try to refresh, so it is not a safe stand-in.
    pub fn keychain_substitute_env_vars(&self) -> &'static [&'static str] {
        match self {
            // Copilot gets no substitute until somebody probes it. It is the
            // default, priority-1 agent, GITHUB_TOKEN is the most commonly
            // exported token on a developer machine, and whether Copilot CLI
            // prefers the env var over the Keychain is exactly the precedence
            // question this trade declines to assume for Gemini. PR #173 asserts
            // an injected token suffices; asserting is not probing, and the
            // default agent is the wrong place to find out. Re-enable this with
            // `["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]` once a run
            // under a grant-dropped profile has been confirmed to authenticate.
            Agent::Copilot => &[],
            // Antigravity has no env substitute either — its credential lives in
            // a file instead, see `credential_outside_keychain`.
            Agent::Antigravity => &[],
            // `claude setup-token` mints a long-lived token for
            // CLAUDE_CODE_OAUTH_TOKEN. Verified against claude 2.1.258: with it
            // set, `claude auth status` reports `authMethod: oauth_token`
            // whether the Keychain is reachable or not — the Keychain item is
            // never consulted, so dropping the grant changes nothing.
            //
            // ANTHROPIC_API_KEY is deliberately NOT here. Claude Code *prefers*
            // the Keychain claude.ai login over it (`authMethod: claude.ai` with
            // the key merely listed as `apiKeySource`), so dropping the grant
            // would silently move a subscription user onto per-token API
            // billing. Users who want that can pass it explicitly with
            // `--pass-env ANTHROPIC_API_KEY`.
            Agent::Claude => &["CLAUDE_CODE_OAUTH_TOKEN"],
            _ => &[],
        }
    }

    /// Where this agent's credential can be read from *without* the login
    /// Keychain, if anywhere. `Some(_)` means the whole-Keychain grant can be
    /// dropped for this run; `None` means the grant must stay (#242).
    ///
    /// `enabled` is `sandbox.keychain_substitute`, off by default. The whole
    /// trade is gated on it because the failure mode when it misjudges an agent
    /// is that the user can neither authenticate nor recover from inside the
    /// sandbox — the recovery path *is* the credential store the trade removed.
    /// With it off this always returns `None`, so both the emitted profile and
    /// the environment reaching the agent are what they were before this key
    /// existed.
    ///
    /// `deny_env` is the resolved `deny.env` list. A repo `.cplt.toml` can name
    /// a credential var there, and it is stripped from the child environment —
    /// so a var listed there is NOT a substitute, or the run would end up with
    /// no Keychain *and* no token. That is the exact failure PR #173 hit, and
    /// here it would be reachable from a checked-in file.
    pub fn credential_outside_keychain(
        &self,
        home: &Path,
        deny_env: &[String],
        enabled: bool,
    ) -> Option<KeychainSubstitute> {
        self.credential_outside_keychain_on(home, deny_env, enabled, cfg!(target_os = "macos"))
    }

    /// [`Agent::credential_outside_keychain`] with the platform as a parameter.
    ///
    /// The only reason this is separate: `cfg!` is read in exactly one place
    /// (the wrapper above), so callers cannot drift, while tests can assert
    /// *both* platform outcomes from either host. A `#[cfg]`-gated test would
    /// leave the Linux answer — "the trade never applies" — asserted nowhere.
    pub(crate) fn credential_outside_keychain_on(
        &self,
        home: &Path,
        deny_env: &[String],
        enabled: bool,
        macos: bool,
    ) -> Option<KeychainSubstitute> {
        // The whole trade is about the macOS login Keychain. On Linux these
        // agents read credential files the sandbox already grants, so there is
        // no grant to drop — and forwarding a token there would be a change with
        // nothing bought for it.
        if !enabled || !macos {
            return None;
        }
        if let Some(var) = self
            .keychain_substitute_env_vars()
            .iter()
            .filter(|k| !deny_env.iter().any(|d| d == *k))
            .find(|k| std::env::var(k).is_ok_and(|v| !v.trim().is_empty()))
        {
            return Some(KeychainSubstitute::EnvVar(var));
        }
        // Antigravity's `agy` falls back to a plaintext token file when its
        // keyring is unavailable ("Failed to load token from keyring, falling
        // back to file"). The file is a *fallback*, not a mirror: a healthy
        // keyring is written in place and the file is never created, so its mere
        // existence is the only safe signal that the agent can still
        // authenticate without the grant. cplt already grants
        // `~/.gemini/antigravity-cli` read+write, so refreshes persist there.
        if *self == Agent::Antigravity {
            let token = home.join(".gemini/antigravity-cli/antigravity-oauth-token");
            // `is_file()` as well as non-empty: a directory reports a non-zero
            // len (64 on macOS, 4096 on ext4), so a stray directory at this path
            // would read as a valid credential and drop the Keychain grant,
            // stranding the agent at a browser re-login it cannot reach.
            if std::fs::metadata(&token).is_ok_and(|m| m.is_file() && m.len() > 0) {
                return Some(KeychainSubstitute::File(token));
            }
        }
        None
    }
    /// Whether this agent needs access to ~/.copilot directory.
    pub fn needs_copilot_dir(&self) -> bool {
        matches!(self, Agent::Copilot)
    }

    /// Paths inside this agent's writable config dir(s) that auto-execute on
    /// the HOST the next time the agent runs *outside* cplt — a persistence
    /// vector the agent never needs to write mid-session. Each entry is joined
    /// onto every writable [`Agent::config_dirs`] grant and denied for writing.
    ///
    /// - Claude: `statusline.sh` runs on every prompt render, `plugins/` loads
    ///   at startup, and `settings.json` carries `hooks` (`SessionStart`,
    ///   `UserPromptSubmit`, …) which fire automatically. `commands/`,
    ///   `agents/` and `skills/` stay writable — those do require explicit user
    ///   invocation.
    /// - Antigravity: its own grants carry the same class. `config/hooks.json`
    ///   names host commands, `config/mcp_config.json` holds `mcpServers` that
    ///   auto-start, and `antigravity-cli/bin/` holds binaries (`agentapi`,
    ///   `webm_encoder`) Antigravity runs on the host.
    /// - Pi: `extensions/*.ts` and `extensions/*/index.ts` are auto-discovered
    ///   at startup (the trust gate covers only the project-local path), and
    ///   `settings.json` can name extension paths and npm/git packages, so
    ///   denying the directory alone is not enough. `npm/` and `git/` hold the
    ///   code of packages already installed by `pi install`: denying only
    ///   `settings.json` stops a *new* entry being added but leaves installed
    ///   package code editable in place, and it loads on the next host run.
    ///
    /// Cost: for Pi this breaks package management and every in-session
    /// setting that persists to `settings.json` — `/model` Ctrl+S,
    /// `/thinking`, `/settings`. Do those outside cplt — see SECURITY.md.
    ///
    /// Enforcement is macOS-first: Seatbelt emits these as write-denies after
    /// the dir-wide allow (last match wins). Landlock cannot sub-deny inside an
    /// allowed tree, so on Linux they are re-bound read-only when bubblewrap is
    /// available and are **unenforced** when it is not.
    pub fn host_persistence_denies(&self) -> &'static [&'static str] {
        match self {
            Agent::Claude => &["statusline.sh", "plugins", "settings.json"],
            Agent::Pi => &["settings.json", "extensions", "npm", "git"],
            // Antigravity's grants are ~/.gemini/config and
            // ~/.gemini/antigravity-cli, not ~/.gemini itself, so Gemini's own
            // entries would not match; these are its equivalents. Each name is
            // joined onto BOTH grants, and the join that does not correspond to
            // a real path is inert (same as ~/.claude.json/statusline.sh).
            Agent::Antigravity => &["hooks.json", "mcp_config.json", "bin"],
            // goose needs no entries: its ONLY auto-execution vector is
            // config.yaml's `extensions:` list, and its config dir is granted
            // read-only, so there is nothing writable left to deny. (These
            // denies are joined onto writable dirs only, so an entry here would
            // be inert anyway.) The data and state dirs hold sessions, logs and
            // downloaded model weights — nothing goose auto-executes.
            Agent::Goose | Agent::Copilot | Agent::OpenCode | Agent::Shell => &[],
        }
    }

    /// The concrete paths [`Agent::host_persistence_denies`] resolves to for a
    /// given set of grants: every entry joined onto every **writable** dir.
    ///
    /// Both backends need exactly this list — Seatbelt turns it into
    /// `(deny file-write*)` rules, the Linux path re-binds it read-only under
    /// bubblewrap — so it lives here rather than being joined twice.
    pub fn host_persistence_paths(&self, dirs: &[AgentDir]) -> Vec<PathBuf> {
        dirs.iter()
            .filter(|d| d.write)
            .flat_map(|d| {
                self.host_persistence_denies()
                    .iter()
                    .map(|sub| d.path.join(sub))
            })
            .collect()
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
    /// GitHub Copilot infra (#52), Antigravity the Google AI infra plus its own
    /// domain, Claude the Anthropic infra,
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
            Agent::Antigravity => &[GOOGLE_AI_DOMAINS, ANTIGRAVITY_DOMAINS],
            Agent::Claude => &[ANTHROPIC_DOMAINS],
            Agent::OpenCode => &[OPENCODE_DOMAINS],
            // goose gets the package-registry base and NOTHING else. This is
            // an observed result, not an omission: `cplt --agent goose
            // --observe-domains -- run -t "…"` with goose 1.48.0 on 2026-09-03
            // recorded only `api.openai.com` — the configured provider — and
            // no goose-owned host at all. goose is provider-agnostic, so the
            // provider domain belongs in the user's `allowed_domains`, not
            // here.
            //
            // Deliberately excluded, both observed but neither on a default
            // path: `us.i.posthog.com` (telemetry, opt-in — the same run with
            // GOOSE_TELEMETRY_OFF=1 contacted nothing but the provider) and
            // `github.com` (only `goose update`, which is self-update inside
            // the sandbox and is not something to enable by default).
            //
            // `block.github.io` from the original patch was never contacted;
            // goose's docs moved to goose-docs.ai and the repo to
            // github.com/aaif-goose/goose.
            Agent::Goose | Agent::Pi | Agent::Shell => &[],
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
            Agent::Goose => {
                // goose keeps its files under XDG dirs on BOTH macOS and Linux —
                // it does not use ~/Library/Application Support. Verified with
                // goose 1.48.0 on macOS via `goose info`, with and without the
                // XDG_* overrides set:
                //   ~/.config/goose        — config.yaml, secrets.yaml, skills
                //   ~/.local/share/goose   — sessions/sessions.db, apps
                //   ~/.local/state/goose   — logs
                // `goose info` reports no cache dir and a full `goose run`
                // created none, so ~/.cache/goose is not granted.
                //
                // The config dir is READ-ONLY, and no `write_files` narrow it
                // back open. config.yaml's `extensions:` entries carry a `cmd`
                // + `args` that goose spawns as a subprocess on every session
                // start, so a writable config dir lets a sandboxed agent plant
                // a command that runs UNSANDBOXED the next time the user
                // launches goose — the same class as .git/hooks and .cplt.toml.
                //
                // A `write_files` carve-out cannot help here anyway: goose
                // rewrites config.yaml, permission.yaml and
                // permissions/tool_permissions.json by creating a temp file in
                // the directory and renaming over the target, which needs
                // directory write, not file write.
                //
                // What read-only costs, all of it a deliberate act that belongs
                // outside the sandbox: `/mode` and theme changes, the first-run
                // telemetry prompt, and persisting "always allow" tool
                // permissions — that last one being a privilege the sandboxed
                // agent should not be able to grant itself for future runs. A
                // full `goose run` against a pre-configured config.yaml left
                // the file byte-identical and wrote only under the data and
                // state dirs.
                //
                // NOT covered here: goose also auto-spawns MCP servers declared
                // in plugin manifests under `~/.agents/plugins/` and
                // `<project>/.agents/plugins/`. The former is outside every
                // granted dir, so it is unreadable and unwritable in the
                // sandbox; the latter sits in the writable project tree and is
                // the same in-repo persistence class as `.git/hooks`, which is
                // handled by the global protected set, not per-agent.
                let config_base = std::env::var("XDG_CONFIG_HOME")
                    .ok()
                    .map_or_else(|| home.join(".config"), PathBuf::from);
                let data_base = std::env::var("XDG_DATA_HOME")
                    .ok()
                    .map_or_else(|| home.join(".local/share"), PathBuf::from);
                let state_base = std::env::var("XDG_STATE_HOME")
                    .ok()
                    .map_or_else(|| home.join(".local/state"), PathBuf::from);
                vec![
                    AgentDir {
                        path: config_base.join("goose"),
                        write: false,
                        map_exec: false,
                        process_exec: false,
                        write_files: vec![],
                    },
                    AgentDir {
                        path: data_base.join("goose"),
                        write: true,
                        map_exec: false,
                        process_exec: false,
                        write_files: vec![],
                    },
                    AgentDir {
                        path: state_base.join("goose"),
                        write: true,
                        map_exec: false,
                        process_exec: false,
                        write_files: vec![],
                    },
                ]
            }
        }
    }

    /// Whether this agent authenticates OAuth-first: after an interactive
    /// login its credentials live on disk in a granted config/data dir (or the
    /// macOS Keychain), so the default path needs no environment variable.
    ///
    /// Used to suppress the "No API keys passed" hint, which otherwise fires
    /// for a correctly configured user and reads like a startup failure (#187).
    /// `auth_env_hint` still lists the vars for people who deliberately route
    /// via an API key or an enterprise endpoint.
    ///
    /// Exhaustive match on purpose: a new agent must declare its auth model
    /// instead of silently inheriting the wrong default.
    pub fn oauth_first(&self) -> bool {
        match self {
            // GitHub device flow; token in the Keychain / ~/.copilot.
            Agent::Copilot => true,
            // `/connect` device flow against a GitHub Copilot subscription;
            // credentials stored in ~/.local/share/opencode/auth.json.
            Agent::OpenCode => true,
            // Google OAuth with keychain/session storage.
            Agent::Antigravity => true,
            // Subscription OAuth token in ~/.claude (.credentials.json on
            // Linux) or the macOS login Keychain.
            Agent::Claude => true,
            // Provider API keys only — no interactive login flow. goose's own
            // `configure` stores the provider key in the OS keyring; there is
            // no goose account to log into.
            Agent::Pi | Agent::Goose => false,
            // Not an AI agent: no auth of its own.
            Agent::Shell => false,
        }
    }

    /// Whether this agent's OAuth login needs a browser cplt blocks by default.
    ///
    /// Device-flow agents (Copilot, OpenCode, Claude Code) print a code and a
    /// URL, so a blocked browser costs nothing. Google's flow opens a browser
    /// instead, and `--allow-browser` is off by default — so a first-time user
    /// hits a dead end with no explanation once the API-key hint is suppressed
    /// for OAuth-first agents (#187).
    ///
    /// Exhaustive match for the same reason as `oauth_first`.
    pub fn oauth_needs_browser(&self) -> bool {
        match self {
            // Google OAuth browser flow on first run.
            Agent::Antigravity => true,
            // Device flow: a code and a URL, no browser required from here.
            Agent::Copilot | Agent::OpenCode | Agent::Claude => false,
            // Not OAuth-first at all.
            Agent::Pi | Agent::Goose | Agent::Shell => false,
        }
    }

    /// Warning for the case where this agent's **first-run login** would have
    /// to write a file that [`Agent::host_persistence_denies`] blocks, and that
    /// login has not happened yet on this host. `None` means nothing to say.
    ///
    /// Warn-and-launch, not refuse: the login may be the only thing the deny
    /// breaks, and blocking the run takes that judgement away from the user.
    /// The trade is that they can still walk into the failure with this text
    /// already scrolled off, so it is written to be **recognised later**, not
    /// merely read at startup: it names the exact file, the reason it is
    /// denied, what will fail, the one-time fix, and why no flag helps.
    /// Shortening it defeats the point.
    ///
    /// Only goose is affected today. `~/.config/goose` is granted read-only
    /// because `config.yaml` names `extensions:` commands that auto-run on the
    /// host, so `goose configure` cannot complete from inside the sandbox. Pi
    /// has no interactive login at all (see `oauth_first`: provider API keys
    /// only) and Claude Code's OAuth token lands in the macOS Keychain or
    /// `~/.claude/.credentials.json`, neither of which is denied. For those two
    /// the deny costs package management and statusline/plugin authoring, not
    /// sign-in.
    ///
    /// Deliberately cheap and infallible: any I/O error is read as "assume
    /// configured", so a filesystem hiccup can never turn into a spurious
    /// warning.
    pub fn login_warning(&self, home: &Path) -> Option<String> {
        if matches!(self, Agent::Goose) {
            return Self::goose_unconfigured_warning(home);
        }
        None
    }

    /// The goose case: `~/.config/goose` is granted
    /// read-only, so a first run inside cplt cannot complete `goose configure`.
    ///
    /// The deny is the point,
    /// and the one-time setup belongs on the host. Only a genuinely missing
    /// `config.yaml` counts as unconfigured; any other error is read as
    /// "assume configured" so a filesystem hiccup stays silent.
    fn goose_unconfigured_warning(home: &Path) -> Option<String> {
        let config = std::env::var("XDG_CONFIG_HOME")
            .ok()
            .map_or_else(|| home.join(".config"), PathBuf::from)
            .join("goose/config.yaml");
        if config.try_exists().unwrap_or(true) {
            return None;
        }
        let shown = config.display();
        Some(format!(
            "goose is not configured yet, and cplt grants {shown}'s directory \
             read-only.\n\
             That directory is where goose stores config.yaml, whose \
             `extensions:` entries name a command goose spawns on every session \
             start — so a sandboxed agent that could write it would be planting \
             code that runs outside the sandbox on your next launch.\n\
             \n\
             Launching anyway. If you configure from in here, goose will fail to \
             save the choice — that error is this deny, not a goose bug.\n\
             \n\
             To fix it, configure once outside cplt — a one-time step:\n\
             \n\
             \x20   goose configure\n\
             \n\
             Then run cplt as normal."
        ))
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
            // goose is provider-agnostic (github.com/aaif-goose/goose): it reads the
            // active provider's API key from the environment or its keyring.
            // goose 1.48.0 embeds a catalogue of several hundred providers, so
            // this is deliberately the common subset — each name below was
            // confirmed present in the goose 1.48.0 binary. NOTE: goose reads
            // GOOGLE_API_KEY for its Google provider and does NOT read
            // GEMINI_API_KEY; anything outside this subset still works via an
            // explicit `--pass-env`.
            Agent::Goose => &[
                // Anthropic
                "ANTHROPIC_API_KEY",
                // OpenAI + Azure OpenAI
                "OPENAI_API_KEY",
                "AZURE_OPENAI_API_KEY",
                // Google
                "GOOGLE_API_KEY",
                // Databricks (a first-class goose provider)
                "DATABRICKS_HOST",
                "DATABRICKS_TOKEN",
                // Popular API providers
                "GROQ_API_KEY",
                "OPENROUTER_API_KEY",
                "XAI_API_KEY",
                // AWS Bedrock (bearer token auth)
                "AWS_BEARER_TOKEN_BEDROCK",
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
        // Windows-side installs reached through WSL interop, tracked only so the
        // failure can name the cause instead of "not found in PATH".
        let mut windows_interop: Option<PathBuf> = None;
        let wsl = cfg!(target_os = "linux") && is_wsl();

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

                // Under WSL the Windows PATH is appended to the distro's, so an
                // agent installed on the Windows side turns up here as
                // /mnt/c/.../<binary>: a Windows executable, or the npm shim
                // that execs `node`. Neither runs in the Linux sandbox. Skip it
                // and keep looking — a distro-side install normally comes first
                // in PATH anyway (#188). Checked after canonicalization so a
                // distro-side symlink into /mnt is caught too, matching what
                // `cplt doctor` reports.
                if is_wsl_interop_binary(&resolved, wsl) {
                    if windows_interop.is_none() {
                        ui::warn(&format!(
                            "Ignoring {}, it is a Windows install reached through WSL interop",
                            resolved.display()
                        ));
                        windows_interop = Some(resolved);
                    }
                    continue;
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
            Agent::Antigravity => {
                "Install Antigravity CLI: see https://antigravity.google/docs/cli-getting-started"
            }
            Agent::Pi => "Install Pi: npm i -g @earendil-works/pi-coding-agent",
            Agent::Goose => {
                "Install goose: brew install block-goose-cli, or see \
                 https://goose-docs.ai/docs/getting-started/installation"
            }
            Agent::Claude => {
                "Install Claude Code: npm i -g @anthropic-ai/claude-code, \
                 or see https://docs.anthropic.com/en/docs/claude-code"
            }
            Agent::Shell => unreachable!("Shell is resolved via $SHELL above"),
        };

        if let Some(win) = windows_interop {
            return Err(format!(
                "{} resolves to a Windows install reached through WSL interop:\n  \
                 {}\n  \
                 Under WSL, /mnt/<drive>/ is the Windows filesystem, so that binary is a \
                 Windows executable (npm installs it as a shim that execs `node`) and cannot \
                 run in the Linux sandbox. Unless you installed Node in the distro too, the \
                 shim also has no `node` to exec.\n  \
                 Fix: install Node and the agent inside the WSL distro. {install_hint}",
                self.display_name(),
                win.display()
            ));
        }

        Err(format!(
            "{} not found in PATH. {install_hint}",
            self.display_name()
        ))
    }

    /// Auto-detect which agent to use based on what's available in PATH.
    /// Returns Copilot if found (backward compat), else OpenCode, else
    /// Antigravity.
    /// Pi and Claude are explicit-only (`--agent pi` / `--agent claude`) and are
    /// never auto-detected, to avoid silently changing the default for existing users.
    /// Returns None if none are found.
    pub fn auto_detect() -> Option<Agent> {
        let path_var = std::env::var("PATH").unwrap_or_default();
        let self_exe = std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::canonicalize(&p).ok());

        // Same WSL interop rule as `resolve_binary`: a Windows-side copilot must
        // not win auto-detection over a working distro-side agent (#188).
        let wsl = cfg!(target_os = "linux") && is_wsl();
        let usable = |resolved: &PathBuf| {
            self_exe.as_ref() != Some(resolved) && !is_wsl_interop_binary(resolved, wsl)
        };

        let mut found_copilot = false;
        let mut found_opencode = false;
        let mut found_antigravity = false;

        for dir in path_var.split(':') {
            if !found_copilot {
                let candidate = PathBuf::from(dir).join("copilot");
                if candidate.is_file() {
                    let resolved =
                        std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                    if usable(&resolved) {
                        found_copilot = true;
                    }
                }
            }
            if !found_opencode {
                let candidate = PathBuf::from(dir).join("opencode");
                if candidate.is_file() {
                    let resolved =
                        std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                    if usable(&resolved) {
                        found_opencode = true;
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
                        if usable(&resolved) {
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
            // Removed in favour of Antigravity, which is Google's supported
            // successor and shares the same ~/.gemini tree. A plain "unknown
            // agent" would be unhelpful for a value that worked before.
            "gemini" | "gem" => Err(
                "The Gemini CLI agent was removed from cplt — Google deprecated it in \
                 favour of Antigravity. Use `--agent agy` (or `sandbox.agent = \
                 \"antigravity\"`) instead."
                    .to_string(),
            ),
            "antigravity" | "agy" | "agi" => Ok(Agent::Antigravity),
            "pi" => Ok(Agent::Pi),
            "claude" | "cc" | "claude-code" => Ok(Agent::Claude),
            "goose" => Ok(Agent::Goose),
            "shell" | "sh" | "bash" | "zsh" => Ok(Agent::Shell),
            _ => Err(format!(
                "Unknown agent '{s}'. Supported: copilot, opencode, gemini, antigravity, pi, claude, goose, shell"
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

/// Resolve each agent dir to its real path, in place.
///
/// Both backends match on the *resolved* path — Seatbelt resolves symlinks
/// before matching a `subpath` rule, and Landlock rules attach to the inode —
/// so a rule emitted for a symlinked config dir never matches. Dotfile managers
/// symlink these constantly (`~/.config/opencode -> ~/dotfiles/opencode`), and
/// the result is a hard startup crash: the agent cannot read its own config,
/// and it fails before initializing its logger, so the log the TUI points the
/// user at stays empty (#171).
///
/// User-supplied `allow.read`/`allow.write` paths already canonicalize; this
/// brings the built-in agent dirs in line. Paths that cannot be resolved (a dir
/// the caller has not created yet, a dangling link) are left as-is so the
/// caller still emits a rule for the literal path rather than dropping it.
pub fn canonicalize_agent_dirs(dirs: &mut [AgentDir]) {
    for dir in dirs {
        if let Ok(resolved) = std::fs::canonicalize(&dir.path) {
            dir.path = resolved;
        }
    }
}

/// Are we running inside WSL? Cached — it cannot change within a process.
///
/// Two independent signals, both cheap reads of kernel-owned state:
///
/// - `/run/WSL` exists. WSL's own init creates it; this is snapd's primary
///   signal, and it survives a custom `[wsl2] kernel=` whose
///   `CONFIG_LOCALVERSION` drops the marker below.
/// - the kernel name in `/proc/sys/kernel/osrelease` (what systemd reads) or
///   `/proc/version` names WSL. They cover the reverse case: snapd notes that
///   `/run/WSL` can be missing under undocumented circumstances.
///
/// Deliberately *not* used: `WSL_DISTRO_NAME` and `WSL_INTEROP`. Both are
/// absent under `sudo`, in systemd units and in cron (microsoft/WSL#5914,
/// #9719) — and any user can export them, which disqualifies them from a
/// decision that refuses to run an agent.
pub fn is_wsl() -> bool {
    static WSL: OnceLock<bool> = OnceLock::new();
    *WSL.get_or_init(|| {
        Path::new("/run/WSL").exists()
            || ["/proc/sys/kernel/osrelease", "/proc/version"]
                .iter()
                .any(|f| std::fs::read_to_string(f).is_ok_and(|s| names_wsl_kernel(&s)))
    })
}

/// Does this kernel release or version string come from a WSL kernel?
///
/// Case-insensitive on purpose: WSL2 writes `-microsoft-standard-WSL2` with a
/// lowercase m, WSL1 wrote `4.4.0-19041-Microsoft` with a capital one, so a
/// case-sensitive match for either spelling misses the other. `wsl` is matched
/// too, as systemd does, for kernels that carry only that marker.
fn names_wsl_kernel(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    s.contains("microsoft") || s.contains("wsl")
}

/// Must this resolved agent binary be refused as a Windows interop install?
///
/// The path shape alone is not enough — see [`is_windows_interop_path`] — so
/// callers pass the WSL signal from [`is_wsl`] and this is the only place the
/// two are combined.
pub fn is_wsl_interop_binary(path: &Path, wsl: bool) -> bool {
    wsl && is_windows_interop_path(path)
}

/// Is this path on a Windows drive exposed to WSL as `/mnt/<drive>/…`?
///
/// WSL2 mounts the Windows drives under `/mnt/c`, `/mnt/d`, … and (with
/// interop enabled, the default) appends the Windows `PATH` to the distro's
/// `PATH`. A tool installed on the Windows side therefore resolves inside the
/// distro to `/mnt/c/Users/<user>/AppData/Roaming/npm/<name>` — a Windows
/// executable, or the npm-generated shim that execs `node`. Neither runs in
/// the Linux sandbox (#188).
///
/// The single-letter component is what separates a drive mount from an
/// ordinary `/mnt/data`-style mount point — and, deliberately, from `/mnt/wsl`
/// and `/mnt/wslg`, which are WSL's own tmpfs and WSLg, not Windows paths.
/// `/mnt/c` is also a perfectly ordinary mount on a non-WSL machine (a NAS, a
/// second disk), so callers must gate this on [`is_wsl`]: on a Linux box that
/// is not WSL, a real agent under `/mnt/d` has to keep working.
///
/// Known ceiling: `/mnt` is only the *default* automount root. `[automount]
/// root` in `/etc/wsl.conf` relocates it (Microsoft's own example is
/// `/windir/c`), automount can be switched off, and drives can be mounted
/// anywhere with `mount -t drvfs`. Such a setup is simply not detected — the
/// agent then fails later with its path in the message, which is the failure
/// mode we prefer over refusing a working install. The exact answer is the
/// longest-matching mount for the path in `/proc/self/mountinfo` having fstype
/// `9p` with `aname=drvfs`, `virtiofs`, `virtio-plan9`, or `drvfs`; worth
/// parsing if relocated automount roots ever show up in a bug report.
pub fn is_windows_interop_path(path: &Path) -> bool {
    let mut parts = path.components();
    matches!(parts.next(), Some(std::path::Component::RootDir))
        && parts.next().is_some_and(|c| c.as_os_str() == "mnt")
        && parts.next().is_some_and(|c| {
            let drive = c.as_os_str().as_encoded_bytes();
            drive.len() == 1 && drive[0].is_ascii_alphabetic()
        })
        && parts.next().is_some()
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

    // Trusted paths, not PATH: this runs in the unsandboxed parent before the
    // agent starts, and mise's own shims directory is one of the write+exec
    // grants an agent can plant into. When neither is found in a trusted
    // directory the installs-dir scan below covers the same case, so nothing is
    // lost beyond mise's own version resolution.
    let output = ["mise", "asdf"]
        .iter()
        .filter_map(|tool| crate::git::trusted_binary(tool))
        .filter_map(|tool| {
            std::process::Command::new(&tool)
                .arg("which")
                .arg(binary_name)
                .current_dir(cwd)
                .output()
                .ok()
        })
        .find(|out| out.status.success());

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

    /// Every `Agent` variant, for the tests that must cover all of them.
    /// `all_agents_covers_every_variant` keeps this honest.
    const ALL_AGENTS: [Agent; 7] = [
        Agent::Copilot,
        Agent::OpenCode,
        Agent::Antigravity,
        Agent::Pi,
        Agent::Claude,
        Agent::Goose,
        Agent::Shell,
    ];

    #[test]
    fn all_agents_covers_every_variant() {
        // The match is exhaustive, so adding a variant to `Agent` fails to
        // compile until it is named here; the length check then forces it into
        // ALL_AGENTS as well. Together they stop a new agent from quietly
        // skipping every cross-agent contract test below.
        for agent in ALL_AGENTS {
            match agent {
                Agent::Copilot
                | Agent::OpenCode
                | Agent::Antigravity
                | Agent::Pi
                | Agent::Claude
                | Agent::Goose
                | Agent::Shell => {}
            }
        }
        let mut seen = ALL_AGENTS.to_vec();
        seen.dedup();
        assert_eq!(seen.len(), ALL_AGENTS.len(), "ALL_AGENTS has a duplicate");
    }

    fn agent_dir(path: PathBuf) -> AgentDir {
        AgentDir {
            path,
            write: true,
            map_exec: false,
            process_exec: false,
            write_files: vec![],
        }
    }

    /// The exact path from the #188 report: Copilot CLI installed on the
    /// Windows side, resolved inside the distro through WSL interop.
    ///
    /// Pure path logic, so it runs on every platform. What is *not* covered
    /// here: the `is_wsl() && …` gating at the three call sites, which needs a
    /// real WSL environment (or process-wide env mutation) to exercise.
    #[test]
    fn windows_interop_path_detects_npm_shim_on_c_drive() {
        assert!(is_windows_interop_path(Path::new(
            "/mnt/c/Users/someone/AppData/Roaming/npm/copilot"
        )));
        assert!(is_windows_interop_path(Path::new("/mnt/d/tools/copilot")));
        // Drive letters are lowercase by default but casing is configurable.
        assert!(is_windows_interop_path(Path::new("/mnt/C/tools/copilot")));
    }

    #[test]
    fn windows_interop_path_ignores_ordinary_mounts_and_linux_paths() {
        // Multi-character component: an ordinary mount point, not a drive.
        assert!(!is_windows_interop_path(Path::new("/mnt/data/bin/copilot")));
        assert!(!is_windows_interop_path(Path::new("/mnt/c1/bin/copilot")));
        // A single component that is not a drive letter.
        assert!(!is_windows_interop_path(Path::new("/mnt/1/bin/copilot")));
        assert!(!is_windows_interop_path(Path::new(
            "/usr/local/bin/copilot"
        )));
        assert!(!is_windows_interop_path(Path::new(
            "/home/user/.local/bin/copilot"
        )));
        // WSL's own mounts: /mnt/wsl is its tmpfs, /mnt/wslg is WSLg. Neither
        // is a Windows path, and both must stay usable.
        assert!(!is_windows_interop_path(Path::new("/mnt/wsl/bin/copilot")));
        assert!(!is_windows_interop_path(Path::new("/mnt/wslg/bin/copilot")));
        // A drive root is not a binary, and only absolute paths are mounts.
        assert!(!is_windows_interop_path(Path::new("/mnt/c")));
        assert!(!is_windows_interop_path(Path::new("mnt/c/bin/copilot")));
        assert!(!is_windows_interop_path(Path::new("sub/mnt/c/copilot")));
        // "mnt" must be the first component, not any component.
        assert!(!is_windows_interop_path(Path::new("/opt/mnt/c/copilot")));
    }

    /// The gate itself: `/mnt/c` on a plain Linux box is a NAS, a second disk,
    /// an encrypted volume — an agent there is real and must keep working.
    #[test]
    fn wsl_interop_binary_only_fires_under_wsl() {
        let win = Path::new("/mnt/c/Users/someone/AppData/Roaming/npm/copilot");
        assert!(is_wsl_interop_binary(win, true));
        assert!(!is_wsl_interop_binary(win, false));
        assert!(!is_wsl_interop_binary(
            Path::new("/usr/local/bin/copilot"),
            true
        ));
    }

    /// `/mnt/c` is an ordinary mount point on plenty of non-WSL Linux boxes, so
    /// the interop rule hangs entirely off this signal. Real strings from
    /// `/proc/sys/kernel/osrelease` and `/proc/version`, WSL2 and WSL1 against
    /// a stock distro kernel.
    #[test]
    fn wsl_kernel_names_distinguish_wsl_from_stock_kernels() {
        // osrelease, one short line — what systemd reads.
        assert!(names_wsl_kernel("5.15.167.4-microsoft-standard-WSL2"));
        assert!(names_wsl_kernel("6.6.87.2-microsoft-standard-WSL2+"));
        // WSL1 spelled it with a capital M, WSL2 with a lowercase one: a
        // case-sensitive match for either spelling misses the other.
        assert!(names_wsl_kernel("4.4.0-19041-Microsoft"));
        // /proc/version, the long form.
        assert!(names_wsl_kernel(
            "Linux version 5.15.167.4-microsoft-standard-WSL2 \
             (root@941d701f84f1) (gcc (GCC) 11.2.0, GNU ld (GNU Binutils) 2.37) #1 SMP"
        ));
        // A kernel carrying only the WSL marker, which systemd also matches.
        assert!(names_wsl_kernel("6.18.0-wsl-custom"));

        assert!(!names_wsl_kernel("6.8.0-45-generic"));
        assert!(!names_wsl_kernel(
            "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-091) \
             (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0) #45-Ubuntu SMP"
        ));
        assert!(!names_wsl_kernel(""));
    }

    /// Nothing on macOS may be treated as WSL — neither `/run/WSL` nor the
    /// `/proc` files exist there, and the call sites are
    /// `cfg!(target_os = "linux")`-gated anyway.
    #[test]
    #[cfg(target_os = "macos")]
    fn is_wsl_is_false_on_macos() {
        assert!(!is_wsl());
    }

    /// Dotfile managers routinely symlink `~/.config/<agent>` elsewhere. Both
    /// sandbox backends match on the resolved path, so emitting a rule for the
    /// link is a silent no-op and the agent cannot read its own config (#171).
    #[test]
    #[cfg(unix)]
    fn canonicalize_agent_dirs_resolves_symlinked_config_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("dotfiles-opencode");
        std::fs::create_dir(&real).expect("create real dir");
        let link = tmp.path().join("config-opencode");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let mut dirs = vec![agent_dir(link)];
        canonicalize_agent_dirs(&mut dirs);

        assert_eq!(
            dirs[0].path,
            real.canonicalize().expect("canonicalize real dir"),
            "a symlinked agent dir must be emitted as its resolved target"
        );
    }

    /// A dir that does not resolve (never created, or a dangling link) keeps
    /// its literal path — dropping it would silently remove the grant instead.
    #[test]
    fn canonicalize_agent_dirs_keeps_unresolvable_paths() {
        let missing = PathBuf::from("/definitely/not/a/real/path/cplt-xyzzy");
        let mut dirs = vec![agent_dir(missing.clone())];
        canonicalize_agent_dirs(&mut dirs);
        assert_eq!(dirs[0].path, missing);
    }

    /// Non-symlinked dirs must survive untouched apart from `..`/`.` cleanup.
    #[test]
    fn canonicalize_agent_dirs_leaves_real_dirs_alone() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("plain");
        std::fs::create_dir(&real).expect("create");
        let mut dirs = vec![agent_dir(real.clone())];
        canonicalize_agent_dirs(&mut dirs);
        assert_eq!(dirs[0].path, real.canonicalize().expect("canonicalize"));
    }

    #[test]
    fn parse_agent_names() {
        assert_eq!(Agent::from_str("copilot").unwrap(), Agent::Copilot);
        assert_eq!(Agent::from_str("Copilot").unwrap(), Agent::Copilot);
        assert_eq!(Agent::from_str("opencode").unwrap(), Agent::OpenCode);
        assert_eq!(Agent::from_str("OpenCode").unwrap(), Agent::OpenCode);
        assert_eq!(Agent::from_str("antigravity").unwrap(), Agent::Antigravity);
        assert_eq!(Agent::from_str("agi").unwrap(), Agent::Antigravity);
        assert_eq!(Agent::from_str("agy").unwrap(), Agent::Antigravity);
        assert_eq!(Agent::from_str("goose").unwrap(), Agent::Goose);
        assert_eq!(Agent::from_str("Goose").unwrap(), Agent::Goose);
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
    fn antigravity_binary_name() {
        assert_eq!(Agent::Antigravity.binary_name(), "antigravity");
    }

    #[test]
    fn copilot_needs_sea_extraction() {
        assert!(Agent::Copilot.needs_sea_extraction());
        assert!(!Agent::OpenCode.needs_sea_extraction());
        assert!(!Agent::Antigravity.needs_sea_extraction());
    }

    #[test]
    fn copilot_extra_args() {
        assert_eq!(Agent::Copilot.extra_args(), &["--no-auto-update"]);
        assert!(Agent::OpenCode.extra_args().is_empty());
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
        for agent in [Agent::Pi, Agent::Shell] {
            assert!(
                agent
                    .session_args(Some("id"), true, Some("name"), true)
                    .is_empty(),
                "{agent:?} should not translate any session flags"
            );
        }
    }

    /// `Agent::ALL` must list every variant. The wildcard-free `match` makes a
    /// new variant a compile error here rather than a silently-skipped agent in
    /// every caller that iterates `ALL`.
    #[test]
    fn agent_all_covers_every_variant() {
        fn tag(a: Agent) -> u8 {
            match a {
                Agent::Copilot => 0,
                Agent::OpenCode => 1,
                Agent::Antigravity => 2,
                Agent::Pi => 3,
                Agent::Claude => 4,
                Agent::Goose => 5,
                Agent::Shell => 6,
            }
        }
        assert_eq!(Agent::ALL.len(), 7, "add the new variant to Agent::ALL");
        let mut seen: Vec<u8> = Agent::ALL.iter().copied().map(tag).collect();
        seen.sort_unstable();
        assert_eq!(
            seen,
            (0..7).collect::<Vec<u8>>(),
            "Agent::ALL has a gap or a duplicate"
        );
    }

    #[test]
    fn keychain_needs() {
        // All four are the *base* term — the grant is still conditional on
        // `credential_outside_keychain` at launch (#242).
        assert!(Agent::Copilot.needs_keychain());
        assert!(Agent::Antigravity.needs_keychain());
        assert!(Agent::Claude.needs_keychain());
        assert!(Agent::Goose.needs_keychain());
        assert!(!Agent::OpenCode.needs_keychain());
    }

    #[test]
    fn host_persistence_denies_per_agent() {
        assert_eq!(
            Agent::Claude.host_persistence_denies(),
            ["statusline.sh", "plugins", "settings.json"],
            "Claude's settings.json hooks auto-fire — it must be denied (#237)"
        );
        assert_eq!(
            Agent::Pi.host_persistence_denies(),
            // npm/ and git/ hold already-installed package code, editable in
            // place: denying settings.json alone only stops a NEW entry.
            ["settings.json", "extensions", "npm", "git"]
        );
        assert_eq!(
            Agent::Antigravity.host_persistence_denies(),
            ["hooks.json", "mcp_config.json", "bin"]
        );
        // No writable dir that hosts auto-executing config for these. goose's
        // one auto-exec vector, config.yaml's `extensions:`, lives in a config
        // dir granted read-only, so there is nothing writable left to deny.
        assert!(Agent::Goose.host_persistence_denies().is_empty());
        assert!(Agent::Copilot.host_persistence_denies().is_empty());
        assert!(Agent::OpenCode.host_persistence_denies().is_empty());
        assert!(Agent::Shell.host_persistence_denies().is_empty());
    }

    /// `host_persistence_paths` is what BOTH backends consume — Seatbelt turns
    /// it into deny rules, the Linux path re-binds it read-only — so pinning it
    /// here covers the bubblewrap assembly without needing a Linux host.
    #[test]
    fn host_persistence_paths_join_only_writable_grants() {
        let home = Path::new("/Users/test");

        let dirs = Agent::Pi.config_dirs(home);
        assert_eq!(
            Agent::Pi.host_persistence_paths(&dirs),
            vec![
                home.join(".pi/agent/settings.json"),
                home.join(".pi/agent/extensions"),
                home.join(".pi/agent/npm"),
                home.join(".pi/agent/git"),
            ],
            "exec-only ~/.pi/agent/bin must contribute nothing — its write-deny \
             comes from the exec-only rule instead"
        );

        // Antigravity has two writable grants and its entries belong to one
        // each; the crossed joins are inert but harmless.
        let dirs = Agent::Antigravity.config_dirs(home);
        let paths = Agent::Antigravity.host_persistence_paths(&dirs);
        assert!(paths.contains(&home.join(".gemini/config/hooks.json")));
        assert!(paths.contains(&home.join(".gemini/config/mcp_config.json")));
        assert!(paths.contains(&home.join(".gemini/antigravity-cli/bin")));

        // No denies declared → nothing joined, whatever the grants look like.
        let dirs = Agent::OpenCode.config_dirs(home);
        assert!(Agent::OpenCode.host_persistence_paths(&dirs).is_empty());
    }

    #[test]
    fn login_warning_for_unconfigured_goose() {
        temp_env::with_var_unset("XDG_CONFIG_HOME", || {
            let tmp = tempfile::tempdir().expect("tempdir");
            let home = tmp.path();

            // No config.yaml: goose's first run would try to write it into a
            // read-only dir, so say so before the user meets the bare failure.
            let msg = Agent::Goose
                .login_warning(home)
                .expect("unconfigured goose must warn");
            assert!(msg.contains("not configured"), "{msg}");
            assert!(msg.contains("extensions:"), "why it is denied: {msg}");
            assert!(msg.contains("goose configure"), "must name the fix: {msg}");
            assert!(
                msg.contains(&home.join(".config/goose/config.yaml").display().to_string()),
                "message must name the path: {msg}"
            );

            // Configured: silent.
            std::fs::create_dir_all(home.join(".config/goose")).expect("mkdir");
            std::fs::write(
                home.join(".config/goose/config.yaml"),
                "GOOSE_PROVIDER: openai\n",
            )
            .expect("write config");
            assert!(Agent::Goose.login_warning(home).is_none());
        });
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
    fn every_agent_declares_its_auth_model() {
        // The expectation comes from an EXHAUSTIVE match, not a pinned list: a
        // new agent variant stops compiling here until someone states its auth
        // model, so it cannot slip in uncovered. OAuth-first agents get no
        // "No API keys passed" warning (#187) — their credentials land on disk
        // or in the Keychain after an interactive login.
        fn expected_oauth_first(agent: Agent) -> bool {
            match agent {
                Agent::Copilot => true,     // GitHub device flow + Keychain
                Agent::OpenCode => true,    // /connect device flow -> auth.json
                Agent::Antigravity => true, // Google OAuth + keychain
                Agent::Claude => true,      // subscription OAuth token
                Agent::Pi => false,         // provider API keys only
                Agent::Goose => false,      // provider API keys in the keyring
                Agent::Shell => false,      // not an AI agent, no auth
            }
        }
        for agent in ALL_AGENTS {
            let (agent, expected) = (agent, expected_oauth_first(agent));
            assert_eq!(
                agent.oauth_first(),
                expected,
                "{agent:?} auth model changed — update the docs and the startup \
                 auth hint in main.rs deliberately"
            );
            // Only OAuth-first agents can need the browser hint; a
            // non-OAuth-first agent claiming to need one would print a
            // login pointer to a login flow it does not have.
            if !expected {
                assert!(
                    !agent.oauth_needs_browser(),
                    "{agent:?} is not OAuth-first, so it cannot need a browser login"
                );
            }
            // The startup warning only fires for a non-OAuth-first agent, and
            // it prints `hints[0]` — so such an agent needs a hint to offer
            // (Shell excepted: it has no auth at all).
            if !expected && agent != Agent::Shell {
                assert!(
                    !agent.auth_env_hint().is_empty(),
                    "{agent:?} is not OAuth-first, so it needs an env hint to suggest"
                );
            }
        }
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
        assert!(err.contains("goose"), "error should mention goose: {err}");
    }

    /// `--agent gemini` / `sandbox.agent = "gemini"` worked until the agent was
    /// removed, so the error has to say that rather than "unknown agent".
    #[test]
    fn removed_gemini_agent_points_at_antigravity() {
        for name in ["gemini", "Gemini", "gem"] {
            let err = Agent::from_str(name).unwrap_err();
            assert!(err.contains("removed"), "{name}: {err}");
            assert!(err.contains("agy"), "{name}: {err}");
            assert!(err.contains("antigravity"), "{name}: {err}");
        }
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
    fn parse_goose_agent() {
        assert_eq!(Agent::from_str("goose").unwrap(), Agent::Goose);
        assert_eq!(Agent::from_str("Goose").unwrap(), Agent::Goose);
        assert_eq!(Agent::from_str("GOOSE").unwrap(), Agent::Goose);
    }

    #[test]
    fn goose_binary_and_display_name() {
        assert_eq!(Agent::Goose.binary_name(), "goose");
        assert_eq!(format!("{}", Agent::Goose), "goose");
    }

    #[test]
    fn goose_no_sea_extraction_or_extra_args() {
        assert!(!Agent::Goose.needs_sea_extraction());
        assert!(Agent::Goose.extra_args().is_empty());
    }

    #[test]
    fn goose_needs_keychain() {
        // goose stores provider secrets in the login Keychain by default.
        assert!(Agent::Goose.needs_keychain());
    }

    #[test]
    fn goose_no_copilot_dir() {
        assert!(!Agent::Goose.needs_copilot_dir());
    }

    #[test]
    fn goose_not_auto_detected() {
        // goose is explicit-only; auto_detect must never return it.
        assert_ne!(Agent::auto_detect(), Some(Agent::Goose));
    }

    #[test]
    fn goose_config_dirs_xdg_default() {
        // Wrapped: config_dirs reads XDG_*, so an unwrapped test fails on a
        // machine that sets them.
        temp_env::with_vars(
            [
                ("XDG_CONFIG_HOME", None::<&str>),
                ("XDG_DATA_HOME", None),
                ("XDG_STATE_HOME", None),
            ],
            || {
                let home = Path::new("/Users/test");
                let dirs = Agent::Goose.config_dirs(home);
                assert_eq!(dirs.len(), 3, "config + data + state, no cache dir");
                let config_dir = dirs
                    .iter()
                    .find(|d| d.path == home.join(".config/goose"))
                    .expect("~/.config/goose");
                let data_dir = dirs
                    .iter()
                    .find(|d| d.path == home.join(".local/share/goose"))
                    .expect("~/.local/share/goose");
                let state_dir = dirs
                    .iter()
                    .find(|d| d.path == home.join(".local/state/goose"))
                    .expect("~/.local/state/goose");
                for d in [data_dir, state_dir] {
                    assert!(d.write, "{:?} should be writable", d.path);
                }
                for d in [config_dir, data_dir, state_dir] {
                    assert!(!d.process_exec && !d.map_exec);
                }
            },
        );
    }

    /// `--name ""` is not a session goose can select. Without the emptiness
    /// filter it emits `session --name ""`, turning a bare run into one goose
    /// rejects. `--resume=""` is already filtered the same way.
    #[test]
    fn goose_ignores_an_empty_session_name() {
        assert!(
            Agent::Goose
                .session_args(None, false, Some(""), false)
                .is_empty(),
            "an empty --name must not produce a session subcommand"
        );
        assert_eq!(
            Agent::Goose.session_args(None, false, Some("work"), false),
            vec!["session", "--name", "work"],
            "a real name still selects by name"
        );
    }

    #[test]
    fn goose_config_dir_is_not_writable() {
        // config.yaml's `extensions:` entries name a `cmd` goose spawns on every
        // session start, so a writable ~/.config/goose is a host-persistence
        // vector: the sandboxed agent plants an extension, it runs unsandboxed
        // on the user's next launch. No write_files carve-out either — goose
        // rewrites those files by rename, which needs directory write.
        let dirs = Agent::Goose.config_dirs(Path::new("/Users/test"));
        let config_dir = dirs
            .iter()
            .find(|d| d.path.ends_with("goose") && d.path.to_string_lossy().contains("config"))
            .expect("goose config dir");
        assert!(!config_dir.write, "goose config dir must stay read-only");
        assert!(
            config_dir.write_files.is_empty(),
            "no write_files carve-out: goose writes config.yaml by rename, \
             which needs directory write and would reopen the vector"
        );
    }

    #[test]
    fn goose_config_dirs_respect_xdg() {
        temp_env::with_vars(
            [
                ("XDG_CONFIG_HOME", Some("/xdg/cfg")),
                ("XDG_DATA_HOME", Some("/xdg/data")),
                ("XDG_STATE_HOME", Some("/xdg/state")),
            ],
            || {
                let dirs = Agent::Goose.config_dirs(Path::new("/Users/test"));
                let paths: Vec<_> = dirs.iter().map(|d| d.path.clone()).collect();
                assert!(paths.contains(&PathBuf::from("/xdg/cfg/goose")));
                assert!(paths.contains(&PathBuf::from("/xdg/data/goose")));
                assert!(paths.contains(&PathBuf::from("/xdg/state/goose")));
            },
        );
    }

    #[test]
    fn goose_auth_env_hints() {
        let hints = Agent::Goose.auth_env_hint();
        assert!(hints.contains(&"ANTHROPIC_API_KEY"));
        assert!(hints.contains(&"OPENAI_API_KEY"));
        assert!(hints.contains(&"DATABRICKS_HOST"));
        assert!(hints.contains(&"DATABRICKS_TOKEN"));
        assert!(hints.contains(&"OPENROUTER_API_KEY"));
    }

    #[test]
    fn session_args_goose() {
        // Verified against goose 1.48.0: the flags belong to the `session`
        // SUBCOMMAND — top-level `goose --resume` is rejected by clap — so
        // every translation has to lead with `session`.

        // --resume=ID selects a session by id; --session-id requires --resume.
        assert_eq!(
            Agent::Goose.session_args(Some("sess1"), false, None, false),
            vec!["session", "--resume", "--session-id", "sess1"]
        );
        // Bare --resume resumes the most recent session.
        assert_eq!(
            Agent::Goose.session_args(Some(""), false, None, false),
            vec!["session", "--resume"]
        );
        // --continue is the same thing: goose has no separate continue flag.
        assert_eq!(
            Agent::Goose.session_args(None, true, None, false),
            vec!["session", "--resume"]
        );
        // --name alone starts (or reuses) a named session; --remote is dropped.
        assert_eq!(
            Agent::Goose.session_args(None, false, Some("x"), true),
            vec!["session", "--name", "x"]
        );
        // --name and --session-id are in the same mutually exclusive clap
        // group, so an explicit id wins and --name is never emitted twice.
        assert_eq!(
            Agent::Goose.session_args(Some("sess1"), false, Some("x"), false),
            vec!["session", "--resume", "--session-id", "sess1"]
        );
        // Nothing to translate: bare `goose` already starts a session, so no
        // subcommand is injected and `-- <args>` reach goose unprefixed.
        assert!(
            Agent::Goose
                .session_args(None, false, None, false)
                .is_empty()
        );
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
    fn antigravity_default_domains_include_google_and_own_domain() {
        let domains = Agent::Antigravity.default_allowed_domains();
        // Google AI infra...
        assert!(domains.contains(&"generativelanguage.googleapis.com"));
        assert!(domains.contains(&"accounts.google.com"));
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
    fn goose_gets_registry_base_only() {
        // Observed with goose 1.48.0 on 2026-09-03 via `--observe-domains`: a
        // full session contacted only the configured provider, no goose-owned
        // host. Keep the list at the registry base until someone observes one.
        let domains = Agent::Goose.default_allowed_domains();
        assert_eq!(
            domains.len(),
            PACKAGE_REGISTRY_DOMAINS.len(),
            "goose has no observed own-infra domain; do not fabricate one"
        );
        assert!(domains.contains(&"registry.npmjs.org"));
        // Never contacted by goose 1.48.0; its docs moved to goose-docs.ai.
        assert!(!domains.contains(&"block.github.io"));
        // goose is provider-agnostic: no provider LLM domain is baked in.
        assert!(
            !domains.contains(&"api.anthropic.com")
                && !domains.contains(&"generativelanguage.googleapis.com"),
            "goose must not assume a specific model provider"
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
        for agent in ALL_AGENTS {
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
