//! CLI entry point and subcommand dispatch.

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
#[cfg(target_os = "macos")]
use cplt::gradle_init;
use cplt::{
    agent, audit, check, config, discover, gh_proxy, proxy, repo_config, sandbox, scratch,
    subscriptions, trust, update,
};
use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

/// Build info: if CPLT_LONG_VERSION is set at compile time (via mise tasks),
/// use that; otherwise fall back to the Cargo package version.
const LONG_VERSION: &str = match option_env!("CPLT_LONG_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Run AI coding agents inside a kernel-level sandbox.
///
/// The agent can read and write your project files, but cannot access your
/// SSH keys, cloud credentials, or other secrets. The sandbox is enforced
/// by the OS kernel — the agent (and any process it spawns) cannot bypass it.
///
/// Platform enforcement:
/// - macOS: Apple Seatbelt/SBPL via sandbox-exec
/// - Linux: Landlock LSM + seccomp-BPF (kernel 5.13+, full network filtering on 6.7+)
///
/// Supports GitHub Copilot CLI, OpenCode, Google Gemini CLI, Antigravity CLI,
/// Pi, and Claude Code. Copilot, OpenCode, Gemini, and Antigravity are
/// auto-detected from PATH; Pi and Claude Code are explicit-only — select them
/// with --agent. Use --agent to override the detected agent at any time.
///
/// Defaults can be saved to ~/.config/cplt/config.toml
/// so you don't need to pass flags every time. Run `cplt config init` to
/// create a starter config, or `cplt config validate` to check for typos.
#[derive(Parser)]
#[command(
    name = "cplt",
    version = LONG_VERSION,
    about,
    after_help = "\
EXAMPLES:
  cplt -- -p \"fix the tests\"
    Run Copilot in sandbox (credentials protected, network allowed)

  cplt --agent opencode --pass-env ANTHROPIC_API_KEY
    Run OpenCode in sandbox with Anthropic API key

  cplt --agent gemini
    Run Gemini CLI in sandbox (uses Google OAuth or GEMINI_API_KEY)

  cplt --with-proxy -- -p \"fix the tests\"
    Run with proxy for connection logging and domain blocking

  cplt --allow-read ~/shared-libs -- -p \"use shared-libs\"
    Let the agent read files outside the project directory

  cplt --deny-path ~/.config/gh -- -p \"refactor auth\"
    Block access to a path that is normally allowed

  cplt config validate
    Check config file for typos and unknown keys

  cplt config show
    Show effective configuration (file + defaults)

  cplt config explain sandbox.quiet
    Learn what a config key does and how to set it

  cplt settings
    Browse and edit settings interactively

  cplt update
    Update cplt to the latest release from GitHub

  cplt init
    Detect project tooling and generate a .cplt.toml config

  cplt init --write
    Write the generated .cplt.toml to disk

  cplt trust
    Show per-repo config permissions and their approval status

  cplt trust accept allow_jvm_attach allow_docker
    Approve specific permissions from .cplt.toml

  cplt exec -- npm install
    Run npm install in the sandbox (filesystem/network isolated)

  cplt exec -c \"npm install && npm test\"
    Run compound shell commands in the sandbox

  alias npm=\"cplt exec -- npm\"
    Sandboxed npm for every invocation

  eval \"$(cplt --shell-setup)\"
    Add to your shell rc so 'copilot' runs the sandboxed version
"
)]
struct Cli {
    /// Which AI coding agent to sandbox.
    /// Resolved in order: this flag > sandbox.agent config > auto-detect from PATH.
    /// Supported: copilot, opencode, gemini, antigravity, pi, claude, shell
    #[arg(long, value_name = "AGENT")]
    agent: Option<String>,

    /// Apply a named policy preset that sets a baseline for the five sandbox
    /// toggles (localhost, env files, tmp exec, docker, lifecycle scripts).
    /// Individual flags still override it (e.g. `--preset permissive
    /// --no-allow-tmp-exec`). Resolved in order: this flag > [sandbox] preset
    /// config. `standard` (the default when omitted) is a no-op baseline.
    ///   strict:      all five off (deny-default)
    ///   standard:    current defaults (all five off, scratch dir stays on)
    ///   permissive:  localhost + tmp exec + lifecycle scripts on
    ///   full-trust:  all five on
    #[arg(long, value_name = "PRESET")]
    preset: Option<config::Preset>,

    /// Which directory the agent can read and write to.
    /// Defaults to the current git repository root, or the working directory
    /// if you're not inside a git repo.
    #[arg(long, short = 'd', value_name = "DIR")]
    project_dir: Option<PathBuf>,

    /// Enable a local CONNECT proxy that logs and filters outbound connections.
    /// All agent traffic is routed through the proxy via
    /// HTTP_PROXY/HTTPS_PROXY env vars. Can block known-bad domains with
    /// --blocked-domains. The proxy enforces the same port restrictions as
    /// the sandbox (443 + --allow-port values).
    #[arg(long)]
    with_proxy: bool,

    /// Disable the proxy, even if enabled in config file.
    #[arg(long)]
    no_proxy: bool,

    /// Force all egress through the proxy (#53). Makes the proxy mandatory and
    /// restricts kernel-level egress to the proxy port only (no direct *:443),
    /// closing the raw-socket / `env -u HTTPS_PROXY` bypass. Fails closed: if the
    /// proxy cannot start, the agent is not launched. Conflicts with --no-proxy.
    #[arg(long)]
    proxy_forced: bool,

    /// Disable proxy-forced mode, even if enabled in config file.
    #[arg(long)]
    no_proxy_forced: bool,

    /// Port for the local proxy to listen on [default: ephemeral port].
    /// Only relevant when --with-proxy is enabled.
    #[arg(long, value_name = "PORT")]
    proxy_port: Option<u16>,

    /// File with domains to block (one per line, e.g. pastebin.com).
    /// Only relevant when --with-proxy is enabled.
    /// The proxy will refuse CONNECT requests to these domains.
    /// The file is re-read on every request, so you can edit it live.
    #[arg(long, value_name = "FILE")]
    blocked_domains: Option<PathBuf>,

    /// File with domains to allow (one per line). When set, the proxy
    /// only permits connections to listed domains — everything else is
    /// blocked. Blocklist still applies on top. Parsed at startup.
    #[arg(long, value_name = "FILE")]
    allowed_domains: Option<PathBuf>,

    /// Enable fail-closed networking for this run (#52): restrict egress to the
    /// agent's built-in default allowlist (GitHub Copilot infrastructure +
    /// package registries for Copilot) merged with any --allowed-domains.
    /// Everything else is blocked. Opt-in; overrides proxy.default_allowlist = false.
    #[arg(long)]
    default_allowlist: bool,

    /// Escape hatch: disable the default allowlist for this run and allow all
    /// domains (subject to the blocklist). Overrides --default-allowlist and
    /// proxy.default_allowlist, and also ignores any --allowed-domains file.
    #[arg(long)]
    allow_all_domains: bool,

    /// Discovery mode: run with the proxy in ALLOW-ALL mode (nothing is blocked)
    /// and record every domain the agent contacts, then print the observed set
    /// as a ready-to-paste allowlist. Use it to empirically build/verify an
    /// agent's default allowlist. This run does NOT enforce domain filtering —
    /// it overrides --preset strict / --default-allowlist / any configured
    /// allowlist for the session. See docs/proxy.md.
    #[arg(long)]
    observe_domains: bool,

    /// With --observe-domains, also write the bare observed domain list (one per
    /// line) to this file, in addition to printing it to stderr.
    #[arg(long, value_name = "FILE")]
    observe_domains_out: Option<PathBuf>,

    /// Write proxy connection log to a file (one line per CONNECT).
    /// Useful for post-session audit. File is created if it doesn't exist.
    #[arg(long, value_name = "FILE")]
    proxy_log: Option<PathBuf>,

    /// Proxy stderr verbosity: none (default), error, blocked, or all.
    /// Controls what the proxy prints to stderr. The audit log file
    /// (--proxy-log) always records everything regardless of this setting.
    #[arg(long, value_name = "LEVEL")]
    proxy_log_level: Option<String>,

    /// Timeout for proxy connections in seconds (default: 60).
    /// Prevents long-running requests (like generating large reports) from hanging.
    #[arg(long, value_name = "SECONDS")]
    proxy_timeout: Option<u64>,

    /// Upstream (corporate) proxy to forward CONNECT tunnels through, e.g.
    /// http://corporate-proxy.example.com:8080. cplt still enforces all domain
    /// filtering, logging, and port checks BEFORE forwarding. Optional basic
    /// auth: http://user:pass@host:8080. Only the http scheme is supported.
    #[arg(long, value_name = "URL")]
    proxy_upstream: Option<String>,

    /// Host that BYPASSES the upstream proxy and is connected to directly, like
    /// NO_PROXY. Only meaningful together with --proxy-upstream. Suffix matching:
    /// "example.com" covers all its subdomains. Can be specified multiple times.
    /// When set, overrides proxy.upstream_no_proxy in config; the ambient
    /// NO_PROXY/no_proxy environment is always merged on top. cplt still enforces
    /// all domain, port, and SSRF filtering — the host is just connected directly.
    #[arg(long = "proxy-upstream-no-proxy", value_name = "DOMAIN")]
    proxy_upstream_no_proxy: Vec<String>,

    /// Allow connections to this domain even if it resolves to a private/internal IP.
    /// Use for corporate intranet services such as internal MCP servers.
    /// Suffix matching: "intern.nav.no" covers all its subdomains.
    /// Can be specified multiple times. Merged with proxy.allow_private_domains in config.
    #[arg(long = "allow-private-domain", value_name = "DOMAIN")]
    allow_private_domains: Vec<String>,

    /// Let the agent read files outside the project directory.
    /// Use when the agent needs to reference shared libraries,
    /// monorepo siblings, or documentation stored elsewhere.
    /// Can be specified multiple times.
    #[arg(long = "allow-read", value_name = "PATH")]
    allow_read: Vec<PathBuf>,

    /// Let the agent read AND write files outside the project directory.
    /// Use carefully — this gives the agent full access to modify these paths.
    /// Can be specified multiple times.
    #[arg(long = "allow-write", value_name = "PATH")]
    allow_write: Vec<PathBuf>,

    /// Allow the agent to access a Unix domain socket path (e.g. for LSP server or Docker).
    /// Can be specified multiple times.
    #[arg(long = "allow-socket", value_name = "PATH")]
    allow_socket: Vec<PathBuf>,

    /// Block access to a specific path, even if it would normally be allowed.
    /// Deny rules always win over allow rules. Use this to protect sensitive
    /// files inside otherwise-allowed directories.
    /// Can be specified multiple times.
    #[arg(long = "deny-path", value_name = "PATH")]
    deny_paths: Vec<PathBuf>,

    /// Allow outbound TCP to an additional port beyond 443.
    /// Use for external services the agent needs to reach.
    /// Can be specified multiple times.
    #[arg(long = "allow-port", value_name = "PORT")]
    allow_ports: Vec<u16>,

    /// Allow outbound TCP to localhost on a specific port.
    /// Localhost is blocked by default to prevent SSRF. Use this for
    /// MCP servers, dev servers, or other local services the agent needs.
    /// Can be specified multiple times.
    #[arg(long = "allow-localhost", value_name = "PORT")]
    allow_localhost: Vec<u16>,

    /// Allow outbound TCP to localhost on ALL ports.
    /// Some build tools (Turbopack/Next.js, Vite, esbuild) spawn worker
    /// processes that communicate via TCP on random localhost ports.
    /// This flag allows all localhost traffic. Use --allow-localhost <PORT>
    /// instead if you only need specific ports.
    #[arg(long)]
    allow_localhost_any: bool,

    // The paired --allow-*/--no-allow-* preset toggles below (localhost-any,
    // env-files, lifecycle-scripts, docker, tmp-exec) deliberately do NOT use
    // clap `conflicts_with`. This matches the convention for every paired
    // toggle in this tool (--with-proxy/--no-proxy, --quiet/--no-quiet, …):
    // contradictions are resolved by `FeatureToggle::from_pair`, where OFF
    // wins if both are passed. Off-wins is the safe default for a security
    // tool — a stray `--allow-*` can never silently re-enable a toggle the
    // user also disabled — so we accept the pair rather than erroring on it.
    /// Force localhost-any off, overriding a permissive/full-trust preset or a
    /// config value. Use with --preset to opt out of just this toggle.
    #[arg(long)]
    no_allow_localhost_any: bool,

    /// Allow the agent to read, write, and delete .env files, private keys
    /// (.pem, .key), and other sensitive files in the project directory.
    /// These are blocked by default because they often contain secrets that
    /// a rogue agent could exfiltrate or destroy.
    #[arg(long)]
    allow_env_files: bool,

    /// Force env-file access off, overriding a full-trust preset or a config
    /// value. Use with --preset to opt out of just this toggle.
    #[arg(long)]
    no_allow_env_files: bool,

    /// Pass an additional environment variable through to the sandbox.
    /// By default, only a safe allowlist of env vars is passed (PATH, HOME,
    /// TERM, Go/Java/Rust/Node paths, etc.). Cloud credentials (AWS_*,
    /// DATABASE_URL, NPM_TOKEN) are stripped. For OpenCode, use this to pass
    /// API keys: --pass-env ANTHROPIC_API_KEY
    /// Can be specified multiple times.
    #[arg(long = "pass-env", value_name = "VAR")]
    pass_env: Vec<String>,

    /// Pass ALL environment variables to the sandbox (DANGEROUS).
    /// Disables env sanitization. Cloud credentials, npm tokens, database URLs,
    /// and all other env vars will be visible to the sandboxed process.
    /// Only use when --pass-env is insufficient for debugging.
    #[arg(long)]
    inherit_env: bool,

    /// Allow npm/yarn/pnpm lifecycle scripts (postinstall hooks) to run (DANGEROUS).
    /// Blocked by default to prevent supply chain attacks.
    #[arg(
        long,
        long_help = "\
Allow npm/yarn/pnpm lifecycle scripts (postinstall hooks) to run (DANGEROUS).

These are blocked by default because malicious postinstall hooks are a primary
supply chain attack vector — they can deploy RATs, exfiltrate env vars, or
modify source files during `npm install`.

Only enable this if your project needs native module compilation (node-gyp,
esbuild native, etc.) and `npm install` fails without it. Prefer using
`--ignore-scripts` in npm and adding specific trusted packages instead."
    )]
    allow_lifecycle_scripts: bool,

    /// Force lifecycle scripts off, overriding a permissive/full-trust preset or
    /// a config value. Use with --preset to opt out of just this toggle.
    #[arg(long)]
    no_allow_lifecycle_scripts: bool,

    /// Allow GPG commit/tag signing inside the sandbox (DANGEROUS).
    /// Exposes the GPG agent socket — enables signing AND decryption requests.
    /// Private keys remain protected — only the public keyring and agent
    /// socket are accessible. A compromised process cannot extract the key,
    /// but CAN request arbitrary signatures and decryptions while active.
    #[arg(long)]
    allow_gpg_signing: bool,

    /// Deny the sandboxed agent access to the macOS clipboard (pasteboard)
    #[arg(long = "deny-clipboard")]
    deny_clipboard: bool,

    /// Allow JVM Attach API unix sockets in /tmp.
    /// Needed for JVM testing frameworks that use runtime self-attach:
    /// MockK inline mocking, Mockito inline agents, ByteBuddy, JMX tools.
    /// Only allows sockets matching /tmp/.java_pid<PID> — SSH agent and
    /// all other unix sockets remain blocked.
    #[arg(long)]
    allow_jvm_attach: bool,

    /// Allow MSBuild worker-node unix sockets in /tmp.
    /// Needed for `dotnet build`, which forks worker nodes that communicate
    /// with the client over a Unix domain socket at /tmp/MSBuild<PID>.
    /// This does NOT allow the persistent MSBuild Server (MSBuildServer-<hash>),
    /// which stays blocked; reuse of that server is also disabled via
    /// DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER=1. SSH agent and all other unix
    /// sockets remain blocked.
    #[arg(long)]
    allow_msbuild: bool,

    /// Allow Docker/Colima/OrbStack access inside the sandbox (DANGEROUS).
    #[arg(
        long,
        long_help = "\
Allow Docker/Colima/OrbStack access inside the sandbox (DANGEROUS).

Exposes ~/.docker config (read-only) and Docker daemon unix sockets.
WARNING: Docker container volumes can mount ANY host path, completely
bypassing sandbox filesystem restrictions. A compromised agent could
use `docker run -v /:/host` to read all files on your machine.

Only enable if you trust the agent to manage containers and understand
that Docker volume mounts are an escape hatch from the sandbox."
    )]
    allow_docker: bool,

    /// Force Docker access off, overriding a full-trust preset or a config
    /// value. Use with --preset to opt out of just this toggle.
    #[arg(long)]
    no_allow_docker: bool,

    /// Allow process execution from system temp directories (DANGEROUS).
    /// Prefer --scratch-dir which creates a controlled executable temp dir.
    #[arg(
        long,
        long_help = "\
Allow process execution from system temp directories (DANGEROUS).

Re-enables exec from /private/tmp and /private/var/folders. This weakens
code-exec isolation significantly — any process can drop a binary in /tmp
and this flag lets it execute.

Prefer --scratch-dir which creates a per-session controlled executable temp
directory. Only use --allow-tmp-exec as a last resort when --scratch-dir is
insufficient (e.g., third-party tools that hardcode /tmp for executables)."
    )]
    allow_tmp_exec: bool,

    /// Force tmp exec off, overriding a permissive/full-trust preset or a config
    /// value. Use with --preset to opt out of just this toggle.
    #[arg(long)]
    no_allow_tmp_exec: bool,

    /// Allow process execution from a specific ~/Library/Caches subdirectory.
    /// By default, exec is blocked from ~/Library/Caches to prevent binary-drop
    /// staging attacks. Use this for tools that cache and run executables there,
    /// such as Playwright browsers (ms-playwright) or pnpm dlx packages.
    /// Example: --allow-cache-exec ms-playwright
    /// Can be specified multiple times.
    #[arg(long = "allow-cache-exec", value_name = "SUBDIR")]
    allow_cache_exec: Vec<String>,

    /// Allow process execution from ALL ~/Library/Caches subdirectories (DANGEROUS).
    /// Much broader than --allow-cache-exec. Prefer specifying exact subdirs.
    #[arg(
        long,
        long_help = "\
Allow process execution from ALL ~/Library/Caches subdirectories (DANGEROUS).

This is much broader than --allow-cache-exec which targets specific tool caches.
Grants exec to every binary cached by any application, significantly expanding
the attack surface. Prefer --allow-cache-exec with specific subdirs (e.g.,
--allow-cache-exec ms-playwright --allow-cache-exec gradle)."
    )]
    allow_cache_exec_any: bool,

    /// Allow the agent to open URLs in your default browser.
    /// Needed for OAuth code flows (MCP servers, Gemini CLI, gh auth login).
    /// Disabled by default because it lets the agent leverage your browser session.
    #[arg(long)]
    allow_browser: bool,

    /// Enable a per-session scratch directory for TMPDIR redirect (default).
    /// Creates ~/.cache/cplt/tmp/{session}/ with write+exec permissions
    /// and redirects TMPDIR/GOTMPDIR there. This allows tools like
    /// `go test`, `mise` inline tasks, and `node-gyp` to work.
    /// Cleaned up automatically on exit.
    #[arg(long)]
    scratch_dir: bool,

    /// Disable the per-session scratch directory. TMPDIR will not be
    /// redirected, so tools needing exec in temp may fail.
    #[arg(long)]
    no_scratch_dir: bool,

    /// Enable the gh CLI guard that blocks destructive GitHub operations.
    /// A wrapper script intercepts `gh` commands and blocks destructive writes
    /// (delete repo, merge PR, etc.) while allowing safe reads.
    #[arg(long)]
    gh_guard: bool,

    /// Disable the gh CLI guard (overrides config file setting).
    #[arg(long)]
    no_gh_guard: bool,

    /// Enable git push prevention. Blocks `git push`, `git request-pull`, and `git send-pack`
    /// while allowing all other git operations.
    #[arg(long)]
    git_guard: bool,

    /// Disable git push prevention (overrides config file setting).
    #[arg(long)]
    no_git_guard: bool,

    /// Use Bubblewrap for namespace isolation on Linux (auto-detect if not specified).
    /// Provides defense-in-depth: PID, mount, IPC, UTS, cgroup, and user namespaces
    /// plus a private /tmp, on top of Landlock + seccomp-BPF. The host network is
    /// shared so proxy-based filtering keeps working. Falls back to Landlock+seccomp
    /// if bwrap is unavailable. Only effective on Linux — ignored on macOS.
    #[arg(long)]
    use_bubblewrap: bool,

    /// Disable Bubblewrap namespace isolation even if available (Linux only).
    /// Falls back to Landlock + seccomp-BPF. Use when Bubblewrap causes compatibility
    /// issues with specific tools or environments.
    #[arg(long)]
    no_bubblewrap: bool,

    /// Skip the startup check that verifies the sandbox is working.
    /// The check runs a quick test command inside the sandbox to confirm
    /// that file and network restrictions are active.
    #[arg(long)]
    no_validate: bool,

    /// Print the generated sandbox profile (SBPL) and exit.
    /// Useful for debugging or auditing the sandbox rules.
    #[arg(long)]
    print_profile: bool,

    /// Show sandbox denial logs from macOS in real time.
    /// Starts `log stream` in the background to capture kernel-level
    /// sandbox violations. Helps diagnose why something isn't working.
    #[arg(long)]
    show_denials: bool,

    /// Create a starter config file at ~/.config/cplt/config.toml.
    /// The config lets you save your preferred defaults so you don't need
    /// to pass flags every time. Will not overwrite an existing file.
    #[arg(long)]
    init_config: bool,

    /// Print shell setup code for your shell rc file.
    /// Usage: eval "$(cplt --shell-setup)"
    /// Creates a 'copilot' alias that transparently runs cplt.
    #[arg(long)]
    shell_setup: bool,

    /// Install the shell alias permanently into your shell rc file.
    /// Detects your shell (zsh/bash/fish) and appends the setup line.
    /// Safe to run multiple times — won't add duplicates.
    #[arg(long)]
    shell_install: bool,

    /// [DEPRECATED: use `cplt doctor`] Run environment diagnostics and report
    /// what the sandbox will do. Checks auth mechanisms, Copilot CLI install,
    /// tool availability, and sandbox-critical paths. Exits 0 if all critical checks pass.
    #[arg(long, hide = true)]
    doctor: bool,

    /// Skip the interactive confirmation prompt and proceed immediately.
    /// The sandbox configuration summary is still printed for auditability.
    /// Required when stdin is not a TTY (CI, scripts, piped input).
    /// Can also be set in config: sandbox.yes = true
    #[arg(long, short = 'y')]
    yes: bool,

    /// Show the confirmation prompt even if sandbox.yes = true in the config file.
    /// Overrides the config setting for this run.
    #[arg(long)]
    no_yes: bool,

    /// Auto-approve all permissions from .cplt.toml for this run only.
    /// For CI/scripts where interactive approval isn't possible.
    /// Does not persist trust — approvals apply only to the current invocation.
    #[arg(long)]
    accept_repo_config: bool,

    /// Suppress the startup configuration summary and non-essential messages.
    /// Errors and warnings are always shown. Use when you've reviewed the
    /// sandbox settings and don't need to see them every time.
    /// Can also be set in config: sandbox.quiet = true
    #[arg(long, short = 'q')]
    quiet: bool,

    /// Show the startup configuration summary even if sandbox.quiet = true
    /// in the config file. Overrides the config setting for this run.
    #[arg(long)]
    no_quiet: bool,

    /// Suppress the post-session project-change audit report.
    /// By default, after the sandboxed agent exits, cplt prints a trustworthy
    /// summary of the net file changes made during the session (measured from
    /// outside the sandbox against a pinned baseline commit). Use this to skip
    /// it. Can also be set in config: sandbox.audit = false.
    /// The report is also suppressed under --quiet.
    #[arg(long)]
    no_audit: bool,

    // --- Copilot pass-through flags ---
    // These are forwarded directly to the copilot process for convenience,
    // avoiding the need for -- when using common session-level flags.
    // Ignored when --agent is anything except Copilot.
    /// Resume a previous session. Use --resume to pick interactively,
    /// or --resume=NAME to resume a specific session by name or ID.
    /// Supported for Copilot (--resume), OpenCode (maps to --session),
    /// and Antigravity (maps to --conversation). Ignored for other agents.
    #[arg(long, value_name = "SESSION", num_args = 0..=1, require_equals = true, default_missing_value = "")]
    resume: Option<String>,

    /// Resume the most recent session in this directory.
    /// Supported for Copilot, OpenCode, and Antigravity (--continue).
    /// Ignored for other agents.
    #[arg(long = "continue", conflicts_with = "resume")]
    continue_session: bool,

    /// Enable remote control for the Copilot session.
    /// Allows monitoring and steering from GitHub.com or mobile.
    /// Copilot-only (ignored for other agents).
    #[arg(long)]
    remote: bool,

    /// Name the Copilot session for later resumption with --resume=NAME.
    /// Copilot-only (ignored for other agents).
    #[arg(long = "name", value_name = "SESSION")]
    session_name: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,

    /// Everything after -- is passed directly to the agent process.
    /// Example: cplt -- -p "fix the tests"
    #[arg(last = true, value_name = "AGENT_ARGS")]
    copilot_args: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Manage cplt configuration.
    ///
    /// cplt reads config from `~/.config/cplt/config.toml` by default
    /// (override with `CPLT_CONFIG`).
    ///
    /// Use `cplt config explain` to learn what each key does, `show` to see the
    /// merged result, `set` to save values, and `validate` to catch typos early.
    ///
    /// Use `--repo` with `config set` for project-specific permissions that
    /// should live in `.cplt.toml`, then approve them with `cplt trust`.
    #[command(after_help = "\
QUICK START:
  cplt config explain
    List all keys with their descriptions, current values, and set commands.

  cplt config explain sandbox.allow_docker
    Learn what a specific key does before enabling it.

  cplt config show
    Show the merged config file + defaults.

  cplt config set sandbox.quiet true
    Save a value without editing TOML.

  cplt config validate
    Catch typos and type errors before launch.
")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Browse and edit global and repository settings interactively.
    ///
    /// Uses the same validation and TOML persistence as `cplt config set`.
    /// Requires an interactive terminal; use `cplt config` in scripts and CI.
    Settings,

    /// Update cplt to the latest release.
    ///
    /// Downloads the latest release from GitHub, verifies the SHA256
    /// checksum, and replaces the current binary atomically.
    ///
    /// If installed via Homebrew, directs you to use `brew upgrade` instead.
    Update {
        /// Only check if an update is available (don't download or install).
        #[arg(long)]
        check: bool,

        /// Force update even if already on the latest version.
        #[arg(long)]
        force: bool,
    },

    /// Update subscribed blocklists (issue #144, Phase 1).
    ///
    /// Fetches, SHA256-verifies (when pinned), and caches every blocklist under
    /// [proxy.subscriptions] in your global config, then reports a per-list
    /// result. Cached lists are UNIONed into the effective blocklist on the next
    /// run. Tighten-only and fail-open: a fetch failure keeps the last-good
    /// cache; a pinned-hash mismatch rejects the download (tamper) and keeps the
    /// last-good cache. Subscriptions are global-only — a repo cannot add one.
    #[command(name = "update-lists")]
    UpdateLists,

    /// Manage per-repo trust for .cplt.toml permissions.
    ///
    /// Shows, approves, or revokes trust for sandbox permissions
    /// requested in the current repository's .cplt.toml file.
    Trust {
        #[command(subcommand)]
        action: Option<TrustAction>,
    },

    /// Detect project tooling and generate a .cplt.toml config.
    ///
    /// Scans the project directory for build files, frameworks, and patterns,
    /// then generates sandbox permissions tailored to your stack.
    ///
    /// By default, prints a preview to stdout.
    /// Use --write to persist the generated .cplt.toml.
    Init {
        /// Write the generated config to .cplt.toml (default: preview to stdout).
        #[arg(long)]
        write: bool,

        /// Overwrite existing file (requires --write).
        #[arg(long, requires = "write", conflicts_with = "merge")]
        force: bool,

        /// Merge new detections into existing .cplt.toml (requires --write).
        /// Adds newly detected ports, paths, and flags without removing existing entries.
        #[arg(long, requires = "write")]
        merge: bool,

        /// Suppress ecosystem details, only show generated TOML.
        #[arg(long, short)]
        quiet: bool,

        /// Scan machine-level tools and generate personal config
        /// (~/.config/cplt/config.toml) instead of per-repo .cplt.toml.
        #[arg(long)]
        global: bool,
    },

    /// Run environment diagnostics.
    ///
    /// Checks auth mechanisms, agent install, tool availability,
    /// and sandbox-critical paths. Exits 0 if all critical checks pass.
    Doctor,

    /// Verify & explain sandbox enforcement.
    ///
    /// Runs probes inside the REAL resolved sandbox/proxy (the same policy the
    /// agent would get) and reports, for each, whether cplt allows or blocks it
    /// AND why + the exact fix. Honours the policy-affecting flags — put them
    /// before `check`, e.g. `cplt --preset strict check`.
    ///
    /// With no subcommand it runs a battery demonstrating enforcement and exits
    /// non-zero if the sandbox is NOT enforcing (useful in CI).
    ///
    /// EXAMPLES:
    ///   cplt check
    ///     Enforcement battery + one-line verdict.
    ///   cplt --preset strict check --json
    ///     Machine-readable battery for CI.
    ///   cplt check path ~/.ssh/id_rsa
    ///     Probe a filesystem path (read, and --write).
    ///   cplt check net evil.example
    ///     Probe a domain against the proxy policy.
    ///   cplt check exec docker
    ///     Report whether a command would run or is gated.
    #[command(after_help = "\
NOTE:
  Probes reflect cplt's resolved policy. A passing network probe means
  \"cplt is not blocking this\" — not that the host is up or that an
  arbitrary agent action would behave identically.")]
    Check {
        #[command(subcommand)]
        target: Option<CheckTarget>,

        /// Emit machine-readable JSON instead of the human report.
        #[arg(long, global = true)]
        json: bool,
    },

    /// Run an arbitrary command inside the sandbox.
    ///
    /// Uses the same sandbox as `--agent shell`: filesystem isolation,
    /// env filtering, network proxy, etc.
    ///
    /// stdin/stdout/stderr are passed through transparently.
    /// Exit code is forwarded from the child process.
    /// No startup banner or confirmation prompt — clean for piping and aliases.
    ///
    /// All top-level cplt flags work: --project-dir, --allow-read, --with-proxy, etc.
    ///
    /// EXAMPLES:
    ///   cplt exec -- npm install
    ///   cplt exec --allow-lifecycle-scripts -- npm install
    ///   cplt exec --project-dir /path/to/repo -- make build
    ///   cplt exec -c "npm install && npm test"
    ///   alias npm="cplt exec -- npm"
    Exec {
        /// Run CMD via the shell interpreter ($SHELL -c CMD).
        /// Useful for shell built-ins and compound commands.
        /// Example: cplt exec -c "npm install && npm test"
        #[arg(short = 'c', value_name = "CMD", conflicts_with = "cmd")]
        shell_cmd: Option<String>,

        /// The command and its arguments (everything after --).
        #[arg(last = true, value_name = "CMD")]
        cmd: Vec<String>,
    },

    /// [internal] Evaluate a gh command against the proxy policy.
    ///
    /// Called by the gh wrapper script inside the sandbox. Not intended
    /// for direct use. Evaluates the command, passes through if allowed,
    /// or exits with an error if blocked.
    #[command(hide = true)]
    GhGate {
        /// Path to the real gh binary.
        #[arg(long)]
        real_gh: PathBuf,

        /// Repository scope captured before the sandboxed agent started.
        #[arg(long)]
        repo_scope: Option<String>,

        /// Enforcement mode: block, warn, or audit.
        #[arg(long, default_value = "block")]
        mode: String,

        /// Enable repository scope checking.
        #[arg(long, default_value_t = true)]
        scope_check: bool,

        /// Disable repository scope checking.
        #[arg(long, conflicts_with = "scope_check")]
        no_scope_check: bool,

        /// Block `gh auth token` (credential exfiltration prevention).
        #[arg(long, default_value_t = true)]
        block_auth_token: bool,

        /// Allow `gh auth token`.
        #[arg(long, conflicts_with = "block_auth_token")]
        no_block_auth_token: bool,

        /// Policy for unrecognized commands: "block" or "allow".
        #[arg(long, default_value = "block")]
        unknown_command: String,

        /// Allow `gh api` write operations (POST/PATCH/PUT and input flags), scope-checked.
        #[arg(long, default_value_t = false)]
        allow_api_write: bool,

        /// Block `gh api` write operations (override for --allow-api-write).
        #[arg(long, conflicts_with = "allow_api_write")]
        no_allow_api_write: bool,

        /// gh arguments to evaluate and potentially pass through.
        #[arg(last = true)]
        args: Vec<String>,
    },

    /// [internal] Evaluate a git command against push prevention policy.
    ///
    /// Called by the git wrapper script inside the sandbox. Blocks push
    /// operations while allowing all other git commands.
    #[command(hide = true)]
    GitGate {
        /// Path to the real git binary.
        #[arg(long)]
        real_git: PathBuf,

        /// Enforcement mode: block, warn, or audit.
        #[arg(long, default_value = "block")]
        mode: String,

        /// Whether push prevention is enabled ("true" or "false").
        #[arg(long, default_value = "true")]
        prevent_push: String,

        /// Whether force push prevention is enabled ("true" or "false").
        #[arg(long, default_value = "true")]
        prevent_force_push: String,

        /// Only block pushes to default branch (main/master). Allows pushes to feature branches.
        #[arg(long, default_value = "false")]
        protect_default_branch_only: String,

        /// JSON-encoded allow_push rules (structured push exceptions).
        #[arg(long, default_value = "")]
        allow_push_rules: String,

        /// git arguments to evaluate and potentially pass through.
        #[arg(last = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum CheckTarget {
    /// Probe filesystem access to PATH inside the sandbox.
    ///
    /// Runs a hermetic read (and, with --write, a write) probe inside the real
    /// sandbox and reports allowed/blocked + why + the fix. Reads nothing from
    /// the file and never mutates user state.
    Path {
        /// The path to probe (file or directory).
        path: PathBuf,

        /// Also probe write access (creates and removes a probe file for
        /// directories; append-opens an existing file without writing bytes).
        #[arg(long)]
        write: bool,
    },

    /// Probe a CONNECT to DOMAIN[:PORT] under the resolved proxy policy.
    ///
    /// Blocked targets never leave cplt. An allowed target additionally gets a
    /// real outbound connection attempt to confirm reachability (skip with
    /// --no-connect for a static, policy-only answer).
    Net {
        /// Target as `domain` or `domain:port` (default port 443).
        target: String,

        /// Explain from policy only — do not make any outbound connection.
        #[arg(long)]
        no_connect: bool,
    },

    /// Report whether CMD would run, is guard-blocked, or needs an allow_*.
    Exec {
        /// The command and its arguments.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Validate config file for syntax errors and unknown keys.
    ///
    /// Catches typos like `inherit_evn = true` that are silently
    /// ignored at runtime. Also warns about dangerous settings.
    Validate,

    /// Show effective configuration (file values + defaults).
    ///
    /// Displays what cplt would use at runtime based on the config file,
    /// without CLI flag overrides (those are ephemeral per-invocation).
    Show,

    /// Print config file path.
    ///
    /// Useful for scripting: $EDITOR $(cplt config path)
    Path,

    /// Create a starter config file with documented defaults.
    ///
    /// Creates ~/.config/cplt/config.toml with all options commented out
    /// and explained. Will not overwrite an existing file.
    Init,

    /// Get a config value (from file, or default if not set).
    ///
    /// Prints the value to stdout for scripting.
    /// Example: cplt config get sandbox.quiet
    Get {
        /// Config key in section.key format (e.g., sandbox.quiet, proxy.port)
        key: String,
    },

    /// Set a config value. Creates the config file if it doesn't exist.
    ///
    /// Example: cplt config set sandbox.quiet true
    Set {
        /// Config key in section.key format (e.g., sandbox.quiet, proxy.port)
        key: String,

        /// Value to set (omit when using --unset)
        value: Option<String>,

        /// Append value to an array key instead of replacing.
        /// Note: `set` already appends for array keys, so --append is optional.
        #[arg(long)]
        append: bool,

        /// Remove from config. For scalar keys: removes the key entirely.
        /// For array keys with a value: removes that element from the array.
        /// For array keys without a value: removes the entire key.
        #[arg(long)]
        unset: bool,

        /// Required when setting dangerous keys to true
        /// (sandbox.inherit_env, sandbox.allow_tmp_exec)
        #[arg(long)]
        force: bool,

        /// Write to the repo-local .cplt.toml (proposed/deny settings).
        /// Relaxations go under [propose], tightenings under [deny].
        #[arg(long, conflicts_with = "global")]
        repo: bool,

        /// Write to the global config (~/.config/cplt/config.toml).
        /// This is the default behavior.
        #[arg(long, conflicts_with = "repo")]
        global: bool,
    },

    /// Explain what config keys do.
    ///
    /// Without a key, lists all keys grouped by section.
    /// With a key, shows the description, current value, default, and the
    /// matching `cplt config set ...` command.
    #[command(after_help = "\
EXAMPLES:
  cplt config explain
    Browse all config keys by section.

  cplt config explain sandbox.allow_jvm_attach
    See why Gradle/MockK/Mockito inline mocking may need JVM attach.

  cplt config explain sandbox.allow_docker
    See why Docker access is treated as dangerous.

  cplt config explain allow.read
    Learn how repeated values are merged.
")]
    Explain {
        /// Config key to explain (omit to list all)
        key: Option<String>,
    },
}

#[derive(Subcommand)]
enum TrustAction {
    /// Show trust status for the current repository.
    ///
    /// Displays what .cplt.toml requests and which permissions are approved.
    Show,

    /// Approve specific permissions from .cplt.toml.
    ///
    /// Example: cplt trust accept allow_jvm_attach allow_docker
    Accept {
        /// Permission keys to approve (e.g. allow_jvm_attach, allow_docker).
        /// Without arguments, shows pending permissions and prompts for confirmation.
        keys: Vec<String>,

        /// Approve all permissions without prompting.
        #[arg(long)]
        all: bool,
    },

    /// Revoke trust for specific permissions.
    ///
    /// Example: cplt trust revoke allow_docker
    Revoke {
        /// Keys to revoke (e.g. allow_docker).
        /// Use --all to revoke all trust for this repo.
        #[arg(required_unless_present = "all")]
        keys: Vec<String>,

        /// Revoke all trust for this repo.
        #[arg(long)]
        all: bool,
    },
}

// ── Display labels (single source of truth for consistent CLI output) ──
const SOURCE_GIT_HEAD: &str = "git HEAD (tamper-proof)";
const SOURCE_WORKING_TREE: &str = "working tree (⚠ not committed)";
const LABEL_DENY_APPLIED: &str = "(applied)";
const LABEL_ALLOW_APPROVED: &str = "(approved)";
const LABEL_ALLOW_PENDING: &str = "(pending approval)";
const STATUS_APPROVED: &str = "✓ approved";
const STATUS_PENDING: &str = "○ pending";

fn source_label(source: repo_config::RepoConfigSource) -> &'static str {
    match source {
        repo_config::RepoConfigSource::GitHead => SOURCE_GIT_HEAD,
        repo_config::RepoConfigSource::WorkingTree => SOURCE_WORKING_TREE,
        _ => "unknown",
    }
}

fn detect_project_root() -> Option<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if output.status.success() {
        let path = String::from_utf8(output.stdout).ok()?;
        Some(PathBuf::from(path.trim()))
    } else {
        None
    }
}

// Use library's is_unsafe_root
use cplt::is_unsafe_root;
use cplt::ui;

/// Prompt the user to confirm the sandbox configuration.
///
/// Returns Ok(()) if the user confirms, Err with message if they decline or
/// if no TTY is available without --yes.
fn prompt_confirm(auto_yes: bool, quiet: bool) -> Result<(), String> {
    if auto_yes {
        if !quiet {
            ui::info("Auto-confirmed (--yes)");
        }
        return Ok(());
    }

    // Try to open /dev/tty for the controlling terminal.
    // This works even if stdin is piped.
    let Ok(tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    else {
        return Err(
            "No TTY available for confirmation. Use --yes for non-interactive runs.".to_string(),
        );
    };

    if quiet {
        eprint!(
            "{}[cplt]{} Proceed with sandboxed Copilot? (run without --quiet to review config) [y/N] ",
            ui::color(ui::BLUE),
            ui::color(ui::RESET)
        );
    } else {
        eprint!(
            "{}[cplt]{} Proceed? [y/N] ",
            ui::color(ui::BLUE),
            ui::color(ui::RESET)
        );
    }

    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(tty);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return Err("Failed to read confirmation input".to_string());
    }

    let answer = line.trim().to_lowercase();
    if answer == "y" || answer == "yes" {
        Ok(())
    } else {
        Err("Aborted by user".to_string())
    }
}

/// Canonicalize a list of paths, warning on failures.
fn canonicalize_paths(paths: &[PathBuf], flag_name: &str) -> Vec<PathBuf> {
    paths
        .iter()
        .filter_map(|p| match std::fs::canonicalize(p) {
            Ok(c) => Some(c),
            Err(e) => {
                ui::warn(&format!("{flag_name} path {}: {e}", p.display()));
                None
            }
        })
        .collect()
}

/// Canonicalize deny-paths, failing on any error (security: silent drops are dangerous).
fn canonicalize_deny_paths(paths: &[PathBuf]) -> anyhow::Result<Vec<PathBuf>> {
    paths
        .iter()
        .map(|p| {
            std::fs::canonicalize(p).with_context(|| {
                format!(
                    "--deny-path {} cannot be resolved.\n\
                     Silently dropping deny rules is a security risk.",
                    p.display()
                )
            })
        })
        .collect()
}

/// Grant sandbox access to tool paths relocated via env vars (e.g. `GOPATH`,
/// `CARGO_HOME`, `NODE_PATH`).
///
/// cplt allowlists each tool's *default* directory (e.g. `~/go`, `~/.cargo`),
/// but when a user overrides one of these env vars to a custom path and that
/// value is passed into the sandbox, the custom path is not in the allow set,
/// so builds fail (e.g. `GOPATH=/custom` → `go build` cannot write there).
///
/// We read the *parent* process env (the well-known tool vars all reach the
/// sandbox via the env allowlist), compute the implied read/write paths, then
/// canonicalize and drop any that don't exist — Landlock requires an existing
/// path to open, and macOS SBPL rules for missing paths are inert. Paths are
/// merged into `allow_read`/`allow_write`, which the backends already handle;
/// this only ever *adds* access.
fn merge_tool_path_env_overrides(resolved: &mut config::Resolved, home: &Path) {
    // Read only the handful of recognized tool-path vars rather than snapshotting
    // the entire parent environment — no need to copy unrelated secrets (tokens,
    // credentials) into a Vec just to inspect a fixed, small set of names.
    let env: Vec<(String, String)> = cplt::sandbox::TOOL_PATH_ENV_VARS
        .iter()
        .filter_map(|tv| {
            std::env::var(tv.name)
                .ok()
                .map(|v| (tv.name.to_string(), v))
        })
        .collect();
    for ovr in cplt::sandbox::tool_path_env_overrides(&env, home) {
        // canonicalize() also serves as the existence check: a missing path errors.
        let Ok(path) = std::fs::canonicalize(&ovr.path) else {
            continue;
        };
        // Security guard: an ambient tool-path env var (exported long ago for
        // unrelated reasons, or injected via a repo config / --pass-env) must
        // never widen the sandbox to an unsafe root or to HOME/its ancestors —
        // e.g. GOPATH=$HOME would make the whole home dir writable, GOPATH=/ the
        // whole filesystem. canonicalize() above has already resolved any `..`,
        // so this is the single choke point where the effective grant is vetted.
        // Applies to read grants too (read access to `/` or `$HOME` over-grants).
        if !cplt::sandbox::tool_override_path_is_safe(&path, home) {
            ui::warn(&format!(
                "Ignoring {} = {}: resolves to an unsafe root or HOME and would defeat the sandbox",
                ovr.name,
                path.display()
            ));
            continue;
        }
        let target = if ovr.write {
            &mut resolved.allow_write
        } else {
            &mut resolved.allow_read
        };
        if !target.contains(&path) {
            target.push(path);
        }
    }
}

/// Resolved configuration, paths, and agent info needed by the sandbox.
#[allow(dead_code)] // unapproved_proposals is consumed by the warning block in resolve_context
struct ResolvedContext {
    resolved: config::Resolved,
    config_path: Option<PathBuf>,
    home_dir: PathBuf,
    project_dir: PathBuf,
    active_agent: agent::Agent,
    unapproved_proposals: Vec<String>,
}

/// Load config, merge CLI flags, resolve paths, detect agent, print info messages.
fn resolve_context(cli: &Cli, check_mode: bool) -> anyhow::Result<ResolvedContext> {
    // Canonicalize CLI paths for consistency with config path handling
    let cli_allow_read = canonicalize_paths(&cli.allow_read, "--allow-read");
    let cli_allow_write = canonicalize_paths(&cli.allow_write, "--allow-write");
    let cli_allow_socket = canonicalize_paths(&cli.allow_socket, "--allow-socket");
    let cli_deny_paths = canonicalize_deny_paths(&cli.deny_paths)?;

    let (cfg, config_path) = match config::Config::load_file() {
        Ok(Some(loaded)) => (loaded.config, Some(loaded.path)),
        Ok(None) => (config::Config::default(), None),
        Err(e) => bail!("{e}"),
    };
    let mut resolved = match cfg.merge(config::CliFlags {
        preset: cli.preset,
        proxy: config::FeatureToggle::from_pair(cli.with_proxy, cli.no_proxy),
        proxy_forced: config::FeatureToggle::from_pair(cli.proxy_forced, cli.no_proxy_forced),
        proxy_port: cli.proxy_port,
        blocked_domains: cli.blocked_domains.clone(),
        allowed_domains: cli.allowed_domains.clone(),
        // --default-allowlist enables, --allow-all-domains disables (off wins).
        default_allowlist: config::FeatureToggle::from_pair(
            cli.default_allowlist,
            cli.allow_all_domains,
        ),
        allow_all_domains: cli.allow_all_domains,
        proxy_log_file: cli.proxy_log.clone(),
        proxy_log_level: match cli.proxy_log_level.as_deref() {
            Some(s) => match s.parse::<crate::proxy::ProxyLogLevel>() {
                Ok(l) => Some(l),
                Err(e) => bail!("{e}"),
            },
            None => None,
        },
        proxy_timeout: cli.proxy_timeout,
        proxy_upstream: cli.proxy_upstream.clone(),
        proxy_upstream_no_proxy: cli.proxy_upstream_no_proxy.clone(),
        allow_private_domains: cli.allow_private_domains.clone(),
        allow_read: cli_allow_read,
        allow_write: cli_allow_write,
        allow_socket: cli_allow_socket,
        deny_paths: cli_deny_paths,
        allow_ports: cli.allow_ports.clone(),
        allow_localhost: cli.allow_localhost.clone(),
        allow_localhost_any: config::FeatureToggle::from_pair(
            cli.allow_localhost_any,
            cli.no_allow_localhost_any,
        ),
        allow_env_files: config::FeatureToggle::from_pair(
            cli.allow_env_files,
            cli.no_allow_env_files,
        ),
        no_validate: cli.no_validate,
        pass_env: cli.pass_env.clone(),
        inherit_env: cli.inherit_env,
        allow_lifecycle_scripts: config::FeatureToggle::from_pair(
            cli.allow_lifecycle_scripts,
            cli.no_allow_lifecycle_scripts,
        ),
        allow_gpg_signing: cli.allow_gpg_signing,
        deny_clipboard: cli.deny_clipboard,
        allow_jvm_attach: cli.allow_jvm_attach,
        allow_msbuild: cli.allow_msbuild,
        // Config-only opt-in; no CLI flag.
        gradle_init: false,
        allow_docker: config::FeatureToggle::from_pair(cli.allow_docker, cli.no_allow_docker),
        allow_tmp_exec: config::FeatureToggle::from_pair(cli.allow_tmp_exec, cli.no_allow_tmp_exec),
        allow_cache_exec: cli.allow_cache_exec.clone(),
        allow_cache_exec_any: cli.allow_cache_exec_any,
        allow_browser: cli.allow_browser,
        scratch: config::FeatureToggle::from_pair(cli.scratch_dir, cli.no_scratch_dir),
        use_bubblewrap: config::FeatureToggle::from_pair(cli.use_bubblewrap, cli.no_bubblewrap),
        quiet: config::FeatureToggle::from_pair(cli.quiet, cli.no_quiet),
        // Audit is on by default; only --no-audit forces it off from the CLI.
        audit: config::FeatureToggle::from_pair(false, cli.no_audit),
        yes: config::FeatureToggle::from_pair(cli.yes, cli.no_yes),
        gh_guard: config::FeatureToggle::from_pair(cli.gh_guard, cli.no_gh_guard),
        git_push_prevention: config::FeatureToggle::from_pair(cli.git_guard, cli.no_git_guard),
    }) {
        Ok(r) => r,
        Err(e) => bail!("{e}"),
    };

    // Resolve home directory
    let home_dir = match std::env::var("HOME") {
        Ok(h) => std::fs::canonicalize(&h)
            .map_err(|e| anyhow::anyhow!("Cannot resolve $HOME ({h}): {e}"))?,
        Err(_) => bail!("$HOME not set"),
    };

    // Resolve project directory
    let project_dir = match &cli.project_dir {
        Some(p) => std::fs::canonicalize(p)
            .map_err(|e| anyhow::anyhow!("Cannot resolve project dir: {e}"))?,
        None => {
            if let Some(root) = detect_project_root() {
                match std::fs::canonicalize(&root) {
                    Ok(p) => p,
                    Err(_) => root,
                }
            } else {
                ui::warn("No git repo detected, using cwd");
                std::env::current_dir()
                    .and_then(std::fs::canonicalize)
                    .map_err(|e| anyhow::anyhow!("Cannot resolve cwd: {e}"))?
            }
        }
    };

    // Safety check: reject overly broad project roots
    if is_unsafe_root(&project_dir, &home_dir) {
        bail!(
            "Refusing to sandbox '{}' — too broad. Use a specific project directory.",
            project_dir.display()
        );
    }

    // ── Load and apply per-repo config (.cplt.toml) ──────────────
    let mut unapproved_proposals: Vec<String> = Vec::new();
    match repo_config::load_repo_config(&project_dir) {
        Ok(Some(loaded)) => {
            if !resolved.quiet {
                let source_note = match loaded.source {
                    repo_config::RepoConfigSource::GitHead => "",
                    repo_config::RepoConfigSource::WorkingTree => {
                        ui::warn(&format!(".cplt.toml source: {SOURCE_WORKING_TREE}"));
                        " (working tree)"
                    }
                    _ => "",
                };
                ui::info(&format!("Repo config: .cplt.toml{source_note}"));
            }

            // Determine approved keys
            let approved_keys: Vec<String> = if cli.accept_repo_config {
                // --accept-repo-config: approve everything
                repo_config::proposed_keys(&loaded.config.propose)
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect()
            } else {
                // Check trust store — validate content hash
                if let Some(t) = trust::load_trust(&project_dir) {
                    let current_hash = trust::proposal_content_hash(&loaded.config.propose);
                    // Finding 4: the trust file is keyed on the git origin URL, which
                    // the repo can forge (`git remote set-url origin <victim>` + copy
                    // the victim's approved [propose] block so the content hash matches
                    // too). Bind the approval to the local checkout path: a matching
                    // fingerprint presented from a DIFFERENT path is NOT auto-trusted,
                    // defeating the confused-deputy escalation.
                    if !trust::approved_path_matches(&t, &project_dir) {
                        if !resolved.quiet {
                            let where_approved = if t.repo.path.is_empty() {
                                "an unrecorded location".to_string()
                            } else {
                                t.repo.path.clone()
                            };
                            ui::warn(&format!(
                                ".cplt.toml for this remote was approved at a different path ({where_approved}) — \
                                 not auto-trusting here. Re-approve with `cplt trust accept`.",
                            ));
                        }
                        Vec::new()
                    }
                    // Treat a legacy empty stored hash as STALE (see approval_is_stale):
                    // it pins nothing, so applying its keys against arbitrary proposal
                    // *values* with no re-prompt would be unsafe.
                    else if trust::approval_is_stale(&t.accepted.content_hash, &current_hash) {
                        // Proposals changed since approval (or a legacy unpinned
                        // entry) — invalidate and require re-approval.
                        if !resolved.quiet {
                            ui::warn(
                                ".cplt.toml permissions changed since last approval — re-approve with `cplt trust accept`",
                            );
                        }
                        Vec::new()
                    } else {
                        t.accepted.keys
                    }
                } else {
                    // No trust entry — first time seeing this repo config
                    let proposed = repo_config::proposed_keys(&loaded.config.propose);
                    if !proposed.is_empty() && !resolved.quiet {
                        ui::warn(
                            "Untrusted .cplt.toml — this repo wants to relax sandbox permissions.",
                        );
                        eprintln!(
                            "  {}⚠{} Review proposed permissions before approving.",
                            ui::color(ui::YELLOW),
                            ui::color(ui::RESET)
                        );
                        eprintln!(
                            "  {}Show:{} cplt trust        {}Approve:{} cplt trust accept --all",
                            ui::color(ui::DIM),
                            ui::color(ui::RESET),
                            ui::color(ui::DIM),
                            ui::color(ui::RESET),
                        );
                    }
                    Vec::new()
                }
            };

            let approved_refs: Vec<&str> = approved_keys
                .iter()
                .map(std::string::String::as_str)
                .collect();
            unapproved_proposals = resolved.apply_repo_config(&loaded.config, &approved_refs);
        }
        Ok(None) => {} // No .cplt.toml — nothing to do
        Err(e) => {
            ui::warn(&format!("Failed to load .cplt.toml: {e}"));
        }
    }

    // Reconcile proxy.forced vs allow_localhost_any (#53). Done here, after all
    // sources (CLI, user config, repo proposal) are merged, so every downstream
    // consumer — the startup summary and the sandbox policy — sees the resolved
    // value. proxy.forced supersedes allow_localhost_any (forces it off) rather
    // than erroring, so the feature stays usable where allow_localhost_any is set.
    if resolved.reconcile_proxy_forced() {
        ui::warn(
            "proxy.forced is active: ignoring allow_localhost_any — all outbound traffic \
             must go through the proxy. Allowing any localhost port would disable kernel \
             network restriction and defeat forced egress.",
        );
    }

    // Show unapproved permissions warning (non-fatal — deny-default keeps us safe)
    if !unapproved_proposals.is_empty() && !resolved.quiet {
        ui::warn(&format!(
            ".cplt.toml has {} unapproved permission(s):",
            unapproved_proposals.len()
        ));
        for key in &unapproved_proposals {
            eprintln!("  {}○{} {key}", ui::color(ui::YELLOW), ui::color(ui::RESET));
        }
        eprintln!(
            "  Run: {}cplt trust accept --all{}  (or select specific keys)",
            ui::color(ui::GREEN),
            ui::color(ui::RESET)
        );
    }

    if !resolved.quiet {
        ui::info(&format!("Project:  {}", project_dir.display()));
        ui::info(&format!("Home:     {}", home_dir.display()));
        if let Some(ref cp) = config_path {
            ui::info(&format!("Config:   {}", cp.display()));
        }
    }

    // Resolve which agent to sandbox
    // Precedence: CLI --agent > config sandbox.agent > auto_detect > error
    let active_agent = match &cli.agent {
        Some(name) => match name.parse::<agent::Agent>() {
            Ok(a) => a,
            Err(e) => bail!("{e}"),
        },
        None => match &resolved.agent {
            Some(name) => match name.parse::<agent::Agent>() {
                Ok(a) => a,
                Err(e) => bail!("Invalid sandbox.agent config value: {e}"),
            },
            None => match agent::Agent::auto_detect() {
                Some(a) => a,
                None => {
                    // --print-profile and --doctor don't need a real agent binary.
                    // Default to Copilot so they work without anything installed.
                    if cli.print_profile || cli.doctor {
                        agent::Agent::Copilot
                    } else if check_mode {
                        // `cplt check` is a diagnostic: users run it precisely when
                        // unsure what's installed, so it must not hard-require an
                        // agent binary. With no --agent and nothing auto-detected,
                        // fall back to the always-available Shell profile (uses
                        // $SHELL / /bin/sh, no external binary) rather than erroring.
                        // Printed even under check's default --quiet: it explains
                        // which profile is being reported. Goes to stderr, so it
                        // never contaminates --json output on stdout.
                        ui::info(
                            "check: no agent specified/detected — checking the 'shell' \
                             sandbox profile (pass --agent <name> to check a specific \
                             agent's policy)",
                        );
                        agent::Agent::Shell
                    } else {
                        bail!(
                            "No supported AI coding agent found in PATH. \
                             Install one of:\n\
                             [cplt]   Copilot CLI: brew install --cask copilot-cli\n\
                             [cplt]   OpenCode:    npm i -g opencode-ai\n\
                             [cplt]   Gemini CLI:  npm i -g @google/gemini-cli\n\
                             [cplt]   Antigravity: https://antigravity.google/docs/cli-getting-started\n\
                             [cplt]   Pi:          npm i -g @earendil-works/pi-coding-agent\n\
                             [cplt]   Claude Code: npm i -g @anthropic-ai/claude-code\n\
                             [cplt] Or specify explicitly: cplt --agent copilot|opencode|gemini|antigravity|pi|claude|shell"
                        );
                    }
                }
            },
        },
    };

    if !resolved.quiet {
        ui::info(&format!("Agent:    {}", active_agent.display_name()));
    }

    // Hint about API keys for agents that need them
    if active_agent != agent::Agent::Copilot {
        let hints = active_agent.auth_env_hint();
        let parent_env: Vec<(String, String)> = std::env::vars().collect();
        let has_api_key = hints.iter().any(|key| {
            parent_env.iter().any(|(k, _)| k == *key) && resolved.pass_env.iter().any(|v| v == *key)
        });
        // OAuth-first agents (Copilot, OpenCode, Gemini, Antigravity, Claude
        // Code) keep their credentials on disk in a granted config dir or the
        // macOS Keychain after an interactive login, so they authenticate with
        // no env var. Don't nag them about API keys: they prompt for login
        // themselves when unauthenticated, and the warning otherwise fires for
        // a correctly configured user and reads like a startup failure (#187).
        // The hints stay for users who deliberately route via an API key or an
        // enterprise endpoint (documented in the README).
        if !has_api_key && !resolved.inherit_env && !hints.is_empty() && !active_agent.oauth_first()
        {
            ui::warn(&format!(
                "No API keys passed. {} needs a provider API key:",
                active_agent.display_name()
            ));
            // Prefer showing a hint for a key that's already in the parent env
            // (user has it set but forgot --pass-env). Fall back to the first hint.
            let hint_to_show = hints
                .iter()
                .find(|key| parent_env.iter().any(|(k, _)| k == *key))
                .copied()
                .unwrap_or(hints[0]);
            ui::warn(&format!(
                "  cplt --agent {} --pass-env {}",
                active_agent.binary_name(),
                hint_to_show
            ));
        }

        // Suppressing the API-key hint for OAuth-first agents leaves the
        // browser-flow ones with no signal at all: Google's login opens a
        // browser, and --allow-browser is off by default, so a first-time user
        // hits a dead end. Point at the flag rather than the key.
        if active_agent.oauth_first()
            && active_agent.oauth_needs_browser()
            && !resolved.allow_browser
        {
            ui::warn(&format!(
                "{} signs in through a browser on first run — add --allow-browser \
                 if you have not authenticated yet.",
                active_agent.display_name()
            ));
        }

        // Warn if Copilot-only flags are used with a non-Copilot agent
        let copilot_flags_used: Vec<&str> = [
            cli.resume.as_ref().map(|_| "--resume"),
            if cli.continue_session {
                Some("--continue")
            } else {
                None
            },
            if cli.remote { Some("--remote") } else { None },
            cli.session_name.as_ref().map(|_| "--name"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !copilot_flags_used.is_empty() {
            ui::warn(&format!(
                "Ignoring Copilot-only flags for {}: {}",
                active_agent.display_name(),
                copilot_flags_used.join(", ")
            ));
        }
    }

    Ok(ResolvedContext {
        resolved,
        config_path,
        home_dir,
        project_dir,
        active_agent,
        unapproved_proposals,
    })
}

/// Start the CONNECT proxy if enabled, returning the handle for RAII ownership.
/// Updates `resolved.proxy_port` with the actual bound port.
/// Print the observed domain set (from `--observe-domains`) to stderr as a
/// ready-to-paste allowlist, and optionally write the bare list to `out_file`.
///
/// Always prints regardless of `--quiet`: observe-domains is an explicit
/// diagnostic whose result is the entire purpose of the run. Subdomains are NOT
/// auto-collapsed — folding e.g. `api.githubcopilot.com` +
/// `proxy.githubcopilot.com` to `githubcopilot.com` needs a registrable-domain
/// (public-suffix) heuristic that would risk over-broadening the allowlist, so
/// the raw observed hosts are emitted and the note points out that the matcher
/// is exact-or-subdomain and a parent can be substituted by hand.
fn emit_observed_domains(
    agent_label: &str,
    observed: &[proxy::ObservedDomain],
    out_file: Option<&Path>,
) {
    let count = observed.len();
    eprintln!(
        "[cplt] observe-domains: {count} domain{} contacted by {agent_label} this session",
        if count == 1 { "" } else { "s" }
    );
    eprintln!("# add to allowed_domains (or src/agent.rs default_allowed_domains):");
    eprintln!("# bare hosts, exact-or-subdomain match; collapse subdomains to a parent by hand");
    eprintln!("# e.g. api.githubcopilot.com + proxy.githubcopilot.com -> githubcopilot.com");
    for o in observed {
        // In pure observe (allow-all) mode every entry is Allowed and prints
        // bare. A Blocked entry can only appear if an allowlist was somehow
        // active; flag it so it is not pasted blindly.
        match o.verdict {
            proxy::DomainVerdict::Allowed => eprintln!("{}", o.host),
            proxy::DomainVerdict::Blocked => eprintln!("{}  # BLOCKED this run", o.host),
        }
    }

    if let Some(path) = out_file {
        // The out-file is meant to be a ready-to-use allowlist, so it must
        // contain ONLY hosts that were actually PERMITTED. In observe mode
        // domain filtering is off, but port policy / blocklist / private-IP
        // guards still enforce — a host refused by those is recorded Blocked.
        // Skip Blocked entries here so a user scripting off --observe-domains-out
        // never pastes a policy-blocked host into their allowlist. (The stderr
        // output above still lists Blocked hosts annotated '# BLOCKED this run'.)
        // If every entry was Blocked the out-file is written empty, which is a
        // valid allowlist.
        let allowed: Vec<&str> = observed
            .iter()
            .filter(|o| o.verdict == proxy::DomainVerdict::Allowed)
            .map(|o| o.host.as_str())
            .collect();
        let written = allowed.len();
        let body: String = allowed.iter().map(|h| format!("{h}\n")).collect();
        match std::fs::write(path, body) {
            Ok(()) => eprintln!(
                "[cplt] observe-domains: wrote {written} domains to {}",
                path.display()
            ),
            Err(e) => ui::warn(&format!(
                "observe-domains: cannot write {}: {e}",
                path.display()
            )),
        }
    }
}

/// The domain-allowlist resolution decision for a run.
///
/// Extracted as a pure function so the security-critical no-leak invariant can
/// be unit-tested in isolation: the observe-mode allow-all override is
/// **flag-gated** — it can only null the allowlist when `--observe-domains` is
/// set — and it touches **only** the domain allowlist, never port/SSRF policy
/// (which are resolved elsewhere and not visible here). A run with no override
/// keeps its configured / default allowlist and enforcement is preserved.
struct DomainAllowlistDecision {
    /// Whether the explicit `allowed_domains` file is consulted this run.
    /// `false` = allow-all (the file is dropped, no domain enforcement from it).
    use_allowed_file: bool,
    /// Whether the agent's built-in default allowlist contributes this run.
    use_default_allowlist: bool,
    /// Whether the proxy must be forced on (observe mode needs a choke point to
    /// record CONNECTs even if the user disabled the proxy).
    force_proxy_on: bool,
}

/// Compute the domain-allowlist decision from the two allow-all escape hatches
/// and whether the agent default allowlist is enabled.
///
/// `--observe-domains` forces allow-all exactly like `--allow-all-domains`
/// (drops both the configured file and the agent defaults so the FULL contacted
/// set is observed) and additionally forces the proxy on. Both overrides are
/// flag-gated: with neither flag set the configured / default allowlist stands.
fn resolve_domain_allowlist_decision(
    observe_domains: bool,
    allow_all_domains: bool,
    default_allowlist_enabled: bool,
) -> DomainAllowlistDecision {
    let observe_allow_all = observe_domains;
    DomainAllowlistDecision {
        use_allowed_file: !(allow_all_domains || observe_allow_all),
        use_default_allowlist: default_allowlist_enabled && !observe_allow_all,
        force_proxy_on: observe_domains,
    }
}

fn start_proxy_if_enabled(
    resolved: &mut config::Resolved,
    cli: &Cli,
    config_path: Option<&PathBuf>,
    active_agent: agent::Agent,
) -> anyhow::Result<Option<proxy::ProxyHandle>> {
    // Proxy-forced (#53): the proxy is mandatory. `with_proxy` defaults to true,
    // so the only way it is false here is an explicit disable (--no-proxy or
    // proxy.enabled = false) — that conflicts with --proxy-forced. Reject it
    // rather than silently picking a side, then force the proxy on so the
    // fail-closed start path below applies.
    if resolved.proxy_forced {
        // proxy.forced vs allow_localhost_any is reconciled earlier in
        // resolve_context (proxy.forced wins, allow_localhost_any forced off).
        // The remaining incompatibility is an explicitly disabled proxy.
        if !resolved.with_proxy {
            bail!(
                "conflicting options: --proxy-forced requires the proxy, but it was \
                 explicitly disabled (--no-proxy or proxy.enabled = false). \
                 Remove one of them."
            );
        }
        resolved.with_proxy = true;
    }

    // Domain-allowlist resolution (security-critical, see
    // resolve_domain_allowlist_decision): the observe-mode allow-all override is
    // flag-gated and touches only the domain allowlist. Computed once here and
    // consumed both to force the proxy on (discovery choke point) and to null
    // the effective allowlist below.
    let allowlist_decision = resolve_domain_allowlist_decision(
        cli.observe_domains,
        resolved.allow_all_domains,
        resolved.default_allowlist,
    );

    // Discovery mode (--observe-domains): force the proxy ON so there is a choke
    // point to record CONNECTs, even if the user disabled it. The allow-all
    // override (empty effective allowlist) is applied below where the allowlist
    // is computed. Print the mandatory warning that this run does NOT enforce
    // domain filtering.
    if allowlist_decision.force_proxy_on {
        resolved.with_proxy = true;
        ui::warn("observe-domains: proxy in allow-all mode; all traffic permitted and recorded");
        ui::warn(
            "observe-domains: this run does NOT enforce domain filtering \
             (overrides --preset strict / --default-allowlist / configured allowlist)",
        );
    }

    if !resolved.with_proxy || cli.print_profile {
        return Ok(None);
    }

    let blocked_file = resolved.blocked_domains.clone().unwrap_or_else(|| {
        // Look for blocked-domains.txt next to the binary, then blocked.txt
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf));
        if let Some(ref dir) = exe_dir {
            let preferred = dir.join("blocked-domains.txt");
            if preferred.exists() {
                return preferred;
            }
            let fallback = dir.join("blocked.txt");
            if fallback.exists() {
                return fallback;
            }
        }
        // No blocklist found — return a path that won't exist,
        // proxy will run without blocking any domains
        PathBuf::from("/dev/null/no-blocklist")
    });

    // Escape hatch (#52): --allow-all-domains forces allow-all for this run,
    // disabling BOTH the agent default allowlist and any explicit
    // allowed_domains file. `resolved.default_allowlist` was already forced off
    // in the config merge when --allow-all-domains is set.
    // --observe-domains forces allow-all exactly like --allow-all-domains: no
    // allowlist file and (below) no agent default allowlist, so nothing is
    // blocked and the FULL contacted set is observed. This must override any
    // configured allowlist, not combine with it (fail-closed would hide domains).
    let allowed_domains_file = if allowlist_decision.use_allowed_file {
        resolved.allowed_domains.clone()
    } else {
        None
    };

    // Fail-closed networking (#52): when proxy.default_allowlist is on, the
    // effective allowlist is the running agent's built-in defaults, which the
    // proxy MERGES with the user's allowed_domains file. Empty vec = feature
    // off, so the proxy keeps today's allow-all behaviour unchanged.
    let default_allowlist: Vec<String> = if allowlist_decision.use_default_allowlist {
        active_agent
            .default_allowed_domains()
            .iter()
            .map(|d| (*d).to_string())
            .collect()
    } else {
        Vec::new()
    };

    // Validate domain allowlist file at startup (fail-closed: abort if
    // unreadable) and capture the user-configured domains for the policy report.
    let mut configured_domains: Vec<String> = Vec::new();
    if let Some(ref path) = allowed_domains_file {
        if path.exists() {
            match proxy::parse_domain_file(path) {
                Ok(domains) => {
                    configured_domains = domains;
                    // Only print the legacy "N from FILE" line when the default
                    // allowlist is off; otherwise the "Domain policy" line below
                    // gives the complete, merged picture.
                    if !resolved.quiet && default_allowlist.is_empty() {
                        ui::info(&format!(
                            "Domain allowlist: {} domains from {}",
                            configured_domains.len(),
                            path.display()
                        ));
                    }
                }
                Err(e) => bail!("Failed to load allowed domains: {e}"),
            }
        } else if !resolved.quiet {
            ui::info(&format!(
                "Domain allowlist file: {} (not found)",
                path.display()
            ));
        }
    }

    // Report the active fail-closed policy: total permitted domains, and how
    // many the user added on top of the agent's built-in base. The merge here
    // mirrors the proxy's own dedup so the count matches what is enforced.
    if !default_allowlist.is_empty() && !resolved.quiet {
        let mut merged = default_allowlist.clone();
        merged.extend(configured_domains.iter().cloned());
        merged.sort_unstable();
        merged.dedup();
        let extra = merged.len().saturating_sub(default_allowlist.len());
        ui::info(&format!(
            "Domain policy: {} domains allowed (agent defaults + {} configured)",
            merged.len(),
            extra
        ));
        ui::info(
            "Fail-closed: unknown domains are blocked (BLOCKED-ALLOWLIST in the \
             proxy log). Add to allowed-domains or use --allow-all-domains.",
        );
    }

    // Blocklist subscriptions (issue #144, Phase 1): union cached, verified
    // subscription domains into the effective blocklist. Tighten-only and
    // fail-open — a fetch/verify failure falls back to the last-good cache (or
    // empty), and the run is NEVER blocked on the network beyond a bounded
    // timeout. Empty when no subscriptions are configured (unchanged behaviour).
    let subscription_blocklist = load_subscription_blocklist(resolved, resolved.quiet);

    let port_hint = if resolved.proxy_port == 0 {
        "ephemeral port".to_string()
    } else {
        format!("localhost:{}", resolved.proxy_port)
    };
    if !resolved.quiet {
        ui::info(&format!("Starting proxy on {port_hint}..."));
    }

    match proxy::start(proxy::ProxyOptions {
        port: resolved.proxy_port,
        blocked_file,
        subscription_blocklist,
        allowed_ports: resolved.allow_ports.clone(),
        allow_localhost_ports: resolved.allow_localhost.clone(),
        allow_localhost_any: resolved.allow_localhost_any,
        allowed_domains_file,
        allowed_domains_initial: Vec::new(),
        default_allowlist,
        cli_private_domains: cli.allow_private_domains.clone(),
        config_private_domains: resolved
            .allow_private_domains
            .iter()
            .filter(|d| !cli.allow_private_domains.contains(d))
            .cloned()
            .collect(),
        config_file: config_path.cloned(),
        log_file: resolved.proxy_log_file.clone(),
        log_level: resolved.proxy_log_level,
        timeout: resolved.proxy_timeout,
        upstream: resolved.proxy_upstream.clone(),
        upstream_no_proxy: resolved.proxy_upstream_no_proxy.clone(),
    }) {
        Ok(handle) => {
            resolved.proxy_port = handle.port;
            if !resolved.quiet {
                ui::ok(&format!(
                    "Proxy running on localhost:{} (thread)",
                    handle.port
                ));
            }
            // Proxy env vars (NODE_USE_ENV_PROXY, HTTP_PROXY, HTTPS_PROXY) are
            // injected by sandbox_exec::exec() when proxy_port is Some.
            Ok(Some(handle))
        }
        Err(e) => {
            // Fail closed under proxy-forced (#53): never fall back to open
            // networking. Refuse to launch the agent if the mandatory proxy
            // cannot bind/start.
            if resolved.proxy_forced {
                bail!(
                    "proxy-forced mode: the mandatory proxy failed to start ({e}); \
                     refusing to launch the agent (fail-closed, no open networking)"
                );
            }
            bail!("Failed to start proxy: {e}")
        }
    }
}

/// Resolve the effective subscription blocklist domains for a run (issue #144,
/// Phase 1). Lazily refreshes stale caches when `refresh != manual` (bounded by
/// the fetch timeout — never hangs the run), prints one-line staleness warnings,
/// and returns the UNION of cached subscription domains to merge into the
/// blocklist. Tighten-only and fail-open: any failure falls back to the
/// last-good cache (or empty). Returns an empty vec when no subscriptions are
/// configured, so networking is byte-identical to today.
fn load_subscription_blocklist(resolved: &config::Resolved, quiet: bool) -> Vec<String> {
    let set = &resolved.proxy_subscriptions;
    if set.is_empty() {
        return Vec::new();
    }

    // Lazy pre-run refresh (no-op under `refresh = "manual"`). Failures fall
    // through to the cache; we surface tamper (verify) failures loudly.
    let now = std::time::SystemTime::now();
    for outcome in subscriptions::refresh_if_stale(set, &subscriptions::curl_fetch_lazy, now) {
        if let subscriptions::UpdateOutcome::VerifyFailed {
            url,
            expected,
            actual,
        } = &outcome
        {
            ui::warn(&format!(
                "SHA256 verification failed for blocklist subscription {url}!\n  \
                 Expected: {expected}\n  Got:      {actual}\n  \
                 Download may be corrupted or tampered with — keeping the last-good cache."
            ));
        }
    }

    if !quiet {
        for warning in subscriptions::staleness_warnings(set, now) {
            ui::warn(&warning);
        }
    }

    let domains = subscriptions::load_cached_domains(set);
    if !quiet && !domains.is_empty() {
        ui::info(&format!(
            "Blocklist subscriptions: {} domains from {} list(s)",
            domains.len(),
            set.blocklists.len()
        ));
    }
    domains
}

/// `cplt update-lists`: fetch, verify, and cache all configured blocklist
/// subscriptions (issue #144, Phase 1 — the explicit refresh path). Reports a
/// per-list result. Tighten-only + fail-open: a fetch failure keeps the
/// last-good cache; a pinned-hash mismatch REJECTS the download (tamper) and
/// keeps the last-good cache. Never fails the process for a bad list.
fn run_update_lists() -> ExitCode {
    let resolved = match resolve_config_only() {
        Ok(r) => r,
        Err(e) => {
            ui::error(&e.to_string());
            return ExitCode::FAILURE;
        }
    };
    let set = &resolved.proxy_subscriptions;

    if set.is_empty() {
        ui::info(
            "No blocklist subscriptions configured. Add one under \
             [proxy.subscriptions] in your global config, e.g.:",
        );
        println!(
            "  [proxy.subscriptions]\n  blocklists = [\
             \"https://raw.githubusercontent.com/navikt/cplt/main/blocked-domains.txt\"]"
        );
        return ExitCode::SUCCESS;
    }

    ui::info(&format!(
        "Updating {} blocklist subscription(s) (refresh = {})...",
        set.blocklists.len(),
        set.refresh
    ));

    let now = std::time::SystemTime::now();
    let outcomes = subscriptions::update_all(set, &subscriptions::curl_fetch, now);

    let mut had_verify_failure = false;
    for outcome in &outcomes {
        match outcome {
            subscriptions::UpdateOutcome::Fetched {
                url,
                domains,
                verified,
            } => {
                let tag = if *verified { " (sha256 verified)" } else { "" };
                ui::ok(&format!("{url}\n    fetched {domains} domains{tag}"));
            }
            subscriptions::UpdateOutcome::CacheKept { url, reason } => {
                ui::warn(&format!(
                    "{url}\n    fetch failed ({reason}) — keeping last-good cache"
                ));
            }
            subscriptions::UpdateOutcome::EmptyNoCache { url, reason } => {
                ui::warn(&format!(
                    "{url}\n    fetch failed ({reason}) — no cache yet, treated as empty"
                ));
            }
            subscriptions::UpdateOutcome::WriteFailed { url, reason } => {
                ui::warn(&format!(
                    "{url}\n    fetched OK but cache write failed ({reason})"
                ));
            }
            subscriptions::UpdateOutcome::VerifyFailed {
                url,
                expected,
                actual,
            } => {
                had_verify_failure = true;
                ui::error(&format!(
                    "{url}\n    SHA256 verification FAILED — download REJECTED (tamper?), \
                     keeping last-good cache\n    Expected: {expected}\n    Got:      {actual}"
                ));
            }
        }
    }

    // A verify failure is a loud, actionable signal but is not fatal: the
    // last-good cache is retained (tighten-only). Exit non-zero so scripts/CI
    // can detect the tamper condition.
    if had_verify_failure {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Load and resolve config (global + repo merge is not needed here — subscriptions
/// are global-only). Used by `cplt update-lists`.
fn resolve_config_only() -> anyhow::Result<config::Resolved> {
    let loaded = config::Config::load_file()?;
    let config = loaded.map(|l| l.config).unwrap_or_default();
    let resolved = config
        .merge(config::CliFlags::default())
        .context("resolving configuration")?;
    Ok(resolved)
}

fn run(mut cli: Cli) -> anyhow::Result<ExitCode> {
    // Handle --init-config
    if cli.init_config {
        return Ok(init_config());
    }

    // Handle --shell-setup: print alias definition and exit
    if cli.shell_setup {
        println!("alias copilot=cplt");
        return Ok(ExitCode::SUCCESS);
    }

    // Handle --shell-install: append setup line to shell rc file
    if cli.shell_install {
        return Ok(shell_install());
    }

    // Handle `cplt exec` before consuming cli.command so resolve_context
    // can still borrow &cli after we take the exec-specific fields out.
    // The outer matches! guard ensures we only call take() when the variant
    // is definitely Exec — without it, take() would consume any subcommand
    // and leave cli.command = None, silently breaking all other subcommands.
    #[allow(clippy::collapsible_if)]
    if matches!(&cli.command, Some(Command::Exec { .. })) {
        if let Some(Command::Exec { shell_cmd, cmd }) = cli.command.take() {
            // exec always uses the shell sandbox policy. Default --agent shell
            // if none is specified so resolve_context doesn't fail when no AI
            // agent binary is installed.
            if cli.agent.is_none() {
                cli.agent = Some("shell".to_string());
            }
            // exec defaults to quiet — apply before resolve_context so that
            // config-loading diagnostics (e.g. "[cplt] Repo config: ...") are
            // suppressed and don't contaminate scripts/pipes using exec.
            if !cli.no_quiet {
                cli.quiet = true;
            }
            return run_exec_command(&cli, shell_cmd, cmd);
        }
    }

    // Handle `cplt check` before consuming cli.command, for the same reason as
    // exec above: run_check_command needs to borrow &cli (via resolve_context)
    // after taking the check-specific fields out.
    #[allow(clippy::collapsible_if)]
    if matches!(&cli.command, Some(Command::Check { .. })) {
        if let Some(Command::Check { target, json }) = cli.command.take() {
            // check defaults to quiet: it prints its own report, so suppress the
            // config-loading diagnostics that would otherwise contaminate --json.
            if !cli.no_quiet {
                cli.quiet = true;
            }
            return run_check_command(&cli, target, json);
        }
    }

    // Handle subcommands (these don't need macOS or sandbox)
    if let Some(command) = cli.command {
        return Ok(match command {
            Command::Config { action } => run_config_command(action),
            Command::Settings => match cplt::settings::run() {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    ui::error(&error);
                    ExitCode::FAILURE
                }
            },
            Command::Update { check, force } => run_update(check, force),
            Command::UpdateLists => run_update_lists(),
            Command::Trust { action } => run_trust_command(action),
            Command::Init {
                write,
                force,
                merge,
                quiet,
                global,
            } => {
                if global {
                    run_init_global_command(write, force, quiet)
                } else {
                    run_init_command(write, force, merge, quiet)
                }
            }
            Command::Doctor => run_doctor(),
            Command::GhGate {
                real_gh,
                repo_scope,
                mode,
                scope_check,
                no_scope_check,
                block_auth_token,
                no_block_auth_token,
                unknown_command,
                allow_api_write,
                no_allow_api_write,
                args,
            } => {
                let policy = gh_proxy::GatePolicy {
                    mode: match mode.as_str() {
                        "warn" => config::EnforcementMode::Warn,
                        "audit" => config::EnforcementMode::Audit,
                        _ => config::EnforcementMode::Block,
                    },
                    scope_check: scope_check && !no_scope_check,
                    block_auth_token: block_auth_token && !no_block_auth_token,
                    unknown_command: if unknown_command == "allow" {
                        gh_proxy::UnknownCommandDecision::Allow
                    } else {
                        gh_proxy::UnknownCommandDecision::Block
                    },
                    allow_api_write: allow_api_write && !no_allow_api_write,
                };
                run_gh_gate(&real_gh, repo_scope.as_deref(), &args, &policy)
            }
            Command::GitGate {
                real_git,
                args,
                mode,
                prevent_push,
                prevent_force_push,
                protect_default_branch_only,
                allow_push_rules,
            } => {
                let mode = match mode.as_str() {
                    "warn" => config::EnforcementMode::Warn,
                    "audit" => config::EnforcementMode::Audit,
                    _ => config::EnforcementMode::Block,
                };
                let prevent_push = prevent_push != "false";
                let prevent_force_push = prevent_force_push != "false";
                let protect_default_branch_only = protect_default_branch_only != "false";
                let rules = parse_allow_push_rules(&allow_push_rules);
                run_git_gate(
                    &real_git,
                    &args,
                    mode,
                    prevent_push,
                    prevent_force_push,
                    protect_default_branch_only,
                    &rules,
                )
            }
            // Exec is handled before this match (see above) — unreachable
            Command::Exec { .. } => unreachable!("Command::Exec handled before this match"),
            // Check is handled before this match (see above) — unreachable
            Command::Check { .. } => unreachable!("Command::Check handled before this match"),
        });
    }

    // Platform check: cplt supports macOS (Seatbelt) and Linux (Landlock).
    // Other platforms (Windows, FreeBSD, etc.) are not supported.
    if cfg!(not(any(target_os = "macos", target_os = "linux"))) {
        bail!("cplt requires macOS or Linux");
    }

    // Handle --doctor: run diagnostics and exit (works on all platforms)
    // DEPRECATED: use `cplt doctor` subcommand instead
    if cli.doctor {
        ui::warn("--doctor is deprecated, use `cplt doctor` instead");
        return Ok(run_doctor());
    }

    // Resolve config, paths, and agent
    let ResolvedContext {
        mut resolved,
        config_path,
        home_dir,
        project_dir,
        active_agent,
        unapproved_proposals: _,
    } = resolve_context(&cli, false)?;

    // Run auto-discovery to tighten the sandbox profile
    let tool_discovery = discover::discover_tools(&home_dir);
    let existing_home_tool_dirs = tool_discovery.existing_home_tool_dirs;
    let existing_app_dirs = tool_discovery.existing_app_dirs;

    // Create per-session scratch directory if enabled
    let scratch_guard = if resolved.scratch_dir {
        // GC stale scratch dirs from previous sessions (best-effort)
        scratch::ScratchDir::gc_stale(&home_dir);

        match scratch::ScratchDir::create(&home_dir) {
            Ok(s) => {
                if !resolved.quiet {
                    ui::ok(&format!("Scratch dir: {}", s.path().display()));
                }
                Some(s)
            }
            Err(e) => bail!("Cannot create scratch dir: {e}"),
        }
    } else {
        None
    };
    let scratch_path = scratch_guard.as_ref().map(cplt::scratch::ScratchDir::path);

    // Resolve the agent binary early so its installation directory
    // can be included in the sandbox profile. Failure is deferred —
    // --print-profile doesn't need the binary.
    let agent_bin_result = active_agent.resolve_binary();
    let copilot_install_dir = if active_agent == agent::Agent::Copilot {
        agent_bin_result
            .as_ref()
            .ok()
            .and_then(|p| {
                // Try package.json discovery first (npm/Homebrew installs)
                discover::copilot_pkg_dir(p, &home_dir).or_else(|| {
                    // Fallback: use the binary's parent directory (VS Code extension installs
                    // at ~/Library/Application Support/Code/.../copilotCli/copilot)
                    p.parent().map(std::path::Path::to_path_buf)
                })
            })
            .filter(|d| !crate::is_unsafe_root(d, &home_dir))
    } else {
        // Non-Copilot agents: use binary's parent dir for read + map-exec
        agent_bin_result
            .as_ref()
            .ok()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
            .filter(|d| !crate::is_unsafe_root(d, &home_dir))
    };

    // Discover global git hooks path from core.hooksPath
    let git_hooks_path = discover::git_hooks_path(&home_dir);

    // Discover git worktree common directory (shared .git for worktrees)
    let git_common_dir = discover::git_common_dir(&home_dir, &project_dir);

    // Discover Electron app bundle when Copilot CLI is installed via VS Code.
    // macOS-only: the shim invokes VS Code's Electron runtime, which needs
    // dyld access to load Electron Framework from within the .app bundle.
    let electron_app_dir = discover_electron_app_dir(&agent_bin_result, active_agent);

    // Discover JAVA_HOME for JDK read access when installed outside TOOL_READ_DIRS.
    // Covers: sdkman (~/.sdkman/candidates/java/), actions/setup-java (hostedtoolcache),
    // jabba, or any other version manager that places JDK under HOME.
    let java_home_dir = std::env::var("JAVA_HOME")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .filter(|p| !crate::is_unsafe_root(p, &home_dir));

    // Discover DOTNET_ROOT for .NET SDK read access when installed outside
    // TOOL_READ_DIRS (e.g. actions/setup-dotnet hostedtoolcache, or
    // dotnet-install.sh into a custom directory under $HOME).
    let dotnet_root_dir = std::env::var("DOTNET_ROOT")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .filter(|p| !crate::is_unsafe_root(p, &home_dir));

    // Compute agent-specific sandbox directories
    let mut agent_dirs = active_agent.config_dirs(&home_dir);

    // Pre-create agent directories before entering sandbox.
    // Agents like OpenCode crash if their data/config dirs don't exist,
    // and the sandbox may block mkdir on parent paths.
    for dir in &agent_dirs {
        if !dir.path.exists() {
            let _ = std::fs::create_dir_all(&dir.path);
        }
    }
    // After pre-creation, so a dir we just made resolves too. See #171.
    agent::canonicalize_agent_dirs(&mut agent_dirs);

    // macOS-only, opt-in (sandbox.gradle_init): install the guarded Gradle
    // init script so sandboxed builds keep the preferIPv4Stack workaround for
    // the daemon and Test/JavaExec forks (WorkerExecutor forks have no
    // init-script hook — see gradle_init module docs). Inert outside the
    // sandbox (__CPLT_WRAPPED guard); a no-op when ~/.gradle doesn't exist.
    #[cfg(target_os = "macos")]
    if resolved.gradle_init
        && let Err(e) = gradle_init::ensure_init_script(&home_dir)
    {
        ui::warn(&format!(
            "Could not install Gradle sandbox init script: {e}"
        ));
    }

    // Start proxy (handle returned for RAII ownership)
    let proxy_handle =
        start_proxy_if_enabled(&mut resolved, &cli, config_path.as_ref(), active_agent)?;

    // Grant access to tool paths relocated via env vars (GOPATH, CARGO_HOME, ...).
    merge_tool_path_env_overrides(&mut resolved, &home_dir);

    // Prepare the sandbox — validates paths, generates platform-specific profile.
    // Path validation (SBPL injection checks on macOS) is handled internally
    // by prepare(), so callers don't need to know about backend-specific risks.
    // proxy_port comes from the running handle so the actual ephemeral port is embedded.
    let proxy_port_for_profile = proxy_handle.as_ref().map(|h| h.port);
    let prepared = match sandbox::prepare(&sandbox::SandboxConfig {
        project_dir: &project_dir,
        home_dir: &home_dir,
        extra_read: &resolved.allow_read,
        extra_write: &resolved.allow_write,
        extra_socket: &resolved.allow_socket,
        extra_deny: &resolved.deny_paths,
        existing_home_tool_dirs: Some(&existing_home_tool_dirs),
        existing_app_dirs: Some(&existing_app_dirs),
        extra_ports: &resolved.allow_ports,
        localhost_ports: &resolved.allow_localhost,
        proxy_port: proxy_port_for_profile,
        proxy_forced: resolved.proxy_forced,
        allow_env_files: resolved.allow_env_files,
        allow_localhost_any: resolved.allow_localhost_any,
        scratch_dir: scratch_path,
        allow_tmp_exec: resolved.allow_tmp_exec,
        copilot_install_dir: copilot_install_dir.as_deref(),
        java_home: java_home_dir.as_deref(),
        dotnet_root: dotnet_root_dir.as_deref(),
        git_hooks_path: git_hooks_path.as_deref(),
        git_common_dir: git_common_dir.as_deref(),
        allow_gpg_signing: resolved.allow_gpg_signing,
        deny_clipboard: resolved.deny_clipboard,
        allow_jvm_attach: resolved.allow_jvm_attach,
        allow_msbuild: resolved.allow_msbuild,
        allow_docker: resolved.allow_docker,
        electron_app_dir: electron_app_dir.as_deref(),
        agent: active_agent,
        agent_dirs: &agent_dirs,
        allow_cache_exec: &resolved.allow_cache_exec,
        allow_cache_exec_any: resolved.allow_cache_exec_any,
        allow_browser: resolved.allow_browser,
        use_bubblewrap: resolved.use_bubblewrap,
    }) {
        Ok(s) => s,
        Err(e) => bail!("{e}"),
    };

    // --print-profile: dump the sandbox policy and exit (no copilot binary needed)
    if cli.print_profile {
        println!("{}", sandbox::describe(&prepared));
        return Ok(ExitCode::SUCCESS);
    }

    // Recursion guard: detect if we're already inside a cplt sandbox.
    // Placed after --print-profile/--doctor/--init-config so those subcommands
    // still work inside the sandbox. Only the actual sandbox launch is blocked.
    if std::env::var("__CPLT_WRAPPED").is_ok() {
        bail!(
            "cplt is already running (recursion detected). \
             Ensure the real agent binary is in PATH and not aliased to cplt."
        );
    }

    // Unwrap the agent binary resolution (deferred from above).
    let agent_bin = match agent_bin_result {
        Ok(path) => path,
        Err(msg) => bail!("{msg}"),
    };

    // Ensure Copilot's bundled runtime is extracted before entering the sandbox.
    // Writes to copilot/pkg are denied inside the sandbox (write-then-exec defense),
    // so extraction must happen here, outside. SEA extraction applies to both
    // macOS (~/Library/Caches/copilot/pkg/) and Linux (~/.cache/copilot/pkg/).
    #[cfg(target_os = "macos")]
    if active_agent.needs_sea_extraction() {
        ensure_copilot_extracted(&agent_bin, &home_dir, &project_dir)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    #[cfg(target_os = "linux")]
    if active_agent.needs_sea_extraction() {
        ensure_copilot_extracted_linux(&agent_bin, &home_dir, &project_dir)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // Preflight: verify the sandbox mechanism works on this system
    if !resolved.no_validate {
        match sandbox::preflight(&prepared) {
            Ok(()) => {
                if !resolved.quiet {
                    print_preflight_ok();
                }
            }
            Err(e) => bail!("Sandbox validation failed: {e}"),
        }
    }

    // Print comprehensive summary and confirm before launching Copilot
    if !resolved.quiet {
        resolved.print_summary(&project_dir, &home_dir, active_agent);
    }
    if let Err(e) = prompt_confirm(resolved.yes, resolved.quiet) {
        bail!("{e}");
    }

    // Compute hardening categories for environment sanitization
    let disabled_categories = resolved.disabled_hardening_categories();

    // proxy_handle is set up before sandbox::prepare() (see above)

    ui::ok(&format!(
        "Starting {} in sandbox...",
        active_agent.display_name()
    ));

    // --show-denials: stream sandbox denial logs in the background.
    #[allow(unused_mut)] // mut needed on macOS where denial_proc is assigned
    let mut denial_proc: Option<std::process::Child> = None;
    if cli.show_denials {
        denial_proc = start_denial_stream();
    }

    eprintln!(
        "{}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{}",
        ui::color(ui::YELLOW),
        ui::color(ui::RESET)
    );
    eprintln!();

    // Build agent args: extra args (e.g. --no-auto-update) + forwarded convenience flags + explicit -- args
    let copilot_args = build_copilot_args(&cli, &active_agent);

    // Run agent inside sandbox, wrapped in the post-session audit lifecycle.
    // The audit is on by default and suppressed by --no-audit or --quiet. The
    // baseline is captured just before exec and the report printed just after,
    // both in the parent (outside the sandbox) — see audit::run.
    let audit_enabled = resolved.audit && !resolved.quiet;
    let exit_code = audit::run(&project_dir, audit_enabled, || {
        sandbox::exec_sandboxed(
            &prepared,
            &agent_bin,
            &copilot_args,
            &resolved.pass_env,
            resolved.inherit_env,
            &disabled_categories,
            &resolved.deny_env,
            &resolved.gh_guard,
            &resolved.git_guard,
        )
    });

    // Cleanup
    if let Some(handle) = proxy_handle {
        // --observe-domains: read the collected set BEFORE shutdown and emit the
        // ready-to-paste allowlist (always, even under --quiet).
        if cli.observe_domains {
            emit_observed_domains(
                active_agent.display_name(),
                &handle.observed_domains(),
                cli.observe_domains_out.as_deref(),
            );
        }
        handle.shutdown();
    }
    if let Some(mut child) = denial_proc {
        let _ = child.kill();
        let _ = child.wait();
    }

    Ok(ExitCode::from(exit_code))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            // Broken pipe (e.g. `cplt config show | head`) — exit silently per Unix convention.
            for cause in e.chain() {
                if let Some(io_err) = cause.downcast_ref::<std::io::Error>()
                    && io_err.kind() == std::io::ErrorKind::BrokenPipe
                {
                    return ExitCode::SUCCESS;
                }
            }
            ui::error(&format!("{e:#}"));
            ExitCode::FAILURE
        }
    }
}

/// Build the argument vector for the agent binary.
/// Prepends agent-specific args (e.g. --no-auto-update for Copilot),
/// then forwarded convenience flags, then explicit -- args.
fn build_copilot_args(cli: &Cli, agent: &agent::Agent) -> Vec<String> {
    let mut args = Vec::new();

    // Agent-specific args (e.g. --no-auto-update for Copilot)
    for extra in agent.extra_args() {
        args.push((*extra).to_string());
    }

    // Translate cplt's session-management convenience flags (--resume,
    // --continue, --remote, --name) into the agent's native flags. Unsupported
    // flags are dropped per agent (see Agent::session_args).
    args.extend(agent.session_args(
        cli.resume.as_deref(),
        cli.continue_session,
        cli.session_name.as_deref(),
        cli.remote,
    ));

    // Auto-resume: when no explicit args are given and no session flags are set,
    // default to --resume so the agent continues the previous session.
    // Applies to Copilot and Gemini. Skipped if user passes -- args or uses
    // explicit session management flags (--resume, --continue, --name).
    let has_session_flags =
        cli.resume.is_some() || cli.continue_session || cli.session_name.is_some();
    if matches!(agent, agent::Agent::Copilot | agent::Agent::Gemini)
        && cli.copilot_args.is_empty()
        && !has_session_flags
    {
        args.push("--resume".into());
    }

    args.extend(cli.copilot_args.iter().cloned());
    args
}

/// Handle `cplt gh-gate` — evaluate a gh command and exec the real binary if allowed.
///
/// Called from the wrapper script placed in the sandbox's PATH. If the command
/// is allowed, this replaces the current process with the real gh binary.
/// If blocked, prints an error message and exits with code 1.
fn run_gh_gate(
    real_gh: &Path,
    repo_scope: Option<&str>,
    args: &[String],
    policy: &gh_proxy::GatePolicy,
) -> ExitCode {
    // Intercept `gh auth token` — serve from cached file instead of blocking.
    // This allows Copilot to authenticate without exposing the token as an env var
    // to all child processes. The token file is written to scratch dir at startup.
    if policy.block_auth_token && is_gh_auth_token_request(args) {
        return serve_cached_gh_token();
    }

    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();

    match gh_proxy::gate_with_repo_scope(&arg_refs, policy, repo_scope) {
        Ok(approval) => exec_gh(real_gh, args, approval.repo_scope.as_deref()),
        Err(msg) => match policy.mode {
            config::EnforcementMode::Block => {
                eprintln!("{msg}");
                ExitCode::FAILURE
            }
            config::EnforcementMode::Warn => {
                eprintln!("⚠️  WARNING (would block): {msg}");
                // Allow through in warn mode
                exec_gh(real_gh, args, None)
            }
            config::EnforcementMode::Audit => {
                // Log the decision to stderr for audit trail
                eprintln!("[audit] gh-gate: would block: {msg}");
                exec_gh(real_gh, args, None)
            }
        },
    }
}

fn exec_gh(real_gh: &Path, args: &[String], repo_scope: Option<&str>) -> ExitCode {
    use std::os::unix::process::CommandExt;

    let mut command = std::process::Command::new(real_gh);
    command.args(args);
    if let Some(repo) = repo_scope {
        command.env_remove("GH_HOST");
        command.env("GH_REPO", repo);
    }
    let err = command.exec();
    ui::error(&format!("Failed to exec gh: {err}"));
    ExitCode::FAILURE
}

/// Check if args represent a `gh auth token` invocation.
fn is_gh_auth_token_request(args: &[String]) -> bool {
    // args are the arguments after `--` in `cplt gh-gate ... -- auth token`
    let mut iter = args
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'));
    iter.next() == Some("auth") && iter.next() == Some("token")
}

/// Serve the cached GitHub token from the scratch dir's `.gh-token` file.
/// Deletes the file after reading so subsequent calls by subprocesses fail.
/// Returns ExitCode::SUCCESS if token found, FAILURE otherwise.
fn serve_cached_gh_token() -> ExitCode {
    // TMPDIR is set to the scratch dir inside the sandbox
    let tmpdir = std::env::var("TMPDIR")
        .or_else(|_| std::env::var("TMP"))
        .unwrap_or_default();

    if tmpdir.is_empty() {
        eprintln!("⚠️ BLOCKED by sandbox: 'gh auth token' — no cached token available.");
        return ExitCode::FAILURE;
    }

    let token_path = Path::new(&tmpdir).join(".gh-token");

    match std::fs::read_to_string(&token_path) {
        Ok(token) if !token.is_empty() => {
            // Delete the file immediately after reading — one-time use only.
            // Copilot caches the token in memory after first read, so subsequent
            // calls to `gh auth token` by tools/subprocesses will get "not available".
            let _ = std::fs::remove_file(&token_path);
            print!("{token}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("⚠️ BLOCKED by sandbox: 'gh auth token' — no cached token available.");
            ExitCode::FAILURE
        }
    }
}

/// Parse JSON-encoded allow_push rules from the CLI flag.
fn parse_allow_push_rules(json: &str) -> Vec<config::ResolvedPushRule> {
    if json.is_empty() {
        return Vec::new();
    }
    // Simple JSON array format: [{"remote":"fork","branches":["agent/*"],"force":false}]
    serde_json::from_str(json).unwrap_or_default()
}

/// Handle `cplt git-gate` — evaluate a git command and exec the real binary if allowed.
fn run_git_gate(
    real_git: &Path,
    args: &[String],
    mode: config::EnforcementMode,
    prevent_push: bool,
    prevent_force_push: bool,
    protect_default_branch_only: bool,
    allow_push_rules: &[config::ResolvedPushRule],
) -> ExitCode {
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();

    match gh_proxy::gate_git(
        &arg_refs,
        prevent_push,
        prevent_force_push,
        protect_default_branch_only,
        allow_push_rules,
        Some(real_git),
    ) {
        Ok(()) => {
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new(real_git).args(args).exec();
            ui::error(&format!("Failed to exec git: {err}"));
            ExitCode::FAILURE
        }
        Err(msg) => match mode {
            config::EnforcementMode::Block => {
                eprintln!("{msg}");
                ExitCode::FAILURE
            }
            config::EnforcementMode::Warn => {
                eprintln!("⚠️  WARNING (would block): {msg}");
                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new(real_git).args(args).exec();
                ui::error(&format!("Failed to exec git: {err}"));
                ExitCode::FAILURE
            }
            config::EnforcementMode::Audit => {
                // Log the decision to stderr for audit trail
                eprintln!("[audit] git-gate: would block: {msg}");
                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new(real_git).args(args).exec();
                ui::error(&format!("Failed to exec git: {err}"));
                ExitCode::FAILURE
            }
        },
    }
}

// ── cplt exec ──────────────────────────────────────────────────────────────

/// Resolve a command name to an absolute binary path.
///
/// If `name` is already an absolute path, validate it exists and return it.
/// Otherwise walk PATH entries (left-to-right) and return the first match.
/// Unlike `Agent::resolve_binary()`, this does not skip cplt aliases — the
/// user explicitly asked for this binary.
fn resolve_exec_binary(name: &str) -> anyhow::Result<PathBuf> {
    let p = PathBuf::from(name);
    if p.is_absolute() {
        // Canonicalize to resolve symlinks and `..` components — consistent with
        // how other paths are handled, and avoids passing a non-canonical path
        // to the OS after the sandbox allow-lists have been resolved.
        let canonical = std::fs::canonicalize(&p).with_context(|| {
            format!("exec: binary not found or not accessible: {}", p.display())
        })?;
        if canonical.is_file() {
            return Ok(canonical);
        }
        bail!("exec: not a file: {}", canonical.display());
    }
    // Relative path (e.g. `./vendor-script.sh`) — resolve against cwd, not PATH.
    if name.contains('/') {
        let cwd = std::env::current_dir().context("exec: cannot determine current directory")?;
        let canonical = std::fs::canonicalize(cwd.join(name)).with_context(|| {
            format!("exec: relative binary not found or not accessible: {name}")
        })?;
        if canonical.is_file() {
            return Ok(canonical);
        }
        bail!("exec: not a file: {}", canonical.display());
    }
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!("exec: '{name}' not found in PATH")
}

/// A fully-built Shell sandbox plus the live resources it depends on.
///
/// `scratch_guard` and `proxy_handle` are RAII/handle values that must outlive
/// any use of `prepared` (the scratch dir is cleaned up on drop; the proxy
/// thread is shut down via the handle). `policy` is the structured Landlock
/// model of the filesystem policy — the same rules the profile enforces —
/// used by `cplt check` for the explain layer (`describe_policy`'s model).
struct ShellSandbox {
    prepared: sandbox::PreparedSandbox,
    policy: sandbox::LandlockPolicy,
    proxy_handle: Option<proxy::ProxyHandle>,
    scratch_guard: Option<scratch::ScratchDir>,
}

/// Build the resolved Shell sandbox: tool discovery, scratch dir, optional
/// proxy, and the compiled sandbox profile.
///
/// This is the shared setup used by both `cplt exec` and `cplt check` so their
/// probes run under byte-for-byte the same policy. Mutates `resolved`
/// (proxy port, tool-path env overrides) exactly as the agent launch does.
fn prepare_shell_sandbox(
    cli: &Cli,
    resolved: &mut config::Resolved,
    config_path: Option<&PathBuf>,
    home_dir: &Path,
    project_dir: &Path,
) -> anyhow::Result<ShellSandbox> {
    let active_agent = agent::Agent::Shell;

    let tool_discovery = discover::discover_tools(home_dir);
    let existing_home_tool_dirs = tool_discovery.existing_home_tool_dirs;
    let existing_app_dirs = tool_discovery.existing_app_dirs;

    let scratch_guard = if resolved.scratch_dir {
        scratch::ScratchDir::gc_stale(home_dir);
        match scratch::ScratchDir::create(home_dir) {
            Ok(s) => Some(s),
            Err(e) => bail!("Cannot create scratch dir: {e}"),
        }
    } else {
        None
    };
    let scratch_path = scratch_guard.as_ref().map(cplt::scratch::ScratchDir::path);

    let git_hooks_path = discover::git_hooks_path(home_dir);
    let git_common_dir = discover::git_common_dir(home_dir, project_dir);
    let java_home_dir = std::env::var("JAVA_HOME")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .filter(|p| !crate::is_unsafe_root(p, home_dir));

    // Discover DOTNET_ROOT for .NET SDK read access when installed outside
    // TOOL_READ_DIRS (e.g. actions/setup-dotnet hostedtoolcache, or
    // dotnet-install.sh into a custom directory under $HOME).
    let dotnet_root_dir = std::env::var("DOTNET_ROOT")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .filter(|p| !crate::is_unsafe_root(p, home_dir));

    let mut agent_dirs = active_agent.config_dirs(home_dir);
    for dir in &agent_dirs {
        if !dir.path.exists() {
            let _ = std::fs::create_dir_all(&dir.path);
        }
    }
    // See the agent-path call site: resolve symlinked agent dirs (#171).
    agent::canonicalize_agent_dirs(&mut agent_dirs);

    // See the agent-path call site: guarded Gradle init script (opt-in via
    // sandbox.gradle_init) so sandboxed builds keep the preferIPv4Stack
    // workaround for the daemon and Test/JavaExec forks.
    #[cfg(target_os = "macos")]
    if resolved.gradle_init
        && let Err(e) = gradle_init::ensure_init_script(home_dir)
    {
        ui::warn(&format!(
            "Could not install Gradle sandbox init script: {e}"
        ));
    }

    let proxy_handle = start_proxy_if_enabled(resolved, cli, config_path, active_agent)?;
    let proxy_port_for_profile = proxy_handle.as_ref().map(|h| h.port);

    // Grant access to tool paths relocated via env vars (GOPATH, CARGO_HOME, ...).
    merge_tool_path_env_overrides(resolved, home_dir);

    let sandbox_config = sandbox::SandboxConfig {
        project_dir,
        home_dir,
        extra_read: &resolved.allow_read,
        extra_write: &resolved.allow_write,
        extra_socket: &resolved.allow_socket,
        extra_deny: &resolved.deny_paths,
        existing_home_tool_dirs: Some(&existing_home_tool_dirs),
        existing_app_dirs: Some(&existing_app_dirs),
        extra_ports: &resolved.allow_ports,
        localhost_ports: &resolved.allow_localhost,
        proxy_port: proxy_port_for_profile,
        proxy_forced: resolved.proxy_forced,
        allow_env_files: resolved.allow_env_files,
        allow_localhost_any: resolved.allow_localhost_any,
        scratch_dir: scratch_path,
        allow_tmp_exec: resolved.allow_tmp_exec,
        // shell/check have no agent install dir to grant special access to
        copilot_install_dir: None,
        java_home: java_home_dir.as_deref(),
        dotnet_root: dotnet_root_dir.as_deref(),
        git_hooks_path: git_hooks_path.as_deref(),
        git_common_dir: git_common_dir.as_deref(),
        allow_gpg_signing: resolved.allow_gpg_signing,
        deny_clipboard: resolved.deny_clipboard,
        allow_jvm_attach: resolved.allow_jvm_attach,
        allow_msbuild: resolved.allow_msbuild,
        allow_docker: resolved.allow_docker,
        electron_app_dir: None,
        agent: active_agent,
        agent_dirs: &agent_dirs,
        allow_cache_exec: &resolved.allow_cache_exec,
        allow_cache_exec_any: resolved.allow_cache_exec_any,
        allow_browser: resolved.allow_browser,
        use_bubblewrap: resolved.use_bubblewrap,
    };

    // The structured Landlock model of the fs policy — used by the check
    // explain layer. It faithfully mirrors the enforced allow-list on both
    // platforms (the live probe remains authoritative where they differ).
    let policy = sandbox::generate_policy(&sandbox_config);
    let prepared = sandbox::prepare(&sandbox_config).map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(ShellSandbox {
        prepared,
        policy,
        proxy_handle,
        scratch_guard,
    })
}

/// Run an arbitrary command inside the sandbox (`cplt exec -- <cmd> [args]`).
///
/// Reuses the Agent::Shell sandbox policy. Defaults to quiet+yes so it is
/// clean for scripting and shell aliases. Pass --no-quiet to show the summary.
fn run_exec_command(
    cli: &Cli,
    shell_cmd: Option<String>,
    cmd: Vec<String>,
) -> anyhow::Result<ExitCode> {
    // Platform check
    if cfg!(not(any(target_os = "macos", target_os = "linux"))) {
        bail!("cplt exec requires macOS or Linux");
    }

    // Recursion guard: block nested exec inside an existing sandbox.
    if std::env::var("__CPLT_WRAPPED").is_ok() {
        bail!(
            "cplt exec: already inside a cplt sandbox (recursion detected). \
             Run this command outside the sandbox."
        );
    }

    // Resolve the binary and args to pass to the sandbox
    let (exec_bin, exec_args): (PathBuf, Vec<String>) = if let Some(ref shell_c) = shell_cmd {
        // -c mode: use the same shell as --agent shell for consistent behaviour.
        // Agent::Shell.resolve_binary() validates $SHELL exists and falls back to
        // /bin/zsh (macOS) or /bin/bash (Linux) — same fallbacks as the interactive shell.
        let shell = agent::Agent::Shell
            .resolve_binary()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        (shell, vec!["-c".to_string(), shell_c.clone()])
    } else {
        if cmd.is_empty() {
            bail!(
                "cplt exec: no command given.\n\
                 Usage: cplt exec -- <cmd> [args...]\n\
                 Or:    cplt exec -c \"cmd && cmd\""
            );
        }
        let bin = resolve_exec_binary(&cmd[0])?;
        (bin, cmd[1..].to_vec())
    };

    // Resolve config, paths, project dir — same pipeline as the main agent launch
    let ResolvedContext {
        mut resolved,
        config_path,
        home_dir,
        project_dir,
        unapproved_proposals: _,
        // active_agent from resolve_context is ignored — exec always uses Shell
        active_agent: _,
    } = resolve_context(cli, false)?;

    // exec defaults to quiet+yes (scripting UX). User can override with --no-quiet / --no-yes.
    if !cli.no_quiet {
        resolved.quiet = true;
    }
    if !cli.no_yes {
        resolved.yes = true;
    }

    // Warn about dangerous flags even in quiet mode — exec defaults to quiet,
    // so these warnings would otherwise be silently swallowed. The main agent
    // flow only warns inside print_summary (shown when !quiet), but for exec
    // the user never explicitly chose quiet mode, so we must warn here.
    if resolved.inherit_env {
        ui::warn(
            "exec: --inherit-env is active — all env vars (including credentials) are passed to the sandbox",
        );
    }
    if resolved.allow_docker {
        ui::warn(
            "exec: --allow-docker is active — container volume mounts bypass sandbox filesystem restrictions",
        );
    }
    if resolved.allow_tmp_exec {
        ui::warn("exec: --allow-tmp-exec is active — code execution from /tmp is allowed");
    }

    // Always use the Shell sandbox policy
    let active_agent = agent::Agent::Shell;

    // Build the resolved Shell sandbox (discovery → proxy → prepare). Shared
    // with `cplt check`, which runs its probes under the identical policy.
    let ShellSandbox {
        prepared,
        proxy_handle,
        scratch_guard: _scratch_guard,
        ..
    } = prepare_shell_sandbox(
        cli,
        &mut resolved,
        config_path.as_ref(),
        &home_dir,
        &project_dir,
    )?;

    if cli.print_profile {
        println!("{}", sandbox::describe(&prepared));
        return Ok(ExitCode::SUCCESS);
    }

    // Preflight: verify the sandbox mechanism works on this system.
    // Respects --no-validate (same as the main agent flow).
    if !resolved.no_validate {
        match sandbox::preflight(&prepared) {
            Ok(()) => {}
            Err(e) => bail!("Sandbox validation failed: {e}"),
        }
    }

    // Summary (only shown with --no-quiet)
    if !resolved.quiet {
        resolved.print_summary(&project_dir, &home_dir, active_agent);
    }
    if let Err(e) = prompt_confirm(resolved.yes, resolved.quiet) {
        bail!("{e}");
    }

    let disabled_categories = resolved.disabled_hardening_categories();

    // Same audit lifecycle as the main agent flow (shared audit::run helper).
    // In exec mode quiet defaults on (scripting UX), so the audit is off unless
    // the user passes --no-quiet.
    let audit_enabled = resolved.audit && !resolved.quiet;
    let exit_code = audit::run(&project_dir, audit_enabled, || {
        sandbox::exec_sandboxed(
            &prepared,
            &exec_bin,
            &exec_args,
            &resolved.pass_env,
            resolved.inherit_env,
            &disabled_categories,
            &resolved.deny_env,
            &resolved.gh_guard,
            &resolved.git_guard,
        )
    });

    if let Some(handle) = proxy_handle {
        // --observe-domains also works for `cplt exec -- <cmd>`: emit the
        // observed set before shutdown (always, even under exec's default quiet).
        if cli.observe_domains {
            emit_observed_domains(
                active_agent.display_name(),
                &handle.observed_domains(),
                cli.observe_domains_out.as_deref(),
            );
        }
        handle.shutdown();
    }

    Ok(ExitCode::from(exit_code))
}

// ── cplt check ─────────────────────────────────────────────────────────────

/// The canonical CLI/config name for a preset (inverse of `Preset::from_name`).
fn preset_label(p: config::Preset) -> &'static str {
    match p {
        config::Preset::Strict => "strict",
        config::Preset::Standard => "standard",
        config::Preset::Permissive => "permissive",
        config::Preset::FullTrust => "full-trust",
    }
}

/// Sentinel exit code meaning "the sandbox probe could not even be spawned".
/// Distinct from any code a probe script itself returns.
const PROBE_SPAWN_FAILED: u8 = 200;

/// Wrap a string as a single-quoted shell literal (safe for arbitrary paths).
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Run a hermetic shell probe inside the resolved sandbox and return its exit
/// code. `PROBE_SPAWN_FAILED` means the shell could not be resolved/spawned.
fn probe_shell(
    prepared: &sandbox::PreparedSandbox,
    resolved: &config::Resolved,
    disabled: &[sandbox::HardeningCategory],
    script: &str,
) -> u8 {
    let Ok(shell) = agent::Agent::Shell.resolve_binary() else {
        return PROBE_SPAWN_FAILED;
    };
    let args = vec!["-c".to_string(), script.to_string()];
    sandbox::exec_sandboxed(
        prepared,
        &shell,
        &args,
        &resolved.pass_env,
        resolved.inherit_env,
        disabled,
        &resolved.deny_env,
        &resolved.gh_guard,
        &resolved.git_guard,
    )
}

/// Interpret a read/write probe exit code as a [`check::Decision`].
fn decode_fs_probe(code: u8) -> check::Decision {
    match code {
        0 => check::Decision::Allowed,
        PROBE_SPAWN_FAILED => check::Decision::Inconclusive,
        _ => check::Decision::Blocked,
    }
}

/// Probe read access to `path` inside the sandbox (opens for read, reads
/// nothing). Works for files and directories.
fn probe_read(
    prepared: &sandbox::PreparedSandbox,
    resolved: &config::Resolved,
    disabled: &[sandbox::HardeningCategory],
    path: &Path,
) -> check::Decision {
    let script = format!(
        "exec >/dev/null 2>&1; : < {}",
        sh_quote(&path.to_string_lossy())
    );
    decode_fs_probe(probe_shell(prepared, resolved, disabled, &script))
}

/// Probe write access to `path` inside the sandbox without mutating user state.
///
/// - Directory: create and immediately remove a uniquely-named probe file.
/// - Existing file: append-open (no bytes written; content-preserving).
/// - Missing file: reported [`check::Decision::Inconclusive`] (creating it would
///   mutate state).
fn probe_write(
    prepared: &sandbox::PreparedSandbox,
    resolved: &config::Resolved,
    disabled: &[sandbox::HardeningCategory],
    path: &Path,
) -> check::Decision {
    let q = sh_quote(&path.to_string_lossy());
    let script = if path.is_dir() {
        format!("exec >/dev/null 2>&1; f={q}/.cplt-check-write.$$; : > \"$f\" && rm -f \"$f\"")
    } else if path.exists() {
        // Append-open an existing file: opens for write, writes nothing.
        format!("exec >/dev/null 2>&1; : >> {q}")
    } else {
        return check::Decision::Inconclusive;
    };
    decode_fs_probe(probe_shell(prepared, resolved, disabled, &script))
}

/// Probe whether a binary staged in a writable-but-non-executable location can
/// be executed (binary-drop prevention). Stages in `~/.cache` — writable on both
/// platforms yet deliberately non-executable, the canonical binary-drop vector
/// (the scratch dir / `$TMPDIR` is intentionally executable for real tooling, so
/// it is NOT the right target). Distinguishes a staging failure (inconclusive)
/// from an actual exec denial (blocked).
fn probe_tmp_exec(
    prepared: &sandbox::PreparedSandbox,
    resolved: &config::Resolved,
    disabled: &[sandbox::HardeningCategory],
) -> (check::Decision, Option<String>) {
    let script = "\
exec >/dev/null 2>&1
d=\"$HOME/.cache\"
mkdir -p \"$d\" || exit 90
f=\"$d/.cplt-check-exec.$$\"
printf '#!/bin/sh\\nexit 0\\n' > \"$f\" || exit 90
chmod +x \"$f\" || { rm -f \"$f\"; exit 91; }
\"$f\"
r=$?
rm -f \"$f\"
exit $r";
    match probe_shell(prepared, resolved, disabled, script) {
        0 => (check::Decision::Allowed, None),
        90 | 91 => (
            check::Decision::Inconclusive,
            Some("could not stage the probe binary".to_string()),
        ),
        PROBE_SPAWN_FAILED => (
            check::Decision::Inconclusive,
            Some("sandbox probe could not be spawned".to_string()),
        ),
        _ => (check::Decision::Blocked, None),
    }
}

/// Pick a known-protected credential path that exists on this host, for the
/// enforcement battery's "read is blocked" demonstration. Falls back to the
/// home directory root (always present and never listable in the sandbox).
fn pick_protected_read(home: &Path) -> (PathBuf, String) {
    const CANDIDATES: &[&str] = &[
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".ssh",
        ".aws/credentials",
        ".aws",
        ".config/gh/hosts.yml",
        ".netrc",
        ".gnupg",
    ];
    for c in CANDIDATES {
        let p = home.join(c);
        if p.exists() {
            return (p, format!("read ~/{c}"));
        }
    }
    (home.to_path_buf(), "read $HOME (root)".to_string())
}

/// The blocklist file cplt would use, mirroring `start_proxy_if_enabled`.
fn default_blocklist_path(resolved: &config::Resolved) -> Option<PathBuf> {
    if let Some(ref p) = resolved.blocked_domains {
        return Some(p.clone());
    }
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))?;
    for name in ["blocked-domains.txt", "blocked.txt"] {
        let candidate = exe_dir.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Build the effective CONNECT policy snapshot from resolved config — the same
/// merge `start_proxy_if_enabled` performs, so `classify_connect` sees exactly
/// what the live proxy would enforce.
fn build_net_policy(resolved: &config::Resolved, agent: agent::Agent) -> proxy::NetPolicy {
    let mut ports = vec![443u16];
    ports.extend_from_slice(&resolved.allow_ports);
    ports.sort_unstable();
    ports.dedup();

    let default_allowlist: Vec<String> = if resolved.default_allowlist {
        agent
            .default_allowed_domains()
            .iter()
            .map(|d| (*d).to_string())
            .collect()
    } else {
        Vec::new()
    };
    let file_domains: Vec<String> = if resolved.allow_all_domains {
        Vec::new()
    } else if let Some(ref path) = resolved.allowed_domains {
        // Parse the allowed_domains file through the EXACT parser the live
        // allowlist cache uses (`parse_lines_file` via `get_cached_domains`), NOT
        // `parse_domain_file`. The latter extra-normalizes (strips scheme/path/
        // port), so a non-canonical entry like `github.com:443` would be stored
        // as `github.com` for check but kept verbatim for live enforcement —
        // making check report ALLOWED while `handle_connect` returns
        // BLOCKED-ALLOWLIST. Sharing one parser keeps the two byte-identical.
        proxy::parse_lines_file(path).unwrap_or_default()
    } else {
        Vec::new()
    };
    let allowed_domains = if default_allowlist.is_empty() {
        file_domains
    } else {
        let mut merged = default_allowlist;
        merged.extend(file_domains);
        merged.sort_unstable();
        merged.dedup();
        merged
    };

    // Same parser-parity requirement for the blocklist: the live cache reads it
    // via `parse_lines_file`, so check must too (see the allowlist note above).
    let mut blocked_domains = default_blocklist_path(resolved)
        .and_then(|p| proxy::parse_lines_file(&p))
        .unwrap_or_default();

    // Union the cached blocklist-subscription domains (issue #144) so `cplt check
    // net` reflects the SAME tighten-only blocks the live proxy freezes into
    // `ProxyState::subscription_blocklist` at startup and unions via
    // `get_blocked_domains`. Read-only: uses the last-good on-disk cache and never
    // triggers a network refresh. When no subscriptions are configured this is a
    // no-op, so `blocked_domains` stays byte-identical to the file/built-in list
    // (matches `get_blocked_domains`'s empty-subscription early return).
    let subscription_domains = subscriptions::load_cached_domains(&resolved.proxy_subscriptions);
    if !subscription_domains.is_empty() {
        blocked_domains.extend(subscription_domains);
        blocked_domains.sort_unstable();
        blocked_domains.dedup();
    }

    proxy::NetPolicy {
        allowed_ports: ports,
        allowed_domains,
        blocked_domains,
        allow_localhost_ports: resolved.allow_localhost.clone(),
        allow_localhost_any: resolved.allow_localhost_any,
        // Mirror the live proxy's private-domain union (config + CLI, deduped),
        // which `resolved.allow_private_domains` already holds, so check's
        // post-DNS resolved-IP guard waives exactly the hosts the live proxy does.
        private_domains: resolved.allow_private_domains.clone(),
    }
}

/// Split a `host[:port]` target into `(host, port)` (default 443).
fn split_host_port(target: &str) -> (String, u16) {
    // IPv6 literal in brackets, optional :port after the closing bracket.
    if let Some(stripped) = target.strip_prefix('[')
        && let Some(end) = stripped.find(']')
    {
        let host = &stripped[..end];
        let rest = &stripped[end + 1..];
        let port = rest
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);
        return (host.to_string(), port);
    }
    match target.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse().unwrap_or(443))
        }
        _ => (target.to_string(), 443),
    }
}

/// Best-effort outbound reachability check (cplt runs outside the sandbox).
/// Only used for an ALLOWED target to confirm "cplt is not blocking this";
/// never affects the decision.
fn probe_reachable(host: &str, port: u16) -> String {
    use std::net::ToSocketAddrs;
    let addr = format!("{host}:{port}");
    let Ok(mut addrs) = addr.to_socket_addrs() else {
        return format!("policy allows it, but {host} did not resolve here");
    };
    let Some(sa) = addrs.next() else {
        return format!("policy allows it, but {host} did not resolve here");
    };
    match std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(4)) {
        Ok(_) => format!("reachable — connected to {sa} then closed"),
        Err(_) => "policy allows it, but the host was not reachable from here".to_string(),
    }
}

fn run_check_command(
    cli: &Cli,
    target: Option<CheckTarget>,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if cfg!(not(any(target_os = "macos", target_os = "linux"))) {
        bail!("cplt check requires macOS or Linux");
    }
    if std::env::var("__CPLT_WRAPPED").is_ok() {
        bail!(
            "cplt check: already inside a cplt sandbox (recursion detected). \
             Run this command outside the sandbox."
        );
    }

    let ResolvedContext {
        mut resolved,
        config_path,
        home_dir,
        project_dir,
        active_agent,
        unapproved_proposals: _,
    } = resolve_context(cli, true)?;

    // check prints its own report; never prompt.
    resolved.yes = true;

    let agent_name = active_agent.display_name().to_string();
    let preset_name = resolved.preset.map(|p| preset_label(p).to_string());
    // Snapshot the effective net policy BEFORE prepare_shell_sandbox mutates
    // resolved (it only changes the proxy port and tool-path env, neither of
    // which affects domain/port classification, but snapshot early to be safe).
    let net_policy = build_net_policy(&resolved, active_agent);

    let ShellSandbox {
        prepared,
        policy,
        proxy_handle,
        scratch_guard: _scratch_guard,
    } = prepare_shell_sandbox(
        cli,
        &mut resolved,
        config_path.as_ref(),
        &home_dir,
        &project_dir,
    )?;

    let proxy_enabled = proxy_handle.is_some();
    let disabled = resolved.disabled_hardening_categories();

    let report = match target {
        None => build_battery(
            &prepared,
            &policy,
            &net_policy,
            proxy_enabled,
            &resolved,
            &disabled,
            &home_dir,
            &project_dir,
            active_agent,
            agent_name,
            preset_name,
        ),
        Some(CheckTarget::Path { path, write }) => {
            let abs = canonicalize_check_path(&path);
            build_path_check(
                &prepared,
                &policy,
                &resolved,
                &disabled,
                &home_dir,
                &project_dir,
                agent_name,
                preset_name,
                &abs,
                write,
            )
        }
        Some(CheckTarget::Net {
            target: dom,
            no_connect,
        }) => build_net_check(
            &net_policy,
            proxy_enabled,
            &dom,
            no_connect,
            agent_name,
            preset_name,
        ),
        Some(CheckTarget::Exec { cmd }) => {
            build_exec_check(&resolved, &project_dir, &cmd, agent_name, preset_name)
        }
    };

    if let Some(handle) = proxy_handle {
        handle.shutdown();
    }

    if json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.render());
    }

    if report.exit_nonzero() {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// Resolve a user-supplied check path to an absolute path without requiring it
/// to exist (canonicalize the existing ancestor, then re-append the tail).
fn canonicalize_check_path(path: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(path) {
        return c;
    }
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(d) => d.join(path),
            Err(_) => path.to_path_buf(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_battery(
    prepared: &sandbox::PreparedSandbox,
    policy: &sandbox::LandlockPolicy,
    net_policy: &proxy::NetPolicy,
    proxy_enabled: bool,
    resolved: &config::Resolved,
    disabled: &[sandbox::HardeningCategory],
    home_dir: &Path,
    project_dir: &Path,
    agent: agent::Agent,
    agent_name: String,
    preset_name: Option<String>,
) -> check::Report {
    let mut items = Vec::new();

    // ── Filesystem ──
    // Sanity: reading & writing the project dir must be ALLOWED.
    let read_proj = probe_read(prepared, resolved, disabled, project_dir);
    let read_proj_expl = check::explain_path(policy, home_dir, project_dir, project_dir);
    items.push(check::CheckItem {
        name: "read project dir".to_string(),
        category: "filesystem".to_string(),
        target: project_dir.display().to_string(),
        decision: read_proj,
        expected: Some(check::Decision::Allowed),
        reason: read_proj_expl.reason,
        fix: read_proj_expl.fix,
        note: baseline_note(read_proj),
    });

    let write_proj = probe_write(prepared, resolved, disabled, project_dir);
    items.push(check::CheckItem {
        name: "write project dir".to_string(),
        category: "filesystem".to_string(),
        target: project_dir.display().to_string(),
        decision: write_proj,
        expected: Some(check::Decision::Allowed),
        reason: "covered by the project-dir rule (read+write+execute).".to_string(),
        fix: None,
        note: baseline_note(write_proj),
    });

    // Protection: a credential path must be BLOCKED for read.
    let (prot_path, prot_label) = pick_protected_read(home_dir);
    let read_prot = probe_read(prepared, resolved, disabled, &prot_path);
    let prot_expl = check::explain_path(policy, home_dir, project_dir, &prot_path);
    items.push(check::CheckItem {
        name: prot_label,
        category: "filesystem".to_string(),
        target: prot_path.display().to_string(),
        decision: read_prot,
        expected: Some(check::Decision::Blocked),
        reason: prot_expl.reason,
        fix: prot_expl.fix,
        note: None,
    });

    // Protection: writing into the home root must be BLOCKED.
    let write_home = probe_write(prepared, resolved, disabled, home_dir);
    items.push(check::CheckItem {
        name: "write $HOME (root)".to_string(),
        category: "filesystem".to_string(),
        target: home_dir.display().to_string(),
        decision: write_home,
        expected: Some(check::Decision::Blocked),
        reason: "the home directory root is not in any write rule (deny-by-default).".to_string(),
        fix: None,
        note: None,
    });

    // ── Exec: binary-drop prevention ──
    // ~/.cache is writable but non-executable unless allow_cache_exec_any opens
    // the whole tree, so that flag — not allow_tmp_exec — governs this probe.
    let (tmp_dec, tmp_note) = probe_tmp_exec(prepared, resolved, disabled);
    let cache_expected = if resolved.allow_cache_exec_any {
        check::Decision::Allowed
    } else {
        check::Decision::Blocked
    };
    items.push(check::CheckItem {
        name: "exec staged binary (~/.cache)".to_string(),
        category: "exec".to_string(),
        target: "~/.cache/<probe>".to_string(),
        decision: tmp_dec,
        expected: Some(cache_expected),
        reason: if resolved.allow_cache_exec_any {
            "cache execution is enabled (allow_cache_exec_any=on).".to_string()
        } else {
            "executing a binary dropped into ~/.cache is blocked (writable-but-non-executable)."
                .to_string()
        },
        fix: None,
        note: tmp_note,
    });

    // ── Network ──
    if proxy_enabled {
        // Allowed: an agent-default domain (in the allowlist even under strict).
        let allowed_host = agent
            .default_allowed_domains()
            .first()
            .map_or_else(|| "github.com".to_string(), |s| (*s).to_string());
        let a_expl = check::explain_domain(net_policy, &allowed_host, 443, true);
        items.push(check::CheckItem {
            name: format!("reach {allowed_host}"),
            category: "network".to_string(),
            target: format!("{allowed_host}:443"),
            decision: a_expl.decision,
            expected: Some(check::Decision::Allowed),
            reason: a_expl.reason,
            fix: a_expl.fix,
            note: None,
        });

        // Blocked: the cloud-metadata IP (SSRF) — always refused, never leaves cplt.
        let b_expl = check::explain_domain(net_policy, "169.254.169.254", 443, true);
        items.push(check::CheckItem {
            name: "reach metadata IP (SSRF)".to_string(),
            category: "network".to_string(),
            target: "169.254.169.254:443".to_string(),
            decision: b_expl.decision,
            expected: Some(check::Decision::Blocked),
            reason: b_expl.reason,
            fix: b_expl.fix,
            note: None,
        });
    } else {
        items.push(check::CheckItem {
            name: "domain filtering".to_string(),
            category: "network".to_string(),
            target: "(proxy)".to_string(),
            decision: check::Decision::Inconclusive,
            expected: None,
            reason: "the CONNECT proxy is disabled — cplt is not filtering domains this run."
                .to_string(),
            fix: Some(
                "enable it with --with-proxy, or --preset strict for a full lockdown.".to_string(),
            ),
            note: Some("network enforcement not tested".to_string()),
        });
    }

    check::Report::new(agent_name, preset_name, true, items)
}

/// A note for a baseline (expected-allowed) probe that unexpectedly failed —
/// usually means the sandbox itself is unavailable here.
fn baseline_note(decision: check::Decision) -> Option<String> {
    match decision {
        check::Decision::Allowed => None,
        check::Decision::Inconclusive => Some("sandbox probe could not be spawned".to_string()),
        check::Decision::Blocked => Some(
            "baseline access failed — the sandbox may be unavailable here \
             (e.g. running inside another sandbox)"
                .to_string(),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_path_check(
    prepared: &sandbox::PreparedSandbox,
    policy: &sandbox::LandlockPolicy,
    resolved: &config::Resolved,
    disabled: &[sandbox::HardeningCategory],
    home_dir: &Path,
    project_dir: &Path,
    agent_name: String,
    preset_name: Option<String>,
    path: &Path,
    write: bool,
) -> check::Report {
    let expl = check::explain_path(policy, home_dir, project_dir, path);
    let mut items = Vec::new();

    let read_dec = probe_read(prepared, resolved, disabled, path);
    let note = mismatch_note(read_dec, expl.read_decision());
    items.push(check::CheckItem {
        name: "read".to_string(),
        category: "filesystem".to_string(),
        target: format!("{} (read)", path.display()),
        decision: read_dec,
        expected: None,
        reason: expl.reason.clone(),
        fix: expl.fix.clone(),
        note,
    });

    if write {
        let write_dec = probe_write(prepared, resolved, disabled, path);
        let (reason, fix) = if expl.write {
            ("covered by a writable rule.".to_string(), None)
        } else if expl.credential {
            (
                "protected path — writes are denied (deny-by-default).".to_string(),
                None,
            )
        } else {
            (
                "not covered by any write rule (deny-by-default).".to_string(),
                Some("grant write with --allow-write <PATH>.".to_string()),
            )
        };
        let note = if write_dec == check::Decision::Inconclusive {
            Some("path does not exist — cannot probe write without creating it".to_string())
        } else {
            mismatch_note(write_dec, expl.write_decision())
        };
        items.push(check::CheckItem {
            name: "write".to_string(),
            category: "filesystem".to_string(),
            target: format!("{} (write)", path.display()),
            decision: write_dec,
            expected: None,
            reason,
            fix,
            note,
        });
    }

    check::Report::new(agent_name, preset_name, false, items)
}

/// When the live probe disagrees with the static model, the probe is
/// authoritative — surface the difference so the explanation stays honest
/// (e.g. a macOS SBPL deny-subpath the Landlock model cannot express).
fn mismatch_note(probe: check::Decision, model: check::Decision) -> Option<String> {
    if probe == check::Decision::Inconclusive || probe == model {
        None
    } else {
        Some(format!(
            "live probe says {}, the policy model predicted {} (the probe is authoritative)",
            probe.as_str(),
            model.as_str()
        ))
    }
}

/// Replicate the live proxy's post-DNS resolved-IP SSRF guard for `cplt check
/// net`. `classify_connect`/`explain_domain` classify PRE-DNS only, but
/// `handle_connect` ALSO runs `resolved_ip_is_blocked` AFTER DNS — blocking a
/// public host whose A record points at a private/link-local IP
/// (10.x/172.16.x/192.168.x/169.254.169.254) with BLOCKED-PRIVATE-RESOLVED.
///
/// Returns `Some(blocked item)` when the resolved IP is blocked (so check
/// reports BLOCKED, matching live enforcement, and never runs the reachability
/// probe for such a target); returns `None` when the resolved IP passes the
/// guard OR the host does not resolve here (in which case the pre-DNS ALLOWED
/// verdict stands and `probe_reachable` reports the resolution failure honestly,
/// exactly as the live proxy would then hit DNS-FAIL rather than a policy block).
///
/// Uses the same resolver ([`proxy::resolve_socket_addr`]) and guard
/// ([`proxy::resolved_ip_is_blocked`]) as the live path, with the same
/// localhost-opt-in and `allow_private_domains` semantics.
fn resolved_ip_block_item(
    net_policy: &proxy::NetPolicy,
    host: &str,
    port: u16,
) -> Option<check::CheckItem> {
    let addr = proxy::resolve_socket_addr(host, port)?;
    let localhost_opt_in =
        net_policy.allow_localhost_any || net_policy.allow_localhost_ports.contains(&port);
    let host_is_private_domain = proxy::is_domain_match(host, &net_policy.private_domains);
    if !proxy::resolved_ip_is_blocked(&addr.ip(), host_is_private_domain, localhost_opt_in) {
        return None;
    }
    Some(check::CheckItem {
        name: "BLOCKED-PRIVATE-RESOLVED".to_string(),
        category: "network".to_string(),
        target: format!("{host}:{port}"),
        decision: check::Decision::Blocked,
        expected: None,
        reason: format!(
            "{host} resolves to {} — a private / loopback / link-local IP the proxy blocks \
             AFTER DNS (BLOCKED-PRIVATE-RESOLVED) as an SSRF / DNS-rebinding safeguard \
             (e.g. cloud metadata 169.254.169.254, internal services).",
            addr.ip()
        ),
        fix: Some(
            "for a trusted internal host use --allow-private-domains <DOMAIN>; \
             for a local dev server use --allow-localhost <PORT>."
                .to_string(),
        ),
        note: None,
    })
}

fn build_net_check(
    net_policy: &proxy::NetPolicy,
    proxy_enabled: bool,
    target: &str,
    no_connect: bool,
    agent_name: String,
    preset_name: Option<String>,
) -> check::Report {
    let (host, port) = split_host_port(target);
    let expl = check::explain_domain(net_policy, &host, port, proxy_enabled);

    // The live proxy applies a SECOND, post-DNS guard once the pre-DNS gates in
    // `classify_connect` pass. Mirror it before trusting an ALLOWED verdict so
    // check never reports ALLOWED — nor probes reachability (which cplt runs
    // OUTSIDE the sandbox, where private IPs ARE reachable) — for a target the
    // live proxy would block on its resolved IP.
    if proxy_enabled
        && expl.decision == check::Decision::Allowed
        && let Some(item) = resolved_ip_block_item(net_policy, &host, port)
    {
        return check::Report::new(agent_name, preset_name, false, vec![item]);
    }

    let note = if !no_connect && expl.decision == check::Decision::Allowed && proxy_enabled {
        Some(probe_reachable(&host, port))
    } else {
        None
    };

    let item = check::CheckItem {
        name: expl.status.clone(),
        category: "network".to_string(),
        target: format!("{host}:{port}"),
        decision: expl.decision,
        expected: None,
        reason: expl.reason,
        fix: expl.fix,
        note,
    };
    check::Report::new(agent_name, preset_name, false, vec![item])
}

fn build_exec_check(
    resolved: &config::Resolved,
    project_dir: &Path,
    cmd: &[String],
    agent_name: String,
    preset_name: Option<String>,
) -> check::Report {
    let ctx = check::ExecContext {
        allow_docker: resolved.allow_docker,
        allow_tmp_exec: resolved.allow_tmp_exec,
        gh_guard: &resolved.gh_guard,
        git_guard: &resolved.git_guard,
        project_dir,
    };
    let expl = check::explain_exec(cmd, &ctx);
    let item = check::CheckItem {
        name: "exec".to_string(),
        category: "exec".to_string(),
        target: cmd.join(" "),
        decision: expl.decision,
        expected: None,
        reason: expl.reason,
        fix: expl.fix,
        note: None,
    };
    check::Report::new(agent_name, preset_name, false, vec![item])
}

fn run_doctor() -> ExitCode {
    let home_dir = if let Ok(h) = std::env::var("HOME") {
        match std::fs::canonicalize(&h) {
            Ok(p) => p,
            Err(e) => {
                ui::error(&format!("Cannot resolve $HOME ({h}): {e}"));
                return ExitCode::FAILURE;
            }
        }
    } else {
        ui::error("$HOME not set");
        return ExitCode::FAILURE;
    };

    let project_dir = if let Some(root) = detect_project_root() {
        std::fs::canonicalize(&root).unwrap_or(root)
    } else {
        std::env::current_dir()
            .and_then(std::fs::canonicalize)
            .unwrap_or_else(|_| PathBuf::from("."))
    };

    println!(
        "{}[cplt]{} cplt:     {}",
        ui::stdout_color(ui::BLUE),
        ui::stdout_color(ui::RESET),
        LONG_VERSION
    );
    println!(
        "{}[cplt]{} Project:  {}",
        ui::stdout_color(ui::BLUE),
        ui::stdout_color(ui::RESET),
        project_dir.display()
    );
    println!(
        "{}[cplt]{} Home:     {}",
        ui::stdout_color(ui::BLUE),
        ui::stdout_color(ui::RESET),
        home_dir.display()
    );
    println!();

    let discovery = discover::discover_all(&home_dir, &project_dir);
    let ok = discovery.print_report();

    // Show project ecosystem detection summary
    let report = cplt::detect::detect_project_recursive(&project_dir);
    if !report.detections.is_empty() || !report.workspace_members.is_empty() {
        println!();
        println!(
            "{}{}[doctor]{} {}Project ecosystems{}",
            ui::stdout_color(ui::BOLD),
            ui::stdout_color(ui::BLUE),
            ui::stdout_color(ui::RESET),
            ui::stdout_color(ui::BOLD),
            ui::stdout_color(ui::RESET)
        );
        for d in &report.detections {
            println!(
                "  {}✓{} {}",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET),
                d.name
            );
        }

        // Show workspace member ecosystems
        if !report.workspace_members.is_empty() {
            // Collect unique sources for the header
            let sources: BTreeSet<String> = report
                .workspace_members
                .iter()
                .map(|m| m.source.to_string())
                .collect();
            let source_label = sources.into_iter().collect::<Vec<_>>().join(", ");

            println!();
            println!(
                "  {}Workspace members ({}){}",
                ui::stdout_color(ui::BOLD),
                source_label,
                ui::stdout_color(ui::RESET),
            );
            for member in &report.workspace_members {
                let ecosystems: Vec<&str> = member.detections.iter().map(|d| d.name).collect();
                if ecosystems.is_empty() {
                    println!(
                        "    {}•{} {}",
                        ui::stdout_color(ui::DIM),
                        ui::stdout_color(ui::RESET),
                        member.relative_path
                    );
                } else {
                    println!(
                        "    {}✓{} {} — {}",
                        ui::stdout_color(ui::GREEN),
                        ui::stdout_color(ui::RESET),
                        member.relative_path,
                        ecosystems.join(", ")
                    );
                }
            }
        }

        let has_repo_config = project_dir.join(".cplt.toml").exists();
        if !has_repo_config {
            println!(
                "  {}→{} Run `cplt init` to generate .cplt.toml",
                ui::stdout_color(ui::BLUE),
                ui::stdout_color(ui::RESET),
            );
        }
    }

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn init_config() -> ExitCode {
    let Some(path) = config::config_path() else {
        ui::error("Cannot determine config path ($HOME not set)");
        return ExitCode::FAILURE;
    };

    if path.exists() {
        ui::error(&format!(
            "Config file already exists: {}\nEdit it directly, or remove it first to regenerate.",
            path.display()
        ));
        return ExitCode::FAILURE;
    }

    // Create parent directory
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        ui::error(&format!("Cannot create config directory: {e}"));
        return ExitCode::FAILURE;
    }

    match std::fs::write(&path, config::default_config_contents()) {
        Ok(()) => {
            ui::ok(&format!("Config file created: {}", path.display()));
            ui::info("Edit it to customize sandbox defaults.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            ui::error(&format!("Cannot write config file: {e}"));
            ExitCode::FAILURE
        }
    }
}

fn run_config_command(action: ConfigAction) -> ExitCode {
    match action {
        ConfigAction::Validate => run_config_validate(),
        ConfigAction::Show => run_config_show(),
        ConfigAction::Path => run_config_path(),
        ConfigAction::Init => init_config(),
        ConfigAction::Get { key } => run_config_get(&key),
        ConfigAction::Set {
            key,
            value,
            append,
            unset,
            force,
            repo,
            global: _,
        } => run_config_set(&key, value.as_deref(), append, unset, force, repo),
        ConfigAction::Explain { key } => run_config_explain(key.as_deref()),
    }
}

fn run_config_validate() -> ExitCode {
    let loaded = match config::Config::load_file() {
        Ok(Some(l)) => l,
        Ok(None) => {
            let path_hint = config::config_path()
                .map(|p| format!(" (looked for {})", p.display()))
                .unwrap_or_default();
            ui::info(&format!("No config file found{path_hint}"));
            ui::info("Run `cplt config init` to create one.");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            ui::error(&e.to_string());
            return ExitCode::FAILURE;
        }
    };

    ui::info(&format!("Validating {}", loaded.path.display()));

    let diagnostics = config::validate_config(&loaded.raw);

    if diagnostics.is_empty() {
        ui::ok("Config OK ✓");
        return ExitCode::SUCCESS;
    }

    let mut has_errors = false;
    for d in &diagnostics {
        match d.level {
            config::DiagnosticLevel::Error => {
                has_errors = true;
                ui::error(&d.message);
            }
            config::DiagnosticLevel::Warning => {
                ui::warn(&d.message);
            }
            _ => {
                ui::info(&d.message);
            }
        }
    }

    if has_errors {
        ExitCode::FAILURE
    } else {
        ui::ok("Config OK ✓ (with warnings)");
        ExitCode::SUCCESS
    }
}

fn run_config_show() -> ExitCode {
    let loaded = match config::Config::load_file() {
        Ok(l) => l,
        Err(e) => {
            ui::error(&e.to_string());
            return ExitCode::FAILURE;
        }
    };

    config::display_config(loaded.as_ref());

    // Show repo config if present
    let project_dir = detect_project_root().or_else(|| std::env::current_dir().ok());
    if let Some(ref dir) = project_dir {
        match repo_config::load_repo_config(dir) {
            Ok(Some(loaded_repo)) => {
                display_repo_config(&loaded_repo, dir);
            }
            Err(e) => {
                eprintln!();
                eprintln!(
                    "{}[cplt] Repo config error: {e}{}",
                    ui::color(ui::YELLOW),
                    ui::color(ui::RESET)
                );
            }
            Ok(None) => {} // No .cplt.toml — nothing to show
        }
    }

    ExitCode::SUCCESS
}

fn display_repo_config(loaded: &repo_config::LoadedRepoConfig, project_dir: &std::path::Path) {
    let dim = ui::stdout_color(ui::DIM);
    let green = ui::stdout_color(ui::GREEN);
    let yellow = ui::stdout_color(ui::YELLOW);
    let blue = ui::stdout_color(ui::BLUE);
    let nc = ui::stdout_color(ui::RESET);

    println!();
    println!("{blue}[cplt]{nc} ── Repo Config (.cplt.toml) ────────────────────────");
    println!(
        "{blue}[cplt]{nc}  {dim}Source:{nc} {}",
        source_label(loaded.source)
    );
    println!(
        "{blue}[cplt]{nc}  {dim}Path:{nc}   {}/.cplt.toml",
        project_dir.display()
    );
    println!();

    let rc = &loaded.config;

    // [deny]
    if !rc.deny.paths.is_empty() || !rc.deny.env.is_empty() {
        println!("{blue}[cplt]{nc}  {dim}[deny]{nc} {green}{LABEL_DENY_APPLIED}{nc}");
        for p in &rc.deny.paths {
            println!("{blue}[cplt]{nc}    paths   = {p}");
        }
        for v in &rc.deny.env {
            println!("{blue}[cplt]{nc}    env     = {v}");
        }
        println!();
    }

    // [propose]
    let proposed = repo_config::proposed_keys(&rc.propose);
    if proposed.is_empty() {
        println!("{blue}[cplt]{nc}  {dim}No additional permissions requested.{nc}");
    } else {
        let trust_entry = crate::trust::load_trust(project_dir);

        // Determine overall approval status for the header
        let all_approved = proposed.iter().all(|key| {
            trust_entry
                .as_ref()
                .is_some_and(|t| crate::trust::is_key_approved(t, key))
        });
        let header_status = if all_approved {
            format!("{green}{LABEL_ALLOW_APPROVED}{nc}")
        } else {
            format!("{yellow}{LABEL_ALLOW_PENDING}{nc}")
        };
        println!("{blue}[cplt]{nc}  {dim}[allow]{nc} {header_status}");

        // Booleans
        let bools: &[(&str, Option<bool>)] = &[
            ("allow_localhost_any", rc.propose.allow_localhost_any),
            ("allow_jvm_attach", rc.propose.allow_jvm_attach),
            ("allow_msbuild", rc.propose.allow_msbuild),
            ("allow_docker", rc.propose.allow_docker),
            ("allow_tmp_exec", rc.propose.allow_tmp_exec),
            ("allow_gpg_signing", rc.propose.allow_gpg_signing),
            (
                "allow_lifecycle_scripts",
                rc.propose.allow_lifecycle_scripts,
            ),
            ("allow_env_files", rc.propose.allow_env_files),
            ("allow_browser", rc.propose.allow_browser),
            ("gh_guard", rc.propose.gh_guard),
            ("git_push_prevention", rc.propose.git_push_prevention),
        ];
        for (name, val) in bools {
            if let Some(v) = val {
                let approved = trust_entry
                    .as_ref()
                    .is_some_and(|t| crate::trust::is_key_approved(t, name));
                let status = if approved {
                    format!("{green}{STATUS_APPROVED}{nc}")
                } else {
                    format!("{yellow}{STATUS_PENDING}{nc}")
                };
                println!("{blue}[cplt]{nc}    {name:<30} = {v}  {status}");
            }
        }

        // Arrays
        if !rc.propose.allow.read.is_empty() {
            println!("{blue}[cplt]{nc}    {dim}allow.read:{nc}");
            for p in &rc.propose.allow.read {
                println!("{blue}[cplt]{nc}      {p}");
            }
        }
        if !rc.propose.allow.write.is_empty() {
            println!("{blue}[cplt]{nc}    {dim}allow.write:{nc}");
            for p in &rc.propose.allow.write {
                println!("{blue}[cplt]{nc}      {p}");
            }
        }
        if !rc.propose.allow.ports.is_empty() {
            println!(
                "{blue}[cplt]{nc}    allow.ports            = {:?}",
                rc.propose.allow.ports
            );
        }
        if !rc.propose.allow.localhost.is_empty() {
            println!(
                "{blue}[cplt]{nc}    allow.localhost         = {:?}",
                rc.propose.allow.localhost
            );
        }
        if !rc.propose.proxy.allow_private_domains.is_empty() {
            println!(
                "{blue}[cplt]{nc}    proxy.allow_private_domains = {:?}",
                rc.propose.proxy.allow_private_domains
            );
        }
    }

    println!("{blue}[cplt]{nc} ──────────────────────────────────────────────────────");
}

fn run_config_path() -> ExitCode {
    if let Some(p) = config::config_path() {
        println!("{}", p.display());
        ExitCode::SUCCESS
    } else {
        ui::error("Cannot determine config path ($HOME not set)");
        ExitCode::FAILURE
    }
}

fn run_config_get(key: &str) -> ExitCode {
    let key_info = match config::lookup_key(key) {
        Ok(k) => k,
        Err(e) => {
            ui::error(&e.to_string());
            return ExitCode::FAILURE;
        }
    };

    let loaded = match config::Config::load_file() {
        Ok(l) => l,
        Err(e) => {
            ui::error(&e.to_string());
            return ExitCode::FAILURE;
        }
    };

    let (value, from_file) = config::get_config_value(key_info, loaded.as_ref());
    println!("{value}");
    if !from_file {
        eprintln!(
            "{}[cplt]{} (default — not set in config file)",
            ui::color(ui::BLUE),
            ui::color(ui::RESET)
        );
    }
    ExitCode::SUCCESS
}

fn run_config_set(
    key: &str,
    value: Option<&str>,
    append: bool,
    unset: bool,
    force: bool,
    repo: bool,
) -> ExitCode {
    let key_info = match config::lookup_key(key) {
        Ok(info) => info,
        Err(e) => {
            ui::error(&e.to_string());
            return ExitCode::FAILURE;
        }
    };

    // Validate flag combinations
    if unset && value.is_some() && !key_info.value_type.is_array() {
        ui::error("--unset does not take a value (except for array keys)");
        return ExitCode::FAILURE;
    }
    if unset && append {
        ui::error("--unset and --append are mutually exclusive");
        return ExitCode::FAILURE;
    }
    if !unset && value.is_none() {
        ui::error(&format!(
            "missing value for {key}\n  Usage: cplt config set {key} <VALUE>"
        ));
        return ExitCode::FAILURE;
    }

    // ── Repo mode ───────────────────────────────────────────────────
    if repo {
        return run_config_set_repo(key, key_info, value, unset, force);
    }

    // ── Global mode (default) ───────────────────────────────────────

    // deny.env is repo-local only (not in global config file schema)
    if key_info.section == "deny" && key_info.key == "env" {
        ui::error(
            "deny.env is only supported in repo-local config (.cplt.toml).\n  Use: cplt config set --repo deny.env <VALUE>",
        );
        return ExitCode::FAILURE;
    }

    let op = match config::ConfigSetOp::new(key) {
        Ok(op) => op,
        Err(e) => {
            ui::error(&e.to_string());
            return ExitCode::FAILURE;
        }
    };

    if !unset
        && !force
        && let Some(val) = value
        && let Some(reason) = config::security_confirmation(op.key_info, val, false)
    {
        ui::error(&format!(
            "{key} = {val} {reason}.\n  Add --force to confirm: cplt config set {key} {val} --force"
        ));
        return ExitCode::FAILURE;
    }

    // Load or create document
    let mut doc = match op.load_document() {
        Ok(d) => d,
        Err(e) => {
            ui::error(&e.to_string());
            return ExitCode::FAILURE;
        }
    };

    // Apply modification
    let mut element_removed = false;
    let result = if unset {
        if let Some(val) = value
            && op.key_info.value_type.is_array()
        {
            config::remove_array_element_in_doc(&mut doc, op.key_info, val)
                .map(|removed| element_removed = removed)
        } else {
            config::unset_value_in_doc(&mut doc, op.key_info);
            Ok(())
        }
    } else if append || op.key_info.value_type.is_array() {
        config::append_value_in_doc(&mut doc, op.key_info, value.unwrap())
    } else {
        config::set_value_in_doc(&mut doc, op.key_info, value.unwrap())
    };

    if let Err(e) = result {
        ui::error(&e.to_string());
        return ExitCode::FAILURE;
    }

    // Skip writing when nothing changed (unset element that wasn't present)
    if let Some(val) = value
        && !element_removed
        && unset
        && op.key_info.value_type.is_array()
    {
        ui::warn(&format!("{key}: {val} is not set"));
        return ExitCode::SUCCESS;
    }

    // Write back
    if let Err(e) = op.write_document(&doc) {
        ui::error(&e.to_string());
        return ExitCode::FAILURE;
    }

    if unset {
        if let Some(val) = value
            && op.key_info.value_type.is_array()
        {
            if let Some(remaining) = config::get_value_from_doc(&doc, op.key_info) {
                ui::ok(&format!("{key}: removed {val} → {remaining}"));
            } else {
                ui::ok(&format!("{key}: removed {val} (now empty)"));
            }
        } else {
            ui::ok(&format!("{key} removed (will use default)"));
        }
    } else if append || op.key_info.value_type.is_array() {
        let current = config::get_value_from_doc(&doc, op.key_info)
            .unwrap_or_else(|| value.unwrap().to_string());
        ui::ok(&format!("{key} = {current}"));
    } else {
        ui::ok(&format!("{key} = {}", value.unwrap()));
    }

    // Hint about repo config if .cplt.toml exists
    let project_dir = detect_project_root().or_else(|| std::env::current_dir().ok());
    if let Some(ref dir) = project_dir
        && dir.join(".cplt.toml").exists()
    {
        let dim = ui::color(ui::DIM);
        eprintln!(
            "{}[cplt]{} {dim}Tip: this repo has .cplt.toml. Use --repo to set project-specific settings.{}",
            ui::color(ui::BLUE),
            ui::color(ui::RESET),
            ui::color(ui::RESET)
        );
    }

    ExitCode::SUCCESS
}

fn run_config_set_repo(
    key: &str,
    key_info: &'static config::ConfigKeyInfo,
    value: Option<&str>,
    unset: bool,
    force: bool,
) -> ExitCode {
    // Determine repo config path (git root preferred, fallback to cwd)
    let project_dir = detect_project_root()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let repo_config_path = project_dir.join(".cplt.toml");

    // Check if key is valid in repo config
    let Some(target) = config::repo_key_target(key_info) else {
        let reason = config::repo_key_rejection_reason(key_info);
        ui::error(&format!(
            "{key} is not valid in repo config.\n  \
             Reason: {reason}.\n  \
             Use: cplt config set {key} {}",
            value.unwrap_or("<VALUE>")
        ));
        return ExitCode::FAILURE;
    };

    // Dangerous key safeguard (still applies for repo permissions)
    if key_info.dangerous
        && !unset
        && let Some(val) = value
        && val == "true"
        && !force
    {
        ui::error(&format!(
            "{key} is dangerous — it requests weakened security for anyone approving this repo config.\n  \
             Add --force to confirm: cplt config set --repo {key} true --force"
        ));
        return ExitCode::FAILURE;
    }

    // Load or create repo config document
    let mut doc = if repo_config_path.exists() {
        let raw = match std::fs::read_to_string(&repo_config_path) {
            Ok(r) => r,
            Err(e) => {
                ui::error(&format!("cannot read {}: {e}", repo_config_path.display()));
                return ExitCode::FAILURE;
            }
        };
        match raw.parse::<toml_edit::DocumentMut>() {
            Ok(d) => d,
            Err(e) => {
                ui::error(&format!(
                    "invalid TOML in {}: {e}",
                    repo_config_path.display()
                ));
                return ExitCode::FAILURE;
            }
        }
    } else {
        toml_edit::DocumentMut::new()
    };

    // Apply modification
    let val = if unset {
        value.unwrap_or("")
    } else {
        value.unwrap()
    };
    if let Err(e) = config::set_repo_value_in_doc(&mut doc, key_info, target, val, unset) {
        ui::error(&e.to_string());
        return ExitCode::FAILURE;
    }

    let output = doc.to_string();
    if let Err(e) = repo_config::parse_and_validate(&output) {
        ui::error(&format!(
            "refusing to write invalid .cplt.toml: {e}\n  No changes were saved."
        ));
        return ExitCode::FAILURE;
    }
    if let Err(e) = config::write_repo_document_atomically(&repo_config_path, &doc) {
        ui::error(&format!("cannot write {}: {e}", repo_config_path.display()));
        return ExitCode::FAILURE;
    }

    // User feedback
    let dim = ui::color(ui::DIM);
    if unset {
        ui::ok(&format!("{key} removed from .cplt.toml"));
    } else {
        let section_name = match target {
            config::RepoKeyTarget::ProposeBool
            | config::RepoKeyTarget::ProposeAllow(_)
            | config::RepoKeyTarget::ProposeProxy(_) => "propose",
            config::RepoKeyTarget::Deny(_) => "deny",
            _ => "unknown",
        };
        ui::ok(&format!("{key} = {val} → .cplt.toml [{section_name}]"));
    }
    let blue = ui::color(ui::BLUE);
    let nc = ui::color(ui::RESET);
    eprintln!(
        "{blue}[cplt]{nc} {dim}Updated: {}{nc}",
        repo_config_path.display()
    );

    // Remind about trust approval for propose keys
    if matches!(
        target,
        config::RepoKeyTarget::ProposeBool
            | config::RepoKeyTarget::ProposeAllow(_)
            | config::RepoKeyTarget::ProposeProxy(_)
    ) && !unset
    {
        eprintln!(
            "{blue}[cplt]{nc} {dim}Proposed changes require approval: cplt trust accept --all{nc}"
        );
        eprintln!("{blue}[cplt]{nc} {dim}Remember to commit .cplt.toml{nc}");
    }

    ExitCode::SUCCESS
}

fn run_config_explain(key: Option<&str>) -> ExitCode {
    // Load config best-effort: no file → defaults only; parse error → warn and show defaults.
    let loaded = match config::Config::load_file() {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "{}[cplt] Warning: {e}; showing defaults only{}",
                ui::color(ui::YELLOW),
                ui::color(ui::RESET)
            );
            None
        }
    };

    if let Some(k) = key {
        match config::lookup_key(k) {
            Ok(info) => {
                config::explain_key(info, loaded.as_ref());
                ExitCode::SUCCESS
            }
            Err(e) => {
                ui::error(&e.to_string());
                ExitCode::FAILURE
            }
        }
    } else {
        config::explain_all(loaded.as_ref());
        ExitCode::SUCCESS
    }
}

fn run_init_command(write: bool, force: bool, merge: bool, quiet: bool) -> ExitCode {
    let project_dir = detect_project_root()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let opts = cplt::init::InitOptions {
        write,
        force,
        merge,
        quiet,
    };

    // Detect once, use for both display and generation (monorepo-aware)
    let report = cplt::detect::detect_project_recursive(&project_dir);

    if report.detections.is_empty() && report.workspace_members.is_empty() {
        if !quiet {
            eprintln!("No project tooling detected in {}", project_dir.display());
            eprintln!("Nothing to generate.");
        }
        return ExitCode::SUCCESS;
    }

    // Show ecosystem report unless quiet
    if !quiet {
        print!("{}", cplt::init::format_report(&report));
    }

    let result = cplt::init::run_init(&project_dir, &report, &opts);

    match result {
        cplt::init::InitResult::Generated {
            toml: _,
            path,
            written: true,
        } => {
            if !quiet {
                eprintln!("Wrote {}", path.display());
                eprintln!();
                eprintln!(
                    "Next: review the file and run `cplt trust accept --all` to approve permissions."
                );
            }
            ExitCode::SUCCESS
        }
        cplt::init::InitResult::Generated {
            toml,
            written: false,
            ..
        } => {
            if !quiet {
                println!("Generated .cplt.toml:");
                println!("─────────────────────────────────────────");
            }
            print!("{toml}");
            if !quiet {
                println!("─────────────────────────────────────────");
                println!();
                println!("Run `cplt init --write` to save this to .cplt.toml");
            }
            ExitCode::SUCCESS
        }
        cplt::init::InitResult::AlreadyExists(path) => {
            eprintln!(
                "error: {} already exists (use --force to overwrite)",
                path.display()
            );
            ExitCode::FAILURE
        }
        cplt::init::InitResult::WriteFailed(path, err) => {
            eprintln!("error: failed to write {}: {err}", path.display());
            ExitCode::FAILURE
        }
        cplt::init::InitResult::NothingDetected => ExitCode::SUCCESS,
    }
}

fn run_init_global_command(write: bool, force: bool, quiet: bool) -> ExitCode {
    let Ok(home) = std::env::var("HOME") else {
        eprintln!("error: $HOME not set");
        return ExitCode::FAILURE;
    };
    let home_dir = PathBuf::from(home);

    let config_path =
        cplt::config::config_path().unwrap_or_else(|| home_dir.join(".config/cplt/config.toml"));

    let report = cplt::detect::detect_global(&home_dir);

    if report.detections.is_empty() {
        if !quiet {
            eprintln!("No machine-level configuration detected.");
            eprintln!("Your setup works with cplt defaults — no personal config needed.");
        }
        return ExitCode::SUCCESS;
    }

    // Show report unless quiet
    if !quiet {
        print!("{}", cplt::init::format_global_report(&report));
    }

    let opts = cplt::init::InitOptions {
        write,
        force,
        merge: false,
        quiet,
    };

    let result = cplt::init::run_init_global(&config_path, &report, &opts);

    match result {
        cplt::init::GlobalInitResult::Generated {
            toml: _,
            written: true,
            path,
        } => {
            if !quiet {
                eprintln!("Wrote {}", path.display());
                eprintln!();
                eprintln!("Review: cplt config show");
            }
            ExitCode::SUCCESS
        }
        cplt::init::GlobalInitResult::Generated {
            toml,
            written: false,
            path,
            ..
        } => {
            if !quiet {
                println!("Generated {}:", path.display());
                println!("─────────────────────────────────────────");
            }
            print!("{toml}");
            if !quiet {
                println!("─────────────────────────────────────────");
                println!();
                println!("Run `cplt init --global --write` to save this config");
            }
            ExitCode::SUCCESS
        }
        cplt::init::GlobalInitResult::AlreadyExists(path) => {
            eprintln!(
                "error: {} already exists (use --force to overwrite)",
                path.display()
            );
            ExitCode::FAILURE
        }
        cplt::init::GlobalInitResult::WriteFailed(path, err) => {
            eprintln!("error: failed to write {}: {err}", path.display());
            ExitCode::FAILURE
        }
    }
}

fn run_trust_command(action: Option<TrustAction>) -> ExitCode {
    // Determine project directory (git root preferred, fallback to cwd)
    let project_dir = detect_project_root()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // Check if inside sandbox — trust commands are blocked there
    if std::env::var("__CPLT_TRUST_LOCKED").is_ok() {
        ui::error("Cannot modify trust from inside the sandbox.");
        eprintln!("  Run `cplt trust` outside the sandbox (before launching the agent).");
        return ExitCode::FAILURE;
    }

    // Load repo config
    let loaded = match repo_config::load_repo_config(&project_dir) {
        Ok(Some(l)) => l,
        Ok(None) => {
            ui::info("No .cplt.toml found in this repository.");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            ui::error(&format!("Failed to load .cplt.toml: {e}"));
            return ExitCode::FAILURE;
        }
    };

    let action = action.unwrap_or(TrustAction::Show);

    match action {
        TrustAction::Show => trust_show(&project_dir, &loaded),
        TrustAction::Accept { keys, all } => trust_accept(&project_dir, &loaded, &keys, all),
        TrustAction::Revoke { keys, all } => trust_revoke(&project_dir, &loaded, &keys, all),
    }
}

fn trust_show(project_dir: &std::path::Path, loaded: &repo_config::LoadedRepoConfig) -> ExitCode {
    let proposed = repo_config::proposed_keys(&loaded.config.propose);
    let trust_entry = trust::load_trust(project_dir);

    let blue = ui::stdout_color(ui::BLUE);
    let nc = ui::stdout_color(ui::RESET);
    let green = ui::stdout_color(ui::GREEN);
    let yellow = ui::stdout_color(ui::YELLOW);
    let red = ui::stdout_color(ui::RED);

    println!("{blue}[cplt]{nc} ── Repo Config Trust ──────────────────────────────");
    println!("{blue}[cplt]{nc}  Source: {}", source_label(loaded.source));
    println!();

    // Deny section
    if !loaded.config.deny.paths.is_empty() || !loaded.config.deny.env.is_empty() {
        println!("{blue}[cplt]{nc}  {green}[deny]{nc} {LABEL_DENY_APPLIED}");
        for p in &loaded.config.deny.paths {
            println!("{blue}[cplt]{nc}    path: {p}");
        }
        for v in &loaded.config.deny.env {
            println!("{blue}[cplt]{nc}    env:  {v}");
        }
        println!();
    }

    // Check if proposals have changed since approval (content hash mismatch)
    let hash_mismatch = trust_entry.as_ref().is_some_and(|t| {
        !t.accepted.content_hash.is_empty() && {
            let current_hash = trust::proposal_content_hash(&loaded.config.propose);
            t.accepted.content_hash != current_hash
        }
    });

    // Proposals
    let all_approved = !hash_mismatch
        && !proposed.is_empty()
        && proposed.iter().all(|&key| {
            trust_entry
                .as_ref()
                .is_some_and(|t| trust::is_key_approved(t, key))
        });
    if proposed.is_empty() {
        println!("{blue}[cplt]{nc}  No additional permissions requested.");
    } else {
        let section_label = if all_approved {
            LABEL_ALLOW_APPROVED
        } else {
            LABEL_ALLOW_PENDING
        };
        println!("{blue}[cplt]{nc}  {yellow}[allow]{nc} {section_label}");
        for &key in &proposed {
            let approved = !hash_mismatch
                && trust_entry
                    .as_ref()
                    .is_some_and(|t| trust::is_key_approved(t, key));
            let status = if approved {
                format!("{green}{STATUS_APPROVED}{nc}")
            } else {
                format!("{yellow}{STATUS_PENDING}{nc}")
            };
            println!("{blue}[cplt]{nc}    {key:<35} {status}");
        }
    }

    // Show actionable hint for unapproved permissions
    let has_pending = !proposed.is_empty() && !all_approved;

    if let Some(ref entry) = trust_entry
        && !entry.accepted.approved_at.is_empty()
    {
        println!();
        println!(
            "{blue}[cplt]{nc}  Last approved: {}",
            entry.accepted.approved_at
        );

        if hash_mismatch {
            println!("{blue}[cplt]{nc}  {red}⚠ Permissions have changed since last approval!{nc}");
            println!("{blue}[cplt]{nc}  {red}  Run `cplt trust accept --all` to re-approve.{nc}");
        }

        // Finding 4: approval is bound to the local checkout path. If this repo's
        // origin matches a trusted entry but sits at a different path, the keys
        // shown above will NOT auto-apply — surface that honestly.
        if !trust::approved_path_matches(entry, project_dir) {
            println!(
                "{blue}[cplt]{nc}  {red}⚠ Approved at a different path ({}) — not auto-trusted here.{nc}",
                if entry.repo.path.is_empty() {
                    "unrecorded"
                } else {
                    &entry.repo.path
                }
            );
            println!(
                "{blue}[cplt]{nc}  {red}  Run `cplt trust accept` to approve at this path.{nc}"
            );
        }
    } else if has_pending {
        println!();
        println!("{blue}[cplt]{nc}  {yellow}To approve all pending permissions:{nc}");
        println!("{blue}[cplt]{nc}    cplt trust accept --all");
        println!();
        println!("{blue}[cplt]{nc}  {yellow}Or approve specific keys:{nc}");
        let pending_keys: Vec<&&str> = proposed
            .iter()
            .filter(|&&key| {
                !trust_entry
                    .as_ref()
                    .is_some_and(|t| trust::is_key_approved(t, key))
            })
            .collect();
        println!(
            "{blue}[cplt]{nc}    cplt trust accept {}",
            pending_keys
                .iter()
                .map(|k| **k)
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    println!("{blue}[cplt]{nc} ──────────────────────────────────────────────────────");
    ExitCode::SUCCESS
}

fn trust_accept(
    project_dir: &std::path::Path,
    loaded: &repo_config::LoadedRepoConfig,
    keys: &[String],
    all: bool,
) -> ExitCode {
    let proposed = repo_config::proposed_keys(&loaded.config.propose);

    if proposed.is_empty() {
        ui::info("No permissions requested in .cplt.toml — nothing to approve.");
        return ExitCode::SUCCESS;
    }

    // Guard: refuse to approve uncommitted .cplt.toml changes.
    // This ensures approved configs are auditable in git history and prevents
    // a malicious process from injecting permissions and immediately accepting them.
    if is_cplt_toml_uncommitted(project_dir) {
        ui::error(
            ".cplt.toml has uncommitted changes.\n  \
             Commit the file first so permissions are auditable in git history:\n    \
             git add .cplt.toml && git commit -m \"chore: update cplt sandbox config\"",
        );
        return ExitCode::FAILURE;
    }

    // Determine which keys to accept
    let keys_to_accept: Vec<String> = if all {
        proposed
            .iter()
            .map(std::string::ToString::to_string)
            .collect()
    } else if keys.is_empty() {
        // Interactive mode: show pending permissions and prompt
        let trust_entry = trust::load_trust(project_dir);

        // If content hash changed, all keys need re-approval
        let hash_mismatch = trust_entry.as_ref().is_some_and(|t| {
            !t.accepted.content_hash.is_empty() && {
                let current_hash = trust::proposal_content_hash(&loaded.config.propose);
                t.accepted.content_hash != current_hash
            }
        });

        let pending: Vec<&str> = if hash_mismatch {
            // Values changed — all keys need re-approval
            proposed.clone()
        } else {
            proposed
                .iter()
                .filter(|&&key| {
                    !trust_entry
                        .as_ref()
                        .is_some_and(|t| trust::is_key_approved(t, key))
                })
                .copied()
                .collect()
        };

        if pending.is_empty() {
            ui::info("All permissions are already approved.");
            return ExitCode::SUCCESS;
        }

        if hash_mismatch {
            println!(
                "{}[cplt]{} Proposal values have changed since last approval — re-approval needed.",
                ui::stdout_color(ui::YELLOW),
                ui::stdout_color(ui::RESET),
            );
            println!();
        }

        let blue = ui::stdout_color(ui::BLUE);
        let nc = ui::stdout_color(ui::RESET);
        let yellow = ui::stdout_color(ui::YELLOW);

        println!(
            "{blue}[cplt]{nc} Pending permissions in .cplt.toml ({} unapproved):",
            pending.len()
        );
        println!();
        for &key in &pending {
            let detail = propose_key_detail(&loaded.config.propose, key);
            if let Some(d) = detail {
                println!("  {yellow}•{nc} {key}: {d}");
            } else {
                println!("  {yellow}•{nc} {key}");
            }
        }
        println!();

        // Check if we can prompt interactively
        if !std::io::stdin().is_terminal() {
            ui::error(
                "Cannot prompt for confirmation (stdin is not a terminal).\n  \
                 Use: cplt trust accept --all",
            );
            return ExitCode::FAILURE;
        }

        eprint!("Accept all? [y/N]: ");
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            return ExitCode::FAILURE;
        }
        let answer = input.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            ui::info("Cancelled — no permissions approved.");
            return ExitCode::SUCCESS;
        }

        pending.iter().map(|s| (*s).to_string()).collect()
    } else {
        // Validate that requested keys are actually proposed
        for key in keys {
            if !proposed.contains(&key.as_str()) {
                ui::error(&format!(
                    "Key {key:?} is not requested in .cplt.toml. Available: {}",
                    proposed
                        .iter()
                        .map(|s| format!("{s:?}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                return ExitCode::FAILURE;
            }
        }
        keys.to_vec()
    };

    // Load or create trust entry
    let mut entry = trust::load_trust(project_dir).unwrap_or_default();

    // Set identity
    entry.repo.path = project_dir.to_string_lossy().into_owned();
    if entry.repo.remote.is_empty()
        && let Ok(output) = std::process::Command::new("git")
            .args(["remote", "get-url", "origin"])
            .current_dir(project_dir)
            .output()
        && output.status.success()
        && let Ok(url) = String::from_utf8(output.stdout)
    {
        entry.repo.remote = trust::normalize_remote_url(url.trim());
    }

    // Add new keys (don't duplicate)
    for key in &keys_to_accept {
        if !entry.accepted.keys.contains(key) {
            entry.accepted.keys.push(key.clone());
        }
    }
    entry.accepted.keys.sort_unstable();
    entry.accepted.approved_at = trust::now_iso8601();
    // Pin content hash so changes to proposal values invalidate approval
    entry.accepted.content_hash = trust::proposal_content_hash(&loaded.config.propose);

    // Save
    if let Err(e) = trust::save_trust(project_dir, &entry) {
        ui::error(&format!("Failed to save trust: {e}"));
        return ExitCode::FAILURE;
    }

    println!(
        "{}✓{} Approved {} permission(s) for this repository:",
        ui::stdout_color(ui::GREEN),
        ui::stdout_color(ui::RESET),
        keys_to_accept.len()
    );
    for key in &keys_to_accept {
        println!("  • {key}");
    }
    ExitCode::SUCCESS
}

/// Check if .cplt.toml has uncommitted changes (staged or unstaged).
fn is_cplt_toml_uncommitted(project_dir: &std::path::Path) -> bool {
    let output = std::process::Command::new("git")
        .args(["status", "--porcelain", "--", ".cplt.toml"])
        .current_dir(project_dir)
        .output();
    match output {
        Ok(o) if o.status.success() => !o.stdout.is_empty(),
        _ => false, // If git fails (not a repo, etc.), don't block
    }
}

/// Format the proposed values for a key for display.
fn propose_key_detail(propose: &repo_config::ProposeSection, key: &str) -> Option<String> {
    match key {
        "allow.read" if !propose.allow.read.is_empty() => Some(format!("{:?}", propose.allow.read)),
        "allow.write" if !propose.allow.write.is_empty() => {
            Some(format!("{:?}", propose.allow.write))
        }
        "allow.ports" if !propose.allow.ports.is_empty() => {
            Some(format!("{:?}", propose.allow.ports))
        }
        "allow.localhost" if !propose.allow.localhost.is_empty() => {
            Some(format!("{:?}", propose.allow.localhost))
        }
        "proxy.allow_private_domains" if !propose.proxy.allow_private_domains.is_empty() => {
            Some(format!("{:?}", propose.proxy.allow_private_domains))
        }
        _ => None,
    }
}

fn trust_revoke(
    project_dir: &std::path::Path,
    loaded: &repo_config::LoadedRepoConfig,
    keys: &[String],
    all: bool,
) -> ExitCode {
    if all {
        if let Err(e) = trust::revoke_trust(project_dir) {
            ui::error(&format!("Failed to revoke trust: {e}"));
            return ExitCode::FAILURE;
        }
        println!(
            "{}✓{} Revoked all trust for this repository.",
            ui::stdout_color(ui::GREEN),
            ui::stdout_color(ui::RESET)
        );
        return ExitCode::SUCCESS;
    }

    let proposed = repo_config::proposed_keys(&loaded.config.propose);
    let Some(mut entry) = trust::load_trust(project_dir) else {
        ui::info("No trust entry exists for this repository.");
        return ExitCode::SUCCESS;
    };

    // Validate keys
    for key in keys {
        if !proposed.contains(&key.as_str()) && !entry.accepted.keys.contains(key) {
            ui::warn(&format!(
                "Key {key:?} is not in permissions or trust store."
            ));
        }
    }

    // Remove keys
    let before_len = entry.accepted.keys.len();
    entry.accepted.keys.retain(|k| !keys.contains(k));
    let removed = before_len - entry.accepted.keys.len();

    if removed == 0 {
        ui::info("No matching keys found to revoke.");
        return ExitCode::SUCCESS;
    }

    if entry.accepted.keys.is_empty() {
        // No keys left — remove the file entirely
        if let Err(e) = trust::revoke_trust(project_dir) {
            ui::error(&format!("Failed to remove trust file: {e}"));
            return ExitCode::FAILURE;
        }
    } else {
        entry.accepted.approved_at = trust::now_iso8601();
        if let Err(e) = trust::save_trust(project_dir, &entry) {
            ui::error(&format!("Failed to save trust: {e}"));
            return ExitCode::FAILURE;
        }
    }

    println!(
        "{}✓{} Revoked {removed} key(s).",
        ui::stdout_color(ui::GREEN),
        ui::stdout_color(ui::RESET)
    );
    ExitCode::SUCCESS
}

fn run_update(check_only: bool, force: bool) -> ExitCode {
    // Check for Homebrew-managed install
    if update::is_homebrew_managed() {
        ui::info("cplt is managed by Homebrew.");
        println!(
            "  Run: {}brew upgrade navikt/tap/cplt{}",
            ui::stdout_color(ui::GREEN),
            ui::stdout_color(ui::RESET)
        );
        return ExitCode::SUCCESS;
    }

    // Fetch latest release
    ui::info("Checking for updates...");
    let latest = match update::fetch_latest_release(LONG_VERSION) {
        Ok(r) => r,
        Err(e) => {
            ui::error(&e.to_string());
            return ExitCode::FAILURE;
        }
    };

    let status = update::check_version(LONG_VERSION, &latest);

    match status {
        update::VersionStatus::UpToDate => {
            ui::info(&format!("✓ cplt is up to date ({LONG_VERSION})"));
            ExitCode::SUCCESS
        }
        update::VersionStatus::UpdateAvailable {
            current,
            latest: latest_ver,
            tag,
        } => {
            ui::info(&format!(
                "Update available: {current} → {}{latest_ver}{}",
                ui::color(ui::GREEN),
                ui::color(ui::RESET)
            ));
            if check_only {
                return ExitCode::SUCCESS;
            }
            do_update(&tag, &latest_ver)
        }
        update::VersionStatus::SameDateDifferentBuild {
            current,
            latest: latest_ver,
            tag,
        } => {
            ui::info(&format!(
                "Same date, different build: {current} vs {latest_ver}"
            ));
            if check_only {
                return ExitCode::SUCCESS;
            }
            if !force {
                ui::warn("Same-date build. Use --force to reinstall.");
                return ExitCode::SUCCESS;
            }
            do_update(&tag, &latest_ver)
        }
        update::VersionStatus::DevBuild {
            latest: latest_ver,
            tag,
        } => {
            ui::warn(&format!(
                "Running dev build (0.0.0). Latest release: {latest_ver}"
            ));
            if check_only {
                return ExitCode::SUCCESS;
            }
            if !force {
                ui::warn("Use --force to replace dev build with release.");
                return ExitCode::SUCCESS;
            }
            do_update(&tag, &latest_ver)
        }
        _ => {
            ui::info(&format!("✓ cplt is up to date ({LONG_VERSION})"));
            ExitCode::SUCCESS
        }
    }
}

fn do_update(tag: &str, expected_version: &str) -> ExitCode {
    match update::perform_update(tag, LONG_VERSION, expected_version) {
        Ok(path) => {
            ui::info(&format!("✓ Updated successfully → {path}"));
            ExitCode::SUCCESS
        }
        Err(e) => {
            ui::error(&e.to_string());
            ExitCode::FAILURE
        }
    }
}

/// Install the cplt shell alias into the user's shell rc file.
///
/// Detects the current shell from $SHELL, picks the right rc file,
/// and appends an eval line. Idempotent — won't add duplicates.
fn shell_install() -> ExitCode {
    let shell = std::env::var("SHELL").unwrap_or_default();
    let home = if let Ok(h) = std::env::var("HOME") {
        PathBuf::from(h)
    } else {
        ui::error("$HOME not set");
        return ExitCode::FAILURE;
    };

    let (rc_file, setup_line) = if shell.ends_with("/fish") {
        (
            home.join(".config/fish/conf.d/cplt.fish"),
            "alias copilot cplt\n",
        )
    } else if shell.ends_with("/bash") {
        (home.join(".bashrc"), "eval \"$(cplt --shell-setup)\"\n")
    } else {
        // Default to zsh (macOS default)
        (home.join(".zshrc"), "eval \"$(cplt --shell-setup)\"\n")
    };

    // Check if already installed
    if rc_file.exists() {
        match std::fs::read_to_string(&rc_file) {
            Ok(contents) if contents.contains("cplt") => {
                ui::ok(&format!("Already installed in {}", rc_file.display()));
                return ExitCode::SUCCESS;
            }
            Ok(_) => {}
            Err(e) => {
                ui::error(&format!("Cannot read {}: {e}", rc_file.display()));
                return ExitCode::FAILURE;
            }
        }
    }

    // For fish, ensure the conf.d directory exists
    if shell.ends_with("/fish")
        && let Some(parent) = rc_file.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        ui::error(&format!("Cannot create {}: {e}", parent.display()));
        return ExitCode::FAILURE;
    }

    // Append the setup line
    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rc_file)
    {
        Ok(f) => f,
        Err(e) => {
            ui::error(&format!("Cannot open {}: {e}", rc_file.display()));
            return ExitCode::FAILURE;
        }
    };

    use std::io::Write;
    // Add a newline before our line if the file doesn't end with one
    let needs_newline = rc_file.exists()
        && std::fs::read_to_string(&rc_file).is_ok_and(|c| !c.is_empty() && !c.ends_with('\n'));

    let content = if needs_newline {
        format!("\n{setup_line}")
    } else {
        setup_line.to_string()
    };

    match file.write_all(content.as_bytes()) {
        Ok(()) => {
            ui::ok(&format!(
                "Installed 'copilot' alias in {}",
                rc_file.display()
            ));
            ui::info(&format!(
                "Restart your shell or run: source {}",
                rc_file.display()
            ));
            ExitCode::SUCCESS
        }
        Err(e) => {
            ui::error(&format!("Cannot write to {}: {e}", rc_file.display()));
            ExitCode::FAILURE
        }
    }
}

// ── Platform-specific helpers ─────────────────────────────────
//
// Named functions with cfg-gated bodies keep the run() function
// free of inline #[cfg] blocks.

/// Discover the VS Code Electron app bundle containing Copilot's shim (macOS only).
///
/// On Linux, Copilot doesn't use Electron app bundles, so this always returns `None`.
/// Skipped for non-Copilot agents.
fn discover_electron_app_dir(
    agent_bin_result: &Result<PathBuf, String>,
    agent: agent::Agent,
) -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        if agent != agent::Agent::Copilot {
            return None;
        }
        agent_bin_result
            .as_ref()
            .ok()
            .and_then(|p| discover::discover_electron_app(p))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (agent_bin_result, agent);
        None
    }
}

/// Print the preflight success message appropriate for this platform.
fn print_preflight_ok() {
    #[cfg(target_os = "macos")]
    ui::ok("Sandbox profile validated ✓");
    #[cfg(target_os = "linux")]
    ui::ok("Landlock sandbox ready ✓");
}

/// Start streaming sandbox denial logs (macOS only).
///
/// On macOS, spawns `log stream` filtering for Sandbox deny events.
/// On Linux, prints a hint about `strace` since Landlock has no audit logs.
fn start_denial_stream() -> Option<std::process::Child> {
    #[cfg(target_os = "macos")]
    {
        ui::info("Streaming sandbox denial logs (--show-denials)...");
        match std::process::Command::new("log")
            .args([
                "stream",
                "--predicate",
                "eventMessage CONTAINS \"Sandbox\" AND eventMessage CONTAINS \"deny\"",
                "--info",
                "--style",
                "compact",
            ])
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
        {
            Ok(child) => Some(child),
            Err(e) => {
                ui::warn(&format!("Could not start denial log stream: {e}"));
                None
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        ui::warn(
            "--show-denials is not available on Linux: Landlock does not produce kernel audit logs.",
        );
        ui::info("Use `strace -f -e trace=file,network` for filesystem/network debugging.");
        None
    }
}

/// Ensure Copilot's bundled package is extracted before entering the sandbox.
///
/// Copilot CLI (SEA binary) extracts its runtime into
/// `~/Library/Caches/copilot/pkg/<platform>/<version>/` on first launch after
/// an update. Writes to that directory are denied inside the sandbox to prevent
/// write-then-exec attacks, so the extraction must happen outside.
///
/// The fast-path cache key is the binary's identity (path + inode + size +
/// mtime). When that misses, we run `copilot --version` to trigger extraction
/// and detect the newly created directory by its `.extraction-complete` marker.
/// If no new directory appears, we accept a pre-existing extraction only when it
/// matches the version copilot reports (exact or `"{version}-"` prefix, since
/// pre-release builds may report `1.0.32` while extracting to `1.0.32-1-73748`).
/// A stale OLD-version directory is never accepted — otherwise the sandboxed
/// session would re-extract the current version and hit EPERM on the write-
/// denied cache.
///
/// Returns Ok(()) if extraction is confirmed or not needed, Err(message) if it
/// failed and entering the sandbox would cause EPERM on copilot/pkg writes.
#[cfg(target_os = "macos")]
fn ensure_copilot_extracted(
    copilot_bin: &Path,
    home: &Path,
    project_dir: &Path,
) -> Result<(), String> {
    // Security guard: this preflight executes `copilot --version` outside the
    // sandbox. If PATH resolves to a project-local wrapper script, that script
    // would run unsandboxed with full user privileges before trust lock applies.
    let bin = copilot_bin
        .canonicalize()
        .map_err(|e| format!("Failed to resolve copilot binary path: {e}"))?;
    let project = project_dir
        .canonicalize()
        .map_err(|e| format!("Failed to resolve project directory path: {e}"))?;
    if bin.starts_with(&project) {
        return Ok(());
    }

    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        _ => return Ok(()),
    };

    let pkg_base = home
        .join("Library/Caches/copilot/pkg")
        .join(format!("darwin-{arch}"));

    // Compute binary identity for the fast-path cache.
    // Works for any file type: Mach-O binary (Homebrew), node/shell wrapper (npm).
    // The identity is based on canonicalized path + inode + size + mtime — changes
    // whenever the copilot binary is updated/reinstalled.
    let binary_id = binary_identity(copilot_bin);

    // Fast path: check cplt-managed marker that records both the binary
    // identity and the actual extraction directory from the last successful run.
    let cache_dir = home.join("Library/Caches/cplt");
    let cache_file = cache_dir.join("copilot-extracted");
    if let Some(ref bid) = binary_id
        && let Ok(cached) = std::fs::read_to_string(&cache_file)
    {
        let mut lines = cached.lines();
        if let (Some(cached_id), Some(cached_dir)) = (lines.next(), lines.next())
            && cached_id == bid.as_str()
        {
            // Binary unchanged — verify the extracted dir still exists on disk
            let extracted_marker = pkg_base.join(cached_dir).join(".extraction-complete");
            if extracted_marker.exists() {
                return Ok(());
            }
        }
    }

    ui::info("Extracting Copilot runtime (first run after update)...");

    // Ensure pkg_base exists — Copilot needs it for extraction
    let _ = std::fs::create_dir_all(&pkg_base);

    // Clean up stale .extracting-* temp dirs from previous failed attempts.
    // These can confuse the SEA loader into thinking extraction is in progress.
    clean_stale_extracting_dirs(&pkg_base);

    // Snapshot existing extraction dirs so we can detect the new one.
    let dirs_before = extraction_dirs(&pkg_base);

    // Run copilot briefly to trigger SEA extraction. The extraction happens
    // during Node.js startup, before any CLI logic. We use `--version` which
    // triggers extraction then exits cleanly (more reliable than `-p ""`
    // which may hang waiting for input in newer versions).
    // stdout is piped (not null) so we can read the reported version string,
    // used below to verify the CURRENT version is extracted (not a stale one).
    let child = std::process::Command::new(copilot_bin)
        .args(["--no-auto-update", "--version"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return Err(format!(
                "Failed to spawn copilot for extraction: {e}\n  \
                 Try running 'copilot --version' manually to trigger extraction"
            ));
        }
    };
    let mut child_stdout = child.stdout.take();

    // Poll for extraction completion. We check for both:
    // 1. A new directory with `.extraction-complete` marker (normal success)
    // 2. An in-progress `.extracting-*` temp dir (extraction is happening)
    // Timeout: 60s (larger SEA payloads in newer versions need more time)
    let mut extracted_dir_name: Option<String> = None;
    let mut saw_extracting = false;
    let mut child_exit_ok = false;
    for i in 0..120 {
        if let Some(name) = find_new_extracted_dir(&pkg_base, &dirs_before) {
            extracted_dir_name = Some(name);
            break;
        }
        // Detect in-progress `.extracting-*` temp dirs — proves extraction started
        if !saw_extracting && has_extracting_dir(&pkg_base) {
            saw_extracting = true;
        }
        if let Ok(Some(status)) = child.try_wait() {
            child_exit_ok = status.success();
            // Process exited — check one more time
            extracted_dir_name = find_new_extracted_dir(&pkg_base, &dirs_before);
            if extracted_dir_name.is_some() {
                break;
            }
            // If extraction started (saw temp dir) but process exited without
            // completion, wait a bit more — rename may be in flight
            if saw_extracting && i < 119 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                extracted_dir_name = find_new_extracted_dir(&pkg_base, &dirs_before);
            }
            if extracted_dir_name.is_none() && !status.success() {
                // Process failed — try fallback with `-p exit`
                extracted_dir_name = try_extraction_fallback(copilot_bin, &pkg_base, &dirs_before);
            }
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // If extraction is still in flight when the poll loop ends, give it time to
    // finish instead of killing it. Interrupting a legitimate extraction leaves
    // a partial (marker-less) dir, which forces the sandboxed session to
    // re-extract — and that write is denied inside the sandbox (EPERM).
    if extracted_dir_name.is_none() && has_extracting_dir(&pkg_base) {
        for _ in 0..240 {
            if let Some(name) = find_new_extracted_dir(&pkg_base, &dirs_before) {
                extracted_dir_name = Some(name);
                break;
            }
            if !has_extracting_dir(&pkg_base) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    // Read the version copilot reported (printed during the same startup that
    // performs extraction). Used to verify the CURRENT version is extracted.
    let reported_version = child_stdout.take().and_then(|mut out| {
        use std::io::Read;
        let mut s = String::new();
        out.read_to_string(&mut s).ok()?;
        parse_copilot_version(&s)
    });

    // Final check after process exit
    if extracted_dir_name.is_none() {
        extracted_dir_name = find_new_extracted_dir(&pkg_base, &dirs_before);
    }

    // If --version didn't produce a new dir, check whether the CURRENT version
    // is already extracted on disk. This handles the migration case (first cplt
    // run on a system with a pre-existing extraction). When the version is
    // known we MUST match it — a stale old-version dir is not proof that the
    // current version is extracted (otherwise the sandboxed session re-extracts
    // and hits EPERM). Fall back to any-complete only when version is unknown.
    if extracted_dir_name.is_none() {
        extracted_dir_name = match reported_version {
            Some(ref v) => find_complete_dir_for_version(&pkg_base, v),
            None => find_any_complete_dir(&pkg_base),
        };
    }

    // If no extraction dir exists anywhere, this copilot doesn't use SEA
    // extraction (e.g., dev builds, non-SEA wrappers, test fakes).
    // Only skip if copilot exited cleanly — a crash isn't proof of "no SEA".
    if extracted_dir_name.is_none() && child_exit_ok && extraction_dirs(&pkg_base).is_empty() {
        return Ok(());
    }

    // Last resort: if no complete dir exists, try `-p exit` which forces full
    // startup (and thus extraction) in case --version uses a lazy code path.
    if extracted_dir_name.is_none() {
        extracted_dir_name = try_extraction_fallback(copilot_bin, &pkg_base, &dirs_before);
        // Check again for the current version's complete dir after fallback.
        if extracted_dir_name.is_none() {
            extracted_dir_name = match reported_version {
                Some(ref v) => find_complete_dir_for_version(&pkg_base, v),
                None => find_any_complete_dir(&pkg_base),
            };
        }
    }

    if let Some(ref dir_name) = extracted_dir_name {
        // Persist success: binary identity + extracted dir name.
        if let Some(ref bid) = binary_id {
            let _ = std::fs::create_dir_all(&cache_dir);
            let _ = std::fs::write(&cache_file, format!("{bid}\n{dir_name}"));
        }
        if !dirs_before.contains(dir_name) {
            ui::ok("Copilot runtime extracted");
        }
        Ok(())
    } else {
        Err(
            "Copilot runtime extraction failed. The sandbox blocks writes to copilot/pkg,\n  \
             so extraction must succeed before entering the sandbox.\n  \
             Fix: run 'copilot --version' manually, then retry cplt."
                .to_string(),
        )
    }
}

/// Ensure Copilot's SEA runtime is extracted on Linux before entering the sandbox.
///
/// Linux equivalent of `ensure_copilot_extracted`. The SEA binary at
/// ~/.local/bin/copilot extracts its Node.js runtime to
/// ~/.cache/copilot/pkg/linux-{arch}/<version>/ on first run. Inside the
/// sandbox, Landlock grants execute to this directory but the extraction
/// (write) must happen outside. If not already extracted, we run
/// `copilot --version` here to trigger it.
#[cfg(target_os = "linux")]
fn ensure_copilot_extracted_linux(
    copilot_bin: &Path,
    home: &Path,
    project_dir: &Path,
) -> Result<(), String> {
    // Security guard: don't run project-local scripts unsandboxed.
    let bin = copilot_bin
        .canonicalize()
        .map_err(|e| format!("Failed to resolve copilot binary path: {e}"))?;
    let project = project_dir
        .canonicalize()
        .map_err(|e| format!("Failed to resolve project directory path: {e}"))?;
    if bin.starts_with(&project) {
        return Ok(());
    }

    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        _ => return Ok(()),
    };

    let pkg_base = home
        .join(".cache/copilot/pkg")
        .join(format!("linux-{arch}"));

    // Compute binary identity for the fast-path cache.
    let binary_id = binary_identity(copilot_bin);

    // Fast path: check cplt-managed marker that records both the binary
    // identity and the actual extraction directory from the last successful run.
    let cache_dir = home.join(".cache/cplt");
    let cache_file = cache_dir.join("copilot-extracted");
    if let Some(ref bid) = binary_id
        && let Ok(cached) = std::fs::read_to_string(&cache_file)
    {
        let mut lines = cached.lines();
        if let (Some(cached_id), Some(cached_dir)) = (lines.next(), lines.next())
            && cached_id == bid.as_str()
        {
            let extracted_marker = pkg_base.join(cached_dir).join(".extraction-complete");
            if extracted_marker.exists() {
                return Ok(());
            }
        }
    }

    ui::info("Extracting Copilot runtime (first run after update)...");

    // Ensure pkg_base exists — Copilot needs it for extraction
    let _ = std::fs::create_dir_all(&pkg_base);

    // Clean up stale .extracting-* temp dirs from previous failed attempts.
    clean_stale_extracting_dirs(&pkg_base);

    // Snapshot existing extraction dirs so we can detect the new one.
    let dirs_before = extraction_dirs(&pkg_base);

    // Run copilot briefly to trigger SEA extraction. stdout is piped so we can
    // read the reported version and verify the CURRENT version is extracted.
    let child = std::process::Command::new(copilot_bin)
        .args(["--no-auto-update", "--version"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return Err(format!(
                "Failed to spawn copilot for extraction: {e}\n  \
                 Try running 'copilot --version' manually to trigger extraction"
            ));
        }
    };
    let mut child_stdout = child.stdout.take();

    // Poll for extraction completion.
    let mut extracted_dir_name: Option<String> = None;
    let mut saw_extracting = false;
    let mut child_exit_ok = false;
    for i in 0..120 {
        if let Some(name) = find_new_extracted_dir(&pkg_base, &dirs_before) {
            extracted_dir_name = Some(name);
            break;
        }
        if !saw_extracting && has_extracting_dir(&pkg_base) {
            saw_extracting = true;
        }
        if let Ok(Some(status)) = child.try_wait() {
            child_exit_ok = status.success();
            extracted_dir_name = find_new_extracted_dir(&pkg_base, &dirs_before);
            if extracted_dir_name.is_some() {
                break;
            }
            if saw_extracting && i < 119 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                extracted_dir_name = find_new_extracted_dir(&pkg_base, &dirs_before);
            }
            if extracted_dir_name.is_none() && !status.success() {
                extracted_dir_name = try_extraction_fallback(copilot_bin, &pkg_base, &dirs_before);
            }
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // If extraction is still in flight when the poll loop ends, give it time to
    // finish instead of killing it (interrupting forces an in-sandbox re-extract
    // that hits EPERM on the write-denied cache).
    if extracted_dir_name.is_none() && has_extracting_dir(&pkg_base) {
        for _ in 0..240 {
            if let Some(name) = find_new_extracted_dir(&pkg_base, &dirs_before) {
                extracted_dir_name = Some(name);
                break;
            }
            if !has_extracting_dir(&pkg_base) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    let reported_version = child_stdout.take().and_then(|mut out| {
        use std::io::Read;
        let mut s = String::new();
        out.read_to_string(&mut s).ok()?;
        parse_copilot_version(&s)
    });

    // Final check after process exit
    if extracted_dir_name.is_none() {
        extracted_dir_name = find_new_extracted_dir(&pkg_base, &dirs_before);
    }

    // Migration case: a pre-existing extraction. When the version is known we
    // MUST match it — a stale old-version dir is not proof the current version
    // is extracted (otherwise the sandboxed session re-extracts → EPERM).
    if extracted_dir_name.is_none() {
        extracted_dir_name = match reported_version {
            Some(ref v) => find_complete_dir_for_version(&pkg_base, v),
            None => find_any_complete_dir(&pkg_base),
        };
    }

    // If no extraction dir exists anywhere, this copilot doesn't use SEA.
    if extracted_dir_name.is_none() && child_exit_ok && extraction_dirs(&pkg_base).is_empty() {
        return Ok(());
    }

    // Last resort: try `-p exit` to force full startup.
    if extracted_dir_name.is_none() {
        extracted_dir_name = try_extraction_fallback(copilot_bin, &pkg_base, &dirs_before);
        if extracted_dir_name.is_none() {
            extracted_dir_name = match reported_version {
                Some(ref v) => find_complete_dir_for_version(&pkg_base, v),
                None => find_any_complete_dir(&pkg_base),
            };
        }
    }

    if let Some(ref dir_name) = extracted_dir_name {
        if let Some(ref bid) = binary_id {
            let _ = std::fs::create_dir_all(&cache_dir);
            let _ = std::fs::write(&cache_file, format!("{bid}\n{dir_name}"));
        }
        if !dirs_before.contains(dir_name) {
            ui::ok("Copilot runtime extracted");
        }
        Ok(())
    } else {
        Err(
            "Copilot runtime extraction failed. The sandbox blocks writes to copilot cache,\n  \
             so extraction must succeed before entering the sandbox.\n  \
             Fix: run 'copilot --version' manually, then retry cplt."
                .to_string(),
        )
    }
}

/// Try a fallback extraction method using `-p exit` (works on older Copilot versions).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn try_extraction_fallback(
    copilot_bin: &Path,
    pkg_base: &Path,
    dirs_before: &std::collections::HashSet<String>,
) -> Option<String> {
    let child = std::process::Command::new(copilot_bin)
        .args(["--no-auto-update", "-p", "exit"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    let Ok(mut child) = child else {
        return None;
    };

    for _ in 0..60 {
        if let Some(name) = find_new_extracted_dir(pkg_base, dirs_before) {
            let _ = child.kill();
            let _ = child.wait();
            return Some(name);
        }
        if let Ok(Some(_)) = child.try_wait() {
            return find_new_extracted_dir(pkg_base, dirs_before);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    let _ = child.kill();
    let _ = child.wait();
    find_new_extracted_dir(pkg_base, dirs_before)
}

/// Compute a stable identity for a binary based on filesystem metadata.
/// Uses canonicalized path + inode + size + full mtime (seconds + nanoseconds).
/// Works for any file type: Mach-O binaries, shell scripts, symlinks (resolved).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn binary_identity(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let canonical = path.canonicalize().ok()?;
    let meta = canonical.metadata().ok()?;
    Some(format!(
        "{}:{}:{}:{}.{}",
        canonical.display(),
        meta.ino(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
    ))
}

/// List non-hidden directory names under `pkg_base` (extraction version dirs).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn extraction_dirs(pkg_base: &Path) -> std::collections::HashSet<String> {
    std::fs::read_dir(pkg_base)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with('.') && e.file_type().ok()?.is_dir() {
                Some(name)
            } else {
                None
            }
        })
        .collect()
}

/// Check if there's an in-progress `.extracting-*` temp directory.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn has_extracting_dir(pkg_base: &Path) -> bool {
    std::fs::read_dir(pkg_base)
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with(".extracting-")
        })
}

/// Remove stale `.extracting-*` temp dirs left over from previous failed attempts.
/// These can prevent the SEA loader from starting a fresh extraction.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn clean_stale_extracting_dirs(pkg_base: &Path) {
    let Ok(entries) = std::fs::read_dir(pkg_base) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(".extracting-") {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Find a newly created extraction dir (not in `before`) that has `.extraction-complete`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn find_new_extracted_dir(
    pkg_base: &Path,
    before: &std::collections::HashSet<String>,
) -> Option<String> {
    let current = extraction_dirs(pkg_base);
    for name in current.difference(before) {
        if pkg_base.join(name).join(".extraction-complete").exists() {
            return Some(name.clone());
        }
    }
    None
}

/// Find any extraction dir that has `.extraction-complete` (most recent first).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn find_any_complete_dir(pkg_base: &Path) -> Option<String> {
    let mut dirs: Vec<_> = std::fs::read_dir(pkg_base)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                return None;
            }
            let marker = pkg_base.join(&name).join(".extraction-complete");
            if marker.exists() {
                let mtime = e.metadata().ok()?.modified().ok()?;
                Some((name, mtime))
            } else {
                None
            }
        })
        .collect();
    // Most recently modified first
    dirs.sort_by_key(|b| std::cmp::Reverse(b.1));
    dirs.into_iter().next().map(|(name, _)| name)
}

/// Parse the semantic version from `copilot --version` output.
///
/// e.g. `"GitHub Copilot CLI 1.0.63."` -> `Some("1.0.63")`. Accepts an optional
/// pre-release suffix (`1.0.63-2`). Returns `None` if no version token is found.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn parse_copilot_version(output: &str) -> Option<String> {
    output.split_whitespace().find_map(|tok| {
        let v = tok.trim_end_matches('.');
        let mut parts = v.splitn(3, '.');
        let major = parts.next()?;
        let minor = parts.next()?;
        let patch = parts.next()?;
        let numeric = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
        // major.minor must be fully numeric; patch must START numeric so that a
        // pre-release suffix like "63-2" is still accepted.
        if numeric(major)
            && numeric(minor)
            && patch.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            Some(v.to_string())
        } else {
            None
        }
    })
}

/// Find a *complete* extraction dir that matches `version`.
///
/// Matches the dir named exactly `version` or one prefixed `"{version}-"`
/// (pre-release builds may report a base version while extracting to a suffixed
/// directory, e.g. version `1.0.32` -> dir `1.0.32-1-73748`).
///
/// Security: this prevents a STALE old-version extraction (e.g. `1.0.62`) from
/// being accepted as proof that the CURRENT version is extracted. Accepting a
/// stale dir would let the preflight return success while the sandboxed session
/// re-extracts the current version and hits EPERM on the write-denied cache.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn find_complete_dir_for_version(pkg_base: &Path, version: &str) -> Option<String> {
    let prefix = format!("{version}-");
    std::fs::read_dir(pkg_base)
        .into_iter()
        .flatten()
        .flatten()
        .find_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || (name != version && !name.starts_with(&prefix)) {
                return None;
            }
            if pkg_base.join(&name).join(".extraction-complete").exists() {
                Some(name)
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("cplt").chain(args.iter().copied()))
    }

    #[test]
    fn observe_domains_flags_parse() {
        let cli = parse(&["--observe-domains", "--observe-domains-out", "/tmp/obs.txt"]);
        assert!(cli.observe_domains);
        assert_eq!(
            cli.observe_domains_out.as_deref(),
            Some(Path::new("/tmp/obs.txt"))
        );
    }

    #[test]
    fn emit_observed_domains_writes_sorted_unique_out_file() {
        use crate::proxy::{DomainVerdict, ObservedDomain};
        let dir = std::env::temp_dir().join(format!("cplt-observe-emit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("domains.txt");
        // The list is already sorted+unique (as ProxyHandle::observed_domains
        // guarantees). The out-file is a ready-to-use allowlist, so it must
        // contain ONLY the Allowed (permitted) hosts, bare, one per line — the
        // Blocked host must be excluded so it is never pasted into an allowlist.
        let observed = vec![
            ObservedDomain {
                host: "a.example".into(),
                verdict: DomainVerdict::Allowed,
                count: 2,
            },
            ObservedDomain {
                host: "b.example".into(),
                verdict: DomainVerdict::Blocked,
                count: 1,
            },
            ObservedDomain {
                host: "c.example".into(),
                verdict: DomainVerdict::Allowed,
                count: 1,
            },
        ];
        emit_observed_domains("Copilot", &observed, Some(&out));
        let body = std::fs::read_to_string(&out).unwrap();
        // Allowed hosts are present, in order; the Blocked host is absent.
        assert_eq!(body, "a.example\nc.example\n");
        assert!(
            !body.contains("b.example"),
            "Blocked host must not appear in the out-file allowlist"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No-leak invariant: the observe-mode allow-all override is flag-gated and
    /// cannot weaken a normal run's domain enforcement, while an observe run
    /// nulls the effective allowlist and forces the proxy on. Exercised at the
    /// allowlist-resolution seam (`resolve_domain_allowlist_decision`), the
    /// single source of truth `start_proxy_if_enabled` consumes.
    #[test]
    fn observe_domains_override_is_flag_gated_and_scoped_to_the_allowlist() {
        // Sample enforcement sources. A non-empty effective allowlist means
        // fail-closed enforcement is active; an empty one means allow-all.
        let configured = ["configured.example".to_string()];
        let agent_defaults = ["default.example"];
        let effective = |d: &DomainAllowlistDecision| -> Vec<String> {
            let mut v: Vec<String> = Vec::new();
            if d.use_default_allowlist {
                v.extend(agent_defaults.iter().map(|s| (*s).to_string()));
            }
            if d.use_allowed_file {
                v.extend(configured.iter().cloned());
            }
            v.sort_unstable();
            v.dedup();
            v
        };

        // WITHOUT --observe-domains, default allowlist on (≈ --preset strict):
        // enforcement preserved — effective allowlist NON-empty, proxy not forced
        // on by observe logic, both allowlist sources honored.
        let normal = resolve_domain_allowlist_decision(false, false, true);
        assert!(
            normal.use_allowed_file,
            "normal run must honor the configured allowlist"
        );
        assert!(
            normal.use_default_allowlist,
            "normal run must keep the default allowlist"
        );
        assert!(
            !normal.force_proxy_on,
            "observe must not force the proxy on a normal run"
        );
        assert!(
            !effective(&normal).is_empty(),
            "normal run must have a NON-empty effective allowlist (enforcement preserved)"
        );

        // WITHOUT --observe-domains, only a configured allowlist file (default
        // off): still enforced (non-empty).
        let normal_file_only = resolve_domain_allowlist_decision(false, false, false);
        assert!(normal_file_only.use_allowed_file);
        assert!(!normal_file_only.force_proxy_on);
        assert!(!effective(&normal_file_only).is_empty());

        // WITH --observe-domains: the domain allowlist is nulled (allow-all) AND
        // the proxy is forced on, regardless of a configured file or default
        // allowlist being present.
        let observe = resolve_domain_allowlist_decision(true, false, true);
        assert!(
            !observe.use_allowed_file,
            "observe must drop the configured allowlist file"
        );
        assert!(
            !observe.use_default_allowlist,
            "observe must drop the agent default allowlist"
        );
        assert!(observe.force_proxy_on, "observe must force the proxy on");
        assert!(
            effective(&observe).is_empty(),
            "observe must NULL the effective allowlist (allow-all)"
        );

        // The override is scoped to the domain allowlist by construction: the
        // decision exposes only allowlist fields, so it cannot touch port/SSRF
        // policy. And it is strictly flag-gated — the only difference between the
        // enforced `normal` case and the allow-all `observe` case above is the
        // observe flag; the allow_all_domains and default_allowlist inputs are
        // identical, proving observe alone flips enforcement.
    }

    #[test]
    fn copilot_auto_resume_when_no_args() {
        let cli = parse(&[]);
        let args = build_copilot_args(&cli, &agent::Agent::Copilot);
        assert_eq!(args, vec!["--no-auto-update", "--resume"]);
    }

    #[test]
    fn no_forwarded_flags() {
        let cli = parse(&["--", "-p", "fix tests"]);
        let args = build_copilot_args(&cli, &agent::Agent::Copilot);
        // --no-auto-update is injected as Copilot extra arg; no auto-resume (has args)
        assert_eq!(args, vec!["--no-auto-update", "-p", "fix tests"]);
    }

    #[test]
    fn resume_interactive() {
        let cli = parse(&["--resume"]);
        let args = build_copilot_args(&cli, &agent::Agent::Copilot);
        assert_eq!(args, vec!["--no-auto-update", "--resume"]);
    }

    #[test]
    fn resume_with_session_name() {
        let cli = parse(&["--resume=my-task"]);
        let args = build_copilot_args(&cli, &agent::Agent::Copilot);
        assert_eq!(args, vec!["--no-auto-update", "--resume=my-task"]);
    }

    #[test]
    fn continue_session() {
        let cli = parse(&["--continue"]);
        let args = build_copilot_args(&cli, &agent::Agent::Copilot);
        assert_eq!(args, vec!["--no-auto-update", "--continue"]);
    }

    #[test]
    fn remote_flag() {
        let cli = parse(&["--remote"]);
        let args = build_copilot_args(&cli, &agent::Agent::Copilot);
        // --remote with no explicit args: auto-resume is also injected
        assert_eq!(args, vec!["--no-auto-update", "--remote", "--resume"]);
    }

    #[test]
    fn name_session() {
        let cli = parse(&["--name", "my-refactor"]);
        let args = build_copilot_args(&cli, &agent::Agent::Copilot);
        assert_eq!(args, vec!["--no-auto-update", "--name", "my-refactor"]);
    }

    #[test]
    fn combined_forwarded_and_passthrough() {
        let cli = parse(&["--remote", "--name", "task", "--", "-p", "fix tests"]);
        let args = build_copilot_args(&cli, &agent::Agent::Copilot);
        assert_eq!(
            args,
            vec![
                "--no-auto-update",
                "--remote",
                "--name",
                "task",
                "-p",
                "fix tests"
            ]
        );
    }

    #[test]
    fn resume_and_continue_conflict() {
        let result = Cli::try_parse_from(["cplt", "--resume", "--continue"]);
        assert!(result.is_err());
    }

    #[test]
    fn forwarded_flags_prepended_before_passthrough() {
        let cli = parse(&["--resume=s1", "--remote", "--", "--other"]);
        let args = build_copilot_args(&cli, &agent::Agent::Copilot);
        assert_eq!(
            args,
            vec!["--no-auto-update", "--remote", "--resume=s1", "--other"]
        );
    }

    #[test]
    fn opencode_maps_session_flags() {
        // Bare --resume maps to opencode's --continue; --remote is dropped.
        let cli = parse(&["--resume", "--remote", "--", "-p", "fix"]);
        let args = build_copilot_args(&cli, &agent::Agent::OpenCode);
        assert_eq!(args, vec!["--continue", "-p", "fix"]);
    }

    #[test]
    fn opencode_continue_and_session() {
        let cli = parse(&["--continue"]);
        let args = build_copilot_args(&cli, &agent::Agent::OpenCode);
        assert_eq!(args, vec!["--continue"]);

        let cli = parse(&["--resume=sess-7"]);
        let args = build_copilot_args(&cli, &agent::Agent::OpenCode);
        assert_eq!(args, vec!["--session", "sess-7"]);
    }

    #[test]
    fn antigravity_maps_session_flags() {
        let cli = parse(&["--continue"]);
        let args = build_copilot_args(&cli, &agent::Agent::Antigravity);
        assert_eq!(args, vec!["--continue"]);

        let cli = parse(&["--resume=conv-9", "--", "-p", "fix"]);
        let args = build_copilot_args(&cli, &agent::Agent::Antigravity);
        assert_eq!(args, vec!["--conversation", "conv-9", "-p", "fix"]);
    }

    #[test]
    fn opencode_no_auto_resume() {
        // OpenCode is not in the auto-resume set: no args means no injected flags.
        let cli = parse(&[]);
        let args = build_copilot_args(&cli, &agent::Agent::OpenCode);
        assert!(args.is_empty());
    }

    #[test]
    fn opencode_passthrough_only() {
        let cli = parse(&["--", "run", "fix tests"]);
        let args = build_copilot_args(&cli, &agent::Agent::OpenCode);
        assert_eq!(args, vec!["run", "fix tests"]);
    }

    #[test]
    fn gemini_auto_resume_when_no_args() {
        let cli = parse(&[]);
        let args = build_copilot_args(&cli, &agent::Agent::Gemini);
        assert_eq!(args, vec!["--resume"]);
    }

    #[test]
    fn gemini_no_auto_resume_when_args_given() {
        let cli = parse(&["--", "-p", "fix tests"]);
        let args = build_copilot_args(&cli, &agent::Agent::Gemini);
        assert_eq!(args, vec!["-p", "fix tests"]);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn parse_copilot_version_extracts_from_banner() {
        assert_eq!(
            parse_copilot_version("GitHub Copilot CLI 1.0.63."),
            Some("1.0.63".to_string())
        );
        assert_eq!(
            parse_copilot_version("GitHub Copilot CLI 1.0.63.\nRun 'copilot update'"),
            Some("1.0.63".to_string())
        );
        // Pre-release suffix is preserved.
        assert_eq!(
            parse_copilot_version("Copilot 1.0.32-1"),
            Some("1.0.32-1".to_string())
        );
        assert_eq!(parse_copilot_version("no version here"), None);
        assert_eq!(parse_copilot_version(""), None);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn find_complete_dir_for_version_rejects_stale_old_version() {
        let tmp = std::env::temp_dir().join(format!("cplt-ver-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // Old version is fully extracted, current version is NOT.
        std::fs::create_dir_all(tmp.join("1.0.62")).unwrap();
        std::fs::write(tmp.join("1.0.62/.extraction-complete"), "").unwrap();
        std::fs::create_dir_all(tmp.join("1.0.63")).unwrap(); // present but incomplete

        // Must NOT accept the stale 1.0.62 dir when asking for 1.0.63.
        assert_eq!(find_complete_dir_for_version(&tmp, "1.0.63"), None);
        // The old version itself still resolves when explicitly requested.
        assert_eq!(
            find_complete_dir_for_version(&tmp, "1.0.62"),
            Some("1.0.62".to_string())
        );

        // Once the current version completes, it is accepted.
        std::fs::write(tmp.join("1.0.63/.extraction-complete"), "").unwrap();
        assert_eq!(
            find_complete_dir_for_version(&tmp, "1.0.63"),
            Some("1.0.63".to_string())
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn find_complete_dir_for_version_matches_prerelease_suffix() {
        let tmp = std::env::temp_dir().join(format!("cplt-ver-pre-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("1.0.32-1-73748")).unwrap();
        std::fs::write(tmp.join("1.0.32-1-73748/.extraction-complete"), "").unwrap();

        // Base version reported by --version matches the suffixed extraction dir.
        assert_eq!(
            find_complete_dir_for_version(&tmp, "1.0.32"),
            Some("1.0.32-1-73748".to_string())
        );
        // A shorter prefix must not spuriously match (1.0.3 != 1.0.32).
        assert_eq!(find_complete_dir_for_version(&tmp, "1.0.3"), None);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── `cplt check net` must MATCH the live proxy's verdict ──────────────

    #[test]
    fn check_net_non_canonical_allowlist_matches_live_blocked() {
        // FIX 1: with a non-canonical allowlist entry (`github.com:443`), the live
        // proxy stores it verbatim and returns BLOCKED-ALLOWLIST for `github.com`
        // (it does not verbatim-match). `build_net_policy` now parses the file with
        // the SAME `parse_lines_file` the live cache uses, so `check net github.com`
        // reports BLOCKED — matching live — instead of the old false ALLOWED that
        // `parse_domain_file`'s port-stripping produced.
        let policy = proxy::NetPolicy {
            allowed_ports: vec![443],
            allowed_domains: vec!["github.com:443".to_string()],
            ..Default::default()
        };
        let report = build_net_check(
            &policy,
            true,
            "github.com",
            true, // no_connect
            "copilot".to_string(),
            None,
        );
        let json = report.to_json();
        assert!(
            json.contains("BLOCKED-ALLOWLIST"),
            "check must match the live BLOCKED-ALLOWLIST verdict, not report ALLOWED:\n{json}"
        );
    }

    #[test]
    fn check_net_applies_post_dns_resolved_ip_guard() {
        // FIX 2: `cplt check net` must apply the live proxy's post-DNS
        // `resolved_ip_is_blocked` guard, not just the pre-DNS classify_connect
        // gates. A host that resolves to a private / link-local IP must be reported
        // BLOCKED-PRIVATE-RESOLVED (matching live enforcement) — never the false
        // ALLOWED + "reachable" the old check produced by probing from cplt (which
        // runs OUTSIDE the sandbox, where private IPs are reachable).
        let policy = proxy::NetPolicy::default();

        let item = resolved_ip_block_item(&policy, "10.0.0.1", 443)
            .expect("a private resolved IP must be reported BLOCKED");
        assert_eq!(item.decision, check::Decision::Blocked);
        assert_eq!(item.name, "BLOCKED-PRIVATE-RESOLVED");

        // Cloud metadata endpoint (link-local) is likewise blocked post-DNS.
        assert!(resolved_ip_block_item(&policy, "169.254.169.254", 443).is_some());

        // A public resolved IP passes the guard, so the pre-DNS ALLOWED verdict
        // stands and reachability may then be probed.
        assert!(resolved_ip_block_item(&policy, "1.1.1.1", 443).is_none());
    }

    #[test]
    fn check_net_resolved_ip_guard_matches_live_optin_semantics() {
        // Same waiver semantics as the live proxy: a host trusted via
        // allow_private_domains that resolves private is waived, and loopback is
        // waived ONLY when localhost access was opted into for this connection.
        let trusted = proxy::NetPolicy {
            private_domains: vec!["10.0.0.1".to_string()],
            ..Default::default()
        };
        assert!(
            resolved_ip_block_item(&trusted, "10.0.0.1", 443).is_none(),
            "allow_private_domains must waive the resolved-IP block, matching live"
        );

        // Loopback without opt-in → blocked (default no-localhost posture).
        let no_optin = proxy::NetPolicy::default();
        assert!(resolved_ip_block_item(&no_optin, "127.0.0.1", 443).is_some());

        // Loopback with opt-in → waived (matches resolved_ip_is_blocked semantics).
        let optin = proxy::NetPolicy {
            allow_localhost_any: true,
            ..Default::default()
        };
        assert!(resolved_ip_block_item(&optin, "127.0.0.1", 443).is_none());
    }
}
