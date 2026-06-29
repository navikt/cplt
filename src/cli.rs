//! CLI argument definitions and display helpers.
//!
//! This module contains all clap structs/enums for argument parsing,
//! plus small display-only helpers used at the CLI boundary.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use cplt::repo_config;

/// Build info: if CPLT_LONG_VERSION is set at compile time (via mise tasks),
/// use that; otherwise fall back to the Cargo package version.
pub const LONG_VERSION: &str = match option_env!("CPLT_LONG_VERSION") {
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
pub struct Cli {
    /// Which AI coding agent to sandbox.
    /// Resolved in order: this flag > sandbox.agent config > auto-detect from PATH.
    /// Supported: copilot, opencode, gemini, antigravity, pi, claude, shell
    #[arg(long, value_name = "AGENT")]
    pub agent: Option<String>,

    /// Which directory the agent can read and write to.
    /// Defaults to the current git repository root, or the working directory
    /// if you're not inside a git repo.
    #[arg(long, short = 'd', value_name = "DIR")]
    pub project_dir: Option<PathBuf>,

    /// Enable a local CONNECT proxy that logs and filters outbound connections.
    /// All agent traffic is routed through the proxy via
    /// HTTP_PROXY/HTTPS_PROXY env vars. Can block known-bad domains with
    /// --blocked-domains. The proxy enforces the same port restrictions as
    /// the sandbox (443 + --allow-port values).
    #[arg(long)]
    pub with_proxy: bool,

    /// Disable the proxy, even if enabled in config file.
    #[arg(long)]
    pub no_proxy: bool,

    /// Port for the local proxy to listen on [default: ephemeral port].
    /// Only relevant when --with-proxy is enabled.
    #[arg(long, value_name = "PORT")]
    pub proxy_port: Option<u16>,

    /// File with domains to block (one per line, e.g. pastebin.com).
    /// Only relevant when --with-proxy is enabled.
    /// The proxy will refuse CONNECT requests to these domains.
    /// The file is re-read on every request, so you can edit it live.
    #[arg(long, value_name = "FILE")]
    pub blocked_domains: Option<PathBuf>,

    /// File with domains to allow (one per line). When set, the proxy
    /// only permits connections to listed domains — everything else is
    /// blocked. Blocklist still applies on top. Parsed at startup.
    #[arg(long, value_name = "FILE")]
    pub allowed_domains: Option<PathBuf>,

    /// Write proxy connection log to a file (one line per CONNECT).
    /// Useful for post-session audit. File is created if it doesn't exist.
    #[arg(long, value_name = "FILE")]
    pub proxy_log: Option<PathBuf>,

    /// Proxy stderr verbosity: none (default), error, blocked, or all.
    /// Controls what the proxy prints to stderr. The audit log file
    /// (--proxy-log) always records everything regardless of this setting.
    #[arg(long, value_name = "LEVEL")]
    pub proxy_log_level: Option<String>,

    /// Timeout for proxy connections in seconds (default: 60).
    /// Prevents long-running requests (like generating large reports) from hanging.
    #[arg(long, value_name = "SECONDS")]
    pub proxy_timeout: Option<u64>,

    /// Allow connections to this domain even if it resolves to a private/internal IP.
    /// Use for corporate intranet services such as internal MCP servers.
    /// Suffix matching: "intern.nav.no" covers all its subdomains.
    /// Can be specified multiple times. Merged with proxy.allow_private_domains in config.
    #[arg(long = "allow-private-domain", value_name = "DOMAIN")]
    pub allow_private_domains: Vec<String>,

    /// Let the agent read files outside the project directory.
    /// Use when the agent needs to reference shared libraries,
    /// monorepo siblings, or documentation stored elsewhere.
    /// Can be specified multiple times.
    #[arg(long = "allow-read", value_name = "PATH")]
    pub allow_read: Vec<PathBuf>,

    /// Let the agent read AND write files outside the project directory.
    /// Use carefully — this gives the agent full access to modify these paths.
    /// Can be specified multiple times.
    #[arg(long = "allow-write", value_name = "PATH")]
    pub allow_write: Vec<PathBuf>,

    /// Block access to a specific path, even if it would normally be allowed.
    /// Deny rules always win over allow rules. Use this to protect sensitive
    /// files inside otherwise-allowed directories.
    /// Can be specified multiple times.
    #[arg(long = "deny-path", value_name = "PATH")]
    pub deny_paths: Vec<PathBuf>,

    /// Allow outbound TCP to an additional port beyond 443.
    /// Use for external services the agent needs to reach.
    /// Can be specified multiple times.
    #[arg(long = "allow-port", value_name = "PORT")]
    pub allow_ports: Vec<u16>,

    /// Allow outbound TCP to localhost on a specific port.
    /// Localhost is blocked by default to prevent SSRF. Use this for
    /// MCP servers, dev servers, or other local services the agent needs.
    /// Can be specified multiple times.
    #[arg(long = "allow-localhost", value_name = "PORT")]
    pub allow_localhost: Vec<u16>,

    /// Allow outbound TCP to localhost on ALL ports.
    /// Some build tools (Turbopack/Next.js, Vite, esbuild) spawn worker
    /// processes that communicate via TCP on random localhost ports.
    /// This flag allows all localhost traffic. Use --allow-localhost <PORT>
    /// instead if you only need specific ports.
    #[arg(long)]
    pub allow_localhost_any: bool,

    /// Allow the agent to read, write, and delete .env files, private keys
    /// (.pem, .key), and other sensitive files in the project directory.
    /// These are blocked by default because they often contain secrets that
    /// a rogue agent could exfiltrate or destroy.
    #[arg(long)]
    pub allow_env_files: bool,

    /// Pass an additional environment variable through to the sandbox.
    /// By default, only a safe allowlist of env vars is passed (PATH, HOME,
    /// TERM, Go/Java/Rust/Node paths, etc.). Cloud credentials (AWS_*,
    /// DATABASE_URL, NPM_TOKEN) are stripped. For OpenCode, use this to pass
    /// API keys: --pass-env ANTHROPIC_API_KEY
    /// Can be specified multiple times.
    #[arg(long = "pass-env", value_name = "VAR")]
    pub pass_env: Vec<String>,

    /// Pass ALL environment variables to the sandbox (DANGEROUS).
    /// Disables env sanitization. Cloud credentials, npm tokens, database URLs,
    /// and all other env vars will be visible to the sandboxed process.
    /// Only use when --pass-env is insufficient for debugging.
    #[arg(long)]
    pub inherit_env: bool,

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
    pub allow_lifecycle_scripts: bool,

    /// Allow GPG commit/tag signing inside the sandbox (DANGEROUS).
    /// Exposes the GPG agent socket — enables signing AND decryption requests.
    /// Private keys remain protected — only the public keyring and agent
    /// socket are accessible. A compromised process cannot extract the key,
    /// but CAN request arbitrary signatures and decryptions while active.
    #[arg(long)]
    pub allow_gpg_signing: bool,

    /// Deny the sandboxed agent access to the macOS clipboard (pasteboard)
    #[arg(long = "deny-clipboard")]
    pub deny_clipboard: bool,

    /// Allow JVM Attach API unix sockets in /tmp.
    /// Needed for JVM testing frameworks that use runtime self-attach:
    /// MockK inline mocking, Mockito inline agents, ByteBuddy, JMX tools.
    /// Only allows sockets matching /tmp/.java_pid<PID> — SSH agent and
    /// all other unix sockets remain blocked.
    #[arg(long)]
    pub allow_jvm_attach: bool,

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
    pub allow_docker: bool,

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
    pub allow_tmp_exec: bool,

    /// Allow process execution from a specific ~/Library/Caches subdirectory.
    /// By default, exec is blocked from ~/Library/Caches to prevent binary-drop
    /// staging attacks. Use this for tools that cache and run executables there,
    /// such as Playwright browsers (ms-playwright) or pnpm dlx packages.
    /// Example: --allow-cache-exec ms-playwright
    /// Can be specified multiple times.
    #[arg(long = "allow-cache-exec", value_name = "SUBDIR")]
    pub allow_cache_exec: Vec<String>,

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
    pub allow_cache_exec_any: bool,

    /// Allow the agent to open URLs in your default browser.
    /// Needed for OAuth code flows (MCP servers, Gemini CLI, gh auth login).
    /// Disabled by default because it lets the agent leverage your browser session.
    #[arg(long)]
    pub allow_browser: bool,

    /// Enable a per-session scratch directory for TMPDIR redirect (default).
    /// Creates ~/.cache/cplt/tmp/{session}/ with write+exec permissions
    /// and redirects TMPDIR/GOTMPDIR there. This allows tools like
    /// `go test`, `mise` inline tasks, and `node-gyp` to work.
    /// Cleaned up automatically on exit.
    #[arg(long)]
    pub scratch_dir: bool,

    /// Disable the per-session scratch directory. TMPDIR will not be
    /// redirected, so tools needing exec in temp may fail.
    #[arg(long)]
    pub no_scratch_dir: bool,

    /// Enable the gh CLI guard that blocks destructive GitHub operations.
    /// A wrapper script intercepts `gh` commands and blocks destructive writes
    /// (delete repo, merge PR, etc.) while allowing safe reads.
    #[arg(long)]
    pub gh_guard: bool,

    /// Disable the gh CLI guard (overrides config file setting).
    #[arg(long)]
    pub no_gh_guard: bool,

    /// Enable git push prevention. Blocks `git push`, `git request-pull`, and `git send-pack`
    /// while allowing all other git operations.
    #[arg(long)]
    pub git_guard: bool,

    /// Disable git push prevention (overrides config file setting).
    #[arg(long)]
    pub no_git_guard: bool,

    /// Skip the startup check that verifies the sandbox is working.
    /// The check runs a quick test command inside the sandbox to confirm
    /// that file and network restrictions are active.
    #[arg(long)]
    pub no_validate: bool,

    /// Print the generated sandbox profile (SBPL) and exit.
    /// Useful for debugging or auditing the sandbox rules.
    #[arg(long)]
    pub print_profile: bool,

    /// Show sandbox denial logs from macOS in real time.
    /// Starts `log stream` in the background to capture kernel-level
    /// sandbox violations. Helps diagnose why something isn't working.
    #[arg(long)]
    pub show_denials: bool,

    /// Create a starter config file at ~/.config/cplt/config.toml.
    /// The config lets you save your preferred defaults so you don't need
    /// to pass flags every time. Will not overwrite an existing file.
    #[arg(long)]
    pub init_config: bool,

    /// Print shell setup code for your shell rc file.
    /// Usage: eval "$(cplt --shell-setup)"
    /// Creates a 'copilot' alias that transparently runs cplt.
    #[arg(long)]
    pub shell_setup: bool,

    /// Install the shell alias permanently into your shell rc file.
    /// Detects your shell (zsh/bash/fish) and appends the setup line.
    /// Safe to run multiple times — won't add duplicates.
    #[arg(long)]
    pub shell_install: bool,

    /// [DEPRECATED: use `cplt doctor`] Run environment diagnostics and report
    /// what the sandbox will do. Checks auth mechanisms, Copilot CLI install,
    /// tool availability, and sandbox-critical paths. Exits 0 if all critical checks pass.
    #[arg(long, hide = true)]
    pub doctor: bool,

    /// Skip the interactive confirmation prompt and proceed immediately.
    /// The sandbox configuration summary is still printed for auditability.
    /// Required when stdin is not a TTY (CI, scripts, piped input).
    /// Can also be set in config: sandbox.yes = true
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Show the confirmation prompt even if sandbox.yes = true in the config file.
    /// Overrides the config setting for this run.
    #[arg(long)]
    pub no_yes: bool,

    /// Auto-approve all permissions from .cplt.toml for this run only.
    /// For CI/scripts where interactive approval isn't possible.
    /// Does not persist trust — approvals apply only to the current invocation.
    #[arg(long)]
    pub accept_repo_config: bool,

    /// Suppress the startup configuration summary and non-essential messages.
    /// Errors and warnings are always shown. Use when you've reviewed the
    /// sandbox settings and don't need to see them every time.
    /// Can also be set in config: sandbox.quiet = true
    #[arg(long, short = 'q')]
    pub quiet: bool,

    /// Show the startup configuration summary even if sandbox.quiet = true
    /// in the config file. Overrides the config setting for this run.
    #[arg(long)]
    pub no_quiet: bool,

    // --- Copilot pass-through flags ---
    // These are forwarded directly to the copilot process for convenience,
    // avoiding the need for -- when using common session-level flags.
    // Ignored when --agent is anything except Copilot.
    /// Resume a previous session. Use --resume to pick interactively,
    /// or --resume=NAME to resume a specific session by name or ID.
    /// Supported for Copilot (--resume), OpenCode (maps to --session),
    /// and Antigravity (maps to --conversation). Ignored for other agents.
    #[arg(long, value_name = "SESSION", num_args = 0..=1, require_equals = true, default_missing_value = "")]
    pub resume: Option<String>,

    /// Resume the most recent session in this directory.
    /// Supported for Copilot, OpenCode, and Antigravity (--continue).
    /// Ignored for other agents.
    #[arg(long = "continue", conflicts_with = "resume")]
    pub continue_session: bool,

    /// Enable remote control for the Copilot session.
    /// Allows monitoring and steering from GitHub.com or mobile.
    /// Copilot-only (ignored for other agents).
    #[arg(long)]
    pub remote: bool,

    /// Name the Copilot session for later resumption with --resume=NAME.
    /// Copilot-only (ignored for other agents).
    #[arg(long = "name", value_name = "SESSION")]
    pub session_name: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,

    /// Everything after -- is passed directly to the agent process.
    /// Example: cplt -- -p "fix the tests"
    #[arg(last = true, value_name = "AGENT_ARGS")]
    pub copilot_args: Vec<String>,
}

#[derive(Subcommand)]
pub enum Command {
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
pub enum ConfigAction {
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
pub enum TrustAction {
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
pub const SOURCE_GIT_HEAD: &str = "git HEAD (tamper-proof)";
pub const SOURCE_WORKING_TREE: &str = "working tree (⚠ not committed)";
pub const LABEL_DENY_APPLIED: &str = "(applied)";
pub const LABEL_ALLOW_APPROVED: &str = "(approved)";
pub const LABEL_ALLOW_PENDING: &str = "(pending approval)";
pub const STATUS_APPROVED: &str = "✓ approved";
pub const STATUS_PENDING: &str = "○ pending";

pub fn source_label(source: repo_config::RepoConfigSource) -> &'static str {
    match source {
        repo_config::RepoConfigSource::GitHead => SOURCE_GIT_HEAD,
        repo_config::RepoConfigSource::WorkingTree => SOURCE_WORKING_TREE,
        _ => "unknown",
    }
}
