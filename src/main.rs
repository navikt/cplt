use clap::{Parser, Subcommand};
use cplt::{config, discover, proxy, sandbox, scratch, update};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Build info: if CPLT_LONG_VERSION is set at compile time (via mise tasks),
/// use that; otherwise fall back to the Cargo package version.
const LONG_VERSION: &str = match option_env!("CPLT_LONG_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Run GitHub Copilot CLI inside a macOS sandbox.
///
/// Copilot can read and write your project files, but cannot access your
/// SSH keys, cloud credentials, or other secrets. The sandbox is enforced
/// by the macOS kernel — Copilot (and any process it spawns) cannot bypass it.
///
/// Network: Outbound TCP is allowed (Copilot needs to reach its API).
/// The filesystem isolation is the primary security control.
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

  cplt --with-proxy -- -p \"fix the tests\"
    Run with proxy for connection logging and domain blocking

  cplt --allow-read ~/shared-libs -- -p \"use shared-libs\"
    Let Copilot read files outside the project directory

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

  eval \"$(cplt --shell-setup)\"
    Add to your shell rc so 'copilot' runs the sandboxed version
"
)]
struct Cli {
    /// Which directory Copilot can read and write to.
    /// Defaults to the current git repository root, or the working directory
    /// if you're not inside a git repo.
    #[arg(long, short = 'd', value_name = "DIR")]
    project_dir: Option<PathBuf>,

    /// Enable a local CONNECT proxy that logs and filters outbound connections.
    /// All traffic (Copilot, gh, curl) is routed through the proxy via
    /// HTTP_PROXY/HTTPS_PROXY env vars. Can block known-bad domains with
    /// --blocked-domains. The proxy enforces the same port restrictions as
    /// the sandbox (443 + --allow-port values).
    #[arg(long)]
    with_proxy: bool,

    /// Disable the proxy, even if enabled in config file.
    #[arg(long)]
    no_proxy: bool,

    /// Port for the local proxy to listen on [default: 18080].
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

    /// Write proxy connection log to a file (one line per CONNECT).
    /// Useful for post-session audit. File is created if it doesn't exist.
    #[arg(long, value_name = "FILE")]
    proxy_log: Option<PathBuf>,

    /// Let Copilot read files outside the project directory.
    /// Use this when Copilot needs to reference shared libraries,
    /// monorepo siblings, or documentation stored elsewhere.
    /// Can be specified multiple times.
    #[arg(long = "allow-read", value_name = "PATH")]
    allow_read: Vec<PathBuf>,

    /// Let Copilot read AND write files outside the project directory.
    /// Use carefully — this gives Copilot full access to modify these paths.
    /// Can be specified multiple times.
    #[arg(long = "allow-write", value_name = "PATH")]
    allow_write: Vec<PathBuf>,

    /// Block access to a specific path, even if it would normally be allowed.
    /// Deny rules always win over allow rules. Use this to protect sensitive
    /// files inside otherwise-allowed directories.
    /// Can be specified multiple times.
    #[arg(long = "deny-path", value_name = "PATH")]
    deny_paths: Vec<PathBuf>,

    /// Allow outbound TCP to an additional port beyond 443.
    /// Use for external services that Copilot needs to reach.
    /// Can be specified multiple times.
    #[arg(long = "allow-port", value_name = "PORT")]
    allow_ports: Vec<u16>,

    /// Allow outbound TCP to localhost on a specific port.
    /// Localhost is blocked by default to prevent SSRF. Use this for
    /// MCP servers, dev servers, or other local services Copilot needs.
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

    /// Allow Copilot to read .env files, private keys (.pem, .key), and
    /// other sensitive files in the project directory. These are blocked
    /// by default because they often contain secrets that a rogue agent
    /// could exfiltrate via HTTPS.
    #[arg(long)]
    allow_env_files: bool,

    /// Pass an additional environment variable through to the sandbox.
    /// By default, only a safe allowlist of env vars is passed (PATH, HOME,
    /// TERM, Go/Java/Rust/Node paths, Copilot auth tokens, etc.).
    /// Cloud credentials (AWS_*, DATABASE_URL, NPM_TOKEN) are stripped.
    /// Use this to pass specific vars your tools need.
    /// Can be specified multiple times.
    #[arg(long = "pass-env", value_name = "VAR")]
    pass_env: Vec<String>,

    /// Pass ALL environment variables to the sandbox (DANGEROUS).
    /// Disables env sanitization. Cloud credentials, npm tokens, database URLs,
    /// and all other env vars will be visible to the sandboxed process.
    /// Only use when --pass-env is insufficient for debugging.
    #[arg(long)]
    inherit_env: bool,

    /// Allow npm/yarn/pnpm lifecycle scripts (postinstall hooks) to run.
    /// These are blocked by default to prevent supply chain attacks
    /// (e.g., malicious postinstall hooks that deploy RATs).
    /// Enable this if your project needs native module compilation.
    #[arg(long)]
    allow_lifecycle_scripts: bool,

    /// Allow GPG commit/tag signing inside the sandbox (DANGEROUS).
    /// Exposes the GPG agent socket — enables signing AND decryption requests.
    /// Private keys remain protected — only the public keyring and agent
    /// socket are accessible. A compromised process cannot extract the key,
    /// but CAN request arbitrary signatures and decryptions while active.
    #[arg(long)]
    allow_gpg_signing: bool,

    /// Allow process execution from system temp directories.
    /// DANGEROUS: re-enables exec from /private/tmp and /private/var/folders.
    /// Prefer --scratch-dir which creates a controlled executable temp dir.
    /// Only use this as a last resort when --scratch-dir is insufficient.
    #[arg(long)]
    allow_tmp_exec: bool,

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

    /// Run environment diagnostics and report what the sandbox will do.
    /// Checks auth mechanisms, Copilot CLI install, tool availability,
    /// and sandbox-critical paths. Exits 0 if all critical checks pass.
    #[arg(long)]
    doctor: bool,

    /// Skip the interactive confirmation prompt and proceed immediately.
    /// The sandbox configuration summary is still printed for auditability.
    /// Required when stdin is not a TTY (CI, scripts, piped input).
    #[arg(long, short = 'y')]
    yes: bool,

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

    #[command(subcommand)]
    command: Option<Command>,

    /// Everything after -- is passed directly to the copilot command.
    /// Example: cplt -- -p "fix the tests"
    #[arg(last = true)]
    copilot_args: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Manage cplt configuration.
    ///
    /// Validate, inspect, or initialize your config file.
    /// Config is stored at ~/.config/cplt/config.toml (override with CPLT_CONFIG).
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
    },

    /// Explain what config keys do.
    ///
    /// Without arguments, lists all keys with descriptions.
    /// With a key, shows detailed info for that key.
    /// Example: cplt config explain sandbox.quiet
    Explain {
        /// Config key to explain (omit to list all)
        key: Option<String>,
    },
}

const GREEN: &str = "\x1b[0;32m";
const YELLOW: &str = "\x1b[0;33m";
const RED: &str = "\x1b[0;31m";
const BLUE: &str = "\x1b[0;34m";
const NC: &str = "\x1b[0m";

fn info(msg: &str) {
    eprintln!("{BLUE}[cplt]{NC} {msg}");
}

fn ok(msg: &str) {
    eprintln!("{GREEN}[cplt]{NC} {msg}");
}

fn warn(msg: &str) {
    eprintln!("{YELLOW}[cplt]{NC} {msg}");
}

fn error(msg: &str) {
    eprintln!("{RED}[cplt]{NC} {msg}");
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

/// Prompt the user to confirm the sandbox configuration.
///
/// Returns Ok(()) if the user confirms, Err with message if they decline or
/// if no TTY is available without --yes.
fn prompt_confirm(auto_yes: bool, quiet: bool) -> Result<(), String> {
    if auto_yes {
        if !quiet {
            eprintln!("{BLUE}[cplt]{NC} Auto-confirmed (--yes)");
        }
        return Ok(());
    }

    // Try to open /dev/tty for the controlling terminal.
    // This works even if stdin is piped.
    let tty = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        Ok(f) => f,
        Err(_) => {
            return Err(
                "No TTY available for confirmation. Use --yes for non-interactive runs."
                    .to_string(),
            );
        }
    };

    if quiet {
        eprint!(
            "{BLUE}[cplt]{NC} Proceed with sandboxed Copilot? (run without --quiet to review config) [y/N] "
        );
    } else {
        eprint!("{BLUE}[cplt]{NC} Proceed? [y/N] ");
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

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Handle --init-config
    if cli.init_config {
        return init_config();
    }

    // Handle --shell-setup: print alias definition and exit
    if cli.shell_setup {
        println!("alias copilot=cplt");
        return ExitCode::SUCCESS;
    }

    // Handle --shell-install: append setup line to shell rc file
    if cli.shell_install {
        return shell_install();
    }

    // Handle subcommands (these don't need macOS or sandbox)
    if let Some(command) = cli.command {
        return match command {
            Command::Config { action } => run_config_command(action),
            Command::Update { check, force } => run_update(check, force),
        };
    }

    // Platform check: cplt currently supports macOS (Seatbelt) and Linux (planned: Landlock).
    // Other platforms (Windows, FreeBSD, etc.) are not supported.
    if cfg!(not(any(target_os = "macos", target_os = "linux"))) {
        error("cplt requires macOS or Linux");
        return ExitCode::FAILURE;
    }

    // Handle --doctor: run diagnostics and exit (works on all platforms)
    if cli.doctor {
        return run_doctor();
    }

    // Linux sandbox is not yet implemented — gate at runtime until Landlock backend lands.
    #[cfg(target_os = "linux")]
    {
        error("Linux sandbox support is not yet implemented (see issue #16)");
        return ExitCode::FAILURE;
    }

    // Load config file and merge with CLI flags
    // Canonicalize CLI paths for consistency with config path handling
    let cli_allow_read: Vec<PathBuf> = cli
        .allow_read
        .iter()
        .filter_map(|p| match std::fs::canonicalize(p) {
            Ok(c) => Some(c),
            Err(e) => {
                warn(&format!("--allow-read path {:?}: {e}", p));
                None
            }
        })
        .collect();
    let cli_allow_write: Vec<PathBuf> = cli
        .allow_write
        .iter()
        .filter_map(|p| match std::fs::canonicalize(p) {
            Ok(c) => Some(c),
            Err(e) => {
                warn(&format!("--allow-write path {:?}: {e}", p));
                None
            }
        })
        .collect();
    let cli_deny_paths: Vec<PathBuf> = cli
        .deny_paths
        .iter()
        .map(|p| {
            std::fs::canonicalize(p).map_err(|e| {
                format!(
                    "--deny-path {:?} cannot be resolved: {e}\n\
                     Silently dropping deny rules is a security risk.",
                    p
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| {
            error(&e);
            std::process::exit(1);
        });

    let (cfg, config_path) = match config::Config::load_file() {
        Ok(Some(loaded)) => (loaded.config, Some(loaded.path)),
        Ok(None) => (config::Config::default(), None),
        Err(e) => {
            error(&e);
            return ExitCode::FAILURE;
        }
    };
    let resolved = match cfg.merge(config::CliFlags {
        with_proxy: cli.with_proxy,
        no_proxy: cli.no_proxy,
        proxy_port: cli.proxy_port,
        blocked_domains: cli.blocked_domains.clone(),
        allowed_domains: cli.allowed_domains.clone(),
        proxy_log_file: cli.proxy_log.clone(),
        allow_read: cli_allow_read,
        allow_write: cli_allow_write,
        deny_paths: cli_deny_paths,
        allow_ports: cli.allow_ports.clone(),
        allow_localhost: cli.allow_localhost.clone(),
        allow_localhost_any: cli.allow_localhost_any,
        allow_env_files: cli.allow_env_files,
        no_validate: cli.no_validate,
        pass_env: cli.pass_env.clone(),
        inherit_env: cli.inherit_env,
        allow_lifecycle_scripts: cli.allow_lifecycle_scripts,
        allow_gpg_signing: cli.allow_gpg_signing,
        allow_tmp_exec: cli.allow_tmp_exec,
        scratch_dir: cli.scratch_dir,
        no_scratch_dir: cli.no_scratch_dir,
        quiet: cli.quiet,
        no_quiet: cli.no_quiet,
    }) {
        Ok(r) => r,
        Err(e) => {
            error(&e);
            return ExitCode::FAILURE;
        }
    };

    // Resolve home directory
    let home_dir = match std::env::var("HOME") {
        Ok(h) => match std::fs::canonicalize(&h) {
            Ok(p) => p,
            Err(e) => {
                error(&format!("Cannot resolve $HOME ({h}): {e}"));
                return ExitCode::FAILURE;
            }
        },
        Err(_) => {
            error("$HOME not set");
            return ExitCode::FAILURE;
        }
    };

    // Resolve project directory
    let project_dir = match &cli.project_dir {
        Some(p) => match std::fs::canonicalize(p) {
            Ok(p) => p,
            Err(e) => {
                error(&format!("Cannot resolve project dir: {e}"));
                return ExitCode::FAILURE;
            }
        },
        None => {
            if let Some(root) = detect_project_root() {
                match std::fs::canonicalize(&root) {
                    Ok(p) => p,
                    Err(_) => root,
                }
            } else {
                warn("No git repo detected, using cwd");
                match std::env::current_dir().and_then(std::fs::canonicalize) {
                    Ok(p) => p,
                    Err(e) => {
                        error(&format!("Cannot resolve cwd: {e}"));
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
    };

    // Safety check: reject overly broad project roots
    if is_unsafe_root(&project_dir, &home_dir) {
        error(&format!(
            "Refusing to sandbox '{}' — too broad. Use a specific project directory.",
            project_dir.display()
        ));
        return ExitCode::FAILURE;
    }

    if !resolved.quiet {
        info(&format!("Project:  {}", project_dir.display()));
        info(&format!("Home:     {}", home_dir.display()));
        if let Some(ref cp) = config_path {
            info(&format!("Config:   {}", cp.display()));
        }
    }

    // Run auto-discovery to tighten the sandbox profile
    let tool_discovery = discover::discover_tools(&home_dir);
    let existing_dirs = tool_discovery.existing_home_tool_dirs;

    // Create per-session scratch directory if enabled
    let scratch_guard = if resolved.scratch_dir {
        // GC stale scratch dirs from previous sessions (best-effort)
        scratch::ScratchDir::gc_stale(&home_dir);

        match scratch::ScratchDir::create(&home_dir) {
            Ok(s) => {
                if !resolved.quiet {
                    ok(&format!("Scratch dir: {}", s.path().display()));
                }
                Some(s)
            }
            Err(e) => {
                error(&format!("Cannot create scratch dir: {e}"));
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };
    let scratch_path = scratch_guard.as_ref().map(|s| s.path());

    // Resolve the Copilot CLI binary early so its installation directory
    // can be included in the sandbox profile. Failure is deferred —
    // --print-profile doesn't need the binary.
    let copilot_bin_result = resolve_copilot_binary();
    let copilot_install_dir = copilot_bin_result
        .as_ref()
        .ok()
        .and_then(|p| {
            // Try package.json discovery first (npm/Homebrew installs)
            discover::copilot_pkg_dir(p, &home_dir).or_else(|| {
                // Fallback: use the binary's parent directory (VS Code extension installs
                // at ~/Library/Application Support/Code/.../copilotCli/copilot)
                p.parent().map(|d| d.to_path_buf())
            })
        })
        .filter(|d| !crate::is_unsafe_root(d, &home_dir));

    // Discover global git hooks path from core.hooksPath
    let git_hooks_path = discover::git_hooks_path(&home_dir);

    // Discover Electron app bundle when Copilot CLI is installed via VS Code.
    // The shim invokes VS Code's Electron runtime, which needs dyld access to
    // load Electron Framework from within the .app bundle.
    let electron_app_dir = copilot_bin_result
        .as_ref()
        .ok()
        .and_then(|p| discover::discover_electron_app(p));

    // Prepare the sandbox — validates paths, generates platform-specific profile.
    // Path validation (SBPL injection checks on macOS) is handled internally
    // by prepare(), so callers don't need to know about backend-specific risks.
    let proxy_port_for_profile = if resolved.with_proxy {
        Some(resolved.proxy_port)
    } else {
        None
    };
    let prepared = match sandbox::prepare(&sandbox::SandboxConfig {
        project_dir: &project_dir,
        home_dir: &home_dir,
        extra_read: &resolved.allow_read,
        extra_write: &resolved.allow_write,
        extra_deny: &resolved.deny_paths,
        existing_home_tool_dirs: Some(&existing_dirs),
        extra_ports: &resolved.allow_ports,
        localhost_ports: &resolved.allow_localhost,
        proxy_port: proxy_port_for_profile,
        allow_env_files: resolved.allow_env_files,
        allow_localhost_any: resolved.allow_localhost_any,
        scratch_dir: scratch_path,
        allow_tmp_exec: resolved.allow_tmp_exec,
        copilot_install_dir: copilot_install_dir.as_deref(),
        git_hooks_path: git_hooks_path.as_deref(),
        allow_gpg_signing: resolved.allow_gpg_signing,
        electron_app_dir: electron_app_dir.as_deref(),
    }) {
        Ok(s) => s,
        Err(e) => {
            error(&e);
            return ExitCode::FAILURE;
        }
    };

    // --print-profile: dump the sandbox policy and exit (no copilot binary needed)
    if cli.print_profile {
        println!("{}", sandbox::describe(&prepared));
        return ExitCode::SUCCESS;
    }

    // Recursion guard: detect if we're already inside a cplt sandbox.
    // Placed after --print-profile/--doctor/--init-config so those subcommands
    // still work inside the sandbox. Only the actual sandbox launch is blocked.
    if std::env::var("__CPLT_WRAPPED").is_ok() {
        error(
            "cplt is already running (recursion detected). \
             If 'copilot' is aliased to cplt, ensure the real Copilot CLI \
             is also in PATH.",
        );
        return ExitCode::FAILURE;
    }

    // Unwrap the copilot binary resolution (deferred from above).
    let copilot_bin = match copilot_bin_result {
        Ok(path) => path,
        Err(msg) => {
            error(&msg);
            return ExitCode::FAILURE;
        }
    };

    // Ensure Copilot's bundled runtime is extracted before entering the sandbox.
    // Writes to copilot/pkg are denied inside the sandbox (write-then-exec defense),
    // so extraction must happen here, outside. macOS-only: SEA extraction is an
    // macOS Copilot packaging detail.
    #[cfg(target_os = "macos")]
    ensure_copilot_extracted(&copilot_bin, &home_dir);

    // Preflight: verify the sandbox mechanism works on this system
    if !resolved.no_validate {
        match sandbox::preflight(&prepared) {
            Ok(()) => {
                if !resolved.quiet {
                    ok("Sandbox profile validated ✓");
                }
            }
            Err(e) => {
                error(&format!("Sandbox validation failed: {e}"));
                return ExitCode::FAILURE;
            }
        }
    }

    // Print comprehensive summary and confirm before launching Copilot
    if !resolved.quiet {
        resolved.print_summary(&project_dir, &home_dir);
    }
    if let Err(e) = prompt_confirm(cli.yes, resolved.quiet) {
        error(&e);
        return ExitCode::FAILURE;
    }

    // Compute hardening categories before proxy setup (which partially moves `resolved`)
    let disabled_categories = resolved.disabled_hardening_categories();

    // Start proxy if requested
    let mut proxy_handle = None;

    if resolved.with_proxy {
        let blocked_file = resolved.blocked_domains.unwrap_or_else(|| {
            // Look for blocked-domains.txt next to the binary, then blocked.txt
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()));
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

        // Parse domain allowlist at startup (fail-closed: startup error if unreadable)
        let allowed_domains = match &resolved.allowed_domains {
            Some(path) => match proxy::parse_domain_file(path) {
                Ok(domains) => {
                    if !resolved.quiet {
                        info(&format!(
                            "Domain allowlist: {} domains from {}",
                            domains.len(),
                            path.display()
                        ));
                    }
                    domains
                }
                Err(e) => {
                    error(&format!("Failed to load allowed domains: {e}"));
                    return ExitCode::FAILURE;
                }
            },
            None => Vec::new(),
        };

        if !resolved.quiet {
            info(&format!(
                "Starting proxy on localhost:{} ...",
                resolved.proxy_port
            ));
        }

        match proxy::start(proxy::ProxyOptions {
            port: resolved.proxy_port,
            blocked_file,
            allowed_ports: resolved.allow_ports.clone(),
            allowed_domains,
            log_file: resolved.proxy_log_file.clone(),
        }) {
            Ok(handle) => {
                if !resolved.quiet {
                    ok(&format!(
                        "Proxy running on localhost:{} (thread)",
                        resolved.proxy_port
                    ));
                }
                proxy_handle = Some(handle);
                // Proxy env vars (NODE_USE_ENV_PROXY, HTTP_PROXY, HTTPS_PROXY) are
                // injected by sandbox_exec::exec() when proxy_port is Some.
            }
            Err(e) => {
                error(&format!("Failed to start proxy: {e}"));
                return ExitCode::FAILURE;
            }
        }
    }

    ok("Starting Copilot in sandbox...");

    // --show-denials: stream macOS sandbox denial logs in the background
    let mut denial_proc = None;
    if cli.show_denials {
        info("Streaming sandbox denial logs (--show-denials)...");
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
            Ok(child) => denial_proc = Some(child),
            Err(e) => warn(&format!("Could not start denial log stream: {e}")),
        }
    }

    eprintln!("{YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}");
    eprintln!();

    // Run copilot inside sandbox
    let exit_code = sandbox::exec_sandboxed(
        &prepared,
        &copilot_bin,
        &cli.copilot_args,
        &resolved.pass_env,
        resolved.inherit_env,
        &disabled_categories,
    );

    // Cleanup
    if let Some(handle) = proxy_handle {
        handle.shutdown();
    }
    if let Some(mut child) = denial_proc {
        let _ = child.kill();
        let _ = child.wait();
    }

    ExitCode::from(exit_code)
}

fn run_doctor() -> ExitCode {
    let home_dir = match std::env::var("HOME") {
        Ok(h) => match std::fs::canonicalize(&h) {
            Ok(p) => p,
            Err(e) => {
                error(&format!("Cannot resolve $HOME ({h}): {e}"));
                return ExitCode::FAILURE;
            }
        },
        Err(_) => {
            error("$HOME not set");
            return ExitCode::FAILURE;
        }
    };

    let project_dir = if let Some(root) = detect_project_root() {
        std::fs::canonicalize(&root).unwrap_or(root)
    } else {
        std::env::current_dir()
            .and_then(std::fs::canonicalize)
            .unwrap_or_else(|_| PathBuf::from("."))
    };

    info(&format!("Project:  {}", project_dir.display()));
    info(&format!("Home:     {}", home_dir.display()));
    eprintln!();

    let discovery = discover::discover_all(&home_dir, &project_dir);
    let ok = discovery.print_report();

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn init_config() -> ExitCode {
    let Some(path) = config::config_path() else {
        error("Cannot determine config path ($HOME not set)");
        return ExitCode::FAILURE;
    };

    if path.exists() {
        error(&format!(
            "Config file already exists: {}\nEdit it directly, or remove it first to regenerate.",
            path.display()
        ));
        return ExitCode::FAILURE;
    }

    // Create parent directory
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        error(&format!("Cannot create config directory: {e}"));
        return ExitCode::FAILURE;
    }

    match std::fs::write(&path, config::default_config_contents()) {
        Ok(()) => {
            ok(&format!("Config file created: {}", path.display()));
            info("Edit it to customize sandbox defaults.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error(&format!("Cannot write config file: {e}"));
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
        } => run_config_set(&key, value.as_deref(), append, unset, force),
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
            info(&format!("No config file found{path_hint}"));
            info("Run `cplt config init` to create one.");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            error(&e);
            return ExitCode::FAILURE;
        }
    };

    info(&format!("Validating {}", loaded.path.display()));

    let diagnostics = config::validate_config(&loaded.raw);

    if diagnostics.is_empty() {
        ok("Config OK ✓");
        return ExitCode::SUCCESS;
    }

    let mut has_errors = false;
    for d in &diagnostics {
        match d.level {
            config::DiagnosticLevel::Error => {
                has_errors = true;
                error(&d.message);
            }
            config::DiagnosticLevel::Warning => {
                warn(&d.message);
            }
        }
    }

    if has_errors {
        ExitCode::FAILURE
    } else {
        ok("Config OK ✓ (with warnings)");
        ExitCode::SUCCESS
    }
}

fn run_config_show() -> ExitCode {
    let loaded = match config::Config::load_file() {
        Ok(l) => l,
        Err(e) => {
            error(&e);
            return ExitCode::FAILURE;
        }
    };

    config::display_config(loaded.as_ref());
    ExitCode::SUCCESS
}

fn run_config_path() -> ExitCode {
    match config::config_path() {
        Some(p) => {
            println!("{}", p.display());
            ExitCode::SUCCESS
        }
        None => {
            error("Cannot determine config path ($HOME not set)");
            ExitCode::FAILURE
        }
    }
}

fn run_config_get(key: &str) -> ExitCode {
    let key_info = match config::lookup_key(key) {
        Ok(k) => k,
        Err(e) => {
            error(&e);
            return ExitCode::FAILURE;
        }
    };

    let loaded = match config::Config::load_file() {
        Ok(l) => l,
        Err(e) => {
            error(&e);
            return ExitCode::FAILURE;
        }
    };

    let (value, from_file) = config::get_config_value(key_info, loaded.as_ref());
    println!("{value}");
    if !from_file {
        eprintln!("{BLUE}[cplt]{NC} (default — not set in config file)");
    }
    ExitCode::SUCCESS
}

fn run_config_set(
    key: &str,
    value: Option<&str>,
    append: bool,
    unset: bool,
    force: bool,
) -> ExitCode {
    let op = match config::ConfigSetOp::new(key) {
        Ok(op) => op,
        Err(e) => {
            error(&e);
            return ExitCode::FAILURE;
        }
    };

    // Validate flag combinations
    if unset && value.is_some() && !op.key_info.value_type.is_array() {
        error("--unset does not take a value (except for array keys)");
        return ExitCode::FAILURE;
    }
    if unset && append {
        error("--unset and --append are mutually exclusive");
        return ExitCode::FAILURE;
    }
    if !unset && value.is_none() {
        error(&format!(
            "missing value for {key}\n  Usage: cplt config set {key} <VALUE>"
        ));
        return ExitCode::FAILURE;
    }

    // Dangerous key safeguard
    if op.key_info.dangerous
        && !unset
        && let Some(val) = value
        && val == "true"
        && !force
    {
        error(&format!(
            "{key} is a dangerous setting — it weakens sandbox security.\n  \
             Add --force to confirm: cplt config set {key} true --force"
        ));
        return ExitCode::FAILURE;
    }

    // Load or create document
    let mut doc = match op.load_document() {
        Ok(d) => d,
        Err(e) => {
            error(&e);
            return ExitCode::FAILURE;
        }
    };

    // Apply modification
    let mut element_removed = false;
    let result = if unset {
        if let Some(val) = value
            && op.key_info.value_type.is_array()
        {
            // Array key + value: remove just that element
            config::remove_array_element_in_doc(&mut doc, op.key_info, val)
                .map(|removed| element_removed = removed)
        } else {
            // Scalar key, or array key without value: remove entire key
            config::unset_value_in_doc(&mut doc, op.key_info);
            Ok(())
        }
    } else if append || op.key_info.value_type.is_array() {
        // Array keys always append — `set` adds to the array, not replaces it.
        // Use `--unset` first to clear, then `set` to start fresh.
        config::append_value_in_doc(&mut doc, op.key_info, value.unwrap())
    } else {
        config::set_value_in_doc(&mut doc, op.key_info, value.unwrap())
    };

    if let Err(e) = result {
        error(&e);
        return ExitCode::FAILURE;
    }

    // Skip writing when nothing changed (unset element that wasn't present)
    if let Some(val) = value
        && !element_removed
        && unset
        && op.key_info.value_type.is_array()
    {
        warn(&format!("{key}: {val} is not set"));
        return ExitCode::SUCCESS;
    }

    // Write back
    if let Err(e) = op.write_document(&doc) {
        error(&e);
        return ExitCode::FAILURE;
    }

    if unset {
        if let Some(val) = value
            && op.key_info.value_type.is_array()
        {
            if let Some(remaining) = config::get_value_from_doc(&doc, op.key_info) {
                ok(&format!("{key}: removed {val} → {remaining}"));
            } else {
                ok(&format!("{key}: removed {val} (now empty)"));
            }
        } else {
            ok(&format!("{key} removed (will use default)"));
        }
    } else if append || op.key_info.value_type.is_array() {
        let current = config::get_value_from_doc(&doc, op.key_info)
            .unwrap_or_else(|| value.unwrap().to_string());
        ok(&format!("{key} = {current}"));
    } else {
        ok(&format!("{key} = {}", value.unwrap()));
    }

    ExitCode::SUCCESS
}

fn run_config_explain(key: Option<&str>) -> ExitCode {
    match key {
        Some(k) => match config::lookup_key(k) {
            Ok(info) => {
                config::explain_key(info);
                ExitCode::SUCCESS
            }
            Err(e) => {
                error(&e);
                ExitCode::FAILURE
            }
        },
        None => {
            config::explain_all();
            ExitCode::SUCCESS
        }
    }
}

fn run_update(check_only: bool, force: bool) -> ExitCode {
    // Check for Homebrew-managed install
    if update::is_homebrew_managed() {
        info("cplt is managed by Homebrew.");
        eprintln!("  Run: {GREEN}brew upgrade navikt/tap/cplt{NC}");
        return ExitCode::SUCCESS;
    }

    // Fetch latest release
    info("Checking for updates...");
    let latest = match update::fetch_latest_release(LONG_VERSION) {
        Ok(r) => r,
        Err(e) => {
            error(&e);
            return ExitCode::FAILURE;
        }
    };

    let status = update::check_version(LONG_VERSION, &latest);

    match status {
        update::VersionStatus::UpToDate => {
            info(&format!("✓ cplt is up to date ({LONG_VERSION})"));
            ExitCode::SUCCESS
        }
        update::VersionStatus::UpdateAvailable {
            current,
            latest: latest_ver,
            tag,
        } => {
            info(&format!(
                "Update available: {current} → {GREEN}{latest_ver}{NC}"
            ));
            if check_only {
                return ExitCode::SUCCESS;
            }
            do_update(&tag)
        }
        update::VersionStatus::SameDateDifferentBuild {
            current,
            latest: latest_ver,
            tag,
        } => {
            info(&format!(
                "Same date, different build: {current} vs {latest_ver}"
            ));
            if check_only {
                return ExitCode::SUCCESS;
            }
            if !force {
                warn("Same-date build. Use --force to reinstall.");
                return ExitCode::SUCCESS;
            }
            do_update(&tag)
        }
        update::VersionStatus::DevBuild {
            latest: latest_ver,
            tag,
        } => {
            warn(&format!(
                "Running dev build (0.0.0). Latest release: {latest_ver}"
            ));
            if check_only {
                return ExitCode::SUCCESS;
            }
            if !force {
                warn("Use --force to replace dev build with release.");
                return ExitCode::SUCCESS;
            }
            do_update(&tag)
        }
    }
}

fn do_update(tag: &str) -> ExitCode {
    match update::perform_update(tag, LONG_VERSION) {
        Ok(path) => {
            info(&format!("✓ Updated successfully → {path}"));
            ExitCode::SUCCESS
        }
        Err(e) => {
            error(&e);
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
    let home = match std::env::var("HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => {
            error("$HOME not set");
            return ExitCode::FAILURE;
        }
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
                ok(&format!("Already installed in {}", rc_file.display()));
                return ExitCode::SUCCESS;
            }
            Ok(_) => {}
            Err(e) => {
                error(&format!("Cannot read {}: {e}", rc_file.display()));
                return ExitCode::FAILURE;
            }
        }
    }

    // For fish, ensure the conf.d directory exists
    if shell.ends_with("/fish")
        && let Some(parent) = rc_file.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        error(&format!("Cannot create {}: {e}", parent.display()));
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
            error(&format!("Cannot open {}: {e}", rc_file.display()));
            return ExitCode::FAILURE;
        }
    };

    use std::io::Write;
    // Add a newline before our line if the file doesn't end with one
    let needs_newline = rc_file.exists()
        && std::fs::read_to_string(&rc_file)
            .map(|c| !c.is_empty() && !c.ends_with('\n'))
            .unwrap_or(false);

    let content = if needs_newline {
        format!("\n{setup_line}")
    } else {
        setup_line.to_string()
    };

    match file.write_all(content.as_bytes()) {
        Ok(()) => {
            ok(&format!(
                "Installed 'copilot' alias in {}",
                rc_file.display()
            ));
            info(&format!(
                "Restart your shell or run: source {}",
                rc_file.display()
            ));
            ExitCode::SUCCESS
        }
        Err(e) => {
            error(&format!("Cannot write to {}: {e}", rc_file.display()));
            ExitCode::FAILURE
        }
    }
}

/// Ensure Copilot's bundled package is extracted before entering the sandbox.
///
/// Copilot CLI (SEA binary) extracts its runtime into
/// `~/Library/Caches/copilot/pkg/<platform>/<version>/` on first launch after
/// an update. Writes to that directory are denied inside the sandbox to prevent
/// write-then-exec attacks, so the extraction must happen outside.
///
/// Uses the binary's identity (path + inode + size + mtime) as a cache key
/// rather than `--version` output, because pre-release builds can report a
/// base version (e.g. `1.0.32`) while the SEA loader extracts to a different
/// directory (e.g. `1.0.32-1-73748`). After extraction, we discover the actual
/// directory created and verify its `.extraction-complete` marker.
#[cfg(target_os = "macos")]
fn ensure_copilot_extracted(copilot_bin: &Path, home: &Path) {
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        _ => return,
    };

    let binary_id = match binary_identity(copilot_bin) {
        Some(id) => id,
        None => return,
    };

    let pkg_base = home
        .join("Library/Caches/copilot/pkg")
        .join(format!("darwin-{arch}"));

    // Fast path: check cplt-managed marker that records both the binary
    // identity and the actual extraction directory from the last successful run.
    let cache_dir = home.join("Library/Caches/cplt");
    let cache_file = cache_dir.join("copilot-extracted");
    if let Ok(cached) = std::fs::read_to_string(&cache_file) {
        let mut lines = cached.lines();
        if let (Some(cached_id), Some(cached_dir)) = (lines.next(), lines.next())
            && cached_id == binary_id
        {
            // Binary unchanged — verify the extracted dir still exists on disk
            let extracted_marker = pkg_base.join(cached_dir).join(".extraction-complete");
            if extracted_marker.exists() {
                return;
            }
        }
    }

    info("Extracting Copilot runtime (first run after update)...");

    // Snapshot existing extraction dirs so we can detect the new one.
    let dirs_before = extraction_dirs(&pkg_base);

    // Run copilot briefly to trigger SEA extraction. The extraction happens
    // during Node.js startup, before any CLI logic. We use `-p ""` to start
    // the runtime, then poll for a new `.extraction-complete` marker.
    let child = std::process::Command::new(copilot_bin)
        .args(["--no-auto-update", "-p", ""])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(_) => return,
    };

    // Poll for a new extraction directory with a `.extraction-complete` marker.
    let mut extracted_dir_name: Option<String> = None;
    for _ in 0..30 {
        if let Some(name) = find_new_extracted_dir(&pkg_base, &dirs_before) {
            extracted_dir_name = Some(name);
            break;
        }
        if let Ok(Some(_)) = child.try_wait() {
            // Process exited — check one more time
            extracted_dir_name = find_new_extracted_dir(&pkg_base, &dirs_before);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    let _ = child.kill();
    let _ = child.wait();

    // Final check after process exit
    if extracted_dir_name.is_none() {
        extracted_dir_name = find_new_extracted_dir(&pkg_base, &dirs_before);
    }

    if let Some(ref dir_name) = extracted_dir_name {
        // Persist success: binary identity + extracted dir name
        let _ = std::fs::create_dir_all(&cache_dir);
        let _ = std::fs::write(&cache_file, format!("{binary_id}\n{dir_name}"));
        ok("Copilot runtime extracted");
    } else if !cache_file.exists() {
        // Migration: first run of new cplt with an already-extracted Copilot.
        // Only cache an existing dir when no marker file exists yet (i.e. this
        // is genuinely the first time cplt tracks extraction). On subsequent
        // runs with a changed binary, we must NOT fall back to an old dir —
        // that would recreate the original version-mismatch bug.
        if let Some(name) = find_any_complete_dir(&pkg_base) {
            let _ = std::fs::create_dir_all(&cache_dir);
            let _ = std::fs::write(&cache_file, format!("{binary_id}\n{name}"));
        }
    } else {
        warn(
            "Copilot runtime extraction may have failed — \
             try running 'copilot -p exit' manually",
        );
    }
}

/// Compute a stable identity for a binary based on filesystem metadata.
/// Uses canonicalized path + inode + size + full mtime (seconds + nanoseconds).
#[cfg(target_os = "macos")]
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
#[cfg(target_os = "macos")]
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

/// Find a newly created extraction dir (not in `before`) that has `.extraction-complete`.
#[cfg(target_os = "macos")]
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
#[cfg(target_os = "macos")]
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
    dirs.sort_by(|a, b| b.1.cmp(&a.1));
    dirs.into_iter().next().map(|(name, _)| name)
}

/// Resolve the real Copilot CLI binary, skipping any symlinks that point back to cplt.
///
/// Walks PATH entries looking for a `copilot` executable. Each candidate is
/// canonicalized and compared to cplt's own binary path. Prefers standalone
/// binaries (Homebrew, npm global) over VS Code editor shims, since standalone
/// binaries don't require Electron Framework access in the sandbox.
///
/// Falls back to a VS Code shim if no standalone binary is found.
fn resolve_copilot_binary() -> Result<PathBuf, String> {
    let self_exe = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(&p).ok());

    let path_var = std::env::var("PATH").unwrap_or_default();

    let mut editor_shim: Option<PathBuf> = None;

    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join("copilot");

        // Must exist and be executable
        if !candidate.is_file() {
            continue;
        }

        // Resolve symlinks and compare to self
        let resolved = std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
        if self_exe.as_ref() == Some(&resolved) {
            continue; // skip — this is cplt aliased as copilot
        }

        // Prefer standalone binaries over editor shims (VS Code, Cursor, etc.)
        // Editor shims invoke an Electron runtime that needs extra sandbox rules.
        if is_editor_shim(&resolved) {
            if editor_shim.is_none() {
                editor_shim = Some(resolved);
            }
            continue;
        }

        return Ok(resolved);
    }

    // Fall back to editor shim if no standalone binary found
    if let Some(shim) = editor_shim {
        return Ok(shim);
    }

    Err("GitHub Copilot CLI not found in PATH. \
         If you installed cplt as a 'copilot' alias, the real Copilot CLI \
         must also be in PATH (e.g. brew install --cask copilot-cli)."
        .to_string())
}

/// Check if a copilot binary is a VS Code/Cursor/editor shim script.
/// These are shell scripts that invoke the editor's Electron runtime.
fn is_editor_shim(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    content.starts_with("#!") && content.contains("copilotCLIShim.js")
}
