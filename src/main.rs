use clap::Parser;
use cplt::{config, discover, proxy, sandbox, scratch};
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
/// so you don't need to pass flags every time. Run --init-config to
/// create a starter config.
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

    /// Allow process execution from system temp directories.
    /// DANGEROUS: re-enables exec from /private/tmp and /private/var/folders.
    /// Prefer --scratch-dir which creates a controlled executable temp dir.
    /// Only use this as a last resort when --scratch-dir is insufficient.
    #[arg(long)]
    allow_tmp_exec: bool,

    /// Enable a per-session scratch directory for TMPDIR redirect.
    /// Creates ~/.cache/cplt/tmp/{session}/ with write+exec permissions
    /// and redirects TMPDIR/GOTMPDIR there. This allows tools like
    /// `go test`, `mise` inline tasks, and `node-gyp` to work.
    /// Cleaned up automatically on exit.
    #[arg(long)]
    scratch_dir: bool,

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

    /// Everything after -- is passed directly to the copilot command.
    /// Example: cplt -- -p "fix the tests"
    #[arg(last = true)]
    copilot_args: Vec<String>,
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
fn prompt_confirm(auto_yes: bool) -> Result<(), String> {
    if auto_yes {
        eprintln!("{BLUE}[cplt]{NC} Auto-confirmed (--yes)");
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

    eprint!("{BLUE}[cplt]{NC} Proceed? [y/N] ");

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

    // macOS only
    if std::env::consts::OS != "macos" {
        error("cplt requires macOS (uses sandbox-exec)");
        return ExitCode::FAILURE;
    }

    // Handle --doctor: run diagnostics and exit
    if cli.doctor {
        return run_doctor();
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

    let cfg = match config::Config::load() {
        Ok(c) => c,
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
        allow_tmp_exec: cli.allow_tmp_exec,
        scratch_dir: cli.scratch_dir,
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

    info(&format!("Project:  {}", project_dir.display()));
    info(&format!("Home:     {}", home_dir.display()));

    // Validate all paths that will be interpolated into SBPL profile
    if let Err(e) = sandbox::validate_sbpl_path(&project_dir) {
        error(&format!("Project dir: {e}"));
        return ExitCode::FAILURE;
    }
    if let Err(e) = sandbox::validate_sbpl_path(&home_dir) {
        error(&format!("Home dir: {e}"));
        return ExitCode::FAILURE;
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
                ok(&format!("Scratch dir: {}", s.path().display()));
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

    // Generate sandbox profile
    let proxy_port_for_profile = if resolved.with_proxy {
        Some(resolved.proxy_port)
    } else {
        None
    };
    let profile = sandbox::generate_profile(&sandbox::ProfileOptions {
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
    });

    // --print-profile: dump the SBPL and exit (no copilot binary needed)
    if cli.print_profile {
        println!("{profile}");
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

    // Resolve the real Copilot CLI binary, skipping any cplt symlinks.
    let copilot_bin = match resolve_copilot_binary() {
        Ok(path) => path,
        Err(msg) => {
            error(&msg);
            return ExitCode::FAILURE;
        }
    };

    // Ensure Copilot's bundled runtime is extracted before entering the sandbox.
    // Writes to copilot/pkg are denied inside the sandbox (write-then-exec defense),
    // so extraction must happen here, outside.
    ensure_copilot_extracted(&copilot_bin, &home_dir);

    // Write profile to temp file with unique name (prevents symlink attacks)
    let profile_path = std::env::temp_dir().join(format!(
        "cplt-{}-{}.sb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    // O_CREAT|O_EXCL: atomic create, fails if exists (prevents symlink following)
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&profile_path)
        {
            Ok(f) => f,
            Err(e) => {
                error(&format!("Cannot create sandbox profile: {e}"));
                return ExitCode::FAILURE;
            }
        };
        if let Err(e) = file.write_all(profile.as_bytes()) {
            error(&format!("Cannot write sandbox profile: {e}"));
            let _ = std::fs::remove_file(&profile_path);
            return ExitCode::FAILURE;
        }
    }

    // Validate profile with a quick test
    if !resolved.no_validate {
        match sandbox::validate(&profile_path, &project_dir, &home_dir) {
            Ok(()) => ok("Sandbox profile validated ✓"),
            Err(e) => {
                error(&format!("Sandbox validation failed: {e}"));
                return ExitCode::FAILURE;
            }
        }
    }

    // Print comprehensive summary and confirm before launching Copilot
    resolved.print_summary(&project_dir, &home_dir);
    if let Err(e) = prompt_confirm(cli.yes) {
        error(&e);
        let _ = std::fs::remove_file(&profile_path);
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
                    info(&format!(
                        "Domain allowlist: {} domains from {}",
                        domains.len(),
                        path.display()
                    ));
                    domains
                }
                Err(e) => {
                    error(&format!("Failed to load allowed domains: {e}"));
                    return ExitCode::FAILURE;
                }
            },
            None => Vec::new(),
        };

        info(&format!(
            "Starting proxy on localhost:{} ...",
            resolved.proxy_port
        ));

        match proxy::start(proxy::ProxyOptions {
            port: resolved.proxy_port,
            blocked_file,
            allowed_ports: resolved.allow_ports.clone(),
            allowed_domains,
            log_file: resolved.proxy_log_file.clone(),
        }) {
            Ok(handle) => {
                ok(&format!(
                    "Proxy running on localhost:{} (thread)",
                    resolved.proxy_port
                ));
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

    info("Protected: ~/.ssh, ~/.gnupg, ~/.aws, ~/.azure, ~/.kube, ~/.docker, ~/.netrc");
    if !resolved.allow_env_files {
        info("Protected: .env*, .pem, .key files in project (--allow-env-files to override)");
    }
    if !resolved.allow_lifecycle_scripts {
        info(
            "Hardened:  npm/yarn/pnpm lifecycle scripts blocked (--allow-lifecycle-scripts to override)",
        );
    }
    if resolved.with_proxy {
        info(&format!(
            "Network:   Port 443{}, proxy logging on localhost:{}",
            if resolved.allow_ports.is_empty() {
                String::new()
            } else {
                format!(
                    "+{}",
                    resolved
                        .allow_ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            },
            resolved.proxy_port
        ));
    } else {
        info(&format!(
            "Network:   Port 443{} (use --with-proxy for connection logging)",
            if resolved.allow_ports.is_empty() {
                String::new()
            } else {
                format!(
                    "+{}",
                    resolved
                        .allow_ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            }
        ));
    }

    eprintln!();
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
    let exit_code = sandbox::exec(
        &copilot_bin,
        &profile_path,
        &project_dir,
        &cli.copilot_args,
        &resolved.pass_env,
        resolved.inherit_env,
        &disabled_categories,
        scratch_path,
        if resolved.with_proxy {
            Some(resolved.proxy_port)
        } else {
            None
        },
    );

    // Cleanup
    let _ = std::fs::remove_file(&profile_path);
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

/// Parse the Copilot CLI version from `copilot --version` output.
///
/// Returns e.g. `"1.0.24"` from `"GitHub Copilot CLI 1.0.24.\n..."`.
fn get_copilot_version(copilot_bin: &Path) -> Option<String> {
    let output = std::process::Command::new(copilot_bin)
        .arg("--version")
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .find(|s| s.starts_with(|c: char| c.is_ascii_digit()))
        .map(|s| s.trim_end_matches('.').to_string())
}

/// Ensure Copilot's bundled package is extracted before entering the sandbox.
///
/// Copilot CLI (SEA binary) extracts its runtime into
/// `~/Library/Caches/copilot/pkg/<platform>/<version>/` on first launch after
/// an update. Writes to that directory are denied inside the sandbox to prevent
/// write-then-exec attacks, so the extraction must happen outside.
///
/// This function checks for the `.extraction-complete` marker and, if missing,
/// runs `copilot` briefly to trigger the SEA loader extraction.
fn ensure_copilot_extracted(copilot_bin: &Path, home: &Path) {
    let version = match get_copilot_version(copilot_bin) {
        Some(v) => v,
        None => return,
    };

    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        _ => return,
    };

    let pkg_dir = home
        .join("Library/Caches/copilot/pkg")
        .join(format!("darwin-{arch}"))
        .join(&version);
    let marker = pkg_dir.join(".extraction-complete");

    if marker.exists() {
        return;
    }

    info(&format!(
        "Extracting Copilot {version} runtime (first run after update)..."
    ));

    // Run copilot briefly to trigger SEA extraction. The extraction happens
    // during Node.js startup, before any CLI logic. We use `-p ""` to start
    // the runtime, then poll for the marker and kill the process once done.
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

    // Poll for extraction completion (typically < 2s).
    for _ in 0..30 {
        if marker.exists() {
            let _ = child.kill();
            let _ = child.wait();
            ok(&format!("Copilot {version} runtime extracted"));
            return;
        }
        // Check if the process exited (extraction might have failed)
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Cleanup: kill if still running
    let _ = child.kill();
    let _ = child.wait();

    if marker.exists() {
        ok(&format!("Copilot {version} runtime extracted"));
    } else {
        warn(&format!(
            "Copilot {version} runtime extraction may have failed — \
             try running 'copilot -p exit' manually"
        ));
    }
}

/// Resolve the real Copilot CLI binary, skipping any symlinks that point back to cplt.
///
/// Walks PATH entries looking for a `copilot` executable. Each candidate is
/// canonicalized and compared to cplt's own binary path. The first non-self
/// match is returned. This allows `copilot` → `cplt` symlinks to work without
/// infinite recursion.
fn resolve_copilot_binary() -> Result<PathBuf, String> {
    let self_exe = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(&p).ok());

    let path_var = std::env::var("PATH").unwrap_or_default();

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

        return Ok(resolved);
    }

    Err("GitHub Copilot CLI not found in PATH. \
         If you installed cplt as a 'copilot' alias, the real Copilot CLI \
         must also be in PATH (e.g. brew install --cask copilot-cli)."
        .to_string())
}
