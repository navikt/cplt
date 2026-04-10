use std::fmt::Write;
use std::path::{Path, PathBuf};

/// Characters that would break SBPL profile string interpolation.
const SBPL_UNSAFE_CHARS: &[char] = &['"', ')', '(', ';', '\\', '\n', '\r', '\0'];

/// Sensitive directories under $HOME that are always denied.
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

/// Sensitive files under $HOME that are always denied.
const DENIED_FILES: &[&str] = &[
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".gem/credentials",
    ".vault-token",
];

/// Sensitive file patterns in the project directory that are denied by default.
/// These often contain secrets (API keys, database passwords, private keys).
/// A rogue agent could read and exfiltrate these via HTTPS.
/// Override with `--allow-env-files` if Copilot genuinely needs them.
const SENSITIVE_PROJECT_PATTERNS: &[&str] = &[
    // .env files — the #1 source of leaked secrets in project dirs
    r"\.env$",
    r"\.env\..*",
    // Private key files
    r"\.pem$",
    r"\.key$",
    r"\.p12$",
    r"\.pfx$",
    r"\.jks$",
];

/// System files that tools commonly need (SSL certs, resolv.conf, etc.)
const SYSTEM_READ_FILES: &[&str] = &[
    "/private/etc/ssl",
    "/private/etc/resolv.conf",
    "/private/etc/hosts",
    "/private/etc/shells",
    "/private/etc/passwd",
    "/private/etc/localtime",
    "/private/etc/zshrc",
    "/private/etc/bashrc",
    "/private/etc/profile",
];

/// Tool directories commonly needed by developers.
const TOOL_READ_DIRS: &[&str] = &[
    "/bin",
    "/usr/bin",
    "/usr/lib",
    "/usr/local",
    "/opt/homebrew",
    "/Library/Developer/CommandLineTools",
];

/// Environment variables safe to pass through to the sandboxed process.
/// Deliberately excludes cloud credentials (AWS_*, AZURE_*), CI tokens,
/// npm/pip tokens, database URLs, and other secrets.
pub const ENV_ALLOWLIST: &[&str] = &[
    // Core system
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    // Terminal
    "TERM",
    "COLORTERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "COLUMNS",
    "LINES",
    // Path
    "PATH",
    // Copilot auth — accepted trade-off: Copilot needs a GitHub token to function.
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "COPILOT_GITHUB_TOKEN",
    // XDG directories
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR",
    // Node.js
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_ENV",
    "NODE_EXTRA_CA_CERTS",
    "NPM_CONFIG_CACHE",
    "NPM_CONFIG_PREFIX",
    // Go
    "GOPATH",
    "GOROOT",
    "GOBIN",
    "GOCACHE",
    "GOMODCACHE",
    "GOPROXY",
    "GOPRIVATE",
    // Java/JVM
    "JAVA_HOME",
    "GRADLE_HOME",
    "GRADLE_USER_HOME",
    "MAVEN_HOME",
    "M2_HOME",
    // Rust
    "CARGO_HOME",
    "RUSTUP_HOME",
    // Python
    "VIRTUAL_ENV",
    "PYTHONPATH",
    // Editor
    "EDITOR",
    "VISUAL",
    "PAGER",
];

/// Environment variable prefixes safe to pass through.
pub const ENV_PREFIX_ALLOWLIST: &[&str] = &[
    "LC_",      // Locale
    "LANG",     // Locale (LANG, LANGUAGE)
    "COPILOT_", // Copilot-specific config
    "MISE_",    // mise tool manager
    "NVM_",     // nvm
    "SDKMAN_",  // SDKMAN
];

/// Environment variables always stripped, even with --inherit-env.
const ENV_ALWAYS_DENY: &[&str] = &[
    "NO_COLOR",      // Color suppression from parent runtime
    "FORCE_COLOR",   // Color suppression from parent runtime
    "SSH_AUTH_SOCK", // SSH agent — intentionally blocked in sandbox
    "SSH_AGENT_PID", // SSH agent PID
];

/// Environment variables redirected to the scratch directory.
/// These control where tools write temporary files and compiled binaries.
const SCRATCH_DIR_ENV_VARS: &[&str] = &[
    "TMPDIR",   // Standard Unix temp dir
    "TMP",      // Used by some tools (Node.js, Python)
    "TEMP",     // Used by some tools (cross-platform)
    "GOTMPDIR", // Go test binary compilation target
];

// ── Security environment hardening ─────────────────────────────

/// Categories of security-hardening environment variables.
/// Opt-outs are per-category, not per-variable — users accept a *risk*,
/// not toggle a specific tool's knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningCategory {
    /// Block npm/yarn/pnpm `postinstall` hooks — the #1 supply chain entry point.
    LifecycleScripts,
    /// Prevent git from prompting or leaking credentials interactively.
    GitHardening,
}

/// A security-hardening environment variable injected into the sandbox.
pub struct HardeningEnvVar {
    pub name: &'static str,
    pub value: &'static str,
    pub category: HardeningCategory,
    pub description: &'static str,
}

/// Declarative list of security-hardening env vars.
/// Adding a new entry is a one-line addition — no plumbing needed.
pub const HARDENING_ENV_VARS: &[HardeningEnvVar] = &[
    // Lifecycle scripts — blocks the postinstall attack vector
    HardeningEnvVar {
        name: "npm_config_ignore_scripts",
        value: "true",
        category: HardeningCategory::LifecycleScripts,
        description: "Block npm/pnpm postinstall hooks",
    },
    HardeningEnvVar {
        name: "YARN_ENABLE_SCRIPTS",
        value: "false",
        category: HardeningCategory::LifecycleScripts,
        description: "Block Yarn Berry lifecycle scripts",
    },
    // Git hardening — prevent interactive prompts in a non-interactive sandbox
    HardeningEnvVar {
        name: "GIT_TERMINAL_PROMPT",
        value: "0",
        category: HardeningCategory::GitHardening,
        description: "Prevent git from prompting for credentials",
    },
];

/// Tool directory under $HOME with granular sandbox permissions.
///
/// Each directory gets `file-read*` unconditionally. The flags control
/// additional permissions:
/// - `process_exec`: allow direct binary execution (`process-exec`)
/// - `map_exec`: allow shared library loading (`file-map-executable`) for native addons
/// - `write`: allow file writes (`file-write*`) for build caches and dependency stores
///
/// Security principle: every writable+executable directory is a potential
/// binary-drop staging path (see SECURITY.md axios case study). Grant exec
/// only where tools genuinely install executables.
pub struct HomeToolDir {
    pub path: &'static str,
    pub process_exec: bool,
    pub map_exec: bool,
    pub write: bool,
}

/// Tool directories under $HOME with per-directory permissions.
/// NOTE: Only tool/binary dirs, never source code dirs.
/// ~/go/src is intentionally excluded — it contains other repos.
pub const HOME_TOOL_DIRS: &[HomeToolDir] = &[
    // Executables: bin/ dirs with shims, compilers, runtimes
    HomeToolDir {
        path: ".local",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    HomeToolDir {
        path: ".mise",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    HomeToolDir {
        path: ".nvm",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    HomeToolDir {
        path: ".cargo",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    HomeToolDir {
        path: ".rustup",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    HomeToolDir {
        path: ".sdkman",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    HomeToolDir {
        path: "go/bin",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    // Dependency stores: JARs, compiled packages — may contain JNI/cgo native libs
    HomeToolDir {
        path: ".gradle",
        process_exec: false,
        map_exec: true,
        write: true,
    },
    HomeToolDir {
        path: ".m2",
        process_exec: false,
        map_exec: true,
        write: true,
    },
    HomeToolDir {
        path: "go/pkg",
        process_exec: false,
        map_exec: true,
        write: false,
    },
    // Build caches: downloads, intermediate artifacts — NO exec (RAT staging risk)
    HomeToolDir {
        path: "Library/Caches",
        process_exec: false,
        map_exec: false,
        write: true,
    },
    // pnpm global store: contains packages + executable shims
    HomeToolDir {
        path: "Library/pnpm",
        process_exec: true,
        map_exec: true,
        write: true,
    },
];

/// Validate that a path is safe for interpolation into SBPL profile strings.
/// Returns an error if the path contains characters that could break or inject SBPL rules.
pub fn validate_sbpl_path(path: &Path) -> Result<(), String> {
    let s = path.to_string_lossy();
    for c in SBPL_UNSAFE_CHARS {
        if s.contains(*c) {
            return Err(format!(
                "Path contains unsafe character '{}' for sandbox profile: {s}\n\
                 This could be used for SBPL injection.",
                c.escape_default()
            ));
        }
    }
    Ok(())
}

/// Options for generating an SBPL sandbox profile.
///
/// All paths are validated for SBPL injection before interpolation.
pub struct ProfileOptions<'a> {
    pub project_dir: &'a Path,
    pub home_dir: &'a Path,
    pub extra_read: &'a [PathBuf],
    pub extra_write: &'a [PathBuf],
    pub extra_deny: &'a [PathBuf],
    /// If `Some`, only include these home tool dirs (tighter profile via discovery).
    /// If `None`, all known home tool dirs are included.
    pub existing_home_tool_dirs: Option<&'a [String]>,
    pub extra_ports: &'a [u16],
    pub localhost_ports: &'a [u16],
    pub proxy_port: Option<u16>,
    /// Allow reading .env files and private keys in the project dir.
    pub allow_env_files: bool,
    /// Allow outbound TCP to localhost on all ports.
    pub allow_localhost_any: bool,
    /// Per-session scratch directory with write+exec permissions.
    /// Used to redirect TMPDIR so tools can compile-then-execute.
    pub scratch_dir: Option<&'a Path>,
    /// Remove temp dir exec denies (break-glass for system TMPDIR exec).
    pub allow_tmp_exec: bool,
}

/// Generate a complete SBPL sandbox profile from the given options.
pub fn generate_profile(opts: &ProfileOptions) -> String {
    let mut sb = String::with_capacity(4096);
    let home = opts.home_dir.to_string_lossy();
    let project = opts.project_dir.to_string_lossy();

    // Header
    writeln!(sb, ";; Auto-generated by cplt").unwrap();
    writeln!(sb, ";; Project: {project}").unwrap();
    writeln!(sb, "(version 1)").unwrap();
    writeln!(sb, "(deny default)").unwrap();
    writeln!(sb).unwrap();

    // Base system profile
    writeln!(sb, "(import \"/System/Library/Sandbox/Profiles/bsd.sb\")").unwrap();
    writeln!(sb).unwrap();

    // Process execution
    writeln!(sb, ";; Process execution").unwrap();
    writeln!(sb, "(allow process-exec)").unwrap();
    writeln!(sb, "(allow process-fork)").unwrap();
    // Allow sending signals to processes in the same sandbox (e.g. Turbopack killing workers)
    writeln!(sb, "(allow signal (target same-sandbox))").unwrap();
    writeln!(sb).unwrap();

    // TTY/terminal control — needed for interactive CLIs (e.g. Node.js setRawMode)
    writeln!(
        sb,
        ";; TTY control (ioctl for terminal raw mode, window size)"
    )
    .unwrap();
    writeln!(sb, "(allow file-ioctl)").unwrap();
    writeln!(sb).unwrap();

    // Device access — Node.js needs /dev/tty, /dev/null, /dev/urandom etc.
    writeln!(sb, ";; Device access (/dev/tty, /dev/null, /dev/urandom)").unwrap();
    writeln!(sb, "(allow file-read* (subpath \"/dev\"))").unwrap();
    writeln!(sb, "(allow file-write* (subpath \"/dev\"))").unwrap();
    writeln!(sb).unwrap();

    // Project directory — full access
    // file-map-executable needed for native Node addons in node_modules
    // (e.g. @next/swc-*, sharp, better-sqlite3 loaded via dlopen)
    writeln!(sb, ";; Project directory — full read/write").unwrap();
    writeln!(sb, "(allow file-read* (subpath \"{project}\"))").unwrap();
    writeln!(sb, "(allow file-write* (subpath \"{project}\"))").unwrap();
    writeln!(sb, "(allow file-map-executable (subpath \"{project}\"))").unwrap();
    writeln!(sb).unwrap();

    // Git persistence prevention — deny writes to files that execute outside the sandbox.
    // .git/hooks/ — post-checkout, pre-push etc. run outside sandbox on next git operation
    // .git/config — core.hooksPath can redirect hooks to /tmp, bypassing the hooks deny;
    //               url.*.insteadOf can hijack git remotes; include.path loads arbitrary config
    // .gitmodules — submodule URLs are a supply chain vector (git submodule update clones them)
    // These denies are more specific than the project allow, so they win (SBPL specificity).
    writeln!(sb, ";; Git persistence prevention").unwrap();
    writeln!(sb, "(deny file-write* (subpath \"{project}/.git/hooks\"))").unwrap();
    writeln!(sb, "(deny file-write* (literal \"{project}/.git/config\"))").unwrap();
    writeln!(sb, "(deny file-write* (literal \"{project}/.gitmodules\"))").unwrap();
    writeln!(sb).unwrap();

    // Sensitive project files — deny read of .env*, .pem, .key etc.
    // These often contain secrets that could be exfiltrated via HTTPS.
    // Placed after the project allow so deny wins (more specific filter).
    // Copilot can still write these files (creating .env from .env.example).
    if !opts.allow_env_files {
        writeln!(sb, ";; Sensitive project files — deny read (.env*, keys)").unwrap();
        for pattern in SENSITIVE_PROJECT_PATTERNS {
            // SBPL regex matches against the full path, so we anchor to
            // any directory separator to avoid matching path components.
            writeln!(sb, "(deny file-read* (regex #\"/{pattern}\"))").unwrap();
        }
        writeln!(sb).unwrap();
    }

    // Copilot config — the CLI needs its auth tokens and settings.
    // file-map-executable is needed for native Node.js addons (keytar.node, pty.node, computer.node)
    // which are loaded via dlopen() from ~/.copilot/pkg/universal/*/prebuilds/
    writeln!(sb, ";; Copilot config + native modules").unwrap();
    writeln!(sb, "(allow file-read* (subpath \"{home}/.copilot\"))").unwrap();
    writeln!(sb, "(allow file-write* (subpath \"{home}/.copilot\"))").unwrap();
    writeln!(
        sb,
        "(allow file-map-executable (subpath \"{home}/.copilot\"))"
    )
    .unwrap();
    // Deny writes to Copilot's installed packages (native modules).
    // Prevents persistence: a rogue agent could replace keytar.node with a
    // malicious version that runs unsandboxed next time Copilot is launched.
    // Must come after the allow (last-match-wins).
    writeln!(sb, "(deny file-write* (subpath \"{home}/.copilot/pkg\"))").unwrap();
    writeln!(sb).unwrap();

    // GitHub CLI auth — Copilot spawns `gh auth token` which reads these specific files.
    // Only the auth files, not the entire ~/.config/gh directory.
    writeln!(sb, ";; GitHub CLI auth (specific files only)").unwrap();
    writeln!(
        sb,
        "(allow file-read* (literal \"{home}/.config/gh/hosts.yml\"))"
    )
    .unwrap();
    writeln!(
        sb,
        "(allow file-read* (literal \"{home}/.config/gh/config.yml\"))"
    )
    .unwrap();
    writeln!(sb).unwrap();

    // mise config — tool version manager reads global config for tool paths and settings.
    // Contains tool versions and PATH entries, no secrets.
    writeln!(sb, ";; mise config (tool versions, no secrets)").unwrap();
    writeln!(sb, "(allow file-read* (subpath \"{home}/.config/mise\"))").unwrap();
    writeln!(sb).unwrap();

    // Microsoft DeviceID — telemetry device identifier
    writeln!(sb, ";; Microsoft DeviceID").unwrap();
    writeln!(
        sb,
        "(allow file-read* (subpath \"{home}/Library/Application Support/Microsoft\"))"
    )
    .unwrap();
    writeln!(sb).unwrap();

    // macOS Keychain access — Copilot stores auth tokens here
    // Security framework needs read+write (locks the db file during access)
    writeln!(sb, ";; macOS Keychain (Copilot auth tokens)").unwrap();
    writeln!(
        sb,
        "(allow file-read* (subpath \"{home}/Library/Keychains\"))"
    )
    .unwrap();
    writeln!(
        sb,
        "(allow file-write* (subpath \"{home}/Library/Keychains\"))"
    )
    .unwrap();
    writeln!(sb).unwrap();

    // Mach IPC — Node.js and macOS frameworks need service lookups
    // (Keychain, security framework, DNS, system services)
    writeln!(sb, ";; Mach IPC (required for Node.js, Keychain, DNS)").unwrap();
    writeln!(sb, "(allow mach-lookup)").unwrap();
    writeln!(sb).unwrap();

    // System info — Node.js queries CPU count, memory, OS version
    writeln!(sb, ";; System info (Node.js runtime needs these)").unwrap();
    writeln!(sb, "(allow sysctl-read)").unwrap();
    writeln!(sb, "(allow ipc-posix-shm-read-data)").unwrap();
    writeln!(sb, "(allow ipc-posix-shm-write-data)").unwrap();
    writeln!(sb, "(allow ipc-posix-shm-write-create)").unwrap();
    writeln!(sb).unwrap();

    // User preferences — Keychain and security framework read preferences
    writeln!(sb, ";; User preferences (Keychain, security framework)").unwrap();
    writeln!(sb, "(allow user-preference-read)").unwrap();
    writeln!(sb).unwrap();

    // Security framework databases — needed for Keychain/TLS operations
    writeln!(sb, ";; Security framework databases").unwrap();
    writeln!(sb, "(allow file-read* (subpath \"/private/var/db/mds\"))").unwrap();
    writeln!(sb).unwrap();

    // Git config (read-only)
    writeln!(sb, ";; Git config (read-only)").unwrap();
    writeln!(sb, "(allow file-read* (literal \"{home}/.gitconfig\"))").unwrap();
    writeln!(
        sb,
        "(allow file-read* (literal \"{home}/.config/git/config\"))"
    )
    .unwrap();
    writeln!(sb).unwrap();

    // Tool version files — mise/asdf read these to determine tool versions
    writeln!(sb, ";; Tool version files (mise/asdf, read-only)").unwrap();
    writeln!(sb, "(allow file-read* (literal \"{home}/.tool-versions\"))").unwrap();
    writeln!(sb).unwrap();

    // Developer tool directories
    writeln!(sb, ";; Developer tools").unwrap();
    for dir in TOOL_READ_DIRS {
        writeln!(sb, "(allow file-read* (subpath \"{dir}\"))").unwrap();
        writeln!(sb, "(allow file-map-executable (subpath \"{dir}\"))").unwrap();
    }
    // Home tool dirs: use discovered existing dirs if available, else include all
    let active_dirs: Vec<&HomeToolDir> = match opts.existing_home_tool_dirs {
        Some(dirs) => HOME_TOOL_DIRS
            .iter()
            .filter(|d| dirs.iter().any(|s| s == d.path))
            .collect(),
        None => HOME_TOOL_DIRS.iter().collect(),
    };
    for dir in &active_dirs {
        let p = dir.path;
        writeln!(sb, "(allow file-read* (subpath \"{home}/{p}\"))").unwrap();
        if dir.process_exec {
            writeln!(sb, "(allow process-exec (subpath \"{home}/{p}\"))").unwrap();
        }
        if dir.map_exec {
            writeln!(sb, "(allow file-map-executable (subpath \"{home}/{p}\"))").unwrap();
        }
        if dir.write {
            writeln!(sb, "(allow file-write* (subpath \"{home}/{p}\"))").unwrap();
        }
    }
    // Deny exec from writable dirs that should not have it.
    // Must come AFTER allows (last-match-wins in Seatbelt).
    // The blanket (allow process-exec) means we need explicit denies,
    // not just absence of a per-dir allow.
    for dir in &active_dirs {
        let p = dir.path;
        if dir.write && !dir.process_exec {
            writeln!(sb, "(deny process-exec (subpath \"{home}/{p}\"))").unwrap();
        }
        if dir.write && !dir.map_exec {
            writeln!(sb, "(deny file-map-executable (subpath \"{home}/{p}\"))").unwrap();
        }
    }
    // Copilot CLI v1.0.22+ stores native modules (pty.node, keytar.node) in
    // ~/Library/Caches/copilot/pkg/. The Library/Caches deny above blocks
    // file-map-executable broadly. This carve-out re-enables dlopen() for
    // Copilot's own native modules. Must come AFTER the deny (last-match-wins).
    writeln!(
        sb,
        "(allow file-map-executable (subpath \"{home}/Library/Caches/copilot/pkg\"))"
    )
    .unwrap();
    writeln!(sb).unwrap();

    // System config files (specific, not broad)
    writeln!(sb, ";; System config (specific files)").unwrap();
    for path in SYSTEM_READ_FILES {
        if path.contains('/') && !path.ends_with('/') {
            // Could be a file or directory — use subpath for dirs like /private/etc/ssl
            if path.ends_with("ssl") {
                writeln!(sb, "(allow file-read* (subpath \"{path}\"))").unwrap();
            } else {
                writeln!(sb, "(allow file-read* (literal \"{path}\"))").unwrap();
            }
        } else {
            writeln!(sb, "(allow file-read* (literal \"{path}\"))").unwrap();
        }
    }
    writeln!(sb).unwrap();

    // Temp directories
    writeln!(sb, ";; Temp directories").unwrap();
    writeln!(sb, "(allow file-read* (subpath \"/private/tmp\"))").unwrap();
    writeln!(sb, "(allow file-write* (subpath \"/private/tmp\"))").unwrap();
    writeln!(sb, "(allow file-read* (subpath \"/private/var/folders\"))").unwrap();
    writeln!(sb, "(allow file-write* (subpath \"/private/var/folders\"))").unwrap();
    if !opts.allow_tmp_exec {
        // Deny direct execution and dlopen from writable temp dirs.
        // Prevents write-then-exec attacks (drop binary → execute it).
        // Limitation: does NOT block interpreter-based exec (e.g. `bash /tmp/evil.sh`,
        // `node /tmp/evil.js`) because the exec target is the interpreter, not the script.
        writeln!(sb, "(deny process-exec (subpath \"/private/tmp\"))").unwrap();
        writeln!(sb, "(deny file-map-executable (subpath \"/private/tmp\"))").unwrap();
        writeln!(sb, "(deny process-exec (subpath \"/private/var/folders\"))").unwrap();
        writeln!(
            sb,
            "(deny file-map-executable (subpath \"/private/var/folders\"))"
        )
        .unwrap();
    }
    writeln!(sb).unwrap();

    // Per-session scratch directory — write+exec for tools that compile-then-execute
    if let Some(scratch) = opts.scratch_dir {
        let scratch_path = scratch.to_string_lossy();
        writeln!(sb, ";; Per-session scratch directory (TMPDIR redirect)").unwrap();
        writeln!(sb, "(allow file-read* (subpath \"{scratch_path}\"))").unwrap();
        writeln!(sb, "(allow file-write* (subpath \"{scratch_path}\"))").unwrap();
        writeln!(sb, "(allow process-exec (subpath \"{scratch_path}\"))").unwrap();
        writeln!(
            sb,
            "(allow file-map-executable (subpath \"{scratch_path}\"))"
        )
        .unwrap();
        writeln!(sb).unwrap();
    }

    // Extra user-specified allows
    if !opts.extra_read.is_empty() || !opts.extra_write.is_empty() {
        writeln!(sb, ";; User-specified allows").unwrap();
        for path in opts.extra_read {
            let p = path.to_string_lossy();
            writeln!(sb, "(allow file-read* (subpath \"{p}\"))").unwrap();
        }
        for path in opts.extra_write {
            let p = path.to_string_lossy();
            writeln!(sb, "(allow file-read* (subpath \"{p}\"))").unwrap();
            writeln!(sb, "(allow file-write* (subpath \"{p}\"))").unwrap();
        }
        writeln!(sb).unwrap();
    }

    // Sensitive directories — DENY (after allows, so these override)
    writeln!(sb, ";; Sensitive directories — DENIED").unwrap();
    for dotfile in DENIED_DOTFILES {
        writeln!(sb, "(deny file-read* (subpath \"{home}/{dotfile}\"))").unwrap();
        writeln!(sb, "(deny file-write* (subpath \"{home}/{dotfile}\"))").unwrap();
    }
    for file in DENIED_FILES {
        writeln!(sb, "(deny file-read* (literal \"{home}/{file}\"))").unwrap();
        writeln!(sb, "(deny file-write* (literal \"{home}/{file}\"))").unwrap();
    }
    for path in opts.extra_deny {
        let p = path.to_string_lossy();
        writeln!(sb, "(deny file-read* (subpath \"{p}\"))").unwrap();
        writeln!(sb, "(deny file-write* (subpath \"{p}\"))").unwrap();
    }
    writeln!(sb).unwrap();

    // Network — outbound restricted to HTTPS/HTTP, localhost blocked by default.
    // Copilot CLI connects directly to api.githubcopilot.com:443 etc.
    // We can't do domain-based rules in SBPL, but we can restrict ports and
    // block localhost to prevent SSRF attacks against local services.
    writeln!(sb, ";; Network — restricted outbound, localhost blocked").unwrap();

    // DNS resolution — only the specific mDNSResponder socket, NOT all unix-sockets.
    // Blocking (remote unix-socket) prevents SSH agent access via launchd sockets.
    writeln!(
        sb,
        "(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))"
    )
    .unwrap();

    // Outbound TCP restricted to port 443 (HTTPS only).
    // All Copilot/GitHub APIs use HTTPS — port 80 is not needed and would
    // allow unencrypted exfiltration. Use --allow-port 80 if required.
    writeln!(sb, "(deny network-outbound (remote tcp))").unwrap();
    writeln!(sb, "(allow network-outbound (remote ip \"*:443\"))").unwrap();

    // Extra ports (e.g., MCP servers, custom services)
    for port in opts.extra_ports {
        writeln!(sb, "(allow network-outbound (remote ip \"*:{port}\"))").unwrap();
    }

    // Block localhost outbound — prevents SSRF to local dev servers, databases, etc.
    // Must come AFTER port allows so it overrides them for localhost.
    if !opts.allow_localhost_any {
        writeln!(sb, "(deny network-outbound (remote ip \"localhost:*\"))").unwrap();
    } else {
        // Explicitly allow all localhost ports — the general TCP deny above
        // blocks non-443 ports, so we need a specific allow for localhost.
        writeln!(sb, "(allow network-outbound (remote ip \"localhost:*\"))").unwrap();
    }

    // Carve-outs for specific localhost ports (proxy, MCP servers, dev servers).
    // These come AFTER the deny so they override it (last-match-wins in SBPL).
    if let Some(port) = opts.proxy_port {
        writeln!(
            sb,
            "(allow network-outbound (remote ip \"localhost:{port}\"))"
        )
        .unwrap();
    }
    for port in opts.localhost_ports {
        writeln!(
            sb,
            "(allow network-outbound (remote ip \"localhost:{port}\"))"
        )
        .unwrap();
    }

    // Allow inbound for localhost services (proxy listener, MCP servers).
    // This only allows accepting connections, not initiating them.
    writeln!(sb, "(allow network-inbound (local tcp))").unwrap();

    sb
}

/// Validate the profile by running a simple command inside the sandbox.
pub fn validate(profile_path: &Path, _project_dir: &Path, _home_dir: &Path) -> Result<(), String> {
    let output = std::process::Command::new("sandbox-exec")
        .arg("-f")
        .arg(profile_path)
        .arg("/usr/bin/true")
        .output()
        .map_err(|e| format!("Failed to run sandbox-exec: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "sandbox-exec exited with {}: {stderr}",
            output.status
        ))
    }
}

/// Build the environment variable map for the sandboxed process.
///
/// Pure function (takes parent env as input) for testability.
/// Returns (vars_to_set, vars_to_remove, should_clear).
///
/// - `should_clear`: if true, caller must `env_clear()` first, then set all vars from `vars_to_set`.
/// - `vars_to_remove`: only relevant when `should_clear` is false (inherit mode).
/// - `scratch_dir`: if Some, TMPDIR/TMP/TEMP/GOTMPDIR are redirected to this path
///   (unless explicitly overridden by user via `extra_pass_env`).
pub fn build_sandbox_env(
    parent_env: &[(String, String)],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    scratch_dir: Option<&Path>,
) -> SandboxEnv {
    let mut env = SandboxEnv {
        vars: Vec::new(),
        remove: Vec::new(),
        clear_first: !inherit_env,
    };

    if inherit_env {
        // Legacy mode: inherit everything, strip known-bad vars
        for var in ENV_ALWAYS_DENY {
            env.remove.push(var.to_string());
        }
    } else {
        // Secure mode: only allowlisted vars
        for &var in ENV_ALLOWLIST {
            if let Some((_, val)) = parent_env.iter().find(|(k, _)| k == var) {
                env.vars.push((var.to_string(), val.clone()));
            }
        }
        for (key, val) in parent_env {
            if ENV_PREFIX_ALLOWLIST
                .iter()
                .any(|prefix| key.starts_with(prefix))
            {
                // Avoid duplicates from the explicit allowlist
                if !env.vars.iter().any(|(k, _)| k == key) {
                    env.vars.push((key.clone(), val.clone()));
                }
            }
        }
        for var in extra_pass_env {
            if let Some((_, val)) = parent_env.iter().find(|(k, _)| k == var)
                && !env.vars.iter().any(|(k, _)| k == var)
            {
                env.vars.push((var.clone(), val.clone()));
            }
        }
    }

    // Apply security hardening: inject vars unless the category is disabled
    // or the user has explicitly set the var (via --pass-env or parent env in inherit mode).
    for hvar in HARDENING_ENV_VARS {
        if disabled_categories.contains(&hvar.category) {
            continue;
        }
        let user_has_set = if inherit_env {
            // In inherit mode, check if user explicitly passed it via --pass-env
            extra_pass_env.iter().any(|v| v == hvar.name)
        } else {
            // In sanitized mode, check if it ended up in our vars (via pass-env)
            env.vars.iter().any(|(k, _)| k == hvar.name)
        };
        if !user_has_set {
            env.vars
                .push((hvar.name.to_string(), hvar.value.to_string()));
        }
    }

    // Redirect temp directories to scratch dir if provided.
    // --scratch-dir means "redirect TMPDIR to the scratch dir" — this overrides any
    // inherited or allowlisted TMPDIR value. The user can prevent this for a specific
    // var by passing --pass-env TMPDIR, which signals "use my value, not scratch".
    if let Some(scratch) = scratch_dir {
        let scratch_str = scratch.to_string_lossy().to_string();
        for var in SCRATCH_DIR_ENV_VARS {
            let user_override = extra_pass_env.iter().any(|v| v == var);
            if !user_override {
                // Remove any existing value (e.g., system TMPDIR from allowlist)
                env.vars.retain(|(k, _)| k != var);
                env.vars.push((var.to_string(), scratch_str.clone()));
            }
        }
    }

    env
}

/// Environment configuration for the sandboxed process.
pub struct SandboxEnv {
    /// Variables to set (name, value).
    pub vars: Vec<(String, String)>,
    /// Variables to remove (only used when `clear_first` is false).
    pub remove: Vec<String>,
    /// Whether to clear all env vars before applying `vars`.
    pub clear_first: bool,
}

/// Execute copilot inside the sandbox, forwarding signals to the child process group.
///
/// Environment handling:
/// - Default (inherit_env=false): env_clear() + allowlist only. Cloud credentials,
///   npm tokens, database URLs, etc. are stripped. Use `extra_pass_env` for extras.
/// - Legacy (inherit_env=true): all env vars inherited, only SSH_AUTH_SOCK and
///   color vars are stripped. Use only when the default breaks something.
/// - Security hardening env vars are injected unless their category is disabled.
pub fn exec(
    profile_path: &Path,
    project_dir: &Path,
    copilot_args: &[String],
    extra_pass_env: &[String],
    inherit_env: bool,
    disabled_categories: &[HardeningCategory],
    scratch_dir: Option<&Path>,
) -> u8 {
    let mut cmd = std::process::Command::new("sandbox-exec");
    cmd.arg("-f").arg(profile_path).arg("copilot");

    // Prevent Copilot from trying to auto-update inside the sandbox
    // (writes to ~/.copilot/pkg are denied, so it would fail anyway).
    cmd.arg("--no-auto-update");

    for arg in copilot_args {
        cmd.arg(arg);
    }

    // Set working directory to project
    cmd.current_dir(project_dir);

    // Build and apply environment
    let parent_env: Vec<(String, String)> = std::env::vars().collect();
    let sandbox_env = build_sandbox_env(
        &parent_env,
        extra_pass_env,
        inherit_env,
        disabled_categories,
        scratch_dir,
    );

    if sandbox_env.clear_first {
        cmd.env_clear();
        for (key, val) in &sandbox_env.vars {
            cmd.env(key, val);
        }
    } else {
        for var in &sandbox_env.remove {
            cmd.env_remove(var);
        }
        for (key, val) in &sandbox_env.vars {
            cmd.env(key, val);
        }
    }

    // Child inherits our process group — terminal signals (Ctrl+C)
    // reach both parent and child naturally. No setpgid/tcsetpgrp needed.
    //
    // Ignore SIGTTOU/SIGTTIN — copilot (Node.js) may manipulate terminal
    // settings (raw mode), and when the child exits the terminal state can
    // cause these signals to be sent to us.
    unsafe {
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("\x1b[0;31m[cplt]\x1b[0m Failed to start sandbox-exec: {e}");
            return 1;
        }
    };

    let child_pid = child.id() as i32;

    // Forward SIGTERM/SIGHUP to the child (these aren't sent by the terminal)
    install_signal_forwarding(child_pid);

    let status = match child.wait() {
        Ok(status) => status.code().unwrap_or(1) as u8,
        Err(e) => {
            eprintln!("\x1b[0;31m[cplt]\x1b[0m Error waiting for child: {e}");
            unsafe {
                libc::kill(child_pid, libc::SIGTERM);
            }
            1
        }
    };

    // Restore default signal handling
    unsafe {
        libc::signal(libc::SIGTTOU, libc::SIG_DFL);
        libc::signal(libc::SIGTTIN, libc::SIG_DFL);
    }

    status
}

fn install_signal_forwarding(child_pid: i32) {
    use std::sync::atomic::{AtomicI32, Ordering};

    static CHILD_PID: AtomicI32 = AtomicI32::new(0);
    CHILD_PID.store(child_pid, Ordering::SeqCst);

    extern "C" fn forward_signal(sig: i32) {
        use std::sync::atomic::Ordering;
        let pid = CHILD_PID.load(Ordering::SeqCst);
        if pid > 0 {
            unsafe {
                libc::kill(pid, sig);
            }
        }
        // Reset to default — second signal kills us immediately
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
        }
    }

    unsafe {
        libc::signal(
            libc::SIGTERM,
            forward_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGHUP,
            forward_signal as *const () as libc::sighandler_t,
        );
    }
}
