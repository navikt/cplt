use std::path::Path;

/// Characters that would break SBPL profile string interpolation.
const SBPL_UNSAFE_CHARS: &[char] = &['"', ')', '(', ';', '\\', '\n', '\r', '\0'];

/// Sensitive directories under $HOME that are always denied.
pub const DENIED_DOTFILES: &[&str] = &[
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
pub const DENIED_FILES: &[&str] = &[
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
pub(super) const SENSITIVE_PROJECT_PATTERNS: &[&str] = &[
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

/// Prefixes of ~/Library/Caches/ subdirectories to deny (non-dev caches).
/// Uses reverse-domain bundle IDs which are stable across app versions.
/// Dev tool caches (go-build, pip, Homebrew, etc.) are NOT prefixed this way,
/// so they pass through automatically — no allowlist maintenance needed.
pub(super) const DENIED_CACHE_PREFIXES: &[&str] = &[
    // macOS system apps (Xcode dev tools exempted via com.apple.dt.)
    "com.apple.",
    // Browsers and personal apps
    "com.google.",
    "com.hnc.", // Discord
    "com.figma.",
    "com.electron.", // Electron app auto-updaters
    "org.mozilla.",  // Firefox
    "org.gpgtools.",
    "org.whispersystems.", // Signal
    "us.zoom.",
    "at.obdev.", // Little Snitch
    // Non-prefixed personal apps
    "Firefox",
    "Google",
    "Mozilla",
    "Chrome",
    "Safari",
];

/// System files that tools commonly need (SSL certs, resolv.conf, etc.)
pub(super) const SYSTEM_READ_FILES: &[&str] = &[
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
pub(super) const TOOL_READ_DIRS: &[&str] = &[
    "/bin",
    "/usr/bin",
    "/usr/lib",
    "/usr/local",
    "/opt/homebrew",
    "/Library/Developer/CommandLineTools",
];

/// Suffixes of env var names that indicate secrets/credentials.
/// Vars matching a prefix allowlist entry BUT also matching one of these
/// suffixes are stripped — deny wins. Prevents `YARN_NPM_AUTH_TOKEN`,
/// `COPILOT_SECRET_KEY`, etc. from leaking through broad prefix rules.
const ENV_PREFIX_DENY_SUFFIXES: &[&str] = &[
    "_TOKEN",
    "_AUTH",
    "_SECRET",
    "_SECRET_KEY",
    "_KEY",
    "_PASSWORD",
    "_CREDENTIALS",
];

/// Check if a var name looks like a secret based on its suffix.
/// Vars in the explicit `ENV_ALLOWLIST` (e.g. `GH_TOKEN`) bypass this check
/// because they are intentionally allowed.
pub(super) fn is_secret_suffix(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    ENV_PREFIX_DENY_SUFFIXES
        .iter()
        .any(|suffix| upper.ends_with(suffix))
}

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
    "MAVEN_OPTS",        // JVM flags for Maven (e.g. -Xmx, -Djava.io.tmpdir)
    "JAVA_TOOL_OPTIONS", // JVM-wide options picked up by all Java processes
    // Rust
    "CARGO_HOME",
    "RUSTUP_HOME",
    // Python
    "VIRTUAL_ENV",
    "PYTHONPATH",
    "PYENV_ROOT",              // pyenv install location
    "PYTHONDONTWRITEBYTECODE", // Prevent .pyc writes (common in CI/sandboxed envs)
    // pnpm
    "PNPM_HOME", // pnpm binary location
    // Locale
    "LANG",
    "LANGUAGE",
    // Editor
    "EDITOR",
    "VISUAL",
    "PAGER",
    // GPG — terminal device path for pinentry (not sensitive, e.g. "/dev/ttys001")
    "GPG_TTY",
];

/// Environment variable prefixes safe to pass through.
pub const ENV_PREFIX_ALLOWLIST: &[&str] = &[
    "LC_",       // Locale
    "COPILOT_",  // Copilot-specific config
    "COREPACK_", // Node.js Corepack (package manager manager)
    "MISE_",     // mise tool manager
    "NVM_",      // nvm
    "PYENV_",    // pyenv (Python version manager)
    "SDKMAN_",   // SDKMAN (Java version manager)
    "YARN_",     // Yarn Berry config (hardening injection overrides YARN_ENABLE_SCRIPTS)
];

/// Environment variables always stripped, even with --inherit-env.
pub(super) const ENV_ALWAYS_DENY: &[&str] = &[
    "NO_COLOR",      // Color suppression from parent runtime
    "FORCE_COLOR",   // Color suppression from parent runtime
    "SSH_AUTH_SOCK", // SSH agent — intentionally blocked in sandbox
    "SSH_AGENT_PID", // SSH agent PID
];

/// Environment variables redirected to the scratch directory.
/// These control where tools write temporary files and compiled binaries.
pub(super) const SCRATCH_DIR_ENV_VARS: &[&str] = &[
    "TMPDIR",       // Standard Unix temp dir
    "TMP",          // Used by some tools (Node.js, Python)
    "TEMP",         // Used by some tools (cross-platform)
    "GOTMPDIR",     // Go test binary compilation target
    "JANSI_TMPDIR", // Maven terminal library (jansi) native lib extraction
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
    /// Disable commit/tag signing inside the sandbox. Separated from GitHardening
    /// so `--allow-gpg-signing` can re-enable signing without removing
    /// `GIT_TERMINAL_PROMPT=0`.
    GitSigning,
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
    // Git signing — ~/.ssh and ~/.gnupg are denied by the sandbox, so commit/tag
    // signing would fail with EPERM. Disable it via config override rather than
    // opening private key directories. Re-enabled by --allow-gpg-signing.
    HardeningEnvVar {
        name: "GIT_CONFIG_COUNT",
        value: "2",
        category: HardeningCategory::GitSigning,
        description: "Number of git config overrides (commit + tag signing)",
    },
    HardeningEnvVar {
        name: "GIT_CONFIG_KEY_0",
        value: "commit.gpgsign",
        category: HardeningCategory::GitSigning,
        description: "Override commit signing config key",
    },
    HardeningEnvVar {
        name: "GIT_CONFIG_VALUE_0",
        value: "false",
        category: HardeningCategory::GitSigning,
        description: "Disable commit signing (private keys inaccessible)",
    },
    HardeningEnvVar {
        name: "GIT_CONFIG_KEY_1",
        value: "tag.gpgsign",
        category: HardeningCategory::GitSigning,
        description: "Override tag signing config key",
    },
    HardeningEnvVar {
        name: "GIT_CONFIG_VALUE_1",
        value: "false",
        category: HardeningCategory::GitSigning,
        description: "Disable tag signing (private keys inaccessible)",
    },
];

/// Files within `~/.gnupg/` that are safe to expose read-only for GPG signing.
/// These contain public key material and configuration — no secrets.
/// Private keys (`private-keys-v1.d/`) are never exposed.
pub const GPG_SIGNING_ALLOW_FILES: &[&str] = &[
    "pubring.kbx", // Public key database (GnuPG 2.x)
    "pubring.gpg", // Public key database (GnuPG 1.x legacy)
    "trustdb.gpg", // Trust metadata (who signed what)
    "gpg.conf",    // User GPG configuration
    "common.conf", // Shared config (GnuPG 2.3+)
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
        path: ".pyenv",
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
        path: ".konan",
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
    // Yarn Berry global cache: packages only, no executables
    HomeToolDir {
        path: ".yarn",
        process_exec: false,
        map_exec: false,
        write: true,
    },
    // Build caches: broad access with deny rules for non-dev caches.
    // Non-dev cache dirs (browsers, system apps) are denied in the generated
    // profile using DENIED_CACHE_PREFIXES regex patterns. NO exec (RAT staging risk).
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

/// Return the platform-appropriate home tool directory list.
///
/// macOS uses `HOME_TOOL_DIRS` (includes `Library/Caches`, `Library/pnpm`).
/// Linux uses `LINUX_HOME_TOOL_DIRS` (includes `.cache`, `.local/share/pnpm`).
pub fn home_tool_dirs() -> &'static [HomeToolDir] {
    #[cfg(target_os = "macos")]
    {
        HOME_TOOL_DIRS
    }
    #[cfg(target_os = "linux")]
    {
        super::landlock_mod::LINUX_HOME_TOOL_DIRS
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        HOME_TOOL_DIRS
    }
}

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
