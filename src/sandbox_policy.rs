//! Sandbox policy constants, deny lists, and environment allowlists.
//!
//! Defines the security policy shared by macOS Seatbelt and Linux Landlock:
//! path validation, tool directory permissions, and hardening env vars.

use directories::ProjectDirs;
use std::path::{Path, PathBuf};

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

/// Credential files inside otherwise-allowed HOME_TOOL_DIRS.
/// These are denied by default because they typically contain registry
/// credentials (Nexus/Artifactory passwords, API tokens, master passwords).
/// Unlike DENIED_FILES, these can be overridden with `--allow-read` or
/// `allow.read` in config.toml for developers using private registries.
///
/// On Linux (Landlock), this deny is NOT enforceable — Landlock cannot deny
/// subpaths within allowed directories. See SECURITY.md for details.
pub const DENIED_HOME_SUBPATHS: &[&str] = &[
    ".m2/settings.xml",
    ".m2/settings-security.xml",
    ".gradle/gradle.properties",
    ".cargo/credentials",
    ".cargo/credentials.toml",
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
    "/Library/Java/JavaVirtualMachines",
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
    // Terminal — base capabilities
    "TERM",
    "COLORTERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "COLUMNS",
    "LINES",
    // Terminal multiplexers — without these, Copilot (Node.js/ink) doesn't know it's
    // inside a multiplexer and sends bare OSC 10/11 color queries. The multiplexer
    // intercepts the queries but can't deliver the response back to the process,
    // so the raw response bytes appear on screen and the process hangs.
    "TMUX",                // tmux: socket path (e.g. /tmp/tmux-1000/default,1234,0)
    "TMUX_PANE",           // tmux: pane identifier (e.g. %0)
    "STY",                 // GNU screen: session name
    "ZELLIJ",              // Zellij: present when running inside Zellij
    "ZELLIJ_SESSION_NAME", // Zellij: session name
    // Terminal emulator identification — lets Copilot/Node.js detect color/feature
    // support without falling back to OSC color queries.
    "VTE_VERSION",           // GNOME Terminal, Tilix, Terminator (VTE-based)
    "KITTY_WINDOW_ID",       // Kitty terminal
    "WEZTERM_PANE",          // WezTerm
    "GHOSTTY_RESOURCES_DIR", // Ghostty terminal (shell integration resources)
    // OSC 8 hyperlink support — allows terminals to render clickable links.
    // Without this, tools like ink/supports-hyperlinks can't detect hyperlink
    // capability when their bundled detection doesn't know the terminal.
    "FORCE_HYPERLINK",
    // Path
    "PATH",
    // Copilot auth — accepted trade-off: Copilot needs a GitHub token to function.
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "COPILOT_GITHUB_TOKEN",
    // XDG directories
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
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
    // Docker/Podman/Testcontainers
    "DOCKER_HOST",                  // Socket URL (e.g. unix:///var/run/docker.sock)
    "CONTAINER_HOST",               // Podman equivalent of DOCKER_HOST
    "TESTCONTAINERS_RYUK_DISABLED", // Testcontainers config
    // Rust
    "CARGO_HOME",
    "RUSTUP_HOME",
    // Python
    "VIRTUAL_ENV",
    "PYTHONPATH",
    "PYENV_ROOT",              // pyenv install location
    "ASDF_DIR",                // asdf install directory
    "ASDF_DATA_DIR",           // asdf data directory (installs, shims)
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
    "LC_",             // Locale
    "COPILOT_",        // Copilot-specific config
    "COREPACK_",       // Node.js Corepack (package manager manager)
    "JENV_",           // jenv (Java version manager)
    "ASDF_",           // asdf version manager
    "MISE_",           // mise tool manager
    "NVM_",            // nvm
    "PYENV_",          // pyenv (Python version manager)
    "SDKMAN_",         // SDKMAN (Java version manager)
    "TESTCONTAINERS_", // Testcontainers configuration
    "YARN_",           // Yarn Berry config (hardening injection overrides YARN_ENABLE_SCRIPTS)
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
#[non_exhaustive]
pub enum HardeningCategory {
    /// Block npm/yarn/pnpm `postinstall` hooks — the #1 supply chain entry point.
    LifecycleScripts,
    /// Prevent git from prompting or leaking credentials interactively.
    GitHardening,
    /// Disable commit/tag signing inside the sandbox. Separated from GitHardening
    /// so `--allow-gpg-signing` can re-enable signing without removing
    /// `GIT_TERMINAL_PROMPT=0`.
    GitSigning,
    /// Always-on markers that signal "you're inside the sandbox". Never disabled.
    SandboxMarker,
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
    // Trust lock — prevents `cplt trust` from running inside the sandbox.
    // The agent cannot approve its own proposals.
    HardeningEnvVar {
        name: "__CPLT_TRUST_LOCKED",
        value: "1",
        category: HardeningCategory::SandboxMarker,
        description: "Block cplt trust commands inside sandbox",
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

/// Application directory kinds according to relevant platform specifications.
/// See https://docs.rs/directories for more details
pub enum AppDirKind {
    /// macOS: `~/Library/Caches/<app>` · Linux/macOS when using XDG: `~/.cache/<app>`
    Cache,
    /// macOS: `~/Library/Application Support/<app>` · Linux/macOS when using XDG: `~/.config/<app>`
    Config,
    /// macOS: `~/Library/Application Support/<app>` · Linux/macOS when using XDG: `~/.config/<app>`
    ConfigLocal,
    /// macOS: `~/Library/Application Support/<app>` · Linux/macOS when using XDG: `~/.local/share/<app>`
    Data,
    /// macOS: `~/Library/Application Support/<app>` · Linux/macOS when using XDG: `~/.local/share/<app>`
    DataLocal,
    /// macOS: `~/Library/Preferences/<app>` · Linux/macOS when using XDG: `~/.config/<app>`
    Preference,
    /// macOS: None · Linux: `/run/user/<uid>/<app>` (via `XDG_RUNTIME_DIR`)
    Runtime,
    /// macOS: None · Linux/macOS when using XDG: `~/.local/state/<app>`
    State,
}

impl AppDirKind {
    pub fn resolve(
        &self,
        qualifier: &str,
        organization: &str,
        application: &str,
        home_dir: &std::path::Path,
    ) -> Option<PathBuf> {
        let project_dir = ProjectDirs::from(qualifier, organization, application)?;
        let use_xdg = qualifier.is_empty();
        type Lookup = (
            &'static str,
            &'static str,
            fn(project_dir: ProjectDirs) -> Option<PathBuf>,
        );
        let lookup: Lookup = match self {
            AppDirKind::Cache => ("XDG_CACHE_HOME", ".cache", |project_dir| {
                Some(project_dir.cache_dir().to_owned())
            }),
            AppDirKind::Config => ("XDG_CONFIG_HOME", ".config", |project_dir| {
                Some(project_dir.config_dir().to_owned())
            }),
            AppDirKind::ConfigLocal => ("XDG_CONFIG_HOME", ".config", |project_dir| {
                Some(project_dir.config_local_dir().to_owned())
            }),
            AppDirKind::Data => ("XDG_DATA_HOME", ".local/share", |project_dir| {
                Some(project_dir.data_dir().to_owned())
            }),
            AppDirKind::DataLocal => ("XDG_DATA_HOME", ".local/share", |project_dir| {
                Some(project_dir.data_local_dir().to_owned())
            }),
            AppDirKind::Preference => ("XDG_CONFIG_HOME", ".config", |project_dir| {
                Some(project_dir.preference_dir().to_owned())
            }),
            AppDirKind::Runtime => ("XDG_RUNTIME_DIR", "", |project_dir| {
                project_dir.runtime_dir().map(ToOwned::to_owned)
            }),
            AppDirKind::State => ("XDG_STATE_HOME", ".local/state", |project_dir| {
                project_dir.state_dir().map(ToOwned::to_owned)
            }),
        };
        if use_xdg {
            let xdg_dir = std::env::var_os(lookup.0)
                .filter(|v| !v.as_encoded_bytes().trim_ascii().is_empty())
                .map(PathBuf::from)
                .or_else(|| {
                    if lookup.1.is_empty() {
                        None
                    } else {
                        Some(home_dir.join(lookup.1))
                    }
                })?
                .join(application);
            // Security: reject relative XDG paths. A relative value would produce a
            // relative sandbox path, potentially widening access beyond the intended
            // directory (e.g. path traversal via a malicious XDG env var).
            if !xdg_dir.is_absolute() {
                eprintln!(
                    "Ignoring relative XDG-directory {} from env-variable {:?}",
                    xdg_dir.display(),
                    lookup.0
                );
                return None;
            }
            Some(xdg_dir)
        } else {
            lookup.2(project_dir)
        }
    }
}

/// Application directories with granular sandbox permissions.
///
/// The fields control permissions given to each application directory kind:
/// - `process_exec`: allow direct binary execution (`process-exec`)
/// - `map_exec`: allow shared library loading (`file-map-executable`) for native addons
/// - `write`: allow file writes (`file-write*`) for build caches, dependency stores, etc.
/// - `read`: allow file reads (`file-read*`) for configuration, etc.
///
/// Security principle: every writable+executable directory is a potential
/// binary-drop staging path (see SECURITY.md axios case study). Grant exec
/// only where tools genuinely install executables.
pub struct AppDir {
    pub qualifier: &'static str,
    pub organization: &'static str,
    pub application: &'static str,
    pub process_exec: &'static [AppDirKind],
    pub map_exec: &'static [AppDirKind],
    pub write: &'static [AppDirKind],
    pub read: &'static [AppDirKind],
}

impl AppDir {
    /// Resolve `kinds` to paths, deduplicating while preserving order.
    fn resolve_dedup(&self, kinds: &[AppDirKind], home_dir: &Path) -> Vec<PathBuf> {
        let mut seen = std::collections::HashSet::new();
        kinds
            .iter()
            .filter_map(|k| {
                k.resolve(
                    self.qualifier,
                    self.organization,
                    self.application,
                    home_dir,
                )
            })
            .filter(|p| seen.insert(p.clone()))
            .collect()
    }

    pub fn process_exec_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        self.resolve_dedup(self.process_exec, home_dir)
    }

    pub fn map_exec_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        self.resolve_dedup(self.map_exec, home_dir)
    }

    pub fn write_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        self.resolve_dedup(self.write, home_dir)
    }

    pub fn read_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        self.resolve_dedup(self.read, home_dir)
    }

    /// Union of all category paths, deduplicated.
    pub fn all_paths(&self, home_dir: &std::path::Path) -> Vec<PathBuf> {
        let mut seen = std::collections::HashSet::new();
        let mut paths = Vec::new();
        for p in self
            .process_exec_paths(home_dir)
            .into_iter()
            .chain(self.map_exec_paths(home_dir))
            .chain(self.write_paths(home_dir))
            .chain(self.read_paths(home_dir))
        {
            if seen.insert(p.clone()) {
                paths.push(p);
            }
        }
        paths
    }
}

pub const DEFAULT_WRITE_APP_DIRS: &[AppDirKind] = &[
    AppDirKind::Cache,
    AppDirKind::Data,
    AppDirKind::DataLocal,
    AppDirKind::Runtime,
    AppDirKind::State,
];

pub const DEFAULT_READ_APP_DIRS: &[AppDirKind] = &[
    AppDirKind::Cache,
    AppDirKind::Config,
    AppDirKind::ConfigLocal,
    AppDirKind::Data,
    AppDirKind::DataLocal,
    AppDirKind::Preference,
    AppDirKind::Runtime,
    AppDirKind::State,
];

pub const APP_DIRS: &[AppDir] = &[
    AppDir {
        qualifier: "",
        organization: "",
        application: "mise",
        process_exec: &[AppDirKind::Data, AppDirKind::DataLocal],
        map_exec: &[AppDirKind::Data, AppDirKind::DataLocal],
        write: DEFAULT_WRITE_APP_DIRS,
        read: DEFAULT_READ_APP_DIRS,
    },
    AppDir {
        qualifier: "",
        organization: "",
        application: "pnpm",
        process_exec: &[AppDirKind::Data, AppDirKind::DataLocal],
        map_exec: &[AppDirKind::Data, AppDirKind::DataLocal],
        write: DEFAULT_WRITE_APP_DIRS,
        read: DEFAULT_READ_APP_DIRS,
    },
];

/// Return the application directory list.
///
/// A single unified list covers both macOS and Linux paths. Some entries may
/// not exist on a given platform or system, but they remain in the shared list
/// and are handled by the platform-specific sandbox implementations at runtime.
pub fn app_dirs() -> &'static [AppDir] {
    APP_DIRS
}

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
///
/// **IMPORTANT: This is the single source of truth for both macOS (SBPL) and
/// Linux (Landlock) sandboxes.** Do NOT create platform-specific lists.
/// Include both macOS paths (e.g. `Library/Caches`) and XDG paths (e.g. `.cache`)
/// in this one list — entries for paths that don't exist on a given platform
/// are harmlessly skipped at runtime (the profile generator checks existence).
///
/// NOTE: Only tool/binary dirs, never source code dirs.
/// ~/go/src is intentionally excluded — it contains other repos.
pub const HOME_TOOL_DIRS: &[HomeToolDir] = &[
    // ── Version managers & runtimes: exec only, no write ──────────────────
    // Pre-installed toolchains managed outside the sandbox (mise, nvm, rustup, etc.).
    // Agent needs to run their binaries but should not modify installations.
    // XDG user bin directory — standard location for user-installed executables
    // (pip install --user, pipx, manually installed tools). Only the bin dir
    // needs exec; other .local subdirs are covered by AppDirs or don't need exec.
    HomeToolDir {
        path: ".local/bin",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    // Legacy mise location — many users still have ~/.mise from before the XDG
    // migration. The AppDir entry covers ~/.local/share/mise (XDG), but this
    // legacy path must remain to avoid breaking existing installations.
    HomeToolDir {
        path: ".mise",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    HomeToolDir {
        path: ".asdf",
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
        path: ".cargo/bin",
        process_exec: true,
        map_exec: true,
        // Installed tools (cargo-fmt, cargo-clippy, etc.) managed by rustup.
        // Read-only: prevents a rogue agent from trojaning binaries that persist
        // across sandbox sessions.
        write: false,
    },
    HomeToolDir {
        path: ".cargo/registry",
        process_exec: false,
        map_exec: true,
        // Crate registry cache — cargo build downloads and extracts crates here.
        // map-exec needed for proc-macro dylibs and -sys crate native libs.
        write: true,
    },
    HomeToolDir {
        path: ".cargo/git",
        process_exec: false,
        map_exec: true,
        // Git dependency checkouts — cargo build clones git deps here.
        write: true,
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
        path: ".jenv",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    HomeToolDir {
        path: ".deno",
        process_exec: true,
        map_exec: true,
        write: true,
    },
    HomeToolDir {
        path: ".bun",
        process_exec: true,
        map_exec: true,
        write: true,
    },
    HomeToolDir {
        path: "go/bin",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    // ── Dependency stores: write + map-exec, no direct exec ────────────────
    // Downloaded packages (JARs, native libs, compiled modules) that build tools
    // write during dependency resolution. Write is required; map-exec is needed
    // for JNI/cgo native libraries. No process-exec (deps aren't standalone bins).
    // Sensitive files within these dirs are blocked via DENIED_HOME_SUBPATHS.
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
        // Go module cache — `go test`, `go get`, etc. need to download/extract
        // modules and update the sum DB cache here.
        write: true,
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
    // XDG cache (Linux equivalent of Library/Caches)
    HomeToolDir {
        path: ".cache",
        process_exec: false,
        map_exec: false,
        write: true,
    },
    // pnpm global store: contains packages + executable shims
    // macOS-native path not following conventions set out by AppDirs
    HomeToolDir {
        path: "Library/pnpm",
        process_exec: true,
        map_exec: true,
        write: true,
    },
    // Kotlin compiler daemon: client marker files and run files.
    // The Kotlin Maven/Gradle plugin uses this for daemon lifecycle management.
    // XDG path (Linux, some macOS setups)
    HomeToolDir {
        path: ".local/share/kotlin",
        process_exec: false,
        map_exec: false,
        write: true,
    },
    // macOS-native path
    HomeToolDir {
        path: "Library/Application Support/kotlin",
        process_exec: false,
        map_exec: false,
        write: true,
    },
];

/// Return the home tool directory list.
///
/// A single unified list covers both macOS and Linux paths. Entries for
/// paths that don't exist on a given platform are harmlessly skipped because
/// `discover.rs` filters them via `existing_home_tool_dirs` before they reach
/// the profile generator.
pub fn home_tool_dirs() -> &'static [HomeToolDir] {
    HOME_TOOL_DIRS
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rejects_relative_xdg_cache_home() {
        // A relative XDG_CACHE_HOME must be rejected to prevent sandbox path widening.
        let home = std::path::Path::new("/tmp/fakehome");
        temp_env::with_var("XDG_CACHE_HOME", Some("relative/path"), || {
            let result = AppDirKind::Cache.resolve("", "", "myapp", home);
            assert!(
                result.is_none(),
                "resolve() must return None for a relative XDG path, got: {result:?}"
            );
        });
    }

    #[test]
    fn resolve_falls_back_when_xdg_cache_home_is_empty() {
        // An empty XDG_CACHE_HOME must be treated as unset so the home-dir default fires.
        let home = std::path::Path::new("/tmp/fakehome");
        temp_env::with_var("XDG_CACHE_HOME", Some(""), || {
            let result = AppDirKind::Cache.resolve("", "", "myapp", home);
            assert_eq!(
                result,
                Some(home.join(".cache/myapp")),
                "resolve() must fall back to home/.cache/<app> when XDG_CACHE_HOME is empty"
            );
        });
    }

    #[test]
    fn write_paths_deduplicates_when_data_and_data_local_resolve_identically() {
        // On Linux with XDG defaults, Data and DataLocal both resolve to
        // ~/.local/share/<app>. write_paths() must return the path only once.
        let home = std::path::Path::new("/tmp/fakehome");
        temp_env::with_vars(
            [
                ("XDG_DATA_HOME", None::<&str>),
                ("XDG_CACHE_HOME", None),
                ("XDG_STATE_HOME", None),
                ("XDG_RUNTIME_DIR", None),
            ],
            || {
                let app_dir = AppDir {
                    qualifier: "",
                    organization: "",
                    application: "testapp",
                    process_exec: &[],
                    map_exec: &[],
                    write: &[AppDirKind::Data, AppDirKind::DataLocal],
                    read: &[],
                };
                let paths = app_dir.write_paths(home);
                assert_eq!(
                    paths.len(),
                    1,
                    "write_paths() must deduplicate identical Data/DataLocal paths, got: {paths:?}"
                );
                assert_eq!(paths[0], home.join(".local/share/testapp"));
            },
        );
    }

    #[test]
    fn resolve_accepts_absolute_xdg_cache_home() {
        let home = std::path::Path::new("/tmp/fakehome");
        temp_env::with_var("XDG_CACHE_HOME", Some("/tmp/test-cache"), || {
            let result = AppDirKind::Cache.resolve("", "", "myapp", home);
            assert!(
                result.is_some(),
                "resolve() must return Some for an absolute XDG path"
            );
            assert!(result.unwrap().is_absolute());
        });
    }
}
