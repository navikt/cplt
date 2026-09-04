//! Sandbox policy constants, deny lists, and environment allowlists.
//!
//! Defines the security policy shared by macOS Seatbelt and Linux Landlock:
//! path validation, tool directory permissions, and hardening env vars.

use crate::agent::Agent;
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
pub const DENIED_FILES: &[&str] = &[".netrc", ".pypirc", ".gem/credentials", ".vault-token"];

/// The [`DENIED_FILES`] entry `path` names, if any.
///
/// Hard denies are absolute: unlike [`DENIED_HOME_SUBPATHS`], no `allow.read`
/// (or `allow.write`, or `allow.socket`) grant may re-open them. Both backends
/// consult this — macOS to keep the SBPL deny authoritative, Linux to keep the
/// path out of the grant-only Landlock ruleset, where an added grant would
/// simply win.
///
/// Exact paths only. A grant on an *ancestor* (`~/.gem`, or `$HOME` itself)
/// still exposes the file on Linux: Landlock cannot deny a subpath inside an
/// allowed directory, the same limitation [`DENIED_HOME_SUBPATHS`] documents.
///
/// Both sides are canonicalized because grants arrive canonicalized
/// (`--allow-read` through `canonicalize_paths`, config `allow.read` through
/// `resolve_config_path`) while `$HOME/.netrc` may be a symlink into a
/// dotfiles repo — comparing the unresolved forms would miss the match.
pub fn hard_denied_file(home: &Path, path: &Path) -> Option<&'static str> {
    denied_entry(DENIED_FILES, home, path)
}

/// The [`DENIED_DOTFILES`] directory `path` names, if any.
///
/// Exact directory match only. A path *inside* one of these directories is a
/// supported override on both backends — macOS re-allows it after the blanket
/// deny (`emit_denied_dotfile_overrides`), Linux emits it as a plain rule — and
/// must not match here.
///
/// The directory itself is refused (#291). macOS could never honour it: the
/// generic `allow.read` is emitted before the subpath deny and loses to it, so
/// the grant sat in config looking effective and did nothing. Linux did honour
/// it, handing an agent every key in `~/.ssh` on the strength of one config
/// line. Refusing is the only answer both backends give alike, and it leaves
/// the per-file grant — which works on both — as the way in.
///
/// Canonicalized on both sides for the same reason [`hard_denied_file`] is:
/// grants arrive canonicalized while `~/.ssh` may be a symlink into a dotfiles
/// repo, and comparing the unresolved forms would miss the match.
///
/// `--allow-docker`'s read-only `~/.docker` grant is unaffected: it is a
/// first-party rule emitted by the backends, never a user grant on this path.
pub fn denied_dotfile_dir(home: &Path, path: &Path) -> Option<&'static str> {
    denied_entry(DENIED_DOTFILES, home, path)
}

/// Whether a grant on `path` must never reach a backend ruleset.
///
/// `sandbox::prepare` refuses both classes before a run starts; the backends
/// consult this too, so the invariant holds for every caller of
/// `generate_policy` and not only the ones that went through `prepare`.
#[must_use]
pub fn grant_is_refused(home: &Path, path: &Path) -> bool {
    hard_denied_file(home, path).is_some() || denied_dotfile_dir(home, path).is_some()
}

/// Exact-path membership of `path` in a `$HOME`-relative deny list, comparing
/// the literal and the canonicalized form.
fn denied_entry(list: &[&'static str], home: &Path, path: &Path) -> Option<&'static str> {
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let resolved = canon(path);
    list.iter().copied().find(|f| {
        let denied = home.join(f);
        path == denied || resolved == canon(&denied)
    })
}

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
    // NuGet.Config can contain <packageSourceCredentials> with plaintext registry passwords.
    // Same threat model as .m2/settings.xml — override with allow.read if private registry needed.
    ".nuget/NuGet.Config",
    // .npmrc is a top-level file, but belongs here so it can be overridden via --allow-read
    // if the user needs to access a private npm registry (unlike hard-denied dotfiles).
    ".npmrc",
];

/// Real UID of this process.
///
/// Used only to spell per-user runtime paths (`/run/user/<uid>/…`) in the
/// policy. `getuid(2)` has no failure mode.
pub fn current_uid() -> u32 {
    // SAFETY: getuid() takes no arguments, touches no memory, and always
    // succeeds.
    unsafe { libc::getuid() }
}

/// Pathname UNIX-socket paths that must be mount-masked on Linux.
///
/// # Why this exists
///
/// Landlock cannot gate `connect(2)` to a **pathname** UNIX socket before ABI
/// v9 (kernel 7.1) — `AccessFs::ResolveUnix` simply does not exist below that,
/// and a read-only bind mount does not stop `connect()` either (the `MS_RDONLY`
/// check runs in `mnt_want_write()`, which UNIX-socket connect never calls; it
/// only needs inode write permission via DAC). seccomp cannot help: the socket
/// path lives behind a pointer argument, which BPF cannot dereference.
///
/// So on every kernel below 7.1 — i.e. essentially every deployed kernel today
/// (Ubuntu 24.04 = 6.8, Debian 13 = 6.12, Fedora 42 ≈ 6.15) — the only thing
/// that can take these sockets away from the agent is making them *not present
/// in its mount namespace*. That is Bubblewrap's job, and **only** Bubblewrap's:
/// when bwrap is absent, disabled, or falls back at spawn time, none of this
/// applies and the sockets are reachable.
///
/// # Why these paths
///
/// Each one hands out arbitrary code execution **outside** the sandbox, because
/// the service on the other end is not a descendant of the sandboxed process
/// and therefore inherits neither the Landlock domain, the seccomp filter, nor
/// the namespaces:
///
/// - `/run/user/<uid>/bus`, `/run/dbus/system_bus_socket` — the D-Bus session
///   and system buses. `systemd-run --user` (or hand-rolled D-Bus) starts a
///   unit as the user, unsandboxed.
/// - `/run/user/<uid>/systemd` — systemd's private socket
///   (`.../systemd/private`), same escape without going through D-Bus.
/// - Docker/Podman daemon sockets — socket access is effectively host root.
///
/// `allow_docker` punches through the container-runtime entries only (#155):
/// the D-Bus and systemd masks are never lifted. On Linux `--allow-docker` was
/// previously a documented no-op; it now means three things — *do not mask
/// the daemon sockets*, *grant Landlock read+write on them* (see
/// [`linux_docker_socket_paths`]) so `connect(2)` still works once the kernel
/// gates it at ABI v9, and *grant `~/.docker` read-only* so the CLI finds its
/// contexts and registry auth. It grants nothing else.
///
/// Abstract-namespace sockets have no path and cannot be masked this way; they
/// are covered (kernel ≥ 6.12 only) by `Scope::AbstractUnixSocket`.
///
/// The runtime-dir entries are produced for every directory
/// [`linux_runtime_dirs`] returns, so a host whose `$XDG_RUNTIME_DIR` is not
/// `/run/user/<uid>` gets its real bus masked rather than a path nobody uses.
pub fn socket_mask_paths(
    uid: u32,
    xdg_runtime_dir: Option<&Path>,
    allow_docker: bool,
) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = linux_runtime_dirs(uid, xdg_runtime_dir)
        .iter()
        .flat_map(|d| [d.join("bus"), d.join("systemd")])
        .collect();
    paths.push(PathBuf::from("/run/dbus/system_bus_socket"));
    if !allow_docker {
        paths.extend(linux_docker_socket_paths(uid, xdg_runtime_dir));
    }
    paths
}

/// The runtime directories a session socket can live in: systemd's
/// `/run/user/<uid>` plus `$XDG_RUNTIME_DIR` when it points somewhere else.
///
/// # Why the environment is consulted at all
///
/// Everything that finds a session socket — D-Bus, systemd, rootless Podman,
/// modern GnuPG — reads `$XDG_RUNTIME_DIR`, and cplt passes that variable
/// through to the agent (`ENV_ALLOWLIST`). A mask list or an ABI-v9 grant
/// keyed only on `/run/user/<uid>` therefore covers a path the agent may not
/// be using: the mask is dropped as non-existent, the launch banner still says
/// the escape sockets are masked, and the real bus stays reachable. That is a
/// control that looks present and is absent, which is the whole subject of
/// #240.
///
/// # Why it is safe to consult
///
/// The list is **additive**: `/run/user/<uid>` is always first and is never
/// dropped, so a poisoned `XDG_RUNTIME_DIR` can only add a mask, never remove
/// one. Relative values are rejected, matching [`AppDirKind::resolve`] — a
/// relative path here would produce a relative mask or grant.
///
/// The value is read from cplt's own (parent) environment, before the agent
/// exists. An attacker who can set it already controls the invocation.
pub fn linux_runtime_dirs(uid: u32, xdg_runtime_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from(format!("/run/user/{uid}"))];
    match xdg_runtime_dir {
        Some(p) if p.is_absolute() && !dirs.iter().any(|d| d == p) => dirs.push(p.to_path_buf()),
        _ => {}
    }
    dirs
}

/// `$XDG_RUNTIME_DIR` from cplt's own environment, for the call sites that
/// feed [`linux_runtime_dirs`]. Read once at the top of policy construction so
/// the path functions below stay pure and testable.
pub fn xdg_runtime_dir_env() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.as_encoded_bytes().trim_ascii().is_empty())
        .map(PathBuf::from)
}

/// Docker/Podman daemon endpoints on Linux.
///
/// Two uses, deliberately sharing one list so they cannot drift: they are
/// mount-masked when `--allow-docker` is off (see [`socket_mask_paths`]), and
/// granted as Landlock read+write rules when it is on — which is what makes
/// `--allow-docker` mean something on Linux for the first time (#155).
///
/// The grant is not a widening on kernels below 7.1: there, `connect(2)` to a
/// pathname socket needs no Landlock right at all, so an ungranted socket was
/// already reachable. It matters from ABI v9 up, where an ungranted socket
/// would otherwise be refused.
///
/// Directory entries (`.../podman`) are intentional: Podman's socket sits at
/// `<dir>/podman.sock`, and a `PathBeneath` rule covers the subtree.
///
/// `~/.docker` is not a socket and not in this list; it is in
/// [`DENIED_DOTFILES`] and gets its own read-only Landlock rule under
/// `--allow-docker` (see `sandbox_landlock.rs`), mirroring the macOS profile.
pub fn linux_docker_socket_paths(uid: u32, xdg_runtime_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("/run/docker.sock"),
        PathBuf::from("/var/run/docker.sock"),
    ];
    paths.extend(
        linux_runtime_dirs(uid, xdg_runtime_dir)
            .iter()
            .flat_map(|d| [d.join("docker.sock"), d.join("podman")]),
    );
    paths.push(PathBuf::from("/run/podman"));
    paths
}

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
    // Xcode.app developer tools — needed when xcode-select points to the full
    // Xcode install instead of standalone CommandLineTools. /usr/bin/git and
    // other shims load libxcrun.dylib from this path.
    "/Applications/Xcode.app/Contents/Developer",
    "/Library/Java/JavaVirtualMachines",
];

/// Suffixes of env var names that indicate secrets/credentials.
/// Vars matching a prefix allowlist entry BUT also matching one of these
/// suffixes are stripped — deny wins. Prevents `YARN_NPM_AUTH_TOKEN`,
/// `COPILOT_SECRET_KEY`, etc. from leaking through broad prefix rules.
///
/// `_IDENT` is included because Yarn Berry's `YARN_NPM_AUTH_IDENT` holds a
/// base64-encoded `user:password` registry credential; without this suffix it
/// would pass through the `YARN_` prefix allowlist and leak to the sandboxed
/// agent in default sanitized mode.
const ENV_PREFIX_DENY_SUFFIXES: &[&str] = &[
    "_TOKEN",
    "_AUTH",
    "_SECRET",
    "_SECRET_KEY",
    "_KEY",
    "_PASSWORD",
    "_CREDENTIALS",
    "_IDENT",
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

/// Fixed macOS parent for cplt-owned Playwright control sockets.
pub const PLAYWRIGHT_SOCKET_ROOT: &str = "/private/tmp";
/// Prefix followed by a 128-bit lowercase hexadecimal session ID.
pub const PLAYWRIGHT_SOCKET_DIR_PREFIX: &str = "cplt-pw-";
/// Conservative budget for the cplt-controlled portion of a Playwright socket path.
///
/// Playwright core 1.63.0-alpha-2026-08-31 appends a domain directory and,
/// in its longest fallback form, `/dashboard/<16 lowercase hex>.sock` (32
/// bytes). Keeping the base at 64 bytes or less leaves at least six spare bytes
/// under Playwright's strict 103-byte Unix-socket limit.
pub const PLAYWRIGHT_SOCKET_BASE_MAX_BYTES: usize = 64;
pub const PLAYWRIGHT_SOCKET_PATH_LIMIT: usize = 103;
pub const PLAYWRIGHT_SOCKET_WORST_CASE_SUFFIX: &str = "/dashboard/0123456789abcdef.sock";

/// Whether cache execution explicitly opts into the Playwright browser runtime.
///
/// This intent gates both Chromium's additional macOS runtime permissions and
/// Playwright-specific child environment setup. `allow_cache_exec_any` is
/// deliberately ignored: broad cache execution must not imply browser runtime
/// intent.
pub fn playwright_runtime_intent(allow_cache_exec: &[String], _allow_cache_exec_any: bool) -> bool {
    allow_cache_exec
        .iter()
        .any(|entry| entry == "ms-playwright" || entry.starts_with("ms-playwright/"))
}

/// Validate the exact shape of a cplt-owned Playwright socket directory.
///
/// This is the authorization boundary for SBPL interpolation: callers cannot
/// turn the dedicated capability into a grant for a parent, sibling, project,
/// scratch, or caller-selected path.
pub fn validate_playwright_socket_dir(path: &Path) -> Result<(), String> {
    validate_sbpl_path(path)?;

    let Some(path_str) = path.to_str() else {
        return Err("Playwright socket dir must be valid UTF-8".to_string());
    };
    if path.as_os_str().len() > PLAYWRIGHT_SOCKET_BASE_MAX_BYTES {
        return Err(format!(
            "Playwright socket dir exceeds the {PLAYWRIGHT_SOCKET_BASE_MAX_BYTES}-byte safety budget"
        ));
    }
    if path.parent() != Some(Path::new(PLAYWRIGHT_SOCKET_ROOT)) {
        return Err(format!(
            "Playwright socket dir must be directly under {PLAYWRIGHT_SOCKET_ROOT}"
        ));
    }

    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err("Playwright socket dir must have an ASCII file name".to_string());
    };
    let Some(session_id) = name.strip_prefix(PLAYWRIGHT_SOCKET_DIR_PREFIX) else {
        return Err("Playwright socket dir has an invalid prefix".to_string());
    };
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "Playwright socket dir must end in exactly 32 lowercase hexadecimal characters"
                .to_string(),
        );
    }

    let worst_case_len = path_str.len() + PLAYWRIGHT_SOCKET_WORST_CASE_SUFFIX.len();
    if worst_case_len >= PLAYWRIGHT_SOCKET_PATH_LIMIT {
        return Err(format!(
            "Playwright socket path would reach {worst_case_len} bytes, but must stay below {PLAYWRIGHT_SOCKET_PATH_LIMIT}"
        ));
    }
    Ok(())
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
    "npm_config_cache",  // npm's canonical lowercase spelling of the cache path
    "YARN_CACHE_FOLDER", // Yarn global cache location (also matches YARN_ prefix)
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
    "PIP_CACHE_DIR",           // pip download/wheel cache location
    // pnpm
    "PNPM_HOME",             // pnpm binary location
    "NPM_CONFIG_USERCONFIG", // path to a custom .npmrc file (not the file itself — no auth tokens)
    // .NET / dotnet CLI
    "DOTNET_CLI_HOME", // override dotnet CLI state dir (default ~/.dotnet)
    // override SDK install location (e.g. Homebrew /usr/local/share/dotnet, or
    // ~/hostedtoolcache via actions/setup-dotnet — the same path also grants
    // sandbox read/dylib access, see sandbox_profile.rs's emit_dotnet_root).
    "DOTNET_ROOT",
    // Locale
    "LANG",
    "LANGUAGE",
    // Editor
    "EDITOR",
    "VISUAL",
    "PAGER",
    // GPG — terminal device path for pinentry (not sensitive, e.g. "/dev/ttys001")
    "GPG_TTY",
    // Claude Code — config root override (path, not a secret). Must reach the
    // child so it uses the same dir Agent::Claude.config_dirs() grants.
    "CLAUDE_CONFIG_DIR",
];

/// Environment variable prefixes safe to pass through.
pub const ENV_PREFIX_ALLOWLIST: &[&str] = &[
    "LC_",             // Locale
    "COPILOT_",        // Copilot-specific config
    "COREPACK_",       // Node.js Corepack (package manager manager)
    "JENV_",           // jenv (Java version manager)
    "ASDF_",           // asdf version manager
    "MISE_",           // mise tool manager
    "FNM_",            // fnm (Fast Node Manager)
    "NVM_",            // nvm
    "PYENV_",          // pyenv (Python version manager)
    "SDKMAN_",         // SDKMAN (Java version manager)
    "TESTCONTAINERS_", // Testcontainers configuration
    "YARN_",           // Yarn Berry config (hardening injection overrides YARN_ENABLE_SCRIPTS)
    "AGY_",            // Antigravity CLI runtime configuration
    // OpenTelemetry vendor-neutral configuration (OTEL_SERVICE_NAME, OTEL_EXPORTER_OTLP_ENDPOINT,
    // OTEL_EXPORTER_OTLP_PROTOCOL, OTEL_RESOURCE_ATTRIBUTES, OTEL_LOG_LEVEL, etc.).
    // OTEL_EXPORTER_OTLP_HEADERS may carry opt-in auth headers (e.g. "Authorization=Bearer
    // <token>"); this is an accepted trade-off in the same class as GH_TOKEN — only present
    // when the user has explicitly configured an exporter. The is_secret_suffix deny-list
    // still strips any OTEL_*_TOKEN / _AUTH / _SECRET / _KEY / _PASSWORD / _CREDENTIALS vars.
    "OTEL_",
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
    "GOCACHE",  // Go build cache (compiled test binaries need exec)
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
    /// Opt-out signals for developer tooling telemetry (build tools, CLIs, editors).
    /// These prevent analytics beacons from reaching external services. Tools still
    /// function normally — only non-essential telemetry collection is disabled.
    TelemetryOptOut,
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
    // The system git config (/etc/gitconfig) is not in the Landlock read
    // allowlist. When it exists — as on Debian/Ubuntu and every GitHub Actions
    // runner — git hits EACCES (not ENOENT) and aborts every command with
    // "fatal: unknown error occurred while reading the configuration files".
    // Skipping system config keeps git working and prevents system-level
    // settings (url rewrites, hooks) from reaching the sandboxed agent.
    HardeningEnvVar {
        name: "GIT_CONFIG_NOSYSTEM",
        value: "1",
        category: HardeningCategory::GitHardening,
        description: "Skip /etc/gitconfig (denied by Landlock; would abort git)",
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
    // Self-update lock — agents that auto-update would write to (and execute
    // from) their install dir inside the sandbox, which is a persistence vector
    // and fails against read-only install paths. Copilot uses --no-auto-update;
    // tools without such a flag (e.g. Claude Code) honour DISABLE_AUTOUPDATER.
    // Injected for all agents like the rest of this list — a no-op for tools
    // that don't recognise it.
    HardeningEnvVar {
        name: "DISABLE_AUTOUPDATER",
        value: "1",
        category: HardeningCategory::SandboxMarker,
        description: "Disable agent auto-updaters inside sandbox (e.g. Claude Code)",
    },
    // Telemetry opt-out — many build tools and CLIs send default-on usage analytics.
    // These env vars instruct tools to disable telemetry collection. They have no
    // effect on tools that don't recognise them and do not affect functionality.
    //
    // DO_NOT_TRACK is a cross-tool standard (https://consoledonottrack.com/).
    // Tool-specific vars cover frameworks that predate or ignore the standard.
    HardeningEnvVar {
        name: "DO_NOT_TRACK",
        value: "1",
        category: HardeningCategory::TelemetryOptOut,
        description: "Cross-tool telemetry disable signal (consoledonottrack.com)",
    },
    HardeningEnvVar {
        name: "NEXT_TELEMETRY_DISABLED",
        value: "1",
        category: HardeningCategory::TelemetryOptOut,
        description: "Disable Next.js build telemetry (telemetry.nextjs.org)",
    },
    HardeningEnvVar {
        name: "TURBO_TELEMETRY_DISABLED",
        value: "1",
        category: HardeningCategory::TelemetryOptOut,
        description: "Disable Turborepo usage telemetry",
    },
    HardeningEnvVar {
        name: "CHECKPOINT_DISABLE",
        value: "1",
        category: HardeningCategory::TelemetryOptOut,
        description: "Disable HashiCorp checkpoint (terraform, vault, packer, nomad)",
    },
    HardeningEnvVar {
        name: "GATSBY_TELEMETRY_DISABLED",
        value: "1",
        category: HardeningCategory::TelemetryOptOut,
        description: "Disable Gatsby build telemetry",
    },
    HardeningEnvVar {
        name: "OMO_DISABLE_POSTHOG",
        value: "1",
        category: HardeningCategory::TelemetryOptOut,
        description: "Disable oh-my-openagent PostHog telemetry (OpenCode plugin)",
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
        // Config/Preference dirs (~/.config/pnpm, ~/Library/Preferences/pnpm) are
        // writable: pnpm reads and writes its settings (hoisting, virtual store state)
        // there during normal operation. These dirs contain no credentials.
        //
        // Data/DataLocal (~/.local/share/pnpm) is deliberately NOT writable: it
        // is $PNPM_HOME on Linux, so the global shims `pnpm setup` puts on PATH
        // live directly in it. Its `store/` subdirectory is granted write by the
        // matching HOME_TOOL_DIRS entry, which is what keeps ordinary
        // `pnpm install` working. Removing write here rather than denying the
        // shims afterwards is what makes the rule hold on Landlock too, which
        // cannot subtract from an allowed tree.
        write: &[
            AppDirKind::Cache,
            AppDirKind::Config,
            AppDirKind::ConfigLocal,
            AppDirKind::Preference,
            AppDirKind::Runtime,
            AppDirKind::State,
        ],
        read: DEFAULT_READ_APP_DIRS,
    },
    AppDir {
        qualifier: "",
        organization: "",
        application: "kubebuilder-envtest",
        process_exec: &[AppDirKind::Data, AppDirKind::DataLocal],
        map_exec: &[AppDirKind::Data, AppDirKind::DataLocal],
        write: &[AppDirKind::Cache, AppDirKind::Data, AppDirKind::DataLocal],
        read: &[AppDirKind::Cache, AppDirKind::Data, AppDirKind::DataLocal],
    },
    AppDir {
        qualifier: "",
        organization: "",
        application: "uv",
        process_exec: &[AppDirKind::Cache, AppDirKind::Data, AppDirKind::DataLocal],
        map_exec: &[AppDirKind::Cache, AppDirKind::Data, AppDirKind::DataLocal],
        write: &[AppDirKind::Cache, AppDirKind::Data, AppDirKind::DataLocal],
        read: &[AppDirKind::Cache, AppDirKind::Data, AppDirKind::DataLocal],
    },
    // rtk (token-optimized CLI proxy) stores its tracking database at
    // ~/Library/Application Support/rtk/history.db (macOS) or
    // ~/.local/share/rtk/ (Linux/XDG). No executables or native libs — write
    // access to Data/DataLocal is sufficient.
    AppDir {
        qualifier: "",
        organization: "",
        application: "rtk",
        process_exec: &[],
        map_exec: &[],
        write: &[AppDirKind::Data, AppDirKind::DataLocal],
        read: &[AppDirKind::Data, AppDirKind::DataLocal],
    },
    // fnm (Fast Node Manager) stores Node.js versions at ~/.local/share/fnm/node-versions/.
    // Node binaries and their bundled JS modules (corepack, yarn, npm) must be readable
    // and executable from inside the sandbox.
    // No write: fnm installs are managed outside the sandbox; write access would allow a
    // rogue agent to overwrite node-versions/ binaries that run unsandboxed on the user's
    // PATH — same trojan-persistence risk that drives write:false on the .nvm HomeToolDir.
    AppDir {
        qualifier: "",
        organization: "",
        application: "fnm",
        process_exec: &[AppDirKind::Data, AppDirKind::DataLocal],
        map_exec: &[AppDirKind::Data, AppDirKind::DataLocal],
        write: &[],
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
#[derive(Debug, PartialEq, Eq)]
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
    // `deno install` and `deno upgrade` write executables into ~/.deno/bin,
    // which the Deno installer prepends to PATH. Read-only for the same reason
    // as .cargo/bin: a binary dropped there runs unsandboxed on the user's next
    // shell command. Nothing else lives under ~/.deno — DENO_DIR (the module
    // cache) defaults to ~/Library/Caches/deno or ~/.cache/deno, both of which
    // stay writable through the cache entries below.
    HomeToolDir {
        path: ".deno",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    // ~/.bun holds bin/ (on PATH, `bun install -g` links here) next to
    // install/ (the global module cache every `bun install` populates). Only
    // the tree as a whole was writable, so the split is what keeps project
    // installs working while bin/ goes read-only.
    HomeToolDir {
        path: ".bun",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    // Must follow `.bun`: SBPL is last-match-wins and Landlock unions a path's
    // ancestors, so the narrower grant has to come second to take effect.
    // Keeps the exec posture ~/.bun had before the split — bunx resolves
    // packages out of this cache.
    HomeToolDir {
        path: ".bun/install",
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
    // NuGet package cache: contains .nupkg archives + extracted native libs.
    // map_exec needed for packages that ship native shared libraries (.so/.dylib).
    HomeToolDir {
        path: ".nuget",
        process_exec: false,
        map_exec: true,
        write: true,
    },
    // dotnet CLI home: stores first-run state, telemetry opt-out flags, tool manifests.
    // write needed for CLI state files dotnet writes on every invocation.
    // process_exec intentionally false: dotnet SDK executables live in system paths
    // (Homebrew: /usr/local/share/dotnet, Linux packages: /usr/share/dotnet) — not here.
    // Granting write + process_exec would let a rogue agent trojan dotnet tools that
    // persist after the sandbox (same pattern as .cargo/bin which is also write: false).
    // map_exec true for JIT-compiled native images the runtime memory-maps.
    // Users who install the SDK via dotnet-install.sh into ~/.dotnet may need to add
    // allow.read = ["~/.dotnet"] and set DOTNET_ROOT explicitly.
    HomeToolDir {
        path: ".dotnet",
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
    // npm global cache: packages only, no executables
    HomeToolDir {
        path: ".npm",
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
    // pnpm global dir ($PNPM_HOME): the global shims sit directly in it and
    // `pnpm setup` prepends it to PATH, so the top level is read-only. The
    // content-addressable store one level down stays writable — every ordinary
    // `pnpm install` hardlinks packages out of it, sandboxed or not.
    // macOS-native path not following conventions set out by AppDirs.
    HomeToolDir {
        path: "Library/pnpm",
        process_exec: true,
        map_exec: true,
        write: false,
    },
    // Must follow `Library/pnpm` (last-match-wins / ancestor union).
    HomeToolDir {
        path: "Library/pnpm/store",
        process_exec: false,
        map_exec: true,
        write: true,
    },
    // XDG spelling of the same store. The parent (~/.local/share/pnpm) is
    // granted read+exec by the pnpm AppDir entry, which no longer grants write
    // there — this is the carve-out that keeps `pnpm install` working.
    HomeToolDir {
        path: ".local/share/pnpm/store",
        process_exec: false,
        map_exec: true,
        write: true,
    },
    // Note: pnpm config dirs (~/.config/pnpm on Linux, ~/Library/Preferences/pnpm on macOS)
    // are handled by the pnpm AppDir entry with Config/Preference write access, not here.
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
    // rtk (token-optimized CLI proxy): tracking database on macOS-native path.
    // XDG path (~/.local/share/rtk) is covered by the AppDir entry above.
    HomeToolDir {
        path: "Library/Application Support/rtk",
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

// ── PATH-resolved bin and shim directories ─────────────────────────────────

/// A directory that lands on the user's `PATH` ahead of `/usr/bin`, together
/// with the shape of the write-deny that protects it.
///
/// These are the drop points for a trojan that outlives the sandbox: a file
/// written to one of them is what the user's *next* unsandboxed `git`, `node`
/// or `python` resolves to. `.cargo/bin` has been read-only for exactly this
/// reason since long before the rest of the class was noticed.
///
/// Most of them are handled structurally instead — [`HOME_TOOL_DIRS`] grants
/// write to the sibling cache rather than the parent, which is the only shape
/// Landlock can express. This list is what remains: the same paths re-denied so
/// a user `allow.write` cannot reopen them, plus the two mise directories that
/// sit inside a tree which has to stay writable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathBinDir {
    /// The directory and everything under it.
    Subtree(PathBuf),
    /// Only the entries directly inside it; subdirectories stay writable.
    ///
    /// The `$PNPM_HOME` shape — the global shims sit at the top level, while
    /// `store/` below it must keep taking writes for ordinary `pnpm install`.
    TopLevel(PathBuf),
}

/// Resolve the PATH-resolved bin/shim directories for `home`.
///
/// mise and pnpm are resolved through [`AppDirKind`] rather than spelled
/// home-relative, so `XDG_DATA_HOME` relocations are followed.
pub fn path_bin_dirs(home: &Path) -> Vec<PathBinDir> {
    let mut dirs = vec![
        PathBinDir::Subtree(home.join(".bun/bin")),
        PathBinDir::Subtree(home.join(".deno/bin")),
        PathBinDir::TopLevel(home.join("Library/pnpm")),
    ];
    for data in app_data_dirs("pnpm", home) {
        dirs.push(PathBinDir::TopLevel(data));
    }
    for data in app_data_dirs("mise", home) {
        // Shims are what `mise activate` puts on PATH.
        dirs.push(PathBinDir::Subtree(data.join("shims")));
        // The whole of `installs/`, not each `<tool>/<version>/bin`. mise only
        // creates a `bin/` for tools that ship one — on a machine with 207
        // installed version directories, 55 did. Everything else lands flat at
        // `installs/<tool>/<version>/<name>` (`installs/actionlint/1.7.12/actionlint`),
        // and in non-shim mode mise puts *that* directory on PATH, so a
        // `bin`-anchored rule leaves the majority of tools writable. Denying
        // the tree costs only `mise install` and `mise upgrade` from inside the
        // sandbox, which is already the accepted cost for the shimmed ones.
        dirs.push(PathBinDir::Subtree(data.join("installs")));
    }
    dirs
}

/// Data and data-local dirs of an XDG-resolved application, deduplicated.
fn app_data_dirs(application: &str, home: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for kind in [AppDirKind::Data, AppDirKind::DataLocal] {
        if let Some(p) = kind.resolve("", "", application, home)
            && !out.contains(&p)
        {
            out.push(p);
        }
    }
    out
}

/// The mise directories that must be re-bound read-only by Bubblewrap on Linux.
///
/// Landlock cannot subtract from an allowed tree, and the mise data dir has to
/// stay writable for the rest of mise's state, so `shims/` and `installs/` are
/// carried by the same read-only overlay that already backs the git- and
/// agent-persistence denies. The whole `installs/` tree is bound rather than
/// each `installs/<tool>/<version>/bin`: bwrap takes no globs, and denying
/// writes across all of `installs/` only widens the already-accepted breakage
/// of `mise install` inside the sandbox.
pub fn mise_ro_protect_paths(home: &Path) -> Vec<PathBuf> {
    app_data_dirs("mise", home)
        .into_iter()
        .flat_map(|d| [d.join("shims"), d.join("installs")])
        .collect()
}

/// Copilot's two package directories, which must be re-bound read-only by
/// Bubblewrap on Linux.
///
/// macOS write-denies both in the SBPL profile — `~/.copilot/pkg` (native
/// modules: `keytar.node`, `pty.node`) and `~/Library/Caches/copilot/pkg` (the
/// SEA runtime). Landlock can express neither:
///
/// - `~/.copilot` is granted read+write+execute wholesale for Copilot, and
///   Landlock cannot subtract `pkg` from an allowed tree.
/// - `~/.cache/copilot/pkg` carries an execute rule so Node can spawn the
///   extracted helpers, and Landlock unions that with the read+write grant
///   `HOME_TOOL_DIRS` gives all of `~/.cache`. The result is writable **and**
///   executable — the binary-drop pair, in the one tree whose whole purpose is
///   holding code Copilot later runs on the host.
///
/// Both are the persistence class SECURITY.md's native-module write protection
/// claims to cover, so the bwrap read-only overlay carries them for parity.
/// Read-only rather than a deny mask: the runtime must stay readable and
/// executable, and the SEA extraction that writes it happens outside the
/// sandbox in `copilot_extract` by design.
///
/// `~/.cache` is spelled literally rather than resolved through
/// `XDG_CACHE_HOME`, to match `copilot_extract`'s `copilot_cache_dirs` — the
/// code that actually creates the directory. If that gains XDG support this
/// must follow it.
///
/// Same caveats as every other `ro_protect` entry: without bubblewrap this is
/// unenforced, and bwrap skips a path that does not exist at launch.
///
/// Returns nothing for an agent that is not Copilot: the agent check lives here
/// rather than at the call site so the whole decision is one unit-testable
/// function on both platforms, instead of a Linux-only `if` no test can reach.
pub fn copilot_ro_protect_paths(agent: Agent, home: &Path) -> Vec<PathBuf> {
    if !agent.needs_copilot_dir() {
        return Vec::new();
    }
    vec![home.join(".copilot/pkg"), home.join(".cache/copilot/pkg")]
}

/// A tool home relocated by an env var (`CARGO_HOME=~/.local/share/cargo`).
///
/// [`HOME_TOOL_DIRS`] entries under `default` (home-relative, e.g. `.cargo`)
/// are re-rooted under `root` (absolute, canonicalized, existence-checked by
/// the caller) and keep their own permission flags, so `$CARGO_HOME/bin` gets
/// the exec-only posture of `~/.cargo/bin` rather than one write grant over
/// the whole tree (#152).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRoot {
    pub default: &'static str,
    pub root: PathBuf,
}

/// A [`HOME_TOOL_DIRS`] entry at its effective absolute path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedToolDir {
    pub path: PathBuf,
    pub dir: &'static HomeToolDir,
}

impl HomeToolDir {
    /// Absolute path of this entry: under the matching [`ToolRoot`] if one
    /// relocates its tree, else under `home`.
    pub fn resolve(&'static self, home: &Path, roots: &[ToolRoot]) -> ResolvedToolDir {
        let rel = Path::new(self.path);
        let path = roots
            .iter()
            .find_map(|r| {
                let rest = rel.strip_prefix(r.default).ok()?;
                // `join("")` would append a trailing separator, and Seatbelt
                // matches the literal string.
                Some(if rest.as_os_str().is_empty() {
                    r.root.clone()
                } else {
                    r.root.join(rest)
                })
            })
            .unwrap_or_else(|| home.join(rel));
        ResolvedToolDir { path, dir: self }
    }
}

/// The default subpath of tool-path env var `name` that has [`HOME_TOOL_DIRS`]
/// entries under it, if any. Such a var relocates those entries (see
/// [`ToolRoot`]) instead of granting its whole tree.
pub fn relocatable_tool_prefix(name: &str) -> Option<&'static str> {
    TOOL_PATH_ENV_VARS
        .iter()
        .find(|tv| tv.name == name)?
        .default_subpaths
        .iter()
        .copied()
        .find(|d| {
            HOME_TOOL_DIRS
                .iter()
                .any(|h| Path::new(h.path).starts_with(d))
        })
}

/// Home tool dirs to grant: the discovered subset when available, else every
/// entry at its default location under `home`.
pub fn active_tool_dirs(
    home: &Path,
    discovered: Option<&[ResolvedToolDir]>,
) -> Vec<ResolvedToolDir> {
    match discovered {
        Some(dirs) => dirs.to_vec(),
        None => HOME_TOOL_DIRS
            .iter()
            .map(|d| d.resolve(home, &[]))
            .collect(),
    }
}

// ── Tool-path environment variable overrides ───────────────────────────────

/// A development tool environment variable that relocates where the tool reads
/// or writes files (e.g. `GOPATH`, `CARGO_HOME`, `NODE_PATH`).
///
/// [`HOME_TOOL_DIRS`] allowlists each tool's *default* location under `$HOME`.
/// When a user points one of these env vars at a **non-default** path and that
/// value is passed into the sandbox, builds fail because the custom path is not
/// in the allow set (e.g. `GOPATH=/custom` → `go build` cannot write there).
/// [`tool_path_env_overrides`] closes that gap by granting the resolved path.
///
/// Security note: an env var value is user-controlled configuration, so honoring
/// it is consistent with how cplt already trusts `pass-env` — the same user who
/// launches cplt set the variable. We only ever *add* access (never remove), and
/// grant write only for the tools that genuinely write to the path.
pub struct ToolPathEnvVar {
    /// Environment variable name (looked up in the parent process env).
    pub name: &'static str,
    /// `true` → grant read+write (build caches / dependency stores the tool
    /// writes to). `false` → grant read-only (lookup paths the tool only reads).
    pub write: bool,
    /// Home-relative default locations already covered by [`HOME_TOOL_DIRS`] (or
    /// redirected elsewhere, e.g. `GOCACHE` → scratch dir). If the env var
    /// resolves to one of these, no extra rule is added — the base policy already
    /// grants it, so adding it again would only widen or duplicate the grant.
    /// Multiple entries cover per-platform defaults (macOS `Library/...` vs XDG).
    pub default_subpaths: &'static [&'static str],
    /// `true` → the value is an OS path list (colon-separated on Unix, e.g.
    /// `GOPATH=/a:/b` or `NODE_PATH=/x:/y`), so each segment is a separate path
    /// and must be resolved and granted independently. `false` → the whole value
    /// is a single path, even if it happens to contain a `:`, so it is never
    /// split.
    pub list: bool,
}

/// Recognized tool-path env vars and how their target path is granted.
///
/// Covers the common Go, Node/npm/yarn/pnpm, Rust/cargo and Python/pip knobs.
/// Write is granted for caches and dependency stores the tool populates; read
/// for pure lookup paths (`NODE_PATH`). All of these vars reach the sandbox via
/// [`ENV_ALLOWLIST`] (or a prefix in [`ENV_PREFIX_ALLOWLIST`]), so the granted
/// path is actually nameable by the sandboxed process.
/// Separator between entries in a list-valued tool-path env var. cplt targets
/// Unix (macOS/Linux) where the OS path-list separator is `:` (as used by
/// `PATH`, `GOPATH`, `NODE_PATH`, …).
const TOOL_PATH_LIST_SEPARATOR: char = ':';

pub const TOOL_PATH_ENV_VARS: &[ToolPathEnvVar] = &[
    // ── Go ──────────────────────────────────────────────────────────────────
    // GOPATH holds go/bin, go/pkg (module cache) and go/src; builds write here.
    ToolPathEnvVar {
        name: "GOPATH",
        write: true,
        default_subpaths: &["go"],
        // GOPATH is a colon-separated list on Unix; each entry is its own root.
        list: true,
    },
    // Module cache — `go build`/`go test`/`go get` download & extract modules.
    ToolPathEnvVar {
        name: "GOMODCACHE",
        write: true,
        default_subpaths: &["go/pkg/mod"],
        list: false,
    },
    // Build cache. Default is redirected to the scratch dir (SCRATCH_DIR_ENV_VARS),
    // so honor only an explicit non-default override.
    ToolPathEnvVar {
        name: "GOCACHE",
        write: true,
        default_subpaths: &["Library/Caches/go-build", ".cache/go-build"],
        list: false,
    },
    // ── Rust / cargo ─────────────────────────────────────────────────────────
    // CARGO_HOME holds bin/, registry/ and git/ — cargo writes to registry & git.
    ToolPathEnvVar {
        name: "CARGO_HOME",
        write: true,
        default_subpaths: &[".cargo"],
        list: false,
    },
    // RUSTUP_HOME holds the toolchains that the `$CARGO_HOME/bin` proxies
    // exec into. Read-only, like the default `.rustup` entry.
    ToolPathEnvVar {
        name: "RUSTUP_HOME",
        write: false,
        default_subpaths: &[".rustup"],
        list: false,
    },
    // ── Node / npm / yarn / pnpm ─────────────────────────────────────────────
    // npm cache (uppercase and npm's canonical lowercase spelling).
    ToolPathEnvVar {
        name: "NPM_CONFIG_CACHE",
        write: true,
        default_subpaths: &[".npm"],
        list: false,
    },
    ToolPathEnvVar {
        name: "npm_config_cache",
        write: true,
        default_subpaths: &[".npm"],
        list: false,
    },
    // Yarn (Classic & Berry) global cache folder.
    ToolPathEnvVar {
        name: "YARN_CACHE_FOLDER",
        write: true,
        default_subpaths: &[".cache/yarn", "Library/Caches/Yarn"],
        list: false,
    },
    // pnpm home (global store + shims).
    ToolPathEnvVar {
        name: "PNPM_HOME",
        write: true,
        default_subpaths: &["Library/pnpm", ".local/share/pnpm"],
        list: false,
    },
    // NODE_PATH is a module *lookup* path — read-only is sufficient. Like the
    // shell PATH, it is a colon-separated list of directories on Unix.
    ToolPathEnvVar {
        name: "NODE_PATH",
        write: false,
        default_subpaths: &[],
        list: true,
    },
    // ── Python / pip ─────────────────────────────────────────────────────────
    // pip download/wheel cache.
    ToolPathEnvVar {
        name: "PIP_CACHE_DIR",
        write: true,
        default_subpaths: &[".cache/pip", "Library/Caches/pip"],
        list: false,
    },
];

/// A single resolved tool-path override to add to the sandbox allow set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPathOverride {
    /// Name of the env var this override came from (e.g. `GOPATH`). Used for
    /// diagnostics when the override is dropped by the safety guard.
    pub name: &'static str,
    /// Resolved path (leading `~/` expanded, relative paths joined onto `$HOME`).
    /// Not yet canonicalized or existence-checked — the caller does that so the
    /// backend only receives paths that actually exist (Landlock requires it).
    pub path: PathBuf,
    /// `true` → read+write, `false` → read-only.
    pub write: bool,
}

/// Expand a raw env var path value into an absolute path.
///
/// - Leading `~/` (or a bare `~`) expands to `home`.
/// - Absolute paths are kept as-is.
/// - Relative paths are joined onto `home` (env-var paths are almost always
///   absolute) rather than resolved against an unknown cwd. This is *not* a
///   containment guarantee: a value like `../../etc` still escapes HOME once the
///   caller's `canonicalize()` collapses the `..` components. Final safety is
///   enforced downstream by [`tool_override_path_is_safe`] at the merge site,
///   which drops any override that resolves to an unsafe root or to HOME/above.
///
/// Does not canonicalize or check existence — kept pure for cross-platform tests.
fn resolve_tool_path(raw: &str, home: &Path) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        home.join(rest)
    } else if raw == "~" {
        home.to_path_buf()
    } else {
        let p = Path::new(raw);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            home.join(p)
        }
    }
}

/// Compute the extra read/write paths implied by tool-path env vars.
///
/// For each variable in [`TOOL_PATH_ENV_VARS`] present in `env`, resolve its
/// value (see [`resolve_tool_path`]) and, if it points at a **non-default**
/// location, emit a [`ToolPathOverride`]. Default locations are skipped because
/// [`HOME_TOOL_DIRS`] already grants them. Unset/empty vars contribute nothing.
///
/// List-valued vars ([`ToolPathEnvVar::list`], e.g. `GOPATH`, `NODE_PATH`) hold a
/// colon-separated list of directories on Unix (`GOPATH=/a:/b`); each segment is
/// resolved and granted independently, and empty segments (from `/a::/b` or a
/// trailing `:`) are skipped. Single-path vars are never split, so a `:` inside a
/// genuine directory name is preserved verbatim.
///
/// `env` is the *parent* process environment as `(name, value)` pairs. Duplicate
/// resolved paths are collapsed; if the same path is requested read-only and
/// read+write, the write grant wins.
///
/// The downstream safety guard ([`tool_override_path_is_safe`]) runs per emitted
/// override at the merge site, so it is applied per segment for list vars.
///
/// Pure function (env passed in, no `std::env` / filesystem access) so rule
/// generation is testable on any platform.
pub fn tool_path_env_overrides(env: &[(String, String)], home: &Path) -> Vec<ToolPathOverride> {
    let mut out: Vec<ToolPathOverride> = Vec::new();
    for tv in TOOL_PATH_ENV_VARS {
        let Some((_, raw)) = env.iter().find(|(k, _)| k == tv.name) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        // List vars are colon-separated path lists on Unix; single-path vars are
        // treated as one value even if they contain a `:`.
        let segments: Vec<&str> = if tv.list {
            raw.split(TOOL_PATH_LIST_SEPARATOR)
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            vec![raw.as_str()]
        };
        for seg in segments {
            let resolved = resolve_tool_path(seg, home);
            // Skip values that resolve to a default location already in the base policy.
            if tv.default_subpaths.iter().any(|d| resolved == home.join(d)) {
                continue;
            }
            // Deduplicate; upgrade an existing read-only grant to write if needed.
            if let Some(existing) = out.iter_mut().find(|o| o.path == resolved) {
                existing.write = existing.write || tv.write;
            } else {
                out.push(ToolPathOverride {
                    name: tv.name,
                    path: resolved,
                    write: tv.write,
                });
            }
        }
    }
    out
}

/// Whether a canonicalized tool-path override is safe to add to the sandbox
/// allow set.
///
/// A tool-path env var (`GOPATH`, `CARGO_HOME`, …) is attacker-influenceable: it
/// may have been exported long ago for unrelated reasons, or injected via a repo
/// config or `--pass-env`. Legitimate tool directories are always
/// *subdirectories* of `$HOME` (e.g. `~/go`, `~/.cargo`) or of a custom project
/// root, so an override that resolves to an unsafe root ([`crate::is_unsafe_root`]:
/// `/`, `$HOME`, `/tmp`, platform system dirs) or to `$HOME` itself or any
/// ancestor of it can only *widen* the sandbox and defeat its purpose. Such
/// overrides must be dropped.
///
/// This is the single choke point where a canonicalized override becomes an
/// allow rule; `canonicalize()` has already collapsed any `..`, so the path
/// passed here is the effective grant. Applies to read grants too — read access
/// to `/` or `$HOME` is also an over-grant.
///
/// `path` must already be canonicalized; `home` is the (canonical) home dir.
pub fn tool_override_path_is_safe(path: &Path, home: &Path) -> bool {
    // `/`, `$HOME`, `/tmp`, and platform system roots — mirrors every other
    // path-widening guard in the codebase (project_dir, tool-dir discovery).
    if crate::is_unsafe_root(path, home) {
        return false;
    }
    // Any ancestor of HOME (e.g. `/Users` on macOS, `/home` on Linux, or a
    // deeper parent). `starts_with` also matches HOME itself, which
    // `is_unsafe_root` already covers — kept as defense in depth.
    if home.starts_with(path) {
        return false;
    }
    true
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

// ── Protected paths inside writable roots ──────────────────────
//
// One list, three backends. Every backend reads the two tables below and
// chooses only how to enforce them; none of them decides *what* is on the
// list. Before this existed the same question — "which paths under a writable
// root must stay unwritable?" — was answered independently in the SBPL
// generator, in the bubblewrap ro-protect set, and (by omission) in Landlock,
// and they disagreed: #276 had to add `.agents/plugins` to two backends by
// hand, #240 found a bubblewrap mask naming a path that did not exist, and
// #207 found a deny list silently effective on macOS and silently ineffective
// on Linux. All three are the same defect.

/// How Linux enforces a [`Protected`] entry.
///
/// Landlock never enforces any of them: it is purely additive, so a write rule
/// on a tree cannot have a sub-path subtracted from it. Anything Linux does
/// enforce is enforced by the bubblewrap read-only overlay, which is only
/// present on hosts with user namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxCoverage {
    /// Bubblewrap re-binds the path read-only, restoring macOS parity when
    /// bubblewrap is available.
    Bwrap,
    /// Not enforced on Linux at all. The payload is the reason, so the gap is
    /// reviewable in one place rather than being an absence nobody can see.
    Gap(&'static str),
}

/// A path that must stay unwritable even though it sits inside a tree the
/// sandbox deliberately makes writable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protected {
    /// Path relative to the writable root ([`PROTECTED_IN_ROOT`]) or to the git
    /// directory ([`PROTECTED_IN_GITDIR`]) the entry hangs off.
    pub rel: &'static str,
    /// `true` → the whole subtree is protected; `false` → a single file.
    pub tree: bool,
    /// Also protect the same relative path under repositories nested *beneath*
    /// a writable root (#247). macOS expresses this with a regex; no other
    /// backend can express it at all.
    pub nested: bool,
    /// One-line rationale. macOS emits it as the SBPL section comment for
    /// [`PROTECTED_IN_ROOT`]; for [`PROTECTED_IN_GITDIR`] it is documentation
    /// only, since those share one section header per git directory.
    pub why: &'static str,
    pub linux: LinuxCoverage,
}

/// Protected paths relative to every writable root — the project directory and
/// every `allow.write` grant (#212). A granted sibling repo is a future
/// `--project-dir`, so it needs everything the project needs.
///
/// Paths *inside* a git directory live in [`PROTECTED_IN_GITDIR`] instead;
/// `<root>/.git` is one of the git directories every root contributes.
pub const PROTECTED_IN_ROOT: &[Protected] = &[
    // Submodule URLs are a supply-chain vector: `git submodule update` clones
    // whatever this file names.
    //
    // Not nested: a nested repo's `.gitmodules` is only reachable through that
    // repo's own `.git/config`, which is already denied at every depth.
    Protected {
        rel: ".gitmodules",
        tree: false,
        nested: false,
        why: "Git submodule config — URLs are a supply-chain vector",
        linux: LinuxCoverage::Gap(
            "not in the bubblewrap ro-protect set. Exploiting a rewritten URL needs \
             a later `git submodule update`, and the bind would also have to skip \
             repos that have no `.gitmodules` yet, which is where `git submodule add` \
             writes it. Adding it would break that command on Linux, so the parity \
             gap is recorded rather than closed silently.",
        ),
    },
    // cplt's own config controls how relaxed the *next* session's sandbox is.
    // Writing it would let the agent prepare a permissive profile for itself.
    Protected {
        rel: ".cplt.toml",
        tree: false,
        nested: false,
        why: "Repo config — deny write to prevent sandbox tampering",
        linux: LinuxCoverage::Bwrap,
    },
    // #267: goose auto-spawns the MCP servers declared under `.agents/plugins/`,
    // so a manifest the agent writes in one session runs on the HOST the next
    // time the user starts an agent in this repo. Same class as `.git/hooks`,
    // and cross-agent: the payload fires whichever agent reads it.
    //
    // Scoped to `plugins/` rather than all of `.agents/` — the rest of that tree
    // is ordinary agent state with no auto-execution.
    Protected {
        rel: ".agents/plugins",
        tree: true,
        nested: true,
        why: "Plugin manifests — auto-spawned on the host next session",
        linux: LinuxCoverage::Bwrap,
    },
];

/// Protected paths relative to a git directory.
///
/// The git directories are `<root>/.git` for every writable root (emitted even
/// for a root that is not a repo today, so a mid-session `git init` is covered),
/// plus a worktree's shared common dir and the resolved gitdir of any grant
/// whose repo data does not live at `<root>/.git` — a worktree, a bare repo, or
/// a grant pointing inside a repo (see `discover::git_dir_of`).
///
/// Pinning the git directory *itself* against rename and unlink is a mechanism,
/// not a path, so it stays with the backend that can express it (macOS
/// `file-write-unlink` / `file-write-data` on the directory entry).
pub const PROTECTED_IN_GITDIR: &[Protected] = &[
    // The primary persistence escape: a planted hook runs *unsandboxed* on the
    // user's next git operation, including one run outside cplt entirely.
    Protected {
        rel: "hooks",
        tree: true,
        nested: true,
        why: "hooks run unsandboxed on the user's next git operation",
        linux: LinuxCoverage::Bwrap,
    },
    // `core.hooksPath` redirects hooks to a writable directory, `url.*.insteadOf`
    // hijacks remotes, `include.path` loads arbitrary config.
    Protected {
        rel: "config",
        tree: false,
        nested: true,
        why: "core.hooksPath / url.insteadOf / include.path all redirect trust",
        linux: LinuxCoverage::Gap(
            "deliberate, not an oversight. A read-only bind here breaks `git config \
             user.email` (without which the next commit fails), `git remote add` and \
             `git push -u`; worse, git rewrites config through `.git/config.lock` + \
             rename, so a denied write can leave a stale lock that blocks the user's \
             next out-of-sandbox git. RESIDUAL: because config stays writable on \
             Linux, `core.hooksPath` can still redirect hooks away from the \
             read-only `hooks` bind. See SECURITY.md.",
        ),
    },
    // git reads `commondir` for ANY gitdir, not just worktrees, and its contents
    // become `git rev-parse --git-common-dir` — a value cplt feeds back into its
    // own profile as a read+write grant. A planted one points the next run's
    // grant at another repository. `discover::git_common_dir` rejects a steered
    // value at the source; this stops it being planted in the first place.
    Protected {
        rel: "commondir",
        tree: false,
        nested: true,
        why: "steers `git rev-parse --git-common-dir`, an input to cplt's own policy",
        linux: LinuxCoverage::Gap(
            "not in the bubblewrap ro-protect set. `discover::git_common_dir` rejects \
             a steered value at the source on every platform, so the escalation is \
             closed there; only the plant-in-place half is macOS-only.",
        ),
    },
    // `modules/<name>/` is a full gitdir per submodule, with the same hooks and
    // config vectors one level down. The whole subtree is denied rather than
    // those two names: submodule gitdirs nest arbitrarily deep
    // (`modules/a/modules/b/...`) and SBPL subpaths have no wildcard. Nothing is
    // lost by being broad — `git submodule add` and `update --init` already fail
    // inside the sandbox, because both write `<gitdir>/config`.
    Protected {
        rel: "modules",
        tree: true,
        nested: true,
        why: "a full gitdir per submodule, same hooks and config vectors one level down",
        linux: LinuxCoverage::Gap(
            "not in the bubblewrap ro-protect set, and reaching it needs the same \
             `<gitdir>/config` write that is itself only denied on macOS.",
        ),
    },
];

/// Escape the regex metacharacters that can still appear in a path.
///
/// `validate_sbpl_path` already rejects `"`, `(`, `)`, `;`, `\` and newlines, so
/// what is left is the set below. Without this a project directory like
/// `~/code/v1.0+rc` would compile to a rule matching more than it names.
pub fn escape_regex(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if matches!(
            c,
            '.' | '*' | '+' | '?' | '[' | ']' | '{' | '}' | '^' | '$' | '|'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The `nested: true` entries of a table, as a regex alternation.
///
/// macOS is the only backend that can protect repositories nested at unknown
/// depth beneath a writable root, and it does so with one regex per table. The
/// alternation is derived here rather than written out next to the regex, so it
/// cannot drift from the table the way it did before #247's comment had to
/// promise it "mirrors `emit_gitdir_denies` exactly".
///
/// Each name is passed through [`escape_regex`] first. Today's gitdir names are
/// all bare words, so the escaping is a no-op for them — but `.agents/plugins`
/// in [`PROTECTED_IN_ROOT`] is not, and an entry added later need not be. The
/// helper says "alternation", so it owes the caller a *regex*, not a list of
/// names that happens to look like one.
pub fn nested_alternation(set: &[Protected]) -> String {
    set.iter()
        .filter(|p| p.nested)
        .map(|p| escape_regex(p.rel))
        .collect::<Vec<_>>()
        .join("|")
}

// ── Execute rights inside a writable tree ──────────────────────────────────
//
// [`PROTECTED_IN_ROOT`] and [`PROTECTED_IN_GITDIR`] cover the other direction:
// persistence-vector paths that must stay unwritable inside a tree the sandbox
// makes writable. This table covers execute rights that overlap a writable
// tree — the write-then-exec pair `validate_exec_grants` refuses for
// `allow.exec` (#295) and that cplt itself creates in a handful of places.

/// A tree that is executable *and* writable, and the reason it stays that way.
///
/// Two rules keep the rest of the policy free of such pairs. On macOS every
/// `HOME_TOOL_DIRS` entry with `write && !process_exec` gets a compensating
/// `(deny process-exec)`, and since #243 so does every `allow.write` tree. On
/// Linux, Landlock's `EXECUTE` follows `process_exec` alone: it is checked only
/// on `execve()` (`file_open` with `FMODE_EXEC`) and has no hook for
/// `mmap(PROT_EXEC)`, which a dynamic loader reaches with `READ_FILE` alone —
/// so honouring `map_exec` as an `EXECUTE` right granted full execve to every
/// `write: true, map_exec: true` dependency store (`.cargo/registry`,
/// `.cargo/git`, `.m2`, `.nuget`, `go/pkg`, the pnpm stores) for a right none
/// of them needed.
///
/// What is left is this table: trees that really do run binaries out of
/// themselves. Each entry says why, and its [`LinuxCoverage`] says what
/// contains the write side there — for all of them, nothing does, because
/// Landlock cannot subtract a write grant from an ancestor and the bubblewrap
/// read-only bind that could is absent on hosts without user namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecInWritable {
    /// Home-relative tree.
    pub path: &'static str,
    /// macOS grants `process-exec` here too, so an `allow.write` covering the
    /// tree must not silently take it away. `false` means the execute right
    /// exists only on Linux, where it cannot be expressed more narrowly.
    pub macos: bool,
    pub why: &'static str,
    pub linux: LinuxCoverage,
}

/// The trees whose execute right survives sitting inside a writable one.
///
/// The Linux entries with `macos: false` are the ones #243 could not settle:
/// the fix was written and verified on macOS, where the tree is already
/// `process-exec`-denied, and neither Gradle nor .NET nor Kotlin/Native could
/// be run on a Linux host to show whether dropping `EXECUTE` breaks them. The
/// pre-existing right is kept rather than guessed away — a wrong carve-out
/// either reopens the hole or breaks every user of the tool, and the second is
/// invisible from a macOS checkout.
pub const EXEC_IN_WRITABLE: &[ExecInWritable] = &[
    // Gradle provisions toolchain JDKs into `~/.gradle/jdks` and execs them.
    // macOS emits the matching `(allow process-exec)` in
    // `emit_gradle_toolchain_exec` and takes the write back at the tail of the
    // profile in `emit_gradle_toolchain_write_deny`; Landlock has no way to do
    // the second half.
    ExecInWritable {
        path: ".gradle/jdks",
        macos: true,
        why: "Gradle toolchain JDKs — auto-provisioned and exec'd by the daemon",
        linux: LinuxCoverage::Gap(
            "Landlock cannot subtract the ~/.gradle write grant from this subtree, and \
             the bubblewrap read-only bind that could is absent on hosts without user \
             namespaces — so the control would be silently missing exactly where it is \
             needed. macOS denies the write at the tail of the profile instead.",
        ),
    },
    // `bunx` resolves and runs packages straight out of the global install
    // cache that `bun install` writes, so the pair is the feature.
    ExecInWritable {
        path: ".bun/install",
        macos: true,
        why: "bunx runs packages out of the global install cache bun writes",
        linux: LinuxCoverage::Gap(
            "write+execute by design on both backends; recorded here so the pair is \
             reviewable rather than an absence. `.bun/bin`, the PATH-resolved half, is \
             write-denied separately.",
        ),
    },
    // The `.dotnet` HOME_TOOL_DIRS entry is `process_exec: false` because the
    // SDK normally lives in a system path. When it does not — `dotnet-install.sh`
    // puts it here — macOS re-grants execute through the configured
    // `dotnet_root`, and Landlock has no counterpart to that rule.
    ExecInWritable {
        path: ".dotnet",
        macos: false,
        why: "DOTNET_ROOT for dotnet-install.sh installs; macOS re-grants exec via \
              `dotnet_root`, Landlock has no equivalent rule",
        linux: LinuxCoverage::Gap(
            "not verified against a real .NET run (#243). Dropping EXECUTE here would \
             break every user who installed the SDK with dotnet-install.sh, and that \
             failure is not visible from a macOS checkout, so the pre-existing right is \
             kept until a Linux host can settle it.",
        ),
    },
    // Kotlin/Native downloads an LLVM and clang toolchain into
    // `~/.konan/dependencies` and execs it during a native build.
    ExecInWritable {
        path: ".konan",
        macos: false,
        why: "Kotlin/Native execs the LLVM toolchain it downloads into ~/.konan/dependencies",
        linux: LinuxCoverage::Gap(
            "not verified against a real Kotlin/Native build (#243). macOS denies \
             process-exec here, so K/N may already be broken there — that could not be \
             demonstrated either way from macOS, and guessing in either direction is \
             what this entry exists to avoid.",
        ),
    },
];

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

    /// The protected-path set is the one place three backends agree, so a new
    /// entry must not slip in with its Linux story unstated. Pinning the whole
    /// table here makes any addition a visible diff on this test, where the
    /// reviewer has to say which side of the platform line it falls on.
    ///
    /// This is also the only cross-platform check of what bubblewrap binds:
    /// `sandbox::bubblewrap` is `cfg(target_os = "linux")`, so its own tests
    /// cannot run on a macOS host, but it consumes exactly this subset.
    #[test]
    fn protected_paths_state_their_linux_coverage() {
        let bwrap = |set: &[Protected]| {
            set.iter()
                .filter(|p| p.linux == LinuxCoverage::Bwrap)
                .map(|p| p.rel)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            bwrap(PROTECTED_IN_ROOT),
            [".cplt.toml", ".agents/plugins"],
            "bubblewrap re-binds these read-only under every writable root"
        );
        assert_eq!(
            bwrap(PROTECTED_IN_GITDIR),
            ["hooks"],
            "`config`, `commondir` and `modules` are macOS-only; each entry \
             carries the reason in its LinuxCoverage::Gap"
        );
        // Every entry says something either way — a Gap with an empty reason is
        // an undocumented gap, which is the failure this table exists to stop.
        for p in PROTECTED_IN_ROOT.iter().chain(PROTECTED_IN_GITDIR) {
            assert!(!p.why.is_empty(), "{} has no rationale", p.rel);
            if let LinuxCoverage::Gap(reason) = p.linux {
                assert!(
                    reason.len() > 40,
                    "{} is unenforced on Linux with no stated reason",
                    p.rel
                );
            }
        }
    }

    #[test]
    fn nested_alternation_covers_the_nested_entries() {
        assert_eq!(
            nested_alternation(PROTECTED_IN_GITDIR),
            "hooks|config|commondir|modules"
        );
        assert_eq!(
            nested_alternation(PROTECTED_IN_ROOT),
            r"\.agents/plugins",
            "a `.` in a rel path must reach the regex escaped, not as `any char`"
        );
    }
}
