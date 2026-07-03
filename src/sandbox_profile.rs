//! macOS SBPL sandbox profile generation.
//!
//! Builds a Seatbelt Profile Language string from [`ProfileOptions`],
//! encoding filesystem, network, and process rules for `sandbox-exec`.

use std::fmt::Write;
use std::path::{Path, PathBuf};

use crate::agent::{Agent, AgentDir};

/// Write an SBPL line to a String buffer. Uses `expect` because writing to
/// String is infallible — a panic here would indicate a logic error, not I/O.
macro_rules! sbpl {
    ($sb:expr) => {
        writeln!($sb).expect("write to String")
    };
    ($sb:expr, $($arg:tt)*) => {
        writeln!($sb, $($arg)*).expect("write to String")
    };
}

use super::policy::{
    DENIED_CACHE_PREFIXES, DENIED_DOTFILES, DENIED_FILES, DENIED_HOME_SUBPATHS,
    GPG_SIGNING_ALLOW_FILES, HOME_TOOL_DIRS, HomeToolDir, SENSITIVE_PROJECT_PATTERNS,
    SYSTEM_READ_FILES, TOOL_READ_DIRS, app_dirs, validate_sbpl_path,
};

/// Options for generating an SBPL sandbox profile.
///
/// All paths are validated for SBPL injection before interpolation.
pub struct ProfileOptions<'a> {
    pub project_dir: &'a Path,
    pub home_dir: &'a Path,
    pub extra_read: &'a [PathBuf],
    pub extra_write: &'a [PathBuf],
    pub allow_socket: &'a [PathBuf],
    pub extra_deny: &'a [PathBuf],
    /// If `Some`, only include these home tool dirs (tighter profile via discovery).
    /// If `None`, all known home tool dirs are included.
    pub existing_home_tool_dirs: Option<&'a [String]>,
    /// If `Some`, only include these app dirs (tighter profile via discovery).
    /// If `None`, all known app dirs are included.
    pub existing_app_dirs: Option<&'a [String]>,
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
    /// Copilot CLI package directory (resolved from the binary location).
    /// Needed when Copilot is installed in a non-standard location (e.g. ~/n/
    /// via the `n` Node version manager) that isn't covered by TOOL_READ_DIRS.
    pub copilot_install_dir: Option<&'a Path>,
    /// JAVA_HOME directory for JDK read + dylib loading.
    /// Needed when Java is installed outside TOOL_READ_DIRS (e.g. ~/hostedtoolcache,
    /// sdkman, or other version managers).
    pub java_home: Option<&'a Path>,
    /// Global git hooks directory from `core.hooksPath`.
    /// Git needs to read and execute hooks from this directory for commits.
    pub git_hooks_path: Option<&'a Path>,
    /// Shared .git directory for git worktrees.
    /// When the project is a worktree, git needs read+write access to the main
    /// repo's .git directory (objects, refs, packed-refs, etc.).
    pub git_common_dir: Option<&'a Path>,
    /// Allow GPG commit/tag signing. When true, grants read-only access to
    /// the public keyring and GPG agent socket. Private keys stay denied.
    pub allow_gpg_signing: bool,
    /// Deny access to the macOS clipboard (pasteboard) Mach service.
    ///
    /// The clipboard is reached via the Mach service `com.apple.pasteboard.1`.
    /// The profile emits a targeted `(deny mach-lookup …)` immediately after
    /// `(allow mach-lookup)` so SBPL last-match-wins blocks only the pasteboard
    /// service — Keychain, DNS (mDNSResponder), and all other Mach services
    /// remain reachable. Useful when the sandboxed agent must not be able to
    /// read or write clipboard contents (e.g. credential-sniffing via pbpaste).
    pub deny_clipboard: bool,
    /// Allow JVM Attach API unix sockets in /tmp (.java_pid* pattern only).
    pub allow_jvm_attach: bool,
    /// Allow Docker/Colima/OrbStack daemon socket and ~/.docker read access.
    pub allow_docker: bool,
    /// Electron app bundle Contents directory (e.g., VS Code .app/Contents).
    /// Needed when Copilot CLI is installed as a VS Code extension and uses
    /// VS Code's Electron runtime. Allows read + file-map-executable so dyld
    /// can load the Electron Framework.
    pub electron_app_dir: Option<&'a Path>,
    /// Which AI coding agent is being sandboxed.
    pub agent: Agent,
    /// Agent-specific directories that need sandbox access.
    pub agent_dirs: &'a [AgentDir],
    /// Specific ~/Library/Caches subdirs to allow process execution from.
    pub allow_cache_exec: &'a [String],
    /// Allow process execution from ALL ~/Library/Caches subdirs.
    pub allow_cache_exec_any: bool,
    /// Allow Launch Services (`open` command) for OAuth browser flows.
    pub allow_browser: bool,
}

/// Generate a complete SBPL sandbox profile from the given options.
///
/// Sections are emitted in a fixed order — SBPL uses last-match-wins semantics,
/// so deny rules must come after their corresponding allows. Each `emit_*` helper
/// writes a contiguous block; their call order must not be changed.
pub fn generate_profile(opts: &ProfileOptions) -> String {
    let mut sb = String::with_capacity(4096);
    let home = opts.home_dir.to_string_lossy();
    let project = opts.project_dir.to_string_lossy();

    // Detect Chromium browser runtime: the user has opted in to executing
    // Playwright's Chromium binaries from ~/Library/Caches/ via allow_cache_exec.
    // When true, extra system-level permissions (syscall*, system-socket,
    // iokit-open-user-client, mach-register) are emitted so Chromium can start.
    //
    // Detection matches "ms-playwright" exactly or any subpath entry whose first
    // component is "ms-playwright" (e.g. "ms-playwright/chromium-1217"). This
    // covers users who pin a specific versioned subdirectory in allow_cache_exec.
    // Substring matching (e.g. contains("playwright")) is intentionally avoided:
    // matching on the first path component prevents a rogue agent from escalating
    // privileges by creating a directory like "evil-ms-playwright-hook/".
    //
    // allow_cache_exec_any does NOT trigger these rules: it grants process-exec
    // broadly, but Chromium's extra IPC/syscall permissions should only be
    // emitted when the user explicitly signals browser testing intent.
    let allow_chromium_runtime = opts
        .allow_cache_exec
        .iter()
        .any(|s| s == "ms-playwright" || s.starts_with("ms-playwright/"));

    emit_header(&mut sb, &project);
    emit_process_rules(&mut sb);
    emit_project_access(&mut sb, &project);
    emit_home_access(&mut sb, &home, opts.agent, opts.agent_dirs);
    emit_git_hooks(&mut sb, opts.git_hooks_path);
    emit_git_worktree(&mut sb, opts.git_common_dir);
    emit_system_access(
        &mut sb,
        &home,
        opts.allow_browser,
        allow_chromium_runtime,
        opts.deny_clipboard,
    );
    emit_tool_dirs(
        &mut sb,
        opts.home_dir,
        opts.existing_home_tool_dirs,
        opts.existing_app_dirs,
        opts.agent,
        opts.allow_cache_exec,
        opts.allow_cache_exec_any,
    );
    emit_copilot_install(&mut sb, opts.copilot_install_dir);
    emit_java_home(&mut sb, opts.java_home);
    emit_electron_app(&mut sb, opts.electron_app_dir);
    emit_system_files(&mut sb);
    emit_temp_rules(
        &mut sb,
        opts.allow_tmp_exec,
        opts.allow_jvm_attach,
        opts.scratch_dir,
        allow_chromium_runtime,
    );
    emit_user_allows(&mut sb, opts.extra_read, opts.extra_write);
    emit_deny_rules(&mut sb, &home, opts.extra_deny);
    emit_registry_config_overrides(&mut sb, &home, opts.extra_read);
    emit_denied_dotfile_overrides(&mut sb, &home, opts.extra_read);
    emit_gpg_signing_rules(&mut sb, &home, opts.allow_gpg_signing, opts.extra_deny);
    emit_docker_rules(&mut sb, &home, opts.allow_docker, opts.extra_deny);
    emit_socket_rules(&mut sb, opts.allow_socket, opts.extra_deny);
    emit_network_rules(
        &mut sb,
        &home,
        opts.extra_ports,
        opts.allow_localhost_any,
        opts.proxy_port,
        opts.localhost_ports,
    );
    // Sensitive project file denies MUST come after all user-configured allows.
    // SBPL uses last-match-wins, so a user allow like `allow.read = ["~/Repos"]`
    // would override the .env deny if emitted before it.
    emit_sensitive_project_denies(&mut sb, &project, opts.allow_env_files);

    sb
}

// ── Profile section helpers ────────────────────────────────────
//
// Each function writes a contiguous SBPL block to the output string.
// Call order matters: SBPL uses last-match-wins, so denies must come
// after their corresponding allows. Do NOT reorder these calls.

fn emit_header(sb: &mut String, project: &str) {
    sbpl!(sb, ";; Auto-generated by cplt");
    sbpl!(sb, ";; Project: {project}");
    sbpl!(sb, "(version 1)");
    sbpl!(sb, "(deny default)");
    sbpl!(sb);

    sbpl!(sb, "(import \"/System/Library/Sandbox/Profiles/bsd.sb\")");
    sbpl!(sb);
}

fn emit_process_rules(sb: &mut String) {
    sbpl!(sb, ";; Process execution");
    sbpl!(sb, "(allow process-exec)");
    sbpl!(sb, "(allow process-fork)");
    // Allow sending signals to processes in the same sandbox (e.g. Turbopack killing workers)
    sbpl!(sb, "(allow signal (target same-sandbox))");
    sbpl!(sb);

    // TTY/terminal control — needed for interactive CLIs (e.g. Node.js setRawMode)
    sbpl!(
        sb,
        ";; TTY control (ioctl for terminal raw mode, window size)"
    );
    sbpl!(sb, "(allow file-ioctl)");
    sbpl!(sb);

    // Device access — Node.js needs /dev/tty, /dev/null, /dev/urandom etc.
    sbpl!(sb, ";; Device access (/dev/tty, /dev/null, /dev/urandom)");
    sbpl!(sb, "(allow file-read* (subpath \"/dev\"))");
    sbpl!(sb, "(allow file-write* (subpath \"/dev\"))");
    sbpl!(sb);
}

fn emit_project_access(sb: &mut String, project: &str) {
    // Project directory — full access
    // file-map-executable needed for native Node addons in node_modules
    // (e.g. @next/swc-*, sharp, better-sqlite3 loaded via dlopen)
    sbpl!(sb, ";; Project directory — full read/write");
    sbpl!(sb, "(allow file-read* (subpath \"{project}\"))");
    sbpl!(sb, "(allow file-write* (subpath \"{project}\"))");
    sbpl!(sb, "(allow file-map-executable (subpath \"{project}\"))");
    sbpl!(sb);
}

fn emit_sensitive_project_denies(sb: &mut String, project: &str, allow_env_files: bool) {
    // All security-critical project denies are emitted LAST in the profile.
    // SBPL uses last-match-wins, so these must come after all user-configured
    // allows (e.g. `allow.write = ["~/Repos"]`) to guarantee they cannot be
    // overridden by broad parent-path allows.

    // Git persistence prevention — deny writes to files that execute outside the sandbox.
    // .git/hooks/ — post-checkout, pre-push etc. run outside sandbox on next git operation
    // .git/config — core.hooksPath can redirect hooks to /tmp, bypassing the hooks deny;
    //               url.*.insteadOf can hijack git remotes; include.path loads arbitrary config
    // .gitmodules — submodule URLs are a supply chain vector (git submodule update clones them)
    sbpl!(sb, ";; Git persistence prevention");
    sbpl!(sb, "(deny file-write* (subpath \"{project}/.git/hooks\"))");
    sbpl!(sb, "(deny file-write* (literal \"{project}/.git/config\"))");
    sbpl!(sb, "(deny file-write* (literal \"{project}/.gitmodules\"))");
    sbpl!(sb);

    // Repo config tamper prevention — agent cannot modify its own sandbox config.
    // The agent has project write access, but .cplt.toml controls sandbox relaxation.
    // Writing it would let the agent prepare malicious config for the next session.
    sbpl!(sb, ";; Repo config — deny write to prevent tampering");
    sbpl!(sb, "(deny file-write* (literal \"{project}/.cplt.toml\"))");
    sbpl!(sb);

    // Sensitive project files — deny read AND write of .env*, .pem, .key etc.
    // Read deny: prevents exfiltration of secrets via HTTPS.
    // Write deny: prevents deletion/overwrite of secrets (rm, truncate).
    if !allow_env_files {
        sbpl!(
            sb,
            ";; Sensitive project files — deny read+write (.env*, keys)"
        );
        for pattern in SENSITIVE_PROJECT_PATTERNS {
            // SBPL regex matches against the full path, so we anchor to
            // any directory separator to avoid matching path components.
            sbpl!(sb, "(deny file-read* (regex #\"/{pattern}\"))");
            sbpl!(sb, "(deny file-write* (regex #\"/{pattern}\"))");
        }
        sbpl!(sb);
    }
}

fn emit_home_access(sb: &mut String, home: &str, agent: Agent, agent_dirs: &[AgentDir]) {
    // Agent-specific directories (Copilot: ~/.copilot, OpenCode: ~/.config/opencode, etc.)
    if agent.needs_copilot_dir() {
        // Copilot config — the CLI needs its auth tokens and settings.
        // file-map-executable is needed for native Node.js addons (keytar.node, pty.node, computer.node)
        // which are loaded via dlopen() from ~/.copilot/pkg/universal/*/prebuilds/
        sbpl!(sb, ";; Copilot config + native modules");
        sbpl!(sb, "(allow file-read* (subpath \"{home}/.copilot\"))");
        sbpl!(sb, "(allow file-write* (subpath \"{home}/.copilot\"))");
        sbpl!(
            sb,
            "(allow file-map-executable (subpath \"{home}/.copilot\"))"
        );
        // Deny writes to Copilot's installed packages (native modules).
        // Prevents persistence: a rogue agent could replace keytar.node with a
        // malicious version that runs unsandboxed next time Copilot is launched.
        // Must come after the allow (last-match-wins).
        sbpl!(sb, "(deny file-write* (subpath \"{home}/.copilot/pkg\"))");
        sbpl!(sb);
    }

    // Agent-specific directories from the Agent trait
    if !agent_dirs.is_empty() {
        sbpl!(sb, ";; {} directories", agent.display_name());
        for dir in agent_dirs {
            let path = dir.path.display();
            sbpl!(sb, "(allow file-read* (subpath \"{path}\"))");
            if dir.write {
                sbpl!(sb, "(allow file-write* (subpath \"{path}\"))");
            }
            // File-level writes: grant write to specific files without full dir write
            for file in &dir.write_files {
                let file_path = dir.path.join(file).display().to_string();
                sbpl!(sb, "(allow file-write* (literal \"{file_path}\"))");
            }
            if dir.map_exec {
                sbpl!(sb, "(allow file-map-executable (subpath \"{path}\"))");
            }
            if dir.process_exec {
                sbpl!(sb, "(allow process-exec (subpath \"{path}\"))");
            }
            // Explicitly deny exec on writable agent data dirs (write+exec = persistence risk)
            if dir.write && !dir.process_exec {
                sbpl!(sb, "(deny process-exec (subpath \"{path}\"))");
            }
            if dir.write && !dir.map_exec {
                sbpl!(sb, "(deny file-map-executable (subpath \"{path}\"))");
            }
            // Explicitly deny writes on exec-only dirs (prevents write+exec persistence
            // even when a parent dir is writable — this deny is emitted after the
            // parent allow, so SBPL last-match-wins lets it override)
            if !dir.write && dir.process_exec {
                sbpl!(sb, "(deny file-write* (subpath \"{path}\"))");
            }
        }
        sbpl!(sb);
    }

    // Claude Code: the config dir is writable (sessions, history, credentials),
    // but a few artifacts auto-execute on the HOST the next time `claude` runs
    // outside the sandbox — a persistence vector the agent never needs to write
    // mid-session. Deny those specifically (emitted after the dir-wide allow
    // above, so SBPL last-match-wins lets the deny override). settings.json,
    // commands/, agents/, skills/ stay
    // writable: Claude legitimately authors them and they require user invocation.
    // macOS only — Landlock cannot deny a subpath within an allowed dir (see SECURITY.md).
    //
    // Apply to every writable grant rather than the first one: the default layout
    // grants both ~/.claude (the data dir these subpaths live under) and the
    // ~/.claude.json file, and we must not depend on their ordering. The deny on
    // a file grant (~/.claude.json/statusline.sh) can never match a real path, so
    // it is a harmless no-op; the deny on the data dir is the one that matters.
    if matches!(agent, Agent::Claude) {
        for cfg in agent_dirs.iter().filter(|d| d.write) {
            for sub in ["statusline.sh", "plugins"] {
                let p = cfg.path.join(sub).display().to_string();
                sbpl!(sb, "(deny file-write* (subpath \"{p}\"))");
            }
        }
    }

    // GitHub CLI auth — Copilot spawns `gh auth token` which reads these specific files.
    // OpenCode may also use `gh` for auth. Allow for all agents.
    sbpl!(sb, ";; GitHub CLI auth (specific files only)");
    sbpl!(
        sb,
        "(allow file-read* (literal \"{home}/.config/gh/hosts.yml\"))"
    );
    sbpl!(
        sb,
        "(allow file-read* (literal \"{home}/.config/gh/config.yml\"))"
    );
    sbpl!(sb);

    // Microsoft DeviceID — telemetry device identifier
    sbpl!(sb, ";; Microsoft DeviceID");
    sbpl!(
        sb,
        "(allow file-read* (subpath \"{home}/Library/Application Support/Microsoft\"))"
    );
    sbpl!(sb);

    // macOS Keychain access — Copilot stores auth tokens here.
    // OpenCode uses API keys from env/config files, no Keychain needed.
    if agent.needs_keychain() {
        sbpl!(sb, ";; macOS Keychain (Copilot auth tokens)");
        sbpl!(
            sb,
            "(allow file-read* (subpath \"{home}/Library/Keychains\"))"
        );
        sbpl!(
            sb,
            "(allow file-write* (subpath \"{home}/Library/Keychains\"))"
        );
    }
    sbpl!(sb);
}

fn emit_system_access(
    sb: &mut String,
    home: &str,
    allow_browser: bool,
    allow_chromium_runtime: bool,
    deny_clipboard: bool,
) {
    // Mach IPC — Node.js and macOS frameworks need service lookups
    // (Keychain, security framework, DNS, system services)
    sbpl!(sb, ";; Mach IPC (required for Node.js, Keychain, DNS)");
    sbpl!(sb, "(allow mach-lookup)");
    if deny_clipboard {
        // Emitted immediately after (allow mach-lookup) so SBPL last-match-wins
        // carves out only com.apple.pasteboard.* — Keychain, DNS (mDNSResponder),
        // Security framework, and every other Mach service remain unaffected.
        sbpl!(
            sb,
            r#"(deny mach-lookup (global-name-regex #"^com\.apple\.pasteboard(\.|$)"))"#
        );
    }
    sbpl!(sb);

    // Chromium browser runtime support (Playwright headless testing).
    //
    // When allow_cache_exec has an entry whose first path component is
    // "ms-playwright" (i.e. "ms-playwright" exactly or "ms-playwright/<subdir>"),
    // extra system-level permissions are needed beyond process-exec and
    // file-map-executable. Without these, chrome-headless-shell segfaults
    // (SEGV_ACCERR at 0x10) during early browser initialization.
    //
    // Determined empirically by bisecting between (deny default) and (allow default):
    //
    // 1. syscall* — system.sb guards `(allow syscall*)` with `(unless *import-path*
    //    ...)`, so it is NOT included when bsd.sb is imported. Most programs work
    //    without it because the sandbox only filters a small subset of syscalls
    //    (Mach traps, certain security-sensitive calls). Chromium's multi-process
    //    architecture uses filtered Mach traps that Node.js and git do not.
    //
    // 2. system-socket — Chromium creates sockets for IPC between its browser,
    //    renderer, and GPU processes. Without this, internal IPC setup fails.
    //    Scoped to AF_UNIX (Unix domain sockets) — Chromium's multi-process IPC
    //    uses Unix sockets, not TCP/UDP between its child processes.
    //
    // 3. iokit-open-user-client — Chromium probes GPU capabilities via IOKit
    //    user clients during renderer init, even in headless mode (SwiftShader
    //    fallback still queries IOKit before deciding to use software rendering).
    //
    // 4. mach-register — Chromium registers Mach services under the org.chromium.*
    //    namespace for IPC between browser, renderer, GPU, and Crashpad processes.
    //    Crashpad's child_port_handshake uses bootstrap_check_in() which requires
    //    this permission; without it, EPERM (1100) cascades into a segfault.
    //    Scoped to ^org\.chromium\..+$ — the trailing \. prevents matching
    //    "org.chromiumevil" and the .+$ ensures at least one character follows
    //    (Chromium uses variable-depth subnamespaces like crashpad.*, Chromium.*).
    //
    // SECURITY: these rules only activate when the user has explicitly opted in
    // to browser execution via allow_cache_exec containing "ms-playwright" or a
    // subpath like "ms-playwright/chromium-1217" (first component must match exactly).
    // syscall* is the broadest rule — Chrome uses undocumented Mach traps that
    // cannot be individually enumerated in a stable allowlist across OS versions.
    // iokit-open-user-client is unscoped because IOKit class names vary by GPU
    // hardware and macOS version; scoping would break on different machines.
    // system-socket is scoped to AF_UNIX — only Unix domain sockets, not TCP/UDP.
    // mach-register is scoped to ^org\.chromium\..+$ to prevent registration
    // of arbitrary global Mach services.
    if allow_chromium_runtime {
        sbpl!(
            sb,
            ";; Chromium browser runtime (Playwright headless testing)"
        );
        sbpl!(sb, "(allow syscall*)");
        sbpl!(sb, "(allow system-socket (socket-domain AF_UNIX))");
        sbpl!(sb, "(allow iokit-open-user-client)");
        sbpl!(
            sb,
            r#"(allow mach-register (global-name-regex #"^org\.chromium\..+$"))"#
        );
        sbpl!(sb);
    }

    // System info — Node.js queries CPU count, memory, OS version
    sbpl!(sb, ";; System info (Node.js runtime needs these)");
    sbpl!(sb, "(allow sysctl-read)");
    sbpl!(sb, "(allow ipc-posix-shm-read-data)");
    sbpl!(sb, "(allow ipc-posix-shm-write-data)");
    sbpl!(sb, "(allow ipc-posix-shm-write-create)");
    sbpl!(sb);

    // Launch Services — allows `open` to launch URLs in the default browser.
    // Needed for OAuth code flows (MCP servers, Gemini CLI, gh auth).
    // Opt-in because it lets the agent leverage the user's browser session state.
    if allow_browser {
        sbpl!(sb, ";; Launch Services (OAuth browser flows)");
        sbpl!(sb, "(allow lsopen)");
        sbpl!(sb);
    }

    // User preferences — Keychain and security framework read preferences
    sbpl!(sb, ";; User preferences (Keychain, security framework)");
    sbpl!(sb, "(allow user-preference-read)");
    sbpl!(sb);

    // Security framework databases — needed for Keychain/TLS operations
    sbpl!(sb, ";; Security framework databases");
    sbpl!(sb, "(allow file-read* (subpath \"/private/var/db/mds\"))");
    sbpl!(sb);

    // Git config (read-only)
    sbpl!(sb, ";; Git config (read-only)");
    sbpl!(sb, "(allow file-read* (literal \"{home}/.gitconfig\"))");
    sbpl!(
        sb,
        "(allow file-read* (literal \"{home}/.config/git/config\"))"
    );
    sbpl!(sb);

    // Tool version files — mise/asdf read these to determine tool versions
    sbpl!(sb, ";; Tool version files (mise/asdf, read-only)");
    sbpl!(sb, "(allow file-read* (literal \"{home}/.tool-versions\"))");
    sbpl!(sb);
}

/// Allow reading global git hooks from `core.hooksPath`.
///
/// Git hooks are user-configured scripts that run on commit/push/etc.
/// We explicitly deny writes to prevent a persistence attack: a rogue agent
/// could plant hooks (pre-commit, post-checkout) that execute unsandboxed
/// the next time the user runs git outside cplt.
fn emit_git_hooks(sb: &mut String, git_hooks_path: Option<&Path>) {
    if let Some(hooks) = git_hooks_path {
        let p = hooks.to_string_lossy();
        sbpl!(sb, ";; Global git hooks (core.hooksPath)");
        sbpl!(sb, "(allow file-read* (subpath \"{p}\"))");
        // Deny writes — hooks must not be modifiable from the sandbox.
        // Must come after any broader allow (last-match-wins).
        sbpl!(sb, "(deny file-write* (subpath \"{p}\"))");
        sbpl!(sb);
    }
}

/// Grant access to the shared .git directory for git worktrees.
/// Git worktrees share objects, refs, and packed-refs with the main repo.
/// Security denies (hooks, config) are applied to the common dir too.
fn emit_git_worktree(sb: &mut String, git_common_dir: Option<&Path>) {
    if let Some(common) = git_common_dir {
        let p = common.to_string_lossy();
        sbpl!(sb, ";; Git worktree shared directory");
        sbpl!(sb, "(allow file-read* (subpath \"{p}\"))");
        sbpl!(sb, "(allow file-write* (subpath \"{p}\"))");
        // Apply the same security denies as the project .git directory
        sbpl!(sb, "(deny file-write* (subpath \"{p}/hooks\"))");
        sbpl!(sb, "(deny file-write* (literal \"{p}/config\"))");
        sbpl!(sb);
    }
}

fn emit_tool_dirs(
    sb: &mut String,
    home_dir: &std::path::Path,
    existing_home_tool_dirs: Option<&[String]>,
    existing_app_dirs: Option<&[String]>,
    agent: Agent,
    allow_cache_exec: &[String],
    allow_cache_exec_any: bool,
) {
    let home = home_dir.to_string_lossy();
    sbpl!(sb, ";; Developer tools");
    for dir in TOOL_READ_DIRS {
        sbpl!(sb, "(allow file-read* (subpath \"{dir}\"))");
        sbpl!(sb, "(allow file-map-executable (subpath \"{dir}\"))");
    }
    // Home tool dirs: use discovered existing dirs if available, else include all
    let active_dirs: Vec<&HomeToolDir> = match existing_home_tool_dirs {
        Some(dirs) => HOME_TOOL_DIRS
            .iter()
            .filter(|d| dirs.iter().any(|s| s == d.path))
            .collect(),
        None => HOME_TOOL_DIRS.iter().collect(),
    };

    for dir in &active_dirs {
        let p = dir.path;
        sbpl!(sb, "(allow file-read* (subpath \"{home}/{p}\"))");
        if dir.process_exec {
            sbpl!(sb, "(allow process-exec (subpath \"{home}/{p}\"))");
        }
        if dir.map_exec {
            sbpl!(sb, "(allow file-map-executable (subpath \"{home}/{p}\"))");
        }
        if dir.write {
            sbpl!(sb, "(allow file-write* (subpath \"{home}/{p}\"))");
        }
    }
    // Deny exec from writable dirs that should not have it.
    // Must come AFTER allows (last-match-wins in Seatbelt).
    // The blanket (allow process-exec) means we need explicit denies,
    // not just absence of a per-dir allow.
    for dir in &active_dirs {
        let p = dir.path;
        if dir.write && !dir.process_exec {
            sbpl!(sb, "(deny process-exec (subpath \"{home}/{p}\"))");
        }
        if dir.write && !dir.map_exec {
            sbpl!(sb, "(deny file-map-executable (subpath \"{home}/{p}\"))");
        }
    }

    // App dirs: absolute paths resolved from XDG/macOS conventions.
    // Use discovered existing dirs if available, else include all.
    // Per-path filtering: each path is checked individually against existing_app_dirs.
    for dir in app_dirs() {
        let read_paths = dir.read_paths(home_dir);
        let write_paths = dir.write_paths(home_dir);
        let process_exec_paths = dir.process_exec_paths(home_dir);
        let map_exec_paths = dir.map_exec_paths(home_dir);

        // Allow rules first — emit only for paths that pass the inclusion check.
        for path in dir.all_paths(home_dir) {
            let include = match existing_app_dirs {
                Some(existing) => existing
                    .iter()
                    .any(|e| e == path.to_string_lossy().as_ref()),
                None => true,
            };
            if !include {
                continue;
            }
            if validate_sbpl_path(&path).is_err() {
                continue;
            }
            let p = path.display();
            if read_paths.contains(&path) {
                sbpl!(sb, "(allow file-read* (subpath \"{p}\"))");
            }
            if write_paths.contains(&path) {
                sbpl!(sb, "(allow file-write* (subpath \"{p}\"))");
            }
            if process_exec_paths.contains(&path) {
                sbpl!(sb, "(allow process-exec (subpath \"{p}\"))");
            }
            if map_exec_paths.contains(&path) {
                sbpl!(sb, "(allow file-map-executable (subpath \"{p}\"))");
            }
        }
        // Deny exec on writable paths that are not in exec lists (last-match-wins).
        // Must come after allows; only emit for included paths.
        for path in &write_paths {
            let include = match existing_app_dirs {
                Some(existing) => existing
                    .iter()
                    .any(|e| e == path.to_string_lossy().as_ref()),
                None => true,
            };
            if !include {
                continue;
            }
            if validate_sbpl_path(path).is_err() {
                continue;
            }
            let p = path.display();
            if !process_exec_paths.contains(path) {
                sbpl!(sb, "(deny process-exec (subpath \"{p}\"))");
            }
            if !map_exec_paths.contains(path) {
                sbpl!(sb, "(deny file-map-executable (subpath \"{p}\"))");
            }
        }
    }

    // Deny non-dev cache dirs under ~/Library/Caches/ (browsers, system apps).
    // Uses prefix matching on reverse-domain bundle IDs — stable across versions.
    // Dev tool caches (go-build, pip, etc.) don't use these prefixes, so they
    // pass through automatically without needing an explicit allowlist.
    // Xcode dev tools (com.apple.dt.*) are re-allowed after the broad com.apple. deny.
    sbpl!(sb, ";; Non-dev cache dirs denied (browsers, system apps)");
    for prefix in DENIED_CACHE_PREFIXES {
        // Escape dots for SBPL regex
        let escaped = prefix.replace('.', r"\.");
        sbpl!(
            sb,
            "(deny file-read* (regex #\"^{home}/Library/Caches/{escaped}\"))"
        );
        sbpl!(
            sb,
            "(deny file-write* (regex #\"^{home}/Library/Caches/{escaped}\"))"
        );
    }
    // Re-allow Xcode dev tools (com.apple.dt.Xcode, com.apple.dt.xcodebuild)
    sbpl!(
        sb,
        "(allow file-read* (regex #\"^{home}/Library/Caches/com\\.apple\\.dt\\.\"))"
    );
    sbpl!(
        sb,
        "(allow file-write* (regex #\"^{home}/Library/Caches/com\\.apple\\.dt\\.\"))"
    );

    // Copilot CLI v1.0.22+ stores native modules and helper binaries in
    // ~/Library/Caches/copilot/pkg/. The Library/Caches deny above blocks
    // process-exec and file-map-executable broadly. These carve-outs re-enable:
    //   - file-map-executable: dlopen() for native modules (keytar.node, pty.node)
    //   - process-exec: helper binaries (spawn-helper, rg) that Copilot spawns
    //   - deny file-write*: prevent write-then-exec attacks (writable + executable
    //     is a binary-drop staging risk). Auto-update is already blocked inside
    //     the sandbox (--no-auto-update), so writes are not needed.
    // Must come AFTER the denies (last-match-wins in SBPL).
    // Only needed for Copilot agent.
    if agent.needs_copilot_dir() {
        sbpl!(
            sb,
            "(allow file-map-executable (subpath \"{home}/Library/Caches/copilot/pkg\"))"
        );
        sbpl!(
            sb,
            "(allow process-exec (subpath \"{home}/Library/Caches/copilot/pkg\"))"
        );
        sbpl!(
            sb,
            "(deny file-write* (subpath \"{home}/Library/Caches/copilot/pkg\"))"
        );
        sbpl!(sb);
    }

    // User-specified ~/Library/Caches exec carve-outs.
    // Emitted AFTER the broad exec denies (last-match-wins), so these override.
    // Write access is already granted by the HOME_TOOL_DIRS allow for ~/Library/Caches —
    // these rules add only process-exec and file-map-executable on top of that.
    // allow_cache_exec_any re-allows exec across the entire Library/Caches subtree.
    if allow_cache_exec_any {
        sbpl!(
            sb,
            "(allow process-exec (subpath \"{home}/Library/Caches\"))"
        );
        sbpl!(
            sb,
            "(allow file-map-executable (subpath \"{home}/Library/Caches\"))"
        );
        sbpl!(sb);
    } else {
        for subdir in allow_cache_exec {
            sbpl!(
                sb,
                "(allow process-exec (subpath \"{home}/Library/Caches/{subdir}\"))"
            );
            sbpl!(
                sb,
                "(allow file-map-executable (subpath \"{home}/Library/Caches/{subdir}\"))"
            );
        }
        if !allow_cache_exec.is_empty() {
            sbpl!(sb);
        }
    }
}

/// Allow reading and dlopen from the Copilot CLI package directory.
/// Needed when Copilot is installed via a non-standard Node version manager
/// (e.g. `n` at ~/n/) whose path isn't covered by TOOL_READ_DIRS.
fn emit_copilot_install(sb: &mut String, install_dir: Option<&Path>) {
    if let Some(dir) = install_dir {
        let p = dir.to_string_lossy();
        sbpl!(sb, ";; Copilot CLI installation directory");
        sbpl!(sb, "(allow file-read* (subpath \"{p}\"))");
        sbpl!(sb, "(allow file-map-executable (subpath \"{p}\"))");
        sbpl!(sb);
    }
}

/// Allow reading and loading JDK libraries from JAVA_HOME.
/// Needed when Java is installed outside TOOL_READ_DIRS — e.g. version managers
/// (sdkman, actions/setup-java hostedtoolcache) that place the JDK under HOME.
fn emit_java_home(sb: &mut String, java_home: Option<&Path>) {
    if let Some(dir) = java_home {
        let p = dir.to_string_lossy();
        sbpl!(sb, ";; JAVA_HOME — JDK read + dylib loading");
        sbpl!(sb, "(allow file-read* (subpath \"{p}\"))");
        sbpl!(sb, "(allow file-map-executable (subpath \"{p}\"))");
        sbpl!(sb);
    }
}

/// Allow reading and loading shared libraries from an Electron app bundle.
/// Needed when Copilot CLI uses VS Code's (or similar editor's) Electron as its
/// Node.js runtime — dyld must load `Electron Framework.framework` from within
/// the `.app/Contents` directory.
fn emit_electron_app(sb: &mut String, electron_app: Option<&Path>) {
    if let Some(dir) = electron_app {
        let p = dir.to_string_lossy();
        sbpl!(
            sb,
            ";; Electron app bundle (VS Code runtime for Copilot CLI)"
        );
        sbpl!(sb, "(allow file-read* (subpath \"{p}\"))");
        sbpl!(sb, "(allow file-map-executable (subpath \"{p}\"))");
        sbpl!(sb);
    }
}

fn emit_system_files(sb: &mut String) {
    sbpl!(sb, ";; System config (specific files)");
    for path in SYSTEM_READ_FILES {
        if path.contains('/') && !path.ends_with('/') {
            // Could be a file or directory — use subpath for dirs like /private/etc/ssl
            if path.ends_with("ssl") {
                sbpl!(sb, "(allow file-read* (subpath \"{path}\"))");
            } else {
                sbpl!(sb, "(allow file-read* (literal \"{path}\"))");
            }
        } else {
            sbpl!(sb, "(allow file-read* (literal \"{path}\"))");
        }
    }
    sbpl!(sb);
}

fn emit_temp_rules(
    sb: &mut String,
    allow_tmp_exec: bool,
    allow_jvm_attach: bool,
    scratch_dir: Option<&Path>,
    allow_chromium_runtime: bool,
) {
    sbpl!(sb, ";; Temp directories");
    sbpl!(sb, "(allow file-read* (subpath \"/private/tmp\"))");
    sbpl!(sb, "(allow file-write* (subpath \"/private/tmp\"))");
    sbpl!(sb, "(allow file-read* (subpath \"/private/var/folders\"))");
    sbpl!(sb, "(allow file-write* (subpath \"/private/var/folders\"))");
    if allow_chromium_runtime {
        // Chrome's ProcessSingleton binds a Unix socket in the macOS user temp dir
        // to prevent multiple Chrome instances sharing the same profile directory.
        // Three operations are required (same pattern as the JVM attach rules below):
        //   - network-bind:    Chrome creates the socket on first launch
        //   - network-inbound: Chrome accepts "already running" probes
        //   - network-outbound: a second Chrome instance connects to check the first
        //
        // Path follows Chrome for Testing's bundle ID convention:
        //   /private/var/folders/.../T/com.google.chrome.for.testing.<random>/SingletonSocket
        //
        // SECURITY: regex is anchored with ^ and $ to the exact bundle-ID prefix
        // and filename. Path segments use [^/]+ (not .+) to prevent matching across
        // directory boundaries, matching the known macOS 2-segment var/folders layout.
        for op in &[
            r#"(allow network-bind (local unix-socket (regex #"^/private/var/folders/[^/]+/[^/]+/T/com\.google\.chrome\.for\.testing\.[^/]+/SingletonSocket$")))"#,
            r#"(allow network-inbound (local unix-socket (regex #"^/private/var/folders/[^/]+/[^/]+/T/com\.google\.chrome\.for\.testing\.[^/]+/SingletonSocket$")))"#,
            r#"(allow network-outbound (remote unix-socket (regex #"^/private/var/folders/[^/]+/[^/]+/T/com\.google\.chrome\.for\.testing\.[^/]+/SingletonSocket$")))"#,
        ] {
            sbpl!(sb, "{op}");
        }
        sbpl!(sb);
    }
    if allow_jvm_attach {
        // Allow Unix domain socket operations for JVM Attach API.
        //
        // ByteBuddy/MockK uses VirtualMachine.attach() which:
        //   1. Creates .attach_pid<PID> trigger file (covered by file-write* above)
        //   2. Sends SIGQUIT to target JVM (covered by signal same-sandbox)
        //   3. Target binds a unix socket at .java_pid<PID>.tmp, renames to .java_pid<PID>
        //   4. Attacher connects to the socket, loads agent
        //
        // All three socket operations are required:
        //   - network-bind:    target creates the socket
        //   - network-inbound: target accepts the connection
        //   - network-outbound: attacher connects to the socket
        //
        // On macOS, the JDK uses confstr(_CS_DARWIN_USER_TEMP_DIR) — NOT java.io.tmpdir —
        // so sockets appear at /var/folders/<xx>/<hash>/T/.java_pid<PID> rather than /tmp.
        // We allow both paths for compatibility with older JDKs that use /tmp.
        //
        // SECURITY: regex-restricted to .java_pid pattern only — a broad
        // (subpath "/private/tmp") would expose SSH_AUTH_SOCK which lives at
        // /private/tmp/com.apple.launchd.*/Listeners on macOS.
        //
        // Note: SBPL regex does not reliably support POSIX character classes like
        // [a-z0-9]{2} in network operations, so we use .+ for the hash directories.
        for op in &[
            r#"(allow network-bind (local unix-socket (regex #"^/private/tmp/\.java_pid")))"#,
            r#"(allow network-inbound (local unix-socket (regex #"^/private/tmp/\.java_pid")))"#,
            r#"(allow network-outbound (remote unix-socket (regex #"^/private/tmp/\.java_pid")))"#,
            r#"(allow network-bind (local unix-socket (regex #"^/private/var/folders/.+/T/\.java_pid")))"#,
            r#"(allow network-inbound (local unix-socket (regex #"^/private/var/folders/.+/T/\.java_pid")))"#,
            r#"(allow network-outbound (remote unix-socket (regex #"^/private/var/folders/.+/T/\.java_pid")))"#,
        ] {
            sbpl!(sb, "{op}");
        }
    }
    if !allow_tmp_exec {
        // Deny direct execution and dlopen from writable temp dirs.
        // Prevents write-then-exec attacks (drop binary → execute it).
        // Limitation: does NOT block interpreter-based exec (e.g. `bash /tmp/evil.sh`,
        // `node /tmp/evil.js`) because the exec target is the interpreter, not the script.
        sbpl!(sb, "(deny process-exec (subpath \"/private/tmp\"))");
        sbpl!(sb, "(deny file-map-executable (subpath \"/private/tmp\"))");
        sbpl!(sb, "(deny process-exec (subpath \"/private/var/folders\"))");
        sbpl!(
            sb,
            "(deny file-map-executable (subpath \"/private/var/folders\"))"
        );
    }
    sbpl!(sb);

    // Per-session scratch directory — write+exec for tools that compile-then-execute
    if let Some(scratch) = scratch_dir {
        let scratch_path = scratch.to_string_lossy();
        sbpl!(sb, ";; Per-session scratch directory (TMPDIR redirect)");
        sbpl!(sb, "(allow file-read* (subpath \"{scratch_path}\"))");
        sbpl!(sb, "(allow file-write* (subpath \"{scratch_path}\"))");
        sbpl!(sb, "(allow process-exec (subpath \"{scratch_path}\"))");
        sbpl!(
            sb,
            "(allow file-map-executable (subpath \"{scratch_path}\"))"
        );
        // Allow Unix domain sockets in scratch dir (build daemons may create them here)
        sbpl!(
            sb,
            "(allow network-bind (local unix-socket (subpath \"{scratch_path}\")))"
        );
        sbpl!(
            sb,
            "(allow network-inbound (local unix-socket (subpath \"{scratch_path}\")))"
        );
        sbpl!(
            sb,
            "(allow network-outbound (remote unix-socket (subpath \"{scratch_path}\")))"
        );
        sbpl!(sb);
    }
}

fn emit_user_allows(sb: &mut String, extra_read: &[PathBuf], extra_write: &[PathBuf]) {
    if !extra_read.is_empty() || !extra_write.is_empty() {
        sbpl!(sb, ";; User-specified allows");
        for path in extra_read {
            let p = path.to_string_lossy();
            sbpl!(sb, "(allow file-read* (subpath \"{p}\"))");
        }
        for path in extra_write {
            let p = path.to_string_lossy();
            sbpl!(sb, "(allow file-read* (subpath \"{p}\"))");
            sbpl!(sb, "(allow file-write* (subpath \"{p}\"))");
        }
        sbpl!(sb);
    }
}

fn emit_deny_rules(sb: &mut String, home: &str, extra_deny: &[PathBuf]) {
    // Sensitive directories — DENY (after allows, so these override)
    sbpl!(sb, ";; Sensitive directories — DENIED");
    for dotfile in DENIED_DOTFILES {
        sbpl!(sb, "(deny file-read* (subpath \"{home}/{dotfile}\"))");
        sbpl!(sb, "(deny file-write* (subpath \"{home}/{dotfile}\"))");
    }
    for file in DENIED_FILES {
        sbpl!(sb, "(deny file-read* (literal \"{home}/{file}\"))");
        sbpl!(sb, "(deny file-write* (literal \"{home}/{file}\"))");
    }
    // Credential files inside allowed tool dirs (overridable with --allow-read)
    for file in DENIED_HOME_SUBPATHS {
        sbpl!(sb, "(deny file-read* (literal \"{home}/{file}\"))");
        sbpl!(sb, "(deny file-write* (literal \"{home}/{file}\"))");
    }
    for path in extra_deny {
        let p = path.to_string_lossy();
        sbpl!(sb, "(deny file-read* (subpath \"{p}\"))");
        sbpl!(sb, "(deny file-write* (subpath \"{p}\"))");
    }
    sbpl!(sb);
}

/// Re-allow credential files from `DENIED_HOME_SUBPATHS` when the user
/// explicitly opts in via `--allow-read` or `allow.read` in config.toml.
///
/// Emitted AFTER `emit_deny_rules` so SBPL last-match-wins re-allows the file.
/// Only matches exact paths from `DENIED_HOME_SUBPATHS` — hard denies
/// (DENIED_FILES, DENIED_DOTFILES) cannot be overridden this way.
fn emit_registry_config_overrides(sb: &mut String, home: &str, extra_read: &[PathBuf]) {
    let home_path = Path::new(home);
    let mut overrides: Vec<&str> = Vec::new();

    for &file in DENIED_HOME_SUBPATHS {
        let full_path = home_path.join(file);
        if extra_read.iter().any(|p| p == &full_path) {
            overrides.push(file);
        }
    }

    if !overrides.is_empty() {
        sbpl!(
            sb,
            ";; User-overridden registry config files (--allow-read)"
        );
        for file in &overrides {
            sbpl!(sb, "(allow file-read* (literal \"{home}/{file}\"))");
        }
        sbpl!(sb);
    }
}

/// Re-allow specific files inside DENIED_DOTFILES directories when the user
/// has explicitly approved them via `allow.read`.
///
/// DENIED_DOTFILES uses `(deny file-read* (subpath ...))` which blocks entire
/// directories. When a user explicitly approves a file inside one of these dirs,
/// we emit a targeted `(allow file-read* (literal ...))` AFTER the deny so
/// SBPL last-match-wins grants access to that specific file only.
fn emit_denied_dotfile_overrides(sb: &mut String, home: &str, extra_read: &[PathBuf]) {
    let home_path = Path::new(home);
    let mut overrides: Vec<String> = Vec::new();

    for path in extra_read {
        for &dotfile in DENIED_DOTFILES {
            let denied_dir = home_path.join(dotfile);
            if path.starts_with(&denied_dir) && *path != denied_dir {
                overrides.push(path.to_string_lossy().into_owned());
                break;
            }
        }
    }

    if !overrides.is_empty() {
        sbpl!(
            sb,
            ";; User-overridden files in sensitive directories (allow.read)"
        );
        for path in &overrides {
            sbpl!(sb, "(allow file-read* (literal \"{path}\"))");
        }
        sbpl!(sb);
    }
}

/// Allow GPG commit signing when `--allow-gpg-signing` is set.
///
/// Emitted AFTER `emit_deny_rules` (which denies all of `~/.gnupg`).
/// SBPL uses last-match-wins, so these targeted allows override the
/// blanket deny. Private keys (`private-keys-v1.d/` and legacy
/// `secring.gpg`) are explicitly re-denied after the allows to
/// ensure they remain locked.
///
/// If any `extra_deny` path overlaps with `~/.gnupg`, GPG rules are
/// skipped entirely — explicit user denies always win.
fn emit_gpg_signing_rules(
    sb: &mut String,
    home: &str,
    allow_gpg_signing: bool,
    extra_deny: &[PathBuf],
) {
    if !allow_gpg_signing {
        return;
    }
    // Explicit --deny-path wins: if the user denied anything under ~/.gnupg,
    // skip all GPG allows so the deny is not overridden.
    let gnupg_dir = format!("{home}/.gnupg");
    for deny in extra_deny {
        let d = deny.to_string_lossy();
        if d == gnupg_dir || d.starts_with(&format!("{gnupg_dir}/")) {
            sbpl!(
                sb,
                ";; GPG signing skipped: --deny-path overlaps with ~/.gnupg"
            );
            return;
        }
    }
    sbpl!(sb, ";; GPG signing (--allow-gpg-signing)");
    // Allow read-only access to public keyring and config
    for file in GPG_SIGNING_ALLOW_FILES {
        sbpl!(sb, "(allow file-read* (literal \"{home}/.gnupg/{file}\"))");
    }
    // Allow connecting to the GPG agent socket for signing requests.
    // The agent holds private keys in memory — the socket is the only
    // interface, and the Assuan protocol cannot export keys.
    // file-read* is needed for the inode lookup before connect(2).
    // S.keyboxd is needed for GnuPG 2.4+ with keyboxd-managed public keys.
    for socket in &["S.gpg-agent", "S.keyboxd"] {
        sbpl!(
            sb,
            "(allow file-read* (literal \"{home}/.gnupg/{socket}\"))"
        );
        sbpl!(
            sb,
            "(allow network-outbound (literal \"{home}/.gnupg/{socket}\"))"
        );
    }
    // Private keys must remain denied even with GPG signing enabled.
    // Covers both modern (private-keys-v1.d/) and legacy (secring.gpg).
    sbpl!(
        sb,
        "(deny file-read* (subpath \"{home}/.gnupg/private-keys-v1.d\"))"
    );
    sbpl!(
        sb,
        "(deny file-read* (literal \"{home}/.gnupg/secring.gpg\"))"
    );
    // No write access to any part of .gnupg
    sbpl!(sb, "(deny file-write* (subpath \"{home}/.gnupg\"))");
    sbpl!(sb);
}

/// Docker/Podman daemon socket paths to allow when `--allow-docker` is set.
/// On macOS, `/var/run` is a symlink to `/private/var/run`.
const DOCKER_SOCKET_PATHS: &[&str] = &[
    "/private/var/run/docker.sock",
    ".colima/default/docker.sock", // Colima (default profile)
    ".colima/docker.sock",         // Colima (root-level)
    ".orbstack/run/docker.sock",   // OrbStack
    ".docker/run/docker.sock",     // Docker Desktop (newer)
    ".local/share/containers/podman/machine/podman.sock", // Podman Machine
    ".local/share/containers/podman/machine/qemu/podman.sock", // Podman Machine (QEMU)
    ".finch/docker.sock",          // AWS Finch
    "Library/Application Support/rancher-desktop/lima/docker.sock", // Rancher Desktop
];

fn emit_socket_rules(sb: &mut String, allow_socket: &[PathBuf], extra_deny: &[PathBuf]) {
    if allow_socket.is_empty() {
        return;
    }

    sbpl!(sb, ";; Unix domain sockets (--allow-socket)");
    for path in allow_socket {
        let path_str = path.to_string_lossy();

        // SECURITY: check if the user explicitly denied the socket path
        let mut denied = false;
        for d in extra_deny {
            if path == d || path.starts_with(d) {
                denied = true;
                break;
            }
        }
        if denied {
            sbpl!(
                sb,
                ";; Socket access skipped: --deny-path overlaps with {}",
                path_str
            );
            continue;
        }

        sbpl!(sb, "(allow file-read* (literal \"{}\"))", path_str);
        sbpl!(sb, "(allow file-write* (literal \"{}\"))", path_str);
        sbpl!(
            sb,
            "(allow network-outbound (remote unix-socket (literal \"{}\")))",
            path_str
        );
        sbpl!(
            sb,
            "(allow network-bind (local unix-socket (literal \"{}\")))",
            path_str
        );
        sbpl!(
            sb,
            "(allow network-inbound (local unix-socket (literal \"{}\")))",
            path_str
        );
    }
    sbpl!(sb);
}

/// Allow Docker access when `--allow-docker` is set.
///
/// Emitted AFTER `emit_deny_rules` (which denies all of `~/.docker`).
/// SBPL uses last-match-wins, so these targeted allows override the deny.
/// Sensitive files under ~/.docker (trust/, TLS private keys) remain denied.
///
/// If any `extra_deny` path overlaps with `~/.docker` or known socket paths,
/// Docker rules are skipped entirely — explicit user denies always win.
fn emit_docker_rules(sb: &mut String, home: &str, allow_docker: bool, extra_deny: &[PathBuf]) {
    if !allow_docker {
        return;
    }

    // Explicit --deny-path wins: if the user denied ~/.docker or any socket path, skip all.
    let docker_dir = format!("{home}/.docker");
    for deny in extra_deny {
        let d = deny.to_string_lossy();
        if d == docker_dir || d.starts_with(&format!("{docker_dir}/")) {
            sbpl!(
                sb,
                ";; Docker access skipped: --deny-path overlaps with ~/.docker"
            );
            return;
        }
        // Check socket paths
        for sock in DOCKER_SOCKET_PATHS {
            let full = if sock.starts_with('/') {
                sock.to_string()
            } else {
                format!("{home}/{sock}")
            };
            if *d == full {
                sbpl!(
                    sb,
                    ";; Docker access skipped: --deny-path overlaps with socket {sock}"
                );
                return;
            }
        }
    }

    sbpl!(sb, ";; Docker/Podman access (--allow-docker)");

    // Read-only access to ~/.docker for Docker CLI config and TLS certs.
    sbpl!(sb, "(allow file-read* (subpath \"{home}/.docker\"))");

    // Re-deny sensitive subdirectories: trust delegation keys, signing keys.
    sbpl!(
        sb,
        "(deny file-read* (subpath \"{home}/.docker/trust/private\"))"
    );

    // No write access to Docker config.
    sbpl!(sb, "(deny file-write* (subpath \"{home}/.docker\"))");

    // Read-only access to ~/.config/containers for Podman CLI config
    // (registries.conf, containers.conf, auth.json read by podman/buildah).
    sbpl!(
        sb,
        "(allow file-read* (subpath \"{home}/.config/containers\"))"
    );

    // Allow Docker/Podman daemon socket connections.
    // Each socket needs file-read* (inode lookup) + network-outbound (connect).
    for sock in DOCKER_SOCKET_PATHS {
        let full = if sock.starts_with('/') {
            sock.to_string()
        } else {
            format!("{home}/{sock}")
        };
        sbpl!(sb, "(allow file-read* (literal \"{full}\"))");
        sbpl!(sb, "(allow network-outbound (literal \"{full}\"))");
    }

    sbpl!(sb);
}

fn emit_network_rules(
    sb: &mut String,
    home: &str,
    extra_ports: &[u16],
    allow_localhost_any: bool,
    proxy_port: Option<u16>,
    localhost_ports: &[u16],
) {
    // Network — outbound restricted to HTTPS/HTTP, localhost blocked by default.
    // Copilot CLI connects directly to api.githubcopilot.com:443 etc.
    // We can't do domain-based rules in SBPL, but we can restrict ports and
    // block localhost to prevent SSRF attacks against local services.
    sbpl!(sb, ";; Network — restricted outbound, localhost blocked");

    // DNS resolution — only the specific mDNSResponder socket, NOT all unix-sockets.
    // Blocking (remote unix-socket) prevents SSH agent access via launchd sockets.
    sbpl!(
        sb,
        "(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))"
    );

    // Outbound TCP restricted to port 443 (HTTPS only).
    // All Copilot/GitHub APIs use HTTPS — port 80 is not needed and would
    // allow unencrypted exfiltration. Use --allow-port 80 if required.
    sbpl!(sb, "(deny network-outbound (remote tcp))");
    sbpl!(sb, "(allow network-outbound (remote ip \"*:443\"))");

    // Extra ports (e.g., MCP servers, custom services)
    for port in extra_ports {
        sbpl!(sb, "(allow network-outbound (remote ip \"*:{port}\"))");
    }

    // Block localhost outbound — prevents SSRF to local dev servers, databases, etc.
    // Must come AFTER port allows so it overrides them for localhost.
    if allow_localhost_any {
        // Allow all localhost ports. With -Djava.net.preferIPv4Stack=true injected
        // via JAVA_TOOL_OPTIONS (macOS), Java connections stay as pure IPv4 and
        // "localhost:*" matches correctly. No need for "*:*" anymore.
        sbpl!(sb, "(allow network-outbound (remote ip \"localhost:*\"))");
    } else {
        // Defense-in-depth: the general `(deny network-outbound (remote tcp))` above
        // already blocks all TCP. This adds explicit localhost deny for clarity.
        sbpl!(sb, "(deny network-outbound (remote ip \"localhost:*\"))");
    }

    // Carve-outs for specific localhost ports (proxy, MCP servers, dev servers).
    // These come AFTER the deny so they override it (last-match-wins in SBPL).
    if let Some(port) = proxy_port {
        sbpl!(
            sb,
            "(allow network-outbound (remote ip \"localhost:{port}\"))"
        );
    }
    for port in localhost_ports {
        sbpl!(
            sb,
            "(allow network-outbound (remote ip \"localhost:{port}\"))"
        );
    }

    // Allow binding and accepting on localhost TCP ports.
    // Needed for: cplt proxy listener, MCP servers, Gradle/Kotlin daemons,
    // dev servers started by the agent.
    //
    // We use `"*:*"` instead of `"localhost:*"` because of a macOS SBPL bug:
    // `(local ip "localhost:*")` matches IPv6 (::1) and INADDR_ANY (0.0.0.0)
    // but does NOT match IPv4 127.0.0.1 bind() calls. Since SBPL only accepts
    // `*` or `localhost` as the host part (literal IPs cause errors), we must
    // use `"*:*"` to cover all local addresses including 127.0.0.1.
    //
    // Security note: this allows binding on all interfaces, not just loopback.
    // Mitigations:
    //   1. Outbound is locked to port 443 via proxy — no data exfiltration
    //   2. Dev machines are typically behind NAT/firewall
    //   3. Inbound connections from external IPs are rare in practice
    //   4. Most build tools (Gradle, Kotlin) bind to 127.0.0.1 explicitly
    sbpl!(sb, "(allow network-bind (local ip \"*:*\"))");
    sbpl!(sb, "(allow network-inbound (local ip \"*:*\"))");

    // Allow Unix domain sockets in writable tool dirs (Gradle/Kotlin daemon IPC).
    // Gradle 6+ uses UDS in ~/.gradle/daemon/<version>/ for client-daemon comms.
    sbpl!(sb, ";; Unix domain sockets for build daemon IPC");
    sbpl!(
        sb,
        "(allow network-bind (local unix-socket (subpath \"{home}/.gradle\")))"
    );
    sbpl!(
        sb,
        "(allow network-inbound (local unix-socket (subpath \"{home}/.gradle\")))"
    );
    sbpl!(
        sb,
        "(allow network-outbound (remote unix-socket (subpath \"{home}/.gradle\")))"
    );
}
